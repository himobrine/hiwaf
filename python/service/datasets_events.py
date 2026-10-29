"""从控制台**事件**生成训练数据集（快照），产物与上传数据同形。

定位：训练数据的第二个来源。上传是「把外面的文件搬进来」，这里是「把 WAF 自己
看到的事件固化成数据集」。两者产物完全一样（`requests.jsonl` /
`requests_train.jsonl` / `stats.json`），所以训练任务、模型登记、阈值校准、
反泄漏全部复用，训练脚本零改动。

## 红线（与项目既定决策一致）

  * **事件的 `attack_label` / `attack_type` 是模型预测，不是标签**。
    本模块**从不**用它们当 label：标签只能由操作者在创建时显式指定
    （`label` 参数，统一标签），并连同 actor / 选择条件写进审计与 `stats`。
  * **快照语义**：创建时把行拷成文件，不引用事件行。事件 90 天保留期清理、
    raw 文件被清理，都不影响已建数据集。
  * **反泄漏**：`requests_train.jsonl` 由 `uploads._split_train_copy` 产出，
    与官方评估集（payload_test / lexical / CSIC 留出）重叠的行在训练时剔除。

## body 的两级回退

事件表默认不存 body（`ingest` 需显式 `with_body=True`）。所以：

  1. 先读 `event_bodies`（完整文本）；
  2. 缺失时按 `src_file` 分组、**一次顺序扫描** raw JSONL，取该行的
     `body`（文本）或 `body_b64`（解出 UTF-8 文本才用；二进制跳过）；
  3. 两边都没有 → body 留空，计入 `stats.body.missing`（不丢行：GET 本来就没有 body）。

## 去重

同一个请求指纹（`method\\x1fpath\\x1fquery\\x1fbody`）只保留**最新一条**
（事件按 ts DESC 处理），被丢掉的计入 `stats.dedup`。扫描器把同一个 payload
打一万次不会变成一万条训练样本。
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import threading
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import config, db, packet, uploads

# `upload_parse` / `realdata` 是 python/ 下的顶层模块。
if str(config.PY) not in sys.path:  # noqa: E402
    sys.path.insert(0, str(config.PY))

#: 转换串行化：raw 扫描是磁盘 IO，别让多个建集任务互相拖慢。
_BUILD_LOCK = threading.BoundedSemaphore(1)

#: SQLite 变量数上限（老版本 999）；IN 查询一律分批。
_CHUNK = 400
#: 预检最多扫描多少行（给弹窗做创建前的体量/body 预估）。
PREVIEW_ROWS = 300

_SELECT_COLS = ("id, ts, src_ip, ua, method, path, query, body_len, body_truncated, "
                "status, src_file, src_line, attack_label, attack_type, action")


def _now() -> int:
    return db.now_ms()


# --------------------------------------------------------------------------- 过滤
def event_where(action: Optional[str] = None, src_ip: Optional[str] = None,
                path: Optional[str] = None, min_score: Optional[float] = None,
                from_ts: Optional[int] = None, to_ts: Optional[int] = None,
                q: Optional[str] = None, rule_testing: Optional[bool] = None,
                attack_type: Optional[str] = None,
                verdict: Optional[str] = None) -> Tuple[str, List[Any]]:
    """与 `/api/events` 同一套过滤语义（单一事实来源，app 也调这里）。

    `attack_type` / `verdict` 是事件选择专用：前者按模型分类**筛选**（不是标签），
    后者按人工 feedback 结论存在性筛选。
    """
    w = ["1=1"]
    p: List[Any] = []
    if action:
        w.append("action=?")
        p.append(action)
    if src_ip:
        w.append("src_ip=?")
        p.append(src_ip)
    if path:
        w.append("path LIKE ?")
        p.append(f"%{path}%")
    if min_score is not None:
        w.append("supervised_score>=?")
        p.append(min_score)
    if from_ts:
        w.append("ts>=?")
        p.append(from_ts)
    if to_ts:
        w.append("ts<=?")
        p.append(to_ts)
    if rule_testing is not None:
        w.append("rule_testing=?")
        p.append(1 if rule_testing else 0)
    if q:
        w.append("(path LIKE ? OR query LIKE ? OR ua LIKE ?)")
        p += [f"%{q}%"] * 3
    if attack_type:
        w.append("attack_type=?")
        p.append(attack_type)
    if verdict:
        w.append("EXISTS (SELECT 1 FROM feedback f WHERE f.event_id=events.id "
                 "AND f.verdict=?)")
        p.append(verdict)
    return " AND ".join(w), p


def _clean_filters(filters: Optional[dict]) -> dict:
    """只允许已知键；空串按未填处理。"""
    f = filters or {}
    out: Dict[str, Any] = {}
    for k in ("action", "src_ip", "path", "q", "attack_type", "verdict"):
        v = f.get(k)
        if v not in (None, ""):
            out[k] = str(v)
    for k in ("min_score",):
        v = f.get(k)
        if v not in (None, ""):
            out[k] = float(v)
    for k in ("from_ts", "to_ts"):
        v = f.get(k)
        if v not in (None, ""):
            out[k] = int(v)
    if f.get("rule_testing") is not None and f.get("rule_testing") != "":
        out["rule_testing"] = bool(f["rule_testing"])
    unknown = set(f) - {"action", "src_ip", "path", "q", "attack_type", "verdict",
                        "min_score", "from_ts", "to_ts", "rule_testing"}
    if unknown:
        raise ValueError(f"不认识的筛选字段：{sorted(unknown)}")
    return out


# --------------------------------------------------------------------------- 选行
def _select_by_ids(ids: List[int], limit: int) -> Tuple[List[dict], bool]:
    out: List[dict] = []
    uniq = list(dict.fromkeys(int(i) for i in ids))
    for i in range(0, len(uniq), _CHUNK):
        part = uniq[i:i + _CHUNK]
        ph = ",".join("?" * len(part))
        out += db.rows(
            f"SELECT {_SELECT_COLS} FROM events WHERE id IN ({ph}) "
            "ORDER BY ts DESC, id DESC", part)
    out.sort(key=lambda r: (int(r.get("ts") or 0), int(r.get("id") or 0)), reverse=True)
    truncated = len(out) > limit
    return out[:limit], truncated


def _select_by_filter(filters: dict, limit: int) -> Tuple[List[dict], bool]:
    w, p = event_where(**filters)
    rows = db.rows(
        f"SELECT {_SELECT_COLS} FROM events WHERE {w} "
        "ORDER BY ts DESC, id DESC LIMIT ?", p + [limit + 1])
    truncated = len(rows) > limit
    return rows[:limit], truncated


def select_events(mode: str, event_ids: Optional[List[int]] = None,
                  filters: Optional[dict] = None,
                  limit: int = 20) -> Tuple[List[dict], bool]:
    """按 ids / filter 选出事件行（ts 倒序）。"""
    if mode == "ids":
        if not event_ids:
            raise ValueError("ids 模式必须给 event_ids")
        if len(event_ids) > config.EVENT_DATASET_MAX_IDS:
            raise ValueError(f"单次最多选 {config.EVENT_DATASET_MAX_IDS} 条事件")
        return _select_by_ids(event_ids, limit)
    if mode == "filter":
        f = _clean_filters(filters)
        if not f:
            raise ValueError("filter 模式至少要有一个筛选条件")
        return _select_by_filter(f, limit)
    raise ValueError("mode 只支持 ids / filter")


# --------------------------------------------------------------------------- body
def _b64_text(b64: Optional[str]) -> Optional[str]:
    """body_b64 → UTF-8 文本；二进制/损坏返回 None（不假装有 body）。"""
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=False)
    except Exception:  # noqa: BLE001
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _raw_bodies(rows: Iterable[dict], counts: Counter) -> Dict[int, str]:
    """缺失行按 `src_file` 分组，一次顺序扫描取回 body。"""
    want: Dict[str, Dict[int, List[int]]] = {}
    for r in rows:
        src = r.get("src_file")
        ln = r.get("src_line")
        if not src or not ln:
            continue
        p = packet._canonical_under_raw(src)  # noqa: SLF001 - 同样拒绝越界路径
        if p is None:
            counts["path_rejected"] += 1
            continue
        want.setdefault(str(p), {}).setdefault(int(ln), []).append(int(r["id"]))

    out: Dict[int, str] = {}
    for spath, lines in want.items():
        need = set(lines)
        try:
            with open(spath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, start=1):
                    if i not in need:
                        continue
                    need.discard(i)
                    line = line.strip()
                    if line:
                        try:
                            d = json.loads(line)
                        except ValueError:
                            d = None
                        if isinstance(d, dict):
                            body = d.get("body")
                            if not (isinstance(body, str) and body):
                                body = _b64_text(d.get("body_b64"))
                            if body:
                                for eid in lines[i]:
                                    out[eid] = body
                            else:
                                counts["binary_or_empty"] += 1
                    if not need:
                        break
        except OSError:
            counts["raw_missing"] += 1
        counts["raw_files_scanned"] += 1
    return out


def resolve_bodies(rows: List[dict]) -> Tuple[Dict[int, str], dict]:
    """event_bodies → raw JSONL → 空。返回 (event_id -> body, 统计)。"""
    bodies: Dict[int, str] = {}
    counts: Counter = Counter()
    ids = [int(r["id"]) for r in rows]
    for i in range(0, len(ids), _CHUNK):
        part = ids[i:i + _CHUNK]
        ph = ",".join("?" * len(part))
        for row in db.rows(
                f"SELECT event_id, body FROM event_bodies WHERE event_id IN ({ph})",
                part):
            if row.get("body"):
                bodies[int(row["event_id"])] = str(row["body"])
    missing = [r for r in rows if int(r["id"]) not in bodies]
    from_raw = _raw_bodies(missing, counts)
    bodies.update(from_raw)
    missing2 = [r for r in missing if int(r["id"]) not in bodies]
    # 区分「本来就没有 body」（GET/HEAD，body_len=0）与「有 body 但拿不到」
    # （raw 被清理 / 二进制 / 采集关掉了 body）。前者不是问题，后者才要告警。
    empty = sum(1 for r in missing2 if not int(r.get("body_len") or 0))
    stats = {
        "from_db": len(bodies) - len(from_raw),
        "from_raw": len(from_raw),
        "missing": len(missing2) - empty,
        "empty": empty,
        "truncated": sum(1 for r in rows if r.get("body_truncated")),
        **{k: int(v) for k, v in counts.items()},
    }
    return bodies, stats


# --------------------------------------------------------------------------- 组行
def build_rows(rows: List[dict], bodies: Dict[int, str], label: int,
               actor: str, mode: str) -> Tuple[List[dict], dict]:
    """事件行 → 训练行（含去重）。label 由调用方显式给出（红线）。"""
    from upload_parse import req_key

    seen = set()
    out: List[dict] = []
    dup = 0
    for r in sorted(rows, key=lambda x: (int(x.get("ts") or 0), int(x.get("id") or 0)),
                    reverse=True):
        eid = int(r["id"])
        row = {
            "method": (r.get("method") or "GET"),
            "path": r.get("path") or "",
            "query": r.get("query") or "",
            "body": bodies.get(eid, ""),
            "label": int(label),
            "label_why": f"console:{actor}:{mode}:event#{eid}",
        }
        for k in ("ts", "src_ip", "ua", "status"):
            if r.get(k):
                row[k] = r[k]
        key = req_key(row)
        if key in seen:
            dup += 1
            continue
        seen.add(key)
        out.append(row)
    return out, {"input": len(rows), "kept": len(out), "duplicates": dup}


# --------------------------------------------------------------------------- 建集
def _dir_of(row: dict) -> Optional[Path]:
    rel = row.get("storage_dir")
    if not rel:
        return None
    p = (config.UPLOADS / rel).resolve()
    try:
        p.relative_to(config.UPLOADS.resolve())
    except ValueError:
        return None
    return p


def _fail(uid: int, msg: str, actor: str = "system") -> None:
    db.execute(
        "UPDATE uploaded_datasets SET status='failed', error=?, updated_at=? WHERE id=?",
        (msg[-4000:], _now(), uid))
    uploads._audit(actor, "dataset_failed", f"upload:{uid}",  # noqa: SLF001
                   {"error": msg[-1000:]})


def _build(uid: int, actor: str) -> None:
    with _BUILD_LOCK:
        row = db.one("SELECT * FROM uploaded_datasets WHERE id=?", (uid,))
        if not row or row["status"] != "converting":
            return
        try:
            sel = json.loads(row.get("selection_json") or "{}")
        except ValueError:
            sel = {}
        d = _dir_of(dict(row))
        if not d:
            _fail(uid, "storage_dir 非法", actor)
            return
        d.mkdir(parents=True, exist_ok=True)
        mode = str(sel.get("mode") or "ids")
        limit = int(sel.get("max_rows") or config.EVENT_DATASET_MAX_ROWS)
        try:
            rows, truncated = select_events(
                mode, event_ids=sel.get("event_ids"), filters=sel.get("filters"),
                limit=limit)
        except ValueError as e:
            _fail(uid, str(e), actor)
            return
        if not rows:
            _fail(uid, "没有选中任何事件", actor)
            return
        bodies, body_stats = resolve_bodies(rows)
        label = int(row.get("default_label") or 0)
        train_rows, dedup = build_rows(rows, bodies, label, actor, mode)

        with open(d / "requests.jsonl", "w", encoding="utf-8") as f:
            for r in train_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        sel_doc = {
            "origin": "events",
            "mode": mode,
            "event_ids": sel.get("event_ids") if mode == "ids" else None,
            "filters": sel.get("filters") if mode == "filter" else None,
            "max_rows": limit,
            "truncated": truncated,
            "label": label,
            "actor": actor,
            "created_at": _now(),
        }
        (d / "selection.json").write_text(
            json.dumps(sel_doc, ensure_ascii=False, indent=2), encoding="utf-8")

        from upload_parse import summarize
        stats = summarize(train_rows, {
            "rows_total": int(dedup["input"]),
            "format": "events",
            "skip_reasons": {},
            "selection": sel_doc,
            "dedup": dedup,
            "body": body_stats,
        })
        try:
            ov = uploads._split_train_copy(uid, d, row["role"])  # noqa: SLF001
        except Exception as e:  # noqa: BLE001
            _fail(uid, f"生成训练副本失败：{e}", actor)
            return
        stats["overlap_official_eval"] = ov
        labels = stats.get("label_counts") or {}
        p = d / "requests.jsonl"
        try:
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            size = p.stat().st_size
        except OSError:
            sha, size = None, 0
        db.execute(
            "UPDATE uploaded_datasets SET status='ready', rows_total=?, rows_kept=?, "
            "rows_skipped=?, label_stats_json=?, stats_json=?, sha256=?, size_bytes=?, "
            "error=NULL, updated_at=? WHERE id=?",
            (int(stats.get("rows_total") or 0), int(stats.get("rows_kept") or 0),
             int(stats.get("rows_skipped") or 0),
             json.dumps(labels, ensure_ascii=False),
             json.dumps(stats, ensure_ascii=False), sha, int(size), _now(), uid))
        uploads._audit(actor, "dataset_ready", f"upload:{uid}",  # noqa: SLF001
                       {"rows": stats.get("rows_kept"), "labels": labels,
                        "body": body_stats, "dedup": dedup, "overlap": ov})


def create_from_events(*, name: str = "", role: str = "supervised", label: int,
                       source_note: str = "", mode: str = "ids",
                       event_ids: Optional[List[int]] = None,
                       filters: Optional[dict] = None,
                       max_rows: Optional[int] = None,
                       actor: str = "system", wait: bool = False) -> dict:
    """从事件创建数据集（默认后台转换，状态机与上传一致）。

    `wait=True` 同步建完再返回（只给测试/脚本用）：测试里如果起线程再失败退出，
    线程会跨过 mock 边界写到真实库，必须避免这种泄漏。
    """
    role = (role or "").strip()
    if role not in config.UPLOAD_ROLES:
        raise ValueError(f"role 只支持 {config.UPLOAD_ROLES}")
    label = int(label)
    if label not in range(5):
        raise ValueError("label 必须是 0-4")
    # 红线：良性数据集的标签只能是 0；标签是操作者显式给出的，绝不从模型预测取。
    if role == "benign" and label != 0:
        raise ValueError("良性数据集（role=benign）的标签只能是 0")
    if role in ("supervised", "benign") and not (source_note or "").strip():
        raise ValueError("监督/良性数据必须填写数据来源说明")
    mode = (mode or "").strip()
    if mode not in ("ids", "filter"):
        raise ValueError("mode 只支持 ids / filter")
    cap = int(config.EVENT_DATASET_MAX_ROWS)
    limit = min(int(max_rows) if max_rows else cap, cap)
    if limit < 1:
        raise ValueError("max_rows 必须 ≥1")

    # 先做一次"抽 1 行"的合法性检查 + 冻结筛选条件快照。
    if mode == "ids":
        ids = [int(i) for i in (event_ids or [])]
        if not ids:
            raise ValueError("ids 模式必须给 event_ids")
        if len(ids) > config.EVENT_DATASET_MAX_IDS:
            raise ValueError(f"单次最多选 {config.EVENT_DATASET_MAX_IDS} 条事件")
        sel_snapshot = {"mode": "ids", "event_ids": ids[:config.EVENT_DATASET_MAX_IDS]}
    else:
        f = _clean_filters(filters)   # 校验键名，防拼错静默变"全量"
        if not f:
            raise ValueError("filter 模式至少要有一个筛选条件")
        sel_snapshot = {"mode": "filter", "filters": f}

    # 快速失败：一条都没匹配就别建"注定失败"的数据集行（也避免白起一个线程）。
    probe, _ = select_events(mode, event_ids=event_ids, filters=filters, limit=1)
    if not probe:
        raise ValueError("没有匹配到任何事件（可能已被保留策略清理）")

    uploads.ensure_dirs()
    token = uuid.uuid4().hex
    d = config.UPLOADS / token
    d.mkdir(parents=True, exist_ok=False)
    display = uploads._safe_name(name, fallback=f"事件选择 {mode}")  # noqa: SLF001
    sel_doc = {**sel_snapshot, "max_rows": limit, "label": label, "actor": actor,
               "created_at": _now()}
    uid = db.execute(
        "INSERT INTO uploaded_datasets(name, role, format, origin, status, storage_dir, "
        "original_name, size_bytes, default_label, source_note, selection_json, "
        "created_at, updated_at, created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (display, role, "events", "events", "converting", token,
         f"events:{mode}", 0, label, (source_note or "").strip()[:1000],
         json.dumps(sel_doc, ensure_ascii=False), _now(), _now(), actor))
    db.execute("UPDATE uploaded_datasets SET log_path=? WHERE id=?",
               (str(d / "selection.json"), uid))
    # 创建审计由 API 路由写（带 ip；选择快照在 detail 里）。这里不再重复写一份。
    if wait:
        _build(uid, actor)
    else:
        threading.Thread(target=_build, args=(uid, actor), daemon=True).start()
    return uploads.get_upload(uid) or {}


# --------------------------------------------------------------------------- 预检
def preview_selection(*, mode: str, event_ids: Optional[List[int]] = None,
                      filters: Optional[dict] = None,
                      max_rows: Optional[int] = None) -> dict:
    """创建前的体量/body 预估。扫描上限 PREVIEW_ROWS，不落盘。"""
    cap = int(config.EVENT_DATASET_MAX_ROWS)
    limit = min(int(max_rows) if max_rows else cap, cap)
    if mode == "ids":
        ids = [int(i) for i in (event_ids or [])]
        if not ids:
            raise ValueError("ids 模式必须给 event_ids")
        if len(ids) > config.EVENT_DATASET_MAX_IDS:
            raise ValueError(f"单次最多选 {config.EVENT_DATASET_MAX_IDS} 条事件")
        matched = 0
        uniq = list(dict.fromkeys(ids))
        for i in range(0, len(uniq), _CHUNK):
            part = uniq[i:i + _CHUNK]
            w = ",".join("?" * len(part))
            matched += int(db.scalar(
                f"SELECT COUNT(*) AS n FROM events WHERE id IN ({w})", part, 0) or 0)
    else:
        f = _clean_filters(filters)
        if not f:
            raise ValueError("filter 模式至少要有一个筛选条件")
        where, p = event_where(**f)
        matched = int(db.scalar(
            f"SELECT COUNT(*) AS n FROM events WHERE {where}", p, 0) or 0)

    rows, _ = select_events(mode, event_ids=event_ids, filters=filters,
                            limit=min(limit, PREVIEW_ROWS))
    bodies, body_stats = resolve_bodies(rows)
    train_rows, dedup = build_rows(rows, bodies, 0, "preview", mode)
    types = Counter(str(r.get("attack_type") or "") for r in rows)
    sample = [
        {"id": int(r["id"]), "ts": r.get("ts"), "method": r.get("method"),
         "path": r.get("path"), "action": r.get("action"),
         "body_len": int(r.get("body_len") or 0)}
        for r in rows[:5]
    ]
    return {
        "matched": matched,
        "truncated": matched > limit,
        "limit": limit,
        "checked": len(rows),
        "preview_capped": matched > PREVIEW_ROWS,
        "unique_checked": dedup["kept"],
        "duplicates_checked": dedup["duplicates"],
        "body": body_stats,
        "attack_type_hint": {k: v for k, v in types.most_common() if k},
        "sample": sample,
        # 提醒前端：这是模型分类的分布提示，不是标签；标签必须人工指定。
        "note": "attack_type 只是模型分类提示，不能当标签；训练标签由创建时显式指定。",
    }
