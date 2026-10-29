"""训练数据集的存储 / 转换 / 预览 / 软删除（上传与事件选择共用）。

控制面只做编排；上传文件的解析在 `python/upload_parse.py`（固定脚本、固定参数），
以子进程运行，避免坏 pcap 把控制台拖死。事件选择生成的数据集见
`service/datasets_events.py`，但存储、`_split_train_copy`（反泄漏）、`_row`、
预览、软删除全部走这里，保证两种来源产物同形。
所有路径由服务端生成，前端不能传路径。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config, db

# `upload_parse` / `realdata` 是 python/ 下的顶层模块；确保无论从哪个 cwd 启动都能 import。
if str(config.PY) not in sys.path:  # noqa: E402
    sys.path.insert(0, str(config.PY))

_CONVERT_LOCK = threading.BoundedSemaphore(1)
_OFFICIAL_KEYS: Optional[set] = None
_OFFICIAL_LOCK = threading.Lock()
_FORMAT_EXT = {v: k for k, v in config.UPLOAD_FORMATS.items()}


def _now() -> int:
    return db.now_ms()


def _audit(actor: str, action: str, target: Optional[str], detail: Any) -> None:
    try:
        db.execute(
            "INSERT INTO audit(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
            (_now(), actor, action, target,
             json.dumps(detail, ensure_ascii=False) if not isinstance(detail, str) else detail))
    except Exception:  # noqa: BLE001
        pass


def ensure_dirs() -> None:
    config.UPLOADS.mkdir(parents=True, exist_ok=True)


def _row(uid: int) -> Optional[dict]:
    r = db.one("SELECT * FROM uploaded_datasets WHERE id=?", (uid,))
    if not r:
        return None
    out = dict(r)
    for k in ("label_stats_json", "stats_json", "selection_json"):
        raw = out.pop(k, None)
        key = k.replace("_json", "")
        try:
            out[key] = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            out[key] = {}
    d = _dir(out)
    out["dir"] = str(d) if d else None
    out["requests_path"] = str(d / "requests.jsonl") if d else None
    out["train_path"] = str(d / "requests_train.jsonl") if d else None
    out["exists"] = bool(d and d.exists())
    return out


def _dir(row: dict) -> Optional[Path]:
    rel = row.get("storage_dir")
    if not rel:
        return None
    p = (config.UPLOADS / rel).resolve()
    try:
        p.relative_to(config.UPLOADS.resolve())
    except ValueError:
        return None
    return p


def _safe_name(name: str, fallback: str = "dataset") -> str:
    s = (name or "").strip()
    if not s:
        s = fallback
    s = "".join(ch for ch in s if ch.isprintable() and ch not in "\r\n\t")
    return s[:120]


def _fmt_from_name(filename: str) -> str:
    ext = os.path.splitext(filename or "")[1].lower()
    return config.UPLOAD_FORMATS.get(ext, "")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fail(uid: int, msg: str, actor: str = "system") -> None:
    db.execute(
        "UPDATE uploaded_datasets SET status='failed', error=?, updated_at=? WHERE id=?",
        (msg[-4000:], _now(), uid))
    _audit(actor, "upload_failed", f"upload:{uid}", {"error": msg[-1000:]})


def _official_eval_keys() -> set:
    """官方评估/校准集请求指纹：payload_test + lexical + CSIC holdout。

    上传训练数据与这些集合精确重叠时必须剔除，否则报告会偏乐观。
    CSIC 加载较慢，进程内缓存一次。
    """
    global _OFFICIAL_KEYS
    if _OFFICIAL_KEYS is not None:
        return _OFFICIAL_KEYS
    with _OFFICIAL_LOCK:
        if _OFFICIAL_KEYS is not None:
            return _OFFICIAL_KEYS
        from realdata import TRAINDATA, csic_normal_index, load_csic, load_payloads
        from upload_parse import req_key

        keys = set()
        for name in ("payload_test.csv", "payload_test_lexical.csv"):
            p = os.path.join(TRAINDATA, name)
            if os.path.exists(p):
                for s in load_payloads(p):
                    keys.add(req_key(s))
        try:
            reqs, _ = load_csic()
            _, hold = csic_normal_index(seed=7, n_train=30000)
            for i in hold:
                keys.add(req_key(reqs[i]))
        except Exception:  # noqa: BLE001 - 缺 CSIC 时仍保护 payload 评估集
            pass
        _OFFICIAL_KEYS = keys
        return keys


def _split_train_copy(uid: int, d: Path, role: str) -> dict:
    """写 requests_train.jsonl：剔除与官方评估集重叠的样本。"""
    from upload_parse import req_key

    src = d / "requests.jsonl"
    dst = d / "requests_train.jsonl"
    if not src.exists():
        raise ValueError("解析结果 requests.jsonl 不存在")
    keys = _official_eval_keys() if role != "eval" else set()
    total = overlap = 0
    with open(src, "r", encoding="utf-8") as fi, open(dst, "w", encoding="utf-8") as fo:
        for line in fi:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            total += 1
            if keys and req_key(obj) in keys:
                overlap += 1
                continue
            fo.write(json.dumps(obj, ensure_ascii=False) + "\n")
    return {"n_input": total, "n_overlap": overlap,
            "n_train": total - overlap,
            "overlap_rate": (overlap / total) if total else 0.0}


def _convert(uid: int, actor: str) -> None:
    with _CONVERT_LOCK:
        row = db.one("SELECT * FROM uploaded_datasets WHERE id=?", (uid,))
        if not row or row["status"] != "converting":
            return
        d = _dir(dict(row))
        if not d:
            _fail(uid, "storage_dir 非法")
            return
        d.mkdir(parents=True, exist_ok=True)
        log_path = d / "convert.log"
        orig = None
        for p in sorted(d.glob("original.*")):
            orig = p
            break
        if not orig:
            _fail(uid, "原始文件丢失")
            return
        cmd = [
            sys.executable, str(config.UPLOAD_PARSER),
            "--input", str(orig), "--out", str(d),
            "--format", row["format"], "--role", row["role"],
            "--max-rows", str(config.UPLOAD_MAX_ROWS),
            "--max-body", str(config.UPLOAD_MAX_BODY),
            "--max-packets", str(config.UPLOAD_MAX_PACKETS),
            "--max-flows", str(config.UPLOAD_MAX_FLOWS),
        ]
        if row.get("default_label") is not None:
            cmd += ["--default-label", str(int(row["default_label"]))]
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write(f"[upload] {' '.join(cmd)}\n")
            lf.flush()
            try:
                p = subprocess.run(
                    cmd, cwd=str(config.PY), stdout=lf, stderr=subprocess.STDOUT,
                    env=env, timeout=config.UPLOAD_TIMEOUT_SEC)
                rc = int(p.returncode)
            except subprocess.TimeoutExpired:
                rc = 124
                lf.write(f"\n[upload] 超时（>{config.UPLOAD_TIMEOUT_SEC}s）\n")
            except Exception as e:  # noqa: BLE001
                rc = 127
                lf.write(f"\n[upload] 启动失败：{e}\n")
        if rc != 0:
            tail = ""
            try:
                tail = "\n".join(log_path.read_text(encoding="utf-8", errors="replace")
                                 .splitlines()[-20:])
            except OSError:
                pass
            _fail(uid, f"解析失败（exit={rc}）\n{tail}", actor)
            return
        try:
            stats = json.loads((d / "stats.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            _fail(uid, f"stats.json 读取失败：{e}", actor)
            return
        if int(stats.get("rows_kept") or 0) <= 0:
            _fail(uid, f"没有解析出任何请求（跳过原因：{stats.get('skip_reasons')}）", actor)
            return
        try:
            ov = _split_train_copy(uid, d, row["role"])
        except Exception as e:  # noqa: BLE001
            _fail(uid, f"生成训练副本失败：{e}", actor)
            return
        stats["overlap_official_eval"] = ov
        labels = stats.get("label_counts") or {}
        db.execute(
            "UPDATE uploaded_datasets SET status='ready', rows_total=?, rows_kept=?, "
            "rows_skipped=?, label_stats_json=?, stats_json=?, error=NULL, updated_at=? "
            "WHERE id=?",
            (int(stats.get("rows_total") or 0), int(stats.get("rows_kept") or 0),
             int(stats.get("rows_skipped") or 0),
             json.dumps(labels, ensure_ascii=False),
             json.dumps(stats, ensure_ascii=False), _now(), uid))
        _audit(actor, "upload_ready", f"upload:{uid}",
               {"rows": stats.get("rows_kept"), "labels": labels, "overlap": ov})


def create_from_stream(stream, filename: str, *, name: Optional[str] = None,
                       role: str = "supervised",
                       default_label: Optional[int] = None,
                       source_note: str = "", actor: str = "system",
                       max_bytes: Optional[int] = None) -> dict:
    """保存上传文件并启动后台转换。stream 需支持 read(size)。"""
    ensure_dirs()
    fmt = _fmt_from_name(filename)
    if not fmt:
        raise ValueError(f"只支持 {sorted(config.UPLOAD_FORMATS)}")
    if role not in config.UPLOAD_ROLES:
        raise ValueError(f"role 只支持 {config.UPLOAD_ROLES}")
    if role in ("supervised", "benign") and not (source_note or "").strip():
        raise ValueError("监督/良性数据必须填写数据来源说明")
    if default_label is not None and int(default_label) not in range(5):
        raise ValueError("default_label 必须是 0-4")
    limit = int(max_bytes if max_bytes is not None else config.UPLOAD_MAX_BYTES)

    token = uuid.uuid4().hex
    d = config.UPLOADS / token
    d.mkdir(parents=True, exist_ok=False)
    ext = os.path.splitext(filename or "")[1].lower() or ".bin"
    dest = d / f"original{ext}"
    size = 0
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = stream.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError(f"文件超过上限 {limit} 字节")
                f.write(chunk)
        if size == 0:
            raise ValueError("空文件")
        sha = _sha256(dest)
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        raise

    display = _safe_name(name or os.path.splitext(os.path.basename(filename))[0],
                         fallback="dataset")
    uid = db.execute(
        "INSERT INTO uploaded_datasets(name, role, format, status, storage_dir, "
        "original_name, size_bytes, sha256, default_label, source_note, created_at, "
        "updated_at, created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (display, role, fmt, "converting", token, os.path.basename(filename or ""),
         size, sha, (int(default_label) if default_label is not None else None),
         (source_note or "").strip()[:1000], _now(), _now(), actor))
    db.execute("UPDATE uploaded_datasets SET log_path=? WHERE id=?",
               (str(d / "convert.log"), uid))
    _audit(actor, "upload_create", f"upload:{uid}",
           {"name": display, "role": role, "format": fmt, "bytes": size, "sha256": sha})
    threading.Thread(target=_convert, args=(uid, actor), daemon=True).start()
    return _row(uid) or {}


def list_uploads(limit: int = 100, include_pruned: bool = False) -> List[dict]:
    where = "" if include_pruned else "WHERE status<>'pruned'"
    rows = db.rows(
        f"SELECT * FROM uploaded_datasets {where} ORDER BY id DESC LIMIT ?", (limit,))
    return [_row(int(r["id"])) or {} for r in rows]


def get_upload(uid: int) -> Optional[dict]:
    return _row(uid)


def preview(uid: int, n: int = 20) -> dict:
    row = _row(uid)
    if not row:
        raise ValueError("数据集不存在")
    d = _dir(row)
    if not d:
        raise ValueError("数据集目录不可用")
    out = []
    p = d / "requests.jsonl"
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if len(out) >= n:
                    break
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                body = obj.get("body") or ""
                if len(body) > 500:
                    obj["body"] = body[:500] + f"…（{len(body)} 字符）"
                out.append(obj)
    return {"dataset": row, "items": out}


def _referenced_by_running_task(uid: int) -> Optional[int]:
    for t in db.rows("SELECT id, args FROM tasks WHERE status IN ('queued','running')"):
        try:
            plan = json.loads(t.get("args") or "{}")
        except (TypeError, ValueError):
            continue
        ids = plan.get("dataset_ids") or []
        if uid in ids:
            return int(t["id"])
        for ds in plan.get("datasets") or []:
            if int(ds.get("id") or -1) == uid:
                return int(t["id"])
    return None


def delete_upload(uid: int, actor: str) -> dict:
    row = db.one("SELECT * FROM uploaded_datasets WHERE id=?", (uid,))
    if not row:
        raise ValueError("数据集不存在")
    if row["status"] == "pruned":
        return _row(uid) or {}
    if row["status"] == "converting":
        raise ValueError("数据集正在转换，不能删除")
    busy = _referenced_by_running_task(uid)
    if busy:
        raise ValueError(f"任务 #{busy} 正在使用该数据集")
    d = _dir(dict(row))
    db.execute("UPDATE uploaded_datasets SET status='pruned', deleted_at=?, updated_at=? "
               "WHERE id=?", (_now(), _now(), uid))
    if d and d.exists():
        shutil.rmtree(d, ignore_errors=True)
    _audit(actor, "upload_delete", f"upload:{uid}",
           {"name": row["name"], "sha256": row.get("sha256")})
    return _row(uid) or {}


def cleanup_stale() -> int:
    """服务重启后，把没有 worker 的 converting 行标失败（幂等）。"""
    rows = db.rows("SELECT id FROM uploaded_datasets WHERE status='converting'")
    for r in rows:
        _fail(int(r["id"]), "服务重启，转换中断；请重新上传")
    return len(rows)
