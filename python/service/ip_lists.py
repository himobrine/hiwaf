"""IP 黑白名单：CRUD + 批量导入导出 + **自动拉黑** + 采集器产物热重载。

产物：`python/artifacts/ip_lists.json`（控制台原子写，采集器每 5s 轮询）：
```json
{"schema":1,"version":1790000000000,
 "whitelist":["10.0.0.5"],"blacklist":["1.2.3.4","203.0.113.0/24"],
 "counts":{"white":1,"black":2},"updated_at":1790000000000}
```
语义（采集器侧）：
  * **白名单优先**：命中白名单 → 跳过模型/规则，直接放行（仍写事件，`ip_list=whitelist`）；
  * 黑名单：`enforce` 直接 403；`dry_run` 只记录 block 证据；`off` 纯采集时不用名单；
  * 自动拉黑只统计“有规则命中的 alert + block”（模型单独的 alert 不算，避免噪声误拉黑）。
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import config, db

_KINDS = ("black", "white")
_KIND_ALIASES = {
    "black": "black", "blacklist": "black", "deny": "black", "block": "black",
    "white": "white", "whitelist": "white", "allow": "white",
}
_ARTIFACT_LOCK = threading.Lock()


def _now() -> int:
    return db.now_ms()


def _audit(actor: str, action: str, target: Optional[str], detail: Any) -> None:
    try:
        db.execute(
            "INSERT INTO audit(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
            (_now(), actor, action, target,
             json.dumps(detail, ensure_ascii=False) if not isinstance(detail, str)
             else detail))
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- 规范化
def normalize(entry: str) -> str:
    s = (entry or "").strip()
    if not s:
        raise ValueError("IP 不能为空")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise ValueError(f"非法 IP/CIDR：{s}")
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def _kind(v: str) -> str:
    k = _KIND_ALIASES.get((v or "").strip().lower())
    if not k:
        raise ValueError(f"kind 只支持 black/white（收到 {v!r}）")
    return k


def _shape(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    out["enabled"] = bool(out.get("enabled"))
    out["expired"] = bool(out.get("expires_at")
                          and int(out["expires_at"]) <= _now())
    out["source"] = out.get("source") or "manual"
    return out


def _get(uid: int) -> Dict[str, Any]:
    row = db.one("SELECT * FROM ip_lists WHERE id=?", (uid,))
    if not row:
        raise ValueError(f"名单条目不存在：{uid}")
    return _shape(row)


# --------------------------------------------------------------------------- CRUD
def _upsert(ip: str, kind: str, *, source: str = "manual", reason: str = "",
            note: str = "", expires_at: Optional[int] = None,
            actor: str = "system") -> Tuple[int, bool]:
    """返回 (id, inserted)。手工条目不会被自动拉黑覆盖。"""
    ip = normalize(ip)
    kind = _kind(kind)
    now = _now()
    cur = db.one("SELECT * FROM ip_lists WHERE kind=? AND ip=?", (kind, ip))
    if cur:
        if cur.get("source") == "manual" and source == "auto":
            if not cur.get("enabled"):
                db.execute("UPDATE ip_lists SET enabled=1, updated_at=? WHERE id=?",
                           (now, cur["id"]))
            return int(cur["id"]), False
        db.execute(
            "UPDATE ip_lists SET source=?, reason=?, note=?, enabled=1, "
            "expires_at=?, updated_at=? WHERE id=?",
            (source, reason or None, note or None, expires_at, now, cur["id"]))
        return int(cur["id"]), False
    uid = db.execute(
        "INSERT INTO ip_lists(ip, kind, source, reason, note, enabled, expires_at, "
        "created_by, created_at, updated_at) VALUES(?,?,?,?,?,1,?,?,?,?)",
        (ip, kind, source, reason or None, note or None, expires_at, actor, now, now))
    return int(uid), True


def add(ip: str, kind: str, *, reason: str = "", note: str = "",
        source: str = "manual", expires_at: Optional[int] = None,
        actor: str = "system") -> Dict[str, Any]:
    uid, _ = _upsert(ip, kind, source=source, reason=reason, note=note,
                     expires_at=expires_at, actor=actor)
    write_artifact()
    return _get(uid)


def list_items(kind: Optional[str] = None, q: Optional[str] = None,
               limit: int = 1000, include_disabled: bool = True) -> List[Dict[str, Any]]:
    where = ["1=1"]
    params: List[Any] = []
    if kind:
        where.append("kind=?")
        params.append(_kind(kind))
    if q:
        where.append("(ip LIKE ? OR reason LIKE ? OR note LIKE ?)")
        params += [f"%{q}%"] * 3
    if not include_disabled:
        where.append("enabled=1")
    rows = db.rows(
        f"SELECT * FROM ip_lists WHERE {' AND '.join(where)} "
        "ORDER BY kind, ip LIMIT ?", params + [max(1, int(limit))])
    return [_shape(r) for r in rows]


def set_enabled(uid: int, enabled: bool, *, actor: str = "system") -> Dict[str, Any]:
    _get(uid)
    db.execute("UPDATE ip_lists SET enabled=?, updated_at=? WHERE id=?",
               (1 if enabled else 0, _now(), uid))
    write_artifact()
    return _get(uid)


def update(uid: int, *, reason: Optional[str] = None, note: Optional[str] = None,
           expires_at: Optional[int] = None, actor: str = "system") -> Dict[str, Any]:
    row = _get(uid)
    sets, params = [], []
    if reason is not None:
        sets.append("reason=?")
        params.append(reason or None)
    if note is not None:
        sets.append("note=?")
        params.append(note or None)
    if expires_at is not None:
        sets.append("expires_at=?")
        params.append(int(expires_at) if int(expires_at) > 0 else None)
    if sets:
        sets.append("updated_at=?")
        params += [_now(), uid]
        db.execute(f"UPDATE ip_lists SET {', '.join(sets)} WHERE id=?", params)
        write_artifact()
    return _get(uid)


def delete(uid: int, *, actor: str = "system") -> Dict[str, Any]:
    row = _get(uid)
    db.execute("DELETE FROM ip_lists WHERE id=?", (uid,))
    write_artifact()
    return row


def bulk_delete(ids: Iterable[int], *, actor: str = "system") -> Dict[str, Any]:
    deleted, missing = [], []
    for raw in ids:
        try:
            uid = int(raw)
        except (TypeError, ValueError):
            continue
        row = db.one("SELECT * FROM ip_lists WHERE id=?", (uid,))
        if not row:
            missing.append(uid)
            continue
        db.execute("DELETE FROM ip_lists WHERE id=?", (uid,))
        deleted.append(_shape(row))
    if deleted:
        write_artifact()
    return {"deleted": deleted, "missing": missing}


# --------------------------------------------------------------------------- 产物
def counts() -> Dict[str, int]:
    now = _now()
    out: Dict[str, int] = {}
    for k in _KINDS:
        out[k] = int(db.scalar(
            "SELECT COUNT(*) AS n FROM ip_lists WHERE kind=? AND enabled=1 "
            "AND (expires_at IS NULL OR expires_at > ?)", (k, now), 0) or 0)
    out["total"] = out.get("black", 0) + out.get("white", 0)
    return out


def _active_rows() -> List[Dict[str, Any]]:
    now = _now()
    return db.rows(
        "SELECT ip, kind FROM ip_lists WHERE enabled=1 "
        "AND (expires_at IS NULL OR expires_at > ?) ORDER BY kind, ip", (now,))


def write_artifact() -> Dict[str, Any]:
    rows = _active_rows()
    white = [r["ip"] for r in rows if r["kind"] == "white"]
    black = [r["ip"] for r in rows if r["kind"] == "black"]
    now = _now()
    doc = {"schema": 1, "version": now,
           "whitelist": white, "blacklist": black,
           "counts": {"white": len(white), "black": len(black)},
           "updated_at": now}
    with _ARTIFACT_LOCK:
        path = config.IP_LISTS
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    return doc


def artifact_state() -> Dict[str, Any]:
    try:
        with open(config.IP_LISTS, "r", encoding="utf-8") as f:
            doc = json.load(f)
        return {"present": True, "counts": doc.get("counts"),
                "version": doc.get("version"),
                "mtime": int(config.IP_LISTS.stat().st_mtime * 1000)}
    except Exception:  # noqa: BLE001
        return {"present": False}


# --------------------------------------------------------------------------- 导入 / 导出
_EXPORT_COLS = ("ip", "kind", "source", "reason", "note", "expires_at",
                "created_by", "created_at")


def export_rows(kind: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = list_items(kind=kind, limit=100000)
    return [{k: r.get(k) for k in _EXPORT_COLS} for r in rows]


def export_csv(kind: Optional[str] = None) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_EXPORT_COLS, lineterminator="\n")
    w.writeheader()
    for r in export_rows(kind):
        w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in _EXPORT_COLS})
    return buf.getvalue()


def export_json(kind: Optional[str] = None) -> str:
    return json.dumps({"items": export_rows(kind)}, ensure_ascii=False, indent=1)


def _parse_import(text: str, default_kind: str) -> List[Tuple[str, str, str, str]]:
    """返回 [(ip, kind, reason, note)]；支持 JSON / CSV / 纯文本行。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("导入内容为空")
    out: List[Tuple[str, str, str, str]] = []

    if text[0] in "[{":
        doc = json.loads(text)
        items = doc.get("items") if isinstance(doc, dict) else doc
        if not isinstance(items, list):
            raise ValueError("JSON 必须是数组或 {\"items\": [...]}")
        for it in items:
            if isinstance(it, str):
                out.append((it, default_kind, "", ""))
            elif isinstance(it, dict):
                out.append((str(it.get("ip") or ""),
                            _kind(str(it.get("kind") or default_kind)),
                            str(it.get("reason") or ""),
                            str(it.get("note") or "")))
        return out

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()
             and not ln.strip().startswith("#")]
    if not lines:
        return out
    first = lines[0].lower()
    if "ip" in first and ("," in first or "\t" in first):
        # CSV / TSV：表头必须含 ip；kind/reason/note 可选
        delim = "\t" if "\t" in first else ","
        rdr = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delim)
        for row in rdr:
            kind_raw = (row.get("kind") or row.get("type") or default_kind).strip()
            out.append((str(row.get("ip") or ""), _kind(kind_raw),
                        str(row.get("reason") or ""), str(row.get("note") or "")))
        return out
    for ln in lines:
        parts = [p.strip() for p in ln.split(",")]
        out.append((parts[0], default_kind,
                    parts[1] if len(parts) > 1 else "",
                    parts[2] if len(parts) > 2 else ""))
    return out


def import_text(text: str, kind: str, *, actor: str = "system") -> Dict[str, Any]:
    default_kind = _kind(kind)
    rows = _parse_import(text, default_kind)
    added = updated = 0
    skipped: List[Dict[str, Any]] = []
    for i, (ip, k, reason, note) in enumerate(rows, start=1):
        try:
            _, inserted = _upsert(ip, k, source="manual", reason=reason,
                                  note=note, actor=actor)
            if inserted:
                added += 1
            else:
                updated += 1
        except ValueError as e:
            skipped.append({"line": i, "ip": ip, "error": str(e)})
    if added or updated:
        write_artifact()
    return {"total": len(rows), "added": added, "updated": updated,
            "skipped": skipped}


# --------------------------------------------------------------------------- 自动拉黑
def auto_settings() -> Dict[str, Any]:
    out = dict(config.IP_AUTO_DEFAULTS)
    for r in db.rows("SELECT key, value FROM app_settings WHERE key LIKE 'ip_auto.%'"):
        k = r["key"].split(".", 1)[1]
        if k not in out:
            continue
        try:
            out[k] = json.loads(r["value"])
        except (TypeError, ValueError):
            pass
    return out


def update_auto_settings(patch: Dict[str, Any], actor: str) -> Dict[str, Any]:
    allowed = set(config.IP_AUTO_DEFAULTS)
    unknown = sorted(set(patch) - allowed)
    if unknown:
        raise ValueError(f"未知设置：{unknown}")
    clean: Dict[str, Any] = {}
    if "threshold" in patch:
        v = int(patch["threshold"])
        if not 1 <= v <= 10000:
            raise ValueError("threshold 必须在 1..10000")
        clean["threshold"] = v
    if "window_min" in patch:
        v = int(patch["window_min"])
        if not 1 <= v <= 1440:
            raise ValueError("window_min 必须在 1..1440")
        clean["window_min"] = v
    if "duration_hours" in patch:
        v = int(patch["duration_hours"])
        if not 0 <= v <= 8760:
            raise ValueError("duration_hours 必须在 0..8760（0=永久）")
        clean["duration_hours"] = v
    for k in ("enabled", "count_rule_alerts"):
        if k in patch:
            clean[k] = bool(patch[k])
    if not clean:
        raise ValueError("没有要更新的设置")
    for k, v in clean.items():
        db.execute(
            "INSERT OR REPLACE INTO app_settings(key, value, updated_at, actor) "
            "VALUES(?,?,?,?)",
            (f"ip_auto.{k}", json.dumps(v), _now(), actor))
    return auto_settings()


def _white_networks() -> List[Any]:
    nets = []
    for r in db.rows("SELECT ip FROM ip_lists WHERE kind='white' AND enabled=1"):
        try:
            nets.append(ipaddress.ip_network(r["ip"], strict=False))
        except ValueError:
            continue
    return nets


def _is_whitelisted(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def auto_scan(actor: str = "system:ip-auto") -> Dict[str, Any]:
    """同一源 IP 在窗口内“有规则命中的 alert + block”达到阈值 → 自动拉黑。"""
    st = auto_settings()
    if not st.get("enabled"):
        return {"enabled": False, "added": [], "candidates": 0}
    now = _now()
    since = now - int(st["window_min"]) * 60 * 1000
    count_alerts = bool(st.get("count_rule_alerts"))
    row = db.rows(
        """SELECT src_ip AS ip, COUNT(*) AS n, MIN(ts) AS first_ts,
                  MAX(ts) AS last_ts
             FROM events
            WHERE ts >= ? AND COALESCE(src_ip,'') <> ''
              AND COALESCE(ip_list,'') = ''
              AND (action='block' OR (? AND action='alert'
                   AND COALESCE(rule_hits_json,'[]') NOT IN ('', '[]')))
            GROUP BY src_ip HAVING COUNT(*) >= ?""",
        (since, 1 if count_alerts else 0, int(st["threshold"])))
    whites = _white_networks()
    added = []
    duration = int(st["duration_hours"])
    expires_at = (now + duration * 3600 * 1000) if duration > 0 else None
    for r in row:
        ip = str(r["ip"])
        if _is_whitelisted(ip, whites):
            continue
        cur = db.one("SELECT * FROM ip_lists WHERE kind='black' AND ip=?", (ip,))
        if cur and cur.get("enabled") and not (
                cur.get("expires_at") and int(cur["expires_at"]) <= now):
            continue
        try:
            uid, _ = _upsert(
                ip, "black", source="auto",
                reason=f"{int(r['n'])} 次告警/阻断（{st['window_min']} 分钟窗口）",
                note="自动拉黑",
                expires_at=expires_at, actor=actor)
        except ValueError:
            continue
        added.append({"id": uid, "ip": ip, "hits": int(r["n"])})
        _audit(actor, "ip_auto_blacklist", f"ip:{ip}",
               {"hits": int(r["n"]), "window_min": st["window_min"],
                "expires_at": expires_at})
    if added:
        write_artifact()
    return {"enabled": True, "added": added, "candidates": len(row)}


def cleanup_expired(actor: str = "system") -> Dict[str, Any]:
    now = _now()
    rows = db.rows(
        "SELECT * FROM ip_lists WHERE expires_at IS NOT NULL AND expires_at <= ?",
        (now,))
    for r in rows:
        db.execute("DELETE FROM ip_lists WHERE id=?", (r["id"],))
    if rows:
        write_artifact()
        _audit(actor, "ip_list_expire", None,
               {"n": len(rows), "ips": [r["ip"] for r in rows][:50]})
    return {"expired": len(rows)}


def scheduler_start() -> None:
    """后台：自动拉黑 + 过期清理（默认 60s 一轮）。"""
    def loop() -> None:
        time.sleep(5)
        while True:
            try:
                auto_scan()
                cleanup_expired()
            except Exception:  # noqa: BLE001
                import traceback
                traceback.print_exc()
            time.sleep(max(10, int(config.IP_AUTO_INTERVAL_SEC)))

    threading.Thread(target=loop, daemon=True, name="ip-list-auto").start()