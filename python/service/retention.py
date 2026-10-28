"""90 天保留期：SQLite 事件 + raw JSONL 清理。

关键顺序：
  1. 先处理 pending（上一轮 DB 已删、文件未删的桥）；
  2. 扫描 RAW_DIR，把候选文件入 pending 并删除 DB 事件（同一事务）；
  3. 再处理新 pending，尝试删文件。

文件删除采用同目录 `<path>.trash` 原子 rename，再校验 size/mtime，最后 unlink。
这样 stat 与 unlink 之间被替换时不会盲删；崩溃后下一轮可按确定性 trash 名恢复。
"""
from __future__ import annotations

import json
import os
import os.path
import re
import stat as statmod
import time
from pathlib import Path
from typing import Callable, Optional

from . import config, db
from .packet import _canonical_under_raw

MTIME_TOL = 1e-6
MAX_ATTEMPTS = 5
_orphan_ignored: set[str] = set()
_DAY_RE = re.compile(r"raw-(\d{8})-\d+\.jsonl$")


def _now_ms() -> int:
    return db.now_ms()


def cutoff_ms(days: int | None = None) -> int:
    d = config.RETENTION_DAYS if days is None else int(days)
    return _now_ms() - d * 86_400_000


def _mtime_matches(st: os.stat_result, mtime: float) -> bool:
    return abs(float(st.st_mtime) - float(mtime)) <= MTIME_TOL


def _file_stat(p: Path) -> tuple[Optional[os.stat_result], Optional[str]]:
    try:
        st = os.lstat(p)
    except OSError:
        return None, "missing"
    if statmod.S_ISLNK(st.st_mode):
        return None, "symlink"
    if not statmod.S_ISREG(st.st_mode):
        return None, "not_regular"
    return st, None


def _set_manual(conn, path: str, err: str) -> None:
    conn.execute(
        "UPDATE raw_cleanup_pending SET state='manual', last_error=?, attempts=attempts+1 WHERE path=?",
        (err, path),
    )
    conn.commit()


def _bump(conn, path: str, err: str) -> None:
    r = conn.execute(
        "SELECT attempts FROM raw_cleanup_pending WHERE path=?", (path,)
    ).fetchone()
    n = int(r["attempts"] if r else 0) + 1
    if n >= MAX_ATTEMPTS:
        conn.execute(
            "UPDATE raw_cleanup_pending SET state='manual', last_error=?, attempts=? WHERE path=?",
            (err, n, path),
        )
    else:
        conn.execute(
            "UPDATE raw_cleanup_pending SET last_error=?, attempts=? WHERE path=?",
            (err, n, path),
        )
    conn.commit()


def _delete_pending(conn, path: str) -> None:
    conn.execute("DELETE FROM raw_cleanup_pending WHERE path=?", (path,))
    conn.execute("DELETE FROM ingest_state WHERE path=?", (path,))
    conn.commit()


def _unlink_checked(p: Path) -> tuple[bool, Optional[str]]:
    try:
        os.unlink(p)
        return True, None
    except OSError as e:
        return False, f"unlink_failed:{e}"


def process_pending(dry_run: bool = False) -> dict:
    """处理 pending；返回统计 + 每个 pending 的动作。"""
    st = {
        "checked": 0,
        "deleted": 0,
        "manual": 0,
        "gone": 0,
        "failed": 0,
        "items": [],
    }
    conn = db.connect()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM raw_cleanup_pending ORDER BY created_at, path"
        ).fetchall()]
        for row in rows:
            st["checked"] += 1
            path_s = row["path"]
            p = _canonical_under_raw(path_s)
            item = {"path": path_s, "state": row["state"], "action": None,
                    "detail": None, "attempts": row["attempts"]}
            if row["state"] == "manual":
                st["manual"] += 1
                item.update(action="skip_manual", detail=row.get("last_error"))
                st["items"].append(item)
                continue
            if p is None:
                st["manual"] += 1
                item.update(action="manual", detail="path_rejected")
                if not dry_run:
                    _set_manual(conn, path_s, "path_rejected")
                st["items"].append(item)
                continue

            trash = Path(str(p) + ".trash")
            path_st, path_err = _file_stat(p)
            trash_st, trash_err = _file_stat(trash)
            path_exists = path_st is not None
            trash_exists = trash_st is not None
            if path_err == "symlink" or trash_err == "symlink":
                st["manual"] += 1
                item.update(action="manual", detail="symlink")
                if not dry_run:
                    _set_manual(conn, path_s, "symlink")
                st["items"].append(item)
                continue

            # 状态 D：path 与 trash 同时存在 —— 不覆盖、不自动处理。
            if path_exists and trash_exists:
                st["manual"] += 1
                item.update(action="manual", detail="path_and_trash_exist")
                if not dry_run:
                    _set_manual(conn, path_s, "path_and_trash_exist")
                st["items"].append(item)
                continue

            # 状态 C：都不在 —— 删 pending 行并审计“已不存在”。
            if not path_exists and not trash_exists:
                st["gone"] += 1
                item.update(action="gone", detail="path_and_trash_missing")
                if not dry_run:
                    _delete_pending(conn, path_s)
                st["items"].append(item)
                continue

            # 状态 A：path 在、trash 不在 —— 校验 -> rename -> 回填 -> unlink。
            if path_exists:
                if path_st is None or path_st.st_size != int(row["size"]) or not _mtime_matches(path_st, row["mtime"]):
                    st["failed"] += 1
                    item.update(action="stat_mismatch", detail="path")
                    if not dry_run:
                        _bump(conn, path_s, "stat_mismatch")
                    st["items"].append(item)
                    continue
                if dry_run:
                    item.update(action="would_rename_unlink", detail="path")
                    st["items"].append(item)
                    continue
                try:
                    os.replace(str(p), str(trash))
                except OSError as e:
                    st["failed"] += 1
                    item.update(action="rename_failed", detail=str(e))
                    _bump(conn, path_s, f"rename_failed:{e}")
                    st["items"].append(item)
                    continue
                conn.execute(
                    "UPDATE raw_cleanup_pending SET trash_path=? WHERE path=?",
                    (str(trash), path_s),
                )
                conn.commit()
                st2, e2 = _file_stat(trash)
                if st2 is None or st2.st_size != int(row["size"]) or not _mtime_matches(st2, row["mtime"]):
                    st["manual"] += 1
                    item.update(action="trash_mismatch", detail=e2 or "stat")
                    _set_manual(conn, path_s, "trash_mismatch")
                    st["items"].append(item)
                    continue
                ok, err = _unlink_checked(trash)
                if not ok:
                    st["failed"] += 1
                    item.update(action="unlink_failed", detail=err)
                    _bump(conn, path_s, err or "unlink_failed")
                    st["items"].append(item)
                    continue
                _delete_pending(conn, path_s)
                st["deleted"] += 1
                item.update(action="deleted", detail="path")
                st["items"].append(item)
                continue

            # 状态 B：path 不在、trash 在 —— 直接校验 trash 后 unlink。
            if trash_st is None or trash_st.st_size != int(row["size"]) or not _mtime_matches(trash_st, row["mtime"]):
                st["failed"] += 1
                item.update(action="trash_mismatch", detail=trash_err or "stat")
                if not dry_run:
                    _bump(conn, path_s, "trash_mismatch")
                st["items"].append(item)
                continue
            if dry_run:
                item.update(action="would_unlink_trash", detail="trash")
                st["items"].append(item)
                continue
            ok, err = _unlink_checked(trash)
            if not ok:
                st["failed"] += 1
                item.update(action="unlink_failed", detail=err)
                _bump(conn, path_s, err or "unlink_failed")
                st["items"].append(item)
                continue
            _delete_pending(conn, path_s)
            st["deleted"] += 1
            item.update(action="deleted", detail="trash")
            st["items"].append(item)
    finally:
        conn.close()
    return st


def _day_of_file(p: Path, max_ts: int | None) -> str:
    m = _DAY_RE.search(p.name)
    if m:
        return m.group(1)
    if max_ts:
        return time.strftime("%Y%m%d", time.gmtime(max_ts / 1000.0))
    return "unknown"


def _candidate_stats(p: Path, conn, cutoff: int) -> dict:
    key = str(p)
    ev = conn.execute(
        """SELECT COUNT(*) AS n, MAX(ts) AS max_ts,
                  SUM(CASE WHEN action IN ('alert','block') THEN 1 ELSE 0 END) AS bad
           FROM events WHERE src_file=?""",
        (key,),
    ).fetchone()
    n = int(ev["n"] or 0) if ev else 0
    max_ts = int(ev["max_ts"]) if ev and ev["max_ts"] is not None else None
    bad = int(ev["bad"] or 0) if ev else 0
    ist = conn.execute("SELECT size, mtime, lines FROM ingest_state WHERE path=?", (key,)).fetchone()
    try:
        fst = os.lstat(p)
    except OSError:
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": 0,
                "events": n, "alert_block": bad, "eligible": False, "reason": "missing"}
    if statmod.S_ISLNK(fst.st_mode):
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": 0,
                "events": n, "alert_block": bad, "eligible": False, "reason": "symlink"}
    if fst.st_mtime >= cutoff / 1000.0:
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
                "events": n, "alert_block": bad, "eligible": False, "reason": "not_old"}
    if max_ts is not None and max_ts >= cutoff:
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
                "events": n, "alert_block": bad, "eligible": False, "reason": "mixed_cutoff"}
    if ist is None:
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
                "events": n, "alert_block": bad, "eligible": False, "reason": "never_ingested"}
    if (int(ist["size"]) != fst.st_size
            or abs(float(ist["mtime"]) - float(fst.st_mtime)) > MTIME_TOL):
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
                "events": n, "alert_block": bad, "eligible": False,
                "reason": "pending_ingest"}
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = sum(1 for _ in f)
    except OSError:
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
                "events": n, "alert_block": bad, "eligible": False, "reason": "unreadable"}
    if lines != int(ist["lines"]):
        return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
                "events": n, "alert_block": bad, "eligible": False,
                "reason": "pending_ingest"}
    return {"path": key, "day": _day_of_file(p, max_ts), "bytes": fst.st_size,
            "events": n, "alert_block": bad, "eligible": True, "reason": "eligible"}


def scan_candidates(cutoff: int, dry_run: bool = True) -> dict:
    st = {"files": 0, "eligible": 0, "skipped": 0, "db_events_deleted": 0,
          "items": [], "by_day": {}}
    if not config.RAW_DIR.exists():
        return st
    conn = db.connect()
    try:
        for p in sorted(config.RAW_DIR.glob("raw-*.jsonl")):
            st["files"] += 1
            item = _candidate_stats(p, conn, cutoff)
            day = item["day"]
            b = st["by_day"].setdefault(day, {"files": 0, "bytes": 0, "events": 0,
                                              "alert_block": 0, "eligible": 0})
            b["files"] += 1
            b["bytes"] += int(item["bytes"])
            b["events"] += int(item["events"])
            b["alert_block"] += int(item["alert_block"])
            if not item["eligible"]:
                st["skipped"] += 1
                st["items"].append(item)
                continue
            # 已存在 pending（可能 manual）就不再入队；dry-run 也如实报告，避免
            # “dry-run 说 eligible、apply 却 already_pending”的误导。
            if conn.execute("SELECT 1 FROM raw_cleanup_pending WHERE path=?", (item["path"],)).fetchone():
                st["skipped"] += 1
                item["reason"] = "already_pending"
                st["items"].append(item)
                continue
            b["eligible"] += 1
            if dry_run:
                st["eligible"] += 1
                item["action"] = "would_enqueue"
                st["items"].append(item)
                continue
            try:
                cur = conn.execute("SELECT id FROM events WHERE src_file=?", (item["path"],))
                ids = [r["id"] for r in cur.fetchall()]
                if ids:
                    ph = ",".join("?" * len(ids))
                    conn.execute(f"DELETE FROM event_shap WHERE event_id IN ({ph})", ids)
                    conn.execute(f"DELETE FROM event_bodies WHERE event_id IN ({ph})", ids)
                    conn.execute(f"DELETE FROM event_rules WHERE event_id IN ({ph})", ids)
                    conn.execute(f"DELETE FROM events WHERE id IN ({ph})", ids)
                fst = os.lstat(p)
                conn.execute(
                    """INSERT OR IGNORE INTO raw_cleanup_pending
                         (path, size, mtime, cutoff_ms, created_at, attempts, last_error, state, trash_path)
                       VALUES (?,?,?,?,?,0,NULL,'pending',NULL)""",
                    (item["path"], fst.st_size, fst.st_mtime, cutoff, db.now_ms()),
                )
                conn.commit()
                st["eligible"] += 1
                st["db_events_deleted"] += len(ids)
                item["action"] = "enqueued"
                item["db_events_deleted"] = len(ids)
            except Exception as e:
                conn.rollback()
                st["skipped"] += 1
                item["reason"] = f"db_error:{e}"
            st["items"].append(item)
    finally:
        conn.close()
    return st


def scan_orphan_trash(dry_run: bool = True) -> dict:
    """登记无 pending 的 `.trash` 为 manual；绝不自动删除。"""
    st = {"found": 0, "registered": 0, "items": []}
    if not config.RAW_DIR.exists():
        return st
    cutoff_old = time.time() - config.RAW_CLEANUP_ORPHAN_AGE_SEC
    conn = db.connect()
    try:
        for t in sorted(config.RAW_DIR.glob("*.trash")):
            try:
                fst = os.lstat(t)
            except OSError:
                continue
            if statmod.S_ISLNK(fst.st_mode) or not statmod.S_ISREG(fst.st_mode):
                continue
            if fst.st_mtime > cutoff_old:
                continue
            original = str(t)[:-len(".trash")]
            if original in _orphan_ignored:
                continue
            has = conn.execute(
                "SELECT 1 FROM raw_cleanup_pending WHERE path=? OR trash_path=?",
                (original, str(t)),
            ).fetchone()
            if has:
                continue
            st["found"] += 1
            st["items"].append({"trash": str(t), "original": original})
            if dry_run:
                continue
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO raw_cleanup_pending
                         (path, size, mtime, cutoff_ms, created_at, attempts, last_error, state, trash_path)
                       VALUES (?,?,?,?,?,0,'orphan_trash','manual',?)""",
                    (original, fst.st_size, fst.st_mtime, cutoff_ms(),
                     db.now_ms(), str(t)),
                )
                conn.commit()
                st["registered"] += 1
            except Exception:
                conn.rollback()
    finally:
        conn.close()
    return st


def prune_aggregates(cutoff: int, dry_run: bool = True) -> dict:
    """清理规则聚合表。

    * `rule_hits_daily`：只删 **cutoff 当天之前** 的 UTC 日桶，避免把 cutoff
      当天切一半；与事件清理使用同一个 cutoff。
    * `rule_incidents`：只删已 resolved 且解决时间早于 cutoff 的记录；
      open/acked 永远保留，不会因为过期而丢失待处置状态。
    """
    day_before = time.strftime("%Y-%m-%d", time.gmtime(cutoff / 1000.0))
    daily_sql = "SELECT COUNT(*) FROM rule_hits_daily WHERE day < ?"
    incident_sql = (
        "SELECT COUNT(*) FROM rule_incidents "
        "WHERE status='resolved' AND COALESCE(resolved_at, opened_at) < ?"
    )
    conn = db.connect()
    try:
        daily = int(conn.execute(daily_sql, (day_before,)).fetchone()[0] or 0)
        incidents = int(conn.execute(incident_sql, (cutoff,)).fetchone()[0] or 0)
        if not dry_run:
            conn.execute("DELETE FROM rule_hits_daily WHERE day < ?", (day_before,))
            conn.execute(
                "DELETE FROM rule_incidents "
                "WHERE status='resolved' AND COALESCE(resolved_at, opened_at) < ?",
                (cutoff,),
            )
            conn.commit()
    finally:
        conn.close()
    return {
        "dry_run": bool(dry_run),
        "day_before": day_before,
        "rule_hits_daily": daily,
        "rule_incidents": incidents,
        "action": "would_delete" if dry_run else "deleted",
    }


def dry_run(days: int | None = None) -> dict:
    cutoff = cutoff_ms(days)
    pend = process_pending(dry_run=True)
    scan = scan_candidates(cutoff, dry_run=True)
    orphan = scan_orphan_trash(dry_run=True)
    try:
        aggregates = prune_aggregates(cutoff, dry_run=True)
    except Exception as e:
        aggregates = {"dry_run": True, "error": f"{type(e).__name__}: {e}"}
    return {"dry_run": True, "cutoff_ms": cutoff, "pending": pend,
            "scan": scan, "orphan_trash": orphan, "aggregates": aggregates}


def apply(days: int | None = None) -> dict:
    cutoff = cutoff_ms(days)
    # 先处理旧 pending；再扫新文件入队并删 DB；最后再处理新 pending（含删文件）。
    pend1 = process_pending(dry_run=False)
    scan = scan_candidates(cutoff, dry_run=False)
    pend2 = process_pending(dry_run=False)
    orphan = scan_orphan_trash(dry_run=False)
    try:
        aggregates = prune_aggregates(cutoff, dry_run=False)
    except Exception as e:
        # raw/事件清理已经提交；聚合表裁剪失败不能把整个 apply 伪装成完全成功。
        aggregates = {"dry_run": False, "error": f"{type(e).__name__}: {e}"}
    return {"dry_run": False, "cutoff_ms": cutoff, "pending_before": pend1,
            "scan": scan, "pending_after": pend2, "orphan_trash": orphan,
            "aggregates": aggregates}


def pending_rows() -> list[dict]:
    return db.rows(
        "SELECT path, size, mtime, cutoff_ms, created_at, attempts, last_error, state, trash_path "
        "FROM raw_cleanup_pending ORDER BY state='manual' DESC, created_at"
    )


def counts() -> dict:
    return {
        "pending": int(db.scalar("SELECT COUNT(*) FROM raw_cleanup_pending WHERE state='pending'", default=0) or 0),
        "manual": int(db.scalar("SELECT COUNT(*) FROM raw_cleanup_pending WHERE state='manual'", default=0) or 0),
    }


def resolve(path: str, action: str, note: str | None = None,
            before_commit: Optional[Callable[[dict], None]] = None) -> dict:
    """retry / adopt / forget。返回变更前后的 stat 供审计。

    `before_commit` 在写入前调用（可写 fail-closed 审计）：回调抛错则本动作不提交。
    """
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM raw_cleanup_pending WHERE path=?", (path,)).fetchone()
        if not row:
            raise KeyError("pending 不存在")
        row = dict(row)
        old = {"size": row["size"], "mtime": row["mtime"],
               "state": row["state"], "attempts": row["attempts"]}
        if action == "retry":
            result = {"path": path, "action": action, "old": old,
                      "new": {"state": "pending", "attempts": 0}}
            if before_commit:
                before_commit(result)
            conn.execute(
                "UPDATE raw_cleanup_pending SET attempts=0, state='pending', last_error=NULL WHERE path=?",
                (path,),
            )
            conn.commit()
            return result
        if action == "adopt":
            p = _canonical_under_raw(path)
            if p is None:
                raise ValueError("path 越界")
            trash = Path(str(p) + ".trash")
            pst, _ = _file_stat(p)
            tst, _ = _file_stat(trash)
            if pst is not None and tst is not None:
                raise ValueError("path 和 trash 同时存在；请先人工处理其中一个")
            target = pst or tst
            if target is None:
                raise ValueError("path/trash 都不存在，无法 adopt")
            result = {"path": path, "action": action, "old": old,
                      "new": {"size": target.st_size, "mtime": target.st_mtime,
                              "state": "pending", "attempts": 0}}
            if before_commit:
                before_commit(result)
            conn.execute(
                "UPDATE raw_cleanup_pending SET size=?, mtime=?, attempts=0, state='pending', "
                "last_error=NULL, trash_path=? WHERE path=?",
                (target.st_size, target.st_mtime, str(trash) if tst is not None else row.get("trash_path"), path),
            )
            conn.commit()
            return result
        if action == "forget":
            trash = row.get("trash_path")
            if not trash:
                p = _canonical_under_raw(path)
                if p is not None and Path(str(p) + ".trash").exists():
                    trash = str(p) + ".trash"
            result = {"path": path, "action": action, "old": old, "new": None}
            if before_commit:
                before_commit(result)
            conn.execute("DELETE FROM raw_cleanup_pending WHERE path=?", (path,))
            conn.commit()
            if trash:
                _orphan_ignored.add(str(trash))
            return result
        raise ValueError("action 只支持 retry|adopt|forget")
    finally:
        conn.close()
