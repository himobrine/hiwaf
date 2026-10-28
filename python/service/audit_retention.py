"""审计日志保留期：按时间清理 + admin 勾选删除。

设计约束：
  * 只处理 `audit` 表，不动 events / raw / 聚合表。
  * 每次真正删除后都写一条新的 `audit_cleanup` / `audit_cleanup_selected`，
    保证“最近一次删除动作”仍有痕；自动清理删除 0 条时不写，避免每天刷屏。
  * 删除在 `BEGIN IMMEDIATE` 事务里分批执行；写清理审计失败则整体回滚。
  * 进程内加锁，自动清理与手动清理不会互相穿插。
"""
from __future__ import annotations

import json
import threading
import time
from typing import Iterable, Optional

from . import config, db

_LOCK = threading.Lock()
DAY_MS = 86_400_000


def _days(value: Optional[int]) -> int:
    d = int(config.AUDIT_RETENTION_DAYS if value is None else value)
    if d < 1 or d > 3650:
        raise ValueError("days 必须在 1–3650 之间")
    return d


def _cutoff(days: int) -> int:
    return db.now_ms() - days * DAY_MS


def _iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ms) / 1000.0))


def preview(days: Optional[int] = None) -> dict:
    """dry-run：返回待删条数、截止时间与按动作统计，不删除任何行。"""
    d = _days(days)
    cutoff = _cutoff(d)
    total = int(db.scalar("SELECT COUNT(*) FROM audit", default=0) or 0)
    delete_count = int(db.scalar(
        "SELECT COUNT(*) FROM audit WHERE ts < ?", (cutoff,), default=0) or 0)
    oldest = db.scalar("SELECT MIN(ts) FROM audit")
    newest = db.scalar("SELECT MAX(ts) FROM audit")
    del_oldest = db.scalar("SELECT MIN(ts) FROM audit WHERE ts < ?", (cutoff,))
    del_newest = db.scalar("SELECT MAX(ts) FROM audit WHERE ts < ?", (cutoff,))
    by_action = [
        {"action": r.get("action"), "n": int(r.get("n") or 0)}
        for r in db.rows(
            "SELECT action, COUNT(*) AS n FROM audit WHERE ts < ? "
            "GROUP BY action ORDER BY n DESC LIMIT 10", (cutoff,))
    ]
    return {
        "days": d,
        "cutoff_ms": cutoff,
        "cutoff_iso": _iso(cutoff),
        "total": total,
        "delete_count": delete_count,
        "keep_count": max(0, total - delete_count),
        "oldest_ts": oldest,
        "newest_ts": newest,
        "delete_oldest_ts": del_oldest,
        "delete_newest_ts": del_newest,
        "by_action": by_action,
        "default_days": int(config.AUDIT_RETENTION_DAYS),
        "auto_enabled": bool(config.AUDIT_RETENTION_SCHEDULER_ENABLED),
    }


def _insert_cleanup(conn, actor: str, action: str, target: str, detail: dict,
                    ip: Optional[str]) -> int:
    cur = conn.execute(
        "INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
        (db.now_ms(), actor, action, target,
         json.dumps(detail, ensure_ascii=False), ip),
    )
    return int(cur.lastrowid or 0)


def _best_effort_failure(actor: str, target: str, exc: Exception,
                         ip: Optional[str], trigger: str) -> None:
    try:
        db.execute(
            "INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
            (db.now_ms(), actor, "audit_cleanup_failed", target,
             json.dumps({"trigger": trigger,
                         "error": f"{type(exc).__name__}: {exc}"},
                        ensure_ascii=False), ip),
        )
    except Exception:  # noqa: BLE001 - 失败留痕本身失败时不能掩盖原异常
        pass


def cleanup(days: Optional[int] = None, *, actor: str = "system",
            ip: Optional[str] = None, trigger: str = "manual",
            record_empty: bool = True) -> dict:
    """删除 cutoff 之前的审计行；`record_empty=False` 用于自动清理 0 条时静默。"""
    d = _days(days)
    cutoff = _cutoff(d)
    target = f"age:{d}d"
    try:
        with _LOCK:
            conn = db.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                deleted = 0
                batches = 0
                while True:
                    cur = conn.execute(
                        "DELETE FROM audit WHERE id IN "
                        "(SELECT id FROM audit WHERE ts < ? LIMIT ?)",
                        (cutoff, int(config.AUDIT_CLEANUP_BATCH)),
                    )
                    n = int(cur.rowcount or 0)
                    if n <= 0:
                        break
                    deleted += n
                    batches += 1
                    if n < int(config.AUDIT_CLEANUP_BATCH):
                        break
                cleanup_id = 0
                if deleted or record_empty:
                    cleanup_id = _insert_cleanup(
                        conn, actor, "audit_cleanup", target,
                        {"trigger": trigger, "days": d, "cutoff_ms": cutoff,
                         "deleted": deleted, "batches": batches},
                        ip,
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
    except Exception as exc:
        _best_effort_failure(actor, target, exc, ip, trigger)
        raise
    return {
        "ok": True,
        "trigger": trigger,
        "days": d,
        "cutoff_ms": cutoff,
        "cutoff_iso": _iso(cutoff),
        "deleted": deleted,
        "batches": batches,
        "cleanup_audit_id": cleanup_id,
    }


def _norm_ids(ids: Iterable[int]) -> list[int]:
    try:
        vals = [int(i) for i in ids]
    except (TypeError, ValueError):
        raise ValueError("ids 必须是整数列表") from None
    vals = list(dict.fromkeys(vals))
    if not vals:
        raise ValueError("至少选择一个审计 id")
    if any(v <= 0 for v in vals):
        raise ValueError("审计 id 必须为正整数")
    if len(vals) > int(config.AUDIT_SELECTED_MAX):
        raise ValueError(f"单次最多删除 {config.AUDIT_SELECTED_MAX} 条")
    return vals


def delete_selected(ids: Iterable[int], *, actor: str, ip: Optional[str] = None,
                    reason: str = "") -> dict:
    """按 id 删除勾选的审计行（admin 单人确认即可）。"""
    vals = _norm_ids(ids)
    target = f"selected:{len(vals)}"
    try:
        with _LOCK:
            conn = db.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                ph = ",".join("?" for _ in vals)
                found = conn.execute(
                    f"SELECT id FROM audit WHERE id IN ({ph})", vals).fetchall()
                found_ids = [int(r["id"]) for r in found]
                missing = sorted(set(vals) - set(found_ids))
                deleted = 0
                if found_ids:
                    ph2 = ",".join("?" for _ in found_ids)
                    cur = conn.execute(
                        f"DELETE FROM audit WHERE id IN ({ph2})", found_ids)
                    deleted = int(cur.rowcount or 0)
                cleanup_id = _insert_cleanup(
                    conn, actor, "audit_cleanup_selected", target,
                    {"trigger": "manual_selected", "requested": len(vals),
                     "deleted": deleted, "missing": missing[:200],
                     "ids": found_ids[:200],
                     "reason": (reason or "")[:500]},
                    ip,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
    except Exception as exc:
        _best_effort_failure(actor, target, exc, ip, "manual_selected")
        raise
    return {
        "ok": True,
        "requested": len(vals),
        "deleted": deleted,
        "missing": missing,
        "cleanup_audit_id": cleanup_id,
    }
