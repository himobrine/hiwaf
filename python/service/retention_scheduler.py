"""保留期巡检（非破坏性）。

设计约束：
  * 每天只跑 **dry-run**，绝不自动 apply/删除 raw 文件；真正清理仍要求 admin
    走 `POST /api/retention/raw-cleanup` 并显式 `confirm=true`。
  * 把最近一次 dry-run 结果原子写到 `config.RETENTION_DRY_RUN_FILE`，同时落审计，
    方便计划任务/告警在 apply 前保留证据。
  * 任何异常都只记录在快照里，不阻塞控制台启动。
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

from . import config, db, retention

_lock = threading.Lock()


def _snapshot_path() -> Path:
    return Path(config.RETENTION_DRY_RUN_FILE)


def load_snapshot() -> Optional[dict]:
    p = _snapshot_path()
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _write_snapshot(doc: dict) -> None:
    p = _snapshot_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(str(tmp), str(p))


def _summary(st: dict) -> dict:
    """审计/清单里只放计数，避免把每个文件的完整路径重复塞进 audit。"""
    pending = st.get("pending") or {}
    scan = st.get("scan") or {}
    orphan = st.get("orphan_trash") or {}
    agg = st.get("aggregates") or {}
    return {
        "pending_checked": int(pending.get("checked") or 0),
        "pending_manual": int(pending.get("manual") or 0),
        "scan_files": int(scan.get("files") or 0),
        "scan_eligible": int(scan.get("eligible") or 0),
        "scan_skipped": int(scan.get("skipped") or 0),
        "orphan_found": int(orphan.get("found") or 0),
        "rule_hits_daily_old": int(agg.get("rule_hits_daily") or 0),
        "rule_incidents_old": int(agg.get("rule_incidents") or 0),
    }


def run_once(force: bool = False) -> dict:
    """跑一次 dry-run；`force=False` 时距上次快照不足一个周期则复用。"""
    now = db.now_ms()
    interval_ms = max(60, int(config.RETENTION_CHECK_INTERVAL_SEC)) * 1000
    with _lock:
        old = load_snapshot()
        if not force and old:
            try:
                age = now - int(old.get("generated_at") or 0)
            except (TypeError, ValueError):
                age = interval_ms
            if 0 <= age < interval_ms:
                return old

        try:
            st = retention.dry_run()
            doc = {
                "generated_at": now,
                "generated_at_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now / 1000.0)),
                "days": config.RETENTION_DAYS,
                "ok": True,
                "summary": _summary(st),
                "result": st,
            }
        except Exception as e:  # 巡检失败也要留痕，但不能影响主服务
            doc = {
                "generated_at": now,
                "generated_at_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now / 1000.0)),
                "days": config.RETENTION_DAYS,
                "ok": False,
                "error": f"{type(e).__name__}: {e}",
                "summary": {},
            }

        try:
            _write_snapshot(doc)
        except OSError as e:
            doc["snapshot_error"] = str(e)

        try:
            detail = {
                "ok": bool(doc.get("ok")),
                "summary": doc.get("summary") or {},
                "error": doc.get("error"),
                "snapshot": str(_snapshot_path()),
            }
            db.execute(
                "INSERT INTO audit(ts, actor, action, target, detail, ip) "
                "VALUES(?,?,?,?,?,?)",
                (now, "system", "retention_dry_run_scheduled", None,
                 json.dumps(detail, ensure_ascii=False), None),
            )
        except Exception:
            pass
        return doc


def _loop() -> None:
    # 启动时先让 ingest 跑一会儿，避免与全量扫文件抢 IO。
    time.sleep(10)
    try:
        # 启动那次尊重已有快照的时效；之后按周期强制刷新。
        run_once(force=False)
    except Exception:
        pass
    while True:
        time.sleep(max(60, int(config.RETENTION_CHECK_INTERVAL_SEC)))
        try:
            run_once(force=True)
        except Exception:
            pass


def start() -> None:
    if not config.RETENTION_SCHEDULER_ENABLED:
        return
    threading.Thread(target=_loop, name="retention-dry-run", daemon=True).start()
