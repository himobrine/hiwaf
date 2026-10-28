"""审计日志 90 天自动清理。

只删 `audit` 表；默认每天一次。自动清理 0 条时不写审计，异常时由
`audit_retention.cleanup()` 尽力写 `audit_cleanup_failed`。
"""
from __future__ import annotations

import threading
import time

from . import audit_retention, config

_START_DELAY_SEC = 30


def run_once() -> dict:
    if not config.AUDIT_RETENTION_SCHEDULER_ENABLED:
        return {"ok": True, "skipped": "disabled"}
    try:
        r = audit_retention.cleanup(
            days=config.AUDIT_RETENTION_DAYS,
            actor="system",
            trigger="auto",
            record_empty=False,
        )
        return {"ok": True, **r}
    except Exception as e:  # noqa: BLE001 - 调度线程不能挂
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _loop() -> None:
    time.sleep(_START_DELAY_SEC)
    while True:
        try:
            run_once()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(max(60, int(config.AUDIT_RETENTION_INTERVAL_SEC)))


def start() -> None:
    if not config.AUDIT_RETENTION_SCHEDULER_ENABLED:
        return
    threading.Thread(target=_loop, name="audit-retention", daemon=True).start()
