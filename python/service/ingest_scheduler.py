"""周期性 raw -> SQLite 吸收。

采集器持续往 `traindata/proxy/raw-*.jsonl` 追加，控制面必须持续 ingest，
否则事件/告警页只能看到启动瞬间的数据。这里只做增量入库，不跑规则判定：
规则命中和 action 仍然是采集器写出的事实，本模块不改写、不补判。
"""
from __future__ import annotations

import threading
import time
import traceback

from . import config, ingest

_started = False
_start_lock = threading.Lock()


def start() -> None:
    """控制面启动时拉起后台线程（幂等）。"""
    global _started
    if not config.INGEST_SCHEDULER_ENABLED:
        return
    with _start_lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_loop, name="raw-ingest", daemon=True).start()


def _loop() -> None:
    # 先给 db.init / 迁移让路；之后按固定周期增量续读。
    time.sleep(1)
    while True:
        try:
            ingest.ingest(with_body=False)
        except Exception:  # noqa: BLE001 - 单轮失败不能拖垮控制面
            traceback.print_exc()
        time.sleep(max(2, int(config.INGEST_INTERVAL_SEC)))
