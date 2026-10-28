"""登录失败限流（单进程内存实现）。

控制面默认单 worker（`service/run.py` 直接 `uvicorn.run`，未开多进程），
因此内存计数足够；如果将来改成多 worker / 多实例，必须换成共享存储
（SQLite 表或 Redis），否则每个进程各自计数。

策略：
  * 以**用户名**为键（控制台 `_ip()` 只取直连地址，上反代后所有请求同 IP，
    按 IP 限流会误伤；用户名维度对单操作员控制台更稳）。
  * 窗口内失败达到 `WAF_LOGIN_MAX_FAILS` 后锁定 `WAF_LOGIN_LOCK_SEC` 秒。
  * 成功登录清零；窗口滑动，不在锁定期内的旧失败会自然过期。
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict

from . import config

# 键数量上限：防止攻击者用随机用户名把内存撑爆。
_MAX_KEYS = 5000

_lock = threading.Lock()
_fails: Dict[str, Deque[float]] = {}
_locked_until: Dict[str, float] = {}


def _now() -> float:
    """单调时钟；测试可 patch。"""
    return time.monotonic()


def normalize(username: str | None) -> str:
    return (username or "").strip().lower()


def _prune(q: Deque[float], now: float) -> None:
    window = max(1, int(config.LOGIN_WINDOW_SEC))
    while q and now - q[0] > window:
        q.popleft()


def _cap_keys() -> None:
    """键过多时丢最早插入的条目（deque 的插入顺序近似攻击先后）。"""
    while len(_fails) > _MAX_KEYS:
        _fails.pop(next(iter(_fails)), None)


def check(username: str) -> int:
    """返回还需等待的秒数；0 表示允许尝试。"""
    key = normalize(username)
    now = _now()
    with _lock:
        until = _locked_until.get(key, 0.0)
        if until > now:
            return max(1, int(until - now + 0.999))
        if until:
            _locked_until.pop(key, None)
        q = _fails.get(key)
        if q:
            _prune(q, now)
            if not q:
                _fails.pop(key, None)
        return 0


def fail(username: str) -> int:
    """记录一次失败；达到阈值时开始锁定并返回锁定秒数（0 = 尚未锁定）。"""
    key = normalize(username)
    now = _now()
    with _lock:
        q = _fails.setdefault(key, deque())
        _prune(q, now)
        q.append(now)
        if len(q) >= max(1, int(config.LOGIN_MAX_FAILS)):
            _locked_until[key] = now + max(1, int(config.LOGIN_LOCK_SEC))
            q.clear()
            _cap_keys()
            return max(1, int(config.LOGIN_LOCK_SEC))
        _cap_keys()
        return 0


def reset(username: str) -> None:
    key = normalize(username)
    with _lock:
        _fails.pop(key, None)
        _locked_until.pop(key, None)


def reset_all() -> None:
    """测试/运维用：清空全部计数。"""
    with _lock:
        _fails.clear()
        _locked_until.clear()
