"""告警（聚合）下钻：取某个聚合组的**精确**事件列表。

聚合定义与 `GET /api/alerts` 完全一致：
    GROUP BY src_ip, action, method, path, ts/(bucket_min*60000)
所以这里用同一公式复算时间窗（左闭右开），且 `method`/`path` 做精确匹配
（NULL 归一为空串比较）——不能用 `/api/events` 的 `path LIKE %..%`，
那会把 `/api/user` 和 `/api/users` 混在一起，条数对不上聚合的 n。

只读、不过滤动作之外的东西；阵营（block/alert）由调用方传入。
"""
from __future__ import annotations

import json
from typing import Optional

from . import db

BUCKET_MS = 60_000


def window(bucket: int, bucket_min: int) -> tuple[int, int]:
    """桶序号 → [from_ts, to_ts) 毫秒窗口；和 SQL 的整数除法互为逆运算。"""
    if bucket < 0:
        raise ValueError("bucket 必须 ≥ 0")
    if bucket_min < 1 or bucket_min > 1440:
        raise ValueError("bucket_min 必须在 1–1440 之间")
    bucket_ms = bucket_min * BUCKET_MS
    from_ts = bucket * bucket_ms
    return from_ts, from_ts + bucket_ms


def group_events(src_ip: str, action: str, bucket: int, bucket_min: int = 10,
                 method: Optional[str] = None, path: Optional[str] = None,
                 limit: int = 50, offset: int = 0) -> dict:
    """按聚合组精确取事件；返回 {total, from_ts, to_ts, items}。"""
    from_ts, to_ts = window(bucket, bucket_min)
    w = ("ts>=? AND ts<? AND src_ip=? AND action=? "
         "AND COALESCE(method,'')=? AND COALESCE(path,'')=?")
    p = [from_ts, to_ts, src_ip, action, method or "", path or ""]
    total = int(db.scalar(f"SELECT COUNT(*) AS n FROM events WHERE {w}", p, 0) or 0)
    items = db.rows(
        f"""SELECT id, ts, src_ip, src_port, method, path, status, dur_ms,
                   body_len, body_truncated, action, supervised_score,
                   supervised_threshold, supervised_flagged,
                   zero_day_score, zero_day_threshold,
                   zero_day_score_crossed, zero_day_flagged, zero_day_enabled,
                   attack_label, attack_type, ua, dry_run, rule_testing,
                   rule_set_sha1_16, rule_hits_json
            FROM events WHERE {w} ORDER BY ts DESC LIMIT ? OFFSET ?""",
        p + [limit, offset],
    )
    for it in items:
        try:
            it["rule_hits"] = json.loads(it.get("rule_hits_json") or "[]")
        except Exception:
            it["rule_hits"] = []
        it.pop("rule_hits_json", None)
    return {
        "src_ip": src_ip,
        "action": action,
        "method": method,
        "path": path,
        "bucket": bucket,
        "bucket_min": bucket_min,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }
