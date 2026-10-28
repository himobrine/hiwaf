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


def dedup_groups(since: int, bucket_min: int = 10, limit: int = 500) -> list[dict]:
    """`/api/alerts?dedup=1` 的聚合：`src_ip + action + attack_type + 时间桶`。

    同一源在同一桶内打不同路径的同类攻击只占一行；`path_count` 是不同
    `method path` 的数量，用来判断是不是扫描/爆破风暴。空攻击类型归为 `None`。
    """
    bucket_ms = bucket_min * BUCKET_MS
    items = db.rows(
        """SELECT src_ip, action,
                  COALESCE(NULLIF(attack_type,''),'') AS attack_type,
                  CAST(ts / ? AS INTEGER) AS bucket,
                  MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n,
                  COUNT(DISTINCT COALESCE(method,'') || ' ' || COALESCE(path,''))
                      AS path_count,
                  MAX(supervised_score) AS max_score
           FROM events
           WHERE ts>=? AND action IN ('block','alert')
           GROUP BY src_ip, action, COALESCE(NULLIF(attack_type,''),''), bucket
           ORDER BY last_ts DESC LIMIT ?""",
        (bucket_ms, since, limit),
    )
    for r in items:
        at = r.get("attack_type") or None
        r["attack_type"] = at
        r["method"] = None
        r["path"] = None
        r["group_key"] = f"{r['src_ip']}|{r['action']}|dedup|{at or '-'}|{r['bucket']}"
        r["severity"] = "P1" if r["action"] == "block" else "P2"
    return items


def group_events(src_ip: str, action: str, bucket: int, bucket_min: int = 10,
                 method: Optional[str] = None, path: Optional[str] = None,
                 attack_type: Optional[str] = None, dedup: bool = False,
                 limit: int = 50, offset: int = 0) -> dict:
    """按聚合组精确取事件；返回 {total, from_ts, to_ts, items}。

    `dedup=True` 时对应 `/api/alerts?dedup=1` 的「同源 + 动作 + 类型 + 桶」合并组：
    忽略 method/path，改为按 `attack_type` 精确匹配（空值归一为空串）。
    """
    from_ts, to_ts = window(bucket, bucket_min)
    if dedup:
        w = ("ts>=? AND ts<? AND src_ip=? AND action=? "
             "AND COALESCE(NULLIF(attack_type,''),'')=?")
        p = [from_ts, to_ts, src_ip, action, attack_type or ""]
    else:
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
        "attack_type": attack_type,
        "dedup": dedup,
        "bucket": bucket,
        "bucket_min": bucket_min,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }
