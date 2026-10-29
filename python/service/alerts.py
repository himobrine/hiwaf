"""告警（聚合）：列表筛选 / 聚合下钻：取某个聚合组的**精确**事件列表。

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


def _where(since: int, until: int, *, src_ip: Optional[str] = None,
           action: Optional[str] = None, attack_type: Optional[str] = None,
           method: Optional[str] = None, host: Optional[str] = None,
           rule: Optional[str] = None, min_score: Optional[float] = None,
           q: Optional[str] = None,
           only_attack_actions: bool = True) -> tuple[str, list]:
    """告警/攻击链共用的过滤条件（事件级，先过滤再聚合/切链）。

    `only_attack_actions=False` 时不再限制 `action IN ('block','alert')`，
    供攻击链取数使用：选源时仍要求有拦截/告警，但切链要保留探测类事件。
    """
    w = ["ts>=?", "ts<=?"]
    if only_attack_actions:
        w.append("action IN ('block','alert')")
    p: list = [since, until]
    if src_ip:
        w.append("src_ip=?")
        p.append(src_ip)
    if action:
        w.append("action=?")
        p.append(action)
    if attack_type:
        w.append("COALESCE(NULLIF(attack_type,''),'')=?")
        p.append(attack_type)
    if method:
        w.append("COALESCE(method,'')=?")
        p.append(method)
    if host:
        w.append("host=?")
        p.append(host)
    if rule:
        w.append("COALESCE(rule_hits_json,'') LIKE ?")
        p.append(f"%{rule}%")
    if min_score is not None:
        w.append("supervised_score>=?")
        p.append(min_score)
    if q:
        like = f"%{q}%"
        w.append("(COALESCE(src_ip,'') LIKE ? OR COALESCE(method,'') LIKE ? "
                 "OR COALESCE(path,'') LIKE ? OR COALESCE(attack_type,'') LIKE ? "
                 "OR COALESCE(ua,'') LIKE ? OR COALESCE(host,'') LIKE ? "
                 "OR COALESCE(rule_hits_json,'') LIKE ?)")
        p += [like] * 7
    return " AND ".join(w), p


def list_groups(since: int, until: int, bucket_min: int = 10,
                dedup: bool = False, *, src_ip: Optional[str] = None,
                action: Optional[str] = None, attack_type: Optional[str] = None,
                method: Optional[str] = None, host: Optional[str] = None,
                rule: Optional[str] = None, min_score: Optional[float] = None,
                q: Optional[str] = None, limit: int = 500) -> dict:
    """聚合告警列表（普通 / dedup 两种模式），支持服务端筛选。

    返回 `{items, truncated}`；`truncated=True` 表示超过 `limit` 被截断。
    """
    bucket_ms = bucket_min * BUCKET_MS
    where, params = _where(since, until, src_ip=src_ip, action=action,
                           attack_type=attack_type, method=method, host=host,
                           rule=rule, min_score=min_score, q=q)
    lim = max(1, int(limit))
    if dedup:
        items = db.rows(
            f"""SELECT src_ip, action,
                       COALESCE(NULLIF(attack_type,''),'') AS attack_type,
                       CAST(ts / ? AS INTEGER) AS bucket,
                       MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n,
                       COUNT(DISTINCT COALESCE(method,'') || ' ' || COALESCE(path,''))
                           AS path_count,
                       MAX(supervised_score) AS max_score
                  FROM events
                 WHERE {where}
                 GROUP BY src_ip, action, COALESCE(NULLIF(attack_type,''),''), bucket
                 ORDER BY last_ts DESC LIMIT ?""",
            [bucket_ms, *params, lim + 1],
        )
        for r in items:
            at = r.get("attack_type") or None
            r["attack_type"] = at
            r["method"] = None
            r["path"] = None
            r["group_key"] = f"{r['src_ip']}|{r['action']}|dedup|{at or '-'}|{r['bucket']}"
            r["severity"] = "P1" if r["action"] == "block" else "P2"
    else:
        items = db.rows(
            f"""SELECT src_ip, action, method, path,
                       CAST(ts / ? AS INTEGER) AS bucket,
                       MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n,
                       MAX(supervised_score) AS max_score,
                       MAX(attack_type) AS attack_type
                  FROM events
                 WHERE {where}
                 GROUP BY src_ip, action, method, path, bucket
                 ORDER BY last_ts DESC LIMIT ?""",
            [bucket_ms, *params, lim + 1],
        )
        for r in items:
            key = f"{r['src_ip']}|{r['action']}|{r.get('method')} {r.get('path')}|{r['bucket']}"
            r["group_key"] = key
            r["severity"] = "P1" if r["action"] == "block" else "P2"
            r["path_count"] = 1
    truncated = len(items) > lim
    return {"items": items[:lim], "truncated": truncated}


def dedup_groups(since: int, bucket_min: int = 10, limit: int = 500,
                 **filters) -> list[dict]:
    """兼容旧调用：`/api/alerts?dedup=1` 的列表（只返回 items）。"""
    return list_groups(since, db.now_ms(), bucket_min, True,
                       limit=limit, **filters)["items"]


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
                   rule_set_sha1_16, rule_hits_json, ip_list
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
