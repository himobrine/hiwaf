"""实体级误报抑制：草案 → 审批 → 生效（TTL）→ 撤销/过期。

设计边界（与规则熔断互补）：

* **只影响控制台告警可见性**：被抑制的聚合组/攻击链默认折叠，但数据面判定
  （block/alert）完全不变 —— 抑制的是「刷屏」，不是「防护」。
* **实体收窄优先**：一条抑制由若干实体字段组成（`src_ip` / `path` / `ua` /
  `host` / `attack_type`），多个字段是 **AND**；至少一个字段非空。
  例如 `src_ip=1.2.3.4 + attack_type=xss` = 只压这个源的 XSS 告警，
  不会关掉 XSS 规则本身。
* **状态机**：`draft`（草案，默认不可见）→ `active`（审批后带 TTL）→
  `revoked`（人工撤销）/ `expired`（到期自动过期，惰性扫描）。
* **误报草案**：`suggest()` 从 `feedback.verdict='false_positive'` 按
  `(src_ip, attack_type)` 统计，达到阈值才生成草案；已有同签名草案/生效抑制
  或撤销冷却期内的直接跳过，避免反复生成。
"""
from __future__ import annotations

from typing import Optional

from . import config, db

FIELDS = ("src_ip", "path", "ua", "host", "attack_type")
STATUSES = ("draft", "active", "revoked", "expired")
HOUR_MS = 3_600_000


# --------------------------------------------------------------------------- 实体
def _clean_entity(data: dict) -> dict:
    """去掉空字段；至少保留一个实体字段。path 统一要求以 `/` 开头。"""
    out: dict = {}
    for f in FIELDS:
        v = data.get(f)
        if v is None:
            continue
        v = str(v).strip()
        if not v:
            continue
        out[f] = v
    if not out:
        raise ValueError("至少需要一个实体字段（src_ip/path/ua/host/attack_type）")
    if "path" in out and not out["path"].startswith("/"):
        raise ValueError("path 必须以 / 开头")
    return out


def _signature(entity: dict) -> str:
    return "|".join(f"{f}={entity[f]}" for f in FIELDS if entity.get(f))


def _now(now: Optional[int] = None) -> int:
    return int(now) if now is not None else db.now_ms()


# --------------------------------------------------------------------------- 读
def _sweep(now: Optional[int] = None) -> None:
    """把已到期的 active 标成 expired（惰性，无后台线程）。

    先用索引探一下有没有到期行，避免每次读列表都发起一次写事务
    （告警页 15s 轮询会高频调用 `active()`）。
    """
    ts = _now(now)
    if not db.one(
        "SELECT 1 AS x FROM suppressions WHERE status='active' "
        "AND expires_at IS NOT NULL AND expires_at<=? LIMIT 1",
        (ts,),
    ):
        return
    db.execute(
        "UPDATE suppressions SET status='expired', updated_at=? "
        "WHERE status='active' AND expires_at IS NOT NULL AND expires_at<=?",
        (ts, ts),
    )


def get(sid: int) -> Optional[dict]:
    return db.one("SELECT * FROM suppressions WHERE id=?", (sid,))


def list_suppressions(status: Optional[str] = None, limit: int = 200,
                      now: Optional[int] = None) -> list[dict]:
    if status and status not in STATUSES:
        raise ValueError(f"status 只支持 {list(STATUSES)}")
    _sweep(now)
    sql = "SELECT * FROM suppressions"
    params: list = []
    if status:
        sql += " WHERE status=?"
        params.append(status)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(max(1, min(1000, int(limit))))
    return db.rows(sql, params)


def active(now: Optional[int] = None) -> list[dict]:
    ts = _now(now)
    _sweep(ts)
    return db.rows(
        "SELECT * FROM suppressions WHERE status='active' "
        "AND (expires_at IS NULL OR expires_at>?) ORDER BY id",
        (ts,),
    )


# --------------------------------------------------------------------------- 写
def create_draft(reason: str, ttl_hours: Optional[int] = None,
                 note: Optional[str] = None, actor: str = "system",
                 now: Optional[int] = None, **entity) -> dict:
    ent = _clean_entity(entity)
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("reason 必填")
    if len(reason) > 500:
        raise ValueError("reason 最长 500 字")
    ttl = config.SUPPRESS_TTL_HOURS if ttl_hours is None else int(ttl_hours)
    if ttl < 1 or ttl > config.SUPPRESS_MAX_TTL_HOURS:
        raise ValueError(f"ttl_hours 必须在 1–{config.SUPPRESS_MAX_TTL_HOURS} 之间")
    ts = _now(now)
    cols = list(ent) + ["reason", "status", "ttl_hours", "created_by",
                        "created_at", "note", "updated_at"]
    vals = list(ent.values()) + [reason, "draft", ttl, actor, ts,
                                 (note or None), ts]
    sid = db.execute(
        f"INSERT INTO suppressions({', '.join(cols)}) "
        f"VALUES({', '.join('?' * len(cols))})",
        vals,
    )
    return get(sid)


def approve(sid: int, actor: str, note: Optional[str] = None,
            now: Optional[int] = None) -> dict:
    row = get(sid)
    if not row:
        raise ValueError("抑制不存在")
    if row["status"] != "draft":
        raise ValueError(f"只有草案可以通过（当前 {row['status']}）")
    ts = _now(now)
    expires = ts + int(row["ttl_hours"]) * HOUR_MS
    db.execute(
        "UPDATE suppressions SET status='active', approved_by=?, approved_at=?, "
        "expires_at=?, decision_note=?, updated_at=? WHERE id=?",
        (actor, ts, expires, (note or None), ts, sid),
    )
    return get(sid)


def revoke(sid: int, actor: str, note: Optional[str] = None,
           now: Optional[int] = None) -> dict:
    row = get(sid)
    if not row:
        raise ValueError("抑制不存在")
    if row["status"] not in ("draft", "active"):
        raise ValueError(f"当前状态不能撤销（{row['status']}）")
    ts = _now(now)
    db.execute(
        "UPDATE suppressions SET status='revoked', revoked_by=?, revoked_at=?, "
        "decision_note=?, updated_at=? WHERE id=?",
        (actor, ts, (note or None), ts, sid),
    )
    return get(sid)


def delete(sid: int, actor: str = "system", now: Optional[int] = None) -> dict:
    """只允许删除草案/已撤销行；active 必须先 revoke，保留审批轨迹。"""
    row = get(sid)
    if not row:
        raise ValueError("抑制不存在")
    if row["status"] not in ("draft", "revoked"):
        raise ValueError("只有草案/已撤销的抑制可以删除")
    db.execute("DELETE FROM suppressions WHERE id=?", (sid,))
    return row


# --------------------------------------------------------------------------- 匹配
def _attack_types(item: dict) -> list[str]:
    ats = item.get("attack_types")
    if isinstance(ats, list):
        out = []
        for a in ats:
            if isinstance(a, dict):
                a = a.get("attack_type")
            if a:
                out.append(str(a))
        return out
    v = item.get("attack_type")
    return [str(v)] if v else []


def _hosts(item: dict) -> list[str]:
    hs = item.get("hosts")
    if isinstance(hs, list):
        return [str(h) for h in hs if h]
    v = item.get("host")
    return [str(v)] if v else []


def _paths(item: dict) -> list[str]:
    ps = item.get("top_paths")
    if isinstance(ps, list) and ps:
        out = []
        for p in ps:
            if isinstance(p, dict):
                p = p.get("path")
            if p:
                out.append(str(p))
        return out
    v = item.get("path")
    return [str(v)] if v else []


def matches(sup: dict, item: dict) -> bool:
    """所有非空实体字段都要命中；item 缺少某字段时视为不匹配（保守）。"""
    if sup.get("src_ip") and (item.get("src_ip") or "") != sup["src_ip"]:
        return False
    if sup.get("ua") and (item.get("ua") or "") != sup["ua"]:
        return False
    if sup.get("host") and sup["host"] not in _hosts(item):
        return False
    if sup.get("attack_type") and sup["attack_type"] not in _attack_types(item):
        return False
    if sup.get("path") and sup["path"] not in _paths(item):
        return False
    return True


def apply(items: list[dict], include_suppressed: bool = False,
          now: Optional[int] = None) -> tuple[list[dict], int]:
    """标注/过滤被抑制的行；返回 (items, 被折叠条数)。

    `include_suppressed=True` 时保留行并附 `suppression` 摘要，供界面展示
    「已抑制」标签；默认折叠，只返回计数。
    """
    sups = active(now)
    hidden = 0
    out: list[dict] = []
    for it in items:
        hit = next((s for s in sups if matches(s, it)), None)
        if not hit:
            out.append(it)
            continue
        if not include_suppressed:
            hidden += 1
            continue
        it = dict(it)
        it["suppression"] = {
            "id": hit["id"],
            "reason": hit["reason"],
            "expires_at": hit["expires_at"],
            "src_ip": hit.get("src_ip"),
            "path": hit.get("path"),
            "ua": hit.get("ua"),
            "host": hit.get("host"),
            "attack_type": hit.get("attack_type"),
            "approved_by": hit.get("approved_by"),
        }
        out.append(it)
    return out, hidden


# --------------------------------------------------------------------------- 误报草案
def suggest(days: Optional[int] = None, min_count: Optional[int] = None,
            ttl_hours: Optional[int] = None, limit: int = 50,
            actor: str = "system", now: Optional[int] = None) -> dict:
    """从人工确认误报生成草案；按 `(src_ip, attack_type)` 统计。

    * 已有草案/生效抑制能覆盖该实体 → 跳过；
    * 撤销/过期未过冷却期 → 跳过，避免「撤销后又自动冒出来」；
    * 只生成草案，**不自动生效**，仍需 admin 审批。
    """
    ts = _now(now)
    days = config.SUPPRESS_SUGGEST_DAYS if days is None else int(days)
    min_count = config.SUPPRESS_SUGGEST_MIN if min_count is None else int(min_count)
    if days < 1 or days > 365:
        raise ValueError("days 必须在 1–365 之间")
    if min_count < 1:
        raise ValueError("min_count 必须 ≥ 1")
    since = ts - days * 24 * HOUR_MS
    rows = db.rows(
        """SELECT e.src_ip AS src_ip,
                  COALESCE(NULLIF(e.attack_type,''),'') AS attack_type,
                  COUNT(*) AS n,
                  MAX(f.ts) AS last_ts,
                  GROUP_CONCAT(DISTINCT e.path) AS paths
             FROM feedback f
             JOIN events e ON e.id = f.event_id
            WHERE f.verdict='false_positive' AND f.ts>=?
              AND e.src_ip IS NOT NULL AND e.src_ip<>''
            GROUP BY e.src_ip, COALESCE(NULLIF(e.attack_type,''),'')
           HAVING COUNT(*)>=?
            ORDER BY n DESC LIMIT ?""",
        (since, max(1, int(min_count)), max(1, min(500, int(limit)))),
    )

    open_sups = db.rows(
        "SELECT * FROM suppressions WHERE status IN ('draft','active')")
    cooldown_ms = config.SUPPRESS_COOLDOWN_HOURS * HOUR_MS
    cooled = db.rows(
        "SELECT * FROM suppressions WHERE status IN ('revoked','expired') "
        "AND updated_at>=?", (ts - cooldown_ms,),
    ) if cooldown_ms else []

    created: list[dict] = []
    skipped: list[dict] = []
    for r in rows:
        ent = {"src_ip": r["src_ip"]}
        if r["attack_type"]:
            ent["attack_type"] = r["attack_type"]
        cand = {"src_ip": ent["src_ip"],
                "attack_type": ent.get("attack_type")}
        why = None
        if any(matches(s, cand) for s in open_sups):
            why = "已有草案/生效抑制覆盖该实体"
        elif any(matches(s, cand) for s in cooled):
            why = f"撤销/过期未过 {config.SUPPRESS_COOLDOWN_HOURS}h 冷却期"
        if why:
            skipped.append({**ent, "n": r["n"], "why": why})
            continue
        paths = [p for p in (r.get("paths") or "").split(",") if p][:5]
        note = ("近期确认误报路径：" + "、".join(paths)) if paths else None
        if note and len(note) > 500:
            note = note[:497] + "..."
        label = r["attack_type"] or "未分类"
        created.append(create_draft(
            reason=f"近 {days} 天 {r['n']} 条人工确认误报（{label}）",
            ttl_hours=ttl_hours, note=note, actor=actor, now=ts, **ent,
        ))
        # 同一次扫描里后续同实体不应重复生成。
        open_sups.append(created[-1])
    return {"scanned": len(rows), "created": created, "skipped": skipped,
            "days": days, "min_count": min_count}
