"""规则误报监控 + 熔断建议（后台线程，60s 一轮）。

原则（用户拍板）：
  * **只认人工确认的误报**触发自动降级：block 规则在 10 分钟内被人工标了
    ≥5 条确认良性、且确认良性占已标样本 ≥50% ⇒ 自动降为 alert + 弹窗。
  * `alert` 规则的噪声只弹窗不自动动（先让人看一眼）。
  * **量突增只提示**：真攻击也会让命中量涨，按量自动熔断等于给攻击者一个
    关规则的后门。
  * 未标注的命中**不计入误报率**；模型也报了的只算「疑似攻击」，不参与触发。
  * 去重：同 (rule, reason) 已有 open 就不新开；同规则 1 小时冷却。
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
from typing import Any, Dict, List, Optional

from . import breaker, db, rules as rules_mod

WINDOW_MIN = int(os.environ.get("WAF_RULE_FP_WINDOW_MIN", "10"))
BLOCK_MIN_BENIGN = int(os.environ.get("WAF_RULE_BLOCK_MIN_BENIGN", "5"))
BLOCK_BENIGN_RATIO = float(os.environ.get("WAF_RULE_BLOCK_BENIGN_RATIO", "0.5"))
ALERT_NOISE_BENIGN = int(os.environ.get("WAF_RULE_ALERT_NOISE_BENIGN", "20"))
SPIKE_WINDOW_MIN = int(os.environ.get("WAF_RULE_SPIKE_WINDOW_MIN", "5"))
SPIKE_MIN_HITS = int(os.environ.get("WAF_RULE_SPIKE_MIN_HITS", "100"))
SPIKE_FACTOR = float(os.environ.get("WAF_RULE_SPIKE_FACTOR", "5"))
BLOCK_SPIKE_MIN = int(os.environ.get("WAF_RULE_BLOCK_SPIKE_MIN", "50"))
COOLDOWN_MIN = int(os.environ.get("WAF_RULE_INCIDENT_COOLDOWN_MIN", "60"))
AUTO_CONFIRMED_FP = os.environ.get("WAF_RULE_AUTO_BREAKER", "1") not in ("0", "false", "no")
SCAN_INTERVAL_SEC = int(os.environ.get("WAF_RULE_MONITOR_INTERVAL", "60"))

_started = False
_lock = threading.Lock()


# --------------------------------------------------------------------------- 读状态
def _intents() -> Dict[str, Dict[str, Any]]:
    """规则 id -> 控制面意图（**不是**产物里的 action）。

    产物里的 action 可能已经被夹成 alert（测试中/熔断），判断"这是不是一条
    block 规则"必须看 DB 里的 `qualified_at + action`，否则会漏掉真正危险的那条。
    """
    out: Dict[str, Dict[str, Any]] = {}
    for r in rules_mod.custom_rows():
        out[str(r["id"])] = {
            "action": r.get("action") or "alert",
            "qualified": bool(r.get("qualified_at")),
            "kind": r.get("kind") or "detector",
            "source": r.get("source") or "custom",
            "name": r.get("name"),
            "enabled": bool(r.get("enabled")),
        }
    for r in (rules_mod.load_authoritative() or {}).get("rules") or []:
        rid = str(r.get("id"))
        if rid in out:
            continue
        prov = r.get("provenance") or {}
        out[rid] = {
            "action": r.get("action") or "alert",
            "qualified": prov.get("qualification") in ("proven", "qualified"),
            "kind": prov.get("kind") or "detector",
            "source": "mined",
            "name": r.get("name"),
            "enabled": True,
        }
    return out


def _window_stats(since: int) -> Dict[str, Dict[str, Any]]:
    sql = """
        WITH hit_events AS (
            SELECT er.rule AS rule, er.event_id AS event_id,
                   MAX(e.ts) AS ts,
                   MAX(CASE WHEN e.action='block' THEN 1 ELSE 0 END) AS block_hit
              FROM event_rules er
              JOIN events e ON e.id = er.event_id
             WHERE e.ts >= ?
             GROUP BY er.rule, er.event_id
        )
        SELECT h.rule AS rule,
               COUNT(*) AS hits,
               COALESCE(SUM(h.block_hit), 0) AS block_hits,
               COALESCE(SUM(CASE WHEN fb.verdict IN ('confirmed_benign','false_positive') THEN 1 ELSE 0 END), 0) AS benign,
               COALESCE(SUM(CASE WHEN fb.verdict IN ('confirmed_attack','missed') THEN 1 ELSE 0 END), 0) AS attack,
               COALESCE(SUM(CASE WHEN fb.verdict IS NULL
                                  AND (e.supervised_flagged=1 OR e.zero_day_flagged=1)
                                 THEN 1 ELSE 0 END), 0) AS suspected,
               MAX(h.ts) AS last_ts
          FROM hit_events h
          JOIN events e ON e.id = h.event_id
          LEFT JOIN feedback fb ON fb.id = (
              SELECT f2.id FROM feedback f2
               WHERE f2.event_id = h.event_id
               ORDER BY f2.ts DESC, f2.id DESC LIMIT 1
          )
         GROUP BY h.rule
    """
    out: Dict[str, Dict[str, Any]] = {}
    for r in db.rows(sql, (since,)):
        d = dict(r)
        for k in ("hits", "block_hits", "benign", "attack", "suspected"):
            d[k] = int(d.get(k) or 0)
        d["labeled"] = d["benign"] + d["attack"]
        out[str(d["rule"])] = d
    return out


def _samples(rule: str, since: int, limit: int = 3) -> List[int]:
    rows = db.rows(
        """SELECT e.id AS id FROM event_rules er JOIN events e ON e.id=er.event_id
            WHERE er.rule=? AND e.ts>=? ORDER BY e.ts DESC LIMIT ?""",
        (rule, since, limit),
    )
    return [int(r["id"]) for r in rows]


def _spike_baseline(rule: str, now: int) -> float:
    """过去 55 分钟的平均每 5 分钟命中数（不含最近 5 分钟）。"""
    lo = now - 60 * 60 * 1000
    hi = now - SPIKE_WINDOW_MIN * 60 * 1000
    n = db.scalar(
        """SELECT COUNT(DISTINCT er.event_id) AS n FROM event_rules er
             JOIN events e ON e.id=er.event_id
            WHERE er.rule=? AND e.ts>=? AND e.ts<?""",
        (rule, lo, hi), 0,
    )
    return float(n or 0) / max(1.0, (60 - SPIKE_WINDOW_MIN) / SPIKE_WINDOW_MIN)


# --------------------------------------------------------------------------- 事件
def _has_open(rule: Optional[str], reason: str) -> bool:
    if rule is None:
        return bool(db.one("SELECT 1 AS x FROM rule_incidents WHERE rule IS NULL AND reason=? AND status='open'",
                           (reason,)))
    return bool(db.one("SELECT 1 AS x FROM rule_incidents WHERE rule=? AND reason=? AND status='open'",
                       (rule, reason)))


def _in_cooldown(rule: Optional[str], reason: str, now: int) -> bool:
    since = now - COOLDOWN_MIN * 60 * 1000
    if rule is None:
        last = int(db.scalar(
            "SELECT MAX(opened_at) FROM rule_incidents WHERE rule IS NULL AND reason=?",
            (reason,), 0) or 0)
    else:
        last = int(db.scalar(
            "SELECT MAX(opened_at) FROM rule_incidents WHERE rule=? AND reason=?",
            (rule, reason), 0) or 0)
    return last >= since


def open_incident(*, rule: Optional[str], scope: str, severity: str,
                  reason: str, detail: Dict[str, Any], actor: str = "system") -> int:
    return db.execute(
        """INSERT INTO rule_incidents
             (rule, scope, severity, status, reason, detail, opened_at, opened_by)
           VALUES(?,?,?, 'open', ?,?,?,?)""",
        (rule, scope, severity, reason,
         json.dumps(detail, ensure_ascii=False), db.now_ms(), actor),
    )


def scan_once(*, actor: str = "system:monitor") -> Dict[str, Any]:
    """扫一轮。返回 `{opened:[...], auto_broken:[...], errors:[...]}`。"""
    if not _lock.acquire(blocking=False):
        return {"skipped": "上一轮还在跑"}
    try:
        now = db.now_ms()
        since = now - WINDOW_MIN * 60 * 1000
        stats = _window_stats(since)
        intents = _intents()
        broken = {b["rule"] for b in rules_mod.breaker_rows()}
        opened: List[Dict[str, Any]] = []
        auto_broken: List[str] = []
        errors: List[str] = []

        for rid, st in stats.items():
            it = intents.get(rid)
            if not it:
                continue   # 规则已删除/不在现役：历史命中不产生新告警
            benign = st["benign"]
            labeled = st["labeled"]
            is_block = it["action"] == "block" and it["qualified"]
            detail = {
                "window_min": WINDOW_MIN,
                "hits": st["hits"],
                "block_hits": st["block_hits"],
                "confirmed_benign": benign,
                "confirmed_attack": st["attack"],
                "suspected_attack": st["suspected"],
                "labeled": labeled,
                "last_ts": st["last_ts"],
                "samples": _samples(rid, since),
                "kind": it["kind"],
                "rule_action": it["action"],
                "qualified": it["qualified"],
            }
            # 1) block 规则的确认误报：唯一允许**自动**动作的信号
            if (is_block and rid not in broken and benign >= BLOCK_MIN_BENIGN
                    and labeled and (benign / labeled) >= BLOCK_BENIGN_RATIO
                    and not _has_open(rid, "confirmed_fp")
                    and not _in_cooldown(rid, "confirmed_fp", now)):
                iid = open_incident(rule=rid, scope="rule", severity="high",
                                    reason="confirmed_fp", detail=detail, actor=actor)
                opened.append({"id": iid, "rule": rid, "reason": "confirmed_fp"})
                if AUTO_CONFIRMED_FP:
                    try:
                        breaker.apply_breaker(
                            scope="rule", rule=rid, reason="confirmed_fp",
                            actor=actor, incident_id=iid,
                            note=(f"自动熔断：{WINDOW_MIN} 分钟内确认良性 {benign} 条 / "
                                  f"已标 {labeled} 条"),
                        )
                        auto_broken.append(rid)
                    except Exception as e:  # noqa: BLE001
                        errors.append(f"{rid}: 自动熔断失败：{e}")
            # 2) alert / 测试规则的噪声：只提示，不自动动
            elif (not is_block and benign >= ALERT_NOISE_BENIGN
                  and not _has_open(rid, "noise")
                  and not _in_cooldown(rid, "noise", now)):
                iid = open_incident(rule=rid, scope="rule", severity="medium",
                                    reason="noise", detail=detail, actor=actor)
                opened.append({"id": iid, "rule": rid, "reason": "noise"})

        # 3) 命中量突增：可能真攻击，只提示（窗口单独按 5 分钟算）
        recent = _window_stats(now - SPIKE_WINDOW_MIN * 60 * 1000)
        for rid, st in recent.items():
            if st["hits"] < SPIKE_MIN_HITS:
                continue
            base = _spike_baseline(rid, now)
            if st["hits"] < SPIKE_FACTOR * max(1.0, base):
                continue
            if _has_open(rid, "hit_spike") or _in_cooldown(rid, "hit_spike", now):
                continue
            iid = open_incident(
                rule=rid, scope="rule", severity="medium", reason="hit_spike",
                detail={**{k: v for k, v in st.items() if k != "rule"},
                        "window_min": SPIKE_WINDOW_MIN, "baseline_per_window": base,
                        "samples": _samples(rid, now - SPIKE_WINDOW_MIN * 60 * 1000),
                        "note": "量突增不等于误报；先看样本再决定。"},
                actor=actor,
            )
            opened.append({"id": iid, "rule": rid, "reason": "hit_spike"})

        # 4) 全局阻断量突增
        blocks = int(db.scalar(
            "SELECT COUNT(*) AS n FROM events WHERE action='block' AND ts>=?",
            (now - SPIKE_WINDOW_MIN * 60 * 1000,), 0) or 0)
        if blocks >= BLOCK_SPIKE_MIN and not _has_open(None, "block_spike") \
                and not _in_cooldown(None, "block_spike", now):
            iid = open_incident(
                rule=None, scope="channel", severity="medium", reason="block_spike",
                detail={"window_min": SPIKE_WINDOW_MIN, "blocks": blocks,
                        "note": "阻断量突增可能是真攻击，也可能是误报；先看样本。"},
                actor=actor,
            )
            opened.append({"id": iid, "rule": None, "reason": "block_spike"})

        return {"opened": opened, "auto_broken": auto_broken, "errors": errors,
                "rules_with_hits": len(stats)}
    finally:
        _lock.release()


def start() -> None:
    """控制面启动时拉起后台线程（幂等）。"""
    global _started
    if _started:
        return
    _started = True

    def loop() -> None:
        # 给服务启动/迁移留一点时间，别在第一个请求前抢跑。
        time.sleep(3)
        while True:
            try:
                scan_once()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(max(10, SCAN_INTERVAL_SEC))

    threading.Thread(target=loop, daemon=True, name="rule-monitor").start()
