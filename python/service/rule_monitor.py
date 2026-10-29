"""规则误报监控 + 自动熔断（后台线程，60s 一轮）。

原则（用户拍板）：
  * **已验证规则永不自动熔断**：block 规则 10 分钟内被人工标了 ≥5 条确认良性、
    且占比 ≥50% ⇒ **只开 confirmed_fp 告警**，降级/停用由人决定。
  * 自动熔断只作用于**未验证**规则（测试中 / 强行启用的 alert 规则）：噪声
    （≥20 条确认良性）且总开关开着 ⇒ 移出现役（`mode=disable`）+ 留 incident。
  * 总开关 `auto_breaker` 关闭 ⇒ 监控只告警、绝不改规则集。
  * `breaker_alerts` 关闭 ⇒ 不再生成 confirmed_fp / noise 事件；但即将发生的
    自动动作仍会留 incident（自动动作必须可追溯）。
  * **量突增只提示，且永远保留**：真攻击也会让命中量涨，按量自动熔断等于给
    攻击者一个关规则的后门；`hit_spike` / `block_spike` 不受任何开关影响。
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
    """扫一轮。返回 `{opened:[...], auto_broken:[...], errors:[...]}`。

    设置语义（`rules.monitor_settings()`，控制台可改、下一轮生效）：

      * `auto_breaker`：自动熔断总开关。**只对未验证规则生效**；已验证规则
        （qualified / proven）永远只告警（`auto_action=none`），降级必须由人点。
      * `breaker_alerts`：confirmed_fp / noise 事件开关。若未验证规则即将被自动
        静默，即使关了告警也会留 incident —— 自动动作必须可追溯。
      * `hit_spike` / `block_spike`：安全信号，**永远保留**，不受上面两个开关影响。
    """
    if not _lock.acquire(blocking=False):
        return {"skipped": "上一轮还在跑"}
    try:
        now = db.now_ms()
        since = now - WINDOW_MIN * 60 * 1000
        settings = rules_mod.monitor_settings()
        auto_breaker = bool(settings.get("auto_breaker"))
        breaker_alerts = bool(settings.get("breaker_alerts"))
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
            verified = bool(it["qualified"])
            is_block = it["action"] == "block" and verified
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
                "qualified": verified,
                "verified": verified,
            }
            fp_trigger = (is_block and rid not in broken and benign >= BLOCK_MIN_BENIGN
                          and labeled and (benign / labeled) >= BLOCK_BENIGN_RATIO
                          and not _has_open(rid, "confirmed_fp")
                          and not _in_cooldown(rid, "confirmed_fp", now))
            noise_trigger = (not is_block and benign >= ALERT_NOISE_BENIGN
                             and not _has_open(rid, "noise")
                             and not _in_cooldown(rid, "noise", now))
            if fp_trigger:
                # 能 block 的规则必然已验证 ⇒ 这里永远只告警，绝不自动降级。
                if not breaker_alerts:
                    continue
                iid = open_incident(
                    rule=rid, scope="rule", severity="high", reason="confirmed_fp",
                    detail={**detail, "auto_action": "none",
                            "note": "已验证规则不自动熔断；确认误报后请人工决定降级/停用。"},
                    actor=actor)
                opened.append({"id": iid, "rule": rid, "reason": "confirmed_fp",
                               "auto_action": "none"})
            elif noise_trigger:
                # 未验证规则才允许自动静默（移出现役）；已验证规则只告警。
                auto_action = "disable" if (auto_breaker and not verified) else "none"
                if auto_action == "none" and not breaker_alerts:
                    continue   # 关熔断 + 关告警：这条规则不留任何事件
                iid = open_incident(
                    rule=rid, scope="rule", severity="medium", reason="noise",
                    detail={**detail, "auto_action": auto_action},
                    actor=actor)
                opened.append({"id": iid, "rule": rid, "reason": "noise",
                               "auto_action": auto_action})
                if auto_action == "disable":
                    try:
                        breaker.apply_breaker(
                            scope="rule", rule=rid, reason="noise",
                            actor=actor, incident_id=iid,
                            note=(f"自动静默（未验证规则）：{WINDOW_MIN} 分钟内确认良性 "
                                  f"{benign} 条 / 已标 {labeled} 条"),
                            auto=True,
                        )
                        auto_broken.append(rid)
                    except Exception as e:  # noqa: BLE001
                        errors.append(f"{rid}: 自动熔断失败：{e}")

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
            it = intents.get(rid) or {}
            verified = bool(it.get("qualified"))
            iid = open_incident(
                rule=rid, scope="rule", severity="medium", reason="hit_spike",
                detail={**{k: v for k, v in st.items() if k != "rule"},
                        "window_min": SPIKE_WINDOW_MIN, "baseline_per_window": base,
                        "samples": _samples(rid, now - SPIKE_WINDOW_MIN * 60 * 1000),
                        "verified": verified,
                        "note": ("量突增不等于误报；已验证规则只告警、不熔断，"
                                 "先看样本再决定。") if verified else
                                ("量突增不等于误报；该规则未验证，先看样本再决定。")},
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
