"""规则熔断：**产物级**降级，5 秒内热重载生效。

设计约束（用户拍板）：
  * 只降动作，**不停采集** —— 熔断后仍要留证据；
  * 三级：单规则（block→alert；alert 规则→从现役移除）/ 全部阻断（block→alert）
    / 规则通道（enabled=false）；
  * 自动动作只绑「人工确认的误报」；量突增只弹窗（真攻击也会让命中量涨）；
  * 中间态 fail-safe：规则集与策略 sha1 不一致时，数据面把规则证据权重当 0
    ⇒ 只会少拦，不会误拦；
  * **只 patch 产物，不重建**：熔断不会顺手把「刚启用、还没提升」的测试规则
    推进数据面（那是提升的职责），也不会改 `rules_custom.action` / `qualified_at`；
  * 恢复 = 把动作/规则还原到熔断前的快照（`prev_action` / `prev_rule_json`），
    不依赖 DB 当前意图；资格不会丢，也不会忘。

快路径刻意不重跑 `thresholds.py`：预算数字沿用旧值（只会更保守，总 FPR ≤ target），
后台可以再跑一次 `rule_promote` / `thresholds.py` 精确重标定。代价是熔断窗口内
`rules_testvec.json` 与策略短暂不一致 —— 门禁测试会红，重标定后恢复。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from . import config, db, rules as rules_mod

FUSION_2 = "supervised_block__zero_day_alert"
FUSION_3 = "supervised_block__zero_day_alert__rules_block"


def _read_policy() -> Dict[str, Any]:
    try:
        with open(config.POLICY_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json_atomic(path, doc: Dict[str, Any]) -> None:
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, str(path))


def _recounts(doc: Dict[str, Any]) -> Dict[str, Any]:
    rules = doc.get("rules") or []
    counts = dict(doc.get("counts") or {})
    counts["total"] = len(rules)
    counts["block"] = sum(1 for r in rules if r.get("action") == "block")
    counts["alert"] = len(rules) - counts["block"]
    counts["testing"] = sum(1 for r in rules
                            if (r.get("provenance") or {}).get("qualification") == "testing")
    counts["breaker"] = sum(1 for r in rules
                            if (r.get("provenance") or {}).get("action_forced") == "breaker")
    doc["counts"] = counts
    return doc


def _target_rule(doc: Dict[str, Any], rid: str) -> Optional[Dict[str, Any]]:
    return next((r for r in doc.get("rules") or [] if str(r.get("id")) == rid), None)


def _rule_exists(rid: str) -> bool:
    if db.one("SELECT 1 AS x FROM rules_custom WHERE id=?", (rid,)):
        return True
    return any(str(r.get("rule")) == rid for r in rules_mod.mined_rows())


def _rule_enabled(rid: str) -> bool:
    """数据面是否仍应包含这条规则（DB 当前意图）。"""
    row = db.one("SELECT enabled FROM rules_custom WHERE id=?", (rid,))
    if row:
        return bool(row.get("enabled"))
    st = db.one("SELECT enabled FROM rule_state WHERE rule=?", (rid,))
    if st:
        return bool(st.get("enabled"))
    raw = next((r for r in rules_mod.mined_rows() if str(r.get("rule")) == rid), None)
    return bool(raw and raw.get("verdict") == "keep")


def _add_one(rid: str, *, rule: Dict[str, Any], mode: str, reason: str,
             actor: str, incident_id: Optional[int], note: str) -> bool:
    now = db.now_ms()
    n = db.insert_ignore(
        "INSERT OR IGNORE INTO rule_breakers"
        "(rule, reason, actor, opened_at, incident_id, prev_action, mode, prev_rule_json, note) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (rid, reason, actor, now, incident_id,
         rule.get("action"), mode,
         json.dumps(rule, ensure_ascii=False) if mode == "disable" else None,
         note or None),
    )
    return bool(n)


def apply_breaker(*, scope: str, rule: Optional[str], reason: str, actor: str,
                  incident_id: Optional[int] = None, note: str = "",
                  auto: bool = False) -> Dict[str, Any]:
    """立即执行熔断（同步、毫秒级写文件；采集器下个轮询周期生效）。

    `scope=rule`：block 规则降为 alert；alert/测试规则从现役规则集移除（停用）。
    `scope=all_block`：所有 block 规则降为 alert。
    `scope=channel`：只把 `rules.enabled` 置 false（融合串同步改成两通道）。

    `auto=True` 只给误报监控用：**已验证规则一律拒绝**（降级必须由人拍板），
    且自动路径只会出现在未验证的 alert 规则上（block 规则必然已验证）。
    """
    scope = (scope or "").strip()
    if scope not in ("rule", "all_block", "channel"):
        raise ValueError("scope 只支持 rule / all_block / channel")
    if auto and scope != "rule":
        raise ValueError("自动熔断只支持 scope=rule")
    doc = rules_mod.load_authoritative()
    if not doc:
        raise ValueError("还没有现役规则集，无法熔断（先「提升到现役」）")
    doc = json.loads(json.dumps(doc))   # 深拷贝，失败时原文件不受影响
    pol = _read_policy()
    if not pol:
        raise ValueError("读不到 decision_policy.json，拒绝只写一半")
    channel_on = bool((pol.get("rules") or {}).get("enabled"))

    added: List[str] = []
    removed: List[str] = []
    if scope == "rule":
        if not rule:
            raise ValueError("scope=rule 必须指定 rule")
        r = _target_rule(doc, rule)
        if not r:
            raise ValueError(f"规则不在现役规则集里：{rule}（先提升，或它已被熔断移除）")
        if auto and rules_mod.is_verified(r):
            raise ValueError(
                f"规则 {rule} 已验证（qualified/proven）：自动熔断被拒绝，只告警等人处理")
        if r.get("action") == "block":
            if _add_one(rule, rule=r, mode="alert", reason=reason, actor=actor,
                        incident_id=incident_id, note=note):
                added.append(rule)
            r["action"] = "alert"
            r.setdefault("provenance", {})["action_requested"] = "block"
            r["provenance"]["action_forced"] = "breaker"
        else:
            # alert / 测试规则：熔断 = 从现役移除（停用），不会影响 DB 里的开关。
            if _add_one(rule, rule=r, mode="disable", reason=reason, actor=actor,
                        incident_id=incident_id, note=note):
                added.append(rule)
            doc["rules"] = [x for x in doc["rules"] if str(x.get("id")) != rule]
            removed.append(rule)
    elif scope == "all_block":
        targets = [r for r in doc["rules"] if r.get("action") == "block"]
        for r in targets:
            rid = str(r.get("id"))
            if _add_one(rid, rule=r, mode="alert", reason=reason, actor=actor,
                        incident_id=incident_id, note=note):
                added.append(rid)
            r["action"] = "alert"
            r.setdefault("provenance", {})["action_requested"] = "block"
            r["provenance"]["action_forced"] = "breaker"
    else:
        channel_on = False

    out = _commit(doc, channel_on=channel_on, actor=actor,
                  note=note or f"熔断 {scope}" + (f" {rule}" if rule else "")
                       + f"（{reason}）")
    out.update({"scope": scope, "rule": rule, "breakers_added": added,
                "removed_from_active": removed})
    out["note"] = ("已写规则集 + 策略（版本 +1）；采集器 5s 内热重载。"
                   "熔断窗口内 testvec 暂未刷新，后台重标定后恢复。")
    return out


def restore(*, rule: Optional[str] = None, all_breakers: bool = False,
            channel_on: bool = False, actor: str, note: str = "") -> Dict[str, Any]:
    """恢复：按熔断快照还原产物 + 删熔断行；可选打开规则通道。"""
    rows = rules_mod.breaker_rows()
    if all_breakers:
        rows = list(rows)
    elif rule:
        rows = [r for r in rows if r["rule"] == rule]
    else:
        rows = []

    doc = rules_mod.load_authoritative()
    if not doc:
        raise ValueError("还没有现役规则集，无法恢复")
    doc = json.loads(json.dumps(doc))
    pol = _read_policy()
    desired_channel = bool((pol.get("rules") or {}).get("enabled")) or bool(channel_on)
    if channel_on:
        desired_channel = True

    restored: List[str] = []
    skipped: List[str] = []
    for row in rows:
        rid = str(row["rule"])
        r = _target_rule(doc, rid)
        mode = row.get("mode") or "alert"
        if mode == "disable":
            if not _rule_exists(rid):
                skipped.append(rid)
                continue
            if not _rule_enabled(rid):
                # 熔断后用户又在控制面停用了它：恢复不能把停用意图翻掉。
                skipped.append(rid)
                continue
            if not r:
                try:
                    prev = json.loads(row.get("prev_rule_json") or "null")
                except Exception:
                    prev = None
                if isinstance(prev, dict):
                    prov = prev.setdefault("provenance", {})
                    prov.pop("action_forced", None)
                    prov.pop("breaker", None)
                    doc["rules"].append(prev)
                    restored.append(rid)
                else:
                    skipped.append(rid)
            else:
                # 已在现役（可能被重新提升过）：只把动作还原到快照，不覆盖新正则。
                try:
                    prev = json.loads(row.get("prev_rule_json") or "null")
                except Exception:
                    prev = None
                if isinstance(prev, dict) and prev.get("action") in ("alert", "block"):
                    r["action"] = prev["action"]
                    prov = r.setdefault("provenance", {})
                    prov.pop("action_forced", None)
                    prov.pop("breaker", None)
                restored.append(rid)
        else:
            if r:
                prev = row.get("prev_action") or "alert"
                r["action"] = prev if prev in ("alert", "block") else "alert"
                prov = r.setdefault("provenance", {})
                prov.pop("action_forced", None)
                restored.append(rid)
            else:
                skipped.append(rid)

    if all_breakers:
        db.execute("DELETE FROM rule_breakers")
    elif rule:
        db.execute("DELETE FROM rule_breakers WHERE rule=?", (rule,))

    out = _commit(doc, channel_on=desired_channel, actor=actor,
                  note=note or (f"恢复熔断 {rule or '全部'}"
                               + ("，并打开规则通道" if channel_on else "")))
    out.update({"restored": restored, "skipped": skipped, "channel_on": desired_channel})
    out["note"] = ("已按熔断前快照还原产物并删除熔断行。若刚恢复 block，建议先观察；"
                   "需要精确预算时再点一次「提升到现役」。")
    return out


def _commit(doc: Dict[str, Any], *, channel_on: bool, actor: str, note: str) -> Dict[str, Any]:
    """落盘规则集（含熔断覆盖）+ patch 策略的 rules/fusion 块。"""
    _recounts(doc)
    rules_mod.write_authoritative(doc)
    sha = rules_mod.authoritative_sha1_16()

    pol = _read_policy()
    if not pol:
        raise ValueError("读不到 decision_policy.json，拒绝只写一半（规则集已重建，策略未改）")
    old_ver = int(pol.get("version") or 0)
    pol = dict(pol)
    pol["version"] = old_ver + 1
    pol["generated_by"] = "console:breaker"
    pol["generated_at"] = db.now_ms()
    r = dict(pol.get("rules") or {})
    r.update({
        "enabled": bool(channel_on),
        "ruleset_sha1_16": sha,
        "n_rules": int(doc["counts"]["total"]),
        "n_block_rules": int(doc["counts"]["block"]),
        "note": (f"规则通道熔断/恢复（{note}）："
                 + ("通道开启，阻断规则按当前产物执行。" if channel_on
                    else "通道已关，规则命中不参与判定。")
                 + "预算数字沿用旧值（偏保守）；后台重标定后会精确扣减。"),
    })
    pol["rules"] = r
    fusion = dict(pol.get("fusion") or {})
    fusion["policy"] = FUSION_3 if channel_on else FUSION_2
    pol["fusion"] = fusion
    _write_json_atomic(config.POLICY_JSON, pol)

    db.execute(
        "INSERT OR REPLACE INTO policy_versions(version, json, actor, created_at, note) "
        "VALUES(?,?,?,?,?)",
        (pol["version"], json.dumps(pol, ensure_ascii=False), actor, db.now_ms(), note),
    )
    return {"policy_version": pol["version"], "ruleset_sha1_16": sha,
            "counts": doc["counts"], "rules_enabled": bool(channel_on)}


def state() -> Dict[str, Any]:
    doc = rules_mod.load_authoritative() or {}
    return {
        "breakers": rules_mod.breaker_rows(),
        "channel_enabled": bool((_read_policy().get("rules") or {}).get("enabled")),
        "n_block_rules": int((doc.get("counts") or {}).get("block") or 0),
    }
