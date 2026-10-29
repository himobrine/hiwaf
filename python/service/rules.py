"""规则通道的**存储与状态机**（挖出的候选 + 用户自撰）。

三层状态（用户拍板，v2 起「启用 ≠ 合格」）：
  草稿 draft    —— 建/改出来的样子，`enabled=0`，① 正则还没编译过；
  测试 testing  —— `enabled=1`，参与判定，但**强制 action=alert**：
                   ① 编译通过即可启用，不等 ②③；真实命中就是证据；
  合格 qualified—— 人工确认后写 `qualified_at`，才允许逐条翻 `block`。

关键语义：
  * **启用 ≠ 合格**：`enabled` 只说明"让它在数据面参与判定（只告警）"；
    合格是 `qualified_at`（人工确认），只有合格才能 `block`。
  * 合格判据按 `kind` 分：
      - `detector`：① 编译 + ② 真实良性 0 误报 + ③ 攻击回放 > 0，
        或在**真实流量**里出现 ≥1 条人工确认攻击且确认良性为 0；
      - `guard`   ：① 编译 + ② 真实良性 0 误报 + 管理员填写政策理由（不看 ③）。
  * **模型只是辅助**：监督/零日也报了的命中只算「疑似攻击」，只展示、不单独定罪；
    合格确认永远由人点按钮。
  * **编辑即作废验证**：改正则 / scope / kind 会清空 `validated_at` 与 `qualified_at`。
  * **熔断是产物级覆盖**：`rule_breakers` 里的规则在构建现役规则集时强制 alert，
    **不改** `rules_custom.action` / `qualified_at`；恢复 = 删行 + 重新提升。
  * **只有 `block` 规则消耗阻断预算**：alert / testing 规则不占 FPR 预算。
  * 命中证据写 `event_rules`，**绝不**回写 `events.attack_label`（标签只能来自溯源）。

判定/校验的**权威实现**在 Rust（`waf-ai-proto rules check|replay`，见 R3/R2）；
本模块只编排 + 统计，不自己实现匹配。
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from . import config, db, rules_dsl

DEFAULT_MIN_WEIGHT_TO_BLOCK = 1.0

#: 合格判据里"在线确认攻击"的最小条数（人工确认的才算）。
MIN_ONLINE_CONFIRMED_ATTACKS = 1

#: 挖出的候选规则没有 severity 字段，按规则名前缀给一个展示用等级
#: （**只影响展示**，不参与记分；记分只认 `weight`）。
_SEVERITY_BY_PREFIX = (
    ("sqli_", "critical"),
    ("rce_", "critical"),
    ("cmd_", "critical"),
    ("php_", "critical"),
    ("log4shell_", "critical"),
    ("xss_", "high"),
    ("path_", "high"),
    ("ssrf_", "high"),
    ("sql_", "medium"),
)


def _severity_of(rule_id: str) -> str:
    for pref, sev in _SEVERITY_BY_PREFIX:
        if rule_id.startswith(pref):
            return sev
    return "medium"


# --------------------------------------------------------------------------- 读
def mined_doc() -> Dict[str, Any]:
    try:
        with open(config.RULE_CANDIDATES, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def mined_rows() -> List[Dict[str, Any]]:
    return list(mined_doc().get("rules") or [])


def _state_map() -> Dict[str, Dict[str, Any]]:
    return {
        r["rule"]: r
        for r in db.rows("SELECT rule, enabled, action, actor, updated_at FROM rule_state")
    }


def breaker_rows() -> List[Dict[str, Any]]:
    return db.rows("SELECT * FROM rule_breakers ORDER BY opened_at DESC")


def breaker_map() -> Dict[str, Dict[str, Any]]:
    return {r["rule"]: r for r in breaker_rows()}


# --------------------------------------------------------------------------- 监控设置
def monitor_settings() -> Dict[str, Any]:
    """误报扫描 / 自动熔断设置（`app_settings.rules.*` 覆盖默认值）。

    `auto_breaker=False` 时监控只告警、绝不改规则集；`breaker_alerts=False` 时
    不再生成 confirmed_fp / noise 事件（突增类告警不受影响）。
    """
    out: Dict[str, Any] = dict(config.RULE_MONITOR_DEFAULTS)
    for r in db.rows("SELECT key, value FROM app_settings WHERE key LIKE 'rules.%'"):
        k = r["key"].split(".", 1)[1] if "." in r["key"] else r["key"]
        if k not in out:
            continue
        try:
            out[k] = bool(json.loads(r["value"]))
        except (TypeError, ValueError):
            pass
    return out


def update_monitor_settings(patch: Dict[str, Any], actor: str) -> Dict[str, Any]:
    clean: Dict[str, bool] = {}
    unknown = sorted(set(patch) - set(config.RULE_MONITOR_DEFAULTS))
    if unknown:
        raise ValueError(f"未知设置：{unknown}")
    for k in config.RULE_MONITOR_DEFAULTS:
        if k in patch:
            clean[k] = bool(patch[k])
    if not clean:
        raise ValueError("没有要更新的设置")
    for k, v in clean.items():
        db.execute(
            "INSERT OR REPLACE INTO app_settings(key, value, updated_at, actor) "
            "VALUES(?,?,?,?)",
            (f"rules.{k}", json.dumps(v), db.now_ms(), actor))
    return monitor_settings()


def is_verified(row: Dict[str, Any]) -> bool:
    """规则是否「已验证」：自撰规则人工确认合格，或挖出候选有真实攻击证据。

    自动熔断对已验证规则一律拒绝（只告警）；手动熔断仍由人决定。
    """
    if not row:
        return False
    if row.get("qualified_at"):
        return True
    prov = row.get("provenance") or {}
    return prov.get("qualification") in ("proven", "qualified")


# --------------------------------------------------------------------------- 在线证据
def online_stats(days: int = 7,
                 rule_ids: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """按规则统计真实命中，并按**来源**分桶。

    桶的优先级（一个事件只有一个结论）：
      * `confirmed_attack` —— 人工标了 attack/missed；
      * `confirmed_benign` —— 人工标了 benign/false_positive；
      * `suspected_attack` —— 没有人工标签，但监督/零日也报了（**模型辅助，只提示**）；
      * `unlabeled`        —— 其余。
    "模型说良性"**不**计入良性证据：规则和监督是并列通道，模型漏掉的正是规则该抓的。
    """
    since = db.now_ms() - max(1, int(days)) * 86400 * 1000
    where = ["e.ts >= ?", "(rc.id IS NULL OR rc.enabled_at IS NULL OR e.ts >= rc.enabled_at)"]
    params: List[Any] = [since]
    if rule_ids:
        where.append("er.rule IN (%s)" % ",".join("?" * len(rule_ids)))
        params.extend(rule_ids)
    sql = f"""
        WITH hit_events AS (
            SELECT er.rule AS rule,
                   er.event_id AS event_id,
                   MAX(e.ts) AS ts,
                   MAX(CASE WHEN e.action='block' THEN 1 ELSE 0 END) AS block_hit
              FROM event_rules er
              JOIN events e ON e.id = er.event_id
              LEFT JOIN rules_custom rc ON rc.id = er.rule
             WHERE {' AND '.join(where)}
             GROUP BY er.rule, er.event_id
        )
        SELECT h.rule AS rule,
               COUNT(*) AS hits,
               COALESCE(SUM(h.block_hit), 0) AS block_hits,
               COALESCE(SUM(CASE WHEN fb.verdict IN ('confirmed_attack','missed') THEN 1 ELSE 0 END), 0) AS confirmed_attack,
               COALESCE(SUM(CASE WHEN fb.verdict IN ('confirmed_benign','false_positive') THEN 1 ELSE 0 END), 0) AS confirmed_benign,
               COALESCE(SUM(CASE WHEN fb.verdict IS NULL
                                  AND (e.supervised_flagged=1 OR e.zero_day_flagged=1)
                                 THEN 1 ELSE 0 END), 0) AS suspected_attack,
               COALESCE(SUM(CASE WHEN fb.verdict IS NULL THEN 1 ELSE 0 END), 0) AS unlabeled,
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
    for r in db.rows(sql, tuple(params)):
        d = dict(r)
        for k in ("hits", "block_hits", "confirmed_attack", "confirmed_benign",
                  "suspected_attack", "unlabeled"):
            d[k] = int(d.get(k) or 0)
        out[str(d["rule"])] = d
    return out


def _def_online(rule_id: str) -> Dict[str, Any]:
    return {"rule": rule_id, "hits": 0, "block_hits": 0, "confirmed_attack": 0,
            "confirmed_benign": 0, "suspected_attack": 0, "unlabeled": 0,
            "last_ts": None}


# --------------------------------------------------------------------------- 自撰规则视图
def _gates(row: Dict[str, Any]) -> Dict[str, Any]:
    v = row.get("validation") or {}
    if isinstance(v, str):
        try:
            v = json.loads(v or "null") or {}
        except Exception:
            v = {}
    return v.get("gates") or {}


def custom_view(row: Dict[str, Any],
                online: Optional[Dict[str, Any]] = None,
                breaker: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """把一行 `rules_custom` 翻译成 UI/判定都能用的状态。

    返回的 `state` 是派生状态，不落库：
      `uncompiled` 未编译 / `noisy` 良性池有误报（可测试，不能合格）/
      `ready` 已编译、未启用 / `testing` 测试中（已启用、只告警）/
      `suggest` 证据已够待人工确认 / `qualified` 已合格（可翻 block）。
    """
    kind = str(row.get("kind") or "detector").lower()
    if kind not in rules_dsl.KINDS:
        kind = "detector"
    g = _gates(row)
    g1 = g.get("regex_safety") or {}
    g2 = g.get("benign_replay") or {}
    g3 = g.get("attack_replay") or {}

    compiled = bool(row.get("compiled_at") or row.get("validated_at") or g1.get("passed"))
    benign_ok = bool(g2.get("passed")) if g2 else None
    attack_ok = bool(g3.get("passed")) if g3 else None
    online = online or _def_online(str(row.get("id") or ""))
    on_attack = int(online.get("confirmed_attack") or 0)
    on_benign = int(online.get("confirmed_benign") or 0)
    on_hits = int(online.get("hits") or 0)

    attack_required = kind != "guard"
    offline_ok = bool(compiled and benign_ok is True and (attack_ok is True or not attack_required))
    online_ok = bool(on_hits > 0 and on_attack >= MIN_ONLINE_CONFIRMED_ATTACKS and on_benign == 0)
    qualified = bool(row.get("qualified_at"))
    breaker_hit = bool(breaker)

    if not compiled:
        state = "uncompiled"
    elif benign_ok is False:
        state = "noisy"
    elif qualified:
        state = "qualified"
    elif offline_ok or online_ok:
        state = "suggest"
    elif not row.get("enabled"):
        state = "ready"
    else:
        state = "testing"

    if not compiled:
        blockers = ["先过 ① 正则编译（Rust regex 权威）"]
    elif benign_ok is False:
        blockers = [f"真实良性池有 {int(g2.get('benign_hits') or 0)} 次误报，不能合格"]
    elif kind == "guard" and benign_ok is not True:
        blockers = ["防御型规则仍需先过 ② 真实良性零误报"]
    elif kind == "guard" and not qualified:
        blockers = ["良性 0 误报已满足；等管理员填写政策理由并确认合格"]
    elif attack_required and not offline_ok and not online_ok:
        blockers = ["池里没有这类攻击样本；等真实流量出现 ≥1 条人工确认攻击，"
                    "且确认良性为 0"]
    elif state == "suggest":
        blockers = ["证据已够；等管理员点「确认合格」"]
    else:
        blockers = []

    return {
        "state": state,
        "kind": kind,
        "compiled": compiled,
        "benign_ok": benign_ok,
        "attack_ok": attack_ok,
        "attack_required": attack_required,
        "offline_ok": offline_ok,
        "online_ok": online_ok,
        "suggest_qualified": bool(offline_ok or online_ok) and not qualified,
        "is_qualified": qualified,
        "can_enable": compiled,
        "can_block": bool(qualified and not breaker_hit and benign_ok is not False),
        "action_locked": bool(not qualified or breaker_hit),
        "breaker": breaker,
        "blockers": blockers,
        "online": online,
    }


def custom_rows() -> List[Dict[str, Any]]:
    out = []
    for r in db.rows("SELECT * FROM rules_custom ORDER BY created_at DESC"):
        r = dict(r)
        try:
            r["scopes"] = json.loads(r.get("scopes") or "[]")
        except Exception:
            r["scopes"] = ["full"]
        try:
            r["validation"] = json.loads(r.get("validation") or "null")
        except Exception:
            r["validation"] = None
        r["enabled"] = bool(r.get("enabled"))
        r["source"] = r.get("source") or "manual"
        r["kind"] = r.get("kind") or "detector"
        out.append(r)
    return out


def mined_merged(online: Optional[Dict[str, Dict[str, Any]]] = None,
                 breakers: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """挖出的候选 + 控制台状态。"""
    state = _state_map()
    online = online or {}
    breakers = breakers or {}
    out = []
    for r in mined_rows():
        rid = r.get("rule")
        st = state.get(rid)
        verdict = r.get("verdict")
        proven = verdict == "keep"
        stored_action = (st or {}).get("action")
        br = breakers.get(rid)
        out.append({
            **r,
            "id": rid,
            "name": r.get("rule"),
            "source": "mined",
            "kind": "detector",
            "severity": _severity_of(str(rid)),
            "weight": float(r.get("weight") or 1.0),
            "scopes": ["full"],          # p7 锚点只在 full 下可复现
            "action": "alert" if (not proven or br) else (stored_action or "alert"),
            "action_requested": stored_action or "alert",
            "action_locked": bool(not proven or br),
            "enabled": bool(st["enabled"]) if st else proven,
            "evidence_grade": verdict,
            "qualified": "proven" if proven else "user_override",
            "overridden": bool(st["enabled"]) and not proven if st else False,
            "state_actor": (st or {}).get("actor"),
            "state_updated_at": (st or {}).get("updated_at"),
            "online": online.get(str(rid)) or _def_online(str(rid)),
            "breaker": br,
        })
    return out


def merged(with_online: bool = True) -> Dict[str, Any]:
    doc = mined_doc()
    online = online_stats(7) if with_online else {}
    breakers = breaker_map()
    mined = mined_merged(online=online, breakers=breakers)
    custom = []
    for r in custom_rows():
        v = custom_view(r, online.get(str(r["id"])), breakers.get(str(r["id"])))
        custom.append({**r, **v})

    counts: Dict[str, int] = {}
    for r in mined:
        counts[r.get("verdict")] = counts.get(r.get("verdict"), 0) + 1
    n_enabled = sum(1 for r in mined if r.get("enabled"))
    n_override = sum(1 for r in mined if r.get("overridden"))
    n_proven = sum(1 for r in mined if r.get("verdict") == "keep")

    custom_state = {
        "n_total": len(custom),
        "n_enabled": sum(1 for r in custom if r.get("enabled")),
        "n_qualified": sum(1 for r in custom if r.get("is_qualified")),
        "n_testing": sum(1 for r in custom if r.get("enabled") and not r.get("is_qualified")),
        "n_ready": sum(1 for r in custom if r.get("state") == "ready"),
        "n_noisy": sum(1 for r in custom if r.get("state") == "noisy"),
        "n_uncompiled": sum(1 for r in custom if r.get("state") == "uncompiled"),
        "n_suggest": sum(1 for r in custom if r.get("suggest_qualified")),
        "n_block": sum(1 for r in custom if r.get("action") == "block"),
        "n_blocked_by_breaker": sum(1 for r in custom if r.get("breaker")),
        "by_kind": {
            "detector": sum(1 for r in custom if r.get("kind") == "detector"),
            "guard": sum(1 for r in custom if r.get("kind") == "guard"),
        },
    }
    return {
        "eval": doc.get("eval"),
        "summary": doc.get("summary"),
        "counts": counts,
        "enabled": {
            "n_total": len(mined),
            "n_enabled": n_enabled,
            "n_proven": n_proven,
            "n_user_override": n_override,
            "n_disabled": len(mined) - n_enabled,
        },
        "custom_state": custom_state,
        "rules": mined,
        "custom": custom,
        "authoritative": authoritative_info(),
        "breakers": breaker_rows(),
        "monitor": monitor_settings(),
        "decode": rules_dsl.DEFAULT_DECODE,
        "scopes": list(rules_dsl.SCOPES),
        "actions": list(rules_dsl.ACTIONS),
        "severities": list(rules_dsl.SEVERITIES),
        "kinds": list(rules_dsl.KINDS),
        "notes": {
            "enable_semantics": "「启用」= 让它参与判定（只告警）；「合格」= 人工确认后写 qualified_at，才允许 block。",
            "testing": "测试中的规则命中会真的产生 alert（rule_testing 标记），方便用真实流量判断。",
            "evidence_grade": "开关不改变证据等级；verdict / validation 如实记录实测结果。",
            "override_lock": "未合格一律锁死 action=alert；只有合格（或 guard 政策声明）才能翻 block。",
            "kind": "detector 需要攻击证据；guard 是防御型入口规则，合格看「良性 0 误报 + 政策理由」。",
            "online_labels": "在线证据只认人工标签；模型也报了的只算「疑似」，不单独定罪。",
            "promote": "现役规则集由「提升」写入 artifacts/rules_authoritative.json，数据面只读它。",
            "budget": "只有 action=block 的规则消耗阻断预算（目标 FPR 会相应收紧）。",
            "new_rule_default": "新规则默认 action=alert；观察真实命中后再人工确认合格、逐条翻 block。",
        },
    }


# --------------------------------------------------------------------------- 写：自撰规则
def create_custom(payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
    raw_id = str(payload.get("id") or "").strip().lower()
    if raw_id and not raw_id.startswith("custom_"):
        raw_id = "custom_" + raw_id
    if not raw_id:
        raw_id = "custom_" + str(int(time.time()))
    rule = rules_dsl.clean({**payload, "id": raw_id})
    # 新规则一律先 alert：没有经过在线证据 + 人工确认，不允许直接把 DB 意图写成 block。
    rule["action"] = "alert"
    errs = rules_dsl.check_spec(rule, custom_id=True)
    if errs:
        raise ValueError("；".join(errs))
    if db.one("SELECT 1 AS x FROM rules_custom WHERE id=?", (rule["id"],)):
        raise ValueError(f"规则 id 已存在：{rule['id']}（自定义规则必须唯一，改名后再存）")
    if len(custom_rows()) >= rules_dsl.MAX_RULES:
        raise ValueError(f"自定义规则数量已达上限 {rules_dsl.MAX_RULES}")
    now = db.now_ms()
    db.execute(
        """INSERT INTO rules_custom
             (id, name, regex, scopes, severity, weight, action, kind, enabled, notes, source,
              validated_at, validation, compiled_at, enabled_at, qualified_at,
              created_at, updated_at, actor)
           VALUES (?,?,?,?,?,?,?,?,0,?,?,NULL,NULL,NULL,NULL,NULL,?,?,?)""",
        (rule["id"], rule["name"], rule["regex"], json.dumps(rule["scopes"]),
         rule["severity"], rule["weight"], rule["action"], rule["kind"], rule["notes"], "manual",
         now, now, actor),
    )
    return {"rule": _get_custom(rule["id"]),
            "warnings": rules_dsl.warn_spec(rule),
            "note": "已存为草稿。启用前会先跑 ① 正则编译；启用后只告警，"
                    "合格要人工确认（可先在真实流量里观察命中）。"}


def update_custom(rid: str, payload: Dict[str, Any], actor: str) -> Dict[str, Any]:
    cur = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not cur:
        raise ValueError(f"规则不存在：{rid}")
    cur_scopes = cur["scopes"]
    if isinstance(cur_scopes, str):
        try:
            cur_scopes = json.loads(cur_scopes or "[]") or ["full"]
        except Exception:
            cur_scopes = ["full"]
    merged_in = {
        "id": rid,
        "name": payload.get("name", cur["name"]),
        "regex": payload.get("regex", cur["regex"]),
        "scopes": payload.get("scopes", cur_scopes),
        "severity": payload.get("severity", cur["severity"]),
        "weight": payload.get("weight", cur["weight"]),
        "action": payload.get("action", cur["action"]),
        "kind": payload.get("kind", cur["kind"] or "detector"),
        "notes": payload.get("notes", cur["notes"]),
    }
    rule = rules_dsl.clean(merged_in)
    # 编辑会作废合格，动作也必须回到 alert；要 block 只能重新确认合格后再逐条翻。
    rule["action"] = "alert"
    errs = rules_dsl.check_spec(rule, custom_id=True)
    if errs:
        raise ValueError("；".join(errs))
    now = db.now_ms()
    # 编辑即作废验证：`validated_at` / `validation` / `compiled_at` / `qualified_at` 一律清空。
    db.execute(
        """UPDATE rules_custom
              SET name=?, regex=?, scopes=?, severity=?, weight=?, action=?, kind=?, notes=?,
                  enabled=0, validated_at=NULL, validation=NULL, compiled_at=NULL,
                  enabled_at=NULL, qualified_at=NULL, qualified_by=NULL,
                  qualification_source=NULL, qualification_note=NULL,
                  updated_at=?, actor=?
            WHERE id=?""",
        (rule["name"], rule["regex"], json.dumps(rule["scopes"]), rule["severity"],
         rule["weight"], rule["action"], rule["kind"], rule["notes"], now, actor, rid),
    )
    return {"rule": _get_custom(rid),
            "warnings": rules_dsl.warn_spec(rule),
            "note": "已保存；因为内容变了，上一轮的验证/合格结论作废（enabled 已复位为草稿）。"}


def delete_custom(rid: str) -> None:
    if not db.one("SELECT 1 AS x FROM rules_custom WHERE id=?", (rid,)):
        raise ValueError(f"规则不存在：{rid}")
    db.execute("DELETE FROM rules_custom WHERE id=?", (rid,))


def _get_mined(rid: str) -> Optional[Dict[str, Any]]:
    for r in mined_merged(online={}, breakers=breaker_map()):
        if str(r.get("id")) == rid:
            return r
    return None


def set_mined_state(rid: str, *, enabled: Optional[bool] = None,
                    action: Optional[str] = None, actor: str = "") -> Dict[str, Any]:
    """设置挖出候选的启用/动作状态。

    候选没有 `rules_custom` 行，状态统一写 `rule_state`。挖出的规则只有
    `verdict=keep` 才有攻击证据，才允许 `block`；没有证据的规则强制 alert。
    """
    candidate = next((r for r in mined_rows() if str(r.get("rule")) == rid), None)
    if not candidate:
        raise ValueError(f"规则不存在：{rid}")
    verdict = candidate.get("verdict")
    proven = verdict == "keep"
    br = breaker_map().get(rid)
    st = db.one("SELECT * FROM rule_state WHERE rule=?", (rid,))
    current_action = (st or {}).get("action") or "alert"
    new_action = action if action is not None else current_action
    if new_action not in rules_dsl.ACTIONS:
        raise ValueError(f"action 非法：{new_action}")
    if new_action == "block":
        if not proven:
            raise ValueError("这条没有攻击证据（verdict != keep），只能 alert")
        if br:
            raise ValueError(f"该规则已被熔断（{br.get('reason')}）：先恢复，再重新确认是否值得阻断。")
    if not proven or br:
        new_action = "alert"

    new_enabled = bool(st["enabled"]) if st else proven
    if enabled is not None:
        new_enabled = bool(enabled)
    db.execute(
        """INSERT OR REPLACE INTO rule_state(rule, enabled, updated_at, actor, action)
           VALUES(?,?,?,?,?)""",
        (rid, 1 if new_enabled else 0, db.now_ms(), actor, new_action),
    )
    return {"rule": _get_mined(rid), "enabled": new_enabled, "action": new_action}


def bulk_set_mined_state(*, enabled: bool, actor: str,
                         only_unproven: bool = False) -> Dict[str, Any]:
    """批量启用/停用挖出的候选（兼容旧的“全部启用”入口）。"""
    rows = mined_merged(online={}, breakers=breaker_map())
    if only_unproven:
        rows = [r for r in rows if r.get("verdict") != "keep"]
    out = bulk_apply_rules(
        scope="mined", ids=[str(r["id"]) for r in rows],
        op="enable" if enabled else "disable", actor=actor,
    )
    out.update({"enabled": bool(enabled), "only_unproven": bool(only_unproven)})
    return out


def bulk_apply_rules(*, scope: str, ids: List[str], op: str,
                     action: Optional[str] = None, actor: str = "") -> Dict[str, Any]:
    """按 ID 批量处理规则。

    逐条执行并返回部分成功结果；任何一条失败都不会回滚其他规则。`scope`
    只允许 mined/custom，`op` 只允许 enable/disable/set_action/delete。
    """
    if scope not in ("mined", "custom"):
        raise ValueError("scope 只支持 mined / custom")
    if op not in ("enable", "disable", "set_action", "delete"):
        raise ValueError("op 只支持 enable / disable / set_action / delete")
    if op == "set_action" and action not in rules_dsl.ACTIONS:
        raise ValueError(f"action 非法：{action}")
    if op == "delete" and scope != "custom":
        raise ValueError("挖出的候选不支持删除")

    seen = set()
    clean_ids: List[str] = []
    for rid in ids or []:
        rid = str(rid)
        if rid and rid not in seen:
            seen.add(rid)
            clean_ids.append(rid)
    if not clean_ids:
        raise ValueError("至少选择一条规则")

    errors: List[Dict[str, str]] = []
    if scope == "custom" and op == "enable":
        need = []
        for rid in clean_ids:
            row = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
            if row and not (row.get("compiled_at") or row.get("validated_at")):
                need.append(rid)
        if need:
            from . import rule_validate
            _good, bad = rule_validate.compile_many(need)
            errors.extend(bad)

    changed: List[str] = []
    skipped: List[str] = []
    failed_ids = {e["rule"] for e in errors}
    for rid in clean_ids:
        if rid in failed_ids:
            skipped.append(rid)
            continue
        try:
            if scope == "mined":
                enabled = True if op == "enable" else False if op == "disable" else None
                set_mined_state(rid, enabled=enabled,
                                action=action if op == "set_action" else None,
                                actor=actor)
            else:
                if op == "delete":
                    delete_custom(rid)
                else:
                    enabled = True if op == "enable" else False if op == "disable" else None
                    set_custom_state(rid, enabled=enabled,
                                     action=action if op == "set_action" else None,
                                     actor=actor)
            changed.append(rid)
        except ValueError as e:
            errors.append({"rule": rid, "error": str(e)})
    return {
        "ok": True,
        "scope": scope,
        "op": op,
        "action": action,
        "n_changed": len(changed),
        "changed": changed,
        "skipped": skipped,
        "errors": errors,
        "note": "只改控制面状态；要在数据面生效必须重新「提升到现役」。",
    }


def _get_custom(rid: str) -> Optional[Dict[str, Any]]:
    for r in custom_rows():
        if r["id"] == rid:
            on = online_stats(7, [rid]).get(rid) or _def_online(rid)
            return {**r, **custom_view(r, on, breaker_map().get(rid))}
    return None


def set_custom_kind(rid: str, kind: str, actor: str) -> Dict[str, Any]:
    if kind not in rules_dsl.KINDS:
        raise ValueError(f"kind 只支持 {list(rules_dsl.KINDS)}")
    cur = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not cur:
        raise ValueError(f"规则不存在：{rid}")
    if (cur.get("kind") or "detector") == kind:
        return {"rule": _get_custom(rid)}
    # kind 改变会改变合格判据 ⇒ 人工确认作废，回到「测试中」。
    db.execute(
        """UPDATE rules_custom
              SET kind=?, qualified_at=NULL, qualified_by=NULL,
                  qualification_source=NULL, qualification_note=NULL,
                  updated_at=?, actor=?
            WHERE id=?""",
        (kind, db.now_ms(), actor, rid),
    )
    return {"rule": _get_custom(rid),
            "note": "kind 已改；合格判据随之改变，需要重新人工确认。"}


def set_custom_state(rid: str, *, enabled: Optional[bool] = None,
                     action: Optional[str] = None, actor: str = "") -> Dict[str, Any]:
    cur = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not cur:
        raise ValueError(f"规则不存在：{rid}")
    if action is not None and action not in rules_dsl.ACTIONS:
        raise ValueError(f"action 非法：{action}")
    if action is None:
        new_action = cur["action"] or "alert"
    else:
        new_action = action

    br = breaker_map().get(rid)
    if new_action == "block":
        if not cur["qualified_at"]:
            raise ValueError(
                "这条规则还没人工确认合格，只能 alert。启用后先用真实流量观察："
                "命中样本里出现「人工确认攻击」且没有确认良性，再点「确认合格」。"
            )
        g2 = _gates(dict(cur)).get("benign_replay") or {}
        if g2.get("passed") is False:
            raise ValueError(
                "真实良性池上有实测误报：这条规则不能 block。先修正则、重新校验；"
                "没有任何“强制”路径可以绕过 ② 真实良性零误报。"
            )
        if br:
            raise ValueError(f"该规则已被熔断（{br.get('reason')}）：先恢复，再重新确认是否值得阻断。")

    new_enabled = cur["enabled"]
    enabled_at = cur["enabled_at"]
    warnings: List[str] = []
    if enabled is not None:
        if enabled:
            # ① 编译通过即可启用；②③ 不再挡启用（启用 ≠ 合格）。
            if not (cur["compiled_at"] or cur["validated_at"]):
                from . import rule_validate
                out = rule_validate.compile_custom(rid)
                if not out.get("passed"):
                    raise ValueError("① 正则编译失败（Rust regex 权威）："
                                     + (out.get("error") or "未知错误"))
                cur = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
            if not cur["enabled"]:
                enabled_at = db.now_ms()
            new_enabled = 1
            g = _gates(dict(cur))
            g2 = g.get("benign_replay") or {}
            if g2.get("passed") is False:
                warnings.append(
                    f"该规则在真实良性池上已有 {int(g2.get('benign_hits') or 0)} 次误报："
                    "启用后会真的产生 alert 噪声；它不能合格、也永远不能 block，除非先修好再校验。"
                )
            if not cur["qualified_at"]:
                warnings.append("启用后先观察真实命中；合格要人工确认，确认前只 alert。")
        else:
            new_enabled = 0
    if new_action == "block" and not cur["qualified_at"]:
        new_action = "alert"      # 双保险：任何路径都不允许未合格规则阻断

    db.execute(
        """UPDATE rules_custom
              SET enabled=?, action=?, enabled_at=?, updated_at=?, actor=?
            WHERE id=?""",
        (new_enabled, new_action, enabled_at, db.now_ms(), actor, rid),
    )
    return {"rule": _get_custom(rid), "warnings": warnings}


def set_custom_qualified(rid: str, *, actor: str, note: str = "",
                         source: str = "manual", force: bool = False) -> Dict[str, Any]:
    """人工确认合格。

    非 `force` 时必须满足判据（detector：池内③ 或 在线确认攻击；guard：② + 政策理由）。
    `force=True` 只允许 admin 在 UI 显式二次确认后调用，并把 `source='admin_override'` 记进审计。
    """
    cur = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not cur:
        raise ValueError(f"规则不存在：{rid}")
    row = {**dict(cur), "validation": _parse_json(cur.get("validation"))}
    on = online_stats(7, [rid]).get(rid) or _def_online(rid)
    view = custom_view(row, on, breaker_map().get(rid))
    if not view["compiled"]:
        raise ValueError("还没过 ① 正则编译：先点「校验」或直接打开启用开关")
    if view["benign_ok"] is False:
        raise ValueError("真实良性池上有实测误报：不能合格。先修正则、重新校验；"
                         "任何“强制确认”都不能绕过 ② 真实良性零误报。")
    if not force:
        if view["kind"] == "guard":
            if not view["benign_ok"]:
                raise ValueError("防御型规则要合格，必须先过 ② 真实良性回放且零误报")
            if not (note or cur.get("notes") or "").strip():
                raise ValueError("防御型规则必须填写政策理由（为什么这个入口必须拒绝）")
        elif not (view["offline_ok"] or view["online_ok"]):
            raise ValueError("证据还不够：池内 ③ 无样本时，需要真实流量里 ≥1 条人工确认攻击，"
                             "且确认良性为 0")
    if force and source == "manual":
        source = "admin_override"
    db.execute(
        """UPDATE rules_custom
              SET qualified_at=?, qualified_by=?, qualification_source=?, qualification_note=?,
                  updated_at=?, actor=?
            WHERE id=?""",
        (db.now_ms(), actor, source, (note or "").strip() or None, db.now_ms(), actor, rid),
    )
    return {"rule": _get_custom(rid)}


def unqualify_custom(rid: str, *, actor: str, note: str = "") -> Dict[str, Any]:
    cur = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not cur:
        raise ValueError(f"规则不存在：{rid}")
    db.execute(
        """UPDATE rules_custom
              SET qualified_at=NULL, qualified_by=NULL, qualification_source=NULL,
                  qualification_note=?, action='alert', updated_at=?, actor=?
            WHERE id=?""",
        (note or "人工撤销合格", db.now_ms(), actor, rid),
    )
    return {"rule": _get_custom(rid),
            "note": "已撤销合格并强制回 alert；要重新阻断需重新确认。"}


def bulk_set_custom_state(*, enabled: bool, actor: str,
                          only_uncompiled: bool = False) -> Dict[str, Any]:
    """批量启用/停用自撰规则。

    启用只要求 ① 编译；为了让 35 条一次点完，先做一次**批量** Rust 编译，
    失败的再逐条定位原因。不改变合格状态、也不改 action。
    """
    rows = custom_rows()
    if only_uncompiled:
        rows = [r for r in rows if not (r.get("compiled_at") or r.get("validated_at"))]
    errors: List[Dict[str, str]] = []
    if enabled:
        need = [r["id"] for r in rows if not (r.get("compiled_at") or r.get("validated_at"))]
        if need:
            from . import rule_validate
            ok, bad = rule_validate.compile_many(need)
            errors.extend(bad)
    changed: List[str] = []
    for r in rows:
        if bool(r.get("enabled")) == enabled:
            continue
        if any(e["rule"] == r["id"] for e in errors):
            continue
        try:
            set_custom_state(r["id"], enabled=enabled, actor=actor)
            changed.append(r["id"])
        except ValueError as e:
            errors.append({"rule": r["id"], "error": str(e)})
    return {"ok": True, "enabled": bool(enabled), "n_changed": len(changed),
            "changed": changed, "errors": errors,
            "note": "只改控制面状态；要在数据面生效必须重新「提升到现役」。"}


def _parse_json(raw: Any) -> Any:
    if raw is None or isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


# --------------------------------------------------------------------------- 现役规则集
def build_authoritative(*, decode: Optional[List[str]] = None,
                        min_weight_to_block: Optional[float] = None,
                        ruleset_id: Optional[str] = None) -> Dict[str, Any]:
    """把「启用」的规则拼成现役规则集（**只返回 dict，不落盘**）。

    未合格的自撰规则会被强制成 `action=alert`（`action_forced='alert'`）；
    被熔断的规则同样强制 alert（`action_forced='breaker'`）。这两条都在产物里留痕。
    """
    decode = [d for d in (decode or rules_dsl.DEFAULT_DECODE) if d in rules_dsl.DECODE_STAGES]
    if not decode:
        decode = list(rules_dsl.DEFAULT_DECODE)
    mw = DEFAULT_MIN_WEIGHT_TO_BLOCK if min_weight_to_block is None else float(min_weight_to_block)
    breakers = breaker_map()

    rules: List[Dict[str, Any]] = []
    by_verdict: Dict[str, int] = {}
    for r in mined_merged(breakers=breakers):
        if not r.get("enabled"):
            continue
        proven = r.get("verdict") == "keep"
        br = r.get("breaker")
        if br and (br.get("mode") or "alert") == "disable":
            continue
        act = (r.get("action") or "alert") if (proven and not br) else "alert"
        by_verdict[r.get("verdict") or "unknown"] = by_verdict.get(r.get("verdict") or "unknown", 0) + 1
        rules.append({
            "id": r["id"],
            "name": r.get("name"),
            "regex": r.get("regex"),
            "scopes": r.get("scopes") or ["full"],
            "severity": r.get("severity"),
            "weight": float(r.get("weight") or 1.0),
            "action": act,
            "source": "mined",
            "provenance": {
                "kind": "detector",
                "verdict": r.get("verdict"),
                "qualification": "proven" if proven else "user_override",
                "overridden": not proven,
                "action_requested": r.get("action_requested") or r.get("action"),
                "action_forced": ("breaker" if br else (None if proven else "alert")),
                "breaker": br,
                "benign_hits": r.get("benign_hits"),
                "benign_n": r.get("benign_n"),
                "attack_hits": r.get("attack_hits"),
                "attack_n": r.get("attack_n"),
                "pool_support": r.get("pool_support"),
                "decoding_gain": r.get("decoding_gain"),
            },
        })

    for r in custom_rows():
        if not r.get("enabled"):
            continue
        # 启用时已经保证编译过；这里再兜一层：没有编译证据的绝不进现役。
        if not (r.get("compiled_at") or r.get("validated_at")):
            continue
        br = breakers.get(str(r["id"]))
        # `mode='disable'` 是 alert 规则的 L1 熔断：重提升也不能把它悄悄放回现役。
        if br and (br.get("mode") or "alert") == "disable":
            continue
        qualified = bool(r.get("qualified_at"))
        act = (r.get("action") or "alert") if (qualified and not br) else "alert"
        forced = "breaker" if br else (None if qualified else "alert")
        rules.append({
            "id": r["id"],
            "name": r.get("name"),
            "regex": r.get("regex"),
            "scopes": r.get("scopes") or ["full"],
            "severity": r.get("severity"),
            "weight": float(r.get("weight") or 1.0),
            "action": act,
            "source": r.get("source") or "custom",
            "provenance": {
                "kind": r.get("kind") or "detector",
                "validation": r.get("validation"),
                "qualification": "qualified" if qualified else "testing",
                "qualified_at": r.get("qualified_at"),
                "qualified_by": r.get("qualified_by"),
                "qualification_source": r.get("qualification_source"),
                "qualification_note": r.get("qualification_note"),
                "action_requested": r.get("action") or "alert",
                "action_forced": forced,
                "breaker": br,
            },
        })

    block = sum(1 for r in rules if r.get("action") == "block")
    overridden = sum(1 for r in rules
                     if (r.get("provenance") or {}).get("overridden"))
    testing = sum(1 for r in rules
                  if (r.get("provenance") or {}).get("qualification") == "testing")
    breaker_n = sum(1 for r in rules
                    if (r.get("provenance") or {}).get("action_forced") == "breaker")
    by_kind: Dict[str, int] = {}
    for r in rules:
        k = (r.get("provenance") or {}).get("kind") or "detector"
        by_kind[k] = by_kind.get(k, 0) + 1
    return {
        "schema": 1,
        "ruleset_id": ruleset_id or f"authoritative-{int(time.time())}",
        "generated_at": db.now_ms(),
        "decode": decode,
        "min_weight_to_block": round(mw, 4),
        "counts": {
            "total": len(rules),
            "block": block,
            "alert": len(rules) - block,
            "mined": sum(1 for r in rules if r["source"] == "mined"),
            "custom": sum(1 for r in rules
                          if r["source"] in ("custom", "manual", "crs", "wafjson")),
            "crs": sum(1 for r in rules if r["source"] == "crs"),
            "wafjson": sum(1 for r in rules if r["source"] == "wafjson"),
            "proven": len(rules) - overridden,
            "user_override": overridden,
            "testing": testing,
            "breaker": breaker_n,
            "by_verdict": by_verdict,
            "by_kind": by_kind,
        },
        "rules": rules,
    }


def load_authoritative() -> Optional[Dict[str, Any]]:
    try:
        with open(config.RULES_AUTHORITATIVE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def authoritative_sha1_16() -> Optional[str]:
    try:
        import hashlib
        h = hashlib.sha1()
        with open(config.RULES_AUTHORITATIVE, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return None


def authoritative_info() -> Dict[str, Any]:
    doc = load_authoritative()
    if not doc:
        return {"present": False, "sha1_16": None,
                "note": "尚无现役规则集；数据面此时按「无规则通道」运行。"}
    return {
        "present": True,
        "sha1_16": authoritative_sha1_16(),
        "ruleset_id": doc.get("ruleset_id"),
        "generated_at": doc.get("generated_at"),
        "decode": doc.get("decode"),
        "min_weight_to_block": doc.get("min_weight_to_block"),
        "counts": doc.get("counts"),
        "mtime": int(config.RULES_AUTHORITATIVE.stat().st_mtime * 1000),
    }


def write_authoritative(doc: Dict[str, Any]) -> None:
    """原子落盘（先写临时文件再替换），避免数据面读到半个文件。"""
    import os
    tmp = str(config.RULES_AUTHORITATIVE) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, str(config.RULES_AUTHORITATIVE))
