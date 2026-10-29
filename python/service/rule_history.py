"""历史告警回放：把自撰规则拿到**过去的事件**上重放，用人工标签做合格证据。

为什么需要它：在线证据只统计「规则启用之后、最近 7 天」的命中，新写的规则在
启用前没有任何 `event_rules` 记录。真实场景往往是「先发生了攻击，后补规则」，
这时只能靠历史事件来证明规则有用。

步骤（全部只用现成的权威实现，不在 Python 里重写匹配）：

  1. 取窗口内最新的一批事件（默认 30 天 / 2 万条，超出标记 truncated）；
  2. body 两级回退复用 `datasets_events.resolve_bodies`（event_bodies → raw JSONL）；
  3. 写 corpus + 单规则 ruleset，调 Rust `waf-ai-proto rules replay`；
  4. 命中的事件按**最新人工 feedback** 分桶（确认攻击 / 确认良性 / 疑似 / 未标注）；
  5. 结果缓存到 `rule_history_evidence`，带规则内容指纹；规则一改即失效。

红线：只有人工标签算数；命中里确认良性 > 0 就不能用来合格；`② 真实良性零误报`
仍然必须先通过（在 `rules.custom_view` / `set_custom_qualified` 里卡）。
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Dict, List, Optional, Tuple

from . import config, datasets_events, db, rules as rules_mod, rules_dsl, toolchain

_SELECT = ("id, ts, method, path, query, body_len, body_truncated, "
           "src_file, src_line, ua, referer, supervised_flagged, zero_day_flagged")
_CHUNK = 400


def _clamp(days: Optional[int], max_events: Optional[int]) -> Tuple[int, int]:
    d = int(days if days is not None else config.RULE_HISTORY_DAYS)
    d = max(1, min(d, int(config.RULE_HISTORY_HARD_DAYS)))
    n = int(max_events if max_events is not None else config.RULE_HISTORY_MAX_EVENTS)
    n = max(1, min(n, int(config.RULE_HISTORY_HARD_EVENTS)))
    return d, n


def _select(since: int, limit: int) -> Tuple[List[dict], bool]:
    rows = db.rows(
        f"SELECT {_SELECT} FROM events WHERE ts>=? "
        "ORDER BY ts DESC, id DESC LIMIT ?", (since, limit + 1))
    return rows[:limit], len(rows) > limit


def _rule_spec(row: dict) -> dict:
    scopes = row.get("scopes")
    if isinstance(scopes, str):
        try:
            scopes = json.loads(scopes or "[]")
        except (TypeError, ValueError):
            scopes = []
    return {
        "id": str(row["id"]),
        "name": row.get("name") or str(row["id"]),
        "regex": row["regex"],
        "scopes": list(scopes or ["full"]),
        "severity": row.get("severity") or "medium",
        "weight": float(row.get("weight") or 1.0),
        "action": "alert",
        "source": row.get("source") or "manual",
    }


def _replay(spec: dict, rows: List[dict], bodies: Dict[int, str], tmpdir: str) -> List[int]:
    corpus = os.path.join(tmpdir, "history.jsonl")
    with open(corpus, "w", encoding="utf-8") as f:
        for r in rows:
            eid = int(r["id"])
            f.write(json.dumps({
                "id": eid, "pool": "history",
                "method": r.get("method") or "GET",
                "path": r.get("path") or "",
                "query": r.get("query") or "",
                "body": bodies.get(eid, ""),
                "ua": r.get("ua") or "",
                "referer": r.get("referer") or "",
            }, ensure_ascii=False) + "\n")
    ruleset = os.path.join(tmpdir, "rules.json")
    with open(ruleset, "w", encoding="utf-8") as f:
        json.dump({
            "schema": 1, "ruleset_id": f"history-{spec['id']}",
            "decode": list(rules_dsl.DEFAULT_DECODE),
            "min_weight_to_block": 1.0, "rules": [spec],
        }, f, ensure_ascii=False)
    out = os.path.join(tmpdir, "out.jsonl")
    p = toolchain.run_proto(
        ["rules", "replay", "--rules", ruleset, "--in", corpus, "--out", out],
        timeout=900)
    if p.returncode != 0:
        raise ValueError("规则回放失败：\n" + (p.stdout or "") + (p.stderr or ""))
    matched: List[int] = []
    with open(out, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "_meta" in obj:
                continue
            if obj.get("hits"):
                try:
                    matched.append(int(obj["id"]))
                except (TypeError, ValueError):
                    continue
    return matched


def _labels(ids: List[int]) -> Dict[int, dict]:
    out: Dict[int, dict] = {}
    for i in range(0, len(ids), _CHUNK):
        part = ids[i:i + _CHUNK]
        ph = ",".join("?" * len(part))
        for r in db.rows(
                f"""SELECT e.id AS id, e.ts, e.supervised_flagged, e.zero_day_flagged,
                           (SELECT f.verdict FROM feedback f WHERE f.event_id = e.id
                             ORDER BY f.ts DESC, f.id DESC LIMIT 1) AS verdict
                      FROM events e WHERE e.id IN ({ph})""", part):
            out[int(r["id"])] = r
    return out


def run(rid: str, *, days: Optional[int] = None, max_events: Optional[int] = None,
        actor: str = "system") -> dict:
    """回放一条自撰规则到历史事件上（同步；结果落库并返回）。"""
    row = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not row:
        raise ValueError(f"规则不存在：{rid}")
    if not (row.get("compiled_at") or row.get("validated_at")):
        raise ValueError("规则还没过 ① 正则编译：先启用一次（或点「校验」）再回放")
    days, max_events = _clamp(days, max_events)
    since = db.now_ms() - days * 86400 * 1000
    rows, truncated = _select(since, max_events)
    if not rows:
        raise ValueError(f"最近 {days} 天没有可回放的事件（可能已被保留策略清理）")

    bodies, body_stats = datasets_events.resolve_bodies(rows)
    spec = _rule_spec(row)
    tmpdir = tempfile.mkdtemp(prefix="waf_rule_history_")
    try:
        matched = _replay(spec, rows, bodies, tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    labels = _labels(matched) if matched else {}
    attack = benign = suspected = unlabeled = 0
    last_ts: Optional[int] = None
    for eid in matched:
        e = labels.get(eid) or {}
        ts = e.get("ts")
        if ts:
            ts = int(ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        v = e.get("verdict")
        if v in ("confirmed_attack", "missed"):
            attack += 1
        elif v in ("confirmed_benign", "false_positive"):
            benign += 1
        elif v is None and (int(e.get("supervised_flagged") or 0)
                            or int(e.get("zero_day_flagged") or 0)):
            suspected += 1
        else:
            unlabeled += 1

    samples = sorted(matched)[:20]
    sha = rules_mod.rule_fingerprint(row)
    now = db.now_ms()
    db.execute(
        """INSERT OR REPLACE INTO rule_history_evidence(
             rule, rule_sha, days, scanned, truncated, matched,
             confirmed_attack, confirmed_benign, suspected_attack, unlabeled,
             samples_json, last_ts, body_json, actor, created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, sha, days, len(rows), 1 if truncated else 0, len(matched),
         attack, benign, suspected, unlabeled,
         json.dumps(samples), last_ts,
         json.dumps(body_stats, ensure_ascii=False), actor, now))

    ok = bool(matched and attack >= rules_mod.MIN_HISTORY_CONFIRMED_ATTACKS and benign == 0)
    if ok:
        reason = f"确认攻击 {attack} 条 / 确认良性 0 条"
    elif benign:
        reason = f"历史命中里确认良性 {benign} 条，不能用于合格"
    elif matched:
        reason = f"命中 {len(matched)} 条，但没有人工确认攻击（未标注 {unlabeled} 条）"
    else:
        reason = f"最近 {days} 天的事件里一条都没命中"

    return {
        "rule": rid, "rule_sha": sha, "days": days,
        "scanned": len(rows), "truncated": truncated,
        "matched": len(matched), "confirmed_attack": attack,
        "confirmed_benign": benign, "suspected_attack": suspected,
        "unlabeled": unlabeled, "samples": samples, "last_ts": last_ts,
        "body": body_stats, "ok": ok, "reason": reason,
        "actor": actor, "created_at": now,
    }