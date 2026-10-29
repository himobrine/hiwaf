"""同源攻击链关联 + 时序规则。

告警页的「聚合告警」回答的是**哪一条路径被打了多少次**；本模块回答另一个问题：
**同一个源在窗口内到底做了一串什么事**（探测 → 试探 → 利用），并把跨时间桶的
事件按源合并成一条链。

设计要点：

* **只读**：不写任何状态。确认/关闭复用 `alert_state`，`chain_key` 直接当
  `group_key` 用；链随时间向后生长时 `chain_key` 保持不变
  （`src_ip|ua|first_event_id`），只有首事件滑出窗口才会换 key。
* **纯函数**：`classify` / `build_chains` / `detect_sequences` 不碰 DB，单测直接喂
  行数据；`collect()` 负责取数。
* **取数有界**：先取窗口内有 `block/alert` 的源 IP（最多 `MAX_SOURCES`），再取这些
  源的全部事件（最多 `MAX_ROWS`），避免全表扫。截断时返回 `truncated=true`。
* **扫描噪音降级**：大量探测（≥`NOISE_RECON`）且没有任何拦截的链标 `noise=true`，
  级别降为 P3，前端默认折叠；这解决「端口扫描把告警列表刷屏」的问题。
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

from . import config, db

#: 探测类状态码：失败/无权限的请求才算探测，成功的 `/login` 不算。
RECON_STATUS = (401, 403, 404)
#: 失败请求里出现这些片段时也算探测（目录扫描、配置/备份探测、管理入口）。
PROBE_PATH_HINTS = (
    ".git", ".env", ".htpasswd", ".bak", ".sql", ".zip", ".tar", ".gz",
    "wp-login", "wp-admin", "xmlrpc", "phpmyadmin", "phpinfo", "cgi-bin",
    "webshell", "shell", "backup", "config", "admin", "login", "server-status",
)
#: 探测次数达到该值且无拦截 → 视为扫描噪音（降级 P3）。
NOISE_RECON = 20
#: 取数上限：源 IP 数与事件行数。
MAX_SOURCES = 500
MAX_ROWS = 50_000

STAGE_ORDER = ("recon", "probe", "exploit")
STAGE_LABEL = {"recon": "探测", "probe": "试探", "exploit": "利用", "normal": "正常"}

#: 内置时序规则；可被 `WAF_TEMPORAL_RULES` 指向的 JSON 覆盖（格式见 `load_rules`）。
DEFAULT_RULES: list[dict] = [
    {
        "id": "scan_then_exploit",
        "name": "扫描后利用",
        "within_min": 10,
        "group_by": ["src_ip"],
        "stages": [{"stage": "recon", "min": 20}, {"stage": "exploit", "min": 1}],
    },
    {
        "id": "probe_then_exploit",
        "name": "试探后利用",
        "within_min": 10,
        "group_by": ["src_ip"],
        "stages": [{"stage": "probe", "min": 3}, {"stage": "exploit", "min": 1}],
    },
    {
        "id": "recon_burst",
        "name": "目录扫描风暴",
        "within_min": 5,
        "group_by": ["src_ip"],
        "stages": [{"stage": "recon", "min": 30}],
    },
]


def _int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def classify(row: dict) -> str:
    """单条事件 → 阶段：`exploit`（已拦截）/ `probe`（只告警）/ `recon`（探测）/ `normal`。

    优先级：拦截 > 告警 > 探测。探测只认**失败**请求（状态码或失败 + 敏感路径），
    避免把正常登录/管理页当成扫描。
    """
    action = (row.get("action") or "").lower()
    if action == "block":
        return "exploit"
    if action == "alert" or _int(row.get("supervised_flagged")):
        return "probe"
    status = row.get("status")
    if status in RECON_STATUS:
        return "recon"
    path = (row.get("path") or "").lower()
    if status is not None and _int(status) >= 400 and any(h in path for h in PROBE_PATH_HINTS):
        return "recon"
    return "normal"


def _chain(src_ip: str, ua: str, evs: list[dict]) -> dict:
    counts = Counter()
    stages: list[str] = []
    attack_types = Counter()
    paths = Counter()
    hosts: set[str] = set()
    max_score = None
    for e in evs:
        st = classify(e)
        counts[st] += 1
        if st in STAGE_ORDER and (not stages or stages[-1] != st):
            stages.append(st)
        at = (e.get("attack_type") or "").strip()
        if at:
            attack_types[at] += 1
        if e.get("path"):
            paths[e["path"]] += 1
        if e.get("host"):
            hosts.add(e["host"])
        sc = e.get("supervised_score")
        if sc is not None and (max_score is None or float(sc) > max_score):
            max_score = float(sc)

    blocked = counts["exploit"]
    alerted = counts["probe"]
    recon = counts["recon"]
    noise = blocked == 0 and recon >= NOISE_RECON
    if blocked:
        severity = "P1"
    elif noise:
        severity = "P3"
    else:
        severity = "P2" if alerted else "P3"
    return {
        "chain_key": f"{src_ip}|{ua or '-'}|{evs[0]['id']}",
        "src_ip": src_ip,
        "ua": ua or None,
        "hosts": sorted(hosts)[:5],
        "first_ts": evs[0]["ts"],
        "last_ts": evs[-1]["ts"],
        "n": len(evs),
        "blocked": blocked,
        "alerted": alerted,
        "recon": recon,
        "stages": stages,
        "attack_types": [{"attack_type": k, "n": v}
                         for k, v in attack_types.most_common(5)],
        "top_paths": [{"path": k, "n": v} for k, v in paths.most_common(5)],
        "max_score": max_score,
        "severity": severity,
        "noise": noise,
        "sequences": [],
    }


def build_chains(rows: Iterable[dict], *, gap_ms: int = 10 * 60 * 1000,
                 min_events: int = 2) -> list[dict]:
    """按 (src_ip, ua) 分组，事件间隔超过 `gap_ms` 就切成新链。

    返回按最近活动倒序的链；`min_events` 过滤掉单事件（单条告警没有「链」的意义）。
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        groups.setdefault((r.get("src_ip") or "", r.get("ua") or ""), []).append(r)

    out: list[dict] = []
    for (src_ip, ua), evs in groups.items():
        evs.sort(key=lambda r: (r["ts"], r["id"]))
        cur: list[dict] = []
        for r in evs:
            if cur and r["ts"] - cur[-1]["ts"] > gap_ms:
                out.append(_chain(src_ip, ua, cur))
                cur = []
            cur.append(r)
        if cur:
            out.append(_chain(src_ip, ua, cur))
    out = [c for c in out if c["n"] >= min_events]
    out.sort(key=lambda c: (c["last_ts"], c["chain_key"]), reverse=True)
    return out


def _group_key(row: dict, fields: list[str]) -> tuple:
    return tuple((row.get(f) or "") for f in fields)


def detect_sequences(rows: Iterable[dict], rules: Optional[list[dict]] = None) -> list[dict]:
    """在事件流里找「阶段 A ≥N 次后、窗口内出现阶段 B」的时序命中。

    每个规则对每个分组只报**最早**的一次命中；返回按 `last_ts` 倒序。
    """
    rows = list(rows)
    hits: list[dict] = []
    for rule in rules if rules is not None else load_rules():
        fields = rule.get("group_by") or ["src_ip"]
        within_ms = int(rule.get("within_min", 10)) * 60_000
        groups: dict[tuple, list[dict]] = {}
        for r in rows:
            groups.setdefault(_group_key(r, fields), []).append(r)
        for gkey, evs in groups.items():
            evs.sort(key=lambda r: (r["ts"], r["id"]))
            idx = 0
            prev_last: Optional[int] = None
            matched: list[dict] = []
            for stage in rule.get("stages") or []:
                need = max(1, int(stage.get("min", 1)))
                name = stage.get("stage")
                found: list[dict] = []
                j = idx
                while j < len(evs):
                    e = evs[j]
                    # 窗口从**上一阶段最后一条**开始算：「A 之后 within 内出现 B」。
                    if prev_last is not None and e["ts"] - prev_last > within_ms:
                        break
                    if classify(e) == name:
                        found.append(e)
                        if len(found) >= need:
                            break
                    j += 1
                if len(found) < need:
                    matched = []
                    break
                matched.append({
                    "stage": name,
                    "label": STAGE_LABEL.get(name, name),
                    "n": len(found),
                    "first_ts": found[0]["ts"],
                    "last_ts": found[-1]["ts"],
                })
                prev_last = found[-1]["ts"]
                idx = j + 1
            if matched:
                hits.append({
                    "rule_id": rule.get("id"),
                    "name": rule.get("name") or rule.get("id"),
                    "group_by": list(fields),
                    "group": {f: (gkey[i] or None) for i, f in enumerate(fields)},
                    "src_ip": gkey[0] if fields and fields[0] == "src_ip" else None,
                    "matched": matched,
                    "n": sum(m["n"] for m in matched),
                    "first_ts": matched[0]["first_ts"],
                    "last_ts": matched[-1]["last_ts"],
                    "within_min": int(rule.get("within_min", 10)),
                })
    hits.sort(key=lambda h: (h["last_ts"], h["rule_id"]), reverse=True)
    return hits


def load_rules() -> list[dict]:
    """读 `WAF_TEMPORAL_RULES` 指向的 JSON；缺失/非法时回退内置规则。

    文件格式：`{"rules": [{"id","name","within_min","group_by","stages":[
    {"stage":"recon|probe|exploit","min":N}]}]}`。非法规则整条跳过并保留其余，
    不会因为一个笔误让整页告警消失。
    """
    path = Path(config.TEMPORAL_RULES_JSON)
    if not path.exists():
        return [dict(r) for r in DEFAULT_RULES]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return [dict(r) for r in DEFAULT_RULES]
    rules = raw.get("rules") if isinstance(raw, dict) else raw
    if not isinstance(rules, list):
        return [dict(r) for r in DEFAULT_RULES]
    out: list[dict] = []
    for r in rules:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        stages = [s for s in (r.get("stages") or [])
                  if isinstance(s, dict) and s.get("stage") in STAGE_ORDER]
        if not stages:
            continue
        try:
            within = max(1, min(1440, int(r.get("within_min", 10))))
            norm_stages = [{"stage": s["stage"], "min": max(1, int(s.get("min", 1)))}
                           for s in stages]
        except (TypeError, ValueError):
            # 单个规则写错（例如 "min": "3 次"）只跳过它，不影响其余规则。
            continue
        gb = r.get("group_by")
        if isinstance(gb, str):
            gb = [gb]
        if not isinstance(gb, list):
            gb = ["src_ip"]
        out.append({
            "id": str(r["id"]),
            "name": r.get("name") or str(r["id"]),
            "within_min": within,
            "group_by": [str(f) for f in gb if f] or ["src_ip"],
            "stages": norm_stages,
        })
    return out or [dict(r) for r in DEFAULT_RULES]


def collect(window_hours: int = 24, gap_min: int = 10, min_events: int = 2,
            only_suspicious: bool = True, include_noise: bool = True,
            limit: int = 200, *, src_ip: Optional[str] = None,
            attack_type: Optional[str] = None, method: Optional[str] = None,
            host: Optional[str] = None, q: Optional[str] = None,
            min_score: Optional[float] = None,
            from_ts: Optional[int] = None, to_ts: Optional[int] = None) -> dict:
    """取数 + 关联；只读，返回 `{items, sequences, scanned_rows, truncated, ...}`。

    `include_noise=False` 时把扫描噪音链（`noise=true`）过滤掉，并返回
    `noise_hidden` 计数供前端提示「另有 N 条扫描噪音已折叠」。
    筛选条件在**事件级**先过滤再切链（与 `/api/alerts` 同一套语义）。

    **选源**用 `block/alert` + 筛选条件；**切链取数**沿用同一套筛选但**不限制
    动作**——探测/放行事件是阶段分类（探测→试探→利用）和噪音判定的输入，
    不能因为「只看 block/alert」而丢掉。
    """
    from .alerts import _where as event_where  # 同一套过滤条件，避免两处漂移

    now = db.now_ms()
    until = int(to_ts) if to_ts is not None else now
    since = int(from_ts) if from_ts is not None else (
        until - window_hours * 3600 * 1000)
    kw = dict(src_ip=src_ip, attack_type=attack_type, method=method, host=host,
              q=q, min_score=min_score)
    w, p = event_where(since, until, **kw)
    w_rows, p_rows = event_where(since, until, only_attack_actions=False, **kw)
    srcs = [r["src_ip"] for r in db.rows(
        f"""SELECT src_ip, COUNT(*) AS n FROM events
             WHERE {w} AND src_ip IS NOT NULL
             GROUP BY src_ip ORDER BY n DESC LIMIT ?""",
        [*p, MAX_SOURCES],
    )]
    if not srcs:
        return {"window_hours": window_hours, "gap_min": gap_min,
                "min_events": min_events, "scanned_rows": 0, "truncated": False,
                "noise_hidden": 0, "items": [], "sequences": [],
                "from_ts": since, "to_ts": until}

    ph = ",".join("?" * len(srcs))
    rows = db.rows(
        f"""SELECT id, ts, src_ip, ua, host, method, path, status, action,
                   attack_type, supervised_score, supervised_flagged
            FROM events
            WHERE {w_rows} AND src_ip IN ({ph})
            ORDER BY ts ASC, id ASC LIMIT ?""",
        [*p_rows, *srcs, MAX_ROWS],
    )
    chains = build_chains(rows, gap_ms=gap_min * 60_000, min_events=min_events)
    sequences = detect_sequences(rows)

    # 把时序命中挂到对应的链上（同源 + 时间有交集）。
    by_ip: dict[str, list[dict]] = {}
    for s in sequences:
        if s.get("src_ip"):
            by_ip.setdefault(s["src_ip"], []).append(s)
    for c in chains:
        for s in by_ip.get(c["src_ip"], []):
            if s["first_ts"] <= c["last_ts"] and s["last_ts"] >= c["first_ts"]:
                c["sequences"].append({"rule_id": s["rule_id"], "name": s["name"],
                                       "n": s["n"], "last_ts": s["last_ts"]})

    if only_suspicious:
        chains = [c for c in chains if c["blocked"] or c["alerted"]]
    noise_hidden = 0
    if not include_noise:
        noise_hidden = sum(1 for c in chains if c.get("noise"))
        chains = [c for c in chains if not c.get("noise")]
    truncated = len(rows) >= MAX_ROWS
    return {
        "window_hours": window_hours,
        "gap_min": gap_min,
        "min_events": min_events,
        "scanned_rows": len(rows),
        "scanned_sources": len(srcs),
        "truncated": truncated,
        "noise_hidden": noise_hidden,
        "items": chains[:limit],
        "sequences": sequences[:limit],
        "from_ts": since,
        "to_ts": until,
    }


def chain_events(src_ip: str, ua: Optional[str], from_ts: int, to_ts: int,
                 limit: int = 50, offset: int = 0) -> dict:
    """某条链的原始事件（精确同源 + UA + 时间范围，升序）。

    与 `collect()` 取数口径一致：这里不按 action/status 过滤，所以条数能对上链的 n。
    """
    if not src_ip:
        raise ValueError("src_ip 不能为空")
    if to_ts < from_ts:
        raise ValueError("to_ts 必须 ≥ from_ts")
    if ua:
        where = "src_ip=? AND ua=? AND ts BETWEEN ? AND ?"
        params: list = [src_ip, ua, from_ts, to_ts]
    else:
        where = "src_ip=? AND (ua IS NULL OR ua='') AND ts BETWEEN ? AND ?"
        params = [src_ip, from_ts, to_ts]
    total = int(db.scalar(f"SELECT COUNT(*) AS n FROM events WHERE {where}", params, 0) or 0)
    items = db.rows(
        f"""SELECT id, ts, src_ip, method, path, status, action,
                   supervised_score, supervised_threshold, supervised_flagged,
                   attack_type, rule_hits_json
            FROM events WHERE {where}
            ORDER BY ts ASC, id ASC LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )
    for it in items:
        try:
            it["rule_hits"] = json.loads(it.get("rule_hits_json") or "[]")
        except Exception:
            it["rule_hits"] = []
        it.pop("rule_hits_json", None)
        it["stage"] = classify(it)
    return {"total": total, "from_ts": from_ts, "to_ts": to_ts,
            "limit": limit, "offset": offset, "items": items}
