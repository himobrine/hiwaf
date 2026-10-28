"""站点（Host）→ 模型：回答「每个站点用的是哪套模型」。

一个 WAF 可能接入多个站点的流量（不同 Host / 不同采集器），本模块从**逐条判决
留证**反查每个站点在用的模型，而不是猜：

  * `events.host`            —— 站点（Host 头；采集器没有时为空）
  * `events.policy_version`  —— 判决时用的策略修订号
  * `policy_versions.json`   —— 该修订号记录的产物文件名 + sha1_16
    （`supervised.artifact[_sha1_16]` / `zero_day.artifact[_sha1_16]` / 规则集指纹）
  * `model_registry`         —— sha1_16 → 可读名称（XGBoost g1 等，仅展示用）

与现役策略对比后给每个站点一个 `status`：
  * `in_sync`     —— 最新判决版本 = 现役策略版本
  * `policy_old`  —— 版本旧了，但监督模型 sha1 与现役一致（只是阈值/规则旧）
  * `stale`       —— 监督模型就是旧模型（切换后采集器未重启，需处理）
  * `unscored`    —— 窗口内该站点没有任何带判定的事件（采集器未 --score）
  * `unknown`     —— 策略快照缺失或现役策略无法对比

只读；不改任何状态。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from . import config, db

TOP_SITES = 100


def _load_json(path) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _chan_models(pol: dict, ch: str) -> Dict[str, Any]:
    p = pol.get(ch) or {}
    return {"artifact": p.get("artifact"), "sha1_16": p.get("artifact_sha1_16")}


def _models_of(pol: dict) -> Dict[str, Any]:
    """从一份策略快照里抽出「这套判决用了什么」。"""
    rules = pol.get("rules") or {}
    zd = _chan_models(pol, "zero_day")
    zd["enabled"] = bool(pol.get("zero_day_enabled"))
    return {
        "supervised": _chan_models(pol, "supervised"),
        "zero_day": zd,
        "rules": {
            "enabled": bool(rules.get("enabled")),
            "sha1_16": rules.get("ruleset_sha1_16"),
            "n_rules": rules.get("n_rules"),
            "n_block_rules": rules.get("n_block_rules"),
        },
    }


def _name_map(pairs: set) -> Dict[tuple, dict]:
    """(channel, sha1_16) → model_registry 的可读名称。缺失就不放（前端退回文件名）。"""
    if not pairs:
        return {}
    shas = sorted({s for _, s in pairs if s})
    if not shas:
        return {}
    ph = ",".join("?" for _ in shas)
    out: Dict[tuple, dict] = {}
    for r in db.rows(
        "SELECT channel, sha1_16, display_name, generation, artifact_name "
        f"FROM model_registry WHERE sha1_16 IN ({ph})",
        tuple(shas),
    ):
        out[(r["channel"], r["sha1_16"])] = {
            "name": r.get("display_name"),
            "generation": r.get("generation"),
            "artifact_name": r.get("artifact_name"),
        }
    return out


def site_models(window_hours: int = 24, live_policy: Optional[dict] = None,
                top: int = TOP_SITES) -> dict:
    """按站点聚合窗口内事件的判定模型；默认与磁盘现役策略对比。"""
    if live_policy is None:
        live_policy = _load_json(config.POLICY_JSON) or {}
    live_version = live_policy.get("version")
    live_models = _models_of(live_policy) if live_policy else {}
    live_sup_sha = (live_models.get("supervised") or {}).get("sha1_16")

    since = db.now_ms() - window_hours * 3600 * 1000
    rows = db.rows(
        """SELECT host, policy_version,
                  COUNT(*) AS n,
                  COALESCE(SUM(action='block'),0) AS blocks,
                  COALESCE(SUM(action='alert'),0) AS alerts,
                  COALESCE(SUM(action='allow'),0) AS allows,
                  MIN(ts) AS first_ts, MAX(ts) AS last_ts,
                  GROUP_CONCAT(DISTINCT COALESCE(model_artifacts,'')) AS artifact_dirs
           FROM events WHERE ts>=?
           GROUP BY host, policy_version""",
        (since,),
    )

    by_host: Dict[Optional[str], List[dict]] = {}
    for r in rows:
        by_host.setdefault(r.get("host"), []).append(r)

    # 策略快照（所有站点窗口内出现过的版本，一次性取）
    vers = {int(r["policy_version"]) for r in rows if r.get("policy_version") is not None}
    snapshots: Dict[int, dict] = {}
    if vers:
        ph = ",".join("?" for _ in vers)
        for r in db.rows(
            f'SELECT version, "json" AS body FROM policy_versions WHERE version IN ({ph})',
            tuple(sorted(vers)),
        ):
            try:
                snapshots[int(r["version"])] = json.loads(r["body"])
            except Exception:
                pass

    # 名称解析（所有站点 + 所有版本涉及到的模型）
    pairs: set = set()
    for v in vers:
        pol = snapshots.get(v)
        if not pol:
            continue
        for ch in ("supervised", "zero_day"):
            m = _chan_models(pol, ch)
            if m.get("sha1_16"):
                pairs.add((ch, m["sha1_16"]))
    for ch in ("supervised", "zero_day"):
        s = (live_models.get(ch) or {}).get("sha1_16") if live_models else None
        if s:
            pairs.add((ch, s))
    names = _name_map(pairs)

    def resolved(ch: str, m: dict) -> dict:
        info = names.get((ch, m.get("sha1_16"))) or {}
        return {
            "artifact": m.get("artifact"),
            "sha1_16": m.get("sha1_16"),
            "name": info.get("name"),
            "generation": info.get("generation"),
        }

    items: List[dict] = []
    for host, rs in by_host.items():
        n = sum(int(r["n"] or 0) for r in rs)
        blocks = sum(int(r["blocks"] or 0) for r in rs)
        alerts = sum(int(r["alerts"] or 0) for r in rs)
        allows = sum(int(r["allows"] or 0) for r in rs)
        first_ts = min(int(r["first_ts"] or 0) for r in rs)
        last_ts = max(int(r["last_ts"] or 0) for r in rs)
        dirs = sorted({d for r in rs
                       for d in str(r.get("artifact_dirs") or "").split(",") if d})

        versioned = [r for r in rs if r.get("policy_version") is not None]
        # 最近的判决版本：先看最后一次使用时间，同一时刻再按版本号大者优先
        # （版本号单调递增，避免同秒并发写入导致"新旧版本并列"时选错）。
        versioned.sort(key=lambda r: (int(r.get("last_ts") or 0),
                                      int(r.get("policy_version") or 0)),
                       reverse=True)

        versions_out: List[dict] = []
        stale_versions = 0
        for r in versioned:
            v = int(r["policy_version"])
            pol = snapshots.get(v)
            sup = resolved("supervised", _chan_models(pol, "supervised")) if pol else \
                {"artifact": None, "sha1_16": None, "name": None, "generation": None}
            if pol and live_sup_sha and sup.get("sha1_16") and \
                    sup["sha1_16"] != live_sup_sha:
                stale_versions += 1
            versions_out.append({
                "policy_version": v,
                "n": int(r["n"] or 0),
                "last_ts": int(r["last_ts"] or 0),
                "snapshot_found": bool(pol),
                "supervised": sup,
            })

        latest = None
        status = "unscored"
        if versioned:
            v = int(versioned[0]["policy_version"])
            pol = snapshots.get(v)
            if not pol:
                status = "unknown"
            else:
                mm = _models_of(pol)
                latest = {
                    "policy_version": v,
                    "last_ts": int(versioned[0]["last_ts"] or 0),
                    "supervised": resolved("supervised", mm["supervised"]),
                    "zero_day": {
                        **resolved("zero_day", mm["zero_day"]),
                        "enabled": mm["zero_day"]["enabled"],
                    },
                    "rules": mm["rules"],
                }
                if not live_version or not live_sup_sha:
                    status = "unknown"
                elif v == int(live_version):
                    status = "in_sync"
                elif latest["supervised"].get("sha1_16") == live_sup_sha:
                    status = "policy_old"
                else:
                    status = "stale"

        items.append({
            "host": host,
            "n": n, "blocks": blocks, "alerts": alerts, "allows": allows,
            "first_ts": first_ts, "last_ts": last_ts,
            "status": status,
            "stale_versions": stale_versions,
            "artifact_dirs": dirs,
            "latest": latest,
            "versions": versions_out,
        })

    items.sort(key=lambda x: (x["n"], x["last_ts"]), reverse=True)
    total_hosts = len(items)
    if top > 0:
        items = items[:int(top)]

    return {
        "window_hours": window_hours,
        "total_hosts": total_hosts,
        "shown": len(items),
        "live": {
            "policy_version": live_version,
            "supervised": resolved("supervised", live_models.get("supervised", {})) if live_models else None,
            "zero_day": ({**resolved("zero_day", live_models.get("zero_day", {})),
                          "enabled": live_models["zero_day"].get("enabled")} if live_models else None),
            "rules": (live_models or {}).get("rules"),
        },
        "items": items,
    }
