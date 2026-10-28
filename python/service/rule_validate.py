"""自撰规则的「三关」校验编排。

三关缺一不可（用户拍板）：
  ① 正则安全   —— **Rust `regex` crate 是权威编译器**（`waf-ai-proto rules check`）。
  ② 真实良性回放 —— 在真实良性池上**误报必须为 0**（`calibrate_rules.py`）。
  ③ 攻击回放    —— 在攻击池上命中必须 **> 0**（否则这条规则只是噪声）。

但 v2 起「启用 ≠ 合格」：
  * 启用只要求 ①（`compile_custom`，毫秒级）；
  * ②③ 是「合格建议」的证据，不再挡启用；
  * `kind=guard`（防御型入口规则）不看 ③ —— 它本来就不对应一次真实攻击；
  * 合格永远由人点「确认合格」，本模块只产出建议。

Python 只做编排 + 统计；**匹配全部交给 Rust**（同一份实现，避免两侧语义漂移）。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple

from . import config, db, rules_dsl, toolchain


def _tmpdir() -> str:
    # 默认落到 %TEMP%（C:）。F: 盘吃紧，别把回放中间产物写在那里。
    return tempfile.mkdtemp(prefix="waf_rule_val_")


def _scopes_of(row: Dict[str, Any]) -> List[str]:
    scopes = row.get("scopes")
    try:
        scopes = json.loads(scopes or "[]") or ["full"]
    except Exception:
        scopes = ["full"]
    return scopes


def _rule_spec(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "regex": row["regex"],
        "scopes": _scopes_of(row),
        "severity": row["severity"],
        "weight": float(row["weight"] or 1.0),
        "action": "alert",           # 校验只看匹配，不关心动作
        "kind": row.get("kind") or "detector",
        "source": "custom",
    }


def _spec(rules: List[Dict[str, Any]], spec_id: str) -> Dict[str, Any]:
    return {
        "schema": 1,
        "ruleset_id": spec_id,
        "decode": list(rules_dsl.DEFAULT_DECODE),
        "min_weight_to_block": 1.0,
        "rules": rules,
    }


def _check(spec: Dict[str, Any]) -> Tuple[bool, str, str]:
    """跑 ①（Rust 编译）。返回 (ok, stdout, stderr)。"""
    tmp = _tmpdir()
    path = os.path.join(tmp, "rules.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)
    try:
        p = toolchain.run_proto(["rules", "check", "--rules", path])
        return p.returncode == 0, (p.stdout or "").strip()[:4000], (p.stderr or "").strip()[:4000]
    except FileNotFoundError as e:
        return False, "", str(e)


def compile_custom(rid: str) -> Dict[str, Any]:
    """只跑 ①：Rust 正则编译。通过就写 `compiled_at`（启用的门槛）。"""
    row = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not row:
        raise ValueError(f"规则不存在：{rid}")
    ok, out, err = _check(_spec([_rule_spec(row)], f"compile-{rid}"))
    if ok:
        db.execute("UPDATE rules_custom SET compiled_at=?, updated_at=? WHERE id=?",
                   (db.now_ms(), db.now_ms(), rid))
    return {"passed": ok, "stdout": out, "stderr": err,
            "error": None if ok else (err or out or "编译失败")}


def compile_many(rids: List[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    """批量 ①：一次调用编译多条，失败的再逐条定位。

    35 条规则一条条起进程要十几秒；批量只是一次 `rules check`。
    """
    rows = db.rows(
        "SELECT * FROM rules_custom WHERE id IN (%s)" % ",".join("?" * len(rids)),
        tuple(rids),
    ) if rids else []
    by_id = {r["id"]: r for r in rows}
    ordered = [by_id[r] for r in rids if r in by_id]
    if not ordered:
        return [], []
    ok, out, err = _check(_spec([_rule_spec(r) for r in ordered], "compile-batch"))
    if ok:
        now = db.now_ms()
        for r in ordered:
            db.execute("UPDATE rules_custom SET compiled_at=?, updated_at=? WHERE id=?",
                       (now, now, r["id"]))
        return [r["id"] for r in ordered], []

    good: List[str] = []
    bad: List[Dict[str, str]] = []
    for r in ordered:
        one_ok, one_out, one_err = _check(_spec([_rule_spec(r)], f"compile-{r['id']}"))
        if one_ok:
            db.execute("UPDATE rules_custom SET compiled_at=?, updated_at=? WHERE id=?",
                       (db.now_ms(), db.now_ms(), r["id"]))
            good.append(r["id"])
        else:
            bad.append({"rule": r["id"], "error": (one_err or one_out or "编译失败")[:500]})
    return good, bad


def validate_custom(rid: str) -> Dict[str, Any]:
    row = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if not row:
        raise ValueError(f"规则不存在：{rid}")
    spec = _spec([_rule_spec(row)], f"validate-{rid}")
    res = validate_spec(spec, rule_id=rid, kind=row.get("kind") or "detector")

    gates = res.get("gates") or {}
    g1 = gates.get("regex_safety") or {}
    g2 = gates.get("benign_replay") or {}
    now = db.now_ms()
    if g1.get("passed"):
        db.execute("UPDATE rules_custom SET compiled_at=? WHERE id=?", (now, rid))

    ok = bool(res["passed"])
    if ok:
        db.execute("UPDATE rules_custom SET validated_at=?, validation=?, updated_at=? WHERE id=?",
                   (now, json.dumps(res, ensure_ascii=False), now, rid))
        res["note"] = (
            "三关全过：正则可编译、真实良性 0 误报、攻击有命中。"
            if (row.get("kind") or "detector") != "guard" else
            "防御型规则通过 ①②（③ 不适用）：真实良性 0 误报。"
        ) + "接下来需要人工确认合格（确认后才允许 block）。"
    else:
        # ② 实测误报 = **反证据**：立即撤销合格并强制 alert，不能等下次提升。
        if g2 and g2.get("passed") is False:
            db.execute(
                """UPDATE rules_custom
                      SET validated_at=NULL, validation=?, qualified_at=NULL,
                          qualified_by=NULL, qualification_source='validation_failed',
                          action='alert', updated_at=?
                    WHERE id=?""",
                (json.dumps(res, ensure_ascii=False), now, rid),
            )
            res["demoted"] = True
            res["note"] = (f"真实良性回放有 {int(g2.get('benign_hits') or 0)} 次误报："
                           "已撤销合格并强制 alert。修好后再校验。")
        else:
            db.execute("UPDATE rules_custom SET validated_at=NULL, validation=?, updated_at=? WHERE id=?",
                       (json.dumps(res, ensure_ascii=False), now, rid))
            res["note"] = ("未通过：规则仍是草稿/测试状态。按失败的那一关修，改完需重新校验；"
                           "也可以先启用去真实流量里攒证据（只告警）。")
    return res


def validate_spec(spec: Dict[str, Any], *, rule_id: str = "",
                  kind: str = "detector") -> Dict[str, Any]:
    """跑三关。返回 `{"passed":bool, "gates":{...}}`。

    `kind=guard` 时第三关标记为 `not_applicable`，不参与 passed 计算。
    """
    tmp = _tmpdir()
    spec_path = os.path.join(tmp, "rules.json")
    with open(spec_path, "w", encoding="utf-8") as f:
        json.dump(spec, f, ensure_ascii=False, indent=1)

    gates: Dict[str, Any] = {}

    # ---- 关 ①：正则安全（Rust 编译，权威） ----
    try:
        p = toolchain.run_proto(["rules", "check", "--rules", spec_path])
        g1 = {
            "passed": p.returncode == 0,
            "engine": "rust regex crate（线性时间；无 lookaround/反向引用）",
            "exit_code": p.returncode,
            "stdout": (p.stdout or "").strip()[:4000],
            "stderr": (p.stderr or "").strip()[:4000],
        }
    except FileNotFoundError as e:
        g1 = {"passed": False, "engine": "rust regex crate", "error": str(e)}
    gates["regex_safety"] = g1
    if not g1["passed"]:
        return {"passed": False, "gates": gates,
                "failed_at": "regex_safety", "tool": str(spec_path)}

    # ---- 关 ②③：真实良性 / 攻击 回放（同一份 Rust 实现） ----
    out_path = os.path.join(tmp, "calibration.json")
    cmd = [sys.executable, str(config.PY / "calibrate_rules.py"),
           "--ruleset", spec_path, "--out", out_path]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        p2 = subprocess.run(cmd, cwd=str(config.PY), capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=1800, env=env)
    except FileNotFoundError:
        gates["replay"] = {"passed": False, "error": "calibrate_rules.py 不存在（R2 未落地）"}
        return {"passed": False, "gates": gates, "failed_at": "replay"}
    if p2.returncode != 0:
        gates["replay"] = {
            "passed": False,
            "exit_code": p2.returncode,
            "stdout": (p2.stdout or "").strip()[-4000:],
            "stderr": (p2.stderr or "").strip()[-4000:],
        }
        return {"passed": False, "gates": gates, "failed_at": "replay"}

    try:
        with open(out_path, "r", encoding="utf-8") as f:
            cal = json.load(f)
    except Exception as e:
        gates["replay"] = {"passed": False, "error": f"读标定结果失败：{e}"}
        return {"passed": False, "gates": gates, "failed_at": "replay"}

    stats = next((r for r in cal.get("rules", []) if r.get("id") == rule_id),
                 (cal.get("rules") or [{}])[0])
    ben_hits = int(stats.get("benign_hits") or 0)
    ben_n = int(stats.get("benign_n") or 0)
    atk_hits = int(stats.get("attack_hits") or 0)
    atk_n = int(stats.get("attack_n") or 0)

    g2 = {
        "passed": ben_hits == 0,
        "name": "真实良性回放",
        "benign_hits": ben_hits, "benign_n": ben_n,
        "benign_rate": (ben_hits / ben_n) if ben_n else None,
        "benign_sources": cal.get("pools", {}).get("unified", {}).get("benign_sources"),
        "caveat": cal.get("pools", {}).get("unified", {}).get("benign_caveat"),
    }
    gates["benign_replay"] = g2

    g3 = {
        "passed": atk_hits > 0,
        "name": "攻击回放",
        "attack_hits": atk_hits, "attack_n": atk_n,
        "attack_rate": (atk_hits / atk_n) if atk_n else None,
        "attack_sources": cal.get("pools", {}).get("unified", {}).get("attack_sources"),
    }
    if kind == "guard":
        g3["not_applicable"] = True
        g3["passed"] = None       # 防御型规则不看第三关
    gates["attack_replay"] = g3

    if kind == "guard":
        passed = bool(g2["passed"])
        failed_at = None if passed else "benign_replay"
    else:
        passed = bool(g2["passed"] and g3["passed"])
        failed_at = None if passed else ("benign_replay" if not g2["passed"] else "attack_replay")
    return {
        "passed": passed,
        "kind": kind,
        "gates": gates,
        "failed_at": failed_at,
        "tool": str(spec_path),
        "calibration": {
            "schema": cal.get("schema"),
            "ruleset_sha1_16": cal.get("ruleset_sha1_16"),
            "pools": cal.get("pools"),
            "p7_anchor": cal.get("p7_anchor"),
        },
    }
