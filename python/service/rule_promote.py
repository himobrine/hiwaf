"""把「合格」的规则提升为**现役规则集**，并把代价如实写进策略。

提升是**唯一的**规则落盘入口（`artifacts/rules_authoritative.json`），数据面只读它。步骤：

  1. Rust 编译校验（权威）—— 有任意一条编不过就拒绝；
  2. 量**只在真良性池上**的命中，得到阻断预算占用 `rules_fpr_on_pool`
     （**用 Wilson 95% 上界**，不是点估计：挖出的规则本身就是在 CSIC 正常流量上
     筛出来的，点估计系统性偏低，拿它去扣预算会把融合 FPR 顶穿目标）；
  3. `--rule-budget-cap`（默认 0.3%）超限就拒绝，并把数字打给用户；
  4. 重跑 `thresholds.py`：`sup_target = target_fpr − rules_fpr_on_pool` 收紧监督阈值，
     融合 FPR 维持不变，策略里写入 `rules` 块；
  5. 原子替换 `rules_authoritative.json`；
  6. 写审计（谁、什么时候、扣了多少预算、策略版本从几到几）。

顺序刻意如此：**先算代价、再落盘**。反过来会出现"规则已经生效但预算没扣"的窗口，
那个窗口里融合 FPR 是超的，而超多少没人知道。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional

from . import config, db, rules as rules_mod, toolchain

DEFAULT_RULE_BUDGET_CAP = 0.003   # 0.3%
MIN_SUP_SHARE = 0.10              # 规则吃掉超过 90% 预算 ⇒ 拒绝，不静默夹紧


def _read_json(p) -> Optional[dict]:
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def measure_budget(ruleset_path: str, *, timeout: int = 1800) -> Dict[str, Any]:
    """量阻断预算占用。没有任何 block 规则时返回 0（不占用预算）。"""
    cmd = [sys.executable, str(config.PY / "calibrate_rules.py"),
           "--ruleset", ruleset_path, "--budget-only"]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run(cmd, cwd=str(config.PY), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout, env=env)
    if p.returncode != 0:
        raise RuntimeError("标定失败：\n" + (p.stdout or "") + (p.stderr or ""))
    for line in reversed((p.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError("标定未返回 JSON：\n" + (p.stdout or ""))


def promote(doc: Dict[str, Any], *, actor: str, note: Optional[str] = None,
            rule_budget_cap: Optional[float] = None, ip: Optional[str] = None) -> Dict[str, Any]:
    cap = DEFAULT_RULE_BUDGET_CAP if rule_budget_cap is None else float(rule_budget_cap)
    if not (0.0 < cap <= 0.05):
        raise ValueError("rule_budget_cap 必须在 (0, 0.05]（单位是比例，不是百分比）")

    tmpdir = tempfile.mkdtemp(prefix="waf_rule_promote_")
    cand = os.path.join(tmpdir, "rules_authoritative.json")
    with open(cand, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)

    # ---- 1. 编译校验（权威） ----
    try:
        pc = toolchain.run_proto(["rules", "check", "--rules", cand])
    except FileNotFoundError as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError(str(e))
    if pc.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError("规则集编译失败（Rust regex 权威）：\n"
                         + (pc.stdout or "") + (pc.stderr or ""))

    # ---- 2. 预检预算（**更宽的**真良性池：p7 池 37,000 条） ----
    # 这一关只回答"这套规则配不配进现役"，**不是**扣预算的账。
    # 扣预算必须在**标定池**上量（`sup_target = target - rules_fpr` 两个数得同源），
    # 那个数由下面 thresholds.py 自己算，我们不传 --rule-fpr 去覆盖它。
    budget = measure_budget(cand)
    fpr_broad = float(budget.get("fpr_upper_95") or 0.0)
    if budget.get("block_rules", 0) and fpr_broad <= 0.0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError("存在 block 规则但没有量到 FPR —— 拒绝提升（宁可不做，不可猜）")
    if fpr_broad > cap:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError(
            f"阻断预算超限：规则在真良性池上的 FPR 上界 {fpr_broad:.5%} > 上限 {cap:.3%}"
            f"（命中 {budget.get('benign_hits')}/{budget.get('benign_n')}）。"
            "要么把部分规则改回 action=alert，要么收窄 scope，要么提高上限。"
        )

    pol_before = _read_json(config.POLICY_JSON) or {}
    # ⚠️ 顶层 `zero_day_enabled` 才是开关；没有 `zero_day.enabled` 这个键。
    #    读错键会让"提升规则"顺手把零日通道关掉，而这种静默降级没人会发现。
    zero_day_on = bool(pol_before.get("zero_day_enabled"))
    cur_fpr = str((pol_before.get("supervised") or {}).get("target_fpr") or "0.01")
    src = (pol_before.get("calibration_pool") or {}).get("source") or "csic"
    old_ver = int(pol_before.get("version") or 0)

    # ---- 3. 原子装上新规则集（备份旧文件）----
    # 为什么先装文件、再跑 thresholds.py：策略里要写**最终路径**的 sha1，
    # 拿临时路径写进去就成了悬空引用（下次热重载一验就失败）。
    # 装文件到写策略之间有一个窗口："新规则文件 + 旧策略" ⇒ 指纹不符 ⇒
    # 采集器把规则通道当**未启用**（宁少拦、不多拦）。这个方向是安全的。
    had_rules = config.RULES_AUTHORITATIVE.exists()
    backup_rules = None
    if had_rules:
        backup_rules = str(config.RULES_AUTHORITATIVE) + ".bak"
        shutil.copy2(str(config.RULES_AUTHORITATIVE), backup_rules)
    try:
        # 候选在 %TEMP%（C:），现役在 F: —— Windows 的 os.replace 不能跨盘。
        # 先落到**同盘同目录**的 .staging，再原子 rename（同一文件系统内才是原子的）。
        staging = str(config.RULES_AUTHORITATIVE) + ".staging"
        shutil.copy2(cand, staging)
        os.replace(staging, str(config.RULES_AUTHORITATIVE))
    except OSError as e:
        if backup_rules and os.path.exists(backup_rules):
            shutil.copy2(backup_rules, str(config.RULES_AUTHORITATIVE))
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError(f"写入现役规则集失败（未改动任何状态）：{e}")

    def _restore(reason: str) -> None:
        """把规则集与策略都退回提升前的状态（失败时**不留半成品**）。"""
        if backup_rules and os.path.exists(backup_rules):
            shutil.copy2(backup_rules, str(config.RULES_AUTHORITATIVE))
        elif not had_rules and config.RULES_AUTHORITATIVE.exists():
            config.RULES_AUTHORITATIVE.unlink()
        if pol_before:
            tmp_pol = str(config.POLICY_JSON) + ".restore.tmp"
            with open(tmp_pol, "w", encoding="utf-8") as f:
                json.dump(pol_before, f, ensure_ascii=False, indent=2)
            os.replace(tmp_pol, str(config.POLICY_JSON))
        print(f"[promote] 已回滚（{reason}）", file=sys.stderr)

    # ---- 4. 重跑标定：写 rules 块 + 从监督目标里**实测**扣减 ----
    cmd = [sys.executable, str(config.PY / "thresholds.py"),
           "--pool", _pool_from_source(str(src)), "--fpr", cur_fpr,
           "--zero-day", "on" if zero_day_on else "off",
           "--rules", str(config.RULES_AUTHORITATIVE),
           "--rule-budget-cap", f"{cap!r}",
           # 不做就地刷新：promote 后面会用 export_testvec.py **重导出**（含逐样本
           # 规则证据）。就地刷新只能改阈值，改不了证据，而这里两个都变了。
           "--no-testvec",
           "--version", str(old_ver + 1)]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        pr = subprocess.run(cmd, cwd=str(config.PY), capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=1800, env=env)
    except Exception as e:
        _restore(f"thresholds.py 调用异常：{e}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError(f"标定失败（策略与规则集均已回滚）：{e}")
    if pr.returncode != 0:
        _restore("thresholds.py 失败")
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError("thresholds.py 失败（策略与规则集均已回滚）：\n"
                         + (pr.stdout or "") + (pr.stderr or ""))

    # ---- 5. 重导出 testvec（阈值变了 + 规则证据变了）----
    # 这里**不能**靠 thresholds.py 的就地刷新：规则证据是逐样本的，
    # 只有 export_testvec.py 会调 `waf-ai-proto rules replay` 去取。
    pe = subprocess.run([sys.executable, str(config.PY / "export_testvec.py")],
                        cwd=str(config.PY), capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=1800, env=env)
    if pe.returncode != 0:
        _restore("export_testvec.py 失败")
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError("export_testvec.py 失败（策略与规则集均已回滚）：\n"
                         + (pe.stdout or "") + (pe.stderr or ""))

    new_pol = _read_json(config.POLICY_JSON) or {}
    rb = new_pol.get("rules") or {}
    fpr_same_pool = float(rb.get("budget_deducted") or 0.0)
    tgt = float(rb.get("nominal_target_fpr") or cur_fpr)
    sup_after = float(rb.get("sup_target_fpr") or tgt)

    db.execute(
        "INSERT OR REPLACE INTO policy_versions(version, json, actor, created_at, note) VALUES(?,?,?,?,?)",
        (int(new_pol.get("version") or 1), json.dumps(new_pol, ensure_ascii=False),
         actor, db.now_ms(),
         note or (f"提升规则集（标定池上扣减预算 {fpr_same_pool:.5%}；"
                  f"宽池预检 {fpr_broad:.5%}）")),
    )
    if backup_rules and os.path.exists(backup_rules):
        try:
            os.unlink(backup_rules)
        except OSError:
            pass
    shutil.rmtree(tmpdir, ignore_errors=True)

    bh = budget.get("benign_hits")
    bn = budget.get("benign_n")
    return {
        "policy": new_pol,
        "ruleset": {k: v for k, v in doc.items() if k != "rules"},
        "ruleset_sha1_16": rules_mod.authoritative_sha1_16(),
        "budget": {
            **budget, "cap": cap,
            # 两个数**故意**分开报：宽池预检回答"这套规则安不安全"，
            # 标定池扣减回答"从监督通道拿走多少预算"。混成一个数就会有人拿
            # 宽池的值去对账，然后发现对不上。
            "fpr_broad_pool_upper_95": fpr_broad,
            "fpr_calibration_pool_deducted": fpr_same_pool,
            "sup_target_before": tgt, "sup_target_after": sup_after,
        },
        "log": (pr.stdout or "")[-6000:] + "\n[export_testvec]\n" + (pe.stdout or "")[-3000:],
        "checklist": {
            "testvec": "export_testvec.py 已重跑（含逐样本规则证据 + 三通道融合动作）",
            "rust_gate": r"必须重跑 F:\waf\rust\build.bat run --release，确认门禁全绿",
            "hot_reload": "采集器每 5s 轮询 policy + rules 的 sha1，校验通过才原子换；无需重启",
            "note": (f"规则命中 {bh}/{bn}（宽良性池）；标定池扣减 {fpr_same_pool:.5%}，"
                     f"监督目标 {tgt:.4%} -> {sup_after:.4%}，融合阻断 FPR 维持不变"),
        },
    }


def _pool_from_source(source: str) -> str:
    if source.startswith("file:"):
        return source
    if "csic" in source:
        return "csic"
    if "lexical" in source:
        return "lexical"
    return "csic"
