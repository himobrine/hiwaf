"""真实流量实测（工作项 F 采集 → S8 真实攻击召回 / S9 零日跨分布）。

用**真实**流量回答三个问题，不做任何合成数据、不拿旧分布硬调参：

    Q1  现役产物（XGB 监督 + CSIC 训练的零日 IF + decision_policy.json 阈值）
        在真实流量上是什么表现？
        ⚠️ 若策略里 `zero_day_enabled=false`（**当前默认**），零日通道不参与融合，
        `alert` 恒为 0；脚本仍打印其**原始穿阈**率作为诊断，但不再把它当动作报告。
    Q2  阈值若改在**真实本地良性**上标定，会漂多少？（本机池只有 ~190 条，结论只能定性）
    Q3  按 S9 处方「用真实本地良性重训零日通道」，跨分布误报是否下降？代价是什么？

## 数据（全部真实，来源见 traindata/local/*_report.json）

| 文件 | n | 性质 | 能回答什么 |
|---|---|---|---|
| `local_lab_benign.jsonl` | 190 | 本机 phpStudy 访问日志，真实用户浏览 | 真实**本地**误报率 |
| `inwild_attack.jsonl` | 12 | 公网服务器 error log 里挖出的在野攻击 URL（IOC 标注） | 真实在野攻击检出（n 极小） |
| `inwild_benign.jsonl` | 105,730 | 同一服务器的 error log 请求 | **命中率**，不是误报率 |

> ⚠️ `inwild_*` 是**公网服务器**的日志：里面混着大量扫描器探测（404 找 webshell / `.htpasswd` /
> `wp-login.php` …）。所以：
> * 它**不能**当良性池标定阈值（会把真攻击算成正常 → 阈值偏高 → 漏报）；
> * 它的"命中率"高是**好事**（多半本来就是敌意流量），但**不能**报成 FPR。
> 干净的良性池只有 `local_lab_benign.jsonl`（本机自己的浏览日志）。

用法：

    py -3.10 p4_local.py
    py -3.10 p4_local.py --local-iforest artifacts/iforest_lean_local_001.onnx
"""
from __future__ import annotations

import argparse
import json
import math
import os
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
LOCAL = os.path.abspath(os.path.join(HERE, "..", "traindata", "local"))

POLICY = os.path.join(ART, "decision_policy.json")
OUT_JSON = os.path.join(ART, "p4_local.json")
LOCAL_IF = os.path.join(ART, "iforest_lean_local_001.onnx")


def wilson(k: int, n: int, z: float = 1.96):
    """Wilson 区间（小样本比例不能正态近似）。"""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def load_jsonl(path):
    from realdata import load_local_jsonl
    return load_local_jsonl(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local-iforest", default=LOCAL_IF,
                    help="Q3：真实本地良性重训的零日通道 onnx（默认 artifacts/iforest_lean_local_001.onnx）")
    ap.add_argument("--lab", default=os.path.join(LOCAL, "local_lab_benign.jsonl"))
    ap.add_argument("--attack", default=os.path.join(LOCAL, "inwild_attack.jsonl"))
    ap.add_argument("--inwild", default=os.path.join(LOCAL, "inwild_benign.jsonl"))
    args = ap.parse_args()

    for p in (POLICY, args.lab, args.attack):
        if not os.path.exists(p):
            raise SystemExit(f"缺文件：{p}")

    with open(POLICY, "r", encoding="utf-8") as f:
        policy = json.load(f)
    sup_thr = policy["supervised"]["threshold"]
    zd_thr = policy["zero_day"]["threshold"]
    fpr = policy["supervised"]["target_fpr"]
    # 零日通道总开关（策略文件顶层，缺省 True）。关闭时零日分数照算留证，
    # 但**不参与融合** -> 不可能产生 alert。这里必须尊重它，否则会把一个
    # 结构上不可能发生的动作（alert）报成"实测 2.63%"。
    zd_enabled = bool(policy.get("zero_day_enabled", True))
    with open(os.path.join(ART, "xgboost_meta.json"), "r", encoding="utf-8") as f:
        meta = json.load(f)
    normal_idx = next((int(k) for k, v in (meta.get("labels") or {}).items() if v == "normal"), 0)

    from features import FeatureExtractor
    from thresholds import xgb_scores, iforest_scores
    fx = FeatureExtractor()

    lab = load_jsonl(args.lab)
    atk = load_jsonl(args.attack)
    inw = load_jsonl(args.inwild) if os.path.exists(args.inwild) else []

    print(f"[policy] {os.path.basename(POLICY)}  v{policy['version']}  "
          f"标定池={policy['calibration_pool']['name']} (n={policy['calibration_pool']['n']:,})")
    print(f"[policy] 目标 FPR={fpr}  监督阈值={sup_thr:.6f}  零日阈值={zd_thr:.6f}")
    print(f"[policy] 零日通道 = {'启用' if zd_enabled else '**关闭**（安全降级）'}"
          + ("" if zd_enabled else "：分数照算留证，但不参与融合 ⇒ 不会产生 alert\n"))

    t0 = time.time()
    sets = {"local_benign": lab, "inwild_attack": atk}
    if inw:
        sets["inwild_all"] = inw
    scores = {}
    for name, reqs in sets.items():
        s_sup = xgb_scores(reqs, fx, normal_idx)
        s_zd = iforest_scores(reqs, fx)
        scores[name] = (s_sup, s_zd)
    print(f"[score] 现役产物打分完成 ({time.time()-t0:.1f}s)\n")

    report = {"policy": {"version": policy["version"], "target_fpr": fpr,
                         "supervised_threshold": sup_thr, "zero_day_threshold": zd_thr,
                         "zero_day_enabled": zd_enabled,
                         "calibration_pool": policy["calibration_pool"]},
              "datasets": {}}

    def summarize(name, reqs, label_note):
        s_sup, s_zd = scores[name]
        sf = s_sup >= sup_thr
        zf = s_zd >= zd_thr                       # 原始穿阈（诊断用，与开关无关）
        zf_eff = zf & zd_enabled                  # 生效命中（参与融合）
        act = {"block": int((sf).sum()), "alert": int((~sf & zf_eff).sum()),
               "allow": int((~sf & ~zf_eff).sum())}
        n = len(reqs)
        rec = {
            "n": n, "note": label_note,
            "zero_day_enabled": zd_enabled,
            "supervised_flag": int(sf.sum()), "supervised_rate": float(sf.mean()),
            "zero_day_flag": int(zf.sum()), "zero_day_rate": float(zf.mean()),
            "zero_day_crossing_rate": float(zf.mean()),
            "action": act,
            "action_rate": {k: v / n for k, v in act.items()},
            "supervised_score": {"min": float(s_sup.min()), "p50": float(np.median(s_sup)),
                                 "p90": float(np.quantile(s_sup, .90)), "max": float(s_sup.max())},
            "zero_day_score": {"min": float(s_zd.min()), "p50": float(np.median(s_zd)),
                               "max": float(s_zd.max())},
        }
        return rec

    report["datasets"]["local_benign"] = summarize(
        "local_benign", lab, "真实本地良性（干净池）→ 这两个比率才是**真实误报率**")
    report["datasets"]["inwild_attack"] = summarize(
        "inwild_attack", atk, "真实在野攻击 → 这两个比率是**真实攻击检出率**（n 极小）")
    if inw:
        report["datasets"]["inwild_all"] = summarize(
            "inwild_all", inw, "公网服务器在野流量（混有扫描器探测）→ 只能叫**命中率**，不是 FPR")

    print("=" * 78)
    print("Q1  现役产物在真实流量上的表现")
    print("=" * 78)
    for name, tag in (("local_benign", "真实本地良性"), ("inwild_attack", "真实在野攻击"),
                      ("inwild_all", "公网在野流量(混扫描器)")):
        if name not in report["datasets"]:
            continue
        d = report["datasets"][name]
        print(f"\n[{tag}]  n={d['n']:,}")
        print(f"  监督通道命中 {d['supervised_flag']:>6,}  ({d['supervised_rate']*100:6.2f}%)"
              f"   零日通道命中 {d['zero_day_flag']:>6,}  ({d['zero_day_rate']*100:6.2f}%)"
              + ("" if zd_enabled else "  ← 零日已**关闭**，仅供诊断"))
        a = d["action_rate"]
        print(f"  融合动作   block {a['block']*100:6.2f}%   alert {a['alert']*100:6.2f}%"
              f"   allow {a['allow']*100:6.2f}%"
              + ("" if zd_enabled else "   ← alert 恒为 0（零日通道已安全降级）"))
        if name == "inwild_attack":
            k = d["supervised_flag"]
            p, lo, hi = wilson(k, d["n"])
            print(f"  → 监督通道真实检出 {k}/{d['n']} = {p*100:.1f}% "
                  f"(95% Wilson {lo*100:.1f}–{hi*100:.1f}%)  ⚠️ n={d['n']}，区间宽到几乎无信息")
            k2 = d["zero_day_flag"]
            p2, lo2, hi2 = wilson(k2, d["n"])
            print(f"  → 零日通道**原始穿阈** {k2}/{d['n']} = {p2*100:.1f}% "
                  f"(95% Wilson {lo2*100:.1f}–{hi2*100:.1f}%)"
                  + ("" if zd_enabled else "  ← 仅诊断：该通道已关闭，不产生动作"))

    # ---------------------------------------------------------------- Q2
    print("\n" + "=" * 78)
    print("Q2  阈值改标定在真实本地良性池上会漂多少（池 ~190 条，仅定性）")
    print("=" * 78)
    s_sup_lab, s_zd_lab = scores["local_benign"]
    q2 = {"n_pool": len(s_sup_lab), "target_fpr": fpr}
    for ch, s, cur in (("supervised", s_sup_lab, sup_thr), ("zero_day", s_zd_lab, zd_thr)):
        newthr = float(np.quantile(s, 1.0 - float(fpr)))
        implied = float((s >= cur).mean())
        q2[ch] = {"policy_threshold": cur, "local_pool_threshold": newthr,
                  "policy_threshold_implied_fpr": implied,
                  "delta": newthr - cur,
                  "n_above_policy_threshold": int((s >= cur).sum())}
        print(f"  {ch:11s} 现役阈值 {cur:+.6f} → 本机池 1% 分为 {newthr:+.6f} "
              f"(Δ={newthr-cur:+.6f})")
        print(f"  {'':11s} 用现役阈值回代本机良性：{int((s>=cur).sum())}/{len(s)} = "
              f"{implied*100:.2f}% 命中")
    report["q2_recalibration_on_local"] = q2
    print(f"  ⚠️ 池只有 {len(s_sup_lab)} 条 → 1% 分位≈第 {max(1,int(len(s_sup_lab)*0.01))} 大的样本，"
          f"抖动极大；要拿它替换 policy 需先把池做到 ≥2,000 条。")

    # ---------------------------------------------------------------- Q3
    if os.path.exists(args.local_iforest):
        print("\n" + "=" * 78)
        print("Q3  用真实本地良性重训零日通道（S9 处方）")
        print("=" * 78)
        t1 = time.time()
        s_zd_local = iforest_scores(lab + atk + inw if inw else lab + atk, fx, args.local_iforest)
        n_lab, n_atk = len(lab), len(atk)
        zl_lab, zl_atk = s_zd_local[:n_lab], s_zd_local[n_lab:n_lab + n_atk]
        zl_inw = s_zd_local[n_lab + n_atk:] if inw else np.array([])
        # 在本地良性上定 1% 分位（注意：这些样本含它自己的留出集，仅作对照）
        thr_local = float(np.quantile(zl_lab, 1.0 - float(fpr)))
        q3 = {
            "onnx": os.path.relpath(args.local_iforest, HERE),
            "local_pool_threshold_at_target_fpr": thr_local,
            "local_benign_hit_rate": float((zl_lab >= thr_local).mean()),
            "inwild_attack_detect": float((zl_atk >= thr_local).mean()),
            "inwild_all_hit_rate": (float((zl_inw >= thr_local).mean()) if len(zl_inw) else None),
            "csic_trained_on_same_sets": {
                "local_benign_hit_rate_at_its_own_thr": float((s_zd_lab >= zd_thr).mean()),
                "inwild_attack_detect": float((scores["inwild_attack"][1] >= zd_thr).mean()),
            },
        }
        print(f"  本地重训零日通道 @本地池 1% 分位 ({thr_local:+.6f})：")
        print(f"    真实本地良性命中   {q3['local_benign_hit_rate']*100:6.2f}%  (目标 1%)")
        print(f"    真实在野攻击检出   {q3['inwild_attack_detect']*100:6.2f}%"
              f"  ({int((zl_atk>=thr_local).sum())}/{n_atk})")
        if len(zl_inw):
            print(f"    公网在野流量命中   {q3['inwild_all_hit_rate']*100:6.2f}%")
        print("  对照 —— CSIC 训练的现役零日通道（用它的 policy 阈值）：")
        print(f"    真实本地良性命中   {q3['csic_trained_on_same_sets']['local_benign_hit_rate_at_its_own_thr']*100:6.2f}%")
        print(f"    真实在野攻击检出   {q3['csic_trained_on_same_sets']['inwild_attack_detect']*100:6.2f}%")
        print("  ⚠️ 本地留出只有几十条，命中率噪声极大；这条通道按 S7 决议**只告警不阻断**"
              + ("" if zd_enabled else "，且当前 `zero_day_enabled=false` —— 连告警也不产生（上面的命中率是"
                                     "**原始穿阈**诊断值）") + "。")
        report["q3_local_iforest"] = q3
        print(f"  ({time.time()-t1:.1f}s)")
    else:
        print(f"\n[Q3] 未找到 {os.path.relpath(args.local_iforest, HERE)}；"
              f"先跑：py -3.10 iforest_lean_onnx.py --data local --benign "
              f"{os.path.relpath(args.lab, HERE)} --attack {os.path.relpath(args.attack, HERE)} --export")

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[out] {os.path.relpath(OUT_JSON, HERE)}")


if __name__ == "__main__":
    main()
