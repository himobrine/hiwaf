"""带 body vs 去 body：量化请求体对当前上线模型的贡献（回答"body 到底有没有用"）。

背景（这是本项目最容易被误判的一点）：
  * 特征契约 v2 **确实**读了 body（`features.py`: `low_all = url + " " + body`、
    `log_body_len`、`is_form_body`、参数值统计……）；
  * 但监督通道的训练集 `payload_train.csv` 是**纯载荷字符串**（字段只有
    payload/length/attack_type/label，无 method/path/body），`load_payloads` 把它统一包成
    `query="q=<payload>"`、`body=""`；lexical 正常样本同理。
    ⇒ 训练集里 `has_body` **恒为 0**，body 分支从未见过任何样本。
  * 结论前的正确态度：不要在 body 上做任何假设，**直接量**。

本脚本用**上线 ONNX**（artifacts/xgboost_v20261015_001.onnx + decision_policy.json）测四组：
  1. CSIC 正常（真实**良性**，含 8,000 条带 body）→ 看 body 会不会把良性抬成告警（误报代价）
  2. CSIC 异常（真实攻击，含 9,977 条带 body）          → 看 body 的检出增益
  3. datacon 官方标注=1（42 条，17 带 body，OOD）       → 跨分布下 body 的增益
  4. datacon 官方标注=0（58 条，23 带 body，**不是良性**）→ 单列，不参与 FPR

每条样本跑两遍：原样、`body=""`，比较 `score >= 策略阈值` 的判定翻转。

产出 `artifacts/p6_body_ablation.json`。

用法：
    py -3.10 p6_body_ablation.py
"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
LOCAL = os.path.abspath(os.path.join(HERE, "..", "traindata", "local"))
POLICY = os.path.join(ART, "decision_policy.json")
OUT_JSON = os.path.join(ART, "p6_body_ablation.json")


def wilson(k: int, n: int, z: float = 1.96):
    import math
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def _strip(reqs):
    return [{**r, "body": ""} for r in reqs]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=POLICY)
    ap.add_argument("--out", default=OUT_JSON)
    args = ap.parse_args()

    with open(args.policy, "r", encoding="utf-8") as f:
        policy = json.load(f)
    sup_thr = float(policy["supervised"]["threshold"])
    sup_fpr = policy["supervised"]["target_fpr"]
    zd_thr = float(policy["zero_day"]["threshold"])

    from features import FeatureExtractor
    from thresholds import xgb_scores, iforest_scores
    from realdata import load_datacon, load_csic
    from train_realdata import load_all

    with open(os.path.join(ART, "xgboost_meta.json"), "r", encoding="utf-8") as f:
        meta = json.load(f)
    labels = meta.get("labels") or {}
    normal_idx = next((int(k) for k, v in labels.items() if v == "normal"), 0)

    fx = FeatureExtractor()
    print(f"[policy] 监督阈值={sup_thr:.6f} (目标FPR={sup_fpr})  零日阈值={zd_thr:.6f}\n")

    # ---- 0. 训练集的 body 覆盖率（"模型从没见过 body"的硬证据）----
    tr, _, _, _, _ = load_all(hard_neg="lexical", seed=11, split_mode="random",
                              use_dict=False, dict_benign_ratio=1.0,
                              extra_benign=0, valid_frac=0.0)
    n_body_train = sum(1 for s in tr if (s.get("body") or "").strip())
    print(f"[coverage] 上线训练集 n={len(tr)}  其中带 body 的 = {n_body_train} 条")
    if n_body_train == 0:
        print("[coverage] ⇒ body 相关特征（has_body/log_body_len/is_form_body + body 文本）"
              "在训练中**恒为常量**，从未被拟合过。\n")

    # ---- 1. 准备四组样本 ----
    reqs, y = load_csic()
    csic_norm = [r for r, v in zip(reqs, y) if v == 0]
    csic_anom = [r for r, v in zip(reqs, y) if v == 1]

    d_train = load_datacon("train")
    d_test = load_datacon("test")
    d_atk = [r for r in (d_train + d_test) if r["label"] == 1]
    d_unk = [r for r in (d_train + d_test) if r["label"] != 1]

    sets = [
        ("csic_normal", csic_norm, "真实良性（CSIC 2010 正常流量）", "benign"),
        ("csic_anomaly", csic_anom, "真实攻击（CSIC 2010 异常流量）", "attack"),
        ("datacon_labeled", d_atk, "真实攻击（datacon 官方标注=1，OOD）", "attack"),
        ("datacon_unlabeled", d_unk, "官方未标注（**≠良性**，单列不参与 FPR）", "unknown"),
    ]

    report = {
        "score_def": policy["supervised"]["score_def"],
        "supervised_threshold": sup_thr,
        "target_fpr": sup_fpr,
        "zero_day_threshold": zd_thr,
        "training_body_coverage": {"n_train": len(tr), "n_with_body": n_body_train},
        "sets": {},
    }

    t0 = time.time()
    for name, reqs_s, desc, kind in sets:
        n = len(reqs_s)
        nb = sum(1 for r in reqs_s if (r.get("body") or "").strip())
        if n == 0:
            continue
        s_with = xgb_scores(reqs_s, fx, normal_idx)
        s_without = xgb_scores(_strip(reqs_s), fx, normal_idx)
        det_with = s_with >= sup_thr
        det_without = s_without >= sup_thr
        both = int((det_with & det_without).sum())
        only_with = int((det_with & ~det_without).sum())    # 靠 body 才检出
        only_without = int((~det_with & det_without).sum())  # body 反而压掉检出

        d = {
            "desc": desc, "kind": kind, "n": n, "n_with_body": nb,
            "hit_with_body": int(det_with.sum()),
            "hit_without_body": int(det_without.sum()),
            "rate_with_body": wilson(int(det_with.sum()), n),
            "rate_without_body": wilson(int(det_without.sum()), n),
            "only_with_body": only_with,
            "only_without_body": only_without,
            "both": both,
            "mean_score_with_body": float(np.mean(s_with)),
            "mean_score_without_body": float(np.mean(s_without)),
            "mean_score_delta": float(np.mean(s_with) - np.mean(s_without)),
        }
        # 只看带 body 的子集：body 的净影响
        if nb:
            idx = [i for i, r in enumerate(reqs_s) if (r.get("body") or "").strip()]
            hw = int(det_with[idx].sum())
            ho = int(det_without[idx].sum())
            d["body_subset"] = {
                "n": nb, "hit_with_body": hw, "hit_without_body": ho,
                "rate_with_body": wilson(hw, nb),
                "rate_without_body": wilson(ho, nb),
                "delta_hits": hw - ho,
            }
        # datacon 只做链路自检：决策已定 —— n=100 的"率"置信区间宽到无意义，
        # 任何引用都会被安全评审质疑（见 export_datacon.py 的 reportable 字段）。
        d["reportable"] = not name.startswith("datacon")
        if not d["reportable"]:
            d["reportable_reason"] = ("datacon 样本量过小：命中/检出只用于确认链路可用，"
                                      "**不得引用其召回率/准确率**")
        report["sets"][name] = d
    # ---- 2. 结论 ----
    n_ben = report["sets"]["csic_normal"]
    a_ben = report["sets"]["csic_anomaly"]
    d_atk_s = report["sets"]["datacon_labeled"]
    report["verdict"] = {
        "benign_fpr_with_body": n_ben["rate_with_body"],
        "benign_fpr_without_body": n_ben["rate_without_body"],
        "benign_body_subset": n_ben.get("body_subset"),
        "attack_lift_with_body": (a_ben["rate_with_body"][0] - a_ben["rate_without_body"][0]),
        "datacon_attack_lift_with_body": (d_atk_s["rate_with_body"][0]
                                          - d_atk_s["rate_without_body"][0]),
        "note": ("body 特征在训练中恒为常量 ⇒ 这里的收益/代价都是**外推**行为，"
                 "不是学出来的；任何要靠 body 才能检出的攻击，本质上都是运气。"),
    }

    os.makedirs(ART, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"{'集合':<18}{'n':>7}{'带body':>7}{'命中(带)':>10}{'命中(去)':>10}"
          f"{'检出率(带)':>18}{'检出率(去)':>18}")
    for name, d in report["sets"].items():
        rw, ro = d["rate_with_body"], d["rate_without_body"]
        print(f"{name:<18}{d['n']:>7}{d['n_with_body']:>7}{d['hit_with_body']:>10}"
              f"{d['hit_without_body']:>10}"
              f"{f'{rw[0]*100:.1f}% [{rw[1]*100:.1f},{rw[2]*100:.1f}]':>18}"
              f"{f'{ro[0]*100:.1f}% [{ro[1]*100:.1f},{ro[2]*100:.1f}]':>18}")
    print()
    non_rep = [n for n, d in report["sets"].items() if not d.get("reportable", True)]
    if non_rep:
        print("[⛔ 不可报告] " + "、".join(non_rep)
              + "：样本量过小，仅用于链路自检；**禁止**在评估报告里引用其召回率/准确率。"
                "OOD 评估请用 CSIC 2010（应用层）+ CIC-IDS2017（流级）。")
    for name, d in report["sets"].items():
        bs = d.get("body_subset")
        if not bs:
            continue
        print(f"[{name}] 只看带 body 的 {bs['n']} 条：带 body 命中 {bs['hit_with_body']}，"
              f"去掉 body 命中 {bs['hit_without_body']}（净变化 {bs['delta_hits']:+d}）")
    print(f"\n[json] -> {os.path.relpath(args.out, HERE)}   ({time.time()-t0:.1f}s)")


if __name__ == "__main__":
    main()
