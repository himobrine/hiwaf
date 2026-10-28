"""在 CSIC 2010 上评估 Isolation Forest 的"零日"检测能力。

设定（贴合 PRD 的无监督零日场景）：
  - 只用**正常流量**训练 IF（30,000），不看任何攻击标签
  - 用留出的正常样本（6,000）+ 异常样本（25,065）评估
  - 报告在 FPR = 0.1% / 1% / 5% 预算下的检测率

⚠️ CSIC 存在分布偏差（正常多为无参裸 GET；异常含 397 个 PUT 而正常为 0），
   因此额外报告**去偏子集**（仅保留带 query/body 的请求）的结果，
   以暴露"靠参数个数/方法就能分开"的虚高。
"""
from __future__ import annotations

import os

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from features import FeatureExtractor
from realdata import load_csic


def detect_at_fpr(score, is_attack, fpr_target):
    neg = score[~is_attack]
    thr = np.quantile(neg, 1.0 - fpr_target)
    tp = int(((score >= thr) & is_attack).sum())
    fp = int(((score >= thr) & ~is_attack).sum())
    fn = int(((score < thr) & is_attack).sum())
    tn = int(((score < thr) & ~is_attack).sum())
    return tp / max(1, tp + fn), fp / max(1, fp + tn)


def evaluate(name, score, is_attack, extra=""):
    auc = float(roc_auc_score(is_attack, score))
    print(f"\n=== {name}  (n={len(score)}, 正常={int((~is_attack).sum())}, "
          f"异常={int(is_attack.sum())}) {extra} ===")
    print(f"  AUC = {auc:.4f}")
    for f in (0.001, 0.01, 0.05):
        dr, fpr = detect_at_fpr(score, is_attack, f)
        print(f"  @FPR<={f*100:g}%  检测率={dr*100:5.1f}%   (实际FPR={fpr*100:.2f}%)")
    return auc


def main():
    print("[data] loading CSIC ...")
    reqs, y = load_csic()
    y = np.asarray(y)
    n_norm = int((y == 0).sum())
    print(f"[data] {len(reqs)} requests: normal={n_norm} anomaly={int((y==1).sum())}")

    fx = FeatureExtractor()
    X = np.asarray(fx.transform_batch(reqs), dtype=np.float32)
    print(f"[data] features: {X.shape}")

    # 正常样本切分：train IF / 留出评估
    rng = np.random.RandomState(7)
    norm_idx = np.where(y == 0)[0]
    rng.shuffle(norm_idx)
    n_train = 30000
    tr = norm_idx[:n_train]
    hold = norm_idx[n_train:]
    atk_idx = np.where(y == 1)[0]
    print(f"[data] IF train(normal)={len(tr)}  holdout(normal)={len(hold)}  anomaly={len(atk_idx)}")

    iso = IsolationForest(n_estimators=100, max_samples=256, random_state=42,
                          n_jobs=os.cpu_count()).fit(X[tr])

    def score_of(idx):
        return -iso.decision_function(X[idx])   # 越大越异常

    # ---- 全量评估 ----
    idx = np.concatenate([hold, atk_idx])
    is_atk = np.concatenate([np.zeros(len(hold), bool), np.ones(len(atk_idx), bool)])
    s = score_of(idx)
    evaluate("CSIC 全量（含分布偏差）", s, is_atk)

    # ---- 去偏子集：仅保留带 query 或 body 的请求 ----
    has_p = np.array([(bool(r["query"]) or bool(r["body"])) for r in reqs])
    idx2 = idx[has_p[idx]]
    is_atk2 = is_atk[has_p[idx]]
    s2 = s[has_p[idx]]
    evaluate("CSIC 去偏子集（仅带 query/body）", s2, is_atk2,
             extra="<-- 去掉'参数个数/裸GET'捷径")

    # ---- 只保留同时有 query 与 body 的部分（更严格）----
    both = np.array([(bool(r["query"]) and bool(r["body"])) for r in reqs])
    idx3 = idx[both[idx]]
    is_atk3 = is_atk[both[idx]]
    if len(idx3) > 100:
        evaluate("CSIC 更严格（query+body 都有）", s[both[idx]], is_atk3)

    # 归一化平均路径长度（供 Rust/精简导出对照）
    print(f"\n[ref] sklearn score_samples mean(normal)={iso.score_samples(X[hold]).mean():.4f} "
          f"mean(anomaly)={iso.score_samples(X[atk_idx]).mean():.4f}")

    # ---- 学习曲线：AUC / 检测率随 n_estimators 增长 ----
    from learning_curve import iforest_curve
    steps = [10, 25, 50, 100, 200]

    def factory(n, prev):
        if prev is None:
            m = IsolationForest(n_estimators=n, max_samples=256, warm_start=True,
                                random_state=42, n_jobs=os.cpu_count())
            m.fit(X[tr])
            return m
        prev.set_params(n_estimators=n)
        prev.fit(X[tr])
        return prev

    rec = iforest_curve(factory, X[hold], X[atk_idx], steps,
                        budget_fprs=(0.001, 0.01, 0.05), run="iforest_csic")
    paths = rec.save(meta={"features": "v2", "n_features": X.shape[1],
                           "train_normal": int(len(tr)), "holdout_normal": int(len(hold)),
                           "anomaly": int(len(atk_idx)), "dataset": "CSIC 2010"})
    print(f"[curve] -> artifacts/curves/iforest_csic_curve.json"
          + (", .png" if "png" in paths else ""))
    for n in steps:
        print(f"    n_estimators={n:<4} auc={dict(rec.series['iforest_auc'])[float(n)]:.4f}  "
              f"detect@1%fpr={dict(rec.series['iforest_detect@fpr0.01'])[float(n)]*100:.1f}%")


if __name__ == "__main__":
    main()
