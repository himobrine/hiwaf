"""在 HTTP Params 真实数据上评估 XGBoost 多分类。

- 训练：payload_train.csv（20,712）
- 测试：payload_test.csv（10,355，与训练**载荷完全不重叠**）
- 困难集：payload_test_lexical.csv（1,106，含"看起来像合法 SQL/JS"的样本）

输出：准确率 / macro-F1 / 每类 F1 / 混淆矩阵 / 二分类（正常 vs 攻击）检测率与误报率，
以及树的节点数（用于对比合成数据"树很浅"的现象）。
"""
from __future__ import annotations

import os

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

from dataset import LABELS
from features import FeatureExtractor
from realdata import TRAINDATA, load_payloads

TARGET_NAMES = [LABELS[i] for i in range(len(LABELS))]


def to_X(fx, samples):
    return np.asarray(fx.transform_batch(samples), dtype=np.float32)


def attack_prob(clf, X):
    p = clf.predict_proba(X)
    normal = list(clf.classes_).index(0)
    return 1.0 - p[:, normal]


def detect_at_fpr(score, is_attack, fpr_target):
    """在给定误报率预算下求检测率（阈值取自正常样本分位数）。"""
    neg = score[~is_attack]
    thr = np.quantile(neg, 1.0 - fpr_target)
    tp = int(((score >= thr) & is_attack).sum())
    fp = int(((score >= thr) & ~is_attack).sum())
    fn = int(((score < thr) & is_attack).sum())
    tn = int(((score < thr) & ~is_attack).sum())
    dr = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    return dr, fpr


def report(name, clf, X, y, attack_type):
    pred = clf.predict(X)
    acc = float((pred == y).mean())
    print(f"\n=== {name}  (n={len(y)}) ===")
    print(f"  accuracy = {acc:.4f}")
    present = sorted(set(y) | set(pred))
    rep = classification_report(y, pred, labels=present,
                                target_names=[TARGET_NAMES[i] for i in present],
                                output_dict=True, zero_division=0)
    print(f"  macro-F1 = {rep['macro avg']['f1-score']:.4f}")
    for i in present:
        r = rep[TARGET_NAMES[i]]
        print(f"    {TARGET_NAMES[i]:<10} P={r['precision']:.3f} R={r['recall']:.3f} F1={r['f1-score']:.3f} n={int(r['support'])}")
    print("  confusion (rows=true, cols=pred):",
          [TARGET_NAMES[i] for i in present])
    print(confusion_matrix(y, pred, labels=present))

    s = attack_prob(clf, X)
    ya = y != 0
    print(f"  二分类 正常 vs 攻击: AUC={_auc(ya, s):.4f}")
    for fpr_t in (0.001, 0.01, 0.05):
        dr, fpr = detect_at_fpr(s, ya, fpr_t)
        print(f"    @FPR<={fpr_t*100:g}%  检测率={dr*100:.1f}%  (实际FPR={fpr*100:.2f}%)")
    if attack_type is not None:
        import collections
        print("  attack_type breakdown:", dict(collections.Counter(attack_type)))
    return acc, rep["macro avg"]["f1-score"]


def _auc(y, s):
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, s))


def main():
    import xgboost as xgb

    tr = load_payloads(os.path.join(TRAINDATA, "payload_train.csv"))
    te = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))
    print(f"[data] train={len(tr)} test={len(te)} lexical={len(lex)}")

    fx = FeatureExtractor()
    Xtr = to_X(fx, tr)
    ytr = np.asarray([s["label"] for s in tr])

    # 类极不均衡 → 逆频率样本权重
    cnt = np.bincount(ytr, minlength=len(LABELS)).astype(np.float64)
    w = (len(ytr) / (len(LABELS) * np.maximum(cnt, 1)))[ytr]
    print("[data] class counts:", {TARGET_NAMES[i]: int(cnt[i]) for i in range(len(cnt))})

    clf = xgb.XGBClassifier(
        n_estimators=400, max_depth=8, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.9,
        objective="multi:softprob", num_class=len(LABELS),
        tree_method="hist", n_jobs=os.cpu_count(),
        eval_metric="mlogloss", random_state=42,
    )
    clf.fit(Xtr, ytr, sample_weight=w, verbose=False)

    booster = clf.get_booster()
    df = booster.trees_to_dataframe()
    n_nodes = len(df)
    n_trees = df["Tree"].nunique()
    depth = booster.get_dump(dump_format="json").__len__()
    print(f"\n[model] {n_trees} trees, {n_nodes} nodes "
          f"(avg {n_nodes/n_trees:.1f} nodes/tree)  <-- 对比合成数据 1000 树仅 3218 节点")

    report("HTTP Params TEST (disjoint)", clf, to_X(fx, te),
           np.asarray([s["label"] for s in te]),
           [s["attack_type"] for s in te])
    report("HTTP Params LEXICAL (hard)", clf, to_X(fx, lex),
           np.asarray([s["label"] for s in lex]),
           [s["attack_type"] for s in lex])
    del depth


if __name__ == "__main__":
    main()
