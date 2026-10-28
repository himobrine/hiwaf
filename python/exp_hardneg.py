"""实验：加入"困难良性负样本"能否把 FPR 压下来？

假设：lexical 困难集里的 1000 条正常样本是**长英文文本**，
而 payload_train 的正常样本几乎都是短值（地址/编号/邮箱）。
模型从未见过长文本正常样本 → 对其产生大量误报（argmax FPR 34%）。
这不是特征归一化能解决的，而是**训练分布覆盖问题（OOD）**。

三个对照组，评估集固定为「lexical 正常的后一半 + lexical 全部异常」：
  A 基线        ：只用 payload_train
  B +CSIC 正常  ：payload_train + CSIC 2010 正常流量（真实、无泄漏、但非长文本）
  C +长文正常   ：payload_train + lexical 正常的前一半（同分布自适应，后一半留出评估）

评估：argmax 正常误报率、以及 @FPR=1%/3% 的异常检测率。
"""
from __future__ import annotations

import json
import os

import numpy as np

from dataset import LABELS
from features import FeatureExtractor
from realdata import TRAINDATA, load_csic, load_payloads
from train_realdata import class_weights, detect_at_fpr, to_X


def fit_eval(Xtr, ytr, sets, rounds=400, depth=8, lr=0.1):
    import xgboost as xgb

    w, _ = class_weights(ytr, len(LABELS))
    clf = xgb.XGBClassifier(n_estimators=rounds, max_depth=depth, learning_rate=lr,
                            subsample=0.9, colsample_bytree=0.9,
                            objective="multi:softprob", num_class=len(LABELS),
                            tree_method="hist", n_jobs=os.cpu_count(), random_state=42)
    clf.fit(Xtr, ytr, sample_weight=w, verbose=False)
    out = {}
    for name, (X, y) in sets.items():
        p = clf.predict_proba(X)
        normal = list(clf.classes_).index(0)
        s = 1.0 - p[:, normal]
        ya = y != 0
        pred = clf.predict(X)
        rec = {
            "n": int(len(y)),
            "argmax_fpr": float((pred[~ya] != 0).mean()) if (~ya).any() else float("nan"),
            "argmax_acc": float((pred == y).mean()),
        }
        for f in (0.01, 0.03, 0.05):
            dr, fpr = detect_at_fpr(s, ya, f)
            rec[f"detect@fpr{f:g}"] = float(dr)
        out[name] = rec
    return out


def main():
    tr = load_payloads(os.path.join(TRAINDATA, "payload_train.csv"))
    te = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))

    fx = FeatureExtractor()
    ytr = np.asarray([s["label"] for s in tr])
    Xtr = to_X(fx, tr)

    yl = np.asarray([s["label"] for s in lex])
    lex_norm = np.where(yl == 0)[0]
    lex_atk = np.where(yl != 0)[0]
    rng = np.random.RandomState(11)
    rng.shuffle(lex_norm)
    ln_train, ln_eval = lex_norm[:500], lex_norm[500:]

    # 评估集（三个对照组完全一致）
    eval_idx = np.concatenate([ln_eval, lex_atk])
    Xev = to_X(fx, [lex[i] for i in eval_idx])
    yev = yl[eval_idx]
    sets = {"lexical(held-out)": (Xev, yev),
            "payload_test": (to_X(fx, te), np.asarray([s["label"] for s in te]))}

    results = {}

    print("[A] 基线：只用 payload_train")
    results["A_baseline"] = fit_eval(Xtr, ytr, sets)

    print("[B] + CSIC 2010 正常流量 8,000 条（真实良性，无泄漏）")
    csic_reqs, csic_y = load_csic()
    csic_norm = [r for r, v in zip(csic_reqs, csic_y) if v == 0][:8000]
    Xb = np.vstack([Xtr, to_X(fx, csic_norm)])
    yb = np.concatenate([ytr, np.zeros(len(csic_norm), dtype=ytr.dtype)])
    results["B_plus_csic_normal"] = fit_eval(Xb, yb, sets)

    print("[C] + lexical 正常前一半 500 条（同分布自适应）")
    Xc = np.vstack([Xtr, to_X(fx, [lex[i] for i in ln_train])])
    yc = np.concatenate([ytr, np.zeros(len(ln_train), dtype=ytr.dtype)])
    results["C_plus_long_text_normal"] = fit_eval(Xc, yc, sets)

    print("\n" + "=" * 78)
    print("对照结果（评估集：lexical 后一半正常 500 + 异常 106）")
    print("=" * 78)
    hdr = f"{'arm':<26}{'argmax_FPR':>12}{'argmax_acc':>12}{'det@1%':>9}{'det@3%':>9}{'det@5%':>9}"
    for name in results:
        r = results[name]["lexical(held-out)"]
        print(hdr if name == "A_baseline" else "", end="")
        print(f"{name:<26}{r['argmax_fpr']:>12.3f}{r['argmax_acc']:>12.3f}"
              f"{r['detect@fpr0.01']:>9.3f}{r['detect@fpr0.03']:>9.3f}{r['detect@fpr0.05']:>9.3f}")
    print("\npayload_test（对照组间应基本不变）")
    for name in results:
        r = results[name]["payload_test"]
        print(f"  {name:<26} acc={r['argmax_acc']:.4f} argmax_FPR={r['argmax_fpr']:.4f}")

    with open(os.path.join("artifacts", "exp_hardneg.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("\n-> artifacts/exp_hardneg.json")


if __name__ == "__main__":
    main()
