"""诊断 v2 特征在 lexical 困难集上的残留误报。"""
from __future__ import annotations

import os

import numpy as np

from dataset import LABELS
from features import FeatureExtractor
from realdata import TRAINDATA, load_payloads
from train_realdata import class_weights, to_X, TARGET_NAMES


def main():
    import xgboost as xgb

    tr = load_payloads(os.path.join(TRAINDATA, "payload_train.csv"))
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))

    fx = FeatureExtractor()
    Xtr = to_X(fx, tr)
    ytr = np.asarray([s["label"] for s in tr])
    w, _ = class_weights(ytr, len(LABELS))
    clf = xgb.XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1,
                            subsample=0.9, colsample_bytree=0.9,
                            objective="multi:softprob", num_class=len(LABELS),
                            tree_method="hist", n_jobs=os.cpu_count(), random_state=42)
    clf.fit(Xtr, ytr, sample_weight=w, verbose=False)

    Xl = to_X(fx, lex)
    yl = np.asarray([s["label"] for s in lex])
    pred = clf.predict(Xl)
    d = [dict(zip(fx.names, row)) for row in Xl]

    norm = yl == 0
    fp = norm & (pred != 0)
    print(f"lexical 正常 {norm.sum()} 条，误报 {fp.sum()} 条 ({100*fp.sum()/norm.sum():.1f}%)")

    keys = ["sql_strong_present", "sql_strong_r", "sql_weak_r", "xss_strong_present",
            "xss_strong_r", "cmd_strong_present", "cmd_strong_r", "trav_strong_present",
            "num_tokens", "val_len_avg", "avg_token_len", "alpha_ratio", "quote_r",
            "val_special_r", "log_url_len"]
    groups = [("正常-判对", norm & (pred == 0)), ("正常-误报", fp),
              ("sql-syntax(真)", yl == 1), ("js-syntax(真)", yl == 2)]
    print(f"\n{'group':<16}" + "".join(f"{k[:13]:>14}" for k in keys))
    for name, m in groups:
        if m.sum() == 0:
            continue
        row = "".join(f"{np.mean([d[i][k] for i in np.where(m)[0]]):>14.4f}" for k in keys)
        print(f"{name:<16}{row}")

    print("\n--- 强关键词出现率 ---")
    for name, m in groups:
        idx = np.where(m)[0]
        if len(idx) == 0:
            continue
        sp = np.mean([d[i]["sql_strong_present"] for i in idx])
        xp = np.mean([d[i]["xss_strong_present"] for i in idx])
        cp = np.mean([d[i]["cmd_strong_present"] for i in idx])
        tp = np.mean([d[i]["trav_strong_present"] for i in idx])
        print(f"  {name:<16} sql={sp:.2f} xss={xp:.2f} cmd={cp:.2f} trav={tp:.2f}")

    imp = clf.feature_importances_
    order = np.argsort(imp)[::-1][:18]
    print("\n--- v2 特征重要性 Top-18 ---")
    for i in order:
        print(f"  {fx.names[i]:<20} {imp[i]:.4f}")

    print("\n--- lexical 正常误报样例 ---")
    for i in np.where(fp)[0][:6]:
        print(f"  [{TARGET_NAMES[pred[i]]}] sqlS={d[i]['sql_strong_r']:.3f} "
              f"sqlW={d[i]['sql_weak_r']:.3f} xss={d[i]['xss_strong_present']:.0f} "
              f"tok={d[i]['num_tokens']:.0f} :: {lex[i]['query'][:100]!r}")

    print("\n--- lexical 正常样例（判对的）---")
    for i in np.where(norm & (pred == 0))[0][:4]:
        print(f"  sqlS={d[i]['sql_strong_r']:.3f} tok={d[i]['num_tokens']:.0f} "
              f":: {lex[i]['query'][:100]!r}")

    print("\n--- lexical 全部 norm 原文（前 12 条，看数据到底是什么）---")
    for i in np.where(norm)[0][:12]:
        print(f"  {lex[i]['query'][:130]!r}")

    print("\n--- lexical anom 原文（前 6 条）---")
    for i in np.where(yl != 0)[0][:6]:
        print(f"  [{TARGET_NAMES[yl[i]]}] {lex[i]['query'][:130]!r}")


if __name__ == "__main__":
    main()
