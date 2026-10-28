"""工作项 F0 spike：用 CIC-IDS2017 检验**流级特征**到底能不能区分攻击。

这一步只回答一个问题：**流级特征设计有没有希望**。
  * 如果连同分布内（随机切分）都分不开 ⇒ 流级特征设计有问题，不必等真实本地流量；
  * 如果同分布能分开、但**跨文件**（换一天的数据）就崩 ⇒ 说明真正的难点是分布漂移，
    和 HTTP 通道遇到的问题同源，需要在采集点/特征上做域适配，而不是加特征。

协议（两种，都报）：
  A. `random`   : 8 个文件合并后随机 70/30 切分 —— **乐观**，会重复流量/同一天同攻击，
                  只用来回答"有没有可分性"。
  B. `cross-file`: 留出 2 个文件不参与训练，用它们做测试 —— **诚实**，
                  直接暴露跨分布退化。

特征：
  * 去掉 `Flow ID`（本发布已无 IP/时间戳列，无身份泄漏）；
  * inf/-inf → NaN 后丢掉含 NaN 的行（周三文件有 inf，必须处理）；
  * 另报一版**去掉 `Destination Port`** 的结果 —— 端口对 PortScan 类几乎是泄漏特征，
    不剔除会把结论抬高。

产出 `artifacts/p5_flow.json`。

用法：
    py -3.10 p5_flow_spike.py                 # 抽样 ~每次 20 行取 1 行
    py -3.10 p5_flow_spike.py --stride 40     # 更小样本
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
CIC = os.path.abspath(os.path.join(HERE, "..", "traindata", "CIC-IDS2017"))
OUT_JSON = os.path.join(ART, "p5_flow.json")

DROP_ALWAYS = {"Flow ID", "Fwd Header Length.1"}      # 重复列
LEAK_COLS = {"Destination Port"}                      # 端口泄漏（PortScan）


def group_label(raw: str) -> str:
    l = str(raw).strip().lower()
    if l == "benign":
        return "BENIGN"
    if "web attack" in l:
        return "WebAttack"
    if "patator" in l:
        return "BruteForce"
    if "portscan" in l:
        return "PortScan"
    if l.startswith("ddos"):
        return "DDoS"
    if l.startswith("dos"):
        return "DoS"
    if l == "bot":
        return "Bot"
    if "infiltration" in l:
        return "Infiltration"
    if "heartbleed" in l:
        return "Heartbleed"
    return str(raw).strip()


def load_frames(stride: int):
    import pandas as pd
    files = sorted(f for f in os.listdir(CIC) if f.endswith(".csv"))
    frames = []
    stats = {}
    for fn in files:
        p = os.path.join(CIC, fn)
        df = pd.read_csv(p, skiprows=lambda i: i > 0 and (i % stride) != 0,
                         low_memory=False)
        df.columns = [str(c).strip() for c in df.columns]
        lab_col = "Label"
        df["_label"] = [group_label(v) for v in df[lab_col]]
        df["_file"] = fn.split("-WorkingHours")[0]
        frames.append(df)
        stats[fn] = {"rows_sampled": int(len(df)),
                     "label_counts": dict(collections.Counter(df["_label"]))}
        print(f"  [load] {fn:<52} sampled={len(df):>7,}  "
              f"{dict(collections.Counter(df['_label']).most_common(6))}")
    return frames, stats


def build_xy(df, drop_leak: bool):
    import pandas as pd
    drop = set(DROP_ALWAYS)
    if drop_leak:
        drop |= LEAK_COLS
    feats = [c for c in df.columns if c not in drop
             and c not in ("_label", "_file", "Label")]
    X = df[feats].replace([np.inf, -np.inf], np.nan)
    y = df["_label"]
    return X, y, feats


def fit_eval(Xtr, ytr, Xte, yte, feats, depth=6, rounds=200):
    import xgboost as xgb
    ytr_b = (ytr != "BENIGN").astype(int)
    yte_b = (yte != "BENIGN").astype(int)
    clf = xgb.XGBClassifier(
        n_estimators=rounds, max_depth=depth, learning_rate=0.15,
        subsample=0.8, colsample_bytree=0.8, tree_method="hist",
        n_jobs=os.cpu_count(), eval_metric="logloss", random_state=42,
    )
    clf.fit(Xtr[feats], ytr_b)
    p = clf.predict_proba(Xte[feats])[:, 1]

    from sklearn.metrics import roc_auc_score
    auc = float(roc_auc_score(yte_b, p)) if len(set(yte_b)) > 1 else float("nan")

    ben = p[yte_b == 0]
    thr = float(np.quantile(ben, 0.99)) if len(ben) else 1.0
    actual_fpr = float((ben >= thr).mean()) if len(ben) else 0.0

    per_class = {}
    for cls in sorted(set(yte)):
        if cls == "BENIGN":
            continue
        m = (yte == cls).to_numpy()
        per_class[cls] = {"n": int(m.sum()),
                          "det@1%FPR": float((p[m] >= thr).mean()) if m.sum() else None}

    imp = sorted(zip(feats, clf.feature_importances_), key=lambda kv: -kv[1])[:15]
    return {"auc": auc, "threshold": thr, "actual_fpr": actual_fpr,
            "attack_tpr_at_thr": float((p[yte_b == 1] >= thr).mean()),
            "n_train": int(len(Xtr)), "n_test": int(len(Xte)),
            "per_class": per_class,
            "top_features": [[f, float(v)] for f, v in imp]}, clf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stride", type=int, default=20,
                    help="每 N 行取 1 行（越大越快、样本越小）")
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--holdout", default="Thursday,Friday",
                    help="cross-file 模式下留出的文件前缀（逗号分隔）")
    ap.add_argument("--out", default=OUT_JSON)
    args = ap.parse_args()

    import pandas as pd  # noqa: F401
    t0 = time.time()
    print(f"[cic] 抽样 stride={args.stride}（每 {args.stride} 行取 1 行）")
    frames, load_stats = load_frames(args.stride)
    df = pd.concat(frames, ignore_index=True)
    df = df.drop(columns=[c for c in DROP_ALWAYS if c in df.columns])
    print(f"[cic] 合并样本 n={len(df):,}  标签分布="
          f"{dict(collections.Counter(df['_label']).most_common())}\n")

    report = {
        "dataset": "CIC-IDS2017",
        "stride": args.stride,
        "n_sampled": int(len(df)),
        "label_counts": {k: int(v) for k, v in collections.Counter(df["_label"]).items()},
        "per_file": load_stats,
        "protocols": {},
        "note": ("spike 用；只回答'流级特征有没有可分性'，不产出上线工件。"
                 "random 切分乐观，cross-file 才是诚实口径。"),
    }

    for drop_leak in (False, True):
        tag = "drop_port" if drop_leak else "with_port"
        X, y, feats = build_xy(df, drop_leak)
        ok = X.notna().all(axis=1)
        X, y = X[ok], y[ok].reset_index(drop=True)
        X = X.reset_index(drop=True)

        # A. random 70/30
        rng = np.random.default_rng(7)
        perm = rng.permutation(len(X))
        cut = int(len(X) * 0.7)
        tr, te = perm[:cut], perm[cut:]
        ra, _ = fit_eval(X.iloc[tr], y.iloc[tr], X.iloc[te], y.iloc[te], feats,
                         rounds=args.rounds)
        report["protocols"][f"random/{tag}"] = ra
        print(f"[A random/{tag:<10}] n={ra['n_train']:,}/{ra['n_test']:,}  "
              f"AUC={ra['auc']:.4f}  攻击TPR@1%FPR={ra['attack_tpr_at_thr']*100:.1f}%  "
              f"实际FPR={ra['actual_fpr']*100:.2f}%")

        # B. cross-file：留出的文件整段不进训练
        hold = [h for h in args.holdout.split(",") if h]
        is_hold = df.loc[ok, "_file"].isin(hold).reset_index(drop=True)
        btr, bte = ~is_hold, is_hold
        if bte.sum() and btr.sum() and y[bte].nunique() > 1:
            rb, _ = fit_eval(X[btr], y[btr], X[bte], y[bte], feats, rounds=args.rounds)
            rb["held_out_files"] = hold
            report["protocols"][f"cross-file/{tag}"] = rb
            print(f"[B cross/{tag:<10}] 留出 {hold}  n={rb['n_train']:,}/{rb['n_test']:,}  "
                  f"AUC={rb['auc']:.4f}  攻击TPR@1%FPR={rb['attack_tpr_at_thr']*100:.1f}%")
            for cls, v in sorted(rb["per_class"].items()):
                if v["det@1%FPR"] is not None:
                    print(f"        {cls:<14} n={v['n']:>7,}  det@1%FPR="
                          f"{v['det@1%FPR']*100:5.1f}%")
        print()

    # 结论
    ra = report["protocols"].get("random/drop_port") or {}
    rb = report["protocols"].get("cross-file/drop_port") or {}
    report["verdict"] = {
        "separable_in_distribution": (ra.get("auc") or 0) > 0.95,
        "auc_random": ra.get("auc"),
        "auc_cross_file": rb.get("auc"),
        "cross_file_gap": ((ra.get("auc") or 0) - (rb.get("auc") or 0)),
        "conclusion": ("同分布可分（AUC 高）并不等于能用：跨文件 AUC 掉多少才决定"
                       "流级通道值不值得做；掉得越多，越说明瓶颈是分布漂移而非特征不够。"),
    }

    os.makedirs(ART, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[verdict] 同分布 AUC={report['verdict']['auc_random']}  "
          f"跨文件 AUC={report['verdict']['auc_cross_file']}  "
          f"gap={report['verdict']['cross_file_gap']}")
    print(f"[json] -> {os.path.relpath(args.out, HERE)}   ({time.time()-t0:.1f}s)")


if __name__ == "__main__":
    main()
