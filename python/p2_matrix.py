"""P2：统一评估矩阵 —— 配方 × 数据集 × 切分。

回答三个问题：
  1. 官方配方（hard-neg lexical, 随机切分）的数字有多稳？（多 seed 抖动）
  2. 攻击字典增强（WEB_APPLICATION_PAYLOADS）值不值得？（cmdi 是最大受益类）
  3. 分组留出（同源不跨训练/评估）后，误报率到底是多少？（不乐观基准）

评估集（互相独立）：
  * payload_test        同分布、载荷零重叠（简单集）
  * lexical             困难集：留出一半正常 + 全部异常（验收门槛）
  * csic_normal_6000    CSIC 留出正常：n=6000，用来**收紧** FPR 估计
  * csic_anomaly        25,065 条真实异常（无子类标签）
  * datacon2025         **OOD** 真实流量：labeled=1 视为攻击，labeled=0 ≠ 良性（人工复核）

用法：
    py -3.10 p2_matrix.py
输出：
    artifacts/p2_matrix.json
"""
from __future__ import annotations

import json
import os
import time

import numpy as np

from dataset import LABELS
from features import FeatureExtractor
from realdata import (TRAINDATA, load_csic, load_datacon, load_payloads)
from train_realdata import (_lexical_halves, class_weights, detect_at_fpr,
                            load_all, to_X)

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
CSIC_FPR_POOL = 6000          # CSIC 正常留出池（取末尾，与训练用的最前面不重叠）
SEEDS = [11, 22, 33, 44, 55]
BUDGETS = (0.001, 0.01, 0.03, 0.05)


# ---------------------------------------------------------------------------
def fit(Xtr, ytr, Xval, yval, *, depth, rounds, es=0, mcw=1.0, lam=1.0,
        seed=42, curve=None, meta=None):
    import xgboost as xgb

    p = dict(n_estimators=rounds, max_depth=depth, learning_rate=0.1,
             subsample=0.9, colsample_bytree=0.9, min_child_weight=mcw,
             reg_lambda=lam, objective="multi:softprob", num_class=len(LABELS),
             tree_method="hist", n_jobs=os.cpu_count(),
             eval_metric=["mlogloss", "merror"], random_state=seed)
    if es:
        p["early_stopping_rounds"] = es
    w, _ = class_weights(ytr, len(LABELS))
    clf = xgb.XGBClassifier(**p)
    clf.fit(Xtr, ytr, sample_weight=w, verbose=False,
            eval_set=[(Xtr, ytr), (Xval, yval)])
    if curve:
        from learning_curve import CurveRecorder
        rec = CurveRecorder(curve)
        rec.from_evals_result(clf.evals_result(),
                              names={"validation_0": "train", "validation_1": "valid"})
        rec.save(meta=dict(meta or {}, depth=depth, rounds=rounds, es=es,
                           mcw=mcw, reg_lambda=lam))
    return clf


def evaluate(clf, X, y, thr_map=None):
    """返回 argmax 指标 + （可选）阈值校准指标。"""
    proba = clf.predict_proba(X)
    pred = proba.argmax(1)
    normal_col = list(clf.classes_).index(0)
    s = 1.0 - proba[:, normal_col]
    ya = y != 0
    out = {"n": int(len(y)), "n_normal": int((~ya).sum()), "n_attack": int(ya.sum()),
           "acc": float((pred == y).mean())}
    if (~ya).any():
        out["fpr_argmax"] = float((pred[~ya] != 0).mean())
    if ya.any() and (~ya).any():
        from sklearn.metrics import roc_auc_score
        out["auc"] = float(roc_auc_score(ya, s))
    if ya.any() and (~ya).any():
        for f in BUDGETS:
            dr, _ = detect_at_fpr(s, ya, f)
            out[f"det@fpr{f:g}"] = float(dr)
    if thr_map:
        for tag, thr in thr_map.items():
            if ya.any():
                out[f"det@{tag}"] = float(((s >= thr) & ya).sum() / max(1, ya.sum()))
            if (~ya).any():
                out[f"fpr@{tag}"] = float(((s >= thr) & ~ya).sum() / max(1, (~ya).sum()))
    return out, s


def print_row(tag, m, n_show=True):
    bits = [f"acc={m['acc']:.4f}"]
    if "fpr_argmax" in m:
        bits.append(f"FPR_arg={m['fpr_argmax']*100:5.2f}%")
    for f in (0.01, 0.03):
        if f"det@fpr{f:g}" in m:
            bits.append(f"det@{f*100:g}%={m[f'det@fpr{f:g}']*100:5.1f}%")
    print(f"    {tag:<16} n={m['n']:<6} " + "  ".join(bits))


# ---------------------------------------------------------------------------
def main():
    t_start = time.time()
    fx = FeatureExtractor()
    report = {"seeds": SEEDS, "budgets": list(BUDGETS), "recipes": {}}

    # ---------------- 固定特征（只算一次） ----------------
    print("[load] payload_train / payload_test / lexical ...")
    payload_train = load_payloads(os.path.join(TRAINDATA, "payload_train.csv"))
    payload_test = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))

    Xp = to_X(fx, payload_train)
    yp = np.asarray([s["label"] for s in payload_train])
    Xte, yte = to_X(fx, payload_test), np.asarray([s["label"] for s in payload_test])
    Xlex_all = to_X(fx, lex)
    ylex_all = np.asarray([s["label"] for s in lex])

    # 字典增强部分（与 seed 无关，只算一次）
    tr_dict, _, _, _, info_dict = load_all("none", use_dict=True, dict_benign_ratio=1.0)
    dict_part = tr_dict[len(payload_train):]
    Xdict = to_X(fx, dict_part)
    ydict = np.asarray([s["label"] for s in dict_part])
    print(f"[dict] +{len(dict_part)} 条  {info_dict['dict']}")

    # CSIC
    print("[load] CSIC 2010 ...")
    csic_reqs, csic_y = load_csic()
    csic_norm = [r for r, v in zip(csic_reqs, csic_y) if v == 0]
    csic_anom = [r for r, v in zip(csic_reqs, csic_y) if v == 1]
    csic_fpr_pool = csic_norm[-CSIC_FPR_POOL:]
    Xcsic, ycsic = to_X(fx, csic_fpr_pool), np.zeros(len(csic_fpr_pool), dtype=int)
    XcsicA, ycsicA = to_X(fx, csic_anom), np.ones(len(csic_anom), dtype=int)
    print(f"[csic] FPR 留出池={len(csic_fpr_pool)}  异常={len(csic_anom)}")

    # datacon OOD
    print("[load] datacon2025 (OOD) ...")
    dc_rows = load_datacon("train") + load_datacon("test")
    Xdc = to_X(fx, dc_rows)
    ydc = np.asarray([r["label"] for r in dc_rows])
    print(f"[datacon] n={len(dc_rows)}  labeled(攻击)={int((ydc==1).sum())} "
          f"unlabeled={int((ydc==0).sum())}"
          f"  <- unlabeled≠良性，仅作人工复核线索")

    # 分组留出的固定切法
    add_g, keep_g, extra_g = _lexical_halves(lex, "grouped", 11)
    lex_idx_all = list(range(len(lex)))
    keep_g_idx = sorted(i for i in lex_idx_all if i in keep_g or ylex_all[i] != 0)

    # ---------------- 配方 ----------------
    RECIPES = {
        "A_official":       dict(split="random", depth=8, rounds=400, es=0),
        "B_official_dict":  dict(split="random", depth=8, rounds=400, es=0, use_dict=True),
        "C_official_es30":  dict(split="random", depth=8, rounds=400, es=30),
        "D_d6_es30_reg":    dict(split="random", depth=6, rounds=400, es=30,
                                 mcw=10.0, lam=5.0),
        "G_grouped":        dict(split="grouped", depth=8, rounds=400, es=0),
        "G_grouped_dict":   dict(split="grouped", depth=8, rounds=400, es=0, use_dict=True),
    }
    SEEDED = {"A_official", "B_official_dict", "C_official_es30", "D_d6_es30_reg"}
    cmp_keys = ("fpr_argmax", "det@fpr0.01", "det@fpr0.03", "acc",
                "fpr@mix0.01", "det@mix0.01")
    AGG_SETS = ("lexical", "csic_normal", "payload_test", "csic_anomaly", "datacon")

    for name, cfg in RECIPES.items():
        seeds = SEEDS if name in SEEDED else [11]
        print("\n" + "=" * 78)
        print(f"[recipe] {name}  {cfg}  seeds={seeds}")
        print("=" * 78)
        per_seed, fitted = [], None

        for sd in seeds:
            add_idx, keep_idx, _ = _lexical_halves(lex, cfg["split"], sd)
            ev_idx = sorted(i for i in lex_idx_all
                            if i in keep_idx or ylex_all[i] != 0)
            parts = [Xp, Xlex_all[add_idx]]
            labs = [yp, np.zeros(len(add_idx), dtype=int)]
            if cfg.get("use_dict"):
                parts.append(Xdict)
                labs.append(ydict)
            Xtr = np.vstack(parts)
            ytr = np.concatenate(labs)

            clf = fit(Xtr, ytr, Xte, yte, depth=cfg["depth"], rounds=cfg["rounds"],
                      es=cfg["es"], mcw=cfg.get("mcw", 1.0), lam=cfg.get("lam", 1.0),
                      curve=(f"p2_{name}" if sd == seeds[0] else None),
                      meta={"recipe": name, "seed": sd, "n_train": int(len(ytr))})
            if fitted is None:
                fitted = clf

            # 校准阈值：只用良性池，且**不用任何评估集的攻击标签**
            #   csicfpr* : 仅 CSIC 正常留出池（B 配方在该池 argmax FPR≈0，会不公）
            #   mix*     : CSIC 池 + lexical 训练半区正常（跨风格，公平的工作点）
            _, s_pool = evaluate(clf, Xcsic, ycsic)
            _, s_ltr = evaluate(clf, Xlex_all[add_idx],
                                np.zeros(len(add_idx), dtype=int))
            mix_scores = np.concatenate([s_pool, s_ltr])
            thr_map = {}
            for f in (0.001, 0.01, 0.03):
                thr_map[f"csicfpr{f:g}"] = float(np.quantile(s_pool, 1.0 - f))
                thr_map[f"mix{f:g}"] = float(np.quantile(mix_scores, 1.0 - f))

            m_lex, _ = evaluate(clf, Xlex_all[ev_idx], ylex_all[ev_idx], thr_map)
            m_te, _ = evaluate(clf, Xte, yte, thr_map)
            m_cn, s_cn = evaluate(clf, Xcsic, ycsic, thr_map)
            m_ca, _ = evaluate(clf, XcsicA, ycsicA, thr_map)
            m_dc, _ = evaluate(clf, Xdc, ydc, thr_map)

            df = clf.get_booster().trees_to_dataframe()
            rec = {"n_trees": int(df["Tree"].nunique()), "n_nodes": int(len(df)),
                   "nodes_per_sample": float(len(df) / max(1, len(ytr))),
                   "best_iteration": int(getattr(clf, "best_iteration", -1) or -1),
                   "per_set": {"payload_test": m_te, "lexical": m_lex,
                               "csic_normal": m_cn, "csic_anomaly": m_ca,
                               "datacon": m_dc}}
            per_seed.append(rec)

            if sd == seeds[0]:
                print(f"  [model] {rec['n_trees']} trees / {rec['n_nodes']} nodes "
                      f"({rec['nodes_per_sample']:.3f} nodes/sample)"
                      + (f"  best_iter={rec['best_iteration']}" if rec['best_iteration'] >= 0 else ""))
                for tag, m in rec["per_set"].items():
                    print_row(tag, m)
                print("    -- 阈值取自良性池（不碰评估集标签）--")
                for tag in ("lexical", "csic_anomaly", "datacon"):
                    m = rec["per_set"][tag]
                    for pre in ("mix", "csicfpr"):
                        got = "  ".join(f"{k}={v:.3f}" for k, v in m.items()
                                        if k.startswith((f"det@{pre}", f"fpr@{pre}")))
                        print(f"    {tag:<16} [{pre}] {got}")
                print(f"    datacon unlabeled 被标记率(需人工复核) = "
                      f"{m_dc.get('fpr@mix0.01', float('nan'))*100:.1f}% @mix1%阈值")

        # 多 seed 汇总
        if len(seeds) > 1:
            agg = {}
            for sname in AGG_SETS:
                agg[sname] = {}
                for k in cmp_keys:
                    vals = [r["per_set"][sname][k] for r in per_seed
                            if k in r["per_set"][sname]]
                    if vals:
                        agg[sname][k] = [float(np.mean(vals)), float(np.std(vals))]
            print(f"  [多 seed mean±std] ({len(seeds)} 个切分)")
            for sname, kk in agg.items():
                bits = "  ".join(f"{k}={v[0]:.4f}±{v[1]:.4f}" for k, v in kk.items())
                print(f"    {sname:<14} {bits}")
            report["recipes"][name] = {"config": cfg, "per_seed": per_seed, "agg": agg}
        else:
            report["recipes"][name] = {"config": cfg, "per_seed": per_seed}

    report["data"] = {
        "payload_train": len(payload_train), "payload_test": len(payload_test),
        "lexical": len(lex), "lexical_split": extra_g,
        "csic_fpr_pool": len(csic_fpr_pool), "csic_anomaly": len(csic_anom),
        "datacon": len(dc_rows), "datacon_labeled": int((ydc == 1).sum()),
        "dict_aug": info_dict["dict"],
    }
    report["elapsed_seconds"] = round(time.time() - t_start, 1)
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, "p2_matrix.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=float)
    print(f"\n-> artifacts/p2_matrix.json  ({report['elapsed_seconds']}s)")


if __name__ == "__main__":
    main()
