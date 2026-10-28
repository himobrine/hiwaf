"""P0 审计：量化"是否过拟合"，并给出不乐观的误报基准。

三种过拟合分开量化：
  (A) 数据泄漏 —— lexical 正常样本的重复/近重复，导致 train-half ↔ eval-half 同源；
  (B) 容量过剩 —— 节点/样本 比、正则与 early stopping 的影响；
  (C) 泛化差距 —— 分组留出（无同源）后的真实 FPR。

产出：
  artifacts/p0_audit.json
运行：
  py -3.10 p0_audit.py
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

import numpy as np

from dataset import LABELS
from realdata import TRAINDATA, load_payloads
from textsim import NEAR_DUP_THR, leak_clusters, payload_of, template
from train_realdata import class_weights, detect_at_fpr, to_X

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
SEED = 11


# --------------------------------------------------------------------------
# 训练 / 评估
# --------------------------------------------------------------------------
def train_eval(Xtr, ytr, Xval, yval, evals: dict, params=None, curve_name=None):
    import xgboost as xgb
    from learning_curve import CurveRecorder

    p = dict(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.9,
             colsample_bytree=0.9, objective="multi:softprob", num_class=len(LABELS),
             tree_method="hist", n_jobs=os.cpu_count(), random_state=42,
             eval_metric=["mlogloss", "merror"])
    extra = dict(params or {})
    es = extra.pop("early_stopping_rounds", None)
    p.update(extra)
    if es:  # xgboost 3.x：early_stopping_rounds 是**构造参数**，不能传给 fit()
        p["early_stopping_rounds"] = es

    w, _ = class_weights(ytr, len(LABELS))
    clf = xgb.XGBClassifier(**p)
    clf.fit(Xtr, ytr, sample_weight=w, verbose=False,
            eval_set=[(Xtr, ytr), (Xval, yval)])

    if curve_name:
        rec = CurveRecorder(curve_name)
        rec.from_evals_result(clf.evals_result(),
                              names={"validation_0": "train", "validation_1": "valid"})
        rec.save(meta={"params": {k: v for k, v in p.items() if k != "n_jobs"},
                       "early_stopping_rounds": es})

    df = clf.get_booster().trees_to_dataframe()
    out = {
        "n_trees": int(df["Tree"].nunique()),
        "n_nodes": int(len(df)),
        "n_train": int(len(ytr)),
        "nodes_per_sample": float(len(df) / max(1, len(ytr))),
        "best_iteration": int(getattr(clf, "best_iteration", -1) or -1),
    }
    normal_col = list(clf.classes_).index(0)
    for name, (X, y) in evals.items():
        proba = clf.predict_proba(X)
        pred = proba.argmax(1)
        s = 1.0 - proba[:, normal_col]
        ya = y != 0
        rec = {"n": int(len(y)), "acc": float((pred == y).mean()),
               "n_normal": int((~ya).sum()), "n_attack": int(ya.sum())}
        if (~ya).any():
            rec["fpr_argmax"] = float((pred[~ya] != 0).mean())
        if ya.any():
            for f in (0.01, 0.03, 0.05):
                dr, fpr = detect_at_fpr(s, ya, f)
                rec[f"det@fpr{f:g}"] = float(dr)
        out[name] = rec
    return clf, out


def print_eval(tag, rec):
    det = "  ".join(f"det@{k.split('fpr')[-1]}={rec[k]:.3f}"
                    for k in ("det@fpr0.01", "det@fpr0.03", "det@fpr0.05") if k in rec)
    print(f"    {tag:<14} n={rec['n']:<5} acc={rec['acc']:.4f} "
          f"FPR={rec.get('fpr_argmax', float('nan')):.4f}  {det}")


# --------------------------------------------------------------------------
def main():
    rep = {}

    payload_train = load_payloads(os.path.join(TRAINDATA, "payload_train.csv"))
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))
    fx = extractor = None
    from features import FeatureExtractor
    fx = FeatureExtractor()

    y_lex = np.array([s["label"] for s in lex])
    norm_pos = list(np.where(y_lex == 0)[0])
    anom_pos = list(np.where(y_lex != 0)[0])
    norm_texts = [payload_of(lex[i]) for i in norm_pos]
    print(f"[data] lexical: normal={len(norm_pos)} anomaly={len(anom_pos)}")
    print(f"[data] payload_train rows={len(payload_train)}")

    # ================= (A) 重复 / 泄漏审计 =================
    print("\n" + "=" * 78)
    print("(A) lexical 正常样本 重复与同源审计")
    print("=" * 78)
    ce = Counter(norm_texts)
    ct = Counter(template(t) for t in norm_texts)
    print(f"  完全重复: 组={sum(1 for v in ce.values() if v > 1)}  行={sum(v for v in ce.values() if v > 1)}"
          f"  (去重后 {len(ce)}/{len(norm_texts)})")
    print(f"  模板重复: 组={sum(1 for v in ct.values() if v > 1)}  行={sum(v for v in ct.values() if v > 1)}"
          f"  (去重后 {len(ct)}/{len(norm_texts)})")

    clusters, S = leak_clusters(norm_texts)
    n_clusters = len(set(clusters))
    print(f"  近重复簇(余弦≥{NEAR_DUP_THR} 或同模板): {n_clusters} 簇 / {len(norm_texts)} 条 "
          f"(平均 {len(norm_texts)/n_clusters:.2f} 条/簇)")

    # 复现 train_realdata 的随机 50/50 切分（seed=11）
    order = np.array(norm_pos)
    rng = np.random.RandomState(SEED)
    perm = np.arange(len(norm_pos))
    rng.shuffle(perm)
    half = len(norm_pos) // 2
    train_sel = set(perm[:half].tolist())      # 位置索引（norm_texts 内）
    eval_sel = set(perm[half:].tolist())

    train_clusters = {clusters[p] for p in train_sel}
    leak_exact = sum(1 for p in eval_sel if norm_texts[p] in {norm_texts[q] for q in train_sel})
    train_tpl = {template(norm_texts[q]) for q in train_sel}
    leak_tpl = sum(1 for p in eval_sel if template(norm_texts[p]) in train_tpl)
    leak_clu = sum(1 for p in eval_sel if clusters[p] in train_clusters)
    n_eval = len(eval_sel)
    print(f"\n  随机切分(seed=11) 下，评估半区 {n_eval} 条中与训练半区同源的：")
    print(f"    完全重复 : {leak_exact:>4}  ({100*leak_exact/n_eval:.1f}%)")
    print(f"    同模板   : {leak_tpl:>4}  ({100*leak_tpl/n_eval:.1f}%)")
    print(f"    同近重复簇: {leak_clu:>4}  ({100*leak_clu/n_eval:.1f}%)  <-- 泄漏率")

    rep["A_duplication"] = {
        "n_normal": len(norm_pos), "n_anomaly": len(anom_pos),
        "exact_dup_groups": sum(1 for v in ce.values() if v > 1),
        "exact_dup_rows": sum(v for v in ce.values() if v > 1),
        "template_dup_groups": sum(1 for v in ct.values() if v > 1),
        "template_dup_rows": sum(v for v in ct.values() if v > 1),
        "n_clusters": n_clusters, "near_dup_threshold": NEAR_DUP_THR,
        "eval_half": n_eval,
        "leak_exact": leak_exact, "leak_template": leak_tpl, "leak_cluster": leak_clu,
        "leak_cluster_rate": leak_clu / n_eval,
    }

    # ================= 三种评估集 =================
    # X: 预先算好全部 lexical + payload_train 特征
    Xp = to_X(fx, payload_train)
    yp = np.array([s["label"] for s in payload_train])
    Xnorm = to_X(fx, [lex[i] for i in norm_pos])
    Xanom = to_X(fx, [lex[i] for i in anom_pos])
    yanom = np.array([lex[i]["label"] for i in anom_pos])

    # --- 随机切分 ---
    tr_idx = sorted(train_sel)
    ev_idx = sorted(eval_sel)

    Xtr_rand = np.vstack([Xp, Xnorm[tr_idx]])
    ytr_rand = np.concatenate([yp, np.zeros(len(tr_idx), dtype=yp.dtype)])

    # --- 分组切分（同簇不跨半区） ---
    by_cluster = defaultdict(list)
    for p, c in enumerate(clusters):
        by_cluster[c].append(p)
    glist = sorted(by_cluster.values(), key=len, reverse=True)
    g_train, g_eval = [], []
    for g in glist:
        (g_train if len(g_train) <= len(g_eval) else g_eval).extend(g)
    g_train.sort()          # 固定行序，保证与 p2_matrix.py 的分组切分逐位可复现
    g_eval.sort()
    Xtr_grp = np.vstack([Xp, Xnorm[g_train]])
    ytr_grp = np.concatenate([yp, np.zeros(len(g_train), dtype=yp.dtype)])
    evals_grp = {
        "grouped": (np.vstack([Xnorm[g_eval], Xanom]),
                    np.concatenate([np.zeros(len(g_eval), dtype=int), yanom])),
    }
    print(f"\n  分组切分: train_normal={len(g_train)}  eval_normal={len(g_eval)} "
          f"(同簇不跨半区)")
    rep["A_duplication"]["grouped_train_normal"] = len(g_train)
    rep["A_duplication"]["grouped_eval_normal"] = len(g_eval)

    # ================= 额外良性池（更稳的 FPR 估计） =================
    from realdata import load_csic
    csic_all, csic_y = load_csic()
    csic_norm = [r for r, v in zip(csic_all, csic_y) if v == 0]
    csic_hold = csic_norm[-6000:]
    Xcsic = to_X(fx, csic_hold)
    print(f"\n[data] 额外良性池：CSIC 留出正常 {len(csic_hold)} 条（用于收紧 FPR 估计）")

    payload_test = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))
    Xval_pt = to_X(fx, payload_test)
    yval_pt = np.array([s["label"] for s in payload_test])

    # ================= (B)/(C) 训练对比 =================
    print("\n" + "=" * 78)
    print("(B)(C) 配方对比：多切分方差 / 分组留出 / 正则化")
    print("=" * 78)

    def make_evals(Xn, yn, y_anom):
        return {
            "lexical": (np.vstack([Xn, Xanom]),
                        np.concatenate([yn, y_anom])),
            "csic_normal": (Xcsic, np.zeros(len(Xcsic), dtype=int)),
        }

    results = {}

    # ---- 1) 多切分方差：同一配方、5 个不同 50/50 切分 ----
    print("\n  [1] baseline_d8 · 5 个不同切分（量化 500 条样本带来的估计抖动）")
    seeds = [11, 22, 33, 44, 55]
    half = len(norm_pos) // 2
    per_seed = []
    for sd in seeds:
        perm = np.arange(len(norm_pos))
        np.random.RandomState(sd).shuffle(perm)
        tr, ev = sorted(perm[:half].tolist()), sorted(perm[half:].tolist())
        Xtr = np.vstack([Xp, Xnorm[tr]])
        ytr = np.concatenate([yp, np.zeros(len(tr), dtype=yp.dtype)])
        evals = make_evals(Xnorm[ev], np.zeros(len(ev), dtype=int), yanom)
        _, rec = train_eval(Xtr, ytr, Xval_pt, yval_pt, evals,
                            params=dict(max_depth=8),
                            curve_name=("p0_baseline_d8" if sd == 11 else None))
        per_seed.append(rec)
        r = rec["lexical"]
        print(f"    seed={sd:<3} FPR_lex={r['fpr_argmax']:.4f} "
              f"FPR_csic={rec['csic_normal']['fpr_argmax']:.4f} "
              f"det@1%={r['det@fpr0.01']:.3f} det@3%={r['det@fpr0.03']:.3f} "
              f"nodes/sample={rec['nodes_per_sample']:.3f}")
    keys = ["fpr_argmax", "det@fpr0.01", "det@fpr0.03", "det@fpr0.05"]
    agg = {k: (float(np.mean([s["lexical"][k] for s in per_seed])),
               float(np.std([s["lexical"][k] for s in per_seed]))) for k in keys}
    agg_csic = (float(np.mean([s["csic_normal"]["fpr_argmax"] for s in per_seed])),
                float(np.std([s["csic_normal"]["fpr_argmax"] for s in per_seed])))
    print("    lexical  mean±std: " + "  ".join(f"{k}={v[0]:.4f}±{v[1]:.4f}"
                                               for k, v in agg.items()))
    print(f"    csic正常 FPR mean±std: {agg_csic[0]:.4f}±{agg_csic[1]:.4f} "
          f"(n={len(Xcsic)})")
    results["multi_seed"] = {"per_seed": [s["lexical"] for s in per_seed],
                             "agg": {k: list(v) for k, v in agg.items()},
                             "csic_fpr": list(agg_csic),
                             "csic_n": int(len(Xcsic))}

    # ---- 2) 分组留出（同簇不跨半区）----
    print("\n  [2] grouped_d8 · 分组留出（同源样本不跨训练/评估）")
    evals_grp = make_evals(Xnorm[g_eval], np.zeros(len(g_eval), dtype=int), yanom)
    _, rec = train_eval(Xtr_grp, ytr_grp, Xval_pt, yval_pt, evals_grp,
                        params=dict(max_depth=8), curve_name="p0_grouped_d8")
    print(f"    model: {rec['n_trees']} trees / {rec['n_nodes']} nodes "
          f"({rec['nodes_per_sample']:.3f} nodes/sample)")
    for tag in evals_grp:
        print_eval(tag, rec[tag])
    results["grouped_d8"] = rec

    # ---- 3) 正则化 / 容量消融（动机：0.87 nodes/sample 是否过剩）----
    print("\n  [3] 正则化与容量消融（随机切分 seed=11）")
    for name, params in [
        ("reg_d6_es", dict(max_depth=6, min_child_weight=10.0, reg_lambda=5.0,
                           early_stopping_rounds=30)),
        ("small_d4_es", dict(max_depth=4, min_child_weight=10.0, reg_lambda=5.0,
                             early_stopping_rounds=30)),
    ]:
        evals_r = make_evals(Xnorm[ev_idx], np.zeros(len(ev_idx), dtype=int), yanom)
        print(f"\n    [{name}] {params}")
        _, rec = train_eval(Xtr_rand, ytr_rand, Xval_pt, yval_pt, evals_r,
                            params=params, curve_name=f"p0_{name}")
        print(f"      model: {rec['n_trees']} trees / {rec['n_nodes']} nodes "
              f"({rec['nodes_per_sample']:.3f} nodes/sample)  "
              f"best_iter={rec['best_iteration']}")
        for tag in evals_r:
            print_eval(tag, rec[tag])
        results[name] = rec

    rep["B_C_recipes"] = results

    # ================= (D) 曲线复核 =================
    print("\n" + "=" * 78)
    print("(D) 已有学习曲线复核")
    print("=" * 78)
    curve_path = os.path.join(ART, "curves", "xgboost_realdata_v2_lexical_curve.json")
    if os.path.exists(curve_path):
        with open(curve_path, "r", encoding="utf-8") as f:
            cv = json.load(f)
        ser = cv["series"]
        vm = np.array([p[1] for p in ser["valid_mlogloss"]])
        lm = np.array([p[1] for p in ser["lexical_mlogloss"]])
        tm = np.array([p[1] for p in ser["train_mlogloss"]])
        best = int(vm.argmin()) + 1
        print(f"  run={cv['run']}")
        print(f"  valid 最优轮次 = {best} / {len(vm)}   valid={vm[best-1]:.4f}")
        print(f"  末轮: train={tm[-1]:.4f}  valid={vm[-1]:.4f}  lexical={lm[-1]:.4f}")
        print(f"  train↔valid 末轮差 = {vm[-1]-tm[-1]:.4f}   train↔lexical = {lm[-1]-tm[-1]:.4f}")
        # 每 50 轮
        idx = list(range(0, len(vm), max(1, len(vm) // 8))) + [len(vm) - 1]
        print("  round :   train    valid  lexical")
        for i in sorted(set(idx)):
            print(f"  {i+1:>5} : {tm[i]:8.4f} {vm[i]:8.4f} {lm[i]:8.4f}")
        rep["D_curve"] = {"run": cv["run"], "best_valid_round": best,
                          "final_train": float(tm[-1]), "final_valid": float(vm[-1]),
                          "final_lexical": float(lm[-1])}
    else:
        print("  (未找到曲线文件)")

    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, "p0_audit.json"), "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2, default=float)
    print("\n-> artifacts/p0_audit.json")


if __name__ == "__main__":
    main()
