"""新语料评估：现役零日/监督通道在 FUR-API 与 exploit_dataset 上的表现。

只读：不训练、不改 `decision_policy.json`、不碰现役产物。阈值直接取现役策略
（`artifacts/decision_policy.json`），与线上数据面判定口径一致：

    监督：score = 1 - P(normal)      flagged = score >= supervised.threshold
    零日：score = -avg_path_len      flagged = score >= zero_day.threshold

回答三个问题：

1. FUR-API 的 1,000 条 normal 在现役模型上误报多少？→ 能不能加训的先决条件
2. FUR-API 的 150 条 anomaly（业务异常）能不能被标出来？
3. exploit_dataset 里 783 条 HTTP poc（按 4 类过滤后）召回多少？

用法
----
    py -3.10 eval_newdata.py
    py -3.10 eval_newdata.py --extra-iforest staged=artifacts/staging/fur_api_add/model/model.onnx
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time
from typing import Any, Dict, List

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from features import FeatureExtractor  # noqa: E402
from realdata import load_local_jsonl    # noqa: E402

ART = os.path.join(HERE, "artifacts")
POLICY = os.path.join(ART, "decision_policy.json")
LIVE_IF = os.path.join(ART, "iforest_lean_v20261015_001.onnx")
LIVE_XGB = os.path.join(ART, "xgboost_v20261015_001.onnx")
OFFICIAL_HOLDOUT = os.path.join(
    ART, "models", "zero_day", "gen-0003-8d21a7c2dce8", "calibration_pool.jsonl")
LABEL_NAMES = {0: "normal", 1: "sqli", 2: "xss", 3: "cmdi", 4: "traversal"}


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise SystemExit(
            f"缺少 {path}\n先跑：py -3.10 convert_fur_api.py / convert_exploit.py")
    return load_local_jsonl(path)


def _to_X(fx, rows, note=""):
    t0 = time.time()
    X = np.asarray(fx.transform_batch(rows), dtype=np.float32)
    print(f"    [fx] {len(rows):,} 条 -> {X.shape}  {time.time()-t0:.1f}s {note}")
    return X


def _session(path: str):
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = 1
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    return ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])


def _iforest_scores(sess, X) -> np.ndarray:
    iname = sess.get_inputs()[0].name
    out = []
    bs = 8192
    for i in range(0, len(X), bs):
        out.append(sess.run(None, {iname: X[i:i + bs]})[0])
    e = np.concatenate(out, axis=0).ravel().astype(np.float64)
    return -e                      # zero_day_score = -avg_path_len


def _proba_index(sess) -> int:
    outs = sess.get_outputs()
    for i, o in enumerate(outs):
        shp = list(o.shape or [])
        if len(shp) == 2 and str(shp[1]) == "5":
            return i
    for i, o in enumerate(outs):
        if o.name in ("probabilities", "proba", "output_probability"):
            return i
    raise SystemExit(f"ONNX 找不到 5 列概率输出：{[(o.name, o.shape) for o in outs]}")


def _xgb_probs(sess, X) -> np.ndarray:
    iname = sess.get_inputs()[0].name
    idx = _proba_index(sess)
    out = []
    for i in range(0, len(X), 8192):
        out.append(sess.run(None, {iname: X[i:i + 8192]})[idx])
    p = np.concatenate(out, axis=0).reshape(len(X), -1).astype(np.float64)
    return p / np.maximum(p.sum(axis=1, keepdims=True), 1e-12)


def _rate(scores: np.ndarray, thr: float) -> float:
    return float((scores >= thr).mean()) if len(scores) else 0.0


def _q(scores: np.ndarray) -> Dict[str, float]:
    if not len(scores):
        return {}
    return {f"p{int(p*100)}": round(float(np.quantile(scores, p)), 4)
            for p in (0.5, 0.9, 0.95, 0.99, 0.999)}


def _thr_at_fpr(normal_scores: np.ndarray, fpr: float) -> float | None:
    if not len(normal_scores):
        return None
    return float(np.quantile(normal_scores, 1.0 - fpr))


def main() -> None:
    ap = argparse.ArgumentParser(description="FUR-API / exploit 新数据评估（只读）")
    ap.add_argument("--fur-test", default=os.path.join(ART, "staging", "fur_api", "test", "requests.jsonl"))
    ap.add_argument("--fur-train", default=os.path.join(ART, "staging", "fur_api", "train", "requests.jsonl"))
    ap.add_argument("--exploit", default=os.path.join(ART, "staging", "exploit", "requests.jsonl"))
    ap.add_argument("--official-holdout", default=OFFICIAL_HOLDOUT)
    ap.add_argument("--policy", default=POLICY)
    ap.add_argument("--iforest", default=LIVE_IF)
    ap.add_argument("--xgb", default=LIVE_XGB)
    ap.add_argument("--extra-iforest", action="append", default=None,
                    metavar="NAME=PATH", help="额外零日 ONNX（可重复），用于加训 A/B")
    ap.add_argument("--extra-xgb", action="append", default=None,
                    metavar="NAME=PATH", help="额外监督 XGBoost ONNX（可重复），用于加训 A/B")
    ap.add_argument("--out", default=os.path.join(ART, "newdata_eval.json"))
    ap.add_argument("--skip-supervised", action="store_true")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    with open(args.policy, "r", encoding="utf-8") as f:
        policy = json.load(f)
    thr_if = float(policy["zero_day"]["threshold"])
    thr_xgb = float(policy["supervised"]["threshold"])
    print(f"[policy] v{policy.get('version')}  zero_day={thr_if:.6f} "
          f"supervised={thr_xgb:.6f}  zero_day_enabled={policy.get('zero_day_enabled')}")

    fx = FeatureExtractor()
    assert len(fx.names) == 80, len(fx.names)

    fur_test = _load_jsonl(args.fur_test)
    fur_norm = [r for r in fur_test if r["label"] == 0]
    fur_anom = [r for r in fur_test if r["label"] != 0]
    exp_rows = _load_jsonl(args.exploit)
    print(f"[data] FUR test normal={len(fur_norm):,} anomaly={len(fur_anom):,} | "
          f"exploit={len(exp_rows):,}")

    X_fn = _to_X(fx, fur_norm, "FUR/test-normal")
    X_fa = _to_X(fx, fur_anom, "FUR/test-anomaly")
    X_ex = _to_X(fx, exp_rows, "exploit/http")

    X_fh = None
    if os.path.exists(args.official_holdout):
        hold = _load_jsonl(args.official_holdout)
        X_fh = _to_X(fx, hold, "official/benign-holdout")
    else:
        print(f"[warn] 官方良性留出不存在，跳过分布对比：{args.official_holdout}")

    report: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "policy": {"version": policy.get("version"), "schema": policy.get("schema"),
                   "zero_day_threshold": thr_if, "supervised_threshold": thr_xgb,
                   "zero_day_enabled": policy.get("zero_day_enabled")},
        "datasets": {
            "fur_test_normal": len(fur_norm), "fur_test_anomaly": len(fur_anom),
            "exploit_http": len(exp_rows),
            "exploit_by_label": dict(collections.Counter(
                LABEL_NAMES.get(r["label"], str(r["label"])) for r in exp_rows)),
        },
        "zero_day": {},
        "supervised": {},
    }

    models = {}
    if os.path.exists(args.iforest):
        models["live"] = args.iforest
    for spec in args.extra_iforest or []:
        name, _, path = spec.partition("=")
        p = path if os.path.isabs(path) else os.path.join(HERE, path)
        if not os.path.exists(p):
            raise SystemExit(f"--extra-iforest 不存在：{p}")
        models[name] = p
    if not models:
        raise SystemExit(f"没有可评估的零日 ONNX：{args.iforest}")

    exp_lab = np.asarray([r["label"] for r in exp_rows])
    for name, path in models.items():
        print(f"\n=== zero_day / {name} ===")
        sess = _session(path)
        t0 = time.time()
        s_fn = _iforest_scores(sess, X_fn)
        s_fa = _iforest_scores(sess, X_fa)
        s_ex = _iforest_scores(sess, X_ex)
        s_fh = _iforest_scores(sess, X_fh) if X_fh is not None else np.array([])
        print(f"  [onnx] 推理 {time.time()-t0:.1f}s")

        fpr = _rate(s_fn, thr_if)
        det_anom = _rate(s_fa, thr_if)
        rec = _rate(s_ex, thr_if)
        by_cls = {}
        for lab in sorted(set(exp_lab.tolist())):
            m = exp_lab == lab
            by_cls[LABEL_NAMES.get(lab, str(lab))] = {
                "n": int(m.sum()),
                "recall_at_policy_threshold": round(_rate(s_ex[m], thr_if), 4),
            }

        report["zero_day"][name] = {
            "artifact": os.path.relpath(os.path.abspath(path), HERE),
            "threshold": round(thr_if, 6),
            "fur_normal_fpr": round(fpr, 4),
            "fur_anomaly_detect_rate": round(det_anom, 4),
            "exploit_recall": round(rec, 4),
            "exploit_by_class": by_cls,
            "fur_normal_score_quantiles": _q(s_fn),
            "official_holdout_score_quantiles": _q(s_fh) if len(s_fh) else None,
            "threshold_for_1pct_fpr_on_fur": (
                round(_thr_at_fpr(s_fn, 0.01), 4) if len(s_fn) else None),
            "threshold_for_5pct_fpr_on_fur": (
                round(_thr_at_fpr(s_fn, 0.05), 4) if len(s_fn) else None),
            "threshold_for_1pct_fpr_on_official": (
                round(_thr_at_fpr(s_fh, 0.01), 4) if len(s_fh) else None),
        }
        # 同一 FPR 预算下的公平对比：拿 FUR normal 的 1% 分位当阈值，
        # 看 exploit 召回能到多少（现役阈值来自别的池子，直接比重召回没意义）。
        thr_1 = _thr_at_fpr(s_fn, 0.01)
        if thr_1 is not None:
            report["zero_day"][name]["exploit_recall_at_1pct_fur_fpr"] = round(
                _rate(s_ex, thr_1), 4)
            report["zero_day"][name]["fur_anomaly_detect_at_1pct_fur_fpr"] = round(
                _rate(s_fa, thr_1), 4)

        print(f"  FUR normal FPR        = {fpr:6.2%}  (阈值 {thr_if:.4f})")
        print(f"  FUR anomaly 检出      = {det_anom:6.2%}")
        print(f"  exploit HTTP 召回     = {rec:6.2%}")
        for k, v in by_cls.items():
            print(f"    - {k:<10} n={v['n']:<4} recall={v['recall_at_policy_threshold']:.2%}")
        if len(s_fh):
            print(f"  官方留出 FPR(同阈值)  = {_rate(s_fh, thr_if):6.2%}")
            print(f"  1% FPR 所需阈值：FUR={_thr_at_fpr(s_fn,0.01):.3f}  "
                  f"官方={_thr_at_fpr(s_fh,0.01):.3f}  (差 "
                  f"{_thr_at_fpr(s_fn,0.01)-_thr_at_fpr(s_fh,0.01):+.3f})")

    xgb_models = {}
    if os.path.exists(args.xgb):
        xgb_models["live"] = args.xgb
    for spec in args.extra_xgb or []:
        name, _, path = spec.partition("=")
        p = path if os.path.isabs(path) else os.path.join(HERE, path)
        if not os.path.exists(p):
            raise SystemExit(f"--extra-xgb 不存在：{p}")
        xgb_models[name] = p
    if not args.skip_supervised:
        if not xgb_models:
            raise SystemExit(f"没有可评估的监督 ONNX：{args.xgb}")
        for name, path in xgb_models.items():
            print(f"\n=== supervised / {name} ===")
            sess = _session(path)
            p_fn = _xgb_probs(sess, X_fn)
            p_fa = _xgb_probs(sess, X_fa)
            p_ex = _xgb_probs(sess, X_ex)
            s_fn, s_fa, s_ex = 1.0 - p_fn[:, 0], 1.0 - p_fa[:, 0], 1.0 - p_ex[:, 0]

            pred_ok = 0
            per_cls = {}
            for lab in sorted(set(exp_lab.tolist())):
                m = exp_lab == lab
                pred_ok += int((p_ex[m].argmax(axis=1) == lab).sum())
                per_cls[LABEL_NAMES.get(lab, str(lab))] = {
                    "n": int(m.sum()),
                    "recall_at_policy_threshold": round(_rate(s_ex[m], thr_xgb), 4),
                    "argmax_acc": round(float((p_ex[m].argmax(axis=1) == lab).mean()), 4),
                }
            rep = {
                "artifact": os.path.relpath(os.path.abspath(path), HERE),
                "threshold": round(thr_xgb, 6),
                "fur_normal_fpr": round(_rate(s_fn, thr_xgb), 4),
                "fur_anomaly_detect_rate": round(_rate(s_fa, thr_xgb), 4),
                "exploit_recall": round(_rate(s_ex, thr_xgb), 4),
                "exploit_argmax_acc": round(pred_ok / max(1, len(exp_rows)), 4),
                "exploit_by_class": per_cls,
                "fur_normal_score_quantiles": _q(s_fn),
                "threshold_for_1pct_fpr_on_fur": (
                    round(_thr_at_fpr(s_fn, 0.01), 4) if len(s_fn) else None),
            }
            # 混淆矩阵：argmax 掉点时要能回答“被错判成哪一类”，不能只看总分
            conf: Dict[str, Dict[str, int]] = {}
            for lab in sorted(set(exp_lab.tolist())):
                preds = p_ex[exp_lab == lab].argmax(axis=1)
                conf[LABEL_NAMES.get(lab, str(lab))] = {
                    LABEL_NAMES.get(k, str(k)): int((preds == k).sum())
                    for k in range(5)}
            rep["exploit_argmax_confusion"] = conf

            # 同一 FPR 预算（FUR normal 1%）下的召回/分类：跨模型直接比才公平
            thr_1 = _thr_at_fpr(s_fn, 0.01)
            if thr_1 is not None:
                rep["exploit_recall_at_1pct_fur_fpr"] = round(_rate(s_ex, thr_1), 4)
                rep["fur_anomaly_detect_at_1pct_fur_fpr"] = round(
                    _rate(s_fa, thr_1), 4)
                rep["exploit_argmax_acc_at_1pct_fur_fpr"] = round(
                    float((p_ex[s_ex >= thr_1].argmax(axis=1)
                           == exp_lab[s_ex >= thr_1]).mean())
                    if int((s_ex >= thr_1).sum()) else 0.0, 4)
            report["supervised"][name] = rep
            print(f"  FUR normal FPR    = {_rate(s_fn, thr_xgb):6.2%}")
            print(f"  exploit 召回      = {_rate(s_ex, thr_xgb):6.2%}  "
                  f"argmax acc={pred_ok/max(1,len(exp_rows)):.2%}")
            for k, v in per_cls.items():
                print(f"    - {k:<10} n={v['n']:<4} "
                      f"recall={v['recall_at_policy_threshold']:.2%} "
                      f"argmax={v['argmax_acc']:.2%}")
            if thr_1 is not None:
                print(f"  @FUR-FPR≤1%（阈值 {thr_1:.4f}）: exploit 召回 "
                      f"{rep['exploit_recall_at_1pct_fur_fpr']:.2%}  "
                      f"argmax={rep['exploit_argmax_acc_at_1pct_fur_fpr']:.2%}")


    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[report] -> {os.path.relpath(args.out, HERE)}")


if __name__ == "__main__":
    main()
