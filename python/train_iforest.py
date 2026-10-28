"""Isolation Forest 无监督训练 + ONNX 导出（PRD 4.1.5 / 5.4 第二层）。

仅在正常样本上训练；评估其对攻击样本的异常检出能力。
"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np

from dataset import generate, split, LABELS
from features import FeatureExtractor
from learning_curve import CurveRecorder, iforest_curve

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")


def build(include_ngram=False):
    reqs, labels = generate(n_per_class=2000)
    tr_r, tr_y, te_r, te_y = split(reqs, labels)
    fx = FeatureExtractor(include_ngram=include_ngram)
    Xtr = np.asarray(fx.transform_batch(tr_r), dtype=np.float32)
    Xte = np.asarray(fx.transform_batch(te_r), dtype=np.float32)
    return fx, Xtr, np.asarray(tr_y), Xte, np.asarray(te_y)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--max-samples", type=int, default=256)
    ap.add_argument("--ngram", action="store_true")
    args = ap.parse_args()
    os.makedirs(ART, exist_ok=True)

    from sklearn.ensemble import IsolationForest

    fx, Xtr, ytr, Xte, yte = build(args.ngram)
    Xtr_norm = Xtr[ytr == 0]
    n_features = Xtr.shape[1]
    print(f"[data] train_normal={Xtr_norm.shape} test={Xte.shape} features={n_features}")

    iso = IsolationForest(n_estimators=args.trees, max_samples=args.max_samples,
                          contamination="auto", random_state=42, n_jobs=os.cpu_count())
    t0 = time.time()
    iso.fit(Xtr_norm)
    print(f"[train] {time.time()-t0:.2f}s")

    # sklearn 侧评估：按固定 FPR 预算衡量攻击检出率
    dec = iso.decision_function(Xte)          # >0 正常, <0 异常
    norm_mask = yte == 0
    atk_mask = ~norm_mask
    norm_scores = dec[norm_mask]
    atk_scores = dec[atk_mask]
    budget = {}
    for fpr_target in (0.01, 0.03, 0.05, 0.10):
        thr = float(np.quantile(norm_scores, fpr_target))
        detect = float((atk_scores < thr).mean())
        budget[f"{int(fpr_target*100)}%"] = round(detect, 4)
        print(f"[eval] FPR预算={fpr_target:.0%} 攻击检出率={detect:.4f}")
    fpr = float((dec[norm_mask] < np.quantile(norm_scores, 0.03)).mean())
    tpr = budget["3%"]

    # ---- 学习曲线：AUC / 检测率随 n_estimators 增长（warm_start 逐档加树）----
    steps = sorted({10, 25, 50, 100, args.trees})

    def factory(n, prev):
        if prev is None:
            iso_c = IsolationForest(n_estimators=n, max_samples=args.max_samples,
                                    warm_start=True, random_state=42,
                                    n_jobs=os.cpu_count())
            iso_c.fit(Xtr_norm)
            return iso_c
        prev.set_params(n_estimators=n)
        prev.fit(Xtr_norm)
        return prev

    rec = iforest_curve(factory, Xte[norm_mask], Xte[atk_mask], steps,
                        budget_fprs=(0.01, 0.03, 0.05), run="iforest_synthetic")
    paths = rec.save(meta={"n_features": n_features, "max_samples": args.max_samples,
                           "include_ngram": bool(args.ngram), "dataset": "synthetic"})
    print(f"[curve] -> artifacts/curves/iforest_synthetic_curve.json"
          + (", .png" if "png" in paths else ""))
    print(f"[curve] steps={steps} " +
          " ".join(f"auc@{n}={dict(rec.series['iforest_auc'])[float(n)]:.4f}" for n in steps))

    # 导出 ONNX
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    onnx_model = convert_sklearn(
        iso, initial_types=[("input", FloatTensorType([None, n_features]))],
        options={id(iso): {"score_samples": True}},
        target_opset={"": 15, "ai.onnx.ml": 3},
    )
    import onnx
    try:
        onnx.checker.check_model(onnx_model)
    except Exception as e:
        print(f"[onnx] checker warning (non-fatal): {e}")
    out = os.path.join(ART, "iforest_synthetic_001.onnx")
    onnx.save(onnx_model, out)
    print(f"[onnx] saved -> {out} ({os.path.getsize(out)/1024:.0f} KB)")

    # 一致性校验
    import onnxruntime as ort
    sess = ort.InferenceSession(out, providers=["CPUExecutionProvider"])
    print("[onnx] outputs:", [(o.name, o.shape) for o in sess.get_outputs()])
    res = sess.run(None, {sess.get_inputs()[0].name: Xte})
    names = [o.name for o in sess.get_outputs()]
    out_map = dict(zip(names, res))
    # skl2onnx: 'scores' == decision_function, 'score_samples' == score_samples
    key = "scores" if "scores" in out_map else names[-1]
    onnx_dec = np.asarray(out_map[key]).ravel()
    print("[onnx] score outputs:", {k: np.asarray(v).shape for k, v in out_map.items()})
    diff = float(np.max(np.abs(onnx_dec - dec))) if onnx_dec.shape == dec.shape else -1.0
    print(f"[onnx] decision_function max|diff| (sklearn vs onnx) = {diff:.6g}")

    meta = {"n_features": n_features, "trees": args.trees,
            "max_samples": args.max_samples, "include_ngram": bool(args.ngram),
            "dataset": "合成数据（仅链路自检，勿用于指标）",
            "detect_at_fpr_budget": budget,
            "onnx_decision_maxdiff": diff,
            "onnx_outputs": [(o.name, str(o.shape)) for o in sess.get_outputs()]}
    # 文件名必须与正式零日通道（iforest_meta.json）区分：合成产物不能覆盖正式产物。
    meta_path = os.path.join(ART, "iforest_meta_synthetic.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print("[meta] -> artifacts/iforest_meta_synthetic.json")


if __name__ == "__main__":
    main()
