"""Isolation Forest 导出/推理变体对比：寻找更优的 CPU 单样本延迟。"""
from __future__ import annotations

import os
import statistics
import time

import numpy as np

from dataset import generate, split
from features import FeatureExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")


def load_data():
    reqs, labels = generate(n_per_class=2000)
    tr_r, tr_y, te_r, te_y = split(reqs, labels)
    fx = FeatureExtractor()
    Xtr = np.asarray(fx.transform_batch(tr_r), dtype=np.float32)
    Xte = np.asarray(fx.transform_batch(te_r), dtype=np.float32)
    return Xtr, np.asarray(tr_y), Xte


def fit():
    from sklearn.ensemble import IsolationForest
    Xtr, ytr, Xte = load_data()
    iso = IsolationForest(n_estimators=100, max_samples=256, random_state=42,
                          n_jobs=os.cpu_count())
    iso.fit(Xtr[ytr == 0])
    return iso, Xtr.shape[1], Xte


def export(iso, n_features, path, **opts):
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    m = convert_sklearn(iso, initial_types=[("input", FloatTensorType([None, n_features]))],
                        options={id(iso): opts}, target_opset={"": 15, "ai.onnx.ml": 3})
    import onnx
    onnx.save(m, path)
    return m


def bench(path, X, threads=1, n=1000, batch=1):
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = threads
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    t0 = time.perf_counter()
    sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
    load = (time.perf_counter() - t0) * 1000
    iname = sess.get_inputs()[0].name
    outs = [o.name for o in sess.get_outputs()]
    xb = X[:batch]
    for _ in range(20):
        sess.run(outs, {iname: xb})
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        sess.run(outs, {iname: xb})
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    size = os.path.getsize(path) / 1024
    return {"path": os.path.basename(path), "load_ms": round(load, 1), "size_kb": round(size),
            "outs": outs, "batch": batch,
            "p50_ms": round(statistics.median(ts), 4),
            "p99_ms": round(ts[int(len(ts) * 0.99)], 4),
            "per_sample_us": round(statistics.median(ts) / batch * 1000, 2)}


def main():
    os.makedirs(ART, exist_ok=True)
    iso, nf, Xte = fit()

    variants = {
        "default": {},
        "score_samples": {"score_samples": True},
        "cdist": {"optim": "cdist"},
        "cdist+ss": {"optim": "cdist", "score_samples": True},
    }
    rows = []
    for name, opts in variants.items():
        p = os.path.join(ART, f"iforest_tmp_{name.replace('+','_')}.onnx")
        try:
            export(iso, nf, p, **opts)
        except Exception as e:
            print(f"[{name}] export failed: {e}")
            continue
        r1 = bench(p, Xte, threads=1, n=800, batch=1)
        r128 = bench(p, Xte, threads=1, n=200, batch=128)
        rows.append((name, r1, r128))
        print(f"[{name:12s}] bs1 p50={r1['p50_ms']}ms p99={r1['p99_ms']}ms | "
              f"bs128 per-sample={r128['per_sample_us']}us | load={r1['load_ms']}ms size={r1['size_kb']}KB")

    print("\n结论: 单样本延迟 vs 批量单样本成本 (ms)")


if __name__ == "__main__":
    main()
