"""ONNX Runtime CPU 推理基准（PRD 4.1.4/4.1.5、七章性能目标）。

测量：单样本延迟分位、批量吞吐、内存占用、线程数影响。
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time

import numpy as np

from dataset import generate, split
from features import FeatureExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")


def rss_mb():
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    except Exception:
        return -1.0


def time_loop(fn, n, warmup=20):
    for _ in range(warmup):
        fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000.0)  # ms
    ts.sort()
    return {
        "p50_ms": round(statistics.median(ts), 4),
        "p95_ms": round(ts[int(len(ts) * 0.95)], 4),
        "p99_ms": round(ts[min(len(ts) - 1, int(len(ts) * 0.99))], 4),
        "mean_ms": round(statistics.mean(ts), 4),
        "n": n,
    }


def bench_model(path, X, threads, n=2000):
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = threads
    so.inter_op_num_threads = 1
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    t0 = time.perf_counter()
    sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
    load_ms = (time.perf_counter() - t0) * 1000
    iname = sess.get_inputs()[0].name
    out_names = [o.name for o in sess.get_outputs()]

    def run_one(i):
        return sess.run(out_names, {iname: X[i:i + 1]})

    single = time_loop(lambda: run_one(0), n=n)
    single["session_load_ms"] = round(load_ms, 1)

    # 批量吞吐
    batch = {}
    for bs in (1, 8, 32, 128):
        xb = X[:bs]

        def run_batch():
            return sess.run(out_names, {iname: xb})

        reps = max(20, n // bs)
        for _ in range(10):
            run_batch()
        t0 = time.perf_counter()
        for _ in range(reps):
            run_batch()
        dt = time.perf_counter() - t0
        batch[bs] = {
            "per_batch_ms": round(dt / reps * 1000, 4),
            "per_sample_us": round(dt / reps / bs * 1e6, 2),
            "qps": round(reps * bs / dt, 1),
        }
    return single, batch, out_names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    args = ap.parse_args()
    os.makedirs(ART, exist_ok=True)

    xgb_path = os.path.join(ART, "xgboost_v20261015_001.onnx")
    if_path = os.path.join(ART, "iforest_synthetic_001.onnx")

    reqs, labels = generate(n_per_class=2000)
    _, _, te_r, te_y = split(reqs, labels)
    fx = FeatureExtractor()
    X = np.asarray(fx.transform_batch(te_r), dtype=np.float32)
    print(f"[bench] samples={X.shape} rss_start={rss_mb():.0f}MB")

    report = {"n_samples": int(X.shape[0]), "features": int(X.shape[1])}

    for name, path in (("xgboost", xgb_path), ("iforest", if_path)):
        if not os.path.exists(path):
            print(f"[skip] {name}: {path} not found")
            continue
        for threads in (1, 4, 12):
            single, batch, outs = bench_model(path, X, threads, n=args.n)
            print(f"\n[{name}] threads={threads} rss={rss_mb():.0f}MB outputs={outs}")
            print(f"  single-sample: p50={single['p50_ms']}ms p95={single['p95_ms']}ms "
                  f"p99={single['p99_ms']}ms mean={single['mean_ms']}ms "
                  f"load={single['session_load_ms']}ms")
            print(f"  batch  per-sample(us)/qps: " +
                  "  ".join(f"bs{bs}:{batch[bs]['per_sample_us']}us/{batch[bs]['qps']}qps"
                            for bs in batch))
            report[f"{name}_threads{threads}"] = {"single": single, "batch": batch}

    report["rss_end_mb"] = round(rss_mb(), 1)
    with open(os.path.join(ART, "bench_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[bench] rss_end={rss_mb():.0f}MB -> artifacts/bench_report.json")


if __name__ == "__main__":
    main()
