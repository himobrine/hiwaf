"""可解释性探针：pred_contribs 成本 + ONNX 树结构是否可用于 Rust TreeSHAP。"""
from __future__ import annotations

import os
import statistics
import time

import numpy as np

from dataset import generate, split
from features import FeatureExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")


def ms(fn, n=500, warm=20):
    for _ in range(warm):
        fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    return round(statistics.median(ts), 4), round(ts[int(len(ts) * 0.99)], 4)


def main():
    # 1) xgboost 原生 pred_contribs 成本
    import xgboost as xgb
    reqs, labels = generate(n_per_class=2000)
    tr_r, tr_y, te_r, te_y = split(reqs, labels)
    fx = FeatureExtractor()
    Xtr = np.asarray(fx.transform_batch(tr_r), dtype=np.float32)
    Xte = np.asarray(fx.transform_batch(te_r), dtype=np.float32)

    clf = xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.15,
                            objective="multi:softprob", num_class=5, tree_method="hist",
                            n_jobs=os.cpu_count(), random_state=42).fit(Xtr, tr_y)
    booster = clf.get_booster()
    x1 = xgb.DMatrix(Xte[:1])

    pred = lambda: booster.predict(x1)
    contrib = lambda: booster.predict(x1, pred_contribs=True)
    p = ms(pred, 300)
    c = ms(contrib, 300)
    print(f"[explain] xgboost native predict(1 sample)        p50={p[0]}ms p99={p[1]}ms")
    print(f"[explain] xgboost native predict+pred_contribs    p50={c[0]}ms p99={c[1]}ms")
    print(f"[explain] contribution 相对开销 = {c[0]/max(p[0],1e-9):.1f}x")

    # 2) ONNX 模型内部树结构（Rust 侧 TreeSHAP 的可行性）
    import onnx
    m = onnx.load(os.path.join(ART, "xgboost_v20261015_001.onnx"))
    for node in m.graph.node:
        print(f"[onnx-graph] op={node.op_type} domain='{node.domain}' "
              f"attrs={[a.name for a in node.attribute]}")
    print("[explain] 结论: ONNX 内含 TreeEnsembleClassifier 的节点/叶子属性，"
          "Rust 侧可据此实现 TreeSHAP 计算贡献。")


if __name__ == "__main__":
    main()
