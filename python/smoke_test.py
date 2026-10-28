"""快速自检：特征维度一致性 / 嵌入通道可用性。

维度从 `FeatureExtractor` 动态读取，避免特征版本变更（v1 78 → v2 80）后忘记改常量。
"""
import numpy as np
from features import FeatureExtractor
from dataset import generate

reqs, labels = generate(n_per_class=5)
fx = FeatureExtractor()
D = len(fx.names)
assert D == 80, f"expected v2 dim 80, got {D}"

v = fx.transform(reqs[0])
assert len(v) == D, (len(v), D)
print("structured features:", len(v), "OK")

NG = 128
fx2 = FeatureExtractor(include_ngram=True, ngram_dim=NG)
v2 = fx2.transform(reqs[0])
assert len(v2) == D + NG, len(v2)
assert all(np.isfinite(v2)), "non-finite feature"
print("with ngram channel:", len(v2), "OK")

X = np.asarray(fx.transform_batch(reqs), dtype=np.float32)
assert X.shape == (len(reqs), D), X.shape
assert np.isfinite(X).all()
print("batch:", X.shape, "OK")

# 真实请求也要能正常抽取（含 latin-1 百分号编码）
from realdata import load_csic

csic_reqs, _ = load_csic(normal_limit=50, anomaly_limit=50)
Xc = np.asarray(fx.transform_batch(csic_reqs), dtype=np.float32)
assert Xc.shape == (len(csic_reqs), D) and np.isfinite(Xc).all(), Xc.shape
print("real CSIC requests:", Xc.shape, "OK")
print("all good")
