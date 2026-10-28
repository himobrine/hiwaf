"""导出 XGBoost 原生 pred_contribs（path-dependent TreeSHAP）作为 Rust 实现的参考。

输出 artifacts/shap_ref.json:
  - features        : 输入特征 (n, M)
  - contribs        : pred_contribs, 已整理为 (n, n_class, M+1)
  - margin          : raw margin (n, n_class)
  - pred_proba      : softmax(margin)
"""
from __future__ import annotations

import json
import os

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

N_SAMPLES = 64  # 参考集规模（验证用）


def main():
    import xgboost as xgb

    with open(os.path.join(ART, "testvec.json"), "r", encoding="utf-8") as f:
        tv = json.load(f)
    X = np.asarray(tv["features"], dtype=np.float32)[:N_SAMPLES]

    booster = xgb.Booster()
    booster.load_model(os.path.join(ART, "xgb_model.json"))
    dm = xgb.DMatrix(X, feature_names=[f"f{i}" for i in range(X.shape[1])])

    margin = booster.predict(dm, output_margin=True)

    # strict_shape -> (n, n_class, M+1)（已在本机确认）
    c = booster.predict(dm, pred_contribs=True, strict_shape=True)
    print("[shap_ref] raw pred_contribs shape =", c.shape)
    # 归一化为 (n, n_class, M+1)
    if c.shape[1] == X.shape[1] + 1:
        c = np.transpose(c, (0, 2, 1))
    print("[shap_ref] normalized shape      =", c.shape, " margin shape =", margin.shape)

    # 一致性：sum(features+1) == margin
    s = c.sum(axis=2)
    err = float(np.abs(s - margin).max())
    print(f"[shap_ref] sum(contribs) vs margin max|diff| = {err:.3e}")

    out = {"n": int(X.shape[0]), "n_features": int(X.shape[1]),
           "n_class": int(c.shape[1]),
           "features": X.tolist(),
           "contribs": c.tolist(),
           "margin": np.asarray(margin).tolist()}
    path = os.path.join(ART, "shap_ref.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print(f"[shap_ref] wrote {path}")


if __name__ == "__main__":
    main()
