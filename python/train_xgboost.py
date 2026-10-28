"""XGBoost 多分类训练 + ONNX 导出（PRD 4.1.4 / 5.4 第一层）。"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from dataset import generate, split, LABELS
from features import FeatureExtractor
from learning_curve import CurveRecorder

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")


def build(include_ngram: bool):
    reqs, labels = generate(n_per_class=2000)
    tr_r, tr_y, te_r, te_y = split(reqs, labels)
    fx = FeatureExtractor(include_ngram=include_ngram)
    Xtr = np.asarray(fx.transform_batch(tr_r), dtype=np.float32)
    Xte = np.asarray(fx.transform_batch(te_r), dtype=np.float32)
    return fx, Xtr, np.asarray(tr_y), Xte, np.asarray(te_y)


def train(Xtr, ytr, Xte, yte):
    import xgboost as xgb
    clf = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.15,
        subsample=0.9, colsample_bytree=0.9,
        objective="multi:softprob", num_class=5,
        tree_method="hist", n_jobs=os.cpu_count(),
        eval_metric=["mlogloss", "merror"], random_state=42,
    )
    t0 = time.time()
    clf.fit(Xtr, ytr, eval_set=[(Xtr, ytr), (Xte, yte)], verbose=False)
    train_s = time.time() - t0
    pred = clf.predict(Xte)
    rep = classification_report(yte, pred, target_names=list(LABELS.values()),
                                output_dict=True, zero_division=0)
    return clf, {"train_seconds": round(train_s, 2),
                 "accuracy": round(accuracy_score(yte, pred), 4),
                 "macro_f1": round(rep["macro avg"]["f1-score"], 4),
                 "per_class_f1": {k: round(rep[k]["f1-score"], 4) for k in LABELS.values()},
                 "confusion_matrix": confusion_matrix(yte, pred).tolist()}


def export_onnx(clf, n_features: int, out_path: str):
    from onnxmltools.convert import convert_xgboost
    from onnxmltools.convert.common.data_types import FloatTensorType
    onnx_model = convert_xgboost(
        clf, initial_types=[("input", FloatTensorType([None, n_features]))],
        target_opset=15,
    )
    import onnx
    onnx.checker.check_model(onnx_model)
    onnx.save(onnx_model, out_path)
    return out_path


def dump_trees(clf, out_path: str, num_class: int, n_features: int):
    """导出可解释性 sidecar：每棵树的节点（含 cover）。

    ONNX 的 TreeEnsemble* 属性里没有节点 cover，而 XGBoost 的 `pred_contribs`
    （path-dependent TreeSHAP）依赖 cover 作为未知特征时的左右分配权重。
    因此数据面需要一个带 cover 的紧凑树件（生产环境同样如此）。
    """
    import json
    booster = clf.get_booster()
    dumps = booster.get_dump(dump_format="json", with_stats=True)
    trees = []
    for t, s in enumerate(dumps):
        root = json.loads(s)
        nodes = []
        stack = [root]
        while stack:
            n = stack.pop()
            if "leaf" in n:
                nodes.append({"id": int(n["nodeid"]), "feature": -1, "split": 0.0,
                              "yes": -1, "no": -1, "missing": -1,
                              "cover": float(n.get("cover", 0.0)),
                              "leaf": float(n["leaf"])})
            else:
                nodes.append({"id": int(n["nodeid"]),
                              "feature": int(str(n["split"]).lstrip("f")),
                              "split": float(n["split_condition"]),
                              "yes": int(n["yes"]), "no": int(n["no"]),
                              "missing": int(n["missing"]),
                              "cover": float(n.get("cover", 0.0)),
                              "leaf": None})
                stack.extend(n["children"])
        nodes.sort(key=lambda d: d["id"])
        trees.append({"tree": t, "class": t % num_class, "nodes": nodes})

    # base_score（XGBoost 3.x 可能是每个类别一个值的向量）
    base_scores = [0.0] * num_class
    try:
        booster.save_model(os.path.join(ART, "_tmp_booster.json"))
        with open(os.path.join(ART, "_tmp_booster.json"), "r", encoding="utf-8") as f:
            mdl = json.load(f)
        raw = mdl["learner"]["learner_model_param"]["base_score"]
        if raw.strip().startswith("["):
            vals = [float(x) for x in raw.strip().strip("[]").split(",")]
            for i in range(min(num_class, len(vals))):
                base_scores[i] = vals[i]
        else:
            v = float(raw)
            base_scores = [v] * num_class
        os.remove(os.path.join(ART, "_tmp_booster.json"))
    except Exception as e:  # noqa: BLE001
        print(f"[trees] base_score parse fallback: {e}")

    out = {"num_class": num_class, "base_scores": base_scores,
           "n_features": n_features, "trees": trees}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    n_nodes = sum(len(t["nodes"]) for t in trees)
    print(f"[trees] -> {out_path}  ({len(trees)} trees, {n_nodes} nodes, "
          f"base_scores={base_scores})")
    return out_path


def verify(clf, onnx_path: str, Xte: np.ndarray):
    import onnxruntime as ort
    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    print("[onnx] inputs :", [(i.name, i.shape, i.type) for i in sess.get_inputs()])
    print("[onnx] outputs:", [(o.name, o.shape, o.type) for o in sess.get_outputs()])
    iname = sess.get_inputs()[0].name
    onnx_out = sess.run(None, {iname: Xte})
    logits = np.asarray(onnx_out[-1])
    if logits.ndim == 1:
        logits = logits.reshape(len(Xte), -1)
    row_sum = float(np.abs(logits).sum(axis=1).mean())
    is_prob = abs(row_sum - 1.0) < 1e-2 and (logits >= 0).all()
    onnx_pred = np.argmax(logits, axis=1)
    skl_pred = clf.predict(Xte)
    agree = float((onnx_pred == skl_pred).mean())
    return onnx_pred, agree, logits, is_prob


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ngram", action="store_true", help="启用字符3-gram哈希通道")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    os.makedirs(ART, exist_ok=True)
    fx, Xtr, ytr, Xte, yte = build(args.ngram)
    n_features = len(fx.names)
    print(f"[data] train={Xtr.shape} test={Xte.shape} features={n_features}")

    clf, metrics = train(Xtr, ytr, Xte, yte)
    print(f"[train] acc={metrics['accuracy']} macroF1={metrics['macro_f1']} "
          f"time={metrics['train_seconds']}s")
    for k, v in metrics["per_class_f1"].items():
        print(f"        F1[{k}]={v}")

    # 学习曲线（每次训练都产出）
    rec = CurveRecorder("xgboost_synthetic")
    rec.from_evals_result(clf.evals_result(),
                          names={"validation_0": "train", "validation_1": "test"})
    paths = rec.save(meta={"features": "v2", "n_features": n_features,
                           "include_ngram": bool(args.ngram),
                           "train_seconds": metrics["train_seconds"],
                           "dataset": "synthetic"})
    print(f"[curve] -> artifacts/curves/xgboost_synthetic_curve.json"
          + (f", .png" if "png" in paths else ""))

    # 注意：合成数据的产物使用独立文件名，避免覆盖真实数据训练出的
    # 「正式」产物（xgboost_v20261015_001.onnx / xgb_model.json / xgb_trees.json）。
    out = args.out or os.path.join(ART, "xgboost_synthetic_001.onnx")
    export_onnx(clf, n_features, out)
    print(f"[onnx] saved -> {out}  ({os.path.getsize(out)/1024:.0f} KB)")

    # 可解释性 sidecar：booster + 带 cover 的树结构
    booster_path = os.path.join(ART, "xgb_model_synthetic.json")
    trees_path = os.path.join(ART, "xgb_trees_synthetic.json")
    clf.get_booster().save_model(booster_path)
    print(f"[booster] -> artifacts/{os.path.basename(booster_path)}")
    dump_trees(clf, trees_path, len(LABELS), n_features)

    _, agree, _, is_prob = verify(clf, out, Xte)
    metrics["onnx_sklearn_agreement"] = round(agree, 4)
    metrics["onnx_output_is_probability"] = bool(is_prob)
    metrics["n_features"] = n_features
    metrics["include_ngram"] = bool(args.ngram)
    print(f"[onnx] prediction agreement onnx vs sklearn = {agree:.4f}")
    print(f"[onnx] output looks like probability = {is_prob}")

    # 保存元数据
    meta_path = os.path.join(ART, "xgboost_meta_synthetic.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({"feature_names": fx.names, "labels": LABELS,
                   "metrics": metrics, "model": os.path.basename(out),
                   "dataset": "synthetic"}, f, ensure_ascii=False, indent=2)
    print(f"[meta] -> artifacts/{os.path.basename(meta_path)}")


if __name__ == "__main__":
    main()
