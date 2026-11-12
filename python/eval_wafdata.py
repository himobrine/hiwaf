"""新 traindata 上的统一评估：**现役模型 vs 新模型**，同一批数据、同一套口径。

口径（与 REALDATA_EVALUATION.md 一致，只是换了语料）：
  * 5 类：分组留出的 `test`（xlsx 事务级 + ModSec 在野 + 载荷集），报 acc / 每类 P/R/F1
  * 二分类：score = 1 - P(normal)
      - 阈值来自**良性留出桶**（parquet train normal，与训练互斥）的 1%/3% 分位
      - 误报率在 **parquet test 的 192,295 条正常**上量（该集合从未参与训练）
      - 检出率在 parquet test 的 48,263 条 anomalous 上量（**无子类**，不报 5 类）
  * 分来源召回：xlsx / modsec / payload —— 三个来源的难度完全不同，混在一起会骗自己
  * 不报"率"的集合：ModSecurity 全是命中规则的事务（零良性）、OOD 集合不参与训练

用法：
    py -3.10 eval_wafdata.py
    py -3.10 eval_wafdata.py --models staging   # 只评新模型
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import realdata_waf as rw                                    # noqa: E402
from features import FeatureExtractor                        # noqa: E402

ART = os.path.join(HERE, "artifacts")
LIVE_ONNX = os.path.join(ART, "xgboost_v20261015_001.onnx")
NEW_ONNX = os.path.join(ART, "staging", "waf2026", "model.onnx")
SCRATCH_ONNX = os.path.join(ART, "staging", "waf2026_scratch", "model.onnx")
LABEL_NAMES = {0: "normal", 1: "sqli", 2: "xss", 3: "cmdi", 4: "traversal"}
FPR_TARGETS = (0.001, 0.01, 0.03)


def to_X(fx, rows, batch_note=""):
    t0 = time.time()
    X = np.asarray(fx.transform_batch(rows), dtype=np.float32)
    print(f"    [fx] {len(rows):,} 条 -> {X.shape}  {time.time()-t0:.1f}s {batch_note}")
    return X


def proba_index(sess) -> int:
    """ONNX 有 `label`(int64) 与 `probabilities`(N,5) 两个输出 —— 必须显式选后者。

    坑：`sess.run(None, ...)[0]` 拿到的是 label，reshape 后当概率用会得到
    "acc=0.017、1% 阈值=1.0" 这种荒谬结果（概率列实际是类别号 0-4）。
    """
    outs = sess.get_outputs()
    for i, o in enumerate(outs):
        shp = list(o.shape or [])
        if len(shp) == 2 and (shp[1] in (5, "5")):
            return i
    for i, o in enumerate(outs):
        if o.name in ("probabilities", "proba", "output_probability"):
            return i
    raise SystemExit(f"ONNX 找不到 5 列概率输出：{[(o.name, o.shape) for o in outs]}")


def probs(sess, X, bs: int = 8192):
    iname = sess.get_inputs()[0].name
    idx = proba_index(sess)
    out = []
    for i in range(0, len(X), bs):
        out.append(sess.run(None, {iname: X[i:i + bs]})[idx])
    p = np.concatenate(out, axis=0).reshape(len(X), -1).astype(np.float64)
    s = p.sum(axis=1, keepdims=True)
    return p / np.maximum(s, 1e-12)


def per_class(y, yh):
    out = {}
    for k in sorted(set(y.tolist())):
        m = y == k
        tp = int(((yh == k) & m).sum())
        prec = tp / max(1, int((yh == k).sum()))
        rec = tp / max(1, int(m.sum()))
        f1 = 2 * prec * rec / max(1e-12, prec + rec)
        out[LABEL_NAMES.get(k, str(k))] = {
            "n": int(m.sum()), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4)}
    return out


def thr_at(scores, fpr):
    return float(np.quantile(scores, 1.0 - fpr))


def rate(scores, thr):
    return float((scores >= thr).mean()) if len(scores) else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description="新 traindata 评估（现役 vs 新模型）")
    ap.add_argument("--models", default="live,new", help="要评估的模型：live,new,scratch")
    ap.add_argument("--extra-onnx", action="append", default=None,
                    metavar="NAME=PATH", help="额外模型（可重复），例如 warm800=artifacts/staging/x/model.onnx")
    ap.add_argument("--out", default=os.path.join(ART, "wafdata_eval.json"))
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    import onnxruntime as ort

    fx = FeatureExtractor()
    assert len(fx.names) == 80, len(fx.names)

    print("[data] 构建数据集 ...")
    ds = rw.build_dataset(verbose=True)
    test, hold = ds["test"], ds["benign_holdout"]
    pq = ds["parquet_test"]
    pq_norm = [r for r in pq if r["label"] == 0]
    pq_atk = [r for r in pq if r["label"] is None]

    print("[data] 特征 ...")
    X_test = to_X(fx, test, "test")
    X_hold = to_X(fx, hold, "benign_holdout")
    X_pqn = to_X(fx, pq_norm, "parquet_test/normal")
    X_pqa = to_X(fx, pq_atk, "parquet_test/anomalous")

    y_test = np.asarray([r["label"] for r in test])
    src_test = [r["source"].split("-")[0] for r in test]

    models = {}
    if "live" in args.models and os.path.exists(LIVE_ONNX):
        models["live(现役)"] = LIVE_ONNX
    if "new" in args.models and os.path.exists(NEW_ONNX):
        models["new(waf2026)"] = NEW_ONNX
    if "scratch" in args.models and os.path.exists(SCRATCH_ONNX):
        models["scratch(waf2026)"] = SCRATCH_ONNX
    for spec in args.extra_onnx or []:
        name, _, path = spec.partition("=")
        p = path if os.path.isabs(path) else os.path.join(HERE, path)
        if not os.path.exists(p):
            raise SystemExit(f"--extra-onnx 指向的文件不存在：{p}")
        models[name] = p
    if not models:
        raise SystemExit("没有可评估的 ONNX（先训练或检查路径）")

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": {
            "test": len(test), "test_by_label": ds["stats"]["test_by_label"],
            "benign_holdout": len(hold),
            "parquet_test_normal": len(pq_norm), "parquet_test_anomalous": len(pq_atk),
            "train": ds["stats"]["n_train"], "train_with_body": ds["stats"]["with_body"]["train"],
        },
        "models": {},
    }

    # 跨代可比性：旧测试集已随旧语料删除，唯一还能对照的是旧 testvec.json 的 200 条
    # （合成请求 + 旧真实请求，特征已算好）。切换后 testvec.json 会更新成新语料，
    # 因此优先读 `testvec_legacy.json` 备份。只看"新模型丢了多少旧能力"，不当作主指标。
    tv = None
    tvp = os.path.join(ART, "testvec_legacy.json")
    if os.path.exists(tvp):
        with open(tvp, "r", encoding="utf-8") as f:
            _tv = json.load(f)
        tv = {
            "X": np.asarray(_tv["features"], dtype=np.float32),
            "y": np.asarray(_tv["labels_true"]),
            "n": len(_tv["labels_true"]),
        }
        print(f"[testvec] 旧语料对照集 {tv['n']} 条（跨代可比）")


    for name, path in models.items():
        print(f"\n=== {name} ===")
        sess = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        t0 = time.time()
        p_test = probs(sess, X_test)
        p_hold = probs(sess, X_hold)
        p_pqn = probs(sess, X_pqn)
        p_pqa = probs(sess, X_pqa)
        print(f"  [onnx] 4 个集合推理 {time.time()-t0:.1f}s")

        yh = p_test.argmax(axis=1)
        acc = float((yh == y_test).mean())
        sc_test = 1.0 - p_test[:, 0]
        sc_hold = 1.0 - p_hold[:, 0]
        sc_pqn = 1.0 - p_pqn[:, 0]
        sc_pqa = 1.0 - p_pqa[:, 0]

        thresholds = {f"{f:g}": thr_at(sc_hold, f) for f in FPR_TARGETS}
        binary = {}
        for key, thr in thresholds.items():
            binary[key] = {
                "threshold": round(thr, 6),
                "fpr_parquet_test_normal": round(rate(sc_pqn, thr), 5),
                "recall_parquet_anomalous": round(rate(sc_pqa, thr), 4),
                "detect_test_attack": round(rate(sc_test[y_test != 0], thr), 4),
                "fpr_holdout": round(rate(sc_hold, thr), 5),
            }

        by_source = {}
        for s in sorted(set(src_test)):
            m = np.asarray([x == s for x in src_test])
            if not m.any():
                continue
            sub_acc = float((yh[m] == y_test[m]).mean())
            sub_det = round(rate(sc_test[m][y_test[m] != 0], thresholds["0.01"]), 4)
            by_source[s] = {"n": int(m.sum()), "accuracy": round(sub_acc, 4),
                            "detect_at_1pct": sub_det}

        report["models"][name] = {
            "onnx": os.path.relpath(path, HERE),
            "onnx_mb": round(os.path.getsize(path) / 1048576, 2),
            "test": {"n": len(test), "accuracy": round(acc, 4),
                     "per_class": per_class(y_test, yh)},
            "binary": binary,
            "by_source": by_source,
            "score_stats": {
                "parquet_test_normal": {"mean": round(float(sc_pqn.mean()), 5),
                                        "p99": round(float(np.quantile(sc_pqn, 0.99)), 5)},
                "parquet_test_anomalous": {"mean": round(float(sc_pqa.mean()), 5),
                                           "p50": round(float(np.quantile(sc_pqa, 0.5)), 5)},
            },
        }
        if tv is not None:
            p_tv = probs(sess, tv["X"])
            yh_tv = p_tv.argmax(axis=1)
            report["models"][name]["testvec_legacy"] = {
                "n": tv["n"],
                "accuracy": round(float((yh_tv == tv["y"]).mean()), 4),
                "per_class": per_class(tv["y"], yh_tv),
            }
            print(f"  testvec(旧语料 {tv['n']} 条) acc="
                  f"{report['models'][name]['testvec_legacy']['accuracy']:.4f}")

        print(f"  acc={acc:.4f}  1%FPR 阈值={thresholds['0.01']:.4f}  "
              f"实测FPR={binary['0.01']['fpr_parquet_test_normal']:.2%}  "
              f"anomalous召回={binary['0.01']['recall_parquet_anomalous']:.2%}")
        for s, v in by_source.items():
            print(f"    {s:<10} n={v['n']:>6,}  acc={v['accuracy']:.3f}  "
                  f"detect@1%={v['detect_at_1pct']:.2%}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[eval] -> {os.path.relpath(args.out, HERE)}")


if __name__ == "__main__":
    main()
