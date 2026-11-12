"""用**新版 traindata/**（2026-11）训练监督通道，并在现役模型上续训（warm start）。

为什么单独一个脚本而不是改 `train_realdata.py`：
  * 旧语料已整体删除，`train_realdata.load_all()` 的入口（payload_train.csv /
    CSIC）不存在；但 `run()`（训练、早停自检、学习曲线、ONNX/树件导出、阈值记录）
    与语料无关，直接复用，避免复制第三份训练实现。
  * 数据接入全部落在 `realdata_waf.build_dataset()` 里，本脚本只负责"配方"与导出。

配方（与现役 gen-0002 的差异只有数据来源）：
  * 特征 v2 / 80 维、标签 0-4 **完全不变** -> ONNX / Rust 契约不动
  * warm start：默认从现役 `artifacts/xgb_model.json`（800 树）+400 轮
  * 5 类训练集：xlsx（事务级）+ parquet 正常 + ModSecurity 在野攻击 +
    WAF-Payload-Collection；无子类攻击（parquet anomalous / bruteforce /
    920 协议规则）**不进 5 类训练**，只做二分类评估
  * 良性校准池：parquet normal 的独立留出桶（与训练桶互斥）

用法：
    py -3.10 train_wafdata.py --export \
        --out-dir artifacts/staging/waf2026 --artifact-name model.onnx

    :: 对照：不从现役续训（全量重训）
    py -3.10 train_wafdata.py --export --no-parent --out-dir artifacts/staging/waf2026_scratch

    :: 只看数据切分，不训练
    py -3.10 train_wafdata.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from dataset import LABELS                      # noqa: E402
from learning_curve import CurveRecorder        # noqa: E402
import realdata_waf as rw                       # noqa: E402
from train_realdata import to_X, make_extractor, run   # noqa: E402

ART = os.path.join(HERE, "artifacts")
LIVE_MODEL = os.path.join(ART, "xgb_model.json")
LIVE_META = os.path.join(ART, "xgboost_meta.json")
DEFAULT_OUT = os.path.join(ART, "staging", "waf2026")

LABEL_NAMES = {0: "normal", 1: "sqli", 2: "xss", 3: "cmdi", 4: "traversal"}


def describe(rows, title):
    import collections
    cnt = collections.Counter(r["label"] for r in rows)
    body = sum(1 for r in rows if r["body"])
    print(f"[{title}] {len(rows):,} 条  body {body:,}  " +
          "  ".join(f"{LABEL_NAMES[k]}={cnt[k]:,}" for k in sorted(cnt)))
    return dict(cnt)


def main() -> None:
    ap = argparse.ArgumentParser(description="新 traindata 监督训练（warm start 现役）")
    ap.add_argument("--features", choices=["v1", "v2"], default="v2")
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--es", type=int, default=0, help="早停轮数（0=不早停，与现役配方一致）")
    ap.add_argument("--balance", choices=["weight", "over", "under", "none"], default="weight")
    ap.add_argument("--export", action="store_true", help="导出 ONNX + xgb_model.json + meta")
    ap.add_argument("--dry-run", action="store_true", help="只构建数据集并打印切分")
    ap.add_argument("--keys-only", action="store_true",
                    help="构建数据集并只重写 dataset_stats/training_keys/calibration_pool（不训练）")
    ap.add_argument("--no-parent", action="store_true", help="不从现役续训（全量重训对照）")
    ap.add_argument("--parent-model", default=LIVE_MODEL)
    ap.add_argument("--parent-meta", default=LIVE_META)
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--artifact-name", default="model.onnx")
    ap.add_argument("--run-name", default=None)
    ap.add_argument("--seed", type=int, default=rw.SEED)
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    t0 = time.time()
    ds = rw.build_dataset(verbose=True)
    train, valid, test = ds["train"], ds["valid"], ds["test"]
    holdout = ds["benign_holdout"]
    stats = ds["stats"]

    describe(train, "train")
    describe(valid, "valid")
    describe(test, "test")
    print(f"[holdout] 良性留出 {len(holdout):,} 条（阈值标定；与训练桶互斥）")
    print(f"[data] 构建耗时 {time.time() - t0:.1f}s")

    out_dir = args.out_dir if os.path.isabs(args.out_dir) else os.path.join(HERE, args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "dataset_stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    # 训练指纹：切换时 thresholds.py --train-keys 用它做校准池污染检查。
    # **必须**用 `req_key_sha1`（与 thresholds.req_key 同口径），不能用去重用的
    # `req_sha1`：后者是 "METHOD url\nbody" 文本哈希，和校准池拼接口径对不上，
    # 污染检查会静默变成 0 交集。
    with open(os.path.join(out_dir, "training_keys.txt"), "w", encoding="utf-8") as f:
        for r in train:
            f.write(rw.req_key_sha1(r) + "\n")
    with open(os.path.join(out_dir, "calibration_pool.jsonl"), "w", encoding="utf-8") as f:
        for r in holdout:
            f.write(json.dumps({k: r[k] for k in ("method", "path", "query", "body")},
                               ensure_ascii=False) + "\n")

    if args.dry_run or args.keys_only:
        print("[keys-only] 已重写 dataset_stats.json / training_keys.txt / "
              "calibration_pool.jsonl（未训练）")
        return

    parent = None if args.no_parent else args.parent_model
    parent_meta = None if args.no_parent else args.parent_meta
    if parent and not os.path.exists(parent):
        print(f"[warm] 父代不存在：{parent} -> 降级全量重训")
        parent = parent_meta = None
    if parent:
        print(f"[warm] 从现役续训：{os.path.basename(parent)} + {args.rounds} 轮")
    else:
        print("[warm] 全量重训（不继承现役）")

    info = {
        "hard_neg": "waf2026",
        "added": len(holdout),
        "seed": args.seed,
        "note": "新版 traindata（xlsx 事务级 + parquet 正常 + ModSec 在野 + 载荷集）",
        "valid_frac": 0.0,
        "n_valid": len(valid),
        "test_title": "新语料 TEST（URL 模板分组留出）",
        "valid_title": "新语料 VALID（URL 模板分组留出）",
        "split_note": ("train/valid/test 按 URL 模板稳定哈希分组切分；"
                       "test 同时含 xlsx 事务级、ModSec 在野、载荷集三个来源"),
        # 切换门禁需要：模型自己的校准池 + 训练指纹（与 thresholds.req_key 同口径）
        "training_keys_file": "training_keys.txt",
        "calib_meta": {"file": "calibration_pool.jsonl", "n": len(holdout),
                       "source": ("parquet WAF Data v2 正常流量留出桶"
                                  "（与训练桶按请求 sha1 互斥，已做良性去污染）")},
        "dataset": ("traindata 2026-11：combined_final_dataset_augmented.xlsx（事务级）"
                    " + WAF Data v2 正常 + OWASP ModSecurity 在野攻击 + WAF-Payload-Collection"),
    }

    res = run(
        args.features, train, test, valid,
        rounds=args.rounds, depth=args.depth, lr=args.lr,
        export=args.export, run_name=args.run_name or (
            "wafdata_v2_warm" if parent else "wafdata_v2_scratch"),
        info=info, es=args.es, balance=args.balance,
        es_set="valid", local_eval=None, valid_eval=valid,
        out_dir=out_dir, artifact_name=args.artifact_name,
        parent_model=parent, parent_meta=parent_meta,
        calib_pool=holdout,
        calib_note=(f"parquet WAF Data v2 正常流量留出桶（{len(holdout):,} 条，"
                    "与训练桶按请求 sha1 互斥）"),
    )
    print(f"[done] {json.dumps({'n_trees': res['n_trees'], 'train_seconds': res['train_seconds']}, ensure_ascii=False)}")
    print(f"[out] {os.path.relpath(out_dir, HERE)}")


if __name__ == "__main__":
    main()
