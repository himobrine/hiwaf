"""精简 Isolation Forest -> ONNX 导出（零日通道）。

skl2onnx 生成的图（含 score_samples 的 log/reduce 运算）单样本延迟 ~1.2ms。
本模块直接把孤森林编码为单个 TreeEnsembleRegressor，输出"平均路径长度" E[h]
（越小越异常），无需逐样本的多算子图，大幅降低单样本延迟。

数学：sklearn 的路径长度 = depth(边数) + c(n_leaf)，其中
  c(n) = 2*(ln(n-1)+γ) - 2(n-1)/n
异常分数 score = 2^(-E[h]/c(max_samples))，是 E[h] 的单调递减函数，
因此直接以 E[h] 排序/阈值即可，与 sklearn 判定等价（单调变换）。

## 两条训练来源（**不可混用文件名**）

| `--data` | 训练集 | 产物文件名 | 用途 |
|---|---|---|---|
| `csic`（默认，正式） | CSIC 2010 正常 30,000 | `iforest_lean_v20261015_001.onnx` + `iforest_meta.json` | **正式零日通道**，Rust 数据面加载 |
| `synthetic` | `dataset.generate()` | `iforest_lean_synthetic_001.onnx` + `iforest_meta_synthetic.json` | 仅链路自检 |
| `local` | 真实本地良性（`collect_http_log.py` 产出） | `iforest_lean_local_001.onnx` + `iforest_meta_local.json` | 验证 S9 处方（本地分布内标定）；**非上线产物** |

> ⚠️ 旧版本把**合成模型**写进 canonical 文件名，而 `eval_csic.py` 评估的是 CSIC 模型 ——
> 数据面实际加载的零日通道与文档里的 CSIC 指标**不是同一个东西**。现已分离。

用法：
    py -3.10 iforest_lean_onnx.py --data csic --export      # 正式零日通道
    py -3.10 iforest_lean_onnx.py --data synthetic --export  # 链路自检
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import deque

import numpy as np
import onnx
from onnx import helper, TensorProto

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

FPR_BUDGETS = (0.001, 0.01, 0.03, 0.05, 0.10)

REQ_KEYS = ("method", "path", "query", "body")


def _req_key(s: dict) -> str:
    return "\x1f".join(str(s.get(k) or "") for k in REQ_KEYS)


def _req_sha1(s: dict) -> str:
    import hashlib
    return hashlib.sha1(_req_key(s).encode("utf-8", "replace")).hexdigest()


def _load_upload_benign(manifest_path: str, skip_id: int | None = None):
    """读取控制台数据集清单里的良性行；非良性行跳过（零日通道只用良性训练）。

    `skip_id`：该数据集已经作为 `--benign` 本地基线单独加载（iforest_local add），
    这里必须跳过，否则同一条请求会同时进训练集和校准留出。
    """
    from realdata import load_local_jsonl

    with open(manifest_path, "r", encoding="utf-8") as f:
        man = json.load(f)
    rows, skipped = [], 0
    for ds in man.get("datasets") or []:
        if skip_id is not None and int(ds.get("id") or -1) == int(skip_id):
            continue
        p = ds.get("train_path") or ds.get("requests_path")
        if not p or not os.path.exists(p):
            raise SystemExit(f"上传数据集 #{ds.get('id')} 的训练副本不存在：{p}")
        for r in load_local_jsonl(p):
            if int(r.get("label", 0)) != 0:
                skipped += 1
                continue
            r["_dataset_id"] = ds.get("id")
            r["_dataset_name"] = ds.get("name")
            rows.append(r)
    return man, rows, skipped


def _split_upload_holdout(rows, frac: float = 0.5, seed: int = 42,
                          max_group: int = 2000):
    """上传良性切训练/校准留出；与 train_realdata 同策略（近重复不跨界）。"""
    from collections import defaultdict as _dd
    import numpy as _np

    if len(rows) < 400:
        return list(rows), [], {"method": "too_small", "n_benign": len(rows)}
    texts = [f"{s.get('method') or ''} {s.get('path') or ''}?{s.get('query') or ''} "
             f"{s.get('body') or ''}" for s in rows]
    hold_pos: set = set()
    method = "template-clusters"
    if len(rows) <= max_group:
        try:
            from textsim import group_split
            tr_pos, ev_pos, extra = group_split(texts)
            hold_pos = set(ev_pos)
            method = f"group_split({extra})"
        except Exception:  # noqa: BLE001
            hold_pos = set()
    if not hold_pos:
        from textsim import template
        by_tpl = _dd(list)
        for i, t in enumerate(texts):
            by_tpl[template(t)].append(i)
        clusters = list(by_tpl.values())
        rng = _np.random.default_rng(seed)
        rng.shuffle(clusters)
        target = max(200, int(len(rows) * frac))
        for idxs in clusters:
            if len(hold_pos) >= target:
                break
            hold_pos.update(idxs)
    if len(hold_pos) < 200 or len(hold_pos) >= len(rows):
        return list(rows), [], {"method": method, "n_holdout": len(hold_pos),
                                "fallback": True}
    tr = [s for i, s in enumerate(rows) if i not in hold_pos]
    hold = [s for i, s in enumerate(rows) if i in hold_pos]
    return tr, hold, {"method": method, "n_holdout": len(hold),
                      "n_train": len(tr)}


def _write_iforest_upload(out_dir: str, train_rows, holdout_rows, manifest: dict,
                          overlap: dict) -> dict:
    import hashlib
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "training_keys.txt"), "w", encoding="utf-8") as f:
        for s in train_rows:
            f.write(_req_sha1(s) + "\n")
    calib = {}
    if holdout_rows:
        p = os.path.join(out_dir, "calibration_pool.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            for s in holdout_rows:
                f.write(json.dumps({k: s.get(k) or "" for k in
                                    ("method", "path", "query", "body", "label")},
                                   ensure_ascii=False) + "\n")
        calib = {"source": "upload", "file": "calibration_pool.jsonl",
                 "n": len(holdout_rows)}
    meta = {"mode": manifest.get("mode"), "datasets": manifest.get("datasets") or [],
            "calib": calib, "n_train_rows": len(train_rows),
            "n_holdout_rows": len(holdout_rows),
            "overlap_official_eval": overlap}
    with open(os.path.join(out_dir, "upload_stats.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return meta


def calibrate(e_norm, e_atk, budgets=FPR_BUDGETS):
    """在**留出正常**上标定零日阈值；分数 = -E[h]（越大越异常）。"""
    s_norm = -np.asarray(e_norm, dtype=float)
    s_atk = -np.asarray(e_atk, dtype=float) if len(e_atk) else np.array([])
    out = {"thresholds": {}, "detect": {}, "n_normal_pool": int(len(s_norm)),
           "n_anomaly": int(len(s_atk))}
    for f in budgets:
        thr = float(np.quantile(s_norm, 1.0 - f))
        out["thresholds"][f"{f:g}"] = thr
        if len(s_atk):
            out["detect"][f"{f:g}"] = float((s_atk >= thr).mean())
    return out


import numpy as np
import onnx
from onnx import helper, TensorProto

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")


def _avg_path_len(n):
    n = np.asarray(n, dtype=float)
    nc = np.maximum(n, 1.0)
    return np.where(n <= 1, 0.0,
                    np.where(n == 2, 1.0,
                             2 * (np.log(np.maximum(nc - 1, 1.0)) + np.euler_gamma)
                             - 2 * (nc - 1) / nc))


def build_iforest_onnx(iso, n_features: int, out_path: str, input_name="input",
                       output_name="avg_path_len"):
    tree_ids, node_ids, feats, vals, modes, ture, fals, missing = ([] for _ in range(8))
    tgt_tree, tgt_node, tgt_id, tgt_w = [], [], [], []

    for tree_idx, est in enumerate(iso.estimators_):
        t = est.tree_
        # 计算每个节点的深度（边数）
        depth = {0: 0}
        dq = deque([0])
        while dq:
            n = dq.popleft()
            l, r = t.children_left[n], t.children_right[n]
            if l != -1:
                depth[l] = depth[n] + 1
                dq.append(l)
            if r != -1:
                depth[r] = depth[n] + 1
                dq.append(r)

        for n in range(t.node_count):
            node_ids.append(n)
            tree_ids.append(tree_idx)
            l, r = t.children_left[n], t.children_right[n]
            if l == -1 and r == -1:  # 叶
                feats.append(0)
                vals.append(0.0)
                modes.append("LEAF")
                ture.append(0)
                fals.append(0)
                missing.append(0)
                n_leaf = t.n_node_samples[n]
                leaf_value = float(depth[n] + _avg_path_len(n_leaf))
                tgt_tree.append(tree_idx)
                tgt_node.append(n)
                tgt_id.append(0)
                tgt_w.append(leaf_value)
            else:
                feats.append(int(t.feature[n]))
                vals.append(float(t.threshold[n]))
                modes.append("BRANCH_LEQ")
                ture.append(int(l))
                fals.append(int(r))
                missing.append(0)

    reg = helper.make_node(
        "TreeEnsembleRegressor",
        [input_name],
        [output_name],
        domain="ai.onnx.ml",
        n_targets=1,
        nodes_treeids=tree_ids,
        nodes_nodeids=node_ids,
        nodes_featureids=feats,
        nodes_values=vals,
        nodes_modes=modes,
        nodes_truenodeids=ture,
        nodes_falsenodeids=fals,
        nodes_missing_value_tracks_true=missing,
        target_treeids=tgt_tree,
        target_nodeids=tgt_node,
        target_ids=tgt_id,
        target_weights=tgt_w,
        aggregate_function="AVERAGE",
        post_transform="NONE",
        base_values=[0.0],
    )

    inp = helper.make_tensor_value_info(input_name, TensorProto.FLOAT, [None, n_features])
    outp = helper.make_tensor_value_info(output_name, TensorProto.FLOAT, [None, 1])
    graph = helper.make_graph([reg], "iforest_lean", [inp], [outp])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 15), helper.make_opsetid("ai.onnx.ml", 3)],
    )
    model.ir_version = 10  # 兼容 onnxruntime 1.20 (max IR 10)
    onnx.checker.check_model(model)
    onnx.save(model, out_path)
    return out_path


def make_session(path, intra_op=1):
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = intra_op
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    t0 = time.perf_counter()
    sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
    return sess, (time.perf_counter() - t0) * 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", choices=["csic", "synthetic", "local", "upload"], default="csic")
    ap.add_argument("--upload-manifest", default=None,
                    help="控制台生成的上传数据清单（staging/datasets.json）")
    ap.add_argument("--upload-skip-id", type=int, default=None,
                    help="该数据集已作为 --benign 基线加载，manifest 里跳过它（防训练/留出重叠）")
    ap.add_argument("--upload-mode", choices=["add", "only"], default=None,
                    help="add=官方基数+上传良性；only=只用上传良性")
    ap.add_argument("--calib-mode", choices=["auto", "official", "upload"], default="auto",
                    help="阈值校准池：auto=上传良性留出优先，不足回退官方；official=官方；upload=必须用上传留出")
    ap.add_argument("--benign", default=None,
                    help="--data local：真实本地良性 jsonl（collect_http_log.py 产出）")
    ap.add_argument("--attack", default=None,
                    help="--data local：真实在野攻击 jsonl（仅用于报告检出率，不进训练）")
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--max-samples", type=int, default=256)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--export", action="store_true")
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--out-dir", default=ART,
                    help="产物目录（控制台训练传 staging；默认 artifacts）")
    ap.add_argument("--onnx-name", default=None,
                    help="导出的 ONNX 文件名（默认按 --data 选；控制台 staging 用 model.onnx）")
    ap.add_argument("--run-name", default=None,
                    help="学习曲线 run 名称")
    ap.add_argument("--parent-model", default=None,
                    help="warm start 父代 iforest_model.joblib 路径")
    args = ap.parse_args()
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)

    from features import FeatureExtractor
    from sklearn.ensemble import IsolationForest

    fx = FeatureExtractor()
    n_features = len(fx.names)

    if args.data == "upload":
        if not args.upload_manifest:
            raise SystemExit("--data upload 需要 --upload-manifest（控制台生成）")
        Xtr = np.empty((0, n_features), dtype=np.float32)
        Xhold = np.empty((0, n_features), dtype=np.float32)
        Xatk = np.empty((0, n_features), dtype=np.float32)
        onnx_name = args.onnx_name or "iforest_lean_v20261015_001.onnx"
        meta_name = "iforest_meta.json"
        meta_extra = {"dataset": "上传良性数据（控制台）", "train_normal": 0,
                      "holdout_normal": 0, "anomaly": 0}
    elif args.data == "csic":
        from realdata import csic_normal_index, load_csic
        print("[lean] loading CSIC 2010 ...")
        reqs, y = load_csic()
        tr_idx, hold_idx = csic_normal_index(seed=7, n_train=30000)
        atk_idx = [i for i, v in enumerate(y) if v == 1]
        X_all = np.asarray(fx.transform_batch(reqs), dtype=np.float32)
        Xtr, Xhold, Xatk = X_all[tr_idx], X_all[hold_idx], X_all[atk_idx]
        onnx_name = args.onnx_name or "iforest_lean_v20261015_001.onnx"
        meta_name = "iforest_meta.json"
        meta_extra = {
            "dataset": "CSIC 2010 正常流量（只用正常训练，不看攻击标签）",
            "train_normal": len(tr_idx), "holdout_normal": len(hold_idx),
            "anomaly": len(atk_idx),
            "split_protocol": "realdata.csic_normal_index(seed=7, n_train=30000)",
        }
        print(f"[lean] train(normal)={len(tr_idx)} holdout(normal)={len(hold_idx)} "
              f"anomaly={len(atk_idx)}")
    elif args.data == "synthetic":
        from dataset import generate, split
        reqs, labels = generate(n_per_class=2000)
        tr_r, tr_y, te_r, te_y = split(reqs, labels)
        Xtr = np.asarray(fx.transform_batch(tr_r), dtype=np.float32)
        Xhold = np.asarray(fx.transform_batch(te_r), dtype=np.float32)
        tr_y, te_y = np.asarray(tr_y), np.asarray(te_y)
        Xtr = Xtr[tr_y == 0]
        Xatk = Xhold[te_y != 0]
        Xhold = Xhold[te_y == 0]
        onnx_name = args.onnx_name or "iforest_lean_synthetic_001.onnx"
        meta_name = "iforest_meta_synthetic.json"
        meta_extra = {"dataset": "合成数据（仅链路自检，勿用于指标）",
                      "train_normal": int(len(Xtr)), "holdout_normal": int(len(Xhold)),
                      "anomaly": int(len(Xatk))}
    else:  # local：真实本地良性（工作项 F 采集）
        from realdata import load_local_jsonl
        from textsim import group_split
        if not args.benign:
            raise SystemExit("--data local 必须给 --benign <真实本地良性 jsonl>")
        benign = load_local_jsonl(args.benign, label=0)
        if len(benign) < 60:
            raise SystemExit(f"--benign 只有 {len(benign)} 条，无法切出互斥留出（同簇不跨界需要 ≥60）")
        texts = [f"{s['method']} {s['path']}?{s['query']}" for s in benign]
        tr_pos, hold_pos, ginfo = group_split(texts)
        X_all = np.asarray(fx.transform_batch(benign), dtype=np.float32)
        Xtr, Xhold = X_all[tr_pos], X_all[hold_pos]
        attack = load_local_jsonl(args.attack) if args.attack else []
        Xatk = (np.asarray(fx.transform_batch(attack), dtype=np.float32) if attack
                else np.empty((0, n_features), dtype=np.float32))
        onnx_name = args.onnx_name or "iforest_lean_local_001.onnx"
        meta_name = "iforest_meta_local.json"
        meta_extra = {
            "dataset": "真实本地良性流量（本机 phpStudy 访问日志，collect_http_log.py 产出）",
            "train_normal": int(len(Xtr)), "holdout_normal": int(len(Xhold)),
            "anomaly": int(len(Xatk)),
            "benign_source": os.path.relpath(os.path.abspath(args.benign), HERE),
            "attack_source": (os.path.relpath(os.path.abspath(args.attack), HERE) if args.attack else None),
            "split_protocol": f"textsim.group_split 近重复分簇不跨界（{ginfo}）",
            "caveat": ("本地良性样本量极小，阈值/检出率的置信区间很宽；"
                       "此产物是**验证 S9 处方可行**，不是可上线的零日通道。"),
        }
        print(f"[lean] local train(normal)={len(Xtr)} holdout(normal)={len(Xhold)} "
              f"attack={len(Xatk)}  clusters={ginfo}")

    # ---- 上传良性数据：add / only + 校准留出 ----
    upload_meta = None
    upload_train_rows = []
    upload_hold_rows = []
    if args.upload_manifest and args.upload_mode:
        manifest, rows, skipped = _load_upload_benign(
            args.upload_manifest, skip_id=args.upload_skip_id)
        manifest["mode"] = args.upload_mode
        if skipped:
            print(f"[upload] 跳过非良性行 {skipped} 条（零日只用 label=0）")
        if not rows:
            raise SystemExit("上传数据里没有良性行")
        if args.calib_mode != "official":
            tr_rows, hold_rows, cinfo = _split_upload_holdout(rows, seed=args.seed)
            print(f"[upload] 校准留出 {len(hold_rows)} 条 {cinfo}")
            if hold_rows:
                upload_train_rows, upload_hold_rows = tr_rows, hold_rows
            elif args.calib_mode == "upload":
                raise SystemExit("--calib-mode upload 但上传数据切不出 ≥200 条良性留出")
            else:
                upload_train_rows = list(rows)
                print("[upload] 留出不足 200 条，校准池回退官方")
        else:
            upload_train_rows = list(rows)

        Xup = np.asarray(fx.transform_batch(upload_train_rows), dtype=np.float32)
        if args.data == "upload":
            Xtr = Xup
        else:
            Xtr = np.vstack([Xtr, Xup]) if len(Xtr) else Xup
        if upload_hold_rows:
            Xhold = np.asarray(fx.transform_batch(upload_hold_rows), dtype=np.float32)
        upload_meta = {
            "mode": args.upload_mode,
            "datasets": manifest.get("datasets") or [],
            "calib_mode": args.calib_mode,
            "overlap_official_eval": {},
        }
        _base_label = {
            "csic": "CSIC 2010 正常",
            "local": "真实本地良性",
            "synthetic": "合成正常",
            "upload": "上传良性",
        }.get(args.data, str(args.data))
        meta_extra["dataset"] = (
            "上传良性数据（only）" if args.upload_mode == "only"
            else f"{_base_label} + 上传良性（add）")
        meta_extra["upload_mode"] = args.upload_mode
        meta_extra["upload_benign_added"] = len(upload_train_rows)

        # upload-only 且校准回退官方时，用官方 CSIC 留出；实在没有才切一半，
        # 保证 calibrate() 有正常样本且 training_keys 与实际训练一致。
        if args.data == "upload" and len(Xhold) == 0 and upload_train_rows:
            used_official = False
            try:
                from realdata import csic_normal_index, load_csic
                reqs, _y = load_csic()
                _tr_idx, hold_idx = csic_normal_index(seed=7, n_train=30000)
                Xhold = np.asarray(fx.transform_batch([reqs[i] for i in hold_idx]),
                                   dtype=np.float32)
                used_official = len(Xhold) > 0
                if used_official:
                    print(f"[upload] upload-only 用官方 CSIC 留出做校准：hold={len(Xhold)}")
            except Exception as e:  # noqa: BLE001
                print(f"[upload] CSIC 留出不可用：{e}")
            if not used_official:
                tr_rows, hold_rows, _ci = _split_upload_holdout(
                    upload_train_rows, frac=0.5, seed=args.seed)
                if not hold_rows:
                    # 分组失败（例如模板完全相同）：按奇偶确定性对半，并在 meta 里注明。
                    hold_rows = [s for i, s in enumerate(upload_train_rows) if i % 2 == 0]
                    tr_rows = [s for i, s in enumerate(upload_train_rows) if i % 2 == 1]
                    meta_extra["split_protocol"] = "odd-even（分组失败，近重复可能跨侧）"
                upload_train_rows, upload_hold_rows = tr_rows, hold_rows
                Xtr = np.asarray(fx.transform_batch(upload_train_rows), dtype=np.float32)
                Xhold = np.asarray(fx.transform_batch(upload_hold_rows), dtype=np.float32)
                print(f"[upload] 无官方留出，改切 50/50：train={len(Xtr)} hold={len(Xhold)}")

    # max_samples 不能超过训练样本数（真实本地良性往往只有几百条）
    ms = int(min(args.max_samples, len(Xtr)))
    base_trees = 0
    parent_iso = None
    if args.parent_model:
        import joblib
        parent_iso = joblib.load(args.parent_model)
        if not hasattr(parent_iso, "estimators_"):
            raise SystemExit("父代 joblib 不是已训练的 IsolationForest，拒绝 warm start")
        if len(getattr(parent_iso, "estimators_", [])) >= args.trees:
            raise SystemExit(
                f"warm start 的 --trees={args.trees} 必须大于父代树数 "
                f"{len(parent_iso.estimators_)}（否则不会新增树）")
        if int(getattr(parent_iso, "max_samples_", ms)) != ms:
            raise SystemExit(
                f"父代 max_samples={getattr(parent_iso, 'max_samples_', None)} 与当前 {ms} 不一致，拒绝 warm start")
        if int(getattr(parent_iso, "n_features_in_", n_features)) != n_features:
            raise SystemExit("父代特征维度与当前不一致，拒绝 warm start")
        base_trees = len(parent_iso.estimators_)
        print(f"[warm] 从父代继续训练：base_trees={base_trees} -> {args.trees}")
        iso = parent_iso
        iso.set_params(n_estimators=args.trees, warm_start=True)
        iso.fit(Xtr)
    else:
        iso = IsolationForest(n_estimators=args.trees, max_samples=ms,
                              random_state=args.seed, n_jobs=os.cpu_count()).fit(Xtr)
    total_trees = len(iso.estimators_)

    out = os.path.join(out_dir, onnx_name)
    build_iforest_onnx(iso, n_features, out)
    print(f"[lean] saved -> {out} ({os.path.getsize(out)/1024:.0f} KB)")
    if args.export:
        import joblib
        joblib.dump(iso, os.path.join(out_dir, "iforest_model.joblib"))
        print(f"[lean] sklearn 模型 -> {os.path.join(out_dir, 'iforest_model.joblib')}")

    if len(Xhold) == 0:
        if len(Xtr) < 2:
            raise SystemExit("没有可用的留出正常样本，无法标定零日阈值")
        cut = len(Xtr) // 2
        Xhold, Xtr = Xtr[cut:], Xtr[:cut]
        if len(Xhold) == 0:
            raise SystemExit("没有可用的留出正常样本，无法标定零日阈值")
        print(f"[lean] 无显式留出，改用训练集后一半：train={len(Xtr)} hold={len(Xhold)}")

    sess, load_ms = make_session(out)
    iname = sess.get_inputs()[0].name
    E_hold = sess.run(None, {iname: Xhold})[0].ravel()
    E_atk = sess.run(None, {iname: Xatk})[0].ravel() if len(Xatk) else np.array([])

    # 与 sklearn 单调一致（排序一致性）；+1.0 = 与 decision_function 完全同序
    from scipy.stats import spearmanr
    dec = iso.decision_function(Xhold)
    rho = float(spearmanr(E_hold, dec).statistic)
    print(f"[lean] spearman(E_hold, decision_function) = {rho:+.4f}  (+1.0=完全同序)")

    calib = calibrate(E_hold, E_atk)
    for f, v in calib["detect"].items():
        print(f"[lean] @FPR<={f:>5}  检测率={v*100:5.1f}%   "
              f"阈值(score=-E[h])={calib['thresholds'][f]:.6f}")

    # ---- 学习曲线（每次训练运行都必须产出，见 python/README.md 约定）----
    # 无监督模型没有"逐轮损失"，改用「检出率/AUC 随树数增长」——这也是容量是否够的直接证据。
    from learning_curve import iforest_curve
    import copy
    steps = sorted({10, 25, 50, 100, args.trees})
    steps = [s for s in steps if base_trees < s <= args.trees] or [args.trees]

    def iso_factory(n, prev):
        if prev is None and parent_iso is not None:
            iso_c = copy.deepcopy(parent_iso)
            iso_c.set_params(n_estimators=n, warm_start=True)
        elif prev is None:
            iso_c = IsolationForest(n_estimators=n, max_samples=ms,
                                    random_state=args.seed, n_jobs=os.cpu_count(),
                                    warm_start=True)
        else:
            iso_c = prev
            iso_c.set_params(n_estimators=n)
        return iso_c.fit(Xtr)

    rec = iforest_curve(iso_factory, Xhold,
                        Xatk if len(Xatk) else Xhold[:1], steps=steps,
                        budget_fprs=(0.001, 0.01, 0.03),
                        run=(args.run_name or f"iforest_lean_{args.data}"))
    paths = rec.save(meta={"data": args.data, "dataset": meta_extra.get("dataset", ""),
                           "train_normal": int(len(Xtr)), "holdout_normal": int(len(Xhold)),
                           "anomaly": int(len(Xatk)), "max_samples": ms,
                           "seed": args.seed, "steps": steps,
                           "base_trees": base_trees, "total_trees": total_trees,
                           "parent_model": (os.path.basename(args.parent_model)
                                            if args.parent_model else None),
                           "inherit_mode": ("warm_start" if args.parent_model else "full")})
    print(f"[curve] -> {os.path.relpath(paths['json'], HERE)}"
          + (f", {os.path.relpath(paths['png'], HERE)}" if "png" in paths else ""))

    if args.export:
        upload_art = None
        if upload_meta is not None:
            upload_art = _write_iforest_upload(
                out_dir, upload_train_rows, upload_hold_rows, upload_meta,
                upload_meta.get("overlap_official_eval") or {})
            print(f"[upload] 训练指纹 {len(upload_train_rows)} 条；校准留出 "
                  f"{len(upload_hold_rows)} 条")
        meta = {
            "n_features": n_features, "trees": args.trees,
            "max_samples": ms, "seed": args.seed,
            "include_ngram": False,
            "output_name": "avg_path_len",
            "score_def": "zero_day_score = -avg_path_len（越大越异常）",
            "zero_day_threshold": calib,
            "spearman_vs_sklearn": rho,
            "onnx": onnx_name,
            "base_trees": base_trees, "total_trees": total_trees,
            "parent_model": (os.path.basename(args.parent_model)
                             if args.parent_model else None),
            "inherit_mode": ("warm_start" if args.parent_model else "full"),
            **({"datasets": upload_meta.get("datasets")} if upload_meta else {}),
            **({"upload": upload_art} if upload_art else {}),
            **({"training_keys_file": "training_keys.txt"} if upload_meta else {}),
            **({"eval_note": "官方 CSIC 仅作迁移评估（训练未使用）"}
               if (upload_meta or {}).get("mode") == "only" else {}),
            **meta_extra,
        }
        with open(os.path.join(out_dir, meta_name), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        print(f"[meta] -> {os.path.join(out_dir, meta_name)}")

    if args.bench:
        import statistics

        def bench(batch, n):
            xb = Xhold[:batch]
            for _ in range(20):
                sess.run(None, {iname: xb})
            ts = []
            for _ in range(n):
                t0 = time.perf_counter()
                sess.run(None, {iname: xb})
                ts.append((time.perf_counter() - t0) * 1000)
            ts.sort()
            return (round(statistics.median(ts), 4), round(ts[int(len(ts) * .99)], 4),
                    round(statistics.median(ts) / batch * 1000, 2))

        for bs, n in ((1, 3000), (32, 400), (128, 200)):
            p50, p99, us = bench(bs, n)
            print(f"[lean] bs{bs}: p50={p50}ms p99={p99}ms per-sample={us}us")
        print(f"[lean] session_load={load_ms:.1f}ms")


if __name__ == "__main__":
    main()
