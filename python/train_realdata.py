"""在真实数据集（HTTP Params 2015）上训练并评估 XGBoost 多分类。

与 `train_xgboost.py`（合成数据）的区别：
  * 训练集 `payload_train.csv`、测试集 `payload_test.csv`（**载荷零重叠**）；
  * 额外用困难集 `payload_test_lexical.csv` 作为**验收门槛**（长正常文本误报率）；
  * 每次训练都产出学习曲线（`artifacts/curves/<run>_curve.{json,csv,png}`）；
  * 支持 `--ab` 同时跑 v1/v2 特征做对比，回答"改特征到底有没有用"。

用法：
    py -3.10 train_realdata.py --ab            # v1 vs v2 对比（不导出模型）
    py -3.10 train_realdata.py --features v2 --export   # 训练并导出 ONNX + 树件
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter, defaultdict

import numpy as np

from dataset import LABELS
from learning_curve import CurveRecorder
from realdata import TRAINDATA, load_csic, load_payloads

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
TARGET_NAMES = [LABELS[i] for i in range(len(LABELS))]


# ---------------------------------------------------------------------------
def make_extractor(version: str):
    if version == "v1":
        from features_v1 import FeatureExtractor as FX1
        return FX1()
    from features import FeatureExtractor
    return FeatureExtractor()


def to_X(fx, samples):
    return np.asarray(fx.transform_batch(samples), dtype=np.float32)


def _lexical_halves(lex, split_mode: str, seed: int):
    """把 lexical 的正常样本切成「进训练」与「留作评估」两部分。

    `split_mode="random"`：按 seed 随机对半（旧行为）。
    `split_mode="grouped"`：按同源簇整体切分，**同一模板/近重复不跨两侧**（P0-4），
    这是"不乐观"的 FPR 基准。
    """
    norm_idx = [i for i, s in enumerate(lex) if s["label"] == 0]
    if split_mode == "random":
        order = list(norm_idx)
        np.random.RandomState(seed).shuffle(order)
        cut = len(order) // 2
        return sorted(order[:cut]), set(order[cut:]), {
            "lexical_split": f"random(seed={seed})"}

    from textsim import group_split, payload_of
    texts = [payload_of(lex[i]) for i in norm_idx]
    tr_pos, ev_pos, extra = group_split(texts)
    return (sorted(norm_idx[p] for p in tr_pos),
            {norm_idx[p] for p in ev_pos},
            {"lexical_split": "grouped(近重复不跨训练/评估)", **extra})


def _split_valid(train, frac: float, seed: int):
    """从训练集里切出一份**不要泄漏**的验证集（早停用）。

    两个约束：
      * **同源不跨界**：整簇进/整簇出，否则验证集里会出现"训练集见过的载荷变体"，
        早停点会偏早；
      * **按类分层**：5 个类各自按 `frac` 取，避免把小类（cmdi=59）整类抽干。

    ⚠️ 这里只用**模板级**同源判定（数字掩码后完全相同 ⇒ 同簇）。payload_train 有
    2 万条，`textsim.leak_clusters` 的稠密 n×n 余弦矩阵需要 ~3.4GB 内存，用不起。
    模板级已能抓住"同一载荷只差常量"这类最主要的泄漏形式；近重复（改一个字符）
    可能跨侧，这一点在 `info["grouping"]` 里写明，不假装更严格。

    返回 (train_rest, valid, info)
    """
    from textsim import payload_of, template

    by_tpl = defaultdict(list)
    for i, s in enumerate(train):
        by_tpl[template(payload_of(s))].append(i)

    rng = np.random.default_rng(seed)
    order = list(by_tpl.values())
    rng.shuffle(order)                        # 同尺寸簇随机化（可复现）
    order.sort(key=lambda idxs: -len(idxs))   # 大簇优先，减少碎片

    want = Counter(s["label"] for s in train)
    target = {k: max(1, int(round(v * frac))) for k, v in want.items()}
    got, valid_pos = Counter(), set()
    for idxs in order:
        lab = Counter(train[i]["label"] for i in idxs).most_common(1)[0][0]
        if got[lab] < target.get(lab, 0):
            valid_pos.update(idxs)
            got[lab] += len(idxs)

    rest = [s for i, s in enumerate(train) if i not in valid_pos]
    valid = [s for i, s in enumerate(train) if i in valid_pos]
    return rest, valid, {
        "valid_frac": frac, "n_valid": len(valid),
        "valid_by_label": {str(k): int(v) for k, v in sorted(got.items())},
        "train_by_label": {str(k): int(v) for k, v in
                           sorted(Counter(s["label"] for s in rest).items())},
        "n_clusters": len(by_tpl),
        "grouping": "template-only（数字掩码同簇；近重复可能跨侧，已如实记录）",
        "note": "验证集从 payload_train 按同源簇 + 分层切出，训练集已剔除",
    }


# ---------------------------------------------------------------------------
# 上传数据（控制台 staging 清单）
# ---------------------------------------------------------------------------
def _req_key(s: dict) -> str:
    return "\x1f".join(str(s.get(k) or "") for k in ("method", "path", "query", "body"))


def _req_sha1(s: dict) -> str:
    return hashlib.sha1(_req_key(s).encode("utf-8", "replace")).hexdigest()


def _upload_text(s: dict) -> str:
    """上传数据的同源分组文本：method + path + query + body（不只 query）。"""
    return f"{s.get('method') or ''} {s.get('path') or ''}?{s.get('query') or ''} " \
           f"{s.get('body') or ''}"


def _load_upload_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        man = json.load(f)
    if not isinstance(man, dict):
        raise SystemExit("上传清单必须是 JSON 对象")
    if not man.get("datasets"):
        raise SystemExit("上传清单没有 datasets")
    return man


def _load_upload_rows(manifest: dict):
    """返回 [(dataset_meta, rows)]；rows 带 `_dataset_id` 便于追溯。"""
    from realdata import load_local_jsonl

    out = []
    for ds in manifest.get("datasets") or []:
        p = ds.get("train_path") or ds.get("requests_path")
        if not p or not os.path.exists(p):
            raise SystemExit(f"上传数据集 #{ds.get('id')} 的训练副本不存在：{p}")
        rows = load_local_jsonl(p)
        for r in rows:
            r["_dataset_id"] = ds.get("id")
            r["_dataset_name"] = ds.get("name")
        out.append((ds, rows))
    return out


def _split_benign_holdout(rows, frac: float = 0.5, seed: int = 11,
                          max_group: int = 2000):
    """从良性样本中切出独立校准留出。

    ≤2000 条用近重复分簇；更大时用模板级分组 + 随机取簇，避免 O(n²)。
    留出 <200 条时返回空 holdout（调用方回退官方 CSIC 池）。
    """
    benign = [s for s in rows if int(s.get("label", -1)) == 0]
    others = [s for s in rows if int(s.get("label", -1)) != 0]
    if len(benign) < 400:
        return list(rows), [], {"method": "too_small", "n_benign": len(benign)}

    texts = [_upload_text(s) for s in benign]
    hold_pos: set = set()
    if len(benign) <= max_group:
        try:
            from textsim import group_split
            tr_pos, ev_pos, extra = group_split(texts)
            hold_pos = set(ev_pos)
            method = f"group_split({extra})"
        except Exception as e:  # noqa: BLE001 - 极端文本退回模板级
            print(f"[upload] group_split 失败，退回模板级：{e}")
    if not hold_pos:
        from textsim import template
        by_tpl = defaultdict(list)
        for i, t in enumerate(texts):
            by_tpl[template(t)].append(i)
        clusters = list(by_tpl.values())
        rng = np.random.default_rng(seed)
        rng.shuffle(clusters)
        target = max(200, int(len(benign) * frac))
        for idxs in clusters:
            if len(hold_pos) >= target:
                break
            hold_pos.update(idxs)
        method = f"template-clusters(n={len(clusters)}, target={target})"

    if len(hold_pos) < 200 or len(hold_pos) >= len(benign):
        return list(rows), [], {"method": method, "n_benign": len(benign),
                                "n_holdout": len(hold_pos), "fallback": True}
    keep = [s for i, s in enumerate(benign) if i not in hold_pos]
    hold = [s for i, s in enumerate(benign) if i in hold_pos]
    return others + keep, hold, {
        "method": method, "n_benign": len(benign), "n_holdout": len(hold),
        "holdout_frac": round(len(hold) / max(1, len(benign)), 4)}


def _write_upload_artifacts(out_dir: str, train_rows, holdout_rows,
                            manifest: dict, calib_source: str,
                            overlap: dict) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "training_keys.txt"), "w", encoding="utf-8") as f:
        for s in train_rows:
            f.write(_req_sha1(s) + "\n")
    calib_meta = {}
    if holdout_rows:
        p = os.path.join(out_dir, "calibration_pool.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            for s in holdout_rows:
                f.write(json.dumps({k: s.get(k) or "" for k in
                                    ("method", "path", "query", "body", "label")},
                                   ensure_ascii=False) + "\n")
        calib_meta = {"source": calib_source, "file": "calibration_pool.jsonl",
                      "n": len(holdout_rows)}
    upload_meta = {
        "mode": manifest.get("mode"),
        "datasets": manifest.get("datasets") or [],
        "calib": calib_meta,
        "n_train_rows": len(train_rows),
        "n_holdout_rows": len(holdout_rows),
        "overlap_official_eval": overlap,
    }
    with open(os.path.join(out_dir, "upload_stats.json"), "w", encoding="utf-8") as f:
        json.dump(upload_meta, f, ensure_ascii=False, indent=2)
    return upload_meta


def _official_eval_keys(te, lex) -> set:
    keys = {_req_key(s) for s in te} | {_req_key(s) for s in lex}
    try:
        from realdata import csic_normal_index, load_csic
        reqs, _ = load_csic()
        _, hold = csic_normal_index(seed=7, n_train=30000)
        keys |= {_req_key(reqs[i]) for i in hold}
    except Exception as e:  # noqa: BLE001 - 缺 CSIC 时仍保护 payload 评估集
        print(f"[upload] CSIC 留出集不可用，跳过其重叠检查：{e}")
    return keys


def _filter_upload_overlap(rows, eval_keys: set):
    kept, dropped = [], []
    for s in rows:
        (dropped if _req_key(s) in eval_keys else kept).append(s)
    return kept, dropped


def load_all(hard_neg: str = "none", seed: int = 11, split_mode: str = "random",
             use_dict: bool = False, dict_benign_ratio: float = 1.0,
             extra_benign: int = 0, valid_frac: float = 0.0):
    """加载数据集。

    `hard_neg` 控制是否把**困难良性负样本**并入训练集（REALDATA_EVALUATION.md §8：
    误报的瓶颈是训练数据未覆盖部署分布，而 CSIC 正常流量覆盖不到长文本区域）：

      - "none"    : 只用 payload_train（公开数据集打底）
      - "lexical" : 把 lexical 正常的**前一半**并入训练；
                    评估改用**后一半**正常 + 全部异常（留出，避免自欺）
      - "csic"    : 把 CSIC 2010 正常流量 8,000 条并入训练（覆盖不到长文本，仅作对照）

    其它开关：
      * `seed`/`split_mode`  : lexical 训练/评估的切法（P0：量化估计抖动与同源泄漏）；
      * `valid_frac`         : 从 `payload_train` 按**同源簇 + 分层**切出验证集（早停用），
                               训练集已剔除它。**这是拿干净泛化指标的前提**：
                               `--es-set valid` 配合它，早停不再看测试集/验收集。
      * `use_dict`           : 并入 WEB_APPLICATION_PAYLOADS 攻击字典（按载荷 md5 去重，
                               **并剔除出现在 payload_test/lexical 里的条目**，避免泄漏）；
      * `dict_benign_ratio`  : 字典只有攻击、没有良性，按此比例补 CSIC 正常流量以维持类先验；
      * `extra_benign`       : 额外并入 N 条 CSIC 正常流量（取**最前面**的，与 FPR 留出池不重叠）。

    返回 (train, valid, test, lexical_eval, info) —— `valid` 在 `valid_frac=0` 时为 None
    （此时早停/验证仍用 `payload_test`，但那是**测试集**，用它早停会让报告偏乐观）。
    """
    tr = load_payloads(os.path.join(TRAINDATA, "payload_train.csv"))
    te = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))
    info = {"hard_neg": hard_neg, "added": 0, "seed": seed, "split_mode": split_mode}

    va = None
    if valid_frac and valid_frac > 0:
        tr, va, vinfo = _split_valid(tr, float(valid_frac), seed)
        info.update(vinfo)

    csic_requests = None

    def csic_normals(limit: int):
        """CSIC 正常流量（**从最前面取**，与评估用的末尾 6,000 条不重叠）。"""
        nonlocal csic_requests
        if csic_requests is None:
            reqs, y = load_csic()
            csic_requests = [r for r, v in zip(reqs, y) if v == 0]
        return csic_requests[:limit]

    if hard_neg == "lexical":
        add_idx, keep, extra = _lexical_halves(lex, split_mode, seed)
        tr = tr + [{**lex[i], "label": 0, "source": "lexical_normal"} for i in add_idx]
        lex_eval = [lex[i] for i in range(len(lex))
                    if (lex[i]["label"] == 0 and i in keep) or lex[i]["label"] != 0]
        info.update({"added": len(add_idx), "lexical_eval_normal": len(keep),
                     "note": "同分布自适应：lexical 正常一半进训练，评估用留出一半",
                     **extra})
    elif hard_neg == "csic":
        normal = csic_normals(8000)
        tr = tr + [{**r, "label": 0, "source": "csic_normal"} for r in normal]
        info.update({"added": len(normal), "note": "CSIC 正常流量（真实但非长文本）"})
        lex_eval = lex
    elif hard_neg == "none":
        lex_eval = lex
    else:
        raise ValueError(f"unknown hard_neg={hard_neg!r}")

    # ---- 攻击字典增强 ----
    if use_dict:
        import hashlib
        from realdata import load_payload_dict

        def md5(sample):
            return hashlib.md5((sample.get("query") or "").encode("utf-8", "replace")).hexdigest()

        seen = {md5(s) for s in tr} | {md5(s) for s in te} | {md5(s) for s in lex_eval}
        entries, bad = load_payload_dict()
        kept, dropped_dup, dropped_unmapped = [], 0, 0
        for s in entries:
            if s["label"] < 0:
                dropped_unmapped += 1
                continue
            h = md5(s)
            if h in seen:
                dropped_dup += 1
                continue
            seen.add(h)
            kept.append({**s, "source": f"dict-{s['family']}"})

        added_benign = 0
        if dict_benign_ratio > 0 and kept:
            n = int(round(dict_benign_ratio * len(kept)))
            benign = csic_normals(n)
            kept += [{**r, "label": 0, "source": "csic_normal(dict_balance)"} for r in benign]
            added_benign = len(benign)

        tr = tr + kept
        from collections import Counter
        info["dict"] = {
            "entries": len(entries), "bad_objects": bad, "kept": len(kept) - added_benign,
            "dropped_dup": dropped_dup, "dropped_unmapped": dropped_unmapped,
            "benign_added": added_benign, "benign_ratio": dict_benign_ratio,
            "by_label": {str(k): v for k, v in
                         sorted(Counter(s["label"] for s in kept if s["label"] > 0).items())},
        }

    if extra_benign:
        benign = csic_normals(extra_benign)
        tr = tr + [{**r, "label": 0, "source": "csic_normal(extra)"} for r in benign]
        info["extra_benign"] = len(benign)

    return tr, va, te, lex_eval, info


def class_weights(y, n_class):
    cnt = np.bincount(y, minlength=n_class).astype(np.float64)
    return (len(y) / (n_class * np.maximum(cnt, 1)))[y], cnt


def balance_classes(X, y, mode: str, seed: int = 11):
    """类别不平衡处理（返回 X', y', 说明）。

      - "weight" : 不动数据，用逆频样本权重（默认，等价历史行为）
      - "over"   : 少数类**过采样**到多数类规模（有放回）
      - "under"  : 多数类**欠采样**到少数类规模（不放回）
      - "none"   : 都不做

    注意过采样会让**同一请求**在训练集里出现多次 —— 学习曲线上会表现为"更快过拟合"，
    所以 `run()` 里对 over/under 不再叠加逆频权重（避免双重纠正）。
    """
    if mode in ("weight", "none"):
        return X, y, ""
    rng = np.random.default_rng(seed)
    cnt = np.bincount(y)
    present = [c for c in range(len(cnt)) if cnt[c] > 0]
    if mode == "over":
        tgt = int(cnt.max())
        idx = np.concatenate([rng.choice(np.flatnonzero(y == c), tgt, replace=True) for c in present])
        note = f"过采样每类 -> {tgt}"
    else:  # under
        tgt = int(min(cnt[c] for c in present))
        idx = np.concatenate([rng.choice(np.flatnonzero(y == c), tgt, replace=False) for c in present])
        note = f"欠采样每类 -> {tgt}"
    rng.shuffle(idx)
    return X[idx], y[idx], note


def detect_at_fpr(score, is_attack, fpr_target):
    neg = score[~is_attack]
    thr = float(np.quantile(neg, 1.0 - fpr_target))
    tp = int(((score >= thr) & is_attack).sum())
    fp = int(((score >= thr) & ~is_attack).sum())
    fn = int(((score < thr) & is_attack).sum())
    tn = int(((score < thr) & ~is_attack).sum())
    return tp / max(1, tp + fn), fp / max(1, fp + tn)


def attack_prob(clf, X):
    p = clf.predict_proba(X)
    normal = list(clf.classes_).index(0)
    return 1.0 - p[:, normal]


def summarize(clf, X, y):
    pred = clf.predict(X)
    if getattr(pred, "ndim", 1) > 1:
        # 上传数据可能只覆盖部分类别；num_class 固定 5 时 predict 可能返回 5 列。
        pred = pred.argmax(axis=1)
    s = attack_prob(clf, X)
    ya = y != 0
    from sklearn.metrics import roc_auc_score
    out = {
        "n": int(len(y)),
        "accuracy": float((pred == y).mean()),
        "auc_binary": float(roc_auc_score(ya, s)) if ya.any() and (~ya).any() else float("nan"),
        "per_class": {},
        "budgets": {},
    }
    for i in sorted(set(y) | set(pred)):
        m = y == i
        tp = int(((pred == i) & m).sum())
        fp = int(((pred == i) & ~m).sum())
        fn = int(((pred != i) & m).sum())
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        out["per_class"][TARGET_NAMES[i]] = {
            "n": int(m.sum()), "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / max(1e-12, prec + rec),
        }
    for f in (0.001, 0.01, 0.03, 0.05):
        dr, fpr = detect_at_fpr(s, ya, f)
        out["budgets"][f"{f:g}"] = {"detect": dr, "fpr": fpr}
    return out


def print_summary(title, s):
    print(f"\n=== {title}  (n={s['n']}) ===")
    print(f"  accuracy={s['accuracy']:.4f}  AUC={s['auc_binary']:.4f}")
    for k, v in s["per_class"].items():
        print(f"    {k:<10} P={v['precision']:.3f} R={v['recall']:.3f} "
              f"F1={v['f1']:.3f} n={v['n']}")
    print("  正常 vs 攻击 @FPR 预算:")
    for k, v in s["budgets"].items():
        print(f"    @{k:>5}  检测率={v['detect']*100:5.1f}%  (实际FPR={v['fpr']*100:.2f}%)")


# ---------------------------------------------------------------------------
def run(version: str, tr, te, lex, rounds: int, depth: int, lr: float,
        export: bool, run_name: str, info: dict | None = None, es: int = 0,
        balance: str = "weight", es_set: str = "lexical", local_eval=None,
        valid_eval=None, out_dir: str = ART, artifact_name: str = "xgboost_v20261015_001.onnx",
        parent_model: str | None = None, parent_meta: str | None = None,
        calib_pool=None, calib_note: str | None = None, upload_meta=None):
    import xgboost as xgb

    fx = make_extractor(version)
    print(f"\n{'='*78}\n[run] {run_name}  features={version}  dim={len(fx.names)}"
          f"{f'  early_stopping={es}' if es else ''}\n{'='*78}")

    # ---- warm start：父代校验（特征版本/维度/标签必须完全一致）----
    base_trees = 0
    if parent_model:
        pm = {}
        if parent_meta and os.path.exists(parent_meta):
            try:
                with open(parent_meta, "r", encoding="utf-8") as f:
                    pm = json.load(f)
            except (OSError, ValueError):
                pm = {}
        if pm:
            pver = pm.get("features_version")
            if pver and pver != version:
                raise SystemExit(f"父代特征版本 {pver} 与当前 {version} 不一致，拒绝 warm start")
            pnames = pm.get("feature_names") or []
            if pnames and len(pnames) != len(fx.names):
                raise SystemExit(f"父代特征维度 {len(pnames)} 与当前 {len(fx.names)} 不一致，拒绝 warm start")
            plabels = pm.get("labels") or {}
            if plabels and {str(k): str(v) for k, v in plabels.items()} != {
                    str(k): str(v) for k, v in LABELS.items()}:
                raise SystemExit("父代标签集与当前不一致，拒绝 warm start")
        booster = xgb.Booster()
        booster.load_model(parent_model)
        if int(booster.num_features()) != len(fx.names):
            raise SystemExit(
                f"父代 booster 特征数 {booster.num_features()} 与当前 {len(fx.names)} 不一致，拒绝 warm start")
        base_trees = int(booster.num_boosted_rounds())
        print(f"[warm] 从父代继续训练：base_trees={base_trees}  +{rounds} rounds")

    Xtr = to_X(fx, tr)
    ytr = np.asarray([s["label"] for s in tr])
    print("[data] train class counts:",
          {TARGET_NAMES[i]: int(v)
           for i, v in enumerate(np.bincount(ytr, minlength=len(LABELS)))})
    Xtr, ytr, bal_note = balance_classes(Xtr, ytr, balance, seed=int((info or {}).get("seed") or 11))
    if bal_note:
        print(f"[balance] {balance}: {bal_note}")
    w, cnt = class_weights(ytr, len(LABELS))
    if balance in ("over", "under", "none"):
        w = None    # 已重采样 / 明确不加权，避免双重纠正
    if bal_note:
        print("[data] train class counts after balance:",
              {TARGET_NAMES[i]: int(cnt[i]) for i in range(len(cnt))})
    else:
        print("[data] class counts:", {TARGET_NAMES[i]: int(cnt[i]) for i in range(len(cnt))})

    Xte, yte = to_X(fx, te), np.asarray([s["label"] for s in te])
    Xlex, ylex = to_X(fx, lex), np.asarray([s["label"] for s in lex])

    if valid_eval is not None and len(valid_eval):
        # 三段切分：valid 来自 payload_train 的同源簇分层留出（干净），
        # payload_test 降级为"报告集"，不再参与早停/选择。
        Xva = to_X(fx, valid_eval)
        yva = np.asarray([s["label"] for s in valid_eval])
        evals = [("train", Xtr, ytr), ("valid", Xva, yva), ("lexical", Xlex, ylex),
                 ("payload_test", Xte, yte)]
        print(f"[split] 三段切分：valid={len(valid_eval)} 条来自 payload_train（同源簇不跨界），"
              f"payload_test 仅作报告集")
    else:
        evals = [("train", Xtr, ytr), ("valid", Xte, yte), ("lexical", Xlex, ylex)]
        if es and es_set == "valid":
            print("[split] ⚠️ 未提供三段切分（--valid-frac），`valid` 就是 payload_test —— "
                  "用测试集早停会让报告偏乐观。建议加 --valid-frac 0.1")
    if local_eval is not None and len(local_eval):
        evals.append(("local", to_X(fx, local_eval),
                      np.asarray([s["label"] for s in local_eval])))
    if es and es_set not in [e[0] for e in evals]:
        raise SystemExit(f"--es-set {es_set} 不在可用监控集 {[e[0] for e in evals]} 内")
    if es:
        # xgboost 用 eval_set 里**最后一个**做早停，所以把监控集排到最后
        evals.sort(key=lambda e: (e[0] == es_set))
    print(f"[es] 监控集 = {es_set if es else '无（不早停）'}"
          + (f"   eval 顺序 = {[e[0] for e in evals]}" if es else ""))
    if es and es_set == "lexical":
        print("[es] ⚠️ 注意：lexical 是**验收集**（验收门槛）。用它早停会让 lexical 指标偏乐观，"
              "报告里必须注明 `es_monitored=lexical`；要干净结论请另切一份同分布验证集。")

    # ⚠️ XGBoost 隐式早停（`early_stopping_rounds`）只看**最后一个** eval 集的
    # **最后一个** 指标。所以 `mlogloss` 必须放在 `merror` 后面，否则监控的是
    # merror（分类错误率）—— 那是阶跃信号，会在"已经全对"时立刻停。
    # 这不是推测：历史曲线的 best_iteration 恰好等于 merror 的 argmin（r62 / r8），
    # 证明之前 "--es-set valid" 实际停在了 merror 上。见 REALDATA_EVALUATION.md §8.6。
    EVAL_METRICS = ["merror", "mlogloss"]      # ← mlogloss 必须最后
    es_metric = "mlogloss"
    clf = xgb.XGBClassifier(
        n_estimators=rounds, max_depth=depth, learning_rate=lr,
        subsample=0.9, colsample_bytree=0.9,
        objective="multi:softprob", num_class=len(LABELS),
        tree_method="hist", n_jobs=os.cpu_count(),
        eval_metric=EVAL_METRICS, random_state=42,
        **({"early_stopping_rounds": es} if es else {}),
    )
    t0 = time.time()
    fit_kw = dict(sample_weight=w, verbose=False,
                  eval_set=[(X, y) for _, X, y in evals])
    if parent_model:
        fit_kw["xgb_model"] = parent_model
    clf.fit(Xtr, ytr, **fit_kw)
    train_s = time.time() - t0
    best_iter = int(getattr(clf, "best_iteration", -1) or -1)
    total_trees = int(clf.get_booster().num_boosted_rounds())
    print(f"[train] {train_s:.1f}s  ({rounds} rounds x {len(LABELS)} classes)"
          + (f"  early-stopped at {best_iter+1}" if es and best_iter >= 0 else ""))

    # 自检：best_iteration 必须等于被监控集 **mlogloss** 的 argmin（0-based）。
    # 若不等，说明 ES 盯上了别的指标，本轮结论不可用。
    if es and best_iter >= 0:
        er = clf.evals_result()
        hit = [(i, e[0]) for i, e in enumerate(evals) if e[0] == es_set]
        for i, nm in hit:
            vals = (er.get(f"validation_{i}") or {}).get(es_metric)
            if not vals:
                continue
            am = min(range(len(vals)), key=lambda j: vals[j])
            ok = (am == best_iter)
            print(f"[es] 自检：监控 {nm}_{es_metric}  argmin@{am+1}  vs "
                  f"best_iteration={best_iter+1}  {'✓ 一致' if ok else '✗ 不一致！'}")
            if not ok:
                print("[es] ⚠️ 早停监控的不是 mlogloss，本轮不得作为结论。")

    # ---- 学习曲线 ----
    curve_dir = os.path.join(out_dir, "curves")
    rec = CurveRecorder(run_name, out_dir=curve_dir)
    rec.from_evals_result(clf.evals_result(),
                          names={f"validation_{i}": e[0] for i, e in enumerate(evals)},
                          x_offset=base_trees)
    paths = rec.save(meta={"features": version, "dim": len(fx.names),
                           "base_trees": base_trees, "total_trees": total_trees,
                           "parent_model": os.path.basename(parent_model) if parent_model else None,
                           "rounds": rounds, "depth": depth, "lr": lr,
                           "early_stopping_rounds": es, "best_iteration": best_iter,
                           "es_monitored": (es_set if es else None),
                           "es_metric": (es_metric if es else None),
                           "balance": balance,
                           "eval_order": [e[0] for e in evals],
                           "n_local_eval": (len(local_eval) if local_eval else 0),
                           "train_seconds": round(train_s, 2),
                           "hard_neg": (info or {}).get("hard_neg", "none"),
                           "hard_neg_added": (info or {}).get("added", 0),
                           "lexical_split": (info or {}).get("lexical_split", ""),
                           "seed": (info or {}).get("seed"),
                           "dict": (info or {}).get("dict"),
                           "run": run_name})
    print(f"[curve] -> {os.path.relpath(paths['json'], HERE)}"
          + (f", {os.path.relpath(paths['png'], HERE)}" if "png" in paths else ""))

    # ---- 树规模（对比"数据太简单"）----
    df = clf.get_booster().trees_to_dataframe()
    n_trees = int(df["Tree"].nunique())
    n_nodes = int(len(df))
    print(f"[model] {n_trees} trees, {n_nodes} nodes (avg {n_nodes/n_trees:.1f}/tree)")

    s_te = summarize(clf, Xte, yte)
    s_lex = summarize(clf, Xlex, ylex)
    print_summary("HTTP Params TEST (载荷不重叠)", s_te)
    print_summary("HTTP Params LEXICAL (困难集/验收门槛)", s_lex)

    s_loc = None
    if any(e[0] == "local" for e in evals):
        s_loc = summarize(clf, to_X(fx, local_eval),
                          np.asarray([s["label"] for s in local_eval]))
        print_summary("真实本地/在野 eval（样本极少，只看方向）", s_loc)
        if len(local_eval) < 200:
            print(f"[local] ⚠️ 真实 eval 只有 {len(local_eval)} 条，"
                  f"检出率置信区间极宽，不要当结论用。")

    if export:
        import train_xgboost as tk
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, artifact_name)
        tk.export_onnx(clf, len(fx.names), out)
        print(f"[onnx] saved -> {out} ({os.path.getsize(out)/1024:.0f} KB)")
        clf.get_booster().save_model(os.path.join(out_dir, "xgb_model.json"))
        tk.dump_trees(clf, os.path.join(out_dir, "xgb_trees.json"), len(LABELS), len(fx.names))

        # ---- 决策阈值（S7）：在**未参与训练**的良性池上标定 ----
        # 理由见 REALDATA_EVALUATION.md §8.3：argmax 的误报落点在 0.8%–3.2% 间乱跳，
        # 换成「score = 1 - P(normal) >= thr」后误报可控且 KPI 可审计。
        # 池协议与零日通道（iforest）**统一**为 realdata.csic_normal_index(seed=7)
        # 的留出一半 —— 否则两条通道的阈值来自不同子集，融合后的误报率不可解释。
        calib = None
        upload_art = None
        try:
            if calib_pool is not None:
                pool = list(calib_pool)
                pool_name = calib_note or "上传良性留出"
            elif (info or {}).get("hard_neg") == "csic":
                pool = [s for s in lex if s["label"] == 0]
                pool_name = "lexical 留出正常 500 条（CSIC 已进训练，故改用 lexical）"
            else:
                from realdata import csic_normal_index
                reqs, _ = load_csic()
                _, hold_idx = csic_normal_index(seed=7, n_train=30000)
                pool = [reqs[i] for i in hold_idx]
                pool_name = ("CSIC 2010 正常流量留出一半（seed=7 随机切分，6000 条，"
                             "与零日通道训练集互斥）")
            s_pool = attack_prob(clf, to_X(fx, pool))
            calib = {
                "score_def": "1 - P(normal)",
                "calibration_pool": pool_name,
                "n_pool": int(len(pool)),
                "thresholds": {f"{f:g}": float(np.quantile(s_pool, 1.0 - f))
                               for f in (0.001, 0.01, 0.03)},
                "actual_fpr": {f"{f:g}": float((s_pool >= np.quantile(s_pool, 1.0 - f)).mean())
                               for f in (0.001, 0.01, 0.03)},
                "recommended": "0.01",
                "authoritative_source": ("artifacts/decision_policy.json（由 thresholds.py 生成；"
                                         "本字段仅为训练记录）"),
                "warning": ("阈值必须在**独立留出**流量上重标定；绝不能把训练用良性样本放进"
                            "校准池（否则估计偏乐观，实测可差 8 倍，见 §8.3）"),
            }
            print(f"[threshold] 1%FPR 阈值 = {calib['thresholds']['0.01']:.6f}  "
                  f"(池: {pool_name})")
        except Exception as exc:  # 缺 CSIC 目录时不阻断导出
            print(f"[threshold] 跳过阈值标定：{exc}")

        # 上传训练产物：训练指纹 + 校准池 + 统计，供切换时按模型自己的口径重标定。
        if upload_meta is not None:
            um = dict(upload_meta)
            um["calib"] = ({"source": (calib_note or "upload"),
                            "file": "calibration_pool.jsonl",
                            "n": len(calib_pool)} if calib_pool is not None else {})
            upload_art = _write_upload_artifacts(
                out_dir, tr, (calib_pool or []), um,
                (calib_note or "upload"), um.get("overlap_official_eval") or {})
            print(f"[upload] 训练指纹 {len(tr)} 条；校准留出 "
                  f"{len(calib_pool) if calib_pool is not None else 0} 条")

        with open(os.path.join(out_dir, "xgboost_meta.json"), "w", encoding="utf-8") as f:
            json.dump({"feature_names": fx.names, "labels": LABELS,
                       "features_version": version,
                       "base_trees": base_trees, "total_trees": total_trees,
                       "parent_model": (os.path.basename(parent_model) if parent_model else None),
                       "inherit_mode": ("warm_start" if parent_model else "full"),
                       "training_recipe": {
                           "n_estimators": rounds, "max_depth": depth, "lr": lr,
                           "early_stopping_rounds": es,
                           "best_iteration": best_iter,
                           "base_trees": base_trees, "total_trees": total_trees,
                           "inherit_mode": ("warm_start" if parent_model else "full"),
                           "class_weight": "balanced (inverse frequency)",
                           "hard_neg": (info or {}).get("hard_neg", "none"),
                           "hard_neg_added": (info or {}).get("added", 0),
                           "hard_neg_note": (info or {}).get("note", ""),
                           "lexical_split": (info or {}).get("lexical_split", ""),
                           "seed": (info or {}).get("seed"),
                           "dict_augmentation": (info or {}).get("dict"),
                           "extra_benign": (info or {}).get("extra_benign", 0),
                           "local_benign_added": (info or {}).get("local_benign_added", 0),
                           "local_benign_source": (info or {}).get("local_benign_source"),
                           "local_eval_n": (len(local_eval) if local_eval else 0),
                           "local_eval_n_attack": (int((np.asarray([s["label"] for s in local_eval]) != 0).sum())
                                                   if local_eval else 0),
                           "balance": balance,
                           "es_monitored": (es_set if es else None),
                           "es_metric": (es_metric if es else None),
                           "valid_frac": (info or {}).get("valid_frac", 0.0),
                           "n_valid": (info or {}).get("n_valid", 0),
                           "n_train": int(len(ytr)),
                           "dataset": (
                               "上传数据（only）" if (upload_meta or {}).get("mode") == "only"
                               else ("HTTP Params 2015 + 上传数据（add）"
                                     if upload_meta else
                                     "HTTP Params 2015 (payload_train/test) + lexical 正常一半")),
                           "upload_mode": (upload_meta or {}).get("mode"),
                           "upload_datasets": (upload_meta or {}).get("datasets"),
                           "upload_calib": (upload_art or {}).get("calib"),
                       },
                       **({"datasets": upload_meta.get("datasets")} if upload_meta else {}),
                       **({"upload": upload_art} if upload_art else {}),
                       **({"training_keys_file": "training_keys.txt"} if upload_meta else {}),
                       **({"eval_note": "official test/lexical 仅作迁移评估（训练未使用官方训练集）"}
                          if (upload_meta or {}).get("mode") == "only" else {}),
                       "decision_threshold": calib,
                       "metrics": {"test": s_te, "lexical": s_lex,
                                   **({"local": s_loc} if s_loc else {}),
                                   "n_trees": n_trees, "n_nodes": n_nodes,
                                   "train_seconds": round(train_s, 2)},
                       "model": os.path.basename(out)}, f, ensure_ascii=False, indent=2)
        print("[meta] -> artifacts/xgboost_meta.json")

    return {"version": version, "dim": len(fx.names), "n_trees": n_trees,
            "n_nodes": n_nodes, "train_seconds": round(train_s, 2),
            "test": s_te, "lexical": s_lex, "local": s_loc}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", choices=["v1", "v2"], default="v2")
    ap.add_argument("--ab", action="store_true", help="同时跑 v1 与 v2 并对比")
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--es", type=int, default=0,
                    help="early stopping 轮数（0=不早停）。监控指标固定为 **mlogloss**（不是 merror）")
    ap.add_argument("--valid-frac", type=float, default=0.0,
                    help="从 payload_train 切出验证集的比例（0=不切，旧行为用 payload_test）")
    ap.add_argument("--es-set", choices=["valid", "lexical", "local"], default="lexical",
                    help="早停监控哪个 eval 集（指标=mlogloss）。lexical=在验收困难集崩塌前停"
                         "（注意：lexical 是验收集，用它早停会让 lexical 指标偏乐观）；"
                         "local=真实本地留出（需 --local）；valid=payload_test（未切验证集时）")
    ap.add_argument("--balance", choices=["weight", "over", "under", "none"], default="weight",
                    help="类别不平衡处理：weight=逆频加权（历史行为）/over=过采样/under=欠采样/none")
    ap.add_argument("--local", action="store_true",
                    help="并入/评估**真实本地流量**（工作项 F 采集产物，见 collect_http_log.py）")
    ap.add_argument("--local-benign", default=None,
                    help="真实本地良性 jsonl（默认 traindata/local/local_lab_benign.jsonl）")
    ap.add_argument("--local-attack", default=None,
                    help="真实攻击 jsonl（默认 traindata/local/inwild_attack.jsonl）")
    ap.add_argument("--local-hard-neg", action="store_true",
                    help="把真实本地良性（训练半边）作为**困难负样本**并入训练集")
    ap.add_argument("--export", action="store_true", help="导出 ONNX + xgb_trees.json")
    ap.add_argument("--out-dir", default=ART,
                    help="产物目录（控制台训练传 staging；默认 artifacts）")
    ap.add_argument("--artifact-name", default="xgboost_v20261015_001.onnx",
                    help="导出的 ONNX 文件名（控制台 staging 用 model.onnx）")
    ap.add_argument("--run-name", default=None,
                    help="学习曲线 run 名称（默认按参数自动生成）")
    ap.add_argument("--parent-model", default=None,
                    help="warm start 父代 xgb_model.json 路径")
    ap.add_argument("--parent-meta", default=None,
                    help="warm start 父代 meta（校验特征/标签）")
    ap.add_argument("--upload-manifest", default=None,
                    help="控制台生成的上传数据清单（staging/datasets.json）")
    ap.add_argument("--upload-mode", choices=["add", "only"], default=None,
                    help="add=官方训练集+上传；only=只用上传数据训练")
    ap.add_argument("--calib-mode", choices=["auto", "official", "upload"], default="auto",
                    help="阈值校准池：auto=上传良性留出优先，不足回退官方；official=官方；upload=必须用上传留出")
    ap.add_argument("--calib-dataset-id", type=int, default=None,
                    help="指定用哪个上传数据集的良性留出做校准池")
    ap.add_argument("--hard-neg", choices=["none", "lexical", "csic"], default="none",
                    help="把困难良性负样本并入训练集（lexical=同分布自适应，见 REALDATA §8）")
    ap.add_argument("--seed", type=int, default=11,
                    help="lexical 训练/评估切分随机种子（P0：估计抖动）")
    ap.add_argument("--lexical-split", choices=["random", "grouped"], default="random",
                    help="grouped = 同源簇不跨训练/评估（不乐观的 FPR 基准）")
    ap.add_argument("--dict", action="store_true",
                    help="并入 WEB_APPLICATION_PAYLOADS 攻击字典（按载荷去重、剔除评估集重叠）")
    ap.add_argument("--dict-benign-ratio", type=float, default=1.0,
                    help="字典只有攻击，按此比例补 CSIC 正常流量以维持类先验（0=不补）")
    ap.add_argument("--extra-benign", type=int, default=0,
                    help="额外并入 N 条 CSIC 正常流量（取自最前面，与 FPR 留出池不重叠）")
    args = ap.parse_args()

    tr, va, te, lex, info = load_all(args.hard_neg, seed=args.seed,
                                     split_mode=args.lexical_split,
                                     use_dict=args.dict,
                                     dict_benign_ratio=args.dict_benign_ratio,
                                     extra_benign=args.extra_benign,
                                     valid_frac=args.valid_frac)
    if va is not None:
        print(f"[split] valid={len(va)} 条（按类分层 {info.get('valid_by_label')}，"
              f"簇数 {info.get('n_clusters')}）；训练集已剔除")

    # ---- 上传数据：合并 / 替换 + 校准留出 ----
    upload_meta = None
    calib_pool = None
    calib_note = None
    if args.upload_mode:
        if not args.upload_manifest:
            raise SystemExit("--upload-mode 需要 --upload-manifest（控制台生成）")
        manifest = _load_upload_manifest(args.upload_manifest)
        manifest["mode"] = args.upload_mode
        eval_keys = _official_eval_keys(te, lex)
        kept_by_ds: dict = {}
        upload_rows: list = []
        ov_total = ov_n = 0
        for ds, rows in _load_upload_rows(manifest):
            kept, dropped = _filter_upload_overlap(rows, eval_keys)
            kept_by_ds[ds.get("id")] = kept
            ov_total += len(rows)
            ov_n += len(dropped)
            ds["rows_loaded"] = len(rows)
            ds["rows_after_overlap"] = len(kept)
            ds["rows_overlap"] = len(dropped)
            upload_rows += kept
        if not upload_rows:
            raise SystemExit("上传数据在剔除官方评估集重叠后为空，拒绝训练")
        print(f"[upload] mode={args.upload_mode} datasets={len(manifest['datasets'])} "
              f"rows={len(upload_rows)}（剔除与官方评估集重叠 {ov_n}/{ov_total}）")

        # 校准数据集选择：显式 > 良性最多。
        calib_ds = None
        if args.calib_dataset_id is not None:
            calib_ds = next((d for d in manifest["datasets"]
                             if int(d.get("id") or -1) == args.calib_dataset_id), None)
            if calib_ds is None:
                raise SystemExit(f"--calib-dataset-id {args.calib_dataset_id} 不在清单里")
        else:
            cands = sorted(manifest["datasets"],
                           key=lambda d: -(int((d.get("label_counts") or {}).get("0", 0))))
            calib_ds = cands[0] if cands else None
        if args.calib_mode != "official" and calib_ds is not None:
            rest, hold, cinfo = _split_benign_holdout(kept_by_ds.get(calib_ds.get("id"), []),
                                                      seed=args.seed)
            print(f"[upload] 校准选择 dataset#{calib_ds.get('id')} "
                  f"holdout={len(hold)} {cinfo}")
            if hold:
                hold_keys = {_req_key(s) for s in hold}
                upload_rows = [s for s in upload_rows if _req_key(s) not in hold_keys]
                calib_pool = hold
                calib_note = f"上传良性留出 upload:{calib_ds.get('id')}（{len(hold)} 条）"
            elif args.calib_mode == "upload":
                raise SystemExit("--calib-mode upload 但上传数据切不出 ≥200 条良性留出")
            else:
                print("[upload] 留出不足 200 条，校准池回退官方 CSIC")
        elif args.calib_mode == "upload":
            raise SystemExit("--calib-mode upload 需要至少一个可用的上传数据集")

        if args.upload_mode == "only":
            tr = upload_rows
            va = None
            if args.valid_frac and args.valid_frac > 0 and len(tr) > 20:
                tr, va, vinfo = _split_valid(tr, float(args.valid_frac), args.seed)
                info.update(vinfo)
                print(f"[upload] only：另切 valid={len(va)} 条")
        else:
            tr = tr + upload_rows
        info["upload_mode"] = args.upload_mode
        info["upload_rows"] = len(upload_rows)
        info["upload_added"] = len(upload_rows)
        upload_meta = {
            "mode": args.upload_mode,
            "datasets": manifest["datasets"],
            "calib_dataset_id": (calib_ds or {}).get("id"),
            "calib_mode": args.calib_mode,
            "overlap_official_eval": {"n": ov_n, "total": ov_total,
                                      "rate": (ov_n / ov_total) if ov_total else 0.0},
        }
        if not tr:
            raise SystemExit("训练集为空")

    local_eval = None
    if args.local:
        from realdata import load_local_jsonl
        from textsim import group_split
        lb = args.local_benign or os.path.join(HERE, "..", "traindata", "local",
                                               "local_lab_benign.jsonl")
        la = args.local_attack or os.path.join(HERE, "..", "traindata", "local",
                                               "inwild_attack.jsonl")
        benign = load_local_jsonl(lb, label=0) if os.path.exists(lb) else []
        attack = load_local_jsonl(la) if os.path.exists(la) else []
        if not benign:
            raise SystemExit(f"--local 需要真实本地良性数据，未找到 {lb}\n"
                             f"        先用 collect_http_log.py 采集（见 python/README.md）")
        texts = [f"{s['method']} {s['path']}?{s['query']}" for s in benign]
        tr_pos, hold_pos, ginfo = group_split(texts)
        if args.local_hard_neg:
            add = [benign[i] for i in tr_pos]
            tr = tr + add
            info["local_benign_added"] = len(add)
        info["local_benign_source"] = os.path.relpath(os.path.abspath(lb), HERE)
        local_eval = [benign[i] for i in hold_pos] + attack
        print(f"[local] 真实本地良性 {len(benign)} 条（训练半边 {len(tr_pos)} / 留出 {len(hold_pos)}，"
              f"{ginfo['n_clusters']} 簇）+ 真实攻击 {len(attack)} 条 → eval n={len(local_eval)}")
        if not attack:
            print("[local] ❗真实攻击样本 = 0：**无法**衡量真实攻击召回，"
                  "XGBoost 也不能在无真实攻击的数据上重训。\n"
                  "        攻击标签必须来自出处（蜜罐/红队/复核），见 collect_http_log.py 模块文档。")
        if args.local and args.export and not attack:
            print("[local] 仍会导出，但产物只体现「真实良性困难负样本」的收益，"
                  "**不体现**真实攻击召回 —— 报告里必须这么写。")

    print(f"[data] train={len(tr)} valid={len(te)} lexical={len(lex)} "
          f"hard_neg={info['hard_neg']} (+{info['added']})  "
          f"split={info.get('lexical_split','')}"
          + (f"  local_hard_neg=+{info.get('local_benign_added',0)}" if args.local_hard_neg else ""))
    if info.get("note"):
        print(f"[data] 注意：{info['note']}")
    if info.get("dict"):
        print(f"[data] 字典增强：{info['dict']}")

    name_bits = []
    if args.hard_neg != "none":
        name_bits.append(args.hard_neg)
    if args.lexical_split != "random":
        name_bits.append(args.lexical_split)
    if args.dict:
        name_bits.append("dict")
    if args.extra_benign:
        name_bits.append(f"extra{args.extra_benign}")
    if args.balance != "weight":
        name_bits.append(f"bal-{args.balance}")
    if args.es:
        name_bits.append(f"es{args.es}-{args.es_set}")
    if args.valid_frac:
        name_bits.append(f"vf{args.valid_frac:g}")
    if args.local:
        name_bits.append("local" + ("-hn" if args.local_hard_neg else ""))
    if args.upload_mode:
        name_bits.append("upload-" + args.upload_mode)
    if args.seed != 11:
        name_bits.append(f"s{args.seed}")

    versions = ["v1", "v2"] if args.ab else [args.features]
    results = []
    for v in versions:
        name = args.run_name or f"xgboost_realdata_{v}"
        if not args.run_name and name_bits:
            name += "_" + "_".join(name_bits)
        results.append(run(v, tr, te, lex, args.rounds, args.depth, args.lr,
                           args.export and not args.ab, name, info, es=args.es,
                           balance=args.balance, es_set=args.es_set, local_eval=local_eval,
                           valid_eval=va, out_dir=args.out_dir,
                           artifact_name=args.artifact_name,
                           parent_model=args.parent_model, parent_meta=args.parent_meta,
                           calib_pool=calib_pool, calib_note=calib_note,
                           upload_meta=upload_meta))

    if args.ab and len(results) == 2:
        a, b = results
        print(f"\n{'='*78}\n[AB] 特征 v1 -> v2 对比\n{'='*78}")
        print(f"  dim           {a['dim']:>8} -> {b['dim']:<8}")
        print(f"  nodes/tree    {a['n_nodes']/a['n_trees']:>8.1f} -> "
              f"{b['n_nodes']/b['n_trees']:<8.1f}")
        for tag, key in [("TEST   acc", "accuracy"), ("TEST   AUC", "auc_binary")]:
            print(f"  {tag:<13} {a['test'][key]:>8.4f} -> {b['test'][key]:<8.4f}")
        for tag, key in [("LEXICAL acc", "accuracy"), ("LEXICAL AUC", "auc_binary")]:
            print(f"  {tag:<13} {a['lexical'][key]:>8.4f} -> {b['lexical'][key]:<8.4f}")
        for fpr in ("0.01", "0.03"):
            na = a["lexical"]["per_class"]["normal"]
            nb = b["lexical"]["per_class"]["normal"]
            da = a["lexical"]["budgets"][fpr]["detect"]
            db = b["lexical"]["budgets"][fpr]["detect"]
            print(f"  LEXICAL @FPR={fpr:<5} 检测率 {da:>7.1%} -> {db:<7.1%}")
        print(f"  LEXICAL 正常类误报率(argmax) {1-a['lexical']['per_class']['normal']['recall']:>7.1%}"
              f" -> {1-b['lexical']['per_class']['normal']['recall']:<7.1%}")
        # 汇总 JSON
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "ab_features.json"), "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n[AB] 汇总 -> {os.path.join(args.out_dir, 'ab_features.json')}")


if __name__ == "__main__":
    main()
