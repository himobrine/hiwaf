"""导出测试向量：请求 / 特征 / 模型期望输出，供 Rust 侧做一致性验证。

与旧版的区别：
  * **不再重训模型**，而是直接加载已导出的产物（`xgb_model.json` booster +
    `xgboost_v20261015_001.onnx`），因此 `xgb_proba` 与 ONNX 产物严格同源，
    消除了旧版"用不同超参重训导致 sklearn vs ort 差 2.7e-4"的噪声；
  * 请求集 = 合成请求 + 真实 HTTP Params 请求各一半，覆盖更广的特征形态；
  * Isolation Forest 期望值取自精简 ONNX（Rust 使用的同一文件）；
  * **判定策略期望值**取自 `artifacts/decision_policy.json`（两通道阈值 + 融合动作），
    见 `thresholds.py`。Rust 侧必须逐条复现这些标记，阈值决策才受回归门禁保护。

输出 artifacts/testvec.json
"""
from __future__ import annotations

import json
import os
import tempfile

import numpy as np

from dataset import generate, split
from features import FeatureExtractor
from realdata import TRAINDATA, load_payloads

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

N_SYNTH = 100
N_REAL = 100


def rule_evidence(requests: list, ruleset_path: str) -> dict:
    """用 **Rust 权威实现**给这 200 条请求取规则证据（逐样本的命中权重）。

    为什么一定要取：门禁要重放**融合动作**，而融合里有规则通道。没有逐样本证据，
    Rust 侧只能按"规则通道不参与"算 —— 那验证的是一个线上不存在的语义。

    ⚠️ 判定来自 `waf-ai-proto rules replay`，Python 不重写一遍匹配（`re` 与 `regex`
    在 lookaround / 反向引用 / `$` 语义上都不同）。
    """
    from service import toolchain

    n = len(requests)
    with tempfile.TemporaryDirectory(prefix="waf_tv_rules_") as td:
        corpus = os.path.join(td, "tv.jsonl")
        with open(corpus, "w", encoding="utf-8") as f:
            for i, r in enumerate(requests):
                f.write(json.dumps({"id": f"tv#{i}", "pool": "testvec",
                                    **{k: r.get(k) or "" for k in
                                       ("method", "path", "query", "body")}},
                                   ensure_ascii=False) + "\n")
        outp = os.path.join(td, "out.jsonl")
        p = toolchain.run_proto(["rules", "replay", "--rules", ruleset_path,
                                 "--in", corpus, "--out", outp], timeout=1200)
        if p.returncode != 0:
            raise SystemExit("[testvec] 规则回放失败：\n" + (p.stdout or "") + (p.stderr or ""))
        tail = (p.stderr or "").strip().splitlines()
        if tail:
            print("  " + tail[-1])
        by_id = {}
        for line in open(outp, encoding="utf-8"):
            o = json.loads(line)
            by_id[o["id"]] = o

    import hashlib
    sha = hashlib.sha1(open(ruleset_path, "rb").read()).hexdigest()[:16]
    ev = {"ruleset_sha1_16": [sha] * n, "weight": [], "block_weight": []}
    for i in range(n):
        o = by_id.get(f"tv#{i}")
        if o is None:
            raise SystemExit(f"[testvec] 规则回放漏了第 {i} 条")
        ev["weight"].append(float(o.get("weight") or 0.0))
        ev["block_weight"].append(float(o.get("block_weight") or 0.0))
    return ev


def main():
    import onnxruntime as ort
    import xgboost as xgb

    # ---- 请求集：合成 + 真实 ----
    reqs, labels = generate(n_per_class=2000)
    _, _, te_r, te_y = split(reqs, labels)
    synth_r = [{k: r.get(k, "") for k in ("method", "path", "query", "body")}
               for r in te_r[:N_SYNTH]]
    synth_y = list(map(int, te_y[:N_SYNTH]))

    real = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))[:N_REAL]
    real_r = [{"method": s["method"], "path": s["path"], "query": s["query"], "body": s["body"]}
              for s in real]
    real_y = [int(s["label"]) for s in real]

    requests = synth_r + real_r
    y_true = synth_y + real_y

    fx = FeatureExtractor()
    X = np.asarray(fx.transform_batch(requests), dtype=np.float32)
    print(f"[testvec] {len(requests)} requests ({N_SYNTH} synthetic + {N_REAL} real) x {X.shape[1]} features")

    # ---- XGBoost 期望输出：直接用已导出产物 ----
    booster = xgb.Booster()
    booster.load_model(os.path.join(ART, "xgb_model.json"))
    dm = xgb.DMatrix(X)
    xgb_proba = booster.predict(dm)

    sess_x = ort.InferenceSession(os.path.join(ART, "xgboost_v20261015_001.onnx"),
                                  providers=["CPUExecutionProvider"])
    xgb_ort = sess_x.run(None, {sess_x.get_inputs()[0].name: X})[1]
    xgb_sk_vs_ort = float(np.abs(xgb_proba - xgb_ort).max())
    print(f"[testvec] booster vs onnxruntime max|diff| = {xgb_sk_vs_ort:.6e}")

    # ---- Isolation Forest 期望输出：精简 ONNX（Rust 同一文件）----
    sess = ort.InferenceSession(os.path.join(ART, "iforest_lean_v20261015_001.onnx"),
                                providers=["CPUExecutionProvider"])
    E = sess.run(None, {sess.get_inputs()[0].name: X})[0].ravel()

    # ---- 判定策略（S7）：从 decision_policy.json 读取两条通道的阈值 ----
    # 背景见 REALDATA_EVALUATION.md §8.3：argmax 的误报落点不稳，改为「score + 标定阈值」。
    # 策略文件由 thresholds.py 生成（含"校准池不得含训练样本"的代码级守卫）。
    from thresholds import build_decision_block
    policy_path = os.path.join(ART, "decision_policy.json")
    if not os.path.exists(policy_path):
        raise SystemExit("[testvec] 缺 artifacts/decision_policy.json，请先跑：\n"
                         "         py -3.10 thresholds.py --pool csic")
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = json.load(f)
    normal_idx = int(policy["supervised"]["normal_class_index"])
    sup_score = 1.0 - xgb_proba[:, normal_idx]
    zd_score = -E.astype(np.float64)

    # ---- 规则通道（第三通道）的逐样本证据 ----
    # 即使当前策略没启用规则通道也照样取：这样以后单改阈值（refresh_testvec）时，
    # testvec 已经带着证据，不必再重跑本脚本。
    rcfg = policy.get("rules") or {}
    rpath = ""
    if rcfg.get("ruleset_path"):
        rpath = os.path.join(HERE, rcfg["ruleset_path"])
    if not rpath or not os.path.exists(rpath):
        fallback = os.path.join(ART, "rules_authoritative.json")
        rpath = fallback if os.path.exists(fallback) else ""
    if rpath:
        print(f"[testvec] 规则证据 <- {os.path.relpath(rpath, HERE)}（Rust 回放）")
        rule_ev = rule_evidence(requests, rpath)
    else:
        print("[testvec] 无现役规则集 ⇒ 规则证据为空（规则通道被视为未启用）")
        rule_ev = {"ruleset_sha1_16": [""] * len(requests),
                   "weight": [0.0] * len(requests), "block_weight": [0.0] * len(requests)}

    decision = build_decision_block(policy, sup_score, zd_score, rule_ev)
    n_sup = sum(decision["supervised"]["expected_flagged"])
    n_zd = sum(decision["zero_day"]["expected_flagged"])
    n_zd_cross = sum(decision["zero_day"].get("expected_crossed") or [])
    n_rule = sum(decision["rules"]["expected_flagged"])
    counts = {}
    for a in decision["expected_action"]:
        counts[a] = counts.get(a, 0) + 1
    print(f"[testvec] 策略 @{policy['supervised']['target_fpr']}FPR: "
          f"监督 thr={policy['supervised']['threshold']:.6f} (标记 {n_sup}/{len(sup_score)})  "
          f"零日 thr={policy['zero_day']['threshold']:.6f} (标记 {n_zd})  动作 {counts}")
    if rcfg.get("enabled"):
        print(f"[testvec] 规则通道 = 启用（{rcfg.get('n_rules')} 条 / block "
              f"{rcfg.get('n_block_rules')} 条，阻断线 {rcfg.get('min_weight_to_block')}）："
              f"达阻断线 {n_rule} 条，指纹 {decision['rules']['ruleset_sha1_16']}")
        if any(decision["rules"]["weight"]):
            print(f"[testvec]   有规则命中的样本 {sum(1 for w in decision['rules']['weight'] if w):d} 条"
                  f"（这些样本的融合动作里含规则通道的贡献）")
    else:
        print("[testvec] 规则通道 = 未启用（证据已留存，但不影响动作）")
    if not decision["zero_day_enabled"]:
        print(f"[testvec] 零日通道 = **关闭**（安全降级）：原始穿阈 {n_zd_cross} 条仅留证，"
              f"不参与融合 -> 动作里不会有 alert")

    out = {
        "feature_names": fx.names,
        "feature_version": "v2",
        "labels": {"0": "normal", "1": "sqli", "2": "xss", "3": "cmdi", "4": "traversal"},
        "requests": requests,
        "labels_true": y_true,
        "features": X.tolist(),
        "xgb_proba": xgb_proba.tolist(),
        "xgb_proba_ort": xgb_ort.tolist(),
        "xgb_sklearn_vs_ort_maxdiff": xgb_sk_vs_ort,
        "iforest_avg_path_len": E.tolist(),
        "decision": decision,
    }
    path = os.path.join(ART, "testvec.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print(f"[testvec] wrote {path}: {len(requests)} samples, {X.shape[1]} features")
    print("[testvec] note: Rust 侧需从原始 requests 重算特征并与 features / decision 比对")


if __name__ == "__main__":
    main()
