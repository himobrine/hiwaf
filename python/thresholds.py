"""判定阈值标定 + 双通道融合策略（S7 收尾）。

产出 `artifacts/decision_policy.json` —— 数据面判定规则的**唯一事实来源**：
两条通道（监督 / 零日）各自的分数定义、阈值、标定池，以及融合动作。

## 为什么需要这个脚本

`REALDATA_EVALUATION.md` §8.3 实测过两件事：

1. 阈值必须标定在**未参与训练**的良性流量上，否则估计偏乐观（实测可差 **8 倍**）；
2. 零日通道（Isolation Forest 的 `avg_path_len`）与监督通道**量纲不同**，
   必须各自标定后再融合，不能用同一个数。

所以"校准池里混进训练样本"是**代码级必须拦住的错误**，不是文档里的提醒。
本脚本会重建记录在 `xgboost_meta.json.training_recipe` 里的训练集，
用 `method|path|query|body` 的 md5 与校准池求交；有交集即**拒绝出策略**（除非 `--force`）。

## 用法

    py -3.10 thresholds.py                            # 默认 CSIC 留出（两通道同池）
    py -3.10 thresholds.py --pool lexical             # lexical 留出正常 500
    py -3.10 thresholds.py --pool file:benign.jsonl   # 本地真实流量（jsonl）
    py -3.10 thresholds.py --fpr 0.01 --write-testvec

## 融合策略

```
监督通道命中            -> block  (阻断 + 告警)
仅零日通道命中          -> alert  (告警，强制人工复核)
都未命中                -> allow
```

零日通道**不单独阻断**是刻意的：它的误报语义是"没见过"，而不是"确认是攻击"，
直接阻断会把误报变成业务中断。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import tempfile
import time

import numpy as np

from realdata import csic_normal_index, load_csic

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

BUDGETS = (0.001, 0.01, 0.03)
# 结构兼容版本：通道布局 / 字段语义变了才 +1（数据面 `decision.rs` 会拒绝不认识的值）。
#   v1 = 双通道（监督 + 零日）
#   v2 = 三条通道（新增 `rules` 块：规则集指纹 / 阻断线 / 实测误报预算）
POLICY_SCHEMA = 2
POLICY_PATH = os.path.join(ART, "decision_policy.json")
TESTVEC_PATH = os.path.join(ART, "testvec.json")
XGB_META = os.path.join(ART, "xgboost_meta.json")
XGB_ONNX = os.path.join(ART, "xgboost_v20261015_001.onnx")
IF_ONNX = os.path.join(ART, "iforest_lean_v20261015_001.onnx")
RULES_AUTHORITATIVE = os.path.join(ART, "rules_authoritative.json")

REQ_KEYS = ("method", "path", "query", "body")

FUSION_2 = "supervised_block__zero_day_alert"
FUSION_3 = "supervised_block__zero_day_alert__rules_block"

# 规则通道能从总预算里吃掉多少（**阻断**预算）。
# 0.3% 是一个保守起点：规则是"人工写的确定性证据"，而它对良性流量的误报是**不可约**的
# （只有人能删规则）。留 10% 给监督通道是下限 —— 低于它，监督通道就没有可用的操作点了。
RULE_BUDGET_CAP_DEFAULT = 0.003
MIN_SUP_SHARE = 0.10


def fusion_block(rules_enabled: bool, ruleset_sha: str, n_rules: int, n_block: int,
                 rule_fpr: float, sup_target: float, nominal: float) -> dict:
    """融合策略描述（**动作语义的唯一人读来源**）。"""
    actions = {
        "allow": "放行",
        "alert": "告警（零日通道 / 规则通道的非 block 命中；强制人工复核）",
    }
    if rules_enabled and n_block:
        actions["block"] = f"阻断（监督通道 或 权重和≥阻断线的 block 规则；当前 {n_block} 条）"
    else:
        actions["block"] = ("阻断（监督通道）"
                            + ("；规则集里**没有** block 规则，规则通道目前只能告警"
                               if rules_enabled else ""))
    desc = ("监督通道命中 -> block；"
            "规则通道的 block 规则权重和 ≥ 阻断线 -> block；"
            "仅零日通道命中、或规则通道有命中（但不够阻断线）-> alert（需人工复核）；"
            "否则 allow。"
            "零日通道不单独阻断：其误报语义是\"没见过\"，而非\"确认是攻击\"。"
            "⚠️ 顶层 `zero_day_enabled=false` 时零日通道**不参与融合**（分数仍计算留证）。")
    if rules_enabled:
        desc += (f" ⚠️ 规则通道的误报预算已从监督通道的目标 FPR 里**扣掉**："
                 f"监督目标 {nominal*100:.4g}% -> {sup_target*100:.4g}%"
                 f"（扣掉规则的阻断误报 {rule_fpr*100:.4g}%，{n_rules} 条规则 / {n_block} 条 block）。"
                 f"并且只有当**磁盘上的规则集指纹与策略记录一致**时规则通道才生效 —— "
                 f"预算是对着特定规则集算出来的。")
    return {
        "policy": FUSION_3 if rules_enabled else FUSION_2,
        "description": desc,
        "actions": actions,
    }

# 零日通道总开关。默认 **关闭**：
#   * 实测它在跨分布（OOD）下会崩 —— CSIC 训练的 IF 对 lexical 困难集良性误报 28.2%，
#     本机真实良性上告警 2.63%（目标 1%）；
#   * 在拿到真实本地良性流量重训 IF 之前，它产生的 alert 会强制人工复核，
#     是纯粹的成本而非收益。
# 置为 True 前必须重跑 thresholds.py（policy 与 testvec 必须同源）并重跑 Rust 门禁。
ZERO_DAY_ENABLED_DEFAULT = False


def req_key(sample: dict) -> str:
    """请求指纹：与任何单一字段的哈希不同，空 query 不会互相碰撞。"""
    return "\x1f".join(str(sample.get(k) or "") for k in REQ_KEYS)


def sha1_short(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# 校准池
# ---------------------------------------------------------------------------
def load_pool(name: str):
    """返回 (requests, pool_name, source)。"""
    if name == "csic":
        print("[pool] loading CSIC 2010 ...")
        reqs, y = load_csic()
        # 与 iforest 训练协议同一份（seed=7 随机切分），保证两通道同池可比
        _, hold_idx = csic_normal_index(seed=7, n_train=30000)
        pool = [reqs[i] for i in hold_idx]
        return pool, (f"CSIC 2010 正常流量留出 {len(pool):,} 条"
                      f"（seed=7 切分，与零日通道训练集互斥）"), "csic-holdout"
    if name == "lexical":
        from realdata import TRAINDATA, load_payloads
        lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))
        normals = [s for s in lex if s["label"] == 0]
        pool = normals[len(normals) // 2:]        # 与训练用的前一半互斥
        return pool, f"lexical 留出正常 {len(pool)} 条（训练用的是前一半）", "lexical-holdout"
    if name.startswith("file:"):
        path = name[len("file:"):]
        if not os.path.isabs(path):
            path = os.path.join(HERE, path)
        pool = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    pool.append({k: v for k, v in json.loads(line).items() if k in REQ_KEYS})
        return pool, f"本地流量文件 {os.path.basename(path)} 共 {len(pool)} 条", f"file:{path}"
    raise SystemExit(f"未知 --pool {name!r}（可选 csic / lexical / file:PATH）")


# ---------------------------------------------------------------------------
# 训练集重建 + 污染检查
# ---------------------------------------------------------------------------
def training_keys(info: dict) -> tuple[set, str]:
    """按 `xgboost_meta.json.training_recipe` 重建训练集指纹。"""
    from train_realdata import load_all

    hard_neg = info.get("hard_neg", "none")
    seed = int(info.get("seed") or 11)
    split = "grouped" if str(info.get("lexical_split", "")).startswith("grouped") else "random"
    dict_aug = info.get("dict_augmentation") or {}
    tr, _, _, _, _ = load_all(
        hard_neg=hard_neg, seed=seed, split_mode=split,
        use_dict=bool(dict_aug), dict_benign_ratio=float(dict_aug.get("benign_ratio", 1.0) or 1.0),
        extra_benign=int(info.get("extra_benign") or 0),
        valid_frac=float(info.get("valid_frac") or 0.0),
    )
    desc = (f"hard_neg={hard_neg} seed={seed} lexical_split={split} "
            f"dict={'on' if dict_aug else 'off'} extra_benign={info.get('extra_benign', 0)} "
            f"valid_frac={info.get('valid_frac', 0.0)}")
    return {req_key(s) for s in tr}, desc


def contamination(pool, info: dict, force: bool, train_keys_path: str | None = None):
    keys, desc = training_keys(info)
    extra_hashes: set = set()
    if train_keys_path:
        try:
            with open(train_keys_path, "r", encoding="utf-8") as f:
                extra_hashes = {ln.strip() for ln in f if ln.strip()}
            desc += f" + upload_keys={len(extra_hashes)}"
        except OSError as e:
            print(f"[guard] ⚠️ 读取上传训练指纹失败：{e}")
    pool_keys = [req_key(s) for s in pool]
    inter = [k for k in pool_keys if k in keys]
    pool_hashes = {hashlib.sha1(k.encode("utf-8", "replace")).hexdigest()
                   for k in pool_keys}
    inter_extra = pool_hashes & extra_hashes
    n_overlap = len(inter) + len(inter_extra)
    rate = n_overlap / max(1, len(pool_keys))
    print(f"[guard] 训练集重建（{desc}）: {len(keys):,} 条")
    print(f"[guard] 校准池 {len(pool_keys):,} 条，与训练集**完全同源** {n_overlap} 条 "
          f"({rate*100:.3f}%)")
    if n_overlap and not force:
        raise SystemExit(
            "[guard] 拒绝出策略：校准池含训练样本，阈值会偏乐观（§8.3 实测可差 8 倍）。\n"
            "        请换一个池（--pool csic / lexical / file:...），或确认后用 --force 覆盖。"
        )
    return {"n_overlap": n_overlap, "overlap_rate": rate, "training_set": desc,
            "n_training": len(keys), "n_upload_training": len(extra_hashes)}


# ---------------------------------------------------------------------------
# 两条通道的分数
# ---------------------------------------------------------------------------
def xgb_scores(reqs, fx, normal_idx: int) -> np.ndarray:
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = 1
    sess = ort.InferenceSession(XGB_ONNX, so, providers=["CPUExecutionProvider"])
    name = sess.get_inputs()[0].name
    outs = [o.name for o in sess.get_outputs()]
    idx = outs.index("probabilities") if "probabilities" in outs else 1
    X = np.asarray(fx.transform_batch(reqs), dtype=np.float32)
    p = np.asarray(sess.run(None, {name: X})[idx])
    if p.ndim != 2:
        raise SystemExit(f"[score] xgboost ONNX 输出形状异常 {p.shape}（outs={outs}）")
    return 1.0 - p[:, normal_idx]


def iforest_scores(reqs, fx, onnx_path: str | None = None) -> np.ndarray:
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = 1
    sess = ort.InferenceSession(onnx_path or IF_ONNX, so, providers=["CPUExecutionProvider"])
    name = sess.get_inputs()[0].name
    X = np.asarray(fx.transform_batch(reqs), dtype=np.float32)
    return -sess.run(None, {name: X})[0].ravel()


def calibrate_channel(scores: np.ndarray, budgets=BUDGETS) -> dict:
    return {f"{f:g}": float(np.quantile(scores, 1.0 - f)) for f in budgets}


def wilson_upper(k: int, n: int, z: float = 1.959963984540054) -> float:
    """二项比例的 Wilson 95% **上界**。

    为什么不用点估计：挖出的规则本身就是在（与本池同源的）CSIC 正常流量上筛出来的，
    留出集的良性又和挖掘池同源 ⇒ 点估计**系统性偏低**。拿它去扣预算，等于把
    "规则的侥幸"当成"规则的清白"，融合误报会被顶穿目标。
    上界是保守的：宁可少扣一点预算（监督通道收紧一点），也不要事后才发现超了。
    """
    if n <= 0:
        return 1.0
    p = k / n
    d = 1.0 + z * z / n
    center = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
    return min(1.0, (center + half) / d)


def rule_budget_on_pool(pool, rules_path: str) -> dict:
    """用 **Rust 权威实现**量现役规则集在这个池上的**阻断**误报率。

    为什么必须在**同一个池**上量：规则预算要从监督通道的目标 FPR 里**扣掉**
    （`sup_target = target_fpr - rules_fpr`）。两个数字不同源就没法相减 ——
    在别的池上量出来的规则 FPR，对不上这个池的监督分位。

    ⚠️ 这里**不允许**在 Python 里重写一遍匹配：Rust `regex` 与 Python `re` 在
    lookaround / 反向引用 / `$` 语义上都不同。判定永远来自 `waf-ai-proto rules replay`。
    """
    from service import toolchain

    with tempfile.TemporaryDirectory(prefix="waf_rulebudget_") as td:
        corpus = os.path.join(td, "pool.jsonl")
        with open(corpus, "w", encoding="utf-8") as f:
            for i, r in enumerate(pool):
                f.write(json.dumps({"id": f"pool#{i}", "pool": "calib",
                                    **{k: r.get(k) or "" for k in REQ_KEYS}},
                                   ensure_ascii=False) + "\n")
        outp = os.path.join(td, "out.jsonl")
        p = toolchain.run_proto(
            ["rules", "replay", "--rules", rules_path, "--in", corpus, "--out", outp],
            timeout=3600,
        )
        if p.returncode != 0:
            raise SystemExit("规则回放失败（预算量测）：\n" + (p.stdout or "") + (p.stderr or ""))
        tail = (p.stderr or "").strip().splitlines()
        if tail:
            print("  " + tail[-1])
        n = n_block = 0
        hits_by_rule: dict[str, int] = {}
        for line in open(outp, encoding="utf-8"):
            o = json.loads(line)
            n += 1
            if o.get("block"):
                n_block += 1
            for h in o.get("hits") or []:
                if h.get("action") == "block":
                    hits_by_rule[h["rule"]] = hits_by_rule.get(h["rule"], 0) + 1
    return {
        "n": n,
        "n_block": n_block,
        "fpr_point": n_block / max(1, n),
        "fpr_upper_95": wilson_upper(n_block, n),
        "method": "wilson95_upper_on_pool",
        "hits_by_rule": dict(sorted(hits_by_rule.items())),
    }


def channel_block(artifact: str, score_def: str, scores: np.ndarray,
                  target_fpr: str, extra: dict | None = None,
                  effective_target: float | None = None) -> dict:
    """标定一条通道。

    `effective_target` 给了就按它取分位。为什么需要它：规则通道会从总预算里扣掉自己
    的实测误报，于是监督通道的**实际**目标可能落在 0.001 / 0.01 / 0.03 三个标准档位
    之间，不能被档位绑死。取同一分位表达式 ⇒ 不扣预算时与旧值**逐位相同**。
    """
    thr = calibrate_channel(scores)
    nominal = float(target_fpr)
    if effective_target is None:
        if target_fpr not in thr:
            raise SystemExit(f"目标 FPR {target_fpr} 不在预算 {sorted(thr)} 内")
        threshold = thr[target_fpr]
    else:
        eff = float(effective_target)
        if eff <= 0.0:
            raise SystemExit(
                f"扣掉规则误报后监督通道没有剩余预算（effective target = {eff:.6g}）："
                f"规则通道占得太满，拒绝出策略"
            )
        threshold = float(np.quantile(scores, 1.0 - eff))
    block = {
        "artifact": artifact,
        "artifact_sha1_16": sha1_short(os.path.join(ART, artifact)),
        "score_def": score_def,
        "target_fpr": target_fpr,
        "threshold": threshold,
        "thresholds": thr,
        # 用阈值回代，报告该池上的**实际**误报率（应 ≈ target）
        "actual_fpr": {
            f: float((scores >= t).mean()) for f, t in thr.items()
        },
    }
    if effective_target is not None:
        # 预算被别的通道扣过：**必须**把代价写进策略文件。否则"融合 FPR 不变"这句话
        # 下次有人调规则的时候就没人能验证了。
        block["effective_target_fpr"] = float(effective_target)
        block["budget_deduction"] = nominal - float(effective_target)
        block["actual_fpr_at_effective"] = float((scores >= threshold).mean())
    block.update(extra or {})
    return block


# ---------------------------------------------------------------------------
# testvec 决策块的唯一形状（export_testvec.py 也复用它）
# ---------------------------------------------------------------------------
def rule_evidence_default(n: int) -> dict:
    """没有规则证据时的占位（指纹为空 ⇒ 规则通道视为未启用）。"""
    return {"ruleset_sha1_16": [""] * n, "weight": [0.0] * n, "block_weight": [0.0] * n}


def build_decision_block(policy: dict, sup_scores, zd_scores, rule_ev: dict | None = None) -> dict:
    """三通道融合的**唯一事实来源**（Python 侧）。

    Rust `decision.rs::decide_with_rules` 必须逐条复现这里，门禁就是靠这个比对。
    规则通道有三层门：
      ① 策略里的全局刹车 `rules.enabled`；
      ② 指纹一致（预算是对着**特定**规则集算出来的，换了规则集就不是同一个预算）；
      ③ 权重和 ≥ `min_weight_to_block`，且**只有 `action=block` 的命中计入权重**。
    """
    sup = policy["supervised"]
    zd = policy["zero_day"]
    # 缺省为 True：老策略文件没有这个键时保持原行为，避免静默改变判定语义。
    # 但 thresholds.py 生成时总是显式写入。
    zd_enabled = bool(policy.get("zero_day_enabled", True))
    rcfg = policy.get("rules") or {}
    r_enabled = bool(rcfg.get("enabled", False))
    r_sha = rcfg.get("ruleset_sha1_16") or ""
    r_min_w = float(rcfg.get("min_weight_to_block", 1.0))

    def flags(scores, thr):
        return [bool(s >= thr) for s in scores]

    sup_f = flags(sup_scores, sup["threshold"])
    zd_crossed = flags(zd_scores, zd["threshold"])          # 原始穿阈（留证）
    zd_f = [c and zd_enabled for c in zd_crossed]           # **生效**标记（参与融合）

    n = len(sup_f)
    if rule_ev is None:
        rule_ev = rule_evidence_default(n)
    raw_w = list(rule_ev.get("weight") or [])
    raw_bw = list(rule_ev.get("block_weight") or [])
    raw_sha = list(rule_ev.get("ruleset_sha1_16") or [])
    if not (len(raw_w) == len(raw_bw) == len(raw_sha) == n):
        raise SystemExit(
            f"规则证据长度不匹配（{len(raw_sha)}/{len(raw_w)}/{len(raw_bw)} vs {n}）："
            f"testvec 与策略不同源，请重跑 export_testvec.py"
        )

    def honored(i: int) -> bool:
        return bool(r_enabled and r_sha and raw_sha[i] == r_sha)

    # **未被认可**的规则证据一律当 0：证据仍在（落盘可见），但不影响动作。
    r_w = [raw_w[i] if honored(i) else 0.0 for i in range(n)]
    r_bw = [raw_bw[i] if honored(i) else 0.0 for i in range(n)]
    rules_f = [bw + 1e-9 >= r_min_w for bw in r_bw]

    action = []
    for sf, zf, rf, rw in zip(sup_f, zd_f, rules_f, r_w):
        if sf or rf:
            action.append("block")
        elif zf or rw > 0.0:
            action.append("alert")
        else:
            action.append("allow")
    return {
        "policy_version": policy["version"],
        "policy_schema": policy["schema"],
        "fusion_policy": policy["fusion"]["policy"],
        "zero_day_enabled": zd_enabled,
        "supervised": {"target_fpr": sup["target_fpr"], "threshold": sup["threshold"],
                       "score": list(map(float, sup_scores)), "expected_flagged": sup_f},
        "zero_day": {"target_fpr": zd["target_fpr"], "threshold": zd["threshold"],
                     "score": list(map(float, zd_scores)),
                     "expected_flagged": zd_f,
                     "expected_crossed": zd_crossed},
        "rules": {"enabled": r_enabled,
                  "ruleset_sha1_16": r_sha,
                  "min_weight_to_block": r_min_w,
                  # 存**原始**证据（引擎输出的原样），两侧各自按同一套规则做屏蔽 ——
                  # 存屏蔽后的值会掩盖"指纹不匹配"这种真问题。
                  "ruleset_sha1_16_per_sample": raw_sha,
                  "weight": [float(x) for x in raw_w],
                  "block_weight": [float(x) for x in raw_bw],
                  "expected_flagged": rules_f},
        "expected_action": action,
    }


def refresh_testvec(policy: dict, verbose=True) -> bool:
    """只重算阈值/标记，不重跑推理（分数已存在 testvec 里）。"""
    if not os.path.exists(TESTVEC_PATH):
        if verbose:
            print("[testvec] 不存在，跳过（请先跑 export_testvec.py）")
        return False
    with open(TESTVEC_PATH, "r", encoding="utf-8") as f:
        tv = json.load(f)
    d = tv.get("decision") or {}
    if "supervised" not in d or "zero_day" not in d:
        if verbose:
            print("[testvec] 缺 decision 分通道分数，无法就地刷新（请重跑 export_testvec.py）")
        return False
    rcfg = policy.get("rules") or {}
    rule_ev = d.get("rules")
    if rule_ev is not None:
        # testvec 里存的是 `build_decision_block` 的**输出**形状（标量 `ruleset_sha1_16`
        # + 逐样本 `ruleset_sha1_16_per_sample`），而它吃的**输入**形状是
        # `{"ruleset_sha1_16": [每样本一个指纹], "weight": [...], "block_weight": [...]}`。
        # 两者只差一个后缀名：混用会让 `len(rule_ev["ruleset_sha1_16"])` 变成
        # `len("")==0`，于是报"长度不匹配（0/200/200 vs 200）"。
        rule_ev = {
            "ruleset_sha1_16": list(rule_ev.get("ruleset_sha1_16_per_sample") or []),
            "weight": list(rule_ev.get("weight") or []),
            "block_weight": list(rule_ev.get("block_weight") or []),
        }
    if rcfg.get("enabled") and not (rule_ev or {}).get("weight"):
        # 规则通道启用了，但 testvec 里没有逐样本的规则证据 ⇒ 没法重算融合动作。
        # **绝不能**就地刷新：那会算出一个"规则通道不参与"的动作序列，而线上是参与的，
        # 门禁就会去验证一个**假的**语义（比报错危险得多）。
        # 正确动作是重跑 export_testvec.py（它会用 waf-ai-proto rules replay 取证据）。
        print("[testvec] ⛔ 策略启用了规则通道，但 testvec 里没有规则证据 —— **跳过刷新**"
              "（就地刷新会验证错误的融合语义）。\n"
              "          必须重跑：py -3.10 export_testvec.py\n"
              "          在那之前 Rust 门禁会因 policy/testvec 不同源而失败 —— 这是**故意的**信号。")
        return False
    block = build_decision_block(policy, d["supervised"]["score"], d["zero_day"]["score"], rule_ev)
    old = d["supervised"].get("threshold"), d["zero_day"].get("threshold")
    tv["decision"] = block
    with open(TESTVEC_PATH, "w", encoding="utf-8") as f:
        json.dump(tv, f)
    if verbose:
        print(f"[testvec] 决策块已刷新：监督阈值 {old[0]} -> {block['supervised']['threshold']:.6f}，"
              f"零日阈值 {old[1]} -> {block['zero_day']['threshold']:.6f}  "
              f"（动作分布 {_action_counts(block['expected_action'])}）")
    return True


def _action_counts(actions) -> dict:
    out = {}
    for a in actions:
        out[a] = out.get(a, 0) + 1
    return out


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="csic",
                    help="csic（默认）/ lexical / file:PATH.jsonl")
    ap.add_argument("--train-keys", default=None,
                    help="额外的训练集指纹文件（每行 sha1；上传训练产物用）")
    ap.add_argument("--fpr", default="0.01", help="推荐档目标 FPR（须在 0.001/0.01/0.03 内）")
    ap.add_argument("--force", action="store_true", help="明知校准池含训练样本仍继续（危险）")
    ap.add_argument("--zero-day", choices=["on", "off"], default="off",
                    help="零日通道总开关（默认 off：跨分布误报不可控，拿到本地良性重训前先降级）")
    ap.add_argument("--no-testvec", action="store_true", help="不刷新 testvec.json")
    ap.add_argument("--out", default=POLICY_PATH,
                    help="策略输出路径（控制台预览时写临时文件；默认 artifacts/decision_policy.json）")
    ap.add_argument("--version", type=int, default=0,
                    help="策略版本号（0=在现有版本上自动 +1）")
    # ---- 规则通道（第三通道）----
    ap.add_argument("--rules", default="",
                    help="现役规则集路径（如 artifacts/rules_authoritative.json）。"
                         "给了就启用规则通道，并从监督通道的目标 FPR 里**扣掉**实测误报。"
                         "不传 = 保持现状；要显式关掉请用 --no-rules")
    ap.add_argument("--no-rules", action="store_true",
                    help="显式关闭规则通道（会在策略里写入 rules.enabled=false）")
    ap.add_argument("--rule-fpr", type=float, default=None,
                    help="已量测的规则**阻断误报上界**（审计复算用；"
                         "不传则由本脚本用 waf-ai-proto rules replay 在同一池上实测 Wilson 上界）")
    ap.add_argument("--rule-budget-cap", type=float, default=RULE_BUDGET_CAP_DEFAULT,
                    help=f"规则通道可占用的阻断预算上限（默认 {RULE_BUDGET_CAP_DEFAULT*100:g}%%）")
    args = ap.parse_args()

    if not os.path.exists(XGB_ONNX) or not os.path.exists(IF_ONNX):
        raise SystemExit("缺 ONNX 产物：请先跑 train_realdata.py --export 与 "
                         "iforest_lean_onnx.py --data csic --export")
    with open(XGB_META, "r", encoding="utf-8") as f:
        meta = json.load(f)
    recipe = meta.get("training_recipe") or {}
    normal_idx = next((int(k) for k, v in (meta.get("labels") or {}).items()
                       if v == "normal"), 0)

    from features import FeatureExtractor
    fx = FeatureExtractor()

    pool, pool_name, source = load_pool(args.pool)
    if len(pool) < 200:
        raise SystemExit(f"校准池太小（{len(pool)} 条），阈值不可靠")
    if len(pool) < 2000:
        print(f"[pool] ⚠️ 校准池只有 {len(pool)} 条：1% 分位≈{max(1, int(len(pool)*0.01))} 个样本，"
              f"阈值估计抖动很大（实测 300 条给 0.4914 vs 6000 条给 0.6998）。"
              f"建议 ≥2,000 条。")

    guard = contamination(pool, recipe, args.force, args.train_keys)

    # ------------------------------------------------------------------
    # 规则通道（第三通道）：**先量它的代价**，才能决定监督通道还剩多少预算
    # ------------------------------------------------------------------
    nominal_target = float(args.fpr)
    rules_enabled = False
    ruleset_path = ""
    ruleset_sha = ""
    n_rules = n_block_rules = 0
    rules_min_w = 1.0
    rule_budget = {"n": 0, "n_block": 0, "fpr_point": 0.0, "fpr_upper_95": 0.0,
                   "method": "not_configured", "hits_by_rule": {}}
    sup_target = None

    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            prev_rules = json.load(f).get("rules") or {}
    except (OSError, ValueError):
        prev_rules = {}

    if args.rules and args.no_rules:
        raise SystemExit("--rules 与 --no-rules 不能同时给")
    if not args.rules and not args.no_rules and prev_rules.get("enabled"):
        # 不拦这一下，重标定就会**静默**把规则通道关掉：既丢召回，也丢预算记账。
        raise SystemExit(
            "现役策略**已启用**规则通道，但本次没传 --rules。\n"
            "        这会静默地把规则通道关掉（放弃召回，也放弃预算记账）。\n"
            "        要保留请传 --rules <现役规则集>；确实要关请显式传 --no-rules。"
        )

    if args.rules and not args.no_rules:
        rp = args.rules if os.path.isabs(args.rules) else os.path.join(HERE, args.rules)
        if not os.path.exists(rp):
            raise SystemExit(f"规则集不存在：{rp}（先在控制台提升规则，或跑 service.rules.build_authoritative）")
        with open(rp, "r", encoding="utf-8") as f:
            rdoc = json.load(f)
        if int(rdoc.get("schema", 1)) != 1:
            raise SystemExit(f"规则集 schema {rdoc.get('schema')} 不被支持（数据面只认 1）")
        rules_list = rdoc.get("rules") or []
        n_rules = len(rules_list)
        n_block_rules = sum(1 for r in rules_list if (r.get("action") or "alert") == "block")
        rules_min_w = float(rdoc.get("min_weight_to_block", 1.0))
        ruleset_path = os.path.relpath(rp, HERE).replace("\\", "/")
        ruleset_sha = sha1_short(rp)
        print(f"[rules] 现役规则集 {ruleset_path}：{n_rules} 条（block {n_block_rules} 条）"
              f" sha1_16={ruleset_sha} 阻断线 weight>={rules_min_w}")

        if args.rule_fpr is None:
            print(f"[rules] 在**同一个标定池**（{len(pool):,} 条）上用 Rust 权威实现量阻断误报 ...")
            rule_budget = rule_budget_on_pool(pool, rp)
            print(f"[rules] 规则阻断误报：点估计 {rule_budget['fpr_point']*100:.4f}%"
                  f"（{rule_budget['n_block']}/{rule_budget['n']}）"
                  f"  Wilson95 上界 {rule_budget['fpr_upper_95']*100:.4f}%")
        else:
            rule_budget = {"n": len(pool), "n_block": -1,
                           "fpr_point": float(args.rule_fpr),
                           "fpr_upper_95": float(args.rule_fpr),
                           "method": "operator_supplied_upper_bound", "hits_by_rule": {}}
            print(f"[rules] ⚠️ 采用人工给定的规则误报上界 {args.rule_fpr:.6g}"
                  f"（跳过量测；只应在复核已量测值时这么用）")

        rules_enabled = True
        # 预算**按实测从总预算里扣**，而不是事先切一块固定比例。
        rule_cost = float(rule_budget["fpr_upper_95"])
        if rule_cost > args.rule_budget_cap:
            raise SystemExit(
                f"规则通道的阻断误报上界 {rule_cost*100:.4f}% 超过可占用上限 "
                f"{args.rule_budget_cap*100:g}%（--rule-budget-cap）。\n"
                f"        规则是人工维护、误报不可约的通道，占满预算会把监督通道挤没。\n"
                f"        先处理误报最大的规则再提升（各规则命中：{rule_budget['hits_by_rule']}）。"
            )
        sup_target = nominal_target - rule_cost
        if sup_target < (1.0 - MIN_SUP_SHARE) * nominal_target:
            raise SystemExit(
                f"规则通道吃掉太多预算：监督目标 {nominal_target*100:.4g}% -> "
                f"{sup_target*100:.4g}%（规则占 {rule_cost*100:.4g}%），"
                f"监督通道剩余不足 {MIN_SUP_SHARE*100:g}%。拒绝出策略。"
            )
        print(f"[rules] 预算记账：监督目标 {nominal_target*100:.4g}% − 规则 {rule_cost*100:.4g}% "
              f"= {sup_target*100:.4g}%（融合的**阻断** FPR 目标仍是 {nominal_target*100:.4g}%）")
        if n_block_rules == 0:
            print("[rules] 注：现役规则集里没有 block 规则 ⇒ 规则通道目前只产生告警，"
                  "预算占用为 0（融合阻断 FPR 与双通道逐位相同）")
    else:
        print("[rules] 规则通道未启用（--no-rules 或从未配置）⇒ 融合等价于双通道")

    t0 = time.time()
    sup_scores = xgb_scores(pool, fx, normal_idx)
    zd_scores = iforest_scores(pool, fx)
    print(f"[score] 两通道打分完成 {len(pool):,} 条 ({time.time()-t0:.1f}s)")

    supervised = channel_block(
        os.path.basename(XGB_ONNX), "1 - P(normal)", sup_scores,
        args.fpr,
        {"normal_class_index": normal_idx,
         "labels": meta.get("labels"),
         "training_recipe_note": "阈值仅在下方 calibration_pool 上标定"},
        effective_target=sup_target,
    )
    zero_day = channel_block(
        os.path.basename(IF_ONNX), "-avg_path_len", zd_scores, args.fpr,
    )

    print(f"[thr] 监督通道 @{args.fpr}: {supervised['threshold']:.6f} "
          f"(池上实际 FPR={supervised['actual_fpr'][args.fpr]*100:.3f}%)")
    if sup_target is not None and isinstance(supervised.get("effective_target_fpr"), float):
        print(f"[thr]   ↑ 规则通道扣减后按 {supervised['effective_target_fpr']*100:.4g}% 取分位，"
              f"池上实际阻断 FPR={supervised['actual_fpr_at_effective']*100:.3f}% "
              f"（扣了 {supervised['budget_deduction']*100:.4g}%）")
    print(f"[thr] 零日通道 @{args.fpr}: {zero_day['threshold']:.6f} "
          f"(池上实际 FPR={zero_day['actual_fpr'][args.fpr]*100:.3f}%)")
    union = float(((sup_scores >= supervised['threshold'])
                   | (zd_scores >= zero_day['threshold'])).mean())
    zd_enabled = (args.zero_day == "on")

    # ---- 融合误报记账（三条通道一起算）----
    # 规则通道的**阻断**误报在量测时已经知道（`rule_budget`），这里把它并进融合口径。
    rule_block_fpr = float(rule_budget["fpr_upper_95"]) if rules_enabled else 0.0
    if rules_enabled and rule_budget["method"] != "operator_supplied_upper_bound":
        # 用池上实测值（与 sup/zd 同池），比 Wilson 上界更贴近"这批数据上真的拦了多少"
        rule_block_fpr_measured = float(rule_budget["fpr_point"])
    else:
        rule_block_fpr_measured = rule_block_fpr
    block_fpr = float((sup_scores >= supervised['threshold']).mean())
    fused_block_fpr = block_fpr if not rules_enabled else min(1.0, block_fpr + rule_block_fpr_measured)
    eff_union = ((union if zd_enabled else block_fpr) if not rules_enabled
                 else min(1.0, (union if zd_enabled else block_fpr) + rule_block_fpr_measured))
    print(f"[thr] 两通道并集在该池上的误报率 = {union*100:.3f}%  "
          f"（含零日的**告警**通道，不构成阻断预算）")
    print(f"[thr] 融合**阻断**误报（预算约束的对象）= 监督 {block_fpr*100:.3f}%"
          + (f" + 规则 {rule_block_fpr_measured*100:.3f}% = {fused_block_fpr*100:.3f}%"
             if rules_enabled else "（规则通道未启用）")
          + f"   目标 {nominal_target*100:g}%")
    print(f"[thr] 零日通道 = {'启用' if zd_enabled else '**关闭**（安全降级）'}  "
          f"-> 生效融合误报率 = {eff_union*100:.3f}%"
          + ("" if zd_enabled else "  （零日分数仍计算并留证，但不产生 alert）"))
    if not zd_enabled:
        print("[thr] ⚠️ 关闭零日通道的理由：跨分布误报不可控（lexical 28.2%、本机真实良性 2.63%），"
              "拿到真实本地良性重训 IF 之前它只有成本。重启前须重跑本脚本 + export_testvec.py + Rust 门禁。")

    # 版本号：预览（--out 指向别处）也基于现役策略递增，便于控制台对比。
    if args.version > 0:
        version = args.version
    else:
        try:
            with open(POLICY_PATH, "r", encoding="utf-8") as f:
                version = int(json.load(f).get("version", 0)) + 1
        except (OSError, ValueError):
            version = 1

    rules_block = {
        "enabled": rules_enabled,
        "ruleset_path": ruleset_path,
        "ruleset_sha1_16": ruleset_sha,
        "n_rules": n_rules,
        "n_block_rules": n_block_rules,
        "min_weight_to_block": rules_min_w,
        # 预算记账：`sup_target = nominal - fpr_upper_95`，所以这两个数必须留在文件里，
        # 否则下次有人调规则时，"融合 FPR 还是 1%"这句话就无从验证。
        "nominal_target_fpr": nominal_target,
        "sup_target_fpr": (nominal_target if sup_target is None else sup_target),
        "measured_fpr_point_on_pool": float(rule_budget["fpr_point"]),
        "fpr_upper_95_on_pool": float(rule_budget["fpr_upper_95"]),
        "budget_deducted": (0.0 if sup_target is None else float(rule_budget["fpr_upper_95"])),
        "budget_cap": float(args.rule_budget_cap),
        "budget_method": rule_budget["method"],
        "n_pool": int(rule_budget["n"]),
        "hits_by_block_rule": rule_budget["hits_by_rule"],
        "note": ("规则通道是**并列第三通道**（不是『规则→AI』串行管线）。只有 action=block "
                 "的命中消耗阻断预算；未被策略认可（总开关关 / 指纹不一致）时规则证据"
                 "完全不影响动作。预算按实测从监督目标里扣，故融合阻断 FPR 目标不变。"),
    }
    if rules_enabled and n_block_rules == 0:
        rules_block["note"] += " 当前 0 条 block 规则 ⇒ 预算占用 0。"
    if not rules_enabled:
        rules_block["note"] += " 当前未启用。"

    policy = {
        # `schema` = **结构兼容版本**（数据面据此拒绝不认识的策略结构）；
        # `version` = **策略修订号**（每次重标定 +1，控制台用它回答"这条记录是哪版策略算的"）。
        "schema": POLICY_SCHEMA,
        "version": version,
        "generated_by": "thresholds.py",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "zero_day_enabled": zd_enabled,
        "calibration_pool": {"name": pool_name, "source": source, "n": len(pool),
                             **guard},
        "supervised": supervised,
        "zero_day": zero_day,
        "rules": rules_block,
        "fusion": fusion_block(rules_enabled, ruleset_sha, n_rules, n_block_rules,
                               rule_block_fpr, rules_block["sup_target_fpr"],
                               nominal_target),
        "union_fpr_on_pool": union,
        "block_fpr_on_pool": block_fpr,
        "fused_block_fpr_on_pool": fused_block_fpr,
        "effective_fused_fpr_on_pool": eff_union,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(policy, f, ensure_ascii=False, indent=2)
    print(f"[policy] -> {args.out}")

    # testvec 只能跟着**现役**策略走；预览写临时文件时不动它（否则门禁会指向未采纳的阈值）。
    if not args.no_testvec and os.path.abspath(args.out) == os.path.abspath(POLICY_PATH):
        refresh_testvec(policy)
    elif not args.no_testvec:
        print("[policy] 预览输出（非现役路径）→ 跳过 testvec 刷新")


if __name__ == "__main__":
    main()
