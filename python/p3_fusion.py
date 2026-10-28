"""P3：双通道融合评估 —— 零日通道到底多召回多少？

`REALDATA_EVALUATION.md` §8.3 定了「分数 + 标定阈值」，但留了两个没答的问题：

1. **标定池选得对不对？** 旧阈值 `0.488107` 标定在 CSIC 正常流量的**文件尾部 6,000 条**上。
   尾部不等于全体：如果尾部恰好以"无参裸 GET"为主，阈值就会被标得偏低（偏乐观）。
2. **零日通道加到监督通道上，真实攻击召回能提多少？** 两个通道量纲不同、误报语义不同，
   融合前必须先各自标定。

## 方法

* **统一池** = CSIC 正常 36,000 中 `seed=7` 随机留出的 6,000（与零日通道的训练集**互斥**），
  两通道在同一池上标定 —— 融合后的误报率才可解释；
* 在 **25,065 条真实异常**（CSIC `anomalousTrafficTest.txt`）上比召回；
* 在**别的**良性池（lexical 留出 500 / HTTP Params 正常）上量**跨池**误报，检验阈值是否只对池过敏；
* 旧阈值回代：把 `0.488107` 放到代表性池上，量它真实的误报率。

输出 `artifacts/p3_fusion.json`。
"""
from __future__ import annotations

import json
import os
import time

import numpy as np

from features import FeatureExtractor
from export_testvec import rule_evidence
from realdata import (TRAINDATA, csic_normal_index, load_csic, load_datacon,
                      load_payloads)

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

BUDGETS = (0.001, 0.01, 0.03)
# 历史值：§8.3 时期在 CSIC 文件尾部 6,000 条上标定的 1%FPR 阈值。
# 保留它是为了量"池选偏了会偏乐观多少"，**不是**当前策略值。
OLD_TAIL_THRESHOLD = 0.488107


class Scorer:
    """一次加载两通道 ONNX，按请求批量打分。"""

    def __init__(self, policy: dict):
        import onnxruntime as ort
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1
        self.ort = ort
        self.so = so
        self.x = ort.InferenceSession(os.path.join(ART, policy["supervised"]["artifact"]),
                                      so, providers=["CPUExecutionProvider"])
        self.i = ort.InferenceSession(os.path.join(ART, policy["zero_day"]["artifact"]),
                                      so, providers=["CPUExecutionProvider"])
        self.normal_idx = int(policy["supervised"]["normal_class_index"])
        outs = [o.name for o in self.x.get_outputs()]
        self.p_idx = outs.index("probabilities") if "probabilities" in outs else 1
        self.fx = FeatureExtractor()

    def _X(self, reqs):
        return np.asarray(self.fx.transform_batch(reqs), dtype=np.float32)

    def sup(self, reqs) -> np.ndarray:
        p = np.asarray(self.x.run(None, {self.x.get_inputs()[0].name: self._X(reqs)})[self.p_idx])
        return 1.0 - p[:, self.normal_idx]

    def zd(self, reqs) -> np.ndarray:
        e = self.i.run(None, {self.i.get_inputs()[0].name: self._X(reqs)})[0]
        return -np.asarray(e).ravel()


def rate(scores, mask, thr) -> float:
    return float((scores[mask] >= thr).mean()) if mask.any() else float("nan")


def main():
    t0 = time.time()
    with open(os.path.join(ART, "decision_policy.json"), "r", encoding="utf-8") as f:
        policy = json.load(f)
    sc = Scorer(policy)
    sup_thr = float(policy["supervised"]["threshold"])
    zd_thr = float(policy["zero_day"]["threshold"])
    print(f"[p3] 策略 @{policy['supervised']['target_fpr']}FPR: "
          f"监督 thr={sup_thr:.6f}  零日 thr={zd_thr:.6f}")
    print(f"[p3] 池: {policy['calibration_pool']['name']}")

    report = {"policy": policy, "budgets": list(BUDGETS)}

    # ------------------------------------------------------------------
    # 0) 规则通道（第三通道）——**纯规则**，与监督 FPR 预算无关
    # ------------------------------------------------------------------
    # 证据一律走 `waf-ai-proto rules replay`（与标定、门禁、采集器同一份实现）。
    # 用 Python `re` 重算一遍是没有意义的：`$`、lookaround、反斜杠转义都会漂。
    rcfg = policy.get("rules") or {}
    rules_on = bool(rcfg.get("enabled"))
    rpath = ""
    if rcfg.get("ruleset_path"):
        cand = os.path.join(HERE, str(rcfg["ruleset_path"]))
        if os.path.exists(cand):
            rpath = cand
    if not rpath:
        cand = os.path.join(ART, "rules_authoritative.json")
        rpath = cand if os.path.exists(cand) else ""
    mw = float(rcfg.get("min_weight_to_block") or 0.0)
    if rules_on and rpath:
        print(f"[p3] 规则通道：{rcfg.get('n_rules')} 条规则（block "
              f"{rcfg.get('n_block_rules')} 条），阻断线 block_weight>={mw}，"
              f"规则集 {os.path.basename(rpath)} sha1_16={rcfg.get('ruleset_sha1_16')}")
    else:
        print("[p3] 规则通道：**未启用**（策略 rules.enabled=false 或无现役规则集）"
              " —— 融合等价于双通道")

    def rules_ev(reqs):
        """返回 (任意命中权重, 阻断权重)。规则通道未启用时全 0（不参与融合）。"""
        n = len(reqs)
        if not (rules_on and rpath) or n == 0:
            return np.zeros(n), np.zeros(n)
        ev = rule_evidence(reqs, rpath)
        return (np.asarray(ev["weight"], dtype=float),
                np.asarray(ev["block_weight"], dtype=float))

    def rules_block(bw) -> np.ndarray:
        """规则阻断命中掩码。阻断线 ≤0 或通道关闭时恒 False（不许"默认开火"）。"""
        if not (rules_on and mw > 0):
            return np.zeros(len(bw), bool)
        return bw + 1e-9 >= mw

    # ------------------------------------------------------------------
    # 1) CSIC：统一池标定 + 真实异常召回
    # ------------------------------------------------------------------
    print("\n[load] CSIC 2010 ...")
    csic_reqs, csic_y = load_csic()
    csic_y = np.asarray(csic_y)
    _, hold_idx = csic_normal_index(seed=7, n_train=30000)
    pool_req = [csic_reqs[i] for i in hold_idx]
    anom_req = [r for r, v in zip(csic_reqs, csic_y) if v == 1]
    print(f"[csic] 统一池(正常留出)={len(pool_req):,}  真实异常={len(anom_req):,}")

    sup_pool, zd_pool = sc.sup(pool_req), sc.zd(pool_req)
    sup_an, zd_an = sc.sup(anom_req), sc.zd(anom_req)

    rw_pool, rb_pool = rules_ev(pool_req)
    rw_an, rb_an = rules_ev(anom_req)
    rb_pool_hit = rules_block(rb_pool)
    rb_an_hit = rules_block(rb_an)
    print(f"[csic] 规则通道：阻断命中 池 {int(rb_pool_hit.sum())}/{len(pool_req)} "
          f"({rb_pool_hit.mean()*100:.3f}%)  异常 {int(rb_an_hit.sum())}/{len(anom_req)} "
          f"(召回 {rb_an_hit.mean()*100:.1f}%)；"
          f"任意命中(→告警) 池 {(rw_pool > 0).mean()*100:.2f}% 异常 {(rw_an > 0).mean()*100:.1f}%")

    print("\n=== CSIC：三通道在**同一代表性池**上标定后的召回 ===")
    print(f"{'预算':>6}  {'监督':>8}  {'零日':>8}  {'规则阻断':>9}  "
          f"{'融合阻断召回':>13}  {'融合阻断误报':>13}")
    csic_rows = {}
    for f in BUDGETS:
        ts = float(np.quantile(sup_pool, 1.0 - f))
        tz = float(np.quantile(zd_pool, 1.0 - f))
        supa, supp = sup_an >= ts, sup_pool >= ts
        zda, zdp = zd_an >= tz, zd_pool >= tz
        rs = float(supa.mean())
        rz = float(zda.mean())
        rr = float(rb_an_hit.mean())
        rf = float((supa | rb_an_hit).mean())          # 融合**阻断**召回
        ff = float((supp | rb_pool_hit).mean())        # 融合**阻断**误报（预算约束对象）
        csic_rows[f"{f:g}"] = {
            "sup_thr": ts, "zd_thr": tz,
            "recall_sup": rs, "recall_zd": rz,
            "recall_rule_block": rr,
            "recall_fused_block": rf, "fpr_fused_block": ff,
            # 两通道并集（含零日**告警**）仍然保留：它是"标记率"，不是阻断口径。
            "recall_union": float((supa | zda).mean()),
            "fpr_union": float((supp | zdp).mean()),
        }
        print(f"{f*100:>5.1f}%  {rs*100:>7.1f}%  {rz*100:>7.1f}%  {rr*100:>8.1f}%  "
              f"{rf*100:>12.1f}%  {ff*100:>12.2f}%")
    report["csic_recall"] = csic_rows

    # 策略值（1% 档）单列，作为对外口径
    key = policy["supervised"]["target_fpr"]
    r = csic_rows.get(key)
    if r:
        print(f"[csic] 正式口径 @1%FPR：监督 {r['recall_sup']*100:.1f}% + 零日 "
              f"{r['recall_zd']*100:.1f}% -> 并集 {r['recall_union']*100:.1f}%  "
              f"(并集误报 {r['fpr_union']*100:.2f}%)")
        print(f"[csic] 零日通道的**净增量** = {(r['recall_union']-r['recall_sup'])*100:+.1f} 个百分点")
        print(f"[csic] 融合**阻断**：监督 {r['recall_sup']*100:.1f}% + 规则阻断 "
              f"{r['recall_rule_block']*100:.1f}% -> {r['recall_fused_block']*100:.1f}%  "
              f"(阻断误报 {r['fpr_fused_block']*100:.2f}%，目标 {float(key)*100:.1f}%)；"
              f"规则净增量 {(r['recall_fused_block']-r['recall_sup'])*100:+.1f} 个百分点")

    # ------------------------------------------------------------------
    # 2) 跨池误报：阈值是不是只对池过敏？
    # ------------------------------------------------------------------
    print("\n=== 跨池误报/召回（用策略阈值，池外数据）===")
    from train_realdata import load_all
    _, _, _, lex_eval, _ = load_all(hard_neg="lexical", seed=11)
    lex_r = [{"method": s["method"], "path": s["path"], "query": s["query"], "body": s["body"]}
             for s in lex_eval]
    lex_a = np.asarray([s["label"] != 0 for s in lex_eval])

    pte = load_payloads(os.path.join(TRAINDATA, "payload_test.csv"))
    pte_r = [{"method": s["method"], "path": s["path"], "query": s["query"], "body": s["body"]}
             for s in pte]
    pte_a = np.asarray([s["label"] != 0 for s in pte])

    cross = {}
    for tag, reqs, is_atk in (("lexical", lex_r, lex_a), ("payload_test", pte_r, pte_a),
                              ("csic_pool", pool_req, np.zeros(len(pool_req), bool)),
                              ("csic_anomaly", anom_req, np.ones(len(anom_req), bool))):
        s, z = sc.sup(reqs), sc.zd(reqs)
        rw, rbw = rules_ev(reqs)
        rbh = rules_block(rbw)
        benign, attack = ~is_atk, is_atk
        row = {
            "n": len(reqs), "n_attack": int(is_atk.sum()),
            "fpr_sup": rate(s, benign, sup_thr), "fpr_zd": rate(z, benign, zd_thr),
            "fpr_union": (float(((s[benign] >= sup_thr) | (z[benign] >= zd_thr)).mean())
                          if benign.any() else float("nan")),
            "recall_sup": rate(s, attack, sup_thr), "recall_zd": rate(z, attack, zd_thr),
            "recall_union": (float(((s[attack] >= sup_thr) | (z[attack] >= zd_thr)).mean())
                             if attack.any() else float("nan")),
            # 规则通道单独一列：阻断（预算口径）与"任意命中"（告警口径）分开报。
            "fpr_rule_block": (float(rbh[benign].mean()) if benign.any() else float("nan")),
            "recall_rule_block": (float(rbh[attack].mean()) if attack.any() else float("nan")),
            "flag_rate_rule_any": float((rw > 0).mean()),
            # **融合**阻断 = 监督 or 规则阻断（零日只告警，不进阻断口径）
            "fpr_fused_block": (float(((s[benign] >= sup_thr) | rbh[benign]).mean())
                                if benign.any() else float("nan")),
            "recall_fused_block": (float(((s[attack] >= sup_thr) | rbh[attack]).mean())
                                   if attack.any() else float("nan")),
        }
        cross[tag] = row
        print(f"  {tag:<14} n={row['n']:<6} "
              f"误报: 监督 {row['fpr_sup']*100:5.2f}% 零日 {row['fpr_zd']*100:5.2f}% "
              f"并集 {row['fpr_union']*100:5.2f}%  规则阻断 {row['fpr_rule_block']*100:5.2f}%  "
              f"融合阻断 {row['fpr_fused_block']*100:5.2f}%")
        print(f"  {'':<14} {'':<6} "
              f"召回: 监督 {row['recall_sup']*100:5.1f}% 零日 {row['recall_zd']*100:5.1f}% "
              f"并集 {row['recall_union']*100:5.1f}%  规则阻断 {row['recall_rule_block']*100:5.1f}%  "
              f"融合阻断 {row['recall_fused_block']*100:5.1f}%  "
              f"规则任意命中 {row['flag_rate_rule_any']*100:5.1f}%")
    report["cross_pool"] = cross

    # ------------------------------------------------------------------
    # 3) 旧（文件尾部池）阈值回代：偏乐观了多少？
    # ------------------------------------------------------------------
    print("\n=== 旧阈值回代（0.488107，标定在 CSIC 文件尾部 6,000 条）===")
    tail_fpr = float((sup_pool >= OLD_TAIL_THRESHOLD).mean())
    tail_rec = float((sup_an >= OLD_TAIL_THRESHOLD).mean())
    lex_fpr_old = float((sc.sup(lex_r)[~lex_a] >= OLD_TAIL_THRESHOLD).mean())
    print(f"  代表性池上实际误报 = {tail_fpr*100:.2f}%（目标 1%）  -> "
          f"偏乐观 {tail_fpr/0.01:.1f} 倍")
    print(f"  CSIC 真实异常召回 = {tail_rec*100:.1f}%（用旧阈值）")
    print(f"  lexical 留出正常误报 = {lex_fpr_old*100:.2f}%")
    report["old_tail_threshold"] = {
        "value": OLD_TAIL_THRESHOLD, "fpr_on_representative_pool": tail_fpr,
        "recall_csic_anomaly": tail_rec, "fpr_lexical": lex_fpr_old,
        "optimism_factor_vs_1pct": tail_fpr / 0.01,
    }

    # ------------------------------------------------------------------
    # 4) datacon2025（OOD，labeled=0 ≠ 良性）
    # ------------------------------------------------------------------
    print("\n=== datacon2025（OOD 复核集；labeled=0 ≠ 良性）===")
    dc = load_datacon("train") + load_datacon("test")
    dc_r = [{"method": s["method"], "path": s["path"], "query": s["query"], "body": s["body"]}
            for s in dc]
    dc_lab = np.asarray([s["label"] == 1 for s in dc])
    s_dc, z_dc = sc.sup(dc_r), sc.zd(dc_r)
    rw_dc, rb_dc = rules_ev(dc_r)
    rbh_dc = rules_block(rb_dc)
    sup_f = s_dc >= sup_thr
    zd_f = z_dc >= zd_thr
    # 三通道融合：监督 或 规则阻断 -> block；零日生效 或 规则任意命中 -> alert。
    # 零日这边按策略开关算（关着就不产生 alert），否则评估出来的动作线上不存在。
    zd_live = zd_f & bool(policy.get("zero_day_enabled"))
    act = np.where(sup_f | rbh_dc, "block",
                   np.where(zd_live | (rw_dc > 0), "alert", "allow"))
    dc_row = {
        "n": len(dc), "n_labeled_attack": int(dc_lab.sum()),
        "recall_labeled_sup": rate(s_dc, dc_lab, sup_thr),
        "recall_labeled_zd": rate(z_dc, dc_lab, zd_thr),
        "recall_labeled_union": float(((s_dc[dc_lab] >= sup_thr) |
                                       (z_dc[dc_lab] >= zd_thr)).mean()),
        "recall_labeled_rule_block": (float(rbh_dc[dc_lab].mean())
                                      if dc_lab.any() else float("nan")),
        "recall_labeled_fused_block": (float((sup_f[dc_lab] | rbh_dc[dc_lab]).mean())
                                       if dc_lab.any() else float("nan")),
        "flag_rate_unlabeled_sup": rate(s_dc, ~dc_lab, sup_thr),
        "flag_rate_unlabeled_zd": rate(z_dc, ~dc_lab, zd_thr),
        "flag_rate_unlabeled_union": float(((s_dc[~dc_lab] >= sup_thr) |
                                            (z_dc[~dc_lab] >= zd_thr)).mean()),
        "flag_rate_unlabeled_rule_block": (float(rbh_dc[~dc_lab].mean())
                                           if (~dc_lab).any() else float("nan")),
        "actions": {a: int((act == a).sum()) for a in ("allow", "alert", "block")},
        "rules_enabled": rules_on,
        "zero_day_enabled": bool(policy.get("zero_day_enabled")),
    }
    print(f"  样本 {dc_row['n']}（labeled=攻击 {dc_row['n_labeled_attack']}）  "
          f"动作分布 {dc_row['actions']}")
    print(f"  labeled 召回: 监督 {dc_row['recall_labeled_sup']*100:.1f}%  "
          f"零日 {dc_row['recall_labeled_zd']*100:.1f}%  "
          f"并集 {dc_row['recall_labeled_union']*100:.1f}%  "
          f"规则阻断 {dc_row['recall_labeled_rule_block']*100:.1f}%  "
          f"融合阻断 {dc_row['recall_labeled_fused_block']*100:.1f}%")
    print(f"  unlabeled 被标记率（**需人工复核**，非 FPR）: "
          f"监督 {dc_row['flag_rate_unlabeled_sup']*100:.1f}%  "
          f"零日 {dc_row['flag_rate_unlabeled_zd']*100:.1f}%  "
          f"并集 {dc_row['flag_rate_unlabeled_union']*100:.1f}%  "
          f"规则阻断 {dc_row['flag_rate_unlabeled_rule_block']*100:.1f}%")
    report["datacon"] = dc_row

    report["elapsed_s"] = round(time.time() - t0, 1)
    with open(os.path.join(ART, "p3_fusion.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n-> artifacts/p3_fusion.json  ({report['elapsed_s']}s)")


if __name__ == "__main__":
    main()
