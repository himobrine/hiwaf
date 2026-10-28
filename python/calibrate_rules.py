"""规则通道标定：**用 Rust 同一份实现**在真实池上量命中 / 误报 / 阻断预算。

三个用途：

  1. **p7 锚点（回归）**：把 p7 挖出的 21 条候选在同一批池上重放，逐条比对 p7 的
     `benign_hits` / `attack_hits` / `pool_support` / `verdict`。断言"7 keep / 6 reject_fp"。
     锚点对不上就必须解释清楚 —— 要么 Rust 实现错了，要么 p7 错了，两个都不能放过。
     ⚠️ 规则与探针的定义**直接 import `p7_rule_mining`**，不复制一份（复制就是第二个事实来源）。

  2. **三关的 ②③ 关**（`service/rule_validate.py` 调它）：
     真实良性池上误报必须为 0；攻击池上命中必须 > 0。

  3. **阻断预算**（`service/rule_promote.py` 调它，`--budget-only`）：
     只统计 `action=block` 的规则在真良性池上的命中，输出 **Wilson 95% 上界**。
     为什么不用点估计：挖出的规则本身就是在 CSIC 正常流量上筛出来的（p7 用了全部
     36,000 条正常流量），留出集是同一批数据 ⇒ 点估计**系统性偏低**。
     拿偏低的数去扣预算，融合 FPR 会被顶穿目标而没人知道。

用法：
    py -3.10 calibrate_rules.py --ruleset rules.json [--out report.json]
    py -3.10 calibrate_rules.py --ruleset rules.json --budget-only      # 只打印一行 JSON
    py -3.10 calibrate_rules.py --anchor-only                          # 只做 p7 锚点
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p7_rule_mining as p7  # noqa: E402  （规则/探针定义的唯一事实来源）

from service import toolchain  # noqa: E402

ART = os.path.join(HERE, "artifacts")
TRAINDATA = os.path.abspath(os.path.join(HERE, "..", "traindata"))
LOCAL = os.path.join(TRAINDATA, "local")
CANDIDATES = os.path.join(ART, "rule_candidates.json")

Z95 = 1.959963984540054


# --------------------------------------------------------------------------- 池
def wilson_upper(k: int, n: int, z: float = Z95) -> float:
    """Wilson score 区间的上界（95%）。n=0 时返回 0。"""
    if n <= 0:
        return 0.0
    p = k / n
    d = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return min(1.0, centre + half)


def as_records(rows, src: str, label: int | None = None):
    """统一成语料行。`label` 用于强制"整份文件都是良性/攻击"的出处式标注。"""
    out = []
    for i, r in enumerate(rows):
        if label is not None and r.get("label") is not None and int(r["label"]) != label:
            continue
        o = {
            "id": f"{src}#{i}",
            "pool": src,
            "method": r.get("method") or "GET",
            "path": r.get("path") or "",
            "query": r.get("query") or "",
            "body": r.get("body") or "",
        }
        hdrs = r.get("headers") or {}
        ua = r.get("ua") or hdrs.get("user-agent")
        if ua:
            o["ua"] = ua
        ref = r.get("referer") or hdrs.get("referer")
        if ref:
            o["referer"] = ref
        out.append(o)
    return out


def build_sources(need_attack: bool) -> dict:
    """按来源构造语料。`need_attack=False` 时跳过攻击池（`--budget-only` 快得多）。"""
    from realdata import load_payloads, load_csic, csic_normal_index, load_datacon, load_local_jsonl

    srcs: dict[str, list] = {}

    print("[pool] CSIC 2010 ...")
    csic_reqs, csic_y = load_csic()
    # 官方协议：与零日通道训练集互斥的 6,000 条留出正常流量。
    # （`csic_normal_index` 内部会再解析一次 CSIC；为协议一致性认这个开销。）
    _, hold_idx = csic_normal_index(seed=7, n_train=30000)
    hold_set = set(int(i) for i in hold_idx)
    norm = [i for i, y in enumerate(csic_y) if y == 0]
    anom = [i for i, y in enumerate(csic_y) if y == 1]
    srcs["csic_norm_holdout"] = as_records([csic_reqs[i] for i in norm if i in hold_set], "csic_norm_holdout")
    srcs["csic_norm_rest"] = as_records([csic_reqs[i] for i in norm if i not in hold_set], "csic_norm_rest")
    if need_attack:
        srcs["csic_anom"] = as_records([csic_reqs[i] for i in anom], "csic_anom")

    print("[pool] lexical (HTTP Params) ...")
    lex = load_payloads(os.path.join(TRAINDATA, "payload_test_lexical.csv"))
    srcs["lex_norm"] = as_records([r for r in lex if r["label"] == 0], "lex_norm")
    if need_attack:
        srcs["lex_atk"] = as_records([r for r in lex if r["label"] != 0], "lex_atk")

        print("[pool] datacon2025 标注攻击 ...")
        d_atk = [r for sp in ("train", "test") for r in load_datacon(sp) if r["label"] == 1]
        srcs["datacon_atk"] = as_records(d_atk, "datacon_atk")

        print("[pool] 在野 IOC 攻击 ...")
        p = os.path.join(LOCAL, "inwild_attack.jsonl")
        if os.path.exists(p):
            srcs["inwild_atk"] = as_records(load_local_jsonl(p, label=1), "inwild_atk")
        else:
            print(f"[pool] ⚠️ 缺 {p}，在野攻击不进攻击池（覆盖面又窄了一块）")

    print("[pool] 本机真实良性 ...")
    p = os.path.join(LOCAL, "local_lab_benign.jsonl")
    if os.path.exists(p):
        srcs["local_benign"] = as_records(load_local_jsonl(p, label=0), "local_benign")
    else:
        print(f"[pool] ⚠️ 缺 {p}，真实良性只有 CSIC 留出集（无法交叉验证『只在 CSIC 上 0 误报』）")

    return {k: v for k, v in srcs.items() if v}


POOLS = {
    # p7 锚点用的池（与 p7_rule_mining.py 完全一致）
    "p7_benign": ["lex_norm", "csic_norm_holdout", "csic_norm_rest"],
    "p7_attack": ["lex_atk", "csic_anom", "datacon_atk"],
    # 三关 + 预算用的池
    "unified_benign": ["csic_norm_holdout", "local_benign"],
    "unified_attack": ["csic_anom", "inwild_atk", "datacon_atk"],
}


# --------------------------------------------------------------------------- 语料 / 回放
def write_corpus(srcs: dict, path: str) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for name, rows in srcs.items():
            for o in rows:
                f.write(json.dumps(o, ensure_ascii=False) + "\n")
                n += 1
    return n


def replay(ruleset_path: str, corpus_path: str, out_path: str, extra=()) -> dict:
    args = ["rules", "replay", "--rules", ruleset_path, "--in", corpus_path,
            "--out", out_path, "--meta", *extra]
    p = toolchain.run_proto(args, timeout=3600)
    if p.returncode != 0:
        raise SystemExit("rules replay 失败：\n" + (p.stdout or "") + (p.stderr or ""))
    meta = None
    for line in (p.stderr or "").splitlines():
        if line.startswith("[rules]"):
            print("   " + line)
    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            if "_meta" in o:
                meta = o["_meta"]
                break
    return {"meta": meta}


def aggregate(result_path: str, srcs: dict) -> tuple:
    """返回 (hits_by_rule_by_source, lines_by_source)。"""
    hits: dict[str, dict[str, int]] = {}
    lines: dict[str, int] = {k: len(v) for k, v in srcs.items()}
    with open(result_path, "r", encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            if "_meta" in o:
                continue
            pool = o.get("pool") or ""
            for h in o.get("hits") or []:
                rid = h["rule"]
                hits.setdefault(rid, {})
                hits[rid][pool] = hits[rid].get(pool, 0) + 1
    return hits, lines


def pool_counts(hits_by_src: dict, lines: dict, src_names: list) -> tuple:
    k = 0
    for s in src_names:
        if s not in lines:
            continue
        k += hits_by_src.get(s, 0)
    return k, sum(lines.get(s, 0) for s in src_names)


# --------------------------------------------------------------------------- 单条规则集的重放
def make_ruleset(rules: list, decode: list, out_path: str, ruleset_id: str,
                 min_weight_to_block: float = 1.0) -> str:
    doc = {"schema": 1, "ruleset_id": ruleset_id, "decode": decode,
           "min_weight_to_block": min_weight_to_block, "rules": rules}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return out_path


def p7_ruleset(decode: list, out_path: str, ruleset_id: str) -> str:
    """从 `p7_rule_mining.RULES` 生成规则集（唯一事实来源，不复制规则文本）。"""
    rules = [{"id": name, "name": name, "regex": pat, "scopes": ["full"],
              "severity": "medium", "weight": 1.0, "action": "alert", "source": "mined"}
             for name, pat in p7.RULES.items()]
    return make_ruleset(rules, decode, out_path, ruleset_id)


def support_count(probe: str, texts: list) -> int:
    rx = re.compile(probe)
    return sum(1 for t in texts if rx.search(t))


# --------------------------------------------------------------------------- p7 锚点
def run_anchor(srcs: dict, tmpdir: str, corpus_path: str | None = None) -> dict:
    print("\n=== p7 锚点（Rust 重放 vs p7 的 Python 记录） ===")
    cand = json.load(open(CANDIDATES, encoding="utf-8")) if os.path.exists(CANDIDATES) else {}
    prev = {r["rule"]: r for r in cand.get("rules", [])}
    if not prev:
        print("[anchor] ⚠️ 没有 rule_candidates.json，跳过锚点对比")
        return {"skipped": True}

    corpus = corpus_path or os.path.join(tmpdir, "p7_corpus.jsonl")
    if corpus_path is None or not os.path.exists(corpus):
        n = write_corpus(srcs, corpus)
    else:
        n = sum(len(v) for v in srcs.values())
    print(f"[anchor] 语料 {n:,} 行 -> {corpus}")

    res: dict = {}
    for tag, decode in (("decoded", ["urlencoded"]), ("raw", ["raw"])):
        rs = p7_ruleset(decode, os.path.join(tmpdir, f"p7_{tag}.json"), f"p7-anchor-{tag}")
        out = os.path.join(tmpdir, f"p7_{tag}_out.jsonl")
        print(f"[anchor] 重放（decode={decode}）...")
        replay(rs, corpus, out)
        h, lines = aggregate(out, srcs)
        res[tag] = (h, lines)

    # p7 的攻击池文本（解码后）用于复算 pool_support —— 探针是 Python 正则，
    # 只有探测（不在线匹配）这一步留在 Python，符合"匹配归 Rust"的边界。
    from realdata import load_payloads, load_csic, load_datacon
    from urllib.parse import unquote_plus

    def dec(t: str) -> str:
        for _ in range(2):
            nn = unquote_plus(t)
            if nn == t:
                break
            t = nn
        return t

    atk_texts_d = [p7.req_text(r) for r in srcs["lex_atk"]] if "lex_atk" in srcs else []
    atk_texts_d += [p7.req_text(r) for r in srcs["csic_anom"]] if "csic_anom" in srcs else []
    atk_texts_d += [p7.req_text(r) for r in srcs["datacon_atk"]] if "datacon_atk" in srcs else []
    atk_texts_d = [dec(t) for t in atk_texts_d]
    atk_texts_raw = [p7.req_text(r) for r in srcs["lex_atk"]] if "lex_atk" in srcs else []
    atk_texts_raw += [p7.req_text(r) for r in srcs["csic_anom"]] if "csic_anom" in srcs else []
    atk_texts_raw += [p7.req_text(r) for r in srcs["datacon_atk"]] if "datacon_atk" in srcs else []

    hd, lines = res["decoded"]
    hr, _ = res["raw"]
    rules_out = []
    n_match_cnt = n_match_verdict = 0
    mism = []
    for name in p7.RULES:
        bh, bn = pool_counts(hd.get(name, {}), lines, POOLS["p7_benign"])
        ah, an = pool_counts(hd.get(name, {}), lines, POOLS["p7_attack"])
        bhr, _ = pool_counts(hr.get(name, {}), lines, POOLS["p7_benign"])
        ahr, _ = pool_counts(hr.get(name, {}), lines, POOLS["p7_attack"])
        sup = support_count(p7.PROBES[name], atk_texts_d) if p7.PROBES.get(name) else None
        sup_raw = support_count(p7.PROBES[name], atk_texts_raw) if p7.PROBES.get(name) else None
        verdict = p7_verdict(bh, ah, sup)

        e = prev.get(name, {})
        ok_cnt = (bh == e.get("benign_hits") and ah == e.get("attack_hits")
                  and bhr == e.get("benign_hits_raw") and ahr == e.get("attack_hits_raw")
                  and sup == e.get("pool_support"))
        ok_verdict = verdict == e.get("verdict")
        n_match_cnt += int(ok_cnt)
        n_match_verdict += int(ok_verdict)
        if not (ok_cnt and ok_verdict):
            mism.append({
                "rule": name, "verdict_rust": verdict, "verdict_py": e.get("verdict"),
                "benign_rust": bh, "benign_py": e.get("benign_hits"),
                "attack_rust": ah, "attack_py": e.get("attack_hits"),
                "attack_raw_rust": ahr, "attack_raw_py": e.get("attack_hits_raw"),
                "support_rust": sup, "support_py": e.get("pool_support"),
            })
        rules_out.append({
            "id": name, "verdict": verdict,
            "benign_hits": bh, "benign_n": bn,
            "attack_hits": ah, "attack_n": an,
            "benign_hits_raw": bhr, "attack_hits_raw": ahr,
            "decoding_gain": ah - ahr,
            "pool_support": sup, "pool_support_raw": sup_raw,
            "matched_p7_counts": ok_cnt, "matched_p7_verdict": ok_verdict,
        })

    gain = sum(r["decoding_gain"] for r in rules_out)
    anchor = {
        "n_rules": len(p7.RULES),
        "counts_exact_match": n_match_cnt,
        "verdicts_match": n_match_verdict,
        "yr_kept": sum(1 for r in rules_out if r["verdict"] == "keep"),
        "yr_reject_fp": sum(1 for r in rules_out if r["verdict"] == "reject_fp"),
        "yr_unverifiable": sum(1 for r in rules_out if r["verdict"] == "unverifiable_by_pool"),
        "yr_insufficient": sum(1 for r in rules_out if r["verdict"] == "insufficient_support"),
        "yr_reject_no_hit": sum(1 for r in rules_out if r["verdict"] == "reject_no_hit"),
        "decoding_gain_total": gain,
        "p7_decoding_gain_total": (cand.get("summary") or {}).get("decoding_gain_total"),
        "p7_benign_n": sum(lines.get(s, 0) for s in POOLS["p7_benign"]),
        "p7_attack_n": sum(lines.get(s, 0) for s in POOLS["p7_attack"]),
        "mismatches": mism,
        "rules": rules_out,
    }
    print(f"[anchor] 计数逐条一致 {n_match_cnt}/{len(p7.RULES)}；"
          f"判定逐条一致 {n_match_verdict}/{len(p7.RULES)}")
    print(f"[anchor] 池规模 benign={anchor['p7_benign_n']:,} attack={anchor['p7_attack_n']:,}"
          f"（p7 记录 37,000 / 25,213）")
    print(f"[anchor] 判定分布 keep={anchor['yr_kept']} reject_fp={anchor['yr_reject_fp']} "
          f"unverifiable={anchor['yr_unverifiable']} insufficient={anchor['yr_insufficient']}"
          f"（p7: 7 / 6 / 6 / 2）")
    print(f"[anchor] 解码增益 {gain}（p7: {anchor['p7_decoding_gain_total']}）")
    for m in mism:
        print(f"  ✗ {m['rule']}: rust={m['verdict_rust']}(b{m['benign_rust']}/a{m['attack_rust']}) "
              f"vs py={m['verdict_py']}(b{m['benign_py']}/a{m['attack_py']})")
    return anchor


def p7_verdict(benign_hits: int, attack_hits: int, support) -> str:
    """与 `p7_rule_mining.eval_rules` 完全一致的判定逻辑。"""
    if benign_hits > 0:
        return "reject_fp"
    if attack_hits > 0:
        return "keep"
    if support == 0:
        return "unverifiable_by_pool"
    if support is not None and support < 5:
        return "insufficient_support"
    return "reject_no_hit"


# --------------------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ruleset", help="待标定的规则集 JSON")
    ap.add_argument("--out", help="完整报告写这里")
    ap.add_argument("--budget-only", action="store_true",
                    help="只量阻断预算并把一行 JSON 打到 stdout（提升流程用）")
    ap.add_argument("--anchor-only", action="store_true", help="只做 p7 锚点（用 p7 的 21 条规则）")
    ap.add_argument("--skip-anchor", action="store_true", help="跳过 p7 锚点（控制台的校验路径用，省时间）")
    ap.add_argument("--corpus-dir", help="把语料写到这个目录（默认临时目录）")
    ap.add_argument("--keep-corpus", action="store_true", help="保留临时目录便于排查")
    args = ap.parse_args()

    t0 = time.time()
    tmpdir = args.corpus_dir or tempfile.mkdtemp(prefix="waf_rule_cal_")
    os.makedirs(tmpdir, exist_ok=True)
    print(f"[cal] 临时目录 {tmpdir}")

    report = {"schema": 1, "generated_at": int(time.time() * 1000)}

    if args.anchor_only:
        srcs = build_sources(need_attack=True)
        report["p7_anchor"] = run_anchor(srcs, tmpdir)
        write_report(report, args.out, t0, tmpdir, args.keep_corpus)
        return

    if not args.ruleset:
        raise SystemExit("需要 --ruleset（或用 --anchor-only）")
    with open(args.ruleset, "r", encoding="utf-8") as f:
        raw = f.read()
    spec = json.loads(raw)
    sha = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    report["ruleset"] = {
        "ruleset_id": spec.get("ruleset_id"),
        "sha1_16": sha,
        "n_rules": len(spec.get("rules") or []),
        "decode": spec.get("decode"),
        "min_weight_to_block": spec.get("min_weight_to_block"),
        "block_rules": [r["id"] for r in (spec.get("rules") or [])
                        if r.get("action") == "block"],
    }
    print(f"[cal] 规则集 {os.path.basename(args.ruleset)}  sha1_16={sha}  "
          f"rules={report['ruleset']['n_rules']}  block={len(report['ruleset']['block_rules'])}")

    # ---- 预算：只需要真良性池 ----
    need_attack = not args.budget_only
    srcs = build_sources(need_attack=need_attack)
    corpus = os.path.join(tmpdir, "corpus.jsonl")
    n_lines = write_corpus(srcs, corpus)
    print(f"[cal] 语料 {n_lines:,} 行 -> {corpus}")

    out_lines = os.path.join(tmpdir, "out.jsonl")
    replay(args.ruleset, corpus, out_lines)
    hits, lines = aggregate(out_lines, srcs)
    print(f"[cal] 回放完成 ({time.time() - t0:.1f}s)")

    # ---- 逐规则统计（统一池） ----
    rules_out = []
    for r in spec.get("rules") or []:
        rid = r["id"]
        bh, bn = pool_counts(hits.get(rid, {}), lines, POOLS["unified_benign"])
        ah, an = pool_counts(hits.get(rid, {}), lines, POOLS["unified_attack"])
        verdict = "reject_fp" if bh > 0 else ("keep" if ah > 0 else "unverifiable_by_pool")
        rules_out.append({
            "id": rid, "action": r.get("action"), "scopes": r.get("scopes"),
            "benign_hits": bh, "benign_n": bn, "benign_rate": bh / bn if bn else None,
            "attack_hits": ah, "attack_n": an, "attack_rate": ah / an if an else None,
            "verdict": verdict,
        })
    report["rules"] = rules_out

    bn_tot = sum(lines.get(s, 0) for s in POOLS["unified_benign"])
    an_tot = sum(lines.get(s, 0) for s in POOLS["unified_attack"])
    report["pools"] = {
        "unified": {
            "benign_n": bn_tot, "attack_n": an_tot,
            "benign_sources": " + ".join(f"{s}({lines.get(s, 0)})" for s in POOLS["unified_benign"]),
            "attack_sources": " + ".join(f"{s}({lines.get(s, 0)})" for s in POOLS["unified_attack"]),
            "benign_caveat": (
                "CSIC 留出集与 p7 的**筛选语料同源**（p7 用了全部 36,000 条正常流量）⇒ "
                "挖出的规则在本池上的点估计系统性偏低。阻断预算一律用 Wilson 95% 上界。"),
        },
    }

    # ---- 阻断预算（只数 block 规则） ----
    block_ids = report["ruleset"]["block_rules"]
    hit_ids: dict[str, int] = {}
    ben_hit_lines = 0
    with open(out_lines, "r", encoding="utf-8") as f:
        benign_srcs = set(POOLS["unified_benign"])
        for line in f:
            o = json.loads(line)
            if "_meta" in o:
                continue
            if o.get("pool") not in benign_srcs:
                continue
            b = [h["rule"] for h in (o.get("hits") or []) if h["rule"] in block_ids]
            if b:
                ben_hit_lines += 1
                for rid in set(b):
                    hit_ids[rid] = hit_ids.get(rid, 0) + 1
    budget = {
        "block_rules": len(block_ids),
        "benign_hits": ben_hit_lines,
        "benign_n": bn_tot,
        "fpr_point": (ben_hit_lines / bn_tot) if bn_tot else 0.0,
        "fpr_upper_95": wilson_upper(ben_hit_lines, bn_tot),
        "method": "Wilson 95% 上界（点估计因选择污染系统性偏低，不能直接拿去扣预算）",
        "hits_by_rule": hit_ids,
        "benign_sources": report["pools"]["unified"]["benign_sources"],
    }
    report["block_budget"] = budget
    print(f"[cal] 阻断预算：{budget['block_rules']} 条 block 规则，命中 {budget['benign_hits']}/"
          f"{budget['benign_n']}，点估计 {budget['fpr_point']:.5%}，"
          f"Wilson 上界 {budget['fpr_upper_95']:.5%}")

    if not args.skip_anchor and not args.budget_only:
        report["p7_anchor"] = run_anchor(srcs, tmpdir, corpus_path=corpus)

    if args.budget_only:
        print(json.dumps(budget, ensure_ascii=False))
    write_report(report, args.out, t0, tmpdir, args.keep_corpus)


def write_report(report: dict, out: str | None, t0: float, tmpdir: str, keep: bool):
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)
        print(f"[cal] 报告 -> {out}")
    if not keep:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(f"[cal] 用时 {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
