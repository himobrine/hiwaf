"""从 WEB_APPLICATION_PAYLOADS.jsonl 挖**规则候选**，并给出可审计的误报率。

⚠️ 定位（和训练无关）：攻击字典**已被否决**用于训练（并入训练集会让 CSIC 异常召回
20.2% → 6.3%，见 REALDATA_EVALUATION.md §8）。它在这里只有两个用途：
  1. 作为**特征/关键词候选**的来源（挖词）；
  2. 作为**规则引擎候选**的对照（M1 数据面）。

⚠️ 该文件本身是**损坏的 JSON**（第 181 行起有编码乱码 `??},`），`json.loads` 会失败。
所以这里用容错正则抽取 `"payload": "..."`，不假装文件是干净的。

每条候选规则都在**真实良性文本**上量误报：
  * 良性池 = lexical 正常 1,000 条（困难长文本）+ CSIC 正常 36,000 条；
  * 攻击池 = lexical 攻击 106 + CSIC 异常 25,065 + datacon 标注攻击 42；
  * 规则文本统一取 `method path?query body`（与 features.py 的 `url + " " + body` 对齐）；
  * **误报>0 的规则一律标 reject**：规则引擎是最容易被误报毁掉的一层。

产出 `artifacts/rule_candidates.json`。

用法：
    py -3.10 p7_rule_mining.py
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
TRAINDATA = os.path.abspath(os.path.join(HERE, "..", "traindata"))
DICT = os.path.join(TRAINDATA, "WEB_APPLICATION_PAYLOADS.jsonl")
OUT_JSON = os.path.join(ART, "rule_candidates.json")

# ---- 候选规则（从字典的 type 归纳 + 常识补全，每条都要在良性文本上过筛）----
RULES = {
    "sqli_union_select": r"(?i)\bunion\b[\s/*+%]{0,4}\bselect\b",
    "sqli_into_outfile": r"(?i)\binto\s+(out|dump)file\b",
    "sqli_meta_table": r"(?i)\b(information_schema|sysobjects|pg_catalog|msdb)\b",
    "sqli_file_func": r"(?i)\b(load_file|xp_cmdshell|utl_http|dbms_pipe)\b",
    "sqli_time_delay": r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*[\(\s]",
    "sqli_tautology": r"(?i)(\bor\b|\band\b)\s*['\"\w]{1,4}\s*=\s*['\"\w]{1,4}",
    "sqli_comment_tail": r"(?i)(--|#|/\*)\s*$",
    "sql_ddl_dml": r"(?i)\b(drop|truncate|insert\s+into|update\s+\w+\s+set)\b",
    "xss_script_tag": r"(?i)<\s*script[\s>]",
    "xss_event_handler": r"(?i)\bon(error|load|click|mouseover|focus|submit)\s*=",
    "xss_js_uri": r"(?i)javascript\s*:|vbscript\s*:",
    "xss_danger_tag": r"(?i)<\s*(img|svg|iframe|object|embed|body|input)[^>]{0,60}>",
    "cmd_shell_bin": r"(?i)[;&|`$]{1,2}\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|cmd|powershell)\b",
    "cmd_subshell": r"\$\(|\`[^\`]{1,40}\`",
    "php_webshell": r"(?i)<\?php|<\?=|eval\s*\(|assert\s*\(|system\s*\(",
    "path_traversal": r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)",
    "path_sensitive_file": r"(?i)(/etc/passwd|/etc/shadow|/windows/win\.ini|/proc/self/environ|\.\.%00)",
    "log4shell_jndi": r"(?i)\$\{jndi:(ldap|rmi|dns|http)",
    "log4shell_lookup": r"(?i)\$\{(\$\{|\w{1,12}:)",
    "ssrf_meta_endpoint": r"(?i)(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data)",
    "rce_gateway_probe": r"(?i)/(actuator/(gateway|env|heapdump)|nacos/v1|/druid/index\.html)",
}

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]{2,}")

# 每条规则的"池支持度探针"：放宽到只留核心 token。
# 用途：区分 **规则写错了**（池里明明有这种攻击却没命中）与
#       **评测池根本不含这种攻击**（不能因此删规则）。CSIC 2010 是购物车站点的
#       SQLi/XSS，几乎不含 UNION、outfile、Log4Shell、SSRF —— 实测 `union` 在
#       25,213 条攻击里只出现 1 次。这个区别必须写清楚，否则会把有用规则误删。
PROBES = {
    "sqli_union_select": r"(?i)\bunion\b",
    "sqli_into_outfile": r"(?i)(out|dump)file",
    "sqli_meta_table": r"(?i)(information_schema|sysobjects|pg_catalog|msdb)",
    "sqli_file_func": r"(?i)(load_file|xp_cmdshell|utl_http|dbms_pipe)",
    "sqli_time_delay": r"(?i)(sleep|benchmark|pg_sleep|waitfor)",
    "sqli_tautology": r"=",
    "sqli_comment_tail": r"(--|#|/\*)",
    "sql_ddl_dml": r"(?i)(drop|truncate|insert|update)",
    "xss_script_tag": r"(?i)<\s*script",
    "xss_event_handler": r"(?i)on\w+\s*=",
    "xss_js_uri": r"(?i)(javascript|vbscript)\s*:",
    "xss_danger_tag": r"(?i)<\s*(img|svg|iframe|object|embed|body|input)",
    "cmd_shell_bin": r"(?i)(cat|ls|whoami|curl|wget|bash|sh|cmd|powershell)\b",
    "cmd_subshell": r"[`$()]",
    "php_webshell": r"(?i)(<\?php|eval|assert|system)",
    "path_traversal": r"\.\.",
    "path_sensitive_file": r"(?i)(passwd|win\.ini|proc/self)",
    "log4shell_jndi": r"(?i)jndi",
    "log4shell_lookup": r"\$\{",
    "ssrf_meta_endpoint": r"(?i)(169\.254|metadata|meta-data)",
    "rce_gateway_probe": r"(?i)(actuator|nacos|druid)",
}
PAYLOAD_RE = re.compile(r'"payload"\s*:\s*"((?:[^"\\]|\\.)*)"')
TYPE_RE = re.compile(r'"type"\s*:\s*"([^"]*)"')
ID_RE = re.compile(r'"id"\s*:\s*"([^"]*)"')


def mine_dict():
    raw = open(DICT, encoding="utf-8", errors="replace").read()
    payloads = [m.group(1) for m in PAYLOAD_RE.finditer(raw)]
    types = [m.group(1) for m in TYPE_RE.finditer(raw)]
    ids = [m.group(1) for m in ID_RE.finditer(raw)]
    return {"n_ids": len(ids), "n_payloads": len(payloads),
            "n_types": len(types), "payloads": payloads,
            "type_counts": dict(collections.Counter(types).most_common())}


def req_text(r) -> str:
    q = r.get("query") or ""
    b = r.get("body") or ""
    return f"{r.get('method', 'GET')} {r.get('path', '')}?{q} {b}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT_JSON)
    args = ap.parse_args()

    from realdata import load_payloads, load_csic, load_datacon, TRAINDATA as TD

    t0 = time.time()
    d = mine_dict()
    print(f"[dict] id={d['n_ids']}  payload={d['n_payloads']}  type={d['n_types']}  "
          f"（文件 JSON 已损坏，用容错正则抽取）")
    print(f"[dict] type 分布: {d['type_counts']}")

    lex = load_payloads(os.path.join(TD, "payload_test_lexical.csv"))
    csic_reqs, csic_y = load_csic()
    d_atk = [r for sp in ("train", "test") for r in load_datacon(sp) if r["label"] == 1]

    benign = [req_text(r) for r in lex if r["label"] == 0]
    benign += [req_text(r) for r, y in zip(csic_reqs, csic_y) if y == 0]
    attack = [req_text(r) for r in lex if r["label"] != 0]
    attack += [req_text(r) for r, y in zip(csic_reqs, csic_y) if y == 1]
    attack += [req_text(r) for r in d_atk]
    print(f"[eval] 良性文本 n={len(benign):,}（lexical 1000 + CSIC 正常 36,000）  "
          f"攻击文本 n={len(attack):,}（lexical 106 + CSIC 异常 25,065 + datacon 42）\n")

    # ---- 挖词：字典里高频、但良性文本里罕见的 token ----
    benign_tok = collections.Counter()
    for t in benign:
        benign_tok.update(x.lower() for x in TOKEN_RE.findall(t))
    dict_tok = collections.Counter()
    for p in d["payloads"]:
        dict_tok.update(x.lower() for x in TOKEN_RE.findall(p))
    n_ben = len(benign) or 1
    scored = [(tok, cnt, benign_tok.get(tok, 0)) for tok, cnt in dict_tok.items() if cnt >= 3]
    scored.sort(key=lambda kv: (-(kv[1] / max(1, kv[2] + 1)), -kv[1]))
    mined = [{"token": t, "in_dict": c, "in_benign": b,
              "dict_per_1k": round(1000 * c / max(1, len(d["payloads"])), 2),
              "benign_per_1k": round(1000 * b / n_ben, 3)}
             for t, c, b in scored[:40]]

    # ---- 规则评估 ----
    # ⚠️ 关键：CSIC 的载荷是 **URL 编码** 的（如 `UNION%20ALL%20SELECT`、`%27`）。
    # 规则跑在原始文本上会几乎全部漏报 —— 实测 `sqli_union_select` 在 25,213 条真实
    # 攻击上命中 **0**。所以这里同时报"原文"和"解码后"两栏，用解码后的结果定去留。
    from urllib.parse import unquote_plus

    def dec(t: str) -> str:
        for _ in range(2):          # 兼容双重编码（%2527）
            n = unquote_plus(t)
            if n == t:
                break
            t = n
        return t

    benign_dec = [dec(t) for t in benign]
    attack_dec = [dec(t) for t in attack]

    def eval_rules(bs, atk_s):
        out = []
        for name, pat in RULES.items():
            rx = re.compile(pat)
            fp = sum(1 for t in bs if rx.search(t))
            hit = sum(1 for t in atk_s if rx.search(t))
            # 池支持度：放宽探针在攻击池里的命中数
            probe = PROBES.get(name)
            support = sum(1 for t in atk_s if re.search(probe, t)) if probe else None
            if fp > 0:
                verdict = "reject_fp"
            elif hit > 0:
                verdict = "keep"
            elif support == 0:
                verdict = "unverifiable_by_pool"   # 池里没有这种攻击，不能判死
            elif support < 5:
                verdict = "insufficient_support"   # 池里只有个位数，判定无统计意义
            else:
                verdict = "reject_no_hit"          # 池里有这种攻击，规则却没命中 ⇒ 规则错
            out.append({
                "rule": name, "regex": pat,
                "benign_hits": fp, "benign_n": len(bs),
                "benign_rate": fp / max(1, len(bs)),
                "attack_hits": hit, "attack_n": len(atk_s),
                "attack_rate": hit / max(1, len(atk_s)),
                "pool_support": support,
                "verdict": verdict,
            })
        return out

    res_raw = eval_rules(benign, attack)
    res_dec = eval_rules(benign_dec, attack_dec)
    by_name = {r["rule"]: r for r in res_raw}
    for r in res_dec:
        r["attack_hits_raw"] = by_name[r["rule"]]["attack_hits"]
        r["benign_hits_raw"] = by_name[r["rule"]]["benign_hits"]
        r["decoding_gain"] = r["attack_hits"] - r["attack_hits_raw"]

    print(f"{'规则':<24}{'原文误报':>9}{'原文命中':>9}{'解码误报':>9}{'解码命中':>9}{'池支持':>7}  判定")
    for r in res_dec:
        print(f"  {r['rule']:<22}{r['benign_hits_raw']:>9}{r['attack_hits_raw']:>9}"
              f"{r['benign_hits']:>9}{r['attack_hits']:>9}"
              f"{(r['pool_support'] if r['pool_support'] is not None else -1):>7}  "
              f"{'✓ keep' if r['verdict'] == 'keep' else r['verdict']}")

    report = {
        "dictionary": {"file": os.path.relpath(DICT, HERE), "n_payloads": d["n_payloads"],
                       "n_types": d["n_types"], "type_counts": d["type_counts"],
                       "warning": "文件 JSON 损坏（第 181 行起乱码），且**禁止用于训练**"},
        "eval": {"benign_n": len(benign), "attack_n": len(attack),
                 "benign_sources": "lexical 正常 1,000 + CSIC 正常 36,000",
                 "attack_sources": "lexical 攻击 106 + CSIC 异常 25,065 + datacon 标注 42",
                 "text": "method path?query body（与 features.py 一致）",
                 "decoding": "urllib.parse.unquote_plus 两次（兼容双重编码）"},
        "mined_tokens": mined,
        "rules": res_dec,
        "rules_raw": res_raw,
        "summary": {
            "n_rules": len(res_dec),
            "n_keep": sum(1 for r in res_dec if r["verdict"] == "keep"),
            "n_reject_fp": sum(1 for r in res_dec if r["verdict"] == "reject_fp"),
            "n_reject_no_hit": sum(1 for r in res_dec if r["verdict"] == "reject_no_hit"),
            "n_unverifiable_by_pool": sum(1 for r in res_dec
                                          if r["verdict"] == "unverifiable_by_pool"),
            "n_insufficient_support": sum(1 for r in res_dec
                                          if r["verdict"] == "insufficient_support"),
            "decoding_gain_total": sum(r["decoding_gain"] for r in res_dec),
            "key_finding": ("不先 URL 解码 → 规则几乎全漏（如 union_select 原文命中 0）；"
                            "M1 规则引擎必须先解码再匹配，且解码后仍要重测误报。"),
            "key_finding_2": ("评测池的**攻击覆盖面很窄**（CSIC 2010 基本只有购物车 SQLi/XSS）："
                              "`union` 在 25,213 条攻击里只出现 1 次，outfile/information_schema/"
                              "jndi 均为 0。所以 `unverifiable_by_pool` 的规则**不能当无用删掉**，"
                              "只能等真的评测数据。"),
            "note": ("只有**误报=0 且在真实攻击上有命中**的规则才建议进 M1 规则引擎；"
                     "`reject_fp` 一律不进；`unverifiable_by_pool` 挂起待数据。"
                     "误报是在真实良性文本上量的，不是估计值。"),
        },
    }
    os.makedirs(ART, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    s = report["summary"]
    print(f"\n[summary] 规则 {s['n_rules']} 条：可留 {s['n_keep']}、误报否决 {s['n_reject_fp']}、"
          f"零命中否决 {s['n_reject_no_hit']}；解码带来的总命中增益={s['decoding_gain_total']}")
    print(f"[json] -> {os.path.relpath(args.out, HERE)}   ({time.time()-t0:.1f}s)")


if __name__ == "__main__":
    main()
