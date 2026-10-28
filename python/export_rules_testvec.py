"""生成规则通道的**同源回归向量** `artifacts/rules_testvec.json`（+ `rules_selftest.json`）。

## 这个向量在防什么

门禁程序（`F:\\waf\\rust\\build.bat run --release`）会在**没有 Python** 的情况下重放这个向量。
它钉死三件事：

  1. **解码**：Rust 的解码必须逐字节等于 Python 参考实现的结果。参考实现里
     `urlencoded` 阶段用 stdlib `urllib.parse.unquote_plus`（不是我写的），
     `unicode` 阶段用另写的一份 —— 两侧独立实现一致才算过。
     特别地，`full` 的期望值是**先拼装再整体解码**（p7 口径），而 Rust 实现是**逐段解码再拼装**；
     两者必须相等（分隔符是 ASCII 空格/`?`，百分号三元组与多字节序列不可能跨过去）。
  2. **匹配**：命中的规则集合、权重之和、是否达到阻断线。
  3. **SHA-1**：Rust 自写的 `sha1_16` 必须等于 Python `hashlib.sha1(...).hexdigest()[:16]`。
     这是热重载"变没变"的判据，算错了就会误判成"没变"而永不重载。

## 生成即自检

脚本自己先用 `waf-ai-proto rules replay --dump-decoded` 跑一遍；**不一致就拒绝写文件并打印差异**。
门禁再独立重放一次。两处都过，才说明两侧同源。

用法：
    py -3.10 export_rules_testvec.py [--out artifacts/rules_testvec.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p7_rule_mining as p7  # noqa: E402

ART = os.path.join(HERE, "artifacts")
RULESET_PATH = os.path.join(ART, "rules_selftest.json")
TESTVEC_PATH = os.path.join(ART, "rules_testvec.json")

HEXD = "0123456789abcdefABCDEF"

# --------------------------------------------------------------------------- 参考解码
def py_unescape_unicode(s: str) -> str:
    """与 Rust `decode::unescape_unicode` 独立实现、语义相同。

    只解 `\\uXXXX` / `\\UXXXXXXXX`（含代理对合并），其余转义原样保留：
    做最小变换，避免把良性文本改造成看起来像攻击的样子。
    """
    if "\\u" not in s and "\\U" not in s:
        return s
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            if s[i + 1] == "u" and i + 5 < n:
                h = s[i + 2:i + 6]
                if len(h) == 4 and all(c in HEXD for c in h):
                    cp = int(h, 16)
                    i += 6
                    if (0xD800 <= cp <= 0xDBFF and i + 5 < n
                            and s[i] == "\\" and s[i + 1] == "u"):
                        lo_h = s[i + 2:i + 6]
                        if len(lo_h) == 4 and all(c in HEXD for c in lo_h):
                            lo = int(lo_h, 16)
                            if 0xDC00 <= lo <= 0xDFFF:
                                out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)))
                                i += 6
                                continue
                    # ⚠️ CPython 的 `chr()` **允许**孤立代理（会产出不可编码的 str），
                    #    而 Rust 的 `char::from_u32` 返回 None。必须显式判代理区间，
                    #    否则 `\ud83d` 会一边给 `'\ud83d'`、一边给 `'\ufffd'` 而静默不一致。
                    out.append("\ufffd" if 0xD800 <= cp <= 0xDFFF else chr(cp))
                    continue
            elif s[i + 1] == "U" and i + 9 < n:
                h = s[i + 2:i + 10]
                if len(h) == 8 and all(c in HEXD for c in h):
                    cp = int(h, 16)
                    i += 10
                    if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                        out.append("\ufffd")
                    else:
                        out.append(chr(cp))
                    continue
        out.append(s[i])
        i += 1
    return "".join(out)


def py_decode(s: str, stages=("urlencoded", "unicode")) -> str:
    from urllib.parse import unquote_plus

    t = s
    for st in stages:
        if st == "urlencoded":
            for _ in range(2):
                n = unquote_plus(t)
                if n == t:
                    break
                t = n
        elif st == "unicode":
            for _ in range(2):
                n = py_unescape_unicode(t)
                if n == t:
                    break
                t = n
    return t


def py_full_text(req: dict) -> str:
    """p7 `req_text()`：`{method} {path}?{query} {body}`（`?` 字面量、恒在）。"""
    return f"{req.get('method') or 'GET'} {req.get('path') or ''}?{req.get('query') or ''} {req.get('body') or ''}"


def py_scope_text(scope: str, req: dict) -> str:
    if scope == "full":
        return py_full_text(req)
    return req.get(scope) or ""


def py_pattern(rx: str) -> str:
    """把 DSL 正则翻译成 **Rust 等价**的 Python `re` 形式。

    只有一处差异要处理，但它是致命的：

      * **裸 `$` → `\\Z`**。Python 的 `$`（非 MULTILINE）也匹配「末尾换行之前」，
        而 Rust（regex crate）的 `$` 只匹配串尾。已经被门禁里的单测钉死：
        `rules::tests::dollar_vs_z_on_trailing_newline` 断言 `(--)$` 对 `"id=1 --\\n"`
        在 **Rust 里不命中**。既然线上权威口径是 Rust，参考实现就必须跟着 Rust 走 ——
        否则参考实现自己就是错的，会反过来冤枉正确的 Rust 实现。
      * `\\z`（DSL 的规范绝对串尾记号）→ `\\Z`（同一个词在 Python 里的写法）。

    注意这**只翻译裸 `$`**：`[$]`（字符类里）和 `\\$`（转义的字面量）原样保留。
    """
    out: list[str] = []
    i, n = 0, len(rx)
    in_class = False
    while i < n:
        c = rx[i]
        if c == "\\" and i + 1 < n:
            if rx[i + 1] == "z" and not in_class:
                out.append("\\Z")
            else:
                out.append(c)
                out.append(rx[i + 1])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            # 类首的 `^` 是取反，类首的 `]` 是字面量，都得原样吃进去
            if i < n and rx[i] == "^":
                out.append("^")
                i += 1
            if i < n and rx[i] == "]":
                out.append("]")
                i += 1
            continue
        if c == "$":
            out.append("\\Z")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _decode_scope(scope: str, req: dict, stages) -> str:
    """参考实现：**先取作用域文本，再整体解码**。

    `full` 取拼装串（p7 口径）；其余取单字段。Rust 侧是**逐段解码再拼装** ——
    参考实现刻意用「先拼装再解码」，这样门禁就是在验证两者的等价性，而不是同义反复。
    """
    return py_decode(py_scope_text(scope, req), stages)


# --------------------------------------------------------------------------- 规则集
def build_ruleset() -> dict:
    """自检规则集：21 条挖出的真规则 + 几条专门压边界的合成规则。

    ⚠️ 合成规则**只存在于门禁向量里**，不进现役规则集（不进 `rules_authoritative.json`）。
    """
    rules = []
    for name, pat in p7.RULES.items():
        rules.append({"id": name, "name": name, "regex": pat, "scopes": ["full"],
                      "severity": "medium", "weight": 1.0, "action": "alert",
                      "source": "mined"})
    rules += [
        # scope 收窄到单字段：验证字段边界与 `field` 归属
        {"id": "selftest_query_scope", "name": "SELECT 只在 query 里算",
         "regex": r"(?i)\bselect\b", "scopes": ["query"], "severity": "low",
         "weight": 1.0, "action": "alert", "source": "synthetic"},
        {"id": "selftest_body_scope", "name": "<script 只在 body 里算",
         "regex": r"(?i)<script", "scopes": ["body"], "severity": "low",
         "weight": 0.5, "action": "alert", "source": "synthetic"},
        {"id": "selftest_ua_scope", "name": "UA 里的 sqlmap",
         "regex": r"(?i)\bsqlmap\b", "scopes": ["ua"], "severity": "low",
         "weight": 1.0, "action": "alert", "source": "synthetic"},
        {"id": "selftest_referer_scope", "name": "referer 里的 evil",
         "regex": r"(?i)\bevil\b", "scopes": ["referer"], "severity": "low",
         "weight": 1.0, "action": "alert", "source": "synthetic"},
        # `\z`（DSL 的规范绝对串尾；Rust 原生、Python 翻译成 \Z）
        {"id": "selftest_z_anchor", "name": "串尾 exec",
         "regex": r"(?i)\bexec\b\z", "scopes": ["body"], "severity": "low",
         "weight": 1.0, "action": "alert", "source": "synthetic"},
        # 双重编码：%2575nion → %75nion → union
        {"id": "selftest_double_encoded", "name": "双重编码的 union",
         "regex": r"(?i)\bunion\b", "scopes": ["query"], "severity": "low",
         "weight": 1.0, "action": "alert", "source": "synthetic"},
        # 加权 + 阻断线：两条各 0.6，凑够 1.0 才 block
        {"id": "selftest_block_a", "name": "加权 A",
         "regex": r"(?i)zzzblocka", "scopes": ["full"], "severity": "high",
         "weight": 0.6, "action": "block", "source": "synthetic"},
        {"id": "selftest_block_b", "name": "加权 B",
         "regex": r"(?i)zzzblockb", "scopes": ["full"], "severity": "high",
         "weight": 0.6, "action": "block", "source": "synthetic"},
        # 权重极大但 action=alert：**绝不能**阻断。钉死"只有 block 规则消耗阻断预算"
        # —— 否则"新规则先设 alert 观察"就是个摆设，用户永远不敢用。
        {"id": "selftest_loud_alert", "name": "大声的告警（权重 9.0，只告警）",
         "regex": r"(?i)zzzloud", "scopes": ["full"], "severity": "high",
         "weight": 9.0, "action": "alert", "source": "synthetic"},
    ]
    return {
        "schema": 1,
        "ruleset_id": "selftest-ruleset",
        "decode": ["urlencoded", "unicode"],
        "min_weight_to_block": 1.0,
        "rules": rules,
    }


# --------------------------------------------------------------------------- 用例
def real_cases(srcs: dict, per_src: int = 6) -> list:
    """从真实池里**确定性地**取样（步长取样，不用随机：向量必须可复现）。"""
    out = []
    for name in sorted(srcs):
        rows = srcs[name]
        if not rows:
            continue
        step = max(1, len(rows) // per_src)
        for j, r in enumerate(rows[::step][:per_src]):
            out.append({
                "id": f"real-{name}-{j}",
                "why": f"真实池 {name} 的第 {j} 个步长样本（覆盖真实的编码/长度分布）",
                "req": {
                    "method": r.get("method") or "GET",
                    "path": r.get("path") or "",
                    "query": r.get("query") or "",
                    "body": r.get("body") or "",
                    "ua": r.get("ua") or "",
                    "referer": r.get("referer") or "",
                },
            })
    return out


def edge_cases() -> list:
    """手写边界用例。每一条都对应一类**曾经会静默出错**的地方。"""
    def c(cid, why, **req):
        base = {"method": "GET", "path": "/a", "query": "", "body": "",
                "ua": "", "referer": ""}
        base.update(req)
        return {"id": cid, "why": why, "req": base}

    return [
        c("edge-empty", "全空请求：`full` = `GET /a? `（`?` 恒在，不能省略；尾部空格也是文本的一部分）"),
        c("edge-query-only", "只有 query", method="GET", path="/x", query="a=1"),
        c("edge-percent-tail", "`%` 结尾（非法转义必须原样保留，不能吞掉）",
          query="a=%"),
        c("edge-percent-badhex", "`%2z`：第二位不是十六进制 → 整段原样",
          query="a=%2zb"),
        c("edge-percent-double", "`%%41` → `%A`（CPython 的 split 语义，Rust 必须逐字节一致）",
          query="a=%%41"),
        c("edge-plus", "`+` → 空格（表单编码语义）", query="a=1+2"),
        c("edge-double-encoded", "双重编码 %2575nion → union（解码要跑两遍）",
          query="q=%2575nion%2520select"),
        c("edge-unicode-json", "json body 里的 \\\\u003c → <（unicode 阶段）",
          method="POST", path="/api", body='{"x":"\\u003cscript\\u003ealert(1)"}'),
        c("edge-unicode-upper", "\\\\U0001F600（8 位大写 U）", body="\\U0001F600"),
        c("edge-unicode-lone", "落单代理 \\\\ud83d → U+FFFD（不能崩）", body="\\ud83d"),
        c("edge-unicode-pair", "代理对 \\\\ud83d\\\\ude00 → 😀", body="\\ud83d\\ude00"),
        c("edge-unicode-badhex", "\\\\uZZZZ 非法 → 原样保留", body="\\uZZZZ"),
        c("edge-keep-newline", "**body 以换行结尾**：`$` 与 `\\z` 在这里分道扬镳 —— "
          "参考实现把裸 `$` 翻译成 `\\Z` 才与 Rust 一致（见 py_pattern 的注释）",
          body="id=1 --\n"),
        c("edge-comment-tail-nonl", "body 末尾 `--`（不带换行）", body="id=1 --"),
        c("edge-comment-tail-decoded", "`%2D%2D` 解码成 `--` 后才命中；"
          "且 `full` 末尾的拼装空格要吃进 `\\s*`", query="a=1%2D%2D"),
        c("edge-z-anchor-hit", "`\\z` 锚点命中", body="run exec"),
        c("edge-z-anchor-miss", "`\\z` 锚点不命中（exec 后还有内容）", body="run exec now"),
        c("edge-scope-query", "SELECT 只在 query 命中（scope 收窄生效）", query="q=select"),
        c("edge-scope-body-xss", "<script 只在 body 命中", body="<script>"),
        c("edge-scope-ua", "UA 命中给 field=ua", ua="sqlmap/1.7.2#stable"),
        c("edge-scope-referer", "referer 命中给 field=referer", referer="https://evil.example/x"),
        c("edge-block-partial", "只有一条 block 规则命中（0.6 < 1.0 ⇒ 不阻断）",
          query="zzzblocka"),
        c("edge-block-full", "两条 block 规则都命中（1.2 >= 1.0 ⇒ 阻断）",
          query="zzzblocka", body="zzzblockb"),
        c("edge-loud-alert", "**权重 9.0 但 action=alert ⇒ 绝不阻断**"
          "（weight=9.0 / block_weight=0.0，旧口径会误判成 block）",
          query="zzzloud"),
        c("edge-loud-alert-plus-block", "alert 的大权重 + 一条 block（0.6 < 1.0）⇒ 仍不阻断",
          query="zzzloud", body="zzzblocka"),
        c("edge-nonascii", "非 ASCII 不被破坏", query="q=中文", body="身体"),
        c("edge-js-uri", "xss_js_uri 解码后命中", query="url=javascript%3Aalert(1)"),
        c("edge-path-sensitive", "path_sensitive_file 命中", path="/.env"),
        c("edge-tautology", "sqli_tautology 命中", query="id=1%20or%20'a'='a'"),
    ]


# --------------------------------------------------------------------------- 主流程
def ref_expectations(ruleset: dict, cases: list) -> list:
    """用 Python 参考实现算每个用例的期望值。

    匹配发生在**解码后**的文本上（这是规则通道存在的意义：`union_select` 在未解码的
    25,213 条真实攻击上命中 0）。`full` 用「先拼装再解码」，Rust 用「逐段解码再拼装」，
    参考实现刻意选前者 —— 门禁因此在验证两者的等价性，而不是同义反复。
    """
    stages = tuple(ruleset.get("decode") or ())
    compiled = []
    for r in ruleset["rules"]:
        scopes = r.get("scopes") or ["full"]
        compiled.append((r["id"], float(r.get("weight", 1.0)),
                         r.get("action") or "alert",
                         [(s, re.compile(py_pattern(r["regex"]))) for s in scopes]))

    out = []
    for cs in cases:
        req = cs["req"]
        hits = []
        for rid, w, action, scopes in compiled:
            for scope, rx in scopes:
                if rx.search(_decode_scope(scope, req, stages)):
                    hits.append({"rule": rid, "scope": scope, "action": action, "weight": w})
                    break  # 每个 (规则, 作用域) 最多一个命中；一条规则只算一次权重
        uniq: dict = {}
        for h in hits:
            uniq.setdefault(h["rule"], h)
        w_all = sum(h["weight"] for h in uniq.values())
        # 只有 `action=block` 的规则消耗**阻断预算**（与 Rust `block_weight_of` 同义）
        w_block = sum(h["weight"] for h in uniq.values() if h["action"] == "block")
        out.append({
            **cs,
            "decoded": {k: _decode_scope(k, req, stages)
                        for k in ("full", "path", "query", "body", "ua", "referer")},
            "hits": sorted(uniq.keys()),
            "hit_detail": sorted(
                [{"rule": h["rule"], "scope": h["scope"],
                  # 单字段作用域下，Rust 报的 `field` 必须正好等于作用域名
                  "expect_field": None if h["scope"] == "full" else h["scope"]}
                 for h in uniq.values()],
                key=lambda d: d["rule"],
            ),
            "weight": round(w_all, 6),
            "block_weight": round(w_block, 6),
            "block": w_block + 1e-9 >= float(ruleset["min_weight_to_block"]),
        })
    return out


def rust_replay(ruleset_path: str, cases: list, tmpdir: str) -> dict:
    from service import toolchain

    corpus = os.path.join(tmpdir, "cases.jsonl")
    with open(corpus, "w", encoding="utf-8") as f:
        for cs in cases:
            f.write(json.dumps({"id": cs["id"], "pool": "-", **cs["req"]},
                               ensure_ascii=False) + "\n")
    out_path = os.path.join(tmpdir, "cases_out.jsonl")
    p = toolchain.run_proto(["rules", "replay", "--rules", ruleset_path, "--in", corpus,
                             "--out", out_path, "--dump-decoded", "--meta"], timeout=600)
    if p.returncode != 0:
        raise SystemExit("rules replay 失败：\n" + (p.stdout or "") + (p.stderr or ""))
    print("   " + (p.stderr or "").strip().splitlines()[-1])
    res = {"meta": None, "by_id": {}}
    with open(out_path, "r", encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            if "_meta" in o:
                res["meta"] = o["_meta"]
                continue
            res["by_id"][o["id"]] = o
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=TESTVEC_PATH)
    ap.add_argument("--ruleset-out", default=RULESET_PATH)
    ap.add_argument("--per-source", type=int, default=6)
    args = ap.parse_args()

    t0 = time.time()
    os.makedirs(ART, exist_ok=True)

    ruleset = build_ruleset()
    with open(args.ruleset_out, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, ensure_ascii=False, indent=1)
    raw = open(args.ruleset_out, "rb").read()
    sha = hashlib.sha1(raw).hexdigest()[:16]
    print(f"[testvec] 规则集 {args.ruleset_out}（{len(ruleset['rules'])} 条）sha1_16={sha}")

    import calibrate_rules as cal

    srcs = cal.build_sources(need_attack=True)
    cases = real_cases(srcs, per_src=args.per_source) + edge_cases()
    print(f"[testvec] 用例 {len(cases)} 条（真实 {len(cases) - len(edge_cases())} + 边界 {len(edge_cases())}）")

    expect = ref_expectations(ruleset, cases)

    tmpdir = tempfile.mkdtemp(prefix="waf_rules_tv_")
    print("[testvec] Rust 重放（生成即自检）...")
    got = rust_replay(args.ruleset_out, cases, tmpdir)

    # ---- 逐项比对 ----
    fails = []
    if got["meta"] is None:
        fails.append("Rust 未输出 _meta")
    else:
        if got["meta"].get("sha1_16") != sha:
            fails.append(f"SHA-1 不一致：rust={got['meta'].get('sha1_16')} python={sha}")
    for e in expect:
        g = got["by_id"].get(e["id"])
        if g is None:
            fails.append(f"{e['id']}: Rust 没有输出这一行")
            continue
        for field in ("full", "path", "query", "body", "ua", "referer"):
            a, b = (g.get("decoded") or {}).get(field), e["decoded"][field]
            if a != b:
                fails.append(f"{e['id']}: decoded.{field} 不一致\n    rust  ={a!r}\n    python={b!r}")
        gh = sorted(h["rule"] for h in (g.get("hits") or []))
        if gh != e["hits"]:
            fails.append(f"{e['id']}: 命中不一致\n    rust  ={gh}\n    python={e['hits']}")
        # 单字段作用域下 `field` 必须等于作用域名（回映射偏移不能张冠李戴）
        gfield = {h["rule"]: h.get("field") for h in (g.get("hits") or [])}
        for d in e["hit_detail"]:
            if d["expect_field"] and gfield.get(d["rule"]) != d["expect_field"]:
                fails.append(f"{e['id']}: {d['rule']} 的 field 不一致 "
                             f"rust={gfield.get(d['rule'])!r} python={d['expect_field']!r}")
        if abs(float(g.get("weight") or 0.0) - e["weight"]) > 1e-6:
            fails.append(f"{e['id']}: weight 不一致 rust={g.get('weight')} python={e['weight']}")
        if abs(float(g.get("block_weight") or 0.0) - e["block_weight"]) > 1e-6:
            fails.append(f"{e['id']}: block_weight 不一致 "
                         f"rust={g.get('block_weight')} python={e['block_weight']}")
        if bool(g.get("block")) != bool(e["block"]):
            fails.append(f"{e['id']}: block 不一致 rust={g.get('block')} python={e['block']}")

    if fails:
        print(f"\n[testvec] ✗ 不一致 {len(fails)} 处，**拒绝写出向量**（写出去的门禁向量必须是可信的）：")
        for m in fails[:30]:
            print("  - " + m)
        raise SystemExit(1)

    n_hits = sum(1 for e in expect if e["hits"])
    n_block = sum(1 for e in expect if e["block"])
    doc = {
        "schema": 1,
        "generated_at": int(time.time() * 1000),
        "generator": "python/export_rules_testvec.py",
        "ruleset_path": os.path.relpath(args.ruleset_out, HERE).replace("\\", "/"),
        "ruleset_sha1_16": sha,
        "ruleset_id": ruleset["ruleset_id"],
        "n_rules": len(ruleset["rules"]),
        "n_cases": len(expect),
        "n_cases_with_hits": n_hits,
        "n_cases_block": n_block,
        "min_weight_to_block": ruleset["min_weight_to_block"],
        "decode": ruleset["decode"],
        "why": ("两侧同源回归向量：Rust 门禁在没有 Python 的情况下重放它，"
                "钉死解码（含双重编码 / \\uXXXX / 代理对 / 孤立代理 / 非法转义）、"
                "作用域字段归属、加权记分、**只有 block 规则消耗阻断预算**、阻断线，"
                "以及二进制的自写 SHA-1。"),
        "notes": [
            "匹配发生在**解码后**文本上；`full` = `METHOD path?query body`（`?` 字面量恒在）。",
            "参考实现用「先拼装再整体解码」，Rust 用「逐段解码再拼装」—— 本向量即二者等价的证据。",
            "裸 `$` 在 Python 里能匹配末尾换行之前、在 Rust 里不能；参考实现把裸 `$` 翻译成 `\\Z` 以对齐 Rust。",
            "`weight` = 全部命中（证据）；`block_weight` = 仅 action=block 的命中（阻断预算）。",
        ],
        "cases": expect,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)
    print(f"[testvec] ✓ Rust 与 Python 参考实现**逐字节一致**"
          f"（解码 ×{len(expect)}×6 字段、命中、权重、阻断线、SHA-1）")
    print(f"[testvec] 用例 {len(expect)}：有命中 {n_hits}，达阻断线 {n_block}；"
          f"规则 {len(ruleset['rules'])}（挖出 {len(p7.RULES)} + 合成 "
          f"{len(ruleset['rules']) - len(p7.RULES)}）")
    print(f"[testvec] 向量 -> {args.out}    用时 {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
