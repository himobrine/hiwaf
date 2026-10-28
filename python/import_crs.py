"""把 OWASP CRS 的 ModSecurity 规则**保守地**导入为本项目的自撰规则（草稿）。

## 为什么是"保守地"

CRS 跑在 ModSecurity 上，它的语义由三部分组成：**变量选择 + `t:` 变换链 + 操作符**。
我们的规则通道只有一条固定的解码管线（`urlencoded`×2 + `unicode`）和一套固定 scope，
**没有** `t:` 变换链，也不支持 `TX:` 变量、链式规则、`@detectSQLi/@detectXSS` 这类
"内置检测器"操作符。硬翻译会得到**看起来一样、实际不一样**的规则 —— 那是本项目
最不能接受的状态（误报/漏报都查不出来源）。

所以这里只收**语义可以证明等价**的那一小撮：

* 单条（非 `chain`）`SecRule`；
* 操作符是 `@rx`（或省略 `@` 的隐式 rx）；
* 变量能一对一映射到我们的 `scope`（`ARGS`/`REQUEST_URI`/UA/Referer/body…）；
* `t:` 只允许 `none` / `urlDecodeUni` / `lowercase`（后者翻译成 `(?i)`）；
* 正则里不含 PCRE 独有构造（lookaround / 反向引用 / 原子组 / 占有量词 / `\\Q..\\E`）。

其余**一律跳过并计数**，跳过原因写进报告。跳过不是失败：把不认识的规则硬塞进来，
才是。

## 导入之后仍然**不是**"启用"

写入 DB 的每一条都是：`action=alert`、`enabled=0`、`validated_at=NULL`（草稿）。
必须逐条过三关（Rust 编译 / 真实良性回放零误报 / 攻击回放命中 > 0），再由人打开开关。
**本脚本永远不会**启用规则、永远不会写现役规则集。

## 许可

OWASP CRS 是 Apache-2.0。见仓库根目录 `THIRD_PARTY_NOTICES.md`。
本脚本不复制 CRS 的文本字段（`msg`/`tag`/`logdata`），只保留 `id` 与 `msg` 的截断
副本用于追溯，并在报告里记录来源版本 —— Apache-2.0 §4(b) 的"声明修改"义务。

## 用法

    # 只解析、出报告（不写 DB）
    py -3.10 import_crs.py --src D:\\coreruleset-4.29.0\\rules

    # 解析并写入草稿规则
    py -3.10 import_crs.py --src ... --write-db

    # 只跑解析器自检（不需要 CRS 检出）
    py -3.10 import_crs.py --self-test
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

CRS_LICENSE = "Apache-2.0"

# 只导入"请求侧"规则文件（REQUEST-9xx）。响应侧（RESPONSE-95x）与 setup 不导入：
# 我们只采集入站请求，导响应规则进来只会制造永远不会命中的噪声。
REQUEST_FILE_RE = re.compile(r"REQUEST-9\d\d-.*\.conf$", re.I)

# --------------------------------------------------------------------------- 变量映射
# ModSecurity 变量 -> 我们的 scope 列表（多条按 OR 处理，正好对应"多个 scope 各评一次"）。
VAR_SCOPES = {
    "REQUEST_URI": ["path", "query"],
    "REQUEST_URI_RAW": ["path", "query"],
    "REQUEST_FILENAME": ["path"],
    "REQUEST_BASENAME": ["path"],
    "ARGS": ["query", "body"],
    "ARGS_GET": ["query"],
    "ARGS_POST": ["body"],
    "REQUEST_BODY": ["body"],
    "REQUEST_HEADERS:USER-AGENT": ["ua"],
    "REQUEST_HEADERS:REFERER": ["referer"],
}

# 允许的变换：能由我们的固定解码管线 + `(?i)` 等价复现的。
ALLOWED_TRANSFORMS = {"none", "urldecodeuni", "lowercase"}

# PCRE 独有 / Rust `regex` 不支持的构造 —— 命中任一就跳过（不要试图"修一下"）。
PCRE_ONLY = (
    "(?=", "(?!", "(?<=", "(?<!", "(?>", "(?#", "(?P=", "(?(", "(?R", "(?&",
    "\\Q", "\\E", "\\G", "\\K", "\\R", "\\X", "\\C",
    "*+", "++", "?+", "*+?", "\\k<", "\\k'",
    "[[:<:]]", "[[:>:]]",
)
_BACKREF_RE = re.compile(r"\\[1-9]")

SEVERITY_MAP = {
    "CRITICAL": ("critical", 5.0),
    "ERROR": ("high", 4.0),
    "WARNING": ("medium", 3.0),
    "NOTICE": ("low", 2.0),
}

MAX_REGEX_LEN = 400          # 与 rules_dsl.MAX_REGEX_LEN 对齐
MAX_NAME_LEN = 60            # 与 rules_dsl.MAX_NAME_LEN 对齐
MAX_RULES = 200              # 与 rules_dsl.MAX_RULES 对齐


# --------------------------------------------------------------------------- 解析原语
def split_logical_lines(text: str) -> List[str]:
    """把 `\\` 续行拼成逻辑行，丢掉注释与空行。"""
    out: List[str] = []
    buf: List[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        s = line.rstrip()
        if s.endswith("\\"):
            buf.append(s[:-1])
            continue
        buf.append(s)
        out.append(" ".join(x.strip() for x in buf).strip())
        buf = []
    if buf:
        out.append(" ".join(x.strip() for x in buf).strip())
    return out


def read_quoted(s: str, i: int) -> Tuple[str, int]:
    """从 `s[i]` 读一个双引号串。返回 (内容, 下一个下标)。

    只解 **`\\"` 和 `\\\\`** 两种字符串层转义；其余反斜杠原样保留 —— 它们是正则的
    一部分（`\\s` / `\\(` / `\\d`）。早期版本把所有 `\\x` 都吞成 `x`，于是
    `sleep\\s*\\(` 变成 `sleeps*(`：绝大多数规则会"导入成功但匹配的东西不一样"，
    只有个别因为括号不配平而报错。这是最坏的一类 bug —— 静默改变检测语义。
    """
    if i >= len(s) or s[i] != '"':
        raise ValueError("期望以双引号开始的串")
    i += 1
    buf: List[str] = []
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == '"' or nxt == "\\":
                buf.append(nxt)          # 字符串层转义：吃掉反斜杠
            else:
                buf.append("\\")         # 正则层转义：原样保留
                buf.append(nxt)
            i += 2
            continue
        if c == '"':
            return "".join(buf), i + 1
        buf.append(c)
        i += 1
    raise ValueError("双引号串未闭合")


def unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1].replace("\\" + v[0], v[0])
    return v


def parse_actions(s: str) -> Dict[str, List[str]]:
    """按逗号切 action 列表，尊重单/双引号。同名 action 收集成列表。"""
    items: List[str] = []
    buf: List[str] = []
    q: Optional[str] = None
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and i + 1 < len(s):
                buf.append(c)
                buf.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
            buf.append(c)
            i += 1
            continue
        if c in "'\"":
            q = c
            buf.append(c)
            i += 1
            continue
        if c == ",":
            items.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        items.append("".join(buf).strip())
    out: Dict[str, List[str]] = {}
    for it in items:
        if not it:
            continue
        if ":" in it:
            k, v = it.split(":", 1)
            out.setdefault(k.strip().lower(), []).append(v.strip())
        else:
            out.setdefault(it.strip().lower(), []).append("")
    return out


def parse_secrule(line: str) -> Optional[Tuple[str, str, str]]:
    """拆 `SecRule <vars> "<op>" "<actions>"`。不是 SecRule 就返回 None。"""
    m = re.match(r"SecRule\s+", line, re.I)
    if not m:
        return None
    rest = line[m.end():]
    mv = re.match(r"(\S+)\s+", rest)
    if not mv:
        raise ValueError("缺变量")
    variables = mv.group(1)
    op, i = read_quoted(rest, mv.end())
    while i < len(rest) and rest[i].isspace():
        i += 1
    if i >= len(rest):
        # 没有 actions：ModSecurity 会套 SecDefaultAction，我们看不见 ⇒ 不可证明等价
        raise ValueError("缺 actions（依赖 SecDefaultAction，无法证明等价）")
    actions, _ = read_quoted(rest, i)
    return variables, op, actions


# --------------------------------------------------------------------------- 正则翻译
def translate_rx(pat: str, *, lowercase: bool) -> Tuple[Optional[str], Optional[str]]:
    """把一条 CRS `@rx` 翻成我们的 DSL。返回 (regex, skip_reason)。"""
    for bad in PCRE_ONLY:
        if bad in pat:
            return None, f"pcre_only:{bad}"
    if _BACKREF_RE.search(pat):
        return None, "pcre_only:backref"
    if len(pat) > MAX_REGEX_LEN:
        return None, f"regex_too_long:{len(pat)}"

    # `\/` 在 PCRE 里就是 `/`；Rust 虽然也接受，但统一去掉以减少歧义。
    pat = pat.replace("\\/", "/")

    # 串尾锚点：PCRE 的 `$` ≈ 我们的 `\z`（DSL 规范：`$` 只警告，`\z` 才保证串尾）。
    # 字符类里的 `$` 是字面量，必须原样保留。
    out: List[str] = []
    i = 0
    in_class = False
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat):
            out.append(pat[i:i + 2])
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
            continue
        if c == "$":
            out.append("\\z")
            i += 1
            continue
        out.append(c)
        i += 1
    rx = "".join(out)
    if lowercase and "(?i)" not in rx:
        rx = "(?i)" + rx
    return rx, None


def map_variables(variables: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """ModSecurity 变量列表 -> 我们的 scope 列表。"""
    if not variables:
        return None, "no_variables"
    if "!" in variables:
        return None, "negated_variable"
    if "&" in variables:
        return None, "counter_variable"
    raw = [v.strip().upper() for v in re.split(r"[,|]", variables) if v.strip()]
    if not raw:
        return None, "no_variables"
    scopes: List[str] = []
    for v in raw:
        if v.startswith("TX:") or v.startswith("IP:"):
            return None, "tx_variable"
        if v not in VAR_SCOPES:
            return None, f"unsupported_variable:{v}"
        for s in VAR_SCOPES[v]:
            if s not in scopes:
                scopes.append(s)
    # 保持稳定顺序，便于对比
    order = ["full", "path", "query", "body", "ua", "referer"]
    return sorted(scopes, key=order.index), None


def convert_one(variables: str, op: str, actions: str) -> Tuple[Optional[dict], Optional[str]]:
    """单条 SecRule -> 我们的规则 dict；不可等价则返回跳过原因。"""
    acts = parse_actions(actions)

    if "chain" in acts:
        return None, "chain"

    op_s = op.strip()
    if not op_s.startswith("@"):
        # ModSecurity：不带 `@` 就是隐式 `@rx`
        op_s = "@rx " + op_s
    mop = re.match(r"@(\w+)\s*(.*)$", op_s, re.S)
    if not mop:
        return None, "bad_operator"
    opname, pat = mop.group(1).lower(), mop.group(2)
    if opname != "rx":
        return None, f"operator:@{opname}"

    # paranoia-level：默认只收 PL1（CRS 的"默认安全档"）。PL2+ 误报明显更高，
    # 而我们的良性池还不足以给它们定预算。
    pl_raw = (acts.get("paranoia-level") or [""])[0]
    if pl_raw:
        try:
            if int(pl_raw) > 1:
                return None, f"paranoia_level:{pl_raw}"
        except ValueError:
            pass

    transforms = [unquote(x).strip().lower() for x in (acts.get("t") or [])]
    bad_t = [t for t in transforms if t not in ALLOWED_TRANSFORMS]
    if bad_t:
        return None, f"transform:{bad_t[0]}"

    rid = unquote((acts.get("id") or [""])[0])
    if not rid:
        return None, "no_id"
    msg = unquote((acts.get("msg") or [""])[0]) or f"CRS {rid}"
    sev_raw = unquote((acts.get("severity") or [""])[0]).upper()
    severity, weight = SEVERITY_MAP.get(sev_raw, ("medium", 3.0))

    scopes, why = map_variables(variables)
    if scopes is None:
        return None, why or "variables"

    rx, why = translate_rx(pat, lowercase=("lowercase" in transforms))
    if rx is None:
        return None, why or "regex"

    rid_clean = re.sub(r"[^a-z0-9_]", "_", f"crs_{rid}".lower())
    return {
        "id": rid_clean[:40],
        "name": msg[:MAX_NAME_LEN],
        "regex": rx,
        "scopes": scopes,
        "severity": severity,
        "weight": weight,
        # 导入的规则**一律**是 alert：变成 block 必须逐条人工决定（并消耗阻断预算）。
        "action": "alert",
        "notes": (f"OWASP CRS id={rid} severity={sev_raw or '?'} "
                  f"t={','.join(transforms) or 'none'} vars={variables}"),
        "crs_id": rid,
    }, None


# --------------------------------------------------------------------------- 主流程
def _bump(report: Dict[str, Any], key: str) -> None:
    report["skip_reasons"][key] = report["skip_reasons"].get(key, 0) + 1


def _consume(lines: List[str], report: Dict[str, Any],
             fstat: Optional[Dict[str, int]] = None) -> None:
    """逐逻辑行解析。`chain` 的**后续条件**必须一起跳过 —— 它们是同一条规则的
    后续 AND 条件，单独导入会变成"只匹配后半段"的规则，语义完全变了。"""
    seen: set = set()
    chained = False
    for line in lines:
        if fstat is not None:
            fstat["logical_lines"] += 1
        report["totals"]["logical_lines"] += 1
        try:
            parsed = parse_secrule(line)
        except ValueError as e:
            report["totals"]["parse_errors"] += 1
            _bump(report, f"parse:{e}")
            continue
        if parsed is None:
            continue
        report["totals"]["secrules"] += 1
        if fstat is not None:
            fstat["secrules"] += 1

        is_chain = "chain" in parse_actions(parsed[2])
        if chained:
            # 上一条开了 chain ⇒ 这一条是它的后续条件，不是独立规则。
            report["totals"]["skipped"] += 1
            if fstat is not None:
                fstat["skipped"] += 1
            _bump(report, "chain_continuation")
            chained = is_chain
            continue

        rule, why = convert_one(*parsed)
        chained = is_chain
        if rule is None:
            report["totals"]["skipped"] += 1
            if fstat is not None:
                fstat["skipped"] += 1
            _bump(report, why or "unknown")
            continue
        if rule["id"] in seen:
            report["totals"]["skipped"] += 1
            if fstat is not None:
                fstat["skipped"] += 1
            _bump(report, "duplicate_id")
            continue
        seen.add(rule["id"])
        if len(report["rules"]) >= MAX_RULES:
            report["totals"]["skipped"] += 1
            if fstat is not None:
                fstat["skipped"] += 1
            _bump(report, "max_rules_cap")
            continue
        report["rules"].append(rule)
        report["totals"]["imported"] += 1
        if fstat is not None:
            fstat["imported"] += 1


def import_dir(src: str) -> Dict[str, Any]:
    files: List[str] = []
    if os.path.isdir(src):
        for p in sorted(glob.glob(os.path.join(src, "*.conf"))):
            if REQUEST_FILE_RE.search(os.path.basename(p)):
                files.append(p)
    else:
        files = [src]

    report: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": os.path.abspath(src),
        "license": CRS_LICENSE,
        "totals": {"files": len(files), "logical_lines": 0, "secrules": 0,
                   "imported": 0, "skipped": 0, "parse_errors": 0},
        "skip_reasons": {},
        "files": {},
        "rules": [],
        "notes": [
            "只导入 REQUEST-9xx（入站请求）里的单条 @rx 规则；其余一律跳过并计数。",
            "导入的规则 action 恒为 alert、enabled=0、validated_at=NULL：必须逐条过三关后人工启用。",
            "CRS 的 anomaly score 记账（tx.*）不复现：每条规则的 weight 只保留相对严重度，"
            "block 的阻断线建议按 CRS 语义设为 5（critical=5/error=4/warning=3/notice=2）。",
            "`t:` 变换链只支持 none/urlDecodeUni/lowercase —— 我们的解码管线是固定的。",
        ],
    }

    for path in files:
        base = os.path.basename(path)
        fstat = {"logical_lines": 0, "secrules": 0, "imported": 0, "skipped": 0}
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
        except OSError as e:
            report["files"][base] = {"error": str(e)}
            continue
        _consume(split_logical_lines(text), report, fstat)
        report["files"][base] = fstat

    report["totals"]["importable"] = len(report["rules"])
    return report


def final_id(rid: str) -> str:
    """与 `rules_mod.create_custom` 的命名规则保持一致。

    payload 里的 id 是 `crs_900001`，落库后是 `custom_crs_900001`。幂等判断必须比
    **落库后的** id，否则第二次导入会全部撞唯一约束而当成"失败"。
    """
    rid = str(rid or "").strip().lower()
    return rid if rid.startswith("custom_") else "custom_" + rid


def write_db(rules: List[dict], *, actor: str = "crs-import", limit: Optional[int] = None) -> Dict[str, Any]:
    """把导入的规则写成**草稿**（不启用、不提升）。"""
    from service import rules as rules_mod
    from service import db

    existing = {final_id(r["id"]) for r in rules_mod.custom_rows()}
    st = {"inserted": 0, "skipped_existing": 0, "failed": 0, "errors": [],
          "ids": []}
    for r in rules:
        if limit is not None and st["inserted"] >= limit:
            break
        fid = final_id(r["id"])
        if fid in existing:
            st["skipped_existing"] += 1
            r["db_id"] = fid
            continue
        try:
            payload = dict(r)
            payload["id"] = fid          # 直接用最终 id，避免 create_custom 再改一次
            out = rules_mod.create_custom(payload, actor)
            rid = out["rule"]["id"]
            # `create_custom` 按自撰规则口径把 source 固定成 manual；这里补回出处，
            # 让"提升/审计"能看出这条是 CRS 来的（Apache-2.0 §4(b) 的修改声明）。
            db.execute("UPDATE rules_custom SET source='crs' WHERE id=?", (rid,))
            existing.add(rid)
            r["db_id"] = rid
            st["inserted"] += 1
            st["ids"].append(rid)
        except Exception as e:
            st["failed"] += 1
            if len(st["errors"]) < 20:
                st["errors"].append(f"{r['id']}: {e}")
    return st


# --------------------------------------------------------------------------- 自检
SELF_TEST_SNIPPETS = r"""
# 1) 简单 rx + lowercase -> 导入，加 (?i) 前缀（模式本身没有内联 flag）
SecRule ARGS "@rx union\s+select" \
    "id:900001,phase:2,block,capture,t:urlDecodeUni,t:lowercase,\
    msg:'SQL Injection: union select',severity:'CRITICAL',tag:'attack-sqli'"

# 2) 串尾 $ -> \z；UA 变量
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap/1\.\d+$" \
    "id:900002,phase:1,block,t:none,msg:'Scanner UA',severity:'WARNING'"

# 3) chain -> 跳过
SecRule ARGS "@rx foo" "id:900003,phase:2,block,chain,msg:'chained'"
SecRule ARGS "@rx bar" "id:900004,phase:2,block,msg:'chained second'"

# 4) @detectSQLi -> 跳过
SecRule ARGS "@detectSQLi" "id:900005,phase:2,block,msg:'libinjection'"

# 5) lookahead -> 跳过
SecRule ARGS "@rx (?=SELECT)" "id:900006,phase:2,block,msg:'lookahead'"

# 6) 不支持的变换 htmlEntityDecode -> 跳过（我们不做实体解码）
SecRule ARGS "@rx &lt;script" \
    "id:900007,phase:2,block,t:htmlEntityDecode,msg:'entity'"

# 7) 不支持的变量 REQUEST_COOKIES -> 跳过
SecRule REQUEST_COOKIES:"session" "@rx abc" "id:900008,phase:3,block,msg:'cookie'"

# 8) 隐式 @rx（不带 @）+ ARGS -> query/body
SecRule ARGS "sleep\s*\(\s*\d+" "id:900009,phase:2,block,t:none,msg:'time delay'"

# 9) 字符类里的 $ 保持字面量
SecRule ARGS "@rx [a$]{2}" "id:900010,phase:2,block,t:none,msg:'literal dollar'"

# 10) 模板注入的 TX 变量 -> 跳过
SecRule TX:sql_injection_score "@gt 5" "id:900011,phase:2,block,msg:'tx'"

# 11) REQUEST_FILENAME -> path only
SecRule REQUEST_FILENAME "@rx /\.git/" "id:900012,phase:1,block,t:none,msg:'git dir'"

# 12) 模式自带 (?i) -> 不能再叠一层前缀
SecRule ARGS "@rx (?i)select\s+.*\s+from" \
    "id:900013,phase:2,block,t:lowercase,msg:'inline flag'"
"""


def self_test() -> Tuple[int, Dict[str, Any]]:
    """解析器自检。**这不是标定数据**，只是喂给解析器的输入。"""
    rep = import_dir_from_text(SELF_TEST_SNIPPETS)
    got = {r["crs_id"]: r for r in rep["rules"]}
    skip = rep["skip_reasons"]

    def want(cond: bool, msg: str) -> bool:
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        return cond

    ok = True
    print("[self-test] 解析器自检（输入是测试片段，不是数据）")
    ok &= want(set(got) == {"900001", "900002", "900009", "900010", "900012", "900013"},
               f"只导入 6 条可等价规则，实际 {sorted(got)}")
    # 反斜杠必须原样保留 —— 这是最容易被静默改坏的地方
    ok &= want(got.get("900001", {}).get("regex") == r"(?i)union\s+select",
               f"lowercase -> (?i) 前缀且保留 \\s：{got.get('900001', {}).get('regex')!r}")
    ok &= want(got.get("900009", {}).get("regex") == r"sleep\s*\(\s*\d+",
               f"正则里的反斜杠原样保留：{got.get('900009', {}).get('regex')!r}")
    ok &= want(got.get("900013", {}).get("regex") == r"(?i)select\s+.*\s+from",
               f"自带 (?i) 不重复加前缀：{got.get('900013', {}).get('regex')!r}")
    ok &= want(got.get("900001", {}).get("weight") == 5.0, "CRITICAL -> weight 5")
    ok &= want(got.get("900002", {}).get("regex") == r"sqlmap/1\.\d+\z",
               f"串尾 $ -> \\z：{got.get('900002', {}).get('regex')!r}")
    ok &= want(got.get("900002", {}).get("scopes") == ["ua"], "UA 变量 -> ua")
    ok &= want(got.get("900009", {}).get("scopes") == ["query", "body"],
               "ARGS -> query+body")
    ok &= want(got.get("900012", {}).get("scopes") == ["path"],
               "REQUEST_FILENAME -> path only")
    ok &= want(r"[a$]{2}" in got.get("900010", {}).get("regex", ""),
               "字符类里的 $ 保持字面量")
    ok &= want(all(r["action"] == "alert" for r in rep["rules"]),
               "导入规则一律 action=alert")
    ok &= want(skip.get("chain") == 1, f"chain 跳过 1 条（实际 {skip.get('chain')}）")
    ok &= want(skip.get("chain_continuation") == 1,
               f"chain 的后续条件也跳过（实际 {skip.get('chain_continuation')}）")
    ok &= want(skip.get("operator:@detectsqli") == 1,
               f"@detectSQLi 跳过（实际 {skip.get('operator:@detectsqli')}）")
    ok &= want(skip.get("pcre_only:(?=") == 1, "lookahead 跳过")
    ok &= want(skip.get("transform:htmlentitydecode") == 1,
               "htmlEntityDecode 跳过")
    ok &= want(skip.get("unsupported_variable:REQUEST_COOKIES:\"SESSION\"") == 1 or
               any(k.startswith("unsupported_variable:REQUEST_COOKIES") for k in skip),
               f"COOKIES 变量跳过（实际 {[k for k in skip if 'COOKIE' in k]}）")
    ok &= want(any(k.startswith("operator:@gt") for k in skip),
               "TX 变量 / @gt 跳过")
    print(f"[self-test] {'OK' if ok else 'FAILED'}：导入 {len(rep['rules'])} 条，跳过 "
          f"{rep['totals']['skipped']} 条")
    rep["status"] = "self_test_only" if ok else "self_test_failed"
    rep["real_crs_imported"] = False
    rep["about"] = (
        "这是**解析器自检**的报告，不是真实 CRS 的导入结果。输入是 import_crs.py 里的"
        " SELF_TEST_SNIPPETS（测试片段），不是 OWASP CRS 的文件。"
        "真实导入需要 --src <coreruleset 的 rules 目录>；本机当前无网络出口、也没有本地"
        " CRS 检出，所以这一步尚未执行。")
    return (0 if ok else 1), rep


def import_dir_from_text(text: str) -> Dict[str, Any]:
    """给自检用：直接解析一段文本（不碰文件系统）。"""
    report: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "<self-test>", "license": CRS_LICENSE,
        "totals": {"files": 1, "logical_lines": 0, "secrules": 0,
                   "imported": 0, "skipped": 0, "parse_errors": 0},
        "skip_reasons": {}, "files": {}, "rules": [], "notes": [],
    }
    _consume(split_logical_lines(text), report)
    return report


# --------------------------------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description="OWASP CRS -> 本项目的自撰规则（草稿）")
    ap.add_argument("--src", default="", help="CRS 的 rules 目录，或单个 .conf")
    ap.add_argument("--out", default=os.path.join(ART, "crs_import_report.json"))
    ap.add_argument("--write-db", action="store_true",
                    help="把导入的规则写成草稿（**不会**启用、**不会**提升）")
    ap.add_argument("--limit", type=int, default=None, help="最多写多少条（默认全部）")
    ap.add_argument("--self-test", action="store_true", help="只跑解析器自检")
    ap.add_argument("--write-report", action="store_true",
                    help="与 --self-test 一起用：把**自检**报告写到 --out（会标注 status）")
    args = ap.parse_args()

    if args.self_test:
        rc, rep = self_test()
        if args.write_report:
            os.makedirs(ART, exist_ok=True)
            tmp = args.out + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(rep, f, ensure_ascii=False, indent=2)
            os.replace(tmp, args.out)
            print(f"[crs] 自检报告 -> {args.out}（status={rep['status']}）")
        return rc
    if not args.src:
        ap.error("需要 --src（CRS 的 rules 目录）或 --self-test")

    rep = import_dir(args.src)
    if args.write_db:
        rep["db"] = write_db(rep["rules"], limit=args.limit)
        rep["notes"].append(
            "已写入 DB 的规则全部是**草稿**（enabled=0/action=alert/validated_at=NULL）。"
            "下一步：逐条 POST /api/rules/custom/{id}/validate，过了三关再打开开关。")
    else:
        rep["notes"].append("未写 DB（加 --write-db 才落库）。")

    os.makedirs(ART, exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    os.replace(tmp, args.out)

    t = rep["totals"]
    print(f"[crs] 文件 {t['files']}｜SecRule {t['secrules']}｜导入 {t['imported']}｜"
          f"跳过 {t['skipped']}｜解析错误 {t['parse_errors']}")
    top = sorted(rep["skip_reasons"].items(), key=lambda kv: -kv[1])[:12]
    for k, v in top:
        print(f"       skip {v:>5}  {k}")
    if rep.get("db"):
        d = rep["db"]
        print(f"[crs] DB: 新增 {d['inserted']}｜已存在 {d['skipped_existing']}｜"
              f"失败 {d['failed']}")
        for e in d["errors"]:
            print("       ! " + e)
    print(f"[crs] -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
