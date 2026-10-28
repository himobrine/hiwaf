"""把外部通用 Web WAF 规则集（`rules/waf_rules.json`）**保守地**导入为本项目的自撰规则（草稿）。

## 这份文件和 CRS 的区别

它是自撰 JSON 规则集（不是 ModSecurity），字段是 `id/category/name/target/regex/severity/action/note`，
正则方言已经声明为「无环视、无反向引用、无占有量词」，比 CRS 好对齐得多。但仍有**两处**
不能直译的地方，必须显式记账：

1. **`target` 语义不完全覆盖**。它的 target 词表里有 `cookie` / `header` / `filename` /
   `response`，而我们的规则通道**只有** `path` / `query` / `body` / `ua` / `referer` / `full`
   这几个 scope，数据面也不落 cookie、不落响应体。所以：
     * `uri`   -> `path`
     * `query` -> `query`
     * `body`  -> `body`
     * `cookie` / `header` / `filename` / `response` -> **无对应**（`header` 尤其不能猜：
       UA 与自定义头是两回事，猜错就是静默改变语义）。
   处理方式：取**交集**导入，并把丢掉的目标写进 `notes` 与报告（`dropped_targets`）。
   交集为空（例如只有 `header`）的规则一律**跳过** —— 那种规则在我们这儿永远不会命中。

2. **编码形态分支在解码后不可达**。它的 matching_pipeline 假设「先做一次 URL 解码再匹配」，
   于是有规则专门去匹配 `%3c` / `%25` / `\u003c` 这类**编码后的字面量**。我们的管线固定
   是 `urlencoded`（最多两遍）+ `unicode`（`\\uXXXX`），匹配发生在解码**之后**：`%3c` 已经
   变成 `<`，`\\u003c` 已经变成 `<`。这类分支永远匹配不到。
   处理方式：按**顶层分支**判断 —— 所有分支都不可达才跳过（`decode_incompatible`）；
   只有部分不可达则照常导入，但把 `dead_branches` 记进报告（`\x3c` 这类分支是**活的**：
   我们的 unicode 阶段不解 `\\x`，保持原样）。
   这类规则留不留，最终由三关决定（攻击回放 0 命中 = 不过关），这里不替它下结论。

3. **大小写**。源文件声明「统一按大小写不敏感方式匹配」，而 Rust `regex` 默认区分大小写，
   所以每条导入规则都补 `(?i)` 前缀（已有 `(?i)` 则不重复加）。这是**语义对齐**，不是调参。

4. **串尾锚点**。`$` 在 Python 可匹配「末尾换行之前」，Rust 只匹配串尾。DSL 的规范记号是
   `\\z`，所以字符类之外的 `$` 一律翻成 `\\z`（与 `import_crs.py` 同一套处理）。

## 导入之后仍然**不是**「启用」

写入 DB 的每一条都是：`action=alert`、`enabled=0`、`validated_at=NULL`（草稿）。
必须逐条过三关（Rust 编译 / 真实良性回放零误报 / 攻击回放命中 > 0），再由人打开开关。
源文件的 `action`（block/log）只作为**意图**记录在 `notes` 里 —— 因为「这条规则该不该拦」
必须由本项目自己的实测证据决定，而不是由外部文件自称。

**本脚本永远不会**启用规则、永远不会改 `action=block`、永远不会写现役规则集。

## 出处 / 许可

`rules/waf_rules.json` 由用户提供（v1.0.0，文件内未声明许可证）。脚本只做字段映射，
不复制其中的说明文字；导入的规则在 DB 里以 `source='wafjson'` 标记，现役规则集的
`counts` 会单独统计，便于审计「这条是谁写的」。

## 用法

    # 只解析、出报告（不写 DB）
    py -3.10 import_waf_rules.py

    # 解析并写入草稿规则
    py -3.10 import_waf_rules.py --write-db

    # 只跑解析器自检（不需要源文件）
    py -3.10 import_waf_rules.py --self-test
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
DEFAULT_SRC = os.path.join(os.path.dirname(HERE), "rules", "waf_rules.json")

SOURCE_TAG = "wafjson"

# --------------------------------------------------------------------------- 字段映射
#  源文件 target -> 我们的 scope。**只映射语义一一对应的**。
TARGET_SCOPES = {
    "uri": "path",        # 源文件：请求路径。我们的 `path` = 解码后的路径，不含 method/query
    "query": "query",     # 查询串（不含 `?`）
    "body": "body",       # 请求体原文（json/multipart 不解码，符合本项目收窄口径）
}

#  源文件有、我们**没有**的目标。`header` 不做 UA 猜测：UA 与自定义头是两回事。
UNSUPPORTED_TARGETS = {
    "cookie": "数据面不落 cookie，规则通道也没有 cookie scope",
    "header": "只有 ua / referer 两个具体头；把 header 猜成 ua 会静默改变语义",
    "filename": "multipart 的文件名参数值未单独抽取（body 里是原文，不能等价替代）",
    "response": "只采集入站请求，不采响应体",
}

#  源文件 severity -> (我们的 severity, weight)。weight 只是记分输入，severity 只用于展示；
#  保持与挖出的候选规则一致的相对关系（critical 最重）。
SEVERITY_MAP = {
    "critical": ("critical", 5.0),
    "high": ("high", 4.0),
    "medium": ("medium", 3.0),
    "low": ("low", 2.0),
}

#  源文件 action -> 我们记录的「意图」。实际入库恒为 alert（见模块文档）。
SRC_ACTION_MAP = {"block": "block", "log": "alert", "alert": "alert"}

MAX_REGEX_LEN = 400          # 与 rules_dsl.MAX_REGEX_LEN 对齐
MAX_NAME_LEN = 60            # 与 rules_dsl.MAX_NAME_LEN 对齐
MAX_RULES = 200              # 与 rules_dsl.MAX_RULES 对齐

#  在**解码后**文本上必然不可达的分支特征。
#  * `%XX`：`unquote_plus` 两遍之后，`%3c` 已是 `<`、`%253c` 也是 `<`。
#  * 字面 `\uXXXX`（正则里写作 `\\u003c`）：`unescape_unicode` 会解成 `<`。
#  注意 `%uXXXX` 与 `\xXX` **不在**此列：我们的管线不解它们，它们在结论文本里原样存在。
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_LIT_U_RE = re.compile(r"\\\\u[0-9a-fA-F]{4}")


# --------------------------------------------------------------------------- 正则预处理
def split_alternatives(rx: str) -> List[str]:
    """按**顶层** `|` 切分（跳过字符类与分组内部），用于判断"是不是所有分支都死了"。

    切错的影响只是统计不准（可能少算 dead / 多算 dead），不会改变导入的语义；
    但分层判断比"整条正则含 `%` 就跳过"精确得多 —— 否则 `..%2f | ../` 这种
    「半死半活」的核心穿越规则会被整条丢掉。
    """
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    in_class = False
    i = 0
    n = len(rx)
    while i < n:
        c = rx[i]
        if c == "\\" and i + 1 < n:
            buf.append(rx[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            buf.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            buf.append(c)
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "|" and depth == 0:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def branch_is_dead(branch: str) -> bool:
    """该分支在解码后的文本上是否必然不可达。"""
    return bool(_PCT_RE.search(branch) or _LIT_U_RE.search(branch))


def reject_dollar(rx: str) -> str:
    """把字符类之外的 `$` 翻成 `\\z`（DSL 规范串尾）。

    逐字符扫描，跳过 `\\` 转义与 `[...]` 字符类 —— 类里的 `$` 是字面量。
    """
    out: List[str] = []
    i = 0
    n = len(rx)
    in_class = False
    while i < n:
        c = rx[i]
        if c == "\\" and i + 1 < n:
            out.append(rx[i:i + 2])
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
    return "".join(out)


def strip_full_wrapper(rx: str) -> str:
    """若整条正则被一个分组**完整包裹**（`(?:a|b|c)`），剥掉这层壳。

    不剥的话，`(?:^|[/?.&=])` 这种写法会被 `split_alternatives` 当成"一个分支"，
    于是"只有部分分支依赖编码形态"的规则会被误判成整条不可导入 ——
    `PT-001`（`(?:../|..\\|..%2f|...)`）就是这么被误杀过一次。

    只剥**恰好覆盖整条**的那一层：`(?:a)(?:b)` / `(?:a)|b` 都不剥。
    """
    s = rx
    for _ in range(4):                      # 最多剥 4 层，防止病态输入
        s = s.strip()
        prefix = ""
        body = s
        m = re.match(r"\(\?[aiLmsux-]+\)", s)   # 内联标志前缀 (?i) / (?is)
        if m:
            prefix, body = m.group(0), s[m.end():].strip()
        if not body.startswith("("):
            return s
        depth = 0
        in_class = False
        end = -1
        i = 0
        while i < len(body):
            c = body[i]
            if c == "\\" and i + 1 < len(body):
                i += 2
                continue
            if in_class:
                if c == "]":
                    in_class = False
                i += 1
                continue
            if c == "[":
                in_class = True
                i += 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end != len(body) - 1:
            return s
        inner = body[1:end]
        if inner.startswith("?:"):
            s = prefix + inner[2:]
            continue
        if inner.startswith("?"):
            return s                        # (?i:...) / (?P<n>...) 等，不动
        s = prefix + inner
    return s


def translate_rx(rx: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """源正则 -> DSL 正则。返回 (regex, 记账信息)。不可导入时 regex 为 None。"""
    info: Dict[str, Any] = {"dead_branches": 0, "branches": 0, "case_insensitive_added": False}
    if not isinstance(rx, str) or not rx.strip():
        return None, {**info, "skip": "empty_regex"}
    if len(rx) > MAX_REGEX_LEN:
        return None, {**info, "skip": f"regex_too_long:{len(rx)}"}

    branches = split_alternatives(strip_full_wrapper(rx))
    dead = [b for b in branches if branch_is_dead(b)]
    info["branches"] = len(branches)
    info["dead_branches"] = len(dead)
    if branches and len(dead) == len(branches):
        return None, {**info, "skip": "decode_incompatible"}

    out = reject_dollar(rx)
    if "(?i)" not in out:
        out = "(?i)" + out
        info["case_insensitive_added"] = True
    if len(out) > MAX_REGEX_LEN:
        return None, {**info, "skip": f"regex_too_long:{len(out)}"}
    return out, info


def map_targets(targets: Any) -> Tuple[List[str], List[str], Optional[str]]:
    """源 target 列表 -> (scopes, dropped_targets, skip_reason)。"""
    if isinstance(targets, str):
        targets = [targets]
    if not isinstance(targets, list) or not targets:
        return [], [], "no_target"
    order = ["path", "query", "body"]
    scopes: List[str] = []
    dropped: List[str] = []
    for t in targets:
        key = str(t or "").strip().lower()
        if not key:
            continue
        if key in TARGET_SCOPES:
            sc = TARGET_SCOPES[key]
            if sc not in scopes:
                scopes.append(sc)
        elif key in UNSUPPORTED_TARGETS:
            if key not in dropped:
                dropped.append(key)
        else:
            # 词表里没见过的目标：不认识就不猜。
            return [], dropped, f"unknown_target:{key}"
    if not scopes:
        return [], dropped, "unsupported_target:" + "+".join(dropped or ["none"])
    return sorted(scopes, key=order.index), dropped, None


def slug_id(src_id: str) -> str:
    """`SQLI-001` -> `waf_sqli_001`（落库后是 `custom_waf_sqli_001`）。"""
    s = re.sub(r"[^a-z0-9]+", "_", str(src_id or "").lower()).strip("_")
    return ("waf_" + (s or "rule"))[:40]


def convert_one(raw: Dict[str, Any], *, version: str = "") -> Tuple[Optional[Dict[str, Any]],
                                                                    Optional[str]]:
    """单条源规则 -> 我们的规则 dict（入库形态）。不可导入则返回跳过原因。"""
    src_id = str(raw.get("id") or "").strip()
    if not src_id:
        return None, "no_id"
    name = str(raw.get("name") or "").strip() or src_id

    scopes, dropped, why = map_targets(raw.get("target"))
    if why:
        return None, why

    rx, info = translate_rx(str(raw.get("regex") or ""))
    if rx is None:
        return None, info.get("skip") or "regex"

    sev_raw = str(raw.get("severity") or "medium").strip().lower()
    severity, weight = SEVERITY_MAP.get(sev_raw, ("medium", 3.0))
    act_raw = str(raw.get("action") or "log").strip().lower()
    intent = SRC_ACTION_MAP.get(act_raw, "alert")
    category = str(raw.get("category") or "").strip()

    full_name = f"[{src_id}] {name}"
    if len(full_name) > MAX_NAME_LEN:
        full_name = full_name[:MAX_NAME_LEN - 1] + "…"

    bits = [f"waf_rules.json v{version or '?'}", f"id={src_id}"]
    if category:
        bits.append(f"cat={category}")
    bits.append(f"sev={sev_raw}")
    bits.append(f"src_action={act_raw or '?'}（意图={intent}；入库恒 alert）")
    bits.append("targets=" + ",".join(str(t) for t in (raw.get("target") or [])))
    bits.append("scopes=" + ",".join(scopes))
    if dropped:
        bits.append("dropped=" + ",".join(dropped) + "（数据面无对应字段）")
    if info["dead_branches"]:
        bits.append(f"dead_branches={info['dead_branches']}/{info['branches']}"
                    "（编码形态分支在解码后不可达）")
    note = str(raw.get("note") or "").strip()
    if note:
        bits.append(note)

    return {
        "id": slug_id(src_id),
        "name": full_name,
        "regex": rx,
        "scopes": scopes,
        "severity": severity,
        "weight": weight,
        # 入库恒为 alert：转 block 必须由人逐条决定，并消耗阻断预算。
        "action": "alert",
        "notes": "；".join(bits),
        "src_id": src_id,
        "src_action": act_raw or "log",
        "src_intent": intent,
        "src_severity": sev_raw,
        "category": category,
        "dropped_targets": dropped,
        "dead_branches": info["dead_branches"],
        "branches": info["branches"],
    }, None


# --------------------------------------------------------------------------- 主流程
def _bump(report: Dict[str, Any], key: str) -> None:
    report["skip_reasons"][key] = report["skip_reasons"].get(key, 0) + 1


def parse_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """解析整份规则集。纯函数：不读盘、不写库。"""
    meta = doc.get("meta") or {}
    version = str(meta.get("version") or "")
    declared = doc.get("rules")
    if not isinstance(declared, list):
        declared = []
    report: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_name": meta.get("name"),
        "source_version": version,
        "source_date": meta.get("date"),
        "source_license": meta.get("license") or "<未声明>",
        "totals": {"declared": len(declared), "imported": 0, "skipped": 0,
                   "parse_errors": 0},
        "skip_reasons": {},
        "by_category": {},
        "by_src_action": {},
        "dropped_target_counts": {},
        "with_dropped_targets": 0,
        "with_dead_branches": 0,
        "rules": [],
        "skipped_rules": [],
        "notes": [
            "只导入 target 与我们的 scope 有交集的规则；cookie/header/filename/response 无对应，"
            "丢弃情况逐条记在 notes 与 dropped_targets。",
            "所有导入规则恒为 action=alert、enabled=0、validated_at=NULL：必须逐条过三关"
            "（Rust 编译 / 真实良性 0 误报 / 攻击回放 > 0）后由人打开开关。",
            "源文件声明大小写不敏感 -> 每条补 (?i)；字符类外的 $ -> \\z。这是语义对齐，不是调参。",
            "含 %XX / 字面 \\uXXXX 的分支在解码后不可达；全部分支都不可达的规则整条跳过"
            "（decode_incompatible），部分不可达的照常导入并记账（dead_branches）。",
            "源文件的 action=block 只作为意图记录在 notes（src_action），不当作证据 —— "
            "能否拦截只能由本项目自己的实测决定。",
        ],
    }
    seen: set = set()
    for raw in declared:
        if not isinstance(raw, dict):
            report["totals"]["parse_errors"] += 1
            _bump(report, "not_an_object")
            report["skipped_rules"].append({"id": "<非对象>", "reason": "not_an_object"})
            continue
        rule, why = convert_one(raw, version=version)
        if rule is None:
            report["totals"]["skipped"] += 1
            _bump(report, why or "unknown")
            report["skipped_rules"].append(
                {"id": str(raw.get("id") or "?"), "reason": why or "unknown",
                 "target": raw.get("target")})
            continue

        # 结构 + 静态正则：用控制面同一份 DSL 预检（快速拒绝层）。
        # 注意：payload 里的 id 是 `waf_xxx`，落库时才加 `custom_` 前缀，
        # 所以结构校验用 custom_id=False，再单独核对**落库后**的 id 形态。
        from service import rules_dsl
        errs = rules_dsl.check_spec(rule, custom_id=False)
        if not errs and not rules_dsl.CUSTOM_ID_RE.match(final_id(rule["id"])):
            errs = [f"落库 id 不合规：{final_id(rule['id'])}"]
        if errs:
            report["totals"]["skipped"] += 1
            _bump(report, "static:" + errs[0].split("：")[0][:60])
            report.setdefault("static_errors", []).append(
                {"id": rule["src_id"], "errors": errs})
            report["skipped_rules"].append(
                {"id": rule["src_id"], "reason": "static", "errors": errs})
            continue

        if rule["id"] in seen:
            report["totals"]["skipped"] += 1
            _bump(report, "duplicate_id")
            report["skipped_rules"].append(
                {"id": rule["src_id"], "reason": "duplicate_id", "id_after_slug": rule["id"]})
            continue
        seen.add(rule["id"])
        if len(report["rules"]) >= MAX_RULES:
            report["totals"]["skipped"] += 1
            _bump(report, "max_rules_cap")
            report["skipped_rules"].append(
                {"id": rule["src_id"], "reason": "max_rules_cap"})
            continue

        rule["warnings"] = rules_dsl.warn_spec(rule)
        report["rules"].append(rule)
        report["totals"]["imported"] += 1
        report["by_category"][rule["category"]] = \
            report["by_category"].get(rule["category"], 0) + 1
        report["by_src_action"][rule["src_action"]] = \
            report["by_src_action"].get(rule["src_action"], 0) + 1
        if rule["dropped_targets"]:
            report["with_dropped_targets"] += 1
            for t in rule["dropped_targets"]:
                report["dropped_target_counts"][t] = \
                    report["dropped_target_counts"].get(t, 0) + 1
        if rule["dead_branches"]:
            report["with_dead_branches"] += 1

    report["totals"]["importable"] = len(report["rules"])
    return report


def import_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    rep = parse_doc(doc)
    rep["source"] = os.path.abspath(path)
    return rep


# --------------------------------------------------------------------------- 落库
def final_id(rid: str) -> str:
    """与 `rules_mod.create_custom` 的命名规则一致（payload `waf_x` -> 落库 `custom_waf_x`）。"""
    rid = str(rid or "").strip().lower()
    return rid if rid.startswith("custom_") else "custom_" + rid


def write_db(rules: List[dict], *, actor: str = "wafjson-import",
             limit: Optional[int] = None) -> Dict[str, Any]:
    """把导入的规则写成**草稿**（不启用、不提升）。"""
    from service import rules as rules_mod
    from service import db

    existing = {final_id(r["id"]) for r in rules_mod.custom_rows()}
    st: Dict[str, Any] = {"inserted": 0, "skipped_existing": 0, "failed": 0,
                          "errors": [], "ids": []}
    for r in rules:
        if limit is not None and st["inserted"] >= limit:
            break
        fid = final_id(r["id"])
        if fid in existing:
            st["skipped_existing"] += 1
            r["db_id"] = fid
            continue
        try:
            payload = {k: r.get(k) for k in
                       ("id", "name", "regex", "scopes", "severity", "weight",
                        "action", "notes")}
            payload["id"] = fid          # 直接用最终 id，避免 create_custom 再改一次
            out = rules_mod.create_custom(payload, actor)
            rid = out["rule"]["id"]
            # `create_custom` 把 source 固定成 manual；这里补回真实出处，
            # 让「提升 / 审计」能看出这条是外部规则集导入的。
            db.execute("UPDATE rules_custom SET source=? WHERE id=?", (SOURCE_TAG, rid))
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
SELF_TEST_DOC: Dict[str, Any] = {
    "meta": {"name": "自检用的规则片段（不是数据）", "version": "0.0.0"},
    "rules": [
        # 1) 基本映射：uri/query/body -> path/query/body，补 (?i)
        {"id": "T-001", "category": "t", "name": "union", "severity": "critical",
         "action": "block", "target": ["uri", "query", "body"],
         "regex": r"union\s+select", "note": "n1"},
        # 2) 有 cookie/header：取交集，丢掉的两个要记账
        {"id": "T-002", "name": "mixed", "severity": "high", "action": "log",
         "target": ["cookie", "body", "header"], "regex": r"\brememberme\s*="},
        # 3) 只有 header：交集为空 -> 跳过
        {"id": "T-003", "name": "ua only", "severity": "high", "action": "block",
         "target": ["header"], "regex": r"sqlmap"},
        # 4) 全部分支都依赖编码形态 -> 跳过（`\\u003c` 是字面 `\uXXXX`，解码后就没了）
        {"id": "T-004", "name": "enc", "severity": "critical", "action": "block",
         "target": ["query"], "regex": r"%3c\s*script|%253c|\\u003c"},
        # 5) 半死半活：保留活的分支，记账 dead_branches
        {"id": "T-005", "name": "traversal", "severity": "critical", "action": "block",
         "target": ["uri", "query"],
         "regex": r"\.\./|\.\.\\|\.\.%2f|%2e%2e%2f|%252e%252e"},
        # 6) 串尾 $ -> \z（字符类里的 $ 保持字面量）
        {"id": "T-006", "name": "backup", "severity": "medium", "action": "log",
         "target": ["uri"], "regex": r"\.(?:bak|sql)\s*$|[a$]{2}"},
        # 7) 自带 (?i)：不重复加前缀
        {"id": "T-007", "name": "inline", "severity": "low", "action": "log",
         "target": ["body"], "regex": r"(?i)select\s+.*\s+from"},
        # 8) response only -> 跳过
        {"id": "T-008", "name": "resp", "severity": "critical", "action": "block",
         "target": ["response"], "regex": r"root:x:0:0:"},
        # 9) 正则能匹配空串 -> 静态预检拒绝
        {"id": "T-009", "name": "empty", "severity": "high", "action": "block",
         "target": ["query"], "regex": r"(?:foo)?"},
        # 10) %uXXXX 不被我们的管线解码 -> 分支是活的，不能算 dead
        {"id": "T-010", "name": "percent-u", "severity": "high", "action": "block",
         "target": ["query"], "regex": r"%u[0-9a-fA-F]{4}|%c0%ae"},
        # 11) 整体被一个 (?:...) 包裹：必须剥壳后切分支，否则"半死半活"会被误判成整条不可导入
        {"id": "T-011", "name": "wrapped", "severity": "critical", "action": "block",
         "target": ["uri", "query"],
         "regex": r"(?:\.\./|\.\.\\|\.\.%2f|%2e%2e%2f|%252f)"},
        # 12) 剥壳后所有分支都死 -> 仍然跳过
        {"id": "T-012", "name": "wrapped-dead", "severity": "high", "action": "block",
         "target": ["query"], "regex": r"(?:%3c|%25|%00)"},
    ],
}


def self_test() -> Tuple[int, Dict[str, Any]]:
    """解析器自检。**这不是数据**，只是喂给解析器的固定片段。"""
    rep = parse_doc(SELF_TEST_DOC)
    got = {r["src_id"]: r for r in rep["rules"]}
    skip = rep["skip_reasons"]

    def want(cond: bool, msg: str) -> bool:
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        return bool(cond)

    ok = True
    print("[self-test] 导入器自检（输入是测试片段，不是数据）")
    ok &= want(set(got) == {"T-001", "T-002", "T-005", "T-006", "T-007", "T-010", "T-011"},
               f"只导入 7 条可映射规则，实际 {sorted(got)}")
    ok &= want(got.get("T-001", {}).get("scopes") == ["path", "query", "body"],
               "uri/query/body -> path/query/body")
    ok &= want(got.get("T-001", {}).get("regex") == r"(?i)union\s+select",
               f"补 (?i) 且保留 \\s：{got.get('T-001', {}).get('regex')!r}")
    ok &= want(got.get("T-001", {}).get("weight") == 5.0, "critical -> weight 5")
    ok &= want(got.get("T-002", {}).get("scopes") == ["body"],
               "cookie/header 无对应 -> 交集只剩 body")
    ok &= want(got.get("T-002", {}).get("dropped_targets") == ["cookie", "header"],
               f"丢掉的目标要记账：{got.get('T-002', {}).get('dropped_targets')}")
    ok &= want(got.get("T-002", {}).get("action") == "alert",
               "源 action=log 也入库 alert")
    ok &= want(skip.get("unsupported_target:header") == 1,
               f"只有 header 的规则跳过（实际 {skip}）")
    ok &= want(skip.get("decode_incompatible") == 2, "全部分支都不可达 -> 跳过（含剥壳后仍全死的）")
    ok &= want(got.get("T-005", {}).get("dead_branches") == 3 and
               got.get("T-005", {}).get("branches") == 5,
               f"半死半活：5 个分支里 3 个不可达（实际 "
               f"{got.get('T-005', {}).get('dead_branches')}/{got.get('T-005', {}).get('branches')}）")
    ok &= want(got.get("T-011", {}).get("dead_branches") == 3 and
               got.get("T-011", {}).get("branches") == 5,
               f"整条被 (?:...) 包裹时先剥壳再切分支（实际 "
               f"{got.get('T-011', {}).get('dead_branches')}/{got.get('T-011', {}).get('branches')}）")
    ok &= want(r"\.\./" in got.get("T-005", {}).get("regex", ""),
               "活的分支必须保留")
    ok &= want(got.get("T-006", {}).get("regex") == r"(?i)\.(?:bak|sql)\s*\z|[a$]{2}",
               f"$ -> \\z 且字符类里的 $ 保持字面量："
               f"{got.get('T-006', {}).get('regex')!r}")
    ok &= want(got.get("T-007", {}).get("regex") == r"(?i)select\s+.*\s+from",
               f"自带 (?i) 不重复加前缀：{got.get('T-007', {}).get('regex')!r}")
    ok &= want(skip.get("unsupported_target:response") == 1, "response only 跳过")
    ok &= want(any(k.startswith("static:") for k in skip),
               f"空串正则被 DSL 静态预检拒绝（实际 {[k for k in skip if k.startswith('static:')]}）")
    ok &= want(got.get("T-010", {}).get("dead_branches") == 1,
               f"%uXXXX 是活的、%c0%ae 是死的（实际 {got.get('T-010', {}).get('dead_branches')}）")
    ok &= want(len(rep["rules"]) + len(rep["skipped_rules"]) ==
               rep["totals"]["declared"],
               "每条声明规则都有归宿（导入或跳过，不静默丢弃）")
    ok &= want(all(r["action"] == "alert" for r in rep["rules"]),
               "导入规则一律 action=alert")
    print(f"[self-test] {'OK' if ok else 'FAILED'}：导入 {len(rep['rules'])} 条，"
          f"跳过 {rep['totals']['skipped']} 条")
    rep["status"] = "self_test_only" if ok else "self_test_failed"
    rep["real_imported"] = False
    rep["about"] = ("这是**导入器自检**报告，不是真实导入结果。输入是 import_waf_rules.py 里的 "
                    "SELF_TEST_DOC（测试片段），不是 rules/waf_rules.json。")
    return (0 if ok else 1), rep


# --------------------------------------------------------------------------- CLI
def _write_json(path: str, doc: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(description="外部 WAF 规则集 -> 本项目的自撰规则（草稿）")
    ap.add_argument("--src", default=DEFAULT_SRC, help="规则集 JSON（默认 rules/waf_rules.json）")
    ap.add_argument("--out", default=os.path.join(ART, "waf_rules_import_report.json"))
    ap.add_argument("--write-db", action="store_true",
                    help="把导入的规则写成草稿（**不会**启用、**不会**提升）")
    ap.add_argument("--limit", type=int, default=None, help="最多写多少条（默认全部）")
    ap.add_argument("--self-test", action="store_true", help="只跑导入器自检")
    ap.add_argument("--write-report", action="store_true",
                    help="与 --self-test 一起用：把**自检**报告写到 --out（会标注 status）")
    args = ap.parse_args()

    if args.self_test:
        rc, rep = self_test()
        if args.write_report:
            _write_json(args.out, rep)
            print(f"[wafjson] 自检报告 -> {args.out}（status={rep['status']}）")
        return rc

    if not os.path.isfile(args.src):
        ap.error(f"找不到规则集：{args.src}")

    rep = import_file(args.src)
    if args.write_db:
        rep["db"] = write_db(rep["rules"], limit=args.limit)
        rep["notes"].append(
            "已写入 DB 的规则全部是**草稿**（enabled=0/action=alert/validated_at=NULL）。"
            "下一步：逐条 POST /api/rules/custom/{id}/validate，过了三关再打开开关。")
    else:
        rep["notes"].append("未写 DB（加 --write-db 才落库）。")
    _write_json(args.out, rep)

    t = rep["totals"]
    print(f"[wafjson] 声明 {t['declared']} 条｜可导入 {t['imported']}｜"
          f"跳过 {t['skipped']}｜解析错误 {t['parse_errors']}")
    for k, v in sorted(rep["skip_reasons"].items(), key=lambda kv: -kv[1]):
        print(f"       skip {v:>4}  {k}")
    if rep["dropped_target_counts"]:
        print(f"[wafjson] 丢弃目标（{rep['with_dropped_targets']} 条规则受影响）：" +
              "，".join(f"{k}={v}" for k, v in rep["dropped_target_counts"].items()))
    if rep["with_dead_branches"]:
        print(f"[wafjson] 含不可达编码分支：{rep['with_dead_branches']} 条（仍导入，见报告）")
    if rep.get("db"):
        d = rep["db"]
        print(f"[wafjson] DB: 新增 {d['inserted']}｜已存在 {d['skipped_existing']}｜"
              f"失败 {d['failed']}")
        for e in d["errors"]:
            print("       ! " + e)
    print(f"[wafjson] -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
