"""规则 DSL v1：结构校验 + **静态**正则安全预检。

定位：规则层是**并列第三通道**，不是「规则 → AI」串行管线。它必须能被单独信任，
所以一条规则只有在三关全过之后才算「合格」：

  ① 正则安全   —— 权威编译器是 Rust `regex` crate（`waf-ai-proto rules check`，见 R3）
  ② 真实良性回放 —— 在真实良性池上误报必须为 0（`calibrate_rules.py`）
  ③ 攻击回放   —— 在攻击池上命中必须 > 0

本模块只负责 **①的 Python 侧预检** 和 **结构校验**。它是"快速拒绝"层，宁可误拒不可漏放：

  * Rust `regex` 是线性时间引擎（**不存在回溯型 ReDoS**），但**不支持** lookaround /
    反向引用 / 原子组 / 条件分支 / 占有量词 / `\\Z` / `\\G` / `\\K` / 递归 / `\\p{..}`。
    这些 Python `re` **支持**而 Rust **不支持** ⇒ 一旦漏放，两侧会给出不同结果，
    而"两侧必须同源"是本项目的红线。
  * 允许的语法 = 两侧语义一致的子集：字面量、字符类、分组（含 `(?:` / `(?P<n>`）、
    分支、有界与无界重复、锚点 `^ $ \\b \\B \\A \\z`、内联标志 `(?i)` `(?s)` `(?m)` `(?x)`。

⚠️ 解码流水线固定为 `urlencoded`（+ → 空格，百分号解码，最多两遍）+ `unicode`
  （`\\uXXXX` / `\\UXXXXXXXX`）。**缩窄是有意的**（用户拍板）：json/multipart 按原文匹配。
  已知残余逃逸面：HTML 实体（`&lt;script&gt;`）不解码；补法是两侧共用一张**固定小实体表**
  （**不要**用 Python `html.unescape`：HTML5 全量实体表、跨版本会变，无法做同源保证）。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# --------------------------------------------------------------------------- 常量
DECODE_STAGES = ("urlencoded", "unicode")
DEFAULT_DECODE: List[str] = ["urlencoded", "unicode"]

#   * `full` = 与 `p7_rule_mining.py` / `features.py` 同源的整串：`METHOD path?query body`
#     （`?` 是字面量、恒在）。**p7 锚点（7 keep / 6 reject_fp）只在 `full` 下可复现。**
#   * 其余为单字段，便于把规则收窄到某一处（降低误报面）。
SCOPES = ("full", "path", "query", "body", "ua", "referer")
ACTIONS = ("alert", "block")
SEVERITIES = ("low", "medium", "high", "critical")
#: `detector` = 攻击检测型（合格要有攻击证据）；
#: `guard`    = 防御型/入口型（如 `.git`、管理入口、actuator）：它不一定对应一次真实攻击，
#:              合格判据是「真实良性 0 误报 + 管理员声明政策理由」，不看攻击回放。
KINDS = ("detector", "guard")

MAX_REGEX_LEN = 400
MAX_RULES = 200
MAX_WEIGHT = 100.0
MAX_NAME_LEN = 60

#: 自定义规则 id 强制前缀，避免与挖出的候选规则（如 `xss_script_tag`）撞名，
#: 也让审计与 `event_rules` 一眼能分清来源。
CUSTOM_ID_RE = re.compile(r"^custom_[a-z0-9_]{3,40}$")

#: 静态拒绝标记（在**去掉字符类之后**的正文里查）。
UNSAFE_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("(?=", "先行断言 lookahead：Rust regex 不支持"),
    ("(?!", "否定先行断言：Rust regex 不支持"),
    ("(?<=", "后行断言 lookbehind：Rust regex 不支持"),
    ("(?<!", "否定后行断言：Rust regex 不支持"),
    ("(?<", "后行断言语法：Rust regex 不支持（命名组请用 (?P<name>）"),
    ("(?>", "原子组：Rust regex 不支持"),
    ("(?(", "条件分支：Rust regex 不支持"),
    ("(?P=", "命名反向引用：Rust regex 不支持"),
    ("(?P>", "递归：Rust regex 不支持"),
    ("\\Z", "\\Z 是 Python 的绝对串尾；Rust 用 \\z。DSL 统一写 \\z（入库时自动翻译）"),
    ("\\G", "\\G：Rust regex 不支持"),
    ("\\K", "\\K：Rust regex 不支持"),
    ("\\p{", "Unicode 属性类：两侧语义不同，拒绝"),
    ("\\P{", "Unicode 属性类：两侧语义不同，拒绝"),
)

#: Rust 与 Python 都支持、但**语义可能有差异**的构造：只警告，不拒绝。
#: `$` —— Python 允许"末尾换行之前"也算匹配，Rust（RE2 语义）只在串尾匹配。
#: 规则引擎的实测口径是 Rust，所以线上不会静默不一致；但如果你写 `...$` 又指望
#: Python 的宽松语义，`calibrate_rules.py` 的 p7 对照会显式报出差异。
WARN_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("$", "`$` 在 Python 可匹配『末尾换行之前』，Rust 只在串尾匹配；要严格请写 `\\z`"),
)

_BACKREF_RE = re.compile(r"\\[1-9]")
_POSSESSIVE_RE = re.compile(r"(?:[*+?]|\{\d+(?:,\d*)?\})\+")
_WEIGHT_RE = re.compile(r"\{\d+(?:,\d*)?\}")


def _py_pattern(rx: str) -> str:
    """Python 侧编译用的等价式。

    DSL 的规范绝对串尾记号是 `\\z`（Rust 原生支持）；Python 只认 `\\Z`。
    这里做翻译，**只为静态预检**——线上匹配永远由 Rust 完成。
    """
    return rx.replace("\\z", "\\Z")


def _strip_classes(pat: str) -> str:
    """去掉 `[...]` 字符类，避免类内字符（如 `[*+]`）触发误判。"""
    out: List[str] = []
    i = 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "\\" and i + 1 < n:
            out.append(pat[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pat[j] == "^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                if pat[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            out.append("[]")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def check_regex(rx: str) -> List[str]:
    """静态检查单条正则。返回错误列表（空 = 通过）。"""
    errs: List[str] = []
    if not isinstance(rx, str) or not rx.strip():
        return ["regex 不能为空"]
    if len(rx) > MAX_REGEX_LEN:
        errs.append(f"regex 过长（{len(rx)} > {MAX_REGEX_LEN}）：正则越复杂越难审")
    body = _strip_classes(rx)
    for mark, why in UNSAFE_MARKERS:
        if mark in body:
            errs.append(f"含 {mark!r}：{why}")
    if _BACKREF_RE.search(body):
        errs.append("含反向引用 \\1-\\9：Rust regex 不支持（且两侧语义不同源）")
    if _POSSESSIVE_RE.search(body):
        errs.append("含占有量词（如 a++ / a*+ / a{2,}+）：Rust regex 不支持")
    # Python 侧编译（语法层）。DSL 规范记号 `\z` 先翻译成 Python 的 `\Z`。
    try:
        compiled = re.compile(_py_pattern(rx))
    except re.error as e:
        errs.append(f"Python 等价式编译失败：{e}")
        return errs
    if compiled.search("") is not None:
        errs.append("正则能匹配空串：会对每个请求命中，误报必然爆表")
    # 括号配对与嵌套深度（粗检）。
    # ⚠️ 必须跳过 `\` 转义：`\(` / `\)` 是**字面括号**，不是分组。
    # 早期版本没跳过，于是 `sleep\(\d+\)` 这种最常见的正则被判成"括号不配对"，
    # 自撰规则和 CRS 导入都会被无理由拒掉。
    depth = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            i += 2
            continue
        if ch == "(":
            depth += 1
            if depth > 12:
                errs.append("分组嵌套过深（>12）")
                break
        elif ch == ")":
            depth -= 1
            if depth < 0:
                errs.append("括号不配对（多了一个 `)`）")
                break
        i += 1
    if depth > 0:
        errs.append("括号不配对")
    return errs


def warn_regex(rx: str) -> List[str]:
    """不拒绝、但必须让作者知道的语义差异。"""
    body = _strip_classes(rx or "")
    out: List[str] = []
    for mark, why in WARN_MARKERS:
        if mark in body:
            out.append(why)
    return out


def normalize_scopes(raw: Any) -> List[str]:
    if raw is None:
        return ["full"]
    if isinstance(raw, str):
        raw = [s.strip() for s in raw.split(",") if s.strip()]
    if not isinstance(raw, list) or not raw:
        return ["full"]
    out: List[str] = []
    for s in raw:
        s = str(s).strip().lower()
        if s and s not in out:
            out.append(s)
    return out or ["full"]


def check_spec(rule: Dict[str, Any], *, custom_id: bool = False) -> List[str]:
    """校验单条规则的规格（结构 + 静态正则）。返回错误列表。"""
    errs: List[str] = []
    rid = str(rule.get("id") or "").strip()
    if not rid:
        errs.append("id 不能为空")
    elif custom_id and not CUSTOM_ID_RE.match(rid):
        errs.append("自定义规则 id 必须形如 custom_<小写字母数字下划线>（3-40 位）")

    name = str(rule.get("name") or "").strip()
    if not name:
        errs.append("name 不能为空")
    elif len(name) > MAX_NAME_LEN:
        errs.append(f"name 过长（> {MAX_NAME_LEN}）")

    errs.extend(check_regex(str(rule.get("regex") or "")))

    scopes = normalize_scopes(rule.get("scopes"))
    bad = [s for s in scopes if s not in SCOPES]
    if bad:
        errs.append(f"scope 非法：{bad}；只支持 {list(SCOPES)}")

    sev = str(rule.get("severity") or "medium").strip().lower()
    if sev not in SEVERITIES:
        errs.append(f"severity 非法：{sev}；只支持 {list(SEVERITIES)}")

    act = str(rule.get("action") or "alert").strip().lower()
    if act not in ACTIONS:
        errs.append(f"action 非法：{act}；只支持 {list(ACTIONS)}")

    kind = str(rule.get("kind") or "detector").strip().lower()
    if kind not in KINDS:
        errs.append(f"kind 非法：{kind}；只支持 {list(KINDS)}")

    try:
        w = float(rule.get("weight", 1.0))
    except Exception:
        errs.append("weight 必须是数字")
    else:
        if not (0.0 <= w <= MAX_WEIGHT):
            errs.append(f"weight 必须在 [0, {MAX_WEIGHT}]")
    return errs


def warn_spec(rule: Dict[str, Any]) -> List[str]:
    """不阻断保存、但必须在界面上显式提示的语义差异。"""
    out = warn_regex(str(rule.get("regex") or ""))
    scopes = normalize_scopes(rule.get("scopes"))
    if "full" in scopes and len(scopes) > 1:
        out.append("同时勾了 `full` 与单字段 scope：`full` 已包含这些字段，重复检查会重复计命中")
    kind = str(rule.get("kind") or "detector").strip().lower()
    if kind == "guard":
        out.append("这是防御型（guard）规则：合格不看攻击回放，只看「真实良性 0 误报 + "
                   "管理员填写政策理由」。它用于拒绝不该被访问的入口/路径，不表示发生过攻击。")
    if str(rule.get("action") or "alert").lower() == "block":
        out.append("这是一条 block 规则：它会消耗阻断预算（目标 FPR 会相应收紧），"
                   "并且只有在「确认合格」且规则集被「提升」后才生效")
    return out


def clean(rule: Dict[str, Any], *, default_action: str = "alert") -> Dict[str, Any]:
    """把入参收敛成入库形态（**不**做校验，校验用 `check_spec`）。"""
    try:
        w = float(rule.get("weight", 1.0))
    except Exception:
        w = 1.0
    return {
        "id": str(rule.get("id") or "").strip(),
        "name": str(rule.get("name") or "").strip(),
        "regex": str(rule.get("regex") or ""),
        "scopes": normalize_scopes(rule.get("scopes")),
        "severity": str(rule.get("severity") or "medium").strip().lower(),
        "weight": round(w, 4),
        "action": str(rule.get("action") or default_action).strip().lower(),
        "kind": str(rule.get("kind") or "detector").strip().lower(),
        "notes": (str(rule.get("notes")).strip() if rule.get("notes") else None),
    }


def check_decode(stages: Any) -> List[str]:
    if stages is None:
        return []
    if isinstance(stages, str):
        stages = [s.strip() for s in stages.split(",") if s.strip()]
    if not isinstance(stages, list) or not stages:
        return ["decode 必须是非空列表"]
    bad = [s for s in stages if s not in DECODE_STAGES]
    if bad:
        return [f"decode 阶段非法：{bad}；v1 只支持 {list(DECODE_STAGES)}"]
    return []
