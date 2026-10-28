"""结构化特征通道 v2（PRD 5.3，通道一）。

v2 相对 v1 的修复，对应 `REALDATA_EVALUATION.md` §4 定位出的根因：

1. **词边界匹配**：关键词由「子串计数」改为「整 token 匹配」（符号类才子串匹配）。
   v1 中 `SQL_KEYWORDS` 含裸 `"or"/"and"`、`CMD_KEYWORDS` 含 `"id"/"sh"/"ls"`，
   导致正常英文（for / nor / guide / should / false）被大量命中。
2. **长度无关化**：关键词分数**按 token 数归一化**（`*_r`），并额外给出
   长度无关的 `*_present` 布尔与 `log1p(count)`，消除 v1「文本越长越像攻击」的伪相关。
3. **特殊字符占比化**：v1 的 `sc_*` 是原始计数（Top 特征重要性 0.32 的 `sc_8`
   属过拟合），v2 全部改为**占比**。
4. **新增参数值维度**：payload 位于参数**值**中，单独统计值的长度/特殊字符密度。
5. **新增语法结构特征**：引号/括号失衡、分隔符连跑、二次编码、转义、注释。

设计约束：必须能被 `rust/src/features.rs` 逐位复现，因此只用整数计数 +
初等浮点运算（`log1p`/`log2`），不引入第三方库。

特征布局（80 维）：
  A 请求形态 11  B 组成/熵 11  C 关键词 16  D 攻击模式 4  E 结构/语法 8  F 特殊字符占比 30
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Tuple

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# ---------------------------------------------------------------------------
# 关键词词典（v2）
#   STRONG：单独出现即高度可疑（select / union / whoami / ../ ...）
#   WEAK  ：需要与其它信号组合才有意义（or / and / id / img ...）
#   _WORDS：按**整个 token**匹配（词边界，大小写不敏感）
#   _SYMS ：按**子串**匹配（符号序列无法分词）
# ---------------------------------------------------------------------------
SQL_STRONG_WORDS = [
    "select", "union", "insert", "update", "delete", "drop", "information_schema",
    "concat", "benchmark", "sleep", "declare", "load_file", "outfile", "having",
    "extractvalue", "updatexml", "waitfor", "exec",
]
SQL_WEAK_WORDS = ["from", "where", "or", "and", "char", "null", "cast"]
SQL_STRONG_SYMS = ["/*", "--", "0x"]
SQL_WEAK_SYMS: List[str] = []

XSS_STRONG_WORDS = [
    "script", "javascript", "onerror", "onload", "onclick", "onmouseover",
    "onfocus", "onmouseout", "alert", "prompt", "confirm", "iframe",
]
XSS_WEAK_WORDS = ["img", "svg", "body", "input", "style", "src", "href"]
XSS_STRONG_SYMS = ["<script", "javascript:", "onerror=", "onload=", "document.cookie",
                   "%3cscript", "<img", "<svg"]
XSS_WEAK_SYMS = ["<", ">", "%3c", "%3e"]

CMD_STRONG_WORDS = [
    "whoami", "powershell", "netcat", "passthru", "popen", "shell_exec",
    "wget", "curl", "chmod", "bash",
]
CMD_WEAK_WORDS = ["cat", "ls", "id", "sh", "cmd", "ping", "kill", "echo",
                  "dir", "type", "passwd", "rm"]
CMD_STRONG_SYMS = ["$(", "`", "&&", "||", "/bin/", "/etc/passwd", "cmd.exe"]
CMD_WEAK_SYMS = ["|", ";"]

TRAV_STRONG_SYMS = ["../", "..\\", "....//", "%2e%2e", "..%2f", "..%5c",
                    "/etc/passwd", "boot.ini", "win.ini", "/proc/self"]
TRAV_WEAK_SYMS = ["%2f", "%5c"]
TRAV_STRONG_WORDS: List[str] = []
TRAV_WEAK_WORDS: List[str] = []

# 特殊字符占比（30 个，去掉 v1 中重复的反斜杠）
SPECIAL_CHARS: List[Tuple[str, str]] = [
    ("'", "quote"), ('"', "dquote"), ('`', "backtick"), ('<', "lt"), ('>', "gt"),
    ('(', "lparen"), (')', "rparen"), ('{', "lbrace"), ('}', "rbrace"),
    ('[', "lbracket"), (']', "rbracket"), (';', "semicolon"), (',', "comma"),
    ('=', "eq"), ('%', "percent"), ('&', "amp"), ('/', "slash"), ('\\', "backslash"),
    ('.', "dot"), (':', "colon"), ('-', "hyphen"), ('+', "plus"), ('*', "star"),
    ('!', "bang"), ('#', "hash"), ('$', "dollar"), ('|', "pipe"), ('@', "at"),
    ('~', "tilde"), ('^', "caret"),
]

# 参数值里被视为「结构性」的字符（用于 val_special_r）
VALUE_SPECIAL = "'\"<>=;(){}[]|&%"

# 分隔符连跑（注入语句常见 `;;`、`||`、`,,`）
DELIM_CHARS = ";|&,"

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def max_repeat_run(s: str) -> int:
    best = run = 0
    prev = None
    for ch in s:
        if ch == prev:
            run += 1
        else:
            run = 1
            prev = ch
        best = max(best, run)
    return best


def max_run_over(s: str, chars: str) -> int:
    """`s` 中只由 `chars` 组成的连续片段的最大长度。"""
    best = run = 0
    for ch in s:
        if ch in chars:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _count_any(hay: str, needles: List[str]) -> int:
    return sum(hay.count(n) for n in needles)


def _cat_hits(low_all: str, tok: Counter, strong_words: List[str],
              weak_words: List[str], strong_syms: List[str],
              weak_syms: List[str]) -> Tuple[int, int]:
    """返回 (strong_hits, weak_hits)：词用 token 计数，符号用子串计数。"""
    strong = sum(tok.get(w, 0) for w in strong_words) + _count_any(low_all, strong_syms)
    weak = sum(tok.get(w, 0) for w in weak_words) + _count_any(low_all, weak_syms)
    return strong, weak


def _param_values(query: str, body: str) -> List[str]:
    """取出所有参数**值**（`k=v` 取 v；无 `=` 取空串）。"""
    vals: List[str] = []
    if query:
        for p in query.split("&"):
            if not p:
                continue
            vals.append(p.split("=", 1)[1] if "=" in p else "")
    if body:
        for p in re.split(r"[&\n]", body):
            if not p:
                continue
            vals.append(p.split("=", 1)[1] if "=" in p else "")
    return vals


# ---------------------------------------------------------------------------
class FeatureExtractor:
    """抽取 80 维结构化特征。"""

    def __init__(self, include_ngram: bool = False, ngram_dim: int = 128):
        self.include_ngram = include_ngram
        self.ngram_dim = ngram_dim
        self._base = self._base_names()
        self.names: List[str] = list(self._base)
        if include_ngram:
            self.names += [f"ng_{i}" for i in range(ngram_dim)]

    @staticmethod
    def _base_names() -> List[str]:
        base = [
            # A 请求形态（11）
            "method_id", "path_depth", "ext_len", "num_params",
            "has_query", "has_body", "is_form_body", "is_json_body",
            "log_url_len", "log_query_len", "log_body_len",
            # B 组成 / 熵（11）
            "entropy", "digit_ratio", "alpha_ratio", "upper_ratio", "nonalnum_ratio",
            "urlencode_ratio", "max_repeat", "num_tokens", "log_num_tokens",
            "avg_token_len", "max_token_len",
            # C 关键词（16 = 4 类 × {strong_present, log_strong, strong_r, weak_r}）
            "sql_strong_present", "sql_strong_log", "sql_strong_r", "sql_weak_r",
            "xss_strong_present", "xss_strong_log", "xss_strong_r", "xss_weak_r",
            "cmd_strong_present", "cmd_strong_log", "cmd_strong_r", "cmd_weak_r",
            "trav_strong_present", "trav_strong_log", "trav_strong_r", "trav_weak_r",
            # D 攻击模式（4）
            "has_or_1eq1", "has_comment", "has_union_select", "random_case_sql",
            # E 结构 / 语法（8）
            "quote_imbalance", "paren_imbalance", "max_delim_run", "double_encode",
            "hex_escape", "val_len_avg", "val_len_max", "val_special_r",
        ]
        base += [f"{name}_r" for _, name in SPECIAL_CHARS]
        return base

    # ------------------------------------------------------------------
    def transform(self, req: Dict[str, str]) -> List[float]:
        method = (req.get("method") or "GET").upper()
        path = req.get("path") or ""
        query = req.get("query") or ""
        body = req.get("body") or ""
        url = path + ("?" + query if query else "")

        low_all = (url + " " + body).lower()
        raw_all = url + " " + body

        # -- 参数个数 --
        params = 0
        if query:
            params += max(1, len([p for p in query.split("&") if p]))
        if body:
            params += max(1, len([p for p in re.split(r"[&\n]", body) if p]))

        # -- token 统计 --
        toks = _TOKEN_RE.findall(raw_all)
        n_tok = len(toks)
        tok = Counter(t.lower() for t in toks)
        avg_tok = (sum(len(t) for t in toks) / n_tok) if n_tok else 0.0
        max_tok = max((len(t) for t in toks), default=0)
        tok_den = n_tok if n_tok else 1

        total = len(raw_all) or 1

        # -- 关键词命中 --
        sql_s, sql_w = _cat_hits(low_all, tok, SQL_STRONG_WORDS, SQL_WEAK_WORDS,
                                 SQL_STRONG_SYMS, SQL_WEAK_SYMS)
        xss_s, xss_w = _cat_hits(low_all, tok, XSS_STRONG_WORDS, XSS_WEAK_WORDS,
                                 XSS_STRONG_SYMS, XSS_WEAK_SYMS)
        cmd_s, cmd_w = _cat_hits(low_all, tok, CMD_STRONG_WORDS, CMD_WEAK_WORDS,
                                 CMD_STRONG_SYMS, CMD_WEAK_SYMS)
        trv_s, trv_w = _cat_hits(low_all, tok, TRAV_STRONG_WORDS, TRAV_WEAK_WORDS,
                                 TRAV_STRONG_SYMS, TRAV_WEAK_SYMS)

        # -- 参数值统计 --
        vals = _param_values(query, body)
        n_val = len(vals)
        val_total = sum(len(v) for v in vals)
        val_max = max((len(v) for v in vals), default=0)
        val_spec = sum(1 for v in vals for ch in v if ch in VALUE_SPECIAL)

        # -- 语法结构 --
        n_single = raw_all.count("'")
        n_double = raw_all.count('"')
        n_lparen = raw_all.count("(")
        n_rparen = raw_all.count(")")

        f: Dict[str, float] = {}
        # A
        f["method_id"] = float(METHODS.index(method)) if method in METHODS else -1.0
        f["path_depth"] = path.count("/")
        seg = path.rsplit("/", 1)[-1]
        f["ext_len"] = len(seg.rsplit(".", 1)[-1]) if "." in seg else 0
        f["num_params"] = params
        f["has_query"] = float(bool(query))
        f["has_body"] = float(bool(body))
        f["is_json_body"] = float(body.strip().startswith("{") or body.strip().startswith("["))
        f["is_form_body"] = float("=" in body and not f["is_json_body"])
        f["log_url_len"] = math.log1p(len(url))
        f["log_query_len"] = math.log1p(len(query))
        f["log_body_len"] = math.log1p(len(body))

        # B
        f["entropy"] = shannon_entropy(raw_all)
        f["digit_ratio"] = sum(c.isdigit() for c in raw_all) / total
        f["alpha_ratio"] = sum(c.isalpha() for c in raw_all) / total
        f["upper_ratio"] = sum(c.isupper() for c in raw_all) / total
        f["nonalnum_ratio"] = sum(not c.isalnum() and not c.isspace() for c in raw_all) / total
        f["urlencode_ratio"] = raw_all.count("%") / total
        f["max_repeat"] = max_repeat_run(raw_all)
        f["num_tokens"] = n_tok
        f["log_num_tokens"] = math.log1p(n_tok)
        f["avg_token_len"] = avg_tok
        f["max_token_len"] = max_tok

        # C
        for prefix, (s, w) in (("sql", (sql_s, sql_w)), ("xss", (xss_s, xss_w)),
                               ("cmd", (cmd_s, cmd_w)), ("trav", (trv_s, trv_w))):
            f[f"{prefix}_strong_present"] = float(s > 0)
            f[f"{prefix}_strong_log"] = math.log1p(s)
            f[f"{prefix}_strong_r"] = s / tok_den
            f[f"{prefix}_weak_r"] = w / tok_den

        # D
        f["has_or_1eq1"] = float(bool(re.search(
            r"\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", low_all)))
        f["has_comment"] = float(("--" in low_all) or ("/*" in low_all))
        f["has_union_select"] = float(bool(re.search(r"union\s+(all\s+)?select", low_all)))
        f["random_case_sql"] = float(any(
            (kw in url and kw.upper() in url and kw.title() not in url)
            for kw in ("select", "union", "from", "where")))

        # E
        f["quote_imbalance"] = abs(n_single - n_double) / total
        f["paren_imbalance"] = abs(n_lparen - n_rparen) / total
        f["max_delim_run"] = max_run_over(raw_all, DELIM_CHARS)
        f["double_encode"] = _count_any(raw_all, ["%25"]) / total
        f["hex_escape"] = float(("0x" in low_all) or ("\\x" in low_all))
        f["val_len_avg"] = math.log1p(val_total / n_val) if n_val else 0.0
        f["val_len_max"] = math.log1p(val_max)
        f["val_special_r"] = (val_spec / val_total) if val_total else 0.0

        # F 特殊字符占比
        for ch, name in SPECIAL_CHARS:
            f[f"{name}_r"] = raw_all.count(ch) / total

        vec = [f.get(n, 0.0) for n in self._base]
        if self.include_ngram:
            vec += self._ngram_vec(raw_all)
        return vec

    def transform_batch(self, reqs: List[Dict[str, str]]) -> List[List[float]]:
        return [self.transform(r) for r in reqs]

    # -- 轻量"嵌入"通道：字符 3-gram 哈希（PRD 5.3 通道二的可落地近似）--
    def _ngram_vec(self, s: str) -> List[float]:
        vec = [0.0] * self.ngram_dim
        s = s.lower()
        for i in range(len(s) - 2):
            g = s[i:i + 3]
            h = (hash(g) & 0x7FFFFFFF) % self.ngram_dim
            vec[h] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]
