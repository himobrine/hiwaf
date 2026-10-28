"""结构化特征通道 (PRD 5.3 双通道特征 - 通道一)。

从单条 HTTP 请求中抽取数值特征，供 XGBoost / Isolation Forest 使用。
设计目标：纯 CPU、微秒级、无外部依赖。
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# 关键字字典（作为输入特征，PRD 5.5：把规则信号喂给模型）
SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "from",
    "where", "or", "and", "concat", "information_schema", "sleep",
    "benchmark", "exec", "cast", "declare", "char(", "0x", "--", "/*",
]
XSS_KEYWORDS = [
    "script", "javascript", "onerror", "onload", "onclick", "alert",
    "eval", "document.cookie", "iframe", "svg", "img", "prompt", "confirm",
    "<", ">", "\"", "'",
]
CMD_KEYWORDS = [
    "cat", "ls", "whoami", "id", "curl", "wget", "nc", "bash", "sh",
    "cmd", "powershell", "ping", "kill", "chmod", "|", ";", "`", "$(",
    "&&", ">&",
]
TRAVERSAL_KEYWORDS = [
    "../", "..\\", "/etc/passwd", "boot.ini", "win.ini", "%2e%2e",
    "%2f", "....//", "..%2f", "\\..\\",
]

SPECIAL_CHARS = list("'\"`<>(){}[];,=%&/\\\\.: -+*!#$|@~^\t\n")

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


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


def _count_any(hay: str, needles: List[str]) -> int:
    return sum(hay.count(n) for n in needles)


class FeatureExtractor:
    """抽取 ~48 维结构化特征。"""

    def __init__(self, include_ngram: bool = False, ngram_dim: int = 128):
        self.include_ngram = include_ngram
        self.ngram_dim = ngram_dim
        self._base = self._base_names()
        self.names: List[str] = list(self._base)
        if include_ngram:
            self.names += [f"ng_{i}" for i in range(ngram_dim)]

    # -- 基础数值特征 -----------------------------------------------------
    @staticmethod
    def _base_names() -> List[str]:
        base = ["method_id", "url_len", "path_len", "query_len", "body_len",
                "num_params", "num_special", "digit_ratio", "alpha_ratio",
                "upper_ratio", "nonalnum_ratio", "entropy", "max_token_len",
                "max_repeat", "urlencode_ratio", "num_tokens", "avg_token_len",
                "num_slashes", "num_dots", "num_percent", "num_null",
                "num_newline", "num_quote", "num_angle", "num_paren",
                "num_semicolon", "num_pipe", "num_amp", "num_backtick",
                "num_dollar", "sql_score", "xss_score", "cmd_score",
                "traversal_score", "has_or_1eq1", "has_comment",
                "has_union_select", "random_case_sql", "path_depth",
                "ext_len", "has_query", "has_body", "is_json_body",
                "is_form_body"]
        base += [f"sc_{i}" for i in range(len(SPECIAL_CHARS))]
        return base

    def transform(self, req: Dict[str, str]) -> List[float]:
        method = (req.get("method") or "GET").upper()
        path = req.get("path") or ""
        query = req.get("query") or ""
        body = req.get("body") or ""
        url = path + ("?" + query if query else "")

        low_url = url.lower()
        low_body = body.lower()
        low_all = low_url + " " + low_body
        raw_all = url + " " + body

        params = 0
        if query:
            params += max(1, len([p for p in query.split("&") if p]))
        if body:
            params += max(1, len([p for p in re.split(r"[&\n]", body) if p]))

        toks = _TOKEN_RE.findall(raw_all)
        n_tok = len(toks)
        avg_tok = (sum(len(t) for t in toks) / n_tok) if n_tok else 0.0
        total = len(raw_all) or 1

        f: Dict[str, float] = {}
        f["method_id"] = float(METHODS.index(method)) if method in METHODS else -1.0
        f["url_len"] = len(url)
        f["path_len"] = len(path)
        f["query_len"] = len(query)
        f["body_len"] = len(body)
        f["num_params"] = params
        f["num_special"] = sum(raw_all.count(c) for c in SPECIAL_CHARS)
        f["digit_ratio"] = sum(c.isdigit() for c in raw_all) / total
        f["alpha_ratio"] = sum(c.isalpha() for c in raw_all) / total
        f["upper_ratio"] = sum(c.isupper() for c in raw_all) / total
        f["nonalnum_ratio"] = sum(not c.isalnum() and not c.isspace() for c in raw_all) / total
        f["entropy"] = shannon_entropy(raw_all)
        f["max_token_len"] = max((len(t) for t in toks), default=0)
        f["max_repeat"] = max_repeat_run(raw_all)
        f["urlencode_ratio"] = raw_all.count("%") / total
        f["num_tokens"] = n_tok
        f["avg_token_len"] = avg_tok
        f["num_slashes"] = raw_all.count("/") + raw_all.count("\\")
        f["num_dots"] = raw_all.count(".")
        f["num_percent"] = raw_all.count("%")
        f["num_null"] = raw_all.count("\x00") + raw_all.count("%00")
        f["num_newline"] = raw_all.count("\n") + raw_all.count("\r") + raw_all.count("%0a")
        f["num_quote"] = raw_all.count("'") + raw_all.count('"') + raw_all.count("`")
        f["num_angle"] = raw_all.count("<") + raw_all.count(">")
        f["num_paren"] = raw_all.count("(") + raw_all.count(")")
        f["num_semicolon"] = raw_all.count(";")
        f["num_pipe"] = raw_all.count("|")
        f["num_amp"] = raw_all.count("&")
        f["num_backtick"] = raw_all.count("`")
        f["num_dollar"] = raw_all.count("$")

        sql_hits = _count_any(low_all, SQL_KEYWORDS)
        xss_hits = _count_any(low_all, XSS_KEYWORDS)
        cmd_hits = _count_any(low_all, CMD_KEYWORDS)
        trav_hits = _count_any(low_all, TRAVERSAL_KEYWORDS)
        f["sql_score"] = float(sql_hits)
        f["xss_score"] = float(xss_hits)
        f["cmd_score"] = float(cmd_hits)
        f["traversal_score"] = float(trav_hits)

        f["has_or_1eq1"] = float(bool(re.search(r"\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", low_all)))
        f["has_comment"] = float(("--" in low_all) or ("/*" in low_all) or ("#" in low_all))
        f["has_union_select"] = float(bool(re.search(r"union\s+(all\s+)?select", low_all)))
        # SQL 关键字大小写混乱（绕过特征）
        sql_random_case = float(any(
            (kw in url and kw.upper() in url and kw.title() not in url)
            for kw in ("select", "union", "from", "where")
        ))
        f["random_case_sql"] = sql_random_case
        f["path_depth"] = path.count("/")
        f["ext_len"] = len(path.rsplit(".", 1)[-1]) if "." in path.rsplit("/", 1)[-1] else 0
        f["has_query"] = float(bool(query))
        f["has_body"] = float(bool(body))
        f["is_json_body"] = float(body.strip().startswith("{") or body.strip().startswith("["))
        f["is_form_body"] = float("=" in body and not f["is_json_body"])

        for i, c in enumerate(SPECIAL_CHARS):
            f[f"sc_{i}"] = float(raw_all.count(c))

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
