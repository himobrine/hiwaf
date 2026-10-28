//! 特征提取的 Rust 移植，对齐 `python/features.py` **v2** 的 80 维结构化通道。
//!
//! 特征顺序（必须与 Python `FeatureExtractor._base_names()` 完全一致）：
//!   A 请求形态 11  B 组成/熵 11  C 关键词 16  D 攻击模式 4  E 结构/语法 8  F 特殊字符占比 30
//!
//! 只用整数计数与初等浮点运算（`ln_1p` / `log2`），保证跨语言可复现。

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

pub const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

// 关键词词典（v2：强/弱 × 词/符号）。词表按**整个 token**匹配，符号表按**子串**匹配。
pub const SQL_STRONG_WORDS: &[&str] = &[
    "select", "union", "insert", "update", "delete", "drop", "information_schema",
    "concat", "benchmark", "sleep", "declare", "load_file", "outfile", "having",
    "extractvalue", "updatexml", "waitfor", "exec",
];
pub const SQL_WEAK_WORDS: &[&str] = &["from", "where", "or", "and", "char", "null", "cast"];
pub const SQL_STRONG_SYMS: &[&str] = &["/*", "--", "0x"];
pub const SQL_WEAK_SYMS: &[&str] = &[];

pub const XSS_STRONG_WORDS: &[&str] = &[
    "script", "javascript", "onerror", "onload", "onclick", "onmouseover",
    "onfocus", "onmouseout", "alert", "prompt", "confirm", "iframe",
];
pub const XSS_WEAK_WORDS: &[&str] = &["img", "svg", "body", "input", "style", "src", "href"];
pub const XSS_STRONG_SYMS: &[&str] = &[
    "<script", "javascript:", "onerror=", "onload=", "document.cookie",
    "%3cscript", "<img", "<svg",
];
pub const XSS_WEAK_SYMS: &[&str] = &["<", ">", "%3c", "%3e"];

pub const CMD_STRONG_WORDS: &[&str] = &[
    "whoami", "powershell", "netcat", "passthru", "popen", "shell_exec",
    "wget", "curl", "chmod", "bash",
];
pub const CMD_WEAK_WORDS: &[&str] = &[
    "cat", "ls", "id", "sh", "cmd", "ping", "kill", "echo", "dir", "type", "passwd", "rm",
];
pub const CMD_STRONG_SYMS: &[&str] = &["$(", "`", "&&", "||", "/bin/", "/etc/passwd", "cmd.exe"];
pub const CMD_WEAK_SYMS: &[&str] = &["|", ";"];

pub const TRAV_STRONG_WORDS: &[&str] = &[];
pub const TRAV_WEAK_WORDS: &[&str] = &[];
pub const TRAV_STRONG_SYMS: &[&str] = &[
    "../", "..\\", "....//", "%2e%2e", "..%2f", "..%5c",
    "/etc/passwd", "boot.ini", "win.ini", "/proc/self",
];
pub const TRAV_WEAK_SYMS: &[&str] = &["%2f", "%5c"];

/// 特殊字符占比（与该字符对应的特征名后缀），30 个
pub const SPECIAL_CHARS: [(char, &str); 30] = [
    ('\'', "quote"), ('"', "dquote"), ('`', "backtick"), ('<', "lt"), ('>', "gt"),
    ('(', "lparen"), (')', "rparen"), ('{', "lbrace"), ('}', "rbrace"),
    ('[', "lbracket"), (']', "rbracket"), (';', "semicolon"), (',', "comma"),
    ('=', "eq"), ('%', "percent"), ('&', "amp"), ('/', "slash"), ('\\', "backslash"),
    ('.', "dot"), (':', "colon"), ('-', "hyphen"), ('+', "plus"), ('*', "star"),
    ('!', "bang"), ('#', "hash"), ('$', "dollar"), ('|', "pipe"), ('@', "at"),
    ('~', "tilde"), ('^', "caret"),
];

/// 参数值里被视为「结构性」的字符（用于 val_special_r）
pub const VALUE_SPECIAL: &str = "'\"<>=;(){}[]|&%";
/// 分隔符连跑（注入语句常见 `;;`、`||`、`,,`）
pub const DELIM_CHARS: &str = ";|&,";

pub const FEATURE_DIM: usize = 80;

#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: String,
}

impl Request {
    pub fn from_json(v: &Value) -> Self {
        let g = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        Request {
            method: g("method"),
            path: g("path"),
            query: g("query"),
            body: g("body"),
        }
    }
}

fn count(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    hay.matches(needle).count()
}

fn count_any(hay: &str, needles: &[&str]) -> usize {
    needles.iter().map(|n| count(hay, n)).sum()
}

/// Python 语义的 Shannon 熵：按字符统计
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len() as f64;
    let mut order: Vec<char> = Vec::new();
    let mut counts: Vec<f64> = Vec::new();
    for &c in &chars {
        if let Some(i) = order.iter().position(|&x| x == c) {
            counts[i] += 1.0;
        } else {
            order.push(c);
            counts.push(1.0);
        }
    }
    let mut sum = 0.0;
    for c in counts {
        let p = c / n;
        sum += p * p.log2();
    }
    -sum
}

fn max_repeat_run(s: &str) -> usize {
    let mut best = 0usize;
    let mut run = 0usize;
    let mut prev = None;
    for c in s.chars() {
        if Some(c) == prev {
            run += 1;
        } else {
            run = 1;
            prev = Some(c);
        }
        if run > best {
            best = run;
        }
    }
    best
}

/// `s` 中只由 `chars` 组成的连续片段的最大长度
fn max_run_over(s: &str, chars: &str) -> usize {
    let mut best = 0usize;
    let mut run = 0usize;
    for c in s.chars() {
        if chars.contains(c) {
            run += 1;
            if run > best {
                best = run;
            }
        } else {
            run = 0;
        }
    }
    best
}

fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// 返回 (strong_hits, weak_hits)
fn cat_hits(
    low_all: &str,
    tok: &HashMap<String, usize>,
    strong_words: &[&str],
    weak_words: &[&str],
    strong_syms: &[&str],
    weak_syms: &[&str],
) -> (usize, usize) {
    let strong: usize = strong_words.iter().map(|w| tok.get(*w).copied().unwrap_or(0)).sum::<usize>()
        + count_any(low_all, strong_syms);
    let weak: usize = weak_words.iter().map(|w| tok.get(*w).copied().unwrap_or(0)).sum::<usize>()
        + count_any(low_all, weak_syms);
    (strong, weak)
}

/// 取出所有参数值：`k=v` 取 v；无 `=` 取空串
fn param_values(query: &str, body: &str) -> Vec<String> {
    let mut vals: Vec<String> = Vec::new();
    let mut take = |p: &str| {
        if p.is_empty() {
            return;
        }
        match p.split_once('=') {
            Some((_, v)) => vals.push(v.to_string()),
            None => vals.push(String::new()),
        }
    };
    if !query.is_empty() {
        for p in query.split('&') {
            take(p);
        }
    }
    if !body.is_empty() {
        for p in body.split(|c| c == '&' || c == '\n') {
            take(p);
        }
    }
    vals
}

fn has_or_1eq1_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bor\b\s*['"]?\d+['"]?\s*=\s*['"]?\d+"#).unwrap())
}

fn has_union_select_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"union\s+(all\s+)?select").unwrap())
}

fn title_case(w: &str) -> String {
    let mut c = w.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// 抽取 80 维特征（与 Python v2 逐位对齐）
pub fn extract(req: &Request) -> Vec<f32> {
    let method = {
        let m = if req.method.is_empty() { "GET" } else { &req.method };
        m.to_uppercase()
    };
    let path = req.path.as_str();
    let query = req.query.as_str();
    let body = req.body.as_str();

    let url = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let raw_all = format!("{url} {body}");
    let low_all = raw_all.to_lowercase();

    // -- num_params --
    let mut params = 0usize;
    if !query.is_empty() {
        params += query.split('&').filter(|p| !p.is_empty()).count().max(1);
    }
    if !body.is_empty() {
        params += body
            .split(|c| c == '&' || c == '\n')
            .filter(|p| !p.is_empty())
            .count()
            .max(1);
    }

    // -- token 统计 --
    let mut tok: HashMap<String, usize> = HashMap::new();
    let mut n_tok = 0usize;
    let mut sum_tok_len = 0usize;
    let mut max_tok_len = 0usize;
    let mut cur = 0usize;
    let flush = |cur: &mut usize, tok: &mut HashMap<String, usize>,
                     n_tok: &mut usize, sum: &mut usize, mx: &mut usize, buf: &str| {
        if *cur > 0 {
            *n_tok += 1;
            *sum += *cur;
            if *cur > *mx {
                *mx = *cur;
            }
            *tok.entry(buf.to_lowercase()).or_insert(0) += 1;
            *cur = 0;
        }
    };
    let mut buf = String::new();
    for c in raw_all.chars() {
        if token_char(c) {
            cur += 1;
            buf.push(c);
        } else {
            flush(&mut cur, &mut tok, &mut n_tok, &mut sum_tok_len, &mut max_tok_len, &buf);
            buf.clear();
        }
    }
    flush(&mut cur, &mut tok, &mut n_tok, &mut sum_tok_len, &mut max_tok_len, &buf);

    let avg_tok = if n_tok > 0 {
        sum_tok_len as f64 / n_tok as f64
    } else {
        0.0
    };
    let tok_den = if n_tok > 0 { n_tok } else { 1 };

    let total = {
        let l = raw_all.chars().count();
        if l == 0 { 1 } else { l }
    } as f64;

    // -- 关键词命中 --
    let (sql_s, sql_w) = cat_hits(&low_all, &tok, SQL_STRONG_WORDS, SQL_WEAK_WORDS,
                                  SQL_STRONG_SYMS, SQL_WEAK_SYMS);
    let (xss_s, xss_w) = cat_hits(&low_all, &tok, XSS_STRONG_WORDS, XSS_WEAK_WORDS,
                                  XSS_STRONG_SYMS, XSS_WEAK_SYMS);
    let (cmd_s, cmd_w) = cat_hits(&low_all, &tok, CMD_STRONG_WORDS, CMD_WEAK_WORDS,
                                  CMD_STRONG_SYMS, CMD_WEAK_SYMS);
    let (trv_s, trv_w) = cat_hits(&low_all, &tok, TRAV_STRONG_WORDS, TRAV_WEAK_WORDS,
                                  TRAV_STRONG_SYMS, TRAV_WEAK_SYMS);

    // -- 参数值统计 --
    let vals = param_values(query, body);
    let n_val = vals.len();
    let mut val_total = 0usize;
    let mut val_max = 0usize;
    let mut val_spec = 0usize;
    for v in &vals {
        val_total += v.chars().count();
        val_max = val_max.max(v.chars().count());
        val_spec += v.chars().filter(|c| VALUE_SPECIAL.contains(*c)).count();
    }

    // -- 语法结构 --
    let n_single = count(&raw_all, "'");
    let n_double = count(&raw_all, "\"");
    let n_lparen = count(&raw_all, "(");
    let n_rparen = count(&raw_all, ")");

    let digit = raw_all.chars().filter(|c| c.is_ascii_digit()).count() as f64;
    let alpha = raw_all.chars().filter(|c| c.is_ascii_alphabetic()).count() as f64;
    let upper = raw_all.chars().filter(|c| c.is_ascii_uppercase()).count() as f64;
    let nonalnum = raw_all
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric() && !c.is_ascii_whitespace())
        .count() as f64;

    let is_json = (body.trim_start().starts_with('{') || body.trim_start().starts_with('['))
        as i32 as f64;
    let is_form = (body.contains('=') && is_json == 0.0) as i32 as f64;

    let random_case_sql = ["select", "union", "from", "where"]
        .iter()
        .any(|kw| {
            url.contains(kw) && url.contains(&kw.to_uppercase()) && !url.contains(&title_case(kw))
        }) as i32 as f64;

    let has_or = has_or_1eq1_re().is_match(&low_all) as i32 as f64;
    let has_comment = (low_all.contains("--") || low_all.contains("/*")) as i32 as f64;
    let has_union = has_union_select_re().is_match(&low_all) as i32 as f64;

    let path_depth = path.matches('/').count();
    let seg = path.rsplitn(2, '/').next().unwrap_or("");
    let ext_len = if seg.contains('.') {
        seg.rsplitn(2, '.').next().unwrap_or("").chars().count()
    } else {
        0
    };

    let mut f: Vec<f32> = Vec::with_capacity(FEATURE_DIM);
    macro_rules! push {
        ($v:expr) => {
            f.push(($v) as f32)
        };
    }

    // A 请求形态（11）
    let method_id = METHODS
        .iter()
        .position(|m| *m == method)
        .map(|i| i as f64)
        .unwrap_or(-1.0);
    push!(method_id);
    push!(path_depth);
    push!(ext_len);
    push!(params);
    push!((!query.is_empty()) as i32);
    push!((!body.is_empty()) as i32);
    push!(is_form);
    push!(is_json);
    push!((url.chars().count() as f64).ln_1p());
    push!((query.chars().count() as f64).ln_1p());
    push!((body.chars().count() as f64).ln_1p());

    // B 组成 / 熵（11）
    push!(shannon_entropy(&raw_all));
    push!(digit / total);
    push!(alpha / total);
    push!(upper / total);
    push!(nonalnum / total);
    push!(count(&raw_all, "%") as f64 / total);
    push!(max_repeat_run(&raw_all));
    push!(n_tok);
    push!((n_tok as f64).ln_1p());
    push!(avg_tok);
    push!(max_tok_len);

    // C 关键词（16）
    for (s, w) in [(sql_s, sql_w), (xss_s, xss_w), (cmd_s, cmd_w), (trv_s, trv_w)] {
        push!((s > 0) as i32);
        push!((s as f64).ln_1p());
        push!(s as f64 / tok_den as f64);
        push!(w as f64 / tok_den as f64);
    }

    // D 攻击模式（4）
    push!(has_or);
    push!(has_comment);
    push!(has_union);
    push!(random_case_sql);

    // E 结构 / 语法（8）
    push!((n_single as i64 - n_double as i64).unsigned_abs() as f64 / total);
    push!((n_lparen as i64 - n_rparen as i64).unsigned_abs() as f64 / total);
    push!(max_run_over(&raw_all, DELIM_CHARS));
    push!(count(&raw_all, "%25") as f64 / total);
    push!((low_all.contains("0x") || low_all.contains("\\x")) as i32);
    push!(if n_val > 0 { (val_total as f64 / n_val as f64).ln_1p() } else { 0.0 });
    push!((val_max as f64).ln_1p());
    push!(if val_total > 0 { val_spec as f64 / val_total as f64 } else { 0.0 });

    // F 特殊字符占比（30）
    for (c, _name) in SPECIAL_CHARS.iter() {
        let s = c.to_string();
        push!(count(&raw_all, &s) as f64 / total);
    }

    debug_assert_eq!(f.len(), FEATURE_DIM);
    f
}
