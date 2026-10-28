//! 规则层文本解码（**与 Python `urllib.parse.unquote_plus` 逐字节等价**）。
//!
//! 为什么必须等价而不仅仅是"差不多"：`p7_rule_mining.py` 的规则去留（7 keep / 6 reject_fp）
//! 是在 Python 侧量出来的，而线上判定在 Rust 侧。两侧解码一旦漂移，就会出现
//! "Python 说这条规则 0 误报、线上却在报"的静默错配 —— 这是本项目最不能接受的一类 bug。
//!
//! `unquote_plus` 的确切语义（CPython `urllib/parse.py`）：
//!   1. `+` → 空格；
//!   2. 把字符串整体按 UTF-8 编成字节；
//!   3. 按 `%` 切分；对第 2..n 段，若前两个字节都是十六进制数字，则转成 1 个字节，
//!      否则原样补回 `%` + 该段；
//!   4. 字节整体按 UTF-8 解码，非法序列 → U+FFFD；
//!   5. **若原串不含 `%`，第 2-4 步整体跳过**（原串原样返回）。
//!
//! DSL 的解码流水线固定为 `urlencoded`（最多两遍，兼容双重编码）+ `unicode`（`\uXXXX`）。
//! 收窄是有意的：json / multipart 按原文匹配，只额外解 `\uXXXX`。

/// 解码阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStage {
    Urlencoded,
    Unicode,
    /// 不做任何解码。**只用于对照实验**（量"解码到底值多少"，即 p7 的 decoding_gain），
    /// 出现它就清空整条流水线。
    Raw,
}

impl DecodeStage {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "urlencoded" | "url" | "percent" => Some(Self::Urlencoded),
            "unicode" | "json-unicode" | "u" => Some(Self::Unicode),
            "raw" | "none" | "off" => Some(Self::Raw),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Urlencoded => "urlencoded",
            Self::Unicode => "unicode",
            Self::Raw => "raw",
        }
    }
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `urllib.parse.unquote_plus` 的等价实现。
pub fn unquote_plus(s: &str) -> String {
    // 第 1 步：`+` → 空格。`replace('+',' ')` 不会新增/删除 `%`，所以先做不影响第 5 步判断。
    let s = if s.contains('+') { s.replace('+', " ") } else { s.to_string() };
    // 第 5 步：不含 `%` 直接返回（Python 里是 `if '%' not in string: return string`）。
    if !s.contains('%') {
        return s;
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 < b.len() {
                if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
            }
            out.push(b'%');
            i += 1;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 解 `\uXXXX` / `\UXXXXXXXX`（JSON 风格）。其余转义（`\n`、`\"` 等）**原样保留**：
/// 只做最小变换，避免把良性文本改造成看起来像攻击的样子。
///
/// 代理对（`\uD83D\uDE00`）合并成单个码点；落单的代理码位输出 U+FFFD。
pub fn unescape_unicode(s: &str) -> String {
    if !s.contains("\\u") && !s.contains("\\U") {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if b[i + 1] == b'u' && i + 5 < b.len() {
                if let Some(cp) = parse_hex(b, i + 2, 4) {
                    i += 6;
                    // 高代理 + 低代理 → 合并
                    if (0xD800..=0xDBFF).contains(&cp)
                        && i + 5 < b.len()
                        && b[i] == b'\\' && b[i + 1] == b'u'
                    {
                        if let Some(lo) = parse_hex(b, i + 2, 4) {
                            if (0xDC00..=0xDFFF).contains(&lo) {
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                                i += 6;
                                continue;
                            }
                        }
                    }
                    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    continue;
                }
            } else if b[i + 1] == b'U' && i + 9 < b.len() {
                if let Some(cp) = parse_hex(b, i + 2, 8) {
                    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    i += 10;
                    continue;
                }
            }
        }
        // 按字符推进（多字节序列不能从中间切开）
        let ch = s[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn parse_hex(b: &[u8], start: usize, n: usize) -> Option<u32> {
    if start + n > b.len() {
        return None;
    }
    let mut v: u32 = 0;
    for k in 0..n {
        let d = hex_val(b[start + k])?;
        v = (v << 4) | d as u32;
    }
    Some(v)
}

/// 按阶段跑解码流水线。每个阶段最多两遍（兼容双重编码），不再变化即停。
pub fn decode_rule_text(s: &str, stages: &[DecodeStage]) -> String {
    let mut t = s.to_string();
    for st in stages {
        match st {
            DecodeStage::Urlencoded => {
                for _ in 0..2 {
                    let n = unquote_plus(&t);
                    if n == t {
                        break;
                    }
                    t = n;
                }
            }
            DecodeStage::Unicode => {
                for _ in 0..2 {
                    let n = unescape_unicode(&t);
                    if n == t {
                        break;
                    }
                    t = n;
                }
            }
            // `Raw` 由 `RuleEngine::compile` 在构建引擎时就清空了，这里只是兜底。
            DecodeStage::Raw => {}
        }
    }
    t
}

/// 把控制字符换成空格，便于入库与展示（不改动可见字符）。
pub fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unquote_plus_matches_python_semantics() {
        assert_eq!(unquote_plus("q=a+b"), "q=a b");
        assert_eq!(unquote_plus("%27%20or%201%3D1"), "' or 1=1");
        assert_eq!(unquote_plus("a%2"), "a%2");
        assert_eq!(unquote_plus("a%2zb"), "a%2zb");
        assert_eq!(unquote_plus("%%41"), "%A");
        assert_eq!(unquote_plus("plain"), "plain");
        // 双重编码：%2527 → %27 → '
        assert_eq!(unquote_plus(&unquote_plus("%2527")), "'");
        // 非 ASCII 原样保留
        assert_eq!(unquote_plus("中文%20x"), "中文 x");
    }

    #[test]
    fn unicode_unescape() {
        assert_eq!(unescape_unicode("\\u003cscript\\u003e"), "<script>");
        assert_eq!(unescape_unicode("a\\n b"), "a\\n b");
        assert_eq!(unescape_unicode("\\ud83d\\ude00"), "😀");
        assert_eq!(unescape_unicode("\\u4e2d"), "中");
        assert_eq!(unescape_unicode("\\U0001F600"), "😀");
    }

    #[test]
    fn pipeline() {
        let st = [DecodeStage::Urlencoded, DecodeStage::Unicode];
        assert_eq!(decode_rule_text("%5Cu003cscript", &st), "<script");
        // 不启用 unicode 阶段时保持原样
        assert_eq!(decode_rule_text("%5Cu003cscript", &[DecodeStage::Urlencoded]), "\\u003cscript");
    }
}
