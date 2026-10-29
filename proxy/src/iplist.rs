//! IP 黑白名单（采集器侧，随 `--reload-interval` 热重载）。
//!
//! 文件：`<artifacts>/ip_lists.json`
//! ```json
//! {"schema":1,"version":1790000000000,
//!  "whitelist":["10.0.0.5","192.168.1.0/24"],
//!  "blacklist":["1.2.3.4"]}
//! ```
//! 支持 IPv4/IPv6 单地址与 CIDR。匹配是线性的（名单通常几百条），每请求开销可忽略。
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

pub const FILE: &str = "ip_lists.json";

#[derive(Debug, Clone, Copy)]
pub(crate) enum Rule {
    V4(u32, u32),
    V6(u128, u128),
}

impl Rule {
    fn matches(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Rule::V4(net, mask), IpAddr::V4(a)) => (u32::from(a) & mask) == net,
            (Rule::V6(net, mask), IpAddr::V6(a)) => (u128::from(a) & mask) == net,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IpList {
    #[allow(dead_code)]
    pub version: u64,
    pub(crate) whitelist: Vec<Rule>,
    pub(crate) blacklist: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Doc {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    whitelist: Vec<String>,
    #[serde(default)]
    blacklist: Vec<String>,
}

fn parse_rule(s: &str) -> Result<Rule, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("空条目".to_string());
    }
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => {
            let p: u8 = p.trim().parse().map_err(|_| format!("非法前缀：{s}"))?;
            (a.trim(), Some(p))
        }
        None => (s, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("非法 IP/CIDR：{s}"))?;
    match ip {
        IpAddr::V4(a) => {
            let p = prefix.unwrap_or(32);
            if p > 32 {
                return Err(format!("IPv4 前缀越界：{s}"));
            }
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            Ok(Rule::V4(u32::from(a) & mask, mask))
        }
        IpAddr::V6(a) => {
            let p = prefix.unwrap_or(128);
            if p > 128 {
                return Err(format!("IPv6 前缀越界：{s}"));
            }
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            Ok(Rule::V6(u128::from(a) & mask, mask))
        }
    }
}

fn parse_list(items: &[String]) -> (Vec<Rule>, Vec<String>) {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for s in items {
        match parse_rule(s) {
            Ok(r) => out.push(r),
            Err(e) => errs.push(e),
        }
    }
    (out, errs)
}

impl IpList {
    /// 解析文件内容。**任意一条非法不会让整份名单失效**：跳过并返回警告。
    pub fn from_json(text: &str) -> Result<(Self, Vec<String>), String> {
        let doc: Doc = serde_json::from_str(text).map_err(|e| format!("JSON 解析失败：{e}"))?;
        let (whitelist, mut errs) = parse_list(&doc.whitelist);
        let (blacklist, e2) = parse_list(&doc.blacklist);
        errs.extend(e2);
        Ok((
            IpList {
                version: doc.version,
                whitelist,
                blacklist,
            },
            errs,
        ))
    }

    pub fn load(path: &Path) -> Result<(Self, Vec<String>), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("读取名单失败：{e}"))?;
        Self::from_json(&text)
    }

    pub fn is_whitelisted(&self, ip: &str) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(a) => self.whitelist.iter().any(|r| r.matches(a)),
            Err(_) => false,
        }
    }

    pub fn is_blacklisted(&self, ip: &str) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(a) => self.blacklist.iter().any(|r| r.matches(a)),
            Err(_) => false,
        }
    }

    pub fn n_white(&self) -> usize {
        self.whitelist.len()
    }

    pub fn n_black(&self) -> usize {
        self.blacklist.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> IpList {
        let (l, errs) = IpList::from_json(
            r#"{"version":7,"whitelist":["10.0.0.5","192.168.1.0/24"],
                "blacklist":["1.2.3.4","203.0.113.0/24","2001:db8::/32"]}"#,
        )
        .unwrap();
        assert!(errs.is_empty());
        l
    }

    #[test]
    fn exact_and_cidr_v4() {
        let l = list();
        assert!(l.is_whitelisted("10.0.0.5"));
        assert!(!l.is_whitelisted("10.0.0.6"));
        assert!(l.is_whitelisted("192.168.1.200"));
        assert!(l.is_blacklisted("1.2.3.4"));
        assert!(l.is_blacklisted("203.0.113.9"));
        assert!(!l.is_blacklisted("203.0.114.9"));
    }

    #[test]
    fn v6_cidr() {
        let l = list();
        assert!(l.is_blacklisted("2001:db8::1"));
        assert!(!l.is_blacklisted("2001:db9::1"));
        assert!(!l.is_blacklisted("not-an-ip"));
    }

    #[test]
    fn invalid_entries_are_skipped_not_fatal() {
        let (l, errs) = IpList::from_json(
            r#"{"whitelist":["10.0.0.1","bad","10.0.0.0/33"],"blacklist":[]}"#,
        )
        .unwrap();
        assert_eq!(l.n_white(), 1);
        assert_eq!(errs.len(), 2);
    }
}