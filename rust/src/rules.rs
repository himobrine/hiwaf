//! 规则通道引擎（并列第三通道）。
//!
//! 设计要点（与 `REALDATA_EVALUATION.md` / 控制面 `python/service/rules_dsl.py` 对齐）：
//!
//! * **不是**「规则 → AI」串行管线，而是并列第三通道 + 校准融合。串行会把规则的误报
//!   变成整个系统的误报下限，还会短路学习回路（模型已经内置了大量词法特征）。
//! * 规则跑在**解码后**文本上（`decode` 模块）。实测不解码时 `union_select` 在 25,213 条
//!   真实攻击上命中 **0** —— 解码不是优化，是可用性的前提。
//! * 匹配文本与 `p7_rule_mining.py` / `features.py` 同源：默认 scope `full` =
//!   `METHOD path?query body`（`?` 是字面量、恒在），这样 p7 的规则去留（7 keep / 6 reject_fp）
//!   是可复现的回归锚点，而不是一段无法验证的历史。
//! * `weight` 是**唯一的记分输入**；`severity` 只用于展示。
//! * `action ∈ {alert, block}` 逐条设定；只有 `block` 规则消耗阻断预算。
//! * 每条命中的 `snippet` 会写进 `event_rules`，属于**证据**，**不是标签**。

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::decode::{decode_rule_text, sanitize_for_log, DecodeStage};

// --------------------------------------------------------------------------- 作用域
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Full,
    Path,
    Query,
    Body,
    Ua,
    Referer,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "full" | "all" => Some(Self::Full),
            "path" | "uri" => Some(Self::Path),
            "query" | "args" => Some(Self::Query),
            "body" | "payload" => Some(Self::Body),
            "ua" | "user-agent" | "user_agent" => Some(Self::Ua),
            "referer" | "referrer" => Some(Self::Referer),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Path => "path",
            Self::Query => "query",
            Self::Body => "body",
            Self::Ua => "ua",
            Self::Referer => "referer",
        }
    }

    fn idx(&self) -> usize {
        match self {
            Self::Full => 0,
            Self::Path => 1,
            Self::Query => 2,
            Self::Body => 3,
            Self::Ua => 4,
            Self::Referer => 5,
        }
    }
}

// --------------------------------------------------------------------------- 输入
#[derive(Debug, Default, Clone)]
pub struct RuleInput {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: String,
    pub ua: String,
    pub referer: String,
}

impl RuleInput {
    fn s(v: &serde_json::Value, k: &str) -> String {
        v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
    }

    pub fn from_json(v: &serde_json::Value) -> Self {
        let hdr = |name: &str| -> String {
            v.get("headers")
                .and_then(|h| h.get(name))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        let ua = {
            let direct = Self::s(v, "ua");
            if direct.is_empty() { hdr("user-agent") } else { direct }
        };
        let referer = {
            let direct = Self::s(v, "referer");
            if direct.is_empty() { hdr("referer") } else { direct }
        };
        Self {
            method: {
                let m = Self::s(v, "method");
                if m.is_empty() { "GET".to_string() } else { m.to_uppercase() }
            },
            path: Self::s(v, "path"),
            query: Self::s(v, "query"),
            body: Self::s(v, "body"),
            ua,
            referer,
        }
    }
}

// --------------------------------------------------------------------------- 规格
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default = "one_f64")]
    pub weight: f64,
    #[serde(default = "alert_s")]
    pub action: String,
}

fn one_f64() -> f64 { 1.0 }
fn alert_s() -> String { "alert".to_string() }
fn one_u32() -> u32 { 1 }

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSetSpec {
    #[serde(default = "one_u32")]
    pub schema: u32,
    #[serde(default)]
    pub ruleset_id: String,
    #[serde(default)]
    pub decode: Vec<String>,
    #[serde(default = "one_f64")]
    pub min_weight_to_block: f64,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleError {
    pub id: String,
    pub message: String,
}

// --------------------------------------------------------------------------- 命中
#[derive(Debug, Clone, Serialize)]
pub struct RuleHit {
    pub rule: String,
    pub name: String,
    pub severity: String,
    pub action: String,
    pub weight: f64,
    /// 规则实际使用的作用域（`full` / `path` / `query` / `body` / `ua` / `referer`）。
    /// `start/end` 始终是**该作用域文本**里的字节偏移；有了 scope，控制面才能把
    /// `full` 命中准确拆回各字段，而不是把全文字段偏移误当成本字段偏移。
    pub scope: String,
    /// 命中落在哪个字段（`full` 作用域下按偏移回映射到 method/path/query/body）。
    pub field: String,
    pub start: usize,
    pub end: usize,
    /// 命中片段（已做控制字符清洗 + 截断）。
    pub snippet: String,
}

// --------------------------------------------------------------------------- 引擎
struct CompiledRule {
    id: String,
    name: String,
    severity: String,
    action: String,
    weight: f64,
    scopes: Vec<Scope>,
    re: Regex,
}

pub struct RuleEngine {
    pub ruleset_id: String,
    pub schema: u32,
    pub decode: Vec<DecodeStage>,
    pub min_weight_to_block: f64,
    pub sha1_16: String,
    rules: Vec<CompiledRule>,
}

struct TextView {
    field: &'static str,
    text: String,
    /// `(字段, 起, 止)` 字节偏移；仅 `full` 非空。
    bounds: Vec<(&'static str, usize, usize)>,
}

fn one_field(name: &'static str, raw: &str, stages: &[DecodeStage]) -> TextView {
    TextView { field: name, text: decode_rule_text(raw, stages), bounds: Vec::new() }
}

fn full_view(req: &RuleInput, stages: &[DecodeStage]) -> TextView {
    // ⚠️ 与 p7 `req_text()` / features.py 同源：`{method} {path}?{query} {body}`，
    //    其中 `?` 是**字面量且恒在**（query 为空时也保留）。
    //
    // 逐段解码再拼接 == 整体解码后拼接：分隔符是单个 ASCII 字节（空格 / `?`），
    // 既不是十六进制数字、也不是 UTF-8 续字节，所以百分号三元组与多字节序列
    // 都不可能跨过分隔符成立。逐段做才有精确的字段边界。
    let dm = decode_rule_text(&req.method, stages);
    let dp = decode_rule_text(&req.path, stages);
    let dq = decode_rule_text(&req.query, stages);
    let db = decode_rule_text(&req.body, stages);

    let mut text = String::with_capacity(dm.len() + dp.len() + dq.len() + db.len() + 3);
    let mut bounds: Vec<(&'static str, usize, usize)> = Vec::with_capacity(4);
    let add = |text: &mut String, bounds: &mut Vec<(&'static str, usize, usize)>,
                   name: &'static str, s: &str| {
        let a = text.len();
        text.push_str(s);
        let b = text.len();
        bounds.push((name, a, b));
    };
    add(&mut text, &mut bounds, "method", &dm);
    text.push(' ');
    add(&mut text, &mut bounds, "path", &dp);
    text.push('?');
    add(&mut text, &mut bounds, "query", &dq);
    text.push(' ');
    add(&mut text, &mut bounds, "body", &db);
    TextView { field: "full", text, bounds }
}

fn view_for(scope: Scope, req: &RuleInput, stages: &[DecodeStage]) -> TextView {
    match scope {
        Scope::Full => full_view(req, stages),
        Scope::Path => one_field("path", &req.path, stages),
        Scope::Query => one_field("query", &req.query, stages),
        Scope::Body => one_field("body", &req.body, stages),
        Scope::Ua => one_field("ua", &req.ua, stages),
        Scope::Referer => one_field("referer", &req.referer, stages),
    }
}

fn field_of(bounds: &[(&'static str, usize, usize)], start: usize, end: usize) -> String {
    for (name, a, b) in bounds {
        if start < *b && end > *a {
            return (*name).to_string();
        }
    }
    "full".to_string()
}

fn snap_forward(text: &str, mut i: usize) -> usize {
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn snap_backward(text: &str, mut i: usize) -> usize {
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn make_snippet(text: &str, start: usize, end: usize, max_chars: usize) -> String {
    // 用「字节半径 + 边界对齐」而不是逐字符统计字符位置：命中可能很密，
    // 逐字符扫描会把回放拖慢。
    let pad = 64usize;
    let lo = snap_forward(text, start.saturating_sub(pad));
    let hi = snap_backward(text, (end + pad).min(text.len()));
    let raw = &text[lo..hi.max(lo)];
    let mut s: String = raw.chars().take(max_chars).collect();
    if raw.chars().count() > max_chars {
        s.push('…');
    }
    sanitize_for_log(&s)
}

impl RuleEngine {
    /// 编译规则集。**只返回第一个错误清单，不 panic** —— 门禁与控制台都要能拿到全部错因。
    pub fn compile(spec: &RuleSetSpec, sha1_16: String) -> Result<Self, Vec<RuleError>> {
        if spec.schema != 1 {
            return Err(vec![RuleError {
                id: "<ruleset>".into(),
                message: format!(
                    "规则集 schema 不兼容：期望 1，实际 {}（旧程序必须拒绝新结构）",
                    spec.schema
                ),
            }]);
        }
        let mut errs: Vec<RuleError> = Vec::new();
        let mut decode: Vec<DecodeStage> = Vec::new();
        let mut saw_raw = false;
        for s in &spec.decode {
            match DecodeStage::parse(s) {
                Some(DecodeStage::Raw) => saw_raw = true,
                Some(d) => {
                    if !decode.contains(&d) {
                        decode.push(d);
                    }
                }
                None => errs.push(RuleError {
                    id: "<decode>".into(),
                    message: format!("未知解码阶段 {s:?}（只支持 urlencoded / unicode / raw）"),
                }),
            }
        }
        // `raw` = 对照实验：清空整条流水线（量"解码值多少"用）。
        if saw_raw {
            decode.clear();
        }
        if !saw_raw && decode.is_empty() {
            decode.push(DecodeStage::Urlencoded);
        }
        if spec.rules.is_empty() {
            errs.push(RuleError {
                id: "<ruleset>".into(),
                message: "规则集为空：一条规则都没有的规则通道只会白耗轮询开销".into(),
            });
        }

        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        let mut rules: Vec<CompiledRule> = Vec::with_capacity(spec.rules.len());
        for (i, r) in spec.rules.iter().enumerate() {
            if let Some(prev) = seen.insert(r.id.as_str(), i) {
                errs.push(RuleError {
                    id: r.id.clone(),
                    message: format!("规则 id 重复（首次出现在第 {} 条）", prev + 1),
                });
            }
            let mut scopes: Vec<Scope> = Vec::new();
            for s in &r.scopes {
                match Scope::parse(s) {
                    Some(sc) => {
                        if !scopes.contains(&sc) {
                            scopes.push(sc);
                        }
                    }
                    None => errs.push(RuleError {
                        id: r.id.clone(),
                        message: format!("未知 scope {s:?}"),
                    }),
                }
            }
            if scopes.is_empty() {
                scopes.push(Scope::Full);
            }
            scopes.sort();
            let action = r.action.trim().to_ascii_lowercase();
            if action != "alert" && action != "block" {
                errs.push(RuleError {
                    id: r.id.clone(),
                    message: format!("action 非法：{:?}（只支持 alert / block）", r.action),
                });
            }
            match Regex::new(&r.regex) {
                Ok(re) => rules.push(CompiledRule {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    severity: r.severity.clone(),
                    action,
                    weight: r.weight,
                    scopes,
                    re,
                }),
                Err(e) => errs.push(RuleError {
                    id: r.id.clone(),
                    // regex crate 的报错信息里含语法定位，直接透出（这是权威编译器的原话）
                    message: format!("regex 编译失败：{e}"),
                }),
            }
        }

        if !errs.is_empty() {
            return Err(errs);
        }
        Ok(Self {
            ruleset_id: spec.ruleset_id.clone(),
            schema: spec.schema,
            decode,
            min_weight_to_block: spec.min_weight_to_block,
            sha1_16,
            rules,
        })
    }

    pub fn from_path(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("读不到规则集 {}：{e}", path.display()))?;
        let spec: RuleSetSpec = serde_json::from_slice(&raw)
            .map_err(|e| anyhow::anyhow!("规则集 {} 不是合法 JSON：{e}", path.display()))?;
        let sha = crate::hash::sha1_16(&raw);
        Self::compile(&spec, sha).map_err(|errs| {
            let mut m = String::from("规则集编译失败（以下由 Rust regex 报出，是权威结论）：\n");
            for e in errs {
                m.push_str(&format!("  - [{}] {}\n", e.id, e.message));
            }
            anyhow::anyhow!(m)
        })
    }

    pub fn n_rules(&self) -> usize { self.rules.len() }

    pub fn rule_ids(&self) -> Vec<&str> { self.rules.iter().map(|r| r.id.as_str()).collect() }

    pub fn block_rules(&self) -> Vec<&str> {
        self.rules.iter().filter(|r| r.action == "block").map(|r| r.id.as_str()).collect()
    }

    pub fn decode_names(&self) -> Vec<&'static str> {
        self.decode.iter().map(|d| d.as_str()).collect()
    }

    /// 评估一条请求。每个 (规则, 作用域) 最多产出一个命中。
    pub fn evaluate(&self, req: &RuleInput) -> Vec<RuleHit> {
        let mut cache: [Option<TextView>; 6] = [None, None, None, None, None, None];
        let mut out: Vec<RuleHit> = Vec::new();
        for r in &self.rules {
            for sc in &r.scopes {
                let i = sc.idx();
                if cache[i].is_none() {
                    cache[i] = Some(view_for(*sc, req, &self.decode));
                }
                let tv = cache[i].as_ref().unwrap();
                if let Some(m) = r.re.find(&tv.text) {
                    let field = if tv.bounds.is_empty() {
                        tv.field.to_string()
                    } else {
                        field_of(&tv.bounds, m.start(), m.end())
                    };
                    out.push(RuleHit {
                        rule: r.id.clone(),
                        name: r.name.clone(),
                        severity: r.severity.clone(),
                        action: r.action.clone(),
                        weight: r.weight,
                        scope: sc.as_str().to_string(),
                        field,
                        start: m.start(),
                        end: m.end(),
                        snippet: make_snippet(&tv.text, m.start(), m.end(), 120),
                    });
                }
            }
        }
        out
    }

    /// 命中权重之和（**按规则去重**：一条规则命中两个作用域只算一次）。
    pub fn weight_of(hits: &[RuleHit]) -> f64 {
        let mut seen: Vec<&str> = Vec::new();
        let mut w = 0.0f64;
        for h in hits {
            if !seen.contains(&h.rule.as_str()) {
                seen.push(h.rule.as_str());
                w += h.weight;
            }
        }
        w
    }

    /// **只有 `action == "block"` 的规则消耗阻断预算**（按规则去重）。
    ///
    /// 这是"逐条设 action"能成立的前提：一条 `alert` 规则无论权重多大都不该让请求变成
    /// block，否则 `action` 字段就只是个装饰，用户永远不敢把新规则设成 alert 观察。
    /// 同时它让误报预算的算术是**精确**的 —— 只有 block 规则的 FP 才可能造成误阻断。
    pub fn block_weight_of(hits: &[RuleHit]) -> f64 {
        let mut seen: Vec<&str> = Vec::new();
        let mut w = 0.0f64;
        for h in hits {
            if h.action == "block" && !seen.contains(&h.rule.as_str()) {
                seen.push(h.rule.as_str());
                w += h.weight;
            }
        }
        w
    }

    /// 规则通道独立是否达到阻断线（对应 CRS 的 `anomaly_score_threshold`）。
    pub fn blocks(&self, hits: &[RuleHit]) -> bool {
        Self::block_weight_of(hits) + 1e-9 >= self.min_weight_to_block
    }

    /// 各字段的解码结果 + `full` 拼装串（供同源回归向量逐字节比对）。
    pub fn decoded_fields(&self, req: &RuleInput) -> BTreeMap<&'static str, String> {
        let mut m = BTreeMap::new();
        for sc in [Scope::Full, Scope::Path, Scope::Query, Scope::Body, Scope::Ua, Scope::Referer] {
            m.insert(sc.as_str(), view_for(sc, req, &self.decode).text);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(json: &str) -> RuleSetSpec { serde_json::from_str(json).unwrap() }

    #[test]
    fn compiles_and_matches_decoded_text() {
        let s = spec(r#"{"schema":1,"decode":["urlencoded","unicode"],
            "rules":[{"id":"r1","regex":"(?i)\\bunion\\b[\\s/*+%]{0,4}\\bselect\\b"}]}"#);
        let e = RuleEngine::compile(&s, "x".into()).unwrap();
        // 原始是 URL 编码的 → 必须先解码才命中
        let req = RuleInput { method: "GET".into(), query: "q=1%20UNION%2FSELECT".into(),
                              ..Default::default() };
        let hits = e.evaluate(&req);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].field, "query");
        assert_eq!(RuleEngine::weight_of(&hits), 1.0);
        // 默认 `action` 是 `alert`：权重进「证据」，但**不**进阻断预算。
        assert_eq!(RuleEngine::block_weight_of(&hits), 0.0);
        assert!(!e.blocks(&hits), "alert 规则永远不该阻断（否则逐条设 action 就是摆设）");
    }

    /// 钉死 `$` 与 `\z` 的分界 —— **权威口径永远是 Rust**。
    ///
    /// 这不是学术细节：`sqli_comment_tail` 用的就是 `$`，而 Python 的 `$` 能匹配
    /// "末尾换行之前"，Rust 的不行。两边理解不一致，规则去留（keep / reject_fp）
    /// 就会在别处悄悄漂移。静态检查因此只对 `$` 出警告、要求改写成 `\z`。
    #[test]
    fn dollar_vs_z_on_trailing_newline() {
        let s = spec(r#"{"schema":1,"decode":["raw"],"rules":[
            {"id":"dollar","regex":"(--)$"},
            {"id":"z","regex":"(--)\\z"}]}"#);
        let e = RuleEngine::compile(&s, "x".into()).unwrap();
        let ids = |body: &str| -> Vec<String> {
            let r = RuleInput { body: body.into(), ..Default::default() };
            e.evaluate(&r).into_iter().map(|h| h.rule).collect()
        };
        assert_eq!(ids("id=1 --"), vec!["dollar", "z"], "无换行：两者都该命中");

        // ⬇️ 这条**就是**两侧的语义分界，也是本测试存在的理由：
        //    Python 的 `$`（非 MULTILINE）会匹配「末尾换行之前」，所以 `(--)$` 对
        //    "id=1 --\n" 在 Python 里**命中**；Rust 的 `$` 只匹配串尾，于是**不**命中。
        //    线上权威口径永远是这里 —— 所以：
        //      * DSL 的规范绝对串尾记号是 `\z`；
        //      * Python 侧静态检查只对 `$` 出**警告**（不拒绝），并要求改写成 `\z`；
        //      * `export_rules_testvec.py` 的参考实现把裸 `$` 翻译成 `\Z`，跟着 Rust 走。
        assert_eq!(
            ids("id=1 --\n"),
            Vec::<String>::new(),
            "Rust 的 `$` 不匹配末尾换行之前；若这里出现 dollar，上述三条结论全部作废"
        );
        assert_eq!(ids("id=1 --\n\n"), Vec::<String>::new());
        // `\z` 的用法是「文本真的以 `--` 结尾」时才命中：
        assert_eq!(ids("--"), vec!["dollar", "z"]);
    }

    /// 一条权重极大的 `alert` 规则也不能把请求变成 block。
    #[test]
    fn alert_rule_never_blocks() {
        let s = spec(r#"{"schema":1,"min_weight_to_block":1.0,"rules":[
            {"id":"loud","regex":"aaa","weight":99.0,"action":"alert"},
            {"id":"quiet","regex":"bbb","weight":1.0,"action":"block"}]}"#);
        let e = RuleEngine::compile(&s, "x".into()).unwrap();
        let loud = e.evaluate(&RuleInput { query: "aaa".into(), ..Default::default() });
        assert_eq!(RuleEngine::weight_of(&loud), 99.0);
        assert_eq!(RuleEngine::block_weight_of(&loud), 0.0);
        assert!(!e.blocks(&loud), "alert 规则不消耗阻断预算");
        // 而 block 规则即使权重小，只要够线就阻断 —— 预算算得准，才敢按预算扣阈值。
        let quiet = e.evaluate(&RuleInput { query: "bbb".into(), ..Default::default() });
        assert!(e.blocks(&quiet));
    }

    #[test]
    fn full_scope_matches_p7_assembly() {
        let s = spec(r#"{"schema":1,"decode":["urlencoded"],"rules":[
            {"id":"tail","regex":"(?i)(--|#|/\\*)\\s*$"}]}"#);
        let e = RuleEngine::compile(&s, "x".into()).unwrap();
        let req = RuleInput { method: "POST".into(), path: "/a".into(),
                              body: "id=1 --".into(), ..Default::default() };
        let hits = e.evaluate(&req);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].field, "body");
    }

    #[test]
    fn rejects_bad_regex_and_dupes() {
        let s = spec(r#"{"schema":1,"rules":[{"id":"a","regex":"(?=x)"},{"id":"a","regex":"z"}]}"#);
        let errs = RuleEngine::compile(&s, "x".into()).err().expect("应当报错");
        assert!(errs.len() >= 2, "{errs:?}");
    }

    #[test]
    fn rejects_wrong_schema() {
        let s = spec(r#"{"schema":2,"rules":[{"id":"a","regex":"z"}]}"#);
        assert!(RuleEngine::compile(&s, "x".into()).is_err());
    }

    #[test]
    fn block_requires_min_weight() {
        let s = spec(r#"{"schema":1,"min_weight_to_block":2.0,"rules":[
            {"id":"a","regex":"aaa","weight":1.0,"action":"block"}]}"#);
        let e = RuleEngine::compile(&s, "x".into()).unwrap();
        let req = RuleInput { query: "aaa".into(), ..Default::default() };
        let hits = e.evaluate(&req);
        assert_eq!(hits.len(), 1);
        assert!(!e.blocks(&hits), "权重 1.0 < 2.0 不应达到阻断线");
    }
}
