//! `waf-ai-proto rules ...` —— 规则通道的命令行入口。
//!
//! 为什么要有它：控制台与标定脚本**不允许**在 Python 里重写一遍匹配。
//! Rust `regex` 与 Python `re` 在 lookaround / 反向引用 / `$` 语义上都不同，
//! 「看起来一样」就等于「某天会静默不一致」。所以：
//!
//!   * `rules check`  —— 权威编译校验（哪条编不过、为什么）；
//!   * `rules replay` —— 权威回放（真实良性池 / 攻击池上到底命中几条）。
//!
//! 控制面只做编排与统计，判定永远来自这里。

use std::io::{BufRead, BufWriter, Write};

use anyhow::{anyhow, Context, Result};
use serde_json::json;

use crate::rules::{RuleEngine, RuleHit, RuleInput, RuleSetSpec};

const DEFAULT_RULES: &str = "../python/artifacts/rules_authoritative.json";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).map(|s| s.as_str());
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    println!(
        "用法：
  waf-ai-proto rules check  [--rules FILE] [--json]
      用 Rust regex 编译校验规则集（权威）。全过 → exit 0；任一编不过 → exit 1 并逐条给出错因。

  waf-ai-proto rules replay --rules FILE --in CORPUS.jsonl [--out OUT.jsonl]
                            [--dump-decoded] [--meta]
      对语料逐行回放。语料每行：{{\"id\":..,\"pool\":..,\"method\":..,\"path\":..,\"query\":..,\"body\":..}}
      输出每行：{{\"id\":..,\"pool\":..,\"hits\":[...],\"weight\":..,\"block_weight\":..,\"block\":..}}
        `weight` = 全部命中权重（证据）；`block_weight` = 仅 `action=block` 的命中（阻断预算）
      --dump-decoded 额外输出各字段解码结果（同源回归向量用）
      --meta 在首行输出 {{\"_meta\":{{...}}}}（规则集 id / sha1_16 / 解码阶段）"
    );
}

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("check") => cmd_check(&args[1..]),
        Some("replay") => cmd_replay(&args[1..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => {
            eprintln!("未知子命令：rules {other}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn load_spec(path: &str) -> Result<(RuleSetSpec, String, Vec<u8>)> {
    let raw = std::fs::read(path).with_context(|| format!("读规则集失败：{path}"))?;
    let spec: RuleSetSpec = serde_json::from_slice(&raw)
        .with_context(|| format!("规则集不是合法 JSON：{path}"))?;
    let sha = crate::hash::sha1_16(&raw);
    Ok((spec, sha, raw))
}

/// `$` 在两侧语义可能不同：Python 允许"末尾换行之前"，Rust（RE2 语义）只在串尾。
fn warn_dollar(pat: &str) -> bool {
    pat.contains('$')
}

fn cmd_check(args: &[String]) -> Result<()> {
    let path = flag(args, "--rules").unwrap_or(DEFAULT_RULES);
    let (spec, sha, _raw) = load_spec(path)?;

    match RuleEngine::compile(&spec, sha.clone()) {
        Ok(e) => {
            if has_flag(args, "--json") {
                println!("{}", serde_json::to_string(&json!({
                    "ok": true,
                    "rules": e.n_rules(),
                    "ruleset_id": e.ruleset_id,
                    "sha1_16": e.sha1_16,
                    "decode": e.decode_names(),
                    "min_weight_to_block": e.min_weight_to_block,
                    "block_rules": e.block_rules(),
                    "path": path,
                }))?);
            } else {
                println!(
                    "OK rules={} ruleset={:?} sha1_16={} decode={:?} min_weight_to_block={} block={}",
                    e.n_rules(), e.ruleset_id, e.sha1_16, e.decode_names(),
                    e.min_weight_to_block, e.block_rules().len()
                );
                for r in &spec.rules {
                    if warn_dollar(&r.regex) {
                        println!(
                            "WARN [{}] 含 `$`：Python 允许匹配『末尾换行之前』，Rust 只在串尾匹配；\
                             要严格请写 `\\z`（本行只是提醒，回放结果以 Rust 为准）",
                            r.id
                        );
                    }
                }
            }
            Ok(())
        }
        Err(errs) => {
            if has_flag(args, "--json") {
                println!("{}", serde_json::to_string(&json!({
                    "ok": false,
                    "path": path,
                    "n_specs": spec.rules.len(),
                    "errors": errs,
                }))?);
            } else {
                for e in &errs {
                    println!("ERR [{}] {}", e.id, e.message);
                }
                println!("FAIL rules={} errors={}", spec.rules.len(), errs.len());
            }
            std::process::exit(1);
        }
    }
}

fn cmd_replay(args: &[String]) -> Result<()> {
    let rules_path = flag(args, "--rules").unwrap_or(DEFAULT_RULES);
    let in_path = flag(args, "--in").ok_or_else(|| anyhow!("replay 需要 --in CORPUS.jsonl"))?;
    let out_path = flag(args, "--out");
    let dump = has_flag(args, "--dump-decoded");
    let meta = has_flag(args, "--meta");

    let engine = RuleEngine::from_path(std::path::Path::new(rules_path))?;
    eprintln!(
        "[rules] ruleset={:?} sha1_16={} rules={} decode={:?} min_weight_to_block={} block={}",
        engine.ruleset_id, engine.sha1_16, engine.n_rules(),
        engine.decode_names(), engine.min_weight_to_block, engine.block_rules().len()
    );

    let src: Box<dyn BufRead> = if in_path == "-" {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(
            std::fs::File::open(in_path).with_context(|| format!("读语料失败：{in_path}"))?,
        ))
    };
    let dst: Box<dyn Write> = match out_path {
        Some(p) => Box::new(BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("写结果失败：{p}"))?,
        )),
        None => Box::new(BufWriter::new(std::io::stdout())),
    };
    let mut dst = dst;

    if meta {
        writeln!(dst, "{}", serde_json::to_string(&json!({
            "_meta": {
                "ruleset_id": engine.ruleset_id,
                "sha1_16": engine.sha1_16,
                "n_rules": engine.n_rules(),
                "decode": engine.decode_names(),
                "min_weight_to_block": engine.min_weight_to_block,
            }
        }))?)?;
    }

    let mut n_lines = 0usize;
    let mut n_hits = 0usize;
    let mut hit_lines = 0usize;
    for (lineno, line) in src.lines().enumerate() {
        let line = line.with_context(|| format!("读取第 {} 行失败", lineno + 1))?;
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(t)
            .with_context(|| format!("第 {} 行不是合法 JSON", lineno + 1))?;
        let req = RuleInput::from_json(&v);
        let hits: Vec<RuleHit> = engine.evaluate(&req);
        let w = RuleEngine::weight_of(&hits);
        let bw = RuleEngine::block_weight_of(&hits);
        let blocked = engine.blocks(&hits);
        n_lines += 1;
        if !hits.is_empty() {
            hit_lines += 1;
            n_hits += hits.len();
        }
        let mut obj = json!({
            "id": v.get("id").cloned().unwrap_or(serde_json::Value::Null),
            "pool": v.get("pool").cloned().unwrap_or(serde_json::Value::Null),
            "hits": hits,
            // `weight` = 全部命中的权重（**证据**）；`block_weight` = 只有 `action=block`
            // 的命中才计入（**阻断预算**）。两者分开，控制台才能说清"为什么没拦"。
            "weight": w,
            "block_weight": bw,
            "block": blocked,
        });
        if dump {
            let map = engine.decoded_fields(&req);
            if let Some(o) = obj.as_object_mut() {
                o.insert(
                    "decoded".to_string(),
                    serde_json::to_value(map).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        writeln!(dst, "{}", serde_json::to_string(&obj)?)?;
    }
    dst.flush()?;
    eprintln!("[rules] 回放完成：{n_lines} 行，命中行 {hit_lines}，命中总计 {n_hits}");
    Ok(())
}
