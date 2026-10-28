//! Pingora `ProxyHttp` 实现：**采集**（不含判定/阻断）。
//!
//! 采集什么（对应工作项 F 与 S4 决策）：
//!   * HTTP 侧：method / path / query / **body** / host / ua / referer / status
//!   * 流级侧：端到端 dur_ms / 上行字节 / 下行字节 / 源 IP·端口
//!     —— 这正是"Proxy 近似做流级采集"（§8.7.5）的落地：同一个上下文里两路都拿到，
//!     不需要第二个采集点（eBPF 在 Windows 不可用，NetFlow 看不到应用层）。
//!
//! 不采集什么：**不打任何 label**。良性/攻击标签由 `python/collect_http_log.py`
//! 按出处（蜜罐路径 / 红队时间窗 / 复核清单）决定。
//!
//! 安全约束：
//!   * body 落盘上限 `body_keep`，缓冲硬上限 `body_limit`（防大文件上传打爆内存）；
//!   * 写盘经有界队列，队列满就丢并计数 —— **采集永不阻塞转发**；
//!   * 本模块**不做任何阻断**。要不要拦是另一个决策（需要先有真实本地良性流量来标定阈值）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::config::{Config, RespBodyMode};
use crate::sink::{BodyOut, Pred, Record, ResponseOut, RulesOut, Sink};

pub struct Ctx {
    start: Option<Instant>,
    body: Vec<u8>,
    body_len: usize,
    truncated: bool,
    req_headers: Vec<(String, String)>,
    req_headers_total: usize,
    req_headers_stored: usize,
    req_headers_truncated: bool,
    req_version: String,
    req_content_type: String,
    resp_headers: Vec<(String, String)>,
    resp_headers_total: usize,
    resp_headers_stored: usize,
    resp_headers_truncated: bool,
    resp_version: String,
    resp_status: u16,
    status: u16,
    resp_captured: bool,
    resp_body: Vec<u8>,
    resp_body_len: usize,
    resp_body_truncated: bool,
    bytes_out: u64,
    host: String,
    ua: String,
    referer: String,
    src_ip: String,
    src_port: u16,
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            start: None,
            body: Vec::new(),
            body_len: 0,
            truncated: false,
            req_headers: Vec::new(),
            req_headers_total: 0,
            req_headers_stored: 0,
            req_headers_truncated: false,
            req_version: String::new(),
            req_content_type: String::new(),
            resp_headers: Vec::new(),
            resp_headers_total: 0,
            resp_headers_stored: 0,
            resp_headers_truncated: false,
            resp_version: String::new(),
            resp_status: 0,
            status: 0,
            resp_captured: false,
            resp_body: Vec::new(),
            resp_body_len: 0,
            resp_body_truncated: false,
            bytes_out: 0,
            host: String::new(),
            ua: String::new(),
            referer: String::new(),
            src_ip: String::new(),
            src_port: 0,
        }
    }
}

/// 把解析后的头收集成有序数组，并按 `name: value\r\n` 的规范化字节数截断。
///
/// 只能做到 post-parse 顺序（Pingora 不暴露原始 wire 顺序）；重复头逐个保留。
fn collect_headers(headers: &http::HeaderMap, cap: usize) -> (Vec<(String, String)>, usize, usize, bool) {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut stored = 0usize;
    let mut truncated = false;
    for (name, value) in headers.iter() {
        let n = name.as_str();
        let v_bytes = value.as_bytes();
        let line_bytes = n.len() + 2 + v_bytes.len() + 2; // ": " + "\r\n"
        total = total.saturating_add(line_bytes);
        if stored.saturating_add(line_bytes) <= cap {
            // JSON 需要字符串；非 UTF-8 头值用 lossy 展示，但计数仍用原始字节。
            out.push((n.to_string(), String::from_utf8_lossy(v_bytes).into_owned()));
            stored += line_bytes;
        } else {
            truncated = true;
        }
    }
    if total > stored {
        truncated = true;
    }
    (out, total, stored, truncated)
}

fn is_textual_content_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    let ct = ct.split(';').next().unwrap_or("").trim();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct == "application/xml"
        || ct == "application/xhtml+xml"
        || ct == "application/javascript"
        || ct == "application/x-javascript"
        || ct == "application/x-www-form-urlencoded"
        || ct == "application/graphql"
        || ct == "application/ld+json"
        || ct.ends_with("+json")
        || ct.ends_with("+xml")
}

/// 文本/二进制双重判断：Content-Type 明确二进制优先；无 CT 时看 UTF-8。
fn body_is_binary(bytes: &[u8], content_type: &str) -> bool {
    let ct = content_type.trim();
    if !ct.is_empty() && !is_textual_content_type(ct) {
        return true;
    }
    std::str::from_utf8(bytes).is_err() || bytes.contains(&0)
}

fn content_type(headers: &http::HeaderMap) -> String {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn version_str(v: http::Version) -> String {
    format!("{v:?}")
}

fn header_str(h: &RequestHeader, name: &str) -> String {
    h.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{body_is_binary, collect_headers, is_textual_content_type};
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn headers_keep_duplicates_and_count_normalized_bytes() {
        let mut h = HeaderMap::new();
        h.append("x-a", HeaderValue::from_static("one"));
        h.append("x-a", HeaderValue::from_static("two"));
        h.append("x-b", HeaderValue::from_static("three"));
        let (out, total, stored, truncated) = collect_headers(&h, 1024);
        assert!(!truncated);
        assert_eq!(out.len(), 3);
        assert_eq!(out.iter().filter(|(n, _)| n == "x-a").count(), 2);
        let expected: usize = out.iter().map(|(n, v)| n.len() + 2 + v.len() + 2).sum();
        assert_eq!(total, expected);
        assert_eq!(stored, expected);
    }

    #[test]
    fn headers_stop_before_cap_but_keep_total_truth() {
        let mut h = HeaderMap::new();
        h.append("x-a", HeaderValue::from_static("12345"));
        h.append("x-b", HeaderValue::from_static("67890"));
        // 第一条规范化后是 7+2+5+2 = 16 字节；cap=16 只保留第一条。
        let (out, total, stored, truncated) = collect_headers(&h, 16);
        assert_eq!(out.len(), 1);
        assert_eq!(total, 24);
        assert_eq!(stored, 12);
        assert!(truncated);
        assert!(stored <= 16);
    }

    #[test]
    fn textual_content_type_is_case_and_parameter_insensitive() {
        assert!(is_textual_content_type("Application/JSON; charset=utf-8"));
        assert!(is_textual_content_type("text/html; charset=gbk"));
        assert!(is_textual_content_type("application/problem+json"));
        assert!(!is_textual_content_type("image/png"));
        assert!(!is_textual_content_type("application/octet-stream"));
    }

    #[test]
    fn binary_decision_prefers_explicit_nontext_type() {
        assert!(body_is_binary(b"plain ascii", "application/octet-stream"));
        assert!(body_is_binary(b"plain ascii", "image/png"));
        assert!(!body_is_binary("中文".as_bytes(), "text/plain; charset=utf-8"));
        assert!(!body_is_binary(b"{\"ok\":true}", "application/json"));
        assert!(body_is_binary(&[0xff, 0xfe], ""));
        assert!(body_is_binary(b"a\0b", ""));
    }
}

/// dry-run 判定动作计数（供 `--stats-out` 指标文件暴露给控制台总览页）。
#[derive(Default)]
pub struct ActionCounts {
    pub allow: AtomicU64,
    pub block: AtomicU64,
    pub alert: AtomicU64,
}

impl ActionCounts {
    pub fn bump(&self, action: &str) {
        match action {
            "block" => &self.block,
            "alert" => &self.alert,
            _ => &self.allow,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

pub struct Collector {
    pub cfg: Arc<Config>,
    pub sink: Sink,
    /// `--score` 时才有：上线模型判定器（dry-run 记录用，**永不阻断**）。
    ///
    /// 用 `Mutex` 而非会话池：`ort::Session::run` 是 `&mut self`，
    /// dry-run 阶段串行化够用；要并发再上会话池。
    pub scorer: Option<Arc<Mutex<waf_ai_proto::engine::Engine>>>,
    /// 判定失败计数（失败只降级为"不记录 pred"，**绝不影响转发**）。
    pub score_errors: Arc<AtomicU64>,
    /// dry-run 动作计数（指标文件用；不影响转发）。
    pub actions: Arc<ActionCounts>,
    /// 规则通道（第三通道）。`None` = 没有现役规则集。
    ///
    /// 用 `RwLock<Arc<RuleEngine>>` 而不是 `Mutex<RuleEngine>`：读路径是每个请求都要走的，
    /// 要能并发；写路径只有热重载那一条，5 秒一次。热重载**校验通过才替换**这个 `Arc`，
    /// 所以正在处理的请求要么看到旧引擎、要么看到新引擎，**不会看到半个引擎**。
    pub rules: Option<Arc<RwLock<Arc<waf_ai_proto::rules::RuleEngine>>>>,
}

#[async_trait]
impl ProxyHttp for Collector {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    /// 请求头阶段：把 HTTP 侧字段与流级起点记进 ctx。
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.start = Some(Instant::now());
        let req = session.req_header();
        ctx.host = header_str(req, "host");
        ctx.ua = header_str(req, "user-agent");
        ctx.referer = header_str(req, "referer");
        ctx.req_version = version_str(req.version);
        ctx.req_content_type = content_type(&req.headers);
        let (headers, total, stored, truncated) =
            collect_headers(&req.headers, self.cfg.headers_keep);
        ctx.req_headers = headers;
        ctx.req_headers_total = total;
        ctx.req_headers_stored = stored;
        ctx.req_headers_truncated = truncated;
        // pingora 的 SocketAddr 是**枚举**（支持 Unix socket），要先 as_inet()
        if let Some(addr) = session.client_addr() {
            if let Some(sa) = addr.as_inet() {
                ctx.src_ip = sa.ip().to_string();
                ctx.src_port = sa.port();
            }
        }
        Ok(false) // false = 继续走后续阶段（本数据面不阻断任何流量）
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(
            self.cfg.upstream.clone(),
            self.cfg.upstream_tls,
            self.cfg.host_hint().to_string(),
        );
        // pingora 0.9 的 PeerOptions 是**公开字段**，没有 set_*_timeout（0.4 时代的方法已移除）。
        // 显式设超时：不给慢速连接无限占用采集进程的机会。
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
        peer.options.read_timeout = Some(std::time::Duration::from_secs(60));
        peer.options.write_timeout = Some(std::time::Duration::from_secs(60));
        Ok(Box::new(peer))
    }

    /// **请求体采集**（选 Pingora 的核心理由，工作项 F 第一约束的解药）。
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(b) = body {
            ctx.body_len += b.len();
            if self.cfg.collect_body {
                let room = self.cfg.body_keep.saturating_sub(ctx.body.len());
                if room > 0 {
                    let take = room.min(b.len());
                    ctx.body.extend_from_slice(&b[..take]);
                }
                // 落盘上限之外的都算截断（哪怕还没到硬上限）
                if ctx.body_len > self.cfg.body_keep {
                    ctx.truncated = true;
                }
            }
            // 硬上限：停止持有，避免大文件上传把内存吃掉
            if ctx.body_len > self.cfg.body_limit {
                ctx.truncated = true;
                b.clear();
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.resp_status = upstream_response.status.as_u16();
        ctx.status = ctx.resp_status;
        ctx.resp_captured = true;
        ctx.resp_version = version_str(upstream_response.version);
        let (headers, total, stored, truncated) =
            collect_headers(&upstream_response.headers, self.cfg.headers_keep);
        ctx.resp_headers = headers;
        ctx.resp_headers_total = total;
        ctx.resp_headers_stored = stored;
        ctx.resp_headers_truncated = truncated;
        Ok(())
    }

    /// 注意：trait 里这个方法是**同步** fn（0.9 中只有它是非 async），别写成 async。
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(b) = body {
            ctx.bytes_out += b.len() as u64;
            ctx.resp_body_len += b.len();
            // Off 正常不缓冲；但启用评分时仍缓冲 64KB，否则评分失败后无法补采证据。
            let should_buffer = self.cfg.resp_body_mode != RespBodyMode::Off || self.cfg.score;
            if should_buffer {
                let room = self.cfg.resp_body_keep.saturating_sub(ctx.resp_body.len());
                if room > 0 {
                    let take = room.min(b.len());
                    ctx.resp_body.extend_from_slice(&b[..take]);
                }
                if ctx.resp_body_len > self.cfg.resp_body_keep {
                    ctx.resp_body_truncated = true;
                }
            }
        }
        Ok(None)
    }

    /// 收尾：把这一条请求落进采集队列（**不写 label**）。
    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX) {
        let dur_ms = ctx
            .start
            .map(|t| t.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let (method, path, query) = {
            let req = session.req_header();
            (
                req.method.to_string(),
                req.uri.path().to_string(),
                req.uri.query().unwrap_or("").to_string(),
            )
        };
        // 顶层 body 只放文本（训练管线兼容）；二进制必须读 body_b64。
        let req_binary = if self.cfg.collect_body {
            body_is_binary(&ctx.body, &ctx.req_content_type)
        } else {
            false
        };
        let body = if self.cfg.collect_body && !req_binary {
            String::from_utf8(ctx.body.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        let body_b64 = if self.cfg.collect_body {
            Some(B64.encode(&ctx.body))
        } else {
            None
        };
        let body_reason = if self.cfg.collect_body {
            "sampled"
        } else {
            "collect_body_off"
        };

        // ---- dry-run 判定：**只记录，永不阻断** ----
        //
        // 放在 `logging` 而不是请求路径上：采集阶段不该给真实业务加延迟，
        // 而 `logging` 时 body 已收齐，判定所需信息完整。
        // 注意判定用的 body 是**落盘前截断后**的体（`body_truncated=true` 时下游可剔除）。
        // ---- 规则通道（第三通道，**独立于模型**，同样 dry-run） ----
        //
        // 顺序刻意放在 `pred` **之前**：融合是"监督命中 或 规则达阻断线 ⇒ block"，
        // 规则证据必须先算出来喂给判定器。否则记录里的 `action` 只反映模型，而线上
        // （启用后）是融合的 —— 那 dry-run 就在验证一个不存在的语义。
        //
        // 与 `pred` 分开落盘：规则命中是**证据**，不是"模型判的"。
        // 规则跑在**解码后**文本上（解码在 Rust 引擎里做，与标定/回放同一份实现）。
        let (rules, rule_ev) = match self.rules.as_ref() {
            None => (None, waf_ai_proto::decision::RuleEvidence::default()),
            Some(slot) => {
                let eng = match slot.read() {
                    Ok(g) => g.clone(),
                    Err(p) => p.into_inner().clone(),
                };
                let sha = eng.sha1_16.clone();
                let hits = if eng.n_rules() == 0 {
                    Vec::new()
                } else {
                    eng.evaluate(&waf_ai_proto::rules::RuleInput {
                        method: method.clone(),
                        path: path.clone(),
                        query: query.clone(),
                        body: body.clone(),
                        ua: ctx.ua.clone(),
                        referer: ctx.referer.clone(),
                    })
                };
                if hits.is_empty() {
                    // 无命中也要给**真指纹**：否则"这次没命中"与"规则集指纹不符"
                    // 在记录里长得一模一样，事后分不清是没打中还是通道被旁路了。
                    // 权重 0 ⇒ 对动作没有任何影响，只是把语义写清楚。
                    // 也不落 `rules` 块：绝大多数请求没有命中，每行塞一个 sha1
                    // 只会把原始记录撑大。命中才留证。
                    (
                        None,
                        waf_ai_proto::decision::RuleEvidence {
                            weight: 0.0,
                            block_weight: 0.0,
                            ruleset_sha1_16: sha,
                        },
                    )
                } else {
                    let weight = waf_ai_proto::rules::RuleEngine::weight_of(&hits);
                    let block_weight = waf_ai_proto::rules::RuleEngine::block_weight_of(&hits);
                    let block = eng.blocks(&hits);
                    self.sink
                        .stats
                        .rule_hit_lines
                        .fetch_add(1, Ordering::Relaxed);
                    self.sink
                        .stats
                        .rule_hits
                        .fetch_add(hits.len() as u64, Ordering::Relaxed);
                    if block {
                        self.sink
                            .stats
                            .rule_block_lines
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    (
                        Some(RulesOut {
                            rule_set_sha1_16: sha.clone(),
                            hits,
                            weight,
                            block_weight,
                            block,
                        }),
                        waf_ai_proto::decision::RuleEvidence {
                            weight,
                            block_weight,
                            ruleset_sha1_16: sha,
                        },
                    )
                }
            }
        };

        let pred = self.scorer.as_ref().and_then(|s| {
            let req = waf_ai_proto::features::Request {
                method: method.clone(),
                path: path.clone(),
                query: query.clone(),
                body: body.clone(),
            };
            let mut eng = match s.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(), // 别的线程 panic 过：不因此丢掉判定
            };
            match eng.score_with_rules(&req, &rule_ev) {
                Ok(sc) => {
                    let v = &sc.verdict;
                    let pol = eng.policy();
                    Some(Pred {
                        action: v.action.as_str().to_string(),
                        supervised_score: v.supervised_score,
                        supervised_threshold: pol.supervised.threshold,
                        supervised_flagged: v.supervised_flagged,
                        zero_day_score: v.zero_day_score,
                        zero_day_threshold: pol.zero_day.threshold,
                        zero_day_score_crossed: v.zero_day_score_crossed,
                        zero_day_flagged: v.zero_day_flagged,
                        zero_day_enabled: pol.zero_day_enabled,
                        artifacts: eng.artifacts.display().to_string(),
                        attack_label: v.label,
                        shap_topk: sc.shap_topk.clone(),
                        rule_weight: v.rule_weight,
                        rule_block_weight: v.rule_block_weight,
                        rules_flagged: v.rules_flagged,
                        dry_run: true,
                    })
                }
                Err(e) => {
                    // 判定失败**只降级为不记录 pred**，绝不影响转发；限流打日志
                    let n = self.score_errors.fetch_add(1, Ordering::Relaxed) + 1;
                    if n <= 3 || n % 10_000 == 0 {
                        eprintln!("[score] 判定失败 {n} 次（已降级为仅采集）：{e:#}");
                    }
                    None
                }
            }
        });
        if let Some(p) = &pred {
            self.actions.bump(&p.action);
        }

        // ---- 响应体采样：必须在最终 action 已知之后决定 ----
        //
        // 响应体在 response_body_filter 里已经缓冲（最多 64KB）；这里 action 已定，
        // 再按策略决定是否放进 Record。评分失败时即使 --resp-body=off 也留证，
        // 但会打警告并计数，避免运维误以为 off 绝对不落盘。
        let action = pred.as_ref().map(|p| p.action.as_str());
        let score_failed = self.scorer.is_some() && pred.is_none();
        let sampled = ctx.resp_captured
            && match self.cfg.resp_body_mode {
                RespBodyMode::All => true,
                RespBodyMode::Alert => matches!(action, Some("alert") | Some("block")),
                RespBodyMode::Off => score_failed,
            };
        let resp_body_reason = if !ctx.resp_captured {
            "no_response"
        } else if sampled {
            if score_failed && self.cfg.resp_body_mode == RespBodyMode::Off {
                self.sink
                    .stats
                    .resp_body_off_overrides
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "[score] 判定失败，--resp-body=off 已临时突破，采样响应体留证（body_reason=score_unavailable）"
                );
                "score_unavailable"
            } else {
                "sampled"
            }
        } else if self.cfg.resp_body_mode == RespBodyMode::Off {
            "off"
        } else if action == Some("allow") {
            "action_allow"
        } else {
            "no_action"
        };
        let resp_body = if sampled {
            Some(BodyOut {
                b64: B64.encode(&ctx.resp_body),
                wire_bytes: ctx.resp_body_len,
                stored_bytes: ctx.resp_body.len(),
                truncated: ctx.resp_body_truncated,
            })
        } else {
            None
        };
        let response = if ctx.resp_captured {
            Some(ResponseOut {
                captured: true,
                http_version: std::mem::take(&mut ctx.resp_version),
                status: ctx.resp_status,
                headers: std::mem::take(&mut ctx.resp_headers),
                headers_total_bytes: ctx.resp_headers_total,
                headers_stored_bytes: ctx.resp_headers_stored,
                headers_truncated: ctx.resp_headers_truncated,
                sampling_mode: self.cfg.resp_body_mode.as_str().to_string(),
                body_sampled: sampled,
                body: resp_body,
                body_reason: resp_body_reason.to_string(),
                body_wire_bytes: ctx.resp_body_len,
                body_truncated: sampled && ctx.resp_body_truncated,
            })
        } else {
            None
        };

        let rec = Record {
            ts: now_ms(),
            src_ip: ctx.src_ip.clone(),
            src_port: ctx.src_port,
            host: std::mem::take(&mut ctx.host),
            method,
            path,
            query,
            http_version: std::mem::take(&mut ctx.req_version),
            headers: std::mem::take(&mut ctx.req_headers),
            headers_total_bytes: ctx.req_headers_total,
            headers_stored_bytes: ctx.req_headers_stored,
            headers_truncated: ctx.req_headers_truncated,
            body,
            body_b64,
            body_is_binary: req_binary,
            body_sampled: self.cfg.collect_body,
            body_reason: body_reason.to_string(),
            body_len: ctx.body_len,
            body_truncated: ctx.truncated,
            ua: std::mem::take(&mut ctx.ua),
            referer: std::mem::take(&mut ctx.referer),
            status: ctx.status,
            dur_ms,
            bytes_in: ctx.body_len as u64,
            bytes_out: ctx.bytes_out,
            src_kind: "pingora-proxy",
            pred,
            rules,
            response,
        };
        self.sink.try_emit(rec);
    }
}

/// epoch 毫秒（不引 chrono；下游 `parse_ts` 认这个形态并按本地时间解析）
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
