//! S4 / 工作项 F：**采集数据面**（Pingora 反向代理 + HTTP/流级采集）。
//!
//! ## 这个程序做什么
//!
//! 挂在真实业务前面当反向代理，把**流过的请求**（含**请求体**）与流级指标写成原始 jsonl。
//! 这是工作项 F 第一约束（access log 没有请求体）的解药：`request_body_filter` 能拿到完整 body。
//!
//! ## 这个程序**不**做什么（很重要）
//!
//!   * **不打标签**。真实流量的攻击没有标签；用内容正则打标 = 把要替换掉的规则抄进训练集。
//!     标签由 `python/collect_http_log.py` 按**出处**（蜜罐路径 / 红队时间窗 / 复核清单）决定。
//!   * **不做阻断**。本程序只采集。要不要拦是另一个决策，前置条件是先拿到**真实本地良性流量**
//!     来标定阈值（否则就是拿公共卫生数据硬调参，项目已否掉这条路）。
//!
//! ## 端到端管线
//!
//! ```text
//!   客户端 ──► waf-collector (本程序)  ──► 真实后端
//!                  │
//!                  └─► traindata/proxy/raw-*.jsonl   （原始，无 label）
//!                            │
//!                            ├─► collect_http_log.py --format jsonl --provenance auto \
//!                            │       --canary-prefix /admin.php --redteam-window ...
//!                            │   ──► *_benign.jsonl / *_attack.jsonl（有 label，来源可审计）
//!                            └─► 流级通道消费者（dur_ms / bytes_in / bytes_out / src_ip）
//! ```
//!
//! ## 安全/健壮性
//!
//!   * body 落盘上限 + 缓冲硬上限（防 OOM，见 `--body-keep/--body-limit`）；
//!   * 写盘走有界队列，满了**丢记录并计数**，绝不阻塞转发；
//!   * `--no-body` 隐私模式（只留元数据）。

mod config;
mod filters;
mod reload;
mod sink;

use std::sync::{Arc, Mutex, RwLock};

use pingora::prelude::*;
use pingora::proxy::http_proxy_service;

fn main() {
    let cfg = match config::parse_args(std::env::args()) {
        Ok(c) => Arc::new(c),
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let sink = match sink::Sink::start(&cfg.out_dir, cfg.file_size, cfg.channel) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[collector] 无法初始化落盘目录 {}：{e}", cfg.out_dir.display());
            std::process::exit(1);
        }
    };

    let mut server = Server::new(None).expect("Server::new");
    server.bootstrap();

    // dry-run 判定（可选）。**失败不致命**：模型加载不了就降级成纯采集，
    // 绝不因为"判定器起不来"把采集面一起拖垮（采集是任务 F 的前提）。
    let scorer = if cfg.score {
        match waf_ai_proto::engine::Engine::load(&cfg.artifacts) {
            Ok(e) => {
                let pol = e.policy();
                eprintln!(
                    "[collector] dry-run 判定已启用：产物 {} | 监督阈值 {:.6} / 零日阈值 {:.6} | 零日通道 {} | 标定池 {}",
                    e.artifacts.display(),
                    pol.supervised.threshold,
                    pol.zero_day.threshold,
                    if pol.zero_day_enabled { "开" } else { "关（安全降级）" },
                    pol.calibration_pool,
                );
                Some(Arc::new(Mutex::new(e)))
            }
            Err(e) => {
                eprintln!("[collector] ⚠️ dry-run 判定启用失败，已降级为**纯采集**：{e:#}");
                None
            }
        }
    } else {
        None
    };

    // ---- 规则通道（第三通道）----
    //
    // 与模型判定**互相独立**：没有 `--score` 也能只跑规则。加载失败**不致命**
    // （降级为无规则通道），但要在 stderr 上讲清楚，不能默默变成"没有规则"。
    let rules: Option<Arc<RwLock<Arc<waf_ai_proto::rules::RuleEngine>>>> =
        match cfg.rules.as_ref() {
            None => {
                eprintln!("[collector] 规则通道：未启用（--no-rules）");
                None
            }
            Some(p) if !p.exists() => {
                eprintln!(
                    "[collector] 规则通道：未启用（{} 不存在；控制台提升规则集后会自动出现，\
                     届时热重载会在 {}s 内接上）",
                    p.display(),
                    cfg.reload_interval.max(1)
                );
                None
            }
            Some(p) => match waf_ai_proto::rules::RuleEngine::from_path(p) {
                Ok(e) => {
                    eprintln!(
                        "[collector] 规则通道已启用：{} 条 | sha1_16={} | 解码 {:?} | \
                         阻断线 weight>={} | block 规则 {} 条",
                        e.n_rules(),
                        e.sha1_16,
                        e.decode_names(),
                        e.min_weight_to_block,
                        e.block_rules().len(),
                    );
                    Some(Arc::new(RwLock::new(Arc::new(e))))
                }
                Err(e) => {
                    eprintln!(
                        "[collector] ⚠️ 规则集加载失败，已降级为**无规则通道**（热重载会继续重试）：{e:#}"
                    );
                    None
                }
            },
        };

    // 进程内监控：把队列/丢弃计数与 dry-run 动作计数定期写 stderr（+ 可选指标文件）。
    // 采集端最怕的不是丢几条，而是**默默**丢（良性池被污染却不自知），所以计数必须可见。
    let score_errors = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let actions = Arc::new(filters::ActionCounts::default());

    // ---- 热重载（策略 + 规则集）----
    let reload_shared = Arc::new(reload::ReloadShared {
        cfg: Arc::clone(&cfg),
        scorer: scorer.clone(),
        rules: rules.clone(),
        stats: sink.stats(),
        state: Mutex::new(reload::ReloadState::default()),
    });
    reload::prime(&reload_shared);
    reload::spawn(Arc::clone(&reload_shared));

    {
        let st = sink.stats();
        let se = Arc::clone(&score_errors);
        let ac = Arc::clone(&actions);
        let cfg2 = Arc::clone(&cfg);
        let rs = Arc::clone(&reload_shared);
        let interval_ms = cfg.stats_interval.max(1) * 1000;
        let artifacts = cfg.artifacts.display().to_string();
        let score_on = cfg.score;
        std::thread::Builder::new()
            .name("collector-stats".to_string())
            .spawn(move || {
                // 先写一次：让控制台在采集器刚起时就能读到指标文件。
                if let Some(p) = &cfg2.stats_out {
                    write_metrics(p, &cfg2, &st, &se, &ac, score_on, &artifacts, &rs);
                }
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(interval_ms));
                    eprintln!("[collector] {}", st.snapshot());
                    if let Some(p) = &cfg2.stats_out {
                        write_metrics(p, &cfg2, &st, &se, &ac, score_on, &artifacts, &rs);
                    }
                }
            })
            .ok();
    }

    let collector = filters::Collector {
        cfg: Arc::clone(&cfg),
        sink,
        scorer,
        score_errors,
        actions,
        rules,
    };
    let mut svc = http_proxy_service(&server.configuration, collector);
    svc.add_tcp(&cfg.listen);

    server.add_service(svc);
    eprintln!(
        "[collector] 监听 {}  ->  上游 {}{}   输出 {}   采集 body={}{}   判定={}   热重载={}",
        cfg.listen,
        cfg.upstream,
        if cfg.upstream_tls { " (TLS)" } else { "" },
        cfg.out_dir.display(),
        cfg.collect_body,
        if cfg.collect_body {
            format!(
                " (keep={} limit={}; headers={}; resp-body={} keep={})",
                cfg.body_keep,
                cfg.body_limit,
                cfg.headers_keep,
                cfg.resp_body_mode.as_str(),
                cfg.resp_body_keep
            )
        } else {
            String::new()
        },
        if cfg.score { "dry-run(只记录)" } else { "关" },
        if cfg.reload_interval == 0 {
            "关".to_string()
        } else {
            format!("每 {}s 轮询 policy+rules 的 sha1", cfg.reload_interval)
        }
    );
    eprintln!("[collector] 提醒：本程序**不打标签**；聚类与标注见 python/collect_http_log.py");
    if let Some(p) = &cfg.stats_out {
        eprintln!(
            "[collector] 指标文件 {}（每 {}s 刷新；控制台读它拿 written/dropped/actions）",
            p.display(),
            cfg.stats_interval.max(1)
        );
    }

    server.run_forever();
}

// --------------------------------------------------------------------------- 指标输出
/// 采集器运行指标（供控制台总览/采集面状态页轮询）。
///
/// ⚠️ 这里的 `actions_*` 是**dry-run 判定**的动作计数（当前不阻断），不是真实拦截数。
#[derive(serde::Serialize)]
struct Metrics {
    ts: i64,
    pid: u32,
    listen: String,
    upstream: String,
    out_dir: String,
    score_enabled: bool,
    artifacts: String,
    written: u64,
    dropped_queue_full: u64,
    dropped_io: u64,
    bytes: u64,
    score_errors: u64,
    actions_allow: u64,
    actions_block: u64,
    actions_alert: u64,
    /// 规则通道计数（history 累计；dry-run 下 `rule_block_lines` **不代表真的拦了**）
    rule_hit_lines: u64,
    rule_hits: u64,
    rule_block_lines: u64,
    /// `--resp-body=off` 因评分失败被临时突破并采样留证的次数。
    resp_body_off_overrides: u64,
    /// 响应体采样模式（alert/all/off），控制台展示用。
    resp_body_mode: String,
    /// 已加载监督模型的槽位文件名（控制台"当前模型"卡片用）。
    model_xgb: Option<String>,
    /// 已加载监督模型的内容 sha1_16。与策略里的 artifact_sha1_16 不一致 ⇒ 切换后尚未重启。
    model_xgb_sha1_16: Option<String>,
    /// 已加载零日模型的槽位文件名。
    model_if: Option<String>,
    /// 已加载零日模型的内容 sha1_16。
    model_if_sha1_16: Option<String>,
    /// 进程内模型会话的加载时刻（ms）。
    models_loaded_ts: Option<i64>,
    /// 热重载状态：控制台据此判断"采集器用的是不是磁盘上那一版"
    reload: reload::ReloadState,
}

/// 首次写指标的时刻（近似"模型会话加载时刻"）：进程内模型只加载一次，之后靠重启更新。
static MODELS_LOADED_TS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

fn write_metrics(
    path: &std::path::Path,
    cfg: &config::Config,
    st: &sink::Stats,
    se: &std::sync::atomic::AtomicU64,
    ac: &filters::ActionCounts,
    score_on: bool,
    artifacts: &str,
    reload: &reload::ReloadShared,
) {
    use std::sync::atomic::Ordering;
    let now = filters::now_ms();
    let _ = MODELS_LOADED_TS.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
    let loaded_ts = MODELS_LOADED_TS.load(Ordering::Relaxed);
    // 先读模型信息（锁 scorer），再读 reload.state —— 与 reload::tick 的加锁顺序一致，
    // 避免两把锁交叉持有。
    let (model_xgb, model_xgb_sha1_16, model_if, model_if_sha1_16, models_loaded_ts) =
        match &reload.scorer {
            Some(sc) => {
                let eng = match sc.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                (
                    Some(eng.xgb_artifact().to_string()),
                    Some(eng.xgb_sha1_16().to_string()),
                    Some(eng.if_artifact().to_string()),
                    Some(eng.if_sha1_16().to_string()),
                    Some(loaded_ts),
                )
            }
            None => (None, None, None, None, None),
        };
    let reload_state = match reload.state.lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    };
    let m = Metrics {
        ts: filters::now_ms(),
        pid: std::process::id(),
        listen: cfg.listen.clone(),
        upstream: cfg.upstream.clone(),
        out_dir: cfg.out_dir.display().to_string(),
        score_enabled: score_on,
        artifacts: artifacts.to_string(),
        written: st.written.load(Ordering::Relaxed),
        dropped_queue_full: st.dropped_full.load(Ordering::Relaxed),
        dropped_io: st.dropped_io.load(Ordering::Relaxed),
        bytes: st.bytes.load(Ordering::Relaxed),
        score_errors: se.load(Ordering::Relaxed),
        actions_allow: ac.allow.load(Ordering::Relaxed),
        actions_block: ac.block.load(Ordering::Relaxed),
        actions_alert: ac.alert.load(Ordering::Relaxed),
        rule_hit_lines: st.rule_hit_lines.load(Ordering::Relaxed),
        rule_hits: st.rule_hits.load(Ordering::Relaxed),
        rule_block_lines: st.rule_block_lines.load(Ordering::Relaxed),
        resp_body_off_overrides: st.resp_body_off_overrides.load(Ordering::Relaxed),
        resp_body_mode: cfg.resp_body_mode.as_str().to_string(),
        model_xgb,
        model_xgb_sha1_16,
        model_if,
        model_if_sha1_16,
        models_loaded_ts,
        reload: reload_state,
    };
    // 原子替换：控制台可能正在读，别让它读到半个 JSON。
    let tmp = path.with_extension("json.tmp");
    if let Ok(buf) = serde_json::to_vec_pretty(&m) {
        if std::fs::write(&tmp, buf).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}
