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
//!   * **不做阻断**。默认 `--block-mode off` 只采集；只有显式 `enforce` 才会在
//!     命中 `block` 时返回 403。要不要拦是另一个决策，前置条件是先拿到**真实本地良性流量**
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
mod engine_pool;
mod filters;
mod iplist;
mod perf;
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

    let mut server = {
        // ⚠️ Pingora 0.9 的 `ServerConf::threads` 默认是 **1**（整个代理只有一个事件循环
        // 线程）。不显式放宽时，判定（≈0.09ms CPU/请求）直接把吞吐从 ~16k 压到 ~5k，
        // 且加引擎实例数完全无效。这里按 `--workers` / 逻辑核数设置。
        let mut conf = pingora::server::configuration::ServerConf::default();
        conf.threads = cfg.worker_threads();
        eprintln!("[collector] worker 线程 {}", conf.threads);
        Server::new_with_opt_and_conf(None, conf)
    };
    server.bootstrap();

    // 判定（可选）。**失败不致命**（除非 enforce）：模型加载不了就降级成纯采集，
    // 绝不因为"判定器起不来"把采集面一起拖垮（采集是任务 F 的前提）。
    // 但 `block_mode=enforce` 时静默降级 = "以为在拦，其实没拦"，必须直接启动失败。
    let scorer = if cfg.block_mode.score_enabled() {
        // 判定器实例数：单实例会把判定串行到一个核（实测 ~5k QPS 封顶），
        // 所以默认按核数开 1–4 个；每份额外约 40–50MB RSS。
        let pool_size = cfg.engine_pool_size();
        match waf_ai_proto::engine::Engine::load_pool(&cfg.artifacts, pool_size) {
            Ok(engines) => {
                let pool = engine_pool::EnginePool::new(engines);
                pool.set_shap_mode(cfg.shap_mode);
                let (sup_thr, zd_thr, zd_on, pool_name) = pool.policy_snapshot();
                eprintln!(
                    "[collector] 判定已启用（{}）：产物 {} | 引擎池 {} | 监督阈值 {:.6} / 零日阈值 {:.6} | 零日通道 {} | 归因 {} | 标定池 {}",
                    cfg.block_mode.as_str(),
                    cfg.artifacts.display(),
                    pool.len(),
                    sup_thr,
                    zd_thr,
                    if zd_on { "开" } else { "关（安全降级）" },
                    cfg.shap_mode.as_str(),
                    pool_name,
                );
                Some(Arc::new(pool))
            }
            Err(e) => {
                if cfg.block_mode == config::BlockMode::Enforce {
                    eprintln!(
                        "[collector] ❌ enforce 模式下判定器加载失败（池大小 {}），拒绝启动：{e:#}",
                        pool_size
                    );
                    std::process::exit(1);
                }
                eprintln!(
                    "[collector] ⚠️ 判定启用失败（池大小 {}），已降级为**纯采集**：{e:#}",
                    pool_size
                );
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
        if !cfg.block_mode.score_enabled() {
            // `off` = 纯采集。规则也是判定，不能在 off 模式下偷偷跑：
            // 91 条正则 + 解码是每请求实打实的 CPU，而结果只写进记录、从不影响动作。
            eprintln!("[collector] 规则通道：未启用（--block-mode off：纯采集，不判定也不跑规则）");
            None
        } else {
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
                    if cfg.block_mode == config::BlockMode::Enforce {
                        eprintln!(
                            "[collector] ❌ enforce 模式下规则集加载失败，拒绝启动：{e:#}"
                        );
                        std::process::exit(1);
                    }
                    eprintln!(
                        "[collector] ⚠️ 规则集加载失败，已降级为**无规则通道**（热重载会继续重试）：{e:#}"
                    );
                    None
                }
            },
        }
        };

    // ---- IP 黑白名单（人工维护，控制台写文件；热重载）----
    let ip_path = cfg.artifacts.join(iplist::FILE);
    let ip_list = match iplist::IpList::load(&ip_path) {
        Ok((l, errs)) => {
            eprintln!(
                "[collector] IP 名单：白 {} 条 / 黑 {} 条（{}）{}",
                l.n_white(),
                l.n_black(),
                ip_path.display(),
                if errs.is_empty() {
                    String::new()
                } else {
                    format!("；跳过 {} 条非法条目", errs.len())
                }
            );
            l
        }
        Err(e) => {
            eprintln!(
                "[collector] IP 名单：未加载（{e}）；先按空名单运行，控制台保存后热重载"
            );
            iplist::IpList::default()
        }
    };
    let ip_lists: Arc<RwLock<Arc<iplist::IpList>>> =
        Arc::new(RwLock::new(Arc::new(ip_list)));

    // 进程内监控：把队列/丢弃计数与 dry-run 动作计数定期写 stderr（+ 可选指标文件）。
    // 采集端最怕的不是丢几条，而是**默默**丢（良性池被污染却不自知），所以计数必须可见。
    let score_errors = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let actions = Arc::new(filters::ActionCounts::default());

    // ---- 热重载（策略 + 规则集）----
    let reload_shared = Arc::new(reload::ReloadShared {
        cfg: Arc::clone(&cfg),
        scorer: scorer.clone(),
        rules: rules.clone(),
        ip_lists: Some(ip_lists.clone()),
        stats: sink.stats(),
        state: Mutex::new(reload::ReloadState::default()),
    });
    reload::prime(&reload_shared);
    reload::spawn(Arc::clone(&reload_shared));

    // 每路由一份滑动窗口性能统计（budget_ms 来自 --route，默认 1ms）。
    let perf: Vec<Arc<perf::RoutePerf>> = cfg
        .routes
        .iter()
        .map(|r| Arc::new(perf::RoutePerf::new(&r.name, r.budget_ms)))
        .collect();

    {
        let st = sink.stats();
        let se = Arc::clone(&score_errors);
        let ac = Arc::clone(&actions);
        let cfg2 = Arc::clone(&cfg);
        let rs = Arc::clone(&reload_shared);
        let perf2: Vec<Arc<perf::RoutePerf>> = perf.clone();
        let interval_ms = cfg.stats_interval.max(1) * 1000;
        let artifacts = cfg.artifacts.display().to_string();
        let score_on = cfg.block_mode.score_enabled();
        std::thread::Builder::new()
            .name("collector-stats".to_string())
            .spawn(move || {
                // 先写一次：让控制台在采集器刚起时就能读到指标文件。
                if let Some(p) = &cfg2.stats_out {
                    write_metrics(p, &cfg2, &st, &se, &ac, score_on, &artifacts, &rs, &perf2);
                }
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(interval_ms));
                    eprintln!("[collector] {}", st.snapshot());
                    for r in perf2.iter().map(|p| p.snapshot(10)) {
                        eprintln!(
                            "[perf] {} qps={:.1} p50={:.3}ms p95={:.3}ms p99={:.3}ms max={:.3}ms \
                             inflight={} samples={} budget={}ms breach={}",
                            r.route, r.qps, r.p50_ms, r.p95_ms, r.p99_ms, r.max_ms,
                            r.inflight, r.samples, r.budget_ms, r.breach
                        );
                    }
                    if let Some(p) = &cfg2.stats_out {
                        write_metrics(p, &cfg2, &st, &se, &ac, score_on, &artifacts, &rs, &perf2);
                    }
                }
            })
            .ok();
    }

    // 每条路由一个 ProxyService，共享 sink / 模型 / 规则 / 指标。
    for (i, route) in cfg.routes.iter().enumerate() {
        let collector = filters::Collector {
            cfg: Arc::clone(&cfg),
            route: Arc::new(route.clone()),
            sink: sink.clone(),
            scorer: scorer.clone(),
            score_errors: Arc::clone(&score_errors),
            actions: Arc::clone(&actions),
            rules: rules.clone(),
            ip_lists: Some(ip_lists.clone()),
            perf: perf[i].clone(),
        };
        let mut svc = http_proxy_service(&server.configuration, collector);
        svc.add_tcp(&route.listen);
        server.add_service(svc);
        eprintln!(
            "[collector] 路由 {}：监听 {}  ->  上游 {}{} | route_ms 预算 {}",
            route.name,
            route.listen,
            route.upstream,
            if route.upstream_tls { " (TLS)" } else { "" },
            if route.budget_ms > 0.0 {
                format!("{:.3}ms", route.budget_ms)
            } else {
                "关".to_string()
            },
        );
    }
    eprintln!(
        "[collector] 共 {} 条路由 | 输出 {} | 采集 body={}{} | 判定={} | 热重载={}",
        cfg.routes.len(),
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
        match cfg.block_mode {
            config::BlockMode::Off => "关".to_string(),
            config::BlockMode::DryRun => "dry-run(只记录)".to_string(),
            config::BlockMode::Enforce => "enforce(命中返回 403)".to_string(),
        },
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
/// `actions_*` 是**判定动作计数**（含 dry_run 的“本来会拦”）；真实拦截数看
/// `blocked_requests`（只有 `block_mode=enforce` 才会增长）。
#[derive(serde::Serialize)]
struct Metrics {
    ts: i64,
    pid: u32,
    /// 第一条路由的监听地址（兼容旧控制台字段）。
    listen: String,
    /// 第一条路由的上游（兼容旧控制台字段）。
    upstream: String,
    /// 全部路由（多端口单进程）。
    routes: Vec<RouteMetric>,
    out_dir: String,
    score_enabled: bool,
    /// `off` / `dry_run` / `enforce`
    block_mode: String,
    artifacts: String,
    written: u64,
    dropped_queue_full: u64,
    dropped_io: u64,
    bytes: u64,
    score_errors: u64,
    actions_allow: u64,
    actions_block: u64,
    actions_alert: u64,
    /// 真正被 403 拦下的请求数（只有 `enforce` 才会增长）。
    blocked_requests: u64,
    /// 规则通道计数（history 累计；dry_run 下 `rule_block_lines` **不代表真的拦了**）
    rule_hit_lines: u64,
    rule_hits: u64,
    rule_block_lines: u64,
    /// `--resp-body=off` 因评分失败被临时突破并采样留证的次数。
    resp_body_off_overrides: u64,
    /// 判定器实例数（1 = 单实例串行；>1 = 会话池）。
    engine_pool: usize,
    /// Pingora worker 线程数（实际生效值）。
    workers: usize,
    /// TreeSHAP 归因触发策略（all/flagged/off）。
    shap_mode: String,
    /// 每路由的性能窗口（qps / route_ms 分位 / 预算是否破线）。控制台据此告警。
    perf: Vec<crate::perf::RoutePerfOut>,
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

#[derive(serde::Serialize)]
struct RouteMetric {
    name: String,
    listen: String,
    upstream: String,
    upstream_tls: bool,
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
    perf: &[std::sync::Arc<crate::perf::RoutePerf>],
) {
    use std::sync::atomic::Ordering;
    let now = filters::now_ms();
    let _ = MODELS_LOADED_TS.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
    let loaded_ts = MODELS_LOADED_TS.load(Ordering::Relaxed);
    // 先读模型信息（锁池里第一个引擎），再读 reload.state —— 与 reload::tick 的加锁顺序一致，
    // 避免两把锁交叉持有。
    let (model_xgb, model_xgb_sha1_16, model_if, model_if_sha1_16, models_loaded_ts) =
        match &reload.scorer {
            Some(sc) => (
                Some(sc.xgb_artifact()),
                Some(sc.xgb_sha1_16()),
                Some(sc.if_artifact()),
                Some(sc.if_sha1_16()),
                Some(loaded_ts),
            ),
            None => (None, None, None, None, None),
        };
    let reload_state = match reload.state.lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    };
    let m = Metrics {
        ts: filters::now_ms(),
        pid: std::process::id(),
        listen: cfg.listen().to_string(),
        upstream: cfg.upstream().to_string(),
        routes: cfg
            .routes
            .iter()
            .map(|r| RouteMetric {
                name: r.name.clone(),
                listen: r.listen.clone(),
                upstream: r.upstream.clone(),
                upstream_tls: r.upstream_tls,
            })
            .collect(),
        out_dir: cfg.out_dir.display().to_string(),
        score_enabled: score_on,
        block_mode: cfg.block_mode.as_str().to_string(),
        artifacts: artifacts.to_string(),
        written: st.written.load(Ordering::Relaxed),
        dropped_queue_full: st.dropped_full.load(Ordering::Relaxed),
        dropped_io: st.dropped_io.load(Ordering::Relaxed),
        bytes: st.bytes.load(Ordering::Relaxed),
        score_errors: se.load(Ordering::Relaxed),
        actions_allow: ac.allow.load(Ordering::Relaxed),
        actions_block: ac.block.load(Ordering::Relaxed),
        actions_alert: ac.alert.load(Ordering::Relaxed),
        blocked_requests: st.blocked.load(Ordering::Relaxed),
        rule_hit_lines: st.rule_hit_lines.load(Ordering::Relaxed),
        rule_hits: st.rule_hits.load(Ordering::Relaxed),
        rule_block_lines: st.rule_block_lines.load(Ordering::Relaxed),
        resp_body_off_overrides: st.resp_body_off_overrides.load(Ordering::Relaxed),
        engine_pool: reload.scorer.as_ref().map(|p| p.len()).unwrap_or(0),
        workers: cfg.worker_threads(),
        shap_mode: cfg.shap_mode.as_str().to_string(),
        perf: perf.iter().map(|p| p.snapshot(10)).collect(),
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
