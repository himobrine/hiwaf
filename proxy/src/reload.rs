//! 策略 / 规则集**热重载**（每 N 秒轮询 sha1，校验通过才原子替换）。
//!
//! ## 为什么必须做
//!
//! 控制台改一条阈值、加一条规则，如果都要**重启采集器**才算数，那这个系统在真实环境里
//! 就是个摆设：采集面一停，良性池就断档，而良性池断档会直接卡住阈值重标定
//! （项目已经因为「真实本地良性只有 190 条」卡过一次）。所以"改规则=重启采集器"
//! 不能作为长期方案。
//!
//! ## 怎么保证不换出事故
//!
//!   * **指纹驱动**：每 `--reload-interval` 秒算一次 `decision_policy.json` 与规则集的
//!     `sha1_16`（纯 Rust 实现，零新依赖）。指纹没变 = 一个字节都没读，开销可忽略。
//!   * **先校验、后替换**：新策略要能通过 `DecisionConfig` 的结构守卫（`schema` / 融合策略 /
//!     标定池无交集），新规则集要能通过 Rust `regex` 编译。任一条不过 → **保留旧内容**，
//!     把失败原因写进指标（控制台亮告警）。**绝不半新半旧**。
//!   * **原子替换**：策略在 `Mutex<Engine>` 里原地换（`reload_policy` 只换阈值，不换 ONNX
//!     会话）；规则集换的是 `RwLock<Arc<RuleEngine>>` 里的 `Arc`，读路径拿到的永远是完整
//!     的一版。
//!   * **换模型不热重载**：产物文件名一变即报错并要求重启。理由见 `Engine::reload_policy`。
//!   * **失败要可见**：`last_err` / `rules_active_sha1_16` 都进指标文件，控制台据此提示
//!     "磁盘上的规则比采集器正在用的新"。

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use serde::Serialize;

use waf_ai_proto::engine::Engine;
use waf_ai_proto::hash::sha1_16_file;
use waf_ai_proto::rules::RuleEngine;

use crate::config::Config;
use crate::sink::Stats;

/// 热重载的当前状态（进指标文件，供控制台显示"采集器到底在用哪一版"）。
#[derive(Debug, Default, Clone, Serialize)]
pub struct ReloadState {
    /// 轮询周期（秒）。0 = 关闭。
    pub interval_sec: u64,
    /// 磁盘上策略的指纹
    pub policy_sha1_16: Option<String>,
    /// 磁盘上规则集的指纹
    pub rules_sha1_16: Option<String>,
    /// **采集器实际在用**的策略修订号
    pub policy_active_revision: Option<u32>,
    /// **采集器实际在用**的规则集指纹。与 `rules_sha1_16` 不同 ⇒ 磁盘上的更新没生效。
    pub rules_active_sha1_16: Option<String>,
    /// 在用规则条数
    pub rules_active_n: Option<usize>,
    pub last_ok_ts: i64,
    pub last_err_ts: i64,
    /// 最近一次失败原因（空 = 最近一次是成功的）
    pub last_err: Option<String>,
}

pub struct ReloadShared {
    pub cfg: Arc<Config>,
    pub scorer: Option<Arc<Mutex<Engine>>>,
    pub rules: Option<Arc<RwLock<Arc<RuleEngine>>>>,
    pub stats: Arc<Stats>,
    pub state: Mutex<ReloadState>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn policy_path(cfg: &Config) -> PathBuf {
    cfg.artifacts.join(waf_ai_proto::engine::POLICY_JSON)
}

/// 起轮询线程。`--reload-interval 0` / `--no-reload` 时不起（返回 None）。
pub fn spawn(shared: Arc<ReloadShared>) -> Option<thread::JoinHandle<()>> {
    let interval = shared.cfg.reload_interval;
    if interval == 0 {
        eprintln!("[reload] 已关闭（--no-reload）：改策略/规则需要重启采集器");
        return None;
    }
    let s = Arc::clone(&shared);
    thread::Builder::new()
        .name("collector-reload".to_string())
        .spawn(move || loop {
            thread::sleep(Duration::from_secs(interval.max(1)));
            if let Err(e) = tick(&s) {
                eprintln!("[reload] 轮询出错（保留旧内容继续跑）：{e}");
            }
        })
        .ok()
}

/// 记下启动时的指纹，避免刚起来就做一次无意义的重载。
pub fn prime(shared: &ReloadShared) {
    let mut st = match shared.state.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    st.interval_sec = shared.cfg.reload_interval;
    st.policy_sha1_16 = sha1_16_file(&policy_path(&shared.cfg));
    st.rules_sha1_16 = shared
        .cfg
        .rules
        .as_ref()
        .and_then(|p| sha1_16_file(p));
    if let Some(sc) = &shared.scorer {
        let eng = match sc.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        st.policy_active_revision = Some(eng.policy_revision());
    }
    if let Some(slot) = &shared.rules {
        let eng = match slot.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        st.rules_active_sha1_16 = Some(eng.sha1_16.clone());
        st.rules_active_n = Some(eng.n_rules());
    }
}

/// 一次轮询：指纹变了才动作。
///
/// 返回 `Result<(), String>` 而不是 `anyhow::Result`：本 crate 没依赖 `anyhow`
/// （pingora 自带错误类型），为了一个日志字符串引进一个依赖不划算。
fn tick(shared: &Arc<ReloadShared>) -> Result<(), String> {
    let cfg = &shared.cfg;
    let disk_policy_sha = sha1_16_file(&policy_path(cfg));
    let disk_rules_sha = cfg.rules.as_ref().and_then(|p| sha1_16_file(p));

    let (change_policy, change_rules) = {
        let st = match shared.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        (
            disk_policy_sha != st.policy_sha1_16,
            disk_rules_sha != st.rules_sha1_16,
        )
    };
    if !change_policy && !change_rules {
        return Ok(());
    }

    // ---- 1) 先构建（校验），任何失败都不动正在用的内容 ----
    let mut err: Option<String> = None;

    if change_policy {
        if let Some(sc) = &shared.scorer {
            let mut eng = match sc.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Err(e) = eng.reload_policy(&cfg.artifacts) {
                err = Some(format!("策略重载被拒（继续用旧策略）：{e:#}"));
            }
        }
    }

    let mut new_rules: Option<Arc<RuleEngine>> = None;
    if change_rules {
        match &cfg.rules {
            None => {}
            Some(p) => {
                if !p.exists() {
                    // 文件被删了：保留正在用的引擎（不给"磁盘上没文件了"就静默变成无规则）。
                    err = Some(format!(
                        "规则集 {} 不存在：保留正在用的规则（不会静默变成无规则）",
                        p.display()
                    ));
                } else {
                    match RuleEngine::from_path(p) {
                        Ok(e) => new_rules = Some(Arc::new(e)),
                        Err(e) => {
                            err = Some(format!("规则集重载被拒（继续用旧规则）：{e:#}"));
                        }
                    }
                }
            }
        }
    }

    // ---- 2) 替换（只替换校验通过的那部分） ----
    if let Some(r) = new_rules {
        if let Some(slot) = &shared.rules {
            match slot.write() {
                Ok(mut g) => *g = r,
                Err(p) => *p.into_inner() = r,
            }
        }
    }

    // ---- 3) 记账 ----
    let mut st = match shared.state.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    st.policy_sha1_16 = disk_policy_sha;
    st.rules_sha1_16 = disk_rules_sha;
    if let Some(sc) = &shared.scorer {
        let eng = match sc.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        st.policy_active_revision = Some(eng.policy_revision());
    }
    if let Some(slot) = &shared.rules {
        let eng = match slot.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        st.rules_active_sha1_16 = Some(eng.sha1_16.clone());
        st.rules_active_n = Some(eng.n_rules());
    }
    match &err {
        None => {
            st.last_ok_ts = now_ms();
            st.last_err = None;
            shared.stats.reload_ok.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "[reload] 已生效：策略 rev={:?} 规则 n={:?} sha1_16={:?}",
                st.policy_active_revision, st.rules_active_n, st.rules_active_sha1_16
            );
        }
        Some(msg) => {
            st.last_err_ts = now_ms();
            st.last_err = Some(msg.clone());
            shared.stats.reload_fail.fetch_add(1, Ordering::Relaxed);
            eprintln!("[reload] ⚠️ {msg}");
        }
    }
    Ok(())
}
