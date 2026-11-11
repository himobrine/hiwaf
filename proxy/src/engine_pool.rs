//! 判定引擎**会话池**。
//!
//! 为什么需要：`ort::Session::run` 是 `&mut self`，单个 `Engine` 只能串行执行。
//! g2（4000 树）实测 allow 判定 ≈0.20ms/请求，单实例天然给出约 **5k QPS 的单核上限**；
//! 而 Pingora 有 N 个 worker 线程，全都排在同一个 `Mutex` 上 —— 加核不会提升判定吞吐。
//!
//! 池化后每个引擎持有**自己的一对 ONNX 会话**（会话之间没有共享可变状态），判定可以
//! 并行到多个核。代价是每份引擎约 40–50 MB RSS（实测 off=19.5MB / 单引擎=76.7MB），
//! 所以池大小由 `--engine-pool` 控制，默认按核数自动取 1–4。
//!
//! 注意：`Forest`（树件）与特征名是只读的，但 `Engine` 里两者与 ONNX 会话绑在一起；
//! 要共享需要拆结构，收益（几 MB）不如复杂度，先不做。

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use waf_ai_proto::engine::{Engine, ShapMode};

pub struct EnginePool {
    engines: Vec<Mutex<Engine>>,
    /// 轮转游标：每个引擎一把锁，worker 之间不再互相排队。
    next: AtomicUsize,
}

impl EnginePool {
    pub fn new(engines: Vec<Engine>) -> Self {
        assert!(!engines.is_empty(), "EnginePool 至少需要一个引擎");
        Self {
            engines: engines.into_iter().map(Mutex::new).collect(),
            next: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.engines.len()
    }

    /// 取一个引擎执行判定（轮转）。锁中毒时继续用（别的线程 panic 过，
    /// 不该因此把整条判定链路变成"永不判定"）。
    /// 取一个引擎执行判定，返回 `(结果, 等锁毫秒数)`。
    ///
    /// 等锁时间单独返回：判定并行度不够时，它会直接变成 `route_ms` 的长尾，
    /// 而分段计时（xgb/shap）里看不到它。
    pub fn with<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> (R, f64) {
        let t_wait = std::time::Instant::now();
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.engines.len();
        let mut g = match self.engines[i].lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let wait_ms = t_wait.elapsed().as_secs_f64() * 1000.0;
        (f(&mut g), wait_ms)
    }

    /// 只读访问第一个引擎（指标/状态读取用，不参与轮转）。
    fn with_first<R>(&self, f: impl FnOnce(&Engine) -> R) -> R {
        let g = match self.engines[0].lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&g)
    }

    /// 把所有引擎的归因策略设为同一档（启动时调用一次）。
    pub fn set_shap_mode(&self, mode: ShapMode) {
        for e in &self.engines {
            let mut g = match e.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.set_shap_mode(mode);
        }
    }

    /// 热重载策略（阈值档位 / 零日开关 / 融合策略）。
    ///
    /// 各引擎加载的是**同一份产物**，`reload_policy` 的校验（schema / 融合策略 /
    /// 产物指纹）是确定性的，所以正常只有"全成功"或"全失败"两种结果。
    /// 仍然把"非首个引擎失败"记成告警而不是静默：宁可指标里看得见。
    pub fn reload_policy(&self, artifacts: &Path) -> Result<(), String> {
        for (i, e) in self.engines.iter().enumerate() {
            let mut g = match e.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Err(err) = g.reload_policy(artifacts) {
                if i == 0 {
                    // 校验在第一个就失败：后面必然同样失败，直接返回（与单实例语义一致）。
                    return Err(format!("{err:#}"));
                }
                eprintln!(
                    "[engine-pool] ⚠️ 引擎 #{i} 策略重载失败（其余引擎已更新，重启可对齐）：{err:#}"
                );
            }
        }
        Ok(())
    }

    pub fn policy_revision(&self) -> u32 {
        self.with_first(|e| e.policy_revision())
    }

    /// 启动日志/指标用的策略快照（读第一个引擎，各引擎同源）。
    pub fn policy_snapshot(&self) -> (f32, f32, bool, String) {
        self.with_first(|e| {
            let p = e.policy();
            (
                p.supervised.threshold,
                p.zero_day.threshold,
                p.zero_day_enabled,
                p.calibration_pool.clone(),
            )
        })
    }

    pub fn xgb_artifact(&self) -> String {
        self.with_first(|e| e.xgb_artifact().to_string())
    }

    pub fn xgb_sha1_16(&self) -> String {
        self.with_first(|e| e.xgb_sha1_16().to_string())
    }

    pub fn if_artifact(&self) -> String {
        self.with_first(|e| e.if_artifact().to_string())
    }

    pub fn if_sha1_16(&self) -> String {
        self.with_first(|e| e.if_sha1_16().to_string())
    }
}