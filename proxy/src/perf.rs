//! 每路由的**滑动窗口性能统计**（1 秒粒度 × 60 秒）。
//!
//! 为什么需要：`stats.json` 之前只有累计计数器（written/dropped/actions），
//! 看不到"现在每秒多少请求、`route_ms` 的 p99 是多少"，因此无法做吞吐异常告警，
//! 也无法回答"1ms 预算下最多能扛多少 QPS"。
//!
//! 实现取舍：
//! * 用**固定直方图**而不是保留每条样本——内存恒定（每路由 ~70KB），无分配；
//! * 每个请求只加一把短锁（18k QPS 下 ≈0.2% CPU），换来精确的按秒分桶；
//! * 分桶 50µs，覆盖 0–4ms（超出落最后一个桶），对 1ms 预算的 p99 足够；
//!   同时单独记录 max，避免长尾被桶宽吃掉。

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// 窗口秒数。
const WINDOW_SECS: usize = 60;
/// 直方图桶数（50µs/桶，最后一桶为溢出）。
const BUCKETS: usize = 81;
/// 桶宽（微秒）。
const BUCKET_US: u64 = 50;
/// 少于这么多样本时不判 `breach`（避免低流量下单个慢请求就触发告警）。
const MIN_SAMPLES: u64 = 20;

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Slot {
    sec: u64,
    count: u64,
    sum_us: u64,
    max_us: u64,
    hist: [u64; BUCKETS],
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            sec: 0,
            count: 0,
            sum_us: 0,
            max_us: 0,
            hist: [0; BUCKETS],
        }
    }
}

impl Slot {
    fn reset(&mut self, sec: u64) {
        self.sec = sec;
        self.count = 0;
        self.sum_us = 0;
        self.max_us = 0;
        self.hist = [0; BUCKETS];
    }
}

pub struct RoutePerf {
    pub route: String,
    /// 该站点的 `route_ms` p99 预算（ms）；`0` = 不设预算。
    pub budget_ms: f64,
    win: Mutex<[Slot; WINDOW_SECS]>,
    /// 当前在途请求数（进入路由 +1，logging 结束 -1）。
    inflight: AtomicI64,
}

impl RoutePerf {
    pub fn new(route: &str, budget_ms: f64) -> Self {
        Self {
            route: route.to_string(),
            budget_ms,
            win: Mutex::new(std::array::from_fn(|_| Slot::default())),
            inflight: AtomicI64::new(0),
        }
    }

    pub fn enter(&self) {
        self.inflight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn leave(&self) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
    }

    /// 记录一条 `route_ms`。锁只在这一瞬间持有。
    pub fn record(&self, ms: f64) {
        if !ms.is_finite() || ms < 0.0 {
            return;
        }
        let us = (ms * 1000.0).round() as u64;
        let now = epoch_secs();
        let mut g = match self.win.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let idx = (now as usize) % WINDOW_SECS;
        if g[idx].sec != now {
            g[idx].reset(now);
        }
        let slot = &mut g[idx];
        let b = ((us / BUCKET_US) as usize).min(BUCKETS - 1);
        slot.hist[b] += 1;
        slot.count += 1;
        slot.sum_us = slot.sum_us.saturating_add(us);
        if us > slot.max_us {
            slot.max_us = us;
        }
    }

    /// 合并最近 `secs` 秒并算分位。`secs` 会被夹到 1..=60。
    pub fn snapshot(&self, secs: u64) -> RoutePerfOut {
        let span = secs.clamp(1, WINDOW_SECS as u64);
        let now = epoch_secs();
        let mut hist = [0u64; BUCKETS];
        let mut count = 0u64;
        let mut sum_us = 0u64;
        let mut max_us = 0u64;
        {
            let g = match self.win.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            for s in g.iter() {
                if s.sec == 0 || now.saturating_sub(s.sec) >= span {
                    continue;
                }
                count += s.count;
                sum_us = sum_us.saturating_add(s.sum_us);
                max_us = max_us.max(s.max_us);
                for (a, b) in hist.iter_mut().zip(s.hist.iter()) {
                    *a += *b;
                }
            }
        }
        let q = |p: f64| -> f64 {
            if count == 0 {
                return 0.0;
            }
            let target = ((count as f64) * p).ceil() as u64;
            let mut acc = 0u64;
            for (i, n) in hist.iter().enumerate() {
                acc += *n;
                if acc >= target {
                    // 落在溢出桶：给一个"下限"值（桶宽），真实值看 max_ms。
                    let us = (i as u64) * BUCKET_US;
                    return us as f64 / 1000.0;
                }
            }
            max_us as f64 / 1000.0
        };
        let p99 = q(0.99);
        RoutePerfOut {
            route: self.route.clone(),
            budget_ms: self.budget_ms,
            qps: if span > 0 {
                count as f64 / span as f64
            } else {
                0.0
            },
            p50_ms: q(0.50),
            p95_ms: q(0.95),
            p99_ms: p99,
            max_ms: max_us as f64 / 1000.0,
            avg_ms: if count > 0 {
                sum_us as f64 / count as f64 / 1000.0
            } else {
                0.0
            },
            samples: count,
            inflight: self.inflight.load(Ordering::Relaxed),
            breach: self.budget_ms > 0.0 && count >= MIN_SAMPLES && p99 > self.budget_ms,
            window_sec: span,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RoutePerfOut {
    pub route: String,
    /// `route_ms` p99 预算（ms；0 = 不设预算）
    pub budget_ms: f64,
    pub qps: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub samples: u64,
    pub inflight: i64,
    /// `p99_ms > budget_ms`（且样本量足够）
    pub breach: bool,
    pub window_sec: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_reports_quantiles() {
        let p = RoutePerf::new("t", 1.0);
        for _ in 0..100 {
            p.record(0.5);
        }
        for _ in 0..10 {
            p.record(2.0);
        }
        let s = p.snapshot(60);
        assert_eq!(s.samples, 110, "窗口内应包含全部样本");
        assert!((s.p50_ms - 0.5).abs() < 0.06, "p50={}", s.p50_ms);
        assert!(s.p99_ms >= 1.9, "p99={}", s.p99_ms);
        assert!(s.breach, "p99 2.0ms > 预算 1ms 应判 breach");
    }

    #[test]
    fn budget_zero_never_breaches() {
        let p = RoutePerf::new("t", 0.0);
        for _ in 0..100 {
            p.record(50.0);
        }
        assert!(!p.snapshot(60).breach);
    }

    #[test]
    fn inflight_is_tracked() {
        let p = RoutePerf::new("t", 1.0);
        p.enter();
        p.enter();
        assert_eq!(p.snapshot(1).inflight, 2);
        p.leave();
        assert_eq!(p.snapshot(1).inflight, 1);
    }
}