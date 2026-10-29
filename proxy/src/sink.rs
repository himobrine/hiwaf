//! 记录结构 + 落盘 sink。
//!
//! **关键设计：本模块（以及整个数据面）不写任何 `label` 字段。**
//! 真实流量里的攻击没有标签，用内容正则去标等于把要替换掉的规则抄进训练集（循环论证）。
//! 标签一律由 `python/collect_http_log.py` 按**出处**决定。这里只记录"看到了什么"。
//!
//! 采集端还有一条硬约束：**不能变成 DoS 面**。所以写盘走有界队列，
//! 队列满就丢记录并计数，永不阻塞转发（fail-open）。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 一条原始请求记录。字段名刻意与 `collect_http_log.py` 的统一 schema 对齐
/// （`method/path/query/body/ts/src_ip/status/ua/referer`），其余为流级补充字段。
#[derive(Debug, serde::Serialize)]
pub struct BodyOut {
    /// 原始存储字节的 base64（可能被上限截断；截断标志见 `truncated`）。
    pub b64: String,
    /// 响应/请求体总字节数（截断前）。
    pub wire_bytes: usize,
    /// 实际存储的原始字节数。
    pub stored_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ResponseOut {
    /// 是否真的拿到了上游响应（连接失败/上游超时为 false）。
    pub captured: bool,
    pub http_version: String,
    pub status: u16,
    /// 有序头数组，保留重复头：[["Set-Cookie","a=1"], ...]。
    pub headers: Vec<(String, String)>,
    /// 截断前所有解析后头行的规范化总字节；不含起始行。
    pub headers_total_bytes: usize,
    /// 实际保留的完整头对字节数。
    pub headers_stored_bytes: usize,
    pub headers_truncated: bool,
    pub sampling_mode: String,
    pub body_sampled: bool,
    /// null = 未采样；采样到空体时是 `Some(BodyOut { b64: "", ... })`。
    pub body: Option<BodyOut>,
    /// sampled / action_allow / off / score_unavailable / no_response / no_action
    pub body_reason: String,
    /// 响应体总字节（截断前）。
    pub body_wire_bytes: usize,
    pub body_truncated: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct Record {
    /// epoch 毫秒（`collect_http_log.parse_ts` 认这个形态，按本地时间解析）
    pub ts: i64,
    pub src_ip: String,
    pub src_port: u16,
    /// IP 名单命中：`whitelist` / `blacklist`（None = 未命中）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_list: Option<String>,
    pub host: String,
    /// 命中的路由名（多端口单进程时用于区分站点）。
    pub route: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub http_version: String,
    /// 请求头有序数组；重复头保留。顺序是解析后顺序，不是 wire order。
    pub headers: Vec<(String, String)>,
    pub headers_total_bytes: usize,
    pub headers_stored_bytes: usize,
    pub headers_truncated: bool,
    /// **训练兼容字段**：仅文本请求体；二进制时为空串。二进制请读 `body_b64`。
    pub body: String,
    /// 请求体精确原始字节的 base64；`--no-body` 时为 None。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
    pub body_is_binary: bool,
    pub body_sampled: bool,
    /// sampled / collect_body_off
    pub body_reason: String,
    /// 请求体**总**字节数（即使 body 被截断也准确）
    pub body_len: usize,
    pub body_truncated: bool,
    pub ua: String,
    pub referer: String,
    pub status: u16,
    /// 端到端耗时（ms，代理视角）
    pub dur_ms: f64,
    /// 客户端上行字节（近似：请求体）
    pub bytes_in: u64,
    /// 后端下行字节（响应体累计）
    pub bytes_out: u64,
    /// 采集来源标记（供下游区分采集点）
    pub src_kind: &'static str,
    /// **诊断**：上线模型的判定结果（dry-run，仅记录，永不阻断）。
    ///
    /// ⚠️ 这不是 `label`，下游 `collect_http_log.py` 的 `parse_jsonl` 只保留已知键，
    /// 因此模型输出**结构上不可能**变成训练标签 —— 这正是我们要的：
    /// 标签只能来自出处，绝不能来自模型自己。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pred: Option<Pred>,
    /// 规则通道命中（第三通道，**独立于模型**）。
    ///
    /// 刻意放在**记录顶层**而不是塞进 `pred`：规则通道与监督通道是并列的两条通道，
    /// 混在一起以后没人分得清"这个 block 是模型判的还是规则判的"。同样地：
    /// 命中是**证据**，不是标签。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<RulesOut>,
    /// 响应侧取证包（头/状态/版本/按策略采样的体）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseOut>,
}

/// 规则通道在一条请求上的结果。
#[derive(Debug, serde::Serialize)]
pub struct RulesOut {
    /// 判定这条请求时用的规则集指纹（回答"是哪一版规则判的"）
    pub rule_set_sha1_16: String,
    /// 命中明细（每条最多一个 `(规则, 作用域)`）
    pub hits: Vec<waf_ai_proto::rules::RuleHit>,
    /// 全部命中的权重之和（按规则去重）——**证据**
    pub weight: f64,
    /// 只有 `action=block` 的规则才计入的权重之和 —— **阻断预算**
    pub block_weight: f64,
    /// 规则通道**独立**是否达到阻断线（`block_weight >= min_weight_to_block`）。
    /// 注意：这不等于最终动作 —— 最终动作由融合策略决定，且规则通道总开关在策略里。
    pub block: bool,
}

/// 单条请求的模型判定留证（dry-run）。
#[derive(Debug, serde::Serialize)]
pub struct Pred {
    /// 融合动作：`allow` / `block` / `alert`
    pub action: String,
    pub supervised_score: f32,
    pub supervised_threshold: f32,
    pub supervised_flagged: bool,
    pub zero_day_score: f32,
    pub zero_day_threshold: f32,
    /// 零日通道**原始**穿阈（即使开关关闭也记录，"本来会不会告警"的证据）
    pub zero_day_score_crossed: bool,
    /// 零日通道**生效**命中（关了开关就恒为 false）
    pub zero_day_flagged: bool,
    pub zero_day_enabled: bool,
    /// 产物目录（回答"这条分数是哪套产物算的"）
    pub artifacts: String,
    /// 多分类 argmax 下标（**仅作攻击类型归类**，不用于判定）。
    /// 名称映射走 `decision_policy.json.supervised.labels`（控制面统一解释）。
    pub attack_label: usize,
    /// **诊断**：TreeSHAP Top-K 特征贡献（供控制台详情页显示"为什么给这个分"）。
    /// 树件/特征名缺失时为空，序列化时省略。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shap_topk: Vec<waf_ai_proto::engine::ShapItem>,
    /// 规则通道**被策略认可**的命中权重（未被认可时恒为 0）。
    /// 与顶层 `rules.weight` 的区别：那个是**证据**（多大都记），这个是**实际参与融合**的值。
    pub rule_weight: f64,
    /// 规则通道被采纳的阻断权重（只有 `action=block` 的命中计入）。
    pub rule_block_weight: f64,
    /// 规则通道是否达到阻断线 —— `action=block` 且 `supervised_flagged=false` 时，
    /// 就是规则把它拦下来的（可审计归因）。
    pub rules_flagged: bool,
    /// `true` = 本次判定只写记录，未执行拦截（`block_mode=off/dry_run`）。
    pub dry_run: bool,
    /// `true` = 这次 `action=block` **真的返回了 403**（`block_mode=enforce`）。
    pub enforced: bool,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub written: AtomicU64,
    pub dropped_full: AtomicU64,
    pub dropped_io: AtomicU64,
    pub bytes: AtomicU64,
    /// 规则通道：有命中的请求数
    pub rule_hit_lines: AtomicU64,
    /// 规则通道：命中数总计（含同一请求多条规则）
    pub rule_hits: AtomicU64,
    /// 规则通道：达到阻断线的请求数（dry-run 下**不**真的阻断）
    pub rule_block_lines: AtomicU64,
    /// 热重载成功 / 失败次数
    pub reload_ok: AtomicU64,
    pub reload_fail: AtomicU64,
    /// `--resp-body=off` 因评分失败被临时突破、采样留证的次数。
    pub resp_body_off_overrides: AtomicU64,
    /// 真正被 403 拦下的请求数（`block_mode=enforce` 且命中 block）。
    pub blocked: AtomicU64,
}

impl Stats {
    pub fn snapshot(&self) -> String {
        format!(
            "written={} dropped(queue_full)={} dropped(io)={} bytes={} \
             rule_hit_lines={} rule_hits={} rule_block_lines={} reload_ok={} reload_fail={} \
             resp_body_off_overrides={} blocked={}",
            self.written.load(Ordering::Relaxed),
            self.dropped_full.load(Ordering::Relaxed),
            self.dropped_io.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.rule_hit_lines.load(Ordering::Relaxed),
            self.rule_hits.load(Ordering::Relaxed),
            self.rule_block_lines.load(Ordering::Relaxed),
            self.reload_ok.load(Ordering::Relaxed),
            self.reload_fail.load(Ordering::Relaxed),
            self.resp_body_off_overrides.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone)]
pub struct Sink {
    tx: SyncSender<Record>,
    pub stats: Arc<Stats>,
}

impl Sink {
    /// 起一个写线程；返回的 `Sink` 可被所有工作线程共享。
    pub fn start(out_dir: &Path, file_size: u64, cap: usize) -> std::io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;
        let (tx, rx) = sync_channel::<Record>(cap.max(1));
        let stats = Arc::new(Stats::default());
        let st = Arc::clone(&stats);
        let dir: PathBuf = out_dir.to_path_buf();
        thread::Builder::new()
            .name("collector-writer".to_string())
            .spawn(move || writer_loop(rx, dir, file_size, st))?;
        Ok(Self { tx, stats })
    }

    /// 非阻塞投递：满了就丢并计数（**绝不阻塞转发**）。
    pub fn try_emit(&self, rec: Record) {
        match self.tx.try_send(rec) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let n = self.stats.dropped_full.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n % 10_000 == 0 {
                    eprintln!("[sink] 写队列已满，已丢 {n} 条（转发未受阻；考虑调大 --channel 或换更快的盘）");
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                self.stats.dropped_io.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// UTC 日期 YYYYMMDD（不引 chrono；Howard Hinnant 的 civil_from_days）。
fn utc_day(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}")
}

/// 创建 `raw-YYYYMMDD-NNNNN.jsonl`；同日多个文件按序号递增，跨天从 0 重新开始。
fn open_rotated(dir: &Path, day: &str, start_seq: u64) -> std::io::Result<(File, PathBuf, u64)> {
    let mut seq = start_seq;
    loop {
        let p = dir.join(format!("raw-{day}-{seq:05}.jsonl"));
        match OpenOptions::new().create_new(true).append(true).open(&p) {
            Ok(f) => return Ok((f, p, seq)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && seq < start_seq + 100_000 => {
                seq += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

fn writer_loop(
    rx: std::sync::mpsc::Receiver<Record>,
    dir: PathBuf,
    file_size: u64,
    stats: Arc<Stats>,
) {
    let mut day = utc_day(now_ms());
    let (mut file, mut path, mut seq) = match open_rotated(&dir, &day, 0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[sink] 无法在 {} 创建输出文件：{e}", dir.display());
            return;
        }
    };
    let mut cur: u64 = 0;
    let mut last_report = std::time::Instant::now();
    eprintln!("[sink] -> {}", path.display());

    while let Ok(rec) = rx.recv() {
        // 跨 UTC 天先轮转；文件名里的日期也是清理任务按天聚合的依据。
        let rec_day = utc_day(rec.ts);
        if rec_day != day {
            day = rec_day;
            match open_rotated(&dir, &day, 0) {
                Ok((f, p, s)) => {
                    file = f;
                    path = p;
                    seq = s;
                    cur = 0;
                    eprintln!("[sink] 跨天轮转 -> {}", path.display());
                }
                Err(e) => eprintln!("[sink] 跨天轮转失败：{e}"),
            }
        }
        // serde_json 负责转义（body 里必然有引号/反斜杠/控制字符）
        let line = match serde_json::to_string(&rec) {
            Ok(s) => s,
            Err(e) => {
                stats.dropped_io.fetch_add(1, Ordering::Relaxed);
                eprintln!("[sink] 序列化失败（不致命，已丢 1 条）：{e}");
                continue;
            }
        };
        let mut buf = line.into_bytes();
        buf.push(b'\n');
        match file.write_all(&buf) {
            Ok(()) => {
                cur += buf.len() as u64;
                stats.written.fetch_add(1, Ordering::Relaxed);
                stats.bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                let n = stats.dropped_io.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n % 1000 == 0 {
                    eprintln!("[sink] 写盘失败（已丢 {n} 条，转发不受影响）：{e}");
                }
                // 盘满/句柄失效时尝试换文件继续，避免永久性丢数据
                if let Ok((f, p, s)) = open_rotated(&dir, &day, seq + 1) {
                    seq = s;
                    file = f;
                    path = p;
                    cur = 0;
                    eprintln!("[sink] 写失败后换文件继续 -> {}", path.display());
                }
                continue;
            }
        }
        if cur >= file_size {
            match open_rotated(&dir, &day, seq + 1) {
                Ok((f, p, s)) => {
                    seq = s;
                    file = f;
                    path = p;
                    cur = 0;
                    eprintln!("[sink] 轮转 -> {}", path.display());
                }
                Err(e) => eprintln!("[sink] 轮转失败：{e}"),
            }
        }
        if last_report.elapsed() > Duration::from_secs(60) {
            last_report = std::time::Instant::now();
            eprintln!("[sink] {}", stats.snapshot());
        }
    }
    let _ = file.flush();
    eprintln!("[sink] 退出，累计 {}", stats.snapshot());
}

#[cfg(test)]
mod tests {
    use super::utc_day;

    #[test]
    fn utc_day_epoch_and_leap() {
        assert_eq!(utc_day(0), "19700101");
        assert_eq!(utc_day(951_782_400_000), "20000229");
        assert_eq!(utc_day(1_709_164_800_000), "20240229");
    }
}
