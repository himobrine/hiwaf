//! 采集数据面配置。手写解析（不引 clap），减少依赖面。

use std::path::PathBuf;

/// 响应体采样策略。
///
/// * `Alert`（默认）：只保存最终 action 为 alert/block 的响应体；评分失败时按
///   `score_unavailable` 例外采样（即使当前是 `Off`，见 `filters.rs` 注释）。
/// * `All`：所有响应体都保存。
/// * `Off`：正常情况不保存；如果启用了 `--score`，仍会缓冲 64KB 以便评分失败时留证。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespBodyMode {
    Alert,
    All,
    Off,
}

impl RespBodyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::All => "all",
            Self::Off => "off",
        }
    }

    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "alert" => Ok(Self::Alert),
            "all" => Ok(Self::All),
            "off" => Ok(Self::Off),
            other => Err(format!("--resp-body 只支持 alert|all|off，收到 {other:?}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// 监听地址（客户端 -> 本代理）。
    pub listen: String,
    /// 上游（本代理 -> 真实后端）。
    pub upstream: String,
    /// 上游是否 TLS。
    pub upstream_tls: bool,
    /// 原始记录输出目录。
    pub out_dir: PathBuf,
    /// 单请求**落盘**的 body 上限（字节）。超出即截断并置 `body_truncated=true`。
    pub body_keep: usize,
    /// 单请求**缓冲**的 body 硬上限（字节）。超过即停止累积（防大文件上传打爆内存）。
    pub body_limit: usize,
    /// 是否采集 body。`--no-body` 时恒为空（隐私模式）。
    pub collect_body: bool,
    /// 请求/响应头落盘上限（规范化 `name: value\r\n` 字节；只保留完整头对）。
    pub headers_keep: usize,
    /// 响应体采样策略。
    pub resp_body_mode: RespBodyMode,
    /// 响应体落盘上限（原始 wire bytes，默认 64KB）。
    pub resp_body_keep: usize,
    /// 单个 jsonl 文件轮转大小（字节）；默认 256 MiB，且 UTC 跨天也会轮转。
    pub file_size: u64,
    /// 写入队列容量：满了就**丢记录并计数**，绝不阻塞转发（采集不能变成 DoS 面）。
    pub channel: usize,
    /// 是否加载上线模型做 **dry-run** 判定（只记录，永不阻断）。
    pub score: bool,
    /// 模型产物目录（`decision_policy.json` + 两个 ONNX）。
    pub artifacts: PathBuf,
    /// 运行指标 JSON 输出路径（供控制台读；`None` = 只打 stderr）。
    pub stats_out: Option<PathBuf>,
    /// 指标刷新周期（秒）。
    pub stats_interval: u64,
    /// 规则集路径（`rules_authoritative.json`）。`None` = 不启用规则通道。
    pub rules: Option<PathBuf>,
    /// 热重载轮询周期（秒）。0 = 关闭轮询（等同 `--no-reload`）。
    pub reload_interval: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:6188".to_string(),
            upstream: "127.0.0.1:8080".to_string(),
            upstream_tls: false,
            out_dir: PathBuf::from("../traindata/proxy"),
            body_keep: 64 * 1024,
            body_limit: 1024 * 1024,
            collect_body: true,
            headers_keep: 8 * 1024,
            resp_body_mode: RespBodyMode::Alert,
            resp_body_keep: 64 * 1024,
            file_size: 256 * 1024 * 1024,
            channel: 8192,
            score: false,
            artifacts: PathBuf::from("../python/artifacts"),
            stats_out: None,
            stats_interval: 60,
            // 默认指向产物目录里的现役规则集；文件不存在就自动不启用（见 main.rs）。
            rules: Some(PathBuf::from("../python/artifacts/rules_authoritative.json")),
            reload_interval: 5,
        }
    }
}

pub fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut c = Config::default();
    let mut it = args.peekable();
    // 跳过 argv[0]
    let _ = it.next();
    while let Some(a) = it.next() {
        let mut val = |name: &str| -> Result<String, String> {
            it.next().ok_or_else(|| format!("{name} 缺少取值"))
        };
        match a.as_str() {
            "--listen" => c.listen = val("--listen")?,
            "--upstream" => c.upstream = val("--upstream")?,
            "--out" => c.out_dir = PathBuf::from(val("--out")?),
            "--body-keep" => {
                c.body_keep = val("--body-keep")?
                    .parse()
                    .map_err(|e| format!("--body-keep 解析失败: {e}"))?
            }
            "--body-limit" => {
                c.body_limit = val("--body-limit")?
                    .parse()
                    .map_err(|e| format!("--body-limit 解析失败: {e}"))?
            }
            "--headers-keep" => {
                c.headers_keep = val("--headers-keep")?
                    .parse()
                    .map_err(|e| format!("--headers-keep 解析失败: {e}"))?
            }
            "--resp-body" => c.resp_body_mode = RespBodyMode::parse(&val("--resp-body")?)?,
            "--resp-body-keep" => {
                c.resp_body_keep = val("--resp-body-keep")?
                    .parse()
                    .map_err(|e| format!("--resp-body-keep 解析失败: {e}"))?
            }
            "--file-size-mb" => {
                let mb: u64 = val("--file-size-mb")?
                    .parse()
                    .map_err(|e| format!("--file-size-mb 解析失败: {e}"))?;
                c.file_size = mb.max(1) * 1024 * 1024;
            }
            "--channel" => {
                c.channel = val("--channel")?
                    .parse()
                    .map_err(|e| format!("--channel 解析失败: {e}"))?
            }
            "--upstream-tls" => c.upstream_tls = true,
            "--no-body" => c.collect_body = false,
            "--score" => c.score = true,
            "--artifacts" => c.artifacts = PathBuf::from(val("--artifacts")?),
            "--stats-out" => c.stats_out = Some(PathBuf::from(val("--stats-out")?)),
            "--stats-interval" => {
                c.stats_interval = val("--stats-interval")?
                    .parse()
                    .map_err(|e| format!("--stats-interval 解析失败: {e}"))?
            }
            "--rules" => c.rules = Some(PathBuf::from(val("--rules")?)),
            "--no-rules" => c.rules = None,
            "--no-reload" => c.reload_interval = 0,
            "--reload-interval" => {
                c.reload_interval = val("--reload-interval")?
                    .parse()
                    .map_err(|e| format!("--reload-interval 解析失败: {e}"))?
            }
            "-h" | "--help" => return Err(HELP.to_string()),
            other => return Err(format!("未知参数：{other}\n\n{HELP}")),
        }
    }
    if c.body_keep > c.body_limit {
        return Err("--body-keep 不能大于 --body-limit".to_string());
    }
    // 这两个是取证包硬上限；允许调小，不允许调大，避免误配置把内存/磁盘吃穿。
    if c.headers_keep == 0 || c.headers_keep > 8 * 1024 {
        return Err("--headers-keep 必须在 1..=8192 字节之间".to_string());
    }
    if c.resp_body_keep == 0 || c.resp_body_keep > 64 * 1024 {
        return Err("--resp-body-keep 必须在 1..=65536 字节之间".to_string());
    }
    Ok(c)
}

impl Config {
    /// 上游 host（去端口），用作 TLS SNI / Host hint。
    pub fn host_hint(&self) -> &str {
        let u = self.upstream.as_str();
        match u.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => u,
        }
    }
}

pub const HELP: &str = "\
用法: waf-collector [选项]

  --listen <addr>        监听地址（默认 127.0.0.1:6188）
  --upstream <addr>      上游地址（默认 127.0.0.1:8080）
  --upstream-tls         上游使用 TLS
  --out <dir>            原始记录输出目录（默认 ../traindata/proxy）
  --body-keep <bytes>    单请求落盘 body 上限（默认 65536）
  --body-limit <bytes>   单请求缓冲硬上限（默认 1048576，防 OOM）
  --headers-keep <bytes> 请求/响应头落盘上限（默认 8192；只保留完整头对）
  --resp-body <mode>     响应体采样：alert（默认，只存 alert/block）/ all / off
  --resp-body-keep <n>   响应体落盘上限（默认 65536；原始 wire bytes）
  --file-size-mb <n>     单文件轮转大小 MB（默认 256；UTC 跨天也会轮转）
  --channel <n>          写队列容量（默认 8192；满了丢记录并计数，不阻塞转发）
  --no-body              不采集 body（隐私模式）
  --score                **dry-run** 加载上线模型，把判定结果写进记录的 `pred` 字段
                         （只记录、**永不阻断**；阈值尚未在真实本地良性上重标定）
  --artifacts <dir>      模型产物目录（默认 ../python/artifacts）
  --stats-out <file>     运行指标 JSON 输出（控制台读；默认只打 stderr）
  --stats-interval <sec> 指标刷新周期（默认 60 秒）
  --rules <file>         规则集路径（默认 ../python/artifacts/rules_authoritative.json；
                         文件不存在则自动不启用规则通道）
  --no-rules             不加载规则通道
  --reload-interval <s>  热重载轮询周期（默认 5 秒）
  --no-reload            关闭热重载轮询（改规则就得重启 —— 只用于排查）
  -h, --help             显示本帮助

热重载：每 N 秒比对 `decision_policy.json` 与规则集的 sha1，**校验通过才原子替换**；
校验失败保留旧策略并把失败原因写进指标（控制台会亮告警）。换**模型**仍需重启：
阈值可热换，ONNX 会话不热换（换模型的热重载风险远大于收益）。

注意：本程序**只采集原始记录，不打任何 label**。良性/攻击标签由
`python/collect_http_log.py` 按**出处**（蜜罐路径 / 红队时间窗 / 复核清单）决定。";
