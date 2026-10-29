//! 采集数据面配置。手写解析（不引 clap），减少依赖面。

use std::path::PathBuf;

/// 响应体采样策略。
///
/// * `Alert`（默认）：只保存最终 action 为 alert/block 的响应体；评分失败时按
///   `score_unavailable` 例外采样（即使当前是 `Off`，见 `filters.rs` 注释）。
/// * `All`：所有响应体都保存。
/// * `Off`：正常情况不保存；如果启用了判定（`block_mode != off`），仍会缓冲 64KB
///   以便评分失败时留证。
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

/// 判定/阻断模式。
///
/// * `Off`：纯采集，不加载模型、不跑规则、不做判定。
/// * `DryRun`：加载模型 + 规则，判定结果只写进记录（`pred.action`），**永不阻断**。
/// * `Enforce`：同 `DryRun`，但命中 `block` 时真正返回 403。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    Off,
    DryRun,
    Enforce,
}

impl BlockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::DryRun => "dry_run",
            Self::Enforce => "enforce",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(Self::Off),
            "dry_run" | "dry-run" => Ok(Self::DryRun),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "--block-mode 只支持 off|dry_run|enforce，收到 {other:?}"
            )),
        }
    }

    /// 是否要加载模型 / 跑规则。
    pub fn score_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// 一条路由：一个监听端口 → 一个上游。
///
/// 多路由共用一个进程：共享写盘队列、模型会话、规则引擎与指标文件，
/// 但每条路由有独立的监听地址与上游。
#[derive(Debug, Clone)]
pub struct Route {
    /// 路由名（控制台展示 / 记录里的 `route` 字段）。
    pub name: String,
    /// 监听地址（客户端 -> 本代理）。
    pub listen: String,
    /// 上游（本代理 -> 真实后端）。
    pub upstream: String,
    /// 上游是否 TLS。
    pub upstream_tls: bool,
}

impl Route {
    /// 上游 host（去端口），用作 TLS SNI / Host hint。
    pub fn host_hint(&self) -> &str {
        split_host(&self.upstream)
    }
}

fn split_host(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => addr,
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// 路由表。至少一条；没有 `--route` 时由旧 `--listen/--upstream` 合成一条。
    pub routes: Vec<Route>,
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
    /// 判定/阻断模式（`off` / `dry_run` / `enforce`）。
    pub block_mode: BlockMode,
    /// 监督通道是否**允许单独阻断**（默认 `true`）。
    ///
    /// `false` 时模型命中只降级成 `alert`（分数/穿阈/规则证据照常落盘），
    /// 只有规则通道达到阻断线才真正返回 403。用于模型在跨分布流量上误报偏高、
    /// 但规则集已经足够精确的部署（`--no-supervised-block`）。
    pub supervised_block: bool,
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
            routes: vec![Route {
                name: "default".to_string(),
                listen: "0.0.0.0:6188".to_string(),
                upstream: "127.0.0.1:8080".to_string(),
                upstream_tls: false,
            }],
            out_dir: PathBuf::from("../traindata/proxy"),
            body_keep: 64 * 1024,
            body_limit: 1024 * 1024,
            collect_body: true,
            headers_keep: 8 * 1024,
            resp_body_mode: RespBodyMode::Alert,
            resp_body_keep: 64 * 1024,
            file_size: 256 * 1024 * 1024,
            channel: 8192,
            block_mode: BlockMode::Off,
            supervised_block: true,
            artifacts: PathBuf::from("../python/artifacts"),
            stats_out: None,
            stats_interval: 60,
            // 默认指向产物目录里的现役规则集；文件不存在就自动不启用（见 main.rs）。
            rules: Some(PathBuf::from("../python/artifacts/rules_authoritative.json")),
            reload_interval: 5,
        }
    }
}

impl Config {
    /// 顶层 `listen` 兼容字段 = 第一条路由。
    pub fn listen(&self) -> &str {
        self.routes.first().map(|r| r.listen.as_str()).unwrap_or("")
    }

    /// 顶层 `upstream` 兼容字段 = 第一条路由。
    pub fn upstream(&self) -> &str {
        self.routes.first().map(|r| r.upstream.as_str()).unwrap_or("")
    }
}

fn looks_like_addr(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((h, p)) => !h.is_empty() && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// 解析 `--route name=site-a,listen=0.0.0.0:80,upstream=127.0.0.1:8080,tls=0`
fn parse_route(spec: &str, idx: usize) -> Result<Route, String> {
    let mut name: Option<String> = None;
    let mut listen: Option<String> = None;
    let mut upstream: Option<String> = None;
    let mut upstream_tls = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("--route 项 {part:?} 必须是 key=value"))?;
        match k.trim() {
            "name" => name = Some(v.trim().to_string()),
            "listen" => listen = Some(v.trim().to_string()),
            "upstream" => upstream = Some(v.trim().to_string()),
            "tls" => {
                upstream_tls = matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            }
            other => return Err(format!("--route 未知键 {other:?}（只支持 name/listen/upstream/tls）")),
        }
    }
    let listen = listen.ok_or_else(|| "--route 缺少 listen".to_string())?;
    let upstream = upstream.ok_or_else(|| "--route 缺少 upstream".to_string())?;
    if !looks_like_addr(&listen) {
        return Err(format!("--route listen 必须是 host:port，收到 {listen:?}"));
    }
    if !looks_like_addr(&upstream) {
        return Err(format!("--route upstream 必须是 host:port，收到 {upstream:?}"));
    }
    if listen == upstream {
        return Err(format!("--route 的 listen 与 upstream 不能相同（自环）：{listen}"));
    }
    let name = name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("route{}", idx + 1));
    Ok(Route {
        name,
        listen,
        upstream,
        upstream_tls,
    })
}

pub fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut c = Config::default();
    let mut it = args.peekable();
    // 跳过 argv[0]
    let _ = it.next();

    // 旧单路由参数：只有没给 --route 时才允许使用。
    let mut legacy_listen: Option<String> = None;
    let mut legacy_upstream: Option<String> = None;
    let mut legacy_tls = false;
    let mut routes: Vec<Route> = Vec::new();
    let mut block_mode_explicit = false;
    let mut score_alias = false;

    while let Some(a) = it.next() {
        let mut val = |name: &str| -> Result<String, String> {
            it.next().ok_or_else(|| format!("{name} 缺少取值"))
        };
        match a.as_str() {
            "--route" => routes.push(parse_route(&val("--route")?, routes.len())?),
            "--listen" => legacy_listen = Some(val("--listen")?),
            "--upstream" => legacy_upstream = Some(val("--upstream")?),
            "--upstream-tls" => legacy_tls = true,
            "--block-mode" => {
                c.block_mode = BlockMode::parse(&val("--block-mode")?)?;
                block_mode_explicit = true;
            }
            // 旧开关：等价于 --block-mode dry_run（显式 --block-mode 优先）。
            "--score" => score_alias = true,
            "--supervised-block" => c.supervised_block = true,
            "--no-supervised-block" => c.supervised_block = false,
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
            "--no-body" => c.collect_body = false,
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

    if !routes.is_empty() {
        if legacy_listen.is_some() || legacy_upstream.is_some() || legacy_tls {
            return Err(
                "--route 与旧的 --listen/--upstream/--upstream-tls 不能同时使用".to_string(),
            );
        }
        c.routes = routes;
    } else {
        if let Some(l) = legacy_listen {
            c.routes[0].listen = l;
        }
        if let Some(u) = legacy_upstream {
            c.routes[0].upstream = u;
        }
        if legacy_tls {
            c.routes[0].upstream_tls = true;
        }
    }

    if !block_mode_explicit && score_alias {
        c.block_mode = BlockMode::DryRun;
    }

    // 路由校验：name / listen 唯一，地址形态正确，禁止自环。
    let mut names = std::collections::HashSet::new();
    let mut listens = std::collections::HashSet::new();
    for r in &c.routes {
        if r.name.trim().is_empty() {
            return Err("--route name 不能为空".to_string());
        }
        if !names.insert(r.name.clone()) {
            return Err(format!("--route name 重复：{}", r.name));
        }
        if !looks_like_addr(&r.listen) {
            return Err(format!("listen 必须是 host:port，收到 {:?}", r.listen));
        }
        if !looks_like_addr(&r.upstream) {
            return Err(format!("upstream 必须是 host:port，收到 {:?}", r.upstream));
        }
        if !listens.insert(r.listen.clone()) {
            return Err(format!("listen 重复：{}（一个端口只能有一条路由）", r.listen));
        }
        if r.listen == r.upstream {
            return Err(format!("listen 与 upstream 不能相同（自环）：{}", r.listen));
        }
    }
    if c.routes.is_empty() {
        return Err("至少需要一条路由".to_string());
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

pub const HELP: &str = "\
用法: waf-collector [选项]

路由（可重复；不给 --route 时用 --listen/--upstream 合成一条）:
  --route name=<名>,listen=<addr>,upstream=<addr>,tls=0|1
                         一条路由：监听 addr -> 上游 addr。可写多次实现多端口。
  --listen <addr>        单路由监听地址（默认 0.0.0.0:6188）
  --upstream <addr>      单路由上游地址（默认 127.0.0.1:8080）
  --upstream-tls         单路由上游使用 TLS
  --block-mode <mode>    off（纯采集，默认）/ dry_run（只记录）/ enforce（命中返回 403）
  --score                旧开关，等价于 --block-mode dry_run
  --supervised-block     模型命中可单独阻断（默认）
  --no-supervised-block  模型命中只告警，只有规则通道能阻断

其他:
  --out <dir>            原始记录输出目录（默认 ../traindata/proxy）
  --body-keep <bytes>    单请求落盘 body 上限（默认 65536）
  --body-limit <bytes>   单请求缓冲硬上限（默认 1048576，防 OOM）
  --headers-keep <bytes> 请求/响应头落盘上限（默认 8192；只保留完整头对）
  --resp-body <mode>     响应体采样：alert（默认，只存 alert/block）/ all / off
  --resp-body-keep <n>   响应体落盘上限（默认 65536；原始 wire bytes）
  --file-size-mb <n>     单文件轮转大小 MB（默认 256；UTC 跨天也会轮转）
  --channel <n>          写队列容量（默认 8192；满了丢记录并计数，不阻塞转发）
  --no-body              不采集 body（隐私模式）
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

#[cfg(test)]
mod tests {
    use super::{parse_args, BlockMode};

    fn parse(args: &[&str]) -> Result<super::Config, String> {
        let mut v = vec!["waf-collector".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        parse_args(v.into_iter())
    }

    #[test]
    fn legacy_single_route_still_works() {
        let c = parse(&["--listen", "0.0.0.0:6188", "--upstream", "127.0.0.1:80"]).unwrap();
        assert_eq!(c.routes.len(), 1);
        assert_eq!(c.routes[0].listen, "0.0.0.0:6188");
        assert_eq!(c.routes[0].upstream, "127.0.0.1:80");
        assert_eq!(c.block_mode, BlockMode::Off);
    }

    #[test]
    fn multiple_routes_parse_and_share_defaults() {
        let c = parse(&[
            "--route",
            "name=a,listen=0.0.0.0:80,upstream=127.0.0.1:8080,tls=0",
            "--route",
            "name=b,listen=0.0.0.0:443,upstream=127.0.0.1:8443,tls=1",
        ])
        .unwrap();
        assert_eq!(c.routes.len(), 2);
        assert_eq!(c.routes[0].name, "a");
        assert!(!c.routes[0].upstream_tls);
        assert_eq!(c.routes[1].name, "b");
        assert!(c.routes[1].upstream_tls);
        assert_eq!(c.listen(), "0.0.0.0:80");
    }

    #[test]
    fn route_rejects_duplicate_listen_and_self_loop() {
        let dup = parse(&[
            "--route",
            "name=a,listen=127.0.0.1:80,upstream=127.0.0.1:8080",
            "--route",
            "name=b,listen=127.0.0.1:80,upstream=127.0.0.1:8081",
        ]);
        assert!(dup.unwrap_err().contains("listen 重复"));

        let looped = parse(&[
            "--route",
            "name=a,listen=127.0.0.1:80,upstream=127.0.0.1:80",
        ]);
        assert!(looped.unwrap_err().contains("自环"));
    }

    #[test]
    fn route_conflicts_with_legacy_flags() {
        let r = parse(&[
            "--route",
            "name=a,listen=127.0.0.1:80,upstream=127.0.0.1:8080",
            "--listen",
            "127.0.0.1:81",
        ]);
        assert!(r.unwrap_err().contains("不能同时使用"));
    }

    #[test]
    fn block_mode_and_legacy_score_alias() {
        assert_eq!(parse(&["--block-mode", "enforce"]).unwrap().block_mode, BlockMode::Enforce);
        assert_eq!(parse(&["--score"]).unwrap().block_mode, BlockMode::DryRun);
        // 显式 --block-mode 优先于旧 --score。
        assert_eq!(
            parse(&["--score", "--block-mode", "off"]).unwrap().block_mode,
            BlockMode::Off
        );
        assert!(parse(&["--block-mode", "nope"]).is_err());
    }

    #[test]
    fn supervised_block_defaults_on_and_can_be_disabled() {
        assert!(parse(&[]).unwrap().supervised_block);
        assert!(!parse(&["--no-supervised-block"]).unwrap().supervised_block);
        // 后写的开关生效，便于运维在脚本里覆盖。
        assert!(parse(&["--no-supervised-block", "--supervised-block"])
            .unwrap()
            .supervised_block);
    }
}
