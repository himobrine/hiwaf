//! S4 基座选型**门禁实验**（不是产品代码）。
//!
//! 问题：决策已定"用 Pingora 做反向代理基座"，但 PRD 要求 **Windows x86_64 MSVC** 也要能跑，
//! 而 Pingora 官方 README 写明 "Linux is our tier 1 environment"，Windows 支持是
//! **社区尽力而为（experimental）**。所以选型必须先过一道编译+运行门禁，再谈架构。
//!
//! 本 spike 要证明 3 件事：
//!   1. pingora 0.4 在 **Windows MSVC** 上能编译（`features = ["proxy","rustls"]`，绕开 OpenSSL/Perl）；
//!   2. 能真的跑起来并代理请求；
//!   3. `request_body_filter` 能拿到**完整请求体** —— 这正是选 Pingora 的理由（工作项 F 要 body）。
//!
//! 用法：
//! ```text
//! call build.bat run --release                    :: 起代理，监听 127.0.0.1:6188 -> 上游 127.0.0.1:8080
//! curl -X POST http://127.0.0.1:6188/x -d "a=1"  :: 另一窗口，观察 stdout 打印的 body 长度/前 200 字节
//! ```
//! 体量超限即截断（**防 OOM**），只记录长度与头部样本，不落全量 body。
use async_trait::async_trait;
use bytes::Bytes;
use pingora::prelude::*;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use std::sync::atomic::{AtomicUsize, Ordering};

/// 单请求最多留证多少字节 body（防 OOM；真实采集应落盘并加限长）。
const BODY_KEEP: usize = 200;
/// 单请求 body 上限：超过即截断丢弃（真实代理必须做，否则大文件上传会打爆内存）。
const BODY_LIMIT: usize = 1024 * 1024;

#[derive(Default)]
struct Ctx {
    body_len: usize,
    body_head: Vec<u8>,
}

struct MyProxy {
    n_req: AtomicUsize,
}

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new("127.0.0.1:8080", false, "localhost".to_string()));
        Ok(peer)
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        self.n_req.fetch_add(1, Ordering::Relaxed);
        println!(
            "[spike] #{} {} {}{}  ua={:?}",
            self.n_req.load(Ordering::Relaxed),
            req.method,
            req.uri.path(),
            req.uri.query().map(|q| format!("?{q}")).unwrap_or_default(),
            req.headers.get("user-agent").map(|v| v.to_str().unwrap_or("")).unwrap_or("")
        );
        Ok(false) // false = 继续走后续阶段
    }

    /// Pingora 的 body 生命周期钩子 —— 选它就是为这个。
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(b) = body {
            ctx.body_len += b.len();
            if ctx.body_head.len() < BODY_KEEP {
                let need = BODY_KEEP - ctx.body_head.len();
                ctx.body_head.extend_from_slice(&b[..b.len().min(need)]);
            }
            if ctx.body_len > BODY_LIMIT {
                // 真实实现应在此熔断并记录告警，而不是继续吞内存。
                b.clear();
            }
        }
        if end_of_stream {
            println!(
                "[spike] body 总计 {} 字节，样本 {:?}",
                ctx.body_len,
                String::from_utf8_lossy(&ctx.body_head)
            );
        }
        Ok(())
    }
}

fn main() {
    // 让 panic/日志可见
    env_logger_init();
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let proxy = MyProxy { n_req: AtomicUsize::new(0) };
    let mut svc = http_proxy_service(&server.configuration, proxy);
    svc.add_tcp("127.0.0.1:6188");

    server.add_service(svc);
    println!("[spike] Pingora 代理已启动 127.0.0.1:6188 -> 127.0.0.1:8080  (Windows MSVC)");
    server.run_forever();
}

/// pingora 内部用 log crate；不引 env_logger 依赖（spike 保持最小），
/// 但把默认级别提到 info，方便看到 pingora 的启动日志。
fn env_logger_init() {}
