//! 极简回环上游（压测/验收专用，**不参与生产**）。
//!
//! 为什么需要：`python -m http.server` 是单进程 GIL，32 并发下 ~13k QPS 就见顶，
//! 用它当上游时，WAF 的路由/判定上限会被上游先卡住（实测会把会话池的收益完全掩盖）。
//! 这个上游每个连接一个线程、零依赖、keep-alive，单机可轻松跑几十万 QPS。
//!
//! 用法：
//! ```text
//! cargo run --release --bin echo-upstream -- --bind 127.0.0.1:8091 [--body ok]
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle(mut s: TcpStream, body: &'static [u8]) {
    let _ = s.set_nodelay(true);
    let mut r = match s.try_clone() {
        Ok(c) => BufReader::new(c),
        Err(_) => return,
    };
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut content_length = 0usize;
        let mut close = false;
        loop {
            let mut h = String::new();
            match r.read_line(&mut h) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if h == "\r\n" || h == "\n" {
                break;
            }
            let lower = h.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if lower.starts_with("connection:") && lower.contains("close") {
                close = true;
            }
        }
        if content_length > 0 {
            let mut buf = vec![0u8; content_length];
            if r.read_exact(&mut buf).is_err() {
                return;
            }
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: {}\r\n\r\n",
            body.len(),
            if close { "close" } else { "keep-alive" }
        );
        if s.write_all(head.as_bytes()).is_err() || s.write_all(body).is_err() {
            return;
        }
        if close {
            return;
        }
    }
}

fn main() {
    let mut bind = "127.0.0.1:8091".to_string();
    let mut body: &'static [u8] = b"ok";
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args.get(i).cloned().unwrap_or(bind);
            }
            "--body" => {
                i += 1;
                // 泄漏一小段字节换取 'static：这是进程级只读配置。
                let leaked: &'static str = Box::leak(
                    args.get(i).cloned().unwrap_or_default().into_boxed_str(),
                );
                body = leaked.as_bytes();
            }
            other => {
                eprintln!("未知参数 {other}（只支持 --bind/--body）");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[echo-upstream] bind {bind} 失败：{e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "[echo-upstream] listening on {bind}（body {} 字节，keep-alive，线程/连接）",
        body.len()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(move || handle(s, body));
            }
            Err(e) => eprintln!("[echo-upstream] accept 失败：{e}"),
        }
    }
}