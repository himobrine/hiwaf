//! 最小 HTTP/1.1 压测器（零依赖，压测/验收专用）。
//!
//! 为什么不用 Python：`bench_proxy.py` 受 GIL 与线程调度限制，单机约 1.7k QPS/进程，
//! 4 进程 ~7k 就先把客户端打满，测不出 WAF 的真实上限。
//!
//! 用法：
//! ```text
//! cargo run --release --bin loadgen -- \
//!     --addr 127.0.0.1:6201 --path /x --connections 32 --threads 4 --seconds 5
//! ```
//! 输出一行：
//! ```text
//! RESULT qps=... p50_us=... p95_us=... p99_us=... max_us=... n=... errors=...
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn request_bytes(host: &str, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: waf-loadgen/1.0\r\n\
         Accept: */*\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes()
}

/// 读一个完整响应（状态行 + 头 + content-length 指定的 body）。返回 false 表示连接已断。
fn read_response(
    r: &mut BufReader<TcpStream>,
    scratch: &mut Vec<u8>,
) -> Result<bool, std::io::Error> {
    scratch.clear();
    let mut content_length = 0usize;
    let mut chunked = false;
    let mut line = String::new();
    // 状态行
    line.clear();
    if r.read_line(&mut line)? == 0 {
        return Ok(false);
    }
    // 头
    let mut close = false;
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Ok(false);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
        if lower.starts_with("connection:") && lower.contains("close") {
            close = true;
        }
    }
    if chunked {
        // 压测后端都用 content-length；chunked 只做兜底读取。
        loop {
            line.clear();
            if r.read_line(&mut line)? == 0 {
                break;
            }
        }
    } else if content_length > 0 {
        scratch.resize(content_length, 0);
        r.read_exact(scratch)?;
    }
    Ok(!close)
}

struct Args {
    addr: String,
    path: String,
    connections: usize,
    threads: usize,
    seconds: f64,
    warmup: f64,
    unique: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        addr: "127.0.0.1:6188".into(),
        path: "/".into(),
        connections: 32,
        threads: 4,
        seconds: 5.0,
        warmup: 1.0,
        unique: false,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let next = || argv.get(i + 1).cloned().unwrap_or_default();
        match argv[i].as_str() {
            "--addr" => a.addr = next(),
            "--path" => a.path = next(),
            "--connections" => a.connections = next().parse().unwrap_or(32),
            "--threads" => a.threads = next().parse().unwrap_or(4),
            "--seconds" => a.seconds = next().parse().unwrap_or(5.0),
            "--warmup" => a.warmup = next().parse().unwrap_or(1.0),
            "--unique" => {
                a.unique = true;
                i -= 1; // 无取值参数
            }
            other => {
                eprintln!("未知参数 {other}");
                std::process::exit(2);
            }
        }
        i += 2;
    }
    a
}

fn main() {
    let args = Arc::new(parse_args());
    let host = args.addr.clone();
    let host_header = host.clone();
    let path = Arc::new(args.path.clone());
    let deadline = Instant::now() + Duration::from_secs_f64(args.warmup + args.seconds);
    let measure_after = Instant::now() + Duration::from_secs_f64(args.warmup);
    let stop = Arc::new(AtomicBool::new(false));

    let per_thread = 1;
    // 一条连接一个线程：只有真正同时在途的请求数才是并发度。
    // （早期版本在一个线程里轮询多条连接，实际并发只有线程数，会把上限测低。）
    let workers = args.connections.max(1);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let host = host.clone();
        let host_header = host_header.clone();
        let path = Arc::clone(&path);
        let stop = Arc::clone(&stop);
        let unique = args.unique;
        handles.push(std::thread::spawn(move || -> (Vec<u32>, u64) {
            let req = request_bytes(&host_header, &path);
            let mut scratch_req: Vec<u8> = Vec::new();
            let mut counter: u64 = 0;
            let mut lat: Vec<u32> = Vec::with_capacity(2_000_000);
            let mut errors = 0u64;
            let mut conns: Vec<Option<(BufReader<TcpStream>, Vec<u8>)>> =
                (0..per_thread).map(|_| None).collect();
            while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                for slot in conns.iter_mut() {
                    if slot.is_none() {
                        match TcpStream::connect(&host) {
                            Ok(s) => {
                                let _ = s.set_nodelay(true);
                                *slot = Some((BufReader::new(s), Vec::new()));
                            }
                            Err(_) => {
                                errors += 1;
                                continue;
                            }
                        }
                    }
                    let (r, scratch) = slot.as_mut().unwrap();
                    let t = Instant::now();
                    if unique {
                        counter += 1;
                        scratch_req = request_bytes(
                            &host_header,
                            &format!("{path}?probe={counter}"),
                        );
                    }
                    let bytes: &[u8] = if unique { &scratch_req } else { &req };
                    let sent = {
                        // `BufReader` 只读；写走 clone 出来的流
                        let s = r.get_mut();
                        s.write_all(bytes)
                    };
                    if sent.is_err() {
                        errors += 1;
                        *slot = None;
                        continue;
                    }
                    match read_response(r, scratch) {
                        Ok(true) => {
                            let us = t.elapsed().as_micros().min(u32::MAX as u128) as u32;
                            if Instant::now() >= measure_after {
                                lat.push(us);
                            }
                        }
                        Ok(false) | Err(_) => {
                            *slot = None;
                        }
                    }
                }
            }
            (lat, errors)
        }));
    }

    let mut all: Vec<u32> = Vec::new();
    let mut errors = 0u64;
    for h in handles {
        if let Ok((l, e)) = h.join() {
            all.extend_from_slice(&l);
            errors += e;
        }
    }
    stop.store(true, Ordering::Relaxed);
    if all.is_empty() {
        println!("RESULT qps=0 p50_us=0 p95_us=0 p99_us=0 max_us=0 n=0 errors={errors}");
        return;
    }
    all.sort_unstable();
    let q = |p: f64| -> u32 { all[((all.len() as f64 - 1.0) * p) as usize] };
    let qps = all.len() as f64 / args.seconds.max(0.001);
    println!(
        "RESULT qps={qps:.0} p50_us={} p95_us={} p99_us={} max_us={} n={} errors={errors} \
         conns={} threads={}",
        q(0.50),
        q(0.95),
        q(0.99),
        all[all.len() - 1],
        all.len(),
        args.connections,
        args.threads
    );
}