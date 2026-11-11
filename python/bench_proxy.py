"""代理数据面压测：单请求延迟分位 + 吞吐（纯标准库，零依赖）。

用途：给 `proxy/`（waf-collector）做**页面级**对照。判定在 `dry_run` 下发生在
`logging`（响应已发出），单发 `curl` 看不出锁竞争；必须并发才能暴露
`Mutex<Engine>` 串行化与 worker 阻塞。

用法：
    python bench_proxy.py --url http://127.0.0.1:6188/index.html --n 2000 --c 10

输出：p50 / p95 / p99 / QPS。只统计成功的响应（状态码照常打印分布）。
"""
from __future__ import annotations

import argparse
import http.client
import statistics
import threading
import time
from collections import Counter
from urllib.parse import urlsplit


def worker(host: str, port: int, path: str, n: int, out: list, errors: list, status: Counter) -> None:
    lat = []
    conn = None
    for _ in range(n):
        try:
            if conn is None:
                conn = http.client.HTTPConnection(host, port, timeout=10)
            t0 = time.perf_counter()
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            lat.append((time.perf_counter() - t0) * 1000.0)
            status[resp.status] += 1
        except Exception as e:  # noqa: BLE001 - 压测脚本，连接复用失败就重连
            errors.append(repr(e))
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            conn = None
    try:
        if conn is not None:
            conn.close()
    except Exception:
        pass
    out.extend(lat)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--n", type=int, default=1000, help="总请求数")
    ap.add_argument("--c", type=int, default=10, help="并发连接数")
    ap.add_argument("--warmup", type=int, default=20)
    args = ap.parse_args()

    u = urlsplit(args.url)
    if not u.hostname or not u.port:
        print("[bench] URL 必须是 http://host:port/path")
        return 2
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    host, port = u.hostname, u.port

    for _ in range(args.warmup):
        try:
            c = http.client.HTTPConnection(host, port, timeout=10)
            c.request("GET", path)
            c.getresponse().read()
            c.close()
        except Exception as e:  # noqa: BLE001
            print(f"[bench] warmup 失败（代理没起？）：{e!r}")
            return 1

    per = max(1, args.n // args.c)
    lat: list = []
    errors: list = []
    status: Counter = Counter()
    threads = [
        threading.Thread(target=worker, args=(host, port, path, per, lat, errors, status))
        for _ in range(args.c)
    ]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.perf_counter() - t0

    if not lat:
        print(f"[bench] 全部失败（{len(errors)} 次）：{errors[:3]}")
        return 1
    lat.sort()
    total = len(lat)
    p = lambda q: lat[min(total - 1, int(total * q))]  # noqa: E731
    print(
        f"[bench] {args.url}  n={total} c={args.c}  "
        f"p50={p(0.50):.2f}ms p95={p(0.95):.2f}ms p99={p(0.99):.2f}ms  "
        f"qps={total / dt:.1f}  errors={len(errors)}  status={dict(status)}"
    )
    print(f"[bench] mean={statistics.mean(lat):.2f}ms max={lat[-1]:.2f}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())