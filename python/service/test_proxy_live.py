"""采集代理托管链路的真实二进制自检（默认跳过）。

需要先构建 `waf-collector`，并显式开启：

    set WAF_PROXY_LIVE_TEST=1
    py -3.10 -m unittest service.test_proxy_live -v

覆盖：真实进程启动 -> 经代理转发 -> 指标 written 增长 -> 停止后端口释放。
二进制缺失时自动 skip，不阻塞常规单测。
"""
from __future__ import annotations

import http.client
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from . import config, db, proxy_manager as pm


class _Upstream(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"hello-from-upstream"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: D401
        pass


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(os.environ.get("WAF_PROXY_LIVE_TEST") == "1",
                     "设置 WAF_PROXY_LIVE_TEST=1 才跑真实采集器")
class ProxyLiveTest(unittest.TestCase):
    def test_start_forward_metrics_stop(self):
        binary = pm.resolve_binary()
        if not binary.is_file():
            self.skipTest(f"找不到采集器：{binary}")

        up = HTTPServer(("127.0.0.1", 0), _Upstream)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        listen_port = _free_port()
        tmp = Path(tempfile.mkdtemp())
        try:
            with mock.patch.object(config, "DB_PATH", tmp / "console.db"), \
                    mock.patch.object(config, "LOG_DIR", tmp / "logs"), \
                    mock.patch.object(config, "RAW_DIR", tmp / "raw"), \
                    mock.patch.object(config, "COLLECTOR_METRICS",
                                      tmp / "raw" / "collector-metrics.json"), \
                    mock.patch.dict(config.PROXY_DEFAULTS, {
                        "listen": f"127.0.0.1:{listen_port}",
                        "upstream": f"127.0.0.1:{up.server_address[1]}",
                        "stats_interval": 1,
                        "reload_interval": 0,
                        "rules": "",
                    }):
                db.init()
                st = pm.start("live-test")
                self.assertTrue(st["running"], st)
                c = http.client.HTTPConnection("127.0.0.1", listen_port, timeout=5)
                c.request("GET", "/hello?x=1")
                r = c.getresponse()
                self.assertEqual(r.status, 200)
                self.assertEqual(r.read(), b"hello-from-upstream")

                deadline = time.time() + 5
                m = None
                while time.time() < deadline:
                    m = pm.metrics()
                    if m and int(m.get("written") or 0) >= 1:
                        break
                    time.sleep(0.2)
                self.assertIsNotNone(m)
                self.assertGreaterEqual(int(m.get("written") or 0), 1)
                self.assertTrue(list((tmp / "raw").glob("raw-*.jsonl")))

                stopped = pm.stop("live-test")
                self.assertFalse(stopped["running"])
                self.assertFalse(stopped["port_listening"])
        finally:
            up.shutdown()


if __name__ == "__main__":
    unittest.main()
