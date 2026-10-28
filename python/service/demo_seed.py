"""生成一小批**真实**采集数据，供控制台演示 / 自检（开发工具，不是门禁）。

流程：
    假上游 + waf-collector（--score --stats-out）
      -> traindata/proxy/raw-*.jsonl（原始，无 label）
      -> service.ingest（pred 只进判定字段，不写 label）

用法（在 F:\\waf\\python 下）：
    py -3.10 -m service.demo_seed
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE.parent

sys.path.insert(0, str(PY))

import p8_proxy_e2e as p8  # noqa: E402

from . import config, ingest as ingest_mod  # noqa: E402


def main() -> int:
    config.RAW_DIR.mkdir(parents=True, exist_ok=True)

    up_port, listen_port = p8.free_port(), p8.free_port()
    srv = p8.QuietServer(("127.0.0.1", up_port), p8.Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    collector = p8.find_collector()
    if not os.path.exists(collector):
        raise SystemExit(
            f"找不到采集器：{collector}\n先 cd F:\\waf\\proxy && build.bat build --release"
        )

    proc = subprocess.Popen(
        [collector,
         "--listen", f"127.0.0.1:{listen_port}",
         "--upstream", f"127.0.0.1:{up_port}",
         "--out", str(config.RAW_DIR),
         "--score", "--artifacts", str(config.ARTIFACTS),
         "--stats-out", str(config.COLLECTOR_METRICS),
         "--stats-interval", "5",
         "--body-keep", "65536"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not p8.wait_port(listen_port):
            raise SystemExit("采集器未就绪（超时）")
        reqs = [
            ("benign GET", p8.http_req("GET", "/index.php")),
            ("benign GET static", p8.http_req("GET", "/assets/app.js")),
            ("benign POST", p8.http_req("POST", "/comment.php", b"msg=hello&x=1")),
            ("benign search", p8.http_req("GET", "/search?q=hello+world")),
            ("sqli", p8.http_req("POST", "/product.php", b"id=1' OR '1'='1", ua="sqlmap/1.7")),
            ("xss", p8.http_req("POST", "/guestbook.php", b"msg=<script>alert(1)</script>")),
            ("traversal", p8.http_req("GET", "/download?file=../../../../etc/passwd")),
            ("cmdi", p8.http_req("GET", "/ping?host=127.0.0.1;cat+/etc/passwd")),
            ("benign 2", p8.http_req("GET", "/about.html")),
            ("sqli 2", p8.http_req("POST", "/product.php", b"id=1 UNION SELECT 1,2,3--", ua="sqlmap/1.7")),
        ]
        for name, raw in reqs:
            print(f"  {name:<18} -> {p8.send_raw(listen_port, raw)}")
        time.sleep(2.0)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        srv.shutdown()

    st = ingest_mod.ingest(with_body=False)
    print("\n[ingest]")
    print(json.dumps(st, ensure_ascii=False, indent=2))
    print(f"\n原始记录 -> {config.RAW_DIR}")
    print(f"指标文件 -> {config.COLLECTOR_METRICS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
