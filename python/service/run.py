"""启动控制面 API。

用法（在 F:\\waf\\python 下）：
    py -3.10 -m service.run
    py -3.10 -m service.run --port 8090 --reload
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import uvicorn

HERE = Path(__file__).resolve().parent
PY = HERE.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--reload", action="store_true")
    a = ap.parse_args()

    # 让 thresholds.py / export_*.py 里的相对路径（..\traindata、artifacts）都能正确解析。
    os.chdir(str(PY))
    if str(PY) not in sys.path:
        sys.path.insert(0, str(PY))

    uvicorn.run("service.app:app", host=a.host, port=a.port, reload=a.reload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
