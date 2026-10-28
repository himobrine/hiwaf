"""定位并调用 Rust 侧二进制。

**判定/校验的权威实现只有一份**（`rust/` = lib `waf_ai_proto` + bin `waf-ai-proto`）。
控制面需要跑规则校验/回放时，一律调用这个二进制，**不在 Python 里重写匹配**：
Python `re` 与 Rust `regex` 在 lookaround/反向引用等语法上语义不同，
一旦"看起来一样"就当作一样，线上的代价是静默漏防。
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence

from . import config

BIN_NAME = "waf-ai-proto"


def _candidates() -> List[Path]:
    out: List[Path] = []
    env = os.environ.get("WAF_PROTO_BIN")
    if env:
        out.append(Path(env))
    tgt = os.environ.get("WAF_CARGO_TARGET") or "E:\\waf-target"
    for name in (BIN_NAME + ".exe", BIN_NAME):
        out.append(Path(tgt) / "release" / name)
        out.append(Path(tgt) / "debug" / name)
    for name in (BIN_NAME + ".exe", BIN_NAME):
        out.append(config.ROOT / "rust" / "target" / "release" / name)
    return out


_BIN: Optional[Path] = None


def find_proto() -> Optional[Path]:
    global _BIN
    if _BIN is not None and _BIN.exists():
        return _BIN
    for c in _candidates():
        if c.exists():
            _BIN = c
            return c
    return None


def proto_bin() -> Path:
    b = find_proto()
    if b is None:
        raise FileNotFoundError(
            "找不到 Rust 判定二进制 waf-ai-proto（判定/校验权威实现）。"
            "先构建：cd F:\\waf\\rust && build.bat build --release；"
            "或用环境变量 WAF_PROTO_BIN 直接指向可执行文件。已探路径："
            + "; ".join(str(c) for c in _candidates())
        )
    return b


def run_proto(args: Sequence[str], *, timeout: int = 900,
              stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    cmd = [str(proto_bin()), *[str(a) for a in args]]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, env=env, input=stdin,
        cwd=str(config.ROOT),
    )
