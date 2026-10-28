"""导出 80 维特征名（契约 v2），供 Python / Rust / 前端三处共用（**单一来源**）。

为什么需要它
------------
控制台的「请求取证详情」页要把 TreeSHAP 的 Top-K 贡献显示成**可读特征名**，而
特征顺序的唯一事实来源是 `features.py::FeatureExtractor._base_names()`。把名字固化成
`artifacts/feature_names_v2.json` 后：

  * Rust `engine.rs` 加载它，按 `features.rs` 的 `push!` 顺序给贡献项贴名，
    并在启动期断言 `len(names) == FEATURE_DIM`（错位即失败，**不会静默算歪**）；
  * 前端只读这一份，不再自己写死 80 个字段名。

用法：
    py -3.10 export_feature_names.py
产物：
    artifacts/feature_names_v2.json
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")
OUT = os.path.join(ART, "feature_names_v2.json")
EXPECT_DIM = 80


def main() -> int:
    sys.path.insert(0, HERE)
    from features import FeatureExtractor  # noqa: E402  （放这里避免 import 期副作用）

    fx = FeatureExtractor()
    names = list(fx.names)
    if len(names) != EXPECT_DIM:
        raise SystemExit(
            f"[names] 维度不符：{len(names)} != {EXPECT_DIM}。"
            f"特征契约变了就必须同步 rust/src/features.rs 的 push! 顺序与 FEATURE_DIM。"
        )
    if len(set(names)) != len(names):
        dup = sorted({n for n in names if names.count(n) > 1})
        raise SystemExit(f"[names] 存在重名特征：{dup}")

    doc = {
        "version": "v2",
        "dim": len(names),
        "source": "python/features.py::FeatureExtractor._base_names()",
        "note": "Rust rust/src/features.rs 的 push! 顺序必须与此一致（启动期断言 dim）。",
        "names": names,
    }
    os.makedirs(ART, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"[names] {len(names)} 维 -> {os.path.relpath(OUT, HERE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
