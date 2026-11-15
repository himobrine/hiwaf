"""FUR-API CSV -> 项目请求 jsonl（method / path / query / body / label）。

为什么需要独立转换器
--------------------
`upload_parse.parse_csv` 能读这份 CSV 的 `method / request_url / request_body`，
但它的标签别名表里**没有 `anomaly`**（只有 normal/sqli/xss/cmdi/traversal），
所以 anomaly 行会被判成 `missing_or_unknown_label` 静默丢弃。做零日通道加训
（只要良性）时无所谓；但做评估/统计时必须把 anomaly 留下来，因此这里显式映射：

    type == "normal"   -> label 0
    type == "anomaly"  -> label 1   （**业务异常**，不是 sqli/xss 子类）

注意：`.csv` 里 `request_headers` / `response_*` / `agent` 全部不入库 ——
`features.py` 的 80 维只吃 method/path/query/body，多存反而制造训练/线上口径漂移。

用法
----
    py -3.10 convert_fur_api.py --input ..\\traindata\\FUR-API\\train.csv --out artifacts\\staging\\fur_api\\train
    py -3.10 convert_fur_api.py --input ..\\traindata\\FUR-API\\test.csv  --out artifacts\\staging\\fur_api\\test
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from upload_parse import split_url  # noqa: E402

LABEL_OF_TYPE = {"normal": 0, "anomaly": 1}
MAX_BODY = 1 << 20
EXPECTED_COLS = 17


def _sha1(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _req_key(row: Dict[str, Any]) -> str:
    return "\x1f".join(str(row.get(k) or "") for k in ("method", "path", "query", "body"))


def convert(path: str, max_rows: int = 200000,
            max_body: int = MAX_BODY) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")

    reader = csv.DictReader(text.splitlines(keepends=True))
    rows: List[Dict[str, Any]] = []
    skip = collections.Counter()
    seen: set = set()
    total = 0
    by_type = collections.Counter()

    for rec in reader:
        if total >= max_rows:
            skip["max_rows"] += 1
            continue
        total += 1
        if not rec or len(rec) != EXPECTED_COLS:
            # 未加引号的逗号会把列冲散，宁可丢也不猜
            skip["broken_columns"] += 1
            continue

        typ = str(rec.get("type") or "").strip().lower()
        by_type[typ or "<empty>"] += 1
        label = LABEL_OF_TYPE.get(typ)
        if label is None:
            skip["unknown_type"] += 1
            continue

        method = str(rec.get("method") or "GET").strip().upper()
        url = str(rec.get("request_url") or "").strip()
        path_only, query = split_url(url)
        if not path_only:
            skip["missing_path"] += 1
            continue
        if not path_only.startswith(("/", "*")):
            path_only = "/" + path_only

        body = str(rec.get("request_body") or "")
        if len(body) > max_body:
            body = body[:max_body]

        row = {"method": method, "path": path_only, "query": query,
               "body": body, "label": label, "type": typ}
        key = _req_key(row)
        if key in seen:
            skip["duplicate"] += 1
            continue
        seen.add(key)
        rows.append(row)

    stats = {
        "input": os.path.abspath(path),
        "input_bytes": len(raw),
        "sha1": _sha1(path),
        "rows_total": total,
        "rows_kept": len(rows),
        "by_type": dict(by_type),
        "label_counts": dict(collections.Counter(r["label"] for r in rows)),
        "skip_reasons": dict(skip),
        "note": "anomaly = 业务异常（非 sqli/xss 子类）；headers/response 不入库",
    }
    return rows, stats


def main() -> None:
    ap = argparse.ArgumentParser(description="FUR-API CSV -> 项目请求 jsonl")
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--max-rows", type=int, default=200000)
    ap.add_argument("--max-body", type=int, default=MAX_BODY)
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    rows, stats = convert(args.input, args.max_rows, args.max_body)
    os.makedirs(args.out, exist_ok=True)
    out_jsonl = os.path.join(args.out, "requests.jsonl")
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(args.out, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print(f"[fur] {stats['rows_kept']:,}/{stats['rows_total']:,} -> {out_jsonl}")
    print(f"[fur] 标签 {stats['label_counts']}  类型 {stats['by_type']}")
    if stats["skip_reasons"]:
        print(f"[fur] 丢弃 {stats['skip_reasons']}")


if __name__ == "__main__":
    main()
