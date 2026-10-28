"""用户上传训练数据的解析与归一化（CSV / JSON / JSONL / pcap / pcapng）。

设计约束
--------
* **只接受原始 HTTP 请求字段**：`method / path / query / body + label`。
  不接受预计算特征列 —— 特征必须由 `features.py` 统一抽取，避免训练/线上口径漂移。
* 本模块可独立运行（控制台用固定参数启动子进程），也可被测试直接 import。
* pcap 只支持**明文 HTTP/1.x**；TLS / HTTP/2 / WebSocket 会被跳过并计数。
  pcap 无法逐包给标签，调用方必须给整份文件一个 `--default-label`。

输出
----
`<out>/requests.jsonl`：每行
    {"method":"GET","path":"/a","query":"x=1","body":"","label":0}
`<out>/stats.json`：行数、标签分布、跳过原因、pcap 统计等。

用法
----
    py -3.10 upload_parse.py --input data.csv --out /tmp/up1 --role supervised
    py -3.10 upload_parse.py --input cap.pcap --out /tmp/up2 --role benign --default-label 0
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlencode

LABELS = {0: "normal", 1: "sqli", 2: "xss", 3: "cmdi", 4: "traversal"}
LABEL_ALIASES = {
    "0": 0, "normal": 0, "norm": 0, "benign": 0, "clean": 0, "none": 0,
    "1": 1, "sqli": 1, "sql": 1, "sql-injection": 1, "sql_injection": 1,
    "2": 2, "xss": 2, "cross-site-scripting": 2,
    "3": 3, "cmdi": 3, "command-injection": 3, "command_injection": 3,
    "rce": 3, "cmd": 3,
    "4": 4, "traversal": 4, "path-traversal": 4, "path_traversal": 4,
    "lfi": 4, "directory-traversal": 4,
}
#: HTTP Params 语料的 attack_type 别名（与 realdata.ATTACK_TYPE_TO_LABEL 对齐）。
ATTACK_TYPE_ALIASES = {
    "norm": 0, "normal": 0,
    "sqli": 1, "sql-syntax": 1,
    "xss": 2, "js-syntax": 2,
    "cmdi": 3,
    "path-traversal": 4, "traversal": 4,
}
METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}

REQ_KEYS = ("method", "path", "query", "body")


def req_key(sample: Dict[str, Any]) -> str:
    """请求指纹：与 thresholds.py 的 req_key 完全一致。"""
    return "\x1f".join(str(sample.get(k) or "") for k in REQ_KEYS)


def parse_label(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            n = int(value)
        except (TypeError, ValueError):
            return default
        return n if n in LABELS else None
    s = str(value).strip().lower()
    if not s:
        return default
    if s in LABEL_ALIASES:
        return LABEL_ALIASES[s]
    if s in ATTACK_TYPE_ALIASES:
        return ATTACK_TYPE_ALIASES[s]
    try:
        n = int(s)
    except ValueError:
        return None
    return n if n in LABELS else None


def split_url(url: str) -> Tuple[str, str]:
    """完整 URL / 绝对路径 -> (path, query)。"""
    u = str(url or "").strip()
    if not u:
        return "", ""
    if u.startswith("http://") or u.startswith("https://"):
        p = urlsplit(u)
        return p.path or "/", p.query or ""
    if u.startswith("//"):
        p = urlsplit("http:" + u)
        return p.path or "/", p.query or ""
    if "?" in u:
        path, query = u.split("?", 1)
        return path or "/", query
    return u, ""


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, str):
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return str(v)


def _as_query(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):
        return urlencode(v, doseq=True)
    if isinstance(v, list):
        return urlencode([(str(k), str(x)) for k, x in v])
    return _as_text(v).lstrip("?")


def normalize_row(obj: Dict[str, Any], default_label: Optional[int] = None,
                  role: str = "supervised", max_body: int = 1 << 20
                  ) -> Tuple[Optional[Dict[str, Any]], str]:
    """把任意输入对象归一化为项目请求格式。返回 (row, skip_reason)。"""
    if not isinstance(obj, dict):
        return None, "not_object"

    # 兼容 {"request": {...}, "label": ...} 嵌套。
    label_hint = obj.get("label", obj.get("y", obj.get("class")))
    attack_hint = obj.get("attack_type", obj.get("attackType"))
    src = obj.get("request") if isinstance(obj.get("request"), dict) else obj

    url = src.get("url", src.get("uri", src.get("request_url", src.get("target"))))
    path = src.get("path", src.get("url_path", src.get("endpoint")))
    query = src.get("query", src.get("querystring", src.get("query_string")))
    if path in (None, "") and url:
        path, q2 = split_url(_as_text(url))
        if not query:
            query = q2
    path = _as_text(path)
    query = _as_query(query)
    if not path:
        return None, "missing_path"
    if not path.startswith(("/", "*")):
        path = "/" + path
    method = _as_text(src.get("method", src.get("http_method", src.get("verb"))) or "GET").upper()
    if method not in METHODS:
        method = method.strip() or "GET"

    body = src.get("body", src.get("request_body", src.get("post_data", "")))
    body = _as_text(body)
    if len(body) > max_body:
        body = body[:max_body]

    if label_hint is None:
        label_hint = attack_hint
    label = parse_label(label_hint, default=default_label)
    if label is None:
        return None, "missing_or_unknown_label"
    if role == "benign" and label != 0:
        return None, "non_benign_label"

    return {"method": method, "path": path, "query": query,
            "body": body, "label": int(label)}, ""


# --------------------------------------------------------------------------- CSV
def _norm_header(k: str) -> str:
    return str(k or "").strip().lower().replace(" ", "_").replace("-", "_")


def _pick(row: Dict[str, Any], names: Iterable[str]) -> Any:
    for n in names:
        if n in row:
            return row[n]
    return None


def parse_csv(path: str, default_label: Optional[int], role: str,
              max_rows: int, max_body: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    with open(path, "rb") as _f:
        raw = _f.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows: List[Dict[str, Any]] = []
    skip = Counter()
    total = 0
    reader = csv.DictReader(io.StringIO(text, newline=""), dialect=dialect)
    for raw_row in reader:
        if total >= max_rows:
            skip["max_rows"] += 1
            continue
        total += 1
        obj = {_norm_header(k): v for k, v in (raw_row or {}).items() if k is not None}
        label_v = _pick(obj, ("label", "y", "class", "attack_label"))
        attack_v = _pick(obj, ("attack_type", "type", "category"))
        body_v = _pick(obj, ("body", "request_body", "post_data"))
        flat = {
            "method": _pick(obj, ("method", "http_method", "verb")),
            "url": _pick(obj, ("url", "uri", "request_url", "target")),
            "path": _pick(obj, ("path", "url_path", "endpoint")),
            "query": _pick(obj, ("query", "querystring", "query_string")),
            "body": body_v,
            "label": label_v if label_v not in (None, "") else None,
            "attack_type": attack_v,
        }
        if flat["label"] is None and flat["attack_type"] is not None:
            flat["label"] = flat["attack_type"]
        row, why = normalize_row(flat, default_label, role, max_body)
        if row is None:
            skip[why] += 1
        else:
            rows.append(row)
    return rows, {"rows_total": total, "skip_reasons": dict(skip)}


# --------------------------------------------------------------------------- JSON
def _har_entries(doc: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    log = doc.get("log")
    if not isinstance(log, dict):
        return None
    entries = log.get("entries")
    if not isinstance(entries, list):
        return None
    out = []
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("request"), dict):
            continue
        r = dict(e["request"])
        # HAR 的 queryString / postData 是结构化字段，转成项目格式。
        if "queryString" in r and not r.get("query"):
            r["query"] = r.get("queryString")
        pd = r.get("postData")
        if isinstance(pd, dict) and not r.get("body"):
            r["body"] = pd.get("text") or pd.get("params") or ""
        if e.get("label") is not None and r.get("label") is None:
            r["label"] = e.get("label")
        out.append(r)
    return out


def parse_json(path: str, default_label: Optional[int], role: str,
               max_rows: int, max_body: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    with open(path, "rb") as _f:
        raw = _f.read()
    text = raw.decode("utf-8-sig", "replace")
    skip = Counter()
    total = 0
    objects: List[Any] = []
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            objects = doc
        elif isinstance(doc, dict):
            entries = _har_entries(doc)
            if entries is not None:
                objects = entries
            else:
                for k in ("requests", "items", "data", "rows"):
                    if isinstance(doc.get(k), list):
                        objects = doc[k]
                        break
                else:
                    objects = [doc]
        else:
            raise ValueError("JSON 顶层必须是对象或数组")
    except (json.JSONDecodeError, ValueError):
        # JSONL：逐行解析；坏行计数，不因单行失败丢掉整个文件。
        objects = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError:
                skip["bad_json_line"] += 1

    rows: List[Dict[str, Any]] = []
    for obj in objects:
        if total >= max_rows:
            skip["max_rows"] += 1
            continue
        total += 1
        row, why = normalize_row(obj, default_label, role, max_body)
        if row is None:
            skip[why] += 1
        else:
            rows.append(row)
    if not rows and not skip:
        raise ValueError("JSON/JSONL 中没有可解析的请求对象")
    return rows, {"rows_total": total, "skip_reasons": dict(skip)}


# --------------------------------------------------------------------------- pcap
_HTTP_REQ_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE) (\S+) HTTP/1\.[01]$")


def _decode_chunked(data: bytes, start: int, max_body: int) -> Tuple[Optional[bytes], int]:
    """从 start 解 chunked body。返回 (body, consumed) 或 (None, 0)。"""
    pos = start
    out = bytearray()
    while True:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            return None, 0
        try:
            size = int(data[pos:eol].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return None, 0
        pos = eol + 2
        if size == 0:
            # 末尾 trailer，至少要有 CRLF
            end = data.find(b"\r\n", pos)
            if end < 0:
                return None, 0
            return bytes(out), (end + 2) - start
        if len(data) < pos + size + 2:
            return None, 0
        out += data[pos:pos + size]
        if len(out) > max_body:
            out = out[:max_body]
        pos += size + 2
        if len(out) >= max_body:
            # 继续消费到结束，避免把剩余 chunk 当新请求。
            while True:
                eol = data.find(b"\r\n", pos)
                if eol < 0:
                    return None, 0
                try:
                    sz = int(data[pos:eol].split(b";", 1)[0].strip(), 16)
                except ValueError:
                    return None, 0
                pos = eol + 2
                if sz == 0:
                    end = data.find(b"\r\n", pos)
                    if end < 0:
                        return None, 0
                    return bytes(out), (end + 2) - start
                pos += sz + 2


def parse_http_requests(data: bytes, label: int, max_body: int
                        ) -> Tuple[List[Dict[str, Any]], int]:
    """从一段连续 TCP 字节流中提取 HTTP/1.x 请求。返回 (rows, incomplete)。"""
    out: List[Dict[str, Any]] = []
    pos = 0
    incomplete = 0
    n = len(data)
    while pos < n:
        # 跳过流首空白 / 残余响应。
        while pos < n and data[pos] in (0x0D, 0x0A, 0x00):
            pos += 1
        if pos >= n:
            break
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            incomplete += 1
            break
        head = data[pos:end]
        lines = head.split(b"\r\n")
        m = _HTTP_REQ_RE.match(lines[0].strip())
        if not m:
            # 可能是响应或非 HTTP；跳到下一行再试。
            nl = data.find(b"\n", pos)
            if nl < 0:
                break
            pos = nl + 1
            incomplete += 1
            continue
        method = m.group(1).decode("ascii")
        target = m.group(2).decode("latin-1", "replace")
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1", "replace").strip().lower()] = \
                v.decode("latin-1", "replace").strip()
        body_start = end + 4
        body = b""
        consumed = 0
        if headers.get("transfer-encoding", "").lower().find("chunked") >= 0:
            body, consumed = _decode_chunked(data, body_start, max_body)
            if body is None:
                incomplete += 1
                break
        else:
            cl = headers.get("content-length")
            if cl:
                try:
                    ln = int(cl)
                except ValueError:
                    ln = 0
                if ln < 0:
                    ln = 0
                if len(data) < body_start + ln:
                    incomplete += 1
                    break
                body = data[body_start:body_start + ln]
                consumed = ln
            else:
                consumed = 0
        if len(body) > max_body:
            body = body[:max_body]
        path, query = split_url(target)
        out.append({"method": method, "path": path or "/", "query": query,
                    "body": body.decode("utf-8", "replace"), "label": int(label)})
        pos = body_start + consumed
    return out, incomplete


def _packet_payload(pkt: Any) -> Tuple[Optional[Tuple[str, int, str, int]], bytes]:
    """取 TCP payload 与方向键；非 TCP 返回 (None, b'')。"""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            ip = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
            if ip is None:
                return None, b""
            payload = bytes(tcp.payload)
            if not payload:
                return None, b""
            return (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport)), payload
    except Exception:  # noqa: BLE001 - 坏包不阻断整份文件
        return None, b""
    return None, b""


def parse_pcap(path: str, default_label: Optional[int], role: str,
               max_rows: int, max_packets: int, max_flows: int,
               max_body: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if default_label is None:
        raise ValueError("pcap 必须提供 --default-label（整份文件一个标签）")
    if role == "benign" and int(default_label) != 0:
        raise ValueError("role=benign 时 pcap 的 default-label 必须是 0")
    try:
        from scapy.all import PcapReader, PcapNgReader
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"pcap 解析需要 scapy（未安装）：{e}") from e

    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        reader = PcapNgReader(path)
        fmt = "pcapng"
    else:
        reader = PcapReader(path)
        fmt = "pcap"

    flows: Dict[Tuple[str, int, str, int], Dict[int, bytes]] = {}
    stats = Counter()
    total_bytes = 0
    t0 = time.time()
    try:
        for i, pkt in enumerate(reader):
            if i >= max_packets:
                stats["max_packets"] += 1
                break
            stats["packets"] += 1
            key, payload = _packet_payload(pkt)
            if key is None:
                continue
            stats["tcp_payload_packets"] += 1
            if payload.startswith(b"\x16\x03"):
                stats["skipped_tls"] += 1
                continue
            if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
                stats["skipped_http2"] += 1
                continue
            if key not in flows:
                if len(flows) >= max_flows:
                    stats["max_flows"] += 1
                    continue
                flows[key] = {}
            seq = 0
            try:
                seq = int(pkt["TCP"].seq)
            except Exception:  # noqa: BLE001
                pass
            old = flows[key].get(seq)
            if old is None or len(payload) > len(old):
                total_bytes += len(payload) - (len(old) if old else 0)
                if total_bytes > 512 << 20:
                    stats["max_bytes"] += 1
                    break
                flows[key][seq] = payload
    finally:
        try:
            reader.close()
        except Exception:  # noqa: BLE001
            pass

    rows: List[Dict[str, Any]] = []
    for key, segs in flows.items():
        if not segs:
            continue
        # 把同方向的段按 seq 拼成连续区间；gap 处切开（丢掉的请求计 incomplete）。
        chunks: List[bytes] = []
        cur = bytearray()
        cursor = None
        for seq in sorted(segs):
            data = segs[seq]
            if cursor is None:
                cur = bytearray(data)
                cursor = seq + len(data)
                continue
            if seq > cursor:
                chunks.append(bytes(cur))
                cur = bytearray(data)
                cursor = seq + len(data)
            elif seq + len(data) > cursor:
                cur += data[cursor - seq:]
                cursor = seq + len(data)
        if cur:
            chunks.append(bytes(cur))
        for chunk in chunks:
            if not chunk:
                continue
            got, inc = parse_http_requests(chunk, int(default_label), max_body)
            stats["incomplete_http"] += inc
            for r in got:
                if len(rows) >= max_rows:
                    stats["max_rows"] += 1
                    break
                rows.append(r)
            if len(rows) >= max_rows:
                break
        if len(rows) >= max_rows:
            break

    stats["flows"] = len(flows)
    stats["requests"] = len(rows)
    stats["elapsed_sec"] = round(time.time() - t0, 3)
    if not rows:
        raise ValueError(
            "pcap 中没有解析出明文 HTTP/1.x 请求（TLS/HTTP2 不支持；"
            "请确认抓包包含完整请求且不是 HTTPS）")
    return rows, {"format": fmt, "rows_total": stats["requests"],
                  "skip_reasons": {k: v for k, v in stats.items()
                                   if k in ("skipped_tls", "skipped_http2", "incomplete_http",
                                            "max_packets", "max_flows", "max_bytes", "max_rows")},
                  "pcap": dict(stats)}


# --------------------------------------------------------------------------- 主流程
def _detect_format(path: str, fmt: str) -> str:
    if fmt != "auto":
        return fmt
    ext = os.path.splitext(path)[1].lower()
    if ext in (".pcap", ".pcapng", ".cap"):
        return "pcap"
    if ext in (".jsonl", ".ndjson"):
        return "json"
    if ext == ".json":
        return "json"
    if ext in (".csv", ".tsv"):
        return "csv"
    with open(path, "rb") as f:
        head = f.read(4)
    if head in (b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    with open(path, "rb") as f:
        first = f.read(4096).lstrip()
    if first.startswith((b"{", b"[")):
        return "json"
    return "csv"


def parse_file(path: str, fmt: str = "auto", role: str = "supervised",
               default_label: Optional[int] = None, max_rows: int = 200000,
               max_body: int = 1 << 20, max_packets: int = 2_000_000,
               max_flows: int = 50_000) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fmt = _detect_format(path, fmt)
    if fmt in ("pcap", "pcapng"):
        return parse_pcap(path, default_label, role, max_rows, max_packets,
                          max_flows, max_body)
    if fmt == "csv":
        return parse_csv(path, default_label, role, max_rows, max_body)
    if fmt in ("json", "jsonl"):
        return parse_json(path, default_label, role, max_rows, max_body)
    raise ValueError(f"不支持的格式 {fmt!r}")


def summarize(rows: List[Dict[str, Any]], extra: Dict[str, Any]) -> Dict[str, Any]:
    labels = Counter(int(r["label"]) for r in rows)
    methods = Counter(str(r.get("method") or "") for r in rows)
    keys = set()
    dup = 0
    for r in rows:
        k = req_key(r)
        if k in keys:
            dup += 1
        else:
            keys.add(k)
    return {
        **extra,
        "rows_kept": len(rows),
        "rows_skipped": max(0, int(extra.get("rows_total", len(rows))) - len(rows)),
        "label_counts": {str(k): int(v) for k, v in sorted(labels.items())},
        "benign": int(labels.get(0, 0)),
        "attack": int(sum(v for k, v in labels.items() if k != 0)),
        "method_counts": dict(methods),
        "duplicates": int(dup),
        "unique_requests": len(keys),
        "body_max_len": max((len(r.get("body") or "") for r in rows), default=0),
        "query_max_len": max((len(r.get("query") or "") for r in rows), default=0),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--format", default="auto",
                    choices=["auto", "csv", "json", "jsonl", "pcap", "pcapng"])
    ap.add_argument("--role", default="supervised",
                    choices=["supervised", "benign", "eval"])
    ap.add_argument("--default-label", type=int, default=None,
                    help="缺标签 / pcap 整份文件的标签（0-4）")
    ap.add_argument("--max-rows", type=int, default=200000)
    ap.add_argument("--max-body", type=int, default=1 << 20)
    ap.add_argument("--max-packets", type=int, default=2_000_000)
    ap.add_argument("--max-flows", type=int, default=50_000)
    args = ap.parse_args()

    if args.default_label is not None and args.default_label not in LABELS:
        raise SystemExit("--default-label 必须是 0-4")
    os.makedirs(args.out, exist_ok=True)
    t0 = time.time()
    rows, extra = parse_file(args.input, args.format, args.role,
                             args.default_label, args.max_rows, args.max_body,
                             args.max_packets, args.max_flows)
    stats = summarize(rows, extra)
    stats["elapsed_sec"] = round(time.time() - t0, 3)
    stats["input"] = os.path.basename(args.input)
    stats["input_bytes"] = os.path.getsize(args.input)
    stats["role"] = args.role
    stats["default_label"] = args.default_label

    req_path = os.path.join(args.out, "requests.jsonl")
    with open(req_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(args.out, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"[upload] {args.input} -> {req_path}  rows={len(rows)}  "
          f"labels={stats['label_counts']}  dup={stats['duplicates']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"[upload] 解析失败：{e}", file=sys.stderr)
        sys.exit(2)
