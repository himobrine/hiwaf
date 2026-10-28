"""事件取证包：从 raw JSONL 读取请求/响应，服务端解码并按需打码。

设计约束：
  * 事件表不新增 headers/response 列；packet 以 `events.src_file/src_line` 回读 raw。
  * raw 已清理/旧采集器缺字段时返回 `reconstructed=true`，绝不假装是完整包。
  * 解压只在服务端做：前端不解 br/zstd，也不缓存 reveal 后的完整值。
  * header 顺序是解析后顺序，不是 wire order；8KB 按规范化 `name: value\\r\\n` 计数。
"""
from __future__ import annotations

import base64
import json
import os
import zlib
from pathlib import Path
from typing import Any, Iterable, Optional

from . import config

MAX_DECODED = 1024 * 1024
HEADER_COUNT_BASIS = (
    "name: value\\r\\n, post-parse, start-line excluded, duplicate headers counted separately"
)
HEADER_ORDER_NOTE = "post-parse, not wire order"
_TEXTUAL_CT = (
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-javascript",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "application/ld+json",
)


# --------------------------------------------------------------------------- 路径
def _raw_dir() -> Path:
    return config.RAW_DIR.resolve()


def _canonical_under_raw(p: str | os.PathLike) -> Optional[Path]:
    """返回 RAW_DIR 内的 canonical path；越界/symlink 逃逸返回 None。"""
    try:
        rp = Path(os.path.abspath(os.fspath(p))).resolve(strict=False)
        root = _raw_dir()
        # Windows 大小写不敏感；用 commonpath + normcase，避免 starts_with 的字符串边界问题。
        a = os.path.normcase(str(rp))
        b = os.path.normcase(str(root))
        if os.path.commonpath([a, b]) != b:
            return None
        return rp
    except (OSError, ValueError):
        return None


def _read_raw_line(event: dict) -> tuple[Optional[dict], Optional[str]]:
    src = event.get("src_file")
    line_no = event.get("src_line")
    if not src:
        return None, "legacy"
    p = _canonical_under_raw(src)
    if p is None:
        return None, "path_rejected"
    if not p.exists():
        return None, "raw_missing"
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                if i == int(line_no or 0):
                    line = line.strip()
                    if not line:
                        return None, "raw_line_missing"
                    try:
                        d = json.loads(line)
                    except Exception:
                        return None, "raw_line_bad_json"
                    return (d if isinstance(d, dict) else None), (None if isinstance(d, dict) else "raw_line_bad_json")
    except OSError:
        return None, "raw_missing"
    return None, "raw_line_missing"


# --------------------------------------------------------------------------- 头
def _norm_headers(v: Any) -> list[list[str]]:
    if not isinstance(v, list):
        return []
    out: list[list[str]] = []
    for item in v:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append([str(item[0]), str(item[1])])
        elif isinstance(item, dict) and "name" in item:
            out.append([str(item.get("name")), str(item.get("value", ""))])
    return out


def _header_line_bytes(name: str, value: str) -> int:
    return len(name.encode("utf-8", "replace")) + 2 + len(value.encode("utf-8", "replace")) + 2


def _header_counts(headers: list[list[str]], raw: dict) -> tuple[int, int, bool]:
    total = sum(_header_line_bytes(n, v) for n, v in headers)
    stored = sum(_header_line_bytes(n, v) for n, v in headers)
    # raw 的 total 是截断前；stored 以数组实际内容为准。旧记录没有字段时两者相等。
    try:
        total = max(total, int(raw.get("headers_total_bytes") or 0))
    except (TypeError, ValueError):
        pass
    try:
        stored = min(stored, int(raw.get("headers_stored_bytes") or stored))
    except (TypeError, ValueError):
        pass
    truncated = bool(raw.get("headers_truncated")) or total > stored
    return total, stored, truncated


def _mask_headers(headers: list[list[str]], reveal: bool) -> tuple[list[list[str]], list[str], list[str]]:
    sensitive: list[str] = []
    masked: list[str] = []
    out: list[list[str]] = []
    for name, value in headers:
        low = name.strip().lower()
        is_sensitive = low in config.SENSITIVE_HEADERS
        if is_sensitive:
            sensitive.append(low)
        if is_sensitive and not reveal:
            masked.append(low)
            # 逐字符打码：保留值的长度，避免把字节数/原值带进默认视图。
            out.append([name, "*" * len(value)])
        else:
            out.append([name, value])
    return out, sorted(set(sensitive)), sorted(set(masked))


def _content_type(headers: list[list[str]]) -> str:
    for n, v in headers:
        if n.lower() == "content-type":
            return v.split(";", 1)[0].strip().lower()
    return ""


def _content_encoding(headers: list[list[str]]) -> list[str]:
    out: list[str] = []
    for n, v in headers:
        if n.lower() == "content-encoding":
            out.extend(x.strip().lower() for x in v.split(",") if x.strip())
    return out


def _is_textual(ct: str) -> bool:
    ct = (ct or "").split(";", 1)[0].strip().lower()
    return (ct.startswith("text/") or ct in _TEXTUAL_CT
            or ct.endswith("+json") or ct.endswith("+xml"))


def _is_binary_bytes(data: bytes, ct: str) -> bool:
    if ct and not _is_textual(ct):
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return b"\x00" in data


# --------------------------------------------------------------------------- 解压
def _decompress_gzip(data: bytes, wbits: int) -> tuple[bytes, bool]:
    d = zlib.decompressobj(wbits)
    out = d.decompress(data, MAX_DECODED + 1)
    truncated = len(out) > MAX_DECODED
    if truncated:
        out = out[:MAX_DECODED]
    if not truncated and not d.eof:
        # 源被 64KB 截断时，gzip 往往不完整；不要展示半截解压结果。
        raise zlib.error("incomplete compressed stream")
    if not truncated:
        extra = d.flush(MAX_DECODED + 1 - len(out))
        out += extra
        if len(out) > MAX_DECODED:
            out = out[:MAX_DECODED]
            truncated = True
    return out, truncated


def _decompress_br(data: bytes) -> tuple[bytes, bool]:
    try:
        import brotli  # type: ignore
    except Exception:
        raise RuntimeError("br_unsupported")
    d = brotli.Decompressor()
    out = bytearray()
    for i in range(0, len(data), 16384):
        out += d.process(data[i:i + 16384])
        if len(out) > MAX_DECODED:
            return bytes(out[:MAX_DECODED]), True
    try:
        out += d.finish()
    except Exception:
        pass
    if hasattr(d, "is_finished") and not d.is_finished():
        # 源体被截断/缺尾部时，不要展示半截解压结果（与 gzip 语义一致）。
        raise RuntimeError("incomplete compressed stream")
    return bytes(out), False


def _decompress_zstd(data: bytes) -> tuple[bytes, bool]:
    try:
        import zstandard as zstd  # type: ignore
    except Exception:
        raise RuntimeError("zstd_unsupported")
    dctx = zstd.ZstdDecompressor()
    with dctx.stream_reader(data) as r:
        out = r.read(MAX_DECODED + 1)
    if len(out) > MAX_DECODED:
        return out[:MAX_DECODED], True
    return out, False


def _decode_chain(data: bytes, encodings: Iterable[str], source_truncated: bool
                  ) -> tuple[Optional[bytes], bool, Optional[str]]:
    """按 HTTP 语义逆序解码。返回 (bytes|None, output_truncated, error)。"""
    encs = [e for e in encodings if e]
    if not encs:
        return data, False, None
    if source_truncated:
        return None, False, "source_truncated"
    out = data
    truncated = False
    for enc in reversed(encs):
        try:
            if enc in ("gzip", "x-gzip"):
                out, t = _decompress_gzip(out, 16 + zlib.MAX_WBITS)
            elif enc == "deflate":
                out, t = _decompress_gzip(out, zlib.MAX_WBITS)
            elif enc == "br":
                out, t = _decompress_br(out)
            elif enc in ("zstd", "x-zstd"):
                out, t = _decompress_zstd(out)
            else:
                return None, False, f"unsupported_encoding:{enc}"
            truncated = truncated or t
            if truncated:
                break
        except RuntimeError as e:
            return None, False, str(e)
        except Exception:
            return None, False, "decode_failed"
    return out, truncated, None


# --------------------------------------------------------------------------- body
def _b64(s: Any) -> bytes:
    if not isinstance(s, str):
        return b""
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return b""


def _body_obj(raw_bytes: bytes, *, wire_bytes: int, truncated: bool,
              content_type: str, encodings: list[str],
              legacy_lossy: bool = False, forced_binary: Optional[bool] = None) -> dict:
    decoded, dec_trunc, dec_err = _decode_chain(raw_bytes, encodings, truncated)
    if decoded is None:
        decoded = raw_bytes
        dec_trunc = False
    binary = (forced_binary if forced_binary is not None
              else _is_binary_bytes(decoded, content_type))
    text: Optional[str] = None
    text_enc: Optional[str] = None
    if not binary and dec_err is None:
        try:
            text = decoded.decode("utf-8")
            text_enc = "utf8"
        except UnicodeDecodeError:
            binary = True
    obj = {
        "b64": base64.b64encode(raw_bytes).decode("ascii"),
        "decoded_text": text,
        "decoded_encoding": text_enc,
        "decoded_is_binary": bool(binary),
        "wire_bytes": max(0, int(wire_bytes)),
        "stored_bytes": len(raw_bytes),
        "truncated": bool(truncated),
        "decode_truncated": bool(dec_trunc),
        "decode_error": dec_err,
        "content_encoding": list(encodings),
    }
    if legacy_lossy:
        obj["legacy_lossy"] = True
    return obj


def _norm_body_message(msg: dict, *, request: bool, content_type: str,
                       encodings: list[str]) -> tuple[Optional[dict], bool, str, int, bool]:
    """把 raw 里请求/响应 body 统一成 packet 契约。"""
    sampled = bool(msg.get("body_sampled", True))
    reason = str(msg.get("body_reason") or ("sampled" if sampled else "off"))
    wire = int(msg.get("body_len") or msg.get("body_wire_bytes") or 0)
    truncated = bool(msg.get("body_truncated"))
    if not sampled:
        return None, False, reason, wire, truncated

    b64 = msg.get("body_b64")
    if isinstance(b64, str) and b64 != "" or (isinstance(b64, str) and b64 == "" and msg.get("body_sampled")):
        raw = _b64(b64)
        forced = bool(msg.get("body_is_binary")) if request else None
        return _body_obj(raw, wire_bytes=wire, truncated=truncated,
                         content_type=content_type, encodings=encodings,
                         forced_binary=forced), True, reason, wire, truncated

    # 旧 raw：顶层 body 是文本，没有 body_b64。显式标记 legacy，避免旧格式漏进新契约。
    legacy = msg.get("body")
    if isinstance(legacy, str) and legacy:
        raw = legacy.encode("utf-8")
        if not wire:
            wire = len(raw)
        return _body_obj(raw, wire_bytes=wire, truncated=truncated,
                         content_type=content_type, encodings=encodings,
                         legacy_lossy=True), True, "legacy", wire, truncated
    if wire == 0:
        return _body_obj(b"", wire_bytes=0, truncated=False, content_type=content_type,
                         encodings=encodings, legacy_lossy=True), True, "legacy", 0, False
    # 旧记录明确 body_len>0 但没留下体：不能假装是空体。
    return None, False, "legacy_not_captured", wire, True


def _request_from_raw(d: Optional[dict], event: dict) -> tuple[dict, bool]:
    raw = d or {}
    headers = _norm_headers(raw.get("headers"))
    # 旧 raw 根本没有 headers 键；新 raw 即使 header 数组为空也不是“重建”。
    reconstructed = "headers" not in raw
    if not headers:
        # 重建粒度：只补 DB 里确实有的字段，不承诺完整请求。
        headers = []
        if event.get("host"):
            headers.append(["Host", str(event["host"])])
        if event.get("ua"):
            headers.append(["User-Agent", str(event["ua"])])
        if event.get("referer"):
            headers.append(["Referer", str(event["referer"])])
        if int(event.get("body_len") or 0) > 0:
            headers.append(["Content-Length", str(event.get("body_len"))])
    total, stored, htrunc = _header_counts(headers, raw)
    body_msg = {
        "body_b64": raw.get("body_b64"),
        "body": raw.get("body"),
        "body_sampled": raw.get("body_sampled", True if raw else False),
        "body_reason": raw.get("body_reason", "legacy" if raw else "reconstructed_no_body"),
        "body_is_binary": raw.get("body_is_binary"),
        "body_len": raw.get("body_len", event.get("body_len") or 0),
        "body_truncated": raw.get("body_truncated", event.get("body_truncated") or False),
    }
    body, sampled, reason, wire, btrunc = _norm_body_message(
        body_msg, request=True, content_type=_content_type(headers),
        encodings=_content_encoding(headers),
    )
    return {
        "http_version": raw.get("http_version"),
        "method": raw.get("method", event.get("method")),
        "path": raw.get("path", event.get("path")),
        "query": raw.get("query", event.get("query") or ""),
        "headers": headers,
        "headers_total_bytes": total,
        "headers_stored_bytes": stored,
        "headers_truncated": htrunc,
        "body_sampled": sampled,
        "body": body,
        "body_reason": reason,
        "body_wire_bytes": wire,
        "body_truncated": btrunc,
    }, reconstructed


def _response_from_raw(d: Optional[dict], event: dict) -> tuple[dict, bool]:
    raw = (d or {}).get("response") if d else None
    raw = raw if isinstance(raw, dict) else None
    recon = raw is None
    if raw is None:
        return {
            "captured": bool(event.get("status")),
            "http_version": None,
            "status": event.get("status"),
            "headers": [],
            "headers_total_bytes": 0,
            "headers_stored_bytes": 0,
            "headers_truncated": False,
            "sampling_mode": None,
            "body_sampled": False,
            "body": None,
            "body_reason": "reconstructed_no_response_body",
            "body_wire_bytes": int(event.get("bytes_out") or 0),
            "body_truncated": False,
        }, recon
    headers = _norm_headers(raw.get("headers"))
    total, stored, htrunc = _header_counts(headers, raw)
    body_msg = {
        "body_b64": raw.get("body", {}).get("b64") if isinstance(raw.get("body"), dict) else None,
        "body_sampled": raw.get("body_sampled", False),
        "body_reason": raw.get("body_reason", "off"),
        "body_len": raw.get("body_wire_bytes") or 0,
        "body_truncated": raw.get("body_truncated", False),
    }
    body, sampled, reason, wire, btrunc = _norm_body_message(
        body_msg, request=False, content_type=_content_type(headers),
        encodings=_content_encoding(headers),
    )
    return {
        "captured": bool(raw.get("captured", True)),
        "http_version": raw.get("http_version"),
        "status": raw.get("status", event.get("status")),
        "headers": headers,
        "headers_total_bytes": total,
        "headers_stored_bytes": stored,
        "headers_truncated": htrunc,
        "sampling_mode": raw.get("sampling_mode"),
        "body_sampled": sampled,
        "body": body,
        "body_reason": reason,
        "body_wire_bytes": wire,
        "body_truncated": btrunc,
    }, recon


# --------------------------------------------------------------------------- 对外
def build_packet(event: dict, reveal: bool = False) -> dict:
    raw, miss = _read_raw_line(event)
    reconstructed = raw is None
    reason = miss
    request, req_recon = _request_from_raw(raw, event)
    response, resp_recon = _response_from_raw(raw, event)
    if isinstance(raw, dict) and raw.get("response") is None and (
        "http_version" in raw or "headers" in raw or "body_b64" in raw
    ):
        # 新 raw 的 response 缺失通常表示上游/连接没有返回，而不是“重建”。
        response["captured"] = False
        response["status"] = None
        response["body_reason"] = "no_response"
        resp_recon = False
        if not reason:
            reason = "no_response"
    reconstructed = reconstructed or req_recon or resp_recon
    if not reason:
        if req_recon:
            reason = "legacy"
        elif resp_recon:
            reason = "legacy_response"

    req_headers, sensitive, masked = _mask_headers(request["headers"], reveal)
    resp_headers, s2, m2 = _mask_headers(response["headers"], reveal)
    request["headers"] = req_headers
    response["headers"] = resp_headers
    sensitive = sorted(set(sensitive + s2))
    masked = sorted(set(masked + m2))
    return {
        "event_id": event.get("id"),
        "reconstructed": bool(reconstructed),
        "reconstructed_reason": reason,
        "header_order_note": HEADER_ORDER_NOTE,
        "headers_count_basis": HEADER_COUNT_BASIS,
        "request": request,
        "response": response,
        "sensitive_headers": sensitive,
        "masked_headers": masked,
    }


def body_download(event: dict, side: str) -> tuple[Optional[bytes], bool, str]:
    """返回 (bytes, truncated, reason)。未采样返回 (None, ..., reason)。"""
    pkt = build_packet(event, reveal=True)
    msg = pkt["request"] if side == "request" else pkt["response"]
    body = msg.get("body")
    if not msg.get("body_sampled") or not isinstance(body, dict):
        return None, False, str(msg.get("body_reason") or "not_sampled")
    try:
        data = base64.b64decode(body.get("b64") or "")
    except Exception:
        return None, False, "bad_b64"
    return data, bool(body.get("truncated")), "ok"
