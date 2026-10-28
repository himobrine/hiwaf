"""把规则命中的字节偏移落成「当前取证包文本」里的精确字符区间。

为什么不在前端直接拿 `start/end` 切片：

* 规则跑在**解码后**文本上（urlencoded 两遍 + unicode 转义），而取证包展示的是
  原始请求行/查询串/正文。`%20` 是 3 个字节，解码后只占 1 个字符，偏移不能直接复用。
* `full` 作用域的 `start/end` 是 `METHOD path?query body` 全文偏移，而 `field`
  已经回映射到某个字段；直接按字段切片会把全文字段偏移误当成本字段偏移。

这里重建与 Rust `decode.rs` 同语义的「解码 + 到原始文本的字符映射」，再用规则
作用域（新数据带 `scope`）切片。老数据没有 `scope` 时用 `snippet` / 局部切片候选
做一次消歧；仍然无法确定就不返回 `segments`，由前端退回字段级标红，绝不猜位置。
"""
from __future__ import annotations

import json
from typing import Optional

from . import config

#: 与 Rust 规则集默认流水线一致。规则集若显式写 `raw`，编译期会清空流水线。
DEFAULT_STAGES = ("urlencoded", "unicode")

MAX_SNIPPET_PAD = 64


def _hex(b: int) -> Optional[int]:
    if 48 <= b <= 57:
        return b - 48
    if 97 <= b <= 102:
        return b - 97 + 10
    if 65 <= b <= 70:
        return b - 65 + 10
    return None


def _utf8_shape(lead: int):
    """返回 `(期望总字节数, 第二字节下限, 第二字节上限)`；非法起始字节长度为 0。"""
    if lead < 0x80:
        return 1, 0x00, 0x7F
    if 0xC2 <= lead <= 0xDF:
        return 2, 0x80, 0xBF
    if lead == 0xE0:
        return 3, 0xA0, 0xBF
    if 0xE1 <= lead <= 0xEC:
        return 3, 0x80, 0xBF
    if lead == 0xED:
        # 代理区不能出现在 UTF-8 里；Python/Rust 都按“起始字节单独非法”处理。
        return 3, 0x80, 0x9F
    if 0xEE <= lead <= 0xEF:
        return 3, 0x80, 0xBF
    if lead == 0xF0:
        return 4, 0x90, 0xBF
    if 0xF1 <= lead <= 0xF3:
        return 4, 0x80, 0xBF
    if lead == 0xF4:
        return 4, 0x80, 0x8F
    return 0, 0x00, -1


def _utf8_decode_with_spans(data: bytes, spans: list[tuple[int, int]]):
    """UTF-8 lossy 解码；输出每个字符的 UTF-8 字节仍带原始字节区间。

    逐字节解析而不是直接 `bytes.decode(errors="replace")`，因为标位需要知道每个
    U+FFFD 覆盖了哪些原始字节。这里按 Python/Rust 的“最大非法子序列”语义：
    `E4 B8`（截断）算一个替换符，`E4 B8 FF` 算「E4 B8」+「FF」两个。
    """
    out_chars: list[str] = []
    out_spans: list[tuple[int, int]] = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        need, lo, hi = _utf8_shape(b)
        ch = None
        consumed = 1

        if need == 1:
            ch = chr(b)
        elif need > 1:
            if i + 1 < n and lo <= data[i + 1] <= hi:
                consumed = 2
                while consumed < need and i + consumed < n \
                        and 0x80 <= data[i + consumed] <= 0xBF:
                    consumed += 1
                if consumed == need:
                    try:
                        candidate = data[i:i + need].decode("utf-8")
                    except UnicodeDecodeError:
                        candidate = ""
                    if len(candidate) == 1:
                        ch = candidate
            # 不完整/后续字节非法：保留已消费的合法前缀，整体输出一个 U+FFFD。

        if ch is None:
            ch = "\ufffd"
            if consumed < 1:
                consumed = 1

        raw_start = spans[i][0]
        raw_end = spans[i + consumed - 1][1]
        for _ in ch.encode("utf-8"):
            out_spans.append((raw_start, raw_end))
        out_chars.append(ch)
        i += consumed
    return "".join(out_chars), out_spans


def _urlencoded_once(text: str, spans: list[tuple[int, int]]):
    data = text.encode("utf-8")
    # `+` -> 空格。字节长度不变，映射直接跟着走。
    plus = bytearray()
    plus_spans: list[tuple[int, int]] = []
    for i, b in enumerate(data):
        if b == 0x2B:
            plus.append(0x20)
        else:
            plus.append(b)
        plus_spans.append(spans[i])

    if 0x25 not in plus:  # 无 `%`，与 unquote_plus 一样直接返回
        return plus.decode("utf-8"), plus_spans

    out = bytearray()
    out_spans: list[tuple[int, int]] = []
    i = 0
    n = len(plus)
    while i < n:
        b = plus[i]
        if b == 0x25 and i + 2 < n:
            h = _hex(plus[i + 1])
            l = _hex(plus[i + 2])
            if h is not None and l is not None:
                out.append((h << 4) | l)
                out_spans.append((plus_spans[i][0], plus_spans[i + 2][1]))
                i += 3
                continue
        out.append(b)
        out_spans.append(plus_spans[i])
        i += 1
    return _utf8_decode_with_spans(bytes(out), out_spans)


def _unicode_once(text: str, spans: list[tuple[int, int]]):
    if "\\u" not in text and "\\U" not in text:
        return text, spans

    out_chars: list[str] = []
    out_spans: list[tuple[int, int]] = []
    i = 0
    bi = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            kind = text[i + 1]
            width = 4 if kind == "u" else 8 if kind == "U" else 0
            if width and i + 2 + width <= n:
                raw_hex = text[i + 2:i + 2 + width]
                try:
                    cp = int(raw_hex, 16)
                except ValueError:
                    cp = -1
                if cp >= 0:
                    consumed = 2 + width
                    # 代理对：高代理 + 紧接着的 \uXXXX 低代理。
                    if (0xD800 <= cp <= 0xDBFF and i + consumed + 5 < n
                            and text[i + consumed:i + consumed + 2] == "\\u"):
                        try:
                            lo = int(text[i + consumed + 2:i + consumed + 6], 16)
                        except ValueError:
                            lo = -1
                        if 0xDC00 <= lo <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            consumed += 6
                    out_ch = (chr(cp) if 0 <= cp <= 0x10FFFF
                              and not 0xD800 <= cp <= 0xDFFF else "\ufffd")
                    start = spans[bi][0]
                    end = spans[bi + consumed - 1][1]
                    for _ in out_ch.encode("utf-8"):
                        out_spans.append((start, end))
                    out_chars.append(out_ch)
                    i += consumed
                    bi += consumed
                    continue

        size = len(ch.encode("utf-8"))
        out_chars.append(ch)
        for k in range(size):
            out_spans.append(spans[bi + k])
        i += 1
        bi += size
    return "".join(out_chars), out_spans


def decode_with_spans(text: str, stages=DEFAULT_STAGES):
    """返回 `(decoded, spans)`；`spans` 是 decoded 每个 UTF-8 字节对应的原始字节区间。"""
    raw = text.encode("utf-8")
    cur = text
    cur_spans = [(i, i + 1) for i in range(len(raw))]
    for stage in stages:
        for _ in range(2):
            if stage == "urlencoded":
                nxt, nspans = _urlencoded_once(cur, cur_spans)
            elif stage == "unicode":
                nxt, nspans = _unicode_once(cur, cur_spans)
            else:
                nxt, nspans = cur, cur_spans
            if nxt == cur:
                break
            cur, cur_spans = nxt, nspans
    return cur, cur_spans


def _active_stages():
    """现役规则集的解码流水线；读不到就退回项目默认值。"""
    try:
        doc = json.loads(config.RULES_AUTHORITATIVE.read_text(encoding="utf-8"))
        raw = [str(s).strip().lower() for s in (doc.get("decode") or [])]
        if any(s in ("raw", "none", "off") for s in raw):
            return ()
        return tuple(raw) if raw else ("urlencoded",)
    except Exception:
        return DEFAULT_STAGES


class DecodedField:
    """一个字段的解码文本 + 每个解码字节到原始字符串字符区间的映射。"""

    def __init__(self, raw: str, stages=DEFAULT_STAGES):
        self.raw = raw or ""
        self.text, self.spans = decode_with_spans(self.raw, stages)

        raw_bytes = self.raw.encode("utf-8")
        self.raw_byte_to_char = [0] * (len(raw_bytes) + 1)
        j = 0
        for ci, ch in enumerate(self.raw):
            size = len(ch.encode("utf-8"))
            for k in range(size):
                self.raw_byte_to_char[j + k] = ci
            j += size
        self.raw_byte_to_char[len(raw_bytes)] = len(self.raw)

        self.utf16_prefix = [0]
        for ch in self.raw:
            self.utf16_prefix.append(self.utf16_prefix[-1] + (2 if ord(ch) > 0xFFFF else 1))

        text_bytes = self.text.encode("utf-8")
        self.text_byte_to_char = [0] * (len(text_bytes) + 1)
        j = 0
        for ci, ch in enumerate(self.text):
            size = len(ch.encode("utf-8"))
            for k in range(size):
                self.text_byte_to_char[j + k] = ci
            j += size
        self.text_byte_to_char[len(text_bytes)] = len(self.text)

    def _raw_char_range(self, start: int, end: int):
        if not self.spans or start >= end:
            return None
        start = max(0, min(int(start), len(self.spans)))
        end = max(0, min(int(end), len(self.spans)))
        if start >= end:
            return None
        rs = self.spans[start][0]
        re = self.spans[end - 1][1]
        cs = self.raw_byte_to_char[rs] if 0 <= rs < len(self.raw_byte_to_char) else len(self.raw)
        ce = self.raw_byte_to_char[re] if 0 <= re < len(self.raw_byte_to_char) else len(self.raw)
        return cs, ce

    def map_byte_range(self, start: int, end: int):
        rr = self._raw_char_range(start, end)
        if rr is None:
            return None
        cs, ce = rr
        return self.utf16_prefix[cs], self.utf16_prefix[ce]

    def decoded_slice(self, start: int, end: int) -> str:
        b = self.text.encode("utf-8")
        if start < 0 or end > len(b) or start >= end:
            return ""
        try:
            return b[start:end].decode("utf-8")
        except UnicodeDecodeError:
            return ""

    def find(self, needle: str):
        """在解码文本里找 needle；返回原始字符串的 UTF-16 区间。"""
        if not needle:
            return None
        # 先看原始文本：大多数未编码字段直接命中，偏移最可靠。
        raw_idx = self.raw.find(needle)
        if raw_idx >= 0:
            start = self.utf16_prefix[raw_idx]
            end = self.utf16_prefix[raw_idx + len(needle)]
            return start, end
        idx = self.text.find(needle)
        if idx < 0:
            return None
        rr = self._raw_char_range(
            len(self.text[:idx].encode("utf-8")),
            len(self.text[:idx + len(needle)].encode("utf-8")),
        )
        if rr is None:
            return None
        return self.utf16_prefix[rr[0]], self.utf16_prefix[rr[1]]


class FullView:
    """`METHOD path?query body` 的解码全文，以及各字段的字节边界。"""

    def __init__(self, fields: dict[str, DecodedField]):
        self.fields = fields
        self.bounds: list[tuple[str, int, int]] = []
        parts: list[str] = []
        pos = 0
        for name in ("method", "path", "query", "body"):
            t = fields[name].text
            a = pos
            pos += len(t.encode("utf-8"))
            self.bounds.append((name, a, pos))
            parts.append(t)
            if name == "method":
                parts.append(" ")
                pos += 1
            elif name == "path":
                parts.append("?")
                pos += 1
            elif name == "query":
                parts.append(" ")
                pos += 1
        self.text = "".join(parts)
        self.bytes = self.text.encode("utf-8")

    def segments(self, start: int, end: int):
        out = []
        for name, a, b in self.bounds:
            lo = max(start, a)
            hi = min(end, b)
            if lo >= hi:
                continue
            mapped = self.fields[name].map_byte_range(lo - a, hi - a)
            if mapped:
                out.append({"field": name, "start": mapped[0], "end": mapped[1]})
        return out

    def decoded_slice(self, start: int, end: int) -> str:
        if start < 0 or end > len(self.bytes) or start >= end:
            return ""
        try:
            return self.bytes[start:end].decode("utf-8")
        except UnicodeDecodeError:
            return ""


def _as_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _snippet_match(hit: dict) -> Optional[str]:
    """从 `snippet` 里抠出规则实际匹配到的文本。

    Rust 的 snippet = 命中前 64 字节（做字符边界对齐）+ 命中 + 后 64 字节，
    再按 120 个字符截断。start/end 是作用域文本的字节偏移，所以匹配在 snippet
    里的起始字节数 = min(start, 64)，只需容忍对齐造成的 0..3 字节回退。
    """
    snippet = hit.get("snippet")
    start = _as_int(hit.get("start"))
    end = _as_int(hit.get("end"))
    if not snippet or start is None or end is None or end <= start:
        return None
    sb = str(snippet).encode("utf-8")
    prefix = min(max(start, 0), MAX_SNIPPET_PAD)
    length = end - start
    for p in range(prefix, max(-1, prefix - 4), -1):
        if p + length > len(sb):
            continue
        try:
            s = sb[p:p + length].decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s:
            return s
    return None


def _local_segment(field: str, df: DecodedField, start: int, end: int):
    mapped = df.map_byte_range(start, end)
    if not mapped:
        return []
    return [{"field": field, "start": mapped[0], "end": mapped[1]}]


def _choose_legacy(field: str, fields: dict[str, DecodedField],
                   full: FullView, start: int, end: int, snip: Optional[str]):
    """老数据没有 scope：用局部切片/全文切片与 snippet 对齐来消歧。"""
    local = fields.get(field)
    local_seg = _local_segment(field, local, start, end) if local else []
    full_seg = full.segments(start, end)

    # 直接比较两种候选的**解码切片**最准确。
    local_txt = local.decoded_slice(start, end) if local else ""
    full_txt = full.decoded_slice(start, end)
    if snip:
        if full_txt == snip:
            return full_seg
        if local_txt == snip:
            return local_seg
        if snip in full_txt:
            return full_seg
        if local_txt and snip in local_txt:
            return local_seg

    if field == "full":
        return full_seg
    if local_seg:
        return local_seg
    return full_seg


def _find_snippet_segments(field: str, fields: dict[str, DecodedField],
                           full: FullView, snip: Optional[str]):
    if not snip:
        return []
    if field in fields:
        found = fields[field].find(snip)
        return [{"field": field, "start": found[0], "end": found[1]}] if found else []
    if field == "full":
        found = full.text.find(snip)
        if found >= 0:
            bs = len(full.text[:found].encode("utf-8"))
            be = bs + len(snip.encode("utf-8"))
            return full.segments(bs, be)
    return []


def attach_spans(request: dict, hits: list[dict], stages=None) -> list[dict]:
    """给每条命中补 `segments`（UTF-16 字符区间，直接可用于 JS `slice`）。"""
    if not hits:
        return hits
    if stages is None:
        stages = _active_stages()

    headers = request.get("headers") or []

    def header(name: str) -> str:
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                if str(item[0]).lower() == name:
                    return str(item[1])
        return ""

    body = request.get("body") or {}
    if body.get("decode_error") or body.get("decoded_is_binary"):
        body_text = ""
    else:
        body_text = str(body.get("decoded_text") or "")

    raw_fields = {
        "method": str(request.get("method") or ""),
        "path": str(request.get("path") or ""),
        "query": str(request.get("query") or ""),
        "body": body_text,
        "ua": header("user-agent"),
        "referer": header("referer") or header("referrer"),
    }
    fields = {k: DecodedField(v, stages) for k, v in raw_fields.items()}
    # Rust `RuleInput::from_json` 对空 method 的默认值是 `GET`；full 文本必须按
    # 规则实际看到的文本拼装，否则 path/query 的全文偏移会整体少 3 个字节。
    full_fields = dict(fields)
    if not raw_fields["method"]:
        full_fields["method"] = DecodedField("GET", stages)
    full = FullView(full_fields)

    for hit in hits:
        if not isinstance(hit, dict):
            continue
        hit.pop("segments", None)
        try:
            start = _as_int(hit.get("start"))
            end = _as_int(hit.get("end"))
            if start is None or end is None or end <= start:
                continue
            scope = str(hit.get("scope") or "").strip().lower()
            field = str(hit.get("field") or "").strip().lower()
            snip = _snippet_match(hit)

            segments = []
            if scope == "full":
                segments = full.segments(start, end)
            elif scope in fields:
                segments = _local_segment(scope, fields[scope], start, end)
            elif field == "full":
                segments = _choose_legacy(field, fields, full, start, end, snip)
            elif field in fields:
                segments = _choose_legacy(field, fields, full, start, end, snip)
            else:
                # 未知字段不猜：绝不因为 snippet 恰好出现在某个已知字段里就染色。
                segments = []

            if not segments and snip:
                segments = _find_snippet_segments(field, fields, full, snip)
            if segments:
                hit["segments"] = segments
        except Exception:
            # 单条命中标位失败不应拖垮整包；该条退回前端字段级（有 scope 时宁可不标）。
            hit.pop("segments", None)
    return hits
