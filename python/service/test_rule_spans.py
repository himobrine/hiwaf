"""规则命中精确标位：解码映射 + scope/局部-全文消歧。"""
from __future__ import annotations

import unittest

from . import rule_spans
from .rule_spans import DecodedField


def _slice(field: DecodedField, seg):
    return field.raw[seg[0]:seg[1]]


class DecodeMapTest(unittest.TestCase):
    def test_percent_maps_back_to_raw(self):
        df = DecodedField("q=1%20UNION%20SELECT")
        self.assertEqual(df.text, "q=1 UNION SELECT")
        start = len(df.text[:df.text.index("UNION SELECT")].encode("utf-8"))
        end = start + len("UNION SELECT")
        seg = df.map_byte_range(start, end)
        self.assertEqual(_slice(df, seg), "UNION%20SELECT")

    def test_plus_and_slash(self):
        df = DecodedField("a+b%2Fc")
        self.assertEqual(df.text, "a b/c")
        self.assertEqual(_slice(df, df.find("b/c")), "b%2Fc")

    def test_unicode_escape(self):
        df = DecodedField(r"\u003cscript\u003e")
        self.assertEqual(df.text, "<script>")
        self.assertEqual(_slice(df, df.find("<script>")), r"\u003cscript\u003e")

    def test_double_encoded(self):
        df = DecodedField("%253Cscript%253E")
        self.assertEqual(df.text, "<script>")
        self.assertEqual(_slice(df, df.find("<script>")), "%253Cscript%253E")

    def test_lone_surrogate_is_replacement(self):
        df = DecodedField(r"\ud800x")
        self.assertEqual(df.text, "\ufffdx")

    def test_multibyte_percent_maps_back(self):
        df = DecodedField("q=%E4%B8%AD%20UNION")
        self.assertEqual(df.text, "q=中 UNION")
        self.assertEqual(_slice(df, df.find(" UNION")), "%20UNION")

    def test_astral_unicode_escape(self):
        df = DecodedField(r"a\U0001F600b")
        self.assertEqual(df.text, "a\U0001F600b")
        self.assertEqual(_slice(df, df.find("\U0001F600")), r"\U0001F600")

    def test_invalid_utf8_replacement_matches_python(self):
        # 百分号解码后可能是非法 UTF-8；Rust/Python 的 lossy 分组必须一致，
        # 否则替换符数量不同，后续偏移会整体错位。
        cases = [
            b"\xe4\xb8", b"\xe4\xb8A", b"\xf0\x9f", b"\xc2",
            b"\xe4A", b"\xed\xa0\x80", b"\xff\xff",
            b"\xe4\xb8\xe4\xb8", b"\xe0\x80\x80", b"\xf4\x90\x80\x80",
        ]
        for data in cases:
            got, _ = rule_spans._utf8_decode_with_spans(
                data, [(i, i + 1) for i in range(len(data))])
            self.assertEqual(got, data.decode("utf-8", "replace"), data)


class AttachSpansTest(unittest.TestCase):
    def setUp(self):
        self.req = {
            "method": "GET",
            "path": "/search",
            "query": "q=hello+world",
            "headers": [["User-Agent", "sqlmap/1.7"], ["Referer", "http://x/%3Ctag%3E"]],
            "body": {"decoded_text": "id=1%27+OR+1%3D1", "decode_error": None,
                     "decoded_is_binary": False},
        }

    def test_query_scope(self):
        hits = [{"rule": "r", "scope": "query", "field": "query",
                 "start": 2, "end": 13, "snippet": "q=hello world"}]
        out = rule_spans.attach_spans(self.req, hits)
        self.assertEqual(out[0]["segments"], [{"field": "query", "start": 2, "end": 13}])

    def test_full_scope_is_split_back_to_field(self):
        # full = "GET /search?q=hello world id=1 OR 1=1"
        full = "GET /search?q=hello world id=1 OR 1=1"
        start = full.index("hello world")
        hits = [{"rule": "r", "scope": "full", "field": "query",
                 "start": start, "end": start + 11, "snippet": full}]
        out = rule_spans.attach_spans(self.req, hits)
        self.assertEqual(out[0]["segments"], [{"field": "query", "start": 2, "end": 13}])

    def test_legacy_without_scope_uses_snippet_to_pick_full(self):
        full = "GET /search?q=hello world id=1 OR 1=1"
        start = full.index("hello world")
        hits = [{"rule": "r", "field": "query",
                 "start": start, "end": start + 11, "snippet": full}]
        out = rule_spans.attach_spans(self.req, hits)
        self.assertEqual(out[0]["segments"], [{"field": "query", "start": 2, "end": 13}])

    def test_legacy_without_scope_keeps_local_query(self):
        hits = [{"rule": "r", "field": "query",
                 "start": 2, "end": 13, "snippet": "q=hello world"}]
        out = rule_spans.attach_spans(self.req, hits)
        self.assertEqual(out[0]["segments"], [{"field": "query", "start": 2, "end": 13}])

    def test_full_scope_uses_rule_default_get_when_method_missing(self):
        req = {"method": "", "path": "/x", "query": "a=1", "headers": [], "body": None}
        # Rust 规则输入把空 method 变成 GET；full = "GET /x?a=1 "
        hits = [{"rule": "r", "scope": "full", "field": "query",
                 "start": 7, "end": 10, "snippet": "GET /x?a=1 "}]
        out = rule_spans.attach_spans(req, hits)
        self.assertEqual(out[0]["segments"], [{"field": "query", "start": 0, "end": 3}])

    def test_full_scope_spanning_fields_excludes_separator(self):
        full = "GET /search?q=hello world id=1 OR 1=1"
        start = full.index("GET")
        end = full.index("q=hello") + len("q=hello")
        hits = [{"rule": "r", "scope": "full", "field": "method",
                 "start": start, "end": end, "snippet": full}]
        out = rule_spans.attach_spans(self.req, hits)
        # `GET` 与 `/search` 分开标，字面量空格和 `?` 不属于任何字段。
        self.assertEqual(out[0]["segments"], [
            {"field": "method", "start": 0, "end": 3},
            {"field": "path", "start": 0, "end": 7},
            {"field": "query", "start": 0, "end": 7},
        ])

    def test_body_scope_percent(self):
        body = "id=1%27+OR+1%3D1"
        df = DecodedField(body)
        decoded = "id=1' OR 1=1"
        start = len(decoded[:decoded.index("1' OR")].encode())
        end = start + len("1' OR 1=1")
        hits = [{"rule": "r", "scope": "body", "field": "body",
                 "start": start, "end": end, "snippet": body}]
        out = rule_spans.attach_spans(self.req, hits)
        seg = out[0]["segments"][0]
        self.assertEqual(self.req["body"]["decoded_text"][seg["start"]:seg["end"]],
                         "1%27+OR+1%3D1")

    def test_unknown_field_no_segments(self):
        hits = [{"rule": "r", "scope": "nope", "field": "nope",
                 "start": 0, "end": 1, "snippet": "x"}]
        out = rule_spans.attach_spans(self.req, hits)
        self.assertNotIn("segments", out[0])


if __name__ == "__main__":
    unittest.main()
