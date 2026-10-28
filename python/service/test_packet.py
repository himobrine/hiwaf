"""packet.py 的纯函数级测试：解码、二进制判定、打码、头字节计数。

运行：
    py -3.10 -m unittest service.test_packet -v
"""
from __future__ import annotations

import base64
import gzip
import importlib.util
import unittest
import zlib

from . import packet


class DecodeTests(unittest.TestCase):
    def test_gzip_decodes_and_keeps_wire_b64(self):
        raw = gzip.compress("你好，压缩响应".encode("utf-8"))
        obj = packet._body_obj(
            raw, wire_bytes=len(raw), truncated=False,
            content_type="application/json", encodings=["gzip"],
        )
        self.assertEqual(obj["decoded_text"], "你好，压缩响应")
        self.assertEqual(obj["decoded_encoding"], "utf8")
        self.assertFalse(obj["decoded_is_binary"])
        self.assertIsNone(obj["decode_error"])
        self.assertEqual(obj["content_encoding"], ["gzip"])
        self.assertEqual(base64.b64decode(obj["b64"]), raw)
        self.assertEqual(obj["wire_bytes"], len(raw))
        self.assertEqual(obj["stored_bytes"], len(raw))

    def test_source_truncated_is_not_decoded(self):
        raw = gzip.compress(b"x" * 1000)[:20]
        obj = packet._body_obj(
            raw, wire_bytes=1000, truncated=True,
            content_type="text/plain", encodings=["gzip"],
        )
        self.assertIsNone(obj["decoded_text"])
        self.assertEqual(obj["decode_error"], "source_truncated")
        self.assertEqual(base64.b64decode(obj["b64"]), raw)

    def test_incomplete_stream_is_reported(self):
        raw = gzip.compress(b"hello world" * 100)[:20]
        obj = packet._body_obj(
            raw, wire_bytes=len(raw), truncated=False,
            content_type="text/plain", encodings=["gzip"],
        )
        self.assertIsNone(obj["decoded_text"])
        self.assertEqual(obj["decode_error"], "decode_failed")

    def test_decode_chain_is_reverse_http_order(self):
        inner = gzip.compress("双层编码".encode("utf-8"))
        outer = zlib.compress(inner)
        obj = packet._body_obj(
            outer, wire_bytes=len(outer), truncated=False,
            content_type="text/plain", encodings=["gzip", "deflate"],
        )
        self.assertEqual(obj["decoded_text"], "双层编码")
        self.assertIsNone(obj["decode_error"])

    def test_decode_cap_marks_truncated(self):
        raw = gzip.compress(b"A" * (packet.MAX_DECODED + 1000))
        obj = packet._body_obj(
            raw, wire_bytes=len(raw), truncated=False,
            content_type="text/plain", encodings=["gzip"],
        )
        self.assertTrue(obj["decode_truncated"])
        self.assertEqual(len(obj["decoded_text"]), packet.MAX_DECODED)

    def test_binary_content_type_stays_binary_even_if_utf8(self):
        obj = packet._body_obj(
            b"plain ascii", wire_bytes=10, truncated=False,
            content_type="application/octet-stream", encodings=[],
        )
        self.assertTrue(obj["decoded_is_binary"])
        self.assertIsNone(obj["decoded_text"])
        self.assertIsNone(obj["decode_error"])

    def test_brotli_unsupported_is_explicit_or_decodes(self):
        if importlib.util.find_spec("brotli") is None:
            obj = packet._body_obj(
                b"not-br", wire_bytes=6, truncated=False,
                content_type="text/plain", encodings=["br"],
            )
            self.assertIsNone(obj["decoded_text"])
            self.assertEqual(obj["decode_error"], "br_unsupported")
        else:
            import brotli  # type: ignore
            raw = brotli.compress(b"br-ok")
            obj = packet._body_obj(
                raw, wire_bytes=len(raw), truncated=False,
                content_type="text/plain", encodings=["br"],
            )
            self.assertEqual(obj["decoded_text"], "br-ok")

    def test_brotli_truncated_is_reported(self):
        if importlib.util.find_spec("brotli") is None:
            self.skipTest("brotli not installed")
        import brotli  # type: ignore
        raw = brotli.compress(b"x" * 10000)
        raw = raw[: max(1, len(raw) // 2)]
        obj = packet._body_obj(
            raw, wire_bytes=len(raw), truncated=False,
            content_type="text/plain", encodings=["br"],
        )
        self.assertIsNone(obj["decoded_text"])
        self.assertEqual(obj["decode_error"], "incomplete compressed stream")

    def test_zstd_unsupported_is_explicit_or_decodes(self):
        if importlib.util.find_spec("zstandard") is None:
            obj = packet._body_obj(
                b"not-zstd", wire_bytes=8, truncated=False,
                content_type="text/plain", encodings=["zstd"],
            )
            self.assertIsNone(obj["decoded_text"])
            self.assertEqual(obj["decode_error"], "zstd_unsupported")
        else:
            import zstandard  # type: ignore
            raw = zstandard.ZstdCompressor().compress(b"zstd-ok")
            obj = packet._body_obj(
                raw, wire_bytes=len(raw), truncated=False,
                content_type="text/plain", encodings=["zstd"],
            )
            self.assertEqual(obj["decoded_text"], "zstd-ok")


class HeaderTests(unittest.TestCase):
    def test_mask_headers_and_reveal(self):
        hs = [["Host", "example"], ["Authorization", "Bearer s"],
              ["Cookie", "a=1"], ["Set-Cookie", "b=2"], ["X", "ok"]]
        masked, sensitive, masked_names = packet._mask_headers(hs, False)
        self.assertEqual(sensitive, ["authorization", "cookie", "set-cookie"])
        self.assertEqual(masked_names, ["authorization", "cookie", "set-cookie"])
        self.assertEqual(masked[1][1], "*" * len("Bearer s"))
        self.assertEqual(masked[2][1], "*" * len("a=1"))
        self.assertNotIn("Bearer s", masked[1][1])
        revealed, sensitive2, masked2 = packet._mask_headers(hs, True)
        self.assertEqual(masked2, [])
        self.assertEqual(sensitive2, sensitive)
        self.assertEqual(revealed[1][1], "Bearer s")
        self.assertEqual(revealed[3][1], "b=2")

    def test_mask_headers_counts_characters_not_bytes(self):
        hs = [["Authorization", "密钥"], ["X-Api-Key", "abc"]]
        masked, _, _ = packet._mask_headers(hs, False)
        self.assertEqual(masked[0][1], "**")
        self.assertEqual(masked[1][1], "***")

    def test_header_bytes_are_utf8_and_duplicates_counted(self):
        hs = [["X-A", "一"], ["X-A", "二"]]
        total = packet._header_line_bytes("X-A", "一") + packet._header_line_bytes("X-A", "二")
        got_total, got_stored, truncated = packet._header_counts(
            hs, {"headers_total_bytes": total, "headers_stored_bytes": total},
        )
        self.assertEqual(got_total, total)
        self.assertEqual(got_stored, total)
        self.assertFalse(truncated)

    def test_header_counts_detect_truncated_raw(self):
        hs = [["X-A", "kept"]]
        got_total, got_stored, truncated = packet._header_counts(
            hs, {"headers_total_bytes": 999, "headers_stored_bytes": 10, "headers_truncated": True},
        )
        self.assertEqual(got_total, 999)
        self.assertLessEqual(got_stored, 10)
        self.assertTrue(truncated)


if __name__ == "__main__":
    unittest.main()
