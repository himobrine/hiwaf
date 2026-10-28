"""upload_parse.py 的解析回归（CSV / JSON / JSONL / pcap）。"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import upload_parse as up  # noqa: E402


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


class UploadParseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_label_aliases(self):
        self.assertEqual(up.parse_label("sqli"), 1)
        self.assertEqual(up.parse_label("path-traversal"), 4)
        self.assertEqual(up.parse_label("2"), 2)
        self.assertIsNone(up.parse_label("wat"))
        self.assertEqual(up.parse_label(None, default=0), 0)

    def test_split_url(self):
        self.assertEqual(up.split_url("http://h/a?x=1"), ("/a", "x=1"))
        self.assertEqual(up.split_url("/b?y=2"), ("/b", "y=2"))
        self.assertEqual(up.split_url("/c"), ("/c", ""))

    def test_csv_full_url_and_missing_label(self):
        p = os.path.join(self.dir, "a.csv")
        _write(p, "method,url,body,attack_type\n"
                  "GET,http://h/a?q=1,,norm\n"
                  "POST,/login,u=1&p=2,sqli\n"
                  "GET,/bad,,wat\n")
        rows, extra = up.parse_csv(p, None, "supervised", 1000, 1 << 20)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["path"], "/a")
        self.assertEqual(rows[0]["query"], "q=1")
        self.assertEqual(rows[1]["label"], 1)
        self.assertIn("missing_or_unknown_label", extra["skip_reasons"])

    def test_csv_quoted_newline_in_body(self):
        p = os.path.join(self.dir, "nl.csv")
        body = "line1\nline2"
        _write(p, "method,path,body,label\n"
                  f'GET,/n,"{body}",0\n')
        rows, _ = up.parse_csv(p, None, "supervised", 1000, 1 << 20)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["body"], body)

    def test_benign_role_rejects_attack(self):
        p = os.path.join(self.dir, "b.csv")
        _write(p, "method,path,label\nGET,/a,0\nGET,/b,1\n")
        rows, extra = up.parse_csv(p, None, "benign", 1000, 1 << 20)
        self.assertEqual(len(rows), 1)
        self.assertIn("non_benign_label", extra["skip_reasons"])

    def test_jsonl_and_har(self):
        p1 = os.path.join(self.dir, "c.jsonl")
        _write(p1, json.dumps({"method": "GET", "path": "/n", "label": 0}) + "\n" +
                   json.dumps({"method": "POST", "url": "http://h/s?x=1", "body": "a=1",
                               "label": 1}) + "\n")
        rows, _ = up.parse_json(p1, None, "supervised", 1000, 1 << 20)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["path"], "/s")
        self.assertEqual(rows[1]["query"], "x=1")
        p2 = os.path.join(self.dir, "d.json")
        _write(p2, json.dumps({"log": {"entries": [
            {"request": {"method": "GET", "url": "http://h/z?k=v"},
             "label": 0}]}}))
        rows2, _ = up.parse_json(p2, None, "supervised", 1000, 1 << 20)
        self.assertEqual(rows2[0]["path"], "/z")
        self.assertEqual(rows2[0]["query"], "k=v")

    def test_pcap_split_retransmit_and_tls(self):
        try:
            from scapy.all import Ether, IP, TCP, Raw, wrpcap
        except Exception:
            self.skipTest("scapy 未安装")
        p = os.path.join(self.dir, "e.pcap")
        req1 = b"GET /a?q=1 HTTP/1.1\r\nHost: h\r\n\r\n"
        req2 = b"POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\n\r\nx=1&y=2"

        def pkt(payload, seq, sport=12345, dport=80):
            return (Ether() / IP(src="10.0.0.2", dst="10.0.0.1") /
                    TCP(sport=sport, dport=dport, seq=seq, flags="PA") / Raw(load=payload))

        pkts = [pkt(req1[:10], 1000), pkt(req1[10:], 1010), pkt(req1, 1000),
                pkt(req2, 2000),
                pkt(b"\x16\x03\x01\x00\x10", 3000, sport=12346, dport=443)]
        wrpcap(p, pkts)
        rows, extra = up.parse_pcap(p, 0, "benign", 1000, 1000, 100, 1 << 20)
        self.assertEqual([r["path"] for r in rows], ["/a", "/b"])
        self.assertEqual(extra["pcap"]["skipped_tls"], 1)

    def test_summarize_duplicates(self):
        rows = [{"method": "GET", "path": "/a", "query": "", "body": "", "label": 0},
                {"method": "GET", "path": "/a", "query": "", "body": "", "label": 0}]
        s = up.summarize(rows, {"rows_total": 2})
        self.assertEqual(s["duplicates"], 1)
        self.assertEqual(s["benign"], 2)


if __name__ == "__main__":
    unittest.main()
