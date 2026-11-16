"""convert_fur_api.py / convert_exploit.py 的回归测试。

这两份转换器各自修了一处"静默丢数据"的坑，必须用测试钉住：

* FUR-API：`upload_parse` 的标签别名表没有 `anomaly`，直接用会把业务异常
  全部丢掉；本转换器显式映射 normal->0 / anomaly->1。
* exploit_dataset：源文件是**缺逗号的 pretty-printed JSON 数组**，且请求藏在
  `poc` 原始报文里；本转换器按缩进切块 + 拆 HTTP 报文。

跑法：`py -3.10 -m unittest test_convert_newdata -v`（在 python/ 下）
"""
from __future__ import annotations

import csv
import json
import os
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import convert_exploit as ce   # noqa: E402
import convert_fur_api as cf   # noqa: E402

FUR_HEADER = [
    "timestamp", "agent", "method", "request_body", "request_headers",
    "request_url", "response_body", "response_headers", "response_size",
    "source_ip", "source_port", "status", "target_ip", "target_port",
    "response_time", "user_identity", "type",
]


def _fur_row(**kw):
    row = {k: "" for k in FUR_HEADER}
    row.update(kw)
    return row


class FurApiConvertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _csv(self, rows, name="train.csv"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FUR_HEADER)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return path

    def test_label_mapping_keeps_anomaly(self):
        path = self._csv([
            _fur_row(method="GET", request_url="/api/a?x=1", type="normal"),
            _fur_row(method="post", request_url="http://h/api/b", type="anomaly"),
        ])
        rows, stats = cf.convert(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["label"], 0)
        self.assertEqual(rows[0]["path"], "/api/a")
        self.assertEqual(rows[0]["query"], "x=1")
        self.assertEqual(rows[1]["label"], 1)
        self.assertEqual(rows[1]["method"], "POST")
        self.assertEqual(rows[1]["path"], "/api/b")
        self.assertEqual(stats["label_counts"], {0: 1, 1: 1})
        self.assertEqual(stats["by_type"], {"normal": 1, "anomaly": 1})

    def test_unknown_type_skipped(self):
        path = self._csv([_fur_row(request_url="/a", type="weird")])
        rows, stats = cf.convert(path)
        self.assertEqual(rows, [])
        self.assertEqual(stats["skip_reasons"].get("unknown_type"), 1)

    def test_broken_columns_skipped(self):
        path = os.path.join(self.dir, "broken.csv")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(",".join(FUR_HEADER) + "\n")
            # 最后一个字段没加引号又带了逗号 -> csV 多出一列
            f.write(",,GET,,,/a,,,,,,,0.0.0.0,80,0.1,,normal,extra\n")
        rows, stats = cf.convert(path)
        self.assertEqual(rows, [])
        self.assertEqual(stats["skip_reasons"].get("broken_columns"), 1)

    def test_duplicate_and_missing_path(self):
        dup = _fur_row(method="GET", request_url="/a?x=1", type="normal")
        path = self._csv([dup, dict(dup), _fur_row(method="GET", request_url="", type="normal")])
        rows, stats = cf.convert(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(stats["skip_reasons"].get("duplicate"), 1)
        self.assertEqual(stats["skip_reasons"].get("missing_path"), 1)

    def test_body_truncated(self):
        path = self._csv([_fur_row(method="POST", request_url="/a",
                                  request_body="x" * 50, type="normal")])
        rows, _ = cf.convert(path, max_body=10)
        self.assertEqual(len(rows[0]["body"]), 10)

    def test_body_placeholder_nan_nulled(self):
        # 与训练端同口径：缺失 body 的 `nan` 不能当载荷（否则评估端多出一个
        # 训练时不存在的特征值，实测把 FUR FPR 从 0.61% 虚增到 1.63%）
        path = self._csv([
            _fur_row(method="GET", request_url="/products", request_body="  nan",
                     type="normal"),
            _fur_row(method="GET", request_url="/cart", request_body="null",
                     type="normal"),
            _fur_row(method="POST", request_url="/a", request_body="{\"a\": 1}",
                     type="normal"),
        ])
        rows, stats = cf.convert(path)
        self.assertEqual(sorted(r["body"] for r in rows), ["", "", '{"a": 1}'])
        self.assertEqual(stats["skip_reasons"].get("body_missing"), 2)


EXPLOIT_TEXT = """[
  {
    "id": "CVE-2024-0001",
    "title": "SQL Injection",
    "date": "2024-01-01",
    "type": "SQL Injection",
    "platform": "Web",
    "poc": "GET /item?id=1%27 HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n"
  }
  {
    "id": "CVE-2024-0002",
    "title": "Reflected XSS",
    "date": "2024-01-02",
    "type": "Cross-Site Scripting (XSS)",
    "platform": "Web",
    "poc": "POST /c HTTP/1.1\\r\\nHost: h\\r\\nContent-Type: x\\r\\n\\r\\nq=<script>alert(1)</script>"
  }
]"""


class ExploitConvertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, text, name="exploit_dataset.jsonl"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return path

    def test_missing_comma_block_repair(self):
        objs, counts, mode = ce._load_objects(EXPLOIT_TEXT)
        self.assertEqual(mode, "block-repair")
        self.assertEqual(len(objs), 2)
        self.assertEqual(counts["started"], 2)
        self.assertEqual(counts["closed"], 2)
        self.assertEqual(counts["bad"], 0)

    def test_valid_json_array_uses_plain_parser(self):
        text = json.dumps([{"id": "CVE-1", "platform": "Web"}])
        objs, counts, mode = ce._load_objects(text)
        self.assertEqual(mode, "json")
        self.assertEqual(len(objs), 1)
        self.assertEqual(counts["bad"], 0)

    def test_convert_splits_poc_and_labels(self):
        path = self._write(EXPLOIT_TEXT)
        rows, stats = ce.convert(path)
        self.assertEqual(len(rows), 2)
        by_type = {r["attack_type"]: r for r in rows}
        sqli = by_type["SQL Injection"]
        self.assertEqual(sqli["label"], 1)
        self.assertEqual(sqli["method"], "GET")
        self.assertEqual(sqli["path"], "/item")
        self.assertEqual(sqli["query"], "id=1%27")
        self.assertEqual(sqli["body"], "")
        xss = by_type["Cross-Site Scripting (XSS)"]
        self.assertEqual(xss["label"], 2)
        self.assertEqual(xss["method"], "POST")
        self.assertEqual(xss["body"], "q=<script>alert(1)</script>")
        self.assertEqual(stats["label_counts"], {1: 1, 2: 1})

    def test_type_mapping(self):
        self.assertEqual(ce._label_for("SQL Injection"), 1)
        self.assertEqual(ce._label_for("Cross-Site Scripting"), 2)
        self.assertEqual(ce._label_for("Command Injection"), 3)
        self.assertEqual(ce._label_for("Remote Code Execution"), 3)
        self.assertEqual(ce._label_for("Path Traversal"), 4)
        self.assertIsNone(ce._label_for("Denial of Service"))
        self.assertIsNone(ce._label_for(None))

    def test_non_web_and_non_http_dropped(self):
        path = self._write(json.dumps([
            {"id": "CVE-1", "type": "SQL Injection", "platform": "Software",
             "poc": "GET /a HTTP/1.1\r\n\r\n"},
            {"id": "CVE-2", "type": "SQL Injection", "platform": "Web",
             "poc": "wmi_exploit --cmd whoami"},
            {"id": "CVE-3", "type": "Denial of Service", "platform": "Web",
             "poc": "GET /a HTTP/1.1\r\n\r\n"},
        ]))
        rows, stats = ce.convert(path)
        self.assertEqual(rows, [])
        self.assertEqual(stats["skip_reasons"].get("non_web_platform"), 1)
        self.assertEqual(stats["skip_reasons"].get("not_http_poc"), 1)
        self.assertEqual(stats["skip_reasons"].get("no_matching_label"), 1)

    def test_duplicate_dropped(self):
        rec = {"id": "CVE-1", "type": "SQL Injection", "platform": "Web",
               "poc": "GET /a?id=1 HTTP/1.1\r\n\r\n"}
        path = self._write(json.dumps([rec, dict(rec)]))
        rows, stats = ce.convert(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(stats["skip_reasons"].get("duplicate"), 1)

    def test_invalid_escape_counted_as_bad_block(self):
        text = EXPLOIT_TEXT.replace(
            '"date": "2024-01-02"', '"date": "2024-01-02", "extra": "C:\\x"')
        objs, counts, mode = ce._load_objects(text)
        self.assertEqual(mode, "block-repair")
        self.assertEqual(len(objs), 1)          # 只有第二块坏，第一块照样能读
        self.assertEqual(counts["started"], 2)
        self.assertEqual(counts["closed"], 1)
        self.assertEqual(counts["bad"], 1)
        self.assertTrue(counts["bad_samples"])


if __name__ == "__main__":
    unittest.main()
