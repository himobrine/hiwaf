"""2026-11-16 新增语料 loader 的回归测试。

这几份语料的坑都是"静默错"或"内存炸"，必须用测试钉住：

* FUR-API：`anomaly` 是**业务异常**，不是攻击子类 —— 映射成 1 会把业务异常
  教成 SQLi；列被逗号冲散的行必须丢，不能猜。
* `sqli.csv` 是 **UTF-16**，按 UTF-8 读会得到带 NUL 的乱码；`Label=0` 是英文
  诗句，不是良性请求。
* wafamole `attacks.sql` **一行一条载荷**，不能按 `;` 再切（堆叠查询本身含 `;`）。
* waffled `.raw` 是 Python **bytes 字面量**，`\\r\\n` / `\\x00` 需要 literal_eval。
* 大语料抽样必须**与扫描顺序无关**（同一批行重排后抽到同一批）。

跑法：`py -3.10 -m unittest test_newdata_loaders -v`（在 python/ 下）
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import realdata_waf as rw   # noqa: E402

FUR_HEADER = [
    "timestamp", "agent", "method", "request_body", "request_headers",
    "request_url", "response_body", "response_headers", "response_size",
    "source_ip", "source_port", "status", "target_ip", "target_port",
    "response_time", "user_identity", "type",
]


def _fur_csv(path, rows):
    lines = [",".join(FUR_HEADER)]
    for r in rows:
        vals = []
        for k in FUR_HEADER:
            v = str(r.get(k, "")).replace('"', '""')
            vals.append(f'"{v}"' if ("," in v or '"' in v or "\n" in v) else v)
        lines.append(",".join(vals))
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + "\n")


class PayloadNormTest(unittest.TestCase):
    def test_case_and_whitespace_collapse(self):
        self.assertEqual(rw._payload_norm("  '  OR\t1=1  "), "' or 1=1")

    def test_does_not_mask_digits(self):
        # 数字掩码会把 `1=1` 和 `2=2` 合成一个模板，精确去重不该这么做
        self.assertNotEqual(rw._payload_norm("1=1"), rw._payload_norm("2=2"))


class TopKTest(unittest.TestCase):
    def _feed(self, texts, cap):
        top = rw._TopK(cap)
        for i, t in enumerate(texts):
            top.offer(t, {"i": i, "text": t})
        return top

    def test_cap_respected(self):
        top = self._feed([f"payload-{i}" for i in range(500)], 100)
        self.assertEqual(len(top.rows()), 100)

    def test_order_independent(self):
        texts = [f"payload-{i}" for i in range(400)]
        a = {r["text"] for r in self._feed(texts, 50).rows()}
        b = {r["text"] for r in self._feed(list(reversed(texts)), 50).rows()}
        self.assertEqual(a, b)

    def test_dedupes_same_norm(self):
        top = self._feed(["dup", "dup", "dup", "other"], 10)
        self.assertEqual(len(top.rows()), 2)
        self.assertEqual(top.dup, 2)

    def test_empty_norm_skipped(self):
        top = self._feed(["", "   ", "x"], 10)
        self.assertEqual(len(top.rows()), 1)

    def test_exact_mode_keeps_case_variants(self):
        # FUR 用 normalize=False：仅大小写不同的请求是两个不同请求，
        # 合并会让训练集规模与 training_keys.txt 对不上
        top = rw._TopK(10, normalize=False)
        top.offer("GET /a?x=1", {"i": 1})
        top.offer("GET /A?x=1", {"i": 2})
        self.assertEqual(len(top.rows()), 2)
        self.assertEqual(top.dup, 0)


class FurApiLoaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "train.csv")

    def tearDown(self):
        self.tmp.cleanup()

    def test_normal_kept_anomaly_dropped(self):
        _fur_csv(self.path, [
            {"method": "GET", "request_url": "/api/a?x=1", "type": "normal"},
            {"method": "POST", "request_url": "/api/b", "request_body": "a=1",
             "type": "normal"},
            {"method": "GET", "request_url": "/api/c", "type": "anomaly"},
        ])
        rows, st = rw.load_fur_api(self.path, verbose=False)
        self.assertEqual(len(rows), 2)
        self.assertEqual(st["non_normal_dropped"], 1)
        self.assertTrue(all(r["label"] == 0 for r in rows))
        self.assertEqual(st["by_type"]["anomaly"], 1)
        self.assertTrue(any(r["body"] == "a=1" for r in rows))

    def test_duplicates_removed(self):
        _fur_csv(self.path, [
            {"method": "GET", "request_url": "/api/a?x=1", "type": "normal"},
            {"method": "GET", "request_url": "/api/a?x=1", "type": "normal"},
        ])
        rows, st = rw.load_fur_api(self.path, verbose=False)
        self.assertEqual(len(rows), 1)
        self.assertEqual(st["duplicates"], 1)

    def test_missing_path_dropped(self):
        _fur_csv(self.path, [{"method": "GET", "request_url": "", "type": "normal"}])
        rows, st = rw.load_fur_api(self.path, verbose=False)
        self.assertEqual(rows, [])
        self.assertEqual(st["missing_path"], 1)

    def test_body_placeholder_nan_becomes_empty(self):
        # 真实 CSV 里缺失 body 是字面量 `nan`（pandas 产物），当载荷会造出
        # "三字母 body 是正常" 的假特征
        _fur_csv(self.path, [
            {"method": "GET", "request_url": "/products", "request_body": "  nan",
             "type": "normal"},
            {"method": "GET", "request_url": "/cart", "request_body": "None",
             "type": "normal"},
            {"method": "POST", "request_url": "/items", "request_body": "{\"a\": 1}",
             "type": "normal"},
        ])
        rows, st = rw.load_fur_api(self.path, verbose=False)
        self.assertEqual(st["body_missing"], 2)
        self.assertEqual(st["with_body"], 1)
        self.assertEqual(sorted(r["body"] for r in rows), ["", "", '{"a": 1}'])


class WafamoleLoaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "attacks.sql")

    def tearDown(self):
        self.tmp.cleanup()

    def test_line_is_payload_and_stacked_queries_kept(self):
        # 堆叠查询里的 `;` 不能被当成分句符，否则载荷会被切碎
        payloads = [
            "SELECT * FROM t WHERE id='1' OR '1'='1';",
            "'; DROP TABLE users; --",
            "  ",
            "' UNION SELECT NULL--",
        ]
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(payloads) + "\n")
        rows, st = rw.load_wafamole(self.path, verbose=False)
        self.assertEqual(len(rows), 3)
        self.assertEqual(st["lines"], 3)
        self.assertTrue(all(r["label"] == 1 for r in rows))
        joined = " ".join(r["query"] for r in rows)
        self.assertIn("DROP TABLE users", joined)

    def test_cap_smaller_than_input(self):
        with open(self.path, "w", encoding="utf-8") as f:
            for i in range(300):
                f.write(f"SELECT {i} FROM t WHERE a={i} OR 1=1\n")
        rows, st = rw.load_wafamole(self.path, max_rows=40, verbose=False)
        self.assertEqual(len(rows), 40)
        self.assertEqual(st["cap"], 40)


class Sqliv5LoaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.json = os.path.join(self.tmp.name, "SQLiV5.json")
        self.csv = os.path.join(self.tmp.name, "sqli.csv")

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_sql_excluded(self):
        with open(self.json, "w", encoding="utf-8") as f:
            f.write("""[
              {"pattern": "' OR 1=1 --", "type": "sqli"},
              {"pattern": "SELECT * FROM users", "type": "valid"},
              {"pattern": "' UNION SELECT NULL--", "type": "sqli"}
            ]""")
        rows, st = rw.load_sqliv5(self.json, self.csv, verbose=False)
        self.assertEqual(len(rows), 2)
        self.assertEqual(st["by_type"]["valid"], 1)
        self.assertTrue(all(r["label"] == 1 for r in rows))

    def test_utf16_csv_read_and_short_dropped(self):
        # sqli.csv 真实文件是 UTF-16（带 BOM），Label=0 是英文诗句
        text = ("Sentence,Label\n"
                "' OR 1=1 --,1\n"
                "a,1\n"
                "Add plain text Ne te quaesiveris extra,0\n")
        with open(self.csv, "w", encoding="utf-16", newline="") as f:
            f.write(text)
        with open(self.json, "w", encoding="utf-8") as f:
            f.write("[]")
        rows, st = rw.load_sqliv5(self.json, self.csv, verbose=False)
        self.assertEqual(len(rows), 1)          # 只留 `' OR 1=1 --`
        self.assertEqual(st["csv_sqli"], 1)     # 单字符 `a` 被丢
        self.assertEqual(st["csv_short_dropped"], 1)
        self.assertEqual(st["csv_benign_dropped"], 1)


class WafriftLoaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "sql"))
        os.makedirs(os.path.join(self.root, "nosql"))

    def tearDown(self):
        self.tmp.cleanup()

    def _toml(self, sub, name, body):
        with open(os.path.join(self.root, sub, name), "w", encoding="utf-8") as f:
            f.write("schema = 1\n" + body)

    def test_class_mapping_and_raw_body(self):
        self._toml("sql", "union.toml",
                   '[[case]]\nid = "u1"\nclass = "sql"\npayload = "\' UNION SELECT NULL--"\n\n'
                   '[[case]]\nid = "u2"\nclass = "sql"\nmode = "raw_body"\n'
                   'payload = "<map><command>id</command></map>"\n')
        self._toml("nosql", "mongo.toml",
                   '[[case]]\nid = "n1"\nclass = "nosql"\npayload = "{\'$ne\': null}"\n')
        rows, st = rw.load_wafrift_corpus(self.root, verbose=False)
        self.assertEqual(len(rows), 2)
        self.assertEqual(st["unmapped_skipped"], 1)
        raw = [r for r in rows if r["method"] == "POST"]
        self.assertEqual(len(raw), 1)
        self.assertIn("<command>", raw[0]["body"])
        self.assertTrue(all(r["label"] == 1 for r in rows))


class WaffledLoaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_bytes_literal_parse_and_labels(self):
        blocks = [
            r"""b'''POST /json HTTP/1.1\r\nHost: h\r\nContent-Length: 25\r\n\r\n{"f":"' and 1=1 --"}'''""",
            r"""b'''POST /json HTTP/1.1\r\nHost: h\r\nContent-Length: 52\r\n\r\n{"f":"<script>alert(1)</script>"}'''""",
            r"""b'''POST /spring/json HTTP/1.1\r\nHost: h\r\n\r\n{"f"\x00:"<script>alert(1)</script>"}'''""",
        ]
        with open(os.path.join(self.root, "json_requests.raw"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(blocks) + "\n")
        rows, st = rw.load_waffled_bypass(self.root, verbose=False)
        self.assertEqual(st["blocks"], 3)
        self.assertEqual(st["bad_blocks"], 0)
        labels = sorted(r["label"] for r in rows)
        self.assertEqual(labels, [1, 2, 2])
        # \x00 必须被还原成真实 NUL，而不是字面量 `\x00`
        self.assertTrue(any("\x00" in r["body"] for r in rows))
        self.assertTrue(all(r["body"] for r in rows))

    def test_bad_literal_counted(self):
        with open(os.path.join(self.root, "x.raw"), "w", encoding="utf-8") as f:
            f.write("b'''POST / HTTP/1.1\\r\\n\\r\\n\\xff'''\n")
        row_ok, st = rw.load_waffled_bypass(self.root, verbose=False)
        self.assertEqual(st["blocks"], 1)
        # `\xff` 是合法的 latin-1 字面量；解析应成功而不是炸掉
        self.assertEqual(st["bad_blocks"], 0)


class ExcludedTest(unittest.TestCase):
    def test_sane_sql_is_excluded(self):
        self.assertIn("wafamole_dataset/sane.sql", rw.EXCLUDED)

    def test_commonhuman_registered(self):
        self.assertIn("commonhuman-payloads-main/", rw.EXCLUDED)

    def test_fur_test_is_eval_only(self):
        self.assertIn("FUR-API/test.csv", rw.EXCLUDED)


class CmdiWrapTest(unittest.TestCase):
    """cmdi 形态对齐：只改外壳，不改载荷，不碰评估集路径。"""

    def _row(self, body="cmd=whoami", query="", label=3):
        return rw._mk("POST", "/a", body, label, "x")

    def test_json_wrap_keeps_payload_bytes(self):
        rows = rw.wrap_cmdi_rows([self._row()], per_row=3)
        self.assertTrue(rows)
        self.assertTrue(all(r["label"] == 3 for r in rows))
        self.assertTrue(all(r["source"] == rw.CMDI_WRAP_SOURCE for r in rows))
        self.assertTrue(all("whoami" in r["body"] for r in rows))

    def test_never_uses_eval_paths(self):
        # 评估集路径绝不能出现在训练外壳里（特征含 path 形态，等于泄漏）
        eval_paths = ("/api/jsonws/invoke", "/mgmt/tm/util/bash", "/webadmin/",
                      "/struts2-showcase/", "/api/v4/ci/lint")
        rows = rw.wrap_cmdi_rows([self._row("cmd=id") for _ in range(30)], per_row=40)
        for r in rows:
            for p in eval_paths:
                self.assertNotIn(p, r["path"])

    def test_payload_extracted_from_query(self):
        row = rw._mk("GET", "/s?exec=cat%20/etc/passwd&x=1", "", 3, "x")
        rows = rw.wrap_cmdi_rows([row], per_row=2)
        self.assertTrue(rows)
        for r in rows:
            from urllib.parse import unquote
            self.assertIn("etc/passwd", unquote(r["body"]))

    def test_short_or_empty_payload_skipped(self):
        rows = rw.wrap_cmdi_rows([self._row(body=""), self._row(body="a")], per_row=3)
        self.assertEqual(rows, [])

    def test_wrap_is_deterministic_and_deduped(self):
        a = rw.wrap_cmdi_rows([self._row()], per_row=5)
        b = rw.wrap_cmdi_rows([self._row()], per_row=5)
        self.assertEqual([rw.req_text(r) for r in a], [rw.req_text(r) for r in b])
        self.assertEqual(len({rw.req_text(r) for r in a}), len(a))

    def test_per_row_zero_disables(self):
        self.assertEqual(rw.wrap_cmdi_rows([self._row()], per_row=0), [])


if __name__ == "__main__":
    unittest.main()
