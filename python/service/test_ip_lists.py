"""IP 黑白名单：规范化 / 导入导出 / 产物 / 自动拉黑。"""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, ip_lists as ip


def _event(src_ip, *, action="block", rule_hits="[]", ts=None, ip_list=None):
    ts = int(ts if ts is not None else db.now_ms())
    db.execute(
        "INSERT INTO events(ts, ingest_ts, method, path, query, action, src_ip, "
        "rule_hits_json, ip_list) VALUES(?,?,?,?,?,?,?,?,?)",
        (ts, ts + 1, "GET", "/x", "id=1", action, src_ip, rule_hits, ip_list))


class IpListsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "IP_LISTS", root / "ip_lists.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _artifact(self):
        return json.loads(Path(config.IP_LISTS).read_text(encoding="utf-8"))

    # ------------------------------------------------------------ 规范化
    def test_normalize(self):
        self.assertEqual(ip.normalize("1.2.3.4"), "1.2.3.4")
        self.assertEqual(ip.normalize("1.2.3.4/32"), "1.2.3.4")
        self.assertEqual(ip.normalize("192.168.1.9/24"), "192.168.1.0/24")
        self.assertEqual(ip.normalize("2001:0db8::1"), "2001:db8::1")
        with self.assertRaises(ValueError):
            ip.normalize("not-an-ip")
        with self.assertRaises(ValueError):
            ip.normalize("")

    # ------------------------------------------------------------ CRUD / 产物
    def test_add_toggle_delete_and_artifact(self):
        black = ip.add("1.2.3.4", "black", reason="scanner", actor="tester")
        white = ip.add("10.0.0.0/8", "white", reason="lan", actor="tester")
        self.assertTrue(black["enabled"])
        doc = self._artifact()
        self.assertEqual(doc["blacklist"], ["1.2.3.4"])
        self.assertEqual(doc["whitelist"], ["10.0.0.0/8"])
        self.assertEqual(doc["counts"], {"white": 1, "black": 1})

        ip.set_enabled(black["id"], False, actor="tester")
        self.assertEqual(self._artifact()["blacklist"], [])
        self.assertEqual(ip.counts(), {"black": 0, "white": 1, "total": 1})

        ip.delete(white["id"], actor="tester")
        self.assertEqual(self._artifact()["whitelist"], [])

    def test_bulk_delete(self):
        a = ip.add("1.1.1.1", "black", actor="t")
        b = ip.add("2.2.2.2", "black", actor="t")
        out = ip.bulk_delete([a["id"], b["id"], 9999], actor="t")
        self.assertEqual(len(out["deleted"]), 2)
        self.assertEqual(out["missing"], [9999])
        self.assertEqual(self._artifact()["blacklist"], [])

    def test_duplicate_upsert(self):
        ip.add("1.1.1.1", "black", reason="old", actor="t")
        row = ip.add("1.1.1.1", "black", reason="new", actor="t")
        self.assertEqual(row["reason"], "new")
        self.assertEqual(len(ip.list_items(kind="black")), 1)

    # ------------------------------------------------------------ 导入导出
    def test_import_lines_csv_json(self):
        out = ip.import_text("1.1.1.1,扫描器\n2.2.2.0/24,内网段\nbad-ip,x",
                             "black", actor="t")
        self.assertEqual(out["added"], 2)
        self.assertEqual(len(out["skipped"]), 1)

        csv_text = "ip,kind,reason\n3.3.3.3,white,合作方\n4.4.4.4,,手工\n"
        out = ip.import_text(csv_text, "black", actor="t")
        self.assertEqual(out["added"], 2)
        self.assertTrue(any(r["kind"] == "white" for r in ip.list_items()))

        js = json.dumps([{"ip": "5.5.5.5", "reason": "json"},
                         {"ip": "6.6.6.6", "kind": "white"}])
        out = ip.import_text(js, "black", actor="t")
        self.assertEqual(out["added"], 2)
        self.assertEqual(len([r for r in ip.list_items() if r["kind"] == "white"]), 2)

    def test_export_csv_json(self):
        ip.add("1.2.3.4", "black", reason="r", note="n", actor="t")
        csv_text = ip.export_csv("black")
        self.assertTrue(csv_text.startswith("ip,kind,source,reason,note"))
        self.assertIn("1.2.3.4,black,manual,r,n", csv_text)
        doc = json.loads(ip.export_json("black"))
        self.assertEqual(doc["items"][0]["ip"], "1.2.3.4")

    # ------------------------------------------------------------ 自动拉黑
    def test_auto_scan_counts_blocks_and_rule_alerts_only(self):
        ip.update_auto_settings({"threshold": 3, "window_min": 10,
                                 "duration_hours": 24}, "t")
        # 3 次 block（无规则命中也算）→ 拉黑
        for _ in range(3):
            _event("1.1.1.1", action="block")
        # 3 次 alert 但没有规则命中（只有模型）→ 不拉黑
        for _ in range(3):
            _event("2.2.2.2", action="alert", rule_hits="[]")
        # 3 次 alert 且有规则命中 → 拉黑
        for _ in range(3):
            _event("3.3.3.3", action="alert",
                   rule_hits='[{"rule":"r1","action":"alert"}]')
        # 白名单 IP 即使刷再多也不拉黑
        ip.add("4.4.4.4", "white", actor="t")
        for _ in range(5):
            _event("4.4.4.4", action="block")
        # 已经手工拉黑：保留手工来源/原因
        ip.add("5.5.5.5", "black", reason="manual-keep", actor="t")
        for _ in range(5):
            _event("5.5.5.5", action="block")

        out = ip.auto_scan(actor="t")
        ips = {a["ip"] for a in out["added"]}
        self.assertEqual(ips, {"1.1.1.1", "3.3.3.3"})
        black = {r["ip"]: r for r in ip.list_items(kind="black")}
        self.assertEqual(black["5.5.5.5"]["reason"], "manual-keep")
        self.assertEqual(black["1.1.1.1"]["source"], "auto")
        self.assertIsNotNone(black["1.1.1.1"]["expires_at"])
        self.assertNotIn("2.2.2.2", black)
        self.assertNotIn("4.4.4.4", black)
        art = self._artifact()
        self.assertEqual(sorted(art["blacklist"]),
                         ["1.1.1.1", "3.3.3.3", "5.5.5.5"])

    def test_auto_scan_can_be_disabled(self):
        ip.update_auto_settings({"enabled": False}, "t")
        for _ in range(50):
            _event("9.9.9.9", action="block")
        out = ip.auto_scan(actor="t")
        self.assertFalse(out["enabled"])
        self.assertEqual(out["added"], [])

    def test_expired_hidden_from_artifact_and_cleaned(self):
        now = db.now_ms()
        ip.add("7.7.7.7", "black", expires_at=now - 1, actor="t")
        self.assertEqual(self._artifact()["blacklist"], [])
        out = ip.cleanup_expired(actor="t")
        self.assertEqual(out["expired"], 1)
        self.assertEqual(ip.list_items(kind="black"), [])

    def test_settings_validation(self):
        with self.assertRaises(ValueError):
            ip.update_auto_settings({"threshold": 0}, "t")
        with self.assertRaises(ValueError):
            ip.update_auto_settings({"window_min": 0}, "t")
        with self.assertRaises(ValueError):
            ip.update_auto_settings({"nope": 1}, "t")
        out = ip.update_auto_settings({"enabled": False, "threshold": 5}, "t")
        self.assertFalse(out["enabled"])
        self.assertEqual(out["threshold"], 5)


if __name__ == "__main__":
    unittest.main()