"""事件筛选（规则命中 / 人工结论 / 分数区间 / 时间）纯 SQL 语义测试。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db
from . import datasets_events as de


class EventFilterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "UPLOADS", root / "uploads"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self._seed()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _event(self, i, *, action="block", method="GET", path="/a",
               query="id=1", score=0.9, attack_type="sqli", status=200,
               ip_list=None, ts=1_700_000_000_000):
        eid = db.execute(
            "INSERT INTO events(ts, ingest_ts, src_ip, method, path, query, "
            "body_len, status, action, supervised_score, attack_type, ip_list) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts + i, ts + i, "10.0.0.1", method, path, query, 0, status,
             action, score, attack_type, ip_list))
        return int(eid)

    def _seed(self):
        # 1) 有规则命中 + 人工确认攻击
        self.e1 = self._event(1, path="/a", action="block")
        db.execute("INSERT INTO event_rules(event_id, rule, name, action) "
                   "VALUES(?,?,?,?)", (self.e1, "r_sqli", "sqlmap", "block"))
        db.execute("INSERT INTO feedback(event_id, verdict, actor, ts) "
                   "VALUES(?,?,?,?)", (self.e1, "confirmed_attack", "t", 1))
        # 2) 有规则命中（alert）但无反馈
        self.e2 = self._event(2, path="/b", action="alert", score=0.2,
                              attack_type="xss", status=404, ip_list="blacklist")
        db.execute("INSERT INTO event_rules(event_id, rule, name, action) "
                   "VALUES(?,?,?,?)", (self.e2, "r_xss", "xss", "alert"))
        # 3) 没有任何规则命中，有误报反馈
        self.e3 = self._event(3, path="/c", action="allow", score=0.01,
                              attack_type="normal", method="POST", status=200)
        db.execute("INSERT INTO feedback(event_id, verdict, actor, ts) "
                   "VALUES(?,?,?,?)", (self.e3, "false_positive", "t", 2))

    # ---- 基础 ----------------------------------------------------------
    def test_all_and_unknown_key(self):
        self.assertEqual(de.count_events({}), 3)
        self.assertEqual(de.count_events({"action": "block"}), 1)
        with self.assertRaises(ValueError):
            de.count_events({"no_such_filter": 1})

    # ---- 规则命中 ------------------------------------------------------
    def test_rule_and_rule_action(self):
        self.assertEqual(de.count_events({"rule": "r_sqli"}), 1)
        self.assertEqual(de.count_events({"rule": "r_xss"}), 1)
        self.assertEqual(de.count_events({"rule": "r_xss", "rule_action": "alert"}), 1)
        self.assertEqual(de.count_events({"rule": "r_xss", "rule_action": "block"}), 0)

    def test_has_rule(self):
        self.assertEqual(de.count_events({"has_rule": True}), 2)
        self.assertEqual(de.count_events({"has_rule": False}), 1)

    # ---- 人工结论 ------------------------------------------------------
    def test_verdict_any_none_exact(self):
        self.assertEqual(de.count_events({"verdict": "any"}), 2)
        self.assertEqual(de.count_events({"verdict": "none"}), 1)
        self.assertEqual(de.count_events({"verdict": "confirmed_attack"}), 1)
        self.assertEqual(de.count_events({"verdict": "false_positive"}), 1)

    # ---- 其它条件 ------------------------------------------------------
    def test_score_method_status_ip_list(self):
        self.assertEqual(de.count_events({"max_score": 0.5}), 2)
        self.assertEqual(de.count_events({"min_score": 0.5}), 1)
        self.assertEqual(de.count_events({"method": "post"}), 1)
        self.assertEqual(de.count_events({"status": 404}), 1)
        self.assertEqual(de.count_events({"ip_list": "blacklist"}), 1)

    # ---- id 选择 / 规则下拉 -------------------------------------------
    def test_select_ids_and_facets(self):
        ids, truncated = de.select_ids({"has_rule": True}, limit=10)
        self.assertEqual(len(ids), 2)
        self.assertFalse(truncated)
        self.assertEqual(ids[0], self.e2)          # ts 倒序
        ids2, truncated2 = de.select_ids({"has_rule": True}, limit=1)
        self.assertEqual(len(ids2), 1)
        self.assertTrue(truncated2)
        with self.assertRaises(ValueError):
            de.select_ids({})

        facets = de.rule_facets()
        by = {r["rule"]: r for r in facets}
        self.assertEqual(by["r_sqli"]["hits"], 1)
        self.assertEqual(by["r_sqli"]["block_hits"], 1)
        self.assertEqual(by["r_xss"]["name"], "xss")


if __name__ == "__main__":
    unittest.main()