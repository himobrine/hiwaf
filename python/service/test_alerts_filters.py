"""告警列表的服务端筛选/搜索 + 攻击链筛选。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import alerts, config, correlate, db


def _event(ts, *, src_ip="1.1.1.1", action="block", method="GET", path="/a",
           attack_type="sqli", host="h1", ua="curl/8", score=0.9,
           rule_hits=None, status=200):
    return db.execute(
        "INSERT INTO events(ts, ingest_ts, src_ip, action, method, path, "
        "attack_type, host, ua, supervised_score, rule_hits_json, status) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, ts, src_ip, action, method, path, attack_type, host, ua, score,
         json.dumps(rule_hits) if rule_hits is not None else None, status))


class AlertFilterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.now = db.now_ms()
        t = self.now - 5000
        self.a1 = _event(t, src_ip="1.1.1.1", path="/a", attack_type="sqli",
                         ua="sqlmap/1", score=0.99,
                         rule_hits=[{"rule": "r1", "action": "block"}])
        self.a2 = _event(t + 1000, src_ip="1.1.1.1", path="/a",
                         attack_type="sqli", score=0.8,
                         rule_hits=[{"rule": "r1", "action": "block"}])
        self.b = _event(t + 2000, src_ip="2.2.2.2", action="alert",
                        method="POST", path="/b", attack_type="xss",
                        host="h2", ua="chrome", score=0.6)
        self.c = _event(t + 3000, src_ip="3.3.3.3", path="/c",
                        attack_type="traversal", score=0.95,
                        rule_hits=[{"rule": "r2", "action": "block"}])

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _groups(self, **kw):
        kw.setdefault("since", self.now - 60_000)
        kw.setdefault("until", self.now + 60_000)
        return alerts.list_groups(bucket_min=10, **kw)["items"]

    def test_default_groups(self):
        items = self._groups()
        self.assertEqual(len(items), 3)
        by_ip = {r["src_ip"]: r for r in items}
        self.assertEqual(by_ip["1.1.1.1"]["n"], 2)
        self.assertEqual(by_ip["1.1.1.1"]["severity"], "P1")
        self.assertEqual(by_ip["2.2.2.2"]["severity"], "P2")

    def test_filters(self):
        self.assertEqual([r["src_ip"] for r in self._groups(src_ip="1.1.1.1")],
                         ["1.1.1.1"])
        self.assertEqual([r["src_ip"] for r in self._groups(action="alert")],
                         ["2.2.2.2"])
        self.assertEqual([r["src_ip"] for r in self._groups(attack_type="sqli")],
                         ["1.1.1.1"])
        self.assertEqual([r["src_ip"] for r in self._groups(method="POST")],
                         ["2.2.2.2"])
        self.assertEqual(sorted(r["src_ip"] for r in self._groups(host="h1")),
                         ["1.1.1.1", "3.3.3.3"])
        self.assertEqual(sorted(r["src_ip"] for r in self._groups(min_score=0.9)),
                         ["1.1.1.1", "3.3.3.3"])

    def test_search_covers_ua_rule_and_path(self):
        self.assertEqual([r["src_ip"] for r in self._groups(q="sqlmap")],
                         ["1.1.1.1"])
        self.assertEqual([r["src_ip"] for r in self._groups(q="r2")],
                         ["3.3.3.3"])
        self.assertEqual([r["src_ip"] for r in self._groups(q="/b")],
                         ["2.2.2.2"])
        self.assertEqual([r["src_ip"] for r in self._groups(rule="r1")],
                         ["1.1.1.1"])

    def test_dedup_mode_with_filter(self):
        out = alerts.list_groups(self.now - 60_000, self.now + 60_000,
                                 bucket_min=10, dedup=True)
        self.assertEqual(len(out["items"]), 3)
        one = alerts.list_groups(self.now - 60_000, self.now + 60_000,
                                 bucket_min=10, dedup=True, attack_type="xss")
        self.assertEqual([r["src_ip"] for r in one["items"]], ["2.2.2.2"])
        self.assertEqual(one["items"][0]["path_count"], 1)

    def test_truncated_and_time_range(self):
        out = alerts.list_groups(self.now - 60_000, self.now + 60_000,
                                 bucket_min=10, limit=1)
        self.assertTrue(out["truncated"])
        self.assertEqual(len(out["items"]), 1)
        # 只看 b/c（a1/a2 更早）
        items = self._groups(since=self.now - 3500)
        self.assertEqual(sorted(r["src_ip"] for r in items), ["2.2.2.2", "3.3.3.3"])

    # ------------------------------------------------------------ 攻击链
    def test_chain_filters(self):
        t = self.now - 10_000
        _event(t, src_ip="4.4.4.4", ua="ua-a", path="/p1",
               attack_type="sqli", score=0.99)
        _event(t + 1000, src_ip="4.4.4.4", ua="ua-a", path="/p2",
               attack_type="sqli", score=0.95)
        _event(t + 2000, src_ip="5.5.5.5", ua="ua-b", path="/x",
               attack_type="xss", score=0.55)

        def chains(**kw):
            kw.setdefault("window_hours", 1)
            kw.setdefault("min_events", 1)
            kw.setdefault("only_suspicious", False)
            kw.setdefault("include_noise", True)
            return correlate.collect(**kw)

        self.assertEqual({c["src_ip"] for c in chains()["items"]},
                         {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"})
        self.assertEqual([c["src_ip"] for c in chains(src_ip="4.4.4.4")["items"]],
                         ["4.4.4.4"])
        self.assertEqual({c["src_ip"] for c in chains(q="ua-b")["items"]},
                         {"5.5.5.5"})
        self.assertEqual({c["src_ip"] for c in chains(attack_type="xss")["items"]},
                         {"2.2.2.2", "5.5.5.5"})
        self.assertEqual({c["src_ip"] for c in chains(min_score=0.9)["items"]},
                         {"1.1.1.1", "3.3.3.3", "4.4.4.4"})
        only_late = chains(from_ts=t + 1500)
        self.assertNotIn("4.4.4.4", {c["src_ip"] for c in only_late["items"]})

    def test_chain_keeps_probe_events_when_unfiltered(self):
        """默认不带筛选时，链的 n 要含探测/放行事件；按类型筛选后才只看该类型。"""
        t = self.now - 10_000
        _event(t, src_ip="6.6.6.6", ua="ua-c", path="/admin", action="allow",
               attack_type=None, status=404, score=0.1)
        _event(t + 1000, src_ip="6.6.6.6", ua="ua-c", path="/admin",
               attack_type="sqli", status=403, score=0.99)

        def chains(**kw):
            kw.setdefault("window_hours", 1)
            kw.setdefault("min_events", 1)
            kw.setdefault("only_suspicious", False)
            kw.setdefault("include_noise", True)
            return [c for c in correlate.collect(**kw)["items"]
                    if c["src_ip"] == "6.6.6.6"]

        self.assertEqual(len(chains()), 1)
        self.assertEqual(chains()[0]["n"], 2)
        filtered = chains(attack_type="sqli")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["n"], 1)


if __name__ == "__main__":
    unittest.main()