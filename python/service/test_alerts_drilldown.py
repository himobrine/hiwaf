"""告警聚合下钻测试（临时 DB，不碰真实 console.db）。

覆盖：精确匹配（子串不混入）、桶边界左闭右开、NULL method/path、分页、
rule_hits 解析、参数校验。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import alerts, config, db

BUCKET_MIN = 10
BUCKET_MS = BUCKET_MIN * 60_000
BUCKET = 100  # 窗口 [60_000_000, 60_600_000)
FROM_TS = BUCKET * BUCKET_MS


class AlertsDrilldownTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
        ]
        for p in self.patches:
            p.start()
        db.init()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _add(self, ts: int, *, src_ip: str = "1.1.1.1", action: str = "block",
             method: str | None = "POST", path: str | None = "/api/user",
             rule_hits: str | None = None, score: float = 0.9) -> int:
        return db.execute(
            "INSERT INTO events(ts, ingest_ts, src_ip, action, method, path, "
            "supervised_score, rule_hits_json) VALUES(?,?,?,?,?,?,?,?)",
            (ts, ts, src_ip, action, method, path, score, rule_hits),
        )

    def test_exact_match_does_not_mix_substring_paths(self):
        a = self._add(FROM_TS + 10_000, path="/api/user")
        self._add(FROM_TS + 20_000, path="/api/users")  # 子串，不应混入
        c = self._add(FROM_TS + 30_000, path="/api/user")
        r = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                bucket_min=BUCKET_MIN, method="POST", path="/api/user")
        self.assertEqual(r["total"], 2)
        self.assertEqual({it["id"] for it in r["items"]}, {a, c})
        # 反向：目标换成 /api/users 只应看到它自己
        r2 = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                 bucket_min=BUCKET_MIN, method="POST", path="/api/users")
        self.assertEqual(r2["total"], 1)
        self.assertEqual(r2["items"][0]["path"], "/api/users")

    def test_action_and_src_ip_are_exact(self):
        good = self._add(FROM_TS + 1_000)
        self._add(FROM_TS + 2_000, action="alert")  # 动作不同
        self._add(FROM_TS + 3_000, src_ip="2.2.2.2")  # IP 不同
        r = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                bucket_min=BUCKET_MIN, method="POST", path="/api/user")
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["id"], good)

    def test_bucket_boundary_left_closed_right_open(self):
        inside_left = self._add(FROM_TS)
        inside_right = self._add(FROM_TS + BUCKET_MS - 1)
        self._add(FROM_TS - 1)  # 上一桶
        self._add(FROM_TS + BUCKET_MS)  # 下一桶
        r = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                bucket_min=BUCKET_MIN, method="POST", path="/api/user")
        self.assertEqual(r["total"], 2)
        self.assertEqual({it["id"] for it in r["items"]}, {inside_left, inside_right})
        self.assertEqual(r["from_ts"], FROM_TS)
        self.assertEqual(r["to_ts"], FROM_TS + BUCKET_MS)
        # 上一桶的下钻能且只能看到 FROM_TS-1 那条
        r_prev = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET - 1,
                                     bucket_min=BUCKET_MIN, method="POST", path="/api/user")
        self.assertEqual(r_prev["total"], 1)
        self.assertEqual(r_prev["items"][0]["ts"], FROM_TS - 1)

    def test_null_method_path_group(self):
        # 聚合把 NULL 作为独立分组；下钻用空串归一，两边必须对得上。
        row = self._add(FROM_TS + 5_000, method=None, path=None)
        r = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                bucket_min=BUCKET_MIN, method="", path="")
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["id"], row)
        r2 = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                 bucket_min=BUCKET_MIN, method=None, path=None)
        self.assertEqual(r2["total"], 1)
        # 别的 path 不应命中 NULL 组
        r3 = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                 bucket_min=BUCKET_MIN, method="POST", path="/api/user")
        self.assertEqual(r3["total"], 0)

    def test_pagination(self):
        ids = [self._add(FROM_TS + 1_000 * i) for i in range(1, 6)]  # 共 5 条
        r = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                bucket_min=BUCKET_MIN, method="POST", path="/api/user",
                                limit=2, offset=0)
        self.assertEqual(r["total"], 5)
        self.assertEqual(len(r["items"]), 2)
        self.assertEqual([it["id"] for it in r["items"]], list(reversed(ids))[:2])  # ts DESC
        r2 = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                 bucket_min=BUCKET_MIN, method="POST", path="/api/user",
                                 limit=2, offset=4)
        self.assertEqual(r2["total"], 5)
        self.assertEqual(len(r2["items"]), 1)
        self.assertEqual(r2["items"][0]["id"], ids[0])

    def test_rule_hits_parsed(self):
        hits = [{"rule": "942100", "action": "block"}]
        self._add(FROM_TS + 1_000, rule_hits=json.dumps(hits))
        r = alerts.group_events(src_ip="1.1.1.1", action="block", bucket=BUCKET,
                                bucket_min=BUCKET_MIN, method="POST", path="/api/user")
        it = r["items"][0]
        self.assertEqual(it["rule_hits"], hits)
        self.assertNotIn("rule_hits_json", it)

    def test_window_validation(self):
        with self.assertRaises(ValueError):
            alerts.window(-1, 10)
        with self.assertRaises(ValueError):
            alerts.window(1, 0)
        with self.assertRaises(ValueError):
            alerts.window(1, 1441)


if __name__ == "__main__":
    unittest.main()
