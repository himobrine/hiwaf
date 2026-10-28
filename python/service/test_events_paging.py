"""事件列表 keyset 分页 + 复合索引（临时库）。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db
from . import app as app_mod

USER = {"id": 1, "username": "tester", "role": "admin"}


def _list(**kw):
    args = dict(limit=50, offset=0, action=None, src_ip=None, path=None,
                min_score=None, from_ts=None, to_ts=None, q=None,
                rule_testing=None, cursor_ts=None, cursor_id=None,
                with_total=True, user=USER)
    args.update(kw)
    return app_mod.list_events(**args)


class EventsPagingTest(unittest.TestCase):
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
        self.base = db.now_ms() - 10_000
        # 5 条事件，其中两条同一毫秒：验证 (ts,id) 游标在同毫秒内也稳定。
        for i, ts in enumerate([self.base, self.base + 1000,
                                self.base + 2000, self.base + 2000,
                                self.base + 3000]):
            db.execute(
                """INSERT INTO events(ts, ingest_ts, src_ip, action, method, path)
                   VALUES(?,?,?,?,?,?)""",
                (ts, ts, "10.0.0.1", "block" if i % 2 else "allow",
                 "GET", f"/p{i}"),
            )

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_offset_first_page_reports_total(self):
        r = _list(limit=2)
        self.assertEqual(r["total"], 5)
        self.assertEqual(len(r["items"]), 2)
        self.assertTrue(r["has_more"])
        self.assertIsNotNone(r["next_cursor"])
        self.assertEqual(r["items"][0]["path"], "/p4")

    def test_keyset_walks_all_pages_without_dup_or_gap(self):
        seen = []
        cursor = None
        for _ in range(10):
            kw = dict(limit=2, with_total=True) if cursor is None else dict(
                limit=2, with_total=False,
                cursor_ts=cursor["ts"], cursor_id=cursor["id"])
            r = _list(**kw)
            seen += [it["id"] for it in r["items"]]
            if not r["has_more"]:
                break
            cursor = r["next_cursor"]
        self.assertEqual(len(seen), 5)
        self.assertEqual(len(set(seen)), 5)

    def test_with_total_false_skips_count(self):
        r = _list(limit=2, with_total=False)
        self.assertIsNone(r["total"])
        self.assertEqual(r["offset"], 0)

    def test_cursor_ignores_offset(self):
        first = _list(limit=2)
        cursor = first["next_cursor"]
        r = _list(limit=2, offset=4, cursor_ts=cursor["ts"], cursor_id=cursor["id"])
        self.assertEqual(r["offset"], 0)
        self.assertNotIn(first["items"][0]["id"], [it["id"] for it in r["items"]])

    def test_action_filter_uses_composite_index(self):
        plan = db.rows(
            "EXPLAIN QUERY PLAN SELECT id FROM events "
            "WHERE action=? AND ts>=? ORDER BY ts DESC LIMIT 10",
            ("block", self.base),
        )
        text = " ".join(str(r["detail"]) for r in plan)
        self.assertIn("ix_events_action_ts", text)

    def test_indexes_replaced(self):
        names = {r["name"] for r in db.rows("PRAGMA index_list(events)")}
        self.assertIn("ix_events_action_ts", names)
        self.assertIn("ix_events_ip_ts", names)
        self.assertIn("ix_events_ts", names)
        self.assertNotIn("ix_events_action", names)
        self.assertNotIn("ix_events_ip", names)

    def test_src_ip_range_uses_composite_index(self):
        plan = db.rows(
            "EXPLAIN QUERY PLAN SELECT id FROM events "
            "WHERE src_ip=? AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 20",
            ("10.0.0.1", self.base, self.base + 5000),
        )
        text = " ".join(str(r["detail"]) for r in plan)
        self.assertIn("ix_events_ip_ts", text)


if __name__ == "__main__":
    unittest.main()
