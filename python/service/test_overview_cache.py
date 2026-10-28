"""总览聚合：SQL 分桶 + 短 TTL 缓存（临时库）。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db
from . import app as app_mod


class OverviewAggregateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "OVERVIEW_CACHE_SEC", 60),
        ]
        for p in self.patches:
            p.start()
        db.init()
        app_mod._overview_cache_clear()
        self.since = db.now_ms() - 3600_000
        self._event(0.05, action="allow")
        self._event(0.35, action="alert")
        self._event(0.99, action="block")
        self._event(None, action="allow")

    def tearDown(self):
        app_mod._overview_cache_clear()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _event(self, score, action="allow"):
        db.execute(
            """INSERT INTO events(ts, ingest_ts, src_ip, action, supervised_score,
                                  supervised_flagged, dur_ms)
               VALUES(?,?,?,?,?,?,?)""",
            (db.now_ms(), db.now_ms(), "10.0.0.1", action, score,
             1 if (score or 0) >= 0.7 else 0, 12.5),
        )

    def test_histogram_is_bucketed_in_sql(self):
        agg = app_mod._overview_event_summary(self.since, 24)
        # 0.05→0，0.35→3，0.99→9；score 为 NULL 的不进直方图。
        self.assertEqual(agg["score_histogram"],
                         [1, 0, 0, 1, 0, 0, 0, 0, 0, 1])
        self.assertEqual(agg["totals"]["n"], 4)
        self.assertEqual(agg["totals"]["blocks"], 1)
        self.assertEqual(agg["totals"]["sup_flagged"], 1)

    def test_cache_hit_returns_previous_snapshot(self):
        first = app_mod._overview_event_summary(self.since, 24)
        self._event(0.5)
        second = app_mod._overview_event_summary(self.since, 24)
        self.assertEqual(first["totals"]["n"], second["totals"]["n"])

        app_mod._overview_cache_clear()
        third = app_mod._overview_event_summary(self.since, 24)
        self.assertEqual(third["totals"]["n"], second["totals"]["n"] + 1)

    def test_cache_keyed_by_window(self):
        a = app_mod._overview_event_summary(self.since, 24)
        b = app_mod._overview_event_summary(self.since, 168)
        self.assertEqual(a["totals"]["n"], b["totals"]["n"])

    def test_cache_can_be_disabled(self):
        with mock.patch.object(config, "OVERVIEW_CACHE_SEC", 0):
            app_mod._overview_event_summary(self.since, 24)
            self._event(0.6)
            fresh = app_mod._overview_event_summary(self.since, 24)
        self.assertEqual(fresh["totals"]["n"], 5)

    def test_scores_out_of_range_are_clamped(self):
        db.execute(
            """INSERT INTO events(ts, ingest_ts, src_ip, action, supervised_score)
               VALUES(?,?,?,?,?)""",
            (db.now_ms(), db.now_ms(), "10.0.0.2", "block", 1.7),
        )
        db.execute(
            """INSERT INTO events(ts, ingest_ts, src_ip, action, supervised_score)
               VALUES(?,?,?,?,?)""",
            (db.now_ms(), db.now_ms(), "10.0.0.3", "allow", -0.4),
        )
        app_mod._overview_cache_clear()
        hist = app_mod._overview_event_summary(self.since, 24)["score_histogram"]
        self.assertEqual(hist[9], 2)   # 0.99 + 1.7
        self.assertEqual(hist[0], 2)   # 0.05 + (-0.4)


if __name__ == "__main__":
    unittest.main()
