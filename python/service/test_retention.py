"""保留期聚合表清理测试（不触碰真实 console.db）。"""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, retention, retention_scheduler


class AggregatePruneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "RAW_DIR", root / "raw"),
            mock.patch.object(config, "RETENTION_DRY_RUN_FILE",
                              root / "logs" / "retention-dry-run.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.cutoff = db.now_ms() - 90 * 86_400_000
        old_day = time.strftime("%Y-%m-%d", time.gmtime(
            (self.cutoff - 86_400_000) / 1000.0))
        new_day = time.strftime("%Y-%m-%d", time.gmtime(
            (self.cutoff + 86_400_000) / 1000.0))
        db.execute(
            "INSERT INTO rule_hits_daily(rule, day, hits) VALUES(?,?,?)",
            ("r_old", old_day, 1),
        )
        db.execute(
            "INSERT INTO rule_hits_daily(rule, day, hits) VALUES(?,?,?)",
            ("r_new", new_day, 1),
        )
        db.execute(
            "INSERT INTO rule_incidents(rule, scope, severity, status, reason, "
            "opened_at, resolved_at) VALUES(?,?,?,?,?,?,?)",
            ("r_old", "rule", "high", "resolved", "manual",
             self.cutoff - 10_000, self.cutoff - 1),
        )
        db.execute(
            "INSERT INTO rule_incidents(rule, scope, severity, status, reason, "
            "opened_at, resolved_at) VALUES(?,?,?,?,?,?,?)",
            ("r_open", "rule", "high", "open", "manual",
             self.cutoff - 20_000, None),
        )
        db.execute(
            "INSERT INTO rule_incidents(rule, scope, severity, status, reason, "
            "opened_at, resolved_at) VALUES(?,?,?,?,?,?,?)",
            ("r_new", "rule", "high", "resolved", "manual",
             self.cutoff + 10_000, self.cutoff + 20_000),
        )

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_dry_run_counts_without_deleting(self):
        st = retention.prune_aggregates(self.cutoff, dry_run=True)
        self.assertEqual(st["rule_hits_daily"], 1)
        self.assertEqual(st["rule_incidents"], 1)
        self.assertEqual(
            db.scalar("SELECT COUNT(*) FROM rule_hits_daily"), 2)
        self.assertEqual(
            db.scalar("SELECT COUNT(*) FROM rule_incidents"), 3)

    def test_apply_keeps_open_and_recent_rows(self):
        st = retention.prune_aggregates(self.cutoff, dry_run=False)
        self.assertEqual(st["rule_hits_daily"], 1)
        self.assertEqual(st["rule_incidents"], 1)
        self.assertEqual(
            db.rows("SELECT rule FROM rule_hits_daily ORDER BY rule"),
            [{"rule": "r_new"}],
        )
        self.assertEqual(
            db.rows("SELECT rule FROM rule_incidents ORDER BY rule"),
            [{"rule": "r_new"}, {"rule": "r_open"}],
        )

    def test_dry_run_exposes_aggregate_section(self):
        st = retention.dry_run(days=90)
        self.assertEqual(st["aggregates"]["rule_hits_daily"], 1)
        self.assertEqual(st["aggregates"]["rule_incidents"], 1)

    def test_scheduled_run_writes_snapshot_and_audit(self):
        doc = retention_scheduler.run_once(force=True)
        self.assertTrue(doc["ok"])
        self.assertTrue(config.RETENTION_DRY_RUN_FILE.exists())
        self.assertEqual(doc["summary"]["scan_files"], 0)
        row = db.one(
            "SELECT action FROM audit WHERE action='retention_dry_run_scheduled'")
        self.assertIsNotNone(row)


if __name__ == "__main__":
    unittest.main()
