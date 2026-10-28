"""保留期兜底：raw 文件已不在盘上的过期事件（临时库 / 临时 RAW_DIR）。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, retention


class OrphanEventPruneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.raw = root / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.present = self.raw / "raw-19700101-0.jsonl"
        self.present.write_text("{}\n", encoding="utf-8")
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "RAW_DIR", self.raw),
            mock.patch.object(config, "RETENTION_DRY_RUN_FILE",
                              root / "logs" / "retention-dry-run.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.cutoff = db.now_ms() - 90 * 86_400_000
        old = self.cutoff - 86_400_000
        new = self.cutoff + 86_400_000
        self.orphan_id = self._event(old, str(self.raw / "gone.jsonl"), "block")
        self.kept_id = self._event(old, str(self.present), "allow")
        self.young_id = self._event(new, str(self.raw / "gone2.jsonl"), "allow")
        self.null_id = self._event(old, None, "alert")
        # 从属行：孤儿事件应一起删；feedback 保留（人工结论不随证据过期丢弃）。
        for eid in (self.orphan_id, self.null_id, self.kept_id):
            db.execute("INSERT INTO event_shap(event_id, rank, feature, value, contribution) "
                       "VALUES(?,?,?,?,?)", (eid, 1, "f", 0.1, 0.2))
            db.execute("INSERT INTO event_bodies(event_id, body) VALUES(?,?)", (eid, "b"))
            db.execute("INSERT INTO event_rules(event_id, rule, field) VALUES(?,?,?)",
                       (eid, "r1", "path"))
        db.execute("INSERT INTO feedback(event_id, verdict, actor, ts) VALUES(?,?,?,?)",
                   (self.orphan_id, "attack", "analyst", db.now_ms()))

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _event(self, ts, src_file, action):
        return db.execute(
            """INSERT INTO events(ts, ingest_ts, src_ip, action, method, path, src_file, src_line)
               VALUES(?,?,?,?,?,?,?,?)""",
            (ts, ts, "10.0.0.1", action, "GET", "/x", src_file, 1),
        )

    def test_dry_run_counts_orphans_without_deleting(self):
        st = retention.prune_orphan_events(self.cutoff, dry_run=True)
        self.assertEqual(st["sources"], 2)          # gone.jsonl + src_file=NULL
        self.assertEqual(st["events"], 2)           # orphan + null，均为旧事件
        self.assertEqual(st["action"], "would_delete")
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM events"), 4)

    def test_apply_keeps_present_and_young_events(self):
        st = retention.prune_orphan_events(self.cutoff, dry_run=False)
        self.assertEqual(st["deleted"], 2)
        remaining = {r["id"] for r in db.rows("SELECT id FROM events")}
        self.assertEqual(remaining, {self.kept_id, self.young_id})
        # 从属行一起删。
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM event_shap"), 1)
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM event_bodies"), 1)
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM event_rules"), 1)
        # 人工结论保留，即便事件已过期删除。
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM feedback"), 1)

    def test_batches_respect_configured_limit(self):
        with mock.patch.object(retention, "ORPHAN_EVENT_BATCH", 1):
            st = retention.prune_orphan_events(self.cutoff, dry_run=False)
        self.assertEqual(st["deleted"], 2)
        self.assertFalse(st["truncated"])

    def test_dry_run_snapshot_includes_orphan_events(self):
        with mock.patch.object(retention, "scan_candidates",
                               lambda cutoff, dry_run=True: {"files": 1}):
            st = retention.dry_run(90)
        self.assertIn("orphan_events", st)
        self.assertEqual(st["orphan_events"]["events"], 2)


if __name__ == "__main__":
    unittest.main()
