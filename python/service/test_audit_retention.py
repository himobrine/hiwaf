"""审计保留期 / 勾选删除 / 自动清理测试（临时 DB，不碰真实 console.db）。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import audit_retention, audit_retention_scheduler, config, db

DAY = 86_400_000


class AuditRetentionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "AUDIT_RETENTION_DAYS", 90),
            mock.patch.object(config, "AUDIT_RETENTION_SCHEDULER_ENABLED", True),
            mock.patch.object(config, "AUDIT_CLEANUP_BATCH", 100),
            mock.patch.object(config, "AUDIT_SELECTED_MAX", 500),
        ]
        for p in self.patches:
            p.start()
        db.init()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _add(self, ts: int, action: str = "login", actor: str = "u",
             target: str | None = None, detail: str | None = None,
             ip: str | None = None) -> int:
        return db.execute(
            "INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
            (ts, actor, action, target, detail, ip))

    def _latest(self) -> dict:
        return db.one("SELECT * FROM audit ORDER BY id DESC LIMIT 1")

    def test_preview_counts_without_deleting(self):
        now = db.now_ms()
        self._add(now - 100 * DAY, action="login")
        self._add(now - 91 * DAY, action="view_packet")
        self._add(now - 10 * DAY, action="login")
        self._add(now, action="login")
        before = db.scalar("SELECT COUNT(*) FROM audit")
        st = audit_retention.preview(90)
        self.assertEqual(st["total"], 4)
        self.assertEqual(st["delete_count"], 2)
        self.assertEqual(st["keep_count"], 2)
        self.assertEqual(st["oldest_ts"], now - 100 * DAY)
        self.assertEqual(st["newest_ts"], now)
        self.assertEqual(st["delete_oldest_ts"], now - 100 * DAY)
        self.assertEqual(st["delete_newest_ts"], now - 91 * DAY)
        self.assertEqual(st["by_action"][0]["n"], 1)
        self.assertEqual(db.scalar("SELECT COUNT(*) FROM audit"), before)

    def test_cleanup_only_old_and_writes_cleanup_audit(self):
        now = db.now_ms()
        old = self._add(now - 100 * DAY, action="login")
        recent = self._add(now - 10 * DAY, action="login")
        r = audit_retention.cleanup(90, actor="admin", ip="1.2.3.4", trigger="manual")
        self.assertTrue(r["ok"])
        self.assertEqual(r["deleted"], 1)
        self.assertGreater(r["cleanup_audit_id"], 0)
        self.assertIsNone(db.one("SELECT id FROM audit WHERE id=?", (old,)))
        self.assertIsNotNone(db.one("SELECT id FROM audit WHERE id=?", (recent,)))
        latest = self._latest()
        self.assertEqual(latest["action"], "audit_cleanup")
        self.assertEqual(latest["actor"], "admin")
        self.assertEqual(latest["target"], "age:90d")
        self.assertEqual(latest["ip"], "1.2.3.4")
        detail = json.loads(latest["detail"])
        self.assertEqual(detail["deleted"], 1)
        self.assertEqual(detail["trigger"], "manual")

    def test_auto_zero_does_not_write_noise(self):
        now = db.now_ms()
        self._add(now - 10 * DAY)
        before = db.scalar("SELECT COUNT(*) FROM audit")
        r = audit_retention.cleanup(
            90, actor="system", trigger="auto", record_empty=False)
        self.assertEqual(r["deleted"], 0)
        self.assertEqual(db.scalar("SELECT COUNT(*) FROM audit"), before)

    def test_manual_zero_still_records_action(self):
        now = db.now_ms()
        self._add(now - 10 * DAY)
        r = audit_retention.cleanup(90, actor="admin", trigger="manual")
        self.assertEqual(r["deleted"], 0)
        self.assertEqual(self._latest()["action"], "audit_cleanup")

    def test_delete_selected_and_missing_ids(self):
        now = db.now_ms()
        a = self._add(now, action="login")
        b = self._add(now, action="view_body")
        c = self._add(now, action="rule_toggle")
        r = audit_retention.delete_selected(
            [a, b, 999999], actor="admin", ip="127.0.0.1", reason="误操作清理")
        self.assertEqual(r["requested"], 3)
        self.assertEqual(r["deleted"], 2)
        self.assertEqual(r["missing"], [999999])
        self.assertIsNone(db.one("SELECT id FROM audit WHERE id=?", (a,)))
        self.assertIsNone(db.one("SELECT id FROM audit WHERE id=?", (b,)))
        self.assertIsNotNone(db.one("SELECT id FROM audit WHERE id=?", (c,)))
        latest = self._latest()
        self.assertEqual(latest["action"], "audit_cleanup_selected")
        detail = json.loads(latest["detail"])
        self.assertEqual(detail["reason"], "误操作清理")
        self.assertEqual(detail["deleted"], 2)
        self.assertIn(999999, detail["missing"])

    def test_validation(self):
        with self.assertRaises(ValueError):
            audit_retention.preview(0)
        with self.assertRaises(ValueError):
            audit_retention.cleanup(3651)
        with self.assertRaises(ValueError):
            audit_retention.delete_selected([], actor="admin")
        with self.assertRaises(ValueError):
            audit_retention.delete_selected([-1], actor="admin")
        with mock.patch.object(config, "AUDIT_SELECTED_MAX", 2):
            with self.assertRaises(ValueError):
                audit_retention.delete_selected([1, 2, 3], actor="admin")

    def test_cleanup_failure_rolls_back_and_records_failure(self):
        now = db.now_ms()
        old = self._add(now - 100 * DAY, action="login")
        with mock.patch.object(audit_retention, "_insert_cleanup",
                               side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                audit_retention.cleanup(90, actor="admin", trigger="manual")
        # 事务回滚：旧行还在
        self.assertIsNotNone(db.one("SELECT id FROM audit WHERE id=?", (old,)))
        failed = db.one("SELECT * FROM audit WHERE action='audit_cleanup_failed'")
        self.assertIsNotNone(failed)
        self.assertIn("boom", failed["detail"])

    def test_scheduler_run_once_and_disabled(self):
        now = db.now_ms()
        old = self._add(now - 100 * DAY, action="login")
        r = audit_retention_scheduler.run_once()
        self.assertTrue(r["ok"])
        self.assertEqual(r["deleted"], 1)
        self.assertIsNone(db.one("SELECT id FROM audit WHERE id=?", (old,)))
        self.assertEqual(self._latest()["actor"], "system")
        self.assertEqual(self._latest()["action"], "audit_cleanup")

        with mock.patch.object(config, "AUDIT_RETENTION_SCHEDULER_ENABLED", False):
            r2 = audit_retention_scheduler.run_once()
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["skipped"], "disabled")


if __name__ == "__main__":
    unittest.main()
