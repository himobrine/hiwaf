"""SQLite 连接复用测试：session() 分组 / 服务模式线程内复用（临时库）。"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from . import config, db


class DbSessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", self.root / "console.db"),
            mock.patch.object(config, "LOG_DIR", self.root / "logs"),
        ]
        for p in self.patches:
            p.start()
        db.enable_pool(False)
        db.init()

    def tearDown(self):
        # 池连接持有临时库的文件句柄，Windows 上不关就删不掉目录。
        db.enable_pool(False)
        db.close_thread_connection()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _insert_audit(self, action: str) -> None:
        db.execute(
            "INSERT INTO audit(ts, actor, action) VALUES(?,?,?)",
            (db.now_ms(), "tester", action),
        )

    # -- session() 显式分组 -------------------------------------------------
    def test_session_reuses_one_connection(self):
        with db.session() as conn:
            self.assertIs(db._SESSION.get(), conn)
            self._insert_audit("a")
            db.rows("SELECT 1 AS x")
            db.scalar("SELECT COUNT(*) AS n FROM audit")
            self.assertIs(db._SESSION.get(), conn)
            self.assertEqual(
                int(conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]), 1)
        self.assertIsNone(db._SESSION.get())

    def test_nested_session_reuses_outer(self):
        with db.session() as outer:
            with db.session() as inner:
                self.assertIs(outer, inner)
        self.assertIsNone(db._SESSION.get())

    def test_write_is_committed_after_session(self):
        with db.session():
            self._insert_audit("visible")
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM audit"), 1)

    def test_falls_back_without_session_or_pool(self):
        self._insert_audit("x")
        self._insert_audit("y")
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM audit"), 2)
        self.assertIsNone(db._SESSION.get())
        self.assertIsNone(getattr(db._local, "conn", None))

    def test_session_does_not_leak_across_threads(self):
        seen = {}

        def worker():
            seen["conn"] = db._SESSION.get()

        with db.session():
            t = threading.Thread(target=worker)
            t.start()
            t.join()
        self.assertIsNone(seen["conn"])

    def test_insert_ignore_still_works_in_session(self):
        sql = ("INSERT OR IGNORE INTO users(username, pw, role, created_at) "
               "VALUES(?,?,?,?)")
        with db.session():
            first = db.insert_ignore(sql, ("u", "p", "viewer", db.now_ms()))
            second = db.insert_ignore(sql, ("u", "p", "viewer", db.now_ms()))
        self.assertGreater(first, 0)
        self.assertEqual(second, 0)
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM users"), 1)

    # -- 服务模式：线程内长连接 ---------------------------------------------
    def test_pool_reuses_connection_across_calls(self):
        db.enable_pool()
        db.rows("SELECT 1 AS x")
        first = db._local.conn
        self.assertIsNotNone(first)
        db.rows("SELECT 1 AS x")
        self._insert_audit("pooled")
        self.assertIs(db._local.conn, first)
        self.assertEqual(db.scalar("SELECT COUNT(*) AS n FROM audit"), 1)

    def test_pool_write_visible_from_a_fresh_connection(self):
        db.enable_pool()
        self._insert_audit("pooled")
        with db.session() as conn:  # 另一条连接
            n = int(conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0])
        self.assertEqual(n, 1)

    def test_pool_switches_connection_when_db_path_changes(self):
        db.enable_pool()
        db.rows("SELECT 1 AS x")
        first = db._local.conn
        other = self.root / "other.db"
        with mock.patch.object(config, "DB_PATH", other):
            db.rows("SELECT 1 AS x")
            self.assertIsNot(db._local.conn, first)
            self.assertEqual(db._local.path, str(other))

    def test_pool_is_per_thread(self):
        db.enable_pool()
        db.rows("SELECT 1 AS x")
        mine = db._local.conn
        seen = {}

        def worker():
            db.rows("SELECT 1 AS x")
            seen["conn"] = db._local.conn

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        self.assertIsNot(seen["conn"], mine)
        self.assertIs(db._local.conn, mine)

    def test_disable_pool_closes_thread_connection(self):
        db.enable_pool()
        db.rows("SELECT 1 AS x")
        self.assertIsNotNone(db._local.conn)
        db.enable_pool(False)
        self.assertIsNone(db._local.conn)


if __name__ == "__main__":
    unittest.main()
