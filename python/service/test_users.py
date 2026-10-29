"""用户管理：创建/改角色/禁用/重置密码/删除 + 安全兜底（最后 admin、自己）。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from . import auth, config, db, users as users_mod


class UsersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "SECRET_PATH", root / ".secret"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.admin = users_mod.create_user("admin", "admin-pass-123", "admin")
        self.analyst = users_mod.create_user("alice", "alice-pass-123", "analyst")

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    # ---------------------------------------------------------------- 创建
    def test_create_and_list(self):
        users_mod.create_user("bob", "bob-pass-1234", "viewer")
        items = users_mod.list_users()
        self.assertEqual([u["username"] for u in items], ["admin", "alice", "bob"])
        bob = next(u for u in items if u["username"] == "bob")
        self.assertEqual(bob["role"], "viewer")
        self.assertFalse(bob["disabled"])
        self.assertNotIn("pw", bob)
        self.assertNotIn("token_version", bob)

    def test_create_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            users_mod.create_user("ab", "12345678", "viewer")          # 用户名太短
        with self.assertRaises(ValueError):
            users_mod.create_user("has space", "12345678", "viewer")   # 非法字符
        with self.assertRaises(ValueError):
            users_mod.create_user("bob", "short", "viewer")            # 密码太短
        with self.assertRaises(ValueError):
            users_mod.create_user("bob", "12345678", "root")           # 非法角色
        users_mod.create_user("bob", "12345678", "viewer")
        with self.assertRaises(ValueError):
            users_mod.create_user("bob", "12345678", "viewer")         # 重名

    # ---------------------------------------------------------------- 角色 / 禁用
    def test_role_change_bumps_token_version(self):
        before = int(db.scalar("SELECT token_version FROM users WHERE id=?",
                               (self.analyst["id"],), 0) or 0)
        out = users_mod.update_user(self.analyst["id"], actor_id=self.admin["id"],
                                    role="admin")
        self.assertEqual(out["role"], "admin")
        after = int(db.scalar("SELECT token_version FROM users WHERE id=?",
                              (self.analyst["id"],), 0) or 0)
        self.assertEqual(after, before + 1)

    def test_cannot_demote_or_disable_last_admin(self):
        with self.assertRaises(ValueError):
            users_mod.update_user(self.admin["id"], actor_id=999, role="analyst")
        with self.assertRaises(ValueError):
            users_mod.update_user(self.admin["id"], actor_id=999, disabled=True)
        # 还有另一个 admin 时可以降级
        users_mod.update_user(self.analyst["id"], actor_id=self.admin["id"], role="admin")
        out = users_mod.update_user(self.admin["id"], actor_id=999, role="analyst")
        self.assertEqual(out["role"], "analyst")

    def test_cannot_disable_or_delete_self(self):
        with self.assertRaises(ValueError):
            users_mod.update_user(self.admin["id"], actor_id=self.admin["id"],
                                  disabled=True)
        with self.assertRaises(ValueError):
            users_mod.update_user(self.admin["id"], actor_id=self.admin["id"],
                                  role="analyst")
        with self.assertRaises(ValueError):
            users_mod.delete_user(self.admin["id"], actor_id=self.admin["id"])

    def test_disabled_user_token_rejected(self):
        tok = auth.make_token("alice", "analyst", token_version=0)
        self.assertEqual(auth.current_user(f"Bearer {tok}")["username"], "alice")
        users_mod.update_user(self.analyst["id"], actor_id=self.admin["id"],
                              disabled=True)
        with self.assertRaises(HTTPException) as ctx:
            auth.current_user(f"Bearer {tok}")
        self.assertEqual(ctx.exception.status_code, 401)

    # ---------------------------------------------------------------- 密码
    def test_reset_password_changes_hash_and_invalidates_token(self):
        tok = auth.make_token("alice", "analyst", token_version=0)
        users_mod.reset_password(self.analyst["id"], "new-alice-pass-1")
        row = db.one("SELECT pw FROM users WHERE id=?", (self.analyst["id"],))
        self.assertTrue(auth.verify_password("new-alice-pass-1", row["pw"]))
        self.assertFalse(auth.verify_password("alice-pass-123", row["pw"]))
        with self.assertRaises(HTTPException):
            auth.current_user(f"Bearer {tok}")
        with self.assertRaises(ValueError):
            users_mod.reset_password(self.analyst["id"], "short")

    # ---------------------------------------------------------------- 删除
    def test_delete_user(self):
        users_mod.delete_user(self.analyst["id"], actor_id=self.admin["id"])
        self.assertIsNone(db.one("SELECT 1 AS x FROM users WHERE id=?",
                                 (self.analyst["id"],)))
        with self.assertRaises(ValueError):
            users_mod.delete_user(99999, actor_id=self.admin["id"])

    def test_cannot_delete_last_admin(self):
        with self.assertRaises(ValueError):
            users_mod.delete_user(self.admin["id"], actor_id=999)


if __name__ == "__main__":
    unittest.main()