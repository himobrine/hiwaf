"""登录限流 / 令牌版本撤销测试（临时库，不触碰真实 console.db）。"""
from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from . import auth, config, db, login_guard
from . import app as app_mod


def _request(ip: str = "127.0.0.1"):
    return types.SimpleNamespace(client=types.SimpleNamespace(host=ip))


class AuthHardeningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "SECRET_PATH", root / ".secret"),
            mock.patch.object(config, "LOGIN_MAX_FAILS", 3),
            mock.patch.object(config, "LOGIN_WINDOW_SEC", 60),
            mock.patch.object(config, "LOGIN_LOCK_SEC", 120),
        ]
        for p in self.patches:
            p.start()
        db.init()
        db.execute(
            "INSERT INTO users(username, pw, role, disabled, created_at) "
            "VALUES(?,?,?,?,?)",
            ("admin", auth.hash_password("correct-password"), "admin", 0, db.now_ms()),
        )
        login_guard.reset_all()

    def tearDown(self):
        login_guard.reset_all()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _login(self, username: str, password: str):
        return app_mod.login(
            app_mod.LoginIn(username=username, password=password), _request())

    def _expect(self, status: int, fn, *args):
        with self.assertRaises(HTTPException) as cm:
            fn(*args)
        self.assertEqual(cm.exception.status_code, status)
        return cm.exception

    # -- 限流 -------------------------------------------------------------
    def test_blocks_after_threshold_and_sets_retry_after(self):
        self._expect(401, self._login, "admin", "wrong-1")
        self._expect(401, self._login, "admin", "wrong-2")
        exc = self._expect(429, self._login, "admin", "wrong-3")
        self.assertIn("Retry-After", exc.headers)
        self.assertGreaterEqual(int(exc.headers["Retry-After"]), 1)

        # 锁定期内即使密码正确也拒绝。
        self._expect(429, self._login, "admin", "correct-password")

        n = db.scalar(
            "SELECT COUNT(*) AS n FROM audit WHERE action='login_failed'", default=0)
        self.assertGreaterEqual(n, 3)

    def test_success_resets_failure_window(self):
        self._expect(401, self._login, "admin", "wrong-1")
        self._expect(401, self._login, "admin", "wrong-2")
        out = self._login("admin", "correct-password")
        self.assertTrue(out["token"])
        # 成功后计数清零：再错两次仍是 401，而不是 429。
        self._expect(401, self._login, "admin", "wrong-3")
        self._expect(401, self._login, "admin", "wrong-4")

    def test_unknown_user_uses_401_not_429(self):
        self._expect(401, self._login, "nobody", "whatever")
        self.assertEqual(
            db.scalar("SELECT COUNT(*) AS n FROM audit WHERE action='login_failed'"),
            1,
        )

    # -- 令牌版本 ---------------------------------------------------------
    def _token(self, version: int = 0) -> str:
        return auth.make_token("admin", "admin", token_version=version)

    def test_token_version_mismatch_rejected(self):
        token = self._token(0)
        me = auth.current_user("Bearer " + token)
        self.assertEqual(me["username"], "admin")

        db.execute("UPDATE users SET token_version=token_version+1")
        exc = self._expect(401, auth.current_user, "Bearer " + token)
        self.assertIn("失效", exc.detail)

    def test_logout_invalidates_old_token(self):
        token = self._token(0)
        user = auth.current_user("Bearer " + token)
        app_mod.logout(_request(), user)
        self._expect(401, auth.current_user, "Bearer " + token)

    def test_password_change_invalidates_old_token(self):
        token = self._token(0)
        user = auth.current_user("Bearer " + token)
        out = app_mod.change_password(
            app_mod.PasswordIn(old="correct-password", new="new-password-123"),
            _request(), user,
        )
        self.assertTrue(out["relogin"])
        self._expect(401, auth.current_user, "Bearer " + token)
        self._expect(401, self._login, "admin", "correct-password")
        self.assertTrue(self._login("admin", "new-password-123")["token"])

    def test_users_table_has_token_version(self):
        cols = {r["name"] for r in db.rows("PRAGMA table_info(users)")}
        self.assertIn("token_version", cols)


if __name__ == "__main__":
    unittest.main()
