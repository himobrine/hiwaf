"""实体级抑制测试（临时 DB，不碰真实 console.db）。

覆盖：实体校验、草案/审批/撤销/删除状态机、TTL 到期惰性扫描、
AND 匹配语义（缺字段保守不匹配）、告警折叠计数、误报草案生成与去重/冷却。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, suppression

HOUR = 3_600_000
NOW = 1_700_000_000_000


class SuppressionTest(unittest.TestCase):
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

    def _event(self, ts: int, *, src_ip: str = "1.1.1.1",
               attack_type: str | None = None, path: str = "/x",
               action: str = "alert") -> int:
        return db.execute(
            "INSERT INTO events(ts, ingest_ts, src_ip, path, attack_type, action) "
            "VALUES(?,?,?,?,?,?)",
            (ts, ts, src_ip, path, attack_type, action),
        )

    def _fb(self, eid: int, verdict: str = "false_positive",
            ts: int = NOW) -> int:
        return db.execute(
            "INSERT INTO feedback(event_id, verdict, actor, ts) VALUES(?,?,?,?)",
            (eid, verdict, "analyst", ts),
        )

    # ---- 校验 -----------------------------------------------------------
    def test_requires_at_least_one_entity(self):
        with self.assertRaises(ValueError):
            suppression.create_draft("原因", now=NOW)
        with self.assertRaises(ValueError):
            suppression.create_draft("原因", src_ip="  ", now=NOW)

    def test_reason_and_ttl_validation(self):
        with self.assertRaises(ValueError):
            suppression.create_draft("  ", src_ip="1.1.1.1", now=NOW)
        with self.assertRaises(ValueError):
            suppression.create_draft("x" * 501, src_ip="1.1.1.1", now=NOW)
        with self.assertRaises(ValueError):
            suppression.create_draft("r", src_ip="1.1.1.1", ttl_hours=0, now=NOW)
        with self.assertRaises(ValueError):
            suppression.create_draft(
                "r", src_ip="1.1.1.1",
                ttl_hours=config.SUPPRESS_MAX_TTL_HOURS + 1, now=NOW)

    def test_path_must_start_with_slash(self):
        with self.assertRaises(ValueError):
            suppression.create_draft("r", path="admin", now=NOW)

    # ---- 状态机 ---------------------------------------------------------
    def test_draft_is_not_active_until_approved(self):
        row = suppression.create_draft(
            "r", src_ip="1.1.1.1", attack_type="xss", ttl_hours=24, now=NOW)
        self.assertEqual(row["status"], "draft")
        self.assertIsNone(row["expires_at"])
        self.assertEqual(suppression.active(now=NOW), [])

        row = suppression.approve(row["id"], "admin", now=NOW)
        self.assertEqual(row["status"], "active")
        self.assertEqual(row["expires_at"], NOW + 24 * HOUR)
        self.assertEqual([s["id"] for s in suppression.active(now=NOW)],
                         [row["id"]])

    def test_expired_is_swept_lazily(self):
        row = suppression.create_draft(
            "r", src_ip="1.1.1.1", ttl_hours=1, now=NOW)
        suppression.approve(row["id"], "admin", now=NOW)
        self.assertEqual([s["id"] for s in suppression.active(now=NOW + HOUR - 1)],
                         [row["id"]])
        self.assertEqual(suppression.active(now=NOW + HOUR), [])
        self.assertEqual(suppression.get(row["id"])["status"], "expired")

    def test_revoke_and_delete_rules(self):
        row = suppression.create_draft("r", src_ip="1.1.1.1", now=NOW)
        suppression.approve(row["id"], "admin", now=NOW)
        with self.assertRaises(ValueError):
            suppression.delete(row["id"])          # active 不能直接删
        row = suppression.revoke(row["id"], "admin", note="误报已修", now=NOW)
        self.assertEqual(row["status"], "revoked")
        self.assertEqual(suppression.active(now=NOW), [])
        suppression.delete(row["id"])
        self.assertIsNone(suppression.get(row["id"]))

    # ---- 匹配 -----------------------------------------------------------
    def test_matches_all_non_null_fields(self):
        sup = {"src_ip": "1.1.1.1", "attack_type": "xss"}
        self.assertTrue(suppression.matches(
            sup, {"src_ip": "1.1.1.1", "attack_type": "xss"}))
        self.assertFalse(suppression.matches(
            sup, {"src_ip": "1.1.1.1", "attack_type": "sqli"}))
        self.assertFalse(suppression.matches(
            sup, {"src_ip": "2.2.2.2", "attack_type": "xss"}))

    def test_missing_item_field_does_not_match(self):
        # 聚合组没有 UA 字段：只按 UA 收窄的抑制不应误伤整组。
        self.assertFalse(suppression.matches(
            {"ua": "curl/8"}, {"src_ip": "1.1.1.1"}))
        self.assertTrue(suppression.matches(
            {"ua": "curl/8"}, {"src_ip": "1.1.1.1", "ua": "curl/8"}))

    def test_host_path_and_chain_shapes(self):
        self.assertTrue(suppression.matches(
            {"host": "a.example"}, {"hosts": ["b.example", "a.example"]}))
        self.assertTrue(suppression.matches(
            {"path": "/login"}, {"top_paths": [{"path": "/login", "n": 3}]}))
        self.assertFalse(suppression.matches(
            {"path": "/login"}, {"path": "/login.php"}))

    def test_apply_hides_and_annotates(self):
        row = suppression.create_draft(
            "r", src_ip="1.1.1.1", attack_type="xss", now=NOW)
        suppression.approve(row["id"], "admin", now=NOW)
        items = [
            {"group_key": "a", "src_ip": "1.1.1.1", "attack_type": "xss"},
            {"group_key": "b", "src_ip": "2.2.2.2", "attack_type": "xss"},
        ]
        out, hidden = suppression.apply(items, now=NOW)
        self.assertEqual(hidden, 1)
        self.assertEqual([i["group_key"] for i in out], ["b"])

        # 显式展示时不折叠任何行，hidden 计数为 0；被抑制的行带 suppression 摘要。
        out2, hidden2 = suppression.apply(items, include_suppressed=True, now=NOW)
        self.assertEqual(hidden2, 0)
        self.assertEqual(len(out2), 2)
        self.assertEqual(out2[0]["suppression"]["id"], row["id"])
        self.assertNotIn("suppression", out2[1])

    # ---- 误报草案 -------------------------------------------------------
    def test_suggest_creates_draft_once_and_respects_cooldown(self):
        for i in range(3):
            eid = self._event(NOW - i * 1000, src_ip="1.1.1.1",
                              attack_type="xss", path=f"/p/{i}")
            self._fb(eid, ts=NOW - i * 1000)
        # 不足阈值的源不应生成
        for i in range(2):
            eid = self._event(NOW - i * 1000, src_ip="2.2.2.2",
                              attack_type="xss")
            self._fb(eid, ts=NOW - i * 1000)

        res = suppression.suggest(days=30, min_count=3, now=NOW)
        self.assertEqual(res["scanned"], 1)
        self.assertEqual(len(res["created"]), 1)
        row = res["created"][0]
        self.assertEqual(row["src_ip"], "1.1.1.1")
        self.assertEqual(row["attack_type"], "xss")
        self.assertEqual(row["status"], "draft")
        self.assertIn("3 条人工确认误报", row["reason"])

        # 已有草案 → 再次扫描跳过
        res2 = suppression.suggest(days=30, min_count=3, now=NOW)
        self.assertEqual(len(res2["created"]), 0)
        self.assertEqual(len(res2["skipped"]), 1)

        # 撤销后在冷却期内不再生成；过了冷却期才允许
        suppression.approve(row["id"], "admin", now=NOW)
        suppression.revoke(row["id"], "admin", now=NOW)
        res3 = suppression.suggest(days=30, min_count=3, now=NOW + HOUR)
        self.assertEqual(len(res3["created"]), 0)
        self.assertIn("冷却期", res3["skipped"][0]["why"])
        res4 = suppression.suggest(
            days=30, min_count=3, now=NOW + (config.SUPPRESS_COOLDOWN_HOURS + 1) * HOUR)
        self.assertEqual(len(res4["created"]), 1)

    def test_suggest_null_attack_type_uses_ip_only(self):
        for i in range(3):
            eid = self._event(NOW - i * 1000, src_ip="3.3.3.3",
                              attack_type=None)
            self._fb(eid, ts=NOW - i * 1000)
        res = suppression.suggest(days=30, min_count=3, now=NOW)
        self.assertEqual(len(res["created"]), 1)
        self.assertIsNone(res["created"][0]["attack_type"])
        self.assertEqual(res["created"][0]["src_ip"], "3.3.3.3")

    def test_suggest_only_counts_false_positive(self):
        for i in range(3):
            eid = self._event(NOW - i * 1000, src_ip="4.4.4.4")
            self._fb(eid, verdict="confirmed_benign", ts=NOW - i * 1000)
        res = suppression.suggest(days=30, min_count=3, now=NOW)
        self.assertEqual(res["scanned"], 0)
        self.assertEqual(res["created"], [])

    # ---- 列表 -----------------------------------------------------------
    def test_list_status_filter_and_validation(self):
        a = suppression.create_draft("a", src_ip="1.1.1.1", now=NOW)
        b = suppression.create_draft("b", src_ip="2.2.2.2", now=NOW)
        suppression.approve(b["id"], "admin", now=NOW)
        self.assertEqual(
            [r["id"] for r in suppression.list_suppressions("draft", now=NOW)],
            [a["id"]])
        self.assertEqual(
            [r["id"] for r in suppression.list_suppressions("active", now=NOW)],
            [b["id"]])
        self.assertEqual(len(suppression.list_suppressions(now=NOW)), 2)
        with self.assertRaises(ValueError):
            suppression.list_suppressions("nope", now=NOW)


if __name__ == "__main__":
    unittest.main()
