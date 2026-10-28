"""规则批量操作测试（临时 DB / 候选文件，不触碰真实控制面）。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, rules


class RuleBulkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.candidates = root / "rule_candidates.json"
        self.candidates.write_text(json.dumps({
            "rules": [
                {
                    "rule": "mined_keep", "regex": "keep", "scopes": ["full"],
                    "verdict": "keep", "weight": 1.0,
                },
                {
                    "rule": "mined_low", "regex": "low", "scopes": ["full"],
                    "verdict": "reject_no_hit", "weight": 1.0,
                },
            ],
        }), encoding="utf-8")
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "RULE_CANDIDATES", self.candidates),
        ]
        for p in self.patches:
            p.start()
        db.init()
        now = db.now_ms()
        for rid, qualified, compiled in (
            ("custom_ok", now, now),
            ("custom_bad", None, now),
            ("custom_delete", None, now),
        ):
            db.execute(
                """INSERT INTO rules_custom
                     (id, name, regex, scopes, severity, weight, action, kind,
                      enabled, qualified_at, compiled_at, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, rid, "x", '["full"]', "medium", 1.0, "alert",
                 "detector", 0, qualified, compiled, now, now),
            )

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_mined_state_blocks_only_proven(self):
        with self.assertRaises(ValueError):
            rules.set_mined_state("mined_low", action="block", actor="tester")

        out = rules.set_mined_state("mined_low", enabled=True, action="alert", actor="tester")
        self.assertTrue(out["enabled"])
        self.assertEqual(out["action"], "alert")

        out = rules.set_mined_state("mined_keep", action="block", actor="tester")
        self.assertEqual(out["action"], "block")

    def test_bulk_mined_enable_disable_and_only_unproven(self):
        out = rules.bulk_set_mined_state(enabled=True, actor="tester", only_unproven=True)
        self.assertEqual(out["changed"], ["mined_low"])
        self.assertEqual(
            db.one("SELECT enabled, action FROM rule_state WHERE rule=?", ("mined_keep",)),
            None,
        )
        self.assertEqual(
            db.one("SELECT enabled, action FROM rule_state WHERE rule=?", ("mined_low",))["enabled"],
            1,
        )

        out = rules.bulk_apply_rules(
            scope="mined", ids=["mined_keep", "mined_low", "mined_keep"],
            op="disable", actor="tester",
        )
        self.assertEqual(out["n_changed"], 2)
        self.assertEqual(
            db.one("SELECT enabled FROM rule_state WHERE rule=?", ("mined_keep",))["enabled"], 0)

    def test_bulk_custom_action_block_is_per_rule(self):
        out = rules.bulk_apply_rules(
            scope="custom", ids=["custom_ok", "custom_bad", "missing"],
            op="set_action", action="block", actor="tester",
        )
        self.assertEqual(out["changed"], ["custom_ok"])
        self.assertEqual(len(out["errors"]), 2)
        self.assertEqual(
            db.one("SELECT action FROM rules_custom WHERE id=?", ("custom_ok",))["action"],
            "block",
        )
        self.assertEqual(
            db.one("SELECT action FROM rules_custom WHERE id=?", ("custom_bad",))["action"],
            "alert",
        )

    def test_bulk_custom_delete(self):
        out = rules.bulk_apply_rules(
            scope="custom", ids=["custom_delete"], op="delete", actor="tester")
        self.assertEqual(out["changed"], ["custom_delete"])
        self.assertIsNone(
            db.one("SELECT 1 AS x FROM rules_custom WHERE id=?", ("custom_delete",)))

    def test_bulk_rejects_empty_and_invalid(self):
        with self.assertRaises(ValueError):
            rules.bulk_apply_rules(scope="mined", ids=[], op="enable", actor="tester")
        with self.assertRaises(ValueError):
            rules.bulk_apply_rules(scope="mined", ids=["mined_keep"], op="delete",
                                   actor="tester")
        with self.assertRaises(ValueError):
            rules.bulk_apply_rules(scope="nope", ids=["x"], op="enable", actor="tester")


if __name__ == "__main__":
    unittest.main()
