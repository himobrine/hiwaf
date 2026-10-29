"""规则删除：DB/证据/熔断清理 + 现役规则集定向移除 + 策略指纹更新。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, rules as rules_mod


def _rule(rid, *, regex="x"):
    now = db.now_ms()
    db.execute(
        "INSERT INTO rules_custom(id, name, regex, scopes, severity, weight, action, "
        "enabled, source, compiled_at, created_at, updated_at, actor) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, rid, regex, '["query"]', "high", 1.0, "alert", 1, "manual",
         now, now, now, "tester"))


def _active_doc(ids):
    docs = []
    for rid in ids:
        docs.append({
            "id": rid, "name": rid, "regex": "x", "scopes": ["query"],
            "severity": "high", "weight": 1.0, "action": "alert",
            "source": "manual" if rid.startswith("custom_") else "mined",
            "provenance": {"kind": "detector",
                           "qualification": "testing",
                           "verdict": "keep" if not rid.startswith("custom_") else None},
        })
    return {"schema": 1, "ruleset_id": "t", "generated_at": 0,
            "decode": ["urlencoded", "unicode"], "min_weight_to_block": 1.0,
            "counts": {}, "rules": docs}


class RuleDeleteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "RULES_AUTHORITATIVE", root / "rules.json"),
            mock.patch.object(config, "POLICY_JSON", root / "policy.json"),
            mock.patch.object(config, "RULE_CANDIDATES", root / "cand.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        config.RULES_AUTHORITATIVE.write_text(
            json.dumps(_active_doc(["custom_del", "sqli_x"]), ensure_ascii=False),
            encoding="utf-8")
        config.POLICY_JSON.write_text(json.dumps({
            "schema": 2, "version": 5,
            "rules": {"enabled": True, "ruleset_sha1_16": "old",
                      "n_rules": 2, "n_block_rules": 0},
            "fusion": {"policy": "supervised_block__zero_day_alert__rules_block"},
        }, ensure_ascii=False), encoding="utf-8")
        _rule("custom_del")
        db.execute("INSERT INTO rule_breakers(rule, reason, actor, opened_at, mode)"
                   " VALUES(?,?,?,?,?)", ("custom_del", "manual", "tester",
                                          db.now_ms(), "alert"))
        db.execute("INSERT INTO rule_history_evidence(rule, rule_sha, days, scanned,"
                   " matched, confirmed_attack, confirmed_benign, created_at)"
                   " VALUES(?,?,?,?,?,?,?,?)",
                   ("custom_del", "x", 30, 10, 1, 1, 0, db.now_ms()))
        self.policy = lambda: json.loads(config.POLICY_JSON.read_text(encoding="utf-8"))
        self.active = lambda: json.loads(
            config.RULES_AUTHORITATIVE.read_text(encoding="utf-8"))

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_delete_removes_from_active_and_policy(self):
        out = rules_mod.delete_custom("custom_del", actor="tester")
        self.assertIsNotNone(out["active"])
        self.assertEqual(out["active"]["policy_version"], 6)

        self.assertIsNone(db.one("SELECT 1 AS x FROM rules_custom WHERE id='custom_del'"))
        self.assertEqual(db.scalar(
            "SELECT COUNT(*) FROM rule_breakers WHERE rule='custom_del'", default=0), 0)
        self.assertEqual(db.scalar(
            "SELECT COUNT(*) FROM rule_history_evidence WHERE rule='custom_del'",
            default=0), 0)

        doc = self.active()
        self.assertEqual([r["id"] for r in doc["rules"]], ["sqli_x"])
        self.assertEqual(doc["counts"]["total"], 1)
        self.assertEqual(doc["counts"]["mined"], 1)
        self.assertEqual(doc["counts"]["custom"], 0)

        pol = self.policy()
        self.assertEqual(pol["version"], 6)
        self.assertEqual(pol["generated_by"], "console:rule_delete")
        self.assertEqual(pol["rules"]["n_rules"], 1)
        self.assertEqual(pol["rules"]["n_block_rules"], 0)
        self.assertEqual(pol["rules"]["ruleset_sha1_16"],
                         rules_mod.authoritative_sha1_16())
        self.assertEqual(db.scalar(
            "SELECT MAX(version) FROM policy_versions", default=0), 6)

    def test_delete_rule_not_active_keeps_policy(self):
        _rule("custom_idle")
        before = config.POLICY_JSON.read_text(encoding="utf-8")
        out = rules_mod.delete_custom("custom_idle", actor="tester")
        self.assertIsNone(out["active"])
        self.assertEqual(config.POLICY_JSON.read_text(encoding="utf-8"), before)
        self.assertIsNone(db.one("SELECT 1 AS x FROM rules_custom WHERE id='custom_idle'"))

    def test_drop_failure_aborts_delete(self):
        with mock.patch.object(rules_mod, "_write_json_atomic",
                               side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                rules_mod.delete_custom("custom_del", actor="tester")
        # 回滚：DB 行还在、现役规则集还包含它
        self.assertIsNotNone(db.one("SELECT 1 AS x FROM rules_custom WHERE id='custom_del'"))
        self.assertIn("custom_del", [r["id"] for r in self.active()["rules"]])

    def test_bulk_delete_refreshes_testvec_once(self):
        _rule("custom_del2")
        doc = self.active()
        doc["rules"].append({
            "id": "custom_del2", "name": "custom_del2", "regex": "x",
            "scopes": ["query"], "severity": "high", "weight": 1.0,
            "action": "alert", "source": "manual",
            "provenance": {"kind": "detector", "qualification": "testing"},
        })
        config.RULES_AUTHORITATIVE.write_text(
            json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        with mock.patch.object(rules_mod, "refresh_testvec",
                               return_value={"ok": True}) as tv:
            out = rules_mod.bulk_apply_rules(
                scope="custom", ids=["custom_del", "custom_del2"], op="delete",
                actor="tester")
        self.assertEqual(out["n_changed"], 2)
        self.assertEqual(sorted(out["active_removed"]), ["custom_del", "custom_del2"])
        tv.assert_called_once()
        self.assertNotIn("custom_del", [r["id"] for r in self.active()["rules"]])


if __name__ == "__main__":
    unittest.main()