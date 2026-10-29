"""熔断策略测试：已验证不自动熔断、总开关、告警开关、突增告警不受影响。

不碰真实 console.db / artifacts / policy：全部路径打到临时目录。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import breaker, config, db, rule_monitor, rules as rules_mod


def _custom(rid, *, action, qualified, enabled=1):
    now = db.now_ms()
    db.execute(
        "INSERT INTO rules_custom(id, name, regex, scopes, severity, weight, action, "
        "enabled, source, compiled_at, qualified_at, created_at, updated_at, actor) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, rid, "x", '["full"]', "high", 1.0, action, enabled, "manual",
         now, (now if qualified else None), now, now, "tester"))


def _authoritative(rules):
    return {
        "schema": 1,
        "ruleset_id": "test-ruleset",
        "generated_at": db.now_ms(),
        "decode": ["urlencoded", "unicode"],
        "min_weight_to_block": 1.0,
        "counts": {"total": len(rules),
                   "block": sum(1 for r in rules if r["action"] == "block"),
                   "alert": sum(1 for r in rules if r["action"] != "block")},
        "rules": rules,
    }


class BreakerPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "RULES_AUTHORITATIVE", root / "rules_authoritative.json"),
            mock.patch.object(config, "POLICY_JSON", root / "decision_policy.json"),
            mock.patch.object(config, "RULE_CANDIDATES", root / "rule_candidates.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        _custom("r_verified", action="block", qualified=True)
        _custom("r_testing", action="alert", qualified=False)
        rules = [
            {"id": "r_verified", "name": "verified", "regex": "x", "scopes": ["full"],
             "severity": "high", "weight": 1.0, "action": "block", "source": "manual",
             "provenance": {"kind": "detector", "qualification": "qualified"}},
            {"id": "r_testing", "name": "testing", "regex": "x", "scopes": ["full"],
             "severity": "medium", "weight": 1.0, "action": "alert", "source": "manual",
             "provenance": {"kind": "detector", "qualification": "testing"}},
        ]
        config.RULES_AUTHORITATIVE.write_text(
            json.dumps(_authoritative(rules), ensure_ascii=False), encoding="utf-8")
        config.POLICY_JSON.write_text(json.dumps({
            "schema": 2, "version": 1,
            "rules": {"enabled": True, "ruleset_sha1_16": "x", "n_rules": 2,
                      "n_block_rules": 1, "min_weight_to_block": 1.0},
            "fusion": {"policy": "supervised_block__zero_day_alert__rules_block"},
        }, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    # ------------------------------------------------------------------ 工具
    def _hit(self, rule, *, action="alert", benign=True, ts=None):
        ts = int(ts if ts is not None else db.now_ms())
        eid = db.execute(
            "INSERT INTO events(ts, ingest_ts, method, path, query, action) "
            "VALUES(?,?,?,?,?,?)",
            (ts, ts + 1, "GET", f"/{rule}", "q=1", action))
        db.execute(
            "INSERT INTO event_rules(event_id, rule, field, weight, action, snippet) "
            "VALUES(?,?,?,?,?,?)", (eid, rule, "", 1.0, action, "x"))
        if benign:
            db.execute(
                "INSERT INTO feedback(event_id, verdict, actor, ts) VALUES(?,?,?,?)",
                (eid, "confirmed_benign", "tester", ts))
        return eid

    def _incidents(self, reason=None):
        sql = "SELECT * FROM rule_incidents"
        rows = db.rows(sql + (" WHERE reason=?" if reason else ""),
                       (reason,) if reason else ())
        for r in rows:
            r["detail"] = json.loads(r.get("detail") or "{}")
        return rows

    def _breakers(self):
        return rules_mod.breaker_rows()

    # ------------------------------------------------------------------ 用例
    def test_verified_rule_is_never_auto_broken(self):
        for _ in range(6):
            self._hit("r_verified", action="block")
        out = rule_monitor.scan_once()
        self.assertEqual(self._breakers(), [])
        self.assertNotIn("r_verified", out["auto_broken"])
        inc = self._incidents("confirmed_fp")
        self.assertEqual(len(inc), 1)
        self.assertTrue(inc[0]["detail"]["verified"])
        self.assertEqual(inc[0]["detail"]["auto_action"], "none")

    def test_auto_breaker_off_keeps_ruleset(self):
        rules_mod.update_monitor_settings({"auto_breaker": False}, "tester")
        for _ in range(22):
            self._hit("r_testing", action="alert")
        out = rule_monitor.scan_once()
        self.assertEqual(self._breakers(), [])
        self.assertEqual(out["auto_broken"], [])
        inc = self._incidents("noise")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["detail"]["auto_action"], "none")
        # 未验证规则仍在现役规则集里（只告警）
        doc = rules_mod.load_authoritative()
        self.assertIn("r_testing", [r["id"] for r in doc["rules"]])

    def test_unverified_noise_is_auto_disabled(self):
        for _ in range(22):
            self._hit("r_testing", action="alert")
        out = rule_monitor.scan_once()
        bs = self._breakers()
        self.assertEqual([b["rule"] for b in bs], ["r_testing"])
        self.assertEqual(bs[0]["mode"], "disable")
        self.assertIn("r_testing", out["auto_broken"])
        doc = rules_mod.load_authoritative()
        self.assertNotIn("r_testing", [r["id"] for r in doc["rules"]])
        inc = self._incidents("noise")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["detail"]["auto_action"], "disable")

    def test_breaker_alerts_off_keeps_spike_alert(self):
        rules_mod.update_monitor_settings({"breaker_alerts": False}, "tester")
        for _ in range(120):
            self._hit("r_verified", action="block", benign=False)
        rule_monitor.scan_once()
        self.assertEqual(self._incidents("confirmed_fp"), [])
        self.assertEqual(self._incidents("noise"), [])
        spike = self._incidents("hit_spike")
        self.assertEqual(len(spike), 1)
        self.assertTrue(spike[0]["detail"]["verified"])

    def test_auto_action_leaves_incident_even_if_alerts_off(self):
        rules_mod.update_monitor_settings({"breaker_alerts": False}, "tester")
        for _ in range(22):
            self._hit("r_testing", action="alert")
        rule_monitor.scan_once()
        # 自动动作必须可追溯：即使告警开关关着，也要留下 incident。
        self.assertEqual([b["rule"] for b in self._breakers()], ["r_testing"])
        inc = self._incidents("noise")
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["detail"]["auto_action"], "disable")

    def test_auto_breaker_rejects_verified_rule(self):
        doc = rules_mod.load_authoritative()
        with self.assertRaises(ValueError):
            breaker.apply_breaker(scope="rule", rule="r_verified", reason="noise",
                                  actor="monitor", auto=True)
        self.assertEqual(self._breakers(), [])
        self.assertEqual(rules_mod.load_authoritative(), doc)

    def test_manual_breaker_still_works(self):
        breaker.apply_breaker(scope="rule", rule="r_verified", reason="manual",
                              actor="tester")
        bs = self._breakers()
        self.assertEqual(len(bs), 1)
        self.assertEqual(bs[0]["mode"], "alert")
        doc = rules_mod.load_authoritative()
        target = next(r for r in doc["rules"] if r["id"] == "r_verified")
        self.assertEqual(target["action"], "alert")

    def test_monitor_settings_roundtrip(self):
        self.assertEqual(rules_mod.monitor_settings(),
                         {"auto_breaker": True, "breaker_alerts": True})
        out = rules_mod.update_monitor_settings(
            {"auto_breaker": False, "breaker_alerts": False}, "tester")
        self.assertEqual(out, {"auto_breaker": False, "breaker_alerts": False})
        with self.assertRaises(ValueError):
            rules_mod.update_monitor_settings({"nope": True}, "tester")
        with self.assertRaises(ValueError):
            rules_mod.update_monitor_settings({}, "tester")


if __name__ == "__main__":
    unittest.main()