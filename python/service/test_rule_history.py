"""历史告警回放证据测试（mock 掉 Rust 回放，只测编排/标签/缓存/失效）。

不碰真实 console.db / artifacts。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, rule_history, rules as rules_mod


def _rule(rid="custom_hist", regex="hit", scopes='["query"]', *, qualified=False,
          benign_passed=True):
    now = db.now_ms()
    validation = None
    if benign_passed is not None:
        validation = json.dumps({"gates": {
            "regex_safety": {"passed": True},
            "benign_replay": {"passed": bool(benign_passed), "benign_hits": 0,
                              "benign_n": 6190},
            "attack_replay": {"passed": False, "attack_hits": 0, "attack_n": 25119},
        }})
    db.execute(
        "INSERT INTO rules_custom(id, name, regex, scopes, severity, weight, action, "
        "enabled, source, compiled_at, validated_at, validation, qualified_at, "
        "created_at, updated_at, actor) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, rid, regex, scopes, "high", 1.0, "alert", 1, "manual",
         now, now, validation, (now if qualified else None), now, now, "tester"))


def _event(query, *, verdict=None, ts=None, rid="custom_hist", record_rule=True):
    ts = int(ts if ts is not None else db.now_ms())
    eid = db.execute(
        "INSERT INTO events(ts, ingest_ts, method, path, query, action, "
        "supervised_flagged, zero_day_flagged) VALUES(?,?,?,?,?,?,?,?)",
        (ts, ts + 1, "GET", "/x", query, "alert", 0, 0))
    if record_rule:
        db.execute("INSERT INTO event_rules(event_id, rule, field) VALUES(?,?,?)",
                   (eid, rid, "query"))
    if verdict:
        db.execute("INSERT INTO feedback(event_id, verdict, actor, ts) VALUES(?,?,?,?)",
                   (eid, verdict, "tester", ts + 1))
    return eid


class HistoryEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "RULE_CANDIDATES", root / "cand.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        _rule()
        # Rust 回放用 mock 代替：命中 = query 里含 "hit"
        self.replay = mock.patch.object(
            rule_history, "_replay",
            side_effect=lambda spec, rows, bodies, tmpdir:
                [int(r["id"]) for r in rows if "hit" in (r["query"] or "")])
        self.replay.start()

    def tearDown(self):
        self.replay.stop()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_attacks_qualify_and_record_source(self):
        for i in range(3):
            _event(f"q=hit{i}", verdict="confirmed_attack")
        _event("q=benign", verdict="confirmed_benign")

        out = rule_history.run("custom_hist", actor="tester")
        self.assertEqual((out["matched"], out["confirmed_attack"],
                          out["confirmed_benign"], out["ok"]), (3, 3, 0, True))

        ev = rules_mod.history_evidence("custom_hist")
        self.assertTrue(ev and ev["ok"])
        row = db.one("SELECT * FROM rules_custom WHERE id='custom_hist'")
        view = rules_mod.custom_view(
            {**row, "validation": json.loads(row["validation"])}, None, None, ev)
        self.assertTrue(view["history_ok"])
        self.assertTrue(view["suggest_qualified"])

        res = rules_mod.set_custom_qualified("custom_hist", actor="tester", note="历史攻击证据")
        self.assertTrue(res["rule"]["is_qualified"])
        self.assertEqual(res["rule"]["qualification_source"], "history_replay")

    def test_benign_label_blocks_qualification(self):
        _event("q=hit1", verdict="confirmed_attack")
        _event("q=hit2", verdict="confirmed_benign")
        out = rule_history.run("custom_hist", actor="tester")
        self.assertEqual((out["confirmed_attack"], out["confirmed_benign"],
                          out["ok"]), (1, 1, False))
        with self.assertRaises(ValueError):
            rules_mod.set_custom_qualified("custom_hist", actor="tester")

    def test_latest_feedback_wins(self):
        eid = _event("q=hit", verdict="confirmed_attack")
        db.execute("INSERT INTO feedback(event_id, verdict, actor, ts) VALUES(?,?,?,?)",
                   (eid, "confirmed_benign", "tester", db.now_ms() + 10))
        out = rule_history.run("custom_hist", actor="tester")
        self.assertEqual((out["confirmed_attack"], out["confirmed_benign"]),
                         (0, 1))
        self.assertFalse(out["ok"])

    def test_window_and_truncation(self):
        import datetime as dt
        _event("q=hit-old", verdict="confirmed_attack",
               ts=db.now_ms() - 40 * 86400 * 1000)
        _event("q=hit1", verdict="confirmed_attack")
        _event("q=hit2", verdict="confirmed_attack")
        _event("q=hit3", verdict="confirmed_attack")

        out = rule_history.run("custom_hist", days=30, max_events=2, actor="tester")
        self.assertEqual(out["scanned"], 2)
        self.assertTrue(out["truncated"])
        self.assertEqual(out["matched"], 2)   # 旧事件不在窗口内

    def test_edit_invalidates_evidence(self):
        _event("q=hit", verdict="confirmed_attack")
        rule_history.run("custom_hist", actor="tester")
        self.assertIsNotNone(rules_mod.history_evidence("custom_hist"))
        rules_mod.update_custom("custom_hist", {"regex": "hit2"}, "tester")
        self.assertIsNone(rules_mod.history_evidence("custom_hist"))
        self.assertEqual(db.scalar(
            "SELECT COUNT(*) FROM rule_history_evidence", default=0), 0)

    def test_benign_replay_gate_still_required(self):
        _rule("custom_noval", benign_passed=None)
        # 不写 event_rules：排除「在线证据」这条路，单独验证历史证据也过不了 ②
        _event("q=hit", verdict="confirmed_attack", rid="custom_noval",
               record_rule=False)
        out = rule_history.run("custom_noval", actor="tester")
        self.assertTrue(out["ok"])
        ev = rules_mod.history_evidence("custom_noval")
        row = db.one("SELECT * FROM rules_custom WHERE id='custom_noval'")
        view = rules_mod.custom_view(row, None, None, ev)
        self.assertFalse(view["history_ok"])       # ② 未通过
        self.assertFalse(view["suggest_qualified"])
        with self.assertRaises(ValueError):
            rules_mod.set_custom_qualified("custom_noval", actor="tester")

    def test_unknown_rule_rejected(self):
        with self.assertRaises(ValueError):
            rule_history.run("nope", actor="tester")


if __name__ == "__main__":
    unittest.main()