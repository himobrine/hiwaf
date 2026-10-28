"""同源攻击链 + 时序规则测试（临时 DB，不碰真实 console.db）。

覆盖：阶段分类优先级、gap 切链、同毫秒排序稳定、扫描噪音降级、
时序命中与窗口边界、规则 JSON 覆盖/非法回退、链下钻精确匹配。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, correlate, db

MIN = 60_000
BASE = 1_700_000_000_000


def ev(eid: int, ts: int, **kw) -> dict:
    row = {
        "id": eid,
        "ts": ts,
        "src_ip": "1.1.1.1",
        "ua": "curl/8",
        "host": "example.com",
        "method": "GET",
        "path": "/",
        "status": 200,
        "action": "pass",
        "attack_type": None,
        "supervised_score": 0.1,
        "supervised_flagged": 0,
    }
    row.update(kw)
    return row


class ClassifyTest(unittest.TestCase):
    def test_priority_block_over_alert_over_recon(self):
        self.assertEqual(correlate.classify(ev(1, 0, action="block", status=404)), "exploit")
        self.assertEqual(correlate.classify(ev(1, 0, action="alert", status=404)), "probe")
        self.assertEqual(correlate.classify(ev(1, 0, supervised_flagged=1, status=404)), "probe")

    def test_failed_request_is_recon(self):
        for status in (401, 403, 404):
            self.assertEqual(correlate.classify(ev(1, 0, status=status)), "recon")

    def test_sensitive_path_only_counts_when_failed(self):
        self.assertEqual(correlate.classify(ev(1, 0, status=500, path="/wp-login.php")), "recon")
        # 成功访问登录/管理页不是探测，避免把正常流量当扫描。
        self.assertEqual(correlate.classify(ev(1, 0, status=200, path="/wp-login.php")), "normal")
        self.assertEqual(correlate.classify(ev(1, 0, status=302, path="/admin")), "normal")

    def test_plain_success_is_normal(self):
        self.assertEqual(correlate.classify(ev(1, 0, status=200, path="/index.html")), "normal")


class BuildChainsTest(unittest.TestCase):
    def test_gap_splits_chains(self):
        rows = [
            ev(1, BASE),
            ev(2, BASE + 5 * MIN),
            ev(3, BASE + 16 * MIN),  # 距上一条 11 分钟 > 10 分钟
        ]
        chains = correlate.build_chains(rows, gap_ms=10 * MIN, min_events=1)
        self.assertEqual(len(chains), 2)
        self.assertEqual(chains[0]["n"], 1)          # 按 last_ts 倒序，最新链在前
        self.assertEqual(chains[1]["n"], 2)
        self.assertEqual(chains[1]["first_ts"], BASE)

    def test_gap_exactly_at_boundary_keeps_chain(self):
        rows = [ev(1, BASE), ev(2, BASE + 10 * MIN)]
        chains = correlate.build_chains(rows, gap_ms=10 * MIN, min_events=1)
        self.assertEqual(len(chains), 1)

    def test_min_events_filters_singletons(self):
        rows = [ev(1, BASE), ev(2, BASE + 20 * MIN)]
        self.assertEqual(correlate.build_chains(rows, gap_ms=10 * MIN, min_events=2), [])

    def test_same_timestamp_sorted_by_id_and_key_stable(self):
        rows = [ev(9, BASE, ua="ua-a"), ev(3, BASE, ua="ua-a")]
        chains = correlate.build_chains(rows, gap_ms=10 * MIN, min_events=1)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["chain_key"], "1.1.1.1|ua-a|3")

    def test_groups_by_ua(self):
        rows = [ev(1, BASE, ua="ua-a"), ev(2, BASE + MIN, ua="ua-b")]
        chains = correlate.build_chains(rows, gap_ms=10 * MIN, min_events=1)
        self.assertEqual(len(chains), 2)
        self.assertEqual({c["ua"] for c in chains}, {"ua-a", "ua-b"})

    def test_severity_and_noise(self):
        recon = [ev(i, BASE + i, status=404) for i in range(1, 21)]
        chains = correlate.build_chains(recon, gap_ms=10 * MIN, min_events=2)
        self.assertEqual(len(chains), 1)
        c = chains[0]
        self.assertTrue(c["noise"])
        self.assertEqual(c["severity"], "P3")
        self.assertEqual(c["recon"], 20)

        with_block = recon + [ev(99, BASE + 5 * MIN, action="block", status=403)]
        c2 = correlate.build_chains(with_block, gap_ms=10 * MIN, min_events=2)[0]
        self.assertFalse(c2["noise"])
        self.assertEqual(c2["severity"], "P1")

        few = [ev(i, BASE + i, status=404) for i in range(1, 4)]
        c3 = correlate.build_chains(few, gap_ms=10 * MIN, min_events=2)[0]
        self.assertFalse(c3["noise"])
        self.assertEqual(c3["severity"], "P3")

    def test_stage_sequence_collapsed(self):
        rows = [
            ev(1, BASE, status=404),
            ev(2, BASE + MIN, status=404),
            ev(3, BASE + 2 * MIN, action="alert"),
            ev(4, BASE + 3 * MIN, action="block"),
            ev(5, BASE + 4 * MIN, action="block"),
        ]
        c = correlate.build_chains(rows, gap_ms=10 * MIN, min_events=1)[0]
        self.assertEqual(c["stages"], ["recon", "probe", "exploit"])
        self.assertEqual((c["recon"], c["alerted"], c["blocked"]), (2, 1, 2))


class SequenceTest(unittest.TestCase):
    def test_scan_then_exploit(self):
        rows = [ev(i, BASE + i, status=404) for i in range(1, 21)]
        rows.append(ev(99, BASE + 5 * MIN, action="block"))
        hits = correlate.detect_sequences(rows, correlate.DEFAULT_RULES)
        ids = {h["rule_id"] for h in hits}
        self.assertIn("scan_then_exploit", ids)
        hit = next(h for h in hits if h["rule_id"] == "scan_then_exploit")
        self.assertEqual([m["stage"] for m in hit["matched"]], ["recon", "exploit"])
        self.assertEqual(hit["group"]["src_ip"], "1.1.1.1")

    def test_outside_window_does_not_match(self):
        rows = [ev(i, BASE + i, status=404) for i in range(1, 21)]
        # 20 条探测的最后一条在 BASE+20，利用发生在 +11 分钟 → 超出 10 分钟窗口。
        rows.append(ev(99, BASE + 31 * MIN, action="block"))
        hits = correlate.detect_sequences(rows, correlate.DEFAULT_RULES)
        self.assertNotIn("scan_then_exploit", {h["rule_id"] for h in hits})

    def test_window_boundary_inclusive(self):
        rows = [ev(i, BASE + i, status=404) for i in range(1, 21)]
        rows.append(ev(99, BASE + 20 + 10 * MIN, action="block"))
        hits = correlate.detect_sequences(rows, correlate.DEFAULT_RULES)
        self.assertIn("scan_then_exploit", {h["rule_id"] for h in hits})

    def test_group_by_src_ip_keeps_sources_separate(self):
        rows = [ev(i, BASE + i, status=404, src_ip="1.1.1.1") for i in range(1, 21)]
        rows.append(ev(99, BASE + 5 * MIN, action="block", src_ip="2.2.2.2"))
        hits = correlate.detect_sequences(rows, correlate.DEFAULT_RULES)
        self.assertNotIn("scan_then_exploit", {h["rule_id"] for h in hits})


class RulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.p = mock.patch.object(
            config, "TEMPORAL_RULES_JSON", self.root / "temporal_rules.json")
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def test_missing_file_falls_back_to_defaults(self):
        self.assertEqual(correlate.load_rules(), correlate.DEFAULT_RULES)

    def test_invalid_json_falls_back(self):
        (self.root / "temporal_rules.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(correlate.load_rules(), correlate.DEFAULT_RULES)

    def test_custom_rules_override(self):
        rules = {"rules": [{
            "id": "custom", "name": "自定义", "within_min": 3,
            "group_by": ["src_ip", "host"],
            "stages": [{"stage": "probe", "min": 2}, {"stage": "exploit", "min": 1}],
        }]}
        (self.root / "temporal_rules.json").write_text(
            json.dumps(rules, ensure_ascii=False), encoding="utf-8")
        out = correlate.load_rules()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "custom")
        self.assertEqual(out[0]["within_min"], 3)
        self.assertEqual(out[0]["group_by"], ["src_ip", "host"])

    def test_invalid_rules_skipped_not_fatal(self):
        rules = {"rules": [
            {"id": "bad-stage", "stages": [{"stage": "nope", "min": 1}]},
            {"name": "缺 id", "stages": [{"stage": "recon", "min": 1}]},
            {"id": "bad-num", "within_min": "abc",
             "stages": [{"stage": "recon", "min": 1}]},
            {"id": "good", "stages": [{"stage": "recon", "min": 1}]},
        ]}
        (self.root / "temporal_rules.json").write_text(
            json.dumps(rules), encoding="utf-8")
        out = correlate.load_rules()
        self.assertEqual([r["id"] for r in out], ["good"])


class ChainEventsTest(unittest.TestCase):
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

    def _add(self, ts: int, *, src_ip="1.1.1.1", ua="curl/8", status=200,
             action="pass", path="/", rule_hits=None) -> int:
        return db.execute(
            "INSERT INTO events(ts, ingest_ts, src_ip, ua, status, action, path, "
            "rule_hits_json) VALUES(?,?,?,?,?,?,?,?)",
            (ts, ts, src_ip, ua, status, action, path, rule_hits),
        )

    def test_exact_src_and_ua(self):
        a = self._add(BASE + 1_000)
        self._add(BASE + 2_000, ua="other/1")       # UA 不同
        self._add(BASE + 3_000, src_ip="2.2.2.2")   # IP 不同
        r = correlate.chain_events("1.1.1.1", "curl/8", BASE, BASE + 10 * MIN)
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["id"], a)

    def test_null_ua_group(self):
        a = self._add(BASE + 1_000, ua=None)
        self._add(BASE + 2_000, ua="curl/8")
        r = correlate.chain_events("1.1.1.1", None, BASE, BASE + 10 * MIN)
        self.assertEqual(r["total"], 1)
        self.assertEqual(r["items"][0]["id"], a)

    def test_time_range_inclusive_and_pagination(self):
        ids = [self._add(BASE + 1_000 * i, status=404) for i in range(1, 6)]
        r = correlate.chain_events("1.1.1.1", "curl/8", BASE + 1_000,
                                   BASE + 5_000, limit=2, offset=0)
        self.assertEqual(r["total"], 5)
        self.assertEqual([it["id"] for it in r["items"]], ids[:2])  # 升序
        r2 = correlate.chain_events("1.1.1.1", "curl/8", BASE + 1_000,
                                    BASE + 5_000, limit=2, offset=4)
        self.assertEqual([it["id"] for it in r2["items"]], [ids[4]])

    def test_stage_and_rule_hits_parsed(self):
        hits = [{"rule": "942100", "action": "block"}]
        self._add(BASE + 1_000, status=404, action="block", rule_hits=json.dumps(hits))
        r = correlate.chain_events("1.1.1.1", "curl/8", BASE, BASE + 10 * MIN)
        it = r["items"][0]
        self.assertEqual(it["stage"], "exploit")
        self.assertEqual(it["rule_hits"], hits)
        self.assertNotIn("rule_hits_json", it)

    def test_validation(self):
        with self.assertRaises(ValueError):
            correlate.chain_events("", None, BASE, BASE + 1)
        with self.assertRaises(ValueError):
            correlate.chain_events("1.1.1.1", None, BASE + 1, BASE)


if __name__ == "__main__":
    unittest.main()
