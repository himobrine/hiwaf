"""从事件生成数据集的测试（不碰真实 console.db / traindata / raw）。

覆盖红线：标签必须人工给（benign 只能 0、来源说明必填）、body 两级回退、
请求指纹去重、按筛选/按 id 选行、官方评估集重叠剔除、审计落库。
"""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, datasets_events, db, uploads


def _ev(eid=None, ts=1_000, method="GET", path="/a", query="x=1", **kw):
    """插一条事件；`eid` 由 SQLite 自增。"""
    cols = {"ts": ts, "ingest_ts": ts + 1, "method": method, "path": path,
            "query": query, "src_ip": "10.0.0.1", "action": "allow",
            "attack_label": 1, "attack_type": "sqli", "status": 200}
    cols.update(kw)
    keys = list(cols)
    cur = db.execute(
        f"INSERT INTO events({','.join(keys)}) VALUES({','.join('?' * len(keys))})",
        [cols[k] for k in keys])
    return int(cur)


class EventDatasetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.raw = root / "raw"
        self.raw.mkdir()
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "UPLOADS", root / "uploads"),
            mock.patch.object(config, "RAW_DIR", self.raw),
            mock.patch.object(uploads, "_official_eval_keys", return_value=set()),
        ]
        for p in self.patches:
            p.start()
        db.init()
        uploads.ensure_dirs()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    # ------------------------------------------------------------------ 工具
    def _create(self, **kw):
        kw.setdefault("name", "unit")
        kw.setdefault("role", "supervised")
        kw.setdefault("source_note", "unit-test")
        # wait=True：测试同步建完，避免后台线程跨过 mock 边界写真实库。
        row = datasets_events.create_from_events(wait=True, **kw)
        self.assertIn(row["status"], ("ready", "failed"), row.get("error"))
        return row

    def _rows(self, ds, name="requests.jsonl"):
        p = Path(ds["dir"]) / name
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip()]

    def _raw_line(self, fname="raw-001.jsonl", **kw):
        d = {"method": "POST", "path": "/login", "query": "", "host": "h",
             "src_ip": "10.0.0.9", "status": 200}
        d.update(kw)
        p = self.raw / fname
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
        return str(p), sum(1 for _ in p.read_text(encoding="utf-8").splitlines())

    # ------------------------------------------------------------------ 基本
    def test_ids_mode_builds_snapshot(self):
        ids = [_ev(path="/a", query="x=1"), _ev(path="/b", query="y=2"),
               _ev(path="/c", query="z=3")]
        ds = self._create(mode="ids", event_ids=ids, label=1)
        self.assertEqual(ds["status"], "ready", ds.get("error"))
        self.assertEqual(ds["origin"], "events")
        self.assertEqual(ds["format"], "events")
        self.assertEqual(ds["rows_kept"], 3)
        self.assertEqual(ds["rows_total"], 3)
        self.assertEqual(ds["label_stats"], {"1": 3})
        self.assertEqual(ds["selection"]["mode"], "ids")
        self.assertEqual(len(self._rows(ds)), 3)
        self.assertEqual(len(self._rows(ds, "requests_train.jsonl")), 3)
        self.assertTrue(ds["sha256"])
        # 标签红线：每条行的 label_why 记录操作者/来源，而不是模型预测
        self.assertTrue(all("console:system" in r["label_why"] for r in self._rows(ds)))
        audit = db.rows("SELECT action FROM audit WHERE action='dataset_ready'")
        self.assertEqual(len(audit), 1)

    def test_filter_mode_and_max_rows_truncation(self):
        for i in range(5):
            _ev(path=f"/sql/{i}", query=f"id={i}")
        ds = self._create(mode="filter", filters={"path": "/sql/"}, label=1,
                          max_rows=3)
        self.assertEqual(ds["status"], "ready", ds.get("error"))
        self.assertEqual(ds["rows_kept"], 3)
        self.assertTrue(ds["stats"]["selection"]["truncated"])

    def test_verdict_and_attack_type_filters(self):
        a = _ev(path="/x", attack_type="sqli")
        _ev(path="/y", attack_type="xss")
        db.execute("INSERT INTO feedback(event_id, verdict, actor, ts) VALUES(?,?,?,?)",
                   (a, "confirmed_attack", "tester", db.now_ms()))
        ds = self._create(mode="filter", filters={"verdict": "confirmed_attack"},
                          label=1)
        self.assertEqual(ds["rows_kept"], 1)
        ds2 = self._create(mode="filter", filters={"attack_type": "xss"}, label=2)
        self.assertEqual(ds2["rows_kept"], 1)
        self.assertEqual(ds2["label_stats"], {"2": 1})

    # ------------------------------------------------------------------ body
    def test_body_db_then_raw_fallback(self):
        a = _ev(path="/db", query="q=1")
        db.execute("INSERT INTO event_bodies(event_id, body) VALUES(?,?)",
                   (a, "id=1'--+"))
        payload = "id=2'--+&submit=Submit"
        src, line = self._raw_line(body=payload,
                                   body_b64=base64.b64encode(payload.encode()).decode())
        b = _ev(method="POST", path="/login", query="", src_file=src, src_line=line)
        c = _ev(path="/empty", query="q=3")          # 没有 body，也没有 raw
        ds = self._create(mode="ids", event_ids=[a, b, c], label=0, role="benign")
        self.assertEqual(ds["status"], "ready", ds.get("error"))
        rows = {r["path"]: r for r in self._rows(ds)}
        self.assertEqual(rows["/db"]["body"], "id=1'--+")
        self.assertEqual(rows["/login"]["body"], payload)
        self.assertEqual(rows["/empty"]["body"], "")
        body = ds["stats"]["body"]
        # /empty 是 GET（body_len=0）：算 empty 而不是 missing。
        self.assertEqual((body["from_db"], body["from_raw"], body["missing"],
                          body["empty"]), (1, 1, 0, 1))

    def test_binary_body_is_not_faked(self):
        src, line = self._raw_line(
            body="", body_b64=base64.b64encode(b"\x00\x01\xff").decode())
        eid = _ev(method="POST", path="/bin", query="", src_file=src, src_line=line,
                  body_len=3)
        ds = self._create(mode="ids", event_ids=[eid], label=1)
        self.assertEqual(self._rows(ds)[0]["body"], "")
        self.assertEqual(ds["stats"]["body"]["missing"], 1)
        self.assertEqual(ds["stats"]["body"]["empty"], 0)

    # ------------------------------------------------------------------ 去重
    def test_dedup_keeps_newest(self):
        old = _ev(path="/same", query="id=1", ts=100)
        new = _ev(path="/same", query="id=1", ts=200)
        ds = self._create(mode="ids", event_ids=[old, new], label=1)
        self.assertEqual(ds["rows_kept"], 1)
        self.assertEqual(ds["rows_total"], 2)
        self.assertEqual(ds["stats"]["dedup"]["duplicates"], 1)
        self.assertEqual(int(self._rows(ds)[0]["ts"]), 200)

    # ------------------------------------------------------------------ 反泄漏
    def test_official_eval_overlap_removed(self):
        from upload_parse import req_key
        a = _ev(path="/keep", query="k=1")
        b = _ev(path="/leak", query="k=2")
        key = req_key({"method": "GET", "path": "/leak", "query": "k=2", "body": ""})
        with mock.patch.object(uploads, "_official_eval_keys", return_value={key}):
            ds = self._create(mode="ids", event_ids=[a, b], label=1)
        self.assertEqual(ds["rows_kept"], 2)
        self.assertEqual(len(self._rows(ds, "requests_train.jsonl")), 1)
        self.assertEqual(ds["stats"]["overlap_official_eval"]["n_overlap"], 1)

    def test_eval_role_skips_overlap_removal(self):
        from upload_parse import req_key
        a = _ev(path="/keep", query="k=1")
        key = req_key({"method": "GET", "path": "/keep", "query": "k=1", "body": ""})
        with mock.patch.object(uploads, "_official_eval_keys", return_value={key}):
            ds = self._create(mode="ids", event_ids=[a], label=0, role="eval",
                              source_note="")
        self.assertEqual(len(self._rows(ds, "requests_train.jsonl")), 1)

    # ------------------------------------------------------------------ 红线
    def test_benign_role_rejects_attack_label(self):
        eid = _ev(path="/b")
        with self.assertRaises(ValueError):
            datasets_events.create_from_events(mode="ids", event_ids=[eid],
                                               role="benign", label=1,
                                               source_note="x")

    def test_source_note_required_for_supervised(self):
        eid = _ev(path="/b")
        with self.assertRaises(ValueError):
            datasets_events.create_from_events(mode="ids", event_ids=[eid],
                                               role="supervised", label=1,
                                               source_note="  ")

    def test_unknown_filter_key_rejected(self):
        _ev(path="/b")
        with self.assertRaises(ValueError):
            datasets_events.create_from_events(mode="filter",
                                               filters={"pth": "/b"}, label=1,
                                               source_note="x")

    def test_empty_selection_rejected(self):
        with self.assertRaises(ValueError):
            datasets_events.create_from_events(mode="ids", event_ids=[999],
                                               label=1, source_note="x")

    # ------------------------------------------------------------------ 预检
    def test_preview_reports_counts_and_body(self):
        a = _ev(path="/p1", query="q=1")
        _ev(path="/p2", query="q=2")
        db.execute("INSERT INTO event_bodies(event_id, body) VALUES(?,?)", (a, "b"))
        pv = datasets_events.preview_selection(mode="filter", filters={"path": "/p"})
        self.assertEqual(pv["matched"], 2)
        self.assertEqual(pv["checked"], 2)
        self.assertEqual(pv["body"]["from_db"], 1)
        self.assertEqual(pv["body"]["missing"], 0)
        self.assertEqual(pv["body"]["empty"], 1)
        self.assertEqual(pv["attack_type_hint"], {"sqli": 2})
        self.assertIn("note", pv)


if __name__ == "__main__":
    unittest.main()