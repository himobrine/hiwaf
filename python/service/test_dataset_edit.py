"""数据集可修改：逐条改标签 / 追加重采样（不碰真实 console.db / traindata）。"""
from __future__ import annotations

import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, uploads
from . import datasets_events as de


class DatasetEditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "UPLOADS", root / "uploads"),
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

    # ---- helpers --------------------------------------------------------
    def _wait_ready(self, uid, timeout=30.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            row = uploads.get_upload(uid)
            if row and row["status"] in ("ready", "failed"):
                return row
            time.sleep(0.2)
        self.fail("转换超时")

    def _csv_dataset(self, *, role="supervised", labels=(0, 1, 1)):
        csv = "method,path,query,body,label\n" + "".join(
            f"GET,/p{i},id={i},,{lab}\n" for i, lab in enumerate(labels))
        row = uploads.create_from_stream(
            io.BytesIO(csv.encode()), "x.csv", name="d", role=role,
            source_note="unit", actor="tester")
        ready = self._wait_ready(row["id"])
        self.assertEqual(ready["status"], "ready", ready.get("error"))
        return ready

    def _event(self, i, *, path, query="", action="block", score=0.9,
               attack_type="sqli", body=""):
        eid = int(db.execute(
            "INSERT INTO events(ts, ingest_ts, src_ip, method, path, query, body_len, "
            "status, action, supervised_score, attack_type) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (1_700_000_000_000 + i, 1_700_000_000_000 + i, "10.0.0.1", "GET",
             path, query, len(body), 200, action, score, attack_type)))
        if body:
            db.execute("INSERT INTO event_bodies(event_id, body) VALUES(?,?)",
                       (eid, body))
        return eid

    def _rows(self, uid):
        row = uploads.get_upload(uid)
        return uploads.read_rows(Path(row["dir"]))

    # ---- 逐条改标签 ----------------------------------------------------
    def test_list_rows_and_relabel(self):
        ready = self._csv_dataset()
        uid = ready["id"]
        page = uploads.list_rows(uid, offset=0, limit=2)
        self.assertEqual(page["total"], 3)
        self.assertEqual(len(page["items"]), 2)
        self.assertTrue(all(len(it["rid"]) == 16 for it in page["items"]))

        only_benign = uploads.list_rows(uid, label=0)
        self.assertEqual(only_benign["total"], 1)
        hit = uploads.list_rows(uid, q="/p2")
        self.assertEqual(hit["total"], 1)

        rid = hit["items"][0]["rid"]
        old_sha = ready["sha256"]
        out = uploads.relabel_rows(uid, [{"rid": rid, "label": 2}], actor="tester")
        self.assertNotEqual(out["sha256"], old_sha)
        self.assertEqual(out["label_stats"].get("2"), 1)
        rows = self._rows(uid)
        self.assertEqual(sum(1 for r in rows if int(r["label"]) == 2), 1)
        # 训练副本同步重建
        train = Path(out["train_path"])
        self.assertTrue(train.exists())
        self.assertEqual(len(uploads.read_rows(Path(out["dir"]))) , 3)
        self.assertEqual(
            sum(1 for line in train.read_text(encoding="utf-8").splitlines() if line),
            3)

    def test_relabel_benign_only_zero(self):
        ready = self._csv_dataset(role="benign", labels=(0, 0))
        uid = ready["id"]
        rid = uploads.list_rows(uid, limit=1)["items"][0]["rid"]
        with self.assertRaises(ValueError):
            uploads.relabel_rows(uid, [{"rid": rid, "label": 1}])
        # 改成 0 是允许的（无变化则直接返回）
        uploads.relabel_rows(uid, [{"rid": rid, "label": 0}])

    def test_relabel_blocked_by_running_task(self):
        ready = self._csv_dataset()
        uid = ready["id"]
        rid = uploads.list_rows(uid, limit=1)["items"][0]["rid"]
        db.execute(
            "INSERT INTO tasks(kind, args, status, created_at, actor) "
            "VALUES(?,?,?,?,?)",
            ("train_realdata", json.dumps({"dataset_ids": [uid]}), "running",
             db.now_ms(), "tester"))
        with self.assertRaises(ValueError):
            uploads.relabel_rows(uid, [{"rid": rid, "label": 1}])

    def test_relabel_unknown_rid(self):
        ready = self._csv_dataset()
        with self.assertRaises(ValueError):
            uploads.relabel_rows(ready["id"], [{"rid": "0" * 16, "label": 1}])

    # ---- 事件追加 / 重采样 ---------------------------------------------
    def test_append_and_replace(self):
        e1 = self._event(1, path="/a", query="id=1", body="x=1")
        e2 = self._event(2, path="/b", query="id=2")
        e3 = self._event(3, path="/c", query="id=3", action="alert", score=0.1)
        uid = de.create_from_events(
            name="ev", role="supervised", label=1, source_note="unit",
            mode="ids", event_ids=[e1, e2], actor="tester", wait=True)["id"]

        self.assertEqual(uploads.get_upload(uid)["rows_kept"], 2)
        rows = self._rows(uid)
        self.assertTrue(all(int(r["label"]) == 1 for r in rows))

        # append：新条件命中 e3，标签 2；已有行标签不动
        out = de.update_selection_from_events(
            uid=uid, action="append", mode="filter", filters={"path": "/c"},
            label=2, actor="tester")
        self.assertEqual(out["rows_kept"], 3)
        labels = sorted(int(r["label"]) for r in self._rows(uid))
        self.assertEqual(labels, [1, 1, 2])
        sel = json.loads((Path(out["dir"]) / "selection.json").read_text(encoding="utf-8"))
        self.assertEqual(len(sel.get("appends") or []), 1)

        # append 同一条不会重复计（按请求指纹去重）
        out2 = de.update_selection_from_events(
            uid=uid, action="append", mode="ids", event_ids=[e3], label=2,
            actor="tester")
        self.assertEqual(out2["rows_kept"], 3)

        # replace：整体重建，标签统一为 3
        out3 = de.update_selection_from_events(
            uid=uid, action="replace", mode="filter", filters={"action": "alert"},
            label=3, actor="tester")
        self.assertEqual(out3["rows_kept"], 1)
        rows3 = self._rows(uid)
        self.assertEqual(len(rows3), 1)
        self.assertEqual(int(rows3[0]["label"]), 3)

    def test_append_rejects_bad_label_and_empty(self):
        e1 = self._event(1, path="/a")
        uid = de.create_from_events(
            name="ev", role="benign", label=0, source_note="unit",
            mode="ids", event_ids=[e1], actor="tester", wait=True)["id"]
        with self.assertRaises(ValueError):
            de.update_selection_from_events(
                uid=uid, action="append", mode="filter", filters={"path": "/a"},
                label=1, actor="tester")
        with self.assertRaises(ValueError):
            de.update_selection_from_events(
                uid=uid, action="append", mode="filter", filters={"path": "/nope"},
                label=0, actor="tester")


if __name__ == "__main__":
    unittest.main()