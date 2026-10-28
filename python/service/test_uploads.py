"""上传数据存储/转换/软删除测试（不碰真实 console.db / traindata）。"""
from __future__ import annotations

import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, uploads


class UploadStoreTest(unittest.TestCase):
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

    def _wait_ready(self, uid, timeout=30.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            row = uploads.get_upload(uid)
            if row and row["status"] in ("ready", "failed"):
                return row
            time.sleep(0.2)
        self.fail("转换超时")

    def test_csv_roundtrip_and_preview(self):
        csv = (b"method,path,label\n"
               b"GET,/a,0\nGET,/b,1\n")
        row = uploads.create_from_stream(
            io.BytesIO(csv), "x.csv", name="demo", role="supervised",
            source_note="unit-test", actor="tester")
        ready = self._wait_ready(row["id"])
        self.assertEqual(ready["status"], "ready", ready.get("error"))
        self.assertEqual(ready["rows_kept"], 2)
        self.assertTrue(Path(ready["train_path"]).exists())
        pv = uploads.preview(row["id"], n=10)
        self.assertEqual(len(pv["items"]), 2)
        self.assertEqual(pv["dataset"]["label_stats"]["1"], 1)

    def test_reject_bad_format_and_empty(self):
        with self.assertRaises(ValueError):
            uploads.create_from_stream(io.BytesIO(b"x"), "a.txt", role="supervised",
                                       source_note="n")
        with self.assertRaises(ValueError):
            uploads.create_from_stream(io.BytesIO(b""), "a.csv", role="supervised",
                                       source_note="n")
        with self.assertRaises(ValueError):
            uploads.create_from_stream(io.BytesIO(b"a"), "a.csv", role="supervised",
                                       source_note="")

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            uploads.create_from_stream(io.BytesIO(b"a,b\n" * 100), "a.csv",
                                       role="supervised", source_note="n",
                                       max_bytes=16)

    def test_delete_soft_and_blocked_by_task(self):
        csv = b"method,path,label\nGET,/a,0\n"
        row = uploads.create_from_stream(io.BytesIO(csv), "x.csv", role="benign",
                                         source_note="n", actor="tester")
        ready = self._wait_ready(row["id"])
        # 被运行中任务引用 -> 拒绝删除
        db.execute("INSERT INTO tasks(kind, args, status, created_at) VALUES(?,?,?,?)",
                   ("train_realdata", json.dumps({"dataset_ids": [ready["id"]]}),
                    "running", db.now_ms()))
        with self.assertRaises(ValueError):
            uploads.delete_upload(ready["id"], "tester")
        db.execute("UPDATE tasks SET status='ok'")
        out = uploads.delete_upload(ready["id"], "tester")
        self.assertEqual(out["status"], "pruned")
        self.assertFalse(Path(ready["dir"]).exists())

    def test_cleanup_stale(self):
        db.execute(
            "INSERT INTO uploaded_datasets(name, role, format, status, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?)",
            ("stale", "benign", "csv", "converting", db.now_ms(), db.now_ms()))
        n = uploads.cleanup_stale()
        self.assertGreaterEqual(n, 1)
        self.assertTrue(all(r["status"] != "converting" for r in uploads.list_uploads()))


if __name__ == "__main__":
    unittest.main()
