"""增量 ingest：只读完整行、按字节偏移续读，并保持幂等。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, ingest


def _rec(n: int) -> dict:
    return {
        "ts": 1792632000000 + n,
        "src_ip": "127.0.0.1",
        "src_port": 40000 + n,
        "method": "GET",
        "path": f"/p{n}",
        "query": "",
        "pred": {"action": "allow"},
    }


class IncrementalIngestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "RAW_DIR", root / "raw"),
        ]
        for p in self.patches:
            p.start()
        config.RAW_DIR.mkdir(parents=True)
        db.init()
        self.fp = config.RAW_DIR / "raw-20261022-00000.jsonl"

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _append(self, text: str) -> None:
        with open(self.fp, "a", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def _line(self, n: int) -> str:
        return json.dumps(_rec(n), ensure_ascii=False) + "\n"

    def test_append_resumes_at_offset(self):
        self._append(self._line(1))
        st = ingest.ingest()
        self.assertEqual(st["inserted"], 1)

        # 没有新内容时不重复入库。
        st = ingest.ingest()
        self.assertEqual(st["inserted"], 0)

        self._append(self._line(2))
        st = ingest.ingest()
        self.assertEqual(st["inserted"], 1)
        self.assertEqual(db.scalar("SELECT COUNT(*) FROM events"), 2)

        row = db.one("SELECT size, lines, offset FROM ingest_state")
        self.assertEqual(row["lines"], 2)
        self.assertEqual(row["offset"], self.fp.stat().st_size)
        self.assertEqual(row["size"], self.fp.stat().st_size)

    def test_incomplete_tail_is_not_consumed(self):
        self._append(self._line(1))
        ingest.ingest()
        partial = json.dumps(_rec(2), ensure_ascii=False)
        self._append(partial)
        offset_before = db.scalar("SELECT offset FROM ingest_state")

        st = ingest.ingest()
        self.assertEqual(st["inserted"], 0)
        self.assertEqual(db.scalar("SELECT COUNT(*) FROM events"), 1)
        self.assertEqual(db.scalar("SELECT offset FROM ingest_state"), offset_before)

        # 下一轮补上换行后才消费。
        self._append("\n")
        st = ingest.ingest()
        self.assertEqual(st["inserted"], 1)
        self.assertEqual(db.scalar("SELECT COUNT(*) FROM events"), 2)
        self.assertEqual(db.scalar("SELECT offset FROM ingest_state"),
                         self.fp.stat().st_size)


if __name__ == "__main__":
    unittest.main()
