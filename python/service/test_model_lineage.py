"""代际传承树（build_lineage）测试：只对结构做断言，不碰真实库。

覆盖：嵌套父子、多根、现役路径、父代缺失/自指/成环的降级、状态统计、
warm start 边统计、通道隔离与排序。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, model_registry as reg

CH = "supervised"


class LineageTest(unittest.TestCase):
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

    # ---- 造数 -------------------------------------------------------------
    def _model(self, channel: str, gen: int, *, parent_id=None, status="candidate",
               inherit_mode="full", current=False, name=None) -> int:
        now = db.now_ms()
        return db.execute(
            """INSERT INTO model_registry(
                 channel, variant, generation, display_name, artifact_name, sha1_16,
                 trainable, parent_id, inherit_mode, status, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (channel, "official", gen, name or f"model g{gen}", f"m{gen}.onnx",
             f"sha{channel}{gen}", 1, parent_id, inherit_mode, status, now, now),
        )

    def _lineage(self, active=()):
        models = reg.list_models()
        return reg.build_lineage(models, active)

    # ---- 测试 -------------------------------------------------------------
    def test_nested_tree_and_current_path(self):
        g1 = self._model(CH, 1, status="archived")
        g2 = self._model(CH, 2, parent_id=g1, status="active")
        g3 = self._model(CH, 3, parent_id=g2, status="candidate",
                         inherit_mode="warm_start")
        out = self._lineage(active=[g2])
        ch = out["channels"][CH]
        self.assertEqual(ch["n"], 3)
        self.assertEqual(len(ch["tree"]), 1)
        self.assertEqual(ch["roots"], [g1])
        self.assertEqual(ch["current_id"], g2)
        self.assertEqual(ch["path_to_current"], [g1, g2])
        self.assertEqual(ch["max_generation"], 3)

        root = ch["tree"][0]
        self.assertEqual(root["id"], g1)
        self.assertEqual(root["children"][0]["id"], g2)
        self.assertEqual(root["children"][0]["children"][0]["id"], g3)
        self.assertEqual(root["children"][0]["children"][0]["depth"], 2)
        self.assertEqual(ch["stats"]["edges"], 2)
        self.assertEqual(ch["stats"]["warm_start_edges"], 1)
        self.assertEqual(ch["stats"]["depth"], 2)
        self.assertEqual(ch["stats"]["by_status"],
                         {"archived": 1, "active": 1, "candidate": 1})
        self.assertEqual(ch["orphans"], [])

    def test_multiple_roots_sorted_by_generation(self):
        # 两条独立血脉 + 一个更早的孤根（g1 之前不会有，这里用 generation 排序验证）
        a1 = self._model(CH, 1, status="archived")
        a2 = self._model(CH, 2, parent_id=a1)
        b1 = self._model(CH, 5, status="archived")
        out = self._lineage()
        ch = out["channels"][CH]
        self.assertEqual(ch["roots"], [a1, b1])
        self.assertEqual([n["id"] for n in ch["tree"]], [a1, b1])
        self.assertEqual(ch["tree"][0]["children"][0]["id"], a2)
        self.assertIsNone(ch["current_id"])
        self.assertEqual(ch["path_to_current"], [])

    def test_children_sorted_by_generation(self):
        root = self._model(CH, 1)
        g3 = self._model(CH, 3, parent_id=root)
        g2 = self._model(CH, 2, parent_id=root)
        out = self._lineage()
        kids = [n["id"] for n in out["channels"][CH]["tree"][0]["children"]]
        self.assertEqual(kids, [g2, g3])

    def test_missing_parent_becomes_orphan_root(self):
        child = self._model(CH, 2, parent_id=9999)
        out = self._lineage()
        ch = out["channels"][CH]
        self.assertEqual(ch["roots"], [child])
        self.assertEqual(ch["orphans"], [{"id": child, "parent_id": 9999,
                                          "reason": "missing"}])
        self.assertEqual(ch["tree"][0]["id"], child)

    def test_self_parent_is_detached(self):
        a = self._model(CH, 1)
        db.execute("UPDATE model_registry SET parent_id=? WHERE id=?", (a, a))
        out = self._lineage()
        ch = out["channels"][CH]
        self.assertEqual(ch["n"], 1)
        self.assertEqual(ch["roots"], [a])
        self.assertEqual(ch["orphans"][0]["reason"], "self")
        self.assertEqual(ch["tree"][0]["children"], [])

    def test_cycle_is_broken_and_still_renderable(self):
        a = self._model(CH, 1)
        b = self._model(CH, 2, parent_id=a)
        # a -> b 手工造环
        db.execute("UPDATE model_registry SET parent_id=? WHERE id=?", (b, a))
        out = self._lineage()
        ch = out["channels"][CH]
        self.assertEqual(ch["n"], 2)
        self.assertEqual(sum(1 for n in ch["orphans"] if n["reason"] == "cycle"), 1)
        # 仍是一棵可渲染的树：两个节点都在，且没有无限递归
        ids = set()

        def walk(n):
            ids.add(n["id"])
            for c in n["children"]:
                walk(c)

        for root in ch["tree"]:
            walk(root)
        self.assertEqual(ids, {a, b})

    def test_channels_are_separated(self):
        s1 = self._model("supervised", 1)
        z1 = self._model("zero_day", 1)
        out = self._lineage(active=[z1])
        self.assertEqual(out["channels"]["supervised"]["roots"], [s1])
        self.assertEqual(out["channels"]["zero_day"]["roots"], [z1])
        self.assertEqual(out["channels"]["zero_day"]["current_id"], z1)
        self.assertIsNone(out["channels"]["supervised"]["current_id"])

    def test_empty_channel(self):
        out = self._lineage()
        for ch in ("supervised", "zero_day"):
            payload = out["channels"][ch]
            self.assertEqual(payload["n"], 0)
            self.assertEqual(payload["tree"], [])
            self.assertEqual(payload["max_generation"], 0)
            self.assertEqual(payload["path_to_current"], [])


if __name__ == "__main__":
    unittest.main()
