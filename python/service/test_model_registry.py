"""模型代际登记 / 保留策略 / 当前状态 测试（不触碰真实 console.db / artifacts）。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, model_registry as reg


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        art = root / "artifacts"
        art.mkdir(parents=True, exist_ok=True)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "ARTIFACTS", art),
            mock.patch.object(config, "MODELS", art / "models"),
            mock.patch.object(config, "STAGING", art / "staging"),
            mock.patch.object(config, "SWITCH_BACKUP", art / "switch_backup"),
            mock.patch.object(config, "CURVES", art / "curves"),
            mock.patch.object(config, "POLICY_JSON", art / "decision_policy.json"),
            mock.patch.object(config, "FEATURE_NAMES", art / "feature_names_v2.json"),
            mock.patch.object(config, "COLLECTOR_METRICS", root / "collector-metrics.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.art = art

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def make_staging(self, kind: str, tag: str, trees: int = 5, parent: str | None = None):
        staging = config.STAGING / f"task_{tag}"
        (staging / "curves").mkdir(parents=True, exist_ok=True)
        (staging / "model.onnx").write_bytes(f"onnx-{tag}".encode())
        if kind == "train_realdata":
            meta = {"feature_names": ["a", "b"], "labels": {"0": "normal", "1": "sqli"},
                    "features_version": "v2",
                    "metrics": {"n_trees": trees, "test": {"accuracy": 0.9, "auc_binary": 0.95}},
                    "training_recipe": {"hard_neg": "lexical"}}
            (staging / "xgboost_meta.json").write_text(json.dumps(meta), encoding="utf-8")
            (staging / "xgb_model.json").write_text('{"x":1}', encoding="utf-8")
            (staging / "xgb_trees.json").write_text("[]", encoding="utf-8")
        else:
            meta = {"n_features": 2, "trees": trees, "max_samples": 256,
                    "zero_day_threshold": {"detect": {"0.01": 0.5}}}
            (staging / "iforest_meta.json").write_text(json.dumps(meta), encoding="utf-8")
            (staging / "iforest_model.joblib").write_bytes(b"joblib")
        (staging / "curves" / f"{tag}_curve.json").write_text(
            json.dumps({"run": tag, "series": {"a": [[1, 1.0]]}}), encoding="utf-8")
        return staging

    def register(self, kind: str, tag: str, **kw):
        staging = self.make_staging(kind, tag)
        return reg.register_from_staging(None, kind, "tester", staging, **kw)

    # -- tests -----------------------------------------------------------
    def test_register_creates_generation_and_snapshot(self):
        m = self.register("train_realdata", "s1")
        self.assertIsNotNone(m)
        self.assertEqual(m["channel"], "supervised")
        self.assertEqual(m["generation"], 1)
        self.assertEqual(m["status"], "candidate")
        self.assertTrue(m["trainable"])
        self.assertTrue(m["snapshot_available"])
        self.assertTrue(m["curve_available"])
        self.assertEqual(m["feature_dim"], 2)
        # staging 已被消费
        self.assertFalse((config.STAGING / "task_s1").exists())

    def test_dedupe_by_sha(self):
        a = self.register("train_realdata", "dup")
        b = self.register("train_realdata", "dup")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(db.scalar("SELECT COUNT(*) FROM model_registry"), 1)

    def test_prune_respects_double_cap_and_keeps_active(self):
        reg.update_settings({"max_per_channel": 2, "max_total": 3, "keep_curves": True}, "tester")
        models = []
        for i in range(5):
            models.append(self.register("train_realdata", f"g{i}"))
        # 标记第一个为现役
        db.execute("UPDATE model_registry SET status='active' WHERE id=?", (models[0]["id"],))
        out = reg.prune(actor="tester", dry_run=False)
        alive = db.rows("SELECT id, status FROM model_registry WHERE status <> 'pruned'")
        self.assertLessEqual(len(alive), 3)
        self.assertEqual(db.one("SELECT status FROM model_registry WHERE id=?",
                                (models[0]["id"],))["status"], "active")
        pruned = db.rows("SELECT id, snapshot_dir, curve_path FROM model_registry "
                         "WHERE status='pruned'")
        self.assertTrue(pruned)
        for r in pruned:
            self.assertIsNone(r["snapshot_dir"])
            self.assertTrue(r["curve_path"])  # keep_curves 保留曲线
        self.assertLessEqual(out["counts_after"]["total"], 3)
        self.assertLessEqual(out["counts_after"]["by_channel"]["supervised"], 2)

    def test_settings_validation(self):
        with self.assertRaises(ValueError):
            reg.update_settings({"max_per_channel": 0}, "tester")
        with self.assertRaises(ValueError):
            reg.update_settings({"inherit_mode": "nope"}, "tester")
        with self.assertRaises(ValueError):
            reg.update_settings({"bogus": 1}, "tester")
        out = reg.update_settings({"max_total": 7}, "tester")
        self.assertEqual(out["max_total"], 7)

    def test_patch_rename_and_notes(self):
        m = self.register("iforest_csic", "z1")
        r = reg.patch_model(m["id"], "  零点  模型 ", "只用于测试", "analyst")
        self.assertEqual(r["display_name"], "零点 模型")
        self.assertEqual(r["notes"], "只用于测试")
        with self.assertRaises(ValueError):
            reg.patch_model(m["id"], "   ", None, "analyst")

    def test_current_state_matches_policy_sha(self):
        m = self.register("train_realdata", "cur")
        live = config.ARTIFACTS / config.LIVE_SLOTS["supervised"]["onnx"]
        live.write_bytes((config.ARTIFACTS / "models" / "supervised").glob("*/model.onnx")
                         .__next__().read_bytes())
        # 零日槽位也放点东西，避免 current_state 直接报缺文件
        (config.ARTIFACTS / config.LIVE_SLOTS["zero_day"]["onnx"]).write_bytes(b"if")
        (config.ARTIFACTS / config.LIVE_SLOTS["zero_day"]["meta"]).write_text("{}", encoding="utf-8")
        pol = {"version": 3, "supervised": {"artifact": live.name, "artifact_sha1_16": m["sha1_16"]},
               "zero_day": {"artifact": config.LIVE_SLOTS["zero_day"]["onnx"]}}
        config.POLICY_JSON.write_text(json.dumps(pol), encoding="utf-8")
        db.execute("UPDATE model_registry SET status='active' WHERE id=?", (m["id"],))
        st = reg.current_state()
        sup = st["channels"]["supervised"]
        self.assertEqual(sup["policy_sha1_16"], m["sha1_16"])
        self.assertEqual(sup["disk_sha1_16"], m["sha1_16"])
        self.assertEqual(sup["state"], "collector_unknown")
        self.assertEqual(sup["model"]["id"], m["id"])

    def test_resolve_parent_falls_back_to_active(self):
        first = self.register("train_realdata", "p1")
        db.execute("UPDATE model_registry SET status='active' WHERE id=?", (first["id"],))
        parent = reg.resolve_parent("supervised", None)
        self.assertEqual(parent["id"], first["id"])
        # 显式指定不存在的父代 -> 报错
        with self.assertRaises(ValueError):
            reg.resolve_parent("supervised", 999999)

    def test_eligible_parents_only_trainable(self):
        a = self.register("iforest_csic", "e1")
        b = self.register("iforest_csic", "e2")
        rows = reg.eligible_parents("zero_day")
        self.assertEqual({r["id"] for r in rows}, {a["id"], b["id"]})


if __name__ == "__main__":
    unittest.main()
