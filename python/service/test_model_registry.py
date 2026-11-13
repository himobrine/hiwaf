"""模型代际登记 / 保留策略 / 当前状态 测试（不触碰真实 console.db / artifacts）。"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, model_registry as reg


class RegistryTest(unittest.TestCase):
    """模型代际登记 / 保留策略 / 当前状态 测试（不触碰真实 console.db / artifacts）。"""
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
            mock.patch.object(config, "REGISTRY_SEED", art / "registry_seed.json"),
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


class SeedImportTest(unittest.TestCase):
    """预置代次清单（随仓库发布）的导入。复用 RegistryTest 的临时环境夹具。"""

    setUp = RegistryTest.setUp
    tearDown = RegistryTest.tearDown
    register = RegistryTest.register
    make_staging = RegistryTest.make_staging

    def make_snapshot(self, channel: str, gen: int, tag: str, trees: int = 5):
        snap = config.MODELS / channel / f"gen-{gen:04d}-{tag}"
        snap.mkdir(parents=True, exist_ok=True)
        (snap / "model.onnx").write_bytes(f"onnx-{channel}-{gen}-{tag}".encode())
        if channel == "supervised":
            (snap / "xgboost_meta.json").write_text("{}", encoding="utf-8")
            (snap / "xgb_model.json").write_text("{}", encoding="utf-8")
        else:
            (snap / "iforest_meta.json").write_text(
                json.dumps({"trees": trees}), encoding="utf-8")
            (snap / "iforest_model.joblib").write_bytes(b"joblib")
        rel = f"models/{channel}/{snap.name}"
        return snap, rel, reg.sha1_16_file(snap / "model.onnx")

    def write_seed(self, items):
        config.REGISTRY_SEED.write_text(
            json.dumps({"schema": 1, "models": items}, ensure_ascii=False), encoding="utf-8")

    def write_policy(self, sup_sha, zd_sha=None):
        payload = {"supervised": {"artifact": "xgboost_v20261015_001.onnx",
                                  "artifact_sha1_16": sup_sha}}
        if zd_sha:
            payload["zero_day"] = {"artifact": "iforest_lean_v20261015_001.onnx",
                                   "artifact_sha1_16": zd_sha}
        config.POLICY_JSON.write_text(json.dumps(payload), encoding="utf-8")

    def write_live(self, channel, snap):
        live = config.LIVE_SLOTS[channel]
        shutil.copy2(snap / "model.onnx", config.ARTIFACTS / live["onnx"])

    def test_import_seed_builds_lineage(self):
        snap1, rel1, sha1 = self.make_snapshot("supervised", 1, "aaaa11112222")
        snap2, rel2, sha2 = self.make_snapshot("supervised", 2, "bbbb33334444")
        self.write_seed([
            {"channel": "supervised", "generation": 1, "display_name": "XGBoost g1",
             "artifact_name": "xgboost_v20261015_001.onnx", "snapshot_dir": rel1,
             "sha1_16": sha1, "bytes": 1, "meta_path": f"{rel1}/xgboost_meta.json",
             "trainable": True, "parent_generation": None, "status": "archived",
             "created_at": 1000, "activated_at": 1000, "retired_at": 2000},
            {"channel": "supervised", "generation": 2, "display_name": "XGBoost g2",
             "artifact_name": "xgboost_v20261015_001.onnx", "snapshot_dir": rel2,
             "sha1_16": sha2, "bytes": 2, "meta_path": f"{rel2}/xgboost_meta.json",
             "trainable": True, "parent_generation": 1, "inherit_mode": "warm_start",
             "status": "active", "created_at": 2000, "activated_at": 2000},
        ])
        out = reg.import_seed("tester")
        self.assertEqual(out["imported"], 2, out)
        self.assertEqual(out["skipped"], [])

        models = reg.list_models("supervised")
        self.assertEqual([m["generation"] for m in models], [2, 1])
        by_gen = {m["generation"]: m for m in models}
        self.assertEqual(by_gen[2]["parent_id"], by_gen[1]["id"])
        self.assertEqual(by_gen[2]["status"], "active")
        self.assertTrue(by_gen[2]["snapshot_available"])
        self.assertTrue(by_gen[2]["trainable"])
        self.assertTrue(by_gen[1]["trainable"])

        lin = reg.build_lineage(models, active_ids=[by_gen[2]["id"]])
        ch = lin["channels"]["supervised"]
        self.assertEqual(ch["orphans"], [])
        self.assertEqual(ch["path_to_current"], [by_gen[1]["id"], by_gen[2]["id"]])
        self.assertEqual(ch["stats"]["warm_start_edges"], 1)

    def test_import_seed_skips_sha_mismatch(self):
        snap, rel, sha = self.make_snapshot("zero_day", 1, "cccc55556666")
        self.write_seed([{
            "channel": "zero_day", "generation": 1, "snapshot_dir": rel,
            "sha1_16": "0" * 16, "meta_path": f"{rel}/iforest_meta.json",
            "status": "active",
        }])
        out = reg.import_seed("tester")
        self.assertEqual(out["imported"], 0)
        self.assertEqual(out["reason"], "nothing_imported")
        self.assertEqual(out["skipped"][0]["reason"], "sha1 不一致")
        self.assertEqual(out["skipped"][0]["actual"], sha)
        self.assertEqual(reg.list_models(), [])

    def test_import_seed_is_noop_when_not_empty(self):
        self.register("train_realdata", "n1")
        before = len(reg.list_models())
        out = reg.import_seed("tester")
        self.assertEqual(out["reason"], "not_empty")
        self.assertEqual(len(reg.list_models()), before)

    def test_import_seed_downgrades_second_active(self):
        _, rel1, sha1 = self.make_snapshot("zero_day", 1, "dddd77778888")
        _, rel2, sha2 = self.make_snapshot("zero_day", 2, "eeee99990000")
        self.write_seed([
            {"channel": "zero_day", "generation": 1, "snapshot_dir": rel1,
             "sha1_16": sha1, "meta_path": f"{rel1}/iforest_meta.json", "status": "active"},
            {"channel": "zero_day", "generation": 2, "snapshot_dir": rel2,
             "sha1_16": sha2, "meta_path": f"{rel2}/iforest_meta.json",
             "parent_generation": 1, "status": "active"},
        ])
        out = reg.import_seed("tester")
        self.assertEqual(out["imported"], 2)
        self.assertEqual(len(out["downgraded"]), 1)
        actives = [m for m in reg.list_models("zero_day") if m["status"] == "active"]
        self.assertEqual([m["generation"] for m in actives], [2])

    # -- 升级：非空库补缺失代次（g3 场景） ------------------------------
    def _seed_item(self, channel, gen, rel, sha, status, parent=None):
        meta = "xgboost_meta.json" if channel == "supervised" else "iforest_meta.json"
        item = {"channel": channel, "generation": gen, "snapshot_dir": rel,
                "sha1_16": sha, "meta_path": f"{rel}/{meta}", "status": status}
        if parent is not None:
            item["parent_generation"] = parent
        return item

    def test_merge_seed_adds_missing_generation_to_nonempty_db(self):
        _, rel1, sha1 = self.make_snapshot("supervised", 1, "aaaa00001111")
        _, rel2, sha2 = self.make_snapshot("supervised", 2, "bbbb22223333")
        self.write_seed([
            self._seed_item("supervised", 1, rel1, sha1, "archived"),
            self._seed_item("supervised", 2, rel2, sha2, "active", parent=1),
        ])
        self.assertEqual(reg.import_seed("tester")["imported"], 2)

        # 模拟 git pull 带来 g3：非空库默认导入仍是 no-op
        _, rel3, sha3 = self.make_snapshot("supervised", 3, "cccc44445555")
        self.write_seed([
            self._seed_item("supervised", 1, rel1, sha1, "archived"),
            self._seed_item("supervised", 2, rel2, sha2, "archived", parent=1),
            self._seed_item("supervised", 3, rel3, sha3, "active", parent=2),
        ])
        self.assertEqual(reg.import_seed("tester")["reason"], "not_empty")

        out = reg.import_seed("tester", merge=True)
        self.assertEqual(out["imported"], 1, out)
        by_gen = {m["generation"]: m for m in reg.list_models("supervised")}
        self.assertEqual(by_gen[3]["parent_id"], by_gen[2]["id"])
        self.assertTrue(by_gen[3]["snapshot_available"])
        # 已有现役不被清单顶掉（真正生效由 sync_seed 按策略决定）
        self.assertEqual(by_gen[2]["status"], "active")
        self.assertEqual(by_gen[3]["status"], "archived")
        self.assertEqual(len(out["downgraded"]), 1)

        # 幂等：再 merge 一次不新增、不报唯一索引错误
        again = reg.import_seed("tester", merge=True)
        self.assertEqual(again["imported"], 0)
        self.assertEqual(again["reason"], "nothing_imported")
        self.assertEqual(len(reg.list_models("supervised")), 3)

    def test_sync_seed_activates_policy_model_after_upgrade(self):
        _, rel1, sha1 = self.make_snapshot("supervised", 1, "aaaa66667777")
        _, rel2, sha2 = self.make_snapshot("supervised", 2, "bbbb88889999")
        self.write_seed([
            self._seed_item("supervised", 1, rel1, sha1, "archived"),
            self._seed_item("supervised", 2, rel2, sha2, "active", parent=1),
        ])
        reg.import_seed("tester")

        snap3, rel3, sha3 = self.make_snapshot("supervised", 3, "ccccaaaabbbb")
        self.write_seed([
            self._seed_item("supervised", 1, rel1, sha1, "archived"),
            self._seed_item("supervised", 2, rel2, sha2, "archived", parent=1),
            self._seed_item("supervised", 3, rel3, sha3, "active", parent=2),
        ])
        self.write_live("supervised", snap3)
        self.write_policy(sha3)

        out = reg.sync_seed("tester")
        self.assertEqual(out["seed"]["imported"], 1, out)
        acts = {r["channel"]: r for r in out["reconciled"]}
        self.assertEqual(acts["supervised"]["action"], "activated")
        by_gen = {m["generation"]: m for m in reg.list_models("supervised")}
        self.assertEqual(by_gen[3]["status"], "active")
        self.assertEqual(by_gen[2]["status"], "archived")

    def test_sync_seed_keeps_user_active_model(self):
        models = [self.register("train_realdata", f"u{i}") for i in range(5)]
        custom = models[-1]
        db.execute("UPDATE model_registry SET status='active' WHERE id=?", (custom["id"],))
        custom_snap = reg._artifact_path(custom["snapshot_dir"])

        snap3, rel3, sha3 = self.make_snapshot("supervised", 6, "ccccccccdddd")
        self.write_seed([self._seed_item("supervised", 6, rel3, sha3, "active", parent=None)])
        self.write_live("supervised", custom_snap)
        self.write_policy(custom["sha1_16"])

        out = reg.sync_seed("tester")
        self.assertEqual(out["seed"]["imported"], 1, out)
        by_gen = {m["generation"]: m for m in reg.list_models("supervised")}
        self.assertEqual(by_gen[6]["status"], "archived")
        self.assertEqual(by_gen[custom["generation"]]["status"], "active")
        acts = {r["channel"]: r for r in out["reconciled"]}
        self.assertEqual(acts["supervised"]["action"], "already_active")


if __name__ == "__main__":
    unittest.main()
