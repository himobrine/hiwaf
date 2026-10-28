"""切换现役 / 回滚编排测试（子进程与门禁二进制全部 mock，不碰真实产物）。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, model_registry as reg, model_switch, toolchain


class SwitchTest(unittest.TestCase):
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
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)

        # 现役槽位（备份源）
        live = config.LIVE_SLOTS["supervised"]
        for name in ("xgboost_v20261015_001.onnx", "xgboost_meta.json",
                     "xgb_model.json", "xgb_trees.json"):
            (art / name).write_bytes(b"OLD-" + name.encode())
        (art / "iforest_lean_v20261015_001.onnx").write_bytes(b"OLD-if")
        (art / "iforest_meta.json").write_text("{}", encoding="utf-8")
        config.POLICY_JSON.write_text(json.dumps({"version": 1}), encoding="utf-8")
        (art / "testvec.json").write_text("{}", encoding="utf-8")
        (art / "shap_ref.json").write_text("{}", encoding="utf-8")

        # 训练产物 -> 登记为一代
        staging = config.STAGING / "task_1"
        staging.mkdir(parents=True)
        (staging / "model.onnx").write_bytes(b"NEW-ONNX")
        (staging / "xgboost_meta.json").write_text(
            json.dumps({"feature_names": ["a", "b"], "labels": {"0": "normal", "1": "sqli"},
                        "features_version": "v2"}), encoding="utf-8")
        (staging / "xgb_model.json").write_text('{"x":1}', encoding="utf-8")
        (staging / "xgb_trees.json").write_text("[]", encoding="utf-8")
        self.model = reg.register_from_staging(None, "train_realdata", "tester", staging)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def _fake_proto(self):
        p = self.art / "waf-ai-proto.exe"
        p.write_text("", encoding="utf-8")
        return p

    def test_preflight_ok(self):
        with mock.patch.object(toolchain, "find_proto", return_value=self._fake_proto()):
            pf = model_switch.preflight(self.model["id"])
        self.assertTrue(pf["ok"], pf["checks"])

    def test_preflight_allows_zero_day_without_joblib(self):
        """老 IForest 产物没有 joblib 时，仍应允许切换/回滚（只影响 warm start）。"""
        staging = config.STAGING / "task_if"
        staging.mkdir(parents=True)
        (staging / "model.onnx").write_bytes(b"IF-ONNX")
        (staging / "iforest_meta.json").write_text(
            json.dumps({"feature_names": ["a", "b"], "features_version": "v2"}),
            encoding="utf-8")
        m = reg.register_from_staging(None, "iforest_csic", "tester", staging)
        self.assertIsNotNone(m)
        self.assertFalse(m["trainable"])
        with mock.patch.object(toolchain, "find_proto", return_value=self._fake_proto()):
            pf = model_switch.preflight(m["id"])
        self.assertTrue(pf["ok"], pf["checks"])
        self.assertTrue(any("iforest_model.joblib" in c["name"] for c in pf["checks"]))

    def test_preflight_rejects_pruned(self):
        db.execute("UPDATE model_registry SET status='pruned', snapshot_dir=NULL WHERE id=?",
                   (self.model["id"],))
        with mock.patch.object(toolchain, "find_proto", return_value=self._fake_proto()):
            pf = model_switch.preflight(self.model["id"])
        self.assertFalse(pf["ok"])

    def test_switch_success_commits_and_bumps_policy(self):
        calls = []

        def fake_run(cmd, fp, **kw):
            calls.append([str(c) for c in cmd])
            if any("thresholds.py" in str(c) for c in cmd):
                config.POLICY_JSON.write_text(json.dumps({"version": 2}), encoding="utf-8")
            return 0

        with mock.patch.object(toolchain, "find_proto", return_value=self._fake_proto()), \
             mock.patch.object(model_switch, "_run", side_effect=fake_run):
            out = model_switch.create_switch(self.model["id"], "admin")
            with open(config.LOG_DIR / "switch.log", "w", encoding="utf-8") as fp:
                res = model_switch.run_switch(out["switch_id"], fp)

        self.assertTrue(res["ok"], res)
        # 现役槽位文件已被替换成快照内容
        self.assertEqual((self.art / "xgboost_v20261015_001.onnx").read_bytes(), b"NEW-ONNX")
        # 登记状态：目标 -> active
        self.assertEqual(db.one("SELECT status FROM model_registry WHERE id=?",
                                (self.model["id"],))["status"], "active")
        sw = db.one("SELECT * FROM model_switches WHERE id=?", (out["switch_id"],))
        self.assertEqual(sw["status"], "ok")
        self.assertEqual(sw["policy_version_after"], 2)
        # 全流程命令：thresholds -> export_testvec -> export_shap_ref -> proto
        flat = " ".join(" ".join(c) for c in calls)
        self.assertIn("thresholds.py", flat)
        self.assertIn("export_testvec.py", flat)
        self.assertIn("export_shap_ref.py", flat)

    def test_switch_failure_rolls_back_files(self):
        def fake_run(cmd, fp, **kw):
            return 3  # thresholds 失败

        with mock.patch.object(toolchain, "find_proto", return_value=self._fake_proto()), \
             mock.patch.object(model_switch, "_run", side_effect=fake_run):
            out = model_switch.create_switch(self.model["id"], "admin")
            with open(config.LOG_DIR / "switch_fail.log", "w", encoding="utf-8") as fp:
                res = model_switch.run_switch(out["switch_id"], fp)

        self.assertFalse(res["ok"])
        # 回滚：现役槽位恢复为原内容
        self.assertEqual((self.art / "xgboost_v20261015_001.onnx").read_bytes(),
                         b"OLD-xgboost_v20261015_001.onnx")
        self.assertEqual(db.one("SELECT status FROM model_registry WHERE id=?",
                                (self.model["id"],))["status"], "candidate")
        self.assertEqual(db.one("SELECT status FROM model_switches WHERE id=?",
                                (out["switch_id"],))["status"], "failed")

    def test_upload_calibration_pool_is_used_by_thresholds(self):
        staging = config.STAGING / "task_up"
        staging.mkdir(parents=True)
        (staging / "model.onnx").write_bytes(b"UP-ONNX")
        (staging / "xgb_model.json").write_text("{}", encoding="utf-8")
        (staging / "calibration_pool.jsonl").write_text(
            "\n".join(json.dumps({"method": "GET", "path": f"/p{i}", "query": "",
                                  "body": "", "label": 0}) for i in range(250)) + "\n",
            encoding="utf-8")
        (staging / "training_keys.txt").write_text("a" * 40 + "\n", encoding="utf-8")
        (staging / "xgboost_meta.json").write_text(json.dumps({
            "feature_names": ["a", "b"], "features_version": "v2",
            "datasets": [{"id": 3, "name": "demo"}],
            "upload": {"mode": "add", "calib": {"source": "upload:3",
                                                "file": "calibration_pool.jsonl", "n": 250}},
            "training_keys_file": "training_keys.txt"}), encoding="utf-8")
        m = reg.register_from_staging(None, "train_realdata", "tester", staging)
        self.assertIsNotNone(m)
        up = model_switch._model_upload_files(m)
        self.assertTrue(Path(up["calib_pool"]).exists())
        args = model_switch._threshold_args({"version": 1}, m)
        self.assertIn("--pool", args)
        self.assertTrue(any(str(a).startswith("file:") for a in args))
        self.assertIn("--train-keys", args)
        with mock.patch.object(toolchain, "find_proto", return_value=self._fake_proto()):
            pf = model_switch.preflight(m["id"])
        self.assertTrue(pf["ok"], pf["checks"])

    def test_rollback_target_points_to_previous_active(self):
        # 造一条成功切换记录：from_model_id = 999
        db.execute("INSERT INTO model_switches(channel, model_id, from_model_id, status, "
                   "created_at) VALUES(?,?,?,?,?)",
                   ("supervised", self.model["id"], 999, "ok", db.now_ms()))
        t = model_switch.rollback_target("supervised")
        self.assertIsNone(t)  # 999 不存在 -> None


if __name__ == "__main__":
    unittest.main()
