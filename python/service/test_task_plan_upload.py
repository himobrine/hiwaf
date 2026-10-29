"""训练任务上传数据 argv 组装测试（不跑子进程 / 不读真实数据）。"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import HTTPException

from . import app as app_mod


def _ds(uid=3, role="supervised", benign=600, attack=400, labels=None):
    labels = labels or {"0": benign, "1": attack}
    return {
        "id": uid, "name": f"ds{uid}", "role": role, "format": "csv",
        "status": "ready", "sha256": "a" * 64,
        "rows_kept": benign + attack, "rows_total": benign + attack,
        "label_stats": labels, "stats": {"benign": benign, "attack": attack,
                                         "label_counts": labels},
        "exists": True, "source_note": "unit",
        "requests_path": rf"C:\tmp\up\{uid}\requests.jsonl",
        "train_path": rf"C:\tmp\up\{uid}\requests_train.jsonl",
    }


class TaskPlanUploadTest(unittest.TestCase):
    def setUp(self):
        self.settings = {"inherit_mode": "warm_start", "auto_register": True}
        self.patchers = [
            mock.patch.object(app_mod.model_registry, "get_settings",
                              side_effect=lambda: dict(self.settings)),
            mock.patch.object(app_mod.uploads, "get_upload",
                              side_effect=lambda uid: _ds(uid)),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in reversed(self.patchers):
            p.stop()

    def test_official_has_no_upload(self):
        plan = app_mod._task_plan(1, "train_realdata", None, None)
        self.assertNotIn("--upload-manifest", plan["argv"])
        self.assertEqual(plan.get("datasets"), [])

    def test_supervised_add_builds_upload_args(self):
        plan = app_mod._task_plan(2, "train_realdata", "warm_start", None,
                                  "add", [3], "auto", None)
        argv = plan["argv"]
        self.assertIn("--upload-manifest", argv)
        self.assertIn("--upload-mode", argv)
        self.assertIn("add", argv)
        self.assertIn("--calib-dataset-id", argv)
        self.assertEqual(plan["data_mode"], "add")
        self.assertEqual(plan["datasets"][0]["id"], 3)
        self.assertEqual(plan["datasets"][0]["train_path"], _ds(3)["train_path"])

    def test_only_forces_lineage_and_swaps_iforest_data(self):
        plan = app_mod._task_plan(3, "iforest_csic", "warm_start", None,
                                  "only", [3], "auto", None)
        self.assertEqual(plan["inherit_mode"], "lineage")
        argv = plan["argv"]
        i = argv.index("--data")
        self.assertEqual(argv[i + 1], "upload")
        self.assertIn("--upload-mode", argv)

    def test_only_removes_hard_neg(self):
        plan = app_mod._task_plan(4, "train_realdata", None, None, "only", [3], "auto", None)
        self.assertNotIn("--hard-neg", plan["argv"])

    def test_dataset_not_supported_for_other_kinds(self):
        with self.assertRaises(HTTPException):
            app_mod._task_plan(5, "p8_e2e", None, None, "add", [3], "auto", None)

    def test_iforest_local_add_uses_dataset_as_baseline(self):
        plan = app_mod._task_plan(6, "iforest_local", None, None, "add", [3], "auto", None)
        argv = plan["argv"]
        self.assertEqual(argv[argv.index("--data") + 1], "local")
        self.assertEqual(argv[argv.index("--benign") + 1],
                         _ds(3)["train_path"])
        # 只有一个数据集：没有可增量的良性行，不能拼 manifest（脚本会报"没有良性行"）。
        self.assertNotIn("--upload-manifest", argv)
        self.assertEqual(plan["baseline_dataset"]["id"], 3)
        self.assertTrue(plan.get("upload_manifest_skipped"))

    def test_iforest_local_add_skips_baseline_in_manifest(self):
        plan = app_mod._task_plan(7, "iforest_local", None, None, "add", [3, 4],
                                  "auto", None)
        argv = plan["argv"]
        self.assertIn("--upload-manifest", argv)
        # 基线已由 --benign 加载；manifest 必须跳过它，否则训练/留出重叠。
        self.assertEqual(argv[argv.index("--upload-skip-id") + 1], "3")
        self.assertEqual(plan["baseline_dataset"]["id"], 3)

    def test_iforest_local_official_needs_local_baseline(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "local_lab_benign.jsonl"
            p.write_text('{"method":"GET","path":"/","query":"","body":"","label":0}\n',
                         encoding="utf-8")
            with mock.patch.object(app_mod.config, "LOCAL_DIR", Path(d)):
                plan = app_mod._task_plan(9, "iforest_local", None, None)
        argv = plan["argv"]
        self.assertEqual(argv[argv.index("--data") + 1], "local")
        self.assertEqual(argv[argv.index("--benign") + 1], str(p))
        self.assertNotIn("--upload-manifest", argv)

    def test_iforest_local_official_without_baseline_rejected(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(app_mod.config, "LOCAL_DIR", Path(d)):
                with self.assertRaises(HTTPException):
                    app_mod._task_plan(10, "iforest_local", None, None)

    def test_iforest_local_only_swaps_data_to_upload(self):
        plan = app_mod._task_plan(8, "iforest_local", "warm_start", None,
                                  "only", [3], "auto", None)
        argv = plan["argv"]
        self.assertEqual(argv[argv.index("--data") + 1], "upload")
        self.assertNotIn("--benign", argv)
        self.assertIn("--upload-manifest", argv)
        self.assertEqual(plan["inherit_mode"], "lineage")

    def test_missing_dataset_id_rejected(self):
        with self.assertRaises(HTTPException):
            app_mod._task_plan(6, "train_realdata", None, None, "add", [], "auto", None)

    def test_not_ready_rejected(self):
        bad = _ds(7)
        bad["status"] = "converting"
        with mock.patch.object(app_mod.uploads, "get_upload", return_value=bad):
            with self.assertRaises(HTTPException):
                app_mod._task_plan(7, "train_realdata", None, None, "add", [7], "auto", None)

    def test_add_allows_benign_only(self):
        ben = _ds(9, role="benign", benign=600, attack=0, labels={"0": 600})
        ben["stats"] = {"benign": 600, "attack": 0, "label_counts": {"0": 600}}
        with mock.patch.object(app_mod.uploads, "get_upload", return_value=ben):
            plan = app_mod._task_plan(9, "train_realdata", None, None, "add", [9],
                                      "auto", None)
        self.assertEqual(plan["data_mode"], "add")
        self.assertIn("--upload-mode", plan["argv"])

    def test_single_label_rejected(self):
        one = _ds(8, labels={"0": 1000, "1": 0})
        one["stats"] = {"benign": 1000, "attack": 0, "label_counts": {"0": 1000}}
        with mock.patch.object(app_mod.uploads, "get_upload", return_value=one):
            with self.assertRaises(HTTPException):
                app_mod._task_plan(8, "train_realdata", None, None, "only", [8], "auto", None)


if __name__ == "__main__":
    unittest.main()
