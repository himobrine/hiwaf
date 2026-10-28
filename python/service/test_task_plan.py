"""训练任务 argv 组装测试（不跑子进程）。"""
from __future__ import annotations

import unittest
from unittest import mock

from . import app as app_mod


class TaskPlanTest(unittest.TestCase):
    def setUp(self):
        self.settings = {"inherit_mode": "warm_start", "auto_register": True,
                         "max_per_channel": 10, "max_total": 20, "keep_curves": True}
        self.patchers = [
            mock.patch.object(app_mod.model_registry, "get_settings",
                              side_effect=lambda: dict(self.settings)),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in reversed(self.patchers):
            p.stop()

    def test_non_train_kind_only_argv(self):
        plan = app_mod._task_plan(1, "export_testvec", None, None)
        self.assertEqual(plan["argv"], ["export_testvec.py"])
        self.assertNotIn("staging", plan)

    def test_supervised_warm_start_args(self):
        parent = {"id": 7, "channel": "supervised", "metrics": {"n_trees": 200},
                  "recipe": {"total_trees": 200}}
        with mock.patch.object(app_mod.model_registry, "resolve_parent", return_value=parent), \
             mock.patch.object(app_mod.model_registry, "parent_paths",
                               return_value={"xgb_model.json": r"C:\p\xgb_model.json",
                                             "xgboost_meta.json": r"C:\p\xgboost_meta.json"}):
            plan = app_mod._task_plan(5, "train_realdata", "warm_start", None)
        argv = plan["argv"]
        self.assertIn("--out-dir", argv)
        self.assertIn("--artifact-name", argv)
        self.assertIn("model.onnx", argv)
        self.assertIn("--parent-model", argv)
        self.assertIn(r"C:\p\xgb_model.json", argv)
        self.assertIn("--parent-meta", argv)
        self.assertEqual(plan["register"]["parent_id"], 7)
        self.assertEqual(plan["register"]["inherit_mode"], "warm_start")

    def test_zeroday_warm_start_bumps_trees(self):
        parent = {"id": 9, "channel": "zero_day", "metrics": {"trees": 100},
                  "recipe": {"total_trees": 100}}
        with mock.patch.object(app_mod.model_registry, "resolve_parent", return_value=parent), \
             mock.patch.object(app_mod.model_registry, "parent_paths",
                               return_value={"iforest_model.joblib": r"C:\p\if.joblib"}):
            plan = app_mod._task_plan(3, "iforest_csic", "warm_start", None)
        argv = plan["argv"]
        self.assertIn("--trees", argv)
        self.assertEqual(argv[argv.index("--trees") + 1], "125")
        self.assertEqual(plan["iforest_trees"], 125)

    def test_zeroday_warm_start_caps_and_falls_back(self):
        parent = {"id": 9, "channel": "zero_day", "metrics": {"trees": 390},
                  "recipe": {"total_trees": 390}}
        with mock.patch.object(app_mod.model_registry, "resolve_parent", return_value=parent), \
             mock.patch.object(app_mod.model_registry, "parent_paths",
                               return_value={"iforest_model.joblib": r"C:\p\if.joblib"}):
            plan = app_mod._task_plan(3, "iforest_csic", "warm_start", None)
        self.assertNotIn("--parent-model", plan["argv"])
        self.assertEqual(plan["register"]["inherit_mode"], "lineage")
        self.assertIn("parent_fallback", plan)

    def test_no_parent_falls_back_to_lineage(self):
        with mock.patch.object(app_mod.model_registry, "resolve_parent", return_value=None):
            plan = app_mod._task_plan(4, "train_realdata", "warm_start", None)
        self.assertEqual(plan["inherit_mode"], "lineage")
        self.assertNotIn("--parent-model", plan["argv"])


if __name__ == "__main__":
    unittest.main()
