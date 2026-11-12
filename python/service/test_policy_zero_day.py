"""零日通道重标定的参数拼装：单独 FPR + 自动训练指纹。

只测**命令构造**（不启动子进程、不碰真实 artifacts/DB），保证控制台三条路径
（预览 / 提升 / 开关）不会再因为缺 `--train-keys` 或漏 `--zero-day-fpr` 而失败。
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import HTTPException

from . import app as app_mod


class _Done:
    returncode = 0
    stdout = ""
    stderr = ""


class RunThresholdsArgsTest(unittest.TestCase):
    def _capture(self, **kwargs):
        box = {}

        def fake_run(cmd, **kw):
            box["cmd"] = [str(c) for c in cmd]
            return _Done()

        keys = r"F:\waf\python\artifacts\models\supervised\gen-0003-x\training_keys.txt"
        pol = {"rules": {"enabled": False}}
        with mock.patch.object(app_mod, "_train_keys_for_pool", return_value=keys), \
             mock.patch.object(app_mod, "_policy", return_value=pol), \
             mock.patch.object(app_mod.subprocess, "run", side_effect=fake_run):
            app_mod._run_thresholds(
                r"file:F:\waf\python\artifacts\models\zero_day\gen-0003-x\calibration_pool.jsonl",
                "0.01", "on", **kwargs)
        return box["cmd"]

    def test_zero_day_fpr_is_passed_through(self):
        cmd = self._capture(zero_day_fpr="0.005")
        self.assertIn("--zero-day-fpr", cmd)
        self.assertEqual(cmd[cmd.index("--zero-day-fpr") + 1], "0.005")

    def test_train_keys_are_auto_attached(self):
        cmd = self._capture(zero_day_fpr="0.005")
        self.assertIn("--train-keys", cmd)
        self.assertTrue(cmd[cmd.index("--train-keys") + 1].endswith("training_keys.txt"))

    def test_omitted_zero_day_fpr_keeps_backward_compatible_argv(self):
        cmd = self._capture()
        self.assertNotIn("--zero-day-fpr", cmd)

    def test_invalid_zero_day_fpr_is_rejected(self):
        for bad in ("0.2", "0", "-0.01", "abc"):
            with self.assertRaises(HTTPException) as ctx:
                app_mod._run_thresholds("file:F:/x/pool.jsonl", "0.01", "on",
                                        zero_day_fpr=bad)
            self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()