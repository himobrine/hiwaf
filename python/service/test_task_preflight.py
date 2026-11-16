"""训练任务语料预检（缺官方语料时给出可读 400，而不是运行期 traceback）。

覆盖：官方语料就位判定、`only` 模式不要求官方语料、只上传模式的良性留出门槛、
CSIC 依赖（官方校准 / 零日通道）。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from . import app as app_mod
from . import config


class TaskPreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.tr = self.root / "traindata"
        self.tr.mkdir(parents=True, exist_ok=True)
        self.patch = mock.patch.object(config, "ROOT", self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    # ---- helpers --------------------------------------------------------
    def _files(self, *, csvs=True, csic=False):
        if csvs:
            for n in ("payload_train.csv", "payload_test.csv", "payload_test_lexical.csv"):
                (self.tr / n).write_text("payload,length,attack_type,label\n", encoding="utf-8")
        if csic:
            d = self.tr / "Machine-Learning-on-CSIC-2010-master" / "Machine-Learning-on-CSIC-2010-master"
            d.mkdir(parents=True, exist_ok=True)
            (d / "normalTrafficTraining.txt").write_text("GET / HTTP/1.1\n\n", encoding="utf-8")

    def _up(self, calib_mode="auto", benign=0, ds_id=5):
        return {
            "calib_mode": calib_mode,
            "calib_dataset_id": ds_id,
            "datasets": [{"id": ds_id, "benign": benign}],
        }

    # ---- 语料就位判定 --------------------------------------------------
    def test_official_corpora_missing(self):
        st = app_mod.official_corpora()
        self.assertFalse(st["ok"])
        self.assertEqual(len(st["missing"]), 3)
        self.assertIn("traindata/payload_train.csv", st["missing"])
        self.assertFalse(st["csic"])

    def test_official_corpora_ok(self):
        self._files(csic=True)
        st = app_mod.official_corpora()
        self.assertTrue(st["ok"])
        self.assertEqual(st["missing"], [])
        self.assertTrue(st["csic"])

    # ---- 预检：official / add ------------------------------------------
    def test_official_mode_rejected_when_csv_missing(self):
        with self.assertRaises(HTTPException) as ctx:
            app_mod._preflight_official("train_realdata", "official", self._up())
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("payload_train.csv", str(ctx.exception.detail))

    def test_add_mode_requires_csic_when_official_calib(self):
        self._files(csvs=True, csic=False)
        with self.assertRaises(HTTPException) as ctx:
            app_mod._preflight_official(
                "train_realdata", "add", self._up(calib_mode="official"))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("CSIC", str(ctx.exception.detail))

    def test_add_mode_requires_csic_when_calib_dataset_too_small(self):
        self._files(csvs=True, csic=False)
        # auto + 校准数据集良性 < 400 → 会回退 CSIC
        with self.assertRaises(HTTPException):
            app_mod._preflight_official(
                "train_realdata", "add", self._up(calib_mode="auto", benign=10))

    def test_add_mode_ok_with_upload_calib(self):
        self._files(csvs=True, csic=False)
        # 上传留出够大 → 不需要 CSIC
        app_mod._preflight_official(
            "train_realdata", "add", self._up(calib_mode="upload", benign=500))

    def test_iforest_csic_requires_csic(self):
        with self.assertRaises(HTTPException) as ctx:
            app_mod._preflight_official("iforest_csic", "official", self._up())
        self.assertIn("CSIC", str(ctx.exception.detail))

    # ---- 预检：only -----------------------------------------------------
    def test_only_mode_does_not_require_official_csvs(self):
        # 没有任何官方语料，only 也不该被拦（良性留出够大）
        app_mod._preflight_official(
            "train_realdata", "only", self._up(calib_mode="auto", benign=500))

    def test_only_mode_requires_big_benign_holdout(self):
        with self.assertRaises(HTTPException) as ctx:
            app_mod._preflight_official(
                "train_realdata", "only", self._up(calib_mode="auto", benign=17))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("≥400", str(ctx.exception.detail))


if __name__ == "__main__":
    unittest.main()