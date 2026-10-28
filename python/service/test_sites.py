"""站点（Host）→ 模型 测试（临时 DB，不碰真实 console.db）。

覆盖：按站点聚合、最新判决版本解析模型、与现役对比的状态
（in_sync / policy_old / stale / unscored / unknown）、名称解析、窗口过滤、Top 截断。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, sites

DAY = 86_400_000


class SitesModelsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", root / "logs"),
            mock.patch.object(config, "POLICY_JSON", root / "decision_policy.json"),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.now = db.now_ms()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    # ---- 造数 -------------------------------------------------------------
    def _snapshot(self, v: int, sup_sha: str, *, zd_sha: str = "zdsha1",
                  zero_day_enabled: bool = False, rules_sha: str = "rsha1") -> dict:
        return {
            "version": v,
            "zero_day_enabled": zero_day_enabled,
            "supervised": {"artifact": f"xgboost_{sup_sha}.onnx",
                           "artifact_sha1_16": sup_sha},
            "zero_day": {"artifact": f"iforest_{zd_sha}.onnx",
                         "artifact_sha1_16": zd_sha},
            "rules": {"enabled": True, "ruleset_sha1_16": rules_sha,
                      "n_rules": 10, "n_block_rules": 3},
        }

    def _put_snapshot(self, pol: dict) -> None:
        db.execute(
            'INSERT OR REPLACE INTO policy_versions(version, "json", actor, created_at, note) '
            "VALUES(?,?,?,?,?)",
            (pol["version"], json.dumps(pol, ensure_ascii=False), "test",
             db.now_ms(), None),
        )

    def _registry(self, channel: str, sha: str, name: str, gen: int = 1,
                  status: str = "active") -> None:
        # 每个通道只允许一条 active（ux_model_one_active）：历史版本用 superseded。
        db.execute(
            "INSERT INTO model_registry(channel, display_name, generation, artifact_name, "
            "sha1_16, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (channel, name, gen, f"{channel}_{sha}.onnx", sha, status,
             db.now_ms(), db.now_ms()),
        )

    def _event(self, host, policy_version, *, action="allow", ts=None,
               artifacts=None) -> int:
        t = ts if ts is not None else self.now - 3600_000
        return db.execute(
            "INSERT INTO events(ts, ingest_ts, host, action, policy_version, model_artifacts) "
            "VALUES(?,?,?,?,?,?)",
            (t, t, host, action, policy_version, artifacts),
        )

    # ---- 测试 -------------------------------------------------------------
    def test_per_site_models_and_status(self):
        v1 = self._snapshot(1, "oldsup", zd_sha="oldzd")
        v2 = self._snapshot(2, "newsup", zd_sha="newzd", zero_day_enabled=True)
        self._put_snapshot(v1)
        self._put_snapshot(v2)
        self._registry("supervised", "oldsup", "XGBoost g1", 1, status="archived")
        self._registry("supervised", "newsup", "XGBoost g2", 2)
        self._registry("zero_day", "newzd", "IForest g2", 2)

        # a 站：旧版本 2 条 + 新版本 3 条（现役 v2 → in_sync）
        self._event("www.a.com", 1, action="block")
        self._event("www.a.com", 1, action="allow")
        self._event("www.a.com", 2, action="block")
        self._event("www.a.com", 2, action="alert")
        self._event("www.a.com", 2, action="allow")
        # b 站：只有旧版本（stale），且带自己的产物目录
        self._event("www.b.com", 1, action="allow", artifacts="D:\\other\\artifacts")
        # c 站：没有判定（unscored）
        self._event("www.c.com", None, action="allow")

        live = v2
        out = sites.site_models(window_hours=24, live_policy=live)
        self.assertEqual(out["total_hosts"], 3)
        self.assertEqual(out["live"]["policy_version"], 2)

        by_host = {it["host"]: it for it in out["items"]}
        a = by_host["www.a.com"]
        self.assertEqual(a["n"], 5)
        self.assertEqual(a["blocks"], 2)
        self.assertEqual(a["alerts"], 1)
        self.assertEqual(a["allows"], 2)
        self.assertEqual(a["status"], "in_sync")
        self.assertEqual(a["stale_versions"], 1)  # v1 的模型与现役不同
        self.assertEqual(len(a["versions"]), 2)
        self.assertEqual(a["versions"][0]["policy_version"], 2)
        self.assertEqual(a["latest"]["supervised"]["name"], "XGBoost g2")
        self.assertEqual(a["latest"]["supervised"]["sha1_16"], "newsup")
        self.assertTrue(a["latest"]["zero_day"]["enabled"])
        self.assertEqual(a["latest"]["zero_day"]["name"], "IForest g2")
        self.assertEqual(a["latest"]["rules"]["n_rules"], 10)

        b = by_host["www.b.com"]
        self.assertEqual(b["status"], "stale")
        self.assertEqual(b["stale_versions"], 1)
        self.assertEqual(b["latest"]["supervised"]["name"], "XGBoost g1")
        self.assertEqual(b["artifact_dirs"], ["D:\\other\\artifacts"])

        c = by_host["www.c.com"]
        self.assertEqual(c["status"], "unscored")
        self.assertIsNone(c["latest"])
        self.assertEqual(c["versions"], [])

        # 排序：请求数降序，a 站第一
        self.assertEqual(out["items"][0]["host"], "www.a.com")

    def test_policy_old_when_model_same(self):
        v1 = self._snapshot(1, "samesup")
        v2 = self._snapshot(2, "samesup")  # 同一模型，只换了阈值
        self._put_snapshot(v1)
        self._put_snapshot(v2)
        self._event("old.example.com", 1)
        out = sites.site_models(window_hours=24, live_policy=v2)
        it = out["items"][0]
        self.assertEqual(it["status"], "policy_old")
        self.assertEqual(it["stale_versions"], 0)

    def test_missing_snapshot_is_unknown(self):
        self._event("ghost.example.com", 42)
        out = sites.site_models(window_hours=24, live_policy=self._snapshot(2, "newsup"))
        it = out["items"][0]
        self.assertEqual(it["status"], "unknown")
        self.assertFalse(it["versions"][0]["snapshot_found"])

    def test_window_filter_and_top_cap(self):
        v1 = self._snapshot(1, "sup1")
        self._put_snapshot(v1)
        # 窗口外的不算
        self._event("old.example.com", 1, ts=self.now - 2 * DAY)
        # 窗口内 3 个站点，各 1 条；top=2 只保留请求数大的前 2 个
        self._event("s1.example.com", 1)
        self._event("s2.example.com", 1)
        self._event("s3.example.com", 1)
        out = sites.site_models(window_hours=24, live_policy=v1, top=2)
        self.assertEqual(out["total_hosts"], 3)
        self.assertEqual(out["shown"], 2)
        hosts = {it["host"] for it in out["items"]}
        self.assertNotIn("old.example.com", hosts)  # 窗口外
        # 三个站点请求数相同，前 2 名谁进都不影响"总共 3 个、只展示 2 个"的结论
        self.assertTrue(hosts <= {"s1.example.com", "s2.example.com", "s3.example.com"})

    def test_null_host_grouped(self):
        v1 = self._snapshot(1, "sup1")
        self._put_snapshot(v1)
        self._event(None, 1)
        out = sites.site_models(window_hours=24, live_policy=v1)
        self.assertEqual(out["items"][0]["host"], None)


if __name__ == "__main__":
    unittest.main()
