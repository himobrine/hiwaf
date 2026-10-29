"""采集代理控制面测试（临时 DB / 日志目录，不碰真实 console.db）。

覆盖：配置白名单与边界、地址注入、项目目录约束、argv 组装、二进制解析、
运行状态、重复启动/端口占用/二进制缺失、托管停止与 PID 复用保护、
重启差异、指标过期、日志尾部。
"""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from . import config, db, proxy_manager as pm


class FakeProc:
    def __init__(self, pid: int = 4242):
        self.pid = pid

    def poll(self):
        return None


class ProxyManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.raw = root / "raw"
        self.logs = root / "logs"
        self.metrics = self.raw / "collector-metrics.json"
        self.bin = root / "waf-collector.exe"
        self.bin.write_bytes(b"fake")
        self.patches = [
            mock.patch.object(config, "DB_PATH", root / "console.db"),
            mock.patch.object(config, "LOG_DIR", self.logs),
            mock.patch.object(config, "RAW_DIR", self.raw),
            mock.patch.object(config, "COLLECTOR_METRICS", self.metrics),
        ]
        for p in self.patches:
            p.start()
        db.init()
        self.raw.mkdir(parents=True, exist_ok=True)
        pm._PROC = None

    def tearDown(self):
        pm._PROC = None
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    # ---- helpers --------------------------------------------------------
    def _pid_file(self, cfg=None, pid=4242, started_at=None, **over):
        cfg = cfg or pm.get_config()
        doc = {
            "pid": pid,
            "started_at": started_at or time.time(),
            "started_at_ms": db.now_ms(),
            "listen": cfg["listen"],
            "upstream": cfg["upstream"],
            "binary": str(self.bin),
            "log_path": str(self.logs / "proxy_test.log"),
            "config": cfg,
            "config_hash": pm.config_hash(cfg),
        }
        doc.update(over)
        pm._write_pid(doc)
        return doc

    def _audit_actions(self):
        return [r["action"] for r in db.rows("SELECT action FROM audit ORDER BY id")]

    # ---- 配置校验 ------------------------------------------------------
    def test_defaults_and_save(self):
        cfg = pm.get_config()
        self.assertEqual(cfg["listen"], "0.0.0.0:6188")
        self.assertEqual(cfg["resp_body"], "alert")

        res = pm.update_config({"listen": "127.0.0.1:6199", "body_keep": 1024}, "admin")
        self.assertEqual(res["config"]["listen"], "127.0.0.1:6199")
        self.assertEqual(res["config"]["body_keep"], 1024)
        self.assertIn("proxy_config_update", self._audit_actions())

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError):
            pm.update_config({"rm_rf": True}, "admin")

    def test_body_keep_cannot_exceed_limit(self):
        with self.assertRaises(ValueError):
            pm.update_config({"body_keep": 2048, "body_limit": 1024}, "admin")

    def test_headers_keep_range(self):
        with self.assertRaises(ValueError):
            pm.update_config({"headers_keep": 8193}, "admin")
        with self.assertRaises(ValueError):
            pm.update_config({"headers_keep": 0}, "admin")

    def test_resp_body_enum(self):
        with self.assertRaises(ValueError):
            pm.update_config({"resp_body": "everything"}, "admin")

    def test_addr_injection_rejected(self):
        with self.assertRaises(ValueError):
            pm.update_config({"listen": "127.0.0.1:6188 & calc"}, "admin")
        with self.assertRaises(ValueError):
            pm.update_config({"upstream": "127.0.0.1"}, "admin")

    def test_paths_must_stay_in_project(self):
        outside = Path(tempfile.gettempdir()).resolve()
        if outside == config.ROOT.resolve():
            self.skipTest("临时目录与项目目录相同，跳过")
        with self.assertRaises(ValueError):
            pm.update_config({"artifacts": str(outside)}, "admin")
        # 空 rules = 显式关闭规则通道（--no-rules）
        res = pm.update_config({"rules": ""}, "admin")
        self.assertEqual(res["config"]["rules"], "")

    def test_build_argv_fixed_paths_and_flags(self):
        cfg = pm.get_config()
        cfg.update({
            "block_mode": "dry_run",
            "no_body": True,
            "rules": "",
            "routes": [{
                "name": "a",
                "listen": "127.0.0.1:6199",
                "upstream": "127.0.0.1:8080",
                "upstream_tls": True,
            }],
        })
        argv = pm.build_argv(cfg, self.bin)
        self.assertIn("--block-mode", argv)
        self.assertEqual(argv[argv.index("--block-mode") + 1], "dry_run")
        self.assertIn("--route", argv)
        self.assertEqual(
            argv[argv.index("--route") + 1],
            "name=a,listen=127.0.0.1:6199,upstream=127.0.0.1:8080,tls=1")
        self.assertIn("--no-body", argv)
        self.assertNotIn("--score", argv)
        self.assertNotIn("--upstream-tls", argv)
        self.assertIn("--no-rules", argv)
        self.assertEqual(argv[argv.index("--out") + 1], str(config.RAW_DIR))
        self.assertEqual(argv[argv.index("--stats-out") + 1],
                         str(config.COLLECTOR_METRICS))

    def test_build_argv_multiple_routes(self):
        cfg = pm.get_config()
        cfg.update({
            "block_mode": "enforce",
            "routes": [
                {"name": "a", "listen": "0.0.0.0:80",
                 "upstream": "127.0.0.1:8080", "upstream_tls": False},
                {"name": "b", "listen": "0.0.0.0:443",
                 "upstream": "127.0.0.1:8443", "upstream_tls": True},
            ],
        })
        argv = pm.build_argv(cfg, self.bin)
        specs = [argv[i + 1] for i, a in enumerate(argv) if a == "--route"]
        self.assertEqual(specs, [
            "name=a,listen=0.0.0.0:80,upstream=127.0.0.1:8080,tls=0",
            "name=b,listen=0.0.0.0:443,upstream=127.0.0.1:8443,tls=1",
        ])
        self.assertEqual(argv[argv.index("--block-mode") + 1], "enforce")

    def test_routes_validation(self):
        with self.assertRaises(ValueError):
            pm.update_config({"routes": []}, "admin")
        with self.assertRaises(ValueError):
            pm.update_config({"routes": [
                {"name": "a", "listen": "127.0.0.1:7001",
                 "upstream": "127.0.0.1:8001", "upstream_tls": False},
                {"name": "b", "listen": "127.0.0.1:7001",
                 "upstream": "127.0.0.1:8002", "upstream_tls": False},
            ]}, "admin")
        with self.assertRaises(ValueError):
            pm.update_config({"routes": [
                {"name": "a", "listen": "127.0.0.1:7001",
                 "upstream": "127.0.0.1:7001", "upstream_tls": False},
            ]}, "admin")
        with self.assertRaises(ValueError):
            pm.update_config({"routes": [
                {"name": "a", "listen": "127.0.0.1:7001",
                 "upstream": "127.0.0.1:8001", "upstream_tls": False,
                 "extra": 1},
            ]}, "admin")
        with self.assertRaises(ValueError):
            pm.update_config({"routes": [
                {"name": "a", "listen": "127.0.0.1:7001",
                 "upstream": "127.0.0.1:8001", "upstream_tls": False},
            ], "listen": "127.0.0.1:7002"}, "admin")

    def test_routes_saved_and_legacy_aliases_synced(self):
        res = pm.update_config({"routes": [
            {"name": "a", "listen": "0.0.0.0:6188",
             "upstream": "192.168.3.97:80", "upstream_tls": False},
            {"name": "b", "listen": "0.0.0.0:6189",
             "upstream": "192.168.3.97:8080", "upstream_tls": False},
        ]}, "admin")
        self.assertEqual(len(res["config"]["routes"]), 2)
        self.assertEqual(res["config"]["listen"], "0.0.0.0:6188")
        self.assertEqual(res["config"]["upstream"], "192.168.3.97:80")
        # 重新读取也要保持一致（老字段是 routes[0] 的别名）。
        cfg = pm.get_config()
        self.assertEqual(len(cfg["routes"]), 2)
        self.assertEqual(cfg["listen"], cfg["routes"][0]["listen"])

    def test_routes_echo_back_with_legacy_aliases(self):
        """GET /api/proxy/config 的返回原样 PUT 回来应成功（旧字段是 routes[0] 别名）。"""
        view = pm.config_view()
        res = pm.update_config(view["config"], "admin")
        self.assertEqual(res["config"]["routes"], view["config"]["routes"])
        self.assertEqual(res["config"]["listen"], view["config"]["listen"])

    def test_block_mode_and_legacy_score_migration(self):
        # 老配置只有 score=true ⇒ 迁移成 dry_run。
        db.execute(
            "INSERT OR REPLACE INTO app_settings(key, value, updated_at, actor) "
            "VALUES(?,?,?,?)", ("proxy.score", "true", db.now_ms(), "admin"))
        cfg = pm.get_config()
        self.assertEqual(cfg["block_mode"], "dry_run")
        self.assertTrue(cfg["score"])

        res = pm.update_config({"block_mode": "enforce"}, "admin")
        self.assertEqual(res["config"]["block_mode"], "enforce")
        self.assertTrue(res["config"]["score"])
        self.assertIn("proxy_block_mode_update", self._audit_actions())

        res = pm.update_config({"block_mode": "off"}, "admin")
        self.assertFalse(res["config"]["score"])
        with self.assertRaises(ValueError):
            pm.update_config({"block_mode": "block-everything"}, "admin")

    def test_resolve_binary_env_override(self):
        with mock.patch.dict("os.environ", {"WAF_COLLECTOR_BIN": str(self.bin)}):
            self.assertEqual(pm.resolve_binary(), self.bin)

    # ---- 状态 ----------------------------------------------------------
    def test_status_not_running(self):
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "port_listening", return_value=False):
            st = pm.status()
        self.assertFalse(st["running"])
        self.assertFalse(st["managed"])
        self.assertFalse(st["restart_required"])
        self.assertTrue(st["binary"]["exists"])
        self.assertEqual(st["out_dir"]["files"], 0)

    def test_status_warns_tls_on_plain_port_80(self):
        """上游 80 + upstream_tls=true 是常见误配：握手失败、事件不入库。"""
        pm.update_config({"upstream": "192.0.2.10:80", "upstream_tls": True}, "admin")
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "port_listening", return_value=False):
            st = pm.status()
        self.assertTrue(any("upstream_tls" in w for w in st["warnings"]))

    def test_status_no_tls_warning_when_disabled(self):
        pm.update_config({"upstream": "192.0.2.10:80", "upstream_tls": False}, "admin")
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "port_listening", return_value=False):
            st = pm.status()
        self.assertFalse(any("upstream_tls" in w for w in st["warnings"]))

    def test_metrics_stale(self):
        self.metrics.write_text(json.dumps({"ts": db.now_ms() - 10 * 60 * 1000}),
                                encoding="utf-8")
        m = pm.metrics()
        self.assertIsNotNone(m)
        self.assertTrue(m["stale"])

    def test_stale_metrics_do_not_force_restart(self):
        """上一次运行留下的指标文件不能把「未运行」误判成需重启。"""
        self.metrics.write_text(json.dumps({
            "ts": db.now_ms() - 10 * 60 * 1000, "pid": 999,
            "listen": "127.0.0.1:39987", "upstream": "127.0.0.1:39986",
            "score_enabled": True, "artifacts": str(config.ARTIFACTS),
            "resp_body_mode": "alert",
        }), encoding="utf-8")
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "port_listening", return_value=False), \
                mock.patch.object(pm, "_pid_alive", return_value=False):
            st = pm.status()
        self.assertFalse(st["restart_required"])
        self.assertEqual(st["restart_keys"], [])
        self.assertIsNone(st["effective"])

    # ---- 启停 ----------------------------------------------------------
    def test_start_refuses_when_already_running(self):
        self._pid_file()
        with mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=True):
            with self.assertRaises(pm.ProxyError) as ctx:
                pm.start("admin")
        self.assertEqual(ctx.exception.status, 409)

    def test_start_refuses_when_port_busy(self):
        with mock.patch.object(pm, "port_listening", return_value=True):
            with self.assertRaises(pm.ProxyError) as ctx:
                pm.start("admin")
        self.assertEqual(ctx.exception.status, 409)

    def test_start_refuses_when_binary_missing(self):
        missing = self.raw / "nope.exe"
        with mock.patch.object(pm, "resolve_binary", return_value=missing), \
                mock.patch.object(pm, "port_listening", return_value=False):
            with self.assertRaises(pm.ProxyError) as ctx:
                pm.start("admin")
        self.assertEqual(ctx.exception.status, 409)

    def test_start_writes_pid_and_audit(self):
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "_spawn", return_value=FakeProc()), \
                mock.patch.object(pm, "port_listening",
                                  side_effect=[False, True, True]), \
                mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=True):
            st = pm.start("admin")
        self.assertTrue(st["running"])
        self.assertEqual(st["pid"], 4242)
        self.assertTrue(pm._pid_path().exists())
        self.assertIn("proxy_start", self._audit_actions())

    def test_stop_managed_removes_pid(self):
        self._pid_file()
        with mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=True), \
                mock.patch.object(pm, "_terminate") as term, \
                mock.patch.object(pm, "_wait_dead", return_value=True):
            pm.stop("admin")
        term.assert_called_once_with(4242, force=False)
        self.assertFalse(pm._pid_path().exists())
        self.assertIn("proxy_stop", self._audit_actions())

    def test_stop_pid_reuse_requires_force(self):
        self._pid_file()
        with mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=False):
            with self.assertRaises(pm.ProxyError) as ctx:
                pm.stop("admin")
        self.assertEqual(ctx.exception.status, 409)
        with mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=False), \
                mock.patch.object(pm, "_terminate"), \
                mock.patch.object(pm, "_wait_dead", return_value=True):
            pm.stop("admin", force=True)
        self.assertIn("proxy_force_stop", self._audit_actions())

    def test_restart_required_diff(self):
        old = pm.get_config()
        self._pid_file(cfg=old)
        pm.update_config({"listen": "127.0.0.1:6199"}, "admin")
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "port_listening", return_value=True), \
                mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=True):
            st = pm.status()
        self.assertTrue(st["restart_required"])
        self.assertIn("listen", st["restart_keys"])
        self.assertIn("routes", st["restart_keys"])

    def test_restart_required_for_block_mode(self):
        old = pm.get_config()
        self._pid_file(cfg=old)
        pm.update_config({"block_mode": "enforce"}, "admin")
        with mock.patch.object(pm, "resolve_binary", return_value=self.bin), \
                mock.patch.object(pm, "port_listening", return_value=True), \
                mock.patch.object(pm, "_pid_alive", return_value=True), \
                mock.patch.object(pm, "_identity_ok", return_value=True):
            st = pm.status()
        self.assertTrue(st["restart_required"])
        self.assertIn("block_mode", st["restart_keys"])

    def test_tail_log(self):
        self.logs.mkdir(parents=True, exist_ok=True)
        log = self.logs / "proxy_test.log"
        log.write_text("a\nb\nc\nd\n", encoding="utf-8")
        self._pid_file(log_path=str(log))
        r = pm.tail_log(2)
        self.assertEqual(r["log"], "c\nd")


if __name__ == "__main__":
    unittest.main()
