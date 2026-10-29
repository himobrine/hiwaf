"""控制面 API 配置（单机）。

所有路径都可被环境变量覆盖，方便换机 / 换盘 / 测试。
"""
from __future__ import annotations

import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE.parent                  # F:\waf\python
ROOT = PY.parent                  # F:\waf

ARTIFACTS = PY / "artifacts"
RAW_DIR = ROOT / "traindata" / "proxy"
LOCAL_DIR = ROOT / "traindata" / "local"

DB_PATH = Path(os.environ.get("WAF_CONSOLE_DB", str(HERE / "console.db")))
#: 90 天保留期（DB 事件与 raw JSONL 使用同一个 cutoff）。
RETENTION_DAYS = int(os.environ.get("WAF_RETENTION_DAYS", "90"))
#: 孤儿 `.trash` 超过一轮（默认 24h）才告警。
RAW_CLEANUP_ORPHAN_AGE_SEC = int(os.environ.get("WAF_RAW_CLEANUP_ORPHAN_AGE_SEC", "86400"))
#: 保留期**只做每日 dry-run 快照**；真正删除仍要求 admin 显式 apply。
RETENTION_SCHEDULER_ENABLED = os.environ.get(
    "WAF_RETENTION_SCHEDULER", "1").strip().lower() not in ("0", "false", "no", "off")
RETENTION_CHECK_INTERVAL_SEC = max(
    60, int(os.environ.get("WAF_RETENTION_CHECK_INTERVAL_SEC", "86400")))
#: 审计日志保留期：默认 90 天，系统每日自动清理；admin 也可手动预览/立即清理。
AUDIT_RETENTION_DAYS = int(os.environ.get("WAF_AUDIT_RETENTION_DAYS", "90"))
AUDIT_RETENTION_SCHEDULER_ENABLED = os.environ.get(
    "WAF_AUDIT_RETENTION_SCHEDULER", "1").strip().lower() not in ("0", "false", "no", "off")
AUDIT_RETENTION_INTERVAL_SEC = max(
    60, int(os.environ.get("WAF_AUDIT_RETENTION_INTERVAL_SEC", "86400")))
#: 按时间清理时每批删除的行数；勾选删除单次上限。
AUDIT_CLEANUP_BATCH = max(100, int(os.environ.get("WAF_AUDIT_CLEANUP_BATCH", "5000")))
AUDIT_SELECTED_MAX = max(1, int(os.environ.get("WAF_AUDIT_SELECTED_MAX", "500")))
#: 控制面持续吸收入库；采集器写入 raw 后最多一个周期就能在事件/告警页看到。
INGEST_SCHEDULER_ENABLED = os.environ.get(
    "WAF_INGEST_SCHEDULER", "1").strip().lower() not in ("0", "false", "no", "off")
INGEST_INTERVAL_SEC = max(
    2, int(os.environ.get("WAF_INGEST_INTERVAL_SEC", "5")))
#: 默认把整个敏感头值逐字符显示为 `*`；Cookie/Set-Cookie 不逐 cookie 解析。
SENSITIVE_HEADERS = {
    h.strip().lower()
    for h in os.environ.get(
        "WAF_SENSITIVE_HEADERS",
        "authorization,proxy-authorization,cookie,set-cookie,x-api-key,"
        "x-auth-token,x-csrf-token,x-session-id",
    ).split(",")
    if h.strip()
}
SECRET_PATH = Path(os.environ.get("WAF_CONSOLE_SECRET_FILE", str(HERE / ".secret")))
LOG_DIR = Path(os.environ.get("WAF_CONSOLE_LOG_DIR", str(HERE / "logs")))
RETENTION_DRY_RUN_FILE = Path(os.environ.get(
    "WAF_RETENTION_DRY_RUN_FILE", str(LOG_DIR / "retention-dry-run.json")))

POLICY_JSON = ARTIFACTS / "decision_policy.json"
#: 时序规则（攻击链）JSON：文件缺失/非法时回退 `service.correlate.DEFAULT_RULES`。
#: 默认指向 artifacts 下的可编辑文件；测试用 patch 指到临时目录。
TEMPORAL_RULES_JSON = Path(os.environ.get(
    "WAF_TEMPORAL_RULES", str(ARTIFACTS / "temporal_rules.json")))
#: 实体级抑制：默认 TTL、从误报生成草案的统计窗口/阈值、撤销后冷却期。
SUPPRESS_TTL_HOURS = max(1, min(2160, int(os.environ.get("WAF_SUPPRESS_TTL_HOURS", "168"))))
SUPPRESS_MAX_TTL_HOURS = 2160
SUPPRESS_SUGGEST_DAYS = max(1, min(90, int(os.environ.get("WAF_SUPPRESS_SUGGEST_DAYS", "30"))))
SUPPRESS_SUGGEST_MIN = max(1, int(os.environ.get("WAF_SUPPRESS_SUGGEST_MIN", "3")))
SUPPRESS_COOLDOWN_HOURS = max(0, int(os.environ.get("WAF_SUPPRESS_COOLDOWN_HOURS", "24")))
FEATURE_NAMES = ARTIFACTS / "feature_names_v2.json"
RULE_CANDIDATES = ARTIFACTS / "rule_candidates.json"
CURVES = ARTIFACTS / "curves"

# 模型代际 / 训练 staging / 切换备份。训练**只写 staging**，现役槽位文件只由
# 「切换现役」流程更新；否则训练会悄悄覆盖数据面正在使用的模型。
MODELS = ARTIFACTS / "models"
STAGING = ARTIFACTS / "staging"
SWITCH_BACKUP = ARTIFACTS / "switch_backup"

#: 数据面按固定文件名加载（`rust/src/engine.rs` 的常量）。切换模型时保持槽位名不变，
#: 只替换内容；采集器用内容 sha1 拒绝"新策略 + 旧内存模型"的混合状态。
LIVE_SLOTS = {
    "supervised": {
        "onnx": "xgboost_v20261015_001.onnx",
        "meta": "xgboost_meta.json",
        "model_json": "xgb_model.json",
        "trees": "xgb_trees.json",
    },
    "zero_day": {
        "onnx": "iforest_lean_v20261015_001.onnx",
        "meta": "iforest_meta.json",
        "model_json": "iforest_model.joblib",
    },
}

#: 训练任务 -> (通道, 变体)。只有 official 会参与「当前模型」判定。
TRAIN_CHANNELS = {
    "train_realdata": ("supervised", "official"),
    "iforest_csic": ("zero_day", "official"),
    "iforest_local": ("zero_day", "local"),
}

#: 用户上传训练数据（控制台）。文件与元数据都在这里；**不**写入 artifacts。
UPLOADS = Path(os.environ.get("WAF_UPLOADS_DIR", str(PY / "traindata" / "uploads")))
UPLOAD_PARSER = PY / "upload_parse.py"
UPLOAD_MAX_BYTES = int(os.environ.get("WAF_UPLOAD_MAX_BYTES", str(256 << 20)))
UPLOAD_MAX_ROWS = int(os.environ.get("WAF_UPLOAD_MAX_ROWS", "200000"))
UPLOAD_MAX_BODY = int(os.environ.get("WAF_UPLOAD_MAX_BODY", str(1 << 20)))
UPLOAD_MAX_PACKETS = int(os.environ.get("WAF_UPLOAD_MAX_PACKETS", "2000000"))
UPLOAD_MAX_FLOWS = int(os.environ.get("WAF_UPLOAD_MAX_FLOWS", "50000"))
UPLOAD_TIMEOUT_SEC = int(os.environ.get("WAF_UPLOAD_TIMEOUT_SEC", "600"))
UPLOAD_ROLES = ("supervised", "benign", "eval")
UPLOAD_FORMATS = {
    ".csv": "csv", ".tsv": "csv",
    ".json": "json", ".jsonl": "json", ".ndjson": "json",
    ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap",
}

MODEL_SETTINGS_DEFAULTS = {
    "max_per_channel": 10,
    "max_total": 20,
    "inherit_mode": "warm_start",     # off | lineage | warm_start
    "auto_register": True,
    "keep_curves": True,
}

# 规则通道（第三通道）产物。`rules_authoritative.json` 是**数据面唯一读的规则集**，
# 由控制台「提升」时生成；`rules_testvec.json` 是 Rust/Python 同源回归向量。
RULES_AUTHORITATIVE = ARTIFACTS / "rules_authoritative.json"
RULES_TESTVEC = ARTIFACTS / "rules_testvec.json"
RULE_CALIBRATION = ARTIFACTS / "rule_calibration.json"
CRS_IMPORT_REPORT = ARTIFACTS / "crs_import_report.json"

# 采集器 `--stats-out` 指向的指标文件（控制台轮询它拿 written/dropped/actions）。
COLLECTOR_METRICS = Path(
    os.environ.get("WAF_COLLECTOR_METRICS", str(RAW_DIR / "collector-metrics.json"))
)

#: 采集代理控制面可编辑配置（`app_settings` 的 `proxy.*` 键）。
#:
#: 刻意**不暴露** `out_dir` 与 `stats_out`：`ingest.py`/`ingest_scheduler` 只扫
#: `RAW_DIR`，控制台状态只读 `COLLECTOR_METRICS`。允许在界面上改这两项，最容易
#: 出现「代理在写、控制台没事件」的假故障。
PROXY_DEFAULTS = {
    # 多路由：一个采集器进程监听多个端口，每个端口映射一个上游。
    # 没有 `routes` 的老配置会在 `proxy_manager.get_config()` 里从
    # listen/upstream/upstream_tls 自动迁移成一条路由。
    "routes": [
        {"name": "default", "listen": "0.0.0.0:6188",
         "upstream": "127.0.0.1:80", "upstream_tls": False},
    ],
    # 旧单路由字段：与 routes[0] 保持同步；PUT 时仍兼容旧写法。
    "listen": "0.0.0.0:6188",
    "upstream": "127.0.0.1:80",
    "upstream_tls": False,
    "body_keep": 65536,
    "body_limit": 1048576,
    "headers_keep": 8192,
    "resp_body": "alert",
    "resp_body_keep": 65536,
    "file_size_mb": 256,
    "channel": 8192,
    "no_body": False,
    # 判定/阻断模式：off（纯采集）| dry_run（只记录）| enforce（命中返回 403）。
    # 默认 off，enforce 必须 admin 显式开启。
    "block_mode": "off",
    # 旧别名：block_mode != off。保存时自动同步。
    "score": False,
    "stats_interval": 60,
    "reload_interval": 5,
    "artifacts": str(ARTIFACTS),
    # 空字符串 = `--no-rules`（只跑模型/纯采集）。
    "rules": str(RULES_AUTHORITATIVE),
}

_EXE = "waf-collector.exe" if os.name == "nt" else "waf-collector"
#: 二进制只从这些固定位置解析（外加 `WAF_COLLECTOR_BIN` 覆盖），不接受请求传入。
#:
#: 顺序：仓库 `bin/`（构建脚本发布到这里）→ 仓库内 target → `WAF_CARGO_TARGET` →
#: 本机旧缓存 `E:\waf-target` → 一键安装的便携缓存（Windows `%LOCALAPPDATA%` /
#: Linux `~/.cache`）→ 旧 `rust/target`。
_CARGO_TARGET_ENV = os.environ.get("WAF_CARGO_TARGET", "").strip()
PROXY_BIN_CANDIDATES = [
    ROOT / "bin" / _EXE,
    ROOT / "proxy" / "bin" / _EXE,
    ROOT / "proxy" / "target" / "release" / _EXE,
]
if _CARGO_TARGET_ENV:
    PROXY_BIN_CANDIDATES.append(Path(_CARGO_TARGET_ENV) / "release" / _EXE)
PROXY_BIN_CANDIDATES += [
    Path(r"E:\waf-target") / "release" / _EXE,
    Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "waf-cargo-target" / "release" / _EXE,
    Path.home() / ".cache" / "waf-cargo-target" / "release" / _EXE,
    ROOT / "rust" / "target" / "release" / _EXE,
]
#: 托管进程的 PID 文件与日志（都在控制台日志目录下）。
PROXY_PID_NAME = "proxy.pid"
PROXY_LOG_KEEP = 10

TOKEN_TTL_SEC = int(os.environ.get("WAF_CONSOLE_TOKEN_TTL", "28800"))
#: 总览的事件聚合缓存（秒）：15s 轮询下 5s 足够，设 0 关闭。
OVERVIEW_CACHE_SEC = max(0, int(os.environ.get("WAF_OVERVIEW_CACHE_SEC", "5")))
#: 登录失败限流：窗口内失败达到上限后锁定一段时间（只影响该用户名）。
LOGIN_MAX_FAILS = max(1, int(os.environ.get("WAF_LOGIN_MAX_FAILS", "10")))
LOGIN_WINDOW_SEC = max(60, int(os.environ.get("WAF_LOGIN_WINDOW_SEC", "300")))
LOGIN_LOCK_SEC = max(60, int(os.environ.get("WAF_LOGIN_LOCK_SEC", "300")))
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "WAF_CONSOLE_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    ).split(",")
    if o.strip()
]

# 内置任务白名单：**不接受任意命令/参数**（避免把控制台变成 RCE 面）。
TASKS = {
    "train_realdata": ["train_realdata.py", "--features", "v2", "--hard-neg", "lexical", "--export"],
    "iforest_csic": ["iforest_lean_onnx.py", "--data", "csic", "--export"],
    "iforest_local": ["iforest_lean_onnx.py", "--data", "local", "--export"],
    "calibrate_csic": ["thresholds.py", "--pool", "csic"],
    "export_testvec": ["export_testvec.py"],
    "export_shap_ref": ["export_shap_ref.py"],
    "export_feature_names": ["export_feature_names.py"],
    "p8_e2e": ["p8_proxy_e2e.py"],
    "p4_local": ["p4_local.py"],
}

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
