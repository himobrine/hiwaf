"""SQLite 存储层。

单机足够。连接有三种使用方式：

* **线程内复用（服务默认）**：`app.py` 启动时调用 `enable_pool()`。每个线程
  （uvicorn 线程池、ingest 线程…）持有一条连接并跨请求复用。这不是可选项：
  本机实测**每条新连接的第一条语句约 23 ms**（打开 DB + WAL 索引），
  总览一次十几条查询、15s 轮询都付这个钱；复用后降到 ~0.1 ms。
* **请求级分组**：`session()` 显式把一组读写绑到同一条连接（中间件或脚本）。
* **独立连接**：未开池、也没有 session 时（测试、一次性脚本）每次调用
  自己开/关，行为与旧版一致 —— 测试用临时库时不会留下文件句柄。

写入一律即时 commit，因此复用连接不会把事务跨请求泄漏出去。
事件由 `ingest.py` 从 `traindata/proxy/raw-*.jsonl` 增量灌入。
"""
from __future__ import annotations

import contextlib
import contextvars
import sqlite3
import threading
import time
from typing import Iterator, Optional, Tuple

from . import config

#: 当前请求/调用显式绑定的连接；None = 未开启 session。
_SESSION: contextvars.ContextVar[Optional[sqlite3.Connection]] = contextvars.ContextVar(
    "waf_db_session", default=None,
)
#: 服务模式：每个线程持有一条长连接（见模块 docstring）。
_POOL_ENABLED = False
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT UNIQUE NOT NULL,
  pw         TEXT NOT NULL,
  role       TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
  disabled   INTEGER NOT NULL DEFAULT 0,
  -- 令牌版本：改密/登出时 +1，旧 token 立即失效（auth.current_user 校验）。
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     INTEGER NOT NULL,
  actor  TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip     TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS ingest_state (
  path   TEXT PRIMARY KEY,
  size   INTEGER NOT NULL,
  mtime  REAL NOT NULL,
  lines  INTEGER NOT NULL,
  -- 已消费的字节偏移；周期性 ingest 从 offset 续读，避免每轮重扫整文件。
  offset INTEGER NOT NULL DEFAULT 0
);

-- raw JSONL 90 天清理：DB 行先删、文件后删，pending 是崩溃/失败后的幂等桥。
-- state 只有 pending/manual；删除成功直接删行，不设 done。
CREATE TABLE IF NOT EXISTS raw_cleanup_pending (
  path       TEXT PRIMARY KEY,
  size       INTEGER NOT NULL,
  mtime      REAL NOT NULL,
  cutoff_ms  INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  state      TEXT NOT NULL DEFAULT 'pending'
             CHECK (state IN ('pending', 'manual')),
  trash_path TEXT
);
CREATE INDEX IF NOT EXISTS ix_raw_cleanup_state ON raw_cleanup_pending(state, created_at);

CREATE TABLE IF NOT EXISTS events (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts                     INTEGER NOT NULL,
  ingest_ts              INTEGER NOT NULL,
  src_ip                 TEXT,
  src_port               INTEGER,
  host                   TEXT,
  route                  TEXT,
  method                 TEXT,
  path                   TEXT,
  query                  TEXT,
  body_len               INTEGER,
  body_truncated         INTEGER,
  status                 INTEGER,
  dur_ms                 REAL,
  bytes_in               INTEGER,
  bytes_out              INTEGER,
  ua                     TEXT,
  referer                TEXT,
  action                 TEXT,
  supervised_score       REAL,
  supervised_threshold   REAL,
  supervised_flagged     INTEGER,
  zero_day_score         REAL,
  zero_day_threshold     REAL,
  zero_day_score_crossed INTEGER,
  zero_day_flagged       INTEGER,
  zero_day_enabled       INTEGER,
  attack_label           INTEGER,
  attack_type            TEXT,
  model_artifacts        TEXT,
  dry_run                INTEGER,
  enforced               INTEGER NOT NULL DEFAULT 0,
  src_kind               TEXT,
  src_file               TEXT,
  src_line               INTEGER,
  policy_version         INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_events_src ON events(src_file, src_line);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
-- 复合索引：事件列表/告警都是「等值 action/src_ip + ts 范围 + ts 倒序」，
-- 单列索引只能定位一半，再回表排序；复合索引可直接按需扫描。
-- 旧的 ix_events_action / ix_events_ip 是它们的前缀，已在 init() 里删除。
CREATE INDEX IF NOT EXISTS ix_events_action_ts ON events(action, ts);
CREATE INDEX IF NOT EXISTS ix_events_ip_ts ON events(src_ip, ts);

CREATE TABLE IF NOT EXISTS event_shap (
  event_id     INTEGER NOT NULL,
  rank         INTEGER NOT NULL,
  feature      TEXT NOT NULL,
  value        REAL,
  contribution REAL,
  PRIMARY KEY (event_id, rank)
);

CREATE TABLE IF NOT EXISTS event_bodies (
  event_id INTEGER PRIMARY KEY,
  body     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  verdict  TEXT NOT NULL,
  note     TEXT,
  actor    TEXT NOT NULL,
  ts       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_state (
  group_key  TEXT PRIMARY KEY,
  status     TEXT NOT NULL DEFAULT 'open',
  assignee   TEXT,
  updated_at INTEGER NOT NULL,
  actor      TEXT
);

-- 实体级误报抑制：draft → active（带 TTL）→ revoked/expired。
-- 只影响控制台告警可见性，**不改**数据面判定（不因抑制而放行）。
-- 至少一个实体字段非空；多个字段是 AND（同时满足才命中）。
CREATE TABLE IF NOT EXISTS suppressions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  src_ip        TEXT,
  path          TEXT,
  ua            TEXT,
  host          TEXT,
  attack_type   TEXT,
  reason        TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft','active','revoked','expired')),
  ttl_hours     INTEGER NOT NULL DEFAULT 168,
  expires_at    INTEGER,
  created_by    TEXT,
  created_at    INTEGER NOT NULL,
  approved_by   TEXT,
  approved_at   INTEGER,
  revoked_by    TEXT,
  revoked_at    INTEGER,
  decision_note TEXT,
  note          TEXT,
  updated_at    INTEGER
);
CREATE INDEX IF NOT EXISTS ix_suppressions_status
  ON suppressions(status, expires_at);

CREATE TABLE IF NOT EXISTS policy_versions (
  version    INTEGER PRIMARY KEY,
  json       TEXT NOT NULL,
  actor      TEXT,
  created_at INTEGER NOT NULL,
  note       TEXT
);

CREATE TABLE IF NOT EXISTS rule_state (
  rule       TEXT PRIMARY KEY,
  enabled    INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  actor      TEXT,
  -- 「启用」只代表该规则**合格**；是否真拦截由 action 逐条决定（用户拍板）。
  action     TEXT NOT NULL DEFAULT 'alert'
);

-- 用户自撰规则（挖出的候选在 artifacts/rule_candidates.json 里，不进这张表）。
CREATE TABLE IF NOT EXISTS rules_custom (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  regex         TEXT NOT NULL,
  scopes        TEXT NOT NULL,          -- JSON 数组
  severity      TEXT NOT NULL DEFAULT 'medium',
  weight        REAL NOT NULL DEFAULT 1.0,
  action        TEXT NOT NULL DEFAULT 'alert',
  enabled       INTEGER NOT NULL DEFAULT 0,
  notes         TEXT,
  source        TEXT NOT NULL DEFAULT 'manual',
  validated_at  INTEGER,
  validation    TEXT,                   -- 三关结果 JSON
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  actor         TEXT
);

-- 每条事件命中的规则（证据，**不是标签**）。
CREATE TABLE IF NOT EXISTS event_rules (
  event_id INTEGER NOT NULL,
  rule     TEXT NOT NULL,
  field    TEXT NOT NULL DEFAULT '',
  weight   REAL,
  action   TEXT,
  snippet  TEXT,
  PRIMARY KEY (event_id, rule, field)
);
CREATE INDEX IF NOT EXISTS ix_event_rules_rule ON event_rules(rule);
CREATE INDEX IF NOT EXISTS ix_event_rules_event ON event_rules(event_id);

-- 规则命中按天聚合（头条数字 + 在线证据窗口；明细永远回 event_rules 查）。
CREATE TABLE IF NOT EXISTS rule_hits_daily (
  rule         TEXT NOT NULL,
  day          TEXT NOT NULL,          -- UTC 日期 YYYY-MM-DD（由事件 ts 换算）
  hits         INTEGER NOT NULL DEFAULT 0,
  block_hits   INTEGER NOT NULL DEFAULT 0,
  testing_hits INTEGER NOT NULL DEFAULT 0,
  last_ts      INTEGER,
  last_event   INTEGER,
  PRIMARY KEY (rule, day)
);
CREATE INDEX IF NOT EXISTS ix_rule_hits_daily_day ON rule_hits_daily(day);

-- 规则熔断/误报事件。系统只负责「发现 + 弹窗」，处置由人点（人工确认）。
CREATE TABLE IF NOT EXISTS rule_incidents (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  rule        TEXT,                    -- NULL = 全局（规则通道级）
  scope       TEXT NOT NULL,           -- rule | all_block | channel
  severity    TEXT NOT NULL,           -- high | medium
  status      TEXT NOT NULL DEFAULT 'open',   -- open | acked | resolved
  reason      TEXT NOT NULL,           -- confirmed_fp | noise | hit_spike | block_spike | manual
  detail      TEXT,                    -- JSON：窗口、命中、确认良性/攻击、样本 event_id
  opened_at   INTEGER NOT NULL,
  opened_by   TEXT,
  resolved_at INTEGER,
  resolved_by TEXT,
  note        TEXT
);
CREATE INDEX IF NOT EXISTS ix_rule_incidents_status ON rule_incidents(status, opened_at);

-- 被熔断的规则（产物级覆盖；**不改** rules_custom.action / qualified_at）。
-- build_authoritative 会把这些规则强制成 alert，恢复 = 删行 + 重新提升。
CREATE TABLE IF NOT EXISTS rule_breakers (
  rule          TEXT PRIMARY KEY,
  reason        TEXT NOT NULL,
  actor         TEXT NOT NULL,
  opened_at     INTEGER NOT NULL,
  incident_id   INTEGER,
  prev_action   TEXT,
  mode          TEXT NOT NULL DEFAULT 'alert',   -- alert（降级）| disable（移出现役）
  prev_rule_json TEXT,                            -- mode=disable 时用于恢复的规则快照
  note          TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,
  args       TEXT,
  status     TEXT NOT NULL,
  log_path   TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  ended_at   INTEGER,
  exit_code  INTEGER,
  actor      TEXT
);

-- 模型代际登记。文件快照在 artifacts/models/<channel>/gen-XXXX-<sha>/。
-- 被保留策略清理的行不删除（status='pruned'，snapshot_dir=NULL），这样父子血缘、
-- 训练指标和曲线历史仍然可查；只是不能再 warm start / 切换。
CREATE TABLE IF NOT EXISTS model_registry (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  channel            TEXT NOT NULL CHECK (channel IN ('supervised','zero_day')),
  variant            TEXT NOT NULL DEFAULT 'official',
  generation         INTEGER NOT NULL,
  display_name       TEXT NOT NULL,
  notes              TEXT,
  artifact_name      TEXT NOT NULL,
  snapshot_dir       TEXT,
  sha1_16            TEXT NOT NULL,
  bytes              INTEGER,
  meta_path          TEXT,
  curve_path         TEXT,
  trainable          INTEGER NOT NULL DEFAULT 0,
  parent_id          INTEGER,
  task_id            INTEGER,
  inherit_mode       TEXT NOT NULL DEFAULT 'full',
  features_version   TEXT,
  feature_dim        INTEGER,
  labels_json        TEXT,
  metrics_json       TEXT,
  recipe_json        TEXT,
  status             TEXT NOT NULL DEFAULT 'candidate'
                     CHECK (status IN ('candidate','active','archived','pruned')),
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER,
  activated_at       INTEGER,
  retired_at         INTEGER,
  actor              TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_model_channel_sha
  ON model_registry(channel, sha1_16);
CREATE UNIQUE INDEX IF NOT EXISTS ux_model_channel_gen
  ON model_registry(channel, generation);
CREATE UNIQUE INDEX IF NOT EXISTS ux_model_one_active
  ON model_registry(channel) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_model_created ON model_registry(created_at);

-- 切换现役模型的操作记录。一次切换 = 一个后台任务 + 一条记录。
CREATE TABLE IF NOT EXISTS model_switches (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  channel               TEXT NOT NULL,
  model_id              INTEGER NOT NULL,
  from_model_id         INTEGER,
  status                TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued','running','ok','failed')),
  task_id               INTEGER,
  backup_dir            TEXT,
  log_path              TEXT,
  policy_version_before INTEGER,
  policy_version_after  INTEGER,
  error                 TEXT,
  actor                 TEXT,
  created_at            INTEGER NOT NULL,
  started_at            INTEGER,
  ended_at              INTEGER
);
CREATE INDEX IF NOT EXISTS ix_model_switch_created ON model_switches(created_at);

-- 控制台可编辑设置（目前只用于模型保留/代际）。
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  actor      TEXT
);

-- 训练数据集（上传文件 / 事件选择两种来源，见 origin）。文件在
-- traindata/uploads/<storage_dir>/；删除只做软删除（status='pruned'），
-- 已登记模型的快照不依赖这里。
CREATE TABLE IF NOT EXISTS uploaded_datasets (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  name              TEXT NOT NULL,
  role              TEXT NOT NULL CHECK (role IN ('supervised','benign','eval')),
  format            TEXT NOT NULL,
  -- 来源：upload = 上传文件；events = 事件页人工选择（快照）。
  origin            TEXT NOT NULL DEFAULT 'upload',
  -- 事件选择的筛选条件 / 事件 id 快照（JSON；上传数据为 NULL）。
  selection_json    TEXT,
  status            TEXT NOT NULL DEFAULT 'converting'
                    CHECK (status IN ('converting','ready','failed','pruned')),
  storage_dir       TEXT,
  original_name     TEXT,
  size_bytes        INTEGER NOT NULL DEFAULT 0,
  sha256            TEXT,
  default_label     INTEGER,
  source_note       TEXT,
  rows_total        INTEGER NOT NULL DEFAULT 0,
  rows_kept         INTEGER NOT NULL DEFAULT 0,
  rows_skipped      INTEGER NOT NULL DEFAULT 0,
  label_stats_json  TEXT,
  stats_json        TEXT,
  error             TEXT,
  log_path          TEXT,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER,
  created_by        TEXT,
  deleted_at        INTEGER
);
CREATE INDEX IF NOT EXISTS ix_uploaded_status ON uploaded_datasets(status, created_at);
CREATE INDEX IF NOT EXISTS ix_uploaded_created ON uploaded_datasets(created_at);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


def _columns(conn: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _ensure_column(conn: sqlite3.Connection, table: str, col: str, ddl: str) -> bool:
    """幂等加列。返回是否真的加过。`CREATE TABLE IF NOT EXISTS` 不会补列。"""
    if col in _columns(conn, table):
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    return True


#: 老库迁移（新增列）。键 = 列名，值 = SQLite 类型 + 默认值。
MIGRATIONS = (
    ("ingest_state", "offset", "INTEGER NOT NULL DEFAULT 0"),
    # 令牌版本：老库补列，历史 token 的 ver 缺省为 0，与补列默认值一致。
    ("users", "token_version", "INTEGER NOT NULL DEFAULT 0"),
    ("events", "rule_set_sha1_16", "TEXT"),
    ("events", "rule_hits_json", "TEXT"),
    ("events", "rule_testing", "INTEGER NOT NULL DEFAULT 0"),
    # 多路由 / 真实拦截标记。
    ("events", "route", "TEXT"),
    ("events", "enforced", "INTEGER NOT NULL DEFAULT 0"),
    ("rule_state", "action", "TEXT NOT NULL DEFAULT 'alert'"),
    # 规则状态机 v2：启用 ≠ 合格。
    ("rules_custom", "kind", "TEXT NOT NULL DEFAULT 'detector'"),
    ("rules_custom", "compiled_at", "INTEGER"),
    ("rules_custom", "enabled_at", "INTEGER"),
    ("rules_custom", "qualified_at", "INTEGER"),
    ("rules_custom", "qualified_by", "TEXT"),
    ("rules_custom", "qualification_source", "TEXT"),
    ("rules_custom", "qualification_note", "TEXT"),
    # 命中明细带上展示字段（规则名/严重度），Rules 页样本弹窗直接读。
    ("event_rules", "name", "TEXT"),
    ("event_rules", "severity", "TEXT"),
    # 精确标位：start/end 是规则作用域文本里的字节偏移；scope 用来区分
    # `full`（全文字段）与 path/query/body 等单字段作用域。老行可为 NULL。
    ("event_rules", "scope", "TEXT"),
    ("event_rules", "start", "INTEGER"),
    ("event_rules", "end", "INTEGER"),
    # 熔断恢复时把动作还原到熔断前的值（产物级，不依赖 DB 当前意图）。
    ("rule_breakers", "prev_action", "TEXT"),
    ("rule_breakers", "mode", "TEXT NOT NULL DEFAULT 'alert'"),
    ("rule_breakers", "prev_rule_json", "TEXT"),
    # 数据集来源：上传 / 事件选择。
    ("uploaded_datasets", "origin", "TEXT NOT NULL DEFAULT 'upload'"),
    ("uploaded_datasets", "selection_json", "TEXT"),
)


def _open(path: str, **kw) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, **kw)
    conn.row_factory = sqlite3.Row
    # journal_mode 持久化在库文件头里；**每次连接都设**会强制拿排它锁
    # （本机实测 23–40 ms/次，API 延迟全被它吃掉）。只有不是 WAL 时才切换。
    mode = conn.execute("PRAGMA journal_mode").fetchone()
    if not mode or str(mode[0]).lower() != "wal":
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def connect() -> sqlite3.Connection:
    return _open(str(config.DB_PATH))


def _session_connect() -> sqlite3.Connection:
    """session 专用连接：允许跨线程创建/使用/关闭（同请求内串行）。"""
    return _open(str(config.DB_PATH), check_same_thread=False)


@contextlib.contextmanager
def session() -> Iterator[sqlite3.Connection]:
    """显式把一组读写绑到同一条连接；可嵌套（内层复用外层）。"""
    current = _SESSION.get()
    if current is not None:
        yield current
        return
    conn = _session_connect()
    token = _SESSION.set(conn)
    try:
        yield conn
    finally:
        _SESSION.reset(token)
        conn.close()


def enable_pool(enabled: bool = True) -> None:
    """服务启动时开启线程内连接复用；测试默认不开启。"""
    global _POOL_ENABLED
    _POOL_ENABLED = bool(enabled)
    if not _POOL_ENABLED:
        close_thread_connection()


def pooling() -> bool:
    return _POOL_ENABLED


def close_thread_connection() -> None:
    """关闭当前线程缓存的连接（换库 / 测试清理 / 进程退出前）。"""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _local.conn = None
    _local.path = None


def _thread_connect() -> sqlite3.Connection:
    path = str(config.DB_PATH)
    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "path", None) != path:
        close_thread_connection()
        conn = None
    if conn is None:
        conn = _session_connect()
        _local.conn = conn
        _local.path = path
    return conn


def _acquire() -> Tuple[sqlite3.Connection, bool]:
    """返回 (连接, 是否需要调用方关闭)。"""
    current = _SESSION.get()
    if current is not None:
        return current, False
    if _POOL_ENABLED:
        return _thread_connect(), False
    return connect(), True


def _execute_write(sql: str, params):
    conn, ephemeral = _acquire()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur
    finally:
        if ephemeral:
            conn.close()


def rows(sql: str, params=()):
    conn, ephemeral = _acquire()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        if ephemeral:
            conn.close()


def _migrate_data(conn: sqlite3.Connection) -> None:
    """一次性数据迁移（用 `PRAGMA user_version` 记进度，幂等）。

    v2（启用 ≠ 合格）：
      * 老库里 `validated_at` = 三关全过 ⇒ 回填 `compiled_at` / `qualified_at`；
        你当时把开关打开，本身就是一次人工放行，不能因为升级把现役 block 全部打回 alert。
      * `enabled_at` 回填成 `updated_at`，在线证据从那一刻开始算。
      * `sensitive-file` 类导入规则标成 `guard`（防御型），其余保持 detector。
    """
    ver = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
    if ver >= 2:
        return
    conn.execute(
        "UPDATE rules_custom SET compiled_at=validated_at "
        "WHERE compiled_at IS NULL AND validated_at IS NOT NULL"
    )
    conn.execute(
        "UPDATE rules_custom SET qualified_at=validated_at, qualified_by='migrated', "
        "qualification_source='offline_pool' "
        "WHERE qualified_at IS NULL AND validated_at IS NOT NULL"
    )
    conn.execute(
        "UPDATE rules_custom SET enabled_at=updated_at "
        "WHERE enabled_at IS NULL AND enabled=1"
    )
    conn.execute(
        "UPDATE rules_custom SET kind='guard' "
        "WHERE kind='detector' AND notes LIKE '%cat=sensitive-file%'"
    )
    conn.execute("PRAGMA user_version=2")


def init() -> None:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        for table, col, ddl in MIGRATIONS:
            _ensure_column(conn, table, col, ddl)
        # 复合索引 (action, ts) / (src_ip, ts) 已覆盖这两列单列索引的能力，
        # 老库把旧索引删掉，减少 ingest 的写放大。
        conn.execute("DROP INDEX IF EXISTS ix_events_action")
        conn.execute("DROP INDEX IF EXISTS ix_events_ip")
        _migrate_data(conn)
        conn.commit()
    finally:
        conn.close()


def one(sql: str, params=()):
    r = rows(sql, params)
    return r[0] if r else None


def scalar(sql: str, params=(), default=None):
    r = one(sql, params)
    if not r:
        return default
    return next(iter(r.values()))


def execute(sql: str, params=()) -> int:
    return _execute_write(sql, params).lastrowid or 0


def insert_ignore(sql: str, params=()) -> int:
    """返回 lastrowid（插入成功）或 0（被唯一约束忽略）。"""
    cur = _execute_write(sql, params)
    return cur.lastrowid or 0 if cur.rowcount else 0
