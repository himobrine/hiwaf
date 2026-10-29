# 控制面 API（`python/service/`）

WAF 控制台的后端。**单机 + 账号 RBAC + 审计**，FastAPI + SQLite。取证包解压 br/zstd 依赖可选的 `brotli` / `zstandard`；缺失时返回明确的 `*_unsupported`，仍可下载原始字节。

```bash
cd F:\waf\python
py -3.10 -m pip install -r requirements-service.txt   # 只需一次
py -3.10 -m service.bootstrap             # 幂等建库 + admin（不启动服务）
py -3.10 -m service.run                   # http://127.0.0.1:8090/docs
```

一键安装（`INSTALL.md`）会建仓库根 `.venv` 并完成上面三步；之后可用
`.venv\Scripts\python.exe -m service.run`（Linux 为 `.venv/bin/python`）。
`service.bootstrap` 与首次启动等价：只建缺失的表/索引，已有账号和密码不会被覆盖。

首次启动会创建 `admin` 账号，初始密码写入 `service/.admin_password`（同时打印到控制台）。
登录后立刻改密码：`POST /api/auth/password`（改密后旧 token 立即失效）。
登录失败超过阈值会返回 429；登出同样会使该用户全部旧 token 失效。

开发前端时另起 `cd F:\waf\web && npm run dev`（5173，`/api` 已代理到 8090）。
生产：`npm run build` 后 FastAPI 直接托管 `web/dist`，单端口 8090。

---

## 1. 文件

| 文件 | 作用 |
| --- | --- |
| `config.py` | 路径、JWT 有效期、CORS、**任务白名单**（`TASKS`）、上传目录/格式/限额 |
| `db.py` | SQLite schema + 连接/查询工具（服务模式**线程内复用连接**，见 §2.2） |
| `auth.py` | PBKDF2 口令、HS256 JWT（标准库实现）、`current_user` / `require_at_least`、令牌版本校验 |
| `login_guard.py` | 登录失败限流（单进程内存；多 worker 需换共享存储） |
| `ingest.py` | `traindata/proxy/raw-*.jsonl` → `events`（**增量、幂等**，按字节偏移续读） |
| `ingest_scheduler.py` | 控制面周期增量入库；采集器写入后无需重启服务即可看到新事件/告警 |
| `packet.py` | 事件取证包：raw 回读、请求/响应头体、服务端解压、默认打码、原始体下载 |
| `rule_spans.py` | 规则命中精确标位：解码映射（`%XX`/`+`/`\uXXXX`）+ `scope`/局部-全文消歧 → UTF-16 区间 |
| `retention.py` | 90 天保留：raw/事件清理、dry-run/apply、pending/trash 状态机、孤儿 `.trash`、聚合表裁剪 |
| `retention_scheduler.py` | 每日非破坏性 dry-run 快照 + 审计；**不自动 apply** |
| `test_packet.py` | packet 纯函数测试（gzip/br/zstd、截断、打码、头字节计数） |
| `test_rule_spans.py` | 精确标位测试（编码映射、full 回拆、旧数据无 scope 消歧、未知字段不猜） |
| `test_rules_bulk.py` | 按 ID 批量规则操作（候选/自撰、block 资格、部分失败、删除范围） |
| `test_retention.py` | 聚合表裁剪与巡检快照/审计测试 |
| `uploads.py` | 用户上传训练数据：存储/子进程解析/重叠剔除/预览/软删除（解析在 `../upload_parse.py`） |
| `alerts.py` | 告警（聚合）下钻：同公式复算时间桶 + 精确匹配，取某聚合组的原始事件（含分页）；`dedup_groups` 做同源同类去重 |
| `correlate.py` | 同源攻击链：按 `(src_ip, ua)` + 间隔切链、阶段分类（探测/试探/利用）、扫描噪音降级、时序规则（`sequence/group_by/within`） |
| `suppression.py` | 实体级误报抑制：草案/审批/TTL/撤销/惰性过期、AND 匹配、告警/攻击链折叠、误报草案生成 |
| `proxy_manager.py` | 采集代理控制面：配置持久化/校验、二进制解析、受控启停、状态/日志、审计 |
| `sites.py` | 站点（Host）→ 模型：按逐条判决留证 + 策略快照反查每站点实际在跑哪套模型，并与现役对比定状态 |
| `audit_retention.py` | 审计保留：90 天 dry-run 预览、按时间分批清理、勾选删除、每次删除写 `audit_cleanup*` |
| `audit_retention_scheduler.py` | 审计日志每日自动清理（0 条不写审计；异常尽力写 `audit_cleanup_failed`） |
| `model_registry.py` | 模型代际登记、双上限保留、当前现役解析、父代/warm start、代际树（`build_lineage`） |
| `model_switch.py` | 切换现役/回滚编排（备份→写槽位→重标定→门禁→登记，失败全量回滚） |
| `test_model_registry.py` | 代际登记/去重/双上限保留/设置校验/现役解析测试 |
| `test_model_lineage.py` | 代际树：嵌套/多根排序/现役路径/父代缺失/自指/成环/通道隔离测试 |
| `test_model_switch.py` | 切换/回滚编排测试（mock 子进程与门禁，验证提交与回滚） |
| `test_task_plan.py` | 训练任务 argv 组装：staging/warm start/IForest 树数递增/降级 |
| `test_upload_parse.py` | 上传解析：CSV/JSON/JSONL/HAR/pcap 分片重传/TLS 跳过/标签别名 |
| `test_uploads.py` | 上传存储：格式/大小/来源校验、转换、预览、软删除、残留清理 |
| `test_task_plan_upload.py` | 上传训练 argv：add/only、lineage、校准集、非法数据拒绝 |
| `test_audit_retention.py` | 审计保留：dry-run、只删旧行、清理留痕、勾选删除、回滚、自动清理开关 |
| `test_alerts_drilldown.py` | 聚合下钻：精确匹配（子串不混入）、桶边界左闭右开、NULL 字段、分页；`dedup=1` 同源同类合并 |
| `test_correlate.py` | 攻击链：阶段分类、gap 切链、同毫秒稳定、噪音降级、时序窗口边界、规则 JSON 覆盖/回退、链下钻 |
| `test_suppression.py` | 抑制：实体校验、草案/审批/撤销/删除、TTL 惰性过期、AND 匹配保守语义、折叠计数、误报草案去重与冷却 |
| `test_proxy_api.py` | 采集代理：配置白名单/边界、地址注入、路径约束、argv、启停状态机、PID 复用保护、重启差异、日志尾部 |
| `test_proxy_live.py` | 采集代理真实二进制自检（`WAF_PROXY_LIVE_TEST=1` 才跑）：启动→转发→指标→停止 |
| `test_db_session.py` | 连接复用：`session()` 分组/嵌套、线程内长连接、换库自动重连、关池释放句柄 |
| `test_overview_cache.py` | 总览聚合：SQL 分桶直方图、越界夹取、TTL 缓存命中/关闭 |
| `test_events_paging.py` | 事件 keyset 分页：(ts,id) 游标不重不漏、`with_total=false` 跳过 COUNT、复合索引命中 |
| `test_retention_orphan.py` | 保留期兜底：raw 已不存在的过期事件（含 `src_file` 为空）分批删除、保留 feedback |
| `test_sites.py` | 站点→模型：多站点归组、版本解析、五种状态、同名模型、快照缺失、窗口/Top |
| `app.py` | 全部 REST 接口 + 静态前端托管 |
| `run.py` | uvicorn 启动器 |
| `smoke.py` | 冒烟自检（含审计保留预览、聚合下钻） |
| `demo_seed.py` | 开发用：假上游 + 采集器 + 判定，灌一小批真实数据 |

## 2. 角色

`viewer < analyst < admin`

| 能力 | viewer | analyst | admin |
| --- | :-: | :-: | :-: |
| 总览 / 事件列表 / 详情（不含 body） | ✅ | ✅ | ✅ |
| SHAP 归因、告警列表 | ✅ | ✅ | ✅ |
| **查看请求/响应取证包**（每次写审计） | ❌ | ✅ | ✅ |
| **显示敏感头 / 下载原始体**（每次写审计） | ❌ | ✅ | ✅ |
| 人工反馈、告警确认 | ❌ | ✅ | ✅ |
| 创建抑制草案 / 从误报生成草案 | ❌ | ✅ | ✅ |
| 审批 / 撤销 / 删除抑制 | ❌ | ❌ | ✅ |
| 策略预览 / 提升、零日开关、规则启停、任务 | ❌ | ❌ | ✅ |
| 上传训练数据 / 预览上传数据集 | ❌ | ✅ | ✅ |
| 删除上传数据集 | ❌ | ❌ | ✅ |
| raw 清理 dry-run / apply / pending 处置 | ❌ | ❌ | ✅ |
| 审计查询 / 保留预览 / 清理 / 勾选删除 | ❌ | ❌ | ✅ |

## 2.1 环境变量

| 变量 | 默认 | 作用 |
| --- | --- | --- |
| `WAF_CONSOLE_DB` | `service/console.db` | SQLite 路径 |
| `WAF_CONSOLE_SECRET_FILE` | `service/.secret` | JWT 密钥文件 |
| `WAF_CONSOLE_LOG_DIR` | `service/logs` | 任务日志目录 |
| `WAF_CONSOLE_TOKEN_TTL` | `28800` | JWT 有效期（秒） |
| `WAF_OVERVIEW_CACHE_SEC` | `5` | 总览事件聚合缓存（秒）；`0` 关闭。多标签页 15s 轮询下省重复 COUNT |
| `WAF_LOGIN_MAX_FAILS` | `10` | 登录失败多少次后锁定该用户名 |
| `WAF_LOGIN_WINDOW_SEC` | `300` | 失败计数滑动窗口（秒） |
| `WAF_LOGIN_LOCK_SEC` | `300` | 触发上限后的锁定时长（秒） |
| `WAF_CONSOLE_ORIGINS` | `http://127.0.0.1:5173,...` | CORS 白名单（逗号分隔） |
| `WAF_INGEST_SCHEDULER` | `1` | 是否周期性增量入库 |
| `WAF_INGEST_INTERVAL_SEC` | `5` | 增量 ingest 周期（秒，最小 2） |
| `WAF_RETENTION_DAYS` | `90` | 事件/raw 的保留天数（SQLite 与 raw 共用 cutoff） |
| `WAF_RETENTION_SCHEDULER` | `1` | 是否每日生成保留期 dry-run 快照；**从不自动 apply** |
| `WAF_RETENTION_CHECK_INTERVAL_SEC` | `86400` | 快照巡检周期（秒，最小 60） |
| `WAF_RETENTION_DRY_RUN_FILE` | `service/logs/retention-dry-run.json` | 最近一次巡检快照路径 |
| `WAF_AUDIT_RETENTION_DAYS` | `90` | 审计日志保留天数（1–3650） |
| `WAF_AUDIT_RETENTION_SCHEDULER` | `1` | 是否每日自动清理审计；`0` 关闭 |
| `WAF_AUDIT_RETENTION_INTERVAL_SEC` | `86400` | 审计自动清理周期（秒，最小 60） |
| `WAF_AUDIT_CLEANUP_BATCH` | `5000` | 按时间清理时每批删除行数 |
| `WAF_AUDIT_SELECTED_MAX` | `500` | 勾选删除单次上限 |
| `WAF_RAW_CLEANUP_ORPHAN_AGE_SEC` | `86400` | 孤儿 `.trash` 超过多久才登记/告警 |
| `WAF_SENSITIVE_HEADERS` | Authorization, Cookie, Set-Cookie, X-Api-Key... | 默认逐字符 `*` 打码的头名（逗号分隔，大小写不敏感） |
| `WAF_COLLECTOR_METRICS` | `traindata/proxy/collector-metrics.json` | 采集器 `--stats-out` 指标文件 |
| `WAF_COLLECTOR_BIN` | 自动查找 | 采集器可执行文件；覆盖 `proxy/target/release` / `E:\waf-target\release` 等候选 |
| `WAF_CARGO_TARGET` | `E:\waf-target` | 采集器/ Rust 共用构建缓存目录（影响二进制查找） |
| `WAF_TEMPORAL_RULES` | `artifacts/temporal_rules.json` | 时序规则 JSON；缺失/非法时回退内置 3 条规则 |
| `WAF_SUPPRESS_TTL_HOURS` | `168` | 抑制草案默认 TTL（小时，1–2160） |
| `WAF_SUPPRESS_SUGGEST_DAYS` | `30` | 从误报生成草案的统计窗口（天，1–90） |
| `WAF_SUPPRESS_SUGGEST_MIN` | `3` | 同一 `(src_ip, attack_type)` 至少多少条确认误报才生成草案 |
| `WAF_SUPPRESS_COOLDOWN_HOURS` | `24` | 撤销/过期后多久内不再自动生成同实体草案 |

## 2.2 性能与数据层

**连接复用（默认开启）**：`app.py` 在 lifespan 末尾调用 `db.enable_pool()`，
每个线程（uvicorn 线程池、ingest 线程…）持有一条 SQLite 长连接跨请求复用。
这不是微优化：本机实测**每条新连接的第一条语句约 23 ms**（打开库文件 + WAL 索引），
总览一次要跑十几条查询、前端 15s 轮询都付这个钱；复用后单查询降到 ~0.1 ms。

- 写入一律即时 `commit`，事务不会跨请求泄漏；`journal_mode` 只在本库不是 WAL 时才设置
  （它持久化在库文件头里，每次设置都会强制拿排它锁）。
- `db.session()` 是显式的「一组读写绑一条连接」，可嵌套；脚本/测试/批删仍可用它。
- 测试与一次性脚本**不开池**（`enable_pool(False)`），每次调用自己开关连接，
  临时库的文件句柄才能正常删除。
- 关池/换库用 `db.close_thread_connection()`；换 `WAF_CONSOLE_DB` 时会自动重连。

**总览聚合缓存**：`/api/overview/summary` 的事件部分（计数、直方图、Top 类型/路径）
按 `(DB 路径, window_hours)` 缓存 `WAF_OVERVIEW_CACHE_SEC` 秒。直方图在 SQL 里分桶
（`MIN(9, MAX(0, CAST(score*10 AS INTEGER)))`），不再把全窗口的分数行拉到 Python。

**事件索引**：`ix_events_ts`（纯时间序）+ `ix_events_action_ts(action, ts)` +
`ix_events_ip_ts(src_ip, ts)`。事件列表/告警都是「等值 + ts 范围 + ts 倒序」，
复合索引可直接按需扫描；旧单列 `ix_events_action` / `ix_events_ip` 是它们的前缀，
`init()` 会自动 `DROP`，减少 ingest 写放大。

**告警状态批量查询**：`/api/alerts` 先用一条 `WHERE group_key IN (...)` 取回全部
`alert_state`，不再每行查一次（最多 500 行 → 1 条 SQL）。

## 2.3 攻击链与时序规则

`correlate.py` 回答「同一源在窗口内到底做了一串什么事」，与聚合告警互补：

- **切链**：按 `(src_ip, ua)` 分组，事件按 `(ts, id)` 升序；相邻间隔 > `gap_min`
  就切新链。`chain_key = src_ip|ua|first_event_id`，随时间向后生长时保持不变，
  只有首事件滑出窗口才换 key——所以它可以直接当 `alert_state.group_key` 用，
  确认/关闭复用 `/api/alerts/ack`。
- **阶段分类**（优先级 拦截 > 告警 > 探测）：`block` → 利用；`alert` 或
  `supervised_flagged` → 试探；状态码 401/403/404 或「失败 + 敏感路径」→ 探测。
  成功的 `/login`、`/admin` 不算探测，避免把正常流量当扫描。
- **扫描噪音**：探测 ≥ 20 且没有任何拦截的链标 `noise=true`，级别降 P3；
  列表默认折叠（`include_noise=0`），只返回 `noise_hidden` 计数，避免端口扫描刷屏。
- **时序规则**：内置「扫描后利用」「试探后利用」「目录扫描风暴」；窗口从**上一阶段
  最后一条**事件起算（`within_min`），每个规则对每个分组只报最早一次命中。
  可用 `WAF_TEMPORAL_RULES` 指向 JSON 覆盖，非法规则逐条跳过、其余保留：

  ```json
  {"rules": [{"id": "scan_then_exploit", "name": "扫描后利用", "within_min": 10,
              "group_by": ["src_ip"],
              "stages": [{"stage": "recon", "min": 20}, {"stage": "exploit", "min": 1}]}]}
  ```
- **取数有界**：先取窗口内有 `block/alert` 的源 IP（最多 500），再取这些源的全部
  事件（最多 50000 行）；截断时返回 `truncated=true`，前端提示缩小窗口。

**同源同类去重**：`/api/alerts?dedup=1` 把 `src_ip + action + attack_type + 时间桶`
相同的路径合并成一行，`path_count` 是不同 `method path` 数；下钻走
`/api/alerts/events?dedup=1&attack_type=...`，条数仍与聚合行一致。

## 2.4 实体级误报抑制

规则熔断的粒度是**整条规则**；抑制的粒度是**实体**。典型场景：某个 IP 的 XSS
命中经人工确认全是误报——要的不是关掉 XSS 规则，而是「该 IP 的 XSS 命中在
控制台折叠 7 天」。

**边界**：只影响控制台告警可见性，**不改数据面 block/alert 判定**。被抑制的
命中仍会拦截/告警、仍进事件表与审计，只是聚合告警/攻击链列表默认折叠。

- **实体字段**：`src_ip` / `path` / `ua` / `host` / `attack_type`。多个字段是
  **AND**（同时满足才命中），至少一个非空；`path` 必须以 `/` 开头。
  `item` 缺少抑制要求的字段时视为**不匹配**（保守），避免误伤整组。
- **状态机**：`draft`（默认不生效）→ `active`（admin 审批，写入 `expires_at`）
  → `revoked`（人工撤销）/ `expired`（到期惰性扫描：读列表/生效项时顺手
  `UPDATE`，无后台线程）。删除只允许 `draft`/`revoked`；`active` 必须先撤销，
  审批轨迹保留在行内与审计里。
- **误报草案**：`POST /api/suppressions/suggest` 按 `(src_ip, attack_type)` 统计
  近 N 天 `feedback.verdict='false_positive'`，达到阈值才生成 `draft`；已有同签名
  草案/生效抑制、或撤销/过期仍在冷却期内 → 跳过。**只生成草案，不自动生效。**
- **匹配范围**：聚合组看 `src_ip/ua/host/attack_type/path`；攻击链额外支持
  `hosts[]` / `attack_types[]` / `top_paths[]`，任一命中即算（再与其它字段 AND）。
- **审计**：创建/扫描/审批/撤销/删除分别写 `suppress_create` / `suppress_suggest`
  / `suppress_approve` / `suppress_revoke` / `suppress_delete`。

## 2.5 采集代理控制面（`proxy_manager.py`）

控制台「采集代理」页（`/proxy`）管理 `waf-collector`：配置持久化 + 受控启停 + 日志。

- **配置**：存 `app_settings` 的 `proxy.*` 键；白名单字段，范围对齐
  `proxy/src/config.rs`（`body_keep<=body_limit`、`headers_keep 1..8192`、
  `resp_body_keep 1..65536`、`resp_body alert|all|off` 等）。保存只落库，
  **启动/重启才生效**；`/api/proxy/config` 返回 `restart_required`/`restart_keys`。
- **固定项**：`--out` 固定 `traindata/proxy`（ingest 只扫它），`--stats-out` 固定
  `WAF_COLLECTOR_METRICS`（状态页只读它）。界面不提供修改入口，避免假故障。
- **二进制**：只从 `WAF_COLLECTOR_BIN` 或固定候选路径解析，**不接受请求传入**；
  参数逐项校验，不拼 shell。
- **进程**：单实例 PID 文件（`logs/proxy.pid`）+ 端口探测；启动前探测端口占用；
  Windows 用 `CREATE_NO_WINDOW`，停止先 `taskkill /T`、5s 后 `/F`；服务重启后靠
  PID 文件接管，PID 复用需 `force=true`（二次确认 + 审计）。
- **日志**：`logs/proxy_YYYYmmdd_HHMMSS.log`，保留最近 10 份；`/api/proxy/log` 只读尾部。
- **审计**：`proxy_config_update` / `proxy_start` / `proxy_stop` /
  `proxy_force_stop` / `proxy_restart`。
- **权限**：状态/配置 viewer；日志 analyst；写操作 admin。

## 3. 接口

### 认证
- `POST /api/auth/login` → `{token, user}`
  - 失败按**用户名**限流：窗口内达到 `WAF_LOGIN_MAX_FAILS` 后返回 `429` + `Retry-After`；
    用户不存在与密码错误同样返回 401（内部跑等开销 PBKDF2，防时序枚举）。
- `GET  /api/auth/me`
- `POST /api/auth/logout`（写审计，并使该用户所有旧 token 立即失效）
- `POST /api/auth/password`（写审计；改密后旧 token 失效，需重新登录）

### 总览 / 采集面
- `GET  /api/overview/summary?window_hours=24` — 计数、分数直方图、Top 类型/路径、策略摘要、采集器指标、入库状态、**warnings**、**sites**
  - `sites`：站点（`events.host`）→ 模型。按窗口内每条判决的 `host` + `policy_version` 归组，
    再用 `policy_versions` 快照里的 `artifact[_sha1_16]` / 规则集指纹还原「该站点这条判决是谁算的」，
    名称从 `model_registry` 解析。每个站点给出 `status`：
    `in_sync`（最新判决 = 现役修订）/ `policy_old`（版本旧但监督模型相同，只差阈值/规则）/
    `stale`（监督模型 sha1 与现役不同，采集器未重启）/ `unscored`（窗口内无带判定的事件）/
    `unknown`（快照缺失或现役读不到）。另含 `total_hosts` / `shown`（Top 100）、逐版本明细、
    `artifact_dirs`（留证里的产物目录，多站点跑不同产物时可见）。**只读，不改任何状态。**
- `GET  /api/collector/status` — 采集器 `--stats-out` 指标文件
- `GET  /api/proxy/status` — 采集代理完整状态（进程/PID/uptime、指标、输出目录、二进制、warnings）
- `GET  /api/proxy/config` — 保存配置 + 实际生效值 + `restart_required` / `restart_keys`
- `PUT  /api/proxy/config`（admin）— 白名单校验后落库；启动/重启才生效
- `POST /api/proxy/start`（admin）— 已在跑/端口占用/二进制缺失返回 409
- `POST /api/proxy/stop`（admin）— body `{"force":true}` 用于 PID 复用/未托管进程
- `POST /api/proxy/restart`（admin）
- `GET  /api/proxy/log?tail=200`（analyst）— 托管日志尾部
- `GET  /api/health/degradation` — 模式（dry_run/collect_only/unknown）、零日开关、阈值、warnings
- `POST /api/ingest/scan`（analyst）body `{with_body:false}`
- `GET  /api/ingest/state`
- 控制面默认每 5s 自动增量 ingest；只消费以换行结尾的完整 JSONL 行，按 `ingest_state.offset`
  续读，采集器持续写盘时无需重启服务。新事件仍由采集器规则引擎产出的 `rules` 决定，
  ingest 不会补判或改写 `pred/action`。

### 事件
- `GET /api/events?limit&offset&action&src_ip&path&min_score&from_ts&to_ts&q&rule_testing`
  - **keyset 翻页**：带 `cursor_ts` + `cursor_id` 时用 `(ts, id) < (cursor)` 定位下一页
    （`ORDER BY ts DESC, id DESC`），不扫描/丢弃前 N 行；此时忽略 `offset`。
    返回 `has_more` / `next_cursor:{ts,id}`，前端存每页起点游标即可前后翻页。
  - `with_total=false` 跳过 `COUNT(*)`，返回 `total: null`；翻页时总数沿用第一页。
  - 不带游标时行为与旧版一致（`offset` + `total`），供脚本/兼容调用。
- `GET /api/events/{id}` — 含 `shap`（Top-8）、`related`（±10min 同源）、`has_body`、`feedback`；
  规则证据优先读 `events.rule_hits_json`，旧事件缺失时回退 `event_rules` 明细
  （新写入的 `event_rules` 带 `scope/start/end`；旧行缺偏移时前端只做字段级降级）
- `GET  /api/events/{id}/packet?reveal=false`（analyst，**每次写审计**）
  - 一次返回请求 + 响应：起始行、全部有序头、响应状态/版本、body 对象（`b64` / `decoded_text` /
    `decoded_encoding` / `decoded_is_binary` / `wire_bytes` / `stored_bytes` / `truncated` /
    `decode_truncated` / `decode_error` / `content_encoding`）。
  - 同时返回 `rule_hits[].segments`：服务端把规则解码空间里的 `start/end` 映射回**当前包展示文本**，
    前端只染正则实际匹配的片段（`%20`/`+`/`\uXXXX` 不会错位；`full` 命中按字段拆开）。
  - 默认对敏感头值逐字符显示 `*`（`Authorization/Cookie/Set-Cookie/...`）；`reveal=1` 返回原值并额外写
    `view_sensitive_headers`。响应体在服务端解 gzip/deflate/br/zstd（缺 `brotli`/`zstandard`
    时返回明确的 `*_unsupported`，仍可下载原始字节）；解码输出上限 1MB。
  - raw 缺失/旧采集器字段不足时返回 `reconstructed=true` + 原因，**不伪造**头或 body。
- `GET  /api/events/{id}/packet/body?side=request|response`（analyst，**先审计后返回**）
  - 下载**存盘的原始 wire bytes**（响应压缩体不在这里解压）；`Content-Disposition: attachment`、
    `no-store`、`nosniff`；文件名固定为 `event-<id>-<side>[-truncated].bin`。
- `GET  /api/events/{id}/body`（analyst，兼容旧前端；新前端已不再调用）

### 90 天保留 / raw 清理（admin）
- `GET  /api/retention/raw-cleanup?days=90` — dry-run；审计 `raw_cleanup_dry_run`
- `POST /api/retention/raw-cleanup` body `{days, confirm, note}` — 必须 `confirm=true`
- `GET  /api/retention/raw-cleanup/pending` — pending/manual 列表 + 计数
- `GET  /api/retention/raw-cleanup/scheduled` — 最近一次内置 dry-run 快照 + 是否启用
- `POST /api/retention/raw-cleanup/pending/resolve` body `{path, action, confirm, note}`
  - `action=retry`：清零 attempts，回到 pending
  - `action=adopt`：以当前 path/trash 的 size/mtime 刷新（唯一的 stat 绕过，审计旧/新值）
  - `action=forget`：删除 pending 行；**不删 raw/trash**；已按清理顺序删除的 DB 事件不会恢复

清理顺序是 **先删 DB 事件并写 pending，再 rename 到 `<path>.trash` 后校验/删除文件**。
文件候选必须同时满足：该文件所有事件 `MAX(ts) < cutoff`、文件 `mtime < cutoff`、
`ingest_state` 的 `size/lines/mtime` 与实际一致；否则跳过并报告 `pending_ingest`。
path/trash 同时存在、symlink、stat 不匹配都不会自动删；连续 5 次 stat 不匹配转 `manual`。
无 pending 的孤儿 `.trash` 超过一轮只登记为 `manual` 并告警，**绝不自动删除**。

内置巡检每天只跑 dry-run，把最近结果写到 `WAF_RETENTION_DRY_RUN_FILE` 并写审计
`retention_dry_run_scheduled`；**不会自动 apply**。需要真正删除时仍由 admin 显式调用
`POST /api/retention/raw-cleanup`。dry-run/apply 的 `aggregates` 段会同时统计/清理
`rule_hits_daily`（cutoff 当天之前的 UTC 日桶）和已 resolved 且解决时间早于 cutoff 的
`rule_incidents`；open/acked incident 永不按时间删除。

**`orphan_events` 兜底**：`scan_candidates` 只遍历 `RAW_DIR` 里**现存**的文件，被外部删掉
（换机、手工清理、磁盘故障）的 raw 对应的事件行会永远留着。dry-run/apply 的 `orphan_events`
段按 `ts < cutoff` + `src_file` 分组，文件不存在的整组删除（`src_file` 为空的旧行同样按过期处理），
每批 1000 行、单次上限 50000 行；`event_shap` / `event_bodies` / `event_rules` 一起删，
**`feedback` 保留**（人工结论不随证据过期丢弃）。

### 告警
- `GET  /api/alerts?window_hours&bucket_min&dedup&include_suppressed` — 默认按 **源IP + 动作 + 方法/路径 + 时间桶**
  聚合；`dedup=1` 改为 **源IP + 动作 + 攻击类型 + 时间桶**，返回 `path_count`。
  生效中的实体级抑制默认折叠，返回 `suppressed_hidden` 计数；`include_suppressed=1`
  保留行并附 `suppression` 摘要（用于「已抑制」标签）。
- `GET  /api/alerts/events` — 下钻：`src_ip/action/bucket/bucket_min/method/path/limit/offset`，
  与聚合同公式复算时间桶（左闭右开）、method/path 精确匹配（NULL 归一空串），
  服务端分页；保证抽屉里的条数 = 聚合行的 n。`dedup=1&attack_type=...` 走下钻合并组。
- `GET  /api/alerts/chains?window_hours&gap_min&min_events&only_suspicious&include_noise&include_suppressed&limit`
  — 同源攻击链（见 §2.3），附带 `status/assignee`（同 `alert_state`）与 `sequences`；
  同样返回 `suppressed_hidden`，`include_suppressed=1` 时保留被抑制链
- `GET  /api/alerts/chains/events?src_ip&ua&from_ts&to_ts&limit&offset`
  — 链下钻：同源 + 同 UA + 时间范围，返回 `stage` 阶段分类
- `POST /api/alerts/ack` body `{group_key, status, assignee}`（链的 `chain_key` 同样走这里）

### 实体级抑制（见 §2.4）
- `GET  /api/suppressions?status&limit` — 列表；`status` 可选 `draft/active/revoked/expired`，
  同时返回 `default_ttl_hours` / `max_ttl_hours`
- `POST /api/suppressions` body `{src_ip?, path?, ua?, host?, attack_type?, reason, ttl_hours?, note?}`
  — 创建**草案**（analyst+）；至少一个实体字段，多个字段 AND
- `POST /api/suppressions/suggest` body `{days?, min_count?, ttl_hours?, limit?}`
  — 从人工确认误报生成草案（analyst+），返回 `scanned/created/skipped`
- `POST /api/suppressions/{id}/approve` body `{note?}` — admin 审批，写入 `expires_at`
- `POST /api/suppressions/{id}/revoke` body `{note?}` — admin 撤销草案/生效项
- `DELETE /api/suppressions/{id}` — admin；只允许 `draft`/`revoked`，`active` 必须先撤销

### 策略（**唯一事实来源仍是 `artifacts/decision_policy.json`**）
- `GET  /api/policy` — 现役策略 + 版本历史 + warnings
- `POST /api/policy/preview`（admin）body `{pool, fpr, zero_day}` → 写**临时文件**，不动现役策略
- `POST /api/policy/promote`（admin）→ 调 `thresholds.py` 写现役策略 + 刷新 `testvec.json`
- `POST /api/policy/zero-day`（admin）body `{enabled}` → 用现役策略的 pool/fpr 重跑

`pool` 只接受 `csic` / `lexical` / `file:<仓库内路径>`。

### 反馈 / 规则 / 模型 / 任务 / 审计
- `POST /api/feedback`（analyst）· `GET /api/feedback` · `GET /api/feedback/export`
- `GET  /api/rules` · `PATCH /api/rules/{rule}`（admin）· `POST /api/rules/bulk-enable`（admin）
  - `PATCH` / `bulk-enable`：只对挖出的候选（`mined`）；`action=block` 只对 `verdict=keep` 开放。
  - `POST /api/rules/bulk`（admin）body `{scope:"mined"|"custom", ids:[...], op:"enable"|"disable"|"set_action"|"delete", action?}`：
    按页面选中的 ID 逐条执行，返回 `changed` / `skipped` / `errors`，允许部分成功；删除只对 `custom` 开放。
    批量写只改控制面，仍需「提升到现役」才会进入数据面。
  - 自撰/导入规则走 `/api/rules/custom/{id}`（`POST` / `PUT|PATCH` / `DELETE` / `POST .../validate`）。
    `source` 取值：`manual`（界面手写）、`crs`（`import_crs.py`）、`wafjson`（`import_waf_rules.py`
    导入 `rules/waf_rules.json`）；`mined` 是挖出的候选（不在 `rules_custom` 表里）。
  - **生命周期**：草稿 → `validate` 三关（① 编译 ② 真实良性 0 误报 ③ 攻击池 >0；guard 跳过 ③）
    → `enable` 进入**测试中**（强制 `action=alert`）→ 在线证据 + `POST /qualify` 人工确认
    → 逐条翻 `block` → `POST /api/rules/promote` 提升到现役。
    `kind=guard`（管理入口、`.git` 探测等）只需 ② + 管理员政策理由；有良性命中时**拒绝合格**。
  - `GET /api/rules/{id}/evidence?days=7`：在线证据分桶（`confirmed_attack` / `confirmed_benign` /
    `suspected_attack` / `unlabeled`）+ 离线三关 + 样本；自撰规则还会带 `history` / `history_ok`。
  - `POST /api/rules/custom/{id}/history-evidence` body `{days?, max_events?}`（analyst）：
    把规则拿到过去 N 天（默认 30 / 上限 90）的事件上重放，用事件已有的人工标签判定。
    `confirmed_attack ≥ 1` 且 `confirmed_benign = 0`、并且 ② 真实良性零误报已通过，
    才能作为合格证据；结果缓存到 `rule_history_evidence`（带规则内容指纹，规则一改即失效）。
    适用于「先有攻击、后补规则」，不用先重放攻击制造在线命中。
  - 批量启用测试：`POST /api/rules/custom/bulk-enable`；确认/撤销合格：`POST /api/rules/{id}/qualify` / `unqualify`。
  - 删除自撰规则：`DELETE /api/rules/custom/{id}`（admin）——删 DB 行 + 历史回放证据 +
    熔断行，并**立即从现役规则集定向移除**（patch 产物 + 策略版本 +1 + 重导出 testvec，
    采集器 ≤5s 热重载）；写入失败会整体回滚，不会出现「DB 删了但现役还在」。
  - 规则页支持关键词搜索、各状态列筛选、行选择批量启用/停用/改动作/删除（admin）。
- **熔断 / incident**：
  - `POST /api/rules/breaker` body `{scope:"rule"|"all_block"|"channel", rule?, reason?}`；
  - `POST /api/rules/breaker/restore` body `{rule?}` / `{all:true}` / `{all:true, channel_on:true}`；
  - `POST /api/rules/breaker/bulk-restore`（admin）body `{rules:[...]}`：按选中熔断项逐条恢复。
  - `GET /api/rules/incidents?status=open`、`POST /api/rules/incidents/{id}/ack` / `resolve`；
  - `POST /api/rules/incidents/bulk`（analyst）body `{ids:[...], op:"ack"|"resolve", restore?, note?}`：
    批量已阅/解决，允许部分成功；`restore=true` 时按熔断快照恢复（admin 建议用于确认误报）。
  - `POST /api/rules/monitor/scan` 手动触发一次扫描（admin）；
  - `GET|PUT /api/rules/monitor/settings`（PUT=admin）body `{auto_breaker?, breaker_alerts?}`：
    下一轮扫描生效，不用重启；`/api/rules` 响应里的 `monitor` 块同步返回。
  - 熔断只 patch 现役产物，不改 DB 里的规则动作。
  - **已验证规则（`qualified_at` / proven）永不自动熔断**：只生成 `confirmed_fp` /
    `hit_spike` 告警，降级必须由人点。自动熔断只作用于**未验证**的 alert 规则
    （噪声达标 → `mode=disable` 移出现役 + 留 incident）。
  - `auto_breaker=false`：监控只告警、绝不改规则集；`breaker_alerts=false`：不再生成
    `confirmed_fp` / `noise`（即将执行的自动动作仍强制留 incident）；
    `hit_spike` / `block_spike` **永远保留**，不受任何开关影响。
- **模型代际 / 切换**（详见 §3.1）：
  - `GET  /api/models`：产物清单 + 代际登记 + 代际树 `lineage` + 当前现役 + 保留策略 + 可 warm start 的父代。
  - `GET  /api/models/current` · `GET /api/models/{id}` · `GET /api/models/{id}/curve`
  - `PATCH /api/models/{id}`（analyst）body `{display_name?, notes?}`：改名/备注。
  - `GET|PUT /api/models/settings`（PUT=admin）：双上限保留 + 继承模式开关。
  - `POST /api/models/prune`（admin）body `{dry_run:true|false}`：按策略清理快照（保留元数据行）。
  - `POST /api/models/register-live`（admin）：把磁盘现役产物补登记进代际表。
  - `POST /api/models/{id}/preflight`：切换前检查（只读）。
  - `POST /api/models/{id}/switch`（admin）· `POST /api/models/rollback/{channel}`（admin）：
    起一个后台任务，走「备份→写槽位→重标定→testvec/SHAP→门禁」；失败全量回滚。
  - `GET  /api/models/switches`：切换/回滚记录。
  - `GET  /api/models/curves/{name}`：曲线库（旧接口，保留）。
- `POST /api/tasks`（admin）· `GET /api/tasks` · `GET /api/tasks/{id}` · `GET /api/tasks/{id}/log`
- 上传数据：`POST /api/uploads`（analyst，multipart）· `GET /api/uploads` ·
  `GET /api/uploads/{id}` · `GET /api/uploads/{id}/preview` · `DELETE /api/uploads/{id}`（admin）。
  解析由固定脚本 `python/upload_parse.py` 子进程完成；训练任务可用 `data_mode=add|only`
  选择上传数据，服务端只把生成好的路径写进白名单 argv。
- 审计（admin）：`GET /api/audit` ·
  `GET /api/audit/retention?days=90`（dry-run 预览）·
  `POST /api/audit/retention` body `{days,confirm}`（按时间清理）·
  `POST /api/audit/delete` body `{ids,confirm,reason?}`（勾选删除）。

### 3.1 模型代际与切换现役

数据面按**固定文件名**加载模型（`rust/src/engine.rs` 的 `XGB_ONNX` / `IF_ONNX`）。
因此「训练完直接覆盖 `artifacts/*.onnx`」会把线上模型换成半成品。本系统改成：

1. **训练只写 staging**：`artifacts/staging/task_<id>/`，含 `model.onnx`、meta、
   训练件（`xgb_model.json` / `iforest_model.joblib`）与曲线。
2. **训练成功自动登记**（`auto_register`）为一代：产物快照到
   `artifacts/models/<channel>/gen-XXXX-<sha>/`，写 `model_registry`（通道 / 代次 / 父代 /
   指标 / 曲线 / 特征维度），并按保留策略清理最老的**非现役**快照。
   被清理的行不删（`status='pruned'`，`snapshot_dir=NULL`），血缘与曲线仍可查。
3. **warm start**：`--parent-model` 从上一代继续训练（XGBoost 追加树；
   IsolationForest `warm_start=True` 增量树）。校验特征版本 / 维度 / 标签一致，不一致拒绝。
   曲线 x 轴用「总树数」右移，多代可对比。
4. **切换现役**（admin，走后台任务）：备份现役 → 目标快照写入固定槽位 →
   `thresholds.py` 重标定 → `export_testvec.py` →（监督通道）`export_shap_ref.py` →
   `waf-ai-proto` 门禁 → 更新登记表。任一步失败**全量回滚**，没有绕门禁的快速恢复。
5. **切换后必须重启采集器**：`Engine::reload_policy` 比较策略里的 `artifact_sha1_16`
   与**已加载文件**的 sha，不一致就拒绝热重载（避免「新阈值 + 旧内存模型」）；
   控制台把这种状态标成 `pending_restart`，采集器指标也会上报 `model_*_sha1_16`。

**代际传承树**：`GET /api/models` 额外返回 `lineage`，每个通道给出
`tree`（嵌套节点，带 `depth`）/ `roots` / `orphans` / `current_id` / `path_to_current` /
`max_generation` / `stats`（按状态计数、血缘边 / warm start 边、树深）/ `variants`。
结构由 `model_registry.build_lineage()` 纯函数整理，**不信任 `parent_id`**：父代缺失、
自指、成环一律降级为根并记入 `orphans`（`missing` / `self` / `cycle`），
保证前端拿到的永远是可渲染的树 —— 一条脏数据不会让整页白屏。
前端把树画在「模型与门禁」的「模型代际与传承」卡片里：颜色 = 状态，蓝色连线 = 现役血脉，
空心虚线 = 快照已清理；点节点可看该代的血缘链 / 子代 / 切换记录（只读）。

保留策略（`app_settings`，默认）：`max_per_channel=10`、`max_total=20`、
`inherit_mode=warm_start`、`auto_register=true`、`keep_curves=true`。
双上限同时生效，但**现役模型永不清理**，实际保存数可能略超上限。

### 3.2 训练数据（上传 / 事件选择）

两种来源，**产物同形**：上传**原始 HTTP 请求**（不是预计算特征），或在「事件」页
勾选/按筛选把 WAF 自己看到的事件固化成数据集。训练任务可以「内置基线 + 数据集」或
「仅数据集」。训练仍只写 staging，上线仍走 §3.1 的切换门禁。

**存储与状态**

- 目录：`traindata/uploads/<uuid>/`。上传含 `original.<ext>` + `convert.log`；
  事件选择含 `selection.json`（筛选条件/事件 id 快照）。
  两者都产出 `requests.jsonl`（全量归一化行）、`requests_train.jsonl`
  （剔除官方评估集重叠后的训练副本）、`stats.json`。
- 元数据：`uploaded_datasets` 表（来源 `origin` / 角色 / 格式 / sha256 / 行列统计 /
  状态 / 错误 / 来源说明 / 选择快照 `selection_json`）。
- 状态：`converting → ready | failed`；删除为软删除 `pruned`（元数据保留，目录删除）。
- 启动时 `uploads.cleanup_stale()` 把上次进程遗留的 `converting` 标为失败（幂等）。

**事件选择（`service/datasets_events.py`）**

- **标签红线**：事件的 `attack_label` / `attack_type` 是模型预测，**不会**变成训练标签。
  标签由操作者在创建时显式指定（统一标签：0 良性；1-4 攻击类型；未细分用 1），
  每条行写 `label_why`，并随 `stats.selection` + 审计（`dataset_from_events` /
  `dataset_ready`）留痕。
- **快照**：创建时把行拷成文件；事件 90 天保留期清理 / raw 清理不影响已建数据集。
- **body 两级回退**：`event_bodies` → raw JSONL（按 `src_file` 分组一次扫描，
  `body` 文本或 `body_b64` 解出 UTF-8）→ 空；统计写在 `stats.body`
  （`from_db` / `from_raw` / `missing` / `empty` / `truncated`）。
  `missing` 只统计「本来有 body（`body_len>0`）却拿不到」，GET 这类
  `body_len=0` 记 `empty`，不是告警项。二进制 body 不伪造。
- **去重**：同一请求指纹 `method\\x1fpath\\x1fquery\\x1fbody` 只保留最新一条，
  丢弃数写入 `stats.dedup`（扫描器重复命中不会放大成训练样本）。
- **上限**：单次勾选 ≤ `WAF_EVENT_DATASET_MAX_IDS`（默认 5000）；
  单个数据集 ≤ `WAF_EVENT_DATASET_MAX_ROWS`（默认 20000，超出截断并在
  `selection.truncated` 标记）。

**API**

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/uploads` | analyst | multipart：`file`、`name`、`role`、`default_label`、`source_note` |
| POST | `/api/uploads/from-events` | analyst | 从事件建数据集：`name`、`role`、`label`、`source_note`、`mode=ids\|filter`、`event_ids` / `filters`、`max_rows` |
| POST | `/api/events/selection-preview` | analyst | 创建前预检（匹配数 / 抽查体量 / body 可得率 / 重复数），只读 |
| GET | `/api/uploads?limit=100&include_pruned=false` | viewer | 列表 `{items:[...]}`（含 `origin` / `selection`） |
| GET | `/api/uploads/{id}` | viewer | 详情（含 `label_stats` / `stats` / `exists`） |
| GET | `/api/uploads/{id}/preview?n=20` | viewer | 预览前 N 条归一化请求 |
| DELETE | `/api/uploads/{id}` | admin | 软删除；被运行中任务引用时拒绝 |

事件选择的 `filters` 与 `/api/events` 同语义（`action` / `src_ip` / `path` / `q` /
`min_score` / `from_ts` / `to_ts` / `rule_testing`），另支持 `attack_type`
（按模型分类**筛事件**，不是标签）与 `verdict`（人工 feedback 结论）。
`role=benign` 时 `label` 只能是 0；`supervised`/`benign` 必须填 `source_note`。

- `role`：`supervised` / `benign` / `eval`；`eval` 只能看，不能进训练。
- `default_label`：`0..4`，仅用于缺标签的行或 pcap 整份文件；CSV/JSON 行内 `label` /
  `attack_type` 优先。
- `source_note`：`supervised` / `benign` 必填（数据出处）。
- 限制：单文件 256MB、20 万行、pcap 200 万包 / 5 万流、body 1MB、解析超时 600s；
  可用 `WAF_UPLOAD_*` 环境变量覆盖。

**训练任务字段**（`POST /api/tasks`，`train_realdata` / `iforest_csic` / `iforest_local`）

```json
{
  "kind": "train_realdata",
  "inherit": "warm_start",
  "data_mode": "add",
  "dataset_ids": [3, 4],
  "calib_mode": "auto",
  "calib_dataset_id": 3
}
```

- `data_mode`：`official`（默认，不带数据集）/ `add`（内置基线 + 数据集）/ `only`（仅数据集）。
- `only` 强制 `inherit_mode=lineage`；监督通道移除官方 `--hard-neg`，零日通道把
  `--data csic|local` 换成 `--data upload`。
- `iforest_local` 的 `add`：第一个含良性样本的数据集作为**本地基线**（`--benign`，
  训练/校准留出从它切），其余数据集增量合并；基线会通过 `--upload-skip-id` 从 manifest
  里跳过，避免同一条请求同时进训练集和留出（只有基线一个数据集时不拼 manifest）。
- 服务端校验：数据集必须 `ready`、文件存在、角色不是 `eval`；监督 `only` 至少 2 类标签且
  ≥500 行（`add` 允许纯良性/纯攻击增量，由官方数据补足类别）；零日训练至少 50 条良性，
  `only` 至少 400 条良性；`calib_mode=upload` 要求校准集 ≥400 条良性。
- 服务端把清单写到 `staging/task_<id>/datasets.json`，argv 只包含固定脚本 + 该清单路径；
  前端不能传路径/命令。

**校准与防污染**

- 校准池优先用上传良性留出（≥200 条，近重复不跨界），不足回退官方 CSIC；
  `calib_mode=upload` 强制上传留出，切不出直接拒绝。
- 生成 `requests_train.jsonl` 时剔除与官方评估集（payload_test / lexical / CSIC holdout）
  精确重叠的请求，记录在 `stats.overlap_official_eval`。
- 训练产物额外写 `training_keys.txt`、`calibration_pool.jsonl`、`upload_stats.json`，
  meta 记录 `datasets` / `upload` / `training_keys_file`；切换时按目标模型 meta 选池，
  并把训练指纹传给 `thresholds.py --train-keys` 做污染检查。

**前端**

「训练数据」页负责上传/列表/预览/删除（列表多一列「来源」：上传 / 事件选择）；
「事件」页支持多选（跨页保留）与「加入训练数据」弹窗，可按勾选或按当前筛选全量创建，
提交前可预检体量与 body 可得率；「训练任务」页在训练通道下增加
「数据来源 / 数据集多选 / 校准池」；「模型与门禁」列表新增「训练数据」列展示出处。

### 3.3 审计保留（90 天）

只处理 `audit` 表，不动 events / raw / 聚合表。

- **默认保留 90 天**：`WAF_AUDIT_RETENTION_DAYS=90`；
- **系统每日自动清理**：`audit_retention_scheduler`，启动 30s 后跑第一次，之后每 24h；
  删 0 条不写审计，异常尽力写 `audit_cleanup_failed`；
  `WAF_AUDIT_RETENTION_SCHEDULER=0` 可关闭；
- **admin 手动清理**：审计页「清理旧审计」先 dry-run 预览（总记录/待删/保留/截止时间/
  动作分布），确认后按时间分批删除（`WAF_AUDIT_CLEANUP_BATCH=5000`）；
- **勾选删除**：审计页可多选行删除，单次上限 `WAF_AUDIT_SELECTED_MAX=500`，可填原因；
- **留痕**：每次真正删除后写一条新的 `audit_cleanup`（按时间）或
  `audit_cleanup_selected`（勾选）记录；删除在 `BEGIN IMMEDIATE` 事务内完成，
  写审计失败则整体回滚；
- 自动清理与手动清理共用进程内锁，不会互相穿插。

## 4. 红线（不要改坏）

1. **阈值不在 UI 状态里**：界面上没有自由编辑阈值的入口，只能「选池 → 预览 → 提升」，
   计算永远由 `thresholds.py` 完成。预览写临时文件，**不会**动现役策略。
2. **`pred` ≠ label**：入库只把模型输出写进判定字段；`events` 表**没有** label 列。
   人工结论进独立的 `feedback` 表，不覆盖 `pred`、不自动成为训练标签。
3. **body 默认不入库，但 raw 里有**：`event_bodies` 仍只在 `with_body=true` 时写；取证包直接回读
   raw。`packet`/`packet/body`/敏感头 reveal 全部要求 analyst+，且**每次读取都写审计**；
   viewer 前端**不请求** `/packet`，只显示事件字段和响应状态摘要。
4. **任务不接受任意命令**：只跑 `config.TASKS` 白名单里的脚本与固定参数。
5. **dry-run 必须显著**：总览/降级页都显示模式标签；采集器 `Pred.dry_run` 恒为 `true`。
6. **提升策略后必须重跑 Rust 门禁**；采集器会在 5s 内热重载（只热换阈值/开关/规则集，
   换模型产物必须先重启）。策略与规则集 sha1 不一致时规则证据权重按 0 处理（只少拦不误拦）。
7. **换模型只能走「切换现役」**：训练产物进 staging，绝不直接覆盖现役槽位；
   切换会备份 + 重标定 + 重出门禁向量 + 跑门禁，失败全量回滚。采集器用模型**内容 sha1**
   拒绝「新策略 + 旧内存模型」，切换成功后必须重启采集器。
8. **上传数据只进训练，不进现役**：上传解析/训练都写独立目录与 staging；
   `role=eval` 不可训练，预计算特征 CSV 不接受；训练副本必须剔除与官方评估集的精确重叠。
   pcap 只解析**明文 HTTP/1.x**，TLS/HTTP2 跳过并计数；不做解密、不从文件名猜标签。
   解析只跑固定脚本 `upload_parse.py`，路径/参数全部服务端生成。
9. **审计删除必须留痕**：删 `audit` 行只能走 `audit_retention`（按时间或勾选），
   每次删除后必须成功写入 `audit_cleanup*` 记录，写失败就回滚；清理只碰 `audit` 表，
   不碰 events / raw / 聚合表。

## 5. 自检

```bash
py -3.10 -X utf8 -m service.smoke          # 需要服务已启动；34 项
py -3.10 -X utf8 -m unittest service.test_packet -v   # packet 纯函数测试
py -3.10 -X utf8 -m service.test_rule_spans -v        # 规则命中精确标位测试
py -3.10 -X utf8 -m service.test_rules_bulk -v        # 按 ID 批量规则操作测试
py -3.10 -X utf8 -m service.test_ingest -v             # 增量 ingest 偏移/半行测试
py -3.10 -X utf8 -m service.test_retention -v         # 聚合表保留/巡检快照测试
py -3.10 -X utf8 -m service.test_model_registry -v    # 模型代际/保留策略/现役解析测试
py -3.10 -X utf8 -m service.test_model_lineage -v      # 代际树：嵌套/多根/缺失/自指/成环降级
py -3.10 -X utf8 -m service.test_model_switch -v      # 切换/回滚编排测试（mock 子进程/门禁）
py -3.10 -X utf8 -m service.test_task_plan -v         # 训练任务 argv/warm start 组装测试
py -3.10 -X utf8 -m service.test_upload_parse -v      # 上传数据 CSV/JSON/JSONL/pcap 解析测试
py -3.10 -X utf8 -m service.test_uploads -v           # 上传存储/转换/软删除测试
py -3.10 -X utf8 -m service.test_task_plan_upload -v  # 上传训练任务 argv 组装测试
py -3.10 -X utf8 -m service.test_audit_retention -v   # 审计保留/勾选删除/自动清理测试
py -3.10 -X utf8 -m service.test_alerts_drilldown -v  # 告警聚合下钻：桶边界/精确匹配/分页/去重
py -3.10 -X utf8 -m service.test_correlate -v         # 攻击链：阶段/gap 切链/噪音降级/时序规则
py -3.10 -X utf8 -m service.test_suppression -v       # 实体级抑制：状态机/TTL/匹配/折叠/误报草案
py -3.10 -X utf8 -m service.test_proxy_api -v         # 采集代理：配置校验/启停状态机/PID 保护
set WAF_PROXY_LIVE_TEST=1 && py -3.10 -X utf8 -m service.test_proxy_live -v  # 真实采集器自检
py -3.10 -X utf8 -m service.test_sites -v             # 站点→模型：归组/状态/快照反查
py -3.10 -X utf8 -m service.test_db_session -v        # 连接复用：session/线程内长连接/换库
py -3.10 -X utf8 -m service.test_overview_cache -v    # 总览：SQL 分桶直方图 + TTL 缓存
py -3.10 -X utf8 -m service.test_events_paging -v     # 事件 keyset 分页 + 复合索引命中
py -3.10 -X utf8 -m service.test_retention_orphan -v  # 保留期兜底：raw 已缺失的过期事件
py -3.10 -X utf8 -m service.demo_seed      # 灌一批真实采集数据（假上游 + 采集器 + 判定）
```

清理演练（**先 dry-run，确认后再 apply**）：

```bash
curl -s -H "Authorization: Bearer <admin-token>" \
  "http://127.0.0.1:8090/api/retention/raw-cleanup?days=90"
# 检查 scan.eligible、pending、orphan_trash、orphan_events 和每个 skipped 的 reason 后：
curl -s -X POST -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"confirm":true,"note":"90d retention"}' \
  "http://127.0.0.1:8090/api/retention/raw-cleanup"
```

## 6. 待办

- [x] **清理调度**：内置每日 dry-run 快照 + 审计（`retention_dry_run_scheduled`）；
      真正 apply 仍需 admin 显式确认，不会自动删 raw。
- [x] **`rule_hits_daily` / `rule_incidents` 的保留策略**：随 dry-run/apply 同一 cutoff 清理；
      只删 cutoff 前日桶与已 resolved 的旧 incident，open/acked 保留。
- [x] **数据层性能**：线程内连接复用、总览 SQL 分桶 + 5s 缓存、事件复合索引 + keyset 分页、
      告警状态批量查询（见 §2.2）。
- [x] **攻击链关联**：`correlate.py` 做同源 + UA 切链、阶段分类、扫描噪音降级与
      时序规则（`sequence/group_by/within`）；`/api/alerts?dedup=1` 做同源同类去重。
- [x] **实体级误报抑制**：`suppression.py` 做草案/审批/TTL/撤销/惰性过期与 AND 匹配；
      告警/攻击链默认折叠已抑制项，误报统计可生成草案（见 §2.4）。
- [x] **采集代理可操作性**：控制面 `proxy_manager.py` + `/api/proxy/*` + 前端「采集代理」页；
      配置持久化、受控启停/重启、日志尾部、接入手册（反向代理前置）。`out_dir`/`stats_out`
      固定，避免「代理在写、控制台没事件」。
- [ ] **抑制生效范围可再收窄**：目前实体字段是精确匹配；若需要 CIDR / 路径前缀 /
      正则 UA，需要新增匹配类型并写清审计与回滚语义。
- [ ] **用户管理页**：目前只有引导创建的 `admin`，没有增删改用户的接口。
- [ ] **SQLite 迁移到 Postgres**（若要多人并发/多机）。
