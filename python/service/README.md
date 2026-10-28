# 控制面 API（`python/service/`）

WAF 控制台的后端。**单机 + 账号 RBAC + 审计**，FastAPI + SQLite。取证包解压 br/zstd 依赖可选的 `brotli` / `zstandard`；缺失时返回明确的 `*_unsupported`，仍可下载原始字节。

```bash
cd F:\waf\python
py -3.10 -m pip install fastapi          # 只需一次
py -3.10 -m service.run                  # http://127.0.0.1:8090/docs
```

首次启动会创建 `admin` 账号，初始密码写入 `service/.admin_password`（同时打印到控制台）。
登录后立刻改密码：`POST /api/auth/password`。

开发前端时另起 `cd F:\waf\web && npm run dev`（5173，`/api` 已代理到 8090）。
生产：`npm run build` 后 FastAPI 直接托管 `web/dist`，单端口 8090。

---

## 1. 文件

| 文件 | 作用 |
| --- | --- |
| `config.py` | 路径、JWT 有效期、CORS、**任务白名单**（`TASKS`）、上传目录/格式/限额 |
| `db.py` | SQLite schema + 连接/查询工具（每调用一连接） |
| `auth.py` | PBKDF2 口令、HS256 JWT（标准库实现）、`current_user` / `require_at_least` |
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
| `alerts.py` | 告警（聚合）下钻：同公式复算时间桶 + 精确匹配，取某聚合组的原始事件（含分页） |
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
| `test_alerts_drilldown.py` | 聚合下钻：精确匹配（子串不混入）、桶边界左闭右开、NULL 字段、分页 |
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

## 3. 接口

### 认证
- `POST /api/auth/login` → `{token, user}`
- `GET  /api/auth/me`
- `POST /api/auth/logout`（写审计）
- `POST /api/auth/password`

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
- `GET  /api/health/degradation` — 模式（dry_run/collect_only/unknown）、零日开关、阈值、warnings
- `POST /api/ingest/scan`（analyst）body `{with_body:false}`
- `GET  /api/ingest/state`
- 控制面默认每 5s 自动增量 ingest；只消费以换行结尾的完整 JSONL 行，按 `ingest_state.offset`
  续读，采集器持续写盘时无需重启服务。新事件仍由采集器规则引擎产出的 `rules` 决定，
  ingest 不会补判或改写 `pred/action`。

### 事件
- `GET  /api/events?limit&offset&action&src_ip&path&min_score&from_ts&to_ts&q`
- `GET  /api/events/{id}` — 含 `shap`（Top-8）、`related`（±10min 同源）、`has_body`、`feedback`；
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

### 告警
- `GET  /api/alerts?window_hours&bucket_min` — 按 **源IP + 动作 + 方法/路径 + 时间桶** 聚合
- `GET  /api/alerts/events` — 下钻：`src_ip/action/bucket/bucket_min/method/path/limit/offset`，
  与聚合同公式复算时间桶（左闭右开）、method/path 精确匹配（NULL 归一空串），
  服务端分页；保证抽屉里的条数 = 聚合行的 n。
- `POST /api/alerts/ack` body `{group_key, status, assignee}`

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
    `suspected_attack` / `unlabeled`）+ 离线三关 + 样本。
  - 批量启用测试：`POST /api/rules/custom/bulk-enable`；确认/撤销合格：`POST /api/rules/{id}/qualify` / `unqualify`。
  - 规则页支持关键词搜索、各状态列筛选、行选择批量启用/停用/改动作/删除（admin）。
- **熔断 / incident**：
  - `POST /api/rules/breaker` body `{scope:"rule"|"all_block"|"channel", rule?, reason?}`；
  - `POST /api/rules/breaker/restore` body `{rule?}` / `{all:true}` / `{all:true, channel_on:true}`；
  - `POST /api/rules/breaker/bulk-restore`（admin）body `{rules:[...]}`：按选中熔断项逐条恢复。
  - `GET /api/rules/incidents?status=open`、`POST /api/rules/incidents/{id}/ack` / `resolve`；
  - `POST /api/rules/incidents/bulk`（analyst）body `{ids:[...], op:"ack"|"resolve", restore?, note?}`：
    批量已阅/解决，允许部分成功；`restore=true` 时按熔断快照恢复（admin 建议用于确认误报）。
  - `POST /api/rules/monitor/scan` 手动触发一次扫描（admin）。
  - 熔断只 patch 现役产物，不改 DB 里的规则动作；自动扫描只自动降级 `confirmed_fp`，其余只弹窗。
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

### 3.2 上传训练数据

用户上传**原始 HTTP 请求**（不是预计算特征），由控制面落到独立目录并异步解析；
训练任务可以「官方 + 上传」或「仅上传」。训练仍只写 staging，上线仍走 §3.1 的切换门禁。

**存储与状态**

- 目录：`traindata/uploads/<uuid>/`，含 `original.<ext>`、`convert.log`、
  `requests.jsonl`（全量）、`requests_train.jsonl`（剔除官方评估集重叠后的训练副本）、
  `stats.json`。
- 元数据：`uploaded_datasets` 表（角色 / 格式 / sha256 / 行列统计 / 状态 / 错误 / 来源说明）。
- 状态：`converting → ready | failed`；删除为软删除 `pruned`（元数据保留，目录删除）。
- 启动时 `uploads.cleanup_stale()` 把上次进程遗留的 `converting` 标为失败（幂等）。

**API**

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/uploads` | analyst | multipart：`file`、`name`、`role`、`default_label`、`source_note` |
| GET | `/api/uploads?limit=100&include_pruned=false` | viewer | 列表 `{items:[...]}` |
| GET | `/api/uploads/{id}` | viewer | 详情（含 `label_stats` / `stats` / `exists`） |
| GET | `/api/uploads/{id}/preview?n=20` | viewer | 预览前 N 条归一化请求 |
| DELETE | `/api/uploads/{id}` | admin | 软删除；被运行中任务引用时拒绝 |

- `role`：`supervised` / `benign` / `eval`；`eval` 只能看，不能进训练。
- `default_label`：`0..4`，仅用于缺标签的行或 pcap 整份文件；CSV/JSON 行内 `label` /
  `attack_type` 优先。
- `source_note`：`supervised` / `benign` 必填（数据出处）。
- 限制：单文件 256MB、20 万行、pcap 200 万包 / 5 万流、body 1MB、解析超时 600s；
  可用 `WAF_UPLOAD_*` 环境变量覆盖。

**训练任务字段**（`POST /api/tasks`，仅 `train_realdata` / `iforest_csic`）

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

- `data_mode`：`official`（默认，不带上传）/ `add`（官方 + 上传）/ `only`（仅上传）。
- `only` 强制 `inherit_mode=lineage`；监督通道移除官方 `--hard-neg`，零日通道把
  `--data csic` 换成 `--data upload`。
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

「训练数据」页负责上传/列表/预览/删除；「训练任务」页在训练通道下增加
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
py -3.10 -X utf8 -m service.smoke          # 需要服务已启动；20 项
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
py -3.10 -X utf8 -m service.test_alerts_drilldown -v  # 告警聚合下钻：桶边界/精确匹配/分页
py -3.10 -X utf8 -m service.test_sites -v             # 站点→模型：归组/状态/快照反查
py -3.10 -X utf8 -m service.demo_seed      # 灌一批真实采集数据（假上游 + 采集器 + 判定）
```

清理演练（**先 dry-run，确认后再 apply**）：

```bash
curl -s -H "Authorization: Bearer <admin-token>" \
  "http://127.0.0.1:8090/api/retention/raw-cleanup?days=90"
# 检查 scan.eligible、pending、orphan_trash 和每个 skipped 的 reason 后：
curl -s -X POST -H "Authorization: Bearer <admin-token>" -H "Content-Type: application/json" \
  -d '{"confirm":true,"note":"90d retention"}' \
  "http://127.0.0.1:8090/api/retention/raw-cleanup"
```

## 6. 待办

- [x] **清理调度**：内置每日 dry-run 快照 + 审计（`retention_dry_run_scheduled`）；
      真正 apply 仍需 admin 显式确认，不会自动删 raw。
- [x] **`rule_hits_daily` / `rule_incidents` 的保留策略**：随 dry-run/apply 同一 cutoff 清理；
      只删 cutoff 前日桶与已 resolved 的旧 incident，open/acked 保留。
- [ ] **用户管理页**：目前只有引导创建的 `admin`，没有增删改用户的接口。
- [ ] **攻击链关联**：告警只做同源 + 同类型 + 时间桶聚合，未做跨阶段链路还原。
- [ ] **SQLite 迁移到 Postgres**（若要多人并发/多机）。
