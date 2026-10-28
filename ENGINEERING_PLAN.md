# WAF + AI 自动检测告警系统 —— 工程执行计划

> 配套文档：`prd.md` V1.0
> 目标：将 PRD 转化为可排期、可验收、可分阶段交付的工程任务
> 数据面：Rust（Cargo workspace）｜控制面：Python 3.10+｜推理：ONNX Runtime CPU｜缓存：Redis

---

## 0. 关键路径与决策（先做技术验证 Spike）

在正式开发前，用 1–2 周完成以下 **风险消除型验证**，避免后期返工：

| 编号 | 验证项 | 目的 | 通过标准 |
|---|---|---|---|
| S1 | `ort` crate 在 Windows MSVC + Linux 双平台加载 ONNX 模型 | 平台兼容性（PRD 12.1 头号风险） | 两平台均能加载 XGBoost/IForest 并输出一致评分 |
| S2 | 单请求端到端延迟压测（regex + 双模型） | 验证 P99 < 10ms 是否现实 | 800 QPS 下 P99 < 10ms，否则调整分层策略 |
| S3 | 模型导出链路：XGBoost → ONNX → ort 输出 pred_contribs | 可解释性可行性 | ontribs 输出与 Python 侧对齐 |
| S4 | ✅ **已完成**：反向代理基座 = **Pingora 0.9+**（Windows MSVC 门禁通过）+ **采集数据面已落地**（`proxy/`，端到端 27/27，含 dry-run 判定） | 决定数据面骨架 | 明确取舍并冻结方案 |
| S5 | Redis 在 Windows 的部署方式（原生 / WSL2 / Memurai） | 依赖落地 | 明确方案与运维文档 |

> 原则：Spike 未通过的技术假设，不允许进入正式排期。

### 0.1 Spike 进展（Rust 原型已交付）

原型工程：`rust/`（详见 `rust/README.md`）。

> **v2 更新**：特征通道按 `REALDATA_EVALUATION.md` 的根因重写（v1 78 维 → v2 80 维），
> 正式模型改为**真实数据集（HTTP Params 2015）训练并烘入困难良性负样本**
> （2000 棵树 / 18,464 节点 / 深度 8）。下表的延迟与一致性均为该正式产物口径。

| 编号 | 状态 | 验证结果 |
|---|---|---|
| **S1** | ✅ Windows(MSVC) 通过 | `ort 2.0.0-rc.14` + 预编译静态 ORT，加载 XGBoost/IForest 成功；与 Python onnxruntime 输出 max\|diff\| = 4.17e-7；Rust 特征 vs Python v2 **逐位一致（200×80）**。**Linux 待验。** |
| **S2** | ✅ 单请求口径通过 | release 端到端（特征+XGB+IF+TreeSHAP）**p50 ≈0.6–0.75ms / p99 ≈1.2–1.5ms**（同机多次复跑），仍远低于 10ms；800 QPS 整机压测**待做** |
| **S3** | ✅ 方案变更后通过 | ONNX **无法**导出 `pred_contribs`（且缺 `cover`）；改为 **Rust 侧 TreeSHAP**，对齐 XGBoost 原生 `pred_contribs`，max\|diff\| = 8.1e-6 |
| **S4** | ✅ 已冻结方案（Pingora 0.9+）；**采集数据面已落地** | **反向代理基座 = Pingora**（不选 hyper 自研：body 特征工程需要 `request_body_filter` 这类 HTTP Body 生命周期钩子，自研要自己处理 chunked/keep-alive/内存池）。**Windows x86_64 MSVC 门禁已通过**：`proxy_spike/` 编译+运行成功，`request_body_filter` 拿到完整请求体（29 字节 SQLi body 精确、5KB 分块累积正确），客户端看到的 `404/501` 来自上游 ⇒ 请求确被完整转发。**基座之上已建成采集数据面 `proxy/`（crate `waf-collector`）**：采集 HTTP（含 body）与流级（dur_ms/bytes_in/bytes_out/src_ip）两路，写原始 jsonl；端到端验证 `python/p8_proxy_e2e.py` **28/28 通过**（20 万字节 body 截断且 `body_len` 仍为真实总长、原始记录**无 label 字段**、下游按蜜罐路径出处标注 2 攻击/4 良性）。**dry-run 判定已接线**（`--score`）：`rust/` 拆为 lib `waf_ai_proto` + bin 门禁，代理 path 依赖复用**同一份** `features.rs`/`decision.rs`（拆库后门禁数字完全一致：BIT-EXACT 200×80、融合动作 200/200、SHAP 8.106e-6）；判定在 `logging` 阶段做（不占真实请求延迟），**只写 `pred`、永不阻断**，加载/判定失败只降级为纯采集。设计红线：**不打标签、不阻断、不静默丢数据**；模型输出与训练标签**结构性分离**（`parse_jsonl` 只保留已知键 ⇒ `pred` 在标注产物里消失）。⚠️ **版本必须锁 ≥0.9**：0.4.0 在 `pingora-core` 里 5 个编译错误（含 Windows 专有 `UniqueIDType` `usize`/`i32` 不匹配 + `sfv` 依赖漂移）。工程约束：`features=["proxy","rustls"]`（本机无 perl，绕开 OpenSSL）+ `CMAKE_GENERATOR=Ninja`（cmake 不认识本机 VS 18/2026）。⚠️ 上游仍定位 Windows 为"community best effort"、Linux 为 tier 1 ⇒ 该路径**已证明可行但须纳入回归门禁**。**尚未接线判定**（下一步，先 dry-run 只记录不拦） |
| S5 | ⏳ 未开始 | Redis on Windows |
| **S6** | ❌ 指标不达标 | **零日检测率**：CSIC 2010 上 IF @FPR 1% 仅 **26.0%**（去偏 28.7%），PRD 的 >70% **不成立**；且误报瓶颈已定位为训练数据未覆盖部署分布（OOD），见 `REALDATA_EVALUATION.md` §8 |
| **S7（新增）** | 🟡 原型已实现 | **决策规则原来用 `argmax` 是错的**：同一模型换评估切分误报在 **0.8%–3.0%** 间乱跳（§8.2/§8.3）。已改为**双通道各自标定 + 融合**：策略文件 `artifacts/decision_policy.json`（`python/thresholds.py` 生成，含"校准池不得含训练样本"的代码级守卫）；`rust/src/decision.rs` 按策略判定，**监督命中→阻断、仅零日命中→告警**；`argmax` 降级为攻击类型归类。一致性校验：两通道 score 差 1.19e-7 / 5.7e-6、标记 200/200、**融合动作 200/200**、策略↔testvec 阈值差 0（断言保护）。**生产数据面接线后须用本地留出流量重标定两条阈值。**（零日通道已加 `zero_day_enabled` 总开关并**默认关闭**，见 S12） |
| **S8（新增）** | ❌ 指标不达标 | **真实攻击召回**：CSIC 2010 的 25,065 条真实异常，正式模型 argmax 仅召回 **20.2%±1.7**。标定到 1%FPR 后：旧（文件尾部池）**22.9%**、新（代表性留出池）**19.3%** —— 即"校准后召回更高"这个早期结论**不成立**，校准只让误报可控，召回基本不变。且"加攻击字典"这类只盯 lexical 的优化会把它打到 6.3%。**双通道融合是当前唯一有效改善（1% 预算 19.3%→28.5%），但见 S9。** |
| **S9（新增）** | 🟡 处方已验证 | **零日通道跨分布迁移差**：CSIC 训练的 IF 对 lexical 困难集良性误报 **28.2%**（监督通道同期 0.80%），其"77% 召回"是假象；在 datacon OOD 上对未标注样本标记率 **56.9%**（§8.4）。=> 零日通道**只能在训练分布内**产生告警。**处方已在真实数据上验证**（§8.5）：用真实本机良性 190 条重训 IF，本机良性命中 1.05%（目标 1%），但在野攻击检出仍是 8.33%（1/12）—— 即**分布内误报可控，召回没改善**，且留出仅几十条，不足以替代 CSIC 产物 |
| **F（新增）** | 🟡 **采集代理已交付（数据量仍不够）**，采集端已交付，数据量远不够 | **真实流量采集（工作项 F）**：`python/collect_http_log.py` 支持 nginx/apache access+error、IIS W3C、JSONL，攻击标签**只来自出处**（蜜罐路径 / 红队会话 / 复核清单）。首批实采：本机 phpStudy 日志 → 真实本地良性 **190 条**（干净池）；公网服务器 error log → 真实在野流量 **105,730 条** + IOC 攻击 **12 条**。**`inwild_*` 混有扫描器探测，不能当良性池**。⚠️ **access log 无请求体** → 最强特征缺失，这是本工作项的第一约束（要 body 须挂采集代理，依赖 S4）。**该约束已解除**：`proxy/` 采集数据面已落地并**接线 dry-run 判定**（§8.8），Pingora `request_body_filter` 拿到完整 body 并端到端验证 **28/28**（20 万字节 body 正确截断且 `body_len` 仍为真实总长；原始记录**不含 label**；`pred` 与 `label` 结构性分离）。**约束的价值已实测**（§8.6.5）：CSIC 异常带 body 的 9,977 条，带 body 命中 1,903、**去掉 body 命中 0**；CSIC 真实良性带 body 的 8,000 条命中 0（body 不抬误报）。但训练集带 body 的 = **0 条**，所以收益是关键词特征的外推，采集后必须重标定。**标注端已补齐本机红队流量**：Burp/SQLmap 打本地靶场的来源 IP 与浏览器同为 `127.0.0.1`，IP 规则区分不了，故新增 `--redteam-window START,END`（**出处**=操作者声明时段；时间戳解析失败即报错退出，绝不静默把红队流量当良性污染良性池） |
| **F0（新增）** | 🟡 spike 完成，方向保留 | **流级通道可行性 spike（CIC-IDS2017）**：`python/p5_flow_spike.py`。同分布随机切分 AUC 0.9999 / @1%FPR 99.9% 是**假象**（同会话流重复）；**跨文件**留出（Thursday+Friday）AUC **0.9021**、@1%FPR 攻击 TPR **仅 29.0%**（PortScan 0.6%、Bot 0/112）。⇒ 流级**特征设计不坏**，瓶颈与 HTTP 通道同源（**分布漂移**），因此**不能因 CIC 数字好看而免掉真实本地流数据**，也不该因跨文件掉下来就推翻方向。**`Destination Port` 是陷阱**（保留它跨文件 AUC 反降到 0.7682），流级上线应排除端口。**采集点已定：Proxy 近似**（S4 选 Pingora 后天然最优——同一上下文即可拿到 header/body 与连接时长/上下行字节/RTT，覆盖 90% 流级特征）；eBPF 在 Windows 不可用、NetFlow 看不到应用层，二者留作未来 Linux 高并发集群的内核层补充 |
| **S8′（新增）** | ❌ 真实数据上确认 | **真实攻击召回（在真实流量上复测）**：现役产物对真实本机良性误报 **4.21%**（≈ 目标 1% 的 4 倍，证明 OOD 问题在真实流量上同样成立）；对真实在野攻击 12 条检出 **58.3%**（95% Wilson 32–81%，n 太小）；对公网在野流量 105,730 条只阻断 **6.54%** —— 即 **93.5% 的在野敌意请求被放过**。结论与 S8 一致：**召回是头号短板，且不是靠换阈值能解决的** |
| **S10（新增）** | ✅ 方法论修正 | **早停监控指标 bug（已修）**：XGBoost 隐式早停只看**最后一个指标**，`eval_metric=["mlogloss","merror"]` 使实际监控落到 **`merror`**（证据：两轮 run 的 `best_iteration` 恰好等于被监控集 `merror` 的 argmin = r62/r8）。已把 `mlogloss` 移到末位并加运行期自检（`es_metric` 写入 meta）。修正后**干净三段切分**（`--valid-frac 0.1`，ES 监控 payload_train 留出的 valid）得 **37.7% @1%FPR**，无早停 43.4%、有偏口径 25.5%，**三者不可区分**（lexical 仅 106 条攻击）⇒ 正式配方**保持无早停**，canonical 产物未被覆盖（§8.6.1–8.6.2）。**并纠正一条旧结论**："用验收集早停会偏乐观"**不成立**（有偏口径反而更低，因为 mlogloss 极小点 ≠ 阈值工作点） |
| **S11（新增）** | ✅ 规则层候选已产出 | **规则引擎候选（M1 输入）**：`python/p7_rule_mining.py`。字典 `WEB_APPLICATION_PAYLOADS.jsonl`（500 条，**文件本身是损坏 JSON**）只用来挖候选，并在 **37,000 条真实良性**文本上量误报：**7 条可留**（`xss_script_tag` 1,151 命中、`sqli_tautology` 604、`sqli_comment_tail` 551…，误报 **0**）、**6 条误报否决**（`cmd_subshell` 129 次 = 0.35%，对阻断级不可接受）。**关键工程结论：规则必须先 URL 解码再匹配**（不解码时 `sqli_union_select` 命中 0，解码后 21 条规则合计 **+3,793** 命中）。另：评测池攻击面极窄（`union` 全池仅 1 次），零命中须区分 `unverifiable_by_pool` 与规则写错 |
| **S12（新增）** | ✅ 安全降级已生效 | **零日通道总开关 `zero_day_enabled`**：`decision_policy.json` 顶层新增该键（`thresholds.py --zero-day {on,off}`，**默认 off**）；`decision.rs` 关闭时零日分数与"**原始穿阈**"仍计算留证，但**结构上不产生 alert**（判定退化为"监督通道单独决策"）；策略/testvec/Rust 三处同源校验（含原始穿阈 200/200、融合动作 200/200）。收益：本机真实良性的 alert **2.63% → 0**，融合误报回到监督通道的 **1.017%**。重启条件：拿到真实本地良性流量重训 IF 后，`thresholds.py --zero-day on` + `export_testvec.py` + Rust 门禁**三件套一起重跑**。理由：IF 跨分布会崩（lexical 困难集良性误报 28.2%、本机真实良性 2.63%），在重训前它只有人工复核成本 |
| **S13（新增）** | ✅ F-A 已落地 | **控制台（业务层）+ 控制面 API**：定位为安全运营业务层，基础设施运维指标仍归 Grafana/Prometheus（PRD §4.9.2），不重复建设。**控制面** `python/service/`（FastAPI + SQLite + stdlib JWT/PBKDF2 + RBAC `viewer<analyst<admin` + 审计）：`total 18/18 PASS`（含训练数据列表、审计保留预览、聚合下钻）。**前端** `web/`（React 18 + AntD 5 + ECharts，`vite build` 后由 FastAPI 单端口托管）：11 个路由全部渲染、**0 条控制台错误**。**自上传训练数据**：CSV/JSON/JSONL/HAR/pcap（明文 HTTP/1.x）→ 原始请求归一化 → 角色/标签 → `add|only` 训练；上传训练副本剔除与官方评估集精确重叠，校准池优先上传良性留出、不足回退 CSIC；训练仍只写 staging，上线仍走切换门禁。**审计日志默认保留 90 天**：系统每日自动清理，admin 可预览后按时间清理或勾选删除（单次 ≤500 条）；删除为硬删除，每次删除都写 `audit_cleanup*` 留痕，写失败回滚。**刷新按要求用手动/定时轮询**（总览可选 15s、顶栏模式 30s、任务日志 2s），**不用 SSE**。红线已落进代码：阈值**不允许界面手改**（只能「选池→预览→提升」，预览走 `thresholds.py --out <tmp>` 写临时文件，**不碰现役策略**）；dry-run 状态在顶栏/总览/降级页三处显著；`zero_day_enabled` 可见可切并解释"关闭时分数仍留证、只是不产生 alert"；**body 默认不入库**、查看需 analyst+ 且**每次写审计**；**反馈是独立台账**（不覆盖 `pred`、不自动成为训练标签）；任务是**服务端白名单**而非任意命令。SHAP Top-8 从采集端 `pred.shap_topk` → `event_shap` 表 → 事件详情画图（**仅解释，不参与判定**）。告警用**即时 SQL 聚合**（源IP+动作+方法/路径+时间桶）+ `alert_state` 存确认状态，点击行可**下钻该组原始流量**（同公式精确复算时间桶 + 服务端分页，事件行开完整详情；`test_alerts_drilldown.py` 7 测）；**未做攻击链关联**。**多站点可见**：总览新增「站点 → 模型」，按每条判决的 `host` + `policy_version` 归组、用 `policy_versions` 快照里的产物 sha1 还原每个站点实际在跑的模型（名称取自 `model_registry`），并与现役对比给出 `in_sync/policy_old/stale/unscored/unknown`（`test_sites.py` 5 测）；只读，不改状态。**模型代际传承树**：`/api/models` 增加 `lineage`（嵌套树 + 现役路径 + 统计），由 `model_registry.build_lineage()` 纯函数生成；不信任 `parent_id`，父代缺失/自指/成环一律降级为根并记入 `orphans`（`test_model_lineage.py` 8 测）；前端在「模型与门禁」用 ECharts tree 画父子血缘，颜色=状态、蓝色连线=现役血脉、空心虚线=快照已清理，点节点看该代血缘链/子代/切换记录。⚠️ 附带的门禁修正见 S14 | 
| **S14（新增）** | ✅ 已修正 | **`schema` 与 `version` 职责分离**：引入控制台后 `decision_policy.json` 的 `version` 会被重标定累加，而数据面原用 `version != 1` 当**结构兼容守卫** ⇒ 正常重标定被判"不兼容"（实测策略 v3 时门禁报 `不支持的 decision_policy 版本 3`，**这是一个真的会挡住上线的坑**）。改为：`schema`=结构兼容版本（`decision.rs` 据此拒绝不认识的策略结构）、`version`=策略修订号（门禁改为与 `testvec.decision.policy_version` **交叉核对同源**，不再硬编码 1）。修正后三件套重跑全绿：BIT-EXACT 200×80、xgboost 4.172e-7、argmax 200/200、iforest 5.722e-6、阈值交叉校验 0.000e0、融合 200/200、SHAP 8.106e-6；`p8` **28/28 PASS** |

**对 PRD 性能指标的修正**（原值不合理）：

| 指标 | PRD 原值 | 实测/建议 |
|---|---|---|
| XGBoost 单样本推理 | 1–3 ms | **< 0.1 ms**（实测 0.019 ms，2000 树） |
| Isolation Forest | 0.035 ms/样本 | 0.035 是**批量吞吐**口径；单样本用精简导出实测 **0.004 ms** |
| TreeSHAP 归因 | 未给指标 | 0.54 ms（2000 树/5 类） |
| 端到端 AI 开销 | — | **p99 ≈ 1.2–1.5 ms**（同机多次复跑区间） |
| 零日检测率 | > 70%（单点） | **改为分误报预算口径**：@FPR 1% ≥ 30%、@FPR 5% ≥ 50%（纯无监督仅 ~26%/40%，不达标） |
| 误报率 FPR | < 3% | **需两个前置条件**：① 用本业务良性流量覆盖负样本（正式产物已烘入困难负样本）；② **换成阈值化决策**。当前 argmax 下：lexical 留出 **1.56%±0.71**（0.80%–2.80%）、CSIC 独立良性池 **1.35%±0.39**、分组留出 **3.00%**（已在边界）。仅靠公开数据集（不烘）实测 33%，**不达标** |
| 真实攻击召回 | 未定义 | **建议新增一等指标**：CSIC 真实异常 ≥ 50%（当前 20.2%，**不达标**）；在真实在野流量上更差：105,730 条公网敌意请求只阻断 **6.54%**（§8.5） |

> **S7/S8 的证据链**：`p0_audit.py`（泄漏 0.2% → 否证；容量过剩 → 成立；切分方差 → 成立）
> 与 `p2_matrix.py`（6 配方 × 5 数据集 × 5 切分）。**口径纪律**：n=500 的池子必须报
> 多切分 mean±std，且校准池**绝不能含训练样本**（否则出现 8.5% 的假象）。



---

## 1. 仓库结构（Monorepo）

```
waf/
├── Cargo.toml                 # workspace 根
├── crates/                    # Rust 数据面
│   ├── waf-core/              # 共享类型、配置、错误、平台抽象
│   ├── waf-proxy/             # 反向代理 + TLS 终止 + 协议(HTTP1/2, WS)
│   ├── waf-pipeline/          # 插件化管道编排, Plugin trait
│   ├── plugin-ipblock/        # IP 黑名单（Redis + BloomFilter）
│   ├── plugin-ratelimit/      # 滑动窗口限速
│   ├── plugin-regex/          # Hyperscan/regex + CRS 加载/热更
│   ├── plugin-xgboost/        # XGBoost ONNX 推理
│   ├── plugin-iforest/        # Isolation Forest 推理
│   ├── plugin-grayzone/       # 灰区(40–70)语义分析
│   ├── plugin-response/       # 异步响应体分析
│   ├── waf-scoring/           # 风险评分 + IP 危险性评分
│   ├── waf-alert/             # 告警降噪/聚合/分级推送
│   ├── waf-policy/            # 版本管理、影子/灰度、回滚
│   ├── waf-telemetry/         # Prometheus 埋点
│   └── waf-server/            # 主程序（bin）
├── python/                    # Python 控制面
│   ├── wafctl/                # CLI 入口
│   ├── features/              # 双通道特征工程
│   ├── training/              # XGBoost / IForest 训练 + 导出
│   ├── adversarial/           # GAN/规则变异对抗样本
│   ├── intel/                 # 威胁情报同步（多源融合）
│   ├── analytics/             # 告警关联/漏判分析（✅ 已建目录，聚合当前在 service 里做）
│   └── service/               # ✅ 控制面 API（FastAPI + SQLite + RBAC + 审计）
├── web/                       # ✅ 控制台 SPA（React 18 + AntD 5 + ECharts，vite build → FastAPI 托管）
├── models/                    # ONNX 模型 + 版本清单
│   └── registry.json
├── rules/                     # OWASP CRS 精简核心 + 自定义规则
├── config/                    # 配置模板（linux/ windows 分平台）
├── deploy/                    # systemd / NSIS / WiX / deb / rpm
├── tests/                     # 集成 / e2e / 回归语料
├── bench/                     # criterion 基准 + 压测脚本
└── docs/                      # 设计文档、运维手册
```

---

## 2. 里程碑与阶段交付（对齐 PRD 第十章优先级）

### M0 · 环境与骨架（Week 1–2）
- 双平台构建环境：rustup + MSVC（Win）、build-essential（Linux）、ONNX Runtime 预编译库、Redis
- Cargo workspace 初始化 + CI（GitHub Actions 双平台 matrix）
- `waf-core`：配置模型、错误体系、平台抽象 trait
- **交付**：两平台 `cargo build --release` 通过；CI 绿灯
- **退出标准**：S1、S5 验证通过

### M1 · 最小可用管道 MVP（Week 3–5）P0
- `waf-proxy`：反向代理 + rustls TLS 终止 + HTTP/1.1
- `waf-pipeline`：Plugin trait（`ALLOW/BLOCK/MONITOR/SCORE`）+ 阶段编排 + 热重载框架
- `plugin-ipblock`（纯内存/Redis + Bloom）、`plugin-ratelimit`、`plugin-regex`（CRS 子集）
- 结构化日志（tracing）+ Prometheus 埋点骨架（`waf-telemetry`）
- **交付**：纯规则引擎 WAF 可拦截 SQLi/XSS/命令注入/路径遍历的回归用例
- **退出标准**：规则层检测正确率达标；S2 基线延迟测量完成

### M2 · AI 推理接入（Week 6–9）P0
- Python `features` + `training`：XGBoost 训练 → ONNX 导出 → 版本命名（`xgboost_vYYYYMMDD_NNN.onnx`）
- `plugin-xgboost` + `plugin-iforest`：ort 加载、批量推理、E 核绑定
- 模型热加载：Linux SIGHUP / Windows 命名事件
- 评分输出 0–100 + 攻击类型分类
- **交付**：规则 + 双模型完整管道；模型可热切换
- **退出标准**：S3 通过；推理延迟达标（XGB **< 0.1ms**、IF 单样本 **< 0.01ms**）
  - ⚠️ 原值（XGB 1–3ms、IF 0.035ms/样本）已在 Rust 原型中证伪并修正，见 §0.1

### M3 · 决策、可解释、告警降噪（Week 10–12）P0
- `waf-scoring`：风险评分融合（规则 + ML + IP 信誉）、动态阈值、灵敏度预设
- 多级响应：<50 放行 / 50–85 挑战限速 / >85 拦截封禁；`plugin-grayzone`
- `waf-alert`：同源/同类型聚合、攻击链关联、P0–P3 分级推送
- 可解释性：TreeSHAP 归因（Rust 实现，见 §0.1 / `rust/README.md`）、决策路径追溯、反事实解释
  - 注：ONNX 无法导出 `pred_contribs`，需随模型附带**含 `cover` 的树件**（`xgb_trees.json`）
- 观察模式（MONITOR）落地
- **交付**：告警事件页数据（聚合后）+ 可解释性字段
- **退出标准**：可解释性验收项通过；告警降噪有效（去重率指标）

### M4 · 降级、监控、版本管理（Week 13–15）P0/P1
- `waf-policy`：版本注册表、影子模式、灰度（10%→50%→100%）、一键回滚（保留 5–10 版）
- 系统降级：AI 超时(>10ms)、模型加载失败、CPU>85% 关 IF、回落 70% 恢复
- 监控完善：Grafana Dashboard、windows_exporter 适配
- **交付**：降级/回滚/灰度全链路演练报告
- **退出标准**：PRD 4.7、4.9 验收项通过

### M5 · IP 危险性评分 + 防火墙联动（Week 16–18）P1
- 离线 IP 库内存加载、加权减法模型、多源情报融合（权重 + 失败重分配）
- 分级封禁 TTL（1h~30d）+ 布隆过滤器历史黑名单 + LRU 兜底
- 防火墙 API 自动下发 / 效果追踪 / 自动解封
- Python `intel`：威胁情报定期同步到本地缓存
- **交付**：封禁联动闭环 + IP 评分可解释
- **退出标准**：PRD 4.3 验收项通过

### M6 · 漏判补救闭环（Week 19–22）P2
- `plugin-response`：异步响应体分析（正则+关键词，不阻塞）
- 告警日志关联（来源 IP/时间/URI/规则 ID）
- 自动响应：封禁 + 响应撤回/脱敏/回滚（业务联动）
- 反馈学习：漏判样本采集 → 增量学习 → 影子验证 → 热加载
- **交付**：误报/漏报反馈闭环 + 概念漂移检测触发再训练
- **退出标准**：PRD 4.4、5.6 验收项通过

### M7 · 协议适配 + 打包分发 + 合规（Week 23–26）P2/P3
- HTTP/2（HPACK/帧）、WebSocket 帧检测、gRPC 拦截器方案
- 合规：数据最小化、脱敏存储、访问控制/审计、90 天自动删除
- 打包：.deb/.rpm/AppImage、.exe(NSIS)/.msi(WiX)，cargo-packager 统一
- 人机协同工作流优化
- **退出标准**：PRD 4.8、十三、验收标准全量通过

---

## 3. 并行工作流（建议）

| 工作流 | 负责面 | 贯穿阶段 |
|---|---|---|
| A. 数据面管道 | Rust | M0–M7 |
| B. 模型与训练 | Python | M2–M6（可与 A 并行） |
| C. 规则与情报 | 规则/情报 | M1–M5 |
| D. 可观测与部署 | 运维/DevOps | M0、M4、M7 |
| E. 测试与基准 | QA | 全程，M1 起建立回归语料 |

---

## 4. 测试与质量策略

- **单元测试**：各 plugin 独立可测（trait 注入 mock Redis/模型）
- **回归语料**：公开集（CSIC 2010、HTTP Params 2015）+ 自建攻击/正常样本库
- **性能基准**：criterion（模块级）+ 端到端压测（QPS/P99/内存/CPU）
- **对抗测试**：对抗样本集持续回归（防止绕过回归）
- **双平台验证**：CI matrix 保证 Linux/Windows 行为一致
- **验收门禁**：每个里程碑对齐 PRD 第十三章验收标准

---

## 5. 主要风险与缓解（承接 PRD 12.1，补充工程视角）

| 风险 | 工程缓解 |
|---|---|
| ort/ONNX Windows 兼容 | M0 S1 前置验证；强制 MSVC；CI 双平台 |
| P99 延迟超标 | 分层降级 + 灰区仅 40–70 触发 + IF 异步/E 核 |
| 模型漂移 | 概念漂移监控 + 定期再训练 + 影子验证 |
| Redis 单点 | 高可用 + 本地缓存兜底 + 降级到纯规则 |
| 范围蔓延（PRD 功能极多） | 严格按 M0–M7 分批，P0 先闭塞，P2/P3 后置 |
| 训练数据合规 | 数据最小化、脱敏、不出域 |

---

## 6. 立即行动项（Next Actions）

1. 确认 S1–S5 五个 Spike 的执行负责人与时间盒
2. 初始化 Cargo workspace + CI（M0 骨架）
3. 冻结反向代理基座（S4）与 Redis on Windows（S5）方案
4. 建立回归语料库目录与首批样本
5. 产出模型导出脚本原型（XGBoost → ONNX → ort 冒烟）
   - ✅ 已完成：`python/train_xgboost.py` + `rust/`（详见 `rust/README.md`）

---

## 7. 待确认问题（需产品/负责人决策）

1. 反向代理基座：采用 Pingora（成熟但 Linux 优先）还是 hyper+rustls 自研（可控但工作量大）？
2. 首个交付目标：完整 M0–M3 后再上线，还是 M1 规则版即可先行部署？
3. 控制面 API 与前端（告警详情页/反馈按钮）是否在本项目范围内？PRD 未明确前端归属。
4. 训练数据来源与合规审批路径（生产流量脱敏方案）。
5. 团队规模与每周可投入人力，用于将周数换算为日历排期。
