# python/ —— AI 控制面（可行性原型）

对应 PRD 第五章（AI 训练体系）与 4.1 检测引擎。本目录用于打通
「特征 → 训练 → ONNX 导出 → CPU 推理」链路并测量性能。

> **数据集已从合成数据切换到 PRD 指定的公开数据集**：
> CSIC 2010 与 HTTP Params 2015（位于 `../traindata`）。
> 真实评估结论、发现的问题与修复过程见根目录 `REALDATA_EVALUATION.md`。
> 合成数据仍保留（`dataset.py`）用于链路自检。

## 环境

- Python **3.10**（用 `py -3.10`；PATH 上的 `python` 可能是 IDA 的 3.8，勿用）
- 依赖见 `requirements.txt`（关键：xgboost 3.2.0 / onnx 1.23.2 / skl2onnx 1.20.0 /
  onnxmltools 1.16.0 / matplotlib 3.9.2）
- Windows 控制台建议 `set PYTHONIOENCODING=utf-8`

## 特征通道

`features.py` 为 **v2（80 维）**。v1（78 维）保留为 `features_v1.py` 仅用于 A/B 复现。

```
A 请求形态 11  B 组成/熵 11  C 关键词 16  D 攻击模式 4  E 结构/语法 8  F 特殊字符占比 30
```

v2 的关键修复（v1 用子串计数 + 未归一化，导致正常英文长文本被大量误报）：

- 关键词改**整 token 词边界匹配**（`or`/`and`/`id`/`sh` 不再命中 `for`/`guide`/`should`）
- 关键词分**强/弱**两层，并按 token 数**归一化** + 提供长度无关的 `*_present`
- 特殊字符由**原始计数**改为**占比**（去掉重复的反斜杠）
- 新增**参数值**维度与**语法结构**特征（引号/括号失衡、分隔符连跑、二次编码、转义）

> ⚠️ `rust/src/features.rs` 必须与之逐项对齐；`push!` 顺序错一位就会被一致性校验抓到。

## 模块

| 文件 | 作用 |
|---|---|
| `features.py` | **v2 结构化特征（80 维）** + 可选 128 维字符 3-gram 哈希 |
| `features_v1.py` | v1 特征（78 维），仅用于 A/B |
| `dataset.py` | 合成请求数据（链路自检用） |
| `realdata.py` | **真实数据加载器**：CSIC 2010 报文解析 + HTTP Params payload + `WEB_APPLICATION_PAYLOADS.jsonl` 攻击字典 + **datacon2025 原始 HTTP 字节**（base64+zlib）→ 统一请求格式 |
| `traindata_catalog.py` | **`traindata/` 数据目录（只读盘点）**：逐语料登记角色/行数/标签分布/sha1/消费方，池成分**直接 import `calibrate_rules`**（不复制定义），产出 `traindata/CATALOG.md` + `artifacts/traindata_catalog.json`；`--self-test` **29 项**断言把硬数字钉死，数据一漂立刻发现（含 `enhanced_security_dataset_clear.json` 的「不是 HTTP 流量」告警） |
| `train_realdata.py` | **正式训练**：HTTP Params 训练/测试 + lexical 门槛集；`--hard-neg {none,lexical,csic}` 并入困难良性负样本；`--lexical-split {random,grouped}` + `--seed` 控制切分；`--dict` 并入攻击字典；**`--es N` + `--es-set {valid,lexical,local}` + `--valid-frac F`** early stopping（**固定监控 `mlogloss`**，运行期自检 `best_iteration == argmin(mlogloss)`；`--valid-frac` 从 `payload_train` 按同源簇+分层切出干净验证集，记录 `es_monitored`/`es_metric`/`valid_frac`）；**`--balance {weight,over,under,none}`** 类别不平衡（逆频加权 / 过采样 / 欠采样）；**`--local [--local-benign --local-attack --local-hard-neg]`** 接入真实本地流量；**`--parent-model <xgb_model.json> [--parent-meta ...]`** warm start（父代缺训练件则降级全量重训并写明原因）；**`--upload-manifest/--upload-mode add|only/--calib-mode/--calib-dataset-id`** 接入控制台上传数据（见「自上传训练数据」）；`--ab` 做 v1/v2 对比；`--export` 导出产物 |
| `upload_parse.py` | **用户上传数据解析**（控制台「训练数据」页调用）：CSV / JSON / JSONL / HAR / pcap / pcapng → 统一 `{method,path,query,body,label}`；pcap 只支持**明文 HTTP/1.x**（scapy TCP 重组，TLS/HTTP2 跳过并计数，整份文件一个标签）；输出 `requests.jsonl` + `stats.json` |
| `collect_http_log.py` | **工作项 F 采集端**：把**真实**日志变成可训练 jsonl。支持 apache/nginx combined、IIS W3C、通用 JSONL、**apache error log**（`--format apache-error`，从 `referer:`/`script '...' not found` 里挖在野攻击 URL 与扫描探测路径）。**攻击标签只来自出处**（`--canary-prefix` / `--attacker-ip` / **`--redteam-window START,END`** / `--review` / `--provenance`），内容正则标注须显式 `--label-pattern` 且只许造测试集；含脱敏（敏感 query 参数、IP）与唯一化。`--redteam-window` 是标注**本机红队流量**的唯一干净方式（`127.0.0.1` 与浏览器同源，IP 规则区分不了），时间戳解析失败即报错退出 |
| `p4_local.py` | **真实流量实测**（REALDATA §8.5）：现役产物在本机良性 / 真实在野攻击 / 公网在野流量上的命中率与融合动作；阈值改标定在本机池的漂移；本地重训零日通道的对照 |
| `export_datacon.py` | **datacon2025 → 统一 jsonl**（REALDATA §8.6.4）：导出 `datacon_attack.jsonl`(42 条，17 带 body) + `datacon_unlabeled.jsonl`(58 条，**≠良性**)；脚本内写死"禁止入训练 / 禁止当良性池"的三条理由 |
| `p6_body_ablation.py` | **body 消融**（REALDATA §8.6.5）：训练集 body 覆盖率（=0 条）+ 上线模型"带 body vs `body=""`"在 CSIC 良性/异常、datacon 上的检出率与翻转，量化请求体的实测价值与误报代价 |
| `p5_flow_spike.py` | **流级通道 spike**（REALDATA §8.6.6，工作项 F0）：CIC-IDS2017 抽样；随机切分 vs **跨文件**留出两种协议 + 去 `Destination Port` 对照，回答"流级特征到底有没有可分性" |
| `p7_rule_mining.py` | **字典 → 规则候选**（REALDATA §8.6.7）：容错解析损坏的 `WEB_APPLICATION_PAYLOADS.jsonl`；每条候选规则在 37,000 条真实良性文本上量误报，产出 `artifacts/rule_candidates.json`（含**原文 vs URL 解码**对照与"池支持度"） |
| `p8_proxy_e2e.py` | **采集数据面端到端验证**（REALDATA §8.8）：起上游+起 `waf-collector` → 发含攻击 body 的请求 → 校验原始 jsonl（**无 label**、body 逐字节、截断后 `body_len` 仍为真实总长、流级字段、转义往返）→ 跑 `collect_http_log.py --canary-prefix` 按**出处**标注 → 阶段 B 用 `--score` 验证**dry-run 判定**（不阻断、`zero_day_enabled=false` ⇒ 不告警、`pred` 进不了标签、**SHAP Top-8 已写入**）→ `artifacts/p8_proxy_e2e.json`（当前 **43/43 PASS**） |
| `export_feature_names.py` | **80 维特征名的单一来源**：从 `features.py` 导出 `artifacts/feature_names_v2.json`，Rust 采集面（归因贴名）与前端共用；启动期断言维度 = 80 |
| `service/` | **控制面 API**（FastAPI + SQLite + JWT/RBAC + 审计）：总览/事件/告警/策略/反馈/规则/模型/任务/审计；见 `service/README.md` |
| `ioc_inwild_attack.txt` | 从 error log 挖真实在野攻击用的 IOC 正则（**只用于造测试集，禁止用于训练标签**） |
| `textsim.py` | 载荷**重复/同源判定**（数字掩码模板 + 字符 4-5gram 余弦 + 并查集聚类）；供审计与分组留出共用 |
| `p0_audit.py` | **过拟合审计**（REALDATA §8.2）：泄漏 / 容量 / 切分方差三分量化 |
| `p2_matrix.py` | **统一评估矩阵**（REALDATA §8.3）：配方 × 数据集 × 切分，含 CSIC 真实异常召回与 datacon OOD |
| `thresholds.py` | **判定阈值标定 + 融合策略**（REALDATA §8.4/§9）：两通道各自标定（监督 `1-P(normal)` / 零日 `-avg_path_len`）-> `artifacts/decision_policy.json`；**代码级拒绝**含训练样本的校准池；可就地刷新 `testvec.json` 的判定期望值。**`--zero-day {on,off}` 默认 off**：零日通道 `zero_day_enabled=false` 时分数仍计算留证但**不参与融合**（不产生 alert，安全降级）。**`--out <tmp>`** 只写临时文件（控制台「预览」走这条路，绝不碰现役策略）；**`schema` = 结构兼容版本**（数据面据此拒绝不认识的策略结构），**`version` = 策略修订号**（每次重标定 +1，控制台据此回答"这条记录是哪版策略算的"） |
| `p3_fusion.py` | **双通道融合评估**（REALDATA §8.4）：同池标定后比召回、跨池误报、旧阈值回代、零日通道迁移性 |
| `train_xgboost.py` | 合成数据 XGBoost 训练（产物写 `*_synthetic*`，不覆盖正式产物） |
| `train_iforest.py` | 合成数据 Isolation Forest 训练 + skl2onnx 导出（meta 写 `iforest_meta_synthetic.json`） |
| `iforest_lean_onnx.py` | **零日通道精简 IF 导出**：`--data csic`（正式，CSIC 正常 30,000）/ `--data synthetic`（链路自检）/ `--data local`（真实本地良性，验证 S9 处方）/ `--data upload`（控制台上传良性）；**`--trees N` + `--parent-model <iforest_model.joblib>`** warm start（树数必须大于父代，父代缺训练件则降级全量重训）；**`--upload-manifest/--upload-mode add|only/--calib-mode`**；单 `TreeEnsembleRegressor`，单样本 ~8us |
| `learning_curve.py` | **学习曲线**记录/绘图（JSON + CSV + PNG），所有训练脚本共用 |
| `eval_http_params.py` | HTTP Params 上的多分类评估（每类 P/R/F1 + 混淆矩阵 + FPR 预算） |
| `eval_csic.py` | CSIC 上的零日评估（IF 只用正常样本训练，含去偏子集对比） |
| `exp_hardneg.py` | **困难良性负样本对照实验**（证明误报瓶颈是 OOD，见 REALDATA §8） |
| `diag_v2.py` | v2 残留误报定位（特征均值对比 + 重要性 + 样例） |
| `export_testvec.py` | 导出 Rust 一致性测试向量（**直接读已导出产物**，不重训）；含两条通道的**判定期望值 + 融合动作**（`decision.supervised/zero_day/expected_action`） |
| `export_shap_ref.py` | 导出 `pred_contribs` 参考值（Rust TreeSHAP 的 oracle） |
| `bench_inference.py` / `explain_probe.py` / `smoke_test.py` / `iforest_variants.py` | 基准与探针 |

## 运行

```bat
set PYTHONIOENCODING=utf-8
cd python

:: 数据核对
py -3.10 realdata.py

:: 正式训练（真实数据 + 困难负样本）+ 学习曲线
py -3.10 train_realdata.py --features v2
py -3.10 train_realdata.py --features v2 --hard-neg lexical --export   :: 导出正式产物
py -3.10 train_realdata.py --features v2 --hard-neg csic              :: 对照：CSIC 正常流量
py -3.10 train_realdata.py --features v2 --hard-neg lexical --lexical-split grouped   :: 分组留出
py -3.10 train_realdata.py --features v2 --hard-neg lexical --seed 22                 :: 换切分
py -3.10 train_realdata.py --features v2 --hard-neg lexical --dict                    :: 攻击字典增强

:: 特征 A/B
py -3.10 train_realdata.py --ab

:: 评估
py -3.10 eval_http_params.py
py -3.10 eval_csic.py
py -3.10 exp_hardneg.py
py -3.10 diag_v2.py
py -3.10 p0_audit.py        :: 过拟合审计（泄漏/容量/切分方差）
py -3.10 p2_matrix.py       :: 统一评估矩阵 + datacon OOD

:: 零日通道 + 判定策略 + 融合评估（S7）
py -3.10 iforest_lean_onnx.py --data csic --export   :: 正式零日通道（CSIC 正常 30,000）
py -3.10 thresholds.py --pool csic                   :: 标定两条阈值 -> decision_policy.json
py -3.10 p3_fusion.py                                :: 融合召回 / 跨池误报 / 迁移性
py -3.10 thresholds.py --pool file:..\traindata\local\local_lab_benign.jsonl   :: 用本地流量重标定（上线前必做）
py -3.10 thresholds.py --pool csic --out %TEMP%\preview.json --no-testvec       :: 只预览（控制台「预览」用的就是这条），不动现役策略

:: 用户上传数据（控制台「训练数据」页）
py -3.10 upload_parse.py --input data.csv --out %TEMP%\up1 --role supervised
py -3.10 upload_parse.py --input cap.pcap --out %TEMP%\up2 --role benign --default-label 0

:: 控制台（前端 + 控制面 API）
py -3.10 -m service.run                                                          :: 8090，托管 web/dist
py -3.10 -m service.smoke                                                        :: 39 项 API 自检
py -3.10 -m service.demo_seed                                                    :: 灌一批真实采集数据

:: 全部单测（279 项）
py -3.10 -m unittest discover -p "test_*.py"

:: Rust 侧所需参考数据
py -3.10 export_testvec.py
py -3.10 export_shap_ref.py

:: 合成数据链路自检
py -3.10 train_xgboost.py
py -3.10 train_iforest.py
py -3.10 smoke_test.py
```

### 自上传训练数据（控制台）

控制台「训练数据」页支持把**原始 HTTP 请求**加入训练，不改变「训练只写 staging、
现役只由切换门禁更新」的约束。解析在固定脚本 `upload_parse.py` 中完成，控制面以固定参数
子进程调用（超时/崩溃隔离），前端不能传路径或命令。

**格式与角色**

| 格式 | 说明 |
| --- | --- |
| CSV / TSV | 列名建议 `method,url,path,query,body,label,attack_type`；`url` 可写完整 URL，服务端拆成 `path` + `query` |
| JSON | 数组、`{"requests":[...]}`、HAR（`log.entries[].request`）均可 |
| JSONL / NDJSON | 每行一个请求对象 |
| pcap / pcapng | 仅**明文 HTTP/1.x**；scapy 按 TCP seq 重组（分片/乱序/重传/chunked/keep-alive）；TLS/HTTP2/WebSocket 跳过并计数；**整份文件只能一个标签** |

- 角色：`supervised`（逐行标签，进 XGBoost）、`benign`（良性，进零日通道 / 校准池）、
  `eval`（只评估，**不能用于训练**）。
- 标签：`0 normal / 1 sqli / 2 xss / 3 cmdi / 4 traversal`；也接受 `normal`、`sqli`、
  `path-traversal` 等别名。CSV/JSON 优先用行内 `label` / `attack_type`，缺失时用上传时选的
  `default_label`；pcap 只能用 `default_label`。
- 只接受原始请求字段；**预计算特征 CSV 会被拒绝**（保证与线上 80 维特征同源）。

**两种训练模式**

- `add`（选择上传数据时的默认）：官方训练集 + 上传数据。XGBoost 保留 warm start；
  零日通道保留 CSIC 基数。
- `only`：只用上传数据训练。强制 `inherit_mode=lineage`（不做 warm start）；官方
  test / lexical / CSIC 不参与训练，只作迁移评估或（回退时）阈值校准。

**校准池与防污染**

- 优先从上传良性数据切独立留出（≥200 条，近重复不跨界）；不足时自动回退官方 CSIC 留出。
  `--calib-mode upload` 可强制要求上传留出，切不出就拒绝训练。
- 上传训练副本生成时，会剔除与官方评估集（payload_test / lexical / CSIC holdout）**精确重叠**
  的请求，并在 `stats.json` / `upload_stats.json` 记录条数。
- 训练产物包含 `training_keys.txt`（训练请求 sha1）与 `calibration_pool.jsonl`（上传留出）；
  切换时 `thresholds.py --train-keys` 会把它并入污染检查，按目标模型自己的口径重标定。

**控制台操作**

1. 启动 `py -3.10 -m service.run`，打开「训练数据」。
2. 选择文件、角色、默认标签（pcap 必填）、来源说明后上传；后台解析为 `ready` 后可在
   「训练任务」里选择「官方 + 上传」或「仅上传」。
3. 权限：`analyst` 可上传/预览；`admin` 可创建训练任务、删除数据集。单文件上限 256MB、
   20 万行、pcap 200 万包 / 5 万流、body 1MB、解析超时 10 分钟。
4. 删除是软删除（保留元数据）；被运行中任务引用的数据集不能删。

**CLI 复现**

```bat
:: 解析上传文件（控制台内部也是这条命令）
py -3.10 upload_parse.py --input data.csv --out %TEMP%\up1 --role supervised
py -3.10 upload_parse.py --input cap.pcap --out %TEMP%\up2 --role benign --default-label 0

:: 只用上传数据训练监督通道（清单由控制台写到 artifacts\staging\task_<id>\datasets.json）
py -3.10 train_realdata.py --features v2 --export ^
    --upload-manifest artifacts\staging\task_1\datasets.json --upload-mode only --calib-mode auto

:: 官方 + 上传，零日通道
py -3.10 iforest_lean_onnx.py --data csic --export ^
    --upload-manifest artifacts\staging\task_1\datasets.json --upload-mode add --calib-mode auto
```

上传数据集的存储与转换在 `service/uploads.py`；控制台 API 与任务字段见
`service/README.md` §3.2。相关自检：

```bat
py -3.10 -m unittest service.test_upload_parse service.test_uploads service.test_task_plan_upload -v
```

### 工作项 F：采真实流量（先采，再谈重训）

```bat
:: 1) 真实日志 -> jsonl（--scrub 脱敏）。可重复传 --src
py -3.10 collect_http_log.py --src <nginx_access.log> --name prod --provenance benign_lab --scrub
py -3.10 collect_http_log.py --src <apache_error.log> --format apache-error --name inwild ^
    --provenance indicator --label-pattern-file ioc_inwild_attack.txt --scrub

:: 2) 持续累积（每 5s 扫新行，追加写入）
py -3.10 collect_http_log.py --src <access.log> --name prod --follow --append --provenance benign_lab

:: 3) 攻击标签只能来自出处：蜜罐路径 / 红队会话 / 人工复核清单
py -3.10 collect_http_log.py --src <access.log> --provenance redteam --name redteam_x

:: 3b) 本机红队自测（Burp/SQLmap 打 DVWA）——来源 IP 与浏览器同为 127.0.0.1，只能靠时间窗
py -3.10 collect_http_log.py --src <access.log> --provenance auto ^
    --redteam-window 2026-10-17T09:30:00,2026-10-17T10:05:00 --name local_lab

:: 4) 实测现役产物在真实流量上的表现（Q1/Q2/Q3）
py -3.10 p4_local.py

:: 5) 挂采集代理后：代理只写原始 jsonl（无 label），标注仍走出处规则
::    先 build： cd ..\proxy && build.bat build --release
::    （build 缓存默认在 %WAF_CARGO_TARGET%，未设则用 %LOCALAPPDATA%\waf-cargo-target；见 proxy/README.md）
::    cd ..\proxy && build.bat run --release -- --listen 127.0.0.1:6188 ^
::        --upstream 127.0.0.1:80 --out ..\traindata\proxy
py -3.10 collect_http_log.py --format jsonl --src ..\traindata\proxy\raw-*.jsonl ^
    --provenance auto --canary-prefix /admin.php --name local_lab --keep-body

:: 5b) 采集数据面端到端自检（自己起上游+代理+标注+dry-run 判定，43 项断言）
py -3.10 p8_proxy_e2e.py
```

> ⚠️ **access log 没有请求体**。POST body 是攻击特征最强的位置，只想靠 access log 建模等于自断一臂 ——
> 要 body 必须挂采集代理（**S4 已定 Pingora**）或读 WAF 自己的日志。这一点是工作项 F 的第一约束。
> **该约束已解除**：`proxy/`（crate `waf-collector`）已把 body 采到并端到端验证（§8.8）——
> 但它**只采集、不打标签、不阻断**；下游 `collect_http_log.py` **默认清空 body**（隐私优先），
> 训练必须显式加 `--keep-body`。
> `--redteam-window` 按**字面本地时间**比较（忽略 CLF 时区偏移），CLI 会打印日志实际时间范围供核对；
> **任一条记录时间戳解析不了就直接报错退出** —— 静默把红队流量标成良性会污染良性池（比漏标更糟）。

产物写入 `artifacts/`；**学习曲线**写入 `artifacts/curves/<run>_curve.{json,csv,png}`。真实流量池写入
`traindata/local/`（`*_benign.jsonl` / `*_attack.jsonl` / `*_report.json`）。

> **代际训练（控制台路径）**：服务端训练会把产物写到 `artifacts/staging/task_<id>/`，
> 不再直接覆盖现役 `artifacts/*.onnx`。两个脚本都支持：
> `--out-dir <dir>`（产物目录）、`--artifact-name` / `--onnx-name`（固定导出名）、
> `--run-name`（曲线名）、`--parent-model`（warm start 父代：
> XGBoost 传 `xgb_model.json` 并可加 `--parent-meta xgboost_meta.json`；IForest 传
> `iforest_model.joblib`）。warm start 会校验特征版本/维度/标签，不一致直接拒绝；
> 曲线 x 轴按**总树数**右移，便于跨代对比。IForest 导出时额外保存
> `iforest_model.joblib`（老版本没有，首次需全量训练一次）。切换现役与门禁见
> `service/README.md` §3.1。

## 关键实测（真实数据 + v2 特征 + 正式配方）

> ⚠️ 下表是 **g1（2000 棵树）** 的历史实测，用于说明方法与结论；现役是 **g2（4000 棵树）**，
> 阈值与部分指标已变（监督 1%FPR 阈值 `0.721004`）。换模型后请按同口径重跑再引用，
> 不要跨代比较阈值数字。现役门禁结果见根 `README.md`「当前状态」。

> **正式产物配方**：`train_realdata.py --features v2 --hard-neg lexical --export`
> （payload_train + lexical 正常前一半 500 条；评估用 lexical 留出的后一半 500 条 + 全部异常）。
> 理由见 `../REALDATA_EVALUATION.md` §8：误报的瓶颈是训练数据未覆盖部署分布（OOD）。

| 项 | 结果 | 备注 |
|---|---|---|
| HTTP Params 常规测试集（载荷不重叠） | acc 0.9992 / AUC 1.0000 | 攻击载荷关键词明显，**不代表真实难度** |
| **lexical 困难集（留出）误报率** | **1.56%±0.71**（5 个切分，区间 0.80%–2.80%） | 单点 0.8% 是切分运气，见 §8.2 |
| **CSIC 留出正常 6,000 条误报率** | **1.35%±0.39** | 第二个独立良性池，结论一致 → 真实误报 ≈1.4% |
| **lexical @FPR 1% / 3% / 5% 检测率** | **30.2%±9.2 / 58.3%±9.6 / 67.9%±5.7** | 低误报工作点可用，但抖动大 |
| **CSIC 真实异常 25,065 条召回（argmax）** | **20.2%±1.7** | ⚠️ **最大短板**，比误报更严重 |
| 分组留出（同源不跨训练/评估） | lexical 误报 **3.00%** / CSIC 1.55% | 泄漏率仅 0.2%，退化为"另一个切分" |
| 校准工作点（CSIC+训练半区 @1% 阈值） | lexical 实误 1.40%、检出 37.0%±4.5 | ⚠️ 校准池**不能含训练数据**，否则假象 8.5% |
| 攻击字典增强（+262 攻击） | lexical 排名变好，但 **CSIC 异常召回 20.2%→6.3%** | **不采用**，见 §8.3 |
| 对照：不烘入困难负样本 | lexical 误报 34.0%，@FPR 3% 仅 16.0% | 见 REALDATA §6/§8 |
| CSIC 零日（IF，@FPR 1%） | 26.0%（去偏 28.7%） | v1 为 14.2%；仍低于 PRD 单点 >70% |
| **双通道融合（同池标定，1% 预算）** | CSIC 真实异常 **19.3%→28.5%**（+9.2pp），并集误报 **1.92%** | §8.4；前提是同分布 |
| **零日通道跨分布误报** | lexical 困难集 **28.2%**（监督通道同期 0.80%） | ⚠️ 只能在训练分布内用，见 §8.4 |
| **真实本机良性 190 条（干净池）** | 监督命中 **4.21%**、零日**原始穿阈** 3.16%、融合 block **4.21%** / alert **0.00%**（零日通道已关闭；关闭前它会 alert 2.63%） | ⚠️ CSIC 标定的 1% 阈值在本机良性上**实际 ~4%**（§8.5） |
| **真实在野攻击 12 条** | 监督检出 **7/12 = 58.3%**（95% Wilson 32–81%）、零日 1/12 | n 太小，只作方向性参考（§8.5） |
| **公网在野流量 105,730 条** | 监督 block **6.54%**、零日 0.01% | 混有扫描器探测 → 只能叫**命中率**，不是 FPR（§8.5） |
| **本地重训零日通道（S9 处方）** | 本机良性命中 1.05%（目标 1%）、在野攻击检出 8.33% | 分布内标定可控，召回没变；留出仅几十条（§8.5） |
| **early stopping 监控集选择** | ~~`--es-set lexical`+`--es 70` 停在 r62；`--es-set local`(n=107) 停在 r5~~ **本条结论已作废**：那是**监控错了指标**（monitor 了 `merror`）。修正为 `mlogloss` 后：干净三段切分 **37.7% @1%FPR** / 有偏口径 25.5% / 无早停 43.4%，**三者不可区分** | 早停不改善工作点 KPI，正式配方保持**无早停**（§8.6.1–8.6.2） |
| **body 消融（上线模型）** | CSIC 异常 19.3%（带 body）vs **11.7%**（去 body）；带 body 子集 **1,903 → 0**；CSIC 良性带 body 8,000 条命中 **0 vs 0** | 训练集带 body 的 = **0 条** ⇒ 收益是外推；工作项 F 采请求体有据可依（§8.6.5） |
| **CIC-IDS2017 流级 spike** | 随机切分 AUC 0.9999/@1%FPR 99.9% → **跨文件** AUC **0.9021** / @1%FPR **29.0%**（PortScan 0.6%） | 特征设计不坏，瓶颈是**分布漂移**；`Destination Port` 是陷阱，应排除（§8.6.6） |
| **字典 → 规则候选** | 21 条候选：**7 条可留**（37,000 条真实良性上误报 **=0**）、**6 条误报否决**；URL 解码带来 **+3,793** 命中 | 规则必须先**解码**再匹配；`union` 全池仅 1 次 ⇒ 零命中要区分"池里没有"（§8.6.7） |
| XGBoost (2000 树/depth8/80 维) | 0.019 ms | 远超 PRD 目标 |
| Isolation Forest (精简导出) | 0.0040 ms | 与 sklearn 排序完全一致 |

## 待办

1. **补困难良性负样本**（最高优先级）：上线后采集本业务良性流量（尤其长文本参数）。
2. **判定规则已落地（S7，原型完成）**：`thresholds.py` 标定两条阈值 -> `decision_policy.json`
   -> `rust/src/decision.rs` 双通道融合判定。校验：两通道 score 差 1.19e-7 / 5.7e-6、
   标记 200/200、**融合动作 200/200**。**遗留**：生产数据面接线后用**本地**留出流量重标定两条阈值。
3. **补齐真实攻击召回**（CSIC 25,065 条仅检出 20%）——比误报更缺的一等指标；
   双通道融合是当前唯一有效改善手段（→28.5%），但零日通道受分布限制。
4. **零日通道：分布内问题 + 安全降级已完成**：跨分布误报 28.2%（§8.4）、本机真实良性告警 2.63%（§8.5）。
   ✅ **`zero_day_enabled` 开关已落地**（`thresholds.py --zero-day {on,off}`，默认 off）：关闭时零日分数
   照算留证但不参与融合，**本机真实良性的 alert 2.63% → 0**，融合误报回到监督通道的 1.017%；
   策略/testvec/Rust 三处同源校验（原始穿阈 200/200、融合动作 200/200）。
   重启条件：拿到真实本地良性流量重训 IF 后，`thresholds.py --zero-day on` + `export_testvec.py` + Rust 门禁三件套一起重跑。
5. 重新校准零日指标口径（分误报预算），不要沿用单点 >70%。
6. 锁定版本、建立 venv 可复现环境。
7. CI：把 200×80 逐位特征比对与模型/判定一致性做成回归门禁（Linux 侧用数值容差）。
8. **datacon2025 只做链路自检**：`reportable: false` 已写进 `datacon_report.json` / `p6_body_ablation.json`
   （n=100 的召回率置信区间宽到无意义）。OOD 评估改用 CSIC 2010 + CIC-IDS2017，
   100 条只回答"能不能检出"，不报任何"率"。
9. **S4 基座已定 Pingora（≥0.9），采集数据面已落地，dry-run 判定已接线**：
   Windows MSVC 门禁已通过（`../proxy_spike/`），采集数据面 `../proxy/`（crate `waf-collector`）
   已建成并端到端验证 **43/43**（§8.8）：`request_body_filter` 里限长截断
   （20 万字节 → `body_truncated=true`，`body_len` 仍为真实总长）→ 写原始 jsonl（**无 label**）
   → `collect_http_log.py` 按出处标注。`--score` 已把 `rust/` 的双通道判定接进来
   （`rust/` 拆 lib `waf_ai_proto` + bin 门禁，代理复用**同一份**判定代码），
   **dry-run 只写 `pred`、永不阻断**。
   **仍待做**：等真实本地良性池够大后重标定阈值，再把 dry-run 变成真阻断。
   ⚠️ 锁 `pingora = "0.9"`（0.4.0 在 `pingora-core` 里编译不过）+ `features=["proxy","rustls"]`
   + `CMAKE_GENERATOR=Ninja`；build 缓存走 `WAF_CARGO_TARGET`（默认
   `%LOCALAPPDATA%\waf-cargo-target`，本机指向 `E:\waf-target`，与 `rust/` 共用，
   避免 `ort` 编译两遍 —— F: 盘几乎满）；Windows 属上游"community best effort"，
   须纳入回归门禁。
10. **真实本地良性池只有 190 条**（目标 ≥2,000）：挂上 `proxy/` 采集后用
    `collect_http_log.py --follow --append` 持续累积，再用 `thresholds.py --pool file:...`
    替换标定作业点（否则分位数抖动，别用 190 条的阈值）。§8.8.2 已给出这类样本的**压力证据**：
    `msg=中文"quote\back<TAB>tab&x=1` 得分 0.3309，比同类良性 `msg=hello&x=1`（0.0021）高两个数量级。
11. **`enhanced_security_dataset_clear.json` 不能训练**：767 条 `{instruction, output}`
    Java 代码漏洞问答，没有 method/path/query/body；`upload_parse.py` 实测全部 `missing_path`、
    `rows_kept=0`。只可当知识库素材，**禁止入训练、禁止当良性池**（`traindata_catalog.py`
    已把它登记为第 10 组语料并给出告警）。
12. **测试规模基线（2026-10-30）**：Python 单测 **279 项**、控制面 smoke **39 项**、
    p8 e2e **43 项**、Rust lib **18 项**、数据目录自检 **29 项**。改代码后这些数字只应增加。
