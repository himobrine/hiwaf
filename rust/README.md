# waf-ai-proto —— WAF AI 数据面原型（Rust + ONNX Runtime）

本目录是 **WAF 数据面 AI 推理引擎** 的 Rust 原型，用于消除 `ENGINEERING_PLAN.md` 中的
技术风险项 **S1（ort 跨平台加载）** 与 **S3（可解释性）**。

目标：验证「纯 Rust 数据面能否在 CPU 上低延迟地完成 特征工程 → 双模型推理 → TreeSHAP 归因」，
并保证与 Python 侧**数值一致**。

---

## 1. 结论速览（已验证 ✅）

> v2 更新：特征通道已按 `REALDATA_EVALUATION.md` 的根因重写（v1 → v2，78 → 80 维），
> 正式模型改为**真实数据集（HTTP Params 2015）训练**，并**烘入困难良性负样本**
> （lexical 正常前一半 500 条，见 `REALDATA_EVALUATION.md` §8/§9），
> 规模 2000 棵树 / 18,464 节点 / 深度 8。下表数值与延迟均为该正式产物口径。

| 验证项 | 结果 |
|---|---|
| `ort` 加载 ONNX（XGBoost + 精简 IForest） | ✅ MSVC 工具链，`download-binaries` 预编译静态库，无需手工编译 ORT |
| Rust 特征提取 vs Python `features.py` **v2** | ✅ **逐位一致**（200×80 全为 0 差异；100 合成 + 100 真实请求） |
| XGBoost 推理 vs Python onnxruntime | ✅ max\|diff\| = **4.17e-7**，argmax 一致率 **200/200** |
| IForest 推理 vs Python onnxruntime | ✅ max\|diff\| = **5.7e-6** |
| **TreeSHAP 可解释性** vs XGBoost 原生 `pred_contribs` | ✅ max\|diff\| = **8.1e-6** |
| TreeSHAP 自洽性 `Σφ = raw margin` | ✅ max\|diff\| = 1.24e-5 |
| **决策规则：双通道 + 融合（S7）** | ✅ 原型已实现并校验：`rust/src/decision.rs` 读 `artifacts/decision_policy.json`（由 `python/thresholds.py` 生成），监督 `score = 1-P(normal)`、零日 `score = -avg_path_len` 各自与标定阈值比较，融合为 **block/alert/allow**；**`argmax` 降级为攻击类型归类**。校验：两通道 score 差 **1.19e-7 / 5.7e-6**、标记 **200/200**、**融合动作 200/200**、策略↔testvec 阈值差 0（断言）。**生产数据面接线后须用本地留出流量重标定。** |
| **判定策略的标定池守卫** | ✅ 由 `python/thresholds.py` 代码级拒绝含训练样本的校准池（实测：合法池通过、`payload_train` 池 100% 重叠被拒） |
| **产物错配检测（防"文档≠产物"）** | ✅ `main.rs` 断言策略里的产物名 = 实际加载文件名，且零日阈值与 `iforest_meta.json` 训练记录一致（本轮真出现过 canonical IF 是合成产物训练的 bug） |

> ⚠️ **S7 背景与遗留**：`REALDATA_EVALUATION.md` §8.2/§8.3 证明 `argmax` 的误报落点会在
> **0.8%–3.0%** 之间乱跳，PRD 的 FPR<3% 无法稳定达成。现改为「两条通道各自取分数、与策略文件里的
> 标定阈值比较，再按融合策略给出动作」：监督命中 → **block**，仅零日命中 → **alert**（不阻断，
> 因为它的误报语义是"没见过"而非"确认是攻击"）。三个档位可配（0.1%/1%/3%），换预算不需重训。
> **遗留**：(a) `rust/src/main.rs` 目前仍是一致性 harness，真正的数据面（S4 反向代理基座）尚未开始；
> (b) 上线前两条阈值必须在**本地留出流量**上重标定，且校准池绝不能含训练样本
> （`thresholds.py` 会拒绝这种池）；(c) 零日通道**跨分布迁移很差**（CSIC 训练的 IF 对 lexical
> 良性误报 **28.2%**，§8.4），在采到本地良性流量重训之前只应"记录不告警"。

### 单请求延迟（release，i5-12500H，`intra_op=1`）

| 阶段 | p50 | p99 |
|---|---|---|
| 特征提取（80 维，纯 Rust） | 0.0059 ms | 0.0083 ms |
| XGBoost（ONNX/ort，2000 棵树） | 0.0188 ms | 0.0701 ms |
| Isolation Forest（精简 ONNX/ort） | 0.0040 ms | 0.0084 ms |
| TreeSHAP（2000 棵树 / 5 类） | 0.57 ms | 1.25 ms |
| **端到端（特征+双模型+TreeSHAP）** | **≈0.70 ms** | **≈1.40 ms** |

> 同一机器多次复跑波动 ±10–20%（长跑后更慢）：端到端实测区间 p50 0.61–0.75ms / p99 1.19–1.53ms。

对比 Python（`AI_FEASIBILITY_REPORT.md`）：XGBoost 0.016–0.026ms、精简 IF 0.0088ms、
XGBoost 原生 `pred_contribs` **0.46ms**（1000 棵树口径）。

> 关键结论：Rust 侧 TreeSHAP 与 XGBoost 自带的 `pred_contribs`（C++）**同级延迟**，
> 且无需在数据面嵌入 C++ XGBoost 运行时。模型规模翻倍（1000 → 2000 棵树）后端到端
> p99 ≈ 1.2–1.4ms，相对 PRD 的 10ms 预算仍有 **约 7–8 倍** 余量。

---

## 2. 目录与文件

```
rust/
├── Cargo.toml
├── build.bat            # Windows 构建包装：自动找 vcvars64 + cargo
├── build.sh             # Linux 构建包装（统一 CARGO_TARGET_DIR）
└── src/
    ├── main.rs          # 加载模型 → 一致性校验（含阈值判定）→ 延迟基准
    ├── features.rs      # 80 维特征提取的 Rust 移植（对齐 python/features.py v2）
    ├── decision.rs      # 判定规则：score = 1 - P(normal) + 标定阈值（替代 argmax）
    └── shap.rs          # TreeSHAP（path-dependent）Rust 实现
```

Python 侧配套产物（`../python/artifacts/`）：

| 文件 | 用途 |
|---|---|
| `xgboost_v20261015_001.onnx` | XGBoost 分类器（监督通道，ort 推理） |
| `iforest_lean_v20261015_001.onnx` | 精简 Isolation Forest（**零日通道**，CSIC 正常流量训练，ort 推理） |
| `testvec.json` | 测试向量：请求 / 特征 / 模型期望输出 / **两通道判定期望值 + 融合动作** |
| `xgboost_meta.json` | 特征名、标签、训练配方、训练时的阈值记录（**判定阈值的事实来源是 `decision_policy.json`**） |
| `decision_policy.json` | **判定策略**：两通道的分数定义/阈值档位/标定池 + 融合动作（由 `python/thresholds.py` 生成，数据面只读） |
| `iforest_meta.json` | 零日通道（IF）的元信息：训练集、`zero_day_threshold` 档位、与 sklearn 的单调一致性 |
| `xgb_trees.json` | **可解释性 sidecar**：每棵树的节点（含 `cover`）+ 每类 base_score |
| `shap_ref.json` | XGBoost 原生 `pred_contribs` 参考值 |

> **模型内容指纹守卫**：`DecisionConfig` 解析 `decision_policy.json` 里的
> `supervised/zero_day.artifact_sha1_16`。`Engine::load` 会把它与**实际加载文件**的
> `sha1_16` 比对，不一致直接拒绝加载；`Engine::reload_policy` 同样比对，产物**文件名没变
> 但内容变了**（切换现役正是这种）会拒绝热重载并提示重启。这样就杜绝了
> 「新阈值 + 旧内存模型」的静默错配。旧策略缺该字段时只告警（向后兼容）。
> 采集器指标会上报 `model_xgb_sha1_16` / `model_if_sha1_16`，控制台据此显示
> `pending_restart`。

配套 Python 脚本：
- 正式产物（监督通道）：`train_realdata.py --features v2 --hard-neg lexical --export`
- 正式产物（零日通道）：`iforest_lean_onnx.py --data csic --export`
- **判定策略**：`thresholds.py --pool csic`（标定两条阈值 -> `decision_policy.json`）
- 融合评估：`p3_fusion.py`
- 合成对照产物：`train_xgboost.py` / `train_iforest.py` / `iforest_lean_onnx.py --data synthetic`
  （写到 `*_synthetic*` 独立文件名）
- 参考向量：`export_testvec.py`（**直接加载已导出产物**，不再重训）、`export_shap_ref.py`

---

## 3. 构建与运行

工具链不需要手工加 PATH：`build.bat` / `build.sh` 会依次尝试 `vswhere`、本机历史路径
`D:\visual_studio`、VS 2022 默认安装目录，并把 `%USERPROFILE%\.cargo\bin` 补进 PATH。

```bat
cd F:\waf\rust
build.bat run --release
build.bat test --release --lib
```

Linux（需要 gcc/make/cmake/ninja）：

```bash
cd waf/rust
./build.sh build --release
./build.sh test --release --lib
```

构建缓存由 `WAF_CARGO_TARGET` 控制，默认：

- Windows：有 `E:\` 时用 `E:\waf-target`，否则 `%LOCALAPPDATA%\waf-cargo-target`；
- Linux：`~/.cache/waf-cargo-target`。

`proxy/` 与 `rust/` 必须共用这份缓存（ort/ONNX-Runtime 树很大，否则会编两遍）。
一键安装的 `-WithRust` / `--with-rust` 会调用同一套脚本。

### 重新生成模型与参考数据

```bat
cd F:\waf\python
py -3.10 train_realdata.py --features v2 --hard-neg lexical --export  :: 监督通道（含困难负样本）
py -3.10 iforest_lean_onnx.py --data csic --export  :: 零日通道（CSIC 正常 30,000，80 维）
py -3.10 thresholds.py --pool csic                 :: 标定两条阈值 -> decision_policy.json
py -3.10 export_testvec.py                         :: 特征/推理/判定期望（直接读已导出产物）
py -3.10 export_shap_ref.py                        :: pred_contribs 参考
```

> 注意：合成数据训练会写到独立文件名（`xgboost_synthetic_001.onnx` /
> `iforest_synthetic_001.onnx` / `iforest_lean_synthetic_001.onnx` 及对应 `*_synthetic*` meta），
> **不会**覆盖正式产物。若误覆盖，重跑上面第 1~3 步即可恢复一致性。

---

## 4. 两个关键技术决策

### 4.1 可解释性需要带 `cover` 的 sidecar

XGBoost 的 `pred_contribs` 使用的是 **path-dependent TreeSHAP**，
未知特征时的左右分流权重来自节点的 **`cover`（Hessian 之和）**。
而 ONNX 的 `TreeEnsemble*` 属性**不包含 `cover`**，无法据此复现 `pred_contribs`。

因此训练侧额外导出了 `xgb_trees.json`（与 ONNX **同源同一 booster**）。
这是生产环境同样适用的做法：数据面推理用 ONNX，解释器用紧凑树件。

> 后续可评估：把树件编译为二进制格式以缩短加载时间（当前 JSON 解析在启动期一次性完成）。

### 4.2 TreeSHAP 移植

`src/shap.rs` 严格移植 shap 的 `src/tree_shap.h`
（`extend_path` / `unwind_path` / `unwound_path_sum` / `tree_shap_recursive` /
`compute_expectations`），仅实现 `condition == 0` 的单实例主效应路径：

- 内部节点 value 预处理为子树加权期望（`compute_expectations`）
- 沿路径逐层 `extend_path`，遇到重复分裂特征时 `unwind_path` 后再展开
- 叶子处按 `unwound_path_sum` 累积各特征贡献

**踩坑记录**：分支比较必须是**严格 `<`**（`x[j] < threshold` 走左子树）。
最初误用 `<=`，由于本数据集含大量整型特征（如 `num_special`），
恰好等于阈值时会整棵子树路由错误，导致归因偏差达 8.5（改为 `<` 后降到 1.9e-6）。

---

## 5. 已知限制 / 下一步

- **Oracle 是 `pred_contribs`，不是 `SHAP` 包**：本机无 `shap`，验证基准为 XGBoost 原生实现；
  两者均实现 path-dependent TreeSHAP，理论一致。
- **仅主效应**：未实现交互效应（`condition != 0`）。
- **深树已压测**：正式模型 2000 棵树 / 18,464 节点 / 深度 8，TreeSHAP 一致性 8.1e-6 ✅
  （v1 时代仅 1000 树 / 3218 节点 / 深度 ≤3，该限制已消除）。
- **跨平台特征一致性**：当前在 **Windows/MSVC + 200 条混合请求上逐位一致**。
  熵使用 `log2`、长度对数使用 `ln_1p`，在 Linux（不同 libm）上可能出现 **1 ULP 级**差异，
  CI 断言应使用数值容差而非"位精确"。
- **非 ASCII 输入**：`to_lowercase`/`is_ascii_*` 与 Python 的 Unicode 语义存在差异，
  生产应对输入做 ASCII 归一化或补齐 Unicode 逻辑（当前测试向量含 latin-1 百分号编码，仍通过）。
- **`cover` 归一化未处理零权重节点**：`w == 0` 时代码会得到 `NaN`；
  真实模型不会出现（`min_child_weight` 保证），但生产应加防御。
- **未做多线程/批处理基准**：`intra_op=1` 单请求口径；批量吞吐与 `E 核绑定`未测。
- 建议正式版用 `criterion` 做微基准，并补 CI（Linux + Windows matrix）。

---

## 6. 特征通道 v1 → v2（移植踩坑记录）

v2 重写动机见 `../REALDATA_EVALUATION.md` §4：v1 用**子串计数**匹配关键词
（`or`/`and`/`id`/`sh`/`ls`），并用**未归一化的原始计数**，导致正常英文长文本被大量误报。

v2 的改动：词边界匹配、强/弱关键词分层、按 token 数归一化 + 长度无关布尔、
特殊字符占比化、新增参数值维度与语法结构特征（80 维）。

**移植时被一致性校验抓到的两个 bug**（都是"特征顺序/公式一处不一致"，肉眼极难发现）：

1. `log_url_len` 误写成原始长度（`url.chars().count()`），漏了 `ln_1p` → 单特征偏差 62.78；
2. `is_form_body` / `is_json_body` 的**向量顺序写反**（Python 顺序是 form 在前、json 在后）
   → 布尔特征偏差 1.0。

结论：`features.rs` 的 `push!` 顺序必须与 Python `_base_names()` **逐项对齐**；
CI 必须包含 200×80 的逐位比对，它正是这次唯一可靠地发现问题的机制。
