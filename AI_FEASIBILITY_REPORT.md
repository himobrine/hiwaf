# AI 部分可行性验证报告

> 对应 PRD：4.1.4 / 4.1.5 / 4.5.1 / 5.3 / 5.4 / 七章
> 验证环境：**本机 i5-12500H（12 核 / 16 线程，无 GPU）**，Windows，Python 3.10.10 (MSVC x64)
> 验证日期：2026-10-16
> 结论一句话：**推理链路完全可行且性能远超预期；但"零日检测率 >70%"与"pred_contribs 进 ONNX"两条 PRD 假设不成立，需调整方案。**

---

## 1. 验证范围

| 项 | 是否验证 | 产物 |
|---|---|---|
| 双通道特征工程（结构化通道） | ✅ | `python/features.py`（v2，80 维；v1 为 78 维，见 `features_v1.py`） |
| XGBoost 多分类训练 | ✅ | `python/train_xgboost.py` |
| XGBoost → ONNX 导出 + 一致性 | ✅ | `artifacts/xgboost_v20261015_001.onnx` |
| Isolation Forest 训练 | ✅ | `python/train_iforest.py` |
| Isolation Forest → ONNX 导出 + 一致性 | ✅ | 合成对照产物 `artifacts/iforest_synthetic_001.onnx`；**正式零日通道**是 `iforest_lean_v20261015_001.onnx`（CSIC 正常流量训练，见 `iforest_lean_onnx.py --data csic`） |
| **精简 IF 导出**（优化单样本延迟） | ✅ | `python/iforest_lean_onnx.py` → `iforest_lean_*.onnx` |
| ONNX Runtime CPU 推理延迟/吞吐/内存 | ✅ | `python/bench_inference.py` → `bench_report.json` |
| 可解释性 pred_contribs | ✅（探针） | `python/explain_probe.py` |
| 真实数据集检测率 | ❌ 未做 | 需 CSIC 2010 / HTTP Params 2015 |

---

## 2. 环境结论

- **CPU 与 PRD 目标一致**：i5-12500H，12 核 / 16 线程。本机即可作为性能基线机。
- **Python 版本陷阱**：PATH 上的默认 `python` 是 IDA 附带的 **3.8**，真正可用的解释器是 `C:\Program Files\Python310\python.exe`（3.10.10）。后续脚本/CI 必须显式固定解释器路径。
- **依赖安装成功（用户级 site-packages）**：`xgboost 3.2.0`、`onnx 1.23.2`、`skl2onnx 1.20.0`、`onnxmltools 1.16.0`、`onnxconverter-common 1.16.0`；`onnxruntime 1.20.0` 为既有环境。
- **Rust 工具链未安装**（`cargo` 不存在）——数据面需另行搭建。

---

## 3. 核心结论：推理延迟（本机实测）

### 3.1 XGBoost（200 棵树，深度 6，78 特征，105 KB）
| 线程 | 单样本 p50 | p99 | 会话加载 |
|---|---|---|---|
| 1 | **0.026 ms** | 0.063 ms | 6 ms |
| 4 | 0.016 ms | 0.042 ms | 24 ms |
| 12 | 0.017 ms | 0.053 ms | 6 ms |

> **远超 PRD 目标**（PRD 承诺 1–3ms）。PRD 对 XGBoost 的延迟估计过于保守。
> 单线程已足够；多线程对单样本几乎无收益（批量才显著）。

### 3.2 Isolation Forest（100 棵树，max_samples=256）—— 关键发现
| 导出方式 | 单样本 p50 | p99 | 会话加载 | 体积 |
|---|---|---|---|---|
| skl2onnx 默认图 | 1.23 ms | 2.23 ms | **1268 ms** | 803 KB |
| **精简 TreeEnsembleRegressor（本项目实现）** | **0.0088 ms** | 0.0153 ms | **13.7 ms** | 398 KB |

- skl2onnx 默认生成的 IF 图（含 log/reduce 等算子）单样本 **1.23ms**，**是 PRD 声称的 0.035ms 的 35 倍**，且会话加载高达 1.27s（影响热加载）。
- **只有批量=128 时**才降到 ~0.035ms/样本 —— 说明 **PRD 的"0.035ms/样本"其实是批量吞吐数字，不是单请求延迟**。
- 本项目实现的**精简导出**（将孤森林直接编码为单个 `TreeEnsembleRegressor` 聚合平均路径长度）把单样本降到 **0.0088ms（136× 提升）**，加载降到 13.7ms，且与 sklearn 判定**排序完全一致**（Spearman = −1.0000，固定 FPR 下检出率完全相同）。
- **结论：IF 层可做成单请求同步、也可批量，不再是性能瓶颈。此项需回写进工程计划（不用 skl2onnx 默认导出）。**

### 3.3 内存
两个模型常驻内存合计 **< 55 MB**（PRD 预算 < 500MB，余量充足）。

---

## 4. 检测质量（合成数据，⚠️ 不可外推）

数据为**合成样本**（`dataset.py`，含大量"硬负样本"），仅用于打通工程链路：

| 模型 | 指标 | 结果 |
|---|---|---|
| XGBoost | 测试集准确率 / macro-F1 | 1.00 / 1.00（**数据过易，无参考价值**） |
| IF | 3% FPR 预算下攻击检出率 | **0.2325** |
| IF | 5% FPR 预算下攻击检出率 | 0.5305 |

> ⚠️ **风险确认（已用真实数据集验证，结论已更新）**：仅用结构化特征、且**训练数据未覆盖部署分布**时，
> Isolation Forest 在低误报预算下检出率很低——CSIC 2010 上 @FPR 1% 仅 **12–14%**（v1 特征）。
>
> 后续工作（详见 `REALDATA_EVALUATION.md`）：
> 1. 特征重写为 v2 后，同一指标提升到 **26.0%**（去偏 28.7%），低误报检出率接近翻倍；
> 2. **决定性结论**：主要的误报来源是训练数据未覆盖部署分布（OOD），而非模型或特征；
>    补入 500 条同分布长文本良性负样本即可把误报率从 33.2% 压到 ~1.4%；
> 3. 因此 PRD 的「零日 >70%」不应作为单点指标沿用，应改为**分误报预算口径**
>    （如 @FPR 1% ≥ 30%、@FPR 5% ≥ 50%），并把"采集本业务良性流量"列为上线前置动作；
> 4. **正式产物已按此落地**：烘入困难良性负样本后（同分布自适应，见 §8.1）；
> 5. **但"过拟合量化审计"（§8.2）修正了原先引用的单点数字**：
>    lexical 留出集误报 **0.8%–2.80%（均值 1.56%±0.71）**、@FPR 3% 检出率
>    **39.6%–66.0%（均值 58.3%±9.6）**；独立 CSIC 良性池（6,000 条）误报 **1.35%±0.39**。
>    **0.8% / 66.0% 是 5 个切分里最好的那个，不能外推。**
> 6. **§8.3/§8.4 又指出两个更严重的问题**：(a) `argmax` 决策使同一模型的误报在 0.8%–3.0% 间乱跳，
>    **已改为**「两条通道各自标定阈值 + 融合」：策略文件 `artifacts/decision_policy.json`
>    （`python/thresholds.py` 生成，代码级拒绝含训练样本的校准池），`rust/src/decision.rs` 按策略
>    判定（监督命中→阻断、仅零日命中→告警），两通道分数与**融合动作均纳入一致性校验**（200/200）；
>    (b) **真实攻击召回仅 20.2%±1.7**（CSIC 25,065 条异常），这比误报更缺；双通道融合能提到
>    **28.5%**（1% 预算，+9.2pp），但**零日通道跨分布误报达 28.2%**，只能在训练分布内启用（S9）。

---

## 5. 可解释性（PRD 4.5.1）

- **onnxmltools 的 XGBoost 转换器不支持 `pred_contribs`**（无该参数，ONNX 图不含贡献输出）。
- 原生 xgboost `pred_contribs` 实测：**0.46ms p50**（predict 为 0.048ms），**额外开销约 +0.41ms / 10×**。PRD 声称 "+0.1–0.3ms" 略乐观，但同数量级、可接受。
- 好消息：导出的 ONNX 图包含 `TreeEnsembleClassifier` 的完整 **`nodes_*` / `class_*` 属性**。
- ⚠️ **但 ONNX 缺节点 `cover`**：XGBoost 的 `pred_contribs` 属 path-dependent TreeSHAP，
  未知特征时的左右分流权重取自节点 `cover`（Hessian 之和），ONNX 属性中不存在。
  因此**仅凭 ONNX 无法精确复现 `pred_contribs`**，需随模型附带含 `cover` 的紧凑树件。

> **方案已落地并验证（`rust/`）**：解释器由 **Rust 侧 TreeSHAP** 实现，
> 读取训练侧导出的 `xgb_trees.json`（含 `cover`，与 ONNX 同源同一 booster）。
> 对齐 XGBoost 原生 `pred_contribs`：**max|diff| = 1.9e-6**；
> 单样本 **0.075ms**，比原生 `pred_contribs`（0.46ms）**快约 6 倍**。
> 详见 `rust/README.md`。

---

## 6. 工程链路上的坑（已踩，供实施避雷）

1. `onnxmltools.convert_xgboost` **不接受 `zipmap` 参数**（与老文档不一致）；输出固定为 `label` + `probabilities`。
2. XGBoost 3.x 的 `base_score` 变为字符串数组，onnxmltools 1.16 已适配，但**版本脆弱**——必须锁定 `xgboost==3.2.0` + `onnxmltools==1.16.0`。
3. skl2onnx 导出 IF 必须指定 `target_opset={"":15,"ai.onnx.ml":3}`，否则报 domain 版本错误。
4. 手写 ONNX 模型需显式设 `ir_version=10`，否则 onnxruntime 1.20 拒绝加载（IR 14 > max 10）。
5. `onnx.checker` 对部分 skl2onnx 模型报 `Field 'shape' ... missing`——**非致命**，ORT 仍可加载，勿据此判定失败。
6. Windows 控制台默认 GBK，中文输出乱码；脚本需 `set PYTHONIOENCODING=utf-8`。
7. shell 内联 `-c "..."` 在本环境引号处理异常，**统一改用脚本文件执行**。

---

## 7. 对 PRD 的修正建议

| PRD 原文 | 实测/结论 | 建议 |
|---|---|---|
| XGBoost 延迟 1–3ms | 实测 0.02ms | 改写为 < 0.1ms（留有工程余量） |
| IF 延迟 ~0.035ms/样本 | 单请求 1.23ms；仅批量达标；精简导出后 0.009ms | 改为"精简导出后单请求 <0.02ms"，并记录导出方式 |
| pred_contribs 进 ONNX | 不支持；且 ONNX 缺 `cover` | 可解释性改为 **Rust TreeSHAP + 含 cover 的树件**（已验证） |
| 零日检测率 >70% | 合成数据仅 23%@3%FPR，未验证 | 标注"待真实数据验证"，并预留更强方案 |
| 峰值内存 <500MB | 两模型 <55MB | 保留，余量充足 |

---

## 8. 可行性总评与下一步

**结论：AI 推理部分可行性 ✅（性能无忧），检测效果与可解释性 ⚠️（需重新设计）。**

下一步（按优先级）：
1. **P0**：拉取真实数据集（CSIC 2010 / HTTP Params 2015），重新评估检测率与 FPR，验证零日方案。
2. **P0**：将"精简 IF 导出"纳入正式导出脚本；制定模型版本/清单规范。
3. **P1**：实现 Rust 侧 ONNX 加载（`ort` crate）+ TreeSHAP 可解释性原型（对应工程计划 Spike S1/S3）。
4. **P1**：锁定依赖版本，建立可复现的 Python 环境（venv + requirements）。
5. **P2**：验证嵌入通道（字符 n-gram / FastText）对低 FPR 检测率的提升。

---

### 复现命令

```bat
set PYTHONIOENCODING=utf-8
cd F:\waf\python
py -3.10 train_xgboost.py
py -3.10 train_iforest.py
py -3.10 iforest_lean_onnx.py --data synthetic --export
py -3.10 bench_inference.py --n 2000
py -3.10 explain_probe.py
```
