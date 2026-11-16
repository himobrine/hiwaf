# 预置模型产物（v30）

本目录下的模型**随仓库发布**，克隆后无需训练即可启动控制台并看到完整代次树。
唯一的判定事实来源仍是 [`decision_policy.json`](decision_policy.json)；本文件只是快照说明。

## 1. 现役槽位（数据面按固定文件名加载）

| 通道 | 文件 | SHA1 前 16 | 大小 |
|---|---|---|---|
| 监督 | `xgboost_v20261015_001.onnx` | `ddd54ebc29469208` | 8.23 MB |
| 零日 | `iforest_lean_v20261015_001.onnx` | `2ae506b521152f31` | 0.51 MB |
| 零日 warm start 训练件 | `iforest_model.joblib` | —（sklearn 产物，不参与推理） | 1.62 MB |

监督通道的 TreeSHAP 还需要 `xgb_trees.json`（与 ONNX 同源、同一个 booster）；
warm start 需要 `xgb_model.json`。两者本来就在库里。

> **2026-11-16 切换（policy v26 → v28 → v30）**：
> v28 = 监督 `gen-0004-87f851e0304d` + 零日 `gen-0005-2ae506b52115`；
> v30 = 监督 `gen-0005-ddd54ebc2946`（cmdi 形态对齐）+ 同一零日。
> 这三代**已随仓库发布**（`.gitignore` 已放行、`registry_seed.json` 已重导为 10 代），
> 克隆后控制台能看到完整代次树并正确解析 `active`。

## 2. 代次快照（`models/<channel>/gen-XXXX-<sha12>/`）

| 通道 | 代次 | 目录 | SHA1 前 16 | 状态 | 父代 | 可 warm start |
|---|---|---|---|---|---|---|
| 监督 | g1 | `models/supervised/gen-0001-f5da765a27b7` | `f5da765a27b73d4b` | archived | — | 是（`xgb_model.json`） |
| 监督 | g2 | `models/supervised/gen-0002-eab7b73e1b04` | `eab7b73e1b04ba0d` | archived | g1 | 是（含学习曲线） |
| 监督 | g3 | `models/supervised/gen-0003-abe16c602d1e` | `abe16c602d1e4893` | archived | g2 | 是 |
| 监督 | g4 | `models/supervised/gen-0004-87f851e0304d` | `87f851e0304da39c` | archived | —（`inherit_mode=off`） | 是（含学习曲线） |
| 监督 | g5 | `models/supervised/gen-0005-ddd54ebc2946` | `ddd54ebc29469208` | **active** | —（`inherit_mode=off`） | 是（含学习曲线） |
| 零日 | g1 | `models/zero_day/gen-0001-c3af8fc61410` | `c3af8fc61410b008` | archived | — | 是（100 棵） |
| 零日 | g2 | `models/zero_day/gen-0002-1a6967a746ea` | `1a6967a746eaa40e` | archived | g1 | 是（125 棵，warm start） |
| 零日 | g3 | `models/zero_day/gen-0003-8d21a7c2dce8` | `8d21a7c2dce87e85` | archived | g2 | 是（200 棵，warm start） |
| 零日 | g4 | `models/zero_day/gen-0004-cfead12f36a4` | `cfead12f36a4dd7c` | archived | g3 | 是（225 棵，warm start） |
| 零日 | g5 | `models/zero_day/gen-0005-2ae506b52115` | `2ae506b521152f31` | **active** | —（`inherit_mode=off`） | 是（225 棵，全量重训） |

> 代次号是**登记表内的自增序号**，与训练批次的叫法不同：A/B 里的
> `g5_sup_fur` 登记成监督第 4 代，`g6_sup_fur1n4` 登记成监督第 5 代
> （`XGBoost g5`），`g5_if` 登记成零日第 5 代。看名字容易混，以 sha 为准。

**为什么还需要 `registry_seed.json`**：代次与血缘存在 `python/service/console.db` 里，
而 db（含用户、审计、密钥）**不入库**。清单把「哪几个目录组成哪一代、父代是谁」固化成
一份小 JSON，启动时由 `model_registry.sync_seed()` 导入：

- 空库：完整导入（与旧版首次启动行为一致）；
- 非空库（升级）：只补入缺失的 `(channel, generation)` / sha，不覆盖任何已有行；
  随后按 `decision_policy.json` 的 `artifact_sha1_16`（缺失时退回现役槽位文件的 sha1）
  校正 `active`——库里已有的现役若与磁盘/策略不一致才切换，不会顶掉用户自己切的模型。

导入时的硬性校验（任一不满足就跳过该行，不会登记出磁盘上不存在的代次）：

1. `snapshot_dir/model.onnx` 存在；
2. 其实际 `sha1_16` 与清单一致；
3. `meta_path` 存在；
4. 每通道最多一个 `active`（同一次导入里多余降级为 `archived`；非空库已有现役时，
   新补入的清单 active 先记为 `archived`，由上面的策略校正决定是否真正生效）。

用户自己训练/导入的代次永远优先：清单不会改写它们的名称、状态或快照。

## 3. 训练配方（摘自 meta，完整字段见各代 `*_meta.json`）

- **监督**：80 维特征（`features_v2`），5 类（normal/sqli/xss/cmdi/traversal）。
  g1 = 2000 棵树；g2 从 g1 warm start 到 4000 棵树；g3 基于 2026-11 语料从 g2
  warm start 到 4000 棵树。
  g4 = **全量重训**（`--no-parent`，800 轮 × 5 类 = 4000 棵），语料为 `traindata/`
  2026-11 全量 + 新增 FUR-API 良性 18,119 / SQLiV5 15,000 / WAF-A-MoLE 20,000 /
  wafrift 796 / waffled 28（train 292,177 行，normal 220,768）。
  g5 = 在 g4 语料上做 **cmdi 形态对齐**（`--cmdi-wrap 1 --cmdi-wrap-neg 4`）：
  真实 cmdi 载荷包进 JSON/SOAP/form 外壳 + 4 倍同外壳 FUR 良性，train 303,581
  （normal 229,928），5 类 acc 0.9912。
- **零日**：IsolationForest。g1 = 100 棵，g2 warm start 到 125 棵（CSIC）；
  g3 基于 2026-11 parquet 正常流量从 g2 warm start 到 200 棵，目标 FPR 0.5%（alert-only）；
  g4 从 g3 warm start 到 225 棵，`--upload-mode add` 并入 FUR-API `train.csv` 的
  18,144 条去重良性（校准仍用官方 12k 留出，`--calib-mode official`，与训练集交集 0）；
  g5 = **全量重训 225 棵**（220,768 条良性，`inherit_mode=off`），目标 FPR 1%（alert-only）。
  两代都按请求 sha1 与 12k 留出池互斥。

## 4. 更新预置产物（发布新一代时）

```bat
:: 1) 训练 / 切换现役（走控制台「模型与门禁」，不要手改槽位文件）
:: 2) 放开新代次的忽略规则（.gitignore 里 python/artifacts/models/* 那一段）
::    2026-11-16 已追加（v28/v30 发布）：
::      !python/artifacts/models/supervised/gen-0004-87f851e0304d/
::      !python/artifacts/models/supervised/gen-0005-ddd54ebc2946/
::      !python/artifacts/models/zero_day/gen-0005-2ae506b52115/
:: 3) 重新导出清单
cd python
..\.venv\Scripts\python.exe -m service.export_registry_seed
:: 4) 同步更新本文件的表格与 README 的「当前状态」
```

> 发布前注意体积：监督每代约 60–70 MB（含 `xgb_model.json` / `xgb_trees.json` /
> `training_keys.txt` / 校准池）。本轮在本地就曾把磁盘写满（`No space left on device`
> 发生在快照复制中途），发布/训练前先确认目标盘有 ≥300 MB 余量。

## 5. 许可

g1/g2 权重由 **CSIC 2010** 与 **HTTP Params 2015** 训练而来；g3 改用 2026-11 语料
（`WAF Data v2` parquet、OWASP ModSecurity 日志、WAF-Payload-Collection、
`WAF_DETECTION_DATASET.jsonl` 等）；g4（监督）与 g5（零日）在此基础上增加了
**FUR-API** 良性样本（`traindata/FUR-API/train.csv`）与 SQLiV5 / WAF-A-MoLE /
wafrift / waffled 攻击样本。各数据集的再分发条款见仓库根
`THIRD_PARTY_NOTICES.md` §2；内部/自用不受影响，**对外分发前请自行复核并承担合规责任**
（FUR-API 的来源与授权未随数据提供，**未核实**）。