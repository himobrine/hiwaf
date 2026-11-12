# 预置模型产物（v22）

本目录下的模型**随仓库发布**，克隆后无需训练即可启动控制台并看到完整代次树。
唯一的判定事实来源仍是 [`decision_policy.json`](decision_policy.json)；本文件只是快照说明。

## 1. 现役槽位（数据面按固定文件名加载）

| 通道 | 文件 | SHA1 前 16 | 大小 |
|---|---|---|---|
| 监督 | `xgboost_v20261015_001.onnx` | `abe16c602d1e4893` | 6.54 MB |
| 零日 | `iforest_lean_v20261015_001.onnx` | `8d21a7c2dce87e85` | 610 KB |
| 零日 warm start 训练件 | `iforest_model.joblib` | —（sklearn 产物，不参与推理） | 1.85 MB |

监督通道的 TreeSHAP 还需要 `xgb_trees.json`（与 ONNX 同源、同一个 booster）；
warm start 需要 `xgb_model.json`。两者本来就在库里。

## 2. 代次快照（`models/<channel>/gen-XXXX-<sha12>/`）

| 通道 | 代次 | 目录 | SHA1 前 16 | 状态 | 父代 | 可 warm start |
|---|---|---|---|---|---|---|
| 监督 | g1 | `models/supervised/gen-0001-f5da765a27b7` | `f5da765a27b73d4b` | archived | — | 是（`xgb_model.json`） |
| 监督 | g2 | `models/supervised/gen-0002-eab7b73e1b04` | `eab7b73e1b04ba0d` | archived | g1 | 是（含学习曲线） |
| 监督 | g3 | `models/supervised/gen-0003-abe16c602d1e` | `abe16c602d1e4893` | **active** | g2 | 是 |
| 零日 | g1 | `models/zero_day/gen-0001-c3af8fc61410` | `c3af8fc61410b008` | archived | — | 是（100 棵） |
| 零日 | g2 | `models/zero_day/gen-0002-1a6967a746ea` | `1a6967a746eaa40e` | archived | g1 | 是（125 棵，warm start） |
| 零日 | g3 | `models/zero_day/gen-0003-8d21a7c2dce8` | `8d21a7c2dce87e85` | **active** | g2 | 是（200 棵，warm start） |

**为什么还需要 `registry_seed.json`**：代次与血缘存在 `python/service/console.db` 里，
而 db（含用户、审计、密钥）**不入库**。清单把「哪几个目录组成哪一代、父代是谁」固化成
一份小 JSON，首次启动且 `model_registry` 表为空时由
`model_registry.import_seed()` 导入。

导入时的硬性校验（任一不满足就跳过该行，不会登记出磁盘上不存在的代次）：

1. `snapshot_dir/model.onnx` 存在；
2. 其实际 `sha1_16` 与清单一致；
3. `meta_path` 存在；
4. 每通道最多一个 `active`（多余降级为 `archived`）。

非空表**绝不覆盖**——用户自己训练的历史优先。

## 3. 训练配方（摘自 meta，完整字段见各代 `*_meta.json`）

- **监督**：80 维特征（`features_v2`），5 类（normal/sqli/xss/cmdi/traversal）。
  g1 = 2000 棵树；g2 从 g1 warm start 到 4000 棵树；g3 基于 2026-11 语料从 g2
  warm start 到 4000 棵深树（210,706 节点）。
- **零日**：IsolationForest。g1 = 100 棵，g2 warm start 到 125 棵（CSIC）；
  g3 基于 2026-11 parquet 正常流量从 g2 warm start 到 200 棵，目标 FPR 0.5%（alert-only）。

复现、换本地数据重训、增量训练：见仓库根 `SETUP.md` 第 4-6 步。

## 4. 更新预置产物（发布新一代时）

```bat
:: 1) 训练 / 切换现役（走控制台「模型与门禁」，不要手改槽位文件）
:: 2) 放开新代次的忽略规则（.gitignore 里 python/artifacts/models/* 那一段）
:: 3) 重新导出清单
cd python
..\.venv\Scripts\python.exe -m service.export_registry_seed
:: 4) 同步更新本文件的表格与 README 的「当前状态」
```

## 5. 许可

g1/g2 权重由 **CSIC 2010** 与 **HTTP Params 2015** 训练而来；g3 改用 2026-11 语料
（`WAF Data v2` parquet、OWASP ModSecurity 日志、WAF-Payload-Collection、
`WAF_DETECTION_DATASET.jsonl` 等）。各数据集的再分发条款见仓库根
`THIRD_PARTY_NOTICES.md` §2；内部/自用不受影响，**对外分发前请自行复核并承担合规责任**。