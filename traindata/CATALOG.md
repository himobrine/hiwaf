# traindata 语料目录（自动生成）

> `python/traindata_catalog.py`（2026-11-16 22:25:26）—— **勿手改**。

- 根目录：`traindata`
- 文件：540 个 / 854.3 MB
- 数字来源：realdata_waf._inventory（与训练同一批 loader）

## 语料角色

| 语料 | 角色 | 可用性 | 关键数字 |
|---|---|---|---|
| `xlsx` | 主训练集（4 类攻击 + 良性） | 可用（按事务聚合 + 去重后） | rows=108,883; transactions=27,686; unique_requests=18,470; with_body=2,112; labels=0:1,140,1:12,693,2:1,270,3:579,4:902,None:1,886 |
| `modsec` | 真实在野攻击（召回评估 + 训练） | 攻击-only，零良性 | requests=150,930; days=30; with_body=14,002 |
| `parquet_train` | 良性池（anomalous 无子类） | 正常可训练；异常只做二分类评估 | rows=1,924,461; label_normal=1,539,108; label_anomalous=385,353; with_body=89 |
| `parquet_test` | 独立评估集（normal 量误报 / anomalous 量检出） |  | rows=240,558; label_normal=192,295; label_anomalous=48,263; with_body=8,594 |
| `payloads` | 载荷集合（TP 进训练；false-positives 作困难良性负例） |  |  |
| `waf_detection` | 外部 WAF 检测结果（无子类，只做二分类评估） |  | rows=644; bad_lines=6 |
| `fur_api` | 真实 API 良性流量（监督/零日训练 + FPR 评估） | normal 全部可用；anomaly 是业务异常，不映射到攻击子类 | rows=20,060; with_body=10,846; labels=0:18,119 |
| `sqliv5` | SQLi 载荷（含 WAF-A-MoLE 对抗样本） | type=sqli 可用；type=valid（合法 SQL）已排除 | sampled=15,000 |
| `wafamole` | WAF-A-MoLE 变异 SQLi 载荷 | attacks.sql 抽样可用；sane.sql 已排除（合法 SQL） | sampled=20,000 |
| `wafrift` | WAF 绕过语料（13 类，8 类可映射 0-4） | sql/xss/cmdi/ssti/xxe/ssrf/log4shell/path 可用；其余无槽位 | cases=932; labels=1:274,2:183,3:269,4:70 |
| `waffled` | 真实 WAF 绕过请求（JSON/multipart/XML body） | body 可用；头字段绕过 80 维特征不可见 | blocks=32; with_body=32; labels=1:9,2:19 |
| `commonhuman` | 载荷库 + 编码器（26 种 evasion） | 本轮不训练：载荷带 `{marker}` 占位符，不替换会成为捷径 token |  |

## 排除的文件及原因

- `CVE_list.json` — JSON 截断（9.5MB 处 unterminated string），且非 HTTP 请求，无法转 80 维特征
- `AgentCyberRangeWebExploitBench/` — 只有 readme.md，内容为“等待通过”，无数据
- `http-attack-requests.json` — 395 字节的清单说明（real/topup 计数），不是数据
- `wafamole_dataset/sane.sql` — 合法 SQL（DDL/DML）。把它塞进参数当良性会教出“SELECT 是正常”的捷径，而它在参数位置上与 SQLi 不可区分；只登记，不入训练
- `sqliv5-dataset-main/` — 只取 SQLiV5.json 的 type=sqli 与 sqli.csv 的 Label=1；type=valid（合法 SQL）与 SQLiV3/V4/V3_clean（V5 已超集）全部排除，sqliv2.csv（旧版重复）与 Label=0（英文诗句，非请求）同样不进训练
- `commonhuman-payloads-main/` — 载荷库 + 编码器，载荷带 `{marker}` 占位符，不替换会成为捷径 token；全笛卡尔积会淹没其它类，本轮只登记不训练
- `FUR-API/test.csv` — 评估专用（984 normal / 137 anomaly），绝不进训练
- `exploit_dataset.jsonl` — 评估专用（172 条 HTTP PoC），不进训练
- `wafrift-main/wafrift-bench/targets/` — 靶场编排/检测脚本，不是载荷数据

## 问题清单

- **warn** `xlsx_host_bias`：xlsx 仅 3 个 host / 7 个 IP，良性代表性有限
- **info** `parquet_no_subclass`：parquet anomalous 385,353 条无子类，只能做二分类评估，不能进 5 类训练
- **info** `parquet_duplicates`：parquet test 有 50,798 行重复请求，去重后 189,760 条唯一
- **info** `wfdet_bad_lines`：WAF_DETECTION_DATASET.jsonl 有 6 行 JSON 损坏，已跳过
- **info** `sqliv5_capped`：sqliv5 抽样 15,000（上限 15,000，稳定哈希）
- **info** `wafamole_capped`：wafamole 抽样 20,000（上限 20,000，稳定哈希）
- **info** `sqliv5_valid_excluded`：sqliv5 的 19,517 条 type=valid（合法 SQL）已排除：放参数里与 SQLi 不可区分

## 建议

- 5 类训练只收 label ∈ 0-4；无子类攻击（parquet anomalous / bruteforce / 920 协议规则）只进二分类评估。
- 校准池必须与训练集**互斥**：用 parquet normal 的独立留出桶，并让 `thresholds.py --train-keys` 校验训练指纹。
- xlsx 的良性只有千余条且只来自 3 个 host —— 误报率的代表性以 parquet 正常流量为准。
- ModSecurity 日志全是命中规则的事务，零良性：它只能量召回，不能量误报。
- 2026-11-16 新增语料（FUR / sqliv5 / wafamole / wafrift / waffled）只进 train/valid（group 85/15），**不进 test**：test 与现役 g3/g5 同一批行，5 类指标才可比；新语料效果看 FUR test + exploit 的独立评估。
- `wafamole_dataset/sane.sql` 与 sqliv5 的 `type=valid` 都是**合法 SQL**，放参数里与 SQLi 不可区分 —— 当良性会教出“SELECT 是正常”的捷径，只登记不入训。
- SQLi 语料有上限（sqliv5 15k / wafamole 20k）且用稳定哈希抽样：否则 128 万行攻击会淹没 ModSec 与 xlsx，其它类召回会掉。

## 文件清单

| 文件 | 大小 | mtime | sha1 |
|---|---|---|---|
| `traindata/AgentCyberRangeWebExploitBench/readme.md` | 0.00 MB | 2026-11-12 19:22 | `d172c55aa04d31d1` |
| `traindata/CATALOG.md` | 0.07 MB | 2026-11-16 11:19 | `6b09434d81cd0bb3` |
| `traindata/CVE_list.json` | 9.07 MB | 2026-11-12 19:21 | `8c2aa3ef4c797d8a` |
| `traindata/FUR-API/test.csv` | 0.93 MB | 2026-11-15 16:25 | `87bcccaa3579ff9b` |
| `traindata/FUR-API/train.csv` | 16.00 MB | 2026-11-15 16:24 | `d906726c6632e9df` |
| `traindata/WAF Data v2/test.parquet` | 10.66 MB | 2026-11-12 19:13 | `ac5147904b6b6e32` |
| `traindata/WAF Data v2/train.parquet` | 76.47 MB | 2026-11-12 19:16 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/LICENSE` | 0.03 MB | 2022-10-11 15:58 | `31a3d460bb3c7d98` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/README.md` | 0.00 MB | 2022-10-11 15:58 | `d0e0138395887536` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/config.yaml` | 0.00 MB | 2022-10-11 15:58 | `631c8c3d695fe233` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/cmdexe/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `681a1d4c4458991b` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/cmdexe/true-positives.txt` | 0.07 MB | 2022-10-11 15:58 | `5b9250cae70c7c08` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/log4shell/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `8eb4a8ec6b240cca` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/log4shell/true-positives.txt` | 0.01 MB | 2022-10-11 15:58 | `1dd05c17c81be204` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/shellshock/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `f710f1f7be9870b9` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/shellshock/true-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `a585e9093522c7e9` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/sqli/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `fd4d23b1f33a02f2` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/sqli/true-positives.txt` | 0.03 MB | 2022-10-11 15:58 | `48ce2e6983fb0b4a` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/traversal/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `9bd84de00702c4b9` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/traversal/true-positives.txt` | 0.99 MB | 2022-10-11 15:58 | `b0a88d2f3d4f9a50` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xss/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `6b5027b3902183ba` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xss/true-positives.txt` | 1.33 MB | 2022-10-11 15:58 | `e2f04723f2438773` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xxe/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `9fe3d87da99a2c11` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xxe/true-positives.txt` | 0.01 MB | 2022-10-11 15:58 | `8564a8cb49e6ab2d` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/cmdexe/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `483b0b7d2c2b5df9` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/cmdexe/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `6ad31c02ebfc670d` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/log4shell/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `fda857b616aeaa12` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/log4shell/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `82cea5eb8500ff6c` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/shellshock/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `55897cbc1a8807bd` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/shellshock/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `52a39c185762f117` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/sqli/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `bfb601d5cb986930` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/sqli/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `f0e05581192f40d9` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/traversal/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `6871734640419813` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/traversal/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `2b3114e81957ed92` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xss/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `5d2afd19d95a66dc` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xss/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `d22b113e46aaf2af` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xxe/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `25d6c51b2aeb71d1` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xxe/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `1581988e29dce746` |
| `traindata/WAF_DETECTION_DATASET.jsonl` | 0.20 MB | 2026-11-12 19:10 | `04e59eb92e05365f` |
| `traindata/combined_final_dataset_augmented.xlsx` | 26.53 MB | 2026-11-12 19:07 | `8dc29279a1f0bf43` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/.gitignore` | 0.00 MB | 2026-06-02 01:44 | `7c30278e2360d18a` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/LICENSE` | 0.03 MB | 2026-06-02 01:44 | `a2f9ffbf32eeb628` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/README.md` | 0.01 MB | 2026-06-02 01:44 | `bcebf1a2683d682c` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/pyproject.toml` | 0.00 MB | 2026-06-02 01:44 | `7bf2c5dcc40450ab` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `a7a6a0bc075da508` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/encoders/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `296c6170b34ed36d` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/encoders/transforms.py` | 0.01 MB | 2026-06-02 01:44 | `e09a22726d49703c` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/js_vulns.py` | 0.01 MB | 2026-06-02 01:44 | `0c46e4626aaae167` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/markers.py` | 0.00 MB | 2026-06-02 01:44 | `80aff6a2bc2b8d14` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `ecab272fc29242c7` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/advanced.py` | 0.01 MB | 2026-06-02 01:44 | `b50dc658a988eb23` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/boolean.py` | 0.00 MB | 2026-06-02 01:44 | `3ebc9875b1e8bdb5` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/error.py` | 0.01 MB | 2026-06-02 01:44 | `9dbdd8f6293b32a6` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/oob.py` | 0.00 MB | 2026-06-02 01:44 | `4a7d8da8c880f718` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/time_based.py` | 0.00 MB | 2026-06-02 01:44 | `1b7dfb0fc24a4fec` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/sqli/union.py` | 0.01 MB | 2026-06-02 01:44 | `e596c23d523fd93a` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/waf/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7ee15b6de8a6270c` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/waf/detect.py` | 0.01 MB | 2026-06-02 01:44 | `e170bfaa955dfcce` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/waf/payloads.py` | 0.01 MB | 2026-06-02 01:44 | `d93be48e65e63407` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/waf/signatures.py` | 0.01 MB | 2026-06-02 01:44 | `6f2bedd6a9d9bbfb` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/xss/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `e56dbb11a9796080` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/xss/advanced.py` | 0.02 MB | 2026-06-02 01:44 | `c4054c01c3b93540` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/xss/html.py` | 0.01 MB | 2026-06-02 01:44 | `c2479fa36cf79bcd` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/src/commonhuman_payloads/xss/script.py` | 0.01 MB | 2026-06-02 01:44 | `8eb9d4f46ad70afa` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/conftest.py` | 0.00 MB | 2026-06-02 01:44 | `a73d309a9262094b` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/fixtures/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/integration/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/integration/test_tool_compat.py` | 0.01 MB | 2026-06-02 01:44 | `b948d947aea569cf` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/regression/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/regression/test_sqli_payload_regression.py` | 0.01 MB | 2026-06-02 01:44 | `33fab27a92ae5d34` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/regression/test_xss_payload_regression.py` | 0.00 MB | 2026-06-02 01:44 | `d332ea3e9b23e810` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/encoders/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/encoders/test_transforms.py` | 0.02 MB | 2026-06-02 01:44 | `34b04f5565a7216d` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/test_advanced.py` | 0.01 MB | 2026-06-02 01:44 | `066d9e1212e22a4f` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/test_boolean.py` | 0.00 MB | 2026-06-02 01:44 | `1e5a8f870bfa097b` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/test_error.py` | 0.00 MB | 2026-06-02 01:44 | `90ccbf721f9862c0` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/test_oob.py` | 0.00 MB | 2026-06-02 01:44 | `22be7718f936f3f6` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/test_time.py` | 0.00 MB | 2026-06-02 01:44 | `9c9a4219316723a2` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/sqli/test_union.py` | 0.00 MB | 2026-06-02 01:44 | `f3c2cdc68ad7d1c3` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/test_js_vulns.py` | 0.01 MB | 2026-06-02 01:44 | `1ae5890c047fabf2` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/test_markers.py` | 0.00 MB | 2026-06-02 01:44 | `b94117c1c746f39e` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/test_version.py` | 0.00 MB | 2026-06-02 01:44 | `c5859fc508b6ff49` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/waf/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/waf/test_detect.py` | 0.01 MB | 2026-06-02 01:44 | `493bcfcc6e9cf898` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/waf/test_payloads.py` | 0.00 MB | 2026-06-02 01:44 | `c4d31ee52e8e7d02` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/waf/test_signatures.py` | 0.00 MB | 2026-06-02 01:44 | `92cf7c2e0e24db26` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/xss/__init__.py` | 0.00 MB | 2026-06-02 01:44 | `7b3dde422f3c6283` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/xss/test_advanced.py` | 0.00 MB | 2026-06-02 01:44 | `ce73c4c0221d2b19` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/xss/test_api.py` | 0.00 MB | 2026-06-02 01:44 | `d68b886b0de6bb3a` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/xss/test_html.py` | 0.00 MB | 2026-06-02 01:44 | `886711981a8e9a3e` |
| `traindata/commonhuman-payloads-main/commonhuman-payloads-main/tests/unit/xss/test_script.py` | 0.00 MB | 2026-06-02 01:44 | `9be390e1c39c222c` |
| `traindata/exploit_dataset.jsonl` | 0.43 MB | 2026-11-15 16:23 | `5db3eb6c3860b7b6` |
| `traindata/http-attack-requests.json` | 0.00 MB | 2026-11-12 19:09 | `db58da79f6d03a47` |
| `traindata/owasp/01-Aug-2025/modsec_audit.anon.log` | 14.97 MB | 2025-09-22 00:26 | `bc17e9a39514e696` |
| `traindata/owasp/02-Aug-2025/modsec_audit.anon.log` | 13.36 MB | 2025-09-22 00:26 | `bc5991b9d71ca17e` |
| `traindata/owasp/03-Aug-2025/modsec_audit.anon.log` | 13.05 MB | 2025-09-22 00:26 | `e5df956577a9b5b2` |
| `traindata/owasp/04-Aug-2025/modsec_audit.anon.log` | 18.17 MB | 2025-09-22 00:26 | `339c5a0d3b10306f` |
| `traindata/owasp/05-Aug-2025/modsec_audit.anon.log` | 11.71 MB | 2025-09-22 00:26 | `7a0f660efed02278` |
| `traindata/owasp/06-Aug-2025/modsec_audit.anon.log` | 9.21 MB | 2025-09-22 00:26 | `d3a8ea6af904b67c` |
| `traindata/owasp/07-Aug-2025/modsec_audit.anon.log` | 4.97 MB | 2025-09-22 00:26 | `071593541cc36790` |
| `traindata/owasp/08-Aug-2025/modsec_audit.anon.log` | 6.64 MB | 2025-09-22 00:26 | `1328a8685b1e8df4` |
| `traindata/owasp/09-Aug-2025/modsec_audit.anon.log` | 8.90 MB | 2025-09-22 00:26 | `65b90f66ff21a5ec` |
| `traindata/owasp/10-Aug-2025/modsec_audit.anon.log` | 18.04 MB | 2025-09-22 00:27 | `667c73bacea7db42` |
| `traindata/owasp/11-Aug-2025/modsec_audit.anon.log` | 8.51 MB | 2025-09-22 00:27 | `5bb2edc8a0b00be6` |
| `traindata/owasp/12-Aug-2025/modsec_audit.anon.log` | 6.39 MB | 2025-09-22 00:27 | `43e89792e034265e` |
| `traindata/owasp/13-Aug-2025/modsec_audit.anon.log` | 14.10 MB | 2025-09-22 00:27 | `d7465dc23778bcf1` |
| `traindata/owasp/14-Aug-2025/modsec_audit.anon.log` | 24.11 MB | 2025-09-22 00:27 | `092b75abc2b6ea69` |
| `traindata/owasp/15-Aug-2025/modsec_audit.anon.log` | 28.44 MB | 2025-09-22 00:27 | `507640598d7e072f` |
| `traindata/owasp/16-Aug-2025/modsec_audit.anon.log` | 27.29 MB | 2025-09-22 00:27 | `907aa945e097cdc9` |
| `traindata/owasp/17-Aug-2025/modsec_audit.anon.log` | 16.07 MB | 2025-09-22 00:27 | `6a96182e61d8184f` |
| `traindata/owasp/18-Aug-2025/modsec_audit.anon.log` | 9.12 MB | 2025-09-22 00:27 | `37d2742791a4d942` |
| `traindata/owasp/19-Aug-2025/modsec_audit.anon.log` | 10.49 MB | 2025-09-22 00:27 | `99c1c4b3d48e7bed` |
| `traindata/owasp/20-Aug-2025/modsec_audit.anon.log` | 7.40 MB | 2025-09-22 00:27 | `ec8da497e1f8ae1b` |
| `traindata/owasp/21-Aug-2025/modsec_audit.anon.log` | 7.49 MB | 2025-09-22 00:27 | `531b23c6326bface` |
| `traindata/owasp/22-Aug-2025/modsec_audit.anon.log` | 7.30 MB | 2025-09-22 00:27 | `992cb10b0e38f59a` |
| `traindata/owasp/23-Aug-2025/modsec_audit.anon.log` | 9.76 MB | 2025-09-22 00:27 | `421fa5b8b6bba105` |
| `traindata/owasp/24-Aug-2025/modsec_audit.anon.log` | 8.74 MB | 2025-09-22 00:27 | `399789dd2121a0f1` |
| `traindata/owasp/25-Aug-2025/modsec_audit.anon.log` | 9.12 MB | 2025-09-22 00:27 | `0283a3463b540192` |
| `traindata/owasp/27-Jul-2025/modsec_audit.anon.log` | 7.51 MB | 2025-09-22 00:27 | `bce0bdf99e21db2d` |
| `traindata/owasp/28-Jul-2025/modsec_audit.anon.log` | 32.58 MB | 2025-09-22 00:27 | `983b17ae08cbd92f` |
| `traindata/owasp/29-Jul-2025/modsec_audit.anon.log` | 7.51 MB | 2025-09-22 00:27 | `67f60f11b8e20231` |
| `traindata/owasp/30-Jul-2025/modsec_audit.anon.log` | 7.88 MB | 2025-09-22 00:27 | `af08de0af4b8bd97` |
| `traindata/owasp/31-Jul-2025/modsec_audit.anon.log` | 10.69 MB | 2025-09-22 00:27 | `d716c237f9963e49` |
| `traindata/proxy/collector-metrics.json` | 0.00 MB | 2026-11-16 22:25 | `4c21eebad0e1688d` |
| `traindata/proxy/raw-20261112-00000.jsonl` | 0.00 MB | 2026-11-12 20:46 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00001.jsonl` | 0.00 MB | 2026-11-12 20:46 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00002.jsonl` | 0.00 MB | 2026-11-12 20:47 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00003.jsonl` | 0.00 MB | 2026-11-12 20:49 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00004.jsonl` | 0.00 MB | 2026-11-12 20:52 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00005.jsonl` | 0.00 MB | 2026-11-12 20:53 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00006.jsonl` | 0.00 MB | 2026-11-12 20:54 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00007.jsonl` | 0.00 MB | 2026-11-12 20:59 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00008.jsonl` | 0.00 MB | 2026-11-12 21:02 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261112-00009.jsonl` | 0.00 MB | 2026-11-12 21:10 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261115-00000.jsonl` | 0.00 MB | 2026-11-15 17:11 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261116-00000.jsonl` | 0.00 MB | 2026-11-16 13:36 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261116-00001.jsonl` | 0.07 MB | 2026-11-16 20:05 | `13e77421e4a3ee2c` |
| `traindata/proxy/raw-20261116-00002.jsonl` | 0.00 MB | 2026-11-16 20:05 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261116-00003.jsonl` | 5.65 MB | 2026-11-16 20:19 | `457644c4201b1a58` |
| `traindata/proxy/raw-20261116-00004.jsonl` | 10.27 MB | 2026-11-16 20:34 | `ea36ee5669de709d` |
| `traindata/proxy/raw-20261116-00005.jsonl` | 0.01 MB | 2026-11-16 20:37 | `74aa2cd686f92077` |
| `traindata/proxy/raw-20261116-00006.jsonl` | 0.00 MB | 2026-11-16 20:40 | `44d5d5a6496c4379` |
| `traindata/proxy/raw-20261116-00007.jsonl` | 0.02 MB | 2026-11-16 20:46 | `f8b91e564d3e5144` |
| `traindata/proxy/raw-20261116-00008.jsonl` | 0.00 MB | 2026-11-16 20:48 | `da39a3ee5e6b4b0d` |
| `traindata/proxy/raw-20261116-00009.jsonl` | 0.01 MB | 2026-11-16 21:08 | `a37813d8b924d0ee` |
| `traindata/proxy/raw-20261116-00010.jsonl` | 22.66 MB | 2026-11-16 21:36 | `8ed4b1c53d29ff8e` |
| `traindata/proxy/raw-20261116-00011.jsonl` | 0.02 MB | 2026-11-16 21:49 | `4c34a8208be9ef90` |
| `traindata/proxy/raw-20261116-00012.jsonl` | 0.00 MB | 2026-11-16 22:10 | `aa123d0f05306aa4` |
| `traindata/proxy/raw-20261116-00013.jsonl` | 0.00 MB | 2026-11-16 22:12 | `097f4f2c629db834` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/LICENSE` | 0.00 MB | 2022-09-21 19:56 | `23d8700ffc432fad` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/README.md` | 0.00 MB | 2022-09-21 19:56 | `8e6d6fdc3201313c` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/SQLiV3.csv` | 2.21 MB | 2022-09-21 19:56 | `cd3ea79d0cade3ab` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/SQLiV3.json` | 3.79 MB | 2022-09-21 19:56 | `23628eca5ce9049f` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/SQLiV3_clean.json` | 3.03 MB | 2022-09-21 19:56 | `a95ef3533b9b7c44` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/SQLiV4.json` | 4.82 MB | 2022-09-21 19:56 | `852b57fdd7acd298` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/SQLiV5.json` | 6.84 MB | 2022-09-21 19:56 | `816b633c23425629` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/sqli.csv` | 0.69 MB | 2022-09-21 19:56 | `c51d4b48f354e4fa` |
| `traindata/sqliv5-dataset-main/sqliv5-dataset-main/sqliv2.csv` | 3.44 MB | 2022-09-21 19:56 | `1697d8726716cf1e` |
| `traindata/wafamole_dataset/attacks.sql` | 163.54 MB | 2026-11-16 09:43 | `` |
| `traindata/wafamole_dataset/sane.sql` | 71.75 MB | 2026-11-16 09:43 | `` |
| `traindata/waffled-main/waffled-main/LICENSE` | 0.00 MB | 2026-06-19 04:17 | `c59a479cabbaa056` |
| `traindata/waffled-main/waffled-main/README.md` | 0.01 MB | 2026-06-19 04:17 | `a8d3206ff47606ef` |
| `traindata/waffled-main/waffled-main/bypass-database/README.md` | 0.00 MB | 2026-06-19 04:17 | `47ad63bd484ab6e1` |
| `traindata/waffled-main/waffled-main/bypass-database/detectables/attack-injection-json-detectable.raw` | 0.00 MB | 2026-06-19 04:17 | `b5c95096de123f98` |
| `traindata/waffled-main/waffled-main/bypass-database/detectables/attack-injection-multipart-detectable.raw` | 0.00 MB | 2026-06-19 04:17 | `eff5b15ada259e61` |
| `traindata/waffled-main/waffled-main/bypass-database/detectables/attack-xss-json-detectable.raw` | 0.00 MB | 2026-06-19 04:17 | `3eaa46899ac706e6` |
| `traindata/waffled-main/waffled-main/bypass-database/detectables/attack-xss-multipart-detectable.raw` | 0.00 MB | 2026-06-19 04:17 | `4dd5a8719f3b36c0` |
| `traindata/waffled-main/waffled-main/bypass-database/json_requests.raw` | 0.00 MB | 2026-06-19 04:17 | `6e28362375006148` |
| `traindata/waffled-main/waffled-main/bypass-database/multipart_requests.raw` | 0.01 MB | 2026-06-19 04:17 | `d6aee108888a3bc7` |
| `traindata/waffled-main/waffled-main/bypass-database/xml_requests.raw` | 0.00 MB | 2026-06-19 04:17 | `e79436b8fd34cbc6` |
| `traindata/waffled-main/waffled-main/echo-servers/Dockerfile` | 0.00 MB | 2026-06-19 04:17 | `79f02f6d4163d220` |
| `traindata/waffled-main/waffled-main/echo-servers/README.md` | 0.00 MB | 2026-06-19 04:17 | `b896b96f30b86a0c` |
| `traindata/waffled-main/waffled-main/echo-servers/processes.json` | 0.00 MB | 2026-06-19 04:17 | `cab4d80730cb7fef` |
| `traindata/waffled-main/waffled-main/echo-servers/setup_servers.sh` | 0.00 MB | 2026-06-19 04:17 | `dccd0f4c4b5088df` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/golang/gin-all/go.mod` | 0.00 MB | 2026-06-19 04:17 | `a5a3ef47f4d8decb` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/golang/gin-all/go.sum` | 0.01 MB | 2026-06-19 04:17 | `f57570ad1f9c042a` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/golang/gin-all/main.go` | 0.00 MB | 2026-06-19 04:17 | `2bc3469077fe96a6` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `c32218a75ca0a7ae` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/build.gradle` | 0.00 MB | 2026-06-19 04:17 | `e89c01ac4267a3bf` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/gradle/wrapper/gradle-wrapper.jar` | 0.04 MB | 2026-06-19 04:17 | `dcbc7c8821eb4e42` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/gradle/wrapper/gradle-wrapper.properties` | 0.00 MB | 2026-06-19 04:17 | `d01c802a6e3d5883` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/gradlew` | 0.01 MB | 2026-06-19 04:17 | `42468a0c00fe36e3` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/gradlew.bat` | 0.00 MB | 2026-06-19 04:17 | `f9fd0fb4f067b868` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/settings.gradle` | 0.00 MB | 2026-06-19 04:17 | `9406140764262890` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/main/java/com/example/demo/Book.java` | 0.00 MB | 2026-06-19 04:17 | `7174ba67d8b63c5a` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/main/java/com/example/demo/DemoApplication.java` | 0.00 MB | 2026-06-19 04:17 | `f726dfd9249a8c91` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/main/java/com/example/demo/MyController.java` | 0.00 MB | 2026-06-19 04:17 | `b9e024ee872692e3` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/main/java/com/example/demo/MyField.java` | 0.00 MB | 2026-06-19 04:17 | `46097d16d0244fe3` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/main/java/com/example/demo/MyResponse.java` | 0.00 MB | 2026-06-19 04:17 | `ff13d71c683ac6d9` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/main/resources/application.properties` | 0.00 MB | 2026-06-19 04:17 | `1aeb9a3af06c2891` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/java/demo/src/test/java/com/example/demo/DemoApplicationTests.java` | 0.00 MB | 2026-06-19 04:17 | `a421949b5094da12` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/.editorconfig` | 0.00 MB | 2026-06-19 04:17 | `6db0651adeff7349` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/.env.example` | 0.00 MB | 2026-06-19 04:17 | `ffe9e6f912dc18a0` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/.gitattributes` | 0.00 MB | 2026-06-19 04:17 | `f4e626ff3ed2fea2` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `5ab9e241c7b7c164` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/README.md` | 0.00 MB | 2026-06-19 04:17 | `d59441194020a632` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Console/Kernel.php` | 0.00 MB | 2026-06-19 04:17 | `7762951222b8c365` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Exceptions/Handler.php` | 0.00 MB | 2026-06-19 04:17 | `fe00c651cc317887` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Controllers/BookController.php` | 0.00 MB | 2026-06-19 04:17 | `cb1f270fcc1c4854` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Controllers/Controller.php` | 0.00 MB | 2026-06-19 04:17 | `1bff29ea03648d6f` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Kernel.php` | 0.00 MB | 2026-06-19 04:17 | `f9b34fdbcbfcc43b` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/Authenticate.php` | 0.00 MB | 2026-06-19 04:17 | `aa7a909ab8e4a8d5` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/EncryptCookies.php` | 0.00 MB | 2026-06-19 04:17 | `fcbbfaae9d7ac781` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/PreventRequestsDuringMaintenance.php` | 0.00 MB | 2026-06-19 04:17 | `3f1cc28f08b8a3a8` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/RedirectIfAuthenticated.php` | 0.00 MB | 2026-06-19 04:17 | `22865d62613f580e` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/TrimStrings.php` | 0.00 MB | 2026-06-19 04:17 | `fdae9e792d68b282` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/TrustHosts.php` | 0.00 MB | 2026-06-19 04:17 | `67a8483c3620b6cd` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/TrustProxies.php` | 0.00 MB | 2026-06-19 04:17 | `4c915478c380e43a` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/ValidateSignature.php` | 0.00 MB | 2026-06-19 04:17 | `ef66937ccd20e6a1` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Http/Middleware/VerifyCsrfToken.php` | 0.00 MB | 2026-06-19 04:17 | `f40416cadebf79ce` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Models/User.php` | 0.00 MB | 2026-06-19 04:17 | `5eac4ff041f949f0` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Providers/AppServiceProvider.php` | 0.00 MB | 2026-06-19 04:17 | `01bf9e5cf5bb6664` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Providers/AuthServiceProvider.php` | 0.00 MB | 2026-06-19 04:17 | `494bb0a4861384d9` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Providers/BroadcastServiceProvider.php` | 0.00 MB | 2026-06-19 04:17 | `65964eb912591e8f` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Providers/EventServiceProvider.php` | 0.00 MB | 2026-06-19 04:17 | `b4c10462ddd299c8` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/app/Providers/RouteServiceProvider.php` | 0.00 MB | 2026-06-19 04:17 | `911cae39925a7232` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/artisan` | 0.00 MB | 2026-06-19 04:17 | `4e3b044dc634aeeb` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/bootstrap/app.php` | 0.00 MB | 2026-06-19 04:17 | `f121735456595d7a` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/bootstrap/cache/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/composer.json` | 0.00 MB | 2026-06-19 04:17 | `d3f7eb29ad4d1340` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/composer.lock` | 0.28 MB | 2026-06-19 04:17 | `063c1b4047a9e691` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/app.php` | 0.01 MB | 2026-06-19 04:17 | `8fe2b61aa052eea8` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/auth.php` | 0.00 MB | 2026-06-19 04:17 | `50da0505d3001faa` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/broadcasting.php` | 0.00 MB | 2026-06-19 04:17 | `d33eca2e4834d2f3` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/cache.php` | 0.00 MB | 2026-06-19 04:17 | `c0f22a12ac4e1165` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/cors.php` | 0.00 MB | 2026-06-19 04:17 | `5a1ab3b06b572de7` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/database.php` | 0.01 MB | 2026-06-19 04:17 | `62a018cea0bd1241` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/filesystems.php` | 0.00 MB | 2026-06-19 04:17 | `24e11749cddc9f0d` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/hashing.php` | 0.00 MB | 2026-06-19 04:17 | `7bad7084a0f18c05` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/logging.php` | 0.00 MB | 2026-06-19 04:17 | `de07f4c2ddad4ea1` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/mail.php` | 0.00 MB | 2026-06-19 04:17 | `78e50a79e7b3e597` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/queue.php` | 0.00 MB | 2026-06-19 04:17 | `fc62a5b3727e1f2c` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/sanctum.php` | 0.00 MB | 2026-06-19 04:17 | `2816cf8558e87701` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/services.php` | 0.00 MB | 2026-06-19 04:17 | `4b80f7e3f84269fa` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/session.php` | 0.01 MB | 2026-06-19 04:17 | `879f17996e48e23a` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/config/view.php` | 0.00 MB | 2026-06-19 04:17 | `2f9e73c59f7a34d0` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `ab1a687b9ddc5179` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/factories/UserFactory.php` | 0.00 MB | 2026-06-19 04:17 | `7ac74334b97dded2` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/migrations/2014_10_12_000000_create_users_table.php` | 0.00 MB | 2026-06-19 04:17 | `5af12f4aa2161f2d` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/migrations/2014_10_12_100000_create_password_reset_tokens_table.php` | 0.00 MB | 2026-06-19 04:17 | `443179b24813b8e4` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/migrations/2019_08_19_000000_create_failed_jobs_table.php` | 0.00 MB | 2026-06-19 04:17 | `58208a62e6f2a9c2` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/migrations/2019_12_14_000001_create_personal_access_tokens_table.php` | 0.00 MB | 2026-06-19 04:17 | `d6cb90f8cb184672` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/database/seeders/DatabaseSeeder.php` | 0.00 MB | 2026-06-19 04:17 | `aa597929aa7bce2b` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/package.json` | 0.00 MB | 2026-06-19 04:17 | `8d6f0a0692725edd` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/phpunit.xml` | 0.00 MB | 2026-06-19 04:17 | `3ceb2a5b4591f820` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/public/.htaccess` | 0.00 MB | 2026-06-19 04:17 | `e841ab885e881ef6` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/public/favicon.ico` | 0.00 MB | 2026-06-19 04:17 | `da39a3ee5e6b4b0d` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/public/index.php` | 0.00 MB | 2026-06-19 04:17 | `bc491ec44dc6148c` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/public/robots.txt` | 0.00 MB | 2026-06-19 04:17 | `c47ccf1a49c24cc5` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/resources/css/app.css` | 0.00 MB | 2026-06-19 04:17 | `da39a3ee5e6b4b0d` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/resources/js/app.js` | 0.00 MB | 2026-06-19 04:17 | `d2e5cf4f96d815b6` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/resources/js/bootstrap.js` | 0.00 MB | 2026-06-19 04:17 | `fbbadcaaa6c454ba` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/resources/views/welcome.blade.php` | 0.03 MB | 2026-06-19 04:17 | `1fcd27b7fa52bfa1` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/routes/api.php` | 0.00 MB | 2026-06-19 04:17 | `1a9931d6ae83d5fd` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/routes/channels.php` | 0.00 MB | 2026-06-19 04:17 | `596353ce723d0b49` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/routes/console.php` | 0.00 MB | 2026-06-19 04:17 | `1332379b839ce87f` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/routes/web.php` | 0.00 MB | 2026-06-19 04:17 | `d2c782e66f78089d` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/app/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `a2dccd13a297931d` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/app/public/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/framework/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `4a90cc2072982dd2` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/framework/cache/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `0110c591f14021b8` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/framework/cache/data/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/framework/sessions/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/framework/testing/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/framework/views/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/storage/logs/.gitignore` | 0.00 MB | 2026-06-19 04:17 | `886e6d00ac28a586` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/tests/CreatesApplication.php` | 0.00 MB | 2026-06-19 04:17 | `1c178c8519b41c9b` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/tests/Feature/ExampleTest.php` | 0.00 MB | 2026-06-19 04:17 | `20fb4281ed2dc142` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/tests/TestCase.php` | 0.00 MB | 2026-06-19 04:17 | `895ec7a34b6905c1` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/tests/Unit/ExampleTest.php` | 0.00 MB | 2026-06-19 04:17 | `91a952d5ada8d3d1` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/laravel/multipart/vite.config.js` | 0.00 MB | 2026-06-19 04:17 | `6115c5173a27e17a` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/local_run_script.sh` | 0.00 MB | 2026-06-19 04:17 | `eccab9a0aa91b227` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/express_all/index.js` | 0.00 MB | 2026-06-19 04:17 | `2d982dc071648ffa` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/express_all/package.json` | 0.00 MB | 2026-06-19 04:17 | `7dc7ecfa9fbbbb39` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/express_all/yarn.lock` | 0.02 MB | 2026-06-19 04:17 | `594a86af4b4cc7eb` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/nodejs_http_json/index.js` | 0.00 MB | 2026-06-19 04:17 | `1e71abf034b503e5` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/nodejs_http_json/package-lock.json` | 0.04 MB | 2026-06-19 04:17 | `774dcd9514304834` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/nodejs_http_json/package.json` | 0.00 MB | 2026-06-19 04:17 | `609bca6aeb5df134` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/nodejs_http_multipart_busboy/index.js` | 0.00 MB | 2026-06-19 04:17 | `0eedaff4ba0e39ed` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/nodejs_http_multipart_busboy/package-lock.json` | 0.00 MB | 2026-06-19 04:17 | `29b946e000b040c7` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/nodejs/nodejs_http_multipart_busboy/package.json` | 0.00 MB | 2026-06-19 04:17 | `0103684799a133e5` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/python/fast_api_all/main.py` | 0.00 MB | 2026-06-19 04:17 | `36255c762edc29dd` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/python/flask_all/app.py` | 0.00 MB | 2026-06-19 04:17 | `266222a3a42cda36` |
| `traindata/waffled-main/waffled-main/echo-servers/webservers/run_script.sh` | 0.00 MB | 2026-06-19 04:17 | `809825d3233c605c` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/README.md` | 0.00 MB | 2026-06-19 04:17 | `94b848cb259a1558` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/json/json_complicated` | 0.01 MB | 2026-06-19 04:17 | `39879a2a3345a19b` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/json/json_simple` | 0.01 MB | 2026-06-19 04:17 | `5483afd0d803a756` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/multipart/multipart_param` | 0.01 MB | 2026-06-19 04:17 | `142f81b14a39c042` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/multipart/multipart_simple` | 0.01 MB | 2026-06-19 04:17 | `fa890a4244beb8aa` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/multipart/readme.md` | 0.00 MB | 2026-06-19 04:17 | `e09f2fcea12cdfeb` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/useful-scripts/hostnames.py` | 0.00 MB | 2026-06-19 04:17 | `de9132a0d9c063ae` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/useful-scripts/seed_generator.py` | 0.00 MB | 2026-06-19 04:17 | `f1ed9ec56bd27b4b` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/useful-scripts/server_headers_multipart.py` | 0.00 MB | 2026-06-19 04:17 | `2b88a7db54a20569` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/xml/readme.md` | 0.00 MB | 2026-06-19 04:17 | `eeddcca75c9435e4` |
| `traindata/waffled-main/waffled-main/fuzzer-grammar/xml/xml_simple` | 0.01 MB | 2026-06-19 04:17 | `421ce0b7b2f44895` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/README.md` | 0.00 MB | 2026-06-19 04:17 | `676209741ac21a64` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/RFCs.md` | 0.00 MB | 2026-06-19 04:17 | `f509281b9c45532b` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/media_type.py` | 0.01 MB | 2026-06-19 04:17 | `2d5e78a83d538314` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/mime_type.py` | 0.04 MB | 2026-06-19 04:17 | `4a07c2f4268ed15e` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/requirements.txt` | 0.00 MB | 2026-06-19 04:17 | `9fae677f3faf5ed6` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/server.py` | 0.00 MB | 2026-06-19 04:17 | `e760209fa96fb81a` |
| `traindata/waffled-main/waffled-main/http-body-normalizer/valid_form_data.py` | 0.01 MB | 2026-06-19 04:17 | `7afca9738b7a1e10` |
| `traindata/waffled-main/waffled-main/http-request-relay/README.md` | 0.00 MB | 2026-06-19 04:17 | `2c097eaedc0e3c2d` |
| `traindata/waffled-main/waffled-main/http-request-relay/http_relay.py` | 0.00 MB | 2026-06-19 04:17 | `ea9d0a498bec328f` |
| `traindata/waffled-main/waffled-main/http-request-relay/sample_requests/valid_json.raw` | 0.00 MB | 2026-06-19 04:17 | `6b7d5495a09cc307` |
| `traindata/waffled-main/waffled-main/http-request-relay/sample_requests/valid_multipart.raw` | 0.00 MB | 2026-06-19 04:17 | `7c12ce1f0ed570ed` |
| `traindata/waffled-main/waffled-main/http-request-relay/sample_requests/valid_xml.raw` | 0.00 MB | 2026-06-19 04:17 | `b4731be897b4e4d7` |
| `traindata/waffled-main/waffled-main/output-parser/README.md` | 0.00 MB | 2026-06-19 04:17 | `db0285cab504adc4` |
| `traindata/waffled-main/waffled-main/output-parser/data/sample-treqs-output` | 2.87 MB | 2026-06-19 04:17 | `e9b16fe9aff8e66a` |
| `traindata/waffled-main/waffled-main/output-parser/extract_mutation_string.sh` | 0.00 MB | 2026-06-19 04:17 | `e97e51dd93312ca2` |
| `traindata/waffled-main/waffled-main/output-parser/extract_raw_req.py` | 0.00 MB | 2026-06-19 04:17 | `40aa6fa57d13f56c` |
| `traindata/waffled-main/waffled-main/output-parser/main.py` | 0.00 MB | 2026-06-19 04:17 | `f604391d84f1f492` |
| `traindata/waffled-main/waffled-main/output-parser/parser.sh` | 0.00 MB | 2026-06-19 04:17 | `986a76ca09f1807a` |
| `traindata/waffled-main/waffled-main/publicwww/publicwww-study.txt` | 0.01 MB | 2026-06-19 04:17 | `2ab94d8bf32384e7` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/LICENSE` | 0.00 MB | 2026-06-19 04:17 | `61358ace4d7658cd` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/README.md` | 0.01 MB | 2026-06-19 04:17 | `440ed7e92f2b987d` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/helper_functions.cpython-36.pyc` | 0.00 MB | 2026-06-19 04:17 | `07a537434982ffc5` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/helper_functions.cpython-37.pyc` | 0.00 MB | 2026-06-19 04:17 | `e21e8a17e7616a89` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/input_tree.cpython-36.pyc` | 0.00 MB | 2026-06-19 04:17 | `b7b5f3af01849f61` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/input_tree.cpython-37.pyc` | 0.00 MB | 2026-06-19 04:17 | `874be67270992c2c` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/input_tree_mutator.cpython-36.pyc` | 0.01 MB | 2026-06-19 04:17 | `f4042a068bd86582` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/input_tree_mutator.cpython-37.pyc` | 0.01 MB | 2026-06-19 04:17 | `f016b5c8423f0d8e` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/input_tree_node.cpython-36.pyc` | 0.00 MB | 2026-06-19 04:17 | `94d3a14f77dda9f4` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/__pycache__/input_tree_node.cpython-37.pyc` | 0.00 MB | 2026-06-19 04:17 | `ba193d7dc36ccbe7` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/feedback-server.py` | 0.00 MB | 2026-06-19 04:17 | `6a7b44fe27d111b1` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/helper_functions.py` | 0.00 MB | 2026-06-19 04:17 | `4d34083f3ad8aa3f` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/input_tree.py` | 0.00 MB | 2026-06-19 04:17 | `4d76cc54c65d7103` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/input_tree_mutator.py` | 0.01 MB | 2026-06-19 04:17 | `ab66a9b317f20b98` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/input_tree_node.py` | 0.00 MB | 2026-06-19 04:17 | `651656760ae48fca` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/code/main.py` | 0.01 MB | 2026-06-19 04:17 | `3591b47231ccff2f` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/figs/mutation-types.png` | 0.01 MB | 2026-06-19 04:17 | `cb45dd9f8595fb04` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/logo-treqs.png` | 0.02 MB | 2026-06-19 04:17 | `43d37d6fab425bb6` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/misc/example-request-body-grammar` | 0.00 MB | 2026-06-19 04:17 | `04ea94ab9c3e2c4a` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/misc/example-request-headers-grammar` | 0.02 MB | 2026-06-19 04:17 | `8d7fe8c9346056bb` |
| `traindata/waffled-main/waffled-main/t-reqs-modified/misc/example-request-line-grammar` | 0.00 MB | 2026-06-19 04:17 | `e17c8cd6eb0daa8b` |
| `traindata/wafrift-main/wafrift-bench/CORPUS.SHA256` | 0.00 MB | 2026-11-15 10:09 | `e7171ec0b3ff45c0` |
| `traindata/wafrift-main/wafrift-bench/README.md` | 0.01 MB | 2026-11-15 10:09 | `85c1cfabd3f3e18c` |
| `traindata/wafrift-main/wafrift-bench/UPDATE-BASELINE.md` | 0.00 MB | 2026-11-15 10:09 | `ad4beef2909278a4` |
| `traindata/wafrift-main/wafrift-bench/WIRING.md` | 0.01 MB | 2026-11-15 10:09 | `90992db9d999b60c` |
| `traindata/wafrift-main/wafrift-bench/canonical-baseline.json` | 0.00 MB | 2026-11-15 10:09 | `6b1a16c293858b6b` |
| `traindata/wafrift-main/wafrift-bench/corpus/cmdi/encoding_evasion.toml` | 0.00 MB | 2026-11-15 10:09 | `febc7924e206ccb2` |
| `traindata/wafrift-main/wafrift-bench/corpus/cmdi/shell_unix.toml` | 0.00 MB | 2026-11-15 10:09 | `4fd24f3f99c924a3` |
| `traindata/wafrift-main/wafrift-bench/corpus/cmdi/shell_windows.toml` | 0.00 MB | 2026-11-15 10:09 | `7daabcc5f48f4ba7` |
| `traindata/wafrift-main/wafrift-bench/corpus/cve_pocs/2024_2025.toml` | 0.00 MB | 2026-11-15 10:09 | `c1e79688a6c691cb` |
| `traindata/wafrift-main/wafrift-bench/corpus/cve_pocs/real_world_2026.toml` | 0.01 MB | 2026-11-15 10:09 | `6359653c0e2aa30e` |
| `traindata/wafrift-main/wafrift-bench/corpus/cve_pocs/web_rce.toml` | 0.01 MB | 2026-11-15 10:09 | `571d62f45632a28c` |
| `traindata/wafrift-main/wafrift-bench/corpus/graphql/injection_2026.toml` | 0.01 MB | 2026-11-15 10:09 | `0b0dc9672c7dd91d` |
| `traindata/wafrift-main/wafrift-bench/corpus/ldap/encoding_evasion.toml` | 0.00 MB | 2026-11-15 10:09 | `60121771e651fe7a` |
| `traindata/wafrift-main/wafrift-bench/corpus/ldap/filter_injection.toml` | 0.00 MB | 2026-11-15 10:09 | `26e5164c51a54a17` |
| `traindata/wafrift-main/wafrift-bench/corpus/log4shell/jndi.toml` | 0.00 MB | 2026-11-15 10:09 | `8807b842a6a3a9b4` |
| `traindata/wafrift-main/wafrift-bench/corpus/log4shell/nested_lookups.toml` | 0.00 MB | 2026-11-15 10:09 | `0b149b69589cecfc` |
| `traindata/wafrift-main/wafrift-bench/corpus/nosql/advanced_operators.toml` | 0.00 MB | 2026-11-15 10:09 | `6362f8d43b06b068` |
| `traindata/wafrift-main/wafrift-bench/corpus/nosql/elastic_couch_redis.toml` | 0.00 MB | 2026-11-15 10:09 | `ae99fbe611973a47` |
| `traindata/wafrift-main/wafrift-bench/corpus/nosql/mongodb.toml` | 0.00 MB | 2026-11-15 10:09 | `7b542177feba735e` |
| `traindata/wafrift-main/wafrift-bench/corpus/path/encoded.toml` | 0.00 MB | 2026-11-15 10:09 | `c2a9e0123f9bea33` |
| `traindata/wafrift-main/wafrift-bench/corpus/path/linux.toml` | 0.00 MB | 2026-11-15 10:09 | `ab69cbd896044a8b` |
| `traindata/wafrift-main/wafrift-bench/corpus/path/routing_disagreement.toml` | 0.00 MB | 2026-11-15 10:09 | `e3c53ee5bb57f288` |
| `traindata/wafrift-main/wafrift-bench/corpus/path/windows.toml` | 0.00 MB | 2026-11-15 10:09 | `8c1e22b2017ac599` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/adjacent_string_concat_2026.toml` | 0.00 MB | 2026-11-15 10:09 | `025a3022753950bb` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/blind.toml` | 0.00 MB | 2026-11-15 10:09 | `98dc8ed0eb695e5c` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/char_chr_decompose_2026.toml` | 0.00 MB | 2026-11-15 10:09 | `2913ac4d9cf04811` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/comments_evasion.toml` | 0.00 MB | 2026-11-15 10:09 | `f6adfd9109ca3d6b` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/concat_split_2026.toml` | 0.00 MB | 2026-11-15 10:09 | `c1c619c232a0dd11` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/dialect_quirks.toml` | 0.00 MB | 2026-11-15 10:09 | `798369a189e5b235` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/error_based.toml` | 0.00 MB | 2026-11-15 10:09 | `88a72579d0ac6ee1` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/frontier_tamper_2026.toml` | 0.01 MB | 2026-11-15 10:09 | `8cb8be69707f692f` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/json_unicode_alnum_2026.toml` | 0.01 MB | 2026-11-15 10:09 | `59381181eeab9e20` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/math_bold_nfkc_2026.toml` | 0.00 MB | 2026-11-15 10:09 | `8bf61e47f3f3cd65` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/stacked.toml` | 0.00 MB | 2026-11-15 10:09 | `75e501faddeeb225` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/tautology.toml` | 0.00 MB | 2026-11-15 10:09 | `ce2537e27b2b2713` |
| `traindata/wafrift-main/wafrift-bench/corpus/sql/union.toml` | 0.00 MB | 2026-11-15 10:09 | `14112cc61988a792` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssi/apache_mod_include.toml` | 0.00 MB | 2026-11-15 10:09 | `9d401763b99a3803` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssrf/cloud_metadata.toml` | 0.00 MB | 2026-11-15 10:09 | `fc3a9a8422dff73e` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssrf/encoded_localhost.toml` | 0.00 MB | 2026-11-15 10:09 | `cec31478f080549a` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssrf/parser_confusion_authority.toml` | 0.00 MB | 2026-11-15 10:09 | `3d4893611119bd94` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssrf/protocol_smuggling.toml` | 0.00 MB | 2026-11-15 10:09 | `025f776ee0ea01e5` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssti/jinja2.toml` | 0.00 MB | 2026-11-15 10:09 | `4b8243e35bf896de` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssti/ruby_dotnet_php.toml` | 0.00 MB | 2026-11-15 10:09 | `8ca542722d7b26c1` |
| `traindata/wafrift-main/wafrift-bench/corpus/ssti/twig_freemarker_velocity.toml` | 0.00 MB | 2026-11-15 10:09 | `8bfd9cb1aa7f9833` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/event_handler.toml` | 0.00 MB | 2026-11-15 10:09 | `6e560ace464394f5` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/frontier_tamper_2026.toml` | 0.00 MB | 2026-11-15 10:09 | `25120192fc4fac95` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/html_attribute.toml` | 0.00 MB | 2026-11-15 10:09 | `9d86317a94a1dfc8` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/html_entity_variants_2026.toml` | 0.00 MB | 2026-11-15 10:09 | `a8a5afed168b5cd8` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/javascript_uri.toml` | 0.00 MB | 2026-11-15 10:09 | `77ae0d268ed3b8de` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/json_unicode_alnum_2026.toml` | 0.01 MB | 2026-11-15 10:09 | `0a8f5ced99ab6033` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/modern_event_handlers.toml` | 0.00 MB | 2026-11-15 10:09 | `73495e948bb38969` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/polyglot.toml` | 0.00 MB | 2026-11-15 10:09 | `188f41cb147ef3ca` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/script_tag.toml` | 0.00 MB | 2026-11-15 10:09 | `9050a5c46908a568` |
| `traindata/wafrift-main/wafrift-bench/corpus/xss/svg.toml` | 0.00 MB | 2026-11-15 10:09 | `227ab1aa1db28b4d` |
| `traindata/wafrift-main/wafrift-bench/corpus/xxe/encoding_evasion.toml` | 0.00 MB | 2026-11-15 10:09 | `eb1bce1c35b400b6` |
| `traindata/wafrift-main/wafrift-bench/corpus/xxe/xml.toml` | 0.00 MB | 2026-11-15 10:09 | `334309db22fa76d8` |
| `traindata/wafrift-main/wafrift-bench/methodology.md` | 0.01 MB | 2026-11-15 10:09 | `3c80c1ad1406ddcc` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-19/modsec-pl4-after-compression.json` | 0.00 MB | 2026-11-15 10:09 | `0d422e9fb036d247` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-20/scan-pl4-after-multi-vector-extraction.json` | 0.07 MB | 2026-11-15 10:09 | `e8f918cc9991328f` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-20/scan-pl4-after-security-audit.json` | 0.07 MB | 2026-11-15 10:09 | `132db971203d6d72` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-20/scan-pl4-post-stress-audit.json` | 0.07 MB | 2026-11-15 10:09 | `4ebab07053f420f9` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-20/scan-pl4-rescue20.json` | 0.08 MB | 2026-11-15 10:09 | `0b6b826c8bbdcc60` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-20/scan-pl4-with-rescue.json` | 0.08 MB | 2026-11-15 10:09 | `cc1b26a595c0c23c` |
| `traindata/wafrift-main/wafrift-bench/results/2026-05-20/scan-pl4-with-xml-vector.json` | 0.07 MB | 2026-11-15 10:09 | `79e10aa20bcb8eb8` |
| `traindata/wafrift-main/wafrift-bench/results/coraza-bench-021.json` | 0.00 MB | 2026-11-15 10:09 | `bd51ec5a93ad6b1d` |
| `traindata/wafrift-main/wafrift-bench/results/final-coraza.json` | 0.00 MB | 2026-11-15 10:09 | `d24529f8cbccb3d7` |
| `traindata/wafrift-main/wafrift-bench/results/final-modsec-pl1.json` | 0.00 MB | 2026-11-15 10:09 | `e058ff9f3ac56678` |
| `traindata/wafrift-main/wafrift-bench/results/final-modsec-pl4.json` | 0.00 MB | 2026-11-15 10:09 | `1648d109db3a107c` |
| `traindata/wafrift-main/wafrift-bench/results/honest-bunkerweb-equiv-cegis-0.2.16.json` | 0.53 MB | 2026-11-15 10:09 | `c03a36d81ddf4053` |
| `traindata/wafrift-main/wafrift-bench/results/honest-coraza-equiv-cegis-0.2.16.json` | 0.53 MB | 2026-11-15 10:09 | `a38ecb8fd7c22f3d` |
| `traindata/wafrift-main/wafrift-bench/results/honest-naxsi-equiv-cegis-0.2.16.json` | 0.49 MB | 2026-11-15 10:09 | `3bbf847b6412c09e` |
| `traindata/wafrift-main/wafrift-bench/results/honest-pl1-equiv-cegis-0.2.16.json` | 0.56 MB | 2026-11-15 10:09 | `49c083fd77aff0f9` |
| `traindata/wafrift-main/wafrift-bench/results/honest-pl3-equiv-cegis-0.2.16.json` | 0.53 MB | 2026-11-15 10:09 | `1dcb20ec4705c55e` |
| `traindata/wafrift-main/wafrift-bench/results/ldap-pl1-equiv-cegis.json` | 0.01 MB | 2026-11-15 10:09 | `7d8be10002af4ca9` |
| `traindata/wafrift-main/wafrift-bench/results/ldap-pl3-equiv-cegis.json` | 0.01 MB | 2026-11-15 10:09 | `454137f4d64099ba` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl1-allstrats.json` | 2.70 MB | 2026-11-15 10:09 | `eafddcb49c882cda` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl1-first.json` | 0.03 MB | 2026-11-15 10:09 | `0750e1d0f34fc987` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl1-multi-with-ast.json` | 2.85 MB | 2026-11-15 10:09 | `fdeedc27b2627df8` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl1-multi.json` | 2.76 MB | 2026-11-15 10:09 | `558a858b3c2ba307` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl1-v2.json` | 0.07 MB | 2026-11-15 10:09 | `a1964b51af106d19` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl2-multi.json` | 2.57 MB | 2026-11-15 10:09 | `c55f2557a64a198a` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl2.json` | 0.05 MB | 2026-11-15 10:09 | `36f5ed8c5a4f56e3` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl3-multi.json` | 2.56 MB | 2026-11-15 10:09 | `3df17f70732bf21d` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl3.json` | 0.04 MB | 2026-11-15 10:09 | `cd967f3e1efe0175` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl4-multi.json` | 2.51 MB | 2026-11-15 10:09 | `f1bd249e484c95b1` |
| `traindata/wafrift-main/wafrift-bench/results/modsec-pl4.json` | 0.04 MB | 2026-11-15 10:09 | `c14011964f7428f3` |
| `traindata/wafrift-main/wafrift-bench/results/naxsi-bench-021.json` | 0.00 MB | 2026-11-15 10:09 | `c6f6b231c98ef702` |
| `traindata/wafrift-main/wafrift-bench/results/v022-bunkerweb.json` | 0.15 MB | 2026-11-15 10:09 | `2e0e13c419ad968d` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_cmdi.json` | 0.08 MB | 2026-11-15 10:09 | `68f30b7f2cecba51` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_ldap.json` | 0.01 MB | 2026-11-15 10:09 | `27f2d703d41ad09c` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_log4shell.json` | 0.03 MB | 2026-11-15 10:09 | `7afbe83a6460efa4` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_nosql.json` | 0.03 MB | 2026-11-15 10:09 | `accc0cd5a77a0217` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_path.json` | 0.07 MB | 2026-11-15 10:09 | `2455f43e0c12af42` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_sql.json` | 0.22 MB | 2026-11-15 10:09 | `39c94cfdb8b8fb6d` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `e6ec755e1f3f8941` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_ssti.json` | 0.06 MB | 2026-11-15 10:09 | `787d527cf08d9b06` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_xss.json` | 0.16 MB | 2026-11-15 10:09 | `c2ff09138601d50b` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/modsec-pl4_xxe.json` | 0.01 MB | 2026-11-15 10:09 | `998d736a652c5b63` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_cmdi.json` | 0.04 MB | 2026-11-15 10:09 | `3c7ed75a16877f50` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_ldap.json` | 0.01 MB | 2026-11-15 10:09 | `0c9a7e31199e7c42` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_log4shell.json` | 0.03 MB | 2026-11-15 10:09 | `08f55ef14d1c452d` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_nosql.json` | 0.02 MB | 2026-11-15 10:09 | `ee5356bdce91a155` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_path.json` | 0.04 MB | 2026-11-15 10:09 | `9b1ab043b2dde143` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_sql.json` | 0.14 MB | 2026-11-15 10:09 | `5dcce94681a69d42` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_ssrf.json` | 0.03 MB | 2026-11-15 10:09 | `21efeb57d9a4d794` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_ssti.json` | 0.04 MB | 2026-11-15 10:09 | `9ecd15d4e6028b64` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_xss.json` | 0.09 MB | 2026-11-15 10:09 | `8f7d088653397330` |
| `traindata/wafrift-main/wafrift-bench/results/v022-by-class/naxsi_xxe.json` | 0.01 MB | 2026-11-15 10:09 | `b1bd6a2cd4bf8d06` |
| `traindata/wafrift-main/wafrift-bench/results/v022-coraza.json` | 0.11 MB | 2026-11-15 10:09 | `5af7e197f0cdea0b` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/bunkerweb_cmdi.json` | 0.08 MB | 2026-11-15 10:09 | `13d59ecdcf58a8a5` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/bunkerweb_ldap.json` | 0.02 MB | 2026-11-15 10:09 | `010443f6983b5902` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/bunkerweb_path.json` | 0.07 MB | 2026-11-15 10:09 | `032dd9294d54f8a5` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/bunkerweb_sql.json` | 0.21 MB | 2026-11-15 10:09 | `c655273da519286e` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/bunkerweb_ssrf.json` | 0.07 MB | 2026-11-15 10:09 | `d62f08609df609c0` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/bunkerweb_xss.json` | 0.16 MB | 2026-11-15 10:09 | `1a71ea8044b948a1` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/coraza_cmdi.json` | 0.07 MB | 2026-11-15 10:09 | `8079357f1cef0b62` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/coraza_ldap.json` | 0.02 MB | 2026-11-15 10:09 | `f45dc3020168dd5b` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/coraza_path.json` | 0.05 MB | 2026-11-15 10:09 | `e6d87660f13a00fd` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/coraza_sql.json` | 0.14 MB | 2026-11-15 10:09 | `f689652e7cd8339c` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/coraza_ssrf.json` | 0.07 MB | 2026-11-15 10:09 | `a127ee2991d37f8f` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/coraza_xss.json` | 0.11 MB | 2026-11-15 10:09 | `d0c5138976595c8f` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl1_cmdi.json` | 0.08 MB | 2026-11-15 10:09 | `8472320c98695687` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl1_ldap.json` | 0.02 MB | 2026-11-15 10:09 | `4823066d338ec6cc` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl1_path.json` | 0.07 MB | 2026-11-15 10:09 | `b4188312c7c6f459` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl1_sql.json` | 0.22 MB | 2026-11-15 10:09 | `d28ff41238a6c846` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl1_ssrf.json` | 0.07 MB | 2026-11-15 10:09 | `5160d41b0335f546` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl1_xss.json` | 0.16 MB | 2026-11-15 10:09 | `af9cebe0e6dbd7d3` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl2_cmdi.json` | 0.08 MB | 2026-11-15 10:09 | `8ad628bee8d8096b` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl2_ldap.json` | 0.02 MB | 2026-11-15 10:09 | `fa1641f58f2dc275` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl2_path.json` | 0.07 MB | 2026-11-15 10:09 | `b32d98ea75d67316` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl2_sql.json` | 0.22 MB | 2026-11-15 10:09 | `a236b5e7c185b8f2` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl2_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `bca278454dc31339` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl2_xss.json` | 0.16 MB | 2026-11-15 10:09 | `ae41e6f35b519a88` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl3_cmdi.json` | 0.08 MB | 2026-11-15 10:09 | `4f7d0f22b4fcab26` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl3_ldap.json` | 0.02 MB | 2026-11-15 10:09 | `6c416059d316aafb` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl3_path.json` | 0.07 MB | 2026-11-15 10:09 | `41e532098f8796fa` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl3_sql.json` | 0.22 MB | 2026-11-15 10:09 | `7ee61c4f4450d838` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl3_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `1533f3bb7619a7d9` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl3_xss.json` | 0.16 MB | 2026-11-15 10:09 | `9775964d2a5e8de7` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl4_cmdi.json` | 0.07 MB | 2026-11-15 10:09 | `4d850c3fd089134f` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl4_ldap.json` | 0.01 MB | 2026-11-15 10:09 | `e09aa335b52f0c33` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl4_path.json` | 0.07 MB | 2026-11-15 10:09 | `ecc57e5762c74e71` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl4_sql.json` | 0.22 MB | 2026-11-15 10:09 | `81370b02dd7c59b6` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl4_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `bd2b70aa3188065e` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/modsec-pl4_xss.json` | 0.16 MB | 2026-11-15 10:09 | `399749df8ec39437` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/naxsi_cmdi.json` | 0.05 MB | 2026-11-15 10:09 | `fd8320c44766c210` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/naxsi_ldap.json` | 0.01 MB | 2026-11-15 10:09 | `d7c72145f539d6b6` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/naxsi_path.json` | 0.05 MB | 2026-11-15 10:09 | `b60048eeba24b0ed` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/naxsi_sql.json` | 0.14 MB | 2026-11-15 10:09 | `c538152b62b959b1` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/naxsi_ssrf.json` | 0.04 MB | 2026-11-15 10:09 | `d666d036edb64241` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final-ALL/naxsi_xss.json` | 0.11 MB | 2026-11-15 10:09 | `bff5ba499c523c79` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/bunkerweb_path.json` | 0.07 MB | 2026-11-15 10:09 | `8f52645d79a19e30` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/bunkerweb_sql.json` | 0.21 MB | 2026-11-15 10:09 | `e3b71d00d650f797` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/bunkerweb_ssrf.json` | 0.07 MB | 2026-11-15 10:09 | `0d459ffb8fad2f60` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/coraza_path.json` | 0.05 MB | 2026-11-15 10:09 | `351c1877d2d6f318` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/coraza_sql.json` | 0.14 MB | 2026-11-15 10:09 | `d232f3b20c6502a2` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/coraza_ssrf.json` | 0.07 MB | 2026-11-15 10:09 | `ee77650f175b8096` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl1_path.json` | 0.07 MB | 2026-11-15 10:09 | `6df46e390c92e248` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl1_sql.json` | 0.22 MB | 2026-11-15 10:09 | `32352b38b1317f76` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl1_ssrf.json` | 0.07 MB | 2026-11-15 10:09 | `2f8740914a3ab183` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl2_path.json` | 0.07 MB | 2026-11-15 10:09 | `a6052cc3a73ddc78` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl2_sql.json` | 0.21 MB | 2026-11-15 10:09 | `aa1dd52f1c5baa51` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl2_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `5b5a6e4fd9813742` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl3_path.json` | 0.07 MB | 2026-11-15 10:09 | `c865dfb74ee9d3b1` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl3_sql.json` | 0.21 MB | 2026-11-15 10:09 | `72e82319e403b91e` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl3_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `43f2a0860821ff65` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl4_path.json` | 0.07 MB | 2026-11-15 10:09 | `3afff6a6646680af` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl4_sql.json` | 0.21 MB | 2026-11-15 10:09 | `84441a4b08a300ac` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/modsec-pl4_ssrf.json` | 0.06 MB | 2026-11-15 10:09 | `1057cfa40be6a5a7` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/naxsi_path.json` | 0.05 MB | 2026-11-15 10:09 | `19c7b4aeaab83fb0` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/naxsi_sql.json` | 0.14 MB | 2026-11-15 10:09 | `ab6c1dd90a4013ec` |
| `traindata/wafrift-main/wafrift-bench/results/v022-final/naxsi_ssrf.json` | 0.04 MB | 2026-11-15 10:09 | `056581ffc520229f` |
| `traindata/wafrift-main/wafrift-bench/results/v022-modsec-pl1.json` | 0.15 MB | 2026-11-15 10:09 | `3cde823b4c495a77` |
| `traindata/wafrift-main/wafrift-bench/results/v022-modsec-pl2.json` | 0.15 MB | 2026-11-15 10:09 | `5d4e7f18e690c624` |
| `traindata/wafrift-main/wafrift-bench/results/v022-modsec-pl3.json` | 0.15 MB | 2026-11-15 10:09 | `5ad86ba09a79a208` |
| `traindata/wafrift-main/wafrift-bench/results/v022-modsec-pl4.json` | 0.15 MB | 2026-11-15 10:09 | `f30390361614cfe5` |
| `traindata/wafrift-main/wafrift-bench/results/v022-naxsi.json` | 0.09 MB | 2026-11-15 10:09 | `36f8d2e29cf1049d` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-bunkerweb.json` | 0.21 MB | 2026-11-15 10:09 | `d0fbd3ef4886a8fd` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-coraza.json` | 0.14 MB | 2026-11-15 10:09 | `4544c7ffbacd6f14` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-modsec-pl1.json` | 0.22 MB | 2026-11-15 10:09 | `e4dae62451a91d85` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-modsec-pl2.json` | 0.21 MB | 2026-11-15 10:09 | `500b5eddcc259663` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-modsec-pl3.json` | 0.22 MB | 2026-11-15 10:09 | `aa3cf362698bd5c0` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-modsec-pl4.json` | 0.21 MB | 2026-11-15 10:09 | `7613000fe083421d` |
| `traindata/wafrift-main/wafrift-bench/results/v022-quotefree-naxsi.json` | 0.14 MB | 2026-11-15 10:09 | `18305e2d36eafa48` |
| `traindata/wafrift-main/wafrift-bench/scripts/dogfood-public.sh` | 0.00 MB | 2026-11-15 10:09 | `505ff0f7afec5b9e` |
| `traindata/wafrift-main/wafrift-bench/scripts/down.sh` | 0.00 MB | 2026-11-15 10:09 | `5c309cba8b2f5bbb` |
| `traindata/wafrift-main/wafrift-bench/scripts/mock_waf.py` | 0.00 MB | 2026-11-15 10:09 | `867c90e0b4009580` |
| `traindata/wafrift-main/wafrift-bench/scripts/render-scoreboard.py` | 0.01 MB | 2026-11-15 10:09 | `b155b7c2b23287e9` |
| `traindata/wafrift-main/wafrift-bench/scripts/test_render_scoreboard.py` | 0.01 MB | 2026-11-15 10:09 | `51c12b7f739ccf66` |
| `traindata/wafrift-main/wafrift-bench/scripts/up.sh` | 0.00 MB | 2026-11-15 10:09 | `cf972129af2eac0d` |
| `traindata/wafrift-main/wafrift-bench/targets/README.md` | 0.00 MB | 2026-11-15 10:09 | `87fc75a0df187c25` |
| `traindata/wafrift-main/wafrift-bench/targets/bunkerweb/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `c57bc9d94c1afaa1` |
| `traindata/wafrift-main/wafrift-bench/targets/coraza/Caddyfile` | 0.00 MB | 2026-11-15 10:09 | `dec488deda0dd465` |
| `traindata/wafrift-main/wafrift-bench/targets/coraza/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `fb1ab1701c7ae945` |
| `traindata/wafrift-main/wafrift-bench/targets/modsec-pl1/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `8c790945d6ddd3ac` |
| `traindata/wafrift-main/wafrift-bench/targets/modsec-pl2/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `ca00f741dbc0fef7` |
| `traindata/wafrift-main/wafrift-bench/targets/modsec-pl3/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `804568e2520a31a3` |
| `traindata/wafrift-main/wafrift-bench/targets/modsec-pl4/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `ab36e4b39b7f3702` |
| `traindata/wafrift-main/wafrift-bench/targets/naxsi/Dockerfile` | 0.00 MB | 2026-11-15 10:09 | `72499a2ccd7c5d0a` |
| `traindata/wafrift-main/wafrift-bench/targets/naxsi/docker-compose.yml` | 0.00 MB | 2026-11-15 10:09 | `9d933d0a048e3feb` |
| `traindata/wafrift-main/wafrift-bench/targets/naxsi/naxsi.conf` | 0.00 MB | 2026-11-15 10:09 | `7c90ed915510e719` |
| `traindata/wafrift-main/wafrift-bench/targets/naxsi/nginx.conf` | 0.00 MB | 2026-11-15 10:09 | `558898cb310fbd7e` |
