# traindata 语料目录（自动生成）

> `python/traindata_catalog.py`（2026-11-12 20:58:58）—— **勿手改**。

- 根目录：`traindata`
- 文件：77 个 / 505.0 MB
- 数字来源：realdata_waf._inventory（与训练同一批 loader）

## 语料角色

| 语料 | 角色 | 可用性 | 关键数字 |
|---|---|---|---|
| `xlsx` | 主训练集（4 类攻击 + 良性） | 可用（按事务聚合 + 去重后） | rows=108,883; transactions=27,686; unique_requests=18,470; with_body=2,112 |
| `modsec` | 真实在野攻击（召回评估 + 训练） | 攻击-only，零良性 | requests=150,930; days=30; with_body=14,002 |
| `parquet_train` | 良性池（anomalous 无子类） | 正常可训练；异常只做二分类评估 | rows=1,924,461; label_normal=1,539,108; label_anomalous=385,353; with_body=89 |
| `parquet_test` | 独立评估集（normal 量误报 / anomalous 量检出） |  | rows=240,558; label_normal=192,295; label_anomalous=48,263; with_body=8,594 |
| `payloads` | 载荷集合（TP 进训练；false-positives 作困难良性负例） |  |  |
| `waf_detection` | 外部 WAF 检测结果（无子类，只做二分类评估） |  | rows=644; bad_lines=6 |

## 排除的文件及原因

- `CVE_list.json` — JSON 截断（9.5MB 处 unterminated string），且非 HTTP 请求，无法转 80 维特征
- `AgentCyberRangeWebExploitBench/` — 只有 readme.md，内容为“等待通过”，无数据
- `http-attack-requests.json` — 395 字节的清单说明（real/topup 计数），不是数据

## 问题清单

- **warn** `xlsx_host_bias`：xlsx 仅 3 个 host / 7 个 IP，良性代表性有限
- **info** `parquet_no_subclass`：parquet anomalous 385,353 条无子类，只能做二分类评估，不能进 5 类训练
- **info** `parquet_duplicates`：parquet test 有 50,798 行重复请求，去重后 189,760 条唯一
- **info** `wfdet_bad_lines`：WAF_DETECTION_DATASET.jsonl 有 6 行 JSON 损坏，已跳过

## 建议

- 5 类训练只收 label ∈ 0-4；无子类攻击（parquet anomalous / bruteforce / 920 协议规则）只进二分类评估。
- 校准池必须与训练集**互斥**：用 parquet normal 的独立留出桶，并让 `thresholds.py --train-keys` 校验训练指纹。
- xlsx 的良性只有千余条且只来自 3 个 host —— 误报率的代表性以 parquet 正常流量为准。
- ModSecurity 日志全是命中规则的事务，零良性：它只能量召回，不能量误报。

## 文件清单

| 文件 | 大小 | mtime | sha1 |
|---|---|---|---|
| `traindata/AgentCyberRangeWebExploitBench/readme.md` | 0.00 MB | 2026-11-12 19:22 | `` |
| `traindata/CATALOG.md` | 0.01 MB | 2026-11-12 20:24 | `` |
| `traindata/CVE_list.json` | 9.07 MB | 2026-11-12 19:21 | `` |
| `traindata/WAF Data v2/test.parquet` | 10.66 MB | 2026-11-12 19:13 | `` |
| `traindata/WAF Data v2/train.parquet` | 76.47 MB | 2026-11-12 19:16 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/LICENSE` | 0.03 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/README.md` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/config.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/cmdexe/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/cmdexe/true-positives.txt` | 0.07 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/log4shell/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/log4shell/true-positives.txt` | 0.01 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/shellshock/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/shellshock/true-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/sqli/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/sqli/true-positives.txt` | 0.03 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/traversal/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/traversal/true-positives.txt` | 0.99 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xss/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xss/true-positives.txt` | 1.33 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xxe/false-positives.txt` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/payloads/xxe/true-positives.txt` | 0.01 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/cmdexe/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/cmdexe/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/log4shell/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/log4shell/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/shellshock/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/shellshock/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/sqli/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/sqli/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/traversal/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/traversal/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xss/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xss/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xxe/false-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF-Payload-Collection-main/WAF-Payload-Collection-main/nuclei/templates/xxe/true-positive.yaml` | 0.00 MB | 2022-10-11 15:58 | `` |
| `traindata/WAF_DETECTION_DATASET.jsonl` | 0.20 MB | 2026-11-12 19:10 | `` |
| `traindata/combined_final_dataset_augmented.xlsx` | 26.53 MB | 2026-11-12 19:07 | `` |
| `traindata/http-attack-requests.json` | 0.00 MB | 2026-11-12 19:09 | `` |
| `traindata/owasp/01-Aug-2025/modsec_audit.anon.log` | 14.97 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/02-Aug-2025/modsec_audit.anon.log` | 13.36 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/03-Aug-2025/modsec_audit.anon.log` | 13.05 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/04-Aug-2025/modsec_audit.anon.log` | 18.17 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/05-Aug-2025/modsec_audit.anon.log` | 11.71 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/06-Aug-2025/modsec_audit.anon.log` | 9.21 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/07-Aug-2025/modsec_audit.anon.log` | 4.97 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/08-Aug-2025/modsec_audit.anon.log` | 6.64 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/09-Aug-2025/modsec_audit.anon.log` | 8.90 MB | 2025-09-22 00:26 | `` |
| `traindata/owasp/10-Aug-2025/modsec_audit.anon.log` | 18.04 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/11-Aug-2025/modsec_audit.anon.log` | 8.51 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/12-Aug-2025/modsec_audit.anon.log` | 6.39 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/13-Aug-2025/modsec_audit.anon.log` | 14.10 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/14-Aug-2025/modsec_audit.anon.log` | 24.11 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/15-Aug-2025/modsec_audit.anon.log` | 28.44 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/16-Aug-2025/modsec_audit.anon.log` | 27.29 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/17-Aug-2025/modsec_audit.anon.log` | 16.07 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/18-Aug-2025/modsec_audit.anon.log` | 9.12 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/19-Aug-2025/modsec_audit.anon.log` | 10.49 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/20-Aug-2025/modsec_audit.anon.log` | 7.40 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/21-Aug-2025/modsec_audit.anon.log` | 7.49 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/22-Aug-2025/modsec_audit.anon.log` | 7.30 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/23-Aug-2025/modsec_audit.anon.log` | 9.76 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/24-Aug-2025/modsec_audit.anon.log` | 8.74 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/25-Aug-2025/modsec_audit.anon.log` | 9.12 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/27-Jul-2025/modsec_audit.anon.log` | 7.51 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/28-Jul-2025/modsec_audit.anon.log` | 32.58 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/29-Jul-2025/modsec_audit.anon.log` | 7.51 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/30-Jul-2025/modsec_audit.anon.log` | 7.88 MB | 2025-09-22 00:27 | `` |
| `traindata/owasp/31-Jul-2025/modsec_audit.anon.log` | 10.69 MB | 2025-09-22 00:27 | `` |
| `traindata/proxy/collector-metrics.json` | 0.00 MB | 2026-11-12 20:58 | `` |
| `traindata/proxy/raw-20261112-00000.jsonl` | 0.00 MB | 2026-11-12 20:46 | `` |
| `traindata/proxy/raw-20261112-00001.jsonl` | 0.00 MB | 2026-11-12 20:46 | `` |
| `traindata/proxy/raw-20261112-00002.jsonl` | 0.00 MB | 2026-11-12 20:47 | `` |
| `traindata/proxy/raw-20261112-00003.jsonl` | 0.00 MB | 2026-11-12 20:49 | `` |
| `traindata/proxy/raw-20261112-00004.jsonl` | 0.00 MB | 2026-11-12 20:52 | `` |
| `traindata/proxy/raw-20261112-00005.jsonl` | 0.00 MB | 2026-11-12 20:53 | `` |
| `traindata/proxy/raw-20261112-00006.jsonl` | 0.00 MB | 2026-11-12 20:54 | `` |
