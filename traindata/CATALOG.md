# `traindata/` 数据目录

> 自动生成：`python/traindata_catalog.py`（2026-10-30 11:02:36）—— **勿手改**。
> 本目录只登记与盘点，不移动/不改名/不删除任何文件。

总计 **59 个文件 / 943.6 MB**；语料 10 组。

## 1. 语料一览

| 语料 | 角色 | 规模 | 消费方 | 可用性 |
|---|---|---|---|---|
| `csic2010` | 良性训练/留出池 + 攻击池（异常无子类标签） | 36,000 正常 + 25,065 异常 | `realdata.load_csic` / `csic_normal_index` → 训练、零日、三关、预算 | 可用（唯一有规模的真实 HTTP 报文） |
| `payload_csv` | 监督通道的训练/测试集（载荷零重叠） | 31,067 行（train 20,712 / test 10,355）+ lexical 1,106 | `train_realdata` / `eval_http_params` / `export_testvec` / `calibrate_rules`（lex_norm、lex_atk） | 可用；full 是派生文件，lexical 才是长文本源 |
| `payload_dict` | 规则挖掘 / 困难负例来源（**不进训练**） | 480 条（坏对象 20） | `p7_rule_mining`（挖词）、`train_realdata --use-dict`（可选增强，官方配方不用） | 仅作攻击侧素材；文件本身是坏 JSON，且零良性 |
| `datacon2025_sample` | **只做 OOD 链路自检**（禁止训练、禁止当良性池） | 100 条（标注攻击 42） | `realdata.load_datacon` → `p2/p3/p6/p7/calibrate`、`export_datacon` | 只能问「检出与否」，不得报率（n=100 置信区间无意义） |
| `cic_ids2017` | 流级通道（独立通道，**不并入 HTTP 特征**） | 2,830,743 行 / 557,646 攻击 | `p5_flow_spike`（仅 spike，抽样 stride=20） | 数据可用，但**流级通道没有生产消费者** |
| `local_benign` | 真实良性池（三关 ② 关 + 融合 FPR） | 190 条 | `calibrate_rules`（unified_benign）、`p4_local` | 可用，但只有 190 条唯一请求（751 行 → 去重 541） |
| `local_inwild` | **不是良性池**：只能看命中率；inwild_attack 是攻击池一员 | 105,730 良性侧 + 12 攻击 | `p4_local`（inwild_benign 命中率）、`calibrate_rules`（inwild_atk） | inwild_benign 不可算 FPR（含 2,074 条扫描器命中）；inwild_attack 仅 12 条 |
| `local_datacon` | OOD 链路自检 | 42 攻击 + 58 未标注 | 人工复核 / 链路自检（判定链路用 `realdata.load_datacon` 现读） | 同 datacon：不报率 |
| `collector_output` | **运行样本，不是语料**（有 pred、无 label） | 3538 条 | 人工排查 / p8 e2e 观察 | 不能进池（无标签；只是运行样本） |
| `enhanced_security` | **不可训练**：不是 HTTP 请求，只可当知识库素材 | 767 条 `instruction`/`output` 问答 | **无**（上传解析实测 767 条全部 `missing_path`、`rows_kept=0`） | 禁止入训练、禁止当良性池；没有 method/path/query/body，无法转成 80 维特征 |

## 2. 明细

### csic2010 — CSIC 2010 HTTP 数据集（正常 + 异常请求报文）

- 路径：`traindata/Machine-Learning-on-CSIC-2010-master/...`
- 角色：良性训练/留出池 + 攻击池（异常无子类标签）
- 出处/许可：公开学术数据集（CSIC 2010）；仓库为第三方整理版，未附许可证文件
- 消费方：`realdata.load_csic` / `csic_normal_index` → 训练、零日、三关、预算
- 正常：GET 28,000、POST 8,000；8,000 条带 query、8,000 条带 body（8,000 条 POST 都带表单）
- 异常：GET 15,088、POST 9,580、PUT 397；9,609 条带 query、9,977 条带 body
- PUT 只在异常里出现（正常 0 条，异常 397 条）—— 这是可泄漏特征，评估时必须报

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/Machine-Learning-on-CSIC-2010-master/Machine-Learning-on-CSIC-2010-master/normalTrafficTraining.txt` | 19.7 MB | 36,000 请求 | 正常流量 · sha1 2c4cf6155593 |
| `traindata/Machine-Learning-on-CSIC-2010-master/Machine-Learning-on-CSIC-2010-master/anomalousTrafficTest.txt` | 15.3 MB | 25,065 请求 | 异常流量（无子类标签）· sha1 49c3585eb790 |

### payload_csv — HTTP Params 词法载荷表（train/test/lexical/full）

- 路径：`traindata/payload_*.csv`
- 角色：监督通道的训练/测试集（载荷零重叠）
- 出处/许可：第三方整理的 HTTP 参数载荷集（`payload,length,attack_type,label`）
- 消费方：`train_realdata` / `eval_http_params` / `export_testvec` / `calibrate_rules`（lex_norm、lex_atk）
- train ∩ test = 0 条（协议要求零重叠）
- lexical 与 train/test 交集 0 条
- payload 统一塞进 `?q=`，位置一致；`norm` 行是数据集自带的良性参数，**不是本机真实用户流量** —— 真实良性只看 CSIC 与 local/

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/payload_train.csv` | 1.3 MB | 20,712 | norm=12870、sqli=7235、xss=355、cmdi=59、path-traversal=193 |
| `traindata/payload_test.csv` | 650.7 KB | 10,355 | norm=6434、sqli=3617、xss=177、cmdi=30、path-traversal=97 |
| `traindata/payload_test_lexical.csv` | 349.8 KB | 1,106 | sql-syntax=87、js-syntax=19、norm=1000 |
| `traindata/payload_full.csv` | 1.9 MB | 31,067 | norm=19304、sqli=10852、xss=532、cmdi=89、path-traversal=290 |

### payload_dict — WEB_APPLICATION_PAYLOADS.jsonl（攻击载荷字典）

- 路径：`traindata/WEB_APPLICATION_PAYLOADS.jsonl`
- 角色：规则挖掘 / 困难负例来源（**不进训练**）
- 出处/许可：第三方攻击载荷字典；项目内**未核实许可与出处**（见 THIRD_PARTY_NOTICES）
- 消费方：`p7_rule_mining`（挖词）、`train_realdata --use-dict`（可选增强，官方配方不用）
- 家族：xss=97、sqli=96、csrf=96、ssrf=96、cmdinj=95
- 可映射到项目标签 288 条，无对应类（csrf/ssrf）192 条
- 已实测：并入训练会让 CSIC 异常召回从 20.2% 掉到 6.3%（REALDATA_EVALUATION §8）

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/WEB_APPLICATION_PAYLOADS.jsonl` | 160.9 KB | 480 | 多行 JSON 数组 |

### datacon2025_sample — datacon2025 xlab-httpcve 样本

- 路径：`traindata/datacon2025-xlab-httpcve-sample/.../data-release`
- 角色：**只做 OOD 链路自检**（禁止训练、禁止当良性池）
- 出处/许可：公开比赛样例（100 条）；标注=1 视为攻击，标注=0 不等于良性
- 消费方：`realdata.load_datacon` → `p2/p3/p6/p7/calibrate`、`export_datacon`
- `label=0` 里有 Spring 网关 RCE 探测（`/actuator/gateway/routes/...`）—— 当良性会算错 FPR
- 入训练会同时毁掉训练集与唯一 OOD 验收集

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/datacon2025-xlab-httpcve-sample/datacon2025-xlab-httpcve-sample/data-release/train_sample.json.gz` | 37.1 KB | 50 | gzip jsonl（payload = base64+zlib 原始报文） |
| `traindata/datacon2025-xlab-httpcve-sample/datacon2025-xlab-httpcve-sample/data-release/test_sample.json.gz` | 45.3 KB | 50 | gzip jsonl（payload = base64+zlib 原始报文） |

### cic_ids2017 — CIC-IDS2017 流级特征表

- 路径：`traindata/CIC-IDS2017/`
- 角色：流级通道（独立通道，**不并入 HTTP 特征**）
- 出处/许可：公开数据集（CIC-IDS2017）；CSV 为官方发布版
- 消费方：`p5_flow_spike`（仅 spike，抽样 stride=20）
- 标签是流级类别（BENIGN/DDoS/PortScan/WebAttack/...），与 HTTP 通道的 5 类标签不是一回事
- `Destination Port` 对 PortScan 近乎泄漏，流级特征必须剔除（p5 已剔除）
- WebAttack 只有 2,180 行，不足以支撑应用层召回

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/CIC-IDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 73.6 MB | 225,745 | DDoS=128,027、BENIGN=97,718 |
| `traindata/CIC-IDS2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 73.3 MB | 286,467 | PortScan=158,930、BENIGN=127,537 |
| `traindata/CIC-IDS2017/Friday-WorkingHours-Morning.pcap_ISCX.csv` | 55.6 MB | 191,033 | BENIGN=189,067、Bot=1,966 |
| `traindata/CIC-IDS2017/Monday-WorkingHours.pcap_ISCX.csv` | 168.7 MB | 529,918 | BENIGN=529,918 |
| `traindata/CIC-IDS2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 79.3 MB | 288,602 | BENIGN=288,566、Infiltration=36 |
| `traindata/CIC-IDS2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 49.6 MB | 170,366 | BENIGN=168,186、Web Attack ï¿½ Brute Force=1,507、Web Attack ï¿½ XSS=652、Web Attack ï¿½ Sql Injection=21 |
| `traindata/CIC-IDS2017/Tuesday-WorkingHours.pcap_ISCX.csv` | 128.8 MB | 445,909 | BENIGN=432,074、FTP-Patator=7,938、SSH-Patator=5,897 |
| `traindata/CIC-IDS2017/Wednesday-workingHours.pcap_ISCX.csv` | 214.7 MB | 692,703 | BENIGN=440,031、DoS Hulk=231,073、DoS GoldenEye=10,293、DoS slowloris=5,796、DoS Slowhttptest=5,499、Heartbleed=11 |

### local_benign — 本机真实良性（phpStudy access log）

- 路径：`traindata/local/local_lab_benign.jsonl`
- 角色：真实良性池（三关 ② 关 + 融合 FPR）
- 出处/许可：本机 Apache/nginx access log，`provenance=benign_lab`，已脱敏
- 消费方：`calibrate_rules`（unified_benign）、`p4_local`
- body 全空（access log 不落请求体）
- 来源是同一台实验机，路径集中在 phpMyAdmin/phpcms/dvwa
- 4 条 probe 命中已记录在 local_lab_report.json

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/local/local_lab_benign.jsonl` | 51.3 KB | 190 | 唯一请求数（非日志行数） |

### local_inwild — 在野良性（error log）+ IOC 攻击

- 路径：`traindata/local/inwild_*.jsonl`
- 角色：**不是良性池**：只能看命中率；inwild_attack 是攻击池一员
- 出处/许可：Apache error log；标签来自 IOC 正则（`provenance=indicator`），不是内容判定
- 消费方：`p4_local`（inwild_benign 命中率）、`calibrate_rules`（inwild_atk）
- 105,742 条唯一请求，但 `audit_pattern_hits.scanner=2074` 已被扫描器污染
- IOC 只命中 3 组模式（union select / .ssh 等敏感文件 / wp-login）→ 12 条
- 所有记录 body 为空、method 全 GET

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/local/inwild_benign.jsonl` | 25.5 MB | 105,730 | label={'0': 105730} |
| `traindata/local/inwild_attack.jsonl` | 3.4 KB | 12 | label={'1': 12} |

### local_datacon — datacon2025 拆出的攻击/未标注 jsonl

- 路径：`traindata/local/datacon_*.jsonl`
- 角色：OOD 链路自检
- 出处/许可：由 `export_datacon.py` 从 datacon 样本导出（保留 cve_labels/row_id）
- 消费方：人工复核 / 链路自检（判定链路用 `realdata.load_datacon` 现读）
- 唯一带 body 的真实请求（攻击 17 条、未标注 23 条）
- `datacon_unlabeled` 不是良性，别混池

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/local/datacon_attack.jsonl` | 70.2 KB | 42 | with_body=17 |
| `traindata/local/datacon_unlabeled.jsonl` | 139.5 KB | 58 | with_body=23 |

### collector_output — 采集器落盘样本（proxy/）

- 路径：`traindata/proxy/`
- 角色：**运行样本，不是语料**（有 pred、无 label）
- 出处/许可：`proxy` 采集器 dry-run 输出（多个 raw 分片 + metrics）
- 消费方：人工排查 / p8 e2e 观察
- 字段含 `pred`（action/attack_label/score）与 `body_truncated`
- 与 `events` 表结构不同：这里是采集器原始记录，别当训练数据

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/proxy/collector-metrics.json` | 1.4 KB | - | with_pred=- |
| `traindata/proxy/raw-1792389542171-00000.jsonl` | 11.5 KB | 10 | with_pred=10 |
| `traindata/proxy/raw-1792391221610-00000.jsonl` | 11.5 KB | 10 | with_pred=10 |
| `traindata/proxy/raw-20261022-00000.jsonl` | 23.8 KB | 10 | with_pred=10 |
| `traindata/proxy/raw-20261022-00001.jsonl` | 24.1 KB | 10 | with_pred=10 |
| `traindata/proxy/raw-20261029-00000.jsonl` | 0 B | 0 | with_pred=0 |
| `traindata/proxy/raw-20261029-00001.jsonl` | 0 B | 0 | with_pred=0 |
| `traindata/proxy/raw-20261029-00002.jsonl` | 0 B | 0 | with_pred=0 |
| `traindata/proxy/raw-20261029-00003.jsonl` | 1.9 KB | 1 | with_pred=1 |
| `traindata/proxy/raw-20261029-00004.jsonl` | 45.8 KB | 7 | with_pred=7 |
| `traindata/proxy/raw-20261029-00005.jsonl` | 6.6 KB | 3 | with_pred=3 |
| `traindata/proxy/raw-20261029-00006.jsonl` | 8.6 KB | 4 | with_pred=4 |
| `traindata/proxy/raw-20261029-00007.jsonl` | 2.7 KB | 1 | with_pred=1 |
| `traindata/proxy/raw-20261029-00008.jsonl` | 1.9 KB | 1 | with_pred=1 |
| `traindata/proxy/raw-20261029-00009.jsonl` | 11.7 KB | 3 | with_pred=3 |
| `traindata/proxy/raw-20261029-00010.jsonl` | 138.7 KB | 62 | with_pred=62 |
| `traindata/proxy/raw-20261029-00011.jsonl` | 8.2 MB | 3170 | with_pred=3170 |
| `traindata/proxy/raw-20261029-00012.jsonl` | 35.4 KB | 12 | with_pred=12 |
| `traindata/proxy/raw-20261029-00013.jsonl` | 588.5 KB | 232 | with_pred=232 |
| `traindata/proxy/raw-20261029-00014.jsonl` | 0 B | 0 | with_pred=0 |
| `traindata/proxy/raw-20261029-00015.jsonl` | 5.4 KB | 2 | with_pred=2 |

### enhanced_security — enhanced_security_dataset_clear.json（名字像安全数据集，实际是代码问答）

- 路径：`traindata/enhanced_security_dataset_clear.json`
- 角色：**不可训练**：不是 HTTP 请求，只可当知识库素材
- 出处/许可：来源不明；无许可证文件（见 THIRD_PARTY_NOTICES §2）
- 消费方：**无**（上传解析实测 767 条全部 `missing_path`、`rows_kept=0`）
- 内容是 Java 代码漏洞问答（Jenkins / Spring 源码片段），不是请求报文
- 字段只有 `instruction`、`output`
- `upload_parse.py` 会把它全部标为 `missing_path`；这是**解析器的正确行为**，不要为了让它「能用」而放宽解析

| 文件 | 大小 | 行/请求 | 备注 |
|---|---|---|---|
| `traindata/enhanced_security_dataset_clear.json` | 23.1 MB | 767 | has_http_fields=False |

## 3. 判定链路实际消费的池

| 池 | 条数 | 带 body | 组成 |
|---|---|---|---|
| `p7_benign` | 37,000 | 8,000 | lex_norm 1,000 + csic_norm_holdout 6,000 + csic_norm_rest 30,000 |
| `p7_attack` | 25,213 | 9,994 | lex_atk 106 + csic_anom 25,065 + datacon_atk 42 |
| `unified_benign` | 6,190 | 1,310 | csic_norm_holdout 6,000 + local_benign 190 |
| `unified_attack` | 25,119 | 9,994 | csic_anom 25,065 + inwild_atk 12 + datacon_atk 42 |

> 池定义来自 calibrate_rules.POOLS；三关用 unified_*，p7 锚点用 p7_*。inwild_benign 不在任何池里（扫描器污染）。

## 4. 已知坑（按现状登记，未修复）

- **[warn] enhanced_security_not_http** — enhanced_security_dataset_clear.json 有 767 条，字段只有 `instruction`、`output` —— 是 Java 代码漏洞问答，**没有 method/path/query/body**。名字像安全数据集，但 `upload_parse.py` 会把它们全部判为 `missing_path`（rows_kept=0）。禁止入训练、禁止当良性池。
- **[info] payload_full_is_derived** — payload_full.csv 只是 train+test 的拼接（31,067 行），无脚本消费；改任何一侧都会让它过期，别当独立语料引用。
- **[info] lexical_outside_full** — payload_test_lexical.csv（1,106 行）与 train/test 载荷零重叠、最长 45,489 字符，是**唯一的长文本源**；规则三关的 lex_norm/lex_atk 用它。
- **[warn] csic_missing_normal_test** — CSIC 缺 normalTrafficTest.txt（只有 normalTrafficTraining + anomalousTrafficTest），留出集是自切（seed=7, n_train=30000），与官方切分不可比。
- **[warn] payload_dict_corrupt** — WEB_APPLICATION_PAYLOADS.jsonl 有 20 个坏对象（第 181 行起编码乱码），已容错跳过；另有 192 条 csrf/ssrf 在项目标签体系里没有对应类（label=-1）。
- **[info] payload_dict_no_benign** — 攻击字典**零良性样本**：只能作规则挖掘/困难负例，并入训练必须同比例补真实良性，否则 FPR 直接上去。
- **[warn] datacon_small** — datacon2025 只有 100 条（标注攻击 42），只能问「检出与否」；任何召回率/准确率的置信区间都无意义（OOD 自检专用）。
- **[warn] body_coverage_zero** — 以下文件 body 全空（来源是 access/error log）：local_lab_benign.jsonl、inwild_benign.jsonl、inwild_attack.jsonl。本机真实流量侧 body 覆盖为 0，body 特征只能靠 CSIC 的 POST（unified_benign 6,190 条里 1,310 条带 body），部署环境上的 POST 攻击基本没有训练素材。
- **[warn] cic_flow_no_consumer** — CIC-IDS2017 共 2,830,743 行 / 557,646 攻击，目前只有 `p5_flow_spike.py`（抽样 spike）消费，**流级通道还没有生产消费者**。其中 WebAttack 仅 2180 行。
- **[info] cic_duplicate_columns** — CIC CSV 有重复列名 Fwd Header Length（pandas 会重命名为 .1），p5 里用 DROP_ALWAYS 剔掉。
- **[info] cic_mojibake_labels** — 标签里含 UTF-8→latin-1 的 mojibake（如 'Web Attack ï¿½ XSS'），按 `'web attack' in label.lower()` 归类比按全等匹配安全。
- **[info] cic_aux_files_mojibake** — CIC-IDS2017/data_py/ 下有 6 个与项目无关的预处理脚本，文件名是 GBK 乱码（`ȥ��������.py` 一类）；不被任何代码 import，可原样保留或移出，**不要当语料**。
- **[info] proxy_samples_in_traindata** — proxy/ 下有 3538 条采集器输出（有 pred、无 label），是**运行样本**不是语料；别混进池子。
- **[info] zip_duplicates** — zip 与解压目录并存：traindata/Machine-Learning-on-CSIC-2010-master.zip、traindata/datacon2025-xlab-httpcve-sample.zip（合计约 2.5 MB）。保留 zip 作原始出处，读数据一律读解压目录。
- **[warn] no_version_control** — F:\waf 不是 git 仓库，traindata 本身也无版本；文件一旦被覆盖没有任何回滚点。差异化请以本目录的 sha1 为准。

## 5. 建议动作

- 良性池 6,190 条（CSIC 留出 6,000 + 本机 190），远低于「按目标 FPR 标定」需要的 2,000 条本机量级；继续采真实 benign 是替换工作点的前置条件（inwild_benign 不能顶，见下）。
- 攻击池 25,119 条里 CSIC 异常占 25,065（词法为主），在野仅 12 条、datacon 仅 42 条；42 条导入规则「攻击回放 0 命中」就是这个池覆盖不足的直接后果。
- inwild_benign.jsonl（105,730 条）带 2,074 条扫描器命中，**只能看命中率**、不能算误报率；把它当良性池会把 FPR 算低。
- 本机真实流量 body 覆盖为 0，根因是日志源（access/error log 不带请求体）；要补 body 只能在采集器侧落 `event_bodies`，别再指望历史日志。
- 需要更宽的攻击语料时，优先级：① 真实本机良性到 ≥2,000 ② 采集器带 body 的真实攻击 ③ CIC-IDS2017 流级消费者。datacon 完整版未公开，不要等它。
