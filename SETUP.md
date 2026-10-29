# WAF + AI 自动检测告警系统 · 完整搭建指南

> 从零搭建这套系统（Rust 数据面 + Python 控制面 + 采集数据面）。
> 所有命令、版本、路径、产物名都与当前仓库一致，可直接照做。
>
> 相关文档：`prd.md`（需求）、`ENGINEERING_PLAN.md`（工程计划）、
> `REALDATA_EVALUATION.md`（真实数据评估，**所有数字与坑的唯一出处**）、
> `rust/README.md`、`proxy/README.md`、`python/README.md`。
>
> **只想把控制台跑起来**：Windows 用 `install.bat`，Linux 用 `./install.sh`，
> 见 **`INSTALL.md`**。脚本默认创建 `.venv`、只装控制面依赖（`requirements-service.txt`）、
> 前台启动；训练/评估/改 Rust 仍按本文的手工步骤。

---

## 0. 总览与目录结构

```
F:\waf\
├─ prd.md                      产品需求（唯一需求源）
├─ ENGINEERING_PLAN.md         工程计划（S1…S12、工作项 F/F0）
├─ REALDATA_EVALUATION.md      真实数据评估（所有数字与坑的唯一出处）
├─ rust\                       Rust 判定引擎（lib waf_ai_proto + bin waf-ai-proto）
├─ proxy\                      采集数据面（crate waf-collector，Pingora 0.9）
├─ proxy_spike\                S4 门禁实验（Pingora 版本能力验证，保留源码）
├─ python\                     控制面：训练 / 标定 / 评估 / 采集清洗
│   └─ artifacts\              全部产物（模型、策略、测试向量、曲线）
└─ traindata\                  数据集（公开数据集 + 真实流量）
    ├─ payload_*.csv           HTTP Params 2015
    ├─ Machine-Learning-on-CSIC-2010-master\   CSIC 2010 原始
    ├─ CIC-IDS2017\            流级数据
    ├─ datacon2025-...\        datacon2025（仅 100 条样本）
    └─ local\                  真实采集流量（良性/攻击/unlabeled）
```

构建缓存统一由 `WAF_CARGO_TARGET` 控制（Windows 优先 `E:\waf-target`，否则
`%LOCALAPPDATA%\waf-cargo-target`；Linux `~/.cache/waf-cargo-target`）。`rust/` 与
`proxy/` 必须共用一份，否则 ort/ONNX-Runtime 会编两遍。

---

## 1. 环境准备（Windows x86_64）

本机已验证通过的版本：

| 组件 | 版本 / 位置 | 说明 |
|---|---|---|
| Visual Studio | `D:\visual_studio` | 需 **C++ 桌面开发**工作负载（提供 `cl.exe` / Windows SDK） |
| CMake | 4.1.2（`C:\Program Files\mingw64\bin\cmake.exe`） | 见坑 #2 |
| Ninja | 1.13.1（同上目录，已在 PATH） | Pingora 的 zlib-ng 编译需要它 |
| Rust | rustc/cargo **1.99.0** | `C:\Users\lenovo\.cargo\bin`（**不在 PATH**，靠 `build.bat` 注入） |
| Python | **3.10.10**（`py -3.10`） | 见坑 #1 |
| Git | 2.47.0 | 已接入 GitHub 私有仓库 `himobrine/hiwaf`；秘密与大数据/模型产物已忽略 |
| Perl | **无** | 因此 Pingora 必须用 rustls，不能用 openssl |

> 若 Rust 未装：`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`（`prd.md` §451）。

**为什么用 `build.bat` / `build.sh`**：Rust 命令需要 MSVC（Windows）或
cmake/ninja（Linux）环境。包装脚本会自动找 `vcvars64.bat`、补 `cargo` 的 PATH、
统一 `CARGO_TARGET_DIR`，所以**不要直接 `cargo build`**（除非你已经自己配好环境）。

---

## 2. 数据准备

### 2.1 需要放置的数据

| 数据集 | 放置位置 | 用途 | 备注 |
|---|---|---|---|
| HTTP Params 2015 | `traindata\payload_{train,test,full,test_lexical}.csv` | **正式训练集** | 20,712 / 10,355 / 31,067 / 1,106 |
| CSIC 2010 | `traindata\Machine-Learning-on-CSIC-2010-master\` | 阈值标定池 / 零日通道训练 / OOD 评估 | 36,000 正常 + 25,065 异常；来源 http://www.isi.csic.es/dataset/ |
| CIC-IDS2017 | `traindata\CIC-IDS2017\*.csv` | 流级通道 + 规则评估池 | 攻击覆盖很窄（见 §14） |
| datacon2025 | `traindata\datacon2025-xlab-httpcve-sample\` | **仅 OOD 评估** | 只有 100 条样本，**不可用于训练、不可报比率** |
| 真实流量 | `traindata\local\*.jsonl` | 真实评估 / 后续重训 | 由 `collect_http_log.py` 产出 |

### 2.2 数据核对

```bat
set PYTHONIOENCODING=utf-8
cd F:\waf\python
py -3.10 realdata.py
```

### 2.3 数据目录（唯一盘点入口）

每个语料"能不能用、给谁用"只能有一份登记，否则就会把 OOD 集当训练集、
把扫描器流量当良性池。盘点工具**只读**（不移动/不改名/不删除任何文件）：

```bat
set PYTHONIOENCODING=utf-8
cd F:\waf\python
py -3.10 traindata_catalog.py              :: 全量，含 CIC 全表扫描，约 20s
py -3.10 traindata_catalog.py --skip-cic   :: 秒级（不数 CIC 行）
```

产物：

* `traindata\CATALOG.md` —— 人读（放在数据旁边，自动生成，勿手改）；
* `python\artifacts\traindata_catalog.json` —— 机器可读（含每个文件的 sha1，
  大文件只登记大小/mtime）；报告的每个数字都应能在这里反查到。

口径说明：

* 行数用 `realdata` 的**同一批 loader** 数（CSIC 行数 ≠ 请求数）；
* 池成分直接 import `calibrate_rules.build_sources` + `POOLS`，**不复制定义**；
* `inwild_benign.jsonl` 不在任何池里（2,074 条扫描器命中）——
  它只能看"命中率"，算 FPR 会把数字算低；
* `traindata\proxy\` 是采集器落盘样本（有 `pred`、无 `label`），不是语料。

当前盘点结论（2026-10-20）：9 组语料 / 40 个文件 / 911 MB，
`unified_benign` 6,190（CSIC 留出 6,000 + 本机 190）、
`unified_attack` 25,119（CSIC 异常 25,065 + 在野 12 + datacon 42），
14 条已知坑见 `CATALOG.md §4`。

---

## 3. 第一步：安装 Python 依赖

```bat
cd F:\waf\python
py -3.10 -m pip install -r requirements.txt
```

控制面 API 的依赖单独放在 `python\requirements-service.txt`（训练机不需要；
控制面也不需要 xgboost/onnx）：

```bat
py -3.10 -m pip install -r requirements-service.txt
```

> **推荐用 venv**：一键安装默认建 `F:\waf\.venv`。手工安装也可以：
>
> ```bat
> py -3.10 -m venv F:\waf\.venv
> F:\waf\.venv\Scripts\python.exe -m pip install -r requirements-service.txt
> ```
>
> 之后把本文所有 `py -3.10` 换成 `.venv\Scripts\python.exe` 即可（训练依赖同理）。

`requirements.txt` 关键版本：numpy 2.1.3 / pandas 2.3.3 / scipy 1.15.3 /
scikit-learn 1.7.2 / **xgboost 3.2.0** / onnx 1.23.2 / skl2onnx 1.20.0 /
onnxmltools 1.16.0 / onnxconverter-common 1.16.0 / onnxruntime 1.20.0 /
psutil 7.2.2 / redis 8.1.0 / python-multipart 0.0.32 / scapy 2.7.0。

> **matplotlib 不在 requirements 里**：学习曲线的 PNG 是**可选**的 ——
> `learning_curve.py` 没有 matplotlib 时只打印 `[curve] matplotlib unavailable, skip png`，
> 仍会写 `.json`/`.csv`。要 PNG 就 `py -3.10 -m pip install matplotlib`。

---

## 4. 第二步：训练正式监督模型（XGBoost）

官方配方（**唯一正式产物口径**）：

```bat
cd F:\waf\python
py -3.10 train_realdata.py --features v2 --hard-neg lexical --export
```

- `--features v2`：80 维特征契约（v1 78 维冻结在 `features_v1.py`，只做 A/B）。
- `--hard-neg lexical`：烘入困难良性负样本（lexical 正常前一半 500 条）。
- `--export`：导出 `xgboost_v*.onnx` + `xgb_model.json` + `xgb_trees.json`。
- 规模：**2000 棵树 / 18,464 节点 / 深度 8**。
- **每次训练都会产出学习曲线** → `artifacts\curves\<run>_curve.{json,csv,png}`。

诊断/对照（不覆盖正式产物）：

```bat
py -3.10 train_realdata.py --features v2                              :: 不导出
py -3.10 train_realdata.py --features v2 --hard-neg csic              :: 对照：CSIC 正常流量
py -3.10 train_realdata.py --features v2 --hard-neg lexical --lexical-split grouped
py -3.10 train_realdata.py --features v2 --hard-neg lexical --seed 22
py -3.10 train_realdata.py --ab                                       :: v1/v2 A/B
```

> **不要用合成数据/旧分布数据硬调参。** 合成训练器只写 `*_synthetic*` 产物名；
> 正式名只属于真实数据。
>
> **Early Stopping 注意**：XGBoost 隐式 ES 监视的是最后一个 eval set 的最后一个指标，
> `["mlogloss","merror"]` 实际监视的是 `merror`。旧轮次结论里 “ES 停在 r62/r5” 已作废。
> 正式配方**保持 ES-free**；`--valid-frac` 仅诊断用。若要 ES，监视 `mlogloss`、停 50–80 轮，
> 且必须在 lexical 塌陷前停。

---

## 5. 第三步：训练零日通道（IForest）

```bat
cd F:\waf\python
py -3.10 iforest_lean_onnx.py --data csic --export
```

- 用 CSIC 正常 30,000 训练，导出精简 IForest（`iforest_lean_v*.onnx` + `iforest_meta.json`）。
- 常用参数：`--trees 100 --max-samples 256 --seed 42`；`--data {csic,synthetic,local}`。
- 换真实本地良性重训：`--data local`（产出 `iforest_lean_local_*.onnx` / `iforest_meta_local.json`，
  不覆盖正式名）。

---

## 6. 第四步：阈值标定（**唯一事实来源**）

```bat
cd F:\waf\python
py -3.10 thresholds.py --pool csic
```

- 产出 **`artifacts\decision_policy.json`** —— 判定规则的**唯一事实来源**。
- **阈值只在留出良性上标定，绝不在训练数据上标。** 两通道各自 `score >= threshold`。
- 推荐档 `--fpr 0.01`。策略档位：
  - 监督：`0.001→0.814499`，`0.01→0.699765`（推荐），`0.03→0.137536`
  - 零日：`0.001→-6.578375`，`0.01→-7.262677`，`0.03→-7.473629`
- 会同时写顶层 `zero_day_enabled` 与 `effective_fused_fpr_on_pool`；
  `--zero-day {on,off}`（**默认 off**）控制零日通道是否进入融合。
- `--pool file:..\traindata\local\local_lab_benign.jsonl` 用本地真实良性重标定（**上线前必做**）。
- `--force` 仅在明知校准池含训练样本时用（危险）。

刷新 Rust 侧参考数据（**直接读已导出产物，不重训**）：

```bat
py -3.10 export_testvec.py     :: -> testvec.json（含判定期望值 + 融合动作）
py -3.10 export_shap_ref.py    :: -> shap_ref.json（TreeSHAP oracle）
```

> ⚠️ **策略 / 测试向量 / Rust 三件套必须同时重生成**，否则 `rust\src\main.rs` 的断言会失败
> （政策缺 `zero_day_enabled` 时 Rust 默认 `true`，但 `thresholds.py` 永远显式写）。

判定语义：双通道 —— 监督通道（XGB）→ **Block**；零日通道（IForest `avg_path_len`）→
**Alert only，永不单独阻断**。融合动作 `supervised_block__zero_day_alert`。
`argmax` 仅用于攻击类型分类，不用于判定。

---

## 7. 第五步：构建并验证 Rust 数据面

Rust 侧 = **lib `waf_ai_proto` + bin `waf-ai-proto`**；`proxy/` 通过 path 依赖它。
**判定逻辑只有这一处，禁止复制**（复制会让 200×80 逐位一致的门禁失效）。

```bat
cd F:\waf\rust
call build.bat run --release
```

- `build.bat` 做三件事：`vcvars64.bat` 建 MSVC 环境 → 把 `C:\Users\lenovo\.cargo\bin`
  加进 PATH → 设 `CARGO_TARGET_DIR=%WAF_CARGO_TARGET%`（默认 `E:\waf-target`）。
- 二进制在 **`E:\waf-target\release\waf-ai-proto.exe`**。
- **门禁必须全绿**（换机器/换编译器后要复核，Linux 侧 libm `log2` 可能有末位差异，
  CI 用数值容差）：

| 校验项 | 期望 |
|---|---|
| Rust 特征 vs Python v2 | **逐位一致** 200×80 全 0 差异 |
| XGBoost 推理 vs onnxruntime | max\|diff\| ≈ **4.17e-7**，argmax **200/200** |
| IForest 推理 | max\|diff\| ≈ **5.72e-6** |
| TreeSHAP vs `pred_contribs` | max\|diff\| ≈ **8.11e-6** |
| 阈值交叉核对 | **0.000e0** |
| 融合动作一致性 | **200/200** |
| e2e 延迟 | p50 ≈ 0.64ms / p99 ≈ 1.18ms |

---

## 8. 第六步：采集数据面（Pingora Proxy）

### 8.1 它是什么 / 不做什么

Pingora 反向代理 + HTTP/流级采集。它把请求原样转发给真实后端，同时把请求/响应头体与
流级字段写进 `traindata/proxy/raw-*.jsonl`（**无 label**）。

**红线（不可越）**：

- **只采集、不打 label、默认不阻断、不静默丢数据**。标签由 `collect_http_log.py` 按**出处**决定。
- `pred`（模型输出）与 `label`（真值）**结构隔离**：`parse_jsonl` 只保留已知键，
  模型输出永远不可能变成训练标签。
- `--block-mode off` 是默认（纯采集）；`dry_run` 只记录；只有 admin 显式切到 `enforce`
  才会真正返回 403。`--score` 是旧开关，等价于 `dry_run`。阈值仍应先在真实本地良性流量上
  重标定，再考虑开 `enforce`。

### 8.2 让业务流量真正走代理（推荐：反向代理前置）

```text
客户端 ──► 采集器 0.0.0.0:6188 ──► 真实后端 127.0.0.1:80
              │
              └─► traindata/proxy/raw-*.jsonl ──► 控制台 ingest ──► 事件/告警
```

**最快接入（3 步）**：

1. 确认后端端口（下面以 `127.0.0.1:80` 为例），采集器监听 `0.0.0.0:6188`
   （局域网/其他机器也能访问；只允许本机就写 `127.0.0.1:6188`）；
2. 启动采集器（控制台「采集代理 → 启动」，或命令行，见 §8.4）；
3. 让客户端访问 **6188** 而不是后端端口，然后验证：

```bat
:: 请求应返回后端内容
curl -i "http://127.0.0.1:6188/?x=1"

:: 应看到 raw 文件；控制台「采集代理」页的 written 应 +1
dir F:\waf\traindata\proxy\raw-*.jsonl
```

**多端口 / 多站点（单进程多路由）**：控制台「采集代理 → 配置 → 路由」可加多条
`名称 / 监听 / 上游 / TLS`；一个采集器进程监听多个端口，共享写盘队列、模型、规则与指标，
记录里的 `route` 字段标明命中哪条路由。

若要求**客户端 URL 不变**，必须让 WAF 占用原业务端口、把真实后端挪到其他端口：

```text
客户端 ──► WAF 0.0.0.0:80 ──► phpStudy 127.0.0.1:8080
```

Windows 上监听 80/443 需要管理员权限；**系统防火墙放行需自行配置**（本程序不会自动改防火墙）。

**真实拦截（`block_mode=enforce`）**：命中阻断条件返回 **403 + 简短页面**。
无 body 的请求（GET/HEAD 等）在请求头阶段完成判定，上游完全收不到请求；有 body 的请求
必须等 body 收齐（或达到 `--body-limit`）才能判定，所以 body 类拦截时上游**可能已收到请求头、
但收不到 body**（流式反向代理的固有限制）。

**模型只告警、规则才阻断（`--no-supervised-block`）**：默认模型（监督通道）命中即可单独阻断。
但监督模型是在 CSIC 上标定的，换到本地业务后可能出现**系统性误报**（实测：本机 sqli-labs 上
任何带 `id=` 的 GET 查询串都被判成 `cmdi`，分数 ≈ 0.999，远高于 0.6998 的阈值）。
加 `--no-supervised-block`（控制台「配置 → 模型命中可单独阻断」关掉）后：

- 模型命中只降级为 `alert`：分数、穿阈、SHAP 与规则证据照常落盘，事件页可见；
- **只有规则通道达到 `min_weight_to_block` 才返回 403**；
- 规则通道命中时仍然是 `block`，降级只放宽模型，不放宽规则。

已知覆盖缺口：`sqli_comment_tail` 的正则是 `(--|#|/\*)\s*$`（要求注释符在**文本结尾**）。
GET 的查询串在结尾，所以 `?id=1'--+` 命中；POST 表单体后面还有 `&submit=Submit`，
`id=1'--+&submit=Submit` **不命中该规则**（其余 `' OR '1'='1`、`UNION SELECT`、`SLEEP()` 都命中）。
补这一类要么给规则集加「引号后跟注释符」的规则并走 `rule_promote` 重新标定预算，
要么保留模型阻断（会带回上面的 GET 误报）。

**nginx 前置（可选）**：客户端仍访问 80，nginx 把请求转给采集器，采集器再转给后端。

```nginx
server {
    listen 80;
    location / {
        proxy_pass http://127.0.0.1:6188;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**HTTPS 限制（必须知道）**：采集器监听侧是纯 TCP，**不做 TLS 终止、不处理 CONNECT 隧道**。
因此：

- HTTP 业务：反向代理前置即可完整采 body；
- HTTPS 业务：在 nginx/Caddy **终止 TLS**，再把明文 HTTP 转给采集器；否则只能看到 CONNECT
  元数据，拿不到 body。系统代理/PAC 同理，只适用于能解密的 HTTP。

> `out_dir` 固定为 `traindata/proxy`：`ingest.py`/`ingest_scheduler` 只扫这个目录。界面上不提供
> 修改入口，避免出现「代理在写、控制台没事件」的假故障。

### 8.3 控制台「采集代理」页与控制面接口

页面：`/proxy`（菜单「采集代理」）。viewer 只读，analyst 可看日志，admin 可改配置/启停。

| 方法 | 路径 | 权限 | 作用 |
|---|---|---|---|
| GET | `/api/proxy/status` | viewer | 进程/PID/uptime、逐路由监听/上游、block_mode、指标、输出目录、二进制、告警 |
| GET | `/api/proxy/config` | viewer | 保存配置 + 实际生效值 + `restart_required` |
| PUT | `/api/proxy/config` | admin | 白名单校验后落库；**启动/重启才生效** |
| POST | `/api/proxy/start` | admin | 端口占用/已在跑/二进制缺失返回 409 |
| POST | `/api/proxy/stop` | admin | body `{"force":true}` 用于 PID 复用/未托管进程 |
| POST | `/api/proxy/restart` | admin | 停止后按保存配置重启 |
| GET | `/api/proxy/log?tail=200` | analyst | 托管日志尾部 |

约束：

- 二进制只从 `WAF_COLLECTOR_BIN` 或固定候选（仓库 `bin/`、`proxy/bin/`、
  `proxy/target/release`、`E:\waf-target\release`、`rust/target/release`）解析，
  **不接受请求传入**；
- 参数逐项白名单校验，范围对齐 `proxy/src/config.rs`；`out_dir`/`stats_out` 固定；
- 路由表至少一条；`name`/`listen` 唯一，禁止 `listen == upstream`（自环）；
- `block_mode` 默认 `off`；切到 `enforce` 前端会二次确认，并写 `proxy_block_mode_update` 审计；
- 单实例 PID 文件 + 端口探测（逐路由检查）；服务重启后靠 PID 文件接管，PID 复用需显式 `force`；
- 所有写操作写审计：`proxy_config_update` / `proxy_start` / `proxy_stop` /
  `proxy_force_stop` / `proxy_restart`。

### 8.4 构建与命令行运行

```bat
cd F:\waf\proxy
call build.bat build --release        :: 构建
:: 单路由（旧写法仍兼容）
call build.bat run --release -- --listen 0.0.0.0:6188 --upstream 127.0.0.1:80 ^
    --out ..\traindata\proxy --stats-out ..\traindata\proxy\collector-metrics.json

:: 多端口：一个进程监听多个端口，每个端口一个上游
call build.bat run --release -- ^
    --route name=site-a,listen=0.0.0.0:80,upstream=127.0.0.1:8080,tls=0 ^
    --route name=site-b,listen=0.0.0.0:8081,upstream=127.0.0.1:8082,tls=0 ^
    --block-mode dry_run ^
    --out ..\traindata\proxy --stats-out ..\traindata\proxy\collector-metrics.json
```

`build.bat` 相比 rust 版**多设 `CMAKE_GENERATOR=Ninja`**（pingora → flate2 → zlib-ng 会调 cmake，
而 cmake 4.1.2 不认识 “Visual Studio 18 2026” 生成器）。

`cargo build --release` 成功后脚本会把产物复制到仓库 `bin/`（Windows
`bin\waf-collector.exe`，Linux `bin/waf-collector`），控制台优先加载这个项目内路径。
**重建前先在控制台「采集代理」页停止采集器**，否则 Windows 上 exe 被占用，复制会失败
（脚本只警告、不算构建失败）。

**全部选项**（`proxy/src/config.rs`）：

| 选项 | 默认 | 作用 |
|---|---|---|
| `--route name=<n>,listen=<addr>,upstream=<addr>,tls=0\|1` | — | 一条路由，**可重复**；多路由共用一个进程，共享写盘/模型/规则/指标 |
| `--listen <addr>` | `0.0.0.0:6188` | 单路由：客户端 → 本代理（未给 `--route` 时使用） |
| `--upstream <addr>` | `127.0.0.1:8080` | 单路由：本代理 → 真实后端 |
| `--upstream-tls` | off | 单路由：上游走 TLS |
| `--block-mode <off\|dry_run\|enforce>` | `off` | `off` 纯采集；`dry_run` 只记录；`enforce` 命中 block 返回 403 |
| `--score` | — | 旧开关，等价于 `--block-mode dry_run`（显式 `--block-mode` 优先） |
| `--supervised-block` / `--no-supervised-block` | 开 | 模型命中是否可单独阻断；关掉后模型只告警、只有规则通道能 403 |
| `--out <dir>` | `../traindata/proxy` | 原始记录输出目录（控制台固定此项） |
| `--body-keep <bytes>` | `65536` | 单请求**落盘** body 上限，超出即截断并置 `body_truncated=true` |
| `--body-limit <bytes>` | `1048576` | 单请求**缓冲**硬上限（**防 OOM**），超过即停止累积 |
| `--headers-keep <bytes>` | `8192` | 请求/响应头落盘上限（`name: value\r\n` 规范化字节） |
| `--resp-body <alert\|all\|off>` | `alert` | 响应体采样；判定开启时 `off` 仍缓冲并在评分失败时留证 |
| `--resp-body-keep <bytes>` | `65536` | 响应体落盘上限（原始 wire bytes） |
| `--file-size-mb <n>` | `256` | 单文件轮转大小；UTC 跨天也会轮转 |
| `--channel <n>` | `8192` | 写队列容量，**满了丢记录并计数，绝不阻塞转发** |
| `--no-body` | — | 隐私模式，body 恒空 |
| `--artifacts <dir>` | `../python/artifacts` | 模型产物目录 |
| `--stats-out <file>` | 关 | 指标 JSON；控制台靠它显示 written/dropped/actions |
| `--stats-interval <sec>` | `60` | 指标刷新周期 |
| `--rules <file>` | 产物规则集 | 规则通道；文件不存在自动不启用 |
| `--no-rules` | — | 不加载规则通道 |
| `--reload-interval <s>` | `5` | 策略/规则热重载轮询；0=关 |
| `--no-reload` | — | 关闭热重载（只用于排查） |

### 8.5 验证与自检

端到端自检（自起假上游 + 代理 + 标注 + dry-run 判定，**43 项断言**）：

```bat
cd F:\waf\python
py -3.10 -X utf8 p8_proxy_e2e.py
```

应 **43/43 PASS**（含请求/响应头体、二进制请求体、阶段 C 规则融合）；产物 `artifacts\p8_proxy_e2e.json`。

控制面托管链路自检（需要先构建采集器，默认跳过）：

```bat
set WAF_PROXY_LIVE_TEST=1
cd F:\waf\python
py -3.10 -m unittest service.test_proxy_live -v
```

### 8.6 取证包与保留

控制台「事件 → 行 → ⑤ 原始请求包 / 原始响应包」读取 `/api/events/{id}/packet`，
请求包和响应包直接展开为连续原始文本；请求中命中规则的字段/行标红。
请求体保留训练兼容的文本 `body`，精确字节在 `body_b64`；二进制时 `body=""` 且只读 `body_b64`。
响应状态/头/体默认按 `--resp-body alert` 采样，`all` 用于联调，`off` 关闭但判定开启时评分失败仍留证。
敏感头值默认逐字符显示 `*`；`reveal=1` 才返回原值并写 `view_sensitive_headers` 审计。

90 天清理**先 dry-run 再 apply**（SQLite 事件与 raw 共用 cutoff；文件候选还要求绝对路径安全、
`ingest_state` 完整性、size/mtime 匹配；pending/trash 状态机见 `python\service\README.md`）：

```bat
:: GET /api/retention/raw-cleanup?days=90   先看 eligible / skipped 原因
:: POST /api/retention/raw-cleanup {"confirm":true,"note":"90d retention"}
```

### 8.7 常见故障

| 现象 | 排查 |
|---|---|
| 启动返回 409 | 端口已被占用 / 已有实例 / 二进制缺失；换 `listen` 或先停止 |
| 502 / 连接失败 | `upstream` 写错或后端没起；采集器不负责拉起后端 |
| 有请求但事件页没有 | 看 `/api/proxy/status` 的 `metrics.written`；确认 `out_dir` 是 `traindata/proxy`，ingest 在跑 |
| 命中条件但不拦 | 确认 `block_mode=enforce`，且采集器已重启（状态页会提示 `restart_keys`） |
| 监听 80/443 失败 | Windows 需要管理员权限；换高位端口或提升权限 |
| 客户端 URL 不变但后端被占 | 先把真实后端挪到其他端口（如 8080），WAF 再占用原端口 |
| HTTPS 拿不到 body | 监听侧不做 TLS 终止/CONNECT；用 nginx/Caddy 终止 TLS 后转 HTTP |
| 指标 stale | 进程卡住或已退出；看「采集代理」页日志尾部，必要时重启 |
| 改配置不生效 | 大多数项需重启；页面会列出 `restart_keys` |


---

## 9. 第七步：采集真实流量并标注

`collect_http_log.py` 是采集/清洗/标注入口，**`--src` 是 `action="append"`** ——
每个文件传一次该参数，逗号拼接无效。

```bat
cd F:\waf\python

:: 1) 日志 -> jsonl（--scrub 脱敏）
py -3.10 collect_http_log.py --src <nginx_access.log> --name prod --provenance benign_lab --scrub

:: 2) 持续累积（每 5s 扫新行，追加写入）
py -3.10 collect_http_log.py --src <access.log> --name prod --follow --append --provenance benign_lab

:: 3) 攻击标签只能来自出处（蜜罐路径 / 红队会话 / 人工复核清单）
py -3.10 collect_http_log.py --src <access.log> --provenance redteam --name redteam_x

:: 3b) 本机红队自测（Burp/SQLmap 打 DVWA，来源 IP 与浏览器同为 127.0.0.1，只能靠时间窗）
py -3.10 collect_http_log.py --src <access.log> --provenance auto ^
    --redteam-window 2026-10-17T09:30:00,2026-10-17T10:05:00 --name local_lab

:: 5) 挂采集代理后：代理只写原始 jsonl（无 label）；要 body 必须显式 --keep-body
py -3.10 collect_http_log.py --format jsonl --src ..\traindata\proxy\raw-*.jsonl ^
    --provenance auto --canary-prefix /admin.php --name local_lab --keep-body
```

关键约定：

- **access log 没有请求体**，而 body 是攻击特征最强的位置。要 body 必须走采集代理
  （**S4 已定 Pingora**）。该约束已解除：`proxy/` 已把 body 采到并端到端验证。
- `collect_http_log.py` **默认清空 body**（隐私优先）；`norm_len` 把落盘 body 截到 8192 字符。
  `pred` 的特征是在**截断后**的 body 上算的。
- `--redteam-window` 按**字面本地时间**比较（忽略 CLF 时区偏移），CLI 会打印日志实际时间范围
  供核对；**任一条时间戳解析不了就直接报错退出** —— 静默把红队流量标成良性会污染良性池。
- `--label-pattern`（内容正则）**只允许用于构造评估集，绝不用于训练标签**。
- `inwild_*`（公网错误日志）被扫描器污染，**不能当良性校准池，其命中率不能当 FPR 报**。
- 假名源策略：datacon2025 里 `labeled=0` **不等于良性**，要报被标记率 + 强制人工复核。

---

## 10. 第八步：真实流量评估

```bat
cd F:\waf\python
py -3.10 p4_local.py
```

产出 `artifacts\p4_local.json`。**当前真实流量基准（不要四舍五入）**：

- 本机良性 block **4.21%**，alert **0.00%**
- 公网 105,730 请求 **6.54% blocked**
- 12 IOC 攻击 **7/12**（n 太小，别引用 58.3%）

阈值会随重标定漂移（监督 0.699765→0.946859，零日 -7.262677→-7.042185），
**别跨 run 比阈值数字，只比 FPR**。

---

## 11. 第九步：上线前重标定与启用零日通道

```bat
cd F:\waf\python

:: 1) 用真实本地良性重标定（良性池要 >=2000 条，否则分位抖动大）
py -3.10 thresholds.py --pool file:..\traindata\local\local_lab_benign.jsonl

:: 2) 重新导出门禁向量
py -3.10 export_testvec.py
py -3.10 export_shap_ref.py

:: 3) 重跑 Rust 门禁（必须全绿）
cd ..\rust && call build.bat run --release

:: 4) 要启用零日通道时（只 alert，永不单独阻断）
py -3.10 thresholds.py --zero-day on
py -3.10 export_testvec.py && cd ..\rust && call build.bat run --release
```

零日通道语义：`zero_day_flagged` 是**有效标志**（关闭时恒 false），原始交叉在
`zero_day_score_crossed` / testvec 的 `expected_crossed`。
**策略 / testvec / Rust 必须同时重生成。**

---

## 12. 第十步：控制台（控制面 API + 前端 SPA）

定位是**安全运营业务层**（事件/告警/策略/反馈/规则/模型/任务/审计）；
CPU/内存/QPS/延迟这类**基础设施运维指标仍归 Grafana + Prometheus**（PRD §4.9.2），不重复建设。

> 一键安装（`INSTALL.md`）会建 `.venv` 并完成下面 1–3 步；手工安装也可以复用同一个
> `.venv`：把 `py -3.10` 换成 `.venv\Scripts\python.exe` 即可。

```bat
:: 1) 装控制面依赖（只需一次；版本与 requirements-service.txt 一致）
py -3.10 -m pip install -r requirements-service.txt

:: 2) 构建前端（产物 web\dist，由 FastAPI 单端口托管）
cd F:\waf\web
npm ci
npm run typecheck
npm run build

:: 3) 初始化 DB/admin（幂等；已有账号/密码不会覆盖）
cd F:\waf\python
py -3.10 -m service.bootstrap

:: 4) 起后端（默认 8090；首次启动会创建 admin 并把初始密码写入 service\.admin_password）
set PYTHONIOENCODING=utf-8
py -3.10 -m service.run --port 8090

:: 5) 浏览器打开 http://127.0.0.1:8090  （接口文档 /docs）
```

开发前端时另开一个口：

```bat
cd F:\waf\web && npm run dev      :: 5173，/api 已代理到 8090；改代码热更新
```

自检与造数：

```bat
cd F:\waf\python
py -3.10 -m service.smoke         :: 34 项 API 自检（需要服务已启动；含聚合下钻与代际树）
py -3.10 -m service.demo_seed     :: 起假上游 + 采集器 + 判定，灌一批真实采集数据
```

**上传训练数据**（页面「训练数据」）：

- 支持 CSV / JSON / JSONL / HAR / pcap / pcapng；pcap 只支持**明文 HTTP/1.x**，
  TLS/HTTP2 跳过并计数，整份文件只能一个标签。
- 上传时必须声明角色：`supervised`（逐行标签）/ `benign`（良性，零日 + 校准）/
  `eval`（仅评估，不能训练）；`supervised`/`benign` 必须填数据来源说明。
- 单文件 ≤256MB；后台解析为 `ready` 后，到「训练任务」选「官方 + 上传」或「仅上传」。
- 上传训练副本会自动剔除与官方评估集（payload_test / lexical / CSIC holdout）精确重叠的请求；
  校准池优先用上传良性留出，不足回退 CSIC。
- 训练产物仍只写 `artifacts\staging\task_<id>\`；上线仍走「模型与门禁」的切换流程。
- 权限：`analyst` 上传/预览，`admin` 训练/删除；删除为软删除，被运行中任务引用时拒绝。

```bat
:: 命令行复现解析（控制台内部同一脚本）
py -3.10 upload_parse.py --input data.csv --out %TEMP%\up1 --role supervised
py -3.10 upload_parse.py --input cap.pcap --out %TEMP%\up2 --role benign --default-label 0
```

**审计保留 / 删除**（页面「审计」，仅 admin）：

- 默认保留 **90 天**；系统每天自动删除 90 天前的 `audit` 记录，启动约 30s 后跑第一次。
- 自动清理删 0 条时不写审计；异常尽力写 `audit_cleanup_failed`。
- 手动清理：点「清理旧审计」→ 先 dry-run 预览（总记录/待删/保留/截止时间/动作分布）→
  确认后硬删除；天数可在 1–3650 之间调整。
- 勾选删除：表格可多选，单次最多 **500 条**，可填删除原因。
- 每次真正删除后都会新增 `audit_cleanup` / `audit_cleanup_selected` 记录；
  删除在事务内完成，写审计失败会回滚。清理只碰 `audit` 表，不动 events/raw/聚合表。
- 关闭自动清理：`set WAF_AUDIT_RETENTION_SCHEDULER=0` 后再启动服务。

**登录**：用户 `admin`，密码见 `python\service\.admin_password`（或在启动日志里打印）。
登录后立刻改密码：网页右上角 → 退出前请先改（或 `POST /api/auth/password`）。

**刷新策略**：按要求用**手动 / 定时轮询**（总览可选 15s、顶栏运行模式 30s、任务日志 2s、
规则 incident 默认 10s 且有 open 时 5s），**没有 SSE**。

**性能（本机实测，单进程）**：

- SQLite 采用**线程内连接复用**（服务启动时 `db.enable_pool()`）：本机每条新连接的第一条
  语句约 23 ms，复用后单查询 ~0.1 ms。`/api/overview/summary`、`/api/events`、`/api/alerts`
  的端到端延迟从 **28–55 ms 降到 1.5–5.4 ms**。
- 总览的事件聚合有 5s 缓存（`WAF_OVERVIEW_CACHE_SEC`，`0` 关闭）；直方图在 SQL 里分桶。
- 事件页用 **keyset 游标**翻页（`cursor_ts`+`cursor_id`），深翻页不再扫前 N 行；
  总数只在第一页统计（`with_total=false`）。
- 事件表索引：`ix_events_ts`、`ix_events_action_ts`、`ix_events_ip_ts`；老库启动时自动删旧单列索引。
- 若要多人并发/多机，SQLite 仍是瓶颈，需要迁 Postgres（见 `python/service/README.md` §6）。

**告警页的两层视图**：

- **聚合告警**：按「源 IP + 动作 + 方法/路径 + 时间桶」看哪条路径被打了多少次；
  打开「同源同类去重」后改为「源 IP + 动作 + 攻击类型 + 时间桶」，同源同桶内打不同
  路径的同类攻击合并成一行（显示「路径数」），扫描风暴不再刷屏。
- **攻击链**：按「源 IP + UA」聚合，间隔超过切链阈值分成新链；阶段按
  拦截→利用 / 告警→试探 / 失败请求→探测归类，并叠加时序规则（扫描后利用等）。
  探测多且无拦截的链标为扫描噪音、默认折叠。确认/关闭复用告警状态（`chain_key`
  即 `alert_state.group_key`），下钻抽屉能看到每条事件的阶段标签。
- 时序规则可用 `WAF_TEMPORAL_RULES` 指向 JSON 覆盖，格式见 `python/service/README.md` §2.3。
- **实体级抑制**：告警页两个页签都有「显示已抑制」开关。默认折叠生效中的抑制项，
  只显示「另有 N 组被折叠」；打开后保留行、置灰并标「已抑制」。「抑制策略」页负责
  草案 → admin 审批（带 TTL）→ 撤销/过期；也可从人工确认误报自动生成草案。
  **抑制只影响控制台可见性，不改数据面 block/alert 判定**，详见 `service/README.md` §2.4。

**必须在界面上记住的四件事**：

1. **阈值不能在界面手改**：策略页只能「选标定池 → 预览 → 提升」。预览走
   `thresholds.py --out <临时文件>`，**不碰现役策略**；提升才写 `decision_policy.json` 并刷新 `testvec.json`。
2. **策略 / 规则集热重载，换模型才重启**：采集器每 5s 轮询 `decision_policy.json` 与
   `rules_authoritative.json` 的 sha1，两者都通过 `decision.rs` 校验才原子换入
   （`RwLock<Arc<Engine>>`）；校验失败**保留旧策略**并把错误上报到控制面，不会把采集器打挂。

   | 改动 | 生效方式 |
   |---|---|
   | 阈值、`zero_day_enabled`、`rules.enabled`、规则集 | ≤5s 热重载，**不用重启** |
   | 换 ONNX 模型 / 特征契约 | 产物名变化即报错，**必须重启采集器** |
   | 改 Rust 代码本身 | 重跑门禁 + 重建两个 crate |

   ```bat
   cd F:\waf\rust  && call build.bat run --release
   cd F:\waf\proxy && call build.bat build --release     :: 重建采集器并发布到 ..\bin
   ```
   重建采集器前先在控制台「采集代理」页停止它（Windows 会锁定正在运行的 exe，
   否则 `bin\waf-collector.exe` 复制失败，只警告不报错）。
   策略 / testvec / Rust 三件套必须同源，否则门禁或采集器启动即报错。
   中间态 fail-safe：策略与规则集 sha1 不一致时，规则证据权重按 0 处理（只少拦，不误拦）。
3. **零日开关是安全降级**：策略页的开关（需 admin）会直接重跑 `thresholds.py` 并刷新 `testvec.json`；
   关闭时零日分数仍计算、**原始穿阈仍留证**，只是不产生 alert。默认关闭。
4. **规则启用 ≠ 合格**：启用只进“测试中”（强制 `alert`）；合格必须人工确认；提升到现役才进数据面。
   误报集中时可三级熔断（单规则 / 全部阻断 / 规则通道），详见 §16.1。

---

## 13. 其他评估 / 分析脚本

```bat
py -3.10 eval_http_params.py     :: HTTP Params 留出评估
py -3.10 eval_csic.py            :: CSIC 评估
py -3.10 exp_hardneg.py          :: 困难负样本实验
py -3.10 diag_v2.py              :: v2 诊断
py -3.10 p0_audit.py             :: 数据审计
py -3.10 p2_matrix.py            :: 统一评估矩阵 + datacon OOD
py -3.10 p3_fusion.py            :: 双通道融合 / 跨池误报 / 迁移性
py -3.10 p5_flow_spike.py        :: 流级通道 spike
py -3.10 p6_body_ablation.py     :: body 消融
py -3.10 p7_rule_mining.py       :: 规则挖掘
py -3.10 textsim.py              :: 文本相似度
py -3.10 traindata_catalog.py    :: traindata 全量盘点（只读，产出 CATALOG.md）

:: 合成数据链路自检
py -3.10 train_xgboost.py
py -3.10 train_iforest.py
py -3.10 smoke_test.py
```

---

## 14. 全部坑（务必先读）

1. **PATH 上的 `python` 可能是 IDA 的 3.8**：一律用 `py -3.10`。
2. **cmake 不认 VS 18/2026 生成器**：Pingora 侧必须 `set CMAKE_GENERATOR=Ninja`。
3. **本机没有 perl**：Pingora 用 `features = ["proxy","rustls"]`，**完全绕开 OpenSSL**
   （Pingora `default = []`，feature 必须显式选）。
4. **`build.bat` 注释必须纯 ASCII**：中文 `REM` 行 + LF 行尾会被 cmd 当命令解析，
   静默跳过前面的 `set`（表现为假的 cmake/生成器报错，还会带上
   `'rapper:' 不是内部或外部命令` 噪声）。
5. **构建缓存必须两个 crate 共用**：默认 Windows 有 `E:\` 时用 `E:\waf-target`，
   否则 `%LOCALAPPDATA%\waf-cargo-target`；Linux 用 `~/.cache/waf-cargo-target`。
   `build.bat` / `build.sh` 已统一设置 `CARGO_TARGET_DIR`，不要各写各的。
6. **Rust 侧 `Session::run` 需要 `&mut self`**；`response_body_filter` 在 Pingora 0.9 是
   **同步** `fn`（写成 `async` 会得到误导性的 `E0195` 生命周期/约束错误）。
7. **Pingora 0.9 的 `PeerOptions` 字段是 pub**（`read_timeout`/`write_timeout`/
   `connection_timeout = Some(..)`），`set_*_timeout` 已移除。
8. **`session.client_addr()` 返回 pingora 的枚举 `SocketAddr`**，要 `.as_inet()` 才能拿到
   `std::net::SocketAddr`。
9. **ort 在本机是静态链接**：目标目录里只有 `DirectML.dll`，**没有 ONNX Runtime DLL 要部署**。
10. **cargo path 依赖按 package 名解析**：crate 是 `waf-ai-proto`，lib 是 `waf_ai_proto`
    （不一致就要 `package = "..."` 重命名）。
11. **Rust 没有 `f` 格式 trait**，用 `{:.6}`；格式串不能索引捕获变量。
12. **cmd 引号坑**：带引号的绝对 Windows 路径在 `del` 里会坏；中文进 `findstr /c:"..."`
    或 PowerShell 的 `$_`/`$s` 会被这个 shell 弄乱 —— 用 ASCII 模式或写 `.ps1` 走
    `powershell -File`。
13. **`--src` 是 append**：一个文件一次参数。
14. **`collect_http_log.py` 默认清空 body**：训练要 body 必须 `--keep-body`。
15. **Windows 是 Pingora 的社区尽力而为平台**（Linux 才 tier 1）：锁 `>=0.9` 并放进回归门禁。
16. **Linux 侧逐位一致未验证**（libm `log2`）：CI 用数值容差。
17. **仓库已托管到 GitHub（私有）**：`https://github.com/himobrine/hiwaf`。
    根 `.gitignore` 已排除 `.secret`、`.admin_password`、`console.db`、日志、
    `traindata/`、模型二进制与构建缓存；改代码走独立分支 + PR，不再直接堆在工作区。
18. **datacon2025 只有 100 条样本**：只用于“能不能检出”，**绝不报比率**；
    `labeled=0` ≠ 良性，要报被标记率 + 强制人工复核。
19. **规则必须先 URL 解码再匹配**（`unquote_plus` 两次，多 3,793 命中）。
20. **规则「启用」≠「合格」**（2026-10-21 起）：`enabled=1` 只表示**参与在线测试**，
    数据面强制 `action=alert`（`action_forced='alert'`），**不产生阻断**。合格必须人工确认：
    `kind=detector` 要池内 ③>0，或在线人工确认攻击 ≥1 且确认良性 = 0；
    `kind=guard` 要真实良性 0 误报 + 管理员填写政策理由（③ 不适用）。
    只有已合格（或 `verdict=keep`）+ 人工把 `action` 翻成 `block` 才真拦；
    任何编辑都会清空 `compiled_at/validated_at/qualified_at` 并强制回到 alert。
    出现大量误报可三级熔断（单规则 / 全部阻断 / 规则通道），熔断只改产物、不改 DB。
    详见 §16.1。
21. **流级特征必须排除 `Destination Port`**；流级与 HTTP 不是 1:1。

---

## 15. 验收 / 门禁清单（新机器搭建完成后逐条跑）

- [ ] `py -3.10 realdata.py` 数据核对通过
- [ ] `py -3.10 traindata_catalog.py --self-test` **27/27 PASS**（数据目录没漂）
- [ ] `train_realdata.py --features v2 --hard-neg lexical --export` 产出 ONNX + 学习曲线
- [ ] `iforest_lean_onnx.py --data csic --export` 产出精简 IForest
- [ ] `thresholds.py --pool csic` 产出 `decision_policy.json`（含 `zero_day_enabled`）
- [ ] `export_testvec.py` / `export_shap_ref.py` 刷新
- [ ] `rust: call build.bat run --release` **门禁全绿**（§7 表）
- [ ] `rust: call build.bat test --release --lib` **18/18 PASS**（判定/熔断守卫）
- [ ] `proxy: call build.bat build --release` 编译通过
- [ ] `py -3.10 -X utf8 p8_proxy_e2e.py` **43/43 PASS**
- [ ] `py -3.10 -m service.smoke` **34/34 PASS**（需服务已启动）
- [ ] 控制面 `PRAGMA user_version == 2`，且 `/api/rules` 的 `custom_state` 字段齐全
- [ ] `py -3.10 p4_local.py` 数值与上次一致（或解释差异）

---

## 16. 产物清单与唯一事实来源

| 产物 | 位置 | 性质 |
|---|---|---|
| `decision_policy.json` | `python\artifacts\` | **判定规则唯一事实来源** |
| `rules_authoritative.json` | 同上 | **现役规则集唯一来源**（只由 `rule_promote` / 熔断 patch 写） |
| `rules_testvec.json` | 同上 | 规则集门禁输入（熔断窗口内可能滞后） |
| `xgb_model.json` / `xgb_trees.json` / `xgboost_v*.onnx` | 同上 | 正式监督模型 |
| `xgboost_meta.json` | 同上 | 训练记录（其 `decision_threshold` **仅供参考**） |
| `iforest_lean_v*.onnx` / `iforest_meta.json` | 同上 | 正式零日通道 |
| `testvec.json` / `shap_ref.json` | 同上 | Rust 门禁输入 |
| `curves\<run>_curve.*` | 同上 | 每次训练的学习曲线 |
| `p8_proxy_e2e.json` / `p4_local.json` / `p2_matrix.json` / `p3_fusion.json` | 同上 | 评估证据 |
| `crs_import_report.json` | 同上 | CRS 导入报告（当前仅解析器自检） |
| `waf_rules_import_report.json` | 同上 | 外部规则集（`rules\waf_rules.json`）导入报告：逐条归宿 + 跳过原因 |
| `waf_rules_preflight.json` | 同上 | 同一批规则的**批量**回放预检（**不是** `validate` 结论，不改任何状态） |
| `waf_rules_validate_all.json` | 同上 | 逐条三关的实测汇总（权威结论仍在 `rules_custom.validation`） |
| `rules_debug_report.json` | 同上 | 规则调试记录：8 条修复明细 + 35 条"池里无该类样本"的逐条证据（marker 计数 / 全 scope 命中） |
| `traindata_catalog.json` | 同上 | `traindata\` 全量盘点（角色/行数/标签/sha1/池成分/已知坑） |
| `CATALOG.md` | `traindata\` | 上者的可读版（自动生成，勿手改） |
| `*_synthetic*` | 同上 | 合成链路自检（**永不用作正式产物**） |
| 采集原始记录 | `traindata\proxy\raw-*.jsonl` | 代理直出，**无 label** |
| 标注后数据 | `traindata\local\*.jsonl` | 按出处打标，**无 `pred`** |

### 16.1 规则生命周期（四层状态，别跳步）

```
草稿 --① 编译--> 已编译/可启用 --启用--> 测试中（强制 alert） --在线证据 + 人工确认--> 合格 --提升--> 现役
                                  \-- ② 良性回放 / ③ 攻击回放（detector）--/
```

| 状态 | 判定依据（DB 字段） | 数据面动作 |
|---|---|---|
| 草稿 | `compiled_at` / `validated_at` 缺失 | 不在现役规则集 |
| 已编译 | `compiled_at` 非空、`enabled=0` | 同上 |
| 测试中 | `enabled=1`、`qualified_at` 为空 | 强制 `alert`（`action_forced='alert'`） |
| 合格 | `qualified_at` 非空 | 可人工逐条翻 `block` |
| 现役 | 提升写进 `rules_authoritative.json` | 采集器 ≤5s 热重载 |

- **启用 ≠ 合格**：`enabled=1` 只是“参与在线测试”，保证能产生 alert 证据，但**不会阻断**。
- **编辑即降级**：改正则/scope/severity → `compiled_at/validated_at/qualified_at` 全清空、`enabled=0`、强制 alert；
  只改 `kind` → 保留编译证据、清空合格。想重新拦截必须重走三关 + 人工确认。
- **三关**（`POST /api/rules/custom/{rid}/validate`）：
  ① Rust `regex` 编译（权威引擎，拒绝 lookaround/反向引用）；
  ② 真实良性池回放 0 误报（池 = `unified_benign` 6,190）；
  ③ 攻击池回放 >0（池 = `unified_attack` 25,119）。
  `kind=guard` 跳过 ③，但 ② 不通过就永远不能合格。
- **合格判据**（`POST /api/rules/{rid}/qualify`，**必须人工点**）：
  - `kind=detector`：三关全过，**或**在线 `confirmed_attack ≥ 1` 且 `confirmed_benign = 0`（`hits > 0`）。
  - `kind=guard`：② 真实良性 0 误报 + 管理员在 `note` 里填写政策理由（如“管理入口探测”）。
  - 真实良性池有误报（`benign_ok=false`）的规则**一律拒绝合格**，强制确认也不行。
- **在线证据分桶**（`GET /api/rules/{rid}/evidence`）：
  - `confirmed_attack`：人工标 `attack` / `missed`；
  - `confirmed_benign`：人工标 `benign` / `false_positive`；
  - `suspected_attack`：没人标，但监督/零日也报了 —— **模型辅助，只提示，不能单独定罪**；
  - `unlabeled`：其余（只看样本）。
  “模型说良性”**不**算良性证据：规则与监督是并列通道，模型漏掉的正是规则该抓的。
  在线证据只统计 `enabled_at` 之后的命中。
- **动作锁**：`build_authoritative()` 是唯一出口，未合格/熔断中的规则一律被改写成 `action=alert`，
  并在产物里留 `provenance.action_forced`；只有 `qualified_at` 非空 + 人工翻 `action=block` 才进阻断预算。
  拦截预算按“实测扣减 + Wilson 95% 上界”计算（`thresholds.py` 读 `rule_fpr`），**alert 命中不扣预算**。
- **提升**（`POST /api/rules/promote`）：写 `rules_authoritative.json` + 刷新策略里的
  `rules.ruleset_sha1_16` / `n_rules` / `n_block_rules` / `version`，采集器 ≤5s 热重载。
  未提升 = 对数据面零影响。
- **熔断**（`POST /api/rules/breaker`）：只 patch 现役产物，**不重建整个规则集**
  （避免把未提升的测试规则带进数据面）。

  | 级别 | `scope` | 动作 |
  |---|---|---|
  | L1 单规则 | `{"scope":"rule","rule":"..."}` | block 规则降 `alert`；alert 规则移出现役（`mode='disable'`） |
  | L2 全部阻断 | `{"scope":"all_block"}` | 所有 block → alert |
  | L3 规则通道 | `{"scope":"channel"}` | `rules.enabled=false` + `fusion.policy` 从 `FUSION_3` 降到 `FUSION_2` |

  恢复：`POST /api/rules/breaker/restore`，body 用 `{"rule":"..."}` / `{"all":true}` /
  `{"all":true,"channel_on":true}`。`mode='disable'` 的规则恢复时若已被重新提升/停用则跳过，
  不会悄悄放回现役。熔断期间**不停采集**、不改 DB 里的规则动作；恢复按
  `prev_action` / `prev_rule_json` 快照还原。
- **自动检测**（`rule_monitor.py`，60s 扫描；默认**只自动降级 `confirmed_fp`**，其余只弹窗）：

  | `reason` | 触发 | 动作 |
  |---|---|---|
  | `confirmed_fp` | block 规则 10 分钟内确认良性 ≥5 且占已标样本 ≥50% | 自动 L1 降级 + 高优先级弹窗 |
  | `noise` | alert 规则 10 分钟内确认良性 ≥20 | 只弹窗 |
  | `hit_spike` | >100 次/5 分钟且 >5× 基线 | 只弹窗 |
  | `block_spike` | >50 次/5 分钟 | 只弹窗 |
  | `manual` | 管理员手动点 | 立即执行 |

  前端 `AppLayout` 轮询 `GET /api/rules/incidents?status=open`（默认 10s；有 open 时 5s）：
  `high` 用常驻 `Modal.error`（每个 incident 只弹一次，`localStorage` 记已弹），
  `medium` 用 `notification.warning`。**已阅 ≠ 关闭**：必须显式 `ack` / `resolve`。
- **中间态 fail-safe**：策略与规则集 sha1 不一致 / 规则集校验失败 → 规则证据权重按 0 处理，只少拦不误拦。
- **熔断与 testvec 的已知差异**：熔断沿用旧 `rule_fpr`（更保守），熔断窗口内
  `rules_testvec.json` 暂不重算；重标定后恢复一致。
- **没有样本 ≠ 规则没用**：池内无该类样本的规则**全部保留**为草稿，等真实流量补证据；
  不删除、不改语义去凑命中。逐条证据在 `rules_debug_report.json`。

外部规则集导入（走同一条生命周期）：

```bat
py -3.10 import_waf_rules.py                    # 只出报告，不写库
py -3.10 import_waf_rules.py --write-db         # 写成草稿（enabled=0 / action=alert）
```

- 只收语义可证明等价的子集；`source='crs'` / `'wafjson'` 保留来源。
- 源文件自称的 `action=block` 只记在 `notes`（`src_action`），**不是**证据。
- 2026-10-20 实测：`rules\waf_rules.json` 70 条声明 → 66 条入库（跳过 4 条不可等价翻译）。

### 16.2 规则过不了三关时怎么查

三关 ③ 只在 `unified_attack`（25,119 = CSIC 异常 25,065 + 在野 IOC 12 + datacon 标注 42）上取证。
这个池以 Paros 扫描器流量为主：**池里没有的类别就是没有** —— 不要为了让它过而改语义、换池或拿
未核实出处的 payload 字典充当证据。

排查顺序（也是 `artifacts\rules_debug_report.json` 的口径）：

1. **scope 错位**：真实载荷落在没勾的字段（例：真实 XXE 把 XML 放在 `query`，不在 `body`）。
2. **解码后形态**：`%0d%0a` 解码后是字面 CRLF、`%00` 解码后是 NUL、`%3cscript` 解码后是 `<script`
   ⇒ 所有"编码形态"分支在匹配时都不可达，必须改写成解码后的形态（或删分支）。
3. **语法过严**：`INTO OUTFILE "C:/..."` 后面没有括号；`<!ENTITY % remote SYSTEM ...>` 是参数实体。
4. **重复检测**：解码后与另一条规则等价（`XSS-008` 之于 `XSS-001`）⇒ 合并/删除，别硬凑。
5. **池里真没有**：用类特征词统计（`rO0AB`、`%uXXXX`、`on\w+=`、`information_schema` …）证明为 0，
   把结论写进该条规则的 `notes`，保持草稿。

2026-10-20 实测：66 条导入规则 → **31 条合格**。按 1–3 修好 8 条：`XXE-001`/`XXE-002`（参数实体 + query）、
`RCE-006`（SpEL `@java.lang.X@`）、`RCE-007`（`${...<proto>://}` 混淆 + ua/referer）、
`SQLI-011`（`INTO OUTFILE` 无括号）、`EN-003`（解码后「换行 + 头名 + 冒号」，不单匹配裸 `\r\n`）、
`UP-002`（解码后 NUL）、`SF-004`（去掉会命中真实管理员的 `phpmyadmin|phpinfo`）。其余 35 条池内该类样本为 0，
保持草稿，逐条证据在 `rules_debug_report.json`。

- `xss_008` 属第 4 类（与 `xss_001` 解码后重复），建议合并。
- `lfi_002` 的"文件包含"在池里只有 SSI `<!--#include -->` 形态（不是 PHP `include()`），按"不近似翻译"
  原则不改语义；现有规则靠 SSI 载荷里的 `/etc/passwd`、`;` 等副特征命中 724 行中的多数。
  2026-10-21 已新增专用规则 `custom_waf_ssi_001`（`(?i)<!--#(?:exec|include|echo|config|printenv)\b`，
  `scopes=["full"]`）：② 真实良性 **0/6,190**，③ 攻击池 **724/25,119**（覆盖池内全部 SSI 行：
  `exec` 528 + `include` 196，含大写 `EXEC`），当前 `suggest` 草稿，等人工确认后启用测试。

### 16.3 规则生命周期的表与端点

| 表 | 用途 |
|---|---|
| `rules_custom` | 规则本体 + `kind` + `compiled_at/validated_at/qualified_at` + `enabled_at` |
| `event_rules` | 每个事件命中了哪些规则（证据；**不回写** `events.attack_label`） |
| `rule_hits_daily` | 按 `rule + day` 聚合命中/阻断/测试命中，给规则页和监控用 |
| `rule_incidents` | 熔断/噪声/突增事件，`status=open/ack/resolved` |
| `rule_breakers` | 当前熔断覆盖：`prev_action` / `mode` / `prev_rule_json` |

| 端点 | 用途 |
|---|---|
| `GET /api/rules` | 全部规则 + `custom_state` + `breakers` + `counts` |
| `GET /api/rules/{rid}/evidence?days=7` | 在线证据分桶 + 离线三关 + 样本 |
| `POST /api/rules/{rid}/qualify` / `unqualify` | 人工确认 / 撤销合格 |
| `POST /api/rules/custom/{rid}/validate` | 三关；guard 的 ③ 记 `not_applicable` |
| `POST /api/rules/custom/bulk-enable` | 批量启用测试（只 alert） |
| `POST /api/rules/promote` | 提升到现役（写规则集 + 策略指纹） |
| `GET /api/rules/incidents?status=open` | 弹窗轮询 |
| `POST /api/rules/incidents/{iid}/ack` / `resolve` | 已阅 / 关闭 |
| `POST /api/rules/breaker` / `breaker/restore` | 三级熔断 / 恢复 |
| `POST /api/rules/monitor/scan` | 手动触发一次扫描（调试用） |

采集器侧：`events.rule_hits_json` 保存命中数组，`events.rule_testing=1` 表示该事件
来自“测试中”规则；`ingest.py` 负责拆到 `event_rules` 和 `rule_hits_daily`，
单事件命中封顶 50 条，避免异常规则刷爆库。

---

## 17. 未决事项（搭建完成后仍待推进）

1. **真实攻击流量采集（S8 短板）**：本机靶场（DVWA/phpStudy + Burp/SQLmap）尚未驱动，
   公网蜜罐路径尚未挂到对外代理上。用 `--redteam-window` 标注本地红队会话。
2. **真实良性池偏小**（190 条，目标 >=2000）：`thresholds.py --pool file:` 暂无法替换
   策略工作点（分位抖动）。用 `--follow --append` 持续累积后再标定。
3. **流级通道消费者未实现**：采集点已定（Proxy 近似），流字段已透传，但流↔HTTP 非 1:1。
4. **datacon2025 完整版仍未拿到**，OOD 评估可信度受限；替代品 = CSIC 2010 + CIC-IDS2017。
5. **CI / 托管暂缓**（用户后续用 VM）；构建缓存不要落在 `F:`。
6. **控制台待办**（见 `python\service\README.md` §6）：
   1. **90 天 raw/事件清理**：dry-run / apply / pending 处置 API + 每日自动 dry-run 已实现，
      真正 apply 仍需 admin 显式确认；`rule_hits_daily` / `rule_incidents` 随同一 cutoff 清理；
   2. **用户管理页缺失**：只有引导创建的 `admin`，没有增删改用户接口；
   3. ~~攻击链关联未实现~~：已实现同源 + UA 切链、阶段分类、扫描噪音降级与
      时序规则；告警页「攻击链」页签 + `dedup=1` 同源同类去重（见 `service/README.md` §2.3）；
   4. ~~实体级误报抑制未实现~~：已实现草案 → 审批（TTL）→ 撤销/过期，支持从确认误报
      生成草案；告警/攻击链默认折叠被抑制项，只影响控制台可见性（见 §2.4）；
   5. 若要多人并发/多机，SQLite 需迁 Postgres。
7. **规则启停不会自动进数据面**：`enabled=1` 只是“测试中”；接进数据面要走「提升到现役」
   （写 `artifacts\rules_authoritative.json` + 策略指纹），采集器 ≤5s 热重载。
   未合格规则即使提升也只会 `alert`；`block` 只对已合格 + 人工翻转开放。
   35 条池内无样本的规则保持草稿，等真实流量补在线证据后再确认合格。
8. **在线证据需要新采集记录**：旧 `raw-*.jsonl` 没有 `rules.hits[]`，重启新采集器前
   `event_rules` / `rule_hits_daily` 会一直是空的（规则页在线证据全 0，熔断也不会触发）。
