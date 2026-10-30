# 第三方组件与数据 —— 许可与出处

本仓库**不重新分发**下列上游的原始数据或规则文件；只在本机读取、派生，并把派生
结果按各自的许可条款标注。若将来要对外分发本仓库，请逐项复核本文件。

---

## 0. 本仓库自身的许可

**GNU Affero General Public License v3.0 or later（AGPL-3.0-or-later）**，全文见根目录
[`LICENSE`](LICENSE)。SPDX 标识同时写进了 `rust/Cargo.toml`、`proxy/Cargo.toml`、
`proxy_spike/Cargo.toml` 与 `web/package.json`。

三条**不随本仓库 AGPL 重新授权**的例外：

1. **CRS 派生规则**（§1）：原始许可 Apache-2.0，与 AGPLv3 单向兼容；版权与修改声明保留。
2. **`rules/waf_rules.json`**（§1b）：用户提供的外部规则集，**许可未知**；对外分发前须自行确认。
3. **数据集**（§2）：不在本仓库内，各自的条款由使用者遵守。

AGPL §13（远程网络交互）提示：如果你修改本项目并把它作为网络服务对外提供，
必须向这些用户提供 Corresponding Source。

---

## 1. OWASP ModSecurity Core Rule Set（CRS）

- **用途**：`python/import_crs.py` 读取 CRS 的 `REQUEST-9xx` 规则，把其中**语义可
  证明等价**的子集翻译成本项目的自撰规则（草稿）。
- **版本**：脚本不内置、也不下载 CRS。导入时由使用者提供本地检出
  （`--src <coreruleset>/rules`）。建议钉在 **v4.29.0**
  （`ab3ccd5fcd691424ba3f320d4040c61417270193`）或更新版本。
- **许可**：**Apache License 2.0**（SPDX: `Apache-2.0`）。
  - Copyright (c) 2006-2020 Trustwave and contributors.
  - Copyright (c) 2021-2026 CRS project and contributors.
  - 全文：<https://github.com/coreruleset/coreruleset/blob/main/LICENSE>
  - 项目主页：<https://coreruleset.org> / <https://owasp.org/www-project-modsecurity-core-rule-set/>

### 修改声明（Apache-2.0 §4(b)）

本仓库**不复制** CRS 的 `.conf` 文件，也不复制其 `msg` / `tag` / `logdata` /
`setvar` 文本。派生过程与改动如下：

1. 只保留**检测意图**：`@rx` 的模式（经下述翻译）、规则 `id`、以及截断到 60 字符的
   `msg` 副本（仅用于在控制台里追溯"这条规则来自哪一条 CRS 规则"）。
2. `@rx` 模式的改动：
   - 串尾 `$` → `\z`（本项目的 DSL 规定：`$` 只警告，串尾用 `\z`）；
   - `\/` → `/`；
   - 带 `t:lowercase` 的规则加 `(?i)` 前缀；
   - **不支持的构造一律丢弃整条规则**，绝不"近似翻译"。
3. 丢弃的部分（写进 `artifacts/crs_import_report.json` 的 `skip_reasons` 计数）：
   `chain`（含链的后续条件）、`@detectSQLi` / `@detectXSS` 等内置检测器操作符、
   `TX:` 变量与 `@gt` 等阈值操作符、lookaround / 反向引用 / 原子组 / 占有量词 /
   `\Q..\E`、以及 `t:` 变换链里除 `none` / `urlDecodeUni` / `lowercase` 之外的项。
4. **不复现** CRS 的 anomaly score 记账（`tx.inbound_anomaly_score_pl1` 等）。
   每条派生规则的 `weight` 只保留相对严重度
   （CRITICAL=5 / ERROR=4 / WARNING=3 / NOTICE=2）；若要按 CRS 语义阻断，
   提升时应把阻断线设为 5。
5. 派生规则落库后**恒为** `action=alert`、`enabled=0`、`validated_at=NULL`。
   启用与拦截是两次独立的人工决定，并各自留下审计记录。

> ⚠️ **当前状态**：`artifacts/crs_import_report.json` 是**解析器自检**的报告
> （`status: self_test_only`、`real_crs_imported: false`）。真实 CRS 导入尚未执行：
> 本机无外网出口，也没有本地 CRS 检出。请在能访问上游的机器上执行：
>
> ```
> py -3.10 import_crs.py --src <coreruleset>/rules --write-db
> ```
>
> 然后逐条 `POST /api/rules/custom/{id}/validate`，过了三关再打开开关。

---

## 1b. 外部通用 Web WAF 规则集（`rules/waf_rules.json`）

- **用途**：`python/import_waf_rules.py` 读取 `rules/waf_rules.json`（用户提供的通用
  WAF 过滤规则集，`meta.version = 1.0.0`），把**能映射到本项目规则通道语义**的子集
  导入为自撰规则（草稿）。
- **许可**：**文件内未声明许可证**。该文件由本仓库使用者提供，不由本项目分发；
  若要对外分发，请先确认其来源与授权。导入的派生规则在 DB 里以 `source='wafjson'` 标记，
  现役规则集的 `counts` 单独统计。

### 转换声明

1. 只做**字段映射**，不复制说明文字（原文的 `note` 截断后仅作为追溯用）：
   - `target`: `uri`→`path`、`query`→`query`、`body`→`body`；
   - `cookie` / `header` / `filename` / `response` **无对应**（数据面不落 cookie、
     不采响应体；`header` 猜成 `ua` 会静默改变语义）⇒ 取交集导入并把丢弃项写进
     `notes` 与 `dropped_targets`；交集为空的规则整条跳过。
   - 源文件声明「统一大小写不敏感」⇒ 每条补 `(?i)`；字符类外的 `$` → `\z`。
2. **编码形态分支**（`%XX` / 字面 `\uXXXX`）在我们的解码管线**之后**匹配，必然不可达：
   全部分支都不可达 ⇒ 跳过（`decode_incompatible`）；部分不可达 ⇒ 照常导入并记
   `dead_branches`（`%uXXXX` 与 `\xXX` 是**活的**，管线不解它们）。
3. 源文件的 `action=block` **不当作证据**：派生规则落库恒为 `action=alert`、
   `enabled=0`、`validated_at=NULL`。能否拦截只能由本项目自己的三关实测决定。

> 实测（`artifacts/waf_rules_validate_all.json`）：70 条声明 → **导入 66 条 → 过三关 23 条**。
> 跳过 4 条：`SC-001`/`SC-002`（target 只有 `header`）、`INF-002`（只有 `response`）、
> `PT-002`（全部分支都是 overlong-UTF8 的百分号编码，解码后不可达）。
> 42 条攻击回放 0 命中（本池证明不了，不等于规则无效）；`SF-004` 在真实良性上误报
> 140/6,190，被关 ② 拦下。

---

## 2. 评估与训练用数据集

这些数据**不在本仓库内**，仅在本地 `traindata/` 下读取。下表记录用途与已知的
许可状态 —— **未核实的不要对外分发**。

| 数据 | 用途 | 是否参与训练 | 许可状态 |
|---|---|---|---|
| CSIC 2010 HTTP dataset | 监督通道训练 + 零日通道训练 + **统一标定池**（正常流量 `seed=7` 留出 6,000） | 是（正常/异常流量） | 学术用途发布；**未核实**再分发条款 |
| HTTP Params 2015（`payload_*.csv`） | 监督通道正式训练/测试集 + 困难门槛集 | 是 | 公开数据集；**未核实**再分发条款 |
| CIC-IDS2017 | 独立**流级**通道（与 HTTP 通道并列，不混训） | 否（流级通道尚未实现消费者） | 加拿大网络安全研究所发布；**未核实**再分发条款 |
| datacon2025 | **OOD 复核集**，永不参与训练 | 否 | 完整版尚未公开；**未核实** |
| `enhanced_security_dataset_clear.json` | **不可用**：767 条 Java 代码漏洞问答，不是 HTTP 请求（上传解析全部 `missing_path`） | 否 | 来源不明；**禁止入训练、禁止当良性池** |
| 本地真实流量（`traindata/local/`） | 真实良性池 / 标定池 | 视采集方式 | 本项目自采；采集前须获得站点授权 |
| 本仓库 `python/artifacts/` 下的模型与曲线 | 派生产物 | — | 由上述数据训练得到，**继承上游数据的限制** |

> 训练集里**不含**任何合成数据或旧分布数据（`*_synthetic*` 产物仅为 A/B 对照，
> 名字带 `_synthetic` 以示区别）。

---

## 3. Python / Rust 依赖

依赖的许可由各自的包管理器解析（`cargo` / `pip`），本文件不逐个列举。
需要对外分发二进制时，请另外生成 SBOM 并逐项复核
（`cargo-license`、`pip-licenses`）。

重点依赖的许可家族：

- **Pingora**（Cloudflare，Apache-2.0）
- **ONNX Runtime**（MIT）
- **XGBoost** / **scikit-learn** / **NumPy**（Apache-2.0 / BSD-3-Clause）
- **FastAPI** / **Uvicorn** / **Pydantic**（MIT）
- **python-multipart**（Apache-2.0，仅控制面上传）
- **Ant Design** / **React** / **ECharts**（MIT / Apache-2.0）

> **Scapy 2.7.0（GPL-2.0-only）—— 许可冲突提示**：仅用于控制台解析用户主动上传的
> pcap/pcapng（`python/upload_parse.py`），**不进入 Rust 数据面、不随数据面二进制分发**。
> 但 `GPL-2.0-only` 与 `AGPL-3.0` **不兼容**：在 AGPLv3 的整体分发中直接 import 它是有风险的。
> 因此：① 内部使用不受影响；② 对外分发前应把 pcap 解析换成宽松许可实现
> （例如自写 pcap 解析，或换 BSD/MIT 的解析库），或把该功能拆成独立可选组件并单独声明；
> ③ 不要把它静态打进任何对外二进制。
