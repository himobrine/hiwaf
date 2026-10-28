WAF + AI 自动检测告警系统 PRD（产品需求文档）
文档信息
项目	内容
产品名称	WAF + AI 自动检测告警系统
文档版本	V1.0
文档状态	正式发布
目标平台	Linux x86_64 + Windows x86_64
技术栈	Rust（数据面）+ Python（控制面/离线训练）
运行环境	纯 CPU 部署（i5-12500H，4P+8E 核心，无 GPU）
设计原则	轻量化、分层化、可解释、可降级、持续进化、跨平台
一、产品概述
1.1 产品背景
中小型业务在安全防护上面临两难：传统 WAF 依赖规则库，对未知威胁和绕过变种检测能力弱；商用 AI WAF 多为云端 GPU 方案，成本高、延迟大、数据出域存在合规风险。本产品面向中小型业务，在纯 CPU 环境下构建 AI 增强 WAF 系统，兼顾已知攻击精准检测、未知威胁兜底、漏判事后补救与防火墙联动封禁。

1.2 产品定位
边缘 WAF（反向代理模式）：WAF 作为独立反向代理与 TLS 终止点，后端应用仅接受来自 WAF 的流量。

CPU-only AI 推理：不依赖 GPU，通过 ONNX Runtime CPU 优化实现毫秒级推理。

双平台原生部署：Linux 与 Windows 均可原生构建运行，业务逻辑平台无关。

可运营、可回滚、可降级：任何 AI 能力异常时均可降级至规则引擎，保证 WAF 可用性优先。

1.3 目标用户
角色	诉求
安全运维工程师	低误报、可解释告警、快速封禁与解封
安全分析师	攻击链关联、告警降噪、误报/漏报反馈闭环
业务研发/运维	低延迟接入、业务上下文适配、不影响业务可用性
安全负责人	检测率指标、合规治理、版本可回滚
1.4 核心价值
已知攻击（SQLi、XSS、命令注入、路径遍历等）精准检测与分类。

未知威胁异常兜底检测（Isolation Forest）。

攻击成功后的漏判事后补救（响应体分析 + 日志关联）。

与网络防火墙联动，实现 IP 危险性动态评分与分级封禁。

全链路可解释、可运营、可回滚、可降级、可跨平台。

二、核心指标
指标	目标值	说明
误报率（FPR）	< 3%	生产环境统计口径
单请求延迟（P99）	< 10ms	含全部检测层
吞吐量	800–1500 QPS	i5-12500H 纯 CPU
峰值内存	< 500MB	含模型与缓存
零日攻击检测率	> 70%	基于未知威胁兜底层
单请求平均延迟	3–5ms	正常负载下
500 QPS 下 CPU 占用	2–3 个物理核心	—
三、整体架构
3.1 架构分层
采用插件化分层管道，控制面与数据面分离：

text
Client → [TLS终止] → [IP黑名单] → [限速] → [正则规则匹配] → [XGBoost分类] → [Isolation Forest] → [灰区语义分析] → Backend
              ↓            ↓           ↓              ↓                  ↓                    ↓
          快速拦截     快速拦截    已知攻击拦截    已知攻击分类       未知威胁兜底        可疑请求精细判定
3.2 控制面 / 数据面分离
面	实现	职责
数据面	Rust	反向代理、TLS 终止、正则匹配、ONNX 推理、Redis 交互、IP 评分等实时逻辑，保证 <5ms 端到端延迟
控制面	Python	模型训练、对抗样本生成、威胁情报同步、告警分析与聚合、策略生成等离线任务
协作方式：Python 训练产出 ONNX 模型，Rust 侧通过 ort crate 加载；Python 生成的规则/黑名单通过共享配置或 Redis 同步给 Rust。

3.3 核心模块与 CPU 开销
模块	实现方式	延迟	CPU 开销
IP 黑名单	Redis + 布隆过滤器	<0.01ms	极低
滑动窗口限速	Redis 计数器	<0.1ms	极低
正则规则匹配	Hyperscan / regex	<0.5ms	低
XGBoost 分类	ONNX Runtime	0.5–2ms	中
Isolation Forest	ONNX Runtime	~0.04ms/样本	低
灰区语义分析	轻量逻辑回归/特征匹配	<5ms	中
响应体分析	异步正则+关键词	不阻塞响应	低
3.4 部署模式
边缘 WAF（反向代理模式），WAF 作为独立反向代理，后端应用仅接受来自 WAF 的流量。

四、功能需求
4.1 检测引擎
4.1.1 IP 黑名单
功能：纯内存查找，支持自动过期和白名单。

实现：Redis + 布隆过滤器（存储历史黑名单，O(1) 预判，容量可达 1 亿）。

需求：

支持 TTL 自动过期（Redis EXPIRE）。

支持 LRU 淘汰兜底（maxmemory-policy allkeys-lru）。

支持白名单优先级高于黑名单。

4.1.2 滑动窗口限速
功能：基于 Redis 计数器的滑动窗口限速。

需求：支持按 IP、按 URL、按业务线配置限速阈值。

4.1.3 正则规则匹配
功能：Hyperscan / regex 线性时间匹配。

需求：

兼容 OWASP CRS 核心规则。

支持规则热加载与动态启用/禁用。

始终保留精简 OWASP CRS 核心规则作为兜底。

4.1.4 XGBoost 分类
功能：SQLi、XSS、命令注入等多分类。

实现：ONNX Runtime（ort crate），延迟 1–3ms。

需求：

模型文件格式：xgboost_v20261015_001.onnx。

支持模型热加载（Linux SIGHUP / Windows 命名事件）。

输出 0–100 风险评分及攻击类型分类。

4.1.5 Isolation Forest
功能：未知威胁兜底检测。

实现：ONNX Runtime，延迟 ~0.035ms/样本。

需求：

CPU 过载时可降级关闭（>85% 持续 30s）。

批量推理可分配至 E 核。

4.1.6 灰区语义分析
功能：仅对评分 40–70 的请求触发精细判定。

实现：轻量逻辑回归/特征匹配，延迟 <5ms。

需求：可配置灰区区间与触发策略。

4.1.7 响应体分析（异步）
功能：WAF 拦截服务器响应，送入轻量级响应分析模块（正则+关键词，<1ms）。

需求：

命中敏感数据模式 → 标记疑似漏判，写入事件队列（不阻塞响应）。

触发响应撤回/脱敏动作。

不存储原始响应体，仅提取必要特征。

4.2 拦截决策与响应分级
4.2.1 风险评分与置信度
模型输出 0–100 风险评分，综合规则匹配、ML 预测、IP 信誉等信号。

4.2.2 多级响应机制
风险等级	评分区间	响应动作
低风险	< 50	放行，仅记录日志
中风险	50–85	挑战（验证码）或限速
高风险	> 85	拦截（403），触发自动封禁
4.2.3 动态阈值调整
根据 WAF 性能状态（CPU 占用率）动态调整信任阈值。

提供多档灵敏度预设（低/中/高）。

4.2.4 安全上线策略
新模型/新策略先运行观察模式至少一周。

核对告警，反馈误报，再逐步开启拦截。

4.3 黑名单与 IP 危险性评分体系
4.3.1 黑名单数量限制的解决
策略	实现
架构分层	网络层（防火墙）承担主力封禁，应用层（WAF）做精准补充
TTL 自动过期	Redis EXPIRE，封禁时长分级（1h ~ 30d）
LRU 淘汰兜底	Redis maxmemory-policy allkeys-lru
布隆过滤器	存储历史黑名单，O(1) 预判，容量可达 1 亿
信誉评分替代	中等风险 IP 触发限速/挑战，不占黑名单容量
4.3.2 封禁时长分级策略
IP 特征	封禁时长
首次攻击、业务区域	1 小时
多次攻击、非业务区域	24 小时
持续攻击、数据中心/代理	7 天
高置信度恶意（C2 节点）	30 天
4.3.3 AI 判断 IP 危险性：连续风险评分
评分维度（加权减法模型）：

连接类型：Tor 出口（-100）、公共代理（-90）、托管/数据中心（-75）、商业 VPN（-45）

ASN 分类：住宅 ISP vs 云服务商

地理位置一致性：与用户声称地址/时区不匹配（-15）

历史信誉：近期滥用记录

多源威胁情报融合（参考 ARGUS 权重）：

本地黑名单 0.30、AbuseIPDB 0.30、CrowdSec 0.15、VirusTotal 0.10、ThreatBook 0.10、CriminalIP 0.05

某源失败时，权重自动重分配

CPU 实现：离线 IP 库内存加载（微秒级查询），规则引擎+加权计算（<1ms），威胁情报定期同步到本地缓存。

4.3.4 WAF 与防火墙协同
WAF（L7）：深度检测，执行拦截、挑战、限速。

防火墙（L3/L4）：基于 IP 快速封禁，处理高置信度恶意 IP。

联动方式：AI 生成封禁指令 → API 自动下发至 WAF 和防火墙 → 效果追踪与自动解封。

4.4 漏判补救闭环
4.4.1 响应体分析（异步）
WAF 拦截服务器响应，送入轻量级响应分析模块（正则+关键词，<1ms）。

命中敏感数据模式 → 标记疑似漏判，写入事件队列（不阻塞响应）。

触发响应撤回/脱敏动作。

4.4.2 告警日志关联分析
WAF 日志与应用日志按来源 IP、时间戳、URI、规则 ID 关联。

检测"WAF 放行但应用报错"的请求。

低分放行但响应异常的请求标记为可疑。

4.4.3 自动响应
确认漏判 → 调用 WAF API 封禁攻击源 IP + 防火墙 API 边界封禁。

封禁有效期 24–48 小时，支持白名单。

响应撤回、应答替换、操作回滚（联动业务系统）。

4.4.4 反馈学习
漏判样本自动采集（请求+响应+评分记录）。

增量学习更新 XGBoost，影子模式验证，热加载切换。

人工确认兜底：低风险自动处理，高风险人工确认。

4.5 可解释性与告警降噪
4.5.1 可解释性
特征贡献排序：XGBoost pred_contribs 原生归因（+0.1–0.3ms）。

决策路径追溯：记录命中规则、各层评分、最终决策触发层。

反事实解释：扰动测试，告诉分析师"去掉哪个字符会放行"。

4.5.2 告警降噪
同源聚合：同 IP 短时间多次告警合并。

同类型聚合：同攻击类型、同目标 URL 合并。

攻击链关联：多阶段攻击关联为一条事件。

分级推送：P0 立即通知、P1 实时推送、P2 每小时汇总、P3 仅记录。

实现：Redis 滑动窗口，不增加实时链路负担。

4.6 业务逻辑适配
业务标签注入：业务线标识、接口敏感级别、调用方身份、历史行为基线。

通过 API 网关/服务网格注入 Header，WAF 读取后作为额外特征。

同一请求在不同业务上下文下得到不同风险评分。

CPU 开销：特征拼接和推理几乎无额外开销。

4.7 版本管理与系统降级
4.7.1 版本管理
模型版本号：xgboost_v20261015_001.onnx，记录训练数据、特征、超参数版本。

影子模式并行：新模型与生产模型并行，记录评分差异。

灰度切换：10% → 50% → 100%，每阶段观察 24 小时。

一键回滚：保留最近 5–10 个版本，秒级回滚。

4.7.2 系统降级
场景	降级策略
AI 超时	单次推理 >10ms，跳过 AI 层，仅规则+IP 黑名单
模型加载失败	自动切换纯规则模式，通知运维
CPU 过载	>85% 持续 30s，关闭 Isolation Forest，仅保留 XGBoost+规则；回落至 70% 以下恢复
规则引擎兜底	始终保留精简 OWASP CRS 核心规则
原则：WAF 可用性优先于检测率。

4.8 协议适配与合规治理
4.8.1 协议适配
TLS 终止：WAF 作为 TLS 终止点，后端内部 HTTP，使用 rustls。

HTTP/2：适配 HPACK 和帧结构。

WebSocket：握手阶段 + 消息帧持续检测。

gRPC/Protobuf：业务侧拦截器集成检测逻辑。

4.8.2 合规治理
数据最小化：只提取必要特征，不存储原始响应体。

脱敏存储：敏感字段用星号替换后再写入日志。

访问控制：响应体日志仅安全团队可查看，操作留痕。

保留期限：90 天自动删除。

审计接口：记录敏感日志查看行为。

4.9 运维监控与容量规划
4.9.1 监控指标
性能：单请求延迟 P50/P95/P99、QPS、CPU 使用率（P/E 核）、内存、各层耗时占比。

质量：误报率、漏报率、模型评分分布、有效告警数。

容量预警：QPS > 800 扩容预警、P99 > 10ms 性能预警、CPU > 80% 降级预案。

4.9.2 可视化
Grafana + Prometheus。

Node Exporter 采集 CPU/内存，WAF 埋点上报业务指标。

额外开销约 2–5%。

Windows 下用 windows_exporter 替代 Node Exporter。

4.10 人机协同工作流
查看聚合后的告警事件（非原始告警）。

查看 AI 可解释性信息（特征贡献、决策路径）。

快速判断：确认攻击 → 自动封禁；确认误报 → 反馈模型；不确定 → 标记待查。

每周 review 误报/漏报反馈，决定是否触发模型更新。

反馈闭环：告警详情页提供"标记误报""标记漏报""确认攻击"按钮，自动写入反馈库并触发处理流程。

五、AI 训练体系
5.1 数据来源
公开数据集打底：CSIC 2010、HTTP Params 2015。

生产流量为主：WAF 日志中 action=blocked 为攻击样本，action=allowed 为正常样本（需脱敏）。

合成增强补缺：GAN 变异、规则变异生成对抗样本（LLM 生成离线执行）。

5.2 样本不平衡处理
只在训练集上做 SMOTE-Tomek 重采样，测试集保持原始分布。

结合代价敏感学习，给漏报和误报设置不同惩罚权重。

5.3 特征工程：双通道特征
结构化特征通道：请求方法、URI 长度、参数数量、特殊字符统计、字母频率、payload 长度等。

嵌入表示通道：字符级/词级 Embedding（Word2Vec、FastText）。

通过注意力融合机制结合。

5.4 模型选型阶梯（CPU-only 精简版）
阶梯	模型	职责	CPU 延迟
第一层	XGBoost	SQLi、XSS、命令注入等多分类	1–3ms
第二层	Isolation Forest	未知威胁兜底	0.035ms/样本
~~第三层~~	~~CNN-BiLSTM~~	CPU 环境放弃	—
5.5 对抗训练
将 OWASP CRS 规则作为输入特征，混入 10–20% 对抗样本训练 XGBoost。

可提升检测率最高 30%，对抗鲁棒性提升 85%。

使用 GAN 或规则变异生成对抗样本，离线执行。

5.6 持续学习闭环
误报反馈学习：安全运营标记误报后，自动更新模型。

概念漂移检测：监控生产错误率，超阈值触发再训练。

增量学习：使用 partial_fit 或回放缓冲区，避免灾难性遗忘。

上线策略：观察模式 → 影子验证 → 灰度切换 → 生产。

5.7 AI 攻击对抗方案
5.7.1 攻击样本生成
方法	说明	CPU 适用性
GAN-based	GSQLi 等，生成器/判别器对抗	✅ 推荐
LLM 驱动	GenXSS、AutoWAFuzzer，绕过率高	❌ 离线执行
规则变异	AdaRode，变异元规则+采样	✅ 最优
5.7.2 对抗训练
将对抗样本混入训练集，提升 XGBoost 鲁棒性。

采用语义泛化策略：聚类攻击样本族，生成泛化规则，而非逐样本修补。

参考 ModSec-AdvLearn：检测率提升最高 30%，鲁棒性提升 85%。

5.7.3 运行时防御
六阶段安全流水线：遥测摄入 → 数据清洗 → AI 候选规则生成 → 治理回测 → 影子验证 → 分级部署。

原则：未经验证的 AI 模型绝不直接接触实时流量。

六、基线建立与维护
6.1 动态基线构建
以 "ServerGroup + URL" 为主键，用 Redis 实时维护请求体大小、频率等均值与峰值。

覆盖工作日/休息日、业务周期、促销活动等场景。

6.2 多维特征建模
访问频率、请求路径、会话逻辑、User-Agent、鼠标轨迹、点击间隔等。

API 场景额外关注参数数量、长度、JSON 结构。

6.3 冷启动与学习期
新业务接入需 24–36 小时建立初步基线。

学习期内 AI 引擎设为观察模式，只记录评分，不拦截。

6.4 基线更新
采用滑动窗口（如过去 7 天）重新计算基线。

定期检测概念漂移，自动触发基线更新。

七、CPU-only 环境性能优化
7.1 推理引擎
将 XGBoost 和 Isolation Forest 导出为 ONNX 格式。

使用 ONNX Runtime CPU 执行提供者，获得图优化和算子融合加速（约 1.7 倍）。

避免 INT8 量化（树模型收益有限，x86 上可能变慢）。

7.2 线程与核心绑定
ONNX Runtime 线程数设置为物理核心数（12），避免超线程开销。

P 核（性能核）：分配给延迟敏感模块（正则、XGBoost、请求转发）。

E 核（能效核）：分配给后台任务（事件队列、日志、Isolation Forest 批量推理）。

Linux 下用 taskset 绑定核心；Windows 下用 SetProcessAffinityMask。

7.3 模型热加载
新模型文件就绪后，通过信号（Linux SIGHUP / Windows 命名事件）触发管道重建，无需重启服务。

7.4 预期性能
指标	数值
单请求延迟	3–5ms
吞吐量	800–1500 QPS
峰值内存	< 500MB
500 QPS 下 CPU 占用	2–3 个物理核心
八、技术栈与跨平台工具链
8.1 技术栈
层面	技术
数据面	Rust
控制面/离线训练	Python 3.10+
推理引擎	ONNX Runtime
缓存/黑名单	Redis
监控	Prometheus + Grafana
8.2 Rust 跨平台工具链
8.2.1 安装
Linux：

bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
Windows：

powershell
winget install --id Microsoft.VisualStudio.Community
然后从 rust-lang.org 下载 rustup-init.exe，选择 x86_64-pc-windows-msvc target。

重要约束：ort crate 在 Windows 上仅支持 x86_64-pc-windows-msvc，整个项目在 Windows 上必须用 MSVC 工具链构建。

8.2.2 跨平台条件编译
rust
#[cfg(target_os = "linux")]
fn platform_specific() { /* Linux 实现 */ }

#[cfg(target_os = "windows")]
fn platform_specific() { /* Windows 实现 */ }
8.2.3 核心依赖
功能	Crate	跨平台支持
异步运行时	tokio	Linux ✅ Windows ✅
ONNX 推理	ort	Linux ✅ Windows ✅（需 MSVC）
Redis	redis 或 redis-oxide	Linux ✅ Windows ✅
正则匹配	hyperscan 或 regex	Linux ✅ Windows ✅
序列化	serde + serde_json	Linux ✅ Windows ✅
日志	tracing + tracing-subscriber	Linux ✅ Windows ✅
HTTP 解析	httparse 或 hyper	Linux ✅ Windows ✅
TLS	rustls	Linux ✅ Windows ✅
8.2.4 平台差异处理
参考 Zenith 的 feature-gated 设计：

Linux：启用高性能特性（AF_XDP、eBPF、io_uring），Tokio 使用 epoll。

Windows：自动降级到 std::net，Tokio 使用 IOCP。

公共代码：检测逻辑、模型推理、评分决策、Redis 交互保持平台无关。

8.2.5 构建策略
方案一：双平台原生构建（推荐）。在 Linux 和 Windows 上分别安装 Rust 工具链和 MSVC 构建工具，各自原生构建。这是最可靠的方式，尤其对于依赖 ONNX Runtime 的项目。

方案二：CI/CD 自动构建。

yaml
jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/checkout@v2
      - name: Install Rust
        run: rustup default stable
      - name: Build
        run: cargo build --release
      - name: Run tests
        run: cargo test --release
8.2.6 打包分发
Linux：.deb（cargo-deb）、.rpm（cargo-rpm）、AppImage（cargo-packager）。

Windows：.exe（NSIS）、.msi（WiX Toolset），通过 cargo-packager 统一生成。

8.3 可参考的 Rust WAF 项目
项目	特点
Zenith（齐天）	L2→L7 全栈数据面，Linux 用 AF_XDP/eBPF/io_uring，Windows 降级到 std::net，feature-gated 设计
Zark WAF	模块化高性能引擎，支持 Nginx/Apache2/HAProxy/IIS
synapse-waf	基于 Cloudflare Pingora，237 条生产规则
coraza-rs	OWASP Coraza WAF 的 Rust 绑定，兼容 ModSecurity SecLang 规则
九、WAF 详细架构设计
9.1 插件化管道
每个检测能力为可加载/禁用的插件（Rust trait 对象）。

管道按阶段执行，返回 ALLOW / BLOCK / MONITOR / SCORE。

通过 module_factory 闭包动态加载，支持热重载。

9.2 模块职责
模块	职责
IP 黑名单	纯内存查找，支持自动过期和白名单
滑动窗口限速	Redis 计数器
正则规则匹配	Hyperscan/regex，线性时间
XGBoost 分类	ONNX Runtime（ort crate）
Isolation Forest	ONNX Runtime
灰区语义分析	仅对评分 40–70 的请求触发
9.3 部署模式
边缘 WAF（反向代理），TLS 终止点。

后端应用仅接受来自 WAF 的流量。

十、实施路线图与优先级
阶段	任务	优先级
第一阶段	可解释性、告警降噪、系统降级、运维监控	P0
第二阶段	版本管理、业务适配、黑名单联动、IP 评分	P1
第三阶段	漏判补救、对抗训练、合规治理	P2
第四阶段	协议适配、持续学习闭环、人机协同优化	P3
建议节奏：每周离线生成对抗样本 → 增量更新 XGBoost → 影子验证 24h → 切换生产。CPU 空闲时执行离线任务，实时链路保持轻量。

十一、开发环境准备清单
11.1 Linux 端
安装 rustup、build-essential。

安装 ONNX Runtime 的 Linux 预编译库。

如需交叉编译：mingw-w64 + rustup target add x86_64-pc-windows-gnu。

安装 Redis、Hyperscan（或使用 regex crate 替代）。

11.2 Windows 端
安装 Visual Studio C++ Build Tools（MSVC 工具链，选择"使用 C++ 的桌面开发"）。

安装 rustup（选择 x86_64-pc-windows-msvc target）。

安装 ONNX Runtime 的 Windows 预编译库。

安装 Redis（Windows 版或 WSL2 中运行）。

11.3 Python 控制面（双平台通用）
Python 3.10+。

xgboost、scikit-learn、onnx、onnxruntime、redis-py、pandas、numpy。

用于模型训练、对抗样本生成、威胁情报同步。

十二、风险与依赖
12.1 技术风险
风险	影响	缓解措施
ONNX Runtime Windows 兼容性	构建失败	强制使用 MSVC 工具链，CI 双平台验证
CPU 过载导致延迟上升	P99 超标	多级降级策略，CPU 阈值触发
模型漂移	检测率下降	概念漂移检测 + 定期再训练
对抗样本绕过	漏判	对抗训练 + 运行时六阶段流水线
Redis 单点故障	黑名单/限速失效	Redis 高可用部署 + 本地缓存兜底
12.2 外部依赖
ONNX Runtime 预编译库（Linux/Windows）。

Redis 服务。

威胁情报 API（AbuseIPDB、CrowdSec、VirusTotal、ThreatBook、CriminalIP）。

OWASP CRS 规则库。

十三、验收标准
类别	验收项	标准
性能	单请求延迟 P99	< 10ms
性能	吞吐量	800–1500 QPS
性能	峰值内存	< 500MB
质量	误报率	< 3%
质量	零日攻击检测率	> 70%
功能	已知攻击检测	SQLi/XSS/命令注入/路径遍历均可检出
功能	未知威胁兜底	Isolation Forest 正常触发
功能	漏判补救	响应体分析 + 日志关联 + 自动响应闭环
功能	IP 评分与封禁	多源情报融合 + 分级封禁 + 自动解封
功能	系统降级	AI 超时/模型失败/CPU 过载均可降级
功能	可解释性	特征贡献 + 决策路径 + 反事实解释
功能	跨平台	Linux + Windows 双平台原生构建运行
合规	数据最小化	不存储原始响应体，敏感字段脱敏
合规	保留期限	90 天自动删除
运维	监控可视化	Grafana + Prometheus 全指标覆盖
十四、总结
本方案以 Rust 构建跨平台数据面核心，以 Python 驱动离线 AI 训练，在纯 CPU（i5-12500H）环境下实现：

检测引擎：XGBoost + Isolation Forest，通过 ONNX Runtime 优化推理性能。

黑名单管理：Redis + 布隆过滤器 + TTL/LRU，突破容量限制。

IP 危险性评分：连续风险评分驱动 WAF 与防火墙协同封禁。

漏判补救：响应体分析 + 告警日志关联 + 自动响应 + 反馈学习。

跨平台：Linux 用高性能特性（io_uring、epoll），Windows 降级到 IOCP/std::net，业务逻辑平台无关。

工程完备性：可解释性、告警降噪、业务适配、版本管理、系统降级、协议适配、合规治理、运维监控、人机协同。

系统可在 Linux 和 Windows 双平台原生构建部署，单请求延迟 3–5ms，吞吐量 800–1500 QPS，满足中小型业务的 WAF 防护需求。