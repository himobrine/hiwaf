# S4 / 工作项 F：采集数据面（`waf-collector`）

Pingora 反向代理 + **HTTP/流级采集**。这是工作项 F 第一约束（**access log 没有请求体**）的解药：
`request_body_filter` 能拿到**完整请求体**，而这正是模型最需要的特征（§8.6.5 实测：CSIC 异常带 body 的
9,977 条里**带 body 命中 1,903 / 去掉 body 命中 0**）。

## 它不做什么（比做什么更重要）

| 不做 | 原因 |
|---|---|
| **不打标签** | 真实流量的攻击没有标签。用内容正则打标 = 把要替换掉的那套规则抄进训练集（循环论证），还会把规则漏掉的新型攻击标成良性。标签由 `python/collect_http_log.py` 按**出处**决定 |
| **默认不阻断** | 默认 `--block-mode off` 只采集；`dry_run` 把判定写进 `pred` 但**不拦截**；只有 admin 显式切到 `enforce` 才会在命中 `block` 时返回 403。要拦必须先有**真实本地良性流量**标定阈值；否则就是拿公共卫生数据硬调参（项目已否掉这条路）。判定逻辑本身在 `waf_ai_proto::decision`，与本代理共用同一份 |
| **不静默丢数据** | 队列满/写盘失败都会**打日志并计数**；良性池被悄悄污染比少采几条危险得多 |

## 端到端管线

```text
客户端 ──► waf-collector  ──► 真实后端
              │
              └─► traindata/proxy/raw-*.jsonl        （原始，**无 label**）
                        │
                        ├─► python/collect_http_log.py --format jsonl --provenance auto \
                        │        --canary-prefix /admin.php --redteam-window <START,END> --keep-body ...
                        │   ──► traindata/local/*_benign.jsonl / *_attack.jsonl（label 来源可审计）
                        │        （`pred` 模型输出在此**结构性消失**，不可能变成标签）
                        ├─► --block-mode dry_run/enforce：规则+模型融合判定写入 pred
                        │      （dry_run 只记录；enforce 命中 block 返回 403）
                        └─► 流级通道（dur_ms / bytes_in / bytes_out / src_ip / status）
```

* HTTP 通道用 `method/path/query/body` + 元数据；
* 流级通道用 `dur_ms / bytes_in / bytes_out / src_ip / src_port / status`。

**一个采集点同时产出两路** —— 这正是 §8.7.5 选 Proxy 近似的理由：同一个上下文里既拿到
应用层 header/body，又顺手拿到连接时长与上下行字节数，不需要第二个采集点
（eBPF 在 Windows 不可用，NetFlow 看不到应用层）。

## 构建与运行

```bat
cd F:\waf\proxy
call build.bat build --release
```

Linux（需要 gcc/make/cmake/ninja）：

```bash
cd waf/proxy
./build.sh build --release
```

`build.bat` / `build.sh` 会自动找 MSVC/cargo、设置 `CMAKE_GENERATOR=Ninja`，并把
`CARGO_TARGET_DIR` 统一到共享缓存（Windows 优先 `E:\waf-target`，否则
`%LOCALAPPDATA%\waf-cargo-target`；Linux `~/.cache/waf-cargo-target`）。
一键安装的 `-WithRust` / `--with-rust` 会调用同一套脚本。

构建成功后脚本会把 `waf-collector[.exe]` 复制到仓库 `bin/`，控制台优先从那里加载
（`bin/waf-collector.exe` / `bin/waf-collector`）。**重建前先停止采集器**，否则 Windows
上 exe 被占用，复制只会警告。

```bat
:: 本地靶场：上游先用 phpStudy/DVWA 或任意后端
:: 单路由（旧写法仍兼容）
call build.bat run --release -- ^
    --listen 127.0.0.1:6188 ^
    --upstream 127.0.0.1:80 ^
    --out ..\traindata\proxy

:: 多端口：一个进程监听多个端口，每个端口一个上游
call build.bat run --release -- ^
    --route name=site-a,listen=0.0.0.0:80,upstream=127.0.0.1:8080,tls=0 ^
    --route name=site-b,listen=0.0.0.0:8081,upstream=127.0.0.1:8082,tls=0 ^
    --block-mode dry_run ^
    --out ..\traindata\proxy
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `--route name=<n>,listen=<addr>,upstream=<addr>,tls=0\|1` | — | 一条路由，**可重复**。多路由共用一个进程（共享写盘队列/模型/规则/指标），每条路由独立监听与上游 |
| `--listen` | `0.0.0.0:6188` | 单路由监听地址（未给 `--route` 时使用） |
| `--upstream` | `127.0.0.1:8080` | 单路由上游地址 |
| `--upstream-tls` | 关 | 单路由上游使用 TLS |
| `--block-mode` | `off` | `off` 纯采集 / `dry_run` 只记录 / `enforce` 命中 block 返回 403 |
| `--score` | — | 旧开关，等价于 `--block-mode dry_run`（显式 `--block-mode` 优先） |
| `--supervised-block` / `--no-supervised-block` | 开 | 模型命中是否可单独阻断。关掉后模型命中只降级为 `alert`（分数/证据照常落盘），只有规则通道能返回 403 |
| `--out` | `../traindata/proxy` | 原始记录目录（**存在真实业务数据，注意访问权限与保留期**） |
| `--body-keep` | 65536 | 单请求**落盘** body 上限（超出标记 `body_truncated=true`） |
| `--body-limit` | 1048576 | 单请求**缓冲**硬上限（防大文件上传打爆内存） |
| `--headers-keep` | 8192 | 请求/响应头**落盘**上限（按 `name: value\r\n` 规范化字节计数，只保留完整头对） |
| `--resp-body` | `alert` | 响应体采样：`alert` 只存最终 alert/block；`all` 全存；`off` 不存（见下方例外） |
| `--resp-body-keep` | 65536 | 响应体**落盘**上限（原始 wire bytes，压缩响应存压缩字节） |
| `--file-size-mb` | 256 | 单文件轮转大小 |
| `--channel` | 8192 | 写队列容量；满了**丢记录并计数**，绝不阻塞转发 |
| `--no-body` | — | 隐私模式：只留元数据 |
| `--artifacts` | `../python/artifacts` | 模型产物目录（`decision_policy.json` + 两个 ONNX + `xgb_trees.json` + `feature_names_v2.json`） |
| `--stats-out` | 关 | 运行指标 JSON（控制台轮询；含 written/dropped/actions/stale 判定依据） |
| `--stats-interval` | 60 | 指标刷新周期（秒）；启动时立即写一次 |

### 怎么让业务流量走代理（推荐：反向代理前置）

```text
客户端 ──► waf-collector:6188 ──► 真实后端:80
              └─► traindata/proxy/raw-*.jsonl
```

1. 把客户端的访问地址改成采集器端口（或让 nginx 前置转发到采集器）；
2. 用 `--upstream` 指向真实后端；
3. 验证：`curl -i http://127.0.0.1:6188/` 返回后端内容，且 `raw-*.jsonl` 多一条记录。

**多端口 / 多站点**：一个采集器进程可以监听多个端口（`--route` 重复），每条路由独立
监听、独立上游，共享同一个写盘队列/模型/规则/指标文件；记录里的 `route` 字段标明命中哪条路由。
注意：如果要求**客户端 URL 不变**，就必须让 WAF 占用原业务端口，把真实后端挪到其他端口
（例如 phpStudy 80 → 8080，WAF 监听 `0.0.0.0:80 → 127.0.0.1:8080`）。Windows 上监听
80/443 需要管理员权限；防火墙放行需自行配置（本程序不改系统防火墙）。

**真实拦截（`--block-mode enforce`）**：命中 `block` 时返回 403 + 简短页面。
无 body 的请求（GET/HEAD 等）在请求头阶段就判定，**上游完全收不到请求**；有 body 的请求
必须等 body 收齐（或达到 `--body-limit`）才能判定，Pingora 会先发请求头再流 body，
所以 body 类拦截时**上游可能已收到请求头、但收不到 body**。这是流式反向代理的固有限制。

**模型只告警、规则才阻断（`--no-supervised-block`）**：监督模型在 CSIC 上标定，跨分布到本地
业务可能系统性误报（实测本机 sqli-labs：任何 `?id=` 的 GET 都被判成 `cmdi` ≈ 0.999，阈值 0.6998）。
关掉这个开关后，模型命中只写 `action=alert`（分数、穿阈、SHAP、规则证据都保留），
**只有规则通道达到 `min_weight_to_block` 才 403**；规则命中时仍是 `block`。
已知缺口：`sqli_comment_tail` 的 `(--|#|/\*)\s*$` 要求注释符在文本结尾，所以 POST 表单
`id=1'--+&submit=Submit` 不命中（GET 的 `?id=1'--+` 命中）。

完整步骤、nginx 示例与故障排查见 `SETUP.md` §8.2 / §8.7。

**HTTPS 限制**：监听侧是纯 TCP，**不做 TLS 终止、不处理 CONNECT**。HTTPS 业务必须在
nginx/Caddy 终止 TLS 后转 HTTP 给采集器，否则只能看到 CONNECT 元数据、拿不到 body。
系统代理/PAC 同理，只适用于能解密的 HTTP。

### 控制面接口（`python/service`）

控制台「采集代理」页（`/proxy`）通过以下接口管理采集器；配置存 `app_settings` 的
`proxy.*` 键，**保存后需启动/重启才生效**：

| 方法 | 路径 | 权限 | 作用 |
|---|---|---|---|
| GET | `/api/proxy/status` | viewer | 进程、指标、输出目录、二进制、告警 |
| GET | `/api/proxy/config` | viewer | 保存值 + 生效值 + `restart_required` |
| PUT | `/api/proxy/config` | admin | 白名单校验后落库 |
| POST | `/api/proxy/start` | admin | 启动（端口占用/已在跑返回 409） |
| POST | `/api/proxy/stop` | admin | 停止；`{"force":true}` 用于 PID 复用 |
| POST | `/api/proxy/restart` | admin | 停止后重启 |
| GET | `/api/proxy/log?tail=200` | analyst | 托管日志尾部 |

安全边界：二进制只从 `WAF_COLLECTOR_BIN` 或固定候选路径解析，不接受请求传入；参数逐项
白名单校验；`--out` 固定 `traindata/proxy`、`--stats-out` 固定控制台指标文件；所有写操作
写审计。`out_dir` 不允许在界面改，是因为控制台 ingest 只扫固定目录。

### 请求/响应取证包落盘 schema

每条 raw 记录在原有训练字段之外，增加**请求头/响应头/响应体**。约束是：**不能破坏
`collect_http_log.parse_jsonl`**，因此顶层 `body` 仍是文本，精确字节另放 `body_b64`。

```json
{
  "ts": 1792582006896,
  "http_version": "HTTP/1.1",
  "headers": [["host", "127.0.0.1"], ["authorization", "Bearer ..."]],
  "headers_total_bytes": 167, "headers_stored_bytes": 167, "headers_truncated": false,
  "body": "hello",
  "body_b64": "aGVsbG8=",
  "body_is_binary": false,
  "body_sampled": true,
  "body_reason": "sampled",
  "body_len": 5,
  "body_truncated": false,
  "response": {
    "captured": true, "http_version": "HTTP/1.1", "status": 200,
    "headers": [["content-type", "text/plain"]],
    "headers_total_bytes": 176, "headers_stored_bytes": 176, "headers_truncated": false,
    "sampling_mode": "all", "body_sampled": true,
    "body": {"b64": "ZWNobzpoZWxsbw==", "wire_bytes": 10, "stored_bytes": 10, "truncated": false},
    "body_reason": "sampled", "body_wire_bytes": 10, "body_truncated": false
  }
}
```

* **请求体**：文本时 `body` 是原文，同时给 `body_b64` 精确字节；二进制（按 Content-Type
  或 UTF-8/空字节判定）时 `body=""`、`body_is_binary=true`、`body_len>0`，只读 `body_b64`。
  `--no-body` 时 `body_b64` 省略、`body_reason=collect_body_off`。
* **响应体**：`response.body` 存的是**原始 wire bytes**（可能是 gzip/br/zstd 压缩流），
  默认按 `--resp-body alert` 只采 alert/block；`all` 用于取证/联调；`off` 关闭。
  启用判定（`block_mode != off`）时即使 `off` 也缓冲至 64KB：评分失败时以 `body_reason=score_unavailable`
  落盘留证，并计数 `resp_body_off_overrides`；未启用评分则 `off` 不缓冲。
* **头**：`headers` 是有序数组，保留重复头；顺序是 Pingora 解析后的 `HeaderMap` 顺序，
  **不是 wire order**。字节口径为 `name: value\r\n`（不含起始行），重复头分别计数；
  `headers_total_bytes` 是截断前，`headers_stored_bytes` 是实际保留，`headers_truncated`
  表示是否丢过完整头对（超 8KB）。
* **响应侧只做人工复核**：响应头/体用于取证，不参与规则匹配，也不新增响应侧规则作用域。
* **轮转**：UTC 跨天或达到 `--file-size-mb` 时新建 `raw-YYYYMMDD-NNNNN.jsonl`；
  旧文件名继续可读。

> 原始报文中的 Cookie/Authorization/Set-Cookie 是敏感数据。控制台默认把敏感头值逐字符显示为
> `*`；只有显式「显示敏感值」才重新读取并写审计；90 天保留清理见 `python/service/README.md`。

> **构建缓存放在 `E:\waf-target`**：F: 盘几乎满了，而 `ort`(ONNX Runtime) 的编译产物很大。
> `build.bat` 把 `CARGO_TARGET_DIR` 指到 `WAF_CARGO_TARGET`（默认 `E:\waf-target`），
> 且 `rust/` 与 `proxy/` **共用同一个目录** —— 于是 `ort` 只编译一次，而不是每个 crate 各编一次。
> 想改位置就设 `WAF_CARGO_TARGET`；`python/p8_proxy_e2e.py` 会按环境变量/默认值自动找到采集器。

### `pred` 字段是什么（以及不是什么）

`--block-mode dry_run|enforce` 时每条记录多一个 `pred`：

```json
"pred": {"action":"allow","supervised_score":0.0112,"supervised_threshold":0.699765,
         "supervised_flagged":false,"zero_day_score":-3.14,"zero_day_threshold":-7.262677,
         "zero_day_score_crossed":false,"zero_day_flagged":false,"zero_day_enabled":false,
         "attack_label":0,
         "shap_topk":[{"feature":"sql_weak_r","value":0.0,"contribution":-0.42}],
         "artifacts":".../python/artifacts","dry_run":true,"enforced":false}
```

* `dry_run=true` 表示本次判定只写记录；`enforced=true` 表示这次 `action=block` **真的返回了 403**
  （只有 `enforce` 模式才可能为 true）。顶层 `route` 标明命中的路由。

* `attack_label` 是 argmax（**只作攻击类型归类**，不参与判定）；名称映射在
  `decision_policy.json.supervised.labels`，由控制面解释。
* `shap_topk` 是 TreeSHAP Top-8（对预测类），**诊断/可解释性用，不参与判定**。
  需要 `xgb_trees.json` + `feature_names_v2.json`；缺任一个就为空（不报错、不影响判定）。
  代价约 **0.5 ms/请求**（2000 棵树），仍在 `logging` 阶段，不占真实请求延迟。

* **不是标签**。下游 `collect_http_log.py` 的 `parse_jsonl` 只保留已知键，`pred` 在标注产物里
  **结构性消失** —— 模型输出不可能变成训练标签（这是刻意的，见 `p8_proxy_e2e.py` 的断言）。
* **不是验收指标**。上线模型训练集带 body 的记录是 **0 条**，拿它对真实流量算的分数只能当诊断；
  阈值必须在真实本地良性留出流量上重标定（`python/thresholds.py --pool file:...`）。
* 判定在 `logging` 阶段做（body 已收齐、**不占用真实请求延迟**）——`off`/`dry_run` 是这种情况；
  `enforce` 必须在转发前判定（无 body 在请求头阶段，有 body 在 body 收齐后），会带来相应延迟。
  `ort::Session::run` 是 `&mut self`，故用 `Mutex` 串行化，需要并发再上会话池。
* 判定/加载失败在 `off`/`dry_run` 下**只降级为不记录 `pred`**，不影响转发；模型加载不了就退化成纯采集（打日志）。
  **`enforce` 下加载失败会直接启动失败**（避免“以为在拦、其实没拦”）。

### 判定代码为什么在 `rust/`

`rust/` 现在同时产出 lib（`waf_ai_proto`）与 bin（`waf-ai-proto` 门禁程序），
本代理通过 path 依赖复用同一份 `features.rs` / `decision.rs`。**复制一份判定逻辑是禁止的**
—— 复制必然漂移，200×80 逐位门禁也就失去意义。

## 怎么拿到"真实的攻击 body"（对应 §8.7.2 的决策）

1. **蜜罐路径**：在代理上挂一个假后台（如 `/admin.php`），公网扫描器每天会送真实攻击 body。
   收集后用 `collect_http_log.py --provenance auto --canary-prefix /admin.php` 标注。
   ⚠️ 假后台必须是**独立路径**且**不接真实后端**（或接到一个只会返回 404 的静态目录），
   别把它接到真实管理系统上。
2. **红队自测**：Burp/SQLmap 打本地 DVWA，用 `--redteam-window` 标出你操作的时段
   （来源 IP 是 `127.0.0.1`，与浏览器同源，IP 规则区分不了）。
3. **良性流量**：本机浏览器的真实访问（这是最难的一环，只能慢慢攒）。

## 已知取舍与风险（如实标注）

* **下游默认不落 body**：`collect_http_log.py` 出于隐私默认清空 body，训练/评估要显式加 `--keep-body`。
  别以为代理采到 body 就自动进数据集。
* **Windows 属上游 "community best effort"**（Linux 是 tier 1）。本 crate 已在 Windows x86_64 MSVC
  编译+运行通过，但这属于"已证明可行"，不是"官方支持平台"，须纳入回归门禁。
* **版本必须 ≥0.9**：0.4.0 在 `pingora-core` 里就有 5 个编译错误（含 Windows 专有
  `UniqueIDType` `usize`/`i32` 不匹配 + `sfv` 依赖漂移）。
* 构建要求：`features = ["proxy","rustls"]`（本机**没有 perl**，OpenSSL 工具链缺失）+
  `CMAKE_GENERATOR=Ninja`（cmake 4.1.2 不认识本机 VS 18/2026）。见 `build.bat`。
* **原始流量含真实业务数据**（query 里有 token/口令的可能）。投产前必须：访问权限收紧、
  保留期明确、必要时用 `--no-body`；下游 `collect_http_log.py --scrub` 会脱敏敏感参数与 IP。
* `bytes_in` 只统计**请求体**字节（不含头），`dur_ms` 是代理视角端到端耗时，都不是内核级精确值
  —— 流级特征用它们做近似足够，但不要当成计费/审计口径。
* **默认不拦截**：`block_mode=off` 纯采集；`dry_run` 只记录；只有显式 `enforce` 才会拦。
  判定失败/模型加载失败在 `off`/`dry_run` 下退化为纯采集，`enforce` 下直接拒绝启动。

## 下一步

1. 判定已在 `dry_run` 下接线；`enforce` 已实现（命中 block 返回 403），但**正式上线前**
   仍应等真实本地良性池攒够、阈值重标定；
2. 攒够 ≥2,000 条真实本地良性后，用 `python/thresholds.py --pool file:...` 替换标定池的作业点；
3. 流级通道按 §8.7.5 的结论（**剔除 `Destination Port`**，跨文件 @1%FPR 仅 29.0%）做旁路信号，
   不做主判定；
4. 判定要并发就上会话池（当前 `Mutex` 串行）；`ort` 常驻会占内存，注意与采集进程的资源配额。
