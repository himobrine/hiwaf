# S4 门禁实验：Pingora 能否作为反向代理基座（Windows x86_64 MSVC）

> 这是**门禁实验**（spike），不是产品代码。目的只有一个：在把架构押到 Pingora 之前，
> 先证明它在 PRD 要求的 **Windows x86_64 MSVC** 上能编译、能跑、**能拿到请求体**。

## 为什么需要这道门禁

- 决策是「用 Pingora，不用 hyper 自研」——理由是 body 特征工程需要 `request_body_filter`
  这类 HTTP Body 生命周期钩子，自研 hyper 要自己处理 chunked / keep-alive / 内存池。
- 但 PRD 要求 **Linux + Windows x86_64 双平台**，而 Pingora 官方 README 写明
  **"Linux is our tier 1 environment"**，Windows 支持是 0.4 起社区尽力而为的**实验特性**
  （cloudflare/pingora#342，closed as completed）。
- ⇒ 如果 Windows 编译不过，"选 Pingora"就等于把跨平台要求悄悄废掉。必须先测。

## 本机踩到的三个坑（都不是 Pingora 的错，但都会让人误判成 "Pingora 不行"）

| 现象 | 归因 | 处置 |
|---|---|---|
| `openssl` / `boringssl` feature 需要 Perl + OpenSSL 工具链 | **本机没有 perl**（`where perl` 无输出） | 改用 `features = ["proxy", "rustls"]`，**完全绕开 OpenSSL**。Pingora `default = []`，feature 必须显式选 |
| `libz-ng-sys` 构建失败：`CMake Error: Could not create named generator Visual Studio 18 2026` | cmake-rs 自动探测出本机 VS 是 18/2026，但 cmake 4.1.2 还不认识这个 generator | 用 Ninja 生成器绕开：`set CMAKE_GENERATOR=Ninja`（ninja 在 PATH，配合 vcvars 的 cl.exe 正常）。见 `build.bat` |
| `pingora-core` 自身 5 个编译错误（`id()` 的 `UniqueIDType` 期望 `usize` 却返回 `i32`；`sfv` API 不匹配） | **pingora 0.4.0 的 Windows 兼容性 bug + 依赖漂移**，与本地环境无关 | **换 pingora 0.9.0**（`Cargo.toml` 里锁 `"0.9"`），全部依赖一次通过 |

> ⚠️ `build.bat` 的注释必须是**纯 ASCII**：带中文的 `REM` 行在 LF 行尾下会被 cmd 解析成命令，
> 结果是 `set CMAKE_GENERATOR` 那行没生效、又回到 generator 报错——很容易误判成 "Pingora 不行"。

## 它验证什么

`src/main.rs` 是一个最小可运行代理：`127.0.0.1:6188 -> 127.0.0.1:8080`。

1. **能编译**（Windows MSVC）；
2. **能跑起来并转发**；
3. **`request_body_filter` 能拿到完整 body** —— 这正是选 Pingora 的理由（工作项 F 要 body），
   且带 `BODY_LIMIT = 1 MiB` 截断，防大文件上传打爆内存（真实采集必须做这件事）。

## 用法

```bat
call build.bat run --release
:: 另一个窗口（上游可先用 py -3.10 -m http.server 8080）：
curl -X POST http://127.0.0.1:6188/dvwa/vulnerabilities/sqli/ -d "id=1' OR '1'='1"
```

## 实测结果（2026-10-17，Windows x86_64 MSVC）

编译：`Finished release profile in 1m 17s`，无错误无警告。运行：

```
[spike] Pingora 代理已启动 127.0.0.1:6188 -> 127.0.0.1:8080  (Windows MSVC)
[spike] #1 GET /index.html  ua="probe/1.0"
[spike] body 总计 0 字节，样本 ""
[spike] #2 POST /dvwa/vulnerabilities/sqli/  ua="sqlmap/1.7"
[spike] body 总计 29 字节，样本 "id=1' OR '1'='1&Submit=Submit"
[spike] #3 POST /upload  ua="probe/1.0"
[spike] body 总计 5005 字节，样本 "data=AAAA…"
```

客户端侧看到 `GET → HTTP/1.0 404`、`POST → HTTP/1.0 501`，都是**上游**返回的码 ⇒
请求（含 body）确实被完整转发了。

## 结论

✅ **门禁通过，但版本必须 ≥0.9**。Pingora 可作为基座；上游仍把 Windows 定位为
"community best effort"（Linux 是 tier 1），所以这是"**已证明可行**"而非"官方支持平台"——
该路径应纳入回归门禁。详见 `../REALDATA_EVALUATION.md` §8.7.4 与 §0 结论速览 #27。
