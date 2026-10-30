# 一键安装（Windows / Linux）

> 只想**把控制台跑起来**：用这里的脚本。需要训练模型、复现评估或改 Rust 数据面，
> 再回头看 `SETUP.md` 的对应章节。
>
> 脚本只做「装依赖 → 建 venv → 装 Python 包 → 构建前端 → 初始化 DB/admin →
> （可选）构建 Rust/采集器 → 启动」。**不会覆盖**已有的 `console.db`、`.secret`、
> `.admin_password`，也不会改你的业务数据。

---

## 0. 默认行为

| 项 | 默认值 | 说明 |
| --- | --- | --- |
| 安装范围 | **控制台优先** | 只装 `python/requirements-service.txt`；训练依赖要显式 `--with-training` / `-WithTraining` |
| Python | **3.10.x** | 版本不符会明确报错，不会静默换版本 |
| Node.js | **18+** | 只用于构建前端 |
| 端口 / 监听 | `8090` / `127.0.0.1` | 仅本机可访问 |
| 虚拟环境 | 仓库根 `.venv` | `--no-venv` / `-NoVenv` 可关闭 |
| Rust / 采集器 | **尽力构建** | 工具链完整才构建；缺失只警告。要强制装工具链用 `--with-rust` / `-WithRust` |
| 启动 | **前台启动** | `--no-start` 只安装；Linux `--systemd` 注册常驻服务 |
| 系统依赖 | **自动安装** | 缺 Python/Node 时用 winget（Windows）或 apt/dnf/yum/pacman（Linux）安装 |

产物位置：

- 控制台入口：`web/dist`（由 FastAPI 单端口托管）
- 数据库：`python/service/console.db`
- 初始密码：`python/service/.admin_password`（首次创建 admin 时生成）
- 采集器二进制：`bin/waf-collector.exe`（Windows）/ `bin/waf-collector`（Linux）；
  `proxy/build.bat|sh build --release` 成功后自动复制到这里，控制台优先使用它
- Rust 构建缓存：Windows 默认 `%LOCALAPPDATA%\waf-cargo-target`（作者本机指向 `E:\waf-target`，
  见 `SETUP.md` 附录 A）；
  Linux 为 `~/.cache/waf-cargo-target`

---

## 1. Windows

### 1.1 快速开始

在仓库根目录双击 `install.bat`，或在 cmd / PowerShell 里：

```bat
install.bat -NoRust -NoStart     :: 只安装，不启动
install.bat -Verify              :: 安装后临时启动并跑 smoke
install.bat -WithRust -Port 8091 :: 连 Rust/采集器一起构建，端口 8091
```

`install.bat` 只是入口，真正的逻辑在 `install.ps1`（PowerShell 5.1+）。
脚本会自己请求 UAC 提权来装系统依赖；不想自动装就加 `-NoInstallDeps`。

安装完成后前台启动：

```bat
cd python
..\.venv\Scripts\python.exe -m service.run --host 127.0.0.1 --port 8090
```

浏览器打开 <http://127.0.0.1:8090>，接口文档在 `/docs`。

### 1.2 参数

| 参数 | 作用 |
| --- | --- |
| `-Port 8090` | 控制台端口 |
| `-BindHost 127.0.0.1` | 监听地址；`0.0.0.0` 会暴露到网络 |
| `-NoVenv` | 不建 `.venv`，直接用当前 Python 3.10 |
| `-WithTraining` | 额外安装训练依赖 `python\requirements.txt` |
| `-NoFrontend` | 不构建前端，复用已有 `web\dist` |
| `-NoRust` | 跳过 Rust/采集器构建 |
| `-WithRust` | 强制安装 Rust 工具链并构建 |
| `-Full` | 等价于 `-WithRust`，且构建失败即退出 |
| `-NoStart` | 只安装，不启动 |
| `-Verify` | 临时启动并跑 `service.smoke` |
| `-NoInstallDeps` | 缺依赖只提示，不自动安装 |
| `-PipIndex URL` | pip 镜像，例如 `https://pypi.tuna.tsinghua.edu.cn/simple` |
| `-NpmRegistry URL` | npm 镜像 |
| `-DryRun` | 只打印命令，不改文件 |
| `-Force` | 跳过非关键检查（不会覆盖 DB/密码） |

### 1.3 开机自启（可选）

Windows 脚本**不注册系统服务**，默认前台运行。需要常驻时用「任务计划程序」：

1. 创建任务 → 触发器「登录时」或「启动时」；
2. 操作「启动程序」：
   - 程序：`<repo>\.venv\Scripts\python.exe`
   - 参数：`-m service.run --host 127.0.0.1 --port 8090`
   - 起始于：`<repo>\python`
3. 勾选「不管用户是否登录都要运行」时需要给账号「作为服务登录」权限；
   更简单的做法是「只在用户登录时运行」。

停止：在任务计划程序里结束该任务，或 `taskkill /IM python.exe /F`（会杀掉所有 Python，慎用）。

---

## 2. Linux

### 2.1 快速开始

```bash
chmod +x install.sh          # 首次从 Windows 拷贝过来时可能需要
./install.sh --no-rust --no-start
./install.sh --verify
sudo ./install.sh --systemd --port 8090
```

默认安装完直接前台启动（Ctrl+C 停止）。`--systemd` 会渲染
`deploy/waf-console.service` 到 `/etc/systemd/system/waf-console.service`，
并执行 `systemctl enable --now`。

常用参数与 Windows 一一对应：

```text
--port N              --host ADDR
--no-venv             --with-training
--no-frontend         --no-rust / --with-rust / --full
--no-start            --verify
--systemd             --no-install-deps
--pip-index URL       --npm-registry URL
--dry-run             --force
```

查看服务：

```bash
systemctl status waf-console
journalctl -u waf-console -f
```

### 2.2 Python 3.10

脚本**只接受 3.10.x**。Ubuntu 24.04 / Debian 12 默认没有 3.10，脚本会报错并给提示：

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.10 python3.10-venv python3.10-dev
```

或用 pyenv / conda 装好后显式指定：

```bash
WAF_PYTHON="$HOME/.pyenv/versions/3.10.14/bin/python3.10" ./install.sh
```

Fedora / RHEL 若仓库没有 `python3.10`，同样用 pyenv 或 `WAF_PYTHON`。
脚本不会把 3.11/3.12 当作 3.10 使用。

### 2.3 包管理器

| 发行版 | 安装命令 |
| --- | --- |
| Debian / Ubuntu | `apt-get update && apt-get install -y ...` |
| Fedora / RHEL 8+ | `dnf install -y ...` |
| CentOS 7 等 | `yum install -y ...` |
| Arch / Manjaro | `pacman -Sy --needed --noconfirm ...` |

非 root 且没有 `sudo` 时，脚本会在安装系统依赖前失败；先用 root 装好依赖，
再加 `--no-install-deps` 以普通用户运行。

Rust 工具链在 `--with-rust` / `--full` 下自动安装：发行版包（gcc/make/cmake/ninja）
+ rustup（`https://sh.rustup.rs`）。默认「尽力构建」时，工具链不完整只警告。

---

## 3. 安装脚本做了什么

1. **检查仓库完整性**：`python/service/app.py`、`web/package.json`、`proxy/Cargo.toml`。
2. **找 Python 3.10 / Node 18+**，缺失则按上面的策略安装。
3. **创建 `.venv`**（已存在则复用）。
4. `pip install --upgrade pip` + `pip install -r python/requirements-service.txt`。
5. **前端**：`npm ci`（无 lock 时 `npm install`）→ `npm run typecheck` → `npm run build`。
6. **初始化 DB/admin**：`python -m service.bootstrap`（幂等）。
7. **Rust/采集器**（可选）：`rust/build.sh build --release`、
   `proxy/build.sh build --release`，共用 `WAF_CARGO_TARGET`。
8. **启动**：前台、`--verify` 临时启动跑 smoke、或 `--systemd` 常驻。

`service.bootstrap` 与首次启动等价：

- 只建缺失的表/索引；
- 已有用户时**不覆盖** admin 密码，也不重写 `.admin_password`；
- 首次创建 admin 时，密码来自 `WAF_CONSOLE_ADMIN_PASSWORD` 或随机生成。

---

## 4. 验证

```bash
# 只装不启动
./install.sh --no-rust --no-start

# 临时启动 + API 自检
./install.sh --no-rust --verify
```

`--verify` 会：

1. 后台启动服务，最多等 60 秒；
2. 请求首页确认端口可用；
3. 跑 `python -m service.smoke`；
4. 结束临时进程。

Windows 对应 `install.bat -NoRust -Verify`。

手动验证：

```bat
cd python
set PYTHONIOENCODING=utf-8
set WAF_CONSOLE_BASE=http://127.0.0.1:8090
..\.venv\Scripts\python.exe -m service.smoke
```

```bash
cd ~/waf/python
PYTHONIOENCODING=utf-8 WAF_CONSOLE_BASE=http://127.0.0.1:8090 .venv/bin/python -m service.smoke
```

---

## 5. 常见问题

**端口被占用**

换端口即可：`install.bat -Port 8091` / `./install.sh --port 8091`。
`--verify` 失败时先看 `python/service/logs/install-verify.err.log`。

**winget 不存在**

Windows 10 1809+ 安装「应用安装程序」：<https://aka.ms/getwinget>。
或手动装 Python 3.10 / Node LTS 后加 `-NoInstallDeps`。

**`npm ci` 失败**

`web/package-lock.json` 与 `package.json` 不一致时用 `npm install` 更新 lock，
或加 `--no-frontend` 复用已有 `web/dist`。国内网络可加 `--npm-registry`。

**Rust 构建失败**

默认只警告，不影响控制台。需要采集器时：

```bat
install.bat -WithRust
```

```bash
./install.sh --with-rust
```

仍失败时按 `SETUP.md` §1 检查 MSVC（Windows）或 gcc/cmake/ninja（Linux）。

**监听 0.0.0.0 的风险**

脚本会警告。控制台带账号体系但没有内置 TLS，暴露到公网前请放在
Nginx/Caddy 之后，并配置 HTTPS 与访问控制。

**重复执行会不会覆盖数据**

不会。DB 用 `CREATE TABLE IF NOT EXISTS`；已有 admin 不改密码；
`.secret`（JWT 密钥）只在缺失时生成。`--force` 也不会删数据。

**重置环境（谨慎）**

只删虚拟环境不会动业务数据：

```bat
rmdir /s /q .venv
```

```bash
rm -rf ~/waf/.venv
```

要彻底重来才需要删 `python/service/console.db`、`.secret`、`.admin_password`；
删除前先备份。

---

## 6. 与手工安装的关系

一键安装只是把 `SETUP.md` §12 的命令串起来。需要训练/评估/改 Rust 时，
按 `SETUP.md` 装 `requirements.txt` 并执行对应章节；两套流程共用同一个 `.venv`
和同一个 DB，不会互相破坏。

| 场景 | 命令 |
| --- | --- |
| 只跑控制台 | `install.bat -NoRust` / `./install.sh --no-rust` |
| 控制台 + 训练 | `install.bat -WithTraining` / `./install.sh --with-training` |
| 控制台 + 采集器 | `install.bat -WithRust` / `./install.sh --with-rust` |
| 全量（含失败即退出） | `install.bat -Full` / `./install.sh --full` |
| Linux 常驻 | `sudo ./install.sh --systemd` |

相关文档：`SETUP.md`（完整搭建）、`python/service/README.md`（控制面）、
`web/README.md`（前端）、`proxy/README.md`（采集器）、`rust/README.md`（判定引擎）。
