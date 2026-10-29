#!/usr/bin/env bash
# WAF 控制台一键安装（Linux）。
#
# 默认「控制台优先」：Python 3.10 + venv + 控制面依赖 + 前端构建 + DB/admin 初始化。
# 缺系统依赖时默认用发行版包管理器自动安装；Rust/采集器只在 --with-rust / --full 时构建。
# 详细说明见仓库根目录 INSTALL.md。
#
#   ./install.sh                       # 安装 + 前台启动（Ctrl+C 停止）
#   ./install.sh --no-rust --no-start  # 只装控制台
#   ./install.sh --verify              # 安装后临时启动并跑 smoke
#   ./install.sh --systemd             # 安装并注册 systemd 常驻服务
#
# 退出码：0 成功；1 失败。
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PORT="${WAF_PORT:-8090}"
BIND_HOST="${WAF_HOST:-127.0.0.1}"
WITH_TRAINING=0
NO_VENV=0
NO_FRONTEND=0
NO_RUST=0
WITH_RUST=0
FULL=0
NO_START=0
VERIFY=0
SYSTEMD=0
NO_INSTALL_DEPS=0
DRY_RUN=0
FORCE=0
PIP_INDEX=""
NPM_REGISTRY=""

if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_OFF=""
fi

log()  { printf '\n%s==> %s%s\n' "$C_CYAN" "$*" "$C_OFF"; }
ok()   { printf '%s[ok] %s%s\n' "$C_GREEN" "$*" "$C_OFF"; }
warn() { printf '%s[warn] %s%s\n' "$C_YELLOW" "$*" "$C_OFF" >&2; }
err()  { printf '%s[x] %s%s\n' "$C_RED" "$*" "$C_OFF" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'EOF'
WAF 控制台一键安装（Linux）

用法：
  ./install.sh [参数]

常用参数：
  --port N            控制台端口（默认 8090）
  --host ADDR         监听地址（默认 127.0.0.1；0.0.0.0 会暴露到网络）
  --no-venv           不创建 .venv，直接用当前 Python 3.10
  --with-training     额外安装训练依赖 requirements.txt（体积大）
  --no-frontend       不构建前端，复用已有 web/dist
  --no-rust           跳过 Rust/采集器构建（默认尽力构建）
  --with-rust         强制安装工具链并构建 Rust/采集器
  --full              等价于 --with-rust，且构建失败即退出
  --no-start          只安装，不启动服务
  --verify            安装后临时启动并跑 service.smoke
  --systemd           安装并注册 systemd 服务（/etc/systemd/system/waf-console.service）
  --no-install-deps   缺依赖时只提示，不自动安装
  --pip-index URL     pip 镜像（例如 https://pypi.tuna.tsinghua.edu.cn/simple）
  --npm-registry URL  npm 镜像
  --dry-run           只打印将执行的命令，不改文件
  --force             跳过非关键检查（不会覆盖 DB/密码）
  -h, --help          显示本帮助

环境变量：
  WAF_PYTHON          Python 3.10 解释器路径（发行版没有 python3.10 时使用）
  WAF_CARGO_TARGET    Rust 构建缓存目录（默认 ~/.cache/waf-cargo-target）

示例：
  ./install.sh --no-rust --no-start
  ./install.sh --verify
  ./install.sh --with-rust --port 8091
  sudo ./install.sh --systemd --port 8090
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port)             PORT="${2:-}"; shift 2 ;;
        --host)             BIND_HOST="${2:-}"; shift 2 ;;
        --no-venv)          NO_VENV=1; shift ;;
        --with-training)    WITH_TRAINING=1; shift ;;
        --no-frontend)      NO_FRONTEND=1; shift ;;
        --no-rust)          NO_RUST=1; shift ;;
        --with-rust)        WITH_RUST=1; shift ;;
        --full)             FULL=1; WITH_RUST=1; shift ;;
        --no-start)         NO_START=1; shift ;;
        --verify)           VERIFY=1; shift ;;
        --systemd)          SYSTEMD=1; shift ;;
        --no-install-deps)  NO_INSTALL_DEPS=1; shift ;;
        --pip-index)        PIP_INDEX="${2:-}"; shift 2 ;;
        --npm-registry)     NPM_REGISTRY="${2:-}"; shift 2 ;;
        --dry-run)          DRY_RUN=1; shift ;;
        --force)            FORCE=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  err "未知参数：$1"; usage; exit 1 ;;
    esac
done

case "$PORT" in
    ''|*[!0-9]*) die "端口必须是数字：$PORT" ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    die "端口超出范围：$PORT"
fi
if [ "$BIND_HOST" = "0.0.0.0" ] || [ "$BIND_HOST" = "::" ]; then
    warn "监听 $BIND_HOST 会把控制台暴露到网络；请确保前面有反向代理/防火墙。"
fi
if [ "$DRY_RUN" -eq 1 ]; then
    NO_START=1
    warn "dry-run：只打印命令，不执行安装/写入"
fi

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

PM="none"
if command -v apt-get >/dev/null 2>&1; then
    PM="apt"
elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
elif command -v yum >/dev/null 2>&1; then
    PM="yum"
elif command -v pacman >/dev/null 2>&1; then
    PM="pacman"
fi

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

run_in() {
    local dir="$1"; shift
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] (cd %s && %s)\n' "$dir" "$*"
        return 0
    fi
    ( cd "$dir" && "$@" )
}

need_root() {
    [ "$DRY_RUN" -eq 1 ] && return 0
    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
        die "需要 root 或 sudo 才能安装系统依赖。"
    fi
}

pkg_install() {
    [ "$PM" = "none" ] && die "未识别包管理器（支持 apt/dnf/yum/pacman）；请手动安装后重试。"
    need_root
    case "$PM" in
        apt)
            run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y
            run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf)    run $SUDO dnf install -y "$@" ;;
        yum)    run $SUDO yum install -y "$@" ;;
        pacman) run $SUDO pacman -Sy --needed --noconfirm "$@" ;;
    esac
}

install_base_deps() {
    log "安装系统基础依赖（$PM）"
    case "$PM" in
        apt)    pkg_install python3.10 python3.10-venv python3.10-dev nodejs npm curl ca-certificates ;;
        dnf)    pkg_install python3.10 python3.10-devel nodejs npm curl ca-certificates ;;
        yum)    pkg_install python3.10 python3.10-devel nodejs npm curl ca-certificates ;;
        pacman) pkg_install python nodejs npm curl ca-certificates ;;
        *)      die "未识别包管理器；请手动安装 Python 3.10、Node.js 18+、npm。" ;;
    esac
}

python_ok() {
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 10) else 1)' >/dev/null 2>&1
}

find_python() {
    if [ -n "${WAF_PYTHON:-}" ]; then
        if python_ok "$WAF_PYTHON"; then
            command -v "$WAF_PYTHON" 2>/dev/null || printf '%s\n' "$WAF_PYTHON"
            return 0
        fi
        die "WAF_PYTHON=$WAF_PYTHON 不是 Python 3.10"
    fi
    local candidate
    for candidate in python3.10 /usr/bin/python3.10 /usr/local/bin/python3.10; do
        if command -v "$candidate" >/dev/null 2>&1 && python_ok "$candidate"; then
            command -v "$candidate"
            return 0
        fi
    done
    if command -v python3 >/dev/null 2>&1 && python_ok python3; then
        command -v python3
        return 0
    fi
    return 1
}

python_hint() {
    cat >&2 <<'EOF'
[x] 未找到 Python 3.10。
    Debian/Ubuntu：新版发行版默认没有 3.10，可加 deadsnakes PPA：
      sudo add-apt-repository ppa:deadsnakes/ppa
      sudo apt-get update
      sudo apt-get install -y python3.10 python3.10-venv python3.10-dev
    或者用 pyenv / conda 安装 3.10，然后：
      WAF_PYTHON=/path/to/python3.10 ./install.sh
    Fedora/RHEL：可用 python3.10 包，或用 pyenv 安装后设置 WAF_PYTHON。
EOF
}

node_ok() {
    command -v node >/dev/null 2>&1 || return 1
    command -v npm  >/dev/null 2>&1 || return 1
    node -e 'const m = process.versions.node.split(".").map(Number); process.exit(m[0] >= 18 ? 0 : 1)' >/dev/null 2>&1
}

install_rust_deps() {
    log "安装 Rust 构建工具链（$PM）"
    case "$PM" in
        apt)    pkg_install build-essential cmake ninja-build pkg-config curl ca-certificates ;;
        dnf)    pkg_install gcc gcc-c++ make cmake ninja-build pkgconf-pkg-config curl ca-certificates ;;
        yum)    pkg_install gcc gcc-c++ make cmake ninja-build pkgconfig curl ca-certificates ;;
        pacman) pkg_install base-devel cmake ninja pkgconf curl ca-certificates ;;
        *)      warn "未识别包管理器；请手动安装 gcc/make/cmake/ninja。" ;;
    esac
    if ! command -v cargo >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
        log "安装 Rust（rustup）"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n'
        else
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        fi
    fi
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
}

has_rust_toolchain() {
    command -v cargo >/dev/null 2>&1 || [ -x "$HOME/.cargo/bin/cargo" ] || return 1
    command -v cmake >/dev/null 2>&1 || return 1
    command -v ninja >/dev/null 2>&1 || return 1
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || return 1
    return 0
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
for rel in python/service/app.py web/package.json proxy/Cargo.toml install.sh; do
    [ -f "$ROOT/$rel" ] || die "仓库不完整：缺少 $rel（脚本应放在仓库根目录）"
done

printf 'WAF 控制台一键安装（Linux）\n仓库：%s\n' "$ROOT"

PY=""
if ! PY="$(find_python)"; then
    warn "缺少 Python 3.10"
    if [ "$NO_INSTALL_DEPS" -eq 1 ]; then
        python_hint
        exit 1
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        install_base_deps
        PY="python3.10"
    else
        install_base_deps
        if ! PY="$(find_python)"; then
            python_hint
            exit 1
        fi
    fi
fi
ok "Python 3.10：$PY"

if ! node_ok; then
    warn "缺少 Node.js 18+（含 npm）"
    if [ "$NO_INSTALL_DEPS" -eq 1 ]; then
        die "请先安装 Node.js 18+（https://nodejs.org/ 或 NodeSource）后重试。"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        install_base_deps
    else
        install_base_deps
        if ! node_ok; then
            die "Node.js 安装后仍不可用或版本 < 18；请用 NodeSource/官方二进制安装后重试。"
        fi
    fi
fi
if command -v node >/dev/null 2>&1; then
    ok "Node.js $(node -v)：$(command -v node)"
fi

# venv
VENV="$ROOT/.venv"
if [ "$NO_VENV" -eq 1 ]; then
    VENV_PY="$PY"
    warn "使用当前 Python（--no-venv）：$VENV_PY"
else
    VENV_PY="$VENV/bin/python"
    if [ ! -x "$VENV_PY" ]; then
        log "创建 venv：$VENV"
        run "$PY" -m venv "$VENV"
    fi
fi

log "安装控制面 Python 依赖"
PIP_ARGS=()
if [ -n "$PIP_INDEX" ]; then PIP_ARGS=(-i "$PIP_INDEX"); fi
run "$VENV_PY" -m pip install --upgrade pip ${PIP_ARGS[@]+"${PIP_ARGS[@]}"}
run "$VENV_PY" -m pip install -r "$ROOT/python/requirements-service.txt" ${PIP_ARGS[@]+"${PIP_ARGS[@]}"}
if [ "$WITH_TRAINING" -eq 1 ]; then
    log "安装训练依赖（体积较大）"
    run "$VENV_PY" -m pip install -r "$ROOT/python/requirements.txt" ${PIP_ARGS[@]+"${PIP_ARGS[@]}"}
fi

# 前端
if [ "$NO_FRONTEND" -eq 1 ]; then
    warn "跳过前端构建（--no-frontend），复用 web/dist"
else
    log "构建前端"
    NPM_ARGS=(ci)
    if [ -n "$NPM_REGISTRY" ]; then NPM_ARGS+=(--registry="$NPM_REGISTRY"); fi
    if [ "$DRY_RUN" -eq 0 ] && [ ! -f "$ROOT/web/package-lock.json" ]; then
        NPM_ARGS=(install)
    fi
    run_in "$ROOT/web" npm "${NPM_ARGS[@]}"
    run_in "$ROOT/web" npm run typecheck
    run_in "$ROOT/web" npm run build
fi

log "初始化数据库与 admin"
run_in "$ROOT/python" env PYTHONIOENCODING=utf-8 "$VENV_PY" -m service.bootstrap

# Rust / 采集器
build_rust=0
if [ "$FULL" -eq 1 ] || [ "$WITH_RUST" -eq 1 ]; then
    build_rust=1
elif [ "$NO_RUST" -eq 0 ] && has_rust_toolchain; then
    build_rust=1
fi

if [ "$NO_RUST" -eq 1 ] && [ "$WITH_RUST" -eq 0 ] && [ "$FULL" -eq 0 ]; then
    warn "跳过 Rust/采集器构建（--no-rust）"
elif [ "$build_rust" -eq 1 ]; then
    if ! has_rust_toolchain; then
        if [ "$NO_INSTALL_DEPS" -eq 1 ]; then
            if [ "$WITH_RUST" -eq 1 ] || [ "$FULL" -eq 1 ]; then
                die "Rust 构建需要 cargo + cmake + ninja + C 编译器；请手动安装后重试。"
            fi
            warn "Rust 工具链不完整，跳过构建"
            build_rust=0
        else
            install_rust_deps
            if ! has_rust_toolchain; then
                if [ "$FULL" -eq 1 ]; then
                    die "工具链安装后仍不完整。"
                fi
                warn "Rust 工具链不完整，跳过构建；需要时用 --with-rust"
                build_rust=0
            fi
        fi
    fi
fi

if [ "$build_rust" -eq 1 ]; then
    export WAF_CARGO_TARGET="${WAF_CARGO_TARGET:-$HOME/.cache/waf-cargo-target}"
    export CARGO_TARGET_DIR="$WAF_CARGO_TARGET"
    log "构建 Rust 判定引擎（缓存：$WAF_CARGO_TARGET）"
    rust_failed=0
    if ! run_in "$ROOT/rust" bash ./build.sh build --release; then
        rust_failed=1
        if [ "$FULL" -eq 1 ]; then
            die "Rust 引擎构建失败"
        fi
        warn "Rust 引擎构建失败（继续）"
    fi
    log "构建采集器 waf-collector"
    if ! run_in "$ROOT/proxy" bash ./build.sh build --release; then
        rust_failed=1
        if [ "$FULL" -eq 1 ]; then
            die "采集器构建失败"
        fi
        warn "采集器构建失败（继续）"
    fi
    if [ "$rust_failed" -eq 0 ]; then
        [ -x "$WAF_CARGO_TARGET/release/waf-ai-proto" ] && ok "Rust 引擎：$WAF_CARGO_TARGET/release/waf-ai-proto"
        [ -x "$WAF_CARGO_TARGET/release/waf-collector" ] && ok "采集器：$WAF_CARGO_TARGET/release/waf-collector"
    fi
    if [ ! -x "$WAF_CARGO_TARGET/release/waf-collector" ]; then
        warn "未找到采集器二进制；控制台「采集代理」页会提示缺失"
    fi
else
    warn "未找到完整 Rust 工具链，跳过 Rust/采集器构建；需要时用 --with-rust"
fi

url_host="$BIND_HOST"
if [ "$url_host" = "0.0.0.0" ] || [ "$url_host" = "::" ]; then
    url_host="127.0.0.1"
fi
URL="http://$url_host:$PORT"

summary() {
    printf '\n%s安装完成%s\n' "$C_GREEN" "$C_OFF"
    printf '  控制台     : %s\n' "$URL"
    printf '  接口文档   : %s/docs\n' "$URL"
    printf '  admin 密码 : %s（首次生成；已有库不会覆盖）\n' "$ROOT/python/service/.admin_password"
    printf '  采集代理   : %s -> 登录后「采集代理」页\n' "$URL"
    printf '  启动命令   : cd "%s/python" && "%s" -m service.run --host %s --port %s\n' "$ROOT" "$VENV_PY" "$BIND_HOST" "$PORT"
}

wait_http() {
    local url="$1" timeout="${2:-60}" i=0
    while [ "$i" -lt $((timeout * 2)) ]; do
        if "$VENV_PY" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2).read(1)' "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

install_systemd() {
    local unit_src="$ROOT/deploy/waf-console.service"
    local unit_dst="/etc/systemd/system/waf-console.service"
    [ -f "$unit_src" ] || die "缺少 systemd 模板：$unit_src"
    need_root
    log "注册 systemd 服务：$unit_dst"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] sed 模板 -> %s\n' "$unit_dst"
        printf '[dry-run] systemctl daemon-reload && systemctl enable --now waf-console.service\n'
        return 0
    fi
    local user
    user="${SUDO_USER:-$(id -un)}"
    local esc_root esc_py esc_host
    esc_root="$(printf '%s' "$ROOT" | sed -e 's/[\\&|]/\\&/g')"
    esc_py="$(printf '%s' "$VENV_PY" | sed -e 's/[\\&|]/\\&/g')"
    esc_host="$(printf '%s' "$BIND_HOST" | sed -e 's/[\\&|]/\\&/g')"
    sed \
        -e "s|@ROOT@|$esc_root|g" \
        -e "s|@PYTHON@|$esc_py|g" \
        -e "s|@HOST@|$esc_host|g" \
        -e "s|@PORT@|$PORT|g" \
        -e "s|@USER@|$user|g" \
        "$unit_src" | $SUDO tee "$unit_dst" >/dev/null
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now waf-console.service
    ok "systemd 已启动：systemctl status waf-console"
    printf '  查看日志：journalctl -u waf-console -f\n'
}

verify_smoke() {
    log "临时启动服务并执行 smoke"
    local logdir="$ROOT/python/service/logs"
    mkdir -p "$logdir"
    local out="$logdir/install-verify.out.log"
    local errlog="$logdir/install-verify.err.log"
    ( cd "$ROOT/python" && exec env PYTHONIOENCODING=utf-8 "$VENV_PY" -m service.run --host "$BIND_HOST" --port "$PORT" >"$out" 2>"$errlog" ) &
    local pid=$!
    local rc=0
    if ! wait_http "$URL" 60; then
        err "服务未在 60s 内就绪；查看 $errlog"
        rc=1
    else
        ( cd "$ROOT/python" && PYTHONIOENCODING=utf-8 WAF_CONSOLE_BASE="$URL" "$VENV_PY" -m service.smoke ) || rc=1
    fi
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    if [ "$rc" -ne 0 ]; then
        die "smoke 失败"
    fi
    ok "smoke 通过"
}

if [ "$SYSTEMD" -eq 1 ]; then
    install_systemd
    summary
    exit 0
fi

if [ "$NO_START" -eq 1 ]; then
    summary
    warn "已跳过启动（--no-start）"
    exit 0
fi

if [ "$VERIFY" -eq 1 ]; then
    verify_smoke
    summary
    exit 0
fi

summary
log "启动控制台：$URL（Ctrl+C 停止）"
cd "$ROOT/python"
export PYTHONIOENCODING=utf-8
exec "$VENV_PY" -m service.run --host "$BIND_HOST" --port "$PORT"
