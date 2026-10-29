"""采集代理（`waf-collector`）控制面：配置持久化 + 进程托管 + 状态。

边界（与 `proxy/README.md`、`SETUP.md` §8 一致）：

* 默认**只采集、不阻断**；`block_mode=enforce` 必须 admin 显式开启。
* 多路由单进程：一个采集器监听多个端口，每个端口映射一个上游。
* 二进制只从 `WAF_COLLECTOR_BIN` 或固定候选路径解析，**不接受请求传入**。
* 参数逐项白名单校验，范围对齐 `proxy/src/config.rs`；`out_dir` / `stats_out`
  固定，避免「代理在写、控制台没事件」。
* 单实例 PID 文件 + 端口探测；服务重启后靠 PID 文件接管，PID 复用需 `force`。
* 所有写操作写审计：`proxy_config_update` / `proxy_start` / `proxy_stop` /
  `proxy_force_stop` / `proxy_restart`。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import config, db

try:  # 可选：有 psutil 时用它校验 PID 身份（防 PID 复用）
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - 服务机未装训练依赖时走降级
    psutil = None  # type: ignore

_LOCK = threading.RLock()
_PROC: Optional[subprocess.Popen] = None

#: host:port。IPv6 用 `[::1]:6188`；host 允许主机名/点分 IPv4。
_ADDR_RE = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):([0-9]{1,5})$")
_BAD_ADDR_CHARS = set(";&|<>`$\"'(){}[]!*\n\r\t ")
_ROUTE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ProxyError(RuntimeError):
    """控制面可预期的错误；`status` 直接映射为 HTTP 状态码。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = int(status)


# --------------------------------------------------------------------------- 配置
def _defaults() -> Dict[str, Any]:
    return dict(config.PROXY_DEFAULTS)


def get_config() -> Dict[str, Any]:
    """保存的配置（缺省值 + `app_settings` 覆盖）。

    老配置迁移：
      * 没有 `routes` ⇒ 用 `listen/upstream/upstream_tls` 合成一条路由；
      * 没有 `block_mode` ⇒ 由旧的 `score` 推断（true=dry_run，false=off）。
    """
    out = _defaults()
    saved: set[str] = set()
    for r in db.rows("SELECT key, value FROM app_settings WHERE key LIKE 'proxy.%'"):
        k = r["key"].split(".", 1)[1] if "." in r["key"] else r["key"]
        if k not in out:
            continue
        try:
            out[k] = json.loads(r["value"])
        except (TypeError, ValueError):
            continue
        saved.add(k)

    if "routes" not in saved:
        out["routes"] = [{
            "name": "default",
            "listen": out.get("listen") or config.PROXY_DEFAULTS["listen"],
            "upstream": out.get("upstream") or config.PROXY_DEFAULTS["upstream"],
            "upstream_tls": bool(out.get("upstream_tls")),
        }]
    # 旧字段始终是 routes[0] 的只读别名，避免控制台/测试读到两套不一致的值。
    routes = out.get("routes")
    if isinstance(routes, list) and routes and isinstance(routes[0], dict):
        r0 = routes[0]
        out["listen"] = r0.get("listen", out.get("listen"))
        out["upstream"] = r0.get("upstream", out.get("upstream"))
        out["upstream_tls"] = bool(r0.get("upstream_tls", out.get("upstream_tls")))

    if "block_mode" not in saved:
        out["block_mode"] = "dry_run" if bool(out.get("score")) else "off"
    out["score"] = str(out.get("block_mode")) != "off"
    return out


def _as_bool(name: str, v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ("true", "false", "1", "0"):
        return v.strip().lower() in ("true", "1")
    raise ValueError(f"{name} 必须是布尔值")


def _as_int(name: str, v: Any, lo: int, hi: int) -> int:
    if isinstance(v, bool):
        raise ValueError(f"{name} 必须是整数")
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} 必须是整数")
    if not lo <= n <= hi:
        raise ValueError(f"{name} 必须在 {lo}..{hi} 之间")
    return n


def _as_addr(name: str, v: Any) -> str:
    s = str(v).strip()
    if any(c in _BAD_ADDR_CHARS for c in s):
        raise ValueError(f"{name} 含非法字符")
    m = _ADDR_RE.match(s)
    if not m:
        raise ValueError(f"{name} 必须是 host:port（例如 127.0.0.1:6188）")
    port = int(m.group(1))
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} 端口必须在 1..65535")
    return s


def _as_root_path(name: str, v: Any, *, allow_empty: bool = False) -> str:
    s = str(v).strip()
    if not s:
        if allow_empty:
            return ""
        raise ValueError(f"{name} 不能为空")
    p = Path(s)
    if not p.is_absolute():
        p = config.ROOT / p
    try:
        p = p.resolve()
        p.relative_to(config.ROOT.resolve())
    except (OSError, ValueError):
        raise ValueError(f"{name} 必须在项目目录 {config.ROOT} 下")
    return str(p)


def _as_routes(name: str, v: Any) -> list[dict]:
    """校验路由表：至少一条；name/listen 唯一；禁止自环。"""
    if not isinstance(v, list) or not v:
        raise ValueError(f"{name} 至少需要一条路由")
    out: list[dict] = []
    names: set[str] = set()
    listens: set[str] = set()
    for i, item in enumerate(v):
        if not isinstance(item, dict):
            raise ValueError(f"{name}[{i}] 必须是对象")
        unknown = set(item) - {"name", "listen", "upstream", "upstream_tls"}
        if unknown:
            raise ValueError(f"{name}[{i}] 含未知字段：{sorted(unknown)}")
        rname = str(item.get("name") or f"route{i + 1}").strip()
        if not _ROUTE_NAME_RE.match(rname):
            raise ValueError(
                f"{name}[{i}].name 只能包含字母/数字/._-，长度 1..64")
        if rname in names:
            raise ValueError(f"{name} 路由名重复：{rname}")
        listen = _as_addr(f"{name}[{i}].listen", item.get("listen"))
        upstream = _as_addr(f"{name}[{i}].upstream", item.get("upstream"))
        if listen == upstream:
            raise ValueError(f"{name}[{i}] 的 listen 与 upstream 不能相同（自环）：{listen}")
        if listen in listens:
            raise ValueError(f"{name} 监听地址重复：{listen}（一个端口只能有一条路由）")
        names.add(rname)
        listens.add(listen)
        out.append({
            "name": rname,
            "listen": listen,
            "upstream": upstream,
            "upstream_tls": _as_bool(
                f"{name}[{i}].upstream_tls", item.get("upstream_tls", False)),
        })
    return out


def _validate_config(patch: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(patch, dict):
        raise ValueError("配置必须是 JSON 对象")
    allowed = set(config.PROXY_DEFAULTS)
    unknown = sorted(set(patch) - allowed)
    if unknown:
        raise ValueError(f"未知配置项：{unknown}")
    cur = get_config()
    cur.update(patch)

    out: Dict[str, Any] = {}

    # ---- 路由：优先用新写法 routes；否则用旧 listen/upstream/upstream_tls ----
    legacy_keys = {"listen", "upstream", "upstream_tls"}
    if "routes" in patch:
        routes = _as_routes("routes", cur["routes"])
        # GET /api/proxy/config 会同时返回 routes 与旧字段别名；客户端原样 PUT 回来
        # 是常见用法。允许旧字段存在，但必须与 routes[0] 一致，避免两套值打架。
        for k in sorted(legacy_keys & set(patch)):
            if patch[k] != routes[0][k]:
                raise ValueError(
                    f"{k} 与 routes[0].{k} 不一致；请只提交 routes，或让两者保持一致")
    else:
        base = cur.get("routes") or []
        first_name = "default"
        if isinstance(base, list) and base and isinstance(base[0], dict):
            first_name = str(base[0].get("name") or "default")
        routes = _as_routes("routes", [{
            "name": first_name,
            "listen": cur["listen"],
            "upstream": cur["upstream"],
            "upstream_tls": cur["upstream_tls"],
        }])
    out["routes"] = routes
    out["listen"] = routes[0]["listen"]
    out["upstream"] = routes[0]["upstream"]
    out["upstream_tls"] = routes[0]["upstream_tls"]

    # ---- 判定/阻断模式：block_mode 优先；旧的 score 布尔仍兼容 ----
    if "block_mode" in patch:
        mode = str(cur["block_mode"]).strip().lower()
    elif "score" in patch:
        mode = "dry_run" if _as_bool("score", cur["score"]) else "off"
    else:
        mode = str(cur.get("block_mode") or "").strip().lower()
        if mode not in ("off", "dry_run", "enforce"):
            mode = "dry_run" if bool(cur.get("score")) else "off"
    if mode not in ("off", "dry_run", "enforce"):
        raise ValueError("block_mode 只支持 off/dry_run/enforce")
    out["block_mode"] = mode
    out["score"] = mode != "off"
    out["supervised_block"] = _as_bool("supervised_block", cur["supervised_block"])

    out["body_keep"] = _as_int("body_keep", cur["body_keep"], 0, 16 * 1024 * 1024)
    out["body_limit"] = _as_int("body_limit", cur["body_limit"], 1, 64 * 1024 * 1024)
    if out["body_keep"] > out["body_limit"]:
        raise ValueError("body_keep 不能大于 body_limit")
    out["headers_keep"] = _as_int("headers_keep", cur["headers_keep"], 1, 8192)
    resp_body = str(cur["resp_body"]).strip().lower()
    if resp_body not in ("alert", "all", "off"):
        raise ValueError("resp_body 只支持 alert/all/off")
    out["resp_body"] = resp_body
    out["resp_body_keep"] = _as_int("resp_body_keep", cur["resp_body_keep"], 1, 65536)
    out["file_size_mb"] = _as_int("file_size_mb", cur["file_size_mb"], 1, 4096)
    out["channel"] = _as_int("channel", cur["channel"], 1, 1_000_000)
    out["no_body"] = _as_bool("no_body", cur["no_body"])
    out["stats_interval"] = _as_int("stats_interval", cur["stats_interval"], 1, 3600)
    out["reload_interval"] = _as_int("reload_interval", cur["reload_interval"], 0, 3600)
    out["artifacts"] = _as_root_path("artifacts", cur["artifacts"])
    out["rules"] = _as_root_path("rules", cur["rules"], allow_empty=True)
    return out


def config_hash(cfg: Dict[str, Any]) -> str:
    raw = json.dumps(cfg, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def update_config(patch: Dict[str, Any], actor: str, ip: Optional[str] = None) -> Dict[str, Any]:
    with _LOCK:
        # 校验依赖当前保存值（例如 body_keep <= body_limit），必须在同一把锁里读改写。
        before = get_config()
        clean = _validate_config(patch)
        now = db.now_ms()
        for k, v in clean.items():
            db.execute(
                "INSERT OR REPLACE INTO app_settings(key, value, updated_at, actor) "
                "VALUES(?,?,?,?)",
                (f"proxy.{k}", json.dumps(v, ensure_ascii=False), now, actor),
            )
        _audit(actor, "proxy_config_update", None, clean, ip)
        if before.get("block_mode") != clean.get("block_mode"):
            _audit(actor, "proxy_block_mode_update", None,
                   {"from": before.get("block_mode"), "to": clean.get("block_mode")}, ip)
    return config_view()


# --------------------------------------------------------------------------- 二进制
def resolve_binary() -> Path:
    env = os.environ.get("WAF_COLLECTOR_BIN", "").strip()
    cands = ([Path(env)] if env else []) + list(config.PROXY_BIN_CANDIDATES)
    for p in cands:
        try:
            if p.is_file():
                return p
        except OSError:
            continue
    return cands[0]


def build_argv(cfg: Dict[str, Any], binary: Path) -> list[str]:
    argv = [str(binary)]
    for r in cfg["routes"]:
        argv += [
            "--route",
            "name={},listen={},upstream={},tls={}".format(
                r["name"], r["listen"], r["upstream"], 1 if r["upstream_tls"] else 0),
        ]
    argv += [
        "--block-mode", str(cfg["block_mode"]),
        "--out", str(config.RAW_DIR),
        "--body-keep", str(cfg["body_keep"]),
        "--body-limit", str(cfg["body_limit"]),
        "--headers-keep", str(cfg["headers_keep"]),
        "--resp-body", str(cfg["resp_body"]),
        "--resp-body-keep", str(cfg["resp_body_keep"]),
        "--file-size-mb", str(cfg["file_size_mb"]),
        "--channel", str(cfg["channel"]),
        "--artifacts", str(cfg["artifacts"]),
        "--stats-out", str(config.COLLECTOR_METRICS),
        "--stats-interval", str(cfg["stats_interval"]),
        "--reload-interval", str(cfg["reload_interval"]),
    ]
    if cfg["no_body"]:
        argv.append("--no-body")
    if not cfg.get("supervised_block", True):
        argv.append("--no-supervised-block")
    if cfg["rules"]:
        argv += ["--rules", str(cfg["rules"])]
    else:
        argv.append("--no-rules")
    return argv


# --------------------------------------------------------------------------- 进程
def _pid_path() -> Path:
    return Path(config.LOG_DIR) / config.PROXY_PID_NAME


def _read_pid() -> Optional[dict]:
    p = _pid_path()
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    try:
        doc["pid"] = int(doc["pid"])
    except (KeyError, TypeError, ValueError):
        return None
    return doc


def _write_pid(doc: dict) -> None:
    p = _pid_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def _remove_pid() -> None:
    try:
        _pid_path().unlink()
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    if psutil is not None:
        try:
            return bool(psutil.pid_exists(pid))
        except Exception:  # noqa: BLE001
            pass
    if os.name == "nt":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
            if not handle:
                return False
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def _identity_ok(info: dict) -> bool:
    """PID 是否仍是当初启动的那个进程。没有 psutil 时只能降级为「活着」。"""
    if psutil is None:
        return True
    try:
        created = psutil.Process(int(info["pid"])).create_time()
        return abs(created - float(info.get("started_at") or 0)) <= 5.0
    except Exception:  # noqa: BLE001
        return False


def _split_addr(addr: str) -> tuple[str, int]:
    m = _ADDR_RE.match(str(addr).strip())
    if not m:
        raise ValueError(f"非法地址：{addr}")
    host = str(addr).strip()[: m.start(1) - 1]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(m.group(1))


def _connect_host(host: str) -> str:
    if host in ("0.0.0.0", ""):
        return "127.0.0.1"
    if host == "::":
        return "::1"
    return host


def port_listening(addr: str) -> bool:
    try:
        host, port = _split_addr(addr)
        with socket.create_connection((_connect_host(host), port), timeout=0.4):
            return True
    except (OSError, ValueError):
        return False


def _log_dir() -> Path:
    return Path(config.LOG_DIR)


def _latest_log() -> Optional[Path]:
    try:
        files = sorted(_log_dir().glob("proxy_*.log"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return None
    return files[0] if files else None


def _new_log_path() -> Path:
    d = _log_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / time.strftime("proxy_%Y%m%d_%H%M%S.log")
    # 同一秒重复启动：加后缀，避免覆盖上一份日志。
    n = 1
    while p.exists():
        p = d / time.strftime("proxy_%Y%m%d_%H%M%S.log").replace(".log", f"_{n}.log")
        n += 1
    _prune_logs()
    return p


def _prune_logs() -> None:
    try:
        files = sorted(_log_dir().glob("proxy_*.log"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return
    # 留一个位置给本次即将创建的日志。
    for old in files[max(0, config.PROXY_LOG_KEEP - 1):]:
        try:
            old.unlink()
        except OSError:
            pass


def _spawn(argv: list[str], log_path: Path) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lf = open(log_path, "a", encoding="utf-8", buffering=1)
    try:
        lf.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} start =====\n")
        lf.write(" ".join(argv) + "\n")
        flags = 0
        if os.name == "nt":
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        return subprocess.Popen(
            argv,
            cwd=str(config.ROOT),
            stdout=lf,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
    finally:
        lf.close()


def _terminate(pid: int, *, force: bool) -> None:
    if os.name == "nt":
        args = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            args.append("/F")
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        os.kill(int(pid), signal.SIGKILL if force else signal.SIGTERM)
    except OSError:
        pass


def _wait_dead(pid: int, timeout: float) -> bool:
    deadline = time.time() + max(0.0, timeout)
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.1)
    return not _pid_alive(pid)


# --------------------------------------------------------------------------- 状态
def metrics() -> Optional[dict]:
    p = Path(config.COLLECTOR_METRICS)
    try:
        m = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(m, dict):
        return None
    age = (db.now_ms() - int(m.get("ts") or 0)) // 1000
    m["available"] = True
    m["age_sec"] = age
    m["stale"] = age > 180
    return m


def _effective(m: Optional[dict]) -> Optional[dict]:
    if not m:
        return None
    return {
        "pid": m.get("pid"),
        "listen": m.get("listen"),
        "upstream": m.get("upstream"),
        "routes": m.get("routes"),
        "out_dir": m.get("out_dir"),
        "score": bool(m.get("score_enabled")),
        "block_mode": m.get("block_mode") or (
            "dry_run" if m.get("score_enabled") else "off"),
        "blocked_requests": m.get("blocked_requests"),
        "artifacts": m.get("artifacts"),
        "resp_body": m.get("resp_body_mode"),
    }


def _restart_keys(saved: dict, info: Optional[dict], effective: Optional[dict]) -> list[str]:
    """保存的配置与「实际在跑」的差异。

    优先用 PID 文件里记录的完整配置（能覆盖所有字段）；指标文件只覆盖一部分字段，
    作为兜底（例如外部启动、没有 PID 文件）。
    """
    keys: set[str] = set()
    if info and isinstance(info.get("config"), dict):
        old = info["config"]
        for k, v in saved.items():
            if k in old and old[k] != v:
                keys.add(k)
    if effective:
        for k in ("listen", "upstream", "routes", "score", "block_mode",
                  "artifacts", "resp_body"):
            if k in effective and effective[k] is not None and effective[k] != saved.get(k):
                keys.add(k)
    return sorted(keys)


def _out_stats() -> dict:
    raw = Path(config.RAW_DIR)
    files = []
    total = 0
    latest = None
    try:
        entries = sorted(raw.glob("raw-*.jsonl"),
                         key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        entries = []
    for p in entries:
        try:
            st = p.stat()
        except OSError:
            continue
        total += st.st_size
        if latest is None:
            latest = {"name": p.name, "size": st.st_size, "mtime": int(st.st_mtime * 1000)}
        files.append(p.name)
    return {"path": str(raw), "files": len(files), "bytes": total,
            "latest": latest, "recent": files[:5]}


def status() -> dict:
    cfg = get_config()
    info = _read_pid()
    alive = bool(info and _pid_alive(info["pid"]))
    managed = bool(alive and _identity_ok(info)) if info else False
    m = metrics()
    # 指标文件可能是上一次运行留下的；只有进程真的活着才把它当「实际生效」。
    m_pid = int(m.get("pid") or 0) if m else 0
    external_alive = bool(m and m_pid and not m.get("stale") and _pid_alive(m_pid))
    live = alive or external_alive
    effective = _effective(m) if live else None
    restart_keys = _restart_keys(cfg, info if alive else None, effective)
    binary = resolve_binary()
    routes = cfg.get("routes") or []
    route_views = []
    for r in routes:
        route_views.append({
            "name": r.get("name"),
            "listen": r.get("listen"),
            "upstream": r.get("upstream"),
            "upstream_tls": bool(r.get("upstream_tls")),
            "listening": port_listening(r.get("listen", "")),
        })
    listening = bool(route_views) and all(r["listening"] for r in route_views)
    try:
        bstat = binary.stat()
        bin_view = {"path": str(binary), "exists": True,
                    "mtime": int(bstat.st_mtime * 1000)}
    except OSError:
        bin_view = {"path": str(binary), "exists": False, "mtime": None}
    log = _latest_log()
    warnings = []
    if not bin_view["exists"]:
        warnings.append(f"找不到采集器：{binary}；先执行 cd proxy && build.bat build --release")
    if cfg.get("block_mode") != "enforce":
        warnings.append(
            f"当前判定模式为 {cfg.get('block_mode')}：只记录、不会拦截；"
            "需要 admin 在采集代理页切到 enforce 并重启采集器")
    for r in route_views:
        if not r.get("upstream_tls"):
            continue
        try:
            _up_host, _up_port = _split_addr(r["upstream"])
        except ValueError:
            _up_port = 0
        if _up_port == 80:
            warnings.append(
                f"路由 {r['name']} 的上游端口是 80，但 upstream_tls=true：与上游握手会失败，"
                "事件不会入库；上游是明文 HTTP 时请关闭 upstream_tls")
    if alive and not m:
        warnings.append("进程在运行，但读不到指标文件（--stats-out）；检查 WAF_COLLECTOR_METRICS")
    if alive and m and m.get("stale"):
        warnings.append("采集器指标已过期（>180s）；进程可能卡住或已退出")
    if info and not alive:
        warnings.append("PID 文件存在但进程已退出；可重新启动")
    if not alive:
        busy = [r["listen"] for r in route_views if r["listening"]]
        if busy:
            warnings.append(
                f"端口 {', '.join(busy)} 已被其他进程占用；启动会失败")
    if psutil is None:
        warnings.append("未安装 psutil：无法校验 PID 身份，强停前请人工确认")
    first = route_views[0] if route_views else {}
    return {
        "running": alive,
        "managed": managed,
        "pid": info["pid"] if alive else None,
        "uptime_sec": int(time.time() - float(info.get("started_at") or 0)) if alive else None,
        "listen": first.get("listen", cfg.get("listen")),
        "upstream": first.get("upstream", cfg.get("upstream")),
        "routes": route_views,
        "block_mode": cfg.get("block_mode"),
        "blocked_requests": (m or {}).get("blocked_requests"),
        "port_listening": listening,
        "binary": bin_view,
        "metrics": m,
        "effective": effective,
        "config": cfg,
        "restart_required": bool(restart_keys),
        "restart_keys": restart_keys,
        "out_dir": _out_stats(),
        "log": {"path": str(log) if log else None,
                "exists": bool(log and log.exists()),
                "size": log.stat().st_size if log and log.exists() else 0},
        "pid_file": str(_pid_path()),
        "pid_file_stale": bool(info and not alive),
        "warnings": warnings,
    }


def config_view() -> dict:
    st = status()
    return {
        "config": st["config"],
        "defaults": _defaults(),
        "effective": st["effective"],
        "restart_required": st["restart_required"],
        "restart_keys": st["restart_keys"],
    }


# --------------------------------------------------------------------------- 启停
def start(actor: str, ip: Optional[str] = None) -> dict:
    global _PROC
    with _LOCK:
        cfg = get_config()
        info = _read_pid()
        if info and _pid_alive(info["pid"]) and _identity_ok(info):
            raise ProxyError("采集器已在运行", 409)
        busy = [r["listen"] for r in cfg["routes"] if port_listening(r["listen"])]
        if busy:
            raise ProxyError(f"端口已被占用：{', '.join(busy)}", 409)
        binary = resolve_binary()
        if not binary.is_file():
            raise ProxyError(
                f"找不到采集器：{binary}；先执行 cd proxy && build.bat build --release", 409)
        Path(config.RAW_DIR).mkdir(parents=True, exist_ok=True)
        Path(config.COLLECTOR_METRICS).parent.mkdir(parents=True, exist_ok=True)
        log_path = _new_log_path()
        argv = build_argv(cfg, binary)
        try:
            proc = _spawn(argv, log_path)
        except OSError as e:
            raise ProxyError(f"启动失败：{e}", 500)
        info = {
            "pid": int(proc.pid),
            "started_at": time.time(),
            "started_at_ms": db.now_ms(),
            "listen": cfg["listen"],
            "upstream": cfg["upstream"],
            "routes": cfg["routes"],
            "block_mode": cfg["block_mode"],
            "binary": str(binary),
            "log_path": str(log_path),
            "config": cfg,
            "config_hash": config_hash(cfg),
        }
        _write_pid(info)
        _PROC = proc

        deadline = time.time() + 3.0 + max(0, len(cfg["routes"]) - 1)
        while time.time() < deadline:
            rc = proc.poll()
            if rc is not None:
                try:
                    proc.wait(timeout=1)
                except Exception:  # noqa: BLE001
                    pass
                _remove_pid()
                _PROC = None
                tail = _tail_path(log_path, 30)
                raise ProxyError(f"采集器启动即退出（rc={rc}）：\n{tail}", 500)
            if all(port_listening(r["listen"]) for r in cfg["routes"]):
                break
            time.sleep(0.1)

        _audit(actor, "proxy_start", str(proc.pid),
               {"routes": cfg["routes"], "block_mode": cfg["block_mode"]}, ip)
        return status()


def stop(actor: str, force: bool = False, ip: Optional[str] = None) -> dict:
    global _PROC
    with _LOCK:
        info = _read_pid()
        if not info:
            raise ProxyError("没有托管的采集器进程", 409)
        pid = int(info["pid"])
        if not _pid_alive(pid):
            _remove_pid()
            _PROC = None
            return status()
        if not _identity_ok(info) and not force:
            raise ProxyError(
                "PID 已被其他进程复用；确认不是误杀后使用 force=true", 409)
        _terminate(pid, force=False)
        if not _wait_dead(pid, 5.0):
            _terminate(pid, force=True)
            _wait_dead(pid, 2.0)
        if _PROC is not None and getattr(_PROC, "pid", None) == pid:
            try:
                _PROC.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        _remove_pid()
        _PROC = None
        _audit(actor, "proxy_force_stop" if force else "proxy_stop",
               str(pid), None, ip)
        return status()


def restart(actor: str, ip: Optional[str] = None) -> dict:
    with _LOCK:
        info = _read_pid()
        if info and _pid_alive(info["pid"]):
            stop(actor, force=False, ip=ip)
        _audit(actor, "proxy_restart", None, None, ip)
        return start(actor, ip=ip)


# --------------------------------------------------------------------------- 日志
def _tail_path(path: Path, lines: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = min(size, 256 * 1024)
            f.seek(size - block)
            data = f.read(block)
    except OSError:
        return ""
    text = data.decode("utf-8", "replace")
    parts = text.splitlines()
    return "\n".join(parts[-max(1, int(lines)):])


def tail_log(lines: int = 200) -> dict:
    info = _read_pid()
    p = Path(info["log_path"]) if info and info.get("log_path") else _latest_log()
    if not p or not p.exists():
        return {"path": str(p) if p else None, "log": "",
                "hint": "还没有托管日志；先通过控制台启动采集器，或用命令行启动。"}
    return {"path": str(p), "log": _tail_path(p, lines)}


# --------------------------------------------------------------------------- 审计
def _audit(actor: str, action: str, target: Optional[str] = None,
           detail: Any = None, ip: Optional[str] = None) -> None:
    if detail is not None and not isinstance(detail, str):
        detail = json.dumps(detail, ensure_ascii=False)
    db.execute(
        "INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
        (db.now_ms(), actor, action, target, detail, ip),
    )
