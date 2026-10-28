"""工作项 F：真实流量采集 / 清洗 / 标注（只收真实流量，不造合成数据）。

## 为什么要有这个脚本

`REALDATA_EVALUATION.md` §8 的结论是：**误报的瓶颈是训练数据没有覆盖部署分布（OOD）**，
而不是特征不够好。所以"拿真实本地流量重训/重标定"是唯一出路。本脚本负责**把真实流量变成
可训练的 jsonl**，并强制记录数据的**来源（provenance）**。

## 关键设计：攻击标签只能来自"出处"，不能来自"内容正则"

真实攻击**没有标签**。用恶意载荷正则去自动标注攻击，等于把"我们想替换掉的那套规则"
又抄进训练集（循环论证，且会把规则漏掉的新型攻击标成良性）。因此本脚本只接受三种**出处**：

| `--provenance` | 含义 | 标签 |
|---|---|---|
| `benign_lab` | 已知良性的本地/测试环境流量 | 0 良性 |
| `canary` | 命中蜜罐/诱捕路径的请求（**出处**即证据） | 1 攻击 |
| `redteam` | 红队自攻击会话（我们自己打的，知道打了什么） | 1 攻击 |
| `incident` | 人工复核/事件响应确认过的请求（需 `--review` 文件） | 1 攻击 |
| `auto` | 按 `--canary-prefix` / `--attacker-ip` / `--redteam-window` / `--review` **出处规则**逐条判定 | 0/1 |

> 内容正则（`--audit-pattern`）**只用于审计报告**，永不用于训练标签。

### 本机红队流量（Burp / SQLmap 打 DVWA）怎么标

`127.0.0.1` 既是你的浏览器、也是你的 SQLmap —— **来源 IP 区分不了**。唯一干净的出处
是操作者自己声明的时段：

    py -3.10 collect_http_log.py --src access.log --provenance auto \
        --redteam-window 2026-10-17T09:30:00,2026-10-17T10:05:00 --name local_lab

时间窗按**字面本地时间**比较（忽略 CLF 里的时区偏移），CLI 会打印日志实际时间范围供核对；
若某条记录的时间戳解析不了，脚本**直接报错退出**——静默把红队流量当良性会污染良性池，
比漏标更有害。

## 支持的日志格式

* `apache`/`nginx` combined / common（含 `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`）
* IIS W3C extended（`#Fields:` 头）
* 通用 JSONL（原生 `{method,path,query,body}`）

### 采集代理（S4 `proxy/waf-collector`）的 jsonl 也走这里

代理只写**原始记录**（`--format jsonl` 直接吃），**不打任何 label** —— 标注仍由本脚本按出处决定。
代理额外写了流级字段（`host/src_port/body_len/body_truncated/dur_ms/bytes_in/bytes_out/src_kind`），
本脚本用 `FLOW_KEYS` **原样透传**，于是"一个采集点产出 HTTP + 流级两路"（REALDATA §8.7.5）不丢信息。

    py -3.10 collect_http_log.py --format jsonl --src raw-*.jsonl \
        --provenance auto --canary-prefix /admin.php --name local_lab --keep-body

> ⚠️ **默认不落 body**（隐私优先）。训练/评估必须显式加 `--keep-body`，
> 否则代理采到的 body 会被这层清空。
>
> 代理用 `--score` 时记录里会有 `pred`（模型 dry-run 判定）。本脚本**只保留已知键**，
> 所以 `pred` 在标注产物里**结构性消失** —— 模型输出不可能变成训练标签。
>
> 端到端自检：`py -3.10 p8_proxy_e2e.py`（27 项断言，含上面两条）。

## 已知限制（必须知道，别当成能力）

1. **access log 没有请求体**。POST body 是攻击特征最强的地方，access log 里根本不存在 ——
   只想靠 access log 建模，等于自断一臂。要 body 必须挂采集代理（S4）或读 WAF 自己的日志。
2. **日志是"已经流过"的流量**，不含被前置设备拦掉的攻击；真实攻击的召回率**无法**从 access log 估出来。
3. 本脚本**不去重到只剩唯一请求就不管了**：默认输出**去重后的池**（重复请求会把分位点带偏，
   例如本机 nginx 日志里 `GET /phpinfo.php` 重复上百次）；原始行数记在报告里。

用法：

    :: 1) 本机真实流量 -> 良性池（隐私脱敏）
    py -3.10 collect_http_log.py --src "F:\\phpStudy\\phpStudy\\Apache\\logs\\access.log" \
        --name local_lab --provenance benign_lab --scrub

    :: 2) 持续采集（追加模式，每 5s 扫一次新行）
    py -3.10 collect_http_log.py --src access.log --name local_lab --follow --append

    :: 3) 蜜罐/诱捕路径的请求算攻击
    py -3.10 collect_http_log.py --src access.log --provenance auto \
        --canary-prefix /honeypot/ --canary-prefix /.trap/ --name local_lab
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_DIR = os.path.abspath(os.path.join(HERE, "..", "traindata", "local"))

REQ_KEYS = ("method", "path", "query", "body")

# 采集代理（S4 / waf-collector）写入的流级与补充字段。
# 解析与落盘都保留：这是"一个采集点同时产出 HTTP 通道与流级通道"（§8.7.5）不丢信息的前提。
FLOW_KEYS = ("host", "src_port", "body_len", "body_truncated", "dur_ms",
             "bytes_in", "bytes_out", "src_kind")

# 日志时间戳的常见形态（用于"红队时间窗"标注；不引入时区库，比较**字面本地时间**）
_TS_FORMATS = (
    "%d/%b/%Y:%H:%M:%S",               # Apache/Nginx CLF: 28/Dec/2017:09:35:39
    "%d/%b/%Y:%H:%M:%S %z",            # 带时区偏移（解析后丢弃偏移，见下）
    "%a %b %d %H:%M:%S.%f %Y",         # Apache error log: Thu Dec 28 09:35:39.375000 2017
    "%a %b %d %H:%M:%S %Y",
    "%Y-%m-%d %H:%M:%S",               # IIS W3C / 通用
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
)


def parse_ts(s) -> Optional[datetime]:
    """把日志里的时间戳字符串解析成 datetime；失败返回 None（调用方必须显式处理）。"""
    if s is None:
        return None
    t = str(s).strip().strip("[]")
    if not t:
        return None
    if t.isdigit() and len(t) >= 10:                      # epoch（秒/毫秒）
        v = int(t)
        return datetime.fromtimestamp(v / 1000.0 if v > 10 ** 11 else v)
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(t, fmt)
        except ValueError:
            continue
        # 统一成 naive：比较的是**字面本地时间**，不做时区换算（见 parse_window 说明）
        return dt.replace(tzinfo=None)
    return None


def parse_window(spec: str) -> Tuple[datetime, datetime, str]:
    """解析 `START,END` 红队时间窗。两端都必须是可解析的本地时间。

    刻意**只在字面本地时间上比较**（忽略 CLF 里的时区偏移）：跨时区推断容易错，
    所以这里宁可让操作者自己核对——CLI 会打印日志里实际观测到的时间范围。
    """
    if "," not in spec:
        raise SystemExit(f"[redteam] 时间窗格式应为 START,END，收到：{spec!r}")
    a, b = (x.strip() for x in spec.split(",", 1))
    da, db = parse_ts(a), parse_ts(b)
    if da is None or db is None:
        raise SystemExit(
            f"[redteam] 时间窗无法解析：{spec!r}。请用 "
            f"`YYYY-MM-DDTHH:MM:SS`（推荐）或 `YYYY-MM-DD HH:MM:SS`。")
    if db < da:
        raise SystemExit(f"[redteam] 时间窗 END < START：{spec!r}")
    return da, db, spec

# apache/nginx common+combined
_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>(?:[^"\\]|\\.)*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<nbytes>\d+|-)'
    r'(?:\s+"(?P<ref>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?'
)
_REQLINE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+(?P<proto>HTTP/\d\.\d))?$')

# 需要脱敏的 query 参数名（真实日志里一定有 token / session / 口令）
SENSITIVE = {
    "token", "accesstoken", "access_token", "auth", "authorization", "apikey", "api_key",
    "key", "secret", "sign", "signature", "password", "passwd", "pwd", "pass",
    "sid", "sessionid", "session_id", "jsessionid", "phpsessid", "csrf", "csrf_token",
    "ticket", "code", "id_token", "bearer",
}


# ---------------------------------------------------------------------------
def split_target(target: str) -> Tuple[str, str]:
    """`/a/b?x=1&y=2` -> ('/a/b', 'x=1&y=2')。"""
    if not target:
        return "", ""
    target = target.strip()
    if target.upper().startswith("HTTP/"):
        return "", ""
    if "?" in target:
        p, q = target.split("?", 1)
        return p, q
    return target, ""


def scrub_query(query: str) -> str:
    """把敏感参数的值替换成 ***（保留参数名与个数，特征不受影响）。"""
    if not query:
        return ""
    out = []
    for part in query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.lower() in SENSITIVE:
                out.append(f"{k}=***")
                continue
            out.append(f"{k}={v}")
        else:
            out.append(part)
    return "&".join(out)


def scrub_ip(ip: str) -> str:
    """IPv4 保留前两段；IPv6 保留前缀。"""
    if not ip or ip == "-":
        return ip
    if "." in ip and ip.count(".") == 3:
        a, b, _, _ = ip.split(".")
        return f"{a}.{b}.0.0"
    if ":" in ip:
        return ":".join(ip.split(":")[:2]) + "::"
    return ip


def fingerprint(req: Dict) -> str:
    return "\x1f".join(str(req.get(k) or "") for k in REQ_KEYS)


def norm_len(s: str, cap: int = 8192) -> str:
    """畸形/超长行截断（日志可能被截断或含二进制）。"""
    return s[:cap]


# ---------------------------------------------------------------------------
# 解析器：返回 dict 或 None（无法解析）
# ---------------------------------------------------------------------------
def parse_apache(line: str) -> Optional[Dict]:
    m = _APACHE.match(line)
    if not m:
        return None
    rm = _REQLINE.match(m.group("req").strip())
    if not rm:
        return None
    path, query = split_target(rm.group("target"))
    return {
        "method": rm.group("method"),
        "path": path,
        "query": query,
        "body": "",                      # access log 无 body
        "ts": m.group("ts"),
        "src_ip": m.group("ip"),
        "status": m.group("status"),
        "bytes": m.group("nbytes"),
        "referer": m.group("ref") or "",
        "ua": m.group("ua") or "",
    }


def parse_jsonl(line: str) -> Optional[Dict]:
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict) or "path" not in obj:
        return None
    out = {k: (obj.get(k) or "") for k in REQ_KEYS}
    out["method"] = (out["method"] or "GET").upper()
    for k in ("ts", "src_ip", "status", "ua", "referer"):
        if obj.get(k) is not None:
            out[k] = str(obj.get(k))
    for k in FLOW_KEYS:                     # 流级/补充字段原样保留（数值不转字符串）
        if obj.get(k) is not None:
            out[k] = obj[k]
    out["_label"] = obj.get("label")            # 外部已标注的（原样尊重）
    return out


# Apache **error** log。真实在野攻击的富矿：PHP notice/warning 会把攻击者构造的 URL
# 原样记进 `referer:`（例如 UNION SELECT ... INTO OUTFILE 写马），
# `script '...' not found` 则暴露扫描器在探测哪些路径（备份/导入/webshell 文件名）。
_ERR_HEAD = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<lvl>[^\]]+)\]"
    r"(?:\s+\[pid[^\]]*\])?"
    r"(?:\s+\[client\s+(?P<ip>[^\]:]+)(?::\d+)?\])?\s*(?P<msg>.*)$"
)
_ERR_REFERER = re.compile(r"referer:\s*(?P<url>\S+)", re.I)
_ERR_SCRIPT = re.compile(r"script\s+'(?P<p>[^']+)'\s+not found", re.I)
_ERR_FILENOTEXIST = re.compile(r"File does not exist:\s*(?P<p>\S+)", re.I)
_ERR_INVALIDURI = re.compile(r"Invalid URI in request\s+(?P<u>\S+)", re.I)
_ERR_DENIED = re.compile(r"client denied by server configuration:\s*(?P<p>\S+)", re.I)
_ERR_AH = re.compile(r"AH\d+:\s*(?:.*?:\s*)?(?P<p>/\S+)")
_URLSPLIT = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://(?P<host>[^/?#]+)?(?P<rest>/[^#]*)?$")
# error log 里的请求路径是**文件系统路径**（`F:/phpStudy/phpStudy/WWW/cms/admin.php`），
# 剥掉 docroot 前缀才变成 URL 路径，否则整批扫描器探测都被丢掉。
_DOCROOT = re.compile(
    r"(?i)^(?:[a-z]:)?(?:/[^/]+)*?/(?:www|wwwroot|htdocs|webroot|public_html|web|html)(?=/|$)"
)


def _fs_to_url(p: str) -> str:
    p = (p or "").replace("\\", "/")
    m = _DOCROOT.match(p)
    if m:
        p = p[m.end():]
    if not p.startswith("/"):
        p = "/" + p.lstrip("/")
    return p


def _to_path_query(u: str) -> Tuple[str, str]:
    """`http://h/p?q` / `/p?q` / `F:/docroot/p?q` -> (path, query)。"""
    if not u:
        return "", ""
    raw = u.strip()
    if raw.startswith("/"):
        return split_target(raw)
    m = _URLSPLIT.match(raw)
    if m:
        return split_target(m.group("rest") or "/")
    return split_target(_fs_to_url(raw))


def parse_apache_error(line: str) -> Optional[Dict]:
    """从 error log 一行里抠出一个**请求候选**（URL/路径），没有就返回 None。"""
    m = _ERR_HEAD.match(line)
    if not m:
        return None
    msg = m.group("msg") or ""
    url = None
    src = ""
    rm = _ERR_REFERER.search(msg)
    if rm and "?" in rm.group("url"):
        url, src = rm.group("url"), "error-referer"
    if url is None:
        for rx, tag in ((_ERR_SCRIPT, "error-script-missing"), (_ERR_FILENOTEXIST, "error-no-file"),
                        (_ERR_INVALIDURI, "error-invalid-uri"), (_ERR_DENIED, "error-denied")):
            p = rx.search(msg)
            if p:
                url, src = p.group(1), tag
                break
    if url is None:
        return None
    if src == "error-invalid-uri":
        path, query = split_target(url)
    else:
        path, query = _to_path_query(url)
    if not path:
        return None
    return {"method": "GET", "path": path, "query": query, "body": "",
            "ts": m.group("ts"), "src_ip": m.group("ip") or "", "status": "",
            "bytes": "", "referer": "", "ua": "", "_src_kind": src}


class W3CParser:
    """IIS W3C extended：`#Fields:` 给列名，数据行空格分隔（UA 可能含空格，故按列名定位）。"""

    def __init__(self):
        self.cols: List[str] = []

    def header(self, line: str) -> bool:
        if line.startswith("#Fields:"):
            self.cols = line[len("#Fields:"):].split()
            return True
        return False

    def parse(self, line: str) -> Optional[Dict]:
        if not self.cols or line.startswith("#"):
            return None
        f = line.split()
        idx = {c: i for i, c in enumerate(self.cols)}
        try:
            method = f[idx["cs-method"]]
            stem = f[idx["cs-uri-stem"]]
        except (KeyError, IndexError):
            return None
        query = f[idx["cs-uri-query"]] if "cs-uri-query" in idx and idx["cs-uri-query"] < len(f) else ""
        if query == "-":
            query = ""
        ip = f[idx["c-ip"]] if "c-ip" in idx and idx["c-ip"] < len(f) else ""
        status = f[idx["sc-status"]] if "sc-status" in idx and idx["sc-status"] < len(f) else ""
        ts = " ".join(f[:2]) if len(f) >= 2 else ""
        return {"method": method.upper(), "path": stem, "query": query, "body": "",
                "ts": ts, "src_ip": ip, "status": status, "bytes": "", "referer": "", "ua": ""}


def iter_lines(path: str, follow: bool, interval: float, encoding: str):
    """逐行产出；`follow=True` 时轮询文件尾部的新增内容。"""
    with open(path, "r", encoding=encoding, errors="replace") as f:
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\r\n")
                continue
            if not follow:
                return
            time.sleep(interval)


def iter_all_lines(paths: List[str], follow: bool, interval: float, encoding: str):
    """把多个来源串成 (src, line) 流。"""
    for p in paths:
        for line in iter_lines(p, follow, interval, encoding):
            yield p, line


# ---------------------------------------------------------------------------
def label_of(req: Dict, provenance: str, canary_prefixes: List[str],
             attacker_ips: set, review: Dict[str, int],
             label_patterns: Iterable = (),
             redteam_windows: Tuple = ()) -> Tuple[int, str]:
    """按**出处**打标签。返回 (label, why)。

    `redteam_windows` 是 `(start, end, spec)` 列表：落在窗口内的请求视为红队自攻击
    （**出处**=操作者自己声明的时段），这是唯一能干净标注"本机 localhost 红队流量"的方式。

    `label_patterns` 是 IOC 内容正则，**显式 opt-in**：只适合构造真实在野攻击**测试集**。
    用它训练 = 把 IOC 抄进模型（循环论证），模块文档已说明。
    """
    if req.get("_label") in (0, 1):
        return int(req["_label"]), "jsonl 自带 label"
    if provenance == "benign_lab":
        return 0, "provenance=benign_lab"
    if provenance == "canary":
        return 1, "provenance=canary"
    if provenance == "redteam":
        return 1, "provenance=redteam"
    if provenance == "incident":
        key = fingerprint(req)
        if key in review:
            return review[key], "incident 复核结论"
        return 0, "未在复核清单中（按良性计，需人工确认）"
    # auto / indicator：先走出处规则（红队时间窗 / 路径 / 来源 IP / 复核清单）
    if redteam_windows:
        dt = parse_ts(req.get("ts"))
        if dt is not None:
            for a, b, spec in redteam_windows:
                if a <= dt <= b:
                    return 1, f"redteam 时间窗 {spec}"
    path = req.get("path") or ""
    for p in canary_prefixes:
        if path.startswith(p):
            return 1, f"canary 路径 {p}"
    if req.get("src_ip") and scrub_ip(req["src_ip"]) in attacker_ips:
        return 1, "attacker-ip 列表"
    key = fingerprint(req)
    if key in review:
        return review[key], "review 清单"
    # 再走 IOC 内容标注（显式 opt-in）
    blob = "\x1f".join(str(req.get(k) or "") for k in REQ_KEYS)
    for p in label_patterns:
        if p.search(blob):
            return 1, f"IOC:{p.pattern[:48]}"
    return 0, ("indicator:IOC 未命中" if provenance == "indicator"
               else "auto 未命中任何出处规则")


DEFAULT_AUDIT = [
    ("sqli", r"(?i)(union\s+select|select\s+\S+\s+from|information_schema|sleep\(\d|benchmark\()"),
    ("xss", r"(?i)(<script|onerror\s*=|javascript:|<svg|alert\(\d)"),
    ("traversal", r"(\.\./|%2e%2e|/etc/passwd|win\.ini|boot\.ini)"),
    ("rce", r"(?i)(;\s*(cat|ls|id|whoami|wget|curl)\b|\|\s*(cat|ls|id)\b|\$\{jndi:)"),
    ("scanner", r"(?i)(sqlmap|nikto|acunetix|nmap|masscan|gobuster|dirbuster|wfuzz|nuclei)"),
    ("probe", r"(?i)(/\.env|/\.git/|/wp-admin|/phpmyadmin/?$|/actuator/|/druid/|/console)"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", action="append", required=True,
                    help="日志文件路径（可重复传入多个来源，或 jsonl）")
    ap.add_argument("--format", choices=["auto", "apache", "nginx", "iis", "jsonl", "apache-error"],
                    default="auto",
                    help="apache-error 用于采集 Apache error log（挖在野攻击 URL / 扫描探测路径）")
    ap.add_argument("--name", required=True, help="数据集名（输出 <name>_benign.jsonl 等）")
    ap.add_argument("--out-dir", default=LOCAL_DIR)
    ap.add_argument("--provenance", choices=["benign_lab", "canary", "redteam", "incident",
                                             "auto", "indicator"],
                    default="benign_lab",
                    help="标签出处（见模块文档；攻击标签只能来自出处，不能来自内容正则）")
    ap.add_argument("--label-pattern", action="append", default=[],
                    help="IOC 正则（显式 opt-in 的内容标注；只适合造真实在野**测试集**，别拿去训练）")
    ap.add_argument("--label-pattern-file", default=None,
                    help="IOC 正则文件（每行一条，# 注释）")
    ap.add_argument("--canary-prefix", action="append", default=[],
                    help="--provenance auto 时，命中该路径前缀的请求视为攻击")
    ap.add_argument("--attacker-ip", action="append", default=[],
                    help="--provenance auto 时，来自这些 IP 的请求视为攻击")
    ap.add_argument("--redteam-window", action="append", default=[],
                    help="--provenance auto 时，落在该时间窗内的请求视为红队自攻击。"
                         "格式 START,END（如 2026-10-17T09:30:00,2026-10-17T10:05:00）。"
                         "这是标注**本机 localhost 红队流量**（Burp/SQLmap 打 DVWA）的唯一干净方式："
                         "来源 IP 是 127.0.0.1，无法与真实浏览器流量区分，只能靠操作者声明的时段")
    ap.add_argument("--redteam-window-file", default=None,
                    help="红队时间窗清单（每行一条 START,END，# 注释）")
    ap.add_argument("--review", default=None,
                    help="人工复核清单 jsonl：{method,path,query,body,label}")
    ap.add_argument("--scrub", action="store_true",
                    help="脱敏（敏感 query 参数 -> ***，IP 只留前两段）；池导出的默认建议")
    ap.add_argument("--keep-body", action="store_true",
                    help="保留 body（access log 本来就没有；jsonl 源可能带，默认保留）")
    ap.add_argument("--encoding", default="utf-8")
    ap.add_argument("--follow", action="store_true", help="持续采集新行")
    ap.add_argument("--follow-interval", type=float, default=5.0)
    ap.add_argument("--append", action="store_true", help="追加到已有 jsonl（配合 --follow 累积）")
    ap.add_argument("--max-lines", type=int, default=0, help="只处理前 N 行（0=不限）")
    ap.add_argument("--audit-pattern", action="append", default=[],
                    help="附加的**审计**正则（只进报告，绝不用于标签）")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    review = {}
    if args.review:
        with open(args.review, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    o = json.loads(line)
                    review[fingerprint(o)] = int(o.get("label", 1))
        print(f"[review] 载入复核清单 {len(review)} 条")

    attacker_ips = {scrub_ip(x) if args.scrub else x for x in args.attacker_ip}

    # ---- 红队时间窗（出处规则，非内容规则）----
    win_specs = list(args.redteam_window)
    if args.redteam_window_file:
        with open(args.redteam_window_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    win_specs.append(line)
    redteam_windows = tuple(parse_window(s) for s in win_specs)
    if redteam_windows:
        for a, b, spec in redteam_windows:
            print(f"[redteam] 时间窗 {spec}  ->  [{a} , {b}]")
        if args.provenance != "auto":
            print(f"[redteam] ⚠️ 时间窗只在 --provenance auto 下生效；"
                  f"当前 provenance={args.provenance}，该参数被忽略")
    raw_label_pats = list(args.label_pattern)
    if args.label_pattern_file:
        with open(args.label_pattern_file, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    raw_label_pats.append(ln)
    label_pats = []
    for p in raw_label_pats:
        try:
            label_pats.append(re.compile(p))
        except re.error as e:
            raise SystemExit(f"[ioc] 正则编译失败 {p!r}: {e}")
    if args.provenance == "indicator" and not label_pats:
        raise SystemExit("[ioc] --provenance indicator 必须配 --label-pattern / --label-pattern-file，"
                         "否则会把所有请求静默标成良性")
    audit = list(DEFAULT_AUDIT) + [("custom", p) for p in args.audit_pattern]
    audit_re = [(n, re.compile(p)) for n, p in audit]

    w3c_parsers: Dict[str, W3CParser] = {}

    def parse(line: str, w3c: W3CParser) -> Optional[Dict]:
        s = line.strip()
        if not s:
            return None
        if args.format in ("auto", "iis") and (s.startswith("#") or w3c.cols):
            if w3c.header(s):
                return None
            r = w3c.parse(s)
            if r is not None:
                return r
            if args.format == "iis":
                return None
        if args.format in ("auto", "jsonl") and s.startswith("{"):
            return parse_jsonl(s)
        if args.format in ("auto", "apache-error") and s.startswith("["):
            return parse_apache_error(s)
        if args.format in ("auto", "apache", "nginx"):
            return parse_apache(s)
        return None

    stats = dict(lines=0, parsed=0, unparsed=0, dup=0, body_present=0)
    label_cnt = Counter()
    why_cnt = Counter()
    src_kinds = Counter()
    paths = Counter()
    methods = Counter()
    statuses = Counter()
    uas = Counter()
    ts_first = ts_last = None
    win_unparsable = 0
    seen = set()
    out: Dict[int, List[Dict]] = {0: [], 1: []}
    audit_hits = Counter()

    t0 = time.time()
    try:
        for src, line in iter_all_lines(args.src, args.follow, args.follow_interval, args.encoding):
            stats["lines"] += 1
            req = parse(line, w3c_parsers.setdefault(src, W3CParser()))
            if req is None:
                stats["unparsed"] += 1
                if args.max_lines and stats["lines"] >= args.max_lines:
                    break
                continue
            stats["parsed"] += 1
            if (req.get("body") or ""):
                stats["body_present"] += 1
            if args.scrub:
                req["query"] = scrub_query(req.get("query") or "")
                if req.get("src_ip"):
                    req["src_ip"] = scrub_ip(req["src_ip"])
            req["path"] = norm_len(req.get("path") or "")
            req["query"] = norm_len(req.get("query") or "")
            # access log 本来就没有 body；显式关掉可减少下游误解
            req["body"] = norm_len(req.get("body") or "") if args.keep_body else ""

            fp = fingerprint(req)
            if fp in seen:
                stats["dup"] += 1
                if args.max_lines and stats["lines"] >= args.max_lines:
                    break
                continue
            seen.add(fp)

            lab, why = label_of(req, args.provenance, args.canary_prefix, attacker_ips, review,
                                label_pats, redteam_windows)
            if redteam_windows and parse_ts(req.get("ts")) is None:
                win_unparsable += 1
            label_cnt[lab] += 1
            why_cnt[why] += 1
            methods[req.get("method") or "?"] += 1
            paths[req.get("path") or "/"] += 1
            if req.get("status"):
                statuses[req["status"]] += 1
            ua = (req.get("ua") or "")[:60]
            if ua:
                uas[ua] += 1
            ts = req.get("ts")
            if ts:
                ts_first = ts_first or ts
                ts_last = ts
            for name, rx in audit_re:
                if rx.search(req.get("path") or "") or rx.search(req.get("query") or ""):
                    audit_hits[f"{name}"] += 1
            req.pop("_label", None)
            req["label"] = lab
            req["label_why"] = why
            if req.get("_src_kind"):
                src_kinds[req["_src_kind"]] += 1
            out[lab].append(req)

            if args.max_lines and stats["lines"] >= args.max_lines:
                break
            if stats["parsed"] % 200000 == 0:
                print(f"[ingest] {stats['parsed']:,} 解析 / {stats['dup']:,} 重复 ...")
    except KeyboardInterrupt:
        print("[ingest] Ctrl-C，落盘已采集部分")

    # ---- 红队时间窗的**显式**自检：标不上就报错，绝不静默把红队流量当良性 ----
    if redteam_windows:
        win_hits = sum(v for k, v in why_cnt.items() if k.startswith("redteam 时间窗"))
        if win_unparsable:
            raise SystemExit(
                f"[redteam] {win_unparsable:,} 条记录的时间戳无法解析，无法判定是否落在时间窗内。\n"
                f"          拒绝继续：静默把红队流量标成良性会污染良性池（比漏标更糟）。\n"
                f"          时间范围示例：{ts_first!r} .. {ts_last!r}\n"
                f"          请检查 --format 是否与日志实际格式一致，或用 --redteam-window-file 提供正确的窗口。")
        if win_hits == 0:
            print(f"[redteam] ⚠️ 时间窗内 0 条命中。日志实际时间范围 {ts_first!r} .. {ts_last!r}。"
                  f"请核对窗口与日志的时间基准（本工具按**字面本地时间**比较，忽略时区偏移）。")
        else:
            print(f"[redteam] 时间窗命中 {win_hits:,} 条（已标为攻击）；"
                  f"日志时间范围 {ts_first!r} .. {ts_last!r}")

    wrote = {}
    for lab, tag in ((0, "benign"), (1, "attack")):
        rows = out[lab]
        if not rows:
            continue
        p = os.path.join(args.out_dir, f"{args.name}_{tag}.jsonl")
        mode = "a" if args.append else "w"
        existing = 0
        if args.append and os.path.exists(p):
            existing = sum(1 for _ in open(p, "r", encoding="utf-8", errors="replace"))
        with open(p, mode, encoding="utf-8") as f:
            for r in rows:
                row = {k: r.get(k, "") for k in REQ_KEYS
                       + ("ts", "src_ip", "status", "ua", "label", "label_why")}
                for k in FLOW_KEYS:
                    if r.get(k) is not None and r.get(k) != "":
                        row[k] = r[k]
                if r.get("_src_kind"):
                    row["src_kind"] = r["_src_kind"]
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        wrote[tag] = {"path": p, "n": len(rows), "appended_to_existing": existing}

    report = {
        "src": args.src, "name": args.name, "format": args.format,
        "provenance": args.provenance, "scrubbed": bool(args.scrub),
        "counts": {**stats, "unique": stats["parsed"] - stats["dup"]},
        "labels": {str(k): v for k, v in label_cnt.items()},
        "label_why": dict(why_cnt),
        "src_kind": dict(src_kinds),
        "methods": dict(methods.most_common(10)),
        "top_paths": dict(paths.most_common(20)),
        "status": dict(statuses.most_common(10)),
        "top_ua": dict(uas.most_common(10)),
        "time_range": [ts_first, ts_last],
        "audit_pattern_hits": dict(audit_hits),
        "written": wrote,
        "elapsed_s": round(time.time() - t0, 1),
        "limitations": [
            "access log 无请求体；body='' 恒真，POST 攻击特征缺失",
            "日志只含已流过前置设备的流量，无法据此估计真实攻击召回",
            "攻击标签来自 provenance，不来自内容正则",
        ],
    }
    rep_path = os.path.join(args.out_dir, f"{args.name}_report.json")
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[ingest] 行 {stats['lines']:,}  解析 {stats['parsed']:,}  重复(唯一化丢弃) "
          f"{stats['dup']:,}  未解析 {stats['unparsed']:,}  带 body {stats['body_present']:,}")
    print(f"[ingest] 标签 {dict(label_cnt)}  时间范围 {ts_first} .. {ts_last}")
    print(f"[ingest] 审计正则命中(仅供审阅,未用于标签): {dict(audit_hits) or '无'}")
    for tag, w in wrote.items():
        print(f"[out] {w['path']}  n={w['n']:,}"
              + (f"（追加于已有 {w['appended_to_existing']:,} 条之后）" if w["appended_to_existing"] else ""))
    print(f"[out] {rep_path}")
    if label_cnt.get(1, 0) == 0:
        print("[!] 本次**没有采集到任何攻击样本**。XGBoost 无法在不含真实攻击的数据上重训 ——\n"
              "    攻击标签需要出处：蜜罐/诱捕路径（--canary-prefix）、红队自攻击（--provenance redteam）、\n"
              "    或人工复核清单（--incident + --review）。不要用内容正则去标攻击（循环论证）。")
    if stats["parsed"] - stats["dup"] < 2000:
        print(f"[!] 唯一请求只有 {stats['parsed'] - stats['dup']:,} 条：够做**标定池**，"
              f"不够训练（建议 ≥10k）。用 --follow --append 持续累积。")


if __name__ == "__main__":
    main()
