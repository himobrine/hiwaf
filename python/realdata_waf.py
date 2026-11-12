"""新 `traindata/`（2026-11 版）接入层：把六组语料统一成项目的请求格式。

为什么单独一个模块：
  * 旧语料（CSIC 2010 / HTTP Params / datacon / local jsonl）在 2026-11 被整体替换，
    `realdata.py` 里的路径全部失效；但**特征契约（80 维 v2）与标签体系（0-4）不变**，
    所以只需要换"数据从哪来"，不需要动 `features.py` / ONNX / Rust。
  * 新语料形态差异极大：xlsx 是"按规则命中行"展开的审计表（事务被拆成多行）、
    parquet 是百万级请求表、ModSecurity 审计日志是分段的文本、载荷表是纯字符串。
    每种的坑都不一样，必须各自有 loader，并且**把坑写进代码**而不是文档里。

统一输出（与 `realdata.py` / `collect_http_log.py` 一致）：
    {method, path, query, body, headers, label, source, group}
  * label: 0 normal / 1 sqli / 2 xss / 3 cmdi / 4 traversal；None = 攻击但无子类
  * group: 分组切分用的键（URL 模板），保证同模板不跨 train/valid/test

标签映射（**标签体系保持 0-4 不变**，不扩类）：
  xlsx:            normal->0, sqli->1, xss->2, rce->3, fileinclusion-ldf->4
                   bruteforce 无槽位 -> None（只进二分类评估，不进 5 类训练）
  ModSecurity 规则: 941->2(xss), 942->1(sqli), 930->4(lfi), 931->4,
                   932/933/934->3(cmd), 944->2(js/xss)，其余(920/921/913/980/949)->None
  parquet:         normal->0, anomalous->None（**无子类**，不能进 5 类训练）

明确排除（并在 inventory 里写明原因）：
  * CVE_list.json —— JSON 在 9.5MB 处截断（unterminated string），且不是 HTTP 请求
  * AgentCyberRangeWebExploitBench/ —— 只有 readme（内容"等待通过"），无数据
  * http-attack-requests.json —— 395 字节的清单说明，不是数据
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import hashlib
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
TRAINDATA = os.path.abspath(os.path.join(HERE, "..", "traindata"))

XLSX = os.path.join(TRAINDATA, "combined_final_dataset_augmented.xlsx")
PARQUET_DIR = os.path.join(TRAINDATA, "WAF Data v2")
PARQUET_TRAIN = os.path.join(PARQUET_DIR, "train.parquet")
PARQUET_TEST = os.path.join(PARQUET_DIR, "test.parquet")
OWASP_GLOB = os.path.join(TRAINDATA, "owasp", "*", "modsec_audit.anon.log")
PAYLOAD_DIR = os.path.join(TRAINDATA, "WAF-Payload-Collection-main",
                           "WAF-Payload-Collection-main", "nuclei", "payloads")
WAF_DET_JSONL = os.path.join(TRAINDATA, "WAF_DETECTION_DATASET.jsonl")

EXCLUDED = {
    "CVE_list.json": "JSON 截断（9.5MB 处 unterminated string），且非 HTTP 请求，无法转 80 维特征",
    "AgentCyberRangeWebExploitBench/": "只有 readme.md，内容为“等待通过”，无数据",
    "http-attack-requests.json": "395 字节的清单说明（real/topup 计数），不是数据",
}

# --------------------------------------------------------------------------- 标签
XLSX_LABEL = {"normal": 0, "sqli": 1, "xss": 2, "rce": 3, "fileinclusion-ldf": 4}
MODSEC_LABEL = {941: 2, 944: 2, 942: 1, 930: 4, 931: 4, 932: 3, 933: 3, 934: 3}
PAYLOAD_LABEL = {"sqli": 1, "xss": 2, "cmdexe": 3, "log4shell": 3, "shellshock": 3,
                 "xxe": 3, "traversal": 4, "lfi": 4}

# --------------------------------------------------------------------------- 采样口径
# parquet train 有 154 万正常行，全量进监督训练既没必要也拖时间：
# 用请求文本 sha1 的稳定桶做均匀抽样（不依赖行序，可复现）。
BENIGN_TRAIN_PERMILLE = 400     # ~154 万 * 40% 候选 -> 去重后约几万条唯一良性
BENIGN_HOLDOUT_PERMILLE = 40    # 留出桶（与训练桶互斥），去重后数千条
SEED = 20261112

_NORM_RE = re.compile(r"\d+")
_WS_RE = re.compile(r"\s+")

# 良性去污染：WAF Data v2 的 `normal` 标签是**WAF 判定**，不是地面真值 ——
# 实测 1.7% 的行（去重后约 5-8%）在 URL/body 里直接写着 `/etc/passwd`、
# `<script>alert(1)</script>`、`%00`、`../` 等。把这些当良性会同时造成两件事：
#   ① 监督训练把明显攻击教成 normal；
#   ② 良性校准池里混进攻击 ⇒ 1% 分位阈值被抬高，工作点失真。
# 因此 **只对自动标注的 normal 行**做保守剔除（人工标注的 false-positives 保留，
# 那些本来就是"看起来像攻击"的困难负例）。
_BENIGN_DENY = [re.compile(p, re.I) for p in (
    r"etc(?:%2f|/)(?:passwd|shadow)",
    r"(?:%3c|<)script",
    r"%00",
    r"(?:\.\./|%2e%2e%2f|%2f\.\.%2f)",
    r"union\s+(?:all\s+)?select",
    r"(?:%3b|;|\||%7c|&&)\s*(?:cat|ls|id|whoami|wget|curl|nc)\b",
    r"/bin/(?:sh|bash)\b",
    r"xp_cmdshell",
    r"<!--|#exec",                             # SSI 注入
    r"%3c!?%21--|%23exec",                     # 同上，URL 编码形态
    r"wp-(?:login|admin|includes|content)[^?]*\.(?:zip|orig|bak|old|sql)\b",
    # CMS 路径上的备份/源码探测（`/blog/index.zip`、`/javascript/xls.orig`、`.save`…）
    r"(?:wp-[a-z-]+|blog|javascript|phpmyadmin|bin)[^?\n]*\.(?:zip|orig|bak|old|sql|save|tgz|tar\.gz)(?:\?|\n|$)",
)]


def benign_suspect(s: Dict) -> bool:
    """自动标注的 normal 行是否含有高精度攻击标记（用于良性池去污染）。"""
    text = (s.get("path") or "") + "?" + (s.get("query") or "") + "\n" + (s.get("body") or "")
    return any(rx.search(text) for rx in _BENIGN_DENY)


def template(text: str) -> str:
    """把数字掩码、空白归一 —— 用来做**分组切分**的键（同模板不跨集合）。"""
    t = (text or "").lower()
    t = _NORM_RE.sub("#", t)
    return _WS_RE.sub(" ", t).strip()[:400]


def req_text(s: Dict) -> str:
    body = s.get("body") or ""
    q = s.get("query") or ""
    url = (s.get("path") or "") + (("?" + q) if q else "")
    return f"{s.get('method') or 'GET'} {url}\n{body}"


def req_sha1(s: Dict) -> str:
    return hashlib.sha1(req_text(s).encode("utf-8", "replace")).hexdigest()


REQ_KEYS = ("method", "path", "query", "body")


def req_key(s: Dict) -> str:
    """与 `thresholds.req_key` **逐字相同**的请求指纹串。

    为什么单独一个：去重/分桶用 `req_text`（人能读），而校准池污染检查用
    `thresholds.req_key` 的 `\x1f` 拼接口径。两者如果混用，`--train-keys` 永远对不上，
    污染检查会静默失效 —— 那是"阈值偏乐观 8 倍"的直接来源。
    """
    return "\x1f".join(str(s.get(k) or "") for k in REQ_KEYS)


def req_key_sha1(s: Dict) -> str:
    """`training_keys.txt` 每行的格式（与 thresholds.py 的池指纹同口径）。"""
    return hashlib.sha1(req_key(s).encode("utf-8", "replace")).hexdigest()


def _bucket(text: str) -> int:
    return int(hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:8], 16) % 1000


def _split_url(url: str) -> Tuple[str, str]:
    """`http://h/p?q` 或 `/p?q` -> (path, query)。"""
    rest = url or ""
    if rest.startswith("http://") or rest.startswith("https://"):
        rest = rest.split("://", 1)[1]
        slash = rest.find("/")
        rest = rest[slash:] if slash >= 0 else "/"
    if "?" in rest:
        p, q = rest.split("?", 1)
        return p, q
    return rest, ""


def _mk(method: str, url: str, body: str, label: Optional[int], source: str,
        headers: str = "") -> Dict:
    path, query = _split_url(url)
    row = {
        "method": (method or "GET").upper(),
        "path": path or "/",
        "query": query,
        "body": body or "",
        "headers": {},
        "label": label,
        "source": source,
    }
    row["group"] = template(req_text(row))
    return row


# --------------------------------------------------------------------------- 1. xlsx
def load_xlsx(path: str = XLSX, verbose: bool = True) -> Tuple[List[Dict], Dict]:
    """ModSecurity 审计表 -> 事务级样本。

    ⚠️ 这个表 **不是一行一个请求**：108,883 行只对应 27,686 个 `transaction_id`，
    因为一个事务命中的每条规则都占一行（`sqli` 标签下 12,820 行其实是 920
    协议规则的命中）。直接按行训练等于给多规则命中的请求重复加权，还会把
    同一请求同时标成 normal 和 sqli。所以：
      1. 按 transaction_id 聚合：攻击类按命中行数取众数，无攻击行才判 normal；
      2. 标签只认 xlsx 的 `label` 列（出处），不拿规则号二次推断；
      3. 按 (method,url,body) 去重（27,686 -> 18,474）；
      4. bruteforce / 其他无槽位标签 -> label=None（二分类评估用）。
    """
    import pandas as pd

    if not os.path.exists(path):
        raise SystemExit(f"缺少 {path}（新语料未放到 traindata/？）")
    df = pd.read_excel(path)
    need = {"transaction_id", "request_line_method", "request_line_url",
            "request_body", "label"}
    missing = need - set(df.columns)
    if missing:
        raise SystemExit(f"xlsx 缺列 {sorted(missing)}")

    stats = {"rows": int(len(df)), "transactions": int(df["transaction_id"].nunique())}
    label_rows = collections.Counter(df["label"].astype(str))

    # 事务级标签：攻击行数最多的类胜出；平票按 1<2<3<4 取小；无攻击行 -> normal
    grp = df.groupby("transaction_id", sort=False)
    rows: List[Dict] = []
    dropped_unmapped = 0
    multi = 0
    for txn, g in grp:
        counts = collections.Counter(g["label"].astype(str))
        attack = [(XLSX_LABEL[k], n) for k, n in counts.items()
                  if k in XLSX_LABEL and XLSX_LABEL[k] != 0]
        if len(counts) > 1:
            multi += 1
        if attack:
            attack.sort(key=lambda kv: (-kv[1], kv[0]))
            lab = attack[0][0]
        elif counts.get("normal", 0):
            lab = 0
        else:
            lab = None          # bruteforce 等无槽位：不进 5 类训练
            dropped_unmapped += 1
        first = g.iloc[0]
        body = "" if pd.isna(first["request_body"]) else str(first["request_body"])
        rows.append(_mk(str(first["request_line_method"]), str(first["request_line_url"]),
                        body, lab, "xlsx"))

    # 按请求文本去重；同文本标签冲突时攻击优先
    uniq: Dict[str, Dict] = {}
    conflict = 0
    for r in rows:
        k = req_text(r)
        old = uniq.get(k)
        if old is None:
            uniq[k] = r
            continue
        conflict += 1
        if (old["label"] in (0, None)) and (r["label"] not in (0, None)):
            uniq[k] = r
    out = list(uniq.values())
    # 与 parquet 同一套良性去污染（xlsx 的 normal 也来自 WAF 判定而非地面真值）
    n_sus = sum(1 for r in out if r["label"] == 0 and benign_suspect(r))
    if n_sus:
        out = [r for r in out if not (r["label"] == 0 and benign_suspect(r))]
    stats.update({
        "label_rows": dict(label_rows),
        "transactions_multi_label": multi,
        "rows_unmapped_label": dropped_unmapped,
        "unique_requests": len(out),
        "benign_suspect_dropped": n_sus,
        "deduped_rows": conflict,
        "label_counts": {str(k): v for k, v in
                         collections.Counter(r["label"] for r in out).items()},
        "with_body": sum(1 for r in out if r["body"]),
        "methods": dict(collections.Counter(r["method"] for r in out)),
        "hosts": int(df["request_host"].nunique()),
        "ips": int(df["remote_address"].nunique()),
    })
    if verbose:
        print(f"[xlsx] {stats['rows']:,} 行 -> {stats['transactions']:,} 事务 -> "
              f"{len(out):,} 唯一请求  标签 {stats['label_counts']}  body {stats['with_body']}")
    return out, stats


# --------------------------------------------------------------------------- 2. parquet
def _iter_parquet(path: str, columns=("method", "url", "body", "label"),
                  batch_size: int = 100_000) -> Iterable[Dict]:
    import pyarrow.parquet as pq

    pf = pq.ParquetFile(path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=list(columns)):
        d = batch.to_pydict()
        n = len(d["method"])
        for i in range(n):
            yield {
                "method": d["method"][i],
                "url": d["url"][i],
                "body": d["body"][i] or "",
                "label": d["label"][i],
            }


def load_parquet(split: str = "train", mode: str = "all",
                 permille: Optional[int] = None,
                 verbose: bool = True) -> Tuple[List[Dict], Dict]:
    """`WAF Data v2` -> 请求列表。

    mode:
      * "all"     : 全部行（评估用；test 只有 24 万行）
      * "benign"  : 只收 normal，并按请求文本 sha1 的稳定桶抽样（训练/留出用）
    `anomalous` **没有子类**，因此 label=None —— 只能做二分类评估，
    绝不能硬塞进 5 类监督训练（会把"未知攻击"教成某一类）。
    """
    path = PARQUET_TRAIN if split == "train" else PARQUET_TEST
    out: List[Dict] = []
    stats = collections.Counter()
    seen = set()
    for i, r in enumerate(_iter_parquet(path)):
        stats["rows"] += 1
        stats["label_" + str(r["label"])] += 1
        lab = 0 if r["label"] == "normal" else None
        if mode == "benign":
            if lab != 0:
                continue
            if _bucket(req_text({"method": r["method"], "path": r["url"],
                                 "query": "", "body": r["body"]})) >= permille:
                continue
        row = _mk(r["method"], r["url"], r["body"], lab,
                  f"parquet-{'normal' if lab == 0 else 'anomalous'}")
        k = req_text(row)
        if k in seen:          # 该语料里同一请求重复率极高（约 10% 唯一），边扫边去重
            stats["duplicates"] += 1
            continue
        seen.add(k)
        if lab == 0 and benign_suspect(row):
            stats["benign_suspect_dropped"] += 1
            continue
        out.append(row)
        if r["body"]:
            stats["with_body"] += 1
    if verbose:
        print(f"[parquet:{split}] 扫描 {stats['rows']:,} 行 -> 唯一请求 {len(out):,} 条 "
              f"(mode={mode}{',' + str(permille) + '‰' if permille else ''}, "
              f"重复 {stats.get('duplicates', 0):,}, "
              f"良性去污染剔除 {stats.get('benign_suspect_dropped', 0):,})")
    return out, dict(stats)


# --------------------------------------------------------------------------- 3. ModSecurity 审计日志
_SEC_RE = re.compile(r"^--([0-9a-fA-F]+)-([A-Z])--\s*$")
_RID_RE = re.compile(r'\[id "(\d+)"\]')


def load_modsec(pattern: str = OWASP_GLOB, verbose: bool = True) -> Tuple[List[Dict], Dict]:
    """OWASP ModSecurity 审计日志 -> 真实在野攻击请求。

    格式：每个事务 `--<id>-A--` 起，B 段是请求行+头，C 段是请求体（可选），
    H 段是命中的规则。**H 段必然存在**（这批日志只收命中规则的事务）——
    所以本语料**零良性**，不能当良性池；标签由规则号前缀映射，未识别的
    规则（920/921/913/980/949…）-> label=None，只进二分类评估。

    切分按**日期文件**做（30 天 -> 训练/评估按天分组），避免同一扫描波
    的同源请求跨集合。
    """
    files = sorted(glob.glob(pattern))
    if not files:
        raise SystemExit(f"未找到 ModSecurity 审计日志：{pattern}")
    rows: List[Dict] = []
    stats = collections.Counter()

    def flush(cur: Dict, day: str):
        if not cur.get("line"):
            return
        stats["requests"] += 1
        body = "\n".join(x for x in cur.get("_body") or [] if x)[:65536]
        if body:
            stats["with_body"] += 1
        ids = cur.get("rids") or []
        fams = [MODSEC_LABEL[int(r[:3])] for r in ids if r[:3].isdigit()
                and int(r[:3]) in MODSEC_LABEL]
        lab = collections.Counter(fams).most_common(1)[0][0] if fams else None
        if lab is None:
            stats["unclassified"] += 1
        else:
            stats["label_" + str(lab)] += 1
        part, _, rest = cur["line"].partition(" ")
        target = rest.split(" ")[0] if rest else "/"
        rows.append(_mk(part, target, body, lab, f"modsec-{day}"))

    for path in files:
        day = os.path.basename(os.path.dirname(path))
        cur: Dict = {}
        section = None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.rstrip("\r\n")
                m = _SEC_RE.match(line)
                if m:
                    if m.group(2) == "A":
                        if cur:
                            flush(cur, day)
                        cur, section = {"day": day}, None
                    else:
                        section = m.group(2)
                    continue
                if not cur:
                    continue
                if section == "B":
                    if line and not cur.get("line") and re.match(
                            r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE) ", line):
                        cur["line"] = line
                elif section == "C":
                    cur.setdefault("_body", []).append(line)
                elif section == "H":
                    cur.setdefault("rids", []).extend(_RID_RE.findall(line))
        if cur:
            flush(cur, day)
    stats["files"] = len(files)
    stats["days"] = len({os.path.basename(os.path.dirname(p)) for p in files})
    if verbose:
        print(f"[modsec] {stats['files']} 天 / {stats['requests']:,} 请求 "
              f"body {stats['with_body']}  已分类 {stats['requests'] - stats['unclassified']:,}")
    return rows, dict(stats)


# --------------------------------------------------------------------------- 4. 载荷集合
def load_payload_collection(root: str = PAYLOAD_DIR, verbose: bool = True
                            ) -> Tuple[List[Dict], Dict]:
    """WAF-Payload-Collection -> 以 `q=<payload>` 嵌入的请求。

    纯载荷没有 method/path，必须嵌入固定模板才能过 80 维特征；这与旧
    `load_payloads` 的 `q=` 口径一致，避免"位置"变成捷径。
    `false-positives.txt` 是**已知会被规则误报的合法/边界文本**，作为困难
    良性负例（label=0）；`true-positives.txt` 按目录族映射到 1-4。
    """
    if not os.path.isdir(root):
        raise SystemExit(f"未找到载荷集：{root}")
    rows: List[Dict] = []
    stats = collections.Counter()
    for fam in sorted(os.listdir(root)):
        d = os.path.join(root, fam)
        if not os.path.isdir(d):
            continue
        for name, lab in (("true-positives.txt", PAYLOAD_LABEL.get(fam)), ("false-positives.txt", 0)):
            p = os.path.join(d, name)
            if not os.path.exists(p):
                continue
            n = 0
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    payload = line.rstrip("\r\n")
                    if not payload.strip():
                        continue
                    n += 1
                    rows.append(_mk("GET", "/api/search?q=" + payload, "", lab,
                                    f"payload-{fam}-{'tp' if lab else 'fp'}"))
            stats[f"{fam}:{'tp' if lab else 'fp'}"] = n
    if verbose:
        print(f"[payload] {len(rows):,} 条（攻击 "
              f"{sum(v for k, v in stats.items() if k.endswith(':tp')):,} / "
              f"已知误报 {sum(v for k, v in stats.items() if k.endswith(':fp')):,}）")
    return rows, dict(stats)


def load_waf_detection_jsonl(path: str = WAF_DET_JSONL, verbose: bool = True
                             ) -> Tuple[List[Dict], Dict]:
    """`WAF_DETECTION_DATASET.jsonl` -> 攻击请求（**无子类**）。

    650 行里有 13 行括号不配对（文件本身损坏），逐行容错跳过并计数；
    `payload` 字段是攻击载荷，但 `technique` 描述的是"WAF 怎么拦的"，
    不是攻击类型，所以不猜子类：label=None，只进二分类评估。
    """
    import json as _json

    rows: List[Dict] = []
    bad = 0
    wafs = collections.Counter()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = _json.loads(line)
            except ValueError:
                bad += 1
                continue
            payload = o.get("payload") or ""
            wafs[str(o.get("waf"))] += 1
            rows.append(_mk("GET", "/api/search?q=" + payload, "", None,
                            f"wfdet-{o.get('waf')}"))
    if verbose:
        print(f"[wfdet] {len(rows):,} 条可用 / 坏行 {bad}  （{len(wafs)} 家 WAF）")
    return rows, {"rows": len(rows), "bad_lines": bad, "wafs": dict(wafs)}


# --------------------------------------------------------------------------- 5. 切分
def _assign_by_group(rows: List[Dict], train_pct: int = 70, valid_pct: int = 15
                     ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """按 group（URL 模板）稳定哈希切分：同模板整体进同一集合。"""
    tr, va, te = [], [], []
    for r in rows:
        b = _bucket(r["group"])
        if b < train_pct * 10:
            tr.append(r)
        elif b < (train_pct + valid_pct) * 10:
            va.append(r)
        else:
            te.append(r)
    return tr, va, te


def _dedupe(rows: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for r in rows:
        k = req_text(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def labeled(rows: List[Dict]) -> List[Dict]:
    """5 类训练/评估只收 label ∈ 0-4；None = 无子类攻击，只进二分类评估。"""
    return [r for r in rows if r["label"] is not None]


def build_dataset(verbose: bool = True) -> Dict:
    """构建训练/验证/测试/评估集 + 良性校准池。返回 dict（含 stats）。"""
    stats: Dict = {"excluded": EXCLUDED}

    xlsx_rows, stats["xlsx"] = load_xlsx(verbose=verbose)
    xlsx_lab = [r for r in xlsx_rows if r["label"] is not None]
    xlsx_unl = [r for r in xlsx_rows if r["label"] is None]
    x_tr, x_va, x_te = _assign_by_group(xlsx_lab)

    pq_benign, stats["parquet_benign"] = load_parquet(
        "train", mode="benign", permille=BENIGN_TRAIN_PERMILLE + BENIGN_HOLDOUT_PERMILLE,
        verbose=verbose)
    # 训练桶与留出桶互斥（同一请求文本不可能同时落两个桶）
    pq_train = [r for r in pq_benign if _bucket(req_text(r)) < BENIGN_TRAIN_PERMILLE]
    pq_hold = [r for r in pq_benign if _bucket(req_text(r)) >= BENIGN_TRAIN_PERMILLE]

    ms_rows, stats["modsec"] = load_modsec(verbose=verbose)
    ms_cls = [r for r in ms_rows if r["label"] is not None]
    ms_unl = [r for r in ms_rows if r["label"] is None]
    m_tr, m_va, m_te = _assign_by_group(ms_cls)

    pay_rows, stats["payloads"] = load_payload_collection(verbose=verbose)
    pay_atk = [r for r in pay_rows if r["label"] not in (0, None)]
    pay_fp = [r for r in pay_rows if r["label"] == 0]
    p_tr, p_va, p_te = _assign_by_group(pay_atk)
    fp_tr, fp_va, fp_te = _assign_by_group(pay_fp)

    wd_rows, stats["waf_detection"] = load_waf_detection_jsonl(verbose=verbose)
    wd_tr, wd_va, wd_te = _assign_by_group(wd_rows)

    pq_test, stats["parquet_test"] = load_parquet("test", mode="all", verbose=verbose)

    train = _dedupe(labeled(x_tr + pq_train + m_tr + p_tr + fp_tr))
    valid = _dedupe(labeled(x_va + m_va + p_va + fp_va))
    test = _dedupe(labeled(x_te + m_te + p_te + fp_te))

    # 防泄漏：test/valid 出现过的请求文本必须从 train 剔除（跨语料同请求）
    seen = {req_text(r) for r in test} | {req_text(r) for r in valid}
    before = len(train)
    train = [r for r in train if req_text(r) not in seen]
    leaked = before - len(train)

    holdout = _dedupe(pq_hold)
    hold_keys = {req_text(r) for r in train} | {req_text(r) for r in valid} | \
                {req_text(r) for r in test}
    holdout = [r for r in holdout if req_text(r) not in hold_keys]
    # ⚠️ 不能直接取前 12,000 条：parquet 按时间/写入顺序排列，前 N 条是**有偏子集**
    # （实测其 1% 分位与全量留出差 ~0.8 个分数单位，IF 检出率 82.7% vs 13.3%）。
    # 按请求指纹排序后再截断 = 确定性均匀抽样，且与文件顺序无关。
    holdout.sort(key=req_key_sha1)
    holdout = holdout[:12000]

    def by_label(rows):
        return {str(k): v for k, v in
                collections.Counter(r["label"] for r in rows).items()}

    stats.update({
        "n_train": len(train), "n_valid": len(valid), "n_test": len(test),
        "n_benign_holdout": len(holdout),
        "train_by_label": by_label(train),
        "valid_by_label": by_label(valid),
        "test_by_label": by_label(test),
        "cross_corpus_leak_removed": leaked,
        "with_body": {"train": sum(1 for r in train if r["body"]),
                      "valid": sum(1 for r in valid if r["body"]),
                      "test": sum(1 for r in test if r["body"])},
        "sources": {k: dict(collections.Counter(r["source"].split("-")[0] for r in rows))
                    for k, rows in (("train", train), ("test", test))},
        "unclassified_eval": {
            "xlsx": len(xlsx_unl), "modsec": len(ms_unl), "waf_detection": len(wd_te),
        },
    })
    if verbose:
        print(f"[split] train {len(train):,} / valid {len(valid):,} / test {len(test):,}  "
              f"良性留出 {len(holdout):,}  跨语料重复剔除 {leaked}")
        print(f"[labels] train {stats['train_by_label']}")
        print(f"[labels] test  {stats['test_by_label']}")
    return {
        "train": train, "valid": valid, "test": test, "benign_holdout": holdout,
        "parquet_test": pq_test, "unclassified": xlsx_unl + ms_unl + wd_te,
        "stats": stats,
    }


# --------------------------------------------------------------------------- CLI
def _inventory() -> Dict:
    """只读盘点（不训练）：行数/标签/坏行/排除原因，写 artifacts/traindata_catalog_waf.json。"""
    inv: Dict = {"generated_at": None, "root": TRAINDATA, "corpora": {}, "excluded": EXCLUDED}
    import datetime as _dt
    inv["generated_at"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows, st = load_xlsx()
    inv["corpora"]["xlsx"] = {**st, "role": "主训练集（4 类攻击 + 良性）",
                              "usable": "可用（按事务聚合 + 去重后）"}
    rows, st = load_modsec()
    inv["corpora"]["modsec"] = {**st, "role": "真实在野攻击（召回评估 + 训练）",
                                "usable": "攻击-only，零良性"}
    rows, st = load_parquet("train", mode="benign", permille=3)
    inv["corpora"]["parquet_train"] = {**st, "role": "良性池（anomalous 无子类）",
                                       "usable": "正常可训练；异常只做二分类评估"}
    rows, st = load_parquet("test", mode="all")
    inv["corpora"]["parquet_test"] = st
    rows, st = load_payload_collection()
    inv["corpora"]["payloads"] = st
    rows, st = load_waf_detection_jsonl()
    inv["corpora"]["waf_detection"] = st
    return inv


def main() -> None:
    ap = argparse.ArgumentParser(description="新 traindata 接入层")
    ap.add_argument("--probe", action="store_true", help="只读盘点，写 artifacts/wafdata_inventory.json")
    ap.add_argument("--build", action="store_true", help="构建数据集并打印切分统计")
    ap.add_argument("--export-holdout", default=None, help="把良性留出导出成 jsonl（阈值标定用）")
    ap.add_argument("--out", default=os.path.join(HERE, "artifacts", "wafdata_inventory.json"))
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    if args.probe:
        inv = _inventory()
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(inv, f, ensure_ascii=False, indent=2)
        print(f"[inventory] -> {os.path.relpath(args.out, HERE)}")
        return

    ds = build_dataset()
    if args.export_holdout:
        os.makedirs(os.path.dirname(os.path.abspath(args.export_holdout)), exist_ok=True)
        with open(args.export_holdout, "w", encoding="utf-8") as f:
            for r in ds["benign_holdout"]:
                f.write(json.dumps({k: r[k] for k in ("method", "path", "query", "body")},
                                   ensure_ascii=False) + "\n")
        print(f"[holdout] -> {args.export_holdout} ({len(ds['benign_holdout'])} 条)")


if __name__ == "__main__":
    main()
