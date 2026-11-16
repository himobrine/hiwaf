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

2026-11-16 新增语料（见 §4.5）：
  FUR-API/train.csv: normal->0；anomaly->None（**业务异常**，不是攻击子类，
                   不能塞进 1=sqli）；test.csv 只做评估，不进训练
  SQLiV5.json:       type=sqli->1；type=valid（**合法 SQL**）-> 排除，
                   与 wafamole `sane.sql` 同理：合法 SQL 放进参数里与 SQLi 不可区分
  wafamole attacks.sql: 每行一条 WAF-A-MoLE 变异后的 SQLi 载荷 -> 1（稳定哈希抽样）
  wafrift corpus:    sql->1, xss->2, cmdi/ssti/xxe/ssrf/log4shell->3, path->4；
                   ldap/nosql/graphql/ssi/cve_pocs 无 0-4 槽位 -> 只计数不进训练
  waffled bypass:    原始 HTTP 报文，按 body/query 内容分 sqli->1 / xss->2

明确排除（并在 inventory 里写明原因）：
  * CVE_list.json —— JSON 在 9.5MB 处截断（unterminated string），且不是 HTTP 请求
  * AgentCyberRangeWebExploitBench/ —— 只有 readme（内容"等待通过"），无数据
  * http-attack-requests.json —— 395 字节的清单说明，不是数据
  * wafamole_dataset/sane.sql —— 合法 SQL DDL/DML；塞进参数后与 SQLi 不可区分
  * sqliv5 的 SQLiV3/V4/V3_clean —— V5 是它们的超集（含 WAF-A-MoLE 对抗样本）
  * commonhuman-payloads-main/ —— 载荷库 + 编码器，带 `{marker}` 占位符；
                    不替换会变成捷径 token，本轮只登记不训练
"""
from __future__ import annotations

import argparse
import ast
import collections
import csv
import glob
import hashlib
import heapq
import io
import json
import os
import random
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, unquote

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

# ---- 2026-11-16 新增语料 ----
FUR_TRAIN = os.path.join(TRAINDATA, "FUR-API", "train.csv")
FUR_TEST = os.path.join(TRAINDATA, "FUR-API", "test.csv")
SQLIV5_DIR = os.path.join(TRAINDATA, "sqliv5-dataset-main", "sqliv5-dataset-main")
SQLIV5_JSON = os.path.join(SQLIV5_DIR, "SQLiV5.json")
SQLIV5_CSV = os.path.join(SQLIV5_DIR, "sqli.csv")
WAFAMOLE_DIR = os.path.join(TRAINDATA, "wafamole_dataset")
WAFAMOLE_ATTACKS = os.path.join(WAFAMOLE_DIR, "attacks.sql")
WAFAMOLE_SANE = os.path.join(WAFAMOLE_DIR, "sane.sql")
WAFRIFT_CORPUS = os.path.join(TRAINDATA, "wafrift-main", "wafrift-bench", "corpus")
WAFFLED_DIR = os.path.join(TRAINDATA, "waffled-main", "waffled-main",
                           "bypass-database")
COMMONHUMAN_DIR = os.path.join(TRAINDATA, "commonhuman-payloads-main")

EXCLUDED = {
    "CVE_list.json": "JSON 截断（9.5MB 处 unterminated string），且非 HTTP 请求，无法转 80 维特征",
    "AgentCyberRangeWebExploitBench/": "只有 readme.md，内容为“等待通过”，无数据",
    "http-attack-requests.json": "395 字节的清单说明（real/topup 计数），不是数据",
    "wafamole_dataset/sane.sql": (
        "合法 SQL（DDL/DML）。把它塞进参数当良性会教出“SELECT 是正常”的捷径，"
        "而它在参数位置上与 SQLi 不可区分；只登记，不入训练"),
    "sqliv5-dataset-main/": (
        "只取 SQLiV5.json 的 type=sqli 与 sqli.csv 的 Label=1；"
        "type=valid（合法 SQL）与 SQLiV3/V4/V3_clean（V5 已超集）全部排除，"
        "sqliv2.csv（旧版重复）与 Label=0（英文诗句，非请求）同样不进训练"),
    "commonhuman-payloads-main/": (
        "载荷库 + 编码器，载荷带 `{marker}` 占位符，不替换会成为捷径 token；"
        "全笛卡尔积会淹没其它类，本轮只登记不训练"),
    "FUR-API/test.csv": "评估专用（984 normal / 137 anomaly），绝不进训练",
    "exploit_dataset.jsonl": "评估专用（172 条 HTTP PoC），不进训练",
    "wafrift-main/wafrift-bench/targets/": "靶场编排/检测脚本，不是载荷数据",
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

# 新语料上限：SQLi 语料体量远大于其它类，全量会淹没 ModSec（15 万）与 xlsx。
# 上限 + 稳定哈希抽样（与扫描顺序无关，可复现），保证每份语料都能反查。
FUR_MAX = 20000                 # FUR train.csv 有 20,060 行（20,000 normal + 60 anomaly）
SQLIV5_MAX = 15000              # SQLiV5 有 21,013 条 sqli（去重后取 15k）
WAFAMOLE_MAX = 20000            # attacks.sql 有 128 万行，抽样 20k
SQLI_MIN_LEN = 4                # sqli.csv 里 `a` / `?` / `@` 这类 1 字符“SQLi”是噪声


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


# ------------------------------------------------------------- 载荷去重 / 抽样
# 大规模载荷语料**不能**用 `textsim.leak_clusters`：它算稠密 n×n 相似度矩阵，
# 30k 条就是 3600 万浮点（~300MB）并做 O(n²) 并查集。这里只用
# 「小写 + 空白折叠」的**精确去重** + 稳定哈希抽样，代价 O(n)。
def _payload_norm(payload: str) -> str:
    """载荷归一化键：小写 + 空白折叠 + 去首尾空白（不掩码数字，避免误合并）。"""
    return _WS_RE.sub(" ", (payload or "").lower()).strip()


def _h64(text: str) -> int:
    return int(hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:16], 16)


class _TopK:
    """保留「归一化键哈希最小」的 N 条 —— 与扫描顺序无关的确定性均匀抽样。

    为什么不用 reservoir/`random.sample`：训练必须可复现，且同一份语料在不同
    机器/不同文件顺序下要抽出**同一批**行。哈希 Top-K 同时完成去重（键相同
    哈希必相同）和抽样，内存只跟 cap 有关，128 万行的 attacks.sql 也能流式跑。
    """

    def __init__(self, cap: int, normalize: bool = True):
        self.cap = int(cap)
        self.normalize = normalize      # False = 按给定键**精确**去重（FUR 的 req_key）
        self._heap: List[Tuple[int, str, Dict]] = []   # (-h, norm, row)
        self._keys = set()
        self.scanned = 0
        self.dup = 0

    def offer(self, norm: str, row: Dict) -> None:
        self.scanned += 1
        if self.normalize:
            norm = _payload_norm(norm)  # 幂等：调用方传原始载荷或已归一化都可以
        if not norm:
            return
        if norm in self._keys:
            self.dup += 1
            return
        h = _h64(norm)
        if len(self._heap) < self.cap:
            heapq.heappush(self._heap, (-h, norm, row))
            self._keys.add(norm)
            return
        if h < -self._heap[0][0]:
            _nh, nk, _nr = heapq.heapreplace(self._heap, (-h, norm, row))
            self._keys.discard(nk)
            self._keys.add(norm)

    def rows(self) -> List[Dict]:
        return [t[2] for t in self._heap]



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


# ======================================================================== 4.5
# 2026-11-16 新增语料。统一约束：
#   * 只进 train/valid（按 group 85/15），**不进 test** —— test 保持与现役 g3/g5
#     同一批行，指标才可比；新语料的价值由 FUR test / exploit 的独立评估体现。
#   * 去重只用 `_payload_norm` 精确去重；不做 textsim 稠密聚类（会爆内存）。
#   * 大语料（SQLi/wafamole）用 `_TopK` 稳定哈希抽样，上限写进 stats。
# ---------------------------------------------------------------------------
def read_text_any(path: str) -> str:
    """读文本：自动识别 UTF-16 BOM，UTF-8 失败回退 latin-1（`sqli.csv` 是 UTF-16）。"""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


FUR_LABEL = {"normal": 0, "anomaly": None}     # anomaly = 业务异常，不是攻击子类
# `request_body` 的缺失值被原始 CSV 写成了字面量 `nan`（pandas 产物），不是载荷。
# 9,034 行原始记录（去重后 7,242）是 GET/DELETE + body="nan"：当成真 body 会让模型
# 学到"三字母 body 是正常"，还会把 `nan` 当成一个可区分的捷径 token。
FUR_BODY_MISSING = {"nan", "none", "null"}


def load_fur_api(path: str = FUR_TRAIN, max_rows: int = FUR_MAX,
                 verbose: bool = True) -> Tuple[List[Dict], Dict]:
    """FUR-API `train.csv` -> 良性请求（normal -> 0）。

    `anomaly` 列是**业务异常**（流量/业务层面的异常），不是 sqli/xss 子类：
    映射成 1 会把业务异常教成 SQLi。这里只收 normal，anomaly 计数后丢弃。
    `test.csv` 是评估集，**不读**（见 `EXCLUDED`）。

    ⚠️ `request_headers` / `response_*` / `agent` 一律不入库：80 维特征只吃
    method/path/query/body，多存会让训练与线上口径漂移。
    ⚠️ `request_body` 的缺失值是字面量 `nan` / `None` / `null`（pandas 产物），
    必须还原成空 body；否则 40% 的良性样本会带一个"三字母 body"的假特征。
    """
    if not os.path.exists(path):
        raise SystemExit(f"缺少 {path}（FUR-API 未放到 traindata/？）")
    text = read_text_any(path)
    reader = csv.DictReader(io.StringIO(text))
    need = {"method", "request_url", "request_body", "type"}
    missing = need - set(reader.fieldnames or [])
    if missing:
        raise SystemExit(f"FUR-API 缺列 {sorted(missing)}")

    out: List[Dict] = []
    seen = set()
    stats = collections.Counter()
    by_type = collections.Counter()
    # normalize=False：FUR 去重用 **精确 req_key**（与 `training_keys` / 校准池
    # 污染检查同口径）。若走载荷归一化，仅大小写不同的请求会被合并，
    # 训练集规模就与 `training_keys.txt` 对不上（历史候选曾因此差 21 条）。
    top = _TopK(max_rows, normalize=False)
    for rec in reader:
        stats["rows"] += 1
        typ = str(rec.get("type") or "").strip().lower()
        by_type[typ or "<empty>"] += 1
        if FUR_LABEL.get(typ) != 0:
            stats["non_normal_dropped"] += 1
            continue
        method = str(rec.get("method") or "GET").strip().upper()
        url = str(rec.get("request_url") or "").strip()
        if not url:
            stats["missing_path"] += 1
            continue
        body = str(rec.get("request_body") or "").strip()
        if body.lower() in FUR_BODY_MISSING:
            stats["body_missing"] += 1
            body = ""
        row = _mk(method, url, body, 0, "fur-api")
        k = req_key(row)
        if k in seen:
            stats["duplicates"] += 1
            continue
        seen.add(k)
        top.offer(k, row)
    out = top.rows()
    stats["with_body"] = sum(1 for r in out if r["body"])
    if len(seen) > len(out):
        stats["sampled_down"] = len(seen) - len(out)
    if verbose:
        print(f"[fur-api] {stats['rows']:,} 行 -> normal {len(out):,} 条"
              f"（anomaly/其它丢弃 {stats.get('non_normal_dropped', 0):,}，"
              f"重复 {stats.get('duplicates', 0):,}，"
              f"body {stats['with_body']:,}，"
              f"缺失值占位符 {stats.get('body_missing', 0):,}，上限 {max_rows:,}）")
    for k in ("rows", "non_normal_dropped", "duplicates", "with_body",
              "missing_path", "max_rows", "sampled_down", "body_missing"):
        stats.setdefault(k, 0)
    return out, {**dict(stats), "by_type": dict(by_type), "cap": max_rows,
                 "label_counts": {"0": len(out)}}


def load_sqliv5(json_path: str = SQLIV5_JSON, csv_path: str = SQLIV5_CSV,
                max_sqli: int = SQLIV5_MAX, verbose: bool = True
                ) -> Tuple[List[Dict], Dict]:
    """SQLiV5 + sqli.csv -> SQLi 载荷（label=1），稳定哈希抽样到上限。

    **`type=valid` 不进训练**：那是合法 SQL，放在参数位置上与 SQLi 不可区分
    （与 wafamole `sane.sql` 同一理由）。V3/V4 是 V5 的子集（V5 = V3 + V4 +
    WAF-A-MoLE 对抗样本），所以只读 V5，避免三份重复把去重表撑大。
    `sqli.csv` 是 UTF-16，`Label=0` 是英文诗句（非请求），只取 `Label=1`；
    1-3 字符的条目（`a` / `?` / `@`）是噪声，丢弃并计数。
    """
    stats = collections.Counter()
    by_type = collections.Counter()
    top = _TopK(max_sqli)
    if os.path.exists(json_path):
        with open(json_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        stats["json_rows"] = len(data)
        for o in data:
            typ = str(o.get("type") or "").strip().lower()
            by_type[typ or "<empty>"] += 1
            if typ != "sqli":
                stats["non_sqli_dropped"] += 1
                continue
            payload = str(o.get("pattern") or "")
            top.offer(_payload_norm(payload),
                      _mk("GET", "/api/search?q=" + payload, "", 1, "sqliv5"))
    else:
        stats["json_missing"] = 1

    if os.path.exists(csv_path):
        text = read_text_any(csv_path)
        reader = csv.DictReader(io.StringIO(text))
        for rec in reader:
            stats["csv_rows"] += 1
            if str(rec.get("Label") or "").strip() != "1":
                stats["csv_benign_dropped"] += 1
                continue
            payload = str(rec.get("Sentence") or "").strip()
            if len(payload) < SQLI_MIN_LEN:
                stats["csv_short_dropped"] += 1
                continue
            stats["csv_sqli"] += 1
            top.offer(_payload_norm(payload),
                      _mk("GET", "/api/search?q=" + payload, "", 1, "sqliv5-csv"))

    rows = top.rows()
    for k in ("json_rows", "non_sqli_dropped", "csv_rows", "csv_benign_dropped",
              "csv_short_dropped", "csv_sqli", "json_missing"):
        stats.setdefault(k, 0)
    if verbose:
        print(f"[sqliv5] {stats.get('json_rows', 0):,} 条 JSON（sqli "
              f"{by_type.get('sqli', 0):,} / valid 排除 {by_type.get('valid', 0):,}）"
              f" + csv sqli {stats.get('csv_sqli', 0):,} -> 抽样 {len(rows):,}"
              f"（上限 {max_sqli:,}，重复 {top.dup:,}）")
    return rows, {**dict(stats), "by_type": dict(by_type), "sampled": len(rows),
                  "cap": max_sqli, "duplicates_in_sample": top.dup,
                  "rows_scanned": top.scanned}

def load_wafamole(path: str = WAFAMOLE_ATTACKS, max_rows: int = WAFAMOLE_MAX,
                  max_len: int = 2048, verbose: bool = True
                  ) -> Tuple[List[Dict], Dict]:
    """WAF-A-MoLE `attacks.sql` -> SQLi 载荷（label=1）。

    **一行就是一条 WAF-A-MoLE 变异后的攻击 SQL**，不是一整个请求。所以不能按
    `;` 再切句：堆叠查询（`'; DROP TABLE ...`）本身就以 `;` 分隔，切开会把
    一条载荷碎成无意义的片段。整行作为载荷，超过 `max_len` 截断并计数。
    `sane.sql`（合法 SQL）在 `EXCLUDED` 里，**不当良性**。
    """
    if not os.path.exists(path):
        raise SystemExit(f"缺少 {path}（wafamole 未放到 traindata/？）")
    top = _TopK(max_rows)
    stats = collections.Counter()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            payload = raw.strip()
            if not payload:
                continue
            stats["lines"] += 1
            if len(payload) > max_len:
                payload = payload[:max_len]
                stats["truncated"] += 1
            top.offer(_payload_norm(payload),
                      _mk("GET", "/api/search?q=" + payload, "", 1, "wafamole"))
    rows = top.rows()
    for k in ("lines", "truncated"):
        stats.setdefault(k, 0)
    if verbose:
        print(f"[wafamole] {stats['lines']:,} 行 -> 抽样 {len(rows):,}"
              f"（上限 {max_rows:,}，重复 {top.dup:,}，截断 {stats['truncated']:,}）")
    return rows, {**dict(stats), "sampled": len(rows), "cap": max_rows,
                  "duplicates_in_sample": top.dup}


WAFRIFT_LABEL = {
    "sql": 1, "xss": 2,
    "cmdi": 3, "ssti": 3, "xxe": 3, "ssrf": 3, "log4shell": 3,
    "path": 4,
}


def load_wafrift_corpus(root: str = WAFRIFT_CORPUS, verbose: bool = True
                        ) -> Tuple[List[Dict], Dict]:
    """wafrift-bench 的 932 个 TOML case -> 载荷请求。

    13 个类里只有 8 个能映射到 0-4；`ldap/nosql/graphql/ssi/cve_pocs` 没有槽位，
    不让它们进 5 类训练（塞进某一类就是在教错标签），只计数。
    `mode = "raw_body"` 的 24 条（CVE PoC）必须放 body，不能塞 query —— 它们
    是序列化/反序列化报文，塞 query 会破坏结构。
    """
    if not os.path.isdir(root):
        raise SystemExit(f"缺少 wafrift 语料：{root}")
    try:
        import tomli
    except ImportError as exc:  # pragma: no cover - 环境缺依赖时给明确指令
        raise SystemExit("需要 tomli 解析 wafrift TOML：py -3.10 -m pip install tomli") from exc

    files = sorted(glob.glob(os.path.join(root, "**", "*.toml"), recursive=True))
    if not files:
        raise SystemExit(f"wafrift 语料为空：{root}")
    rows: List[Dict] = []
    seen = set()
    stats = collections.Counter()
    by_class = collections.Counter()
    for fp in files:
        try:
            with open(fp, "rb") as f:
                doc = tomli.load(f)
        except Exception:  # noqa: BLE001 - 坏 TOML 计数跳过，不中断整批
            stats["bad_files"] += 1
            continue
        for case in doc.get("case") or []:
            cls = str(case.get("class") or "").strip().lower()
            by_class[cls] += 1
            stats["cases"] += 1
            lab = WAFRIFT_LABEL.get(cls)
            payload = str(case.get("payload") or "")
            if lab is None or not payload:
                stats["unmapped_skipped"] += 1
                continue
            if str(case.get("mode") or "") == "raw_body":
                row = _mk("POST", "/api/upload", payload, lab, f"wafrift-{cls}")
                stats["raw_body"] += 1
            else:
                row = _mk("GET", "/api/search?q=" + payload, "", lab,
                          f"wafrift-{cls}")
            k = req_key(row)
            if k in seen:
                stats["duplicates"] += 1
                continue
            seen.add(k)
            rows.append(row)
    for k in ("bad_files", "cases", "unmapped_skipped", "duplicates", "raw_body"):
        stats.setdefault(k, 0)
    if verbose:
        print(f"[wafrift] {stats['cases']} case -> {len(rows)} 条"
              f"（无槽位跳过 {stats['unmapped_skipped']}，重复 {stats['duplicates']}）"
              f" 类分布 {dict(by_class)}")
    return rows, {**dict(stats), "files": len(files), "by_class": dict(by_class),
                  "label_counts": {str(k): v for k, v in collections.Counter(
                      r["label"] for r in rows).items()}}


_XSS_MARK = re.compile(
    r"<script|onerror\s*=|onload\s*=|javascript:|document\.cookie|svg/onload", re.I)
_SQL_MARK = re.compile(
    r"'\s*(?:and|or)\s+\d|union\s+(?:all\s+)?select|'\s*--|sleep\s*\(|"
    r"benchmark\s*\(|information_schema|'\s*;", re.I)
_WAFFLED_BLOCK = re.compile(r"b'''(.*?)'''", re.S)


def load_waffled_bypass(root: str = WAFFLED_DIR, verbose: bool = True
                        ) -> Tuple[List[Dict], Dict]:
    """WAFFFLED `bypass-database/*.raw` -> **带 body 的原始 HTTP 请求**。

    36 类绕过里最有价值的是 JSON / multipart / XML 报文体：现役语料 body 极少
    （xlsx 2,112 / parquet 89），而绕过正是发生在 body 解析上。文件里是
    `b'''...'''` 形式的 Python bytes 字面量，`\\r\\n` / `\\x00` 是转义序列，
    必须走 `ast.literal_eval` 才能还原真实字节（手写 replace 会漏）。

    ⚠️ 局限：头字段类绕过（`ContentType`、`Content_-Type`、头部 `\\x00`）在
    80 维特征里**看不见**——特征只吃 method/path/query/body。这些样本仍保留
    （body 里的载荷是真的），但别指望模型学到"畸形 header"。
    """
    if not os.path.isdir(root):
        raise SystemExit(f"缺少 waffled 语料：{root}")
    rows: List[Dict] = []
    seen = set()
    stats = collections.Counter()
    for fp in sorted(glob.glob(os.path.join(root, "*.raw"))):
        try:
            text = read_text_any(fp)
        except OSError:
            stats["bad_files"] += 1
            continue
        for m in _WAFFLED_BLOCK.finditer(text):
            stats["blocks"] += 1
            try:
                raw = ast.literal_eval("b'''" + m.group(1) + "'''")
                msg = raw.decode("latin-1")
            except (ValueError, SyntaxError):
                stats["bad_blocks"] += 1
                continue
            head, _, body = msg.partition("\r\n\r\n")
            lines = head.split("\r\n")
            parts = (lines[0] if lines else "").split(" ")
            if len(parts) < 2:
                stats["bad_request_line"] += 1
                continue
            method, target = parts[0], parts[1]
            blob = target + " " + body
            if _XSS_MARK.search(blob):
                lab = 2
            elif _SQL_MARK.search(blob):
                lab = 1
            else:
                lab = None
                stats["unclassified"] += 1
            row = _mk(method, target, body, lab, f"waffled-{os.path.basename(fp)[:-4]}")
            if body:
                stats["with_body"] += 1
            k = req_key(row)
            if k in seen:
                stats["duplicates"] += 1
                continue
            seen.add(k)
            rows.append(row)
    for k in ("bad_files", "blocks", "bad_blocks", "bad_request_line",
              "unclassified", "duplicates", "with_body"):
        stats.setdefault(k, 0)
    if verbose:
        print(f"[waffled] {stats['blocks']} 块 -> {len(rows)} 条"
              f"（坏块 {stats['bad_blocks']}，重复 {stats['duplicates']}，"
              f"body {stats['with_body']}）"
              f" 标签 {dict(collections.Counter(r['label'] for r in rows))}")
    return rows, {**dict(stats), "label_counts": {str(k): v for k, v in
                  collections.Counter(r["label"] for r in rows).items()}}



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


# ======================================================================== 4.6
# cmdi（label=3，含 ssti/xxe/ssrf 这类 RCE 家族）**形态对齐**。
#
# 为什么需要：exploit 集剩下的召回缺口全在同一形态 —— 短 JSON body / SOAP 里塞命令，
# 而现有 cmdi 样本几乎都是 query 参数（`?cmd=whoami`）。80 维特征对 body 形态很敏感，
# 模型因此学到"短 JSON body = 正常 API"，P(cmd) 掉到 1e-4 量级（实测，见 P0 诊断）。
#
# 修法只做**外壳**：
#   * 载荷字节原样保留（来自已有的真实 cmdi 行，不新造 payload）；
#   * 路径走通用池，**禁止使用评估集的路径**（`/api/jsonws/invoke` 等）——
#     特征里有 path 形态，抄路径等于把评估集写进训练；
#   * 键名 / 空白 / 长度随机化，避免模型学到"某一个固定模板"。
CMDI_WRAP_PATHS = (
    "/api/v1/exec", "/api/v1/run", "/api/task/run", "/service/invoke",
    "/api/actions", "/internal/command", "/api/v2/jobs", "/gateway/exec",
    "/api/v1/tools/call", "/remote/execute",
)
CMDI_WRAP_KEYS = ("cmd", "command", "exec", "args", "arguments", "payload", "input")
CMDI_WRAP_SOURCE = "cmdi-wrap"
BENIGN_WRAP_SOURCE = "benign-wrap"


def _cmdi_payload(row: Dict) -> str:
    """从一行 cmdi 请求里取出**载荷本体**（优先 body，其次 query）。

    形态可能是 `cmd=whoami`、`?exec=id`、或整段就是载荷。取「最长的参数值」：
    命令/脚本几乎总是比 `1`、`submit` 这类占位值长。
    """
    for raw in ((row.get("body") or "").strip(), (row.get("query") or "").strip()):
        if not raw:
            continue
        parts = []
        for p in raw.split("&"):
            v = p.split("=", 1)[1] if "=" in p else p
            v = unquote(v).strip()
            if v:
                parts.append(v)
        if parts:
            best = max(parts, key=len)
            if len(best) >= 3:
                return best
    return ""


def _wrap_payload_one(payload: str, rng: "random.Random", label: int,
                      source: str) -> Dict:
    path = rng.choice(CMDI_WRAP_PATHS)
    key = rng.choice(CMDI_WRAP_KEYS)
    js = json.dumps(payload, ensure_ascii=False)
    xml = (payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    pad = (',"id": "%d"' % rng.randrange(10 ** 6)) if rng.random() < 0.5 else ""
    shape = rng.randrange(5)
    if shape == 0:
        body = '{"%s": %s%s}' % (key, js, pad)
    elif shape == 1:
        body = '{"command": "run", "utilCmdArgs": %s%s}' % (js, pad)
    elif shape == 2:
        body = ("<soapenv:Envelope><soapenv:Body><cmd:run><cmd:arg>%s</cmd:arg>"
                "</cmd:run></soapenv:Body></soapenv:Envelope>") % xml
    elif shape == 3:
        body = "%s=%s" % (key, quote(payload, safe=""))
    else:
        body = '[{"%s": %s}]' % (key, js)
    return _mk("POST", path, body, label, source)


def wrap_payload_rows(rows: List[Dict], per_row: int, label: int, source: str,
                      seed: int = SEED, extract=_cmdi_payload) -> List[Dict]:
    """把载荷包进 FUR 形态外壳（纯函数，可单测）。

    `label` / `source` 由调用方给：攻击行标 3，**良性行标 0** —— 外壳必须标签中立，
    否则模型学到的是"JSON + cmd 键 = 攻击"，而不是"载荷内容 = 攻击"（实测会把
    FUR 正常流量误报从 0.6% 推到 1.9%）。
    """
    if per_row <= 0:
        return []
    rng = random.Random(seed)
    out: List[Dict] = []
    for r in rows:
        payload = extract(r)
        if not payload:
            continue
        payload = payload[:400]        # 超长载荷截断：贴合真实 API body 长度
        for _ in range(per_row):
            w = _wrap_payload_one(payload, rng, label, source)
            w["z"] = _h64(req_text(w))  # 排序用（不影响特征）
            out.append(w)
    out.sort(key=lambda r: r["z"])
    seen = set()
    deduped = []
    for r in out:
        k = req_text(r)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    for r in deduped:
        r.pop("z", None)
    return deduped


def wrap_cmdi_rows(rows: List[Dict], per_row: int = 3,
                   seed: int = SEED) -> List[Dict]:
    """cmdi 行 -> FUR 形态（label 3）。"""
    return wrap_payload_rows(rows, per_row, 3, CMDI_WRAP_SOURCE, seed)


def build_dataset(verbose: bool = True, include_fur: bool = True,
                  fur_max: int = FUR_MAX, cmdi_wrap: int = 0,
                  cmdi_wrap_neg: float = 1.0,
                  extra_rows: Optional[List[Dict]] = None) -> Dict:
    """构建训练/验证/测试/评估集 + 良性校准池。返回 dict（含 stats）。

    `include_fur=False` 只用于 A/B 对照：新攻击语料照收，但不并入 FUR 良性，
    用来单独量化「FUR 良性入训」对 FUR 正常流量误报的贡献。
    `fur_max` 用来做召回/误报的折中档位（全量 18k 会压制 body 类攻击的召回）。
    `extra_rows` 是外部增量（例如从控制台事件 + 人工反馈导出的快照）。它**只进 train**，
    并且照样过「跨语料泄漏剔除」，不会污染 valid/test/校准池。
    """
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

    # ---- 2026-11-16 新增语料：按 group 85/15 只进 train/valid，不进 test ----
    # 理由：test 必须与现役 g3/g5 同一批行，5 类 acc 才可比；新语料的效果由
    # FUR/test + exploit 的独立评估回答（eval_newdata.py）。
    nd: Dict = {}
    if include_fur:
        fur_rows, stats["fur_api"] = load_fur_api(max_rows=fur_max, verbose=verbose)
    else:
        fur_rows = []
        stats["fur_api"] = {"skipped": True, "reason": "A/B 对照：FUR 良性不入训"}
    nd["fur_api"] = len(fur_rows)
    fur_tr, fur_va, _ = _assign_by_group(fur_rows, 85, 15)

    sq_rows, stats["sqliv5"] = load_sqliv5(verbose=verbose)
    nd["sqliv5"] = len(sq_rows)
    sq_tr, sq_va, _ = _assign_by_group(sq_rows, 85, 15)

    am_rows, stats["wafamole"] = load_wafamole(verbose=verbose)
    nd["wafamole"] = len(am_rows)
    am_tr, am_va, _ = _assign_by_group(am_rows, 85, 15)

    wr_rows, stats["wafrift"] = load_wafrift_corpus(verbose=verbose)
    nd["wafrift"] = len(wr_rows)
    wr_tr, wr_va, _ = _assign_by_group(wr_rows, 85, 15)

    wf_rows, stats["waffled"] = load_waffled_bypass(verbose=verbose)
    nd["waffled"] = len(wf_rows)
    wf_tr, wf_va, _ = _assign_by_group(wf_rows, 85, 15)

    nd_tr = fur_tr + sq_tr + am_tr + wr_tr + wf_tr
    nd_va = fur_va + sq_va + am_va + wr_va + wf_va

    train = _dedupe(labeled(x_tr + pq_train + m_tr + p_tr + fp_tr + nd_tr))
    valid = _dedupe(labeled(x_va + m_va + p_va + fp_va + nd_va))
    test = _dedupe(labeled(x_te + m_te + p_te + fp_te))

    # ---- cmdi 形态对齐（可选，--cmdi-wrap N）----
    # 只从**已入训**的 label=3 行取载荷，再包装成 JSON/SOAP/form 形态。不新造 payload、
    # 不碰 test，也绝不使用 exploit 评估集的路径。
    #
    # ⚠️ 必须同时包**等量良性**：只包攻击会让模型学到「JSON body + cmd 键 = 攻击」，
    # 实测把 FUR 正常流量误报从 0.61% 推到 1.93%（P2 第一版 g6_w3）。外壳标签中立后，
    # 模型只能靠载荷内容区分。
    wrap_stats: Dict = {"per_row": int(cmdi_wrap), "train_cmdi": 0,
                        "wrapped_train": 0, "wrapped_benign_train": 0,
                        "wrapped_valid": 0, "wrapped_benign_valid": 0}
    if cmdi_wrap > 0:
        tr_cmdi = [r for r in train if r["label"] == 3]
        va_cmdi = [r for r in valid if r["label"] == 3]
        wrap_stats["train_cmdi"] = len(tr_cmdi)
        wt = wrap_cmdi_rows(tr_cmdi, per_row=cmdi_wrap)
        wv = wrap_cmdi_rows(va_cmdi, per_row=max(1, cmdi_wrap // 3), seed=SEED + 1)

        def benign_payload(row: Dict) -> str:
            for v in ((row.get("body") or "").strip(), (row.get("query") or "").strip(),
                      (row.get("path") or "").strip()):
                if len(v) >= 3:
                    return v
            return ""

        def pick_benign(pool: List[Dict], n: int) -> List[Dict]:
            # 良性外壳必须优先取 **FUR 真实 API body**：FPR 就发生在那一域。
            # 早期版本从全部良性里按哈希抽，被 22 万条 parquet 长英文文本淹没，
            # 结果模型把"短 JSON body"整体推向攻击侧（FUR FPR 0.61% -> 1.93%）。
            def fam(r):
                return (r.get("source") or "").split("-")[0]

            cand = [r for r in pool if r["label"] == 0 and benign_payload(r)]
            cand.sort(key=lambda r: _h64(req_text(r)))
            fur_like = [r for r in cand if fam(r) == "fur"]
            out = fur_like[:n]
            if len(out) < n:
                out += [r for r in cand if r not in out][:n - len(out)]
            return out

        wb = wrap_payload_rows(pick_benign(train, int(len(wt) * cmdi_wrap_neg)),
                               per_row=1, label=0,
                               source=BENIGN_WRAP_SOURCE, seed=SEED + 7,
                               extract=benign_payload)
        wbv = wrap_payload_rows(pick_benign(valid, int(len(wv) * cmdi_wrap_neg)),
                                per_row=1, label=0,
                                source=BENIGN_WRAP_SOURCE, seed=SEED + 8,
                                extract=benign_payload)
        bt, bv = len(train), len(valid)
        train = _dedupe(train + wt + wb)
        valid = _dedupe(valid + wv + wbv)
        wrap_stats["wrapped_train"] = len(train) - bt
        wrap_stats["wrapped_valid"] = len(valid) - bv
        wrap_stats["wrapped_attack_train"] = len(wt)
        wrap_stats["wrapped_benign_train"] = len(wb)
        wrap_stats["wrapped_attack_valid"] = len(wv)
        wrap_stats["wrapped_benign_valid"] = len(wbv)
        if verbose:
            print(f"[cmdi-wrap] {len(tr_cmdi):,} 条 cmdi × {cmdi_wrap} + "
                  f"{len(wb):,} 条同外壳良性 -> train {len(train):,} "
                  f"（+{wrap_stats['wrapped_train']:,}）/ valid {len(valid):,} "
                  f"（+{wrap_stats['wrapped_valid']:,}）；通用路径池，未用评估集路径")
    stats["cmdi_wrap"] = wrap_stats


    # ---- 外部增量（人工反馈导出的事件快照）----
    n_pre_extra = len(train)
    if extra_rows:
        import collections as _col
        _c = _col.Counter(int(r.get("label", -1)) for r in extra_rows)
        stats["extra_rows"] = {
            "n_in": len(extra_rows),
            "by_label": {str(k): v for k, v in sorted(_c.items())},
            "note": "外部增量（事件 + 人工反馈）；只进 train，并过跨语料泄漏剔除",
        }
        train = _dedupe(train + list(extra_rows))
        stats["extra_rows"]["n_after_dedupe"] = len(train) - n_pre_extra
    else:
        stats["extra_rows"] = {"n_in": 0}

    # 防泄漏：test/valid 出现过的请求文本必须从 train 剔除（跨语料同请求）
    seen = {req_text(r) for r in test} | {req_text(r) for r in valid}
    before = len(train)
    train = [r for r in train if req_text(r) not in seen]
    leaked = before - len(train)
    if extra_rows:
        stats["extra_rows"]["n_final"] = len(train) - n_pre_extra
        stats["extra_rows"]["leak_removed"] = (
            stats["extra_rows"]["n_after_dedupe"] - stats["extra_rows"]["n_final"])

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
        "newdata": {**nd, "train_rows": len(nd_tr), "valid_rows": len(nd_va),
                    "note": "只进 train/valid（group 85/15），不进 test；"
                            "SQLi 语料有抽样上限，明细见各语料 stats"},
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
    rows, st = load_fur_api()
    inv["corpora"]["fur_api"] = {**st, "role": "真实 API 良性流量（监督/零日训练 + FPR 评估）",
                                 "usable": "normal 全部可用；anomaly 是业务异常，不映射到攻击子类"}
    rows, st = load_sqliv5()
    inv["corpora"]["sqliv5"] = {**st, "role": "SQLi 载荷（含 WAF-A-MoLE 对抗样本）",
                                "usable": "type=sqli 可用；type=valid（合法 SQL）已排除"}
    rows, st = load_wafamole()
    inv["corpora"]["wafamole"] = {**st, "role": "WAF-A-MoLE 变异 SQLi 载荷",
                                  "usable": "attacks.sql 抽样可用；sane.sql 已排除（合法 SQL）"}
    rows, st = load_wafrift_corpus()
    inv["corpora"]["wafrift"] = {**st, "role": "WAF 绕过语料（13 类，8 类可映射 0-4）",
                                 "usable": "sql/xss/cmdi/ssti/xxe/ssrf/log4shell/path 可用；其余无槽位"}
    rows, st = load_waffled_bypass()
    inv["corpora"]["waffled"] = {**st, "role": "真实 WAF 绕过请求（JSON/multipart/XML body）",
                                 "usable": "body 可用；头字段绕过 80 维特征不可见"}
    inv["corpora"]["commonhuman"] = {
        "role": "载荷库 + 编码器（26 种 evasion）",
        "usable": "本轮不训练：载荷带 `{marker}` 占位符，不替换会成为捷径 token",
        "files": len(glob.glob(os.path.join(COMMONHUMAN_DIR, "**", "*.py"), recursive=True)),
    }
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
