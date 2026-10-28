"""真实数据集加载器：CSIC 2010 与 HTTP Params（payload CSV）。

统一输出项目的请求格式 `{method, path, query, body, headers}`，
标签沿用 `dataset.LABELS`（0=normal,1=sqli,2=xss,3=cmdi,4=traversal）。

数据来源（`F:\\waf\\traindata`）：
  - CSIC 2010: Machine-Learning-on-CSIC-2010-master/
      normalTrafficTraining.txt   36,000 请求（正常）
      anomalousTrafficTest.txt    25,065 请求（异常，无子类标签）
  - HTTP Params: payload_train.csv / payload_test.csv / payload_test_lexical.csv
      列：payload,length,attack_type,label
      attack_type ∈ {norm, sqli, xss, path-traversal, cmdi, sql-syntax, js-syntax}

注意：
  * CSIC 缺 normalTrafficTest.txt，正常样本需自行切分；
  * CSIC 存在分布偏差（正常多为无参裸 GET；异常含 397 个 PUT 而正常为 0），
    评估时必须同时报告「可泄漏特征」影响。
"""
from __future__ import annotations

import csv
import json
import os
import re
from typing import Dict, List, Tuple

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
TRAINDATA = os.path.abspath(os.path.join(HERE, "..", "traindata"))
CSIC_DIR = os.path.join(TRAINDATA, "Machine-Learning-on-CSIC-2010-master",
                        "Machine-Learning-on-CSIC-2010-master")

# attack_type -> 项目标签
ATTACK_TYPE_TO_LABEL = {
    "norm": 0,
    "sqli": 1, "sql-syntax": 1,
    "xss": 2, "js-syntax": 2,
    "cmdi": 3,
    "path-traversal": 4,
}

_METHOD_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE) (\S+)")

# datacon2025（真实 HTTP 请求 + CVE 标签）
DATACON_DIR = os.path.join(TRAINDATA, "datacon2025-xlab-httpcve-sample",
                           "datacon2025-xlab-httpcve-sample", "data-release")
# WEB_APPLICATION_PAYLOADS.jsonl（攻击载荷字典，**无良性样本**）
PAYLOAD_DICT = os.path.join(TRAINDATA, "WEB_APPLICATION_PAYLOADS.jsonl")

# 载荷字典 id 前缀 -> 项目标签（未列出的族 = -1，调用方跳过）
DICT_FAMILY_TO_LABEL = {
    "sqli": 1, "sql": 1, "sql-injection": 1,
    "xss": 2, "cross-site": 2,
    "cmdi": 3, "cmdinj": 3, "rce": 3, "command": 3, "command-injection": 3,
    "os-command": 3, "shell": 3,
    "path-traversal": 4, "traversal": 4, "lfi": 4, "directory-traversal": 4,
}
# 字典里存在但项目标签体系没有对应类的族（csrf/ssrf 等），只能丢弃
DICT_UNMAPPED = ("csrf", "ssrf", "xxe", "open-redirect", "ssti")


def _split_url(url: str) -> Tuple[str, str]:
    """把 `http://host/path?query` 拆成 (path, query)。"""
    if url.startswith("http://") or url.startswith("https://"):
        # 去掉 scheme://host
        rest = url.split("://", 1)[1]
        slash = rest.find("/")
        rest = rest[slash:] if slash >= 0 else "/"
    else:
        rest = url
    if "?" in rest:
        p, q = rest.split("?", 1)
        return p, q
    return rest, ""


# --------------------------------------------------------------------------
# HTTP Params
# --------------------------------------------------------------------------
def load_payloads(path: str) -> List[Dict]:
    """读取 payload CSV，把 payload 放进单参数的 query，构造统一请求。

    统一放在 `q=` 参数里，保证正常/异常样本的位置一致，避免位置混淆。
    """
    out = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            payload = row.get("payload") or ""
            at = (row.get("attack_type") or "").strip().lower()
            if at not in ATTACK_TYPE_TO_LABEL:
                continue
            out.append({
                "method": "GET",
                "path": "/api/search",
                "query": f"q={payload}",
                "body": "",
                "headers": {},
                "label": ATTACK_TYPE_TO_LABEL[at],
                "attack_type": at,
            })
    return out


def load_local_jsonl(path: str, label: int | None = None) -> List[Dict]:
    """读取 `collect_http_log.py` 产出的真实流量 jsonl。

    `label=None` 时沿用文件里的 label（缺省 0）；给 `label` 则强制覆盖
    （用于"整份文件都是良性/攻击"的出处式标注）。
    """
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            row = {k: (o.get(k) or "") for k in ("method", "path", "query", "body")}
            row["method"] = (row["method"] or "GET").upper()
            lab = label if label is not None else int(o.get("label", 0) or 0)
            row["label"] = lab
            for k in ("ts", "src_ip", "status", "ua", "src_kind"):
                if o.get(k):
                    row[k] = o[k]
            out.append(row)
    return out


# --------------------------------------------------------------------------
# CSIC 2010
# --------------------------------------------------------------------------
def _parse_csic(path: str) -> List[Dict]:
    """解析 CSIC 的原始 HTTP 报文（latin-1，请求以方法行分界）。"""
    reqs = []
    with open(path, "r", encoding="latin-1", errors="replace") as f:
        lines = f.read().split("\n")
    i = 0
    n = len(lines)
    while i < n:
        m = _METHOD_RE.match(lines[i])
        if not m:
            i += 1
            continue
        method, url = m.group(1), m.group(2)
        headers = {}
        i += 1
        while i < n and lines[i].strip() != "":
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                headers[k.strip().lower()] = v.strip()
            i += 1
        while i < n and lines[i].strip() == "":
            i += 1
        body = ""
        if headers.get("content-length") and i < n:
            body = lines[i]
            i += 1
        path, query = _split_url(url)
        reqs.append({"method": method, "path": path, "query": query, "body": body,
                     "headers": headers})
    return reqs


def load_csic(normal_limit: int | None = None,
              anomaly_limit: int | None = None) -> Tuple[List[Dict], List[int]]:
    """返回 (requests, is_attack)。异常不做子类区分（CSIC 未提供）。"""
    norm = _parse_csic(os.path.join(CSIC_DIR, "normalTrafficTraining.txt"))
    anom = _parse_csic(os.path.join(CSIC_DIR, "anomalousTrafficTest.txt"))
    if normal_limit:
        norm = norm[:normal_limit]
    if anomaly_limit:
        anom = anom[:anomaly_limit]
    reqs = norm + anom
    y = [0] * len(norm) + [1] * len(anom)
    return reqs, y


def csic_normal_index(seed: int = 7, n_train: int = 30000) -> Tuple[List[int], List[int]]:
    """CSIC 正常流量的「训练 / 留出」索引切分（**与 `eval_csic.py` 同一协议**）。

    返回 `(train_idx, holdout_idx)`，索引指向 `load_csic()` 的返回列表。
    只切正常样本（这正符合 Isolation Forest "只用正常流量训练"的设定）；
    异常样本永远不进训练。

    统一协议的目的：零日通道的训练集、阈值标定池、评估集三者必须在
    任何文档里都指同一批数据，否则会出现"两个 CSIC 数字对不上"的经典问题。
    """
    reqs, y = load_csic()
    y = np.asarray(y)
    norm_idx = np.where(y == 0)[0].copy()
    np.random.RandomState(seed).shuffle(norm_idx)
    return [int(i) for i in norm_idx[:n_train]], [int(i) for i in norm_idx[n_train:]]


# --------------------------------------------------------------------------
# WEB_APPLICATION_PAYLOADS.jsonl —— 攻击载荷字典（**只有攻击，无良性**）
# --------------------------------------------------------------------------
def _iter_json_objects(text: str):
    """从（可能被截断/污染的）JSON 数组文本里逐个切出 `{...}` 对象。"""
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    yield text[start:i + 1]
                    start = None


def load_payload_dict(path: str | None = None) -> Tuple[List[Dict], int]:
    """读取整理好的攻击载荷字典。

    ⚠️ 字典里**没有任何良性样本**，只能作攻击增强；并入训练时必须同比例补良性，
    否则误报率只会上升。

    文件是"名为 .jsonl 的多行 JSON 数组"，且个别行有编码污染（非法 UTF-8），
    因此这里逐个对象解析、跳过坏对象，返回 (样本, 坏对象数)。

    每个样本带 `label`（0/1..4，未识别族为 -1）/`family`/`severity`。
    """
    path = path or PAYLOAD_DICT
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    text = text.replace("\ufffd", "")  # 去掉编码污染产生的替换字符

    out, bad = [], 0
    for obj_text in _iter_json_objects(text):
        try:
            it = json.loads(obj_text)
        except Exception:
            bad += 1
            continue
        pid = str(it.get("id") or "")
        family = pid.split("-", 1)[0].lower() if "-" in pid else ""
        payload = it.get("payload") or ""
        out.append({
            "method": "GET",
            "path": "/api/search",
            "query": f"q={payload}",
            "body": "",
            "headers": {},
            "label": DICT_FAMILY_TO_LABEL.get(family, -1),
            "family": family,
            "severity": it.get("severity") or "",
            "attack_type": f"dict-{family}",
        })
    return out, bad


# --------------------------------------------------------------------------
# datacon2025 —— 真实原始 HTTP 请求字节 + CVE 标签
# --------------------------------------------------------------------------
def _parse_raw_request(raw: bytes) -> Dict:
    """防御式解析原始 HTTP 请求字节（样本里可能混有二进制噪声）。"""
    text = raw.decode("latin-1", errors="replace")
    head, sep, body = text.partition("\r\n\r\n")
    if not sep:
        head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        return {"method": "", "path": "", "query": "", "body": "", "headers": {}}
    m = _METHOD_RE.match(lines[0].strip())
    if m:
        method, url = m.group(1), m.group(2)
    else:
        parts = lines[0].strip().split(" ")
        method = parts[0] if parts else ""
        url = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    path, query = _split_url(url)
    # 请求行后可能跟着二进制噪声 -> 只保留可打印字符
    path = "".join(ch for ch in path if ch.isprintable() and ch != " ")
    return {"method": method.upper(), "path": path or "/", "query": query,
            "body": body, "headers": headers}


def load_datacon(split: str = "train", path: str | None = None) -> List[Dict]:
    """读取 datacon2025 样本（gzip jsonl；payload 是 base64+zlib 的原始请求字节）。

    `label`：1 = 在主办方标注集内（视为攻击）；0 = 未标注。

    ⚠️ **`label==0` 不等于良性**：例如 `GET /actuator/gateway/routes/...`
    （Spring 网关 RCE 探测）被标为 0。因此这只是"疑似良性"，误报率必须人工复核。
    """
    import base64
    import gzip
    import zlib

    path = path or os.path.join(DATACON_DIR, f"{split}_sample.json.gz")
    with open(path, "rb") as f:
        blob = f.read()
    try:
        text = gzip.decompress(blob).decode("utf-8", "replace")
    except Exception:
        text = zlib.decompress(blob, 16 + zlib.MAX_WBITS).decode("utf-8", "replace")

    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        try:
            raw = zlib.decompress(base64.b64decode(obj.get("payload") or ""))
        except Exception:
            raw = b""
        req = _parse_raw_request(raw)
        labeled = bool(obj.get("labeled"))
        req.update({
            "label": 1 if labeled else 0,
            "cve_labels": [x for x in str(obj.get("cve_labels") or "").split(" ") if x],
            "row_id": obj.get("id"),
            "attack_type": "datacon-labeled" if labeled else "datacon-unlabeled",
        })
        out.append(req)
    return out


if __name__ == "__main__":
    import collections

    for name in ["payload_train.csv", "payload_test.csv", "payload_test_lexical.csv"]:
        s = load_payloads(os.path.join(TRAINDATA, name))
        c = collections.Counter(x["attack_type"] for x in s)
        print(f"{name}: {len(s)} rows -> {dict(c)}")
        print("   e.g.", s[0]["method"], s[0]["path"], "?" + s[0]["query"][:70])

    reqs, y = load_csic()
    print(f"\nCSIC: {len(reqs)} requests, attack={sum(y)} normal={len(y) - sum(y)}")
    q = sum(1 for r in reqs[:36000] if r["query"])
    print(f"  normal with query: {q}/36000  ({100*q/36000:.1f}%)")
    qa = sum(1 for r in reqs[36000:] if r["query"])
    print(f"  anomaly with query: {qa}/{len(reqs)-36000}  ({100*qa/(len(reqs)-36000):.1f}%)")
    put_n = sum(1 for r in reqs[:36000] if r["method"] == "PUT")
    put_a = sum(1 for r in reqs[36000:] if r["method"] == "PUT")
    print(f"  PUT: normal={put_n}  anomaly={put_a}   <-- 完美泄漏特征")

    print("\n--- WEB_APPLICATION_PAYLOADS ---")
    d, bad = load_payload_dict()
    print(f"  entries={len(d)}  坏对象={bad}  "
          f"labels={dict(collections.Counter(x['label'] for x in d))}")
    print(f"  families={dict(collections.Counter(x['family'] for x in d).most_common())}")

    print("\n--- datacon2025 sample ---")
    for split in ("train", "test"):
        rows = load_datacon(split)
        lab = collections.Counter(x["label"] for x in rows)
        cve = sum(1 for x in rows if x["cve_labels"])
        print(f"  {split}: {len(rows)} rows  labeled(attack)={lab.get(1,0)} "
              f"unlabeled={lab.get(0,0)}  with_cve={cve}")
        print(f"    e.g. {rows[0]['method']} {rows[0]['path'][:60]!r} "
              f"query={rows[0]['query'][:40]!r}")
