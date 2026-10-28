"""`traindata/` 数据目录：把每个语料登记成**可审计的一行**（谁、多少、干什么用、能不能用）。

为什么需要它：
  * 项目对语料的要求是"标签只来自出处、良性来自真实 IP/UA"，所以**每个文件都得有
    明确角色**（训练 / 良性池 / 攻击池 / 只做 OOD 自检 / 采集器输出），
    否则很容易把 OOD 集当训练集、把扫描器流量当良性池；
  * 目录里同时躺着 zip 与解压目录、派生 CSV（`payload_full` = train+test）、
    采集器原始日志，光看文件名分不清哪些是"语料"、哪些是"残留"；
  * 评估报告里出现的每个数字都要能反查到文件 —— 这里给出**行数 / 标签分布 / sha1**。

本工具**只读**：不移动、不改名、不删除任何文件。它只产出
  * `artifacts/traindata_catalog.json`（机器可读，CI/报告引用）
  * `../traindata/CATALOG.md`（人读，放在数据旁边）

口径与判定链路保持一致：
  * 池成分**直接 import `calibrate_rules.build_sources` + `POOLS`**，不复制一份
    （复制就是第二个事实来源，迟早与三关/预算对不上）；
  * 行数用 `realdata` 的**同一批 loader** 数，而不是 `wc -l`
    （CSIC 是两个原始 HTTP 报文文件，行数 ≠ 请求数）。

用法：
    py -3.10 traindata_catalog.py                # 全量（含 CIC-IDS2017 全表扫描，约 1–2 分钟）
    py -3.10 traindata_catalog.py --skip-cic     # 跳过 CIC（秒级）
    py -3.10 traindata_catalog.py --out x.json --md x.md
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as _dt
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

ROOT = os.path.abspath(os.path.join(HERE, ".."))
TRAINDATA = os.path.join(ROOT, "traindata")
ART = os.path.join(HERE, "artifacts")
OUT_JSON = os.path.join(ART, "traindata_catalog.json")
OUT_MD = os.path.join(TRAINDATA, "CATALOG.md")

CIC_DIR = os.path.join(TRAINDATA, "CIC-IDS2017")
LOCAL = os.path.join(TRAINDATA, "local")
PROXY = os.path.join(TRAINDATA, "proxy")

# 小文件算 sha1 作指纹；大文件（CIC 单表 200MB+）只登记大小/mtime，
# 否则每次跑目录都要多读 ~900MB。
HASH_LIMIT = 64 << 20


def sha1_of(path: str, limit: int = HASH_LIMIT) -> str | None:
    if os.path.getsize(path) > limit:
        return None
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_meta(path: str) -> dict:
    st = os.stat(path)
    return {
        "path": os.path.relpath(path, ROOT).replace("\\", "/"),
        "bytes": st.st_size,
        "mtime": _dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
        "sha1": sha1_of(path),
    }


def human(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    v = float(n)
    for unit in ("KB", "MB", "GB"):
        v /= 1024.0
        if v < 1024 or unit == "GB":
            return f"{v:.1f} {unit}"
    return f"{v:.1f} GB"


# --------------------------------------------------------------------------- 语料扫描
def scan_payload_csv() -> dict:
    """HTTP Params 的词法载荷表：train/test 载荷零重叠，full = train ∪ test。"""
    from realdata import load_payloads

    out = {"corpus": "payload_csv", "files": [], "stats": {}}
    sets = {}
    for name in ("payload_train.csv", "payload_test.csv",
                 "payload_test_lexical.csv", "payload_full.csv"):
        p = os.path.join(TRAINDATA, name)
        meta = file_meta(p)
        rows = load_payloads(p)
        pl = [r["query"][2:] for r in rows]      # load_payloads 把载荷放进 `q=`
        at = collections.Counter(r["attack_type"] for r in rows)
        meta.update({
            "rows": len(rows),
            "attack_type": dict(at),
            "n_attack": sum(v for k, v in at.items() if k != "norm"),
            "unique_payload": len(set(pl)),
            "max_payload_len": max((len(x) for x in pl), default=0),
        })
        out["files"].append(meta)
        sets[name] = set(pl)

    tr, te, lex = sets["payload_train.csv"], sets["payload_test.csv"], \
        sets["payload_test_lexical.csv"]
    out["stats"] = {
        "train_test_overlap": len(tr & te),
        "full_is_train_plus_test": sets["payload_full.csv"] == (tr | te),
        "full_rows_equal_sum": (len(tr) + len(te)) == len(sets["payload_full.csv"]),
        "lexical_in_full": len(lex & (tr | te)),
    }
    return out


def scan_csic() -> dict:
    """CSIC 2010：36,000 正常 + 25,065 异常（异常无子类标签）。"""
    from realdata import load_csic, _parse_csic, CSIC_DIR

    norm_p = os.path.join(CSIC_DIR, "normalTrafficTraining.txt")
    anom_p = os.path.join(CSIC_DIR, "anomalousTrafficTest.txt")
    norm = _parse_csic(norm_p)
    anom = _parse_csic(anom_p)
    reqs, y = load_csic()

    def prof(rows):
        return {
            "requests": len(rows),
            "with_query": sum(1 for r in rows if r["query"]),
            "with_body": sum(1 for r in rows if r["body"]),
            "methods": dict(collections.Counter(r["method"] for r in rows)),
        }

    return {
        "corpus": "csic2010",
        "files": [file_meta(norm_p), file_meta(anom_p)],
        "stats": {
            "normal": prof(norm),
            "anomalous": prof(anom),
            "loader_requests": len(reqs),
            "loader_attack": int(sum(y)),
            "normal_test_file_present": os.path.exists(
                os.path.join(CSIC_DIR, "normalTrafficTest.txt")),
        },
    }


def scan_payload_dict() -> dict:
    """攻击载荷字典：**没有良性样本**，只作规则挖掘 / 困难负例来源。"""
    from realdata import load_payload_dict

    rows, bad = load_payload_dict()
    fam = collections.Counter(r["family"] for r in rows)
    lab = collections.Counter(r["label"] for r in rows)
    return {
        "corpus": "payload_dict",
        "files": [file_meta(os.path.join(TRAINDATA, "WEB_APPLICATION_PAYLOADS.jsonl"))],
        "stats": {
            "entries": len(rows),
            "bad_objects": bad,
            "families": dict(fam.most_common()),
            "labels": {str(k): v for k, v in sorted(lab.items())},
            "mapped": sum(v for k, v in lab.items() if k != -1),
            "unmapped": lab.get(-1, 0),
            "has_benign": False,
        },
    }


def scan_datacon() -> dict:
    """datacon2025 样本：100 条，只允许做 OOD 链路自检。"""
    from realdata import load_datacon

    stats = {}
    files = []
    for split in ("train", "test"):
        rows = load_datacon(split)
        stats[split] = {
            "rows": len(rows),
            "labeled_attack": sum(1 for r in rows if r["label"] == 1),
            "unlabeled": sum(1 for r in rows if r["label"] == 0),
            "with_body": sum(1 for r in rows if r["body"]),
            "with_cve": sum(1 for r in rows if r.get("cve_labels")),
        }
        files.append(file_meta(os.path.join(
            ROOT, "traindata", "datacon2025-xlab-httpcve-sample",
            "datacon2025-xlab-httpcve-sample", "data-release",
            f"{split}_sample.json.gz")))
    stats["total"] = sum(v["rows"] for v in stats.values())
    stats["total_labeled_attack"] = sum(v["labeled_attack"] for k, v in stats.items()
                                        if k in ("train", "test"))
    return {"corpus": "datacon2025_sample", "files": files, "stats": stats}


def scan_local() -> dict:
    """`local/` 是采集管线产出的**统一 jsonl**（也是判定链路的真实池）。"""
    out = {}
    names = ["local_lab_benign.jsonl", "inwild_benign.jsonl", "inwild_attack.jsonl",
             "datacon_attack.jsonl", "datacon_unlabeled.jsonl"]
    for name in names:
        p = os.path.join(LOCAL, name)
        if not os.path.exists(p):
            out[name] = {"missing": True}
            continue
        n = body = 0
        labels = collections.Counter()
        keys = set()
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                o = json.loads(line)
                n += 1
                body += 1 if o.get("body") else 0
                labels[str(o.get("label"))] += 1
                keys.update(o.keys())
        meta = file_meta(p)
        meta.update({"rows": n, "with_body": body, "labels": dict(labels),
                     "fields": sorted(keys)})
        out[name] = meta

    reports = {}
    for name in ("local_lab_report.json", "inwild_report.json", "datacon_report.json"):
        p = os.path.join(LOCAL, name)
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8") as f:
            rep = json.load(f)
        reports[name] = {
            "src": rep.get("src") or rep.get("source"),
            "provenance": rep.get("provenance") or rep.get("role"),
            "counts": rep.get("counts"),
            "audit_pattern_hits": rep.get("audit_pattern_hits"),
            "limitations": rep.get("limitations"),
            "reportable": rep.get("reportable"),
        }
    return {"corpus": "local_jsonl", "files": out, "reports": reports}


def scan_cic() -> dict:
    """CIC-IDS2017 全表：逐文件数行 + 标签分布（79 列，标签在最后一列）。"""
    files = []
    totals = collections.Counter()
    total_rows = 0
    cols = None
    for fn in sorted(f for f in os.listdir(CIC_DIR) if f.lower().endswith(".csv")):
        p = os.path.join(CIC_DIR, fn)
        with open(p, "r", encoding="latin-1", newline="") as f:
            r = csv.reader(f)
            head = [h.strip() for h in next(r)]
            cols = cols or head
            li = head.index("Label")
            labs = collections.Counter()
            n = 0
            for row in r:
                n += 1
                labs[row[li].strip() if len(row) > li else "<short>"] += 1
        meta = file_meta(p)
        meta.update({"rows": n, "columns": len(head), "labels": dict(labs.most_common())})
        files.append(meta)
        total_rows += n
        totals.update(labs)
        print(f"  [cic] {fn:<52} rows={n:>9,}")

    dup_cols = [c for c, k in collections.Counter(cols or []).items() if k > 1]
    attacks = {k: v for k, v in totals.items() if k.upper() != "BENIGN"}
    aux = []
    for dirpath, _dirs, fns in os.walk(CIC_DIR):
        for fn in fns:
            if fn.lower().endswith(".csv"):
                continue
            p = os.path.join(dirpath, fn)
            if os.path.abspath(p) == os.path.abspath(OUT_MD):
                continue
            aux.append({"name": fn, "bytes": os.path.getsize(p),
                        "ascii_name": all(ord(ch) < 128 for ch in fn)})
    return {
        "corpus": "cic_ids2017",
        "files": files,
        "stats": {
            "rows": total_rows,
            "label_counts": dict(totals.most_common()),
            "attack_rows": sum(attacks.values()),
            "benign_rows": totals.get("BENIGN", 0),
            "columns": len(cols or []),
            "duplicate_column_names": dup_cols,
            "mojibake_labels": [k for k in totals if "\ufffd" in k or "ï¿½" in k],
            "aux_files": len(aux),
            "aux_non_ascii_names": sum(1 for a in aux if not a["ascii_name"]),
        },
    }


def scan_proxy() -> dict:
    """`proxy/` 是采集器落盘样本，**不是语料**（无标签、条数极少）。"""
    files = []
    for fn in sorted(os.listdir(PROXY)) if os.path.isdir(PROXY) else []:
        p = os.path.join(PROXY, fn)
        meta = file_meta(p)
        if fn.endswith(".jsonl"):
            n = with_pred = with_body = 0
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    o = json.loads(line)
                    n += 1
                    with_pred += 1 if o.get("pred") else 0
                    with_body += 1 if o.get("body") else 0
            meta.update({"rows": n, "with_pred": with_pred, "with_body": with_body,
                         "has_label_field": False})
        files.append(meta)
    return {"corpus": "collector_output", "files": files,
            "stats": {"n_files": len(files)}}


def scan_archives() -> list:
    """zip 与解压目录并存：登记但不删（zip 是原始出处）。"""
    import zipfile

    out = []
    for fn in sorted(os.listdir(TRAINDATA)):
        p = os.path.join(TRAINDATA, fn)
        if not fn.lower().endswith(".zip"):
            continue
        try:
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
        except Exception as e:  # noqa: BLE001
            out.append({"path": fn, "error": str(e)})
            continue
        meta = file_meta(p)
        top = sorted({n.split("/")[0] for n in names if n})
        meta.update({
            "entries": len(names),
            "top_level": top,
            "extracted_dir_exists": all(os.path.exists(os.path.join(TRAINDATA, t))
                                        for t in top),
        })
        out.append(meta)
    return out


# --------------------------------------------------------------------------- 池成分
def pool_report() -> dict:
    """判定链路实际消费的池。定义与数量都来自 `calibrate_rules`（单一事实来源）。"""
    try:
        from calibrate_rules import POOLS, build_sources
    except Exception as e:  # noqa: BLE001
        return {"error": f"import calibrate_rules 失败: {e}"}

    srcs = build_sources(need_attack=True)
    sizes = {k: len(v) for k, v in srcs.items()}
    body = {k: sum(1 for r in v if r.get("body")) for k, v in srcs.items()}
    pools = {}
    for name, members in POOLS.items():
        miss = [m for m in members if m not in sizes]
        pools[name] = {
            "members": {m: {"rows": sizes.get(m, 0), "with_body": body.get(m, 0)}
                        for m in members},
            "rows": sum(sizes.get(m, 0) for m in members),
            "with_body": sum(body.get(m, 0) for m in members),
            "missing": miss,
        }
    return {"pools": pools,
            "note": ("池定义来自 calibrate_rules.POOLS；三关用 unified_*，"
                     "p7 锚点用 p7_*。inwild_benign 不在任何池里（扫描器污染）。")}


# --------------------------------------------------------------------------- 结论
def build_issues(catalog: dict) -> list:
    """把"看文件名看不出来"的坑固化成条目，避免下一轮又踩。"""
    issues = []
    payload = catalog["payload_csv"]
    local = catalog["local_jsonl"]
    dict_ = catalog["payload_dict"]["stats"]
    dc = catalog["datacon2025_sample"]["stats"]
    cic = catalog.get("cic_ids2017", {}).get("stats") or {}
    proxy = catalog["collector_output"]["files"]

    if payload["stats"].get("full_is_train_plus_test"):
        issues.append({
            "id": "payload_full_is_derived",
            "severity": "info",
            "detail": "payload_full.csv 只是 train+test 的拼接（31,067 行），"
                      "无脚本消费；改任何一侧都会让它过期，别当独立语料引用。",
        })
    if payload["stats"].get("lexical_in_full") == 0:
        issues.append({
            "id": "lexical_outside_full",
            "severity": "info",
            "detail": "payload_test_lexical.csv（1,106 行）与 train/test 载荷零重叠、"
                      "最长 45,489 字符，是**唯一的长文本源**；规则三关的 lex_norm/lex_atk 用它。",
        })
    if not catalog["csic"]["stats"]["normal_test_file_present"]:
        issues.append({
            "id": "csic_missing_normal_test",
            "severity": "warn",
            "detail": "CSIC 缺 normalTrafficTest.txt（只有 normalTrafficTraining + "
                      "anomalousTrafficTest），留出集是自切（seed=7, n_train=30000），"
                      "与官方切分不可比。",
        })
    if dict_["bad_objects"]:
        issues.append({
            "id": "payload_dict_corrupt",
            "severity": "warn",
            "detail": f"WEB_APPLICATION_PAYLOADS.jsonl 有 {dict_['bad_objects']} 个坏对象"
                      f"（第 181 行起编码乱码），已容错跳过；另有 {dict_['unmapped']} 条 "
                      "csrf/ssrf 在项目标签体系里没有对应类（label=-1）。",
        })
    if dict_["has_benign"] is False:
        issues.append({
            "id": "payload_dict_no_benign",
            "severity": "info",
            "detail": "攻击字典**零良性样本**：只能作规则挖掘/困难负例，"
                      "并入训练必须同比例补真实良性，否则 FPR 直接上去。",
        })
    if dc["total"] <= 200:
        issues.append({
            "id": "datacon_small",
            "severity": "warn",
            "detail": f"datacon2025 只有 {dc['total']} 条（标注攻击 {dc['total_labeled_attack']}），"
                      "只能问「检出与否」；任何召回率/准确率的置信区间都无意义（OOD 自检专用）。",
        })
    no_body = [n for n, m in local["files"].items()
               if isinstance(m, dict) and not m.get("missing") and m.get("rows")
               and not m.get("with_body")]
    if no_body:
        issues.append({
            "id": "body_coverage_zero",
            "severity": "warn",
            "detail": "以下文件 body 全空（来源是 access/error log）："
                      + "、".join(no_body)
                      + "。本机真实流量侧 body 覆盖为 0，body 特征只能靠 CSIC 的 POST"
                        "（unified_benign 6,190 条里 1,310 条带 body），"
                        "部署环境上的 POST 攻击基本没有训练素材。",
        })
    if cic:
        issues.append({
            "id": "cic_flow_no_consumer",
            "severity": "warn",
            "detail": f"CIC-IDS2017 共 {cic['rows']:,} 行 / {cic['attack_rows']:,} 攻击，"
                      "目前只有 `p5_flow_spike.py`（抽样 spike）消费，"
                      "**流级通道还没有生产消费者**。其中 WebAttack 仅 "
                      f"{sum(v for k, v in cic['label_counts'].items() if 'web attack' in k.lower())} 行。",
        })
        if cic.get("duplicate_column_names"):
            issues.append({
                "id": "cic_duplicate_columns",
                "severity": "info",
                "detail": "CIC CSV 有重复列名 " + "、".join(cic["duplicate_column_names"])
                          + "（pandas 会重命名为 .1），p5 里用 DROP_ALWAYS 剔掉。",
            })
        if cic.get("mojibake_labels"):
            issues.append({
                "id": "cic_mojibake_labels",
                "severity": "info",
                "detail": "标签里含 UTF-8→latin-1 的 mojibake（如 'Web Attack ï¿½ XSS'），"
                          "按 `'web attack' in label.lower()` 归类比按全等匹配安全。",
            })
        if cic.get("aux_non_ascii_names"):
            issues.append({
                "id": "cic_aux_files_mojibake",
                "severity": "info",
                "detail": f"CIC-IDS2017/data_py/ 下有 {cic['aux_non_ascii_names']} 个"
                          "与项目无关的预处理脚本，文件名是 GBK 乱码（`ȥ��������.py` 一类）；"
                          "不被任何代码 import，可原样保留或移出，**不要当语料**。",
            })
    if any(f.get("rows") for f in proxy):
        issues.append({
            "id": "proxy_samples_in_traindata",
            "severity": "info",
            "detail": f"proxy/ 下有 {sum(f.get('rows', 0) for f in proxy)} 条采集器输出"
                      "（有 pred、无 label），是**运行样本**不是语料；别混进池子。",
        })
    if catalog["archives"]:
        dup = [a["path"] for a in catalog["archives"] if a.get("extracted_dir_exists")]
        if dup:
            issues.append({
                "id": "zip_duplicates",
                "severity": "info",
                "detail": "zip 与解压目录并存：" + "、".join(dup)
                          + "（合计约 2.5 MB）。保留 zip 作原始出处，读数据一律读解压目录。",
            })
    issues.append({
        "id": "no_version_control",
        "severity": "warn",
        "detail": "F:\\waf 不是 git 仓库，traindata 本身也无版本；"
                  "文件一旦被覆盖没有任何回滚点。差异化请以本目录的 sha1 为准。",
    })
    return issues


def build_recommendations(catalog: dict, pools: dict) -> list:
    recs = []
    ub = (pools.get("pools") or {}).get("unified_benign", {})
    ua = (pools.get("pools") or {}).get("unified_attack", {})
    if ub:
        recs.append(
            f"良性池 {ub['rows']:,} 条（CSIC 留出 6,000 + 本机 190），远低于"
            "「按目标 FPR 标定」需要的 2,000 条本机量级；继续采真实 benign 是"
            "替换工作点的前置条件（inwild_benign 不能顶，见下）。")
    if ua:
        recs.append(
            f"攻击池 {ua['rows']:,} 条里 CSIC 异常占 "
            f"{ua['members'].get('csic_anom', {}).get('rows', 0):,}（词法为主），"
            f"在野仅 {ua['members'].get('inwild_atk', {}).get('rows', 0)} 条、"
            f"datacon 仅 {ua['members'].get('datacon_atk', {}).get('rows', 0)} 条；"
            "42 条导入规则「攻击回放 0 命中」就是这个池覆盖不足的直接后果。")
    recs.append(
        "inwild_benign.jsonl（105,730 条）带 2,074 条扫描器命中，**只能看命中率**、"
        "不能算误报率；把它当良性池会把 FPR 算低。")
    recs.append(
        "本机真实流量 body 覆盖为 0，根因是日志源（access/error log 不带请求体）；"
        "要补 body 只能在采集器侧落 `event_bodies`，别再指望历史日志。")
    recs.append(
        "需要更宽的攻击语料时，优先级：① 真实本机良性到 ≥2,000 ② 采集器带 body 的"
        "真实攻击 ③ CIC-IDS2017 流级消费者。datacon 完整版未公开，不要等它。")
    return recs


# --------------------------------------------------------------------------- 输出
def render_md(catalog: dict) -> str:
    L = []
    A = L.append
    A("# `traindata/` 数据目录")
    A("")
    A(f"> 自动生成：`python/traindata_catalog.py`（{catalog['generated_at']}）—— **勿手改**。")
    A("> 本目录只登记与盘点，不移动/不改名/不删除任何文件。")
    A("")
    A(f"总计 **{catalog['totals']['files']} 个文件 / {human(catalog['totals']['bytes'])}**；"
      f"语料 {len(catalog['corpora'])} 组"
      + ("（CIC-IDS2017 未扫描：`--skip-cic`）" if not catalog["coverage"]["cic_scanned"] else "")
      + "。")
    A("")

    A("## 1. 语料一览")
    A("")
    A("| 语料 | 角色 | 规模 | 消费方 | 可用性 |")
    A("|---|---|---|---|---|")
    for c in catalog["corpora"]:
        A(f"| `{c['id']}` | {c['role']} | {c['scale']} | {c['consumers']} | {c['usable']} |")
    A("")

    A("## 2. 明细")
    A("")
    for c in catalog["corpora"]:
        A(f"### {c['id']} — {c['title']}")
        A("")
        A(f"- 路径：`{c['path']}`")
        A(f"- 角色：{c['role']}")
        A(f"- 出处/许可：{c['provenance']}")
        A(f"- 消费方：{c['consumers']}")
        if c.get("notes"):
            for n in c["notes"]:
                A(f"- {n}")
        A("")
        if c.get("table"):
            A("| 文件 | 大小 | 行/请求 | 备注 |")
            A("|---|---|---|---|")
            for row in c["table"]:
                A(f"| `{row['file']}` | {row['bytes']} | {row['rows']} | {row.get('note', '')} |")
            A("")

    pools = catalog["pools"]
    if pools.get("pools"):
        A("## 3. 判定链路实际消费的池")
        A("")
        A("| 池 | 条数 | 带 body | 组成 |")
        A("|---|---|---|---|")
        for name, p in pools["pools"].items():
            comp = " + ".join(f"{m} {v['rows']:,}" for m, v in p["members"].items())
            A(f"| `{name}` | {p['rows']:,} | {p['with_body']:,} | {comp} |")
        A("")
        A(f"> {pools['note']}")
        A("")

    A("## 4. 已知坑（按现状登记，未修复）")
    A("")
    for i in catalog["issues"]:
        A(f"- **[{i['severity']}] {i['id']}** — {i['detail']}")
    A("")
    A("## 5. 建议动作")
    A("")
    for r in catalog["recommendations"]:
        A(f"- {r}")
    A("")
    return "\n".join(L)


def build_catalog(skip_cic: bool = False, skip_pools: bool = False) -> dict:
    t0 = time.time()
    print("[catalog] payload csv ...")
    payload_csv = scan_payload_csv()
    print("[catalog] CSIC 2010 ...")
    csic = scan_csic()
    print("[catalog] 攻击载荷字典 ...")
    payload_dict = scan_payload_dict()
    print("[catalog] datacon2025 ...")
    datacon = scan_datacon()
    print("[catalog] local/ ...")
    local = scan_local()
    cic = {"corpus": "cic_ids2017", "files": [], "stats": {}}
    if not skip_cic:
        print("[catalog] CIC-IDS2017（全表，逐文件）...")
        cic = scan_cic()
    else:
        print("[catalog] CIC-IDS2017 跳过（--skip-cic）")
    print("[catalog] proxy/ ...")
    proxy = scan_proxy()
    archives = scan_archives()
    pools = {"pools": {}} if skip_pools else pool_report()
    if pools.get("pools"):
        for name, p in pools["pools"].items():
            print(f"  [pool] {name:<14} rows={p['rows']:,}  body={p['with_body']:,}")

    # ---- 语料登记（角色/消费方/可用性都是**人写死的结论**，不是扫描猜的）
    corpora = [
        {
            "id": "csic2010",
            "title": "CSIC 2010 HTTP 数据集（正常 + 异常请求报文）",
            "path": "traindata/Machine-Learning-on-CSIC-2010-master/...",
            "role": "良性训练/留出池 + 攻击池（异常无子类标签）",
            "provenance": "公开学术数据集（CSIC 2010）；仓库为第三方整理版，未附许可证文件",
            "consumers": "`realdata.load_csic` / `csic_normal_index` → 训练、零日、三关、预算",
            "usable": "可用（唯一有规模的真实 HTTP 报文）",
            "scale": f"{csic['stats']['normal']['requests']:,} 正常 + "
                     f"{csic['stats']['anomalous']['requests']:,} 异常",
            "notes": [
                "正常：" + "、".join(f"{k} {v:,}" for k, v in
                                    csic["stats"]["normal"]["methods"].items())
                + f"；{csic['stats']['normal']['with_query']:,} 条带 query、"
                  f"{csic['stats']['normal']['with_body']:,} 条带 body（8,000 条 POST 都带表单）",
                "异常：" + "、".join(f"{k} {v:,}" for k, v in
                                    csic["stats"]["anomalous"]["methods"].items())
                + f"；{csic['stats']['anomalous']['with_query']:,} 条带 query、"
                  f"{csic['stats']['anomalous']['with_body']:,} 条带 body",
                "PUT 只在异常里出现（正常 0 条，异常 397 条）—— 这是可泄漏特征，评估时必须报",
            ],
            "table": [
                {"file": csic["files"][0]["path"],
                 "bytes": human(csic["files"][0]["bytes"]),
                 "rows": f"{csic['stats']['normal']['requests']:,} 请求",
                 "note": "正常流量 · sha1 " + (csic["files"][0]["sha1"] or "")[:12]},
                {"file": csic["files"][1]["path"],
                 "bytes": human(csic["files"][1]["bytes"]),
                 "rows": f"{csic['stats']['anomalous']['requests']:,} 请求",
                 "note": "异常流量（无子类标签）· sha1 "
                         + (csic["files"][1]["sha1"] or "")[:12]},
            ],
            "stats": csic["stats"],
            "files": csic["files"],
        },
        {
            "id": "payload_csv",
            "title": "HTTP Params 词法载荷表（train/test/lexical/full）",
            "path": "traindata/payload_*.csv",
            "role": "监督通道的训练/测试集（载荷零重叠）",
            "provenance": "第三方整理的 HTTP 参数载荷集（`payload,length,attack_type,label`）",
            "consumers": "`train_realdata` / `eval_http_params` / `export_testvec` / "
                         "`calibrate_rules`（lex_norm、lex_atk）",
            "usable": "可用；full 是派生文件，lexical 才是长文本源",
            "scale": "31,067 行（train 20,712 / test 10,355）+ lexical 1,106",
            "notes": [
                f"train ∩ test = {payload_csv['stats']['train_test_overlap']} 条（协议要求零重叠）",
                f"lexical 与 train/test 交集 {payload_csv['stats']['lexical_in_full']} 条",
                "payload 统一塞进 `?q=`，位置一致；`norm` 行是数据集自带的良性参数，"
                "**不是本机真实用户流量** —— 真实良性只看 CSIC 与 local/",
            ],
            "table": [
                {"file": f["path"], "bytes": human(f["bytes"]), "rows": f"{f['rows']:,}",
                 "note": "、".join(f"{k}={v}" for k, v in f["attack_type"].items())}
                for f in payload_csv["files"]
            ],
            "stats": {"files": payload_csv["files"], **payload_csv["stats"]},
            "files": payload_csv["files"],
        },
        {
            "id": "payload_dict",
            "title": "WEB_APPLICATION_PAYLOADS.jsonl（攻击载荷字典）",
            "path": "traindata/WEB_APPLICATION_PAYLOADS.jsonl",
            "role": "规则挖掘 / 困难负例来源（**不进训练**）",
            "provenance": "第三方攻击载荷字典；项目内**未核实许可与出处**（见 THIRD_PARTY_NOTICES）",
            "consumers": "`p7_rule_mining`（挖词）、`train_realdata --use-dict`（可选增强，"
                         "官方配方不用）",
            "usable": "仅作攻击侧素材；文件本身是坏 JSON，且零良性",
            "scale": f"{payload_dict['stats']['entries']} 条（坏对象 {payload_dict['stats']['bad_objects']}）",
            "notes": [
                "家族：" + "、".join(f"{k}={v}" for k, v in payload_dict["stats"]["families"].items()),
                f"可映射到项目标签 {payload_dict['stats']['mapped']} 条，"
                f"无对应类（csrf/ssrf）{payload_dict['stats']['unmapped']} 条",
                "已实测：并入训练会让 CSIC 异常召回从 20.2% 掉到 6.3%（REALDATA_EVALUATION §8）",
            ],
            "table": [{"file": f["path"], "bytes": human(f["bytes"]),
                       "rows": f"{payload_dict['stats']['entries']}", "note": "多行 JSON 数组"} 
                      for f in payload_dict["files"]],
            "stats": payload_dict["stats"],
            "files": payload_dict["files"],
        },
        {
            "id": "datacon2025_sample",
            "title": "datacon2025 xlab-httpcve 样本",
            "path": "traindata/datacon2025-xlab-httpcve-sample/.../data-release",
            "role": "**只做 OOD 链路自检**（禁止训练、禁止当良性池）",
            "provenance": "公开比赛样例（100 条）；标注=1 视为攻击，标注=0 不等于良性",
            "consumers": "`realdata.load_datacon` → `p2/p3/p6/p7/calibrate`、`export_datacon`",
            "usable": "只能问「检出与否」，不得报率（n=100 置信区间无意义）",
            "scale": f"{datacon['stats']['total']} 条（标注攻击 {datacon['stats']['total_labeled_attack']}）",
            "notes": [
                "`label=0` 里有 Spring 网关 RCE 探测（`/actuator/gateway/routes/...`）—— 当良性会算错 FPR",
                "入训练会同时毁掉训练集与唯一 OOD 验收集",
            ],
            "table": [{"file": f["path"], "bytes": human(f["bytes"]),
                       "rows": f"{datacon['stats'][os.path.basename(f['path']).split('_')[0]]['rows']}",
                       "note": "gzip jsonl（payload = base64+zlib 原始报文）"}
                      for f in datacon["files"]],
            "stats": datacon["stats"],
            "files": datacon["files"],
        },
        {
            "id": "cic_ids2017",
            "title": "CIC-IDS2017 流级特征表",
            "path": "traindata/CIC-IDS2017/",
            "role": "流级通道（独立通道，**不并入 HTTP 特征**）",
            "provenance": "公开数据集（CIC-IDS2017）；CSV 为官方发布版",
            "consumers": "`p5_flow_spike`（仅 spike，抽样 stride=20）",
            "usable": "数据可用，但**流级通道没有生产消费者**",
            "scale": f"{cic['stats'].get('rows', 0):,} 行 / "
                     f"{cic['stats'].get('attack_rows', 0):,} 攻击" if cic["stats"] else "未扫描（--skip-cic）",
            "notes": [
                "标签是流级类别（BENIGN/DDoS/PortScan/WebAttack/...），与 HTTP 通道的 5 类标签不是一回事",
                "`Destination Port` 对 PortScan 近乎泄漏，流级特征必须剔除（p5 已剔除）",
                "WebAttack 只有 "
                f"{sum(v for k, v in (cic['stats'].get('label_counts') or {}).items() if 'web attack' in k.lower()):,} 行，"
                "不足以支撑应用层召回",
            ],
            "table": [{"file": f["path"], "bytes": human(f["bytes"]), "rows": f"{f['rows']:,}",
                       "note": "、".join(f"{k}={v:,}" for k, v in f["labels"].items())}
                      for f in cic["files"]],
            "stats": cic["stats"],
            "files": cic["files"],
        },
        {
            "id": "local_benign",
            "title": "本机真实良性（phpStudy access log）",
            "path": "traindata/local/local_lab_benign.jsonl",
            "role": "真实良性池（三关 ② 关 + 融合 FPR）",
            "provenance": "本机 Apache/nginx access log，`provenance=benign_lab`，已脱敏",
            "consumers": "`calibrate_rules`（unified_benign）、`p4_local`",
            "usable": "可用，但只有 190 条唯一请求（751 行 → 去重 541）",
            "scale": f"{local['files']['local_lab_benign.jsonl']['rows']:,} 条",
            "notes": ["body 全空（access log 不落请求体）",
                      "来源是同一台实验机，路径集中在 phpMyAdmin/phpcms/dvwa",
                      "4 条 probe 命中已记录在 local_lab_report.json"],
            "table": [{"file": local["files"]["local_lab_benign.jsonl"]["path"],
                       "bytes": human(local["files"]["local_lab_benign.jsonl"]["bytes"]),
                       "rows": f"{local['files']['local_lab_benign.jsonl']['rows']}",
                       "note": "唯一请求数（非日志行数）"}],
            "stats": local["files"]["local_lab_benign.jsonl"],
            "files": [local["files"]["local_lab_benign.jsonl"]],
        },
        {
            "id": "local_inwild",
            "title": "在野良性（error log）+ IOC 攻击",
            "path": "traindata/local/inwild_*.jsonl",
            "role": "**不是良性池**：只能看命中率；inwild_attack 是攻击池一员",
            "provenance": "Apache error log；标签来自 IOC 正则（`provenance=indicator`），不是内容判定",
            "consumers": "`p4_local`（inwild_benign 命中率）、`calibrate_rules`（inwild_atk）",
            "usable": "inwild_benign 不可算 FPR（含 2,074 条扫描器命中）；inwild_attack 仅 12 条",
            "scale": f"{local['files']['inwild_benign.jsonl']['rows']:,} 良性侧 + "
                     f"{local['files']['inwild_attack.jsonl']['rows']} 攻击",
            "notes": ["105,742 条唯一请求，但 `audit_pattern_hits.scanner=2074` 已被扫描器污染",
                      "IOC 只命中 3 组模式（union select / .ssh 等敏感文件 / wp-login）→ 12 条",
                      "所有记录 body 为空、method 全 GET"],
            "table": [{"file": local["files"][n]["path"],
                       "bytes": human(local["files"][n]["bytes"]),
                       "rows": f"{local['files'][n]['rows']:,}",
                       "note": f"label={local['files'][n]['labels']}"}
                      for n in ("inwild_benign.jsonl", "inwild_attack.jsonl")],
            "stats": {n: local["files"][n] for n in ("inwild_benign.jsonl", "inwild_attack.jsonl")},
            "files": [local["files"][n] for n in ("inwild_benign.jsonl", "inwild_attack.jsonl")],
        },
        {
            "id": "local_datacon",
            "title": "datacon2025 拆出的攻击/未标注 jsonl",
            "path": "traindata/local/datacon_*.jsonl",
            "role": "OOD 链路自检",
            "provenance": "由 `export_datacon.py` 从 datacon 样本导出（保留 cve_labels/row_id）",
            "consumers": "人工复核 / 链路自检（判定链路用 `realdata.load_datacon` 现读）",
            "usable": "同 datacon：不报率",
            "scale": f"{local['files']['datacon_attack.jsonl']['rows']} 攻击 + "
                     f"{local['files']['datacon_unlabeled.jsonl']['rows']} 未标注",
            "notes": ["唯一带 body 的真实请求（攻击 17 条、未标注 23 条）",
                      "`datacon_unlabeled` 不是良性，别混池"],
            "table": [{"file": local["files"][n]["path"],
                       "bytes": human(local["files"][n]["bytes"]),
                       "rows": f"{local['files'][n]['rows']}",
                       "note": f"with_body={local['files'][n]['with_body']}"}
                      for n in ("datacon_attack.jsonl", "datacon_unlabeled.jsonl")],
            "stats": {n: local["files"][n] for n in
                      ("datacon_attack.jsonl", "datacon_unlabeled.jsonl")},
            "files": [local["files"][n] for n in
                      ("datacon_attack.jsonl", "datacon_unlabeled.jsonl")],
        },
        {
            "id": "collector_output",
            "title": "采集器落盘样本（proxy/）",
            "path": "traindata/proxy/",
            "role": "**运行样本，不是语料**（有 pred、无 label）",
            "provenance": "`proxy` 采集器 dry-run 输出（2 个 raw 分片 + metrics）",
            "consumers": "人工排查 / p8 e2e 观察",
            "usable": "不能进池（20 条、无标签）",
            "scale": f"{sum(f.get('rows', 0) for f in proxy['files'])} 条",
            "notes": ["字段含 `pred`（action/attack_label/score）与 `body_truncated`",
                      "与 `events` 表结构不同：这里是采集器原始记录，别当训练数据"],
            "table": [{"file": f["path"], "bytes": human(f["bytes"]),
                       "rows": f"{f.get('rows', '-')}",
                       "note": "with_pred=" + str(f.get("with_pred", "-"))}
                      for f in proxy["files"]],
            "stats": proxy["stats"],
            "files": proxy["files"],
        },
    ]

    totals_bytes = 0
    totals_files = 0
    for dirpath, _dirs, files in os.walk(TRAINDATA):
        for fn in files:
            p = os.path.join(dirpath, fn)
            if os.path.abspath(p) == os.path.abspath(OUT_MD):
                continue          # 目录说明本身不算语料
            totals_files += 1
            totals_bytes += os.path.getsize(p)

    catalog = {
        "schema": 1,
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "root": TRAINDATA,
        "coverage": {"cic_scanned": not skip_cic, "pools_computed": not skip_pools},
        "totals": {"files": totals_files, "bytes": totals_bytes},
        "corpora": corpora,
        "pools": pools,
        "archives": archives,
        "local_reports": local["reports"],
    }
    catalog["issues"] = build_issues({
        **catalog,
        "csic": csic,
        "payload_csv": payload_csv,
        "local_jsonl": local,
        "payload_dict": payload_dict,
        "datacon2025_sample": datacon,
        "cic_ids2017": cic,
        "collector_output": proxy,
    })
    catalog["recommendations"] = build_recommendations(catalog, pools)
    catalog["elapsed_s"] = round(time.time() - t0, 1)
    return catalog


def self_test() -> int:
    """自检：把目录里的**硬数字**钉成断言，改动数据后一眼看出哪里漂了。

    只跑秒级扫描（跳过 CIC 全表，CIC 的数字在 JSON 里但不在断言里）。
    """
    print("[self-test] 构建目录（skip_cic=True）...")
    cat = build_catalog(skip_cic=True, skip_pools=False)
    checks: list[tuple[str, bool, str]] = []

    def ck(name: str, cond: bool, detail: str = "") -> None:
        checks.append((name, bool(cond), detail))

    files = {os.path.basename(f["path"]): f for f in cat["corpora"][1]["stats"]["files"]}
    ck("T-01 payload train 行数", files["payload_train.csv"]["rows"] == 20712,
       str(files["payload_train.csv"]["rows"]))
    ck("T-02 payload test 行数", files["payload_test.csv"]["rows"] == 10355,
       str(files["payload_test.csv"]["rows"]))
    ck("T-03 payload full = train+test",
       files["payload_full.csv"]["rows"] == 20712 + 10355,
       str(files["payload_full.csv"]["rows"]))
    ck("T-04 train∩test = 0", cat["corpora"][1]["stats"]["train_test_overlap"] == 0)
    ck("T-05 full 集合 == train ∪ test",
       cat["corpora"][1]["stats"]["full_is_train_plus_test"] is True)
    ck("T-06 lexical 与 train/test 不相交",
       cat["corpora"][1]["stats"]["lexical_in_full"] == 0)
    ck("T-07 CSIC 正常 36,000",
       cat["corpora"][0]["stats"]["normal"]["requests"] == 36000,
       str(cat["corpora"][0]["stats"]["normal"]["requests"]))
    ck("T-08 CSIC 异常 25,065",
       cat["corpora"][0]["stats"]["anomalous"]["requests"] == 25065,
       str(cat["corpora"][0]["stats"]["anomalous"]["requests"]))
    ck("T-09 CSIC 正常无 PUT",
       cat["corpora"][0]["stats"]["normal"]["methods"].get("PUT", 0) == 0)
    ck("T-10 CSIC 异常有 PUT 397",
       cat["corpora"][0]["stats"]["anomalous"]["methods"].get("PUT", 0) == 397)
    ck("T-11 载荷字典 480 条",
       cat["corpora"][2]["stats"]["entries"] == 480,
       str(cat["corpora"][2]["stats"]["entries"]))
    ck("T-12 载荷字典坏对象 20",
       cat["corpora"][2]["stats"]["bad_objects"] == 20,
       str(cat["corpora"][2]["stats"]["bad_objects"]))
    ck("T-13 datacon 100 条 / 标注 42",
       cat["corpora"][3]["stats"]["total"] == 100
       and cat["corpora"][3]["stats"]["total_labeled_attack"] == 42,
       f"{cat['corpora'][3]['stats']['total']}/{cat['corpora'][3]['stats']['total_labeled_attack']}")
    lf = cat["corpora"][5]["stats"]
    ck("T-14 本机良性 190", lf["rows"] == 190, str(lf["rows"]))
    lw = cat["corpora"][6]["stats"]
    ck("T-15 inwild 良性 105,730 / 攻击 12",
       lw["inwild_benign.jsonl"]["rows"] == 105730
       and lw["inwild_attack.jsonl"]["rows"] == 12)
    ld = cat["corpora"][7]["stats"]
    ck("T-16 datacon 拆出 42 / 58，body 17 / 23",
       ld["datacon_attack.jsonl"]["rows"] == 42
       and ld["datacon_unlabeled.jsonl"]["rows"] == 58
       and ld["datacon_attack.jsonl"]["with_body"] == 17
       and ld["datacon_unlabeled.jsonl"]["with_body"] == 23)
    pools = cat["pools"]["pools"]
    ck("T-17 unified_benign = 6,190", pools["unified_benign"]["rows"] == 6190,
       str(pools["unified_benign"]["rows"]))
    ck("T-18 unified_attack = 25,119", pools["unified_attack"]["rows"] == 25119,
       str(pools["unified_attack"]["rows"]))
    ck("T-19 p7_benign = 37,000", pools["p7_benign"]["rows"] == 37000,
       str(pools["p7_benign"]["rows"]))
    ck("T-20 inwild_benign 不在任何池",
       all("inwild_benign" not in p["members"] for p in pools.values()))
    ck("T-21 池无缺成员", all(not p["missing"] for p in pools.values()))
    ck("T-22 语料 9 组", len(cat["corpora"]) == 9, str(len(cat["corpora"])))
    ck("T-23 每条语料都有 role/consumers/usable/scale/files",
       all((c.get("files") or c["id"] == "cic_ids2017")
           and all(c.get(k) for k in ("role", "consumers", "usable", "scale"))
           for c in cat["corpora"]))
    ck("T-24 issues 结构完整",
       cat["issues"] and all(i.get("id") and i.get("severity") and i.get("detail")
                             for i in cat["issues"]))
    ck("T-25 有 body 覆盖告警",
       any(i["id"] == "body_coverage_zero" for i in cat["issues"]))
    ck("T-26 md 能渲染", "traindata/" in render_md(cat))
    ck("T-27 覆盖率标记如实（skip_cic=True）",
       cat["coverage"]["cic_scanned"] is False and cat["coverage"]["pools_computed"] is True)

    bad = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))
    print(f"[self-test] {len(checks) - len(bad)}/{len(checks)} PASS")
    return 0 if not bad else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="traindata 数据目录（只读盘点）")
    ap.add_argument("--out", default=OUT_JSON)
    ap.add_argument("--md", default=OUT_MD)
    ap.add_argument("--skip-cic", action="store_true", help="跳过 CIC-IDS2017 全表扫描")
    ap.add_argument("--skip-pools", action="store_true", help="跳过池成分统计")
    ap.add_argument("--self-test", action="store_true", help="只跑断言，不写产物")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    if args.self_test:
        raise SystemExit(self_test())

    t0 = time.time()
    catalog = build_catalog(skip_cic=args.skip_cic, skip_pools=args.skip_pools)

    os.makedirs(ART, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)
    with open(args.md, "w", encoding="utf-8") as f:
        f.write(render_md(catalog))

    totals = catalog["totals"]
    print(f"\n[catalog] 语料 {len(catalog['corpora'])} 组 / {totals['files']} 文件 / "
          f"{human(totals['bytes'])}")
    print(f"[catalog] 问题 {len(catalog['issues'])} 条 / 建议 {len(catalog['recommendations'])} 条")
    print(f"[json] -> {os.path.relpath(args.out, HERE)}")
    print(f"[md]   -> {os.path.relpath(args.md, ROOT)}")
    print(f"[elapsed] {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
