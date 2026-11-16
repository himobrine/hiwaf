"""`traindata/` 数据目录（2026-11 版）：把每份语料登记成**可审计的一行**。

为什么重写：2026-11 语料被整体替换，旧目录（CSIC 2010 / HTTP Params 2015 /
CIC-IDS2017 / datacon / local / proxy）**已从磁盘删除**，旧版 `traindata_catalog.py`
的扫描器与 29 条断言全部失效。本版只认一个事实来源：`realdata_waf._inventory()`
（训练脚本用的同一批 loader），因此目录里的数字和训练集切分不会各说各话。

每个语料登记：角色（训练 / 良性池 / 攻击池 / 只评估）、行数、标签分布、
可用性判定，以及**为什么排除**某些文件。评估报告里出现的每个数字都应能反查到这里。

本工具**只读**：不改名、不移动、不删除任何文件。产出：
  * `artifacts/traindata_catalog.json`（机器可读）
  * `traindata/CATALOG.md`（人读，放在数据旁边）

用法：
    py -3.10 traindata_catalog.py                  # 全量盘点（约 1 分钟）
    py -3.10 traindata_catalog.py --skip-hash      # 不哈希文件（更快）
    py -3.10 traindata_catalog.py --self-test      # 盘点 + 断言，失败则退出码 1
    py -3.10 traindata_catalog.py --out x.json --md x.md
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

ROOT = os.path.abspath(os.path.join(HERE, ".."))
TRAINDATA = os.path.join(ROOT, "traindata")
ART = os.path.join(HERE, "artifacts")
OUT_JSON = os.path.join(ART, "traindata_catalog.json")
OUT_MD = os.path.join(TRAINDATA, "CATALOG.md")

HASH_LIMIT = 64 << 20

ROLES = {
    "xlsx": "主训练集：事务级 4 类攻击 + 良性（bruteforce 无槽位，只评估）",
    "parquet_train": "良性池来源（normal 可训练；anomalous 无子类，只做二分类评估）",
    "parquet_test": "独立评估集（normal 量误报 / anomalous 量检出）",
    "modsec": "真实在野攻击（目标 channel：召回评估 + 训练；零良性）",
    "payloads": "载荷集合（TP 进训练；false-positives 作困难良性负例）",
    "waf_detection": "外部 WAF 检测结果（无子类，只做二分类评估）",
    "fur_api": "真实 API 良性流量（监督/零日训练 + FUR test FPR 评估）",
    "sqliv5": "SQLi 载荷（含 WAF-A-MoLE 对抗样本，抽样进 train/valid）",
    "wafamole": "WAF-A-MoLE 变异 SQLi 载荷（流式抽样进 train/valid）",
    "wafrift": "WAF 绕过语料（13 类，8 类映射 0-4）",
    "waffled": "真实 WAF 绕过请求（JSON/multipart/XML body）",
    "commonhuman": "载荷库 + 编码器（**本轮不训练**，只登记）",
}


def sha1_of(path: str, limit: int = HASH_LIMIT) -> str | None:
    if os.path.getsize(path) > limit:
        return None
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def file_table(do_hash: bool = True) -> list:
    out = []
    for dirpath, _dirnames, filenames in os.walk(TRAINDATA):
        for name in sorted(filenames):
            p = os.path.join(dirpath, name)
            st = os.stat(p)
            out.append({
                "path": os.path.relpath(p, ROOT).replace("\\", "/"),
                "bytes": st.st_size,
                "mtime": _dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "sha1": (sha1_of(p) if do_hash else None),
            })
    return sorted(out, key=lambda x: x["path"])


def build_catalog(do_hash: bool = True) -> dict:
    import realdata_waf as rw

    inv = rw._inventory()
    catalog = {
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "root": os.path.relpath(TRAINDATA, ROOT).replace("\\", "/"),
        "loader": "realdata_waf._inventory（与训练同一批 loader）",
        "roles": ROLES,
        "corpora": {},
        "excluded": inv.get("excluded") or {},
        "files": file_table(do_hash),
    }
    for key, st in (inv.get("corpora") or {}).items():
        catalog["corpora"][key] = {**st, "role": st.get("role") or ROLES.get(key, "")}
    catalog["totals"] = {
        "files": len(catalog["files"]),
        "bytes": sum(f["bytes"] for f in catalog["files"]),
        "corpora": len(catalog["corpora"]),
    }
    return catalog


def build_issues(catalog: dict) -> list:
    issues = []
    x = catalog["corpora"].get("xlsx") or {}
    pq = catalog["corpora"].get("parquet_train") or {}
    pqte = catalog["corpora"].get("parquet_test") or {}
    ms = catalog["corpora"].get("modsec") or {}
    pay = catalog["corpora"].get("payloads") or {}
    wd = catalog["corpora"].get("waf_detection") or {}
    fur = catalog["corpora"].get("fur_api") or {}
    sq = catalog["corpora"].get("sqliv5") or {}
    am = catalog["corpora"].get("wafamole") or {}
    wr = catalog["corpora"].get("wafrift") or {}
    wf = catalog["corpora"].get("waffled") or {}

    if not x:
        issues.append({"level": "error", "code": "xlsx_missing", "msg": "缺 xlsx 主训练集"})
    else:
        if x.get("unique_requests", 0) < 1000:
            issues.append({"level": "warn", "code": "xlsx_small",
                           "msg": f"xlsx 去重后仅 {x.get('unique_requests')} 条"})
        if x.get("hosts", 99) < 10:
            issues.append({"level": "warn", "code": "xlsx_host_bias",
                           "msg": f"xlsx 仅 {x.get('hosts')} 个 host / {x.get('ips')} 个 IP，"
                                  "良性代表性有限"})
    if pq and pq.get("label_anomalous"):
        issues.append({"level": "info", "code": "parquet_no_subclass",
                       "msg": f"parquet anomalous {pq['label_anomalous']:,} 条无子类，"
                              "只能做二分类评估，不能进 5 类训练"})
    if pqte and pqte.get("duplicates"):
        issues.append({"level": "info", "code": "parquet_duplicates",
                       "msg": f"parquet test 有 {pqte['duplicates']:,} 行重复请求，"
                              f"去重后 {pqte.get('rows', 0) - pqte['duplicates']:,} 条唯一"})
    if ms and not ms.get("with_body"):
        issues.append({"level": "warn", "code": "modsec_no_body",
                       "msg": "ModSecurity 日志没有解析出任何 body（C 段格式可能变了）"})
    if wd and wd.get("bad_lines"):
        issues.append({"level": "info", "code": "wfdet_bad_lines",
                       "msg": f"WAF_DETECTION_DATASET.jsonl 有 {wd['bad_lines']} 行 JSON 损坏，已跳过"})
    if pay and not pay:
        issues.append({"level": "error", "code": "payload_empty", "msg": "载荷集为空"})
    # ---- 2026-11-16 新增语料 ----
    if not fur:
        issues.append({"level": "error", "code": "fur_missing", "msg": "缺 FUR-API train.csv（良性主力）"})
    elif fur.get("label_counts", {}).get("0", 0) < 1000:
        issues.append({"level": "error", "code": "fur_empty",
                       "msg": f"FUR normal 仅 {fur.get('label_counts', {}).get('0')} 条"})
    for key, blob, cap_key in (("sqliv5", sq, "cap"), ("wafamole", am, "cap")):
        if not blob:
            issues.append({"level": "error", "code": f"{key}_missing", "msg": f"缺 {key} 语料"})
            continue
        cap = blob.get(cap_key, 0)
        n = blob.get("sampled", 0)
        if n <= 0:
            issues.append({"level": "error", "code": f"{key}_empty", "msg": f"{key} 抽样为空"})
        elif cap and n > cap:
            issues.append({"level": "error", "code": f"{key}_over_cap",
                           "msg": f"{key} 抽样 {n:,} 超过上限 {cap:,}（上限没生效）"})
        else:
            issues.append({"level": "info", "code": f"{key}_capped",
                           "msg": f"{key} 抽样 {n:,}（上限 {cap:,}，稳定哈希）"})
    if sq.get("by_type", {}).get("valid"):
        issues.append({"level": "info", "code": "sqliv5_valid_excluded",
                       "msg": f"sqliv5 的 {sq['by_type']['valid']:,} 条 type=valid（合法 SQL）"
                              "已排除：放参数里与 SQLi 不可区分"})
    if wr and not wr.get("label_counts"):
        issues.append({"level": "error", "code": "wafrift_empty", "msg": "wafrift 无可映射样本"})
    if wf and wf.get("bad_blocks"):
        issues.append({"level": "warn", "code": "waffled_bad_blocks",
                       "msg": f"waffled 有 {wf['bad_blocks']} 个 bytes 字面量解析失败"})
    if wf and wf.get("unclassified"):
        issues.append({"level": "info", "code": "waffled_unclassified",
                       "msg": f"waffled 有 {wf['unclassified']} 条无法判定 sqli/xss，"
                              "只进二分类评估"})
    if "wafamole_dataset/sane.sql" not in (catalog.get("excluded") or {}):
        issues.append({"level": "error", "code": "sane_not_excluded",
                       "msg": "wafamole sane.sql 必须在排除清单里（合法 SQL 不能当良性）"})
    if "commonhuman-payloads-main/" not in (catalog.get("excluded") or {}):
        issues.append({"level": "warn", "code": "commonhuman_unregistered",
                       "msg": "commonhuman 未登记为排除（本轮不训练）"})
    return issues



def build_recommendations(catalog: dict) -> list:
    recs = [
        "5 类训练只收 label ∈ 0-4；无子类攻击（parquet anomalous / bruteforce / "
        "920 协议规则）只进二分类评估。",
        "校准池必须与训练集**互斥**：用 parquet normal 的独立留出桶，"
        "并让 `thresholds.py --train-keys` 校验训练指纹。",
        "xlsx 的良性只有千余条且只来自 3 个 host —— 误报率的代表性以 parquet 正常流量为准。",
        "ModSecurity 日志全是命中规则的事务，零良性：它只能量召回，不能量误报。",
        "2026-11-16 新增语料（FUR / sqliv5 / wafamole / wafrift / waffled）只进 "
        "train/valid（group 85/15），**不进 test**：test 与现役 g3/g5 同一批行，"
        "5 类指标才可比；新语料效果看 FUR test + exploit 的独立评估。",
        "`wafamole_dataset/sane.sql` 与 sqliv5 的 `type=valid` 都是**合法 SQL**，"
        "放参数里与 SQLi 不可区分 —— 当良性会教出“SELECT 是正常”的捷径，只登记不入训。",
        "SQLi 语料有上限（sqliv5 15k / wafamole 20k）且用稳定哈希抽样："
        "否则 128 万行攻击会淹没 ModSec 与 xlsx，其它类召回会掉。",
    ]
    if any(i["level"] == "error" for i in build_issues(catalog)):
        recs.insert(0, "⛔ 存在 error 级问题，先修数据再接训练。")
    return recs


def render_md(catalog: dict) -> str:
    L = []
    L.append("# traindata 语料目录（自动生成）\n")
    L.append(f"> `python/traindata_catalog.py`（{catalog['generated_at']}）—— **勿手改**。\n")
    L.append(f"- 根目录：`{catalog['root']}`")
    L.append(f"- 文件：{catalog['totals']['files']} 个 / "
             f"{catalog['totals']['bytes']/1048576:.1f} MB")
    L.append(f"- 数字来源：{catalog['loader']}\n")

    L.append("## 语料角色\n")
    L.append("| 语料 | 角色 | 可用性 | 关键数字 |")
    L.append("|---|---|---|---|")
    for key, c in catalog["corpora"].items():
        nums = []
        for k in ("rows", "transactions", "unique_requests", "requests", "days",
                  "cases", "blocks", "sampled", "label_normal", "label_anomalous",
                  "with_body", "bad_lines"):
            if k in c:
                nums.append(f"{k}={c[k]:,}" if isinstance(c[k], int) else f"{k}={c[k]}")
        if c.get("label_counts"):
            nums.append("labels=" + ",".join(f"{k}:{v:,}" for k, v in
                                             sorted(c["label_counts"].items())))
        L.append(f"| `{key}` | {c.get('role', '')} | {c.get('usable', '')} "
                 f"| {'; '.join(nums)} |")
    L.append("")

    L.append("## 排除的文件及原因\n")
    for name, why in (catalog.get("excluded") or {}).items():
        L.append(f"- `{name}` — {why}")
    L.append("")

    issues = catalog.get("issues") or []
    L.append("## 问题清单\n")
    if issues:
        for i in issues:
            L.append(f"- **{i['level']}** `{i['code']}`：{i['msg']}")
    else:
        L.append("- 无")
    L.append("")

    L.append("## 建议\n")
    for r in catalog.get("recommendations") or []:
        L.append(f"- {r}")
    L.append("")

    L.append("## 文件清单\n")
    L.append("| 文件 | 大小 | mtime | sha1 |")
    L.append("|---|---|---|---|")
    for f in catalog["files"]:
        L.append(f"| `{f['path']}` | {f['bytes']/1048576:.2f} MB | {f['mtime']} "
                 f"| `{(f['sha1'] or '')[:16]}` |")
    L.append("")
    return "\n".join(L)


def self_test(catalog: dict) -> int:
    """对**已构建**的目录做断言（不联网、不重扫数据）。"""
    n = 0
    bad = []

    def ck(name: str, cond: bool, detail: str = "") -> None:
        nonlocal n
        n += 1
        if not cond:
            bad.append(f"{name} {detail}".strip())

    c = catalog["corpora"]
    ck("xlsx 存在", "xlsx" in c)
    ck("xlsx 事务数 > 10k", (c.get("xlsx") or {}).get("transactions", 0) > 10000,
       f"={ (c.get('xlsx') or {}).get('transactions') }")
    ck("xlsx 唯一请求 > 10k", (c.get("xlsx") or {}).get("unique_requests", 0) > 10000)
    labels = (c.get("xlsx") or {}).get("label_counts") or {}
    for lab in ("0", "1", "2", "3", "4"):
        ck(f"xlsx 含标签 {lab}", lab in labels, f"labels={list(labels)}")
    ck("xlsx 有 body", (c.get("xlsx") or {}).get("with_body", 0) > 0)
    ck("parquet train 有 normal", (c.get("parquet_train") or {}).get("label_normal", 0) > 0)
    ck("parquet test 有 anomalous",
       (c.get("parquet_test") or {}).get("label_anomalous", 0) > 0)
    ck("modsec 有天数", (c.get("modsec") or {}).get("days", 0) > 0)
    ck("modsec 请求 > 1000", (c.get("modsec") or {}).get("requests", 0) > 1000)
    ck("payload 集非空", bool(c.get("payloads")))
    ck("wfdet 行数 > 0", (c.get("waf_detection") or {}).get("rows", 0) > 0)
    # ---- 2026-11-16 新增语料 ----
    ck("fur_api 存在", "fur_api" in c)
    ck("fur_api normal > 10k",
       (c.get("fur_api") or {}).get("label_counts", {}).get("0", 0) > 10000,
       f"={ (c.get('fur_api') or {}).get('label_counts', {}).get('0') }")
    ck("fur_api anomaly 未混入攻击子类",
       all(k in ("0",) for k in ((c.get("fur_api") or {}).get("label_counts") or {})),
       f"labels={ (c.get('fur_api') or {}).get('label_counts') }")
    sq = c.get("sqliv5") or {}
    ck("sqliv5 抽样非空", sq.get("sampled", 0) > 0)
    ck("sqliv5 抽样不超上限", sq.get("sampled", 0) <= (sq.get("cap") or 0),
       f"sampled={sq.get('sampled')} cap={sq.get('cap')}")
    ck("sqliv5 排除 valid", sq.get("by_type", {}).get("valid", 0) > 0)
    am = c.get("wafamole") or {}
    ck("wafamole 抽样非空", am.get("sampled", 0) > 0)
    ck("wafamole 抽样不超上限", am.get("sampled", 0) <= (am.get("cap") or 0),
       f"sampled={am.get('sampled')} cap={am.get('cap')}")
    wr = c.get("wafrift") or {}
    ck("wafrift case > 800", wr.get("cases", 0) > 800, f"={wr.get('cases')}")
    ck("wafrift 有可映射标签", bool(wr.get("label_counts")), f"={wr.get('label_counts')}")
    wf = c.get("waffled") or {}
    ck("waffled 有 block", wf.get("blocks", 0) > 0)
    ck("waffled 有 sqli/xss 标签", bool(wf.get("label_counts")), f"={wf.get('label_counts')}")
    ck("sane.sql 已排除", "wafamole_dataset/sane.sql" in (catalog.get("excluded") or {}))
    ck("FUR test 未登记为语料", "fur_test" not in c)
    ck("新语料都有角色", all(catalog["roles"].get(k) for k in
                            ("fur_api", "sqliv5", "wafamole", "wafrift",
                             "waffled", "commonhuman")))
    ck("排除清单非空", bool(catalog.get("excluded")))
    ck("文件清单非空", len(catalog.get("files") or []) > 0)
    ck("无 error 级问题",
       not any(i["level"] == "error" for i in build_issues(catalog)))
    print(f"[self-test] {n - len(bad)}/{n} 通过")
    for b in bad:
        print("  FAIL", b)
    return 0 if not bad else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="traindata 语料目录（2026-11 版）")
    ap.add_argument("--out", default=OUT_JSON)
    ap.add_argument("--md", default=OUT_MD)
    ap.add_argument("--skip-hash", action="store_true", help="不计算文件 sha1（更快）")
    ap.add_argument("--skip-cic", action="store_true",
                    help="兼容旧参数；新版没有 CIC，忽略")
    ap.add_argument("--self-test", action="store_true", help="盘点并断言，失败退出码 1")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    catalog = build_catalog(do_hash=not args.skip_hash)
    catalog["issues"] = build_issues(catalog)
    catalog["recommendations"] = build_recommendations(catalog)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)
    print(f"[catalog] -> {os.path.relpath(args.out, ROOT)}")

    if args.md:
        os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(render_md(catalog))
        print(f"[catalog] -> {os.path.relpath(args.md, ROOT)}")

    for i in catalog["issues"]:
        print(f"[{i['level']}] {i['code']}: {i['msg']}")

    if args.self_test:
        raise SystemExit(self_test(catalog))


if __name__ == "__main__":
    main()