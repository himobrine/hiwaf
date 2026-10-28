"""把 datacon2025-xlab-httpcve-sample 导出成项目统一 JSONL（**只作 OOD 验收集**）。

为什么它**不能**进训练（用户曾提议当"核心恶意样本池"）：

  * **量太小**：整个发布只有 50(train) + 50(test) = 100 条，其中官方标注=1 的共 42 条、
    带 body 的 20+20 = 40 条。这个量级训练不出任何监督模型（本项目 lexical 有 106 条
    攻击就已经在报告里标注"n 太小，不要引用百分比"）。
  * **label=0 不是良性**：例如 `GET /actuator/gateway/routes/...`（Spring 网关 RCE 探测）
    被标成 0。把 label=0 当良性池会把 FPR 直接算错，所以这里**拆成两个文件**。
  * **它是本项目唯一的真实 OOD 验收集**（见 REALDATA_EVALUATION.md §8.4）。放进训练
    会同时毁掉训练集和验收集——这正是"用旧分布数据硬调参"的另一种形态。

它**真正**的价值：这是手里唯一一个**带真实请求 body** 的真实攻击样本集，用来回答
"当前特征/模型到底会不会用 body"（见 p6_body_ablation.py）。

产出（`traindata/local/`）：
  * `datacon_attack.jsonl`    —— 官方标注=1（真实攻击，含真实 body）
  * `datacon_unlabeled.jsonl` —— 官方标注=0（**不是良性**，只可人工复核）

字段与 `inwild_attack.jsonl` 对齐，可直接喂给 `p4_local.py` / `p6_body_ablation.py`。

用法：
    py -3.10 export_datacon.py
    py -3.10 export_datacon.py --out-dir ..\\traindata\\local
"""
from __future__ import annotations

import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL = os.path.abspath(os.path.join(HERE, "..", "traindata", "local"))


def _clean_body(s: str, limit: int = 4096) -> str:
    """去掉二进制噪声（base64 段被解出来后常带不可打印字节），并限长。"""
    s = "".join(ch for ch in (s or "") if ch.isprintable() or ch in "\r\n\t")
    return s[:limit]


def export(out_dir: str) -> dict:
    from realdata import load_datacon

    rows = []
    for split in ("train", "test"):
        for r in load_datacon(split):
            rows.append((split, r))

    atk = [(sp, r) for sp, r in rows if r["label"] == 1]
    unk = [(sp, r) for sp, r in rows if r["label"] != 1]

    os.makedirs(out_dir, exist_ok=True)
    paths = {}

    def _write(name, items, why):
        p = os.path.join(out_dir, name)
        with open(p, "w", encoding="utf-8") as f:
            for sp, r in items:
                f.write(json.dumps({
                    "method": r["method"], "path": r["path"], "query": r["query"],
                    "body": _clean_body(r.get("body") or ""),
                    "ts": "", "src_ip": "", "status": "", "ua": "",
                    "headers": r.get("headers") or {},
                    "label": r["label"], "label_why": why,
                    "src_kind": f"datacon-{sp}",
                    "cve_labels": r.get("cve_labels") or [],
                    "row_id": r.get("row_id"),
                }, ensure_ascii=False) + "\n")
        paths[name] = p
        return p

    _write("datacon_attack.jsonl", atk, "datacon官方标注=1（真实攻击；OOD 验收集，禁止入训练）")
    _write("datacon_unlabeled.jsonl", unk, "datacon官方未标注（≠良性！需人工复核，不得当良性池）")

    n_body = sum(1 for _, r in atk if (r.get("body") or "").strip())
    n_body_unk = sum(1 for _, r in unk if (r.get("body") or "").strip())
    summary = {
        "source": "datacon2025-xlab-httpcve-sample",
        "role": "OOD 验收集（禁止入训练，禁止当良性池）",
        # 决策记录：100 条样本的 Wilson 区间宽到没有统计意义（n=42 时 95% CI ≈ 32%~81%），
        # 任何"召回率"数字都会被安全评审直接质疑。它只能回答"链路通不通 / 能不能检出"。
        "reportable": False,
        "reportable_reason": (
            "样本量 n=100（标注=1 仅 42）过小，召回率的置信区间宽到无意义；"
            "且它来自与部署分布不同的采集源（见 why_not_training）。"
            "**只能用于链路自检（能不能检出），不得在任何评估报告里引用其召回率/准确率。**"
            "OOD 评估请改用 CSIC 2010（应用层）+ CIC-IDS2017（流级）。"
        ),
        "allowed_use": "链路自检 / 冒烟测试（只问\"检出与否\"，不报率）",
        "n_total": len(rows),
        "n_labeled_attack": len(atk),
        "n_labeled_attack_with_body": n_body,
        "n_unlabeled": len(unk),
        "n_unlabeled_with_body": n_body_unk,
        "distinct_cves": len({c for _, r in atk for c in (r.get("cve_labels") or [])}),
        "files": {k: os.path.relpath(v, HERE) for k, v in paths.items()},
        "why_not_training": [
            "100 条总量（标注=1 仅 42，带 body 仅 40）不足以训练监督模型",
            "label=0 不是良性（含 Spring 网关 RCE 探测），当良性池会算错 FPR",
            "它已是本项目唯一真实 OOD 验收集，入训练会同时毁掉训练集与验收集",
        ],
    }
    with open(os.path.join(out_dir, "datacon_report.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=LOCAL)
    args = ap.parse_args()
    s = export(os.path.abspath(args.out_dir))
    print(f"[datacon] 总 {s['n_total']} 条 -> 标注攻击 {s['n_labeled_attack']} 条"
          f"（带 body {s['n_labeled_attack_with_body']}）"
          f" + 未标注 {s['n_unlabeled']} 条（带 body {s['n_unlabeled_with_body']}）")
    for k, v in s["files"].items():
        print(f"  -> {v}")
    print(f"[datacon] 覆盖 CVE 数 = {s['distinct_cves']}；定位 = {s['role']}")
    if not s.get("reportable", True):
        print("[datacon] ⛔ reportable = False：" + s["reportable_reason"])
        print(f"[datacon] 允许用途：{s['allowed_use']}")


if __name__ == "__main__":
    main()
