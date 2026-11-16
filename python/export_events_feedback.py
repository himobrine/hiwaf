"""控制台事件 + **人工反馈** → 训练增量 jsonl（带「去工具特征」）。

红线
----
* **标签只来自 `feedback`**（人工结论）。事件里的 `attack_type` 是模型预测，
  绝不当标签。攻击子类（1/2/3/4）由 **payload 形态签名**判定（确定性规则，
  可审计），导出报告里标 `label_source=payload_signature`。
* 未标注（`uncertain` / 无反馈）的事件一律不导出。

去工具特征（为什么）
--------------------
扫描器（sqlmap 等）会在编码风格上留下强指纹：`%27/%20` 密度、`/**/` 替空格、
随机数字/hex。直接拿这些样本训练，模型学的可能是"sqlmap 长什么样"，而不是注入本身。
所以对每条**攻击**样本额外生成两个变体：
  1. `decoded`：payload 解码后放回原位（去掉百分号编码指纹）；
  2. `reencoded`：payload 重新百分号编码（去掉"固定编码风格"这一捷径）。
良性样本不扩增（避免无意义地放大 FP 面），只保留原始请求。

用法
----
    python3 export_events_feedback.py --out artifacts/staging/events_fb.jsonl
    python3 export_events_feedback.py --from-ts 1794758400000 --no-augment
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import re
import sqlite3
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "service", "console.db")

#: 人工结论 → 正/负。`uncertain` 明确不导出。
VERDICT_SIDE = {
    "confirmed_attack": "attack",
    "missed": "attack",
    "false_positive": "benign",
    "confirmed_benign": "benign",
}

#: 参数名候选：避免「靶场里永远是 id」成为捷径。
PARAM_NAMES = ["id", "q", "pid", "uid", "item", "key", "search", "name", "page"]
#: 良性/攻击路径池：只在参数名层面随机化，路径保持原样（路径语义属于业务）。
MAX_BODY = 8192

CMD_RE = re.compile(
    r"(?:[;|&`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd|ping|sleep)\b(?=\s|/|$))"
    r"|(?:\$\(|\|\||&&)"
    r"|(?:/bin/(?:sh|bash))"
    r"|(?:cmd\.exe|powershell\.exe)"
    r"|(?:\b(?:system|exec|passthru|shell_exec)\s*\()",
    re.I,
)
XSS_RE = re.compile(r"(?:<\s*script|on(?:error|load|mouseover)\s*=|javascript:|<\s*svg|%3cscript)", re.I)
TRAV_RE = re.compile(r"(?:\.\./|\.\.\\|%2e%2e(?:/|%2f)|/etc/passwd|win\.ini)", re.I)
SQLI_RE = re.compile(
    r"(?:'\s*(?:or|and)\b"
    r"|\b(?:or|and)\s+'?\w+'?\s*(?:=|like)\s*'?\w+"
    r"|\bunion\s+(?:all\s+)?select\b"
    r"|--\s|#\s*$"
    r"|\b(?:sleep|benchmark)\s*\("
    r"|\binformation_schema\b"
    r"|\b(?:extractvalue|updatexml)\s*\()",
    re.I,
)


def has_attack_signal(text: str) -> bool:
    """模型可见字段里是否**真的有**攻击特征。

    为什么需要：人工确认的"攻击"可能把 payload 放在 Cookie / 自定义头里（模型看不到）。
    这种样本如果原样进训练集，就等于教模型"一个裸 GET /xxx 也是攻击" —— 会直接
    毒化正常页面。没有可见证据的样本必须跳过，改走规则通道。

    入参可以是编码后的文本（内部统一解码一次再匹配）。
    """
    s = decode_payload(text or "")
    return bool(CMD_RE.search(s) or XSS_RE.search(s)
                or TRAV_RE.search(s) or SQLI_RE.search(s))


def classify_payload(payload: str) -> int:
    """payload 形态签名 → 0-4（确定性、可审计）。`0` 只用于良性样本。

    顺序很重要：先判 cmdi（`;cat /etc/passwd` 里也含 `/etc/passwd`），
    再判 xss，最后判 traversal。`;id=1 AND 1=1` 是 path-info 型 SQLi ——
    `;id` 后面跟 `=` 而不是命令分隔，所以不会被误判成 cmdi。
    """
    s = payload or ""
    if CMD_RE.search(s):
        return 3
    if XSS_RE.search(s):
        return 2
    if TRAV_RE.search(s):
        return 4
    return 1


def decode_payload(s: str, rounds: int = 3) -> str:
    """反复 url-decode（最多 `rounds` 次），剥掉多重编码指纹。"""
    out = s or ""
    for _ in range(max(1, rounds)):
        nxt = urllib.parse.unquote(out, errors="replace")
        if nxt == out:
            break
        out = nxt
    return out


def split_query(q: str):
    """`a=1&b=2` → [(a, 1), (b, 2)]；保留顺序与空值。"""
    if not q:
        return []
    pairs = []
    for part in q.split("&"):
        if not part:
            continue
        k, sep, v = part.partition("=")
        pairs.append((k, v if sep else ""))
    return pairs


def rebuild_query(query: str, payload: str, *, encode: bool,
                  rng: random.Random) -> str:
    """把 payload 塞回 query（首参数），参数名按一半概率随机化。"""
    pairs = split_query(decode_payload(query))
    val = urllib.parse.quote(payload, safe="") if encode else payload
    name = rng.choice(PARAM_NAMES) if (pairs and rng.random() < 0.5) else "id"
    if pairs:
        pairs[0] = (name, val)
        rest = pairs[1:]
    else:
        rest = []
    out = [f"{k}={v}" for k, v in [(pairs[0] if pairs else (name, val))] + rest]
    return "&".join(out)


def variants(method: str, path: str, query: str, body: str, label: int,
             rng: random.Random, augment: bool = True):
    """一条样本 → [(method, path, query, body, variant)]。"""
    out = [(method, path, query, body, "orig")]
    if not augment or label == 0:
        return out
    if query or body:
        payload = decode_payload(query) if query else decode_payload(body)
        if not payload:
            return out
        out.append((method, path,
                    rebuild_query(query, payload, encode=False, rng=rng),
                    body, "decoded"))
        out.append((method, path,
                    rebuild_query(query, payload, encode=True, rng=rng),
                    body, "reencoded"))
        return out
    # payload 在 path 里（path-info 注入）：解码/重编码 path 本身
    if "%" in path:
        dp = decode_payload(path)
        out.append((method, dp, query, body, "path-decoded"))
        enc = urllib.parse.quote(dp, safe="/;=&?")
        if enc != path:
            out.append((method, enc, query, body, "path-reencoded"))
    return out


def _latest_verdicts(db_path: str, from_ts: int):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    rows = con.execute(
        """
        SELECT e.id, e.method, e.path, e.query, e.ts, b.body AS body,
               (SELECT f.verdict FROM feedback f WHERE f.event_id = e.id
                ORDER BY f.ts DESC, f.id DESC LIMIT 1) AS verdict
        FROM events e
        LEFT JOIN event_bodies b ON b.event_id = e.id
        WHERE e.ts >= ?
        """,
        (from_ts,),
    ).fetchall()
    con.close()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="事件 + 人工反馈 → 训练增量 jsonl")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--out", required=True)
    ap.add_argument("--from-ts", type=int, default=0,
                    help="只导出该毫秒时间戳之后的事件（默认全部）")
    ap.add_argument("--to-ts", type=int, default=0)
    ap.add_argument("--no-augment", action="store_true",
                    help="不做去工具特征扩增（只导出原始请求）")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()

    if not os.path.exists(a.db):
        raise SystemExit(f"找不到数据库：{a.db}")

    rows = _latest_verdicts(a.db, a.from_ts)
    rng = random.Random(a.seed)
    out_rows = []
    seen = set()
    stats = {
        "db": a.db, "from_ts": a.from_ts, "to_ts": a.to_ts or None,
        "events_scanned": len(rows),
        "by_verdict": collections.Counter(),
        "skipped_unlabeled": 0,
        "skipped_no_visible_payload": 0,
        "by_label": collections.Counter(),
        "by_variant": collections.Counter(),
        "label_source": "feedback(verdict) + payload_signature(subtype)",
        "augment": not a.no_augment,
    }
    for eid, method, path, query, ts, body, verdict in rows:
        if a.to_ts and int(ts or 0) > a.to_ts:
            continue
        side = VERDICT_SIDE.get((verdict or "").strip())
        if not side:
            stats["skipped_unlabeled"] += 1
            continue
        stats["by_verdict"][verdict] += 1
        method = (method or "GET").strip().upper()
        path = str(path or "")
        query = str(query or "")
        body = str(body or "")[:MAX_BODY]
        if side == "benign":
            label = 0
        else:
            evidence = " ".join([decode_payload(path), decode_payload(query),
                                 decode_payload(body)])
            if not has_attack_signal(evidence):
                # payload 在 Cookie / 自定义头里（模型看不到）：不能当训练样本，
                # 否则等于教模型「裸 GET 也是攻击」。
                stats["skipped_no_visible_payload"] += 1
                continue
            label = classify_payload(evidence)
        for m, p, q, b, variant in variants(method, path, query, body, label,
                                            rng, augment=not a.no_augment):
            key = (m, p, q, b)
            if key in seen:
                continue
            seen.add(key)
            out_rows.append({
                "method": m, "path": p, "query": q, "body": b,
                "label": int(label), "source": f"event-{eid}-{variant}",
                "event_id": int(eid),
            })
            stats["by_label"][str(label)] += 1
            stats["by_variant"][variant] += 1

    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    stats["rows_out"] = len(out_rows)
    print(f"[export] {a.out}: {len(out_rows):,} 条")
    print(f"[export] verdicts {dict(stats['by_verdict'])}  "
          f"labels {dict(stats['by_label'])}  variants {dict(stats['by_variant'])}")
    print(f"[export] 未标注/待查跳过 {stats['skipped_unlabeled']} 条")
    if stats["skipped_no_visible_payload"]:
        print(f"[export] 跳过 {stats['skipped_no_visible_payload']} 条：payload 只在 "
              f"Cookie/请求头里，模型输入看不到（标成攻击会毒化正常页面；这类应进规则通道）")
    meta = os.path.splitext(a.out)[0] + ".stats.json"
    with open(meta, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    print(f"[export] stats -> {meta}")
    if not out_rows:
        print("[export] ⚠️ 没有任何可用样本：先在事件页对样本打人工结论（确认攻击/误报/正常）")
    return 0


if __name__ == "__main__":
    sys.exit(main())