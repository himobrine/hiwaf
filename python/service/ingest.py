"""原始 jsonl -> SQLite（增量、幂等）。

输入：`traindata/proxy/raw-*.jsonl`（采集器直出，**无 label**，`pred` 是模型输出）。

红线（与 `proxy/README.md`、`collect_http_log.py` 一致）：
  * 这里根本**不写 label**；`pred` 只进 `events` 的判定字段，绝不变成真值。
  * **body 默认不入库**（隐私优先，和 `collect_http_log.py` 的默认一致）；
    只有显式 `with_body=True` 才写入 `event_bodies`。
  * 按 `(src_file, src_line)` 唯一约束去重：重复扫描不会重复入库。
"""
from __future__ import annotations

import json
import threading
import time

from . import config, db

#: 单条事件最多落多少条规则命中（防病态规则集把一张事件撑爆）。
MAX_HITS_PER_EVENT = 50

#: 启动 ingest、定时 ingest、API 手动 scan 可能并发；串行化，避免重复统计/写状态。
_INGEST_LOCK = threading.Lock()


def _policy() -> dict:
    try:
        with open(config.POLICY_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _day_of(ts_ms: int) -> str:
    """UTC 日期。按天聚合只用于看趋势，不参与判定。"""
    return time.strftime("%Y-%m-%d", time.gmtime(max(0, int(ts_ms)) / 1000.0))


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _custom_qual(conn) -> dict:
    """规则 id -> 合格时间（NULL = 测试中）。只含自撰/导入规则。"""
    return {r["id"]: r["qualified_at"]
            for r in conn.execute("SELECT id, qualified_at FROM rules_custom")}


def _write_rules(conn, rid: int, ts: int, rules_out, custom_qual: dict) -> int:
    """把一条原始记录的 `rules` 块落成证据：events 快照 + event_rules + 按天聚合。

    返回 `(写入的命中条数, 是否由未合格规则触发)`。**绝不**把命中写成
    `events.attack_label`。
    """
    if not isinstance(rules_out, dict):
        return 0, 0
    hits = rules_out.get("hits") or []
    if not isinstance(hits, list) or not hits:
        # 没有命中时也把规则集指纹记下来：回答"这条请求是哪版规则判的"。
        sha = rules_out.get("rule_set_sha1_16")
        if sha:
            conn.execute("UPDATE events SET rule_set_sha1_16=? WHERE id=?", (sha, rid))
        return 0, 0

    hits = [h for h in hits[:MAX_HITS_PER_EVENT] if isinstance(h, dict) and h.get("rule")]
    if not hits:
        return 0, 0
    sha = rules_out.get("rule_set_sha1_16")
    # 控制 `rule_hits_json` 体积：逐条砍到 JSON 能完整解析为止（不能硬截断字符串）。
    store = hits
    while store and len(json.dumps(store, ensure_ascii=False)) > 16000:
        store = store[:-1]
    hits = store or hits[:1]
    testing = 1 if any(
        h.get("rule") in custom_qual and custom_qual.get(h.get("rule")) is None
        for h in hits
    ) else 0
    conn.execute(
        "UPDATE events SET rule_set_sha1_16=?, rule_hits_json=?, rule_testing=? WHERE id=?",
        (sha, json.dumps(hits, ensure_ascii=False), testing, rid),
    )

    day = _day_of(ts)
    seen_rules: set = set()
    for h in hits:
        rule = str(h.get("rule"))
        field = str(h.get("field") or "")
        action = str(h.get("action") or "alert")
        try:
            weight = float(h.get("weight") or 0.0)
        except (TypeError, ValueError):
            weight = 0.0
        snippet = (str(h.get("snippet")) if h.get("snippet") is not None else "")[:500]
        conn.execute(
            """INSERT OR IGNORE INTO event_rules
                 (event_id, rule, field, weight, action, snippet, name, severity,
                  scope, start, end)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, rule, field, weight, action, snippet,
             h.get("name"), h.get("severity"),
             h.get("scope"), _as_int(h.get("start")), _as_int(h.get("end"))),
        )
        if rule in seen_rules:
            continue
        seen_rules.add(rule)
        is_testing = 1 if (rule in custom_qual and custom_qual.get(rule) is None) else 0
        conn.execute(
            """INSERT INTO rule_hits_daily
                 (rule, day, hits, block_hits, testing_hits, last_ts, last_event)
               VALUES (?,?,1,?,?,?,?)
               ON CONFLICT(rule, day) DO UPDATE SET
                 hits         = hits + 1,
                 block_hits   = block_hits + excluded.block_hits,
                 testing_hits = testing_hits + excluded.testing_hits,
                 last_ts      = MAX(COALESCE(last_ts, 0), excluded.last_ts),
                 last_event   = CASE
                                  WHEN COALESCE(excluded.last_ts, 0) >= COALESCE(last_ts, 0)
                                  THEN excluded.last_event ELSE last_event END""",
            (rule, day, 1 if action == "block" else 0, is_testing, ts, rid),
        )
    return len(hits), testing


def _labels(policy: dict) -> dict[int, str]:
    lab = ((policy.get("supervised") or {}).get("labels") or {})
    out = {}
    for k, v in lab.items():
        try:
            out[int(k)] = str(v)
        except (TypeError, ValueError):
            pass
    return out


def ingest(with_body: bool = False) -> dict:
    """扫一遍 raw 目录，把新行灌进 events。返回统计。"""
    with _INGEST_LOCK:
        return _ingest_locked(with_body)


def _ingest_locked(with_body: bool = False) -> dict:
    policy = _policy()
    labels = _labels(policy)
    pver = policy.get("version")

    files = sorted(config.RAW_DIR.glob("raw-*.jsonl")) if config.RAW_DIR.exists() else []
    stats = {
        "files": len(files),
        "new_lines": 0,
        "inserted": 0,
        "skipped": 0,
        "bad": 0,
        "shap_rows": 0,
        "bodies": 0,
        "rule_hits": 0,
        "rule_testing_events": 0,
        "with_body": with_body,
    }

    conn = db.connect()
    try:
        custom_qual = _custom_qual(conn)
        for fp in files:
            key = str(fp)
            st = conn.execute(
                "SELECT size, lines, offset FROM ingest_state WHERE path=?", (key,)
            ).fetchone()
            try:
                st_size = fp.stat().st_size
                st_mtime = fp.stat().st_mtime
            except OSError:
                continue

            # 文件被截断（理论上轮转不会）就从头重扫；否则从已消费字节偏移续读。
            # 老库刚迁移时 offset=0 但 lines>0：从 0 重扫一次，靠 (src_file,src_line)
            # 唯一约束去重，之后 offset 就会前进。
            truncated = bool(st) and st_size < int(st["size"] or 0)
            use_offset = bool(st) and not truncated and int(st["offset"] or 0) > 0
            n = int(st["lines"] or 0) if use_offset else 0
            offset = int(st["offset"] or 0) if use_offset else 0
            if offset > st_size:
                n, offset = 0, 0

            with open(fp, "rb") as f:
                f.seek(offset)
                while True:
                    pos = f.tell()
                    raw = f.readline()
                    if not raw:
                        break
                    # 采集器写完一整行才可见；没有换行说明还在写，留给下一轮。
                    if not raw.endswith(b"\n"):
                        f.seek(pos)
                        break
                    n += 1
                    offset = f.tell()
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    stats["new_lines"] += 1
                    try:
                        d = json.loads(line)
                    except Exception:
                        stats["bad"] += 1
                        continue
                    pred = d.get("pred") or {}
                    if not isinstance(pred, dict):
                        pred = {}
                    ts = int(d.get("ts") or 0)
                    lab = pred.get("attack_label")
                    try:
                        lab_i = int(lab) if lab is not None else None
                    except (TypeError, ValueError):
                        lab_i = None
                    attack_type = labels.get(lab_i) if lab_i is not None else None
                    ip_list = d.get("ip_list") or None
                    if ip_list == "blacklist":
                        attack_type = "ip_blacklist"
                    elif ip_list == "whitelist":
                        attack_type = "ip_whitelist"

                    cur = conn.execute(
                        """INSERT OR IGNORE INTO events(
                            ts, ingest_ts, src_ip, src_port, host, route, method, path, query,
                            body_len, body_truncated, status, dur_ms, bytes_in, bytes_out,
                            ua, referer, action,
                            supervised_score, supervised_threshold, supervised_flagged,
                            zero_day_score, zero_day_threshold,
                            zero_day_score_crossed, zero_day_flagged, zero_day_enabled,
                            attack_label, attack_type, model_artifacts, dry_run, enforced,
                            src_kind, src_file, src_line, policy_version, ip_list
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            ts,
                            db.now_ms(),
                            d.get("src_ip"),
                            d.get("src_port"),
                            d.get("host"),
                            d.get("route"),
                            d.get("method"),
                            d.get("path"),
                            d.get("query"),
                            d.get("body_len"),
                            1 if d.get("body_truncated") else 0,
                            d.get("status"),
                            d.get("dur_ms"),
                            d.get("bytes_in"),
                            d.get("bytes_out"),
                            d.get("ua"),
                            d.get("referer"),
                            pred.get("action"),
                            pred.get("supervised_score"),
                            pred.get("supervised_threshold"),
                            1 if pred.get("supervised_flagged") else 0,
                            pred.get("zero_day_score"),
                            pred.get("zero_day_threshold"),
                            1 if pred.get("zero_day_score_crossed") else 0,
                            1 if pred.get("zero_day_flagged") else 0,
                            1 if pred.get("zero_day_enabled") else 0,
                            lab_i,
                            attack_type,
                            pred.get("artifacts"),
                            1 if pred.get("dry_run") else 0,
                            1 if pred.get("enforced") else 0,
                            d.get("src_kind"),
                            key,
                            n,
                            pver,
                            ip_list,
                        ),
                    )
                    if not cur.rowcount:
                        stats["skipped"] += 1
                        continue
                    rid = cur.lastrowid
                    stats["inserted"] += 1

                    n_hits, is_testing = _write_rules(conn, rid, ts, d.get("rules"), custom_qual)
                    stats["rule_hits"] += n_hits
                    if is_testing:
                        stats["rule_testing_events"] += 1

                    for rank, it in enumerate(pred.get("shap_topk") or []):
                        if not isinstance(it, dict):
                            continue
                        conn.execute(
                            "INSERT OR REPLACE INTO event_shap(event_id, rank, feature, value, contribution) VALUES(?,?,?,?,?)",
                            (rid, rank, it.get("feature"), it.get("value"), it.get("contribution")),
                        )
                        stats["shap_rows"] += 1

                    if with_body and d.get("body"):
                        conn.execute(
                            "INSERT OR REPLACE INTO event_bodies(event_id, body) VALUES(?,?)",
                            (rid, d["body"]),
                        )
                        stats["bodies"] += 1

            try:
                final_stat = fp.stat()
                state_size = final_stat.st_size
                state_mtime = final_stat.st_mtime
            except OSError:
                state_size, state_mtime = st_size, st_mtime
            conn.execute(
                "INSERT OR REPLACE INTO ingest_state(path, size, mtime, lines, offset) "
                "VALUES(?,?,?,?,?)",
                (key, state_size, state_mtime, n, offset),
            )
            conn.commit()

        conn.commit()
    finally:
        conn.close()
    return stats


def ingest_state() -> dict:
    files = db.rows("SELECT path, size, mtime, lines FROM ingest_state ORDER BY path")
    last = db.scalar("SELECT MAX(ts) AS t FROM events")
    return {
        "files": files,
        "last_event_ts": last,
        "lag_sec": (None if not last else max(0, (db.now_ms() - int(last)) // 1000)),
        "n_events": db.scalar("SELECT COUNT(*) AS n FROM events", default=0),
    }
