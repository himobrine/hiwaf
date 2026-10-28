"""S4 / 工作项 F：**采集数据面端到端验证**（Pingora collector -> 原始 jsonl -> 出处标注 [+ dry-run 判定]）。

阶段 A（纯采集）要证明的链路（全程**不依赖任何内容正则**打标签）：

    请求（含攻击 body）
      └─► waf-collector（Pingora 反向代理）
            └─► traindata/proxy/raw-*.jsonl        **原始，无 label**
                  └─► collect_http_log.py --provenance auto --canary-prefix /admin.php
                        └─► *_attack.jsonl / *_benign.jsonl（label 来自**出处**，可审计）

阶段 B（`--score`，dry-run）额外证明：

  * 判定只**记录**不阻断（7 个请求全部 200，客户端行为不变）；
  * `pred.zero_day_enabled=false` 的**安全降级已传播到数据面**
    （`zero_day_flagged` 恒 false，但 `zero_day_score_crossed` 原始穿阈证据仍保留）；
  * **模型输出结构上不可能变成训练标签**：`pred` 只出现在原始 jsonl，
    `collect_http_log.py` 的 `parse_jsonl` 只保留已知键，标注后 `pred` 键消失，
    而标签仍只由出处规则（蜜罐路径）决定。

产物：`artifacts/p8_proxy_e2e.json`

用法：
    py -3.10 p8_proxy_e2e.py                 :: 需先 build 过 proxy（proxy/target/release/waf-collector.exe）
    py -3.10 p8_proxy_e2e.py --no-score       :: 跳过阶段 B（不加载 ONNX，跑得更快）
    py -3.10 p8_proxy_e2e.py --keep-tmp       :: 保留临时目录以便手工查看
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
ART = os.path.join(HERE, "artifacts")
ARTIFACTS_DIR = os.path.join(HERE, "artifacts")          # 模型产物目录（绝对路径，避免 CWD 依赖）
COLLECTOR = None          # 运行期解析（见 find_collector）
CANARY = "/admin.php"
BODY_KEEP = 65536
N_REQS = 7


def find_collector(explicit: str = None) -> str:
    """找 `waf-collector` 可执行文件。

    build.bat 把 cargo 的 target 目录放在 `WAF_CARGO_TARGET`（默认 `E:\\waf-target`，
    因为 F: 盘几乎满了、且要与 rust/ 共用缓存，避免 ort 编译两遍）。所以这里按
    候选顺序查：显式参数 -> 环境变量 -> 默认共享目录 -> 两个 crate 自己的 target。
    """
    names = ["waf-collector.exe", "waf-collector"] if os.name == "nt" else ["waf-collector"]
    roots = []
    if explicit:
        roots.append(explicit if os.path.isdir(explicit) else os.path.dirname(explicit))
    for k in ("CARGO_TARGET_DIR", "WAF_CARGO_TARGET"):
        if os.environ.get(k):
            roots.append(os.environ[k])
    roots += [r"E:\waf-target", os.path.join(ROOT, "target"),
              os.path.join(ROOT, "proxy", "target")]
    for r in roots:
        for n in names:
            p = os.path.join(r, "release", n)
            if os.path.isfile(p):
                return p
    return os.path.join(r"E:\waf-target", "release", names[0])


# --------------------------------------------------------------------------- 假上游
class QuietServer(ThreadingHTTPServer):
    """采集器收工时会重置 keep-alive 连接；这里静音，避免把 traceback 混进验证输出。"""
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class Upstream(BaseHTTPRequestHandler):
    """最小上游：任何方法都回 200 + 4 字节，好让 bytes_out > 0 可验证。"""
    protocol_version = "HTTP/1.1"

    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = b"ok!!"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = _reply

    def log_message(self, *a):  # 静音
        pass


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port: int, timeout: float = 25.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def send_raw(port: int, req: bytes, timeout: float = 20.0) -> str:
    """发原始 HTTP 请求，返回状态行。用裸 socket 避免 shell/客户端转义干扰。"""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(req)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            c = s.recv(4096)
            if not c:
                break
            data += c
        return data.split(b"\r\n", 1)[0].decode("latin-1") if data else "<no response>"
    finally:
        s.close()


def http_req(method: str, path: str, body: bytes = b"", ua: str = "p8-probe/1.0",
             ctype: str = "application/x-www-form-urlencoded", extra_headers: str = "") -> bytes:
    h = (f"{method} {path} HTTP/1.1\r\n"
         f"Host: 127.0.0.1\r\n"
         f"User-Agent: {ua}\r\n"
         f"Connection: close\r\n")
    if extra_headers:
        h += extra_headers
    if body:
        h += f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
    return h.encode() + b"\r\n" + body


SQLI_BODY = b"id=1' OR '1'='1&Submit=Submit"
TRICKY = "msg=\u4e2d\u6587\"quote\\back\x09tab&x=1".encode("utf-8")
BIG = b"data=" + b"A" * 200_000
BINARY_BODY = bytes(range(256)) * 8

REQS = [
    ("良性 GET", http_req("GET", "/index.php")),
    ("良性 POST", http_req("POST", "/comment.php", b"msg=hello&x=1")),
    ("攻击 SQLi(canary 路径)",
     http_req("POST", CANARY, SQLI_BODY, ua="sqlmap/1.7",
              extra_headers="Authorization: Bearer p8-secret\r\nX-P8-Probe: headers\r\n")),
    ("攻击 XSS(canary 路径)", http_req("POST", CANARY,
                                    b"msg=<script>alert(1)</script>", ua="Mozilla/5.0")),
    ("转义刁钻", http_req("POST", "/comment.php", TRICKY)),
    ("超大 body", http_req("POST", "/upload.php", BIG)),
    ("二进制 body", http_req("POST", "/binary.php", BINARY_BODY,
                            ctype="application/octet-stream")),
]


# --------------------------------------------------------------------------- 跑一个阶段
def run_phase(tmp: str, tag: str, extra: list, collector_log_name: str, collector: str):
    """起假上游 + 采集器，发 7 个请求，收工。返回 (记录列表, raw 目录, 状态行列表)。"""
    raw_dir = os.path.join(tmp, tag)
    up_port, listen_port = free_port(), free_port()
    srv = QuietServer(("127.0.0.1", up_port), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    clog = open(os.path.join(tmp, collector_log_name), "wb")
    proc = subprocess.Popen(
        [collector, "--listen", f"127.0.0.1:{listen_port}",
         "--upstream", f"127.0.0.1:{up_port}",
         "--out", raw_dir, "--body-keep", str(BODY_KEEP)] + extra,
        stdout=clog, stderr=subprocess.STDOUT,
    )
    statuses = []
    try:
        ready = wait_port(listen_port)
        if not ready:
            return None, raw_dir, statuses
        for label, raw in REQS:
            st = send_raw(listen_port, raw)
            statuses.append(st)
            print(f"       [{tag}] {label:<24} -> {st}")
        time.sleep(1.5)                                   # 等落盘 + 判定
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        clog.close()
        srv.shutdown()

    raws = []
    if os.path.isdir(raw_dir):
        for fn in sorted(os.listdir(raw_dir)):
            if fn.endswith(".jsonl"):
                with open(os.path.join(raw_dir, fn), "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            raws.append(json.loads(line))
    return raws, raw_dir, statuses


def main():
    ap_ = argparse.ArgumentParser()
    ap_.add_argument("--keep-tmp", action="store_true")
    ap_.add_argument("--no-score", action="store_true", help="跳过阶段 B（dry-run 判定）")
    ap_.add_argument("--collector", default=None, help="waf-collector 可执行文件路径（默认自动查找）")
    args = ap_.parse_args()

    checks = []

    def check(name: str, ok: bool, detail: str):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    collector = find_collector(args.collector)
    if not os.path.exists(collector):
        raise SystemExit(f"[p8] 找不到采集器，尝试过 {collector}\n"
                         f"     请先在 F:\\waf\\proxy 下跑 build.bat build --release\n"
                         f"     （可用 --collector <path> 指定，或设 CARGO_TARGET_DIR）")
    print(f"[p8] 采集器 {collector}")

    tmp = tempfile.mkdtemp(prefix="p8_proxy_")
    print(f"[p8] 临时目录 {tmp}")

    # =========================== 阶段 A：纯采集 ===========================
    print("\n[p8] ==== 阶段 A：纯采集（无判定） ====")
    # 纯采集阶段显式用 `--resp-body all`，验证响应体/头确实能落盘；
    # 默认 alert 模式只采 alert/block，仍在阶段 B 用默认参数覆盖。
    raws, raw_dir_a, statuses_a = run_phase(
        tmp, "rawA", ["--resp-body", "all"], "collectorA.log", collector)
    if raws is None:
        check("采集器监听就绪", False, "超时未监听")
        return finish(tmp, args, checks, {})
    check("采集器监听就绪", True, "up+collector 已起")
    check("请求条数一致", len(raws) == N_REQS, f"{len(raws)}/{N_REQS}")
    check("全部 200（采集不改变客户端行为）",
          all(s.endswith("200 OK") for s in statuses_a), f"{sorted(set(statuses_a))}")
    check("原始记录**不含 label 字段**", all("label" not in r for r in raws),
          "采集端不许自己打标签")
    check("不启用 --score 时不写 pred", all("pred" not in r for r in raws),
          "默认纯采集，不加载模型")

    sq = next((r for r in raws if r.get("body") == SQLI_BODY.decode()), None)
    check("SQLi body 逐字节一致", sq is not None, repr(SQLI_BODY.decode())[:48])
    xss = next((r for r in raws if "alert(1)" in (r.get("body") or "")), None)
    check("XSS body 保留", xss is not None, repr((xss or {}).get("body", ""))[:60])
    check("UA 采集", (sq or {}).get("ua") == "sqlmap/1.7", f"ua={(sq or {}).get('ua')!r}")
    check("请求版本/有序头落盘",
          all(r.get("http_version") == "HTTP/1.1"
              and isinstance(r.get("headers"), list)
              and all(isinstance(h, list) and len(h) == 2 for h in r["headers"])
              for r in raws),
          f"versions={sorted({r.get('http_version') for r in raws})} "
          f"header_counts={[len(r.get('headers') or []) for r in raws]}")
    auth_hdr = next((h for h in ((sq or {}).get("headers") or [])
                     if h[0].lower() == "authorization"), None)
    check("Authorization 头落盘（前端默认打码）",
          auth_hdr is not None and auth_hdr[0].lower() == "authorization"
          and auth_hdr[1] == "Bearer p8-secret",
          f"auth={auth_hdr}")
    check("请求 body_b64 精确字节 == 原 body",
          sq is not None
          and base64.b64decode(sq.get("body_b64") or "") == SQLI_BODY,
          f"b64_len={len((sq or {}).get('body_b64') or '')}")

    resp = (sq or {}).get("response") or {}
    rb = (resp.get("body") or {}) if isinstance(resp.get("body"), dict) else {}
    check("响应状态/版本/头落盘",
          resp.get("captured") is True and resp.get("status") == 200
          and resp.get("http_version") == "HTTP/1.1"
          and any(h[0].lower() == "content-type" for h in (resp.get("headers") or [])),
          f"status={resp.get('status')} version={resp.get('http_version')} "
          f"headers={[h[0] for h in (resp.get('headers') or [])][:5]}")
    check("响应体采样（--resp-body all，wire bytes 可逆）",
          resp.get("body_sampled") is True
          and base64.b64decode(rb.get("b64") or "") == b"ok!!"
          and rb.get("wire_bytes") == 4,
          f"sampled={resp.get('body_sampled')} b64={rb.get('b64')!r} "
          f"wire={rb.get('wire_bytes')}")

    bin_r = next((r for r in raws if r.get("path") == "/binary.php"), None)
    check("二进制请求体：body 为空 + body_b64 精确 + body_is_binary",
          bin_r is not None
          and bin_r.get("body") == ""
          and bin_r.get("body_is_binary") is True
          and base64.b64decode(bin_r.get("body_b64") or "") == BINARY_BODY
          and bin_r.get("body_len") == len(BINARY_BODY),
          f"body={ (bin_r or {}).get('body')!r} "
          f"binary={(bin_r or {}).get('body_is_binary')} "
          f"len={(bin_r or {}).get('body_len')}")

    big_r = next((r for r in raws if r.get("path") == "/upload.php"), None)
    if big_r:
        check("超大 body 标记截断", big_r.get("body_truncated") is True,
              f"body_truncated={big_r.get('body_truncated')}")
        check("截断后 body_len 仍为真实总长", big_r.get("body_len") == len(BIG),
              f"body_len={big_r.get('body_len')} expect={len(BIG)}")
        check("落盘 body 长度 = body_keep", len(big_r.get("body") or "") == BODY_KEEP,
              f"len={len(big_r.get('body') or '')} expect={BODY_KEEP}")
    else:
        check("超大 body 记录存在", False, "缺 /upload.php")

    if sq:
        flow_ok = (float(sq.get("dur_ms") or 0) > 0
                   and int(sq.get("bytes_in") or 0) == len(SQLI_BODY)
                   and int(sq.get("bytes_out") or 0) > 0
                   and (sq.get("src_ip") or "") != "")
        check("流级字段(dur_ms/bytes_in/bytes_out/src_ip)", flow_ok,
              f"dur_ms={sq.get('dur_ms')} bytes_in={sq.get('bytes_in')} "
              f"bytes_out={sq.get('bytes_out')} src={sq.get('src_ip')}")

    tr = next((r for r in raws if "\u4e2d\u6587" in (r.get("body") or "")), None)
    check("中文/引号/反斜杠/制表 转义往返一致",
          tr is not None and tr.get("body") == TRICKY.decode("utf-8"),
          repr((tr or {}).get("body", ""))[:70])

    # =========================== 阶段 B：dry-run 判定 ===========================
    pred_stats = {}
    if args.no_score:
        print("\n[p8] ==== 阶段 B 跳过（--no-score） ====")
    else:
        print("\n[p8] ==== 阶段 B：dry-run 判定（--score，只记录不阻断） ====")
        raws_b, raw_dir_b, statuses_b = run_phase(
            tmp, "rawB", ["--score", "--artifacts", ARTIFACTS_DIR], "collectorB.log", collector)
        if raws_b is None:
            check("阶段 B 采集器就绪", False, "超时未监听")
        else:
            check("B: 请求条数一致", len(raws_b) == N_REQS, f"{len(raws_b)}/{N_REQS}")
            check("B: 判定不阻断（全部 200）",
                  all(s.endswith("200 OK") for s in statuses_b), f"{sorted(set(statuses_b))}")
            check("B: 原始记录仍**不含 label**", all("label" not in r for r in raws_b), "ok")
            npred = sum(1 for r in raws_b if "pred" in r)
            check("B: 每条都有 pred（dry_run=true）", npred == len(raws_b) and
                  all((r.get("pred") or {}).get("dry_run") is True
                      for r in raws_b if "pred" in r), f"{npred}/{len(raws_b)}")

            preds = [r["pred"] for r in raws_b if "pred" in r]
            actions = sorted({p["action"] for p in preds})
            check("B: action ∈ {allow,block,alert}", set(actions) <= {"allow", "block", "alert"},
                  f"actions={actions}")
            check("B: **安全降级已传播**：zero_day_enabled=false ⇒ zero_day_flagged 恒 false",
                  all(p["zero_day_enabled"] is False for p in preds)
                  and all(p["zero_day_flagged"] is False for p in preds),
                  f"enabled={sorted({p['zero_day_enabled'] for p in preds})} "
                  f"flagged={sorted({p['zero_day_flagged'] for p in preds})}")
            check("B: 零日**原始穿阈**证据仍保留（有 crossed 也不告警）",
                  all("zero_day_score_crossed" in p for p in preds),
                  f"crossed={sum(1 for p in preds if p['zero_day_score_crossed'])}/{len(preds)}")
            check("B: 阈值与 policy 同源（监督 0.699765 / 零日 -7.262677）",
                  all(abs(p["supervised_threshold"] - 0.699765) < 1e-4 for p in preds)
                  and all(abs(p["zero_day_threshold"] - (-7.262677)) < 1e-4 for p in preds),
                  f"sup={sorted({round(p['supervised_threshold'], 6) for p in preds})} "
                  f"zd={sorted({round(p['zero_day_threshold'], 6) for p in preds})}")
            check("B: **SHAP Top-K 归因**已写入记录（控制台详情页的「为什么」）",
                  all(isinstance(p.get("shap_topk"), list) and len(p["shap_topk"]) == 8
                      for p in preds)
                  and all(set(it.keys()) == {"feature", "value", "contribution"}
                          for p in preds for it in p["shap_topk"]),
                  f"K={sorted({len(p.get('shap_topk') or []) for p in preds})} "
                  f"top1={[(p['shap_topk'][0]['feature'] if p.get('shap_topk') else None) for p in preds]}")

            pred_stats = {
                "actions": {a: sum(1 for p in preds if p["action"] == a) for a in
                            ("allow", "block", "alert")},
                # 逐条列出（**不要**按 path 做 key：SQLi/XSS 同路径会被覆盖掉一条）
                "per_request": [
                    {
                        "method": r["method"], "path": r["path"],
                        "ua": r.get("ua", ""), "body_len": r.get("body_len"),
                        "action": r["pred"]["action"],
                        "supervised_score": round(r["pred"]["supervised_score"], 6),
                        "supervised_flagged": r["pred"]["supervised_flagged"],
                        "zero_day_score": round(r["pred"]["zero_day_score"], 6),
                        "zero_day_score_crossed": r["pred"]["zero_day_score_crossed"],
                        "zero_day_flagged": r["pred"]["zero_day_flagged"],
                        "shap_top1": (r["pred"].get("shap_topk") or [{}])[0].get("feature"),
                    }
                    for r in raws_b if "pred" in r
                ],
                "note": "**诊断值，不是验收指标**：上线模型训练集带 body 记录 = 0 条，"
                        "且阈值未在真实本地良性上重标定。这 7 条不构成任何率的证据。",
            }
            # ---- 关键：把**带 pred 的**原始文件下游标注一遍，验证模型输出进不去标签 ----
            raw_dir_a = raw_dir_b

    # =========================== 阶段 C：规则通道 ===========================
    # 这一步专门验证 R4b 的**接线**：规则证据必须真的进判定器，而不是只落盘。
    # 混淆点：`RulesOut`（证据）和 `pred.action`（融合动作）是两条独立写出的路径，
    # 如果只在 filters 里算了规则却没喂给 `decide_with_rules`，两边都会"看起来正常"。
    if args.no_score:
        print("\n[p8] ==== 阶段 C 跳过（--no-score：规则证据要和判定一起看） ====")
    else:
        rules_path = os.path.join(ARTIFACTS_DIR, "rules_authoritative.json")
        pol_path = os.path.join(ARTIFACTS_DIR, "decision_policy.json")
        pol = {}
        try:
            with open(pol_path, "r", encoding="utf-8") as f:
                pol = json.load(f)
        except OSError:
            pass
        rcfg = pol.get("rules") or {}
        if not rcfg.get("enabled") or not os.path.exists(rules_path):
            print("\n[p8] ==== 阶段 C 跳过（策略未启用规则通道，或无现役规则集） ====")
        else:
            print("\n[p8] ==== 阶段 C：规则通道（--rules，证据必须进融合） ====")
            raws_c, _, statuses_c = run_phase(
                tmp, "rawC",
                ["--score", "--artifacts", ARTIFACTS_DIR, "--rules", rules_path],
                "collectorC.log", collector)
            if raws_c is None:
                check("阶段 C 采集器就绪", False, "超时未监听")
            else:
                check("C: 请求条数一致", len(raws_c) == N_REQS, f"{len(raws_c)}/{N_REQS}")
                preds_c = [r["pred"] for r in raws_c if "pred" in r]
                check("C: 每条都有 pred", len(preds_c) == len(raws_c),
                      f"{len(preds_c)}/{len(raws_c)}")
                # R4b 新加的三个字段必须存在 —— 缺了就说明采集器还是旧二进制
                check("C: pred 带规则通道字段(rule_weight/block_weight/rules_flagged)",
                      all({"rule_weight", "rule_block_weight", "rules_flagged"} <= set(p)
                          for p in preds_c),
                      f"keys={sorted(set(preds_c[0]) & {'rule_weight', 'rule_block_weight', 'rules_flagged'}) if preds_c else []}")

                hit_rows = [r for r in raws_c if r.get("rules")]
                check("C: 至少 1 条命中规则并落盘证据", len(hit_rows) >= 1,
                      f"{len(hit_rows)}/{len(raws_c)} 条带 rules，"
                      f"命中规则={sorted({h['rule'] for r in hit_rows for h in (r['rules'].get('hits') or [])})}")
                check("C: 命中记录的规则集指纹与策略**同源**",
                      all(r["rules"].get("rule_set_sha1_16") == rcfg.get("ruleset_sha1_16")
                          for r in hit_rows),
                      f"disk={sorted({r['rules'].get('rule_set_sha1_16') for r in hit_rows})} "
                      f"policy={rcfg.get('ruleset_sha1_16')}")
                # 证据被**采纳**（指纹匹配）⇒ pred.rule_weight 必须等于证据里的 weight。
                # 若不相等，说明 rule_evidence_honored 判成 false（通道被静默旁路）。
                ev_ok = all(
                    abs((r["pred"].get("rule_weight") or 0.0)
                        - float((r.get("rules") or {}).get("weight") or 0.0)) < 1e-9
                    for r in raws_c
                )
                check("C: 规则证据被策略采纳（pred.rule_weight == rules.weight）", ev_ok,
                      f"weights={[round(r['pred'].get('rule_weight', 0), 3) for r in raws_c]}")
                # 规则证据与阻断线的**一致性**（策略无关：现役里可能已经有 block 规则）。
                # 达阻断线必须 flagged；未达线必须不 flagged；指纹不符 ⇒ 整条通道不生效。
                # 写成"恒 false"是旧假设（那时 0 条 block 规则），策略一改就会误报。
                mw = float(rcfg.get("min_weight_to_block") or 1.0)
                pol_rules_sha = rcfg.get("ruleset_sha1_16") or ""

                def _want_flagged(r):
                    ev = r.get("rules") or {}
                    if (ev.get("rule_set_sha1_16") or "") != pol_rules_sha:
                        return False
                    return float(ev.get("block_weight") or 0.0) + 1e-9 >= mw

                mismatch = [(r["pred"].get("rules_flagged"), _want_flagged(r))
                            for r in raws_c
                            if bool(r["pred"].get("rules_flagged")) != _want_flagged(r)]
                check("C: rules_flagged 与规则集阻断线逐条一致"
                      f"（现役 block 规则 {rcfg.get('n_block_rules')} 条 / 阻断线 {mw}）",
                      not mismatch,
                      f"不一致={mismatch}" if mismatch else
                      f"flagged={sum(1 for r in raws_c if r['pred']['rules_flagged'])}/{len(raws_c)}")
                # **核心断言**：规则通道只允许让动作**变严**（allow→alert→block），
                # 绝不允许变松；而且每一次变严都必须有规则证据撑着 ——
                # "没有命中却默认开火"（min_weight_to_block=0 那类致命 bug）会在这里立刻暴露。
                def _key(r):
                    # 用 body 全文而不是 body_len 做键：SQLi 与 XSS 的 body 恰好都是
                    # 29 字节，只用长度会让两条请求撞键，比较就少了一条。
                    return (r.get("method"), r.get("path"), r.get("body") or "")
                b_act = {_key(r): r["pred"]["action"] for r in (raws_b or []) if "pred" in r}
                RANK = {"allow": 0, "alert": 1, "block": 2}
                problems = []
                for r in raws_c:
                    if "pred" not in r or not b_act:
                        continue
                    k = _key(r)
                    b = b_act.get(k)
                    if b is None:
                        continue
                    c = r["pred"]["action"]
                    ev = r.get("rules") or {}
                    if RANK.get(c, -1) < RANK.get(b, -1):
                        problems.append((k, b, c, "比双通道更松"))
                    elif c != b:
                        if RANK.get(c) == 1 and float(ev.get("weight") or 0.0) <= 0.0:
                            problems.append((k, b, c, "变成 alert 但没有任何规则命中"))
                        if RANK.get(c) == 2 and not r["pred"].get("rules_flagged"):
                            problems.append((k, b, c, "变成 block 但没有达阻断线的规则证据"))
                check("C: 融合动作只会因规则证据变严（绝不更松、绝不凭空开火）", not problems,
                      f"problems={problems}" if problems else
                      f"B={sorted(b_act.values())} C={sorted({r['pred']['action'] for r in raws_c})}")
                check("C: 判定不阻断（dry-run 全部 200）",
                      all(s.endswith("200 OK") for s in statuses_c),
                      f"{sorted(set(statuses_c))}")

    # =========================== 下游出处标注 ===========================
    print("\n[p8] ==== 下游标注（出处规则，不是内容正则） ====")
    ds_dir = os.path.join(tmp, "ds")
    raw_files = [os.path.join(raw_dir_a, f)
                 for f in sorted(os.listdir(raw_dir_a))] if os.path.isdir(raw_dir_a) else []
    cmd = [sys.executable, os.path.join(HERE, "collect_http_log.py"), "--format", "jsonl"]
    for p in raw_files:                          # --src 是 action="append"：必须重复传
        cmd += ["--src", p]
    cmd += ["--provenance", "auto", "--canary-prefix", CANARY,
            "--name", "proxy_e2e", "--out-dir", ds_dir,
            "--keep-body"]                       # 默认**不落 body**（隐私优先），训练才需要显式打开
    r = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    print(f"      [标注] 退出码 {r.returncode}")
    if r.stdout:
        print("      " + r.stdout.strip().replace("\n", "\n      "))

    atk_p = os.path.join(ds_dir, "proxy_e2e_attack.jsonl")
    ben_p = os.path.join(ds_dir, "proxy_e2e_benign.jsonl")

    def rows(p):
        if not os.path.exists(p):
            return []
        with open(p, "r", encoding="utf-8") as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    atk, ben = rows(atk_p), rows(ben_p)
    check("canary 路径 -> label=1（2 条）", len(atk) == 2, f"attack={len(atk)}")
    check("其余 -> label=0（5 条）", len(ben) == 5, f"benign={len(ben)}")
    why = {}
    for row in atk:
        w = row.get("label_why", "")
        why[w] = why.get(w, 0) + 1
    check("攻击标签来源 = 出处（canary 路径）",
          bool(why) and all("canary" in k for k in why), f"label_why={why}")
    check("标注输出保留攻击 body（需 `--keep-body`）",
          any("OR '1'='1" in (row.get("body") or "") for row in atk),
          "不加 --keep-body 下游按隐私默认清空 body")
    check("标注后仍保留流级字段",
          any("dur_ms" in row and "bytes_out" in row for row in atk + ben),
          "dur_ms/bytes_out 透传")
    check("**模型输出不可能变成标签**：标注后无 `pred` 键",
          all("pred" not in row for row in atk + ben),
          "parse_jsonl 只保留已知键 ⇒ pred 被结构性地挡在标签之外"
          if not args.no_score else "（阶段 B 跳过，不适用）")

    return finish(tmp, args, checks, {
        "n_raw": len(raws), "n_attack": len(atk), "n_benign": len(ben),
        "label_why": why, "pred_stats": pred_stats,
    })


def finish(tmp, args, checks, extra):
    failed = [c for c in checks if not c["ok"]]
    rep = {
        "what": "S4/工作项 F 采集数据面端到端验证（Pingora collector -> 原始 jsonl -> 出处标注 [+ dry-run 判定]）",
        "collector": "proxy/target/release/waf-collector.exe (pingora 0.9 + rustls)",
        "checks": checks,
        "n_pass": len(checks) - len(failed),
        "n_fail": len(failed),
        "verdict": "PASS" if not failed else "FAIL",
        **extra,
        "limitations": [
            "本验证只覆盖**采集、出处标注与 dry-run 判定留证**；判定按设计**不阻断**，",
            "上游是本地假的 echo 后端；真实业务的 body 分布需上线后采集",
            "攻击标签来自**蜜罐路径出处**，不是内容正则 —— 这正是可审计的前提",
            "`pred` 是拿**上线模型**（训练集带 body 记录 = 0 条）对真实流量算的诊断值，**不能当验收指标**；",
            "阈值必须在真实本地良性留出流量上重标定（python/thresholds.py --pool file:...）",
        ],
        "tmp_dir": tmp,
    }
    os.makedirs(ART, exist_ok=True)
    out = os.path.join(ART, "p8_proxy_e2e.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print(f"\n[p8] {'✅ PASS' if not failed else '❌ FAIL'}  "
          f"{len(checks)-len(failed)}/{len(checks)} 检查通过")
    print(f"[p8] -> {os.path.relpath(out, HERE)}")
    if not args.keep_tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print(f"[p8] 临时目录保留：{tmp}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
