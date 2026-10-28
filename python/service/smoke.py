"""控制面 API 冒烟自检（服务需已启动）。

用法：
    py -3.10 -m service.smoke
    set WAF_CONSOLE_ADMIN_PASSWORD=...   # 或用 service/.admin_password
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("WAF_CONSOLE_BASE", "http://127.0.0.1:8090")


def call(method: str, path: str, body=None, token: str | None = None, timeout: float = 60.0):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}
    except Exception as e:  # 连接失败
        return 0, {"error": str(e)}


def main() -> int:
    checks = []

    def ck(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    pw = os.environ.get("WAF_CONSOLE_ADMIN_PASSWORD")
    if not pw:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".admin_password")
        if os.path.exists(p):
            pw = open(p, encoding="utf-8").read().strip()
    if not pw:
        print("没有 admin 密码：设置 WAF_CONSOLE_ADMIN_PASSWORD，或先启动一次服务生成 .admin_password")
        return 2

    # 等服务起来
    token = None
    for _ in range(40):
        st, r = call("POST", "/api/auth/login", {"username": "admin", "password": pw})
        if st == 200:
            token = r["token"]
            break
        time.sleep(0.5)
    if not token:
        print(f"登录失败：{st} {r}")
        return 1
    ck("登录", True, "admin")

    st, me = call("GET", "/api/auth/me", token=token)
    ck("GET /api/auth/me", st == 200 and me.get("role") == "admin", f"{st} {me}")

    st, ov = call("GET", "/api/overview/summary?window_hours=168", token=token)
    ck("总览", st == 200 and "totals" in ov,
       f"{st} events={((ov.get('totals') or {}).get('n'))} mode={ov.get('mode')}")

    sites = ov.get("sites") or {}
    ck("总览·站点→模型", st == 200 and isinstance(sites.get("items"), list)
       and bool(sites.get("live")) and "total_hosts" in sites,
       f"{st} hosts={sites.get('total_hosts')} "
       f"live=v{(sites.get('live') or {}).get('policy_version')}")

    st, ev = call("GET", "/api/events?limit=5", token=token)
    ck("事件列表", st == 200 and "items" in ev, f"{st} total={ev.get('total')}")

    st, pol = call("GET", "/api/policy", token=token)
    ck("策略", st == 200 and bool(pol.get("policy")),
       f"v={(pol.get('policy') or {}).get('version')} zd={(pol.get('policy') or {}).get('zero_day_enabled')}")

    st, al = call("GET", "/api/alerts?window_hours=168", token=token)
    ck("告警聚合", st == 200 and "items" in al, f"{st} n={len(al.get('items') or [])}")

    if al.get("items"):
        a0 = al["items"][0]
        qs = urllib.parse.urlencode({
            "src_ip": a0.get("src_ip") or "",
            "action": a0.get("action") or "",
            "bucket": int(a0.get("bucket") or 0),
            "bucket_min": 10,
            "method": a0.get("method") or "",
            "path": a0.get("path") or "",
            "limit": 5,
        })
        st, ae = call("GET", f"/api/alerts/events?{qs}", token=token)
        ck("聚合下钻", st == 200 and "items" in ae,
           f"{st} total={ae.get('total')} n={len(ae.get('items') or [])}")
    else:
        ck("聚合下钻（无告警数据，跳过）", True, "no items")

    st, ru = call("GET", "/api/rules", token=token)
    ck("规则", st == 200 and "rules" in ru, f"{st} n={len(ru.get('rules') or [])}")

    st, mo = call("GET", "/api/models", token=token)
    ck("模型", st == 200 and "artifacts" in mo,
       f"{st} onnx={len(mo.get('artifacts') or [])} curves={len(mo.get('curves') or [])} "
       f"registry={len(mo.get('models') or [])}")

    # 代际树必须是前端拿来就能画的树：节点数与 n 一致、根/现役路径都落在树上。
    chans = (mo.get("lineage") or {}).get("channels") or {}

    def _walk(nodes):
        ids = []
        for node in nodes or []:
            ids.append(node.get("id"))
            ids += _walk(node.get("children"))
        return ids

    lin_ok, lin_detail = True, []
    for ch in ("supervised", "zero_day"):
        p = chans.get(ch) or {}
        ids = _walk(p.get("tree"))
        n = p.get("n")
        path = p.get("path_to_current") or []
        ok = (isinstance(n, int) and len(ids) == n == len(set(ids))
              and (n == 0 or bool(p.get("roots")))
              and set(path) <= set(ids)
              and (p.get("current_id") is None or p.get("current_id") in ids))
        lin_ok = lin_ok and ok
        lin_detail.append(f"{ch} n={n} roots={len(p.get('roots') or [])} "
                          f"orphans={len(p.get('orphans') or [])} path={len(path)}")
    ck("模型代际树", st == 200 and lin_ok, f"{st} " + " · ".join(lin_detail))

    st, cur = call("GET", "/api/models/current", token=token)
    ck("当前模型", st == 200 and "channels" in cur,
       f"{st} sup={((cur.get('channels') or {}).get('supervised') or {}).get('state')} "
       f"zd={((cur.get('channels') or {}).get('zero_day') or {}).get('state')}")

    st, se = call("GET", "/api/models/settings", token=token)
    ck("模型保留设置", st == 200 and "settings" in se,
       f"{st} {se.get('settings')}")

    st, sw = call("GET", "/api/models/switches", token=token)
    ck("切换记录", st == 200 and "items" in sw, f"{st} n={len(sw.get('items') or [])}")

    st, up = call("GET", "/api/uploads?limit=20", token=token)
    ck("训练数据列表", st == 200 and "items" in up, f"{st} n={len(up.get('items') or [])}")

    st, cs = call("GET", "/api/collector/status", token=token)
    ck("采集面状态（可缺指标文件）", st == 200, f"{st} available={cs.get('available')}")

    st, au = call("GET", "/api/audit", token=token)
    ck("审计", st == 200 and "items" in au, f"{st} n={len(au.get('items') or [])}")

    st, ar = call("GET", "/api/audit/retention?days=90", token=token)
    ck("审计保留预览", st == 200 and "delete_count" in ar,
       f"{st} del={ar.get('delete_count')} keep={ar.get('keep_count')}")

    st, tg = call("GET", "/api/tasks", token=token)
    ck("任务列表", st == 200 and "items" in tg, f"{st} n={len(tg.get('items') or [])}")

    st, dg = call("GET", "/api/health/degradation", token=token)
    ck("降级状态", st == 200 and "zero_day_enabled" in dg, f"{st} mode={dg.get('mode')}")

    bad = len([c for c in checks if not c])
    print(f"\n{'PASS' if not bad else 'FAIL'}  {len(checks)-bad}/{len(checks)}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
