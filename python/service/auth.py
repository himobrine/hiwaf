"""认证与 RBAC。

- 密码：PBKDF2-HMAC-SHA256（标准库，无额外依赖）
- 令牌：HS256 JWT（标准库实现；不引 PyJWT）
- 角色：viewer < analyst < admin

密钥：优先环境变量 `WAF_CONSOLE_SECRET`；否则首次启动生成 `service/.secret`。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time

from fastapi import Depends, Header, HTTPException

from . import config, db

PBKDF2_ITER = 120_000

#: 强密码策略（固定，不提供“放宽”开关）：
#:   * 12–128 位，不能含空白；
#:   * 必须同时包含大写、小写、数字、特殊字符；
#:   * 至少 8 个不同字符；不能包含用户名；不能是常见弱口令/连续序列。
PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128
PASSWORD_MIN_DISTINCT = 8
_WEAK_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "abc123", "admin", "admin123", "administrator",
    "letmein", "welcome", "welcome1", "iloveyou", "monkey", "dragon",
    "changeme", "root", "toor", "guest", "test", "test123", "waf", "waf123",
}
_SEQUENCES = (
    "0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "abcd", "bcde", "cdef", "qwer", "wert", "asdf", "sdfg", "zxcv", "xcvb",
    "!@#$", "@#$%", "#$%^",
)


def password_error(pw: str, username: str | None = None) -> str | None:
    """返回第一条不合规原因；None = 通过。前后端共用同一套规则（前端只做提示）。"""
    if not isinstance(pw, str):
        return "密码格式错误"
    if len(pw) < PASSWORD_MIN_LEN:
        return f"密码至少 {PASSWORD_MIN_LEN} 位"
    if len(pw) > PASSWORD_MAX_LEN:
        return f"密码最多 {PASSWORD_MAX_LEN} 位"
    if any(c.isspace() for c in pw):
        return "密码不能包含空格/制表符"
    low = pw.lower()
    if username and len(username) >= 3 and username.lower() in low:
        return "密码不能包含用户名"
    if low in _WEAK_PASSWORDS:
        return "密码太常见，请换一个"
    if len(set(pw)) < PASSWORD_MIN_DISTINCT:
        return f"密码至少要有 {PASSWORD_MIN_DISTINCT} 个不同字符"
    classes = (
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    )
    if not all(classes):
        return "密码必须同时包含大写字母、小写字母、数字和特殊字符"
    if re.search(r"(.)\1{3,}", pw):
        return "密码包含过长的重复字符"
    for seq in _SEQUENCES:
        if seq in low:
            return "密码包含连续/键盘序列"
    return None


def validate_password(pw: str, username: str | None = None) -> str:
    err = password_error(pw, username)
    if err:
        raise ValueError(err)
    return pw


# --------------------------------------------------------------------------- 密码
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITER)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITER,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        want = base64.b64decode(hash_b64)
        got = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(got, want)
    except Exception:
        return False


#: 用户不存在时也跑一次同等开销的 PBKDF2，避免用响应时间枚举用户名。
DUMMY_HASH = hash_password("waf-console-dummy-password")


# --------------------------------------------------------------------------- JWT
def _secret() -> bytes:
    env = os.environ.get("WAF_CONSOLE_SECRET")
    if env:
        return env.encode("utf-8")
    p = config.SECRET_PATH
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    s = secrets.token_bytes(48)
    p.write_bytes(s)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return s


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(username: str, role: str, ttl: int | None = None,
               token_version: int = 0, must_change: bool = False) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + (ttl if ttl is not None else config.TOKEN_TTL_SEC),
        "ver": int(token_version),
    }
    if must_change:
        # 密码不合规：该 token 只能访问 /api/auth/*（改密/登出/me），其余接口 403。
        payload["mc"] = True
    header = {"alg": "HS256", "typ": "JWT"}
    seg = [
        _b64e(json.dumps(header, separators=(",", ":")).encode()),
        _b64e(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(seg).encode("ascii")
    sig = hmac.new(_secret(), signing_input, hashlib.sha256).digest()
    return ".".join(seg + [_b64e(sig)])


def decode_token(token: str) -> dict:
    try:
        h64, p64, s64 = token.split(".")
        signing_input = f"{h64}.{p64}".encode("ascii")
        want = hmac.new(_secret(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(want, _b64d(s64)):
            raise ValueError("signature")
        header = json.loads(_b64d(h64))
        if header.get("alg") != "HS256":
            raise ValueError("alg")
        payload = json.loads(_b64d(p64))
    except Exception:
        raise HTTPException(status_code=401, detail="令牌无效")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="令牌已过期")
    return payload


# --------------------------------------------------------------------------- 依赖
def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="缺少 Bearer 令牌")
    payload = decode_token(authorization.split(" ", 1)[1].strip())
    u = db.one(
        "SELECT id, username, role, disabled, token_version "
        "FROM users WHERE username=?",
        (payload.get("sub"),),
    )
    if not u or u["disabled"]:
        raise HTTPException(status_code=401, detail="用户不存在或已禁用")
    if int(payload.get("ver", 0)) != int(u["token_version"] or 0):
        raise HTTPException(status_code=401, detail="令牌已失效，请重新登录")
    return {"id": u["id"], "username": u["username"], "role": u["role"],
            "must_change": bool(payload.get("mc"))}


def require_at_least(role: str):
    need = config.ROLE_RANK[role]

    def dep(user: dict = Depends(current_user)) -> dict:
        if config.ROLE_RANK.get(user["role"], 0) < need:
            raise HTTPException(status_code=403, detail=f"需要 {role} 及以上角色")
        return user

    return dep


# --------------------------------------------------------------------------- 引导
def ensure_admin() -> None:
    if db.scalar("SELECT COUNT(*) AS n FROM users", default=0):
        return
    pw = os.environ.get("WAF_CONSOLE_ADMIN_PASSWORD") or ""
    generated = False
    if not pw.strip():
        # 生成到满足强密码策略为止（token_urlsafe 偶尔缺某一类字符）。
        while True:
            cand = secrets.token_urlsafe(18)
            if password_error(cand) is None:
                pw = cand
                break
        generated = True
    else:
        err = password_error(pw)
        if err:
            print(f"[auth] 警告：WAF_CONSOLE_ADMIN_PASSWORD 不满足强密码策略（{err}）；"
                  "仍按该值创建，请登录后立即修改。")
    weak = password_error(pw) is not None
    db.execute(
        "INSERT INTO users(username, pw, role, disabled, pw_weak, created_at) "
        "VALUES(?,?,?,0,?,?)",
        ("admin", hash_password(pw), "admin", 1 if weak else 0, db.now_ms()),
    )
    print("[auth] 已创建 admin 账号")
    if generated:
        p = config.HERE / ".admin_password"
        p.write_text(pw, encoding="utf-8")
        print(f"[auth] 初始密码已写入 {p}")
        print(f"[auth] 初始密码：{pw}")
    print("[auth] 登录后请修改密码：POST /api/auth/password")
