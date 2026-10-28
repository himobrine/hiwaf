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
import secrets
import time

from fastapi import Depends, Header, HTTPException

from . import config, db

PBKDF2_ITER = 120_000


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


def make_token(username: str, role: str, ttl: int | None = None) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + (ttl if ttl is not None else config.TOKEN_TTL_SEC),
    }
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
    u = db.one("SELECT id, username, role, disabled FROM users WHERE username=?", (payload.get("sub"),))
    if not u or u["disabled"]:
        raise HTTPException(status_code=401, detail="用户不存在或已禁用")
    return {"id": u["id"], "username": u["username"], "role": u["role"]}


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
    pw = os.environ.get("WAF_CONSOLE_ADMIN_PASSWORD")
    generated = False
    if not pw:
        pw = secrets.token_urlsafe(12)
        generated = True
    db.execute(
        "INSERT INTO users(username, pw, role, disabled, created_at) VALUES(?,?,?,0,?)",
        ("admin", hash_password(pw), "admin", db.now_ms()),
    )
    print("[auth] 已创建 admin 账号")
    if generated:
        p = config.HERE / ".admin_password"
        p.write_text(pw, encoding="utf-8")
        print(f"[auth] 初始密码已写入 {p}")
        print(f"[auth] 初始密码：{pw}")
    print("[auth] 登录后请修改密码：POST /api/auth/password")
