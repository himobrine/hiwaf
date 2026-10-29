"""控制台用户管理（RBAC：viewer < analyst < admin）。

约束（安全兜底，全部在服务端执行，前端只做提示）：

  * 用户名 3–32 位：字母/数字/`_ . -`；密码 8–128 位；
  * **不能禁用/删除自己**，也不能改自己的角色（避免把自己锁在门外）；
  * 系统里**至少保留一个启用的 admin**：降级/禁用/删除最后一个启用 admin 一律拒绝；
  * 改密码 / 改角色 / 禁用会把 `token_version + 1`，该用户已签发的 token 立即失效；
  * 删除是硬删除；历史审计/事件里的 username 作为字符串保留，不受影响。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import auth, config, db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 8
MAX_PASSWORD = 128
_ROLES = ("viewer", "analyst", "admin")


def _now() -> int:
    return db.now_ms()


def _shape(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": int(row["id"]),
        "username": row["username"],
        "role": row["role"],
        "disabled": bool(row.get("disabled")),
        "created_at": int(row.get("created_at") or 0),
    }


def _get(uid: int) -> Dict[str, Any]:
    row = db.one("SELECT * FROM users WHERE id=?", (uid,))
    if not row:
        raise ValueError(f"用户不存在：{uid}")
    return dict(row)


def _validate_username(username: str) -> str:
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise ValueError("用户名需为 3–32 位字母/数字/下划线/点/短横线")
    return username


def _validate_password(password: str) -> str:
    password = password or ""
    if not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
        raise ValueError(f"密码长度需在 {MIN_PASSWORD}–{MAX_PASSWORD} 之间")
    if password.strip() != password:
        raise ValueError("密码首尾不能有空白字符")
    return password


def _enabled_admins(exclude_id: Optional[int] = None) -> int:
    sql = "SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0"
    params: List[Any] = []
    if exclude_id is not None:
        sql += " AND id<>?"
        params.append(int(exclude_id))
    return int(db.scalar(sql, params, 0) or 0)


def _bump(uid: int) -> None:
    db.execute("UPDATE users SET token_version=token_version+1 WHERE id=?", (uid,))


def list_users() -> List[Dict[str, Any]]:
    return [_shape(r) for r in db.rows(
        "SELECT id, username, role, disabled, created_at FROM users ORDER BY id")]


def create_user(username: str, password: str, role: str) -> Dict[str, Any]:
    username = _validate_username(username)
    password = _validate_password(password)
    role = (role or "").strip()
    if role not in _ROLES:
        raise ValueError(f"role 只支持 {list(_ROLES)}")
    if db.one("SELECT 1 AS x FROM users WHERE username=?", (username,)):
        raise ValueError(f"用户名已存在：{username}")
    uid = db.execute(
        "INSERT INTO users(username, pw, role, disabled, token_version, created_at) "
        "VALUES(?,?,?,0,0,?)",
        (username, auth.hash_password(password), role, _now()))
    return _shape(_get(uid))


def update_user(uid: int, *, actor_id: int,
                role: Optional[str] = None,
                disabled: Optional[bool] = None) -> Dict[str, Any]:
    row = _get(uid)
    role = (role or "").strip() if role is not None else None
    if role is not None and role not in _ROLES:
        raise ValueError(f"role 只支持 {list(_ROLES)}")
    changing_role = role is not None and role != row["role"]
    changing_disabled = (disabled is not None
                         and bool(disabled) != bool(row["disabled"]))
    if not changing_role and not changing_disabled:
        return _shape(row)

    if int(uid) == int(actor_id):
        if changing_role:
            raise ValueError("不能修改自己的角色（避免把自己锁在门外）")
        if changing_disabled and bool(disabled):
            raise ValueError("不能禁用自己")

    if changing_role and row["role"] == "admin" and role != "admin" \
            and not bool(row["disabled"]):
        if _enabled_admins(exclude_id=uid) < 1:
            raise ValueError("至少要保留一个启用的 admin")
    if changing_disabled and bool(disabled) and row["role"] == "admin" \
            and not bool(row["disabled"]):
        if _enabled_admins(exclude_id=uid) < 1:
            raise ValueError("至少要保留一个启用的 admin")

    sets, params = [], []
    if changing_role:
        sets.append("role=?")
        params.append(role)
    if changing_disabled:
        sets.append("disabled=?")
        params.append(1 if disabled else 0)
    params.append(uid)
    db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", params)
    # 角色/状态变了：旧 token 立即失效（角色本来就每请求从 DB 读，双保险）。
    _bump(uid)
    return _shape(_get(uid))


def reset_password(uid: int, password: str) -> Dict[str, Any]:
    _get(uid)
    password = _validate_password(password)
    db.execute("UPDATE users SET pw=? WHERE id=?",
               (auth.hash_password(password), uid))
    _bump(uid)
    return _shape(_get(uid))


def delete_user(uid: int, *, actor_id: int) -> Dict[str, Any]:
    row = _get(uid)
    if int(uid) == int(actor_id):
        raise ValueError("不能删除自己")
    if row["role"] == "admin" and not bool(row["disabled"]):
        if _enabled_admins(exclude_id=uid) < 1:
            raise ValueError("至少要保留一个启用的 admin")
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    return _shape(row)