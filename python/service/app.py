"""WAF 控制台控制面 API。

设计约束（与项目已冻结的决策一致）：
  * 阈值**不允许**在界面上自由编辑：只能「选标定池 → 预览 → 提升」，计算仍由
    `thresholds.py` 完成（唯一事实来源 = `artifacts/decision_policy.json`）。
  * `pred`（模型输出）与 `feedback`（人工反馈）分开存；反馈**不会**覆盖 `pred`，
    也不会自动变成训练标签。
  * body 默认不入库；查看 body 需要 analyst/admin，且每次查看写审计。
  * 任务只接受白名单内的脚本（`config.TASKS`），不接受任意命令。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import (Depends, FastAPI, File, Form, HTTPException, Query, Request,
                     Response, UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import (alerts as alerts_mod, audit_retention, audit_retention_scheduler,
               auth, config, correlate, datasets_events, db,
               ingest as ingest_mod, ingest_scheduler, ip_lists as ip_lists_mod, login_guard,
               model_registry, model_switch,
               packet as packet_mod, proxy_manager, retention, retention_scheduler,
               rule_spans, rules as rules_mod, rules_dsl, sites as sites_mod,
               suppression, uploads, users as users_mod)

# --------------------------------------------------------------------------- 应用
@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init()
    auth.ensure_admin()
    _seed_policy_version()
    # 首次启动：把磁盘上的现役模型登记进代际表（幂等），并套用保留策略。
    try:
        model_registry.ensure_dirs()
        if not db.one("SELECT id FROM model_registry LIMIT 1"):
            model_registry.register_live("bootstrap")
        model_registry.prune(actor="system")
    except Exception:  # noqa: BLE001 - 登记失败不能挡住控制台启动
        pass
    # 持续增量入库：采集器写入后最多一个周期即可在事件/告警页看到。
    # 上传数据：建目录；把上次进程留下的 converting 行标失败（幂等）。
    try:
        uploads.ensure_dirs()
        uploads.cleanup_stale()
    except Exception:  # noqa: BLE001 - 不影响控制台启动
        pass
    # IP 黑白名单：清过期 + 写热重载产物 + 起自动拉黑线程。
    try:
        ip_lists_mod.cleanup_expired()
        ip_lists_mod.write_artifact()
        ip_lists_mod.scheduler_start()
    except Exception:  # noqa: BLE001 - 不影响控制台启动
        pass
    ingest_scheduler.start()
    # 误报监控（只在有真实命中 + 人工标签时才可能触发；默认 60s 一轮）。
    from . import rule_monitor
    rule_monitor.start()
    # 保留期每日 dry-run：只生成快照/审计，绝不自动删除；apply 仍要 admin 显式确认。
    retention_scheduler.start()
    # 审计日志默认保留 90 天：系统每日自动清理；admin 也可在审计页手动预览/清理。
    audit_retention_scheduler.start()
    # 线程内连接复用：每条新连接的第一条语句本机约 23 ms（见 db.py）。
    # 放在 init() 之后、开始接请求之前；测试不启动 app，因此不受影响。
    db.enable_pool()
    yield
    db.close_thread_connection()


app = FastAPI(title="WAF 控制台 API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def force_password_change(request: Request, call_next):
    """密码不合规（登录时判定，token 带 `mc`）时，只放行 /api/auth/*。

    真正的改密校验在后端；这里保证“不改密码就什么都干不了”，而不是只在
    前端弹个可以关掉的提示。token 解码失败交给路由返回 401。
    """
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/"):
        h = request.headers.get("authorization") or ""
        if h.lower().startswith("bearer "):
            try:
                payload = auth.decode_token(h.split(" ", 1)[1].strip())
            except Exception:  # noqa: BLE001
                payload = None
            if isinstance(payload, dict) and payload.get("mc"):
                return JSONResponse(
                    {"detail": "当前密码不符合强密码策略，请先修改密码"}, status_code=403)
    return await call_next(request)


# --------------------------------------------------------------------------- 工具
def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def audit(actor: str, action: str, target: Optional[str] = None,
          detail: Optional[str] = None, ip: Optional[str] = None) -> None:
    db.execute(
        "INSERT INTO audit(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)",
        (db.now_ms(), actor, action, target, detail, ip),
    )


def _read_json(path: Path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _policy() -> dict:
    return _read_json(config.POLICY_JSON, {}) or {}


def _seed_policy_version() -> None:
    pol = _policy()
    if not pol:
        return
    db.execute(
        "INSERT OR REPLACE INTO policy_versions(version, json, actor, created_at, note) VALUES(?,?,?,?,?)",
        (int(pol.get("version") or 1), json.dumps(pol, ensure_ascii=False),
         "bootstrap", db.now_ms(), "启动时导入现役策略"),
    )


def _sha1_16(p: Path) -> str:
    h = hashlib.sha1()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _sha1_16_file(p) -> Optional[str]:
    try:
        import hashlib
        h = hashlib.sha1()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return None


def _reload_view(pol: dict, metrics: Optional[dict]) -> dict:
    """把「磁盘上的策略/规则集」与「采集器实际在用的」对照起来。

    两侧指纹不同 = 改动**没生效**。这是最容易被忽略的状态：控制台里显示新规则，
    数据面还在按旧规则跑 —— 而且两边都不报错。热重载失败也会在这里露出来。
    """
    if not metrics:
        return {"available": False, "reason": "无采集器指标文件"}
    r = metrics.get("reload")
    if not r:
        return {"available": False,
                "reason": "采集器未上报 reload（用了 --no-reload 或老版本二进制）：改策略/规则后必须重启"}
    disk_pol = _sha1_16_file(config.POLICY_JSON)
    disk_rules = _sha1_16_file(config.RULES_AUTHORITATIVE)
    pol_rev = int(pol.get("version") or 0)
    seen_pol = r.get("policy_sha1_16")
    seen_rules = r.get("rules_sha1_16")
    active_rules = r.get("rules_active_sha1_16")
    return {
        "available": True,
        "interval_sec": r.get("interval_sec"),
        "policy_disk_sha1_16": disk_pol,
        "policy_seen_sha1_16": seen_pol,
        "policy_active_revision": r.get("policy_active_revision"),
        "policy_revision": pol_rev,
        "rules_disk_sha1_16": disk_rules,
        "rules_seen_sha1_16": seen_rules,
        "rules_active_sha1_16": active_rules,
        "rules_active_n": r.get("rules_active_n"),
        "last_ok_ts": r.get("last_ok_ts"),
        "last_err_ts": r.get("last_err_ts"),
        "last_err": r.get("last_err"),
        # 磁盘 > 采集器「已看见」= 还没轮询到
        "policy_drift": bool(disk_pol and seen_pol and disk_pol != seen_pol),
        "rules_drift": bool(disk_rules and seen_rules and disk_rules != seen_rules),
        # 磁盘 > 采集器「在用」= 轮询过但没换成（校验失败/指纹不符）—— 这个才是真问题
        "rules_effective_drift": bool(disk_rules and active_rules and disk_rules != active_rules),
    }


def _collector_metrics() -> Optional[dict]:
    """采集器 `--stats-out` 指标（兼容旧调用；实现统一在 proxy_manager）。"""
    return proxy_manager.metrics()


# --------------------------------------------------------------------------- 入参模型
class LoginIn(BaseModel):
    username: str
    password: str


class PasswordIn(BaseModel):
    old: str
    # 长度/复杂度由 auth.validate_password 统一校验（返回可读的 400）。
    new: str = Field(min_length=1, max_length=128)


class UserCreateIn(BaseModel):
    """管理员新建用户（用户名/密码策略在 service/users.py 里统一校验）。"""
    model_config = {"extra": "forbid"}

    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)
    role: str = "analyst"


class UserPatchIn(BaseModel):
    model_config = {"extra": "forbid"}

    role: Optional[str] = None
    disabled: Optional[bool] = None


class UserPasswordIn(BaseModel):
    model_config = {"extra": "forbid"}

    password: str = Field(min_length=1, max_length=128)


class IpListIn(BaseModel):
    model_config = {"extra": "forbid"}

    ip: str
    kind: str = "black"
    reason: Optional[str] = None
    note: Optional[str] = None
    expires_at: Optional[int] = None


class IpListPatchIn(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: Optional[bool] = None
    reason: Optional[str] = None
    note: Optional[str] = None
    expires_at: Optional[int] = None


class IpListImportIn(BaseModel):
    model_config = {"extra": "forbid"}

    kind: str = "black"
    text: str


class IpListBulkDeleteIn(BaseModel):
    model_config = {"extra": "forbid"}

    ids: List[int] = Field(min_length=1, max_length=5000)


class IpAutoSettingsIn(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: Optional[bool] = None
    threshold: Optional[int] = None
    window_min: Optional[int] = None
    duration_hours: Optional[int] = None
    count_rule_alerts: Optional[bool] = None


class FeedbackIn(BaseModel):
    event_id: int
    verdict: str
    note: Optional[str] = None


class PreviewIn(BaseModel):
    pool: str = "csic"
    fpr: str = "0.01"
    zero_day: str = "off"


class PromoteIn(PreviewIn):
    note: Optional[str] = None


class ZeroDayIn(BaseModel):
    enabled: bool
    note: Optional[str] = None


class AckIn(BaseModel):
    group_key: str
    status: str = "ack"
    assignee: Optional[str] = None


class SuppressionIn(BaseModel):
    """实体级抑制草案；至少一个实体字段非空，多个字段是 AND。"""
    src_ip: Optional[str] = None
    path: Optional[str] = None
    ua: Optional[str] = None
    host: Optional[str] = None
    attack_type: Optional[str] = None
    reason: str
    ttl_hours: Optional[int] = None
    note: Optional[str] = None


class SuppressionDecisionIn(BaseModel):
    note: Optional[str] = None


class SuppressionSuggestIn(BaseModel):
    days: Optional[int] = None
    min_count: Optional[int] = None
    ttl_hours: Optional[int] = None
    limit: int = 50


class RulePatch(BaseModel):
    enabled: Optional[bool] = None
    action: Optional[str] = None
    kind: Optional[str] = None


class RuleBulkIn(BaseModel):
    """批量启停挖出的候选。`only_unproven=True` 只动 `verdict != keep` 那批。"""
    enabled: bool = True
    only_unproven: bool = False


class CustomBulkIn(BaseModel):
    """批量启停自撰/导入规则（启用只要求 ① 编译）。"""
    enabled: bool = True
    only_uncompiled: bool = False


class RuleBulkOpIn(BaseModel):
    """按选中 ID 批量处理规则。"""
    scope: str
    ids: List[str]
    op: str
    action: Optional[str] = None


class IncidentBulkIn(BaseModel):
    """按选中 ID 批量处理误报/熔断事件。"""
    ids: List[int]
    op: str = "ack"
    note: Optional[str] = None
    restore: bool = False


class BreakerBulkRestoreIn(BaseModel):
    rules: List[str]
    note: Optional[str] = None


class RuleIn(BaseModel):
    id: Optional[str] = None
    name: str
    regex: str
    scopes: Optional[List[str]] = None
    severity: Optional[str] = "medium"
    weight: Optional[float] = 1.0
    action: Optional[str] = "alert"
    kind: Optional[str] = "detector"
    notes: Optional[str] = None


class RuleEditIn(BaseModel):
    name: Optional[str] = None
    regex: Optional[str] = None
    scopes: Optional[List[str]] = None
    severity: Optional[str] = None
    weight: Optional[float] = None
    action: Optional[str] = None
    kind: Optional[str] = None
    notes: Optional[str] = None


class QualifyIn(BaseModel):
    note: Optional[str] = None
    force: bool = False
    source: Optional[str] = None


class BreakerIn(BaseModel):
    scope: str = "rule"          # rule | all_block | channel
    rule: Optional[str] = None
    reason: str = "manual"
    note: Optional[str] = None


class BreakerRestoreIn(BaseModel):
    rule: Optional[str] = None
    all: bool = False
    channel_on: bool = False
    note: Optional[str] = None


class IncidentActionIn(BaseModel):
    note: Optional[str] = None
    restore: bool = False


class RuleMonitorSettingsIn(BaseModel):
    """规则监控开关（下一轮扫描生效，不用重启）。"""
    model_config = {"extra": "forbid"}

    auto_breaker: Optional[bool] = None
    breaker_alerts: Optional[bool] = None


class HistoryReplayIn(BaseModel):
    """历史告警回放：窗口天数 / 最多回放条数（都有服务端硬上限）。"""
    model_config = {"extra": "forbid"}

    days: Optional[int] = None
    max_events: Optional[int] = None


class RulesPromoteIn(BaseModel):
    min_weight_to_block: Optional[float] = None
    decode: Optional[List[str]] = None
    ruleset_id: Optional[str] = None
    rule_budget_cap: Optional[float] = None
    note: Optional[str] = None


class TaskIn(BaseModel):
    kind: str
    #: 训练任务专用：inherit = off | lineage | warm_start；parent_model_id 指定父代。
    inherit: Optional[str] = None
    parent_model_id: Optional[int] = None
    #: 数据集（仅训练任务）：data_mode = official | add | only。
    data_mode: Optional[str] = None
    dataset_ids: Optional[List[int]] = None
    calib_mode: Optional[str] = None
    calib_dataset_id: Optional[int] = None


class EventSelectionFilters(BaseModel):
    """事件选择的筛选条件（与 /api/events 同语义 + 两个选择专用项）。

    `attack_type` 只是**按模型分类筛事件**，不是标签；`verdict` 按人工 feedback
    结论的存在性筛。真正写进数据的 `label` 在 FromEventsIn / SelectionPreviewIn 上。
    """
    action: Optional[str] = None
    src_ip: Optional[str] = None
    path: Optional[str] = None
    q: Optional[str] = None
    min_score: Optional[float] = None
    from_ts: Optional[int] = None
    to_ts: Optional[int] = None
    rule_testing: Optional[bool] = None
    attack_type: Optional[str] = None
    verdict: Optional[str] = None


class SelectionPreviewIn(BaseModel):
    mode: str = "ids"                       # ids | filter
    event_ids: Optional[List[int]] = None
    filters: Optional[EventSelectionFilters] = None
    max_rows: Optional[int] = None


class FromEventsIn(SelectionPreviewIn):
    """从事件建数据集：标签**必须**由调用方显式给出（红线：模型预测不是标签）。"""
    name: str = ""
    role: str = "supervised"
    label: int = Field(..., ge=0, le=4)
    source_note: str = ""


class ModelPatchIn(BaseModel):
    display_name: Optional[str] = None
    notes: Optional[str] = None


class ModelSettingsIn(BaseModel):
    max_per_channel: Optional[int] = None
    max_total: Optional[int] = None
    inherit_mode: Optional[str] = None
    auto_register: Optional[bool] = None
    keep_curves: Optional[bool] = None


class ModelPruneIn(BaseModel):
    dry_run: bool = True


class ModelSwitchIn(BaseModel):
    #: 允许前端在并发提示时强制（当前仅做提示，真正并发由预检拦截）。
    confirm: bool = False


class IngestIn(BaseModel):
    with_body: bool = False


class RawCleanupIn(BaseModel):
    confirm: bool = False
    days: Optional[int] = None
    note: Optional[str] = None


class RawCleanupResolveIn(BaseModel):
    path: str
    action: str
    confirm: bool = False
    note: Optional[str] = None


class AuditRetentionIn(BaseModel):
    days: int = Field(90, ge=1, le=3650)
    confirm: bool = False


class AuditDeleteIn(BaseModel):
    ids: List[int] = Field(..., min_length=1, max_length=500)
    confirm: bool = False
    reason: Optional[str] = Field(None, max_length=500)


FPR_CHOICES = {"0.001", "0.01", "0.03"}
# `confirmed_benign` 是 v2 新增的**请求级**人工标签：模型 allow 但确认是正常业务。
# 旧四个 verdict 是模型视角；判定规则证据时统一映射：
#   attack = confirmed_attack | missed
#   benign = confirmed_benign | false_positive
VERDICTS = {"false_positive", "missed", "confirmed_attack", "confirmed_benign", "uncertain"}


def _check_policy_args(body: PreviewIn) -> str:
    pool = body.pool
    if pool in ("csic", "lexical"):
        return pool
    if pool.startswith("file:"):
        raw = pool[len("file:"):]
        p = Path(raw)
        if not p.is_absolute():
            p = (config.PY / raw).resolve()
        try:
            p.relative_to(config.ROOT.resolve())
        except ValueError:
            raise HTTPException(400, "校准池路径必须在仓库目录内")
        if not p.exists():
            raise HTTPException(400, f"校准池文件不存在：{p}")
        return "file:" + str(p)
    raise HTTPException(400, "pool 只支持 csic / lexical / file:PATH")
    # unreachable


def _run_thresholds(pool: str, fpr: str, zero_day: str,
                    out: Optional[str] = None, timeout: int = 900):
    if fpr not in FPR_CHOICES:
        raise HTTPException(400, f"fpr 只支持 {sorted(FPR_CHOICES)}")
    if zero_day not in ("on", "off"):
        raise HTTPException(400, "zero_day 只支持 on/off")
    cmd = [sys.executable, str(config.PY / "thresholds.py"),
           "--pool", pool, "--fpr", fpr, "--zero-day", zero_day]
    if out:
        cmd += ["--out", out, "--no-testvec"]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        cmd, cwd=str(config.PY), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, env=env,
    )


def _pool_from_source(source: str) -> str:
    if source.startswith("file:"):
        return _check_policy_args(PreviewIn(pool=source))
    if "csic" in source:
        return "csic"
    if "lexical" in source:
        return "lexical"
    return "csic"


# --------------------------------------------------------------------------- 认证
@app.post("/api/auth/login")
def login(body: LoginIn, request: Request):
    wait = login_guard.check(body.username)
    if wait:
        audit(body.username, "login_blocked", ip=_ip(request),
              detail=f"retry_after={wait}s")
        raise HTTPException(429, f"登录失败次数过多，请 {wait} 秒后再试",
                            headers={"Retry-After": str(wait)})

    u = db.one("SELECT * FROM users WHERE username=?", (body.username,))
    # 用户不存在时也跑一次等开销的 PBKDF2，避免用响应时间枚举用户名。
    if u is None:
        auth.verify_password(body.password, auth.DUMMY_HASH)
        pw_ok = False
    else:
        pw_ok = auth.verify_password(body.password, u["pw"])
    if u is None or u["disabled"] or not pw_ok:
        wait = login_guard.fail(body.username)
        audit(body.username, "login_failed", ip=_ip(request),
              detail=f"locked={wait}s" if wait else None)
        if wait:
            raise HTTPException(429, f"登录失败次数过多，请 {wait} 秒后再试",
                                headers={"Retry-After": str(wait)})
        raise HTTPException(401, "用户名或密码错误")
    login_guard.reset(body.username)
    # 登录时按明文现算一次强密码策略：老账号也会被识别出来并强制先改密。
    weak = auth.password_error(body.password, u["username"]) is not None
    if bool(u.get("pw_weak")) != weak:
        db.execute("UPDATE users SET pw_weak=? WHERE id=?",
                   (1 if weak else 0, u["id"]))
    token = auth.make_token(u["username"], u["role"],
                            token_version=u["token_version"],
                            must_change=weak)
    audit(u["username"], "login", ip=_ip(request))
    return {"token": token,
            "user": {"username": u["username"], "role": u["role"]},
            "must_change_password": weak}


@app.get("/api/auth/me")
def me(user: dict = Depends(auth.current_user)):
    return user


@app.post("/api/auth/logout")
def logout(request: Request, user: dict = Depends(auth.current_user)):
    # 令牌版本 +1：该用户已签发的 token 全部立即失效（单操作员控制台可接受）。
    db.execute("UPDATE users SET token_version=token_version+1 WHERE id=?",
               (user["id"],))
    audit(user["username"], "logout", ip=_ip(request))
    return {"ok": True}


@app.post("/api/auth/password")
def change_password(body: PasswordIn, request: Request,
                    user: dict = Depends(auth.current_user)):
    u = db.one("SELECT pw FROM users WHERE username=?", (user["username"],))
    if not u or not auth.verify_password(body.old, u["pw"]):
        raise HTTPException(400, "原密码错误")
    if body.new == body.old:
        raise HTTPException(400, "新密码不能与原密码相同")
    try:
        auth.validate_password(body.new, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.execute(
        "UPDATE users SET pw=?, pw_weak=0, token_version=token_version+1 "
        "WHERE username=?",
        (auth.hash_password(body.new), user["username"]),
    )
    audit(user["username"], "change_password", ip=_ip(request))
    # 旧 token 立即失效；前端需重新登录。
    return {"ok": True, "relogin": True}


# ---- 用户管理（仅 admin） ---------------------------------------------------
@app.get("/api/users")
def user_list(user: dict = Depends(auth.require_at_least("admin"))):
    return {"items": users_mod.list_users()}


@app.post("/api/users")
def user_create(body: UserCreateIn, request: Request,
                user: dict = Depends(auth.require_at_least("admin"))):
    try:
        row = users_mod.create_user(body.username, body.password, body.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "user_create", f"user:{row['id']}",
          json.dumps({"username": row["username"], "role": row["role"]},
                     ensure_ascii=False), _ip(request))
    return {"user": row}


@app.patch("/api/users/{uid}")
def user_update(uid: int, body: UserPatchIn, request: Request,
                user: dict = Depends(auth.require_at_least("admin"))):
    try:
        row = users_mod.update_user(uid, actor_id=int(user["id"]),
                                    role=body.role, disabled=body.disabled)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "user_update", f"user:{uid}",
          json.dumps({"role": row["role"], "disabled": row["disabled"]},
                     ensure_ascii=False), _ip(request))
    return {"user": row}


@app.post("/api/users/{uid}/password")
def user_reset_password(uid: int, body: UserPasswordIn, request: Request,
                        user: dict = Depends(auth.require_at_least("admin"))):
    try:
        row = users_mod.reset_password(uid, body.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    # 审计只记事件，不记密码。
    audit(user["username"], "user_password_reset", f"user:{uid}",
          json.dumps({"username": row["username"]}, ensure_ascii=False), _ip(request))
    return {"user": row,
            "note": "该用户已签发的 token 已失效，需要重新登录。"}


@app.delete("/api/users/{uid}")
def user_delete(uid: int, request: Request,
                user: dict = Depends(auth.require_at_least("admin"))):
    try:
        row = users_mod.delete_user(uid, actor_id=int(user["id"]))
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "user_delete", f"user:{uid}",
          json.dumps({"username": row["username"], "role": row["role"]},
                     ensure_ascii=False), _ip(request))
    return {"ok": True, "user": row}


# ---- IP 黑白名单 -----------------------------------------------------------
@app.get("/api/ip-lists")
def ip_list_list(kind: Optional[str] = None, q: Optional[str] = None,
                 limit: int = Query(500, ge=1, le=5000),
                 user: dict = Depends(auth.current_user)):
    try:
        items = ip_lists_mod.list_items(kind=kind, q=q, limit=limit)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"items": items, "counts": ip_lists_mod.counts(),
            "artifact": ip_lists_mod.artifact_state(),
            "settings": ip_lists_mod.auto_settings()}


@app.post("/api/ip-lists")
def ip_list_add(body: IpListIn, request: Request,
                user: dict = Depends(auth.require_at_least("analyst"))):
    try:
        row = ip_lists_mod.add(body.ip, body.kind, reason=body.reason or "",
                               note=body.note or "", expires_at=body.expires_at,
                               actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "ip_list_add", f"ip:{row['ip']}",
          json.dumps({"kind": row["kind"], "source": row["source"],
                      "reason": row["reason"], "expires_at": row["expires_at"]},
                     ensure_ascii=False), _ip(request))
    return {"item": row}


@app.patch("/api/ip-lists/{uid}")
def ip_list_update(uid: int, body: IpListPatchIn, request: Request,
                   user: dict = Depends(auth.require_at_least("analyst"))):
    try:
        if body.enabled is not None:
            ip_lists_mod.set_enabled(uid, body.enabled, actor=user["username"])
        row = ip_lists_mod.update(uid, reason=body.reason, note=body.note,
                                  expires_at=body.expires_at,
                                  actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "ip_list_update", f"ip:{row['ip']}",
          json.dumps({"enabled": row["enabled"], "expires_at": row["expires_at"]},
                     ensure_ascii=False), _ip(request))
    return {"item": row}


@app.delete("/api/ip-lists/{uid}")
def ip_list_delete(uid: int, request: Request,
                   user: dict = Depends(auth.require_at_least("admin"))):
    try:
        row = ip_lists_mod.delete(uid, actor=user["username"])
    except ValueError as e:
        raise HTTPException(404, str(e))
    audit(user["username"], "ip_list_delete", f"ip:{row['ip']}",
          json.dumps({"kind": row["kind"], "source": row["source"]},
                     ensure_ascii=False), _ip(request))
    return {"ok": True, "item": row}


@app.post("/api/ip-lists/bulk-delete")
def ip_list_bulk_delete(body: IpListBulkDeleteIn, request: Request,
                        user: dict = Depends(auth.require_at_least("admin"))):
    out = ip_lists_mod.bulk_delete(body.ids, actor=user["username"])
    audit(user["username"], "ip_list_bulk_delete", f"n={len(out['deleted'])}",
          json.dumps({"ids": body.ids, "missing": out["missing"]},
                     ensure_ascii=False), _ip(request))
    return {"ok": True, **out}


@app.post("/api/ip-lists/import")
def ip_list_import(body: IpListImportIn, request: Request,
                   user: dict = Depends(auth.require_at_least("analyst"))):
    try:
        out = ip_lists_mod.import_text(body.text, body.kind, actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "ip_list_import", body.kind,
          json.dumps({k: out.get(k) for k in ("total", "added", "updated")},
                     ensure_ascii=False), _ip(request))
    return out


@app.get("/api/ip-lists/export")
def ip_list_export(kind: Optional[str] = None,
                   format: str = Query("csv", pattern="^(csv|json)$"),
                   user: dict = Depends(auth.current_user)):
    try:
        if format == "json":
            content, media = ip_lists_mod.export_json(kind), "application/json"
        else:
            content, media = ip_lists_mod.export_csv(kind), "text/csv"
    except ValueError as e:
        raise HTTPException(400, str(e))
    fname = f"ip_lists_{kind or 'all'}.{format}"
    return Response(content=content, media_type=f"{media}; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.get("/api/ip-lists/settings")
def ip_auto_settings_get(user: dict = Depends(auth.current_user)):
    return {"settings": ip_lists_mod.auto_settings()}


@app.put("/api/ip-lists/settings")
def ip_auto_settings_put(body: IpAutoSettingsIn, request: Request,
                         user: dict = Depends(auth.require_at_least("admin"))):
    patch = body.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "没有要更新的设置")
    try:
        out = ip_lists_mod.update_auto_settings(patch, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "ip_auto_settings", None,
          json.dumps(patch, ensure_ascii=False), _ip(request))
    return {"settings": out}


@app.post("/api/ip-lists/auto/scan")
def ip_auto_scan(request: Request,
                 user: dict = Depends(auth.require_at_least("admin"))):
    out = ip_lists_mod.auto_scan(actor=user["username"])
    audit(user["username"], "ip_auto_scan", None,
          json.dumps({"added": out.get("added"), "candidates": out.get("candidates")},
                     ensure_ascii=False), _ip(request))
    return out


# --------------------------------------------------------------------------- 总览
#: 事件聚合缓存：key = (DB 路径, window_hours)。15s 轮询下 5s 足够新；
#: 多标签页同时打开时能省掉重复的 COUNT/分组扫描。
_OVERVIEW_CACHE: dict = {}
_OVERVIEW_LOCK = threading.Lock()


def _overview_cache_clear() -> None:
    """测试 / 运维用：清空总览聚合缓存。"""
    with _OVERVIEW_LOCK:
        _OVERVIEW_CACHE.clear()


def _mode_from_metrics(metrics: Optional[dict]) -> str:
    """采集器判定模式：优先读 `block_mode`，兼容旧指标（只有 score_enabled）。"""
    if not metrics:
        return "unknown"
    mode = metrics.get("block_mode")
    if mode in ("off", "dry_run", "enforce"):
        return mode
    return "dry_run" if metrics.get("score_enabled") else "collect_only"


def _overview_event_summary(since: int, window_hours: int) -> dict:
    ttl = max(0, int(config.OVERVIEW_CACHE_SEC))
    key = (str(config.DB_PATH), int(window_hours))
    now = time.monotonic()
    if ttl:
        with _OVERVIEW_LOCK:
            hit = _OVERVIEW_CACHE.get(key)
            if hit and hit[0] > now:
                return hit[1]

    t = db.one(
        """SELECT COUNT(*) AS n,
                  COALESCE(SUM(action='block'),0)  AS blocks,
                  COALESCE(SUM(action='alert'),0)  AS alerts,
                  COALESCE(SUM(action='allow'),0)  AS allows,
                  COALESCE(SUM(enforced),0)        AS enforced,
                  COALESCE(SUM(supervised_flagged),0) AS sup_flagged,
                  COALESCE(SUM(zero_day_score_crossed),0) AS zd_crossed,
                  AVG(dur_ms) AS avg_dur_ms
           FROM events WHERE ts>=?""",
        (since,),
    ) or {}

    # 直方图在 SQL 里分桶：0.0–0.1 → 0 … 0.9–1.0 → 9，超界夹到两端。
    hist = [0] * 10
    for r in db.rows(
        """SELECT MIN(9, MAX(0, CAST(supervised_score * 10 AS INTEGER))) AS b,
                  COUNT(*) AS n
           FROM events
           WHERE ts>=? AND supervised_score IS NOT NULL
           GROUP BY b""",
        (since,),
    ):
        hist[int(r["b"])] = int(r["n"])

    top = db.rows(
        """SELECT COALESCE(attack_type,'unknown') AS attack_type, COUNT(*) AS n
           FROM events WHERE ts>=? AND supervised_flagged=1
           GROUP BY attack_type ORDER BY n DESC LIMIT 10""",
        (since,),
    )
    top_paths = db.rows(
        """SELECT path, COUNT(*) AS n FROM events
           WHERE ts>=? AND action IN ('block','alert')
           GROUP BY path ORDER BY n DESC LIMIT 10""",
        (since,),
    )
    payload = {
        "totals": t,
        "score_histogram": hist,
        "top_attack_types": top,
        "top_paths": top_paths,
    }
    if ttl:
        with _OVERVIEW_LOCK:
            # 窗口数有限，简单限长避免长期进程里无限增长。
            if len(_OVERVIEW_CACHE) > 64:
                _OVERVIEW_CACHE.clear()
            _OVERVIEW_CACHE[key] = (now + ttl, payload)
    return payload


@app.get("/api/overview/summary")
def overview(window_hours: int = Query(24, ge=1, le=24 * 90),
             user: dict = Depends(auth.current_user)):
    since = db.now_ms() - window_hours * 3600 * 1000
    agg = _overview_event_summary(since, window_hours)

    pol = _policy()
    metrics = _collector_metrics()
    mode = _mode_from_metrics(metrics)

    return {
        "window_hours": window_hours,
        "totals": agg["totals"],
        "score_histogram": agg["score_histogram"],
        "top_attack_types": agg["top_attack_types"],
        "top_paths": agg["top_paths"],
        "policy": {
            "version": pol.get("version"),
            "zero_day_enabled": pol.get("zero_day_enabled"),
            "supervised_threshold": (pol.get("supervised") or {}).get("threshold"),
            "zero_day_threshold": (pol.get("zero_day") or {}).get("threshold"),
            "calibration_pool": (pol.get("calibration_pool") or {}).get("name"),
            "calibration_n": (pol.get("calibration_pool") or {}).get("n"),
            "effective_fused_fpr_on_pool": pol.get("effective_fused_fpr_on_pool"),
            "generated_at": pol.get("generated_at"),
            "rules_enabled": bool((pol.get("rules") or {}).get("enabled")),
            "rules_sha1_16": (pol.get("rules") or {}).get("ruleset_sha1_16"),
            "rules_n": (pol.get("rules") or {}).get("n_rules"),
            "rules_n_block": (pol.get("rules") or {}).get("n_block_rules"),
        },
        "mode": mode,
        "dry_run": mode == "dry_run",
        "enforce": mode == "enforce",
        "collector": ({**metrics, "reload_view": _reload_view(pol, metrics)}
                      if metrics else metrics),
        "ingest": ingest_mod.ingest_state(),
        # 站点（Host）→ 模型：从逐条判决留证反查，回答「每个站点用的是什么模型」。
        "sites": sites_mod.site_models(window_hours, live_policy=pol),
        "warnings": _warnings(pol, metrics),
    }


def _warnings(pol: dict, metrics: Optional[dict]) -> list:
    w = []
    if pol.get("zero_day_enabled") is False:
        w.append("零日通道已关闭（安全降级）：分数与原始穿阈仍留证，但不产生 alert。")
    n = (pol.get("calibration_pool") or {}).get("n") or 0
    if n and n < 2000:
        w.append(f"校准池只有 {n} 条（建议 ≥2000）：阈值分位抖动大，不要据此上线拦截。")
    if metrics and metrics.get("stale"):
        w.append(f"采集器指标已 {metrics.get('age_sec')}s 未刷新，可能已停止。")
    if metrics and metrics.get("dropped_queue_full"):
        w.append(f"采集器写队列已丢 {metrics['dropped_queue_full']} 条（考虑调大 --channel）。")
    if metrics and metrics.get("dropped_io"):
        w.append(f"采集器写盘失败已丢 {metrics['dropped_io']} 条（检查磁盘）。")
    if metrics:
        bm = _mode_from_metrics(metrics)
        if bm != "enforce":
            w.append(
                f"采集器判定模式为 {bm}：只记录、不会拦截。"
                "需要拦截请在「采集代理」页把判定模式切到 enforce 并重启采集器。")
    if not metrics:
        w.append("未找到采集器指标文件：启动 waf-collector 时加 --stats-out <file>。")
    else:
        rv = _reload_view(pol, metrics)
        if rv.get("available"):
            if rv.get("last_err"):
                w.append(f"采集器热重载最近一次失败：{rv['last_err']}（已保留旧策略继续跑）。")
            if rv.get("policy_drift"):
                w.append(
                    f"磁盘策略（修订 {rv.get('policy_revision')}）比采集器在用的"
                    f"（修订 {rv.get('policy_active_revision')}）新 —— 等下一个轮询周期，"
                    "若一直不消失就是重载失败。"
                )
            if rv.get("rules_effective_drift"):
                w.append("磁盘规则集比采集器在用的新 —— 规则改动尚未生效（等轮询，或检查校验失败原因）。")
        else:
            w.append(
                "采集器未上报热重载状态（可能用了 --no-reload）：改策略/规则后必须重启采集器，"
                "否则控制台显示的是新规则、数据面跑的是旧规则。"
            )
    try:
        rc = retention.counts()
        if rc.get("manual"):
            w.append(f"raw 清理有 {rc['manual']} 个 manual 条目需要人工处理（stat 不符/孤儿 trash/path+trash 并存）。")
    except Exception:
        pass
    return w


# --------------------------------------------------------------------------- 事件
def _event_filter(action=None, src_ip=None, path=None, min_score=None,
                  from_ts=None, to_ts=None, q=None, rule_testing=None):
    """事件过滤条件。实现放在 `datasets_events.event_where`（事件选择用的是
    同一套语义），这里只保留调用点，避免两份 SQL 漂移。"""
    return datasets_events.event_where(
        action=action, src_ip=src_ip, path=path, min_score=min_score,
        from_ts=from_ts, to_ts=to_ts, q=q, rule_testing=rule_testing)


def _event_rule_hits(e: dict) -> list:
    """事件详情/取证包共用的规则命中读取。

    新事件优先用 `events.rule_hits_json`（含 scope/start/end/snippet）；老事件
    退回 `event_rules`。返回值统一是 list[dict]，字段缺失的旧行由 `/packet`
    的 `attach_spans` 决定是否还能精确标位。
    """
    try:
        hits = json.loads(e.get("rule_hits_json") or "[]")
    except Exception:
        hits = []
    if isinstance(hits, list) and hits:
        return hits
    return db.rows(
        """SELECT rule, name, severity, field, weight, action, snippet, scope, start, end
           FROM event_rules WHERE event_id=? ORDER BY rule, field""",
        (e.get("id"),),
    )


@app.get("/api/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    src_ip: Optional[str] = None,
    path: Optional[str] = None,
    min_score: Optional[float] = None,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    q: Optional[str] = None,
    rule_testing: Optional[bool] = None,
    cursor_ts: Optional[int] = None,
    cursor_id: Optional[int] = None,
    with_total: bool = True,
    user: dict = Depends(auth.current_user),
):
    """事件列表：offset 分页或 keyset 游标分页。

    keyset（`cursor_ts` + `cursor_id`）用 `(ts, id) < (cursor)` 定位下一页，
    大 offset 时不需要扫描/丢弃前 N 行；返回 `next_cursor` / `has_more`。
    `with_total=false` 跳过 `COUNT(*)`（翻页时总数可由第一页带过来）。
    """
    w, p = _event_filter(action, src_ip, path, min_score, from_ts, to_ts, q, rule_testing)
    if cursor_ts is not None and cursor_id is not None:
        # (ts, id) 复合游标：同一毫秒内多条事件也能稳定翻页，不重不漏。
        w += " AND (ts < ? OR (ts = ? AND id < ?))"
        p = p + [cursor_ts, cursor_ts, cursor_id]
        offset = 0

    total = (db.scalar(f"SELECT COUNT(*) AS n FROM events WHERE {w}", p, 0)
             if with_total else None)
    items = db.rows(
        f"""SELECT id, ts, src_ip, src_port, host, route, method, path, status, dur_ms,
                   body_len, body_truncated, action, supervised_score,
                   supervised_threshold, supervised_flagged,
                   zero_day_score, zero_day_threshold,
                   zero_day_score_crossed, zero_day_flagged, zero_day_enabled,
                   attack_label, attack_type, ua, dry_run, enforced, rule_testing,
                   rule_set_sha1_16, rule_hits_json, ip_list
            FROM events WHERE {w} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?""",
        p + [limit + 1, offset],
    )
    has_more = len(items) > limit
    items = items[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = {"ts": last["ts"], "id": last["id"]}
    for it in items:
        try:
            it["rule_hits"] = json.loads(it.get("rule_hits_json") or "[]")
        except Exception:
            it["rule_hits"] = []
        it.pop("rule_hits_json", None)
    return {"total": total, "limit": limit, "offset": offset, "items": items,
            "has_more": has_more, "next_cursor": next_cursor}


@app.post("/api/events/selection-preview")
def events_selection_preview(body: SelectionPreviewIn,
                             user: dict = Depends(auth.require_at_least("analyst"))):
    """创建数据集前的体量/body 预估（只读，不落盘）。

    必须声明在 `/api/events/{eid}` **之前**：`selection-preview` 也能匹配
    `{eid}` 路径模板，先注册的先匹配。
    """
    try:
        return datasets_events.preview_selection(
            mode=body.mode, event_ids=body.event_ids,
            filters=body.filters.model_dump(exclude_none=True) if body.filters else None,
            max_rows=body.max_rows)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/events/{eid}")
def event_detail(eid: int, user: dict = Depends(auth.current_user)):
    e = db.one("SELECT * FROM events WHERE id=?", (eid,))
    if not e:
        raise HTTPException(404, "事件不存在")
    shap = db.rows(
        "SELECT rank, feature, value, contribution FROM event_shap WHERE event_id=? ORDER BY rank",
        (eid,),
    )
    has_body = bool(db.one("SELECT 1 AS x FROM event_bodies WHERE event_id=?", (eid,)))
    fb = db.rows("SELECT id, verdict, note, actor, ts FROM feedback WHERE event_id=? ORDER BY ts DESC", (eid,))
    rule_hits = _event_rule_hits(e)
    e.pop("rule_hits_json", None)
    related = db.rows(
        """SELECT id, ts, action, path, supervised_score FROM events
           WHERE src_ip=? AND id<>? AND ts BETWEEN ? AND ?
           ORDER BY ts DESC LIMIT 20""",
        (e.get("src_ip"), eid, int(e.get("ts") or 0) - 600_000, int(e.get("ts") or 0) + 600_000),
    )
    return {**e, "shap": shap, "has_body": has_body, "feedback": fb, "related": related,
            "rule_hits": rule_hits}


@app.get("/api/events/{eid}/body")
def event_body(eid: int, request: Request,
               user: dict = Depends(auth.require_at_least("analyst"))):
    """兼容旧 Events 的请求体接口；新前端已改用 `/packet`，保留但不再新增调用方。"""
    row = db.one("SELECT body FROM event_bodies WHERE event_id=?", (eid,))
    if row is None:
        raise HTTPException(404, "body 未入库（隐私默认不存；采集/入库需显式开启）")
    audit(user["username"], "view_body", f"event:{eid}", ip=_ip(request))
    return {"event_id": eid, "body": row["body"]}


@app.get("/api/events/{eid}/packet")
def event_packet(eid: int, request: Request, response: Response,
                 reveal: bool = False,
                 user: dict = Depends(auth.require_at_least("analyst"))):
    """请求 + 响应取证包。

    - 默认把敏感头值逐字符显示为 `*`（Authorization/Cookie/Set-Cookie/...）；
      `reveal=true` 才返回原值。
    - 每次读取都审计；审计失败则抛错，不返回数据。
    - raw 已清理/旧记录缺失时 `reconstructed=true` + 明确原因，不伪造 wire 包。
    """
    e = db.one("SELECT * FROM events WHERE id=?", (eid,))
    if not e:
        raise HTTPException(404, "事件不存在")
    pkt = packet_mod.build_packet(e, reveal=reveal)
    # 精确命中标位依赖“当前包里实际展示的文本”：路径/查询/正文/UA/Referer
    # 都已解码成前端看到的样子。匹配文本仍在**规则解码后**空间里，所以这里
    # 同时重建解码映射，把规则字节偏移换成前端可 slice 的 UTF-16 区间。
    try:
        pkt["rule_hits"] = rule_spans.attach_spans(pkt.get("request") or {}, _event_rule_hits(e))
    except Exception:
        # 标位失败不应让整张取证包不可读；前端会退回字段级标红。
        pkt["rule_hits"] = []
    detail = {
        "reveal": bool(reveal),
        "reconstructed": pkt.get("reconstructed"),
        "reconstructed_reason": pkt.get("reconstructed_reason"),
        "masked_headers": pkt.get("masked_headers") or [],
    }
    audit(user["username"], "view_packet", f"event:{eid}",
          json.dumps(detail, ensure_ascii=False), _ip(request))
    if reveal:
        audit(user["username"], "view_sensitive_headers", f"event:{eid}",
              json.dumps({"revealed_headers": pkt.get("sensitive_headers") or []},
                         ensure_ascii=False), _ip(request))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return pkt


@app.get("/api/events/{eid}/packet/body")
def event_packet_body(eid: int, request: Request, side: str = Query("response"),
                      user: dict = Depends(auth.require_at_least("analyst"))):
    """下载原始（存盘的 wire bytes）请求/响应体；响应体为未解码压缩字节。"""
    if side not in ("request", "response"):
        raise HTTPException(400, "side 只支持 request|response")
    e = db.one("SELECT * FROM events WHERE id=?", (eid,))
    if not e:
        raise HTTPException(404, "事件不存在")
    data, truncated, reason = packet_mod.body_download(e, side)
    # 审计先于返回；审计写失败会抛错，导致数据不返回（fail-closed）。
    audit(user["username"], "download_packet_body", f"event:{eid}:{side}",
          json.dumps({"truncated": bool(truncated), "reason": reason,
                      "bytes": None if data is None else len(data)}, ensure_ascii=False),
          _ip(request))
    if data is None:
        raise HTTPException(404, f"该侧 body 未采样：{reason}")
    name = f"event-{eid}-{side}" + ("-truncated" if truncated else "") + ".bin"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "X-Packet-Truncated": "1" if truncated else "0",
            "X-Packet-Body-Reason": reason,
        },
    )


# --------------------------------------------------------------------------- 告警（聚合）
@app.get("/api/alerts")
def list_alerts(
    window_hours: int = Query(24, ge=1, le=24 * 90),
    bucket_min: int = Query(10, ge=1, le=1440),
    dedup: bool = False,
    include_suppressed: bool = False,
    user: dict = Depends(auth.current_user),
):
    """聚合告警。

    * 默认：`src_ip + action + method/path + 时间桶`，一条路径一组。
    * `dedup=1`：`src_ip + action + attack_type + 时间桶`，把同一源在同一桶内
      打不同路径的同类攻击合并成一行（`path_count` 是路径数），用于扫描风暴去重。
    * 生效中的实体级抑制默认折叠（`suppressed_hidden` 计数），
      `include_suppressed=1` 可显示并带 `suppression` 摘要。
    """
    since = db.now_ms() - window_hours * 3600 * 1000
    bucket_ms = bucket_min * 60 * 1000
    if dedup:
        items = alerts_mod.dedup_groups(since, bucket_min)
    else:
        items = db.rows(
            """SELECT src_ip, action, method, path,
                      CAST(ts / ? AS INTEGER) AS bucket,
                      MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS n,
                      MAX(supervised_score) AS max_score,
                      MAX(attack_type) AS attack_type
               FROM events
               WHERE ts>=? AND action IN ('block','alert')
               GROUP BY src_ip, action, method, path, bucket
               ORDER BY last_ts DESC LIMIT 500""",
            (bucket_ms, since),
        )
        for r in items:
            key = f"{r['src_ip']}|{r['action']}|{r.get('method')} {r.get('path')}|{r['bucket']}"
            r["group_key"] = key
            r["severity"] = "P1" if r["action"] == "block" else "P2"
            r["path_count"] = 1

    # 批量取确认状态，避免每行一次查询（最多 500 行）。
    states = {}
    keys = [r["group_key"] for r in items]
    if keys:
        ph = ",".join("?" * len(keys))
        states = {
            s["group_key"]: s
            for s in db.rows(
                f"SELECT group_key, status, assignee FROM alert_state "
                f"WHERE group_key IN ({ph})", keys)
        }
    for r in items:
        st = states.get(r["group_key"])
        r["status"] = st["status"] if st else "open"
        r["assignee"] = st["assignee"] if st else None

    items, suppressed_hidden = suppression.apply(
        items, include_suppressed=include_suppressed)
    return {"window_hours": window_hours, "bucket_min": bucket_min,
            "dedup": dedup, "include_suppressed": include_suppressed,
            "suppressed_hidden": suppressed_hidden, "items": items}


@app.get("/api/alerts/events")
def alert_group_events(
    src_ip: str,
    action: str,
    bucket: int,
    bucket_min: int = Query(10, ge=1, le=1440),
    method: Optional[str] = None,
    path: Optional[str] = None,
    attack_type: Optional[str] = None,
    dedup: bool = False,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(auth.current_user),
):
    """某个聚合组的事件下钻（精确匹配，含服务端分页）。"""
    try:
        return alerts_mod.group_events(
            src_ip=src_ip, action=action, bucket=bucket, bucket_min=bucket_min,
            method=method, path=path, attack_type=attack_type, dedup=dedup,
            limit=limit, offset=offset)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/alerts/chains")
def alert_chains(
    window_hours: int = Query(24, ge=1, le=24 * 90),
    gap_min: int = Query(10, ge=1, le=1440),
    min_events: int = Query(2, ge=1, le=1000),
    only_suspicious: bool = True,
    include_noise: bool = False,
    include_suppressed: bool = False,
    limit: int = Query(200, ge=1, le=500),
    user: dict = Depends(auth.current_user),
):
    """同源攻击链：按 (src_ip, ua) 聚合窗口内事件，间隔 > `gap_min` 切链。

    `chain_key` 与聚合告警共用 `alert_state.group_key`，所以确认/关闭走同一个
    `/api/alerts/ack`。扫描噪音（大量探测且无拦截）默认折叠，`include_noise=1` 可看。
    生效中的实体级抑制同样默认折叠（`suppressed_hidden` 计数）。
    """
    res = correlate.collect(
        window_hours=window_hours, gap_min=gap_min, min_events=min_events,
        only_suspicious=only_suspicious, include_noise=include_noise, limit=limit)

    keys = [c["chain_key"] for c in res["items"]]
    states = {}
    if keys:
        ph = ",".join("?" * len(keys))
        states = {
            s["group_key"]: s
            for s in db.rows(
                f"SELECT group_key, status, assignee FROM alert_state "
                f"WHERE group_key IN ({ph})", keys)
        }
    for c in res["items"]:
        st = states.get(c["chain_key"])
        c["status"] = st["status"] if st else "open"
        c["assignee"] = st["assignee"] if st else None

    res["items"], res["suppressed_hidden"] = suppression.apply(
        res["items"], include_suppressed=include_suppressed)
    res["include_suppressed"] = include_suppressed
    return res


@app.get("/api/alerts/chains/events")
def alert_chain_events(
    src_ip: str,
    from_ts: int,
    to_ts: int,
    ua: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(auth.current_user),
):
    """攻击链下钻：同源 + 同 UA + 时间范围（升序，含阶段分类）。"""
    try:
        return correlate.chain_events(
            src_ip=src_ip, ua=ua, from_ts=from_ts, to_ts=to_ts,
            limit=limit, offset=offset)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/alerts/ack")
def ack_alert(body: AckIn, request: Request,
              user: dict = Depends(auth.require_at_least("analyst"))):
    if body.status not in ("open", "ack", "closed", "pending"):
        raise HTTPException(400, "status 只支持 open/ack/closed/pending")
    db.execute(
        "INSERT OR REPLACE INTO alert_state(group_key, status, assignee, updated_at, actor) VALUES(?,?,?,?,?)",
        (body.group_key, body.status, body.assignee or user["username"], db.now_ms(), user["username"]),
    )
    audit(user["username"], "ack_alert", body.group_key, body.status, _ip(request))
    return {"ok": True}


# --------------------------------------------------------------------------- 抑制
@app.get("/api/suppressions")
def list_suppressions(
    status: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    user: dict = Depends(auth.current_user),
):
    """实体级抑制列表（只影响控制台告警可见性，不改数据面判定）。"""
    try:
        items = suppression.list_suppressions(status=status, limit=limit)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "items": items,
        "status": status,
        "default_ttl_hours": config.SUPPRESS_TTL_HOURS,
        "max_ttl_hours": config.SUPPRESS_MAX_TTL_HOURS,
    }


@app.post("/api/suppressions")
def create_suppression(
    body: SuppressionIn,
    request: Request,
    user: dict = Depends(auth.require_at_least("analyst")),
):
    """创建抑制草案（draft）。需要 admin 审批后才生效。"""
    try:
        row = suppression.create_draft(
            reason=body.reason, ttl_hours=body.ttl_hours, note=body.note,
            actor=user["username"], src_ip=body.src_ip, path=body.path,
            ua=body.ua, host=body.host, attack_type=body.attack_type)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "suppress_create", f"suppression:{row['id']}",
          json.dumps({k: row.get(k) for k in suppression.FIELDS}, ensure_ascii=False),
          _ip(request))
    return row


@app.post("/api/suppressions/suggest")
def suggest_suppressions(
    body: SuppressionSuggestIn,
    request: Request,
    user: dict = Depends(auth.require_at_least("analyst")),
):
    """从人工确认误报生成草案；只生成 draft，不自动生效。"""
    try:
        res = suppression.suggest(
            days=body.days, min_count=body.min_count, ttl_hours=body.ttl_hours,
            limit=body.limit, actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "suppress_suggest", None,
          json.dumps({"scanned": res["scanned"], "created": len(res["created"]),
                      "skipped": len(res["skipped"])}, ensure_ascii=False),
          _ip(request))
    return res


@app.post("/api/suppressions/{sid}/approve")
def approve_suppression(
    sid: int,
    body: SuppressionDecisionIn,
    request: Request,
    user: dict = Depends(auth.require_at_least("admin")),
):
    try:
        row = suppression.approve(sid, user["username"], body.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "suppress_approve", f"suppression:{sid}",
          json.dumps({"expires_at": row.get("expires_at")}, ensure_ascii=False),
          _ip(request))
    return row


@app.post("/api/suppressions/{sid}/revoke")
def revoke_suppression(
    sid: int,
    body: SuppressionDecisionIn,
    request: Request,
    user: dict = Depends(auth.require_at_least("admin")),
):
    try:
        row = suppression.revoke(sid, user["username"], body.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "suppress_revoke", f"suppression:{sid}",
          body.note, _ip(request))
    return row


@app.delete("/api/suppressions/{sid}")
def delete_suppression(
    sid: int,
    request: Request,
    user: dict = Depends(auth.require_at_least("admin")),
):
    """只允许删草案/已撤销行；生效中的必须先撤销，保留审批轨迹。"""
    try:
        row = suppression.delete(sid, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "suppress_delete", f"suppression:{sid}",
          json.dumps({k: row.get(k) for k in suppression.FIELDS}, ensure_ascii=False),
          _ip(request))
    return {"ok": True, "deleted": row}


# --------------------------------------------------------------------------- 策略
@app.get("/api/policy")
def policy_get(user: dict = Depends(auth.current_user)):
    pol = _policy()
    versions = db.rows(
        "SELECT version, actor, created_at, note FROM policy_versions ORDER BY version DESC LIMIT 30"
    )
    return {"policy": pol, "versions": versions, "warnings": _warnings(pol, _collector_metrics())}


@app.post("/api/policy/preview")
def policy_preview(body: PreviewIn, user: dict = Depends(auth.require_at_least("admin"))):
    pool = _check_policy_args(body)
    tmpdir = tempfile.mkdtemp(prefix="waf_policy_")
    out = os.path.join(tmpdir, "policy.json")
    try:
        p = _run_thresholds(pool, body.fpr, body.zero_day, out=out)
        if p.returncode != 0:
            raise HTTPException(400, detail=(p.stdout or "") + (p.stderr or ""))
        pol = _read_json(Path(out), None)
        if not pol:
            raise HTTPException(500, "thresholds.py 未产出策略文件")
        return {
            "policy": pol,
            "log": p.stdout,
            "note": "预览写入临时文件，未改动决策策略；采用需调用 /api/policy/promote。",
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/api/policy/promote")
def policy_promote(body: PromoteIn, request: Request,
                   user: dict = Depends(auth.require_at_least("admin"))):
    pool = _check_policy_args(body)
    p = _run_thresholds(pool, body.fpr, body.zero_day)
    if p.returncode != 0:
        raise HTTPException(400, detail=(p.stdout or "") + (p.stderr or ""))
    pol = _policy()
    db.execute(
        "INSERT OR REPLACE INTO policy_versions(version, json, actor, created_at, note) VALUES(?,?,?,?,?)",
        (int(pol.get("version") or 1), json.dumps(pol, ensure_ascii=False),
         user["username"], db.now_ms(), body.note or "控制台提升"),
    )
    audit(user["username"], "policy_promote", f"v{pol.get('version')}",
          json.dumps({"pool": pool, "fpr": body.fpr, "zero_day": body.zero_day}, ensure_ascii=False),
          _ip(request))
    return {
        "policy": pol,
        "log": p.stdout,
        "checklist": {
            "testvec": "thresholds.py 已自动刷新 testvec.json",
            "rust_gate": r"必须重跑 F:\waf\rust\build.bat run --release，确认门禁全绿",
            "reload": "采集器启动时读取策略；当前无热重载，改策略后需重启 waf-collector",
        },
    }


@app.post("/api/policy/zero-day")
def policy_zero_day(body: ZeroDayIn, request: Request,
                    user: dict = Depends(auth.require_at_least("admin"))):
    pol = _policy()
    src = (pol.get("calibration_pool") or {}).get("source") or "csic"
    pool = _pool_from_source(str(src))
    fpr = str((pol.get("supervised") or {}).get("target_fpr") or "0.01")
    p = _run_thresholds(pool, fpr, "on" if body.enabled else "off")
    if p.returncode != 0:
        raise HTTPException(400, detail=(p.stdout or "") + (p.stderr or ""))
    new = _policy()
    db.execute(
        "INSERT OR REPLACE INTO policy_versions(version, json, actor, created_at, note) VALUES(?,?,?,?,?)",
        (int(new.get("version") or 1), json.dumps(new, ensure_ascii=False),
         user["username"], db.now_ms(), body.note or f"零日通道 {'开' if body.enabled else '关'}"),
    )
    audit(user["username"], "zero_day_toggle", "on" if body.enabled else "off",
          f"pool={pool} fpr={fpr}", _ip(request))
    return {"policy": new, "log": p.stdout}


# --------------------------------------------------------------------------- 反馈
@app.post("/api/feedback")
def add_feedback(body: FeedbackIn, request: Request,
                 user: dict = Depends(auth.require_at_least("analyst"))):
    if body.verdict not in VERDICTS:
        raise HTTPException(400, f"verdict 只支持 {sorted(VERDICTS)}")
    if not db.one("SELECT 1 AS x FROM events WHERE id=?", (body.event_id,)):
        raise HTTPException(404, "事件不存在")
    fid = db.execute(
        "INSERT INTO feedback(event_id, verdict, note, actor, ts) VALUES(?,?,?,?,?)",
        (body.event_id, body.verdict, body.note, user["username"], db.now_ms()),
    )
    audit(user["username"], "feedback", f"event:{body.event_id}", body.verdict, _ip(request))
    return {
        "id": fid,
        "note": "反馈写入独立库；经人工复核后才可能成为训练标签，不会覆盖 pred。",
    }


@app.get("/api/feedback")
def list_feedback(limit: int = Query(100, ge=1, le=500),
                  user: dict = Depends(auth.current_user)):
    return {"items": db.rows(
        "SELECT id, event_id, verdict, note, actor, ts FROM feedback ORDER BY ts DESC LIMIT ?",
        (limit,),
    )}


@app.get("/api/feedback/export")
def export_feedback(user: dict = Depends(auth.require_at_least("analyst"))):
    data = db.rows(
        """SELECT f.id, f.event_id, f.verdict, f.note, f.actor, f.ts,
                  e.src_ip, e.method, e.path, e.action, e.supervised_score, e.supervised_flagged,
                  e.zero_day_score, e.zero_day_flagged, e.attack_type
           FROM feedback f LEFT JOIN events e ON e.id = f.event_id
           ORDER BY f.ts DESC"""
    )
    return {"items": data, "note": "导出仅用于人工复核与构造评估集；不可直接当训练标签。"}


# --------------------------------------------------------------------------- 规则
# 语义（v2）：`enabled` = 参与判定（只告警）；`qualified_at` = 人工确认合格；
# 只有合格才能 `action=block`；全局刹车在策略里；熔断是产物级覆盖。
@app.get("/api/rules")
def list_rules(user: dict = Depends(auth.current_user)):
    return rules_mod.merged()


@app.get("/api/rules/authoritative")
def rules_authoritative(user: dict = Depends(auth.current_user)):
    return {"info": rules_mod.authoritative_info(),
            "ruleset": rules_mod.load_authoritative()}


# ---- 规则事件（熔断/误报） -------------------------------------------------
def _parse_detail(raw):
    try:
        return json.loads(raw or "{}")
    except Exception:
        return {}


@app.get("/api/rules/incidents")
def list_incidents(status: Optional[str] = Query("open"),
                   limit: int = Query(50, ge=1, le=200),
                   user: dict = Depends(auth.current_user)):
    if status in ("open", "acked", "resolved"):
        rows = db.rows(
            "SELECT * FROM rule_incidents WHERE status=? ORDER BY opened_at DESC LIMIT ?",
            (status, limit),
        )
    else:
        rows = db.rows(
            "SELECT * FROM rule_incidents ORDER BY opened_at DESC LIMIT ?", (limit,),
        )
    names: Dict[str, str] = {
        r["id"]: r["name"] for r in db.rows("SELECT id, name FROM rules_custom")
    }
    for r in rows:
        r["detail"] = _parse_detail(r.get("detail"))
        r["rule_name"] = names.get(r.get("rule")) if r.get("rule") else None
    return {"items": rows, "n_open": db.scalar(
        "SELECT COUNT(*) AS n FROM rule_incidents WHERE status='open'", default=0)}


@app.post("/api/rules/incidents/{iid}/ack")
def ack_incident(iid: int, body: IncidentActionIn, request: Request,
                 user: dict = Depends(auth.require_at_least("analyst"))):
    inc = db.one("SELECT * FROM rule_incidents WHERE id=?", (iid,))
    if not inc:
        raise HTTPException(404, "事件不存在")
    if inc["status"] == "open":
        db.execute("UPDATE rule_incidents SET status='acked', note=COALESCE(?, note) WHERE id=?",
                   (body.note, iid))
    audit(user["username"], "rule_incident_ack", f"incident:{iid}", body.note, _ip(request))
    return {"ok": True}


@app.post("/api/rules/incidents/{iid}/resolve")
def resolve_incident(iid: int, body: IncidentActionIn, request: Request,
                     user: dict = Depends(auth.require_at_least("analyst"))):
    inc = db.one("SELECT * FROM rule_incidents WHERE id=?", (iid,))
    if not inc:
        raise HTTPException(404, "事件不存在")
    restored = None
    if body.restore:
        from . import breaker
        if inc.get("rule"):
            restored = breaker.restore(rule=inc["rule"], channel_on=False,
                                       actor=user["username"],
                                       note=f"处理 incident:{iid}")
        else:
            restored = breaker.restore(channel_on=True, actor=user["username"],
                                       note=f"处理 incident:{iid}")
    db.execute(
        "UPDATE rule_incidents SET status='resolved', resolved_at=?, resolved_by=?, "
        "note=COALESCE(?, note) WHERE id=?",
        (db.now_ms(), user["username"], body.note, iid),
    )
    audit(user["username"], "rule_incident_resolve", f"incident:{iid}",
          json.dumps({"restore": body.restore, "note": body.note}, ensure_ascii=False),
          _ip(request))
    return {"ok": True, "restored": restored}


@app.post("/api/rules/incidents/bulk")
def bulk_incidents(body: IncidentBulkIn, request: Request,
                   user: dict = Depends(auth.require_at_least("analyst"))):
    """批量已阅/解决误报事件；解决时可选按熔断快照恢复。"""
    if body.op not in ("ack", "resolve"):
        raise HTTPException(400, "op 只支持 ack / resolve")
    ids = []
    seen = set()
    for iid in body.ids or []:
        if iid not in seen:
            seen.add(iid)
            ids.append(iid)
    if not ids:
        raise HTTPException(400, "至少选择一个事件")
    if len(ids) > 200:
        raise HTTPException(400, "单次最多处理 200 个事件")

    changed: List[int] = []
    skipped: List[int] = []
    errors: List[Dict[str, Any]] = []
    restored: List[Any] = []
    for iid in ids:
        inc = db.one("SELECT * FROM rule_incidents WHERE id=?", (iid,))
        if not inc:
            errors.append({"id": iid, "error": "事件不存在"})
            continue
        if body.op == "ack":
            if inc["status"] != "open":
                skipped.append(iid)
                continue
            db.execute(
                "UPDATE rule_incidents SET status='acked', note=COALESCE(?, note) WHERE id=?",
                (body.note, iid),
            )
            changed.append(iid)
            continue

        if inc["status"] == "resolved":
            skipped.append(iid)
            continue
        if body.restore:
            try:
                from . import breaker
                if inc.get("rule"):
                    restored.append(breaker.restore(
                        rule=inc["rule"], channel_on=False, actor=user["username"],
                        note=body.note or f"批量处理 incident:{iid}"))
                else:
                    restored.append(breaker.restore(
                        channel_on=True, actor=user["username"],
                        note=body.note or f"批量处理 incident:{iid}"))
            except ValueError as e:
                errors.append({"id": iid, "error": str(e)})
                continue
        db.execute(
            "UPDATE rule_incidents SET status='resolved', resolved_at=?, resolved_by=?, "
            "note=COALESCE(?, note) WHERE id=?",
            (db.now_ms(), user["username"], body.note, iid),
        )
        changed.append(iid)

    audit(user["username"], f"rule_incident_bulk_{body.op}", f"n={len(changed)}",
          json.dumps({"ids": ids, "changed": changed, "skipped": skipped,
                      "errors": errors, "restore": body.restore,
                      "note": body.note}, ensure_ascii=False), _ip(request))
    return {"ok": True, "op": body.op, "n_changed": len(changed),
            "changed": changed, "skipped": skipped, "errors": errors,
            "restored": restored}


@app.post("/api/rules/breaker")
def apply_rule_breaker(body: BreakerIn, request: Request,
                       user: dict = Depends(auth.require_at_least("admin"))):
    from . import breaker
    try:
        out = breaker.apply_breaker(scope=body.scope, rule=body.rule,
                                    reason=body.reason or "manual",
                                    actor=user["username"], note=body.note or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_breaker", body.rule or body.scope,
          json.dumps({"reason": body.reason, "note": body.note}, ensure_ascii=False),
          _ip(request))
    return out


@app.post("/api/rules/breaker/restore")
def restore_rule_breaker(body: BreakerRestoreIn, request: Request,
                         user: dict = Depends(auth.require_at_least("admin"))):
    from . import breaker
    if not body.rule and not body.all and not body.channel_on:
        raise HTTPException(400, "至少要指定 rule / all / channel_on 之一")
    try:
        out = breaker.restore(rule=body.rule, all_breakers=body.all,
                              channel_on=body.channel_on, actor=user["username"],
                              note=body.note or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_breaker_restore",
          body.rule or ("all" if body.all else "channel"),
          json.dumps({"channel_on": body.channel_on, "note": body.note}, ensure_ascii=False),
          _ip(request))
    return out


@app.post("/api/rules/breaker/bulk-restore")
def bulk_restore_breakers(body: BreakerBulkRestoreIn, request: Request,
                          user: dict = Depends(auth.require_at_least("admin"))):
    """按选中的熔断规则批量恢复（每条按自己的熔断前快照还原）。"""
    ids = []
    seen = set()
    for rid in body.rules or []:
        rid = str(rid)
        if rid and rid not in seen:
            seen.add(rid)
            ids.append(rid)
    if not ids:
        raise HTTPException(400, "至少选择一条熔断规则")
    if len(ids) > 200:
        raise HTTPException(400, "单次最多恢复 200 条")

    existing = {str(r["rule"]) for r in rules_mod.breaker_rows()}
    restored: List[str] = []
    skipped: List[str] = []
    errors: List[Dict[str, str]] = []
    from . import breaker
    for rid in ids:
        if rid not in existing:
            skipped.append(rid)
            continue
        try:
            out = breaker.restore(rule=rid, channel_on=False, actor=user["username"],
                                  note=body.note or "控制台批量恢复熔断")
            restored.extend(out.get("restored") or [])
            skipped.extend(out.get("skipped") or [])
        except ValueError as e:
            errors.append({"rule": rid, "error": str(e)})
    audit(user["username"], "rule_breaker_bulk_restore", f"n={len(restored)}",
          json.dumps({"rules": ids, "restored": restored, "skipped": skipped,
                      "errors": errors, "note": body.note}, ensure_ascii=False),
          _ip(request))
    return {"ok": True, "n_changed": len(restored), "restored": restored,
            "skipped": skipped, "errors": errors}


@app.get("/api/rules/monitor/settings")
def rule_monitor_settings(user: dict = Depends(auth.current_user)):
    return {"settings": rules_mod.monitor_settings()}


@app.put("/api/rules/monitor/settings")
def rule_monitor_settings_update(body: RuleMonitorSettingsIn, request: Request,
                                 user: dict = Depends(auth.require_at_least("admin"))):
    patch = body.model_dump(exclude_none=True)
    if not patch:
        raise HTTPException(400, "没有要更新的设置")
    try:
        out = rules_mod.update_monitor_settings(patch, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_monitor_settings", "rules",
          json.dumps(patch, ensure_ascii=False), _ip(request))
    return {"settings": out}


@app.post("/api/rules/monitor/scan")
def rule_monitor_scan(request: Request,
                      user: dict = Depends(auth.require_at_least("admin"))):
    """手动跑一轮误报扫描（测试/演示用；后台默认 60s 自动跑）。"""
    from . import rule_monitor
    out = rule_monitor.scan_once(actor=user["username"])
    audit(user["username"], "rule_monitor_scan", None,
          json.dumps({"opened": out.get("opened"), "auto_broken": out.get("auto_broken")},
                     ensure_ascii=False), _ip(request))
    return out


# ---- 证据 / 样本 / 合格 -----------------------------------------------------
@app.get("/api/rules/{rid}/evidence")
def rule_evidence(rid: str, days: int = Query(7, ge=1, le=90),
                  limit: int = Query(50, ge=1, le=200),
                  user: dict = Depends(auth.current_user)):
    since = db.now_ms() - days * 86400 * 1000
    online = rules_mod.online_stats(days, [rid]).get(rid) or {
        "rule": rid, "hits": 0, "block_hits": 0, "confirmed_attack": 0,
        "confirmed_benign": 0, "suspected_attack": 0, "unlabeled": 0, "last_ts": None,
    }
    samples = db.rows(
        """SELECT e.id AS event_id, e.ts, e.src_ip, e.method, e.path, e.action,
                  e.supervised_score, e.supervised_flagged, e.zero_day_flagged,
                  e.rule_testing, er.field, er.snippet, er.weight AS rule_weight,
                  er.action AS rule_action,
                  (SELECT f.verdict FROM feedback f WHERE f.event_id=e.id
                    ORDER BY f.ts DESC, f.id DESC LIMIT 1) AS verdict
             FROM event_rules er JOIN events e ON e.id=er.event_id
            WHERE er.rule=? AND e.ts>=?
            ORDER BY e.ts DESC LIMIT ?""",
        (rid, since, limit),
    )
    incidents = db.rows(
        "SELECT * FROM rule_incidents WHERE rule=? ORDER BY opened_at DESC LIMIT 10",
        (rid,),
    )
    for r in incidents:
        r["detail"] = _parse_detail(r.get("detail"))

    row = db.one("SELECT * FROM rules_custom WHERE id=?", (rid,))
    if row:
        row = dict(row)
        try:
            row["validation"] = json.loads(row.get("validation") or "null")
        except Exception:
            row["validation"] = None
        history = rules_mod.history_evidence(rid)
        view = rules_mod.custom_view(row, online, rules_mod.breaker_map().get(rid), history)
        return {
            "rule": rid, "source": row.get("source") or "custom",
            "name": row.get("name"), "kind": row.get("kind") or "detector",
            "state": view["state"], "view": view,
            "offline": (row.get("validation") or {}).get("gates") or {},
            "online": online, "history": history, "history_ok": view["history_ok"],
            "samples": samples, "incidents": incidents,
            "qualified_at": row.get("qualified_at"),
            "qualified_by": row.get("qualified_by"),
            "qualification_source": row.get("qualification_source"),
            "qualification_note": row.get("qualification_note"),
        }
    mined = next((r for r in rules_mod.mined_rows() if r.get("rule") == rid), None)
    if not mined:
        raise HTTPException(404, "规则不存在")
    return {
        "rule": rid, "source": "mined", "name": rid, "kind": "detector",
        "state": mined.get("verdict"), "view": None,
        "offline": {
            "benign_replay": {"passed": (mined.get("benign_hits") or 0) == 0,
                              "benign_hits": mined.get("benign_hits"),
                              "benign_n": mined.get("benign_n")},
            "attack_replay": {"passed": (mined.get("attack_hits") or 0) > 0,
                              "attack_hits": mined.get("attack_hits"),
                              "attack_n": mined.get("attack_n")},
        },
        "online": online, "samples": samples, "incidents": incidents,
        "history": None, "history_ok": False,
    }


@app.post("/api/rules/custom/{rid}/history-evidence")
def rule_history_evidence(rid: str, body: HistoryReplayIn, request: Request,
                          user: dict = Depends(auth.require_at_least("analyst"))):
    """用历史告警回放验证规则（只读 + 缓存证据，不改规则集）。"""
    from . import rule_history
    try:
        out = rule_history.run(rid, days=body.days, max_events=body.max_events,
                               actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_history_replay", rid,
          json.dumps({k: out.get(k) for k in
                      ("days", "scanned", "truncated", "matched",
                       "confirmed_attack", "confirmed_benign", "unlabeled", "ok")},
                     ensure_ascii=False), _ip(request))
    return out


@app.post("/api/rules/{rid}/qualify")
def qualify_rule(rid: str, body: QualifyIn, request: Request,
                 user: dict = Depends(auth.require_at_least("admin"))):
    try:
        out = rules_mod.set_custom_qualified(
            rid, actor=user["username"], note=body.note or "",
            source=body.source or "manual", force=body.force,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_qualify", rid,
          json.dumps({"force": body.force, "note": body.note}, ensure_ascii=False),
          _ip(request))
    return out


@app.post("/api/rules/{rid}/unqualify")
def unqualify_rule(rid: str, body: IncidentActionIn, request: Request,
                   user: dict = Depends(auth.require_at_least("admin"))):
    try:
        out = rules_mod.unqualify_custom(rid, actor=user["username"], note=body.note or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_unqualify", rid, body.note, _ip(request))
    return out


@app.post("/api/rules/preview-authoritative")
def rules_preview_authoritative(body: RulesPromoteIn,
                               user: dict = Depends(auth.require_at_least("admin"))):
    if body.decode:
        errs = rules_dsl.check_decode(body.decode)
        if errs:
            raise HTTPException(400, errs[0])
    doc = rules_mod.build_authoritative(
        decode=body.decode, min_weight_to_block=body.min_weight_to_block,
        ruleset_id=body.ruleset_id,
    )
    return {"ruleset": doc,
            "note": "预览未落盘。提升才会写 artifacts/rules_authoritative.json。"}


@app.post("/api/rules/promote")
def rules_promote(body: RulesPromoteIn, request: Request,
                  user: dict = Depends(auth.require_at_least("admin"))):
    """把启用的规则写成现役规则集，并同步策略里的 rules 块与预算扣减。"""
    if body.decode:
        errs = rules_dsl.check_decode(body.decode)
        if errs:
            raise HTTPException(400, errs[0])
    doc = rules_mod.build_authoritative(
        decode=body.decode, min_weight_to_block=body.min_weight_to_block,
        ruleset_id=body.ruleset_id,
    )
    if not doc["rules"]:
        raise HTTPException(400, "没有任何启用的规则；先启用（只要求 ① 编译），或留一条挖出的 keep 规则")
    from . import rule_promote
    out = rule_promote.promote(doc, actor=user["username"], note=body.note,
                               rule_budget_cap=body.rule_budget_cap,
                               ip=_ip(request))
    pol = out.get("policy") or {}
    if not bool((pol.get("rules") or {}).get("enabled")):
        out.setdefault("checklist", {})["channel_warning"] = (
            "规则通道当前是熔断关闭状态；本次提升会把它重新打开（由 thresholds.py 写入 enabled=true）。"
        )
    return out


@app.post("/api/rules/custom")
def create_custom_rule(body: RuleIn, request: Request,
                       user: dict = Depends(auth.require_at_least("admin"))):
    try:
        out = rules_mod.create_custom(body.model_dump(), user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_create", out["rule"]["id"], out["rule"]["regex"], _ip(request))
    return out


@app.post("/api/rules/custom/bulk-enable")
def bulk_custom_enable(body: CustomBulkIn, request: Request,
                       user: dict = Depends(auth.require_at_least("admin"))):
    """批量启用/停用自撰规则。启用只要求 ① 编译，不等三关。"""
    out = rules_mod.bulk_set_custom_state(enabled=body.enabled,
                                          actor=user["username"],
                                          only_uncompiled=body.only_uncompiled)
    audit(user["username"], "rule_custom_bulk", f"n={out.get('n_changed')}",
          json.dumps({"enabled": body.enabled, "only_uncompiled": body.only_uncompiled},
                     ensure_ascii=False), _ip(request))
    return out


@app.put("/api/rules/custom/{rid}")
def update_custom_rule(rid: str, body: RuleEditIn, request: Request,
                       user: dict = Depends(auth.require_at_least("admin"))):
    try:
        out = rules_mod.update_custom(rid, body.model_dump(exclude_none=True), user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_edit", rid, "内容变更 ⇒ 验证/合格作废", _ip(request))
    return out


@app.delete("/api/rules/custom/{rid}")
def delete_custom_rule(rid: str, request: Request,
                       user: dict = Depends(auth.require_at_least("admin"))):
    """删除自撰规则：DB 行 + 历史证据 + 熔断行，并从现役规则集立即移除。"""
    try:
        out = rules_mod.delete_custom(rid, actor=user["username"])
    except ValueError as e:
        raise HTTPException(404 if "不存在" in str(e) else 400, str(e))
    except Exception as e:  # noqa: BLE001 - 产物写入失败：已回滚，未删 DB
        raise HTTPException(500, f"删除失败（未改动任何状态）：{e}")
    if out.get("active"):
        # 现役规则集变了：重导出 testvec，避免 Rust 门禁指纹不一致。
        out["testvec"] = rules_mod.refresh_testvec()
    audit(user["username"], "rule_delete", rid,
          json.dumps({"name": out.get("name"), "active": out.get("active"),
                      "testvec_ok": (out.get("testvec") or {}).get("ok")},
                     ensure_ascii=False), _ip(request))
    return {"ok": True, **out}


@app.patch("/api/rules/custom/{rid}")
def patch_custom_rule(rid: str, body: RulePatch, request: Request,
                      user: dict = Depends(auth.require_at_least("admin"))):
    try:
        if body.kind is not None:
            rules_mod.set_custom_kind(rid, body.kind, user["username"])
        out = rules_mod.set_custom_state(rid, enabled=body.enabled, action=body.action,
                                         actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_toggle", rid,
          json.dumps({"enabled": body.enabled, "action": body.action, "kind": body.kind},
                     ensure_ascii=False), _ip(request))
    return out


@app.post("/api/rules/custom/{rid}/validate")
def validate_custom_rule(rid: str, request: Request,
                         user: dict = Depends(auth.require_at_least("admin"))):
    """三关校验（正则安全 / 真实良性回放 / 攻击回放）。回放**用 Rust 同一份实现**。"""
    from . import rule_validate
    try:
        out = rule_validate.validate_custom(rid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_validate", rid,
          "pass" if out.get("passed") else "fail", _ip(request))
    return out


@app.patch("/api/rules/{rule}")
def patch_rule(rule: str, body: RulePatch, request: Request,
               user: dict = Depends(auth.require_at_least("admin"))):
    """挖出的候选规则：开关（=合格）与逐条 action。"""
    try:
        out = rules_mod.set_mined_state(rule, enabled=body.enabled, action=body.action,
                                        actor=user["username"])
    except ValueError as e:
        code = 404 if str(e).startswith("规则不存在") else 400
        raise HTTPException(code, str(e))
    audit(user["username"], "rule_toggle", rule,
          json.dumps({"enabled": body.enabled, "action": body.action}, ensure_ascii=False),
          _ip(request))
    return out


@app.post("/api/rules/bulk")
def bulk_rules(body: RuleBulkOpIn, request: Request,
               user: dict = Depends(auth.require_at_least("admin"))):
    """按选中 ID 批量启停、改动作或删除规则。"""
    if len(body.ids or []) > 500:
        raise HTTPException(400, "单次最多处理 500 条规则")
    try:
        out = rules_mod.bulk_apply_rules(
            scope=body.scope, ids=body.ids, op=body.op,
            action=body.action, actor=user["username"],
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "rule_bulk", f"{body.scope}/{body.op}/{out['n_changed']}",
          json.dumps({"ids": body.ids, "op": body.op, "action": body.action,
                      "changed": out.get("changed"), "skipped": out.get("skipped"),
                      "errors": out.get("errors")}, ensure_ascii=False),
          _ip(request))
    return out


@app.post("/api/rules/bulk-enable")
def bulk_enable_rules(body: RuleBulkIn, request: Request,
                      user: dict = Depends(auth.require_at_least("admin"))):
    """批量把挖出的候选设为「合格（启用）」（或批量停用）。"""
    out = rules_mod.bulk_set_mined_state(enabled=body.enabled, actor=user["username"],
                                         only_unproven=body.only_unproven)
    audit(user["username"], "rule_bulk_enable", f"mined/{out['n_changed']}",
          json.dumps({"enabled": body.enabled, "only_unproven": body.only_unproven},
                     ensure_ascii=False),
          _ip(request))
    return out


# --------------------------------------------------------------------------- 模型
@app.get("/api/models")
def models(user: dict = Depends(auth.current_user)):
    arts = []
    for p in sorted(config.ARTIFACTS.glob("*.onnx")):
        st = p.stat()
        arts.append({
            "name": p.name,
            "bytes": st.st_size,
            "mtime": int(st.st_mtime * 1000),
            "sha1_16": _sha1_16(p),
        })
    metas = {}
    for n in ("xgboost_meta.json", "iforest_meta.json", "iforest_meta_local.json"):
        p = config.ARTIFACTS / n
        if p.exists():
            metas[n] = _read_json(p, {})
    curves = sorted(p.stem for p in config.CURVES.glob("*_curve.json")) if config.CURVES.exists() else []
    current = model_registry.current_state()
    models_list = model_registry.list_models()
    # 给每一行标注当前现役（按通道），前端无需自己比对 sha。
    active_ids = {int(v["model"]["id"]) for v in current["channels"].values()
                  if v.get("model")}
    for m in models_list:
        m["is_current"] = int(m["id"]) in active_ids
    return {
        "artifacts": arts,
        "metas": metas,
        "curves": curves,
        "policy_version": _policy().get("version"),
        "feature_names": _read_json(config.FEATURE_NAMES, {}),
        "models": models_list,
        # 代际传承图：父子血缘 + 现役路径（只读，纯结构整理）
        "lineage": model_registry.build_lineage(models_list, active_ids),
        "current": current,
        "settings": model_registry.get_settings(),
        "parents": {ch: model_registry.eligible_parents(ch)
                    for ch in model_registry.CHANNELS},
    }


@app.get("/api/models/current")
def models_current(user: dict = Depends(auth.current_user)):
    return model_registry.current_state()


@app.get("/api/models/settings")
def models_settings_get(user: dict = Depends(auth.current_user)):
    return {"settings": model_registry.get_settings(),
            "defaults": config.MODEL_SETTINGS_DEFAULTS,
            "channels": model_registry.CHANNEL_LABEL}


@app.put("/api/models/settings")
def models_settings_put(body: ModelSettingsIn, request: Request,
                        user: dict = Depends(auth.require_at_least("admin"))):
    try:
        patch = {k: v for k, v in body.model_dump().items() if v is not None}
        out = model_registry.update_settings(patch, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "model_settings_update", None,
          json.dumps(patch, ensure_ascii=False), _ip(request))
    return {"settings": out, "prune": model_registry.prune(actor=user["username"], dry_run=True)}


@app.post("/api/models/prune")
def models_prune(body: ModelPruneIn, request: Request,
                 user: dict = Depends(auth.require_at_least("admin"))):
    out = model_registry.prune(actor=user["username"], dry_run=body.dry_run)
    audit(user["username"], "model_prune_dry_run" if body.dry_run else "model_prune_apply",
          None, json.dumps({"count": len(out.get("models", []))}, ensure_ascii=False),
          _ip(request))
    return out


@app.post("/api/models/register-live")
def models_register_live(request: Request,
                         user: dict = Depends(auth.require_at_least("admin"))):
    out = model_registry.register_live(user["username"])
    audit(user["username"], "model_register_live", None,
          json.dumps({"registered": [m["id"] for m in out.get("registered", []) if m]},
                     ensure_ascii=False), _ip(request))
    return out


@app.get("/api/models/switches")
def models_switches(limit: int = Query(30, ge=1, le=200),
                    user: dict = Depends(auth.current_user)):
    return {"items": db.rows(
        "SELECT * FROM model_switches ORDER BY id DESC LIMIT ?", (limit,))}


@app.get("/api/models/{model_id}")
def model_detail(model_id: int, user: dict = Depends(auth.current_user)):
    m = model_registry.get_model(model_id)
    if not m:
        raise HTTPException(404, "模型不存在")
    return m


@app.patch("/api/models/{model_id}")
def model_patch(model_id: int, body: ModelPatchIn, request: Request,
                user: dict = Depends(auth.require_at_least("analyst"))):
    try:
        m = model_registry.patch_model(model_id, body.display_name, body.notes,
                                       user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "model_patch", f"model:{model_id}",
          json.dumps({"display_name": body.display_name is not None,
                      "notes": body.notes is not None}, ensure_ascii=False), _ip(request))
    return m


@app.get("/api/models/{model_id}/curve")
def model_curve_of(model_id: int, user: dict = Depends(auth.current_user)):
    m = model_registry.get_model(model_id)
    if not m:
        raise HTTPException(404, "模型不存在")
    if not m.get("curve_available"):
        raise HTTPException(404, "该模型没有学习曲线")
    p = model_registry._artifact_path(m.get("curve_path"))  # noqa: SLF001
    if not p or not p.exists():
        raise HTTPException(404, "曲线文件已被清理")
    return _read_json(p, {})


@app.post("/api/models/{model_id}/switch")
def model_switch_start(model_id: int, body: ModelSwitchIn, request: Request,
                       user: dict = Depends(auth.require_at_least("admin"))):
    try:
        out = model_switch.create_switch(model_id, user["username"])
    except ValueError as e:
        raise HTTPException(400, f"预检失败：{e}")
    audit(user["username"], "model_switch_start", f"model:{model_id}",
          json.dumps(out, ensure_ascii=False), _ip(request))
    threading.Thread(target=model_switch.run_switch_task,
                     args=(out["switch_id"], out["task_id"]), daemon=True).start()
    return {**out, "status": "queued",
            "restart_required_after": True,
            "hint": "切换成功后必须重启采集器，新模型才会生效"}


@app.post("/api/models/{model_id}/preflight")
def model_switch_preflight(model_id: int, user: dict = Depends(auth.current_user)):
    return model_switch.preflight(model_id)


@app.post("/api/models/rollback/{channel}")
def model_rollback(channel: str, request: Request,
                   user: dict = Depends(auth.require_at_least("admin"))):
    if channel not in model_registry.CHANNELS:
        raise HTTPException(400, f"channel 只支持 {model_registry.CHANNELS}")
    target = model_switch.rollback_target(channel)
    if not target:
        raise HTTPException(400, "没有可回滚的上一代现役模型")
    try:
        out = model_switch.create_switch(int(target["id"]), user["username"])
    except ValueError as e:
        raise HTTPException(400, f"预检失败：{e}")
    audit(user["username"], "model_rollback", f"channel:{channel}",
          json.dumps({**out, "target": target["id"]}, ensure_ascii=False), _ip(request))
    threading.Thread(target=model_switch.run_switch_task,
                     args=(out["switch_id"], out["task_id"]), daemon=True).start()
    return {**out, "target_model_id": target["id"], "status": "queued",
            "hint": "回滚同样走完整门禁；成功后必须重启采集器"}


@app.get("/api/models/curves/{name}")
def model_curve(name: str, user: dict = Depends(auth.current_user)):
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        raise HTTPException(400, "非法曲线名")
    p = config.CURVES / f"{name}.json"
    if not p.exists():
        raise HTTPException(404, "曲线不存在")
    return _read_json(p, {})


# --------------------------------------------------------------------------- 上传数据
@app.post("/api/uploads")
def upload_create(request: Request,
                  file: UploadFile = File(...),
                  name: str = Form(""),
                  role: str = Form("supervised"),
                  default_label: Optional[int] = Form(None),
                  source_note: str = Form(""),
                  user: dict = Depends(auth.require_at_least("analyst"))):
    cl = request.headers.get("content-length")
    if cl:
        try:
            if int(cl) > config.UPLOAD_MAX_BYTES + (1 << 20):
                raise HTTPException(413, f"文件超过上限 {config.UPLOAD_MAX_BYTES} 字节")
        except ValueError:
            pass
    try:
        row = uploads.create_from_stream(
            file.file, file.filename or "upload", name=name, role=role,
            default_label=default_label, source_note=source_note,
            actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "upload_create", f"upload:{row.get('id')}",
          json.dumps({"name": row.get("name"), "role": role,
                      "format": row.get("format"), "bytes": row.get("size_bytes")},
                     ensure_ascii=False), _ip(request))
    return row


@app.get("/api/uploads")
def upload_list(limit: int = Query(100, ge=1, le=500),
                include_pruned: bool = Query(False),
                user: dict = Depends(auth.current_user)):
    return {"items": uploads.list_uploads(limit, include_pruned)}


@app.get("/api/uploads/{uid}")
def upload_detail(uid: int, user: dict = Depends(auth.current_user)):
    row = uploads.get_upload(uid)
    if not row:
        raise HTTPException(404, "数据集不存在")
    return row


@app.get("/api/uploads/{uid}/preview")
def upload_preview(uid: int, n: int = Query(20, ge=1, le=200),
                   user: dict = Depends(auth.current_user)):
    try:
        return uploads.preview(uid, n)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.delete("/api/uploads/{uid}")
def upload_delete(uid: int, request: Request,
                  user: dict = Depends(auth.require_at_least("admin"))):
    try:
        row = uploads.delete_upload(uid, user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "upload_delete", f"upload:{uid}", None, _ip(request))
    return row


@app.post("/api/uploads/from-events")
def uploads_from_events(body: FromEventsIn, request: Request,
                        user: dict = Depends(auth.require_at_least("analyst"))):
    """从事件页选中的事件生成数据集（快照）。

    标签由操作者显式指定（`label`），**绝不**取事件的模型预测；审计里记录完整的
    选择条件与标签，便于日后追溯每个样本的标签来源。
    """
    try:
        row = datasets_events.create_from_events(
            name=body.name, role=body.role, label=body.label,
            source_note=body.source_note, mode=body.mode,
            event_ids=body.event_ids,
            filters=body.filters.model_dump(exclude_none=True) if body.filters else None,
            max_rows=body.max_rows, actor=user["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user["username"], "dataset_from_events", f"upload:{row.get('id')}",
          json.dumps({"name": row.get("name"), "role": body.role, "label": body.label,
                      "mode": body.mode,
                      "event_ids": (body.event_ids or [])[:50],
                      "filters": (body.filters.model_dump(exclude_none=True)
                                  if body.filters else None)},
                     ensure_ascii=False), _ip(request))
    return row


# --------------------------------------------------------------------------- 任务
def _validate_upload_plan(kind: str, data_mode: str, dataset_ids: Optional[List[int]],
                          calib_mode: str, calib_dataset_id: Optional[int]) -> dict:
    """校验上传数据选择；返回可直接写进任务 args 的清单（含服务端生成的路径）。"""
    ids = list(dict.fromkeys(int(i) for i in (dataset_ids or [])))
    if data_mode == "official":
        if ids:
            raise HTTPException(400, "data_mode=official 时不能指定 dataset_ids")
        return {"datasets": [], "calib_dataset_id": None, "calib_mode": "official"}
    if kind not in ("train_realdata", "iforest_csic", "iforest_local"):
        raise HTTPException(
            400, f"{kind} 不支持数据集（仅 train_realdata / iforest_csic / iforest_local）")
    if data_mode not in ("add", "only"):
        raise HTTPException(400, "data_mode 只支持 official / add / only")
    if not ids:
        raise HTTPException(400, "add/only 模式必须选择至少一个数据集")
    if calib_mode not in ("auto", "official", "upload"):
        raise HTTPException(400, "calib_mode 只支持 auto / official / upload")

    rows = []
    for uid in ids:
        ds = uploads.get_upload(uid)
        if not ds:
            raise HTTPException(400, f"数据集 #{uid} 不存在")
        if ds.get("status") != "ready":
            raise HTTPException(400, f"数据集 #{uid} 状态为 {ds.get('status')}，不可用")
        if ds.get("role") == "eval":
            raise HTTPException(400, f"数据集 #{uid} 角色是 eval，不能用于训练")
        if not ds.get("exists") or not ds.get("train_path"):
            raise HTTPException(400, f"数据集 #{uid} 文件缺失")
        stats = ds.get("stats") or {}
        labels = ds.get("label_stats") or {}
        benign = int(stats.get("benign") or labels.get("0") or 0)
        attack = int(stats.get("attack") or 0)
        if kind == "train_realdata" and ds["role"] == "benign":
            pass  # 良性数据可作为监督训练的困难负样本/校准池
        if kind != "train_realdata" and ds["role"] == "supervised" and benign == 0:
            raise HTTPException(400, f"数据集 #{uid} 没有良性样本，不能用于零日通道")
        rows.append({
            "id": ds["id"], "name": ds["name"], "role": ds["role"],
            "format": ds["format"], "sha256": ds.get("sha256"),
            "rows": int(ds.get("rows_kept") or 0), "benign": benign,
            "attack": attack, "label_counts": labels,
            "source_note": ds.get("source_note") or "",
            "requests_path": ds.get("requests_path"),
            "train_path": ds.get("train_path"),
        })

    # 标签/规模红线。
    if kind == "train_realdata":
        total_labels = {}
        for r in rows:
            for k, v in (r.get("label_counts") or {}).items():
                total_labels[k] = total_labels.get(k, 0) + int(v)
        present = [k for k, v in total_labels.items() if int(v) > 0]
        if data_mode == "only":
            if len(present) < 2:
                raise HTTPException(400, "only 模式的数据集至少要有 2 类标签（含正常）")
            if sum(total_labels.values()) < 500:
                raise HTTPException(400, "only 模式的数据集太少（<500 行），请用 add 或补充数据")
        elif not present:
            raise HTTPException(400, "数据集没有可用标签")
    else:
        benign = sum(int(r.get("benign") or 0) for r in rows)
        if benign < 50:
            raise HTTPException(400, f"零日通道需要良性样本，当前只有 {benign} 条")
        if data_mode == "only" and benign < 400:
            raise HTTPException(400, "only 模式零日训练需要 ≥400 条良性（切出 ≥200 条校准留出）")

    # 校准数据集：显式指定 > 良性最多。
    if calib_mode == "official":
        calib_dataset_id = None
    elif calib_dataset_id is None:
        calib_dataset_id = max(rows, key=lambda r: int(r.get("benign") or 0))["id"]
    else:
        calib_dataset_id = int(calib_dataset_id)
        if calib_dataset_id not in {int(r["id"]) for r in rows}:
            raise HTTPException(400, "calib_dataset_id 必须在 dataset_ids 里")
    if calib_mode == "upload":
        sel = next(r for r in rows if int(r["id"]) == int(calib_dataset_id))
        if int(sel.get("benign") or 0) < 400:
            raise HTTPException(400, "calib_mode=upload 要求校准数据集 ≥400 条良性")
    return {"datasets": rows, "calib_dataset_id": calib_dataset_id,
            "calib_mode": calib_mode}


def _task_plan(tid_hint: Optional[int], kind: str, inherit: Optional[str],
               parent_model_id: Optional[int], data_mode: Optional[str] = None,
               dataset_ids: Optional[List[int]] = None,
               calib_mode: Optional[str] = None,
               calib_dataset_id: Optional[int] = None) -> dict:
    """把白名单脚本 + 训练专用参数组装成可执行的 argv（不接受任意命令）。"""
    base = list(config.TASKS[kind])
    if kind not in config.TRAIN_CHANNELS:
        if dataset_ids or (data_mode and data_mode != "official"):
            raise HTTPException(400, f"{kind} 不支持数据集")
        return {"argv": base}
    channel, variant = config.TRAIN_CHANNELS[kind]
    settings = model_registry.get_settings()
    mode = inherit or settings.get("inherit_mode") or "lineage"
    if mode not in ("off", "lineage", "warm_start"):
        mode = "lineage"

    data_mode = data_mode or "official"
    calib_mode = calib_mode or "auto"
    up = _validate_upload_plan(kind, data_mode, dataset_ids, calib_mode, calib_dataset_id)
    if data_mode == "only":
        # only：官方训练集不参与，warm start 已无意义（分布也不一致）。
        mode = "lineage"

    staging = config.STAGING / f"task_{tid_hint if tid_hint is not None else 'x'}"
    plan: dict = {"channel": channel, "variant": variant, "inherit_mode": mode,
                  "staging": str(staging), "data_mode": data_mode,
                  "datasets": up["datasets"], "calib_dataset_id": up["calib_dataset_id"],
                  "calib_mode": up["calib_mode"],
                  "register": {"kind": kind, "variant": variant,
                               "parent_id": None, "inherit_mode": mode}}
    if kind == "train_realdata":
        if data_mode == "only":
            # 去掉官方困难负样本，只保留上传数据。
            for i in range(len(base) - 1, -1, -1):
                if base[i] == "--hard-neg":
                    del base[i:i + 2]
                    break
        base += ["--out-dir", str(staging), "--artifact-name", "model.onnx"]
    else:
        if data_mode == "only":
            base = ["iforest_lean_onnx.py", "--data", "upload", "--export"]
        base += ["--out-dir", str(staging), "--onnx-name", "model.onnx"]

    # `--data local` 需要本地良性基线文件。add 模式下用选中的良性数据集当基线
    # （快照闭环，不依赖磁盘上的默认文件）；其余数据集仍走 manifest 增量。
    # 基线会同时出现两次（--benign 与 manifest），所以必须让脚本把它从 manifest 里跳过，
    # 否则训练集与校准留出会重叠。
    use_manifest = data_mode in ("add", "only")
    if kind == "iforest_local" and data_mode == "add":
        base_ds = next((r for r in up["datasets"] if int(r.get("benign") or 0) > 0), None)
        if base_ds is None:
            raise HTTPException(
                400, "iforest_local（add）需要至少一个含良性样本的数据集作为本地基线")
        base += ["--benign", base_ds["train_path"]]
        plan["baseline_dataset"] = {
            "id": base_ds["id"], "name": base_ds["name"],
            "train_path": base_ds["train_path"], "benign": base_ds["benign"]}
        others = [r for r in up["datasets"]
                  if int(r["id"]) != int(base_ds["id"]) and int(r.get("benign") or 0) > 0]
        if others:
            base += ["--upload-skip-id", str(base_ds["id"])]
        else:
            # 只有基线一个数据集：没有可增量的良性行，manifest 会因"没有良性行"报错。
            use_manifest = False
            plan["upload_manifest_skipped"] = "只有基线数据集，无需增量清单"
    elif kind == "iforest_local" and data_mode == "official":
        # `--data local` 必须给 --benign；官方模式用本机采集产出的默认良性池，
        # 文件不存在就明确拒绝（而不是让脚本抛 SystemExit）。
        p = config.LOCAL_DIR / "local_lab_benign.jsonl"
        if not p.exists():
            raise HTTPException(
                400, "iforest_local 需要本地良性基线：请改用数据集（add/only），"
                     f"或先跑 collect_http_log.py 产出 {p}")
        base += ["--benign", str(p)]
        plan["baseline_dataset"] = {"id": None, "name": "内置本地良性池",
                                    "train_path": str(p), "benign": None}

    if use_manifest:
        manifest = str(staging / "datasets.json")
        base += ["--upload-manifest", manifest, "--upload-mode", data_mode,
                 "--calib-mode", up["calib_mode"]]
        if up["calib_dataset_id"] is not None:
            base += ["--calib-dataset-id", str(up["calib_dataset_id"])]

    parent = None
    if variant == "official" and mode == "warm_start":
        try:
            parent = model_registry.resolve_parent(channel, parent_model_id)
        except ValueError as e:
            plan["parent_error"] = str(e)
            parent = None
        if parent is None:
            mode = "lineage"
            plan["inherit_mode"] = mode
            plan["register"]["inherit_mode"] = mode
            plan["parent_fallback"] = "没有可继承的父代，降级为 lineage（只记血缘）"
    elif parent_model_id is not None:
        try:
            parent = model_registry.resolve_parent(channel, parent_model_id)
        except ValueError:
            parent = None

    if parent:
        paths = model_registry.parent_paths(parent)
        plan["register"]["parent_id"] = int(parent["id"])
        if mode == "warm_start":
            if channel == "supervised" and "xgb_model.json" in paths:
                base += ["--parent-model", paths["xgb_model.json"]]
                if "xgboost_meta.json" in paths:
                    base += ["--parent-meta", paths["xgboost_meta.json"]]
            elif channel == "zero_day" and "iforest_model.joblib" in paths:
                # IForest warm start 要求目标树数 > 父代树数，否则不会新增树。
                # 官方 CSIC IF 默认 100 棵；每代 +25，超过 400 则降级为全量重训。
                pmetrics = parent.get("metrics") or {}
                pbase = pmetrics.get("trees") or (parent.get("recipe") or {}).get("total_trees")
                try:
                    pbase = int(pbase) if pbase is not None else None
                except (TypeError, ValueError):
                    pbase = None
                if pbase is None:
                    base += ["--parent-model", paths["iforest_model.joblib"]]
                elif pbase + 25 <= 400:
                    target = max(100, pbase + 25)
                    base += ["--parent-model", paths["iforest_model.joblib"],
                             "--trees", str(target)]
                    plan["iforest_trees"] = target
                else:
                    plan["parent_fallback"] = (
                        f"父代已有 {pbase} 棵树，继续追加会无界增长；降级为全量重训")
                    plan["register"]["inherit_mode"] = "lineage"
            else:
                plan["parent_fallback"] = "父代缺少可继承训练件，降级为 lineage"
                plan["register"]["inherit_mode"] = "lineage"
    plan["argv"] = base
    return plan


def _parse_task_args(raw) -> dict:
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if isinstance(doc, list):          # 旧任务行
        return {"argv": doc}
    return doc if isinstance(doc, dict) else {}


def _run_task(tid: int, kind: str) -> None:
    row = db.one("SELECT args FROM tasks WHERE id=?", (tid,))
    plan = _parse_task_args(row["args"] if row else None)
    argv = plan.get("argv") or list(config.TASKS.get(kind, []))
    cmd = [sys.executable] + [str(a) for a in argv]
    log = config.LOG_DIR / f"task_{tid}.log"
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    db.execute("UPDATE tasks SET status='running', started_at=?, log_path=? WHERE id=?",
               (db.now_ms(), str(log), tid))
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    rc = -1
    staging = plan.get("staging")
    if staging:
        Path(staging).mkdir(parents=True, exist_ok=True)
        if (plan.get("datasets") is not None and plan.get("data_mode") in ("add", "only")
                and not plan.get("upload_manifest_skipped")):
            man = {"mode": plan.get("data_mode"), "datasets": plan.get("datasets") or [],
                   "calib_mode": plan.get("calib_mode"),
                   "calib_dataset_id": plan.get("calib_dataset_id")}
            (Path(staging) / "datasets.json").write_text(
                json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        with open(log, "w", encoding="utf-8") as lf:
            lf.write(f"[task] {' '.join(cmd)}\n")
            rc = subprocess.call(cmd, cwd=str(config.PY), stdout=lf,
                                 stderr=subprocess.STDOUT, env=env)
    except Exception as e:  # noqa: BLE001
        with open(log, "a", encoding="utf-8") as lf:
            lf.write(f"\n[task] 启动失败：{e}\n")

    status = "ok" if rc == 0 else "failed"
    # 训练成功后登记为新一代（默认开启；失败/关闭时保留 staging 供排查）。
    reg_plan = plan.get("register")
    if rc == 0 and reg_plan and staging and model_registry.get_settings().get("auto_register"):
        try:
            m = model_registry.register_from_staging(
                tid, reg_plan["kind"], f"task:{tid}", staging,
                parent_id=reg_plan.get("parent_id"),
                inherit_mode=reg_plan.get("inherit_mode", "full"),
                variant=reg_plan.get("variant"))
            with open(log, "a", encoding="utf-8") as lf:
                lf.write(f"\n[task] 已登记模型：{m['display_name']} id={m['id']}"
                         f" gen={m['generation']} sha={m['sha1_16']}\n" if m else
                         "\n[task] 未登记模型（staging 缺产物）。staging 保留供排查。\n")
        except Exception as e:  # noqa: BLE001
            with open(log, "a", encoding="utf-8") as lf:
                lf.write(f"\n[task] 登记模型失败：{e}（staging 保留）\n")
            status = "failed"

    db.execute("UPDATE tasks SET status=?, ended_at=?, exit_code=? WHERE id=?",
               (status, db.now_ms(), rc, tid))


@app.post("/api/tasks")
def create_task(body: TaskIn, request: Request,
                user: dict = Depends(auth.require_at_least("admin"))):
    if body.kind not in config.TASKS:
        raise HTTPException(400, f"kind 只支持 {sorted(config.TASKS)}")
    tid = db.execute(
        "INSERT INTO tasks(kind, args, status, created_at, actor) VALUES(?,?,?,?,?)",
        (body.kind, "{}", "queued", db.now_ms(), user["username"]),
    )
    try:
        plan = _task_plan(tid, body.kind, body.inherit, body.parent_model_id,
                          body.data_mode, body.dataset_ids, body.calib_mode,
                          body.calib_dataset_id)
    except HTTPException:
        db.execute("UPDATE tasks SET status='failed', ended_at=?, exit_code=? WHERE id=?",
                   (db.now_ms(), -2, tid))
        raise
    db.execute("UPDATE tasks SET args=? WHERE id=?",
               (json.dumps(plan, ensure_ascii=False), tid))
    audit(user["username"], "task_create", body.kind, f"task:{tid}", _ip(request))
    threading.Thread(target=_run_task, args=(tid, body.kind), daemon=True).start()
    resp = {"id": tid, "kind": body.kind, "status": "queued"}
    if plan.get("register"):
        resp["inherit_mode"] = plan["register"].get("inherit_mode")
        resp["parent_id"] = plan["register"].get("parent_id")
        resp["parent_fallback"] = plan.get("parent_fallback")
        resp["staging"] = plan.get("staging")
    return resp


@app.get("/api/tasks")
def list_tasks(limit: int = Query(50, ge=1, le=200), user: dict = Depends(auth.current_user)):
    return {"items": db.rows(
        "SELECT id, kind, args, status, log_path, created_at, started_at, ended_at, exit_code, actor "
        "FROM tasks ORDER BY id DESC LIMIT ?", (limit,),
    )}


@app.get("/api/tasks/{tid}")
def get_task(tid: int, user: dict = Depends(auth.current_user)):
    t = db.one("SELECT * FROM tasks WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404, "任务不存在")
    return t


@app.get("/api/tasks/{tid}/log")
def task_log(tid: int, tail: int = Query(200, ge=1, le=2000),
             user: dict = Depends(auth.current_user)):
    t = db.one("SELECT log_path, status FROM tasks WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404, "任务不存在")
    p = Path(t["log_path"]) if t.get("log_path") else None
    if not p or not p.exists():
        return {"status": t["status"], "log": ""}
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    return {"status": t["status"], "log": "\n".join(lines[-tail:])}


# --------------------------------------------------------------------------- 采集面 / 健康
@app.get("/api/collector/status")
def collector_status(user: dict = Depends(auth.current_user)):
    m = _collector_metrics()
    if not m:
        return {
            "available": False,
            "path": str(config.COLLECTOR_METRICS),
            "hint": "启动采集器时加 --stats-out <file>，并把路径配到 WAF_COLLECTOR_METRICS。",
        }
    pol = _policy()
    # `**m` 保持向后兼容（顶层仍是采集器原始指标）；`reload_view` 是控制台的解释层：
    # 「磁盘上的策略/规则」vs「采集器实际在用的」，以及是否需要重启。
    return {**m, "reload_view": _reload_view(pol, m), "policy_revision": pol.get("version")}


# --------------------------------------------------------------------------- 采集代理管理
def _proxy_http_error(e: Exception) -> HTTPException:
    return HTTPException(getattr(e, "status", 400), str(e))


@app.get("/api/proxy/status")
def proxy_status(user: dict = Depends(auth.current_user)):
    return proxy_manager.status()


@app.get("/api/proxy/config")
def proxy_config(user: dict = Depends(auth.current_user)):
    return proxy_manager.config_view()


@app.put("/api/proxy/config")
def proxy_config_update(body: dict, request: Request,
                        user: dict = Depends(auth.require_at_least("admin"))):
    try:
        return proxy_manager.update_config(body, user["username"], _ip(request))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/proxy/start")
def proxy_start(request: Request,
                user: dict = Depends(auth.require_at_least("admin"))):
    try:
        return proxy_manager.start(user["username"], _ip(request))
    except proxy_manager.ProxyError as e:
        raise _proxy_http_error(e)


@app.post("/api/proxy/stop")
def proxy_stop(request: Request, body: Optional[dict] = None,
               user: dict = Depends(auth.require_at_least("admin"))):
    force = bool((body or {}).get("force"))
    try:
        return proxy_manager.stop(user["username"], force=force, ip=_ip(request))
    except proxy_manager.ProxyError as e:
        raise _proxy_http_error(e)


@app.post("/api/proxy/restart")
def proxy_restart(request: Request,
                  user: dict = Depends(auth.require_at_least("admin"))):
    try:
        return proxy_manager.restart(user["username"], _ip(request))
    except proxy_manager.ProxyError as e:
        raise _proxy_http_error(e)


@app.get("/api/proxy/log")
def proxy_log(tail: int = Query(200, ge=1, le=2000),
              user: dict = Depends(auth.require_at_least("analyst"))):
    return proxy_manager.tail_log(tail)


@app.post("/api/ingest/scan")
def ingest_scan(body: IngestIn, request: Request,
                user: dict = Depends(auth.require_at_least("analyst"))):
    st = ingest_mod.ingest(with_body=body.with_body)
    audit(user["username"], "ingest_scan", None, json.dumps(st, ensure_ascii=False), _ip(request))
    return st


@app.get("/api/ingest/state")
def ingest_get_state(user: dict = Depends(auth.current_user)):
    return ingest_mod.ingest_state()


@app.get("/api/health/degradation")
def degradation(user: dict = Depends(auth.current_user)):
    pol = _policy()
    m = _collector_metrics()
    return {
        "zero_day_enabled": pol.get("zero_day_enabled"),
        "zero_day_threshold": (pol.get("zero_day") or {}).get("threshold"),
        "supervised_threshold": (pol.get("supervised") or {}).get("threshold"),
        "mode": _mode_from_metrics(m),
        "enforce": _mode_from_metrics(m) == "enforce",
        "collector": m,
        "warnings": _warnings(pol, m),
    }


@app.get("/api/audit")
def get_audit(limit: int = Query(200, ge=1, le=1000),
              user: dict = Depends(auth.require_at_least("admin"))):
    return {"items": db.rows(
        "SELECT id, ts, actor, action, target, detail, ip FROM audit ORDER BY id DESC LIMIT ?",
        (limit,),
    )}


@app.get("/api/audit/retention")
def audit_retention_preview(days: Optional[int] = Query(None, ge=1, le=3650),
                            user: dict = Depends(auth.require_at_least("admin"))):
    try:
        return audit_retention.preview(days)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/audit/retention")
def audit_retention_apply(body: AuditRetentionIn, request: Request,
                          user: dict = Depends(auth.require_at_least("admin"))):
    if not body.confirm:
        raise HTTPException(400, "confirm=true 才执行审计清理")
    try:
        return audit_retention.cleanup(
            days=body.days, actor=user["username"], ip=_ip(request), trigger="manual")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:  # noqa: BLE001 - 已尽力写 audit_cleanup_failed
        raise HTTPException(500, f"审计清理失败：{type(e).__name__}: {e}")


@app.post("/api/audit/delete")
def audit_delete_selected(body: AuditDeleteIn, request: Request,
                          user: dict = Depends(auth.require_at_least("admin"))):
    if not body.confirm:
        raise HTTPException(400, "confirm=true 才删除审计记录")
    try:
        return audit_retention.delete_selected(
            body.ids, actor=user["username"], ip=_ip(request),
            reason=body.reason or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"删除审计记录失败：{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- 90 天 raw 清理
@app.get("/api/retention/raw-cleanup")
def raw_cleanup_dry_run(request: Request, days: Optional[int] = Query(None, ge=1, le=3650),
                        user: dict = Depends(auth.require_at_least("admin"))):
    st = retention.dry_run(days)
    audit(user["username"], "raw_cleanup_dry_run", None,
          json.dumps({"days": days, "cutoff_ms": st.get("cutoff_ms")}, ensure_ascii=False),
          _ip(request))
    return st


@app.post("/api/retention/raw-cleanup")
def raw_cleanup_apply(body: RawCleanupIn, request: Request,
                      user: dict = Depends(auth.require_at_least("admin"))):
    if not body.confirm:
        raise HTTPException(400, "必须显式 confirm=true 才执行清理")
    # fail-closed 意图审计：先落审计，再执行不可逆的 DB/文件删除。
    audit(user["username"], "raw_cleanup_apply_intent", None,
          json.dumps({"days": body.days, "note": body.note}, ensure_ascii=False),
          _ip(request))
    st = retention.apply(body.days)
    audit(user["username"], "raw_cleanup_apply", None,
          json.dumps({"days": body.days, "note": body.note,
                      "stats": st}, ensure_ascii=False), _ip(request))
    return st


@app.get("/api/retention/raw-cleanup/pending")
def raw_cleanup_pending(request: Request,
                        user: dict = Depends(auth.require_at_least("admin"))):
    items = retention.pending_rows()
    audit(user["username"], "view_raw_cleanup_pending", None,
          json.dumps({"n": len(items)}, ensure_ascii=False), _ip(request))
    return {"items": items, "counts": retention.counts()}


@app.get("/api/retention/raw-cleanup/scheduled")
def raw_cleanup_scheduled(request: Request,
                          user: dict = Depends(auth.require_at_least("admin"))):
    """最近一次内置 dry-run 快照；它永不自动 apply。"""
    doc = retention_scheduler.load_snapshot()
    audit(user["username"], "view_raw_cleanup_scheduled", None,
          json.dumps({"available": bool(doc),
                      "generated_at": (doc or {}).get("generated_at")},
                     ensure_ascii=False), _ip(request))
    return {"available": bool(doc), "snapshot": doc,
            "enabled": config.RETENTION_SCHEDULER_ENABLED,
            "interval_sec": config.RETENTION_CHECK_INTERVAL_SEC}


@app.post("/api/retention/raw-cleanup/pending/resolve")
def raw_cleanup_resolve(body: RawCleanupResolveIn, request: Request,
                        user: dict = Depends(auth.require_at_least("admin"))):
    if not body.confirm:
        raise HTTPException(400, "必须显式 confirm=true 才执行恢复动作")
    if body.action not in ("retry", "adopt", "forget"):
        raise HTTPException(400, "action 只支持 retry|adopt|forget")
    try:
        def _audit_before(result: dict) -> None:
            # 在 retention 写入前落审计；审计失败则动作不提交。
            audit(user["username"], "raw_cleanup_action", body.path,
                  json.dumps({"action": body.action, "note": body.note,
                              "result": result}, ensure_ascii=False), _ip(request))
        result = retention.resolve(body.path, body.action, body.note,
                                   before_commit=_audit_before)
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "result": result}


# --------------------------------------------------------------------------- 静态前端
WEB_DIST = config.ROOT / "web" / "dist"
if WEB_DIST.exists():
    if (WEB_DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(WEB_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "not found")
        f = (WEB_DIST / full_path).resolve()
        try:
            f.relative_to(WEB_DIST.resolve())
        except ValueError:
            raise HTTPException(404, "not found")
        if f.is_file():
            return FileResponse(f)
        return FileResponse(WEB_DIST / "index.html")
else:
    @app.get("/")
    def root():
        return {
            "ok": True,
            "hint": "前端未构建。开发：cd web && npm run dev（5173）；生产：npm run build 后再起本服务。",
            "docs": "/docs",
        }
