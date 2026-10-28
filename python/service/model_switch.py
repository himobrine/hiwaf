"""切换现役模型 / 回滚的编排。

## 为什么需要这一层

训练产物先落在 `artifacts/staging/`，**不能**直接覆盖数据面的固定槽位文件 ——
否则「训练中途失败」就等于「线上的模型被半成品替换」。本模块做的是：

    备份现役 → 目标快照写入固定槽位 → 重标定阈值 → 重出 testvec / shap_ref
    → `waf-ai-proto` 门禁 → 更新登记表；任一步失败则**全量回滚**。

关键约束（红线）：
  * 目标文件只能来自已登记的模型快照，不接受任意路径；
  * 门禁失败即回滚，**没有**绕开门禁的快速恢复通道；
  * 切换只改文件内容，槽位名不变，采集器靠内容 sha1 判断「策略 vs 内存模型」是否同源。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from . import config, db, model_registry as reg, toolchain

#: 切换要备份/回滚的现役文件（相对 artifacts）。
_LIVE_FILES: Dict[str, List[str]] = {
    "supervised": ["xgboost_v20261015_001.onnx", "xgboost_meta.json",
                   "xgb_model.json", "xgb_trees.json"],
    "zero_day": ["iforest_lean_v20261015_001.onnx", "iforest_meta.json",
                 "iforest_model.joblib"],
}
#: 与模型同源、切换时必须一起重算/回滚的公共产物。
_SHARED_FILES = ["decision_policy.json", "testvec.json", "shap_ref.json"]


def _now() -> int:
    return db.now_ms()


def _log(fp, msg: str) -> None:
    fp.write(msg.rstrip() + "\n")
    fp.flush()


def _run(cmd: List[str], fp, *, timeout: int = 7200,
         cwd: Optional[str] = None) -> int:
    _log(fp, f"\n$ {' '.join(str(c) for c in cmd)}")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True,
                           encoding="utf-8", errors="replace",
                           env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        _log(fp, f"[switch] 超时（>{timeout}s）")
        return 124
    except Exception as e:  # noqa: BLE001
        _log(fp, f"[switch] 启动失败：{e}")
        return 127
    if p.stdout:
        fp.write(p.stdout)
        if not p.stdout.endswith("\n"):
            fp.write("\n")
    fp.flush()
    _log(fp, f"[switch] exit={p.returncode}")
    return int(p.returncode)


# --------------------------------------------------------------------------- 备份
def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + f".tmp{os.getpid()}")
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)


def _backup(files: List[str], dest: Path) -> List[str]:
    dest.mkdir(parents=True, exist_ok=True)
    saved: List[str] = []
    for name in files:
        src = config.ARTIFACTS / name
        if not src.exists():
            continue
        _copy(src, dest / Path(name).name)
        saved.append(name)
    (dest / "manifest.json").write_text(
        json.dumps({"files": saved, "restored": False}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    return saved


def _restore(dest: Path, fp) -> None:
    man = dest / "manifest.json"
    if not man.exists():
        _log(fp, "[switch] 无备份清单，跳过回滚")
        return
    saved = json.loads(man.read_text(encoding="utf-8")).get("files") or []
    for name in saved:
        b = dest / Path(name).name
        if b.exists():
            _copy(b, config.ARTIFACTS / name)
            _log(fp, f"[switch] 回滚 {name}")
    doc = json.loads(man.read_text(encoding="utf-8"))
    doc["restored"] = True
    man.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- 预检
def _map_pool(source: str) -> str:
    if source.startswith("file:"):
        return source
    if "csic" in source:
        return "csic"
    if "lexical" in source:
        return "lexical"
    return "csic"


def _snapshot_files(model: dict) -> Dict[str, str]:
    """快照文件 -> 现役槽位名。返回目标文件名到源路径的映射。"""
    snap = reg._artifact_path(model.get("snapshot_dir"))  # noqa: SLF001
    if not snap:
        return {}
    ch = model["channel"]
    live = config.LIVE_SLOTS[ch]
    out: Dict[str, str] = {}
    onnx = snap / "model.onnx"
    if onnx.exists():
        out[live["onnx"]] = str(onnx)
    meta = snap / live["meta"]
    if meta.exists():
        out[live["meta"]] = str(meta)
    if ch == "supervised":
        for name in ("xgb_model.json", "xgb_trees.json"):
            p = snap / name
            if p.exists():
                out[name] = str(p)
    else:
        p = snap / "iforest_model.joblib"
        if p.exists():
            out[live["model_json"]] = str(p)
    return out


def preflight(model_id: int) -> dict:
    checks: List[dict] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    model = reg._row_to_model(db.one(  # noqa: SLF001
        "SELECT * FROM model_registry WHERE id=?", (model_id,)))
    add("模型存在", model is not None, "model_registry 无此行" if not model else "")
    if not model:
        return {"ok": False, "checks": checks, "model": None}

    add("未被保留策略清理", model.get("status") != "pruned",
        "模型元数据仍在，但文件快照已删除" if model.get("status") == "pruned" else "")
    add("快照可用", bool(model.get("snapshot_available")), str(model.get("snapshot_dir")))
    files = _snapshot_files(model)
    ch = model["channel"]
    add("ONNX 就位", config.LIVE_SLOTS[ch]["onnx"] in files, ",".join(sorted(files)))
    add("meta 就位", config.LIVE_SLOTS[ch]["meta"] in files,
        "缺 meta 无法写出策略" if config.LIVE_SLOTS[ch]["meta"] not in files else "")
    if ch == "supervised":
        has_xgb = "xgb_model.json" in files
        add("训练件 xgb_model.json", has_xgb,
            "" if has_xgb else "缺 xgb_model.json，无法重出 testvec / shap_ref")
    else:
        has_joblib = config.LIVE_SLOTS[ch]["model_json"] in files
        # joblib 只用于 warm start，切换/回滚只需要 ONNX + meta；老产物没有它，
        # 不能因此把「回滚到上一代」也堵死，所以这里只做提示不做阻断。
        add("warm start 训练件 iforest_model.joblib（可选）", True,
            "" if has_joblib else "缺 sklearn joblib：不影响切换，但该代无法再 warm start")

    # 上传数据训练的模型：meta 声明了校准池就必须可用，否则阈值会退回旧池。
    up = _model_upload_files(model)
    if up.get("calib_pool"):
        ok = Path(up["calib_pool"]).exists() and int(up.get("calib_n") or 0) >= 200
        add("上传校准池可用", ok,
            f"{up.get('calib_pool')} (n={up.get('calib_n')})" if ok
            else "meta 声明了上传校准池但文件缺失或不足 200 条")
    if up.get("train_keys"):
        add("上传训练指纹可用", Path(up["train_keys"]).exists(), up["train_keys"])

    # 特征维度一致性
    fnames = reg._read_json(config.FEATURE_NAMES, {}) or {}  # noqa: SLF001
    cur_dim = len(fnames.get("names") or fnames.get("feature_names") or [])
    md = model.get("feature_dim")
    add("特征维度一致", (not cur_dim or not md or int(md) == cur_dim),
        f"模型 {md} vs 当前 {cur_dim}" if (cur_dim and md) else "缺记录，跳过")

    # 并发保护
    busy = db.one("SELECT id FROM model_switches WHERE status IN ('queued','running') LIMIT 1")
    add("无进行中的切换", busy is None, f"switch#{busy['id']} 正在进行" if busy else "")
    train = db.one("SELECT id FROM tasks WHERE status IN ('queued','running') LIMIT 1")
    add("无进行中的任务", train is None, f"task#{train['id']} 正在进行" if train else "")

    # 门禁二进制
    pb = toolchain.find_proto()
    add("waf-ai-proto 可用", pb is not None,
        "找不到 Rust 门禁二进制；切换会失败关闭（fail-closed）" if pb is None else str(pb))

    return {"ok": all(c["ok"] for c in checks), "checks": checks,
            "model": model, "files": files}


# --------------------------------------------------------------------------- 编排
def create_switch(model_id: int, actor: str) -> Dict[str, int]:
    pf = preflight(model_id)
    if not pf["ok"]:
        bad = [c for c in pf["checks"] if not c["ok"]]
        raise ValueError("；".join(f"{c['name']}：{c['detail']}" for c in bad) or "预检失败")
    model = pf["model"]
    ch = model["channel"]
    old = db.one("SELECT id FROM model_registry WHERE channel=? AND status='active' LIMIT 1", (ch,))
    sw = db.execute(
        "INSERT INTO model_switches(channel, model_id, from_model_id, status, actor, created_at)"
        " VALUES(?,?,?,?,?,?)",
        (ch, model_id, old["id"] if old else None, "queued", actor, _now()),
    )
    tid = db.execute(
        "INSERT INTO tasks(kind, args, status, created_at, actor) VALUES(?,?,?,?,?)",
        ("switch_model", json.dumps({"switch_id": sw, "model_id": model_id}, ensure_ascii=False),
         "queued", _now(), actor),
    )
    db.execute("UPDATE model_switches SET task_id=? WHERE id=?", (tid, sw))
    db.execute("INSERT INTO audit(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
               (_now(), actor, "model_switch_create", f"model:{model_id}",
                json.dumps({"switch_id": sw, "task_id": tid, "channel": ch},
                           ensure_ascii=False)))
    return {"switch_id": sw, "task_id": tid}


def _model_upload_files(model: dict) -> dict:
    """目标模型 meta 里声明的上传校准池 / 训练指纹（绝对路径）。"""
    mp = reg._artifact_path(model.get("meta_path"))  # noqa: SLF001
    if not mp or not mp.exists():
        return {}
    meta = reg._read_json(mp, {}) or {}  # noqa: SLF001
    up = meta.get("upload") or {}
    calib = up.get("calib") or {}
    out = {}
    rel = calib.get("file")
    if rel:
        p = (mp.parent / rel).resolve()
        out["calib_pool"] = str(p)
        out["calib_n"] = int(calib.get("n") or 0)
        out["calib_source"] = calib.get("source")
    rel = meta.get("training_keys_file")
    if rel:
        p = (mp.parent / rel).resolve()
        out["train_keys"] = str(p)
    return out


def _threshold_args(policy: dict, model: Optional[dict] = None) -> List[str]:
    pool_src = ((policy.get("calibration_pool") or {}).get("source")
                or "csic-holdout")
    pool = _map_pool(str(pool_src))
    upload = _model_upload_files(model) if model else {}
    if upload.get("calib_pool") and Path(upload["calib_pool"]).exists():
        pool = f"file:{upload['calib_pool']}"
    rules = policy.get("rules") or {}
    fpr = rules.get("nominal_target_fpr")
    if not fpr:
        fpr = (policy.get("supervised") or {}).get("target_fpr") or "0.01"
    fpr = str(fpr)
    if fpr not in ("0.001", "0.01", "0.03"):
        fpr = "0.01"
    zd = "on" if policy.get("zero_day_enabled") else "off"
    args = ["--pool", pool, "--fpr", fpr, "--zero-day", zd,
            "--no-testvec", "--out", str(config.POLICY_JSON)]
    if upload.get("train_keys") and Path(upload["train_keys"]).exists():
        args += ["--train-keys", upload["train_keys"]]
    if rules.get("enabled"):
        rp = rules.get("ruleset_path") or "artifacts/rules_authoritative.json"
        args += ["--rules", rp]
    else:
        args += ["--no-rules"]
    return args


def run_switch_task(switch_id: int, task_id: int) -> None:
    log = config.LOG_DIR / f"switch_{switch_id}.log"
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    db.execute("UPDATE tasks SET status='running', started_at=?, log_path=? WHERE id=?",
               (_now(), str(log), task_id))
    db.execute("UPDATE model_switches SET status='running', started_at=?, log_path=? WHERE id=?",
               (_now(), str(log), switch_id))
    try:
        with open(log, "w", encoding="utf-8") as fp:
            result = run_switch(switch_id, fp)
        rc = 0 if result.get("ok") else 1
    except Exception as e:  # noqa: BLE001
        with open(log, "a", encoding="utf-8") as fp:
            _log(fp, f"[switch] 未捕获异常：{e!r}")
        db.execute("UPDATE model_switches SET status='failed', error=?, ended_at=? WHERE id=?",
                   (repr(e), _now(), switch_id))
        rc = 1
    db.execute("UPDATE tasks SET status=?, ended_at=?, exit_code=? WHERE id=?",
               ("ok" if rc == 0 else "failed", _now(), rc, task_id))


def run_switch(switch_id: int, fp) -> dict:
    sw = db.one("SELECT * FROM model_switches WHERE id=?", (switch_id,))
    if not sw:
        return {"ok": False, "error": "切换记录不存在"}
    model = reg._row_to_model(db.one(  # noqa: SLF001
        "SELECT * FROM model_registry WHERE id=?", (int(sw["model_id"]),)))
    if not model:
        return _fail(switch_id, fp, "目标模型不存在")

    ch = sw["channel"]
    files = _snapshot_files(model)
    pol_before = reg._read_json(config.POLICY_JSON, {}) or {}  # noqa: SLF001
    _log(fp, f"[switch] 目标：{model['display_name']} (id={model['id']} gen={model['generation']}"
            f" sha={model['sha1_16']})  通道={ch}")
    _log(fp, f"[switch] 目标文件：{sorted(files)}")

    backup_dir = config.SWITCH_BACKUP / f"switch_{switch_id}"
    shared = _LIVE_FILES[ch] + _SHARED_FILES
    saved = _backup(shared, backup_dir)
    db.execute("UPDATE model_switches SET backup_dir=? WHERE id=?",
               (str(backup_dir), switch_id))
    _log(fp, f"[switch] 已备份 {len(saved)} 个现役文件 -> {backup_dir}")

    # ---- 1) 写入固定槽位 ----
    for name, src in files.items():
        _copy(Path(src), config.ARTIFACTS / name)
        _log(fp, f"[switch] live {name} <- {src}")

    # ---- 2) 重标定阈值 ----
    if _run([sys.executable, str(config.PY / "thresholds.py"), *_threshold_args(pol_before, model)],
            fp, cwd=str(config.PY)) != 0:
        return _fail(switch_id, fp, "thresholds.py 失败", backup_dir)

    # ---- 3) testvec / shap_ref ----
    if _run([sys.executable, str(config.PY / "export_testvec.py")], fp,
            cwd=str(config.PY)) != 0:
        return _fail(switch_id, fp, "export_testvec.py 失败", backup_dir)
    if ch == "supervised":
        if _run([sys.executable, str(config.PY / "export_shap_ref.py")], fp,
                cwd=str(config.PY)) != 0:
            return _fail(switch_id, fp, "export_shap_ref.py 失败（监督通道）", backup_dir)

    # ---- 4) 门禁（fail-closed）----
    pb = toolchain.find_proto()
    if pb is None:
        return _fail(switch_id, fp, "找不到 waf-ai-proto 门禁二进制（fail-closed）", backup_dir)
    if _run([str(pb)], fp, cwd=str(config.ROOT / "rust")) != 0:
        return _fail(switch_id, fp, "waf-ai-proto 门禁未通过", backup_dir)

    # ---- 5) 提交登记状态 ----
    pol_after = reg._read_json(config.POLICY_JSON, {}) or {}  # noqa: SLF001
    now = _now()
    db.execute("UPDATE model_registry SET status='archived', retired_at=?, updated_at=? "
               "WHERE channel=? AND status='active' AND id<>?",
               (now, now, ch, model["id"]))
    db.execute("UPDATE model_registry SET status='active', activated_at=?, updated_at=? "
               "WHERE id=?", (now, now, model["id"]))
    db.execute("UPDATE model_switches SET status='ok', ended_at=?, policy_version_before=?, "
               "policy_version_after=?, error=NULL WHERE id=?",
               (now, pol_before.get("version"), pol_after.get("version"), switch_id))
    db.execute("INSERT INTO policy_versions(version, json, actor, created_at, note) "
               "VALUES(?,?,?,?,?)",
               (int(pol_after.get("version") or 1), json.dumps(pol_after, ensure_ascii=False),
                str(sw.get("actor") or "system"), now,
                f"切换现役模型 model:{model['id']}"))
    db.execute("INSERT INTO audit(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
               (now, str(sw.get("actor") or "system"), "model_switch_ok", f"model:{model['id']}",
                json.dumps({"switch_id": switch_id, "channel": ch,
                            "policy_before": pol_before.get("version"),
                            "policy_after": pol_after.get("version")}, ensure_ascii=False)))
    _log(fp, f"[switch] 成功：policy v{pol_before.get('version')} -> v{pol_after.get('version')}")
    _log(fp, "[switch] ⚠️ 采集器仍在用旧模型，必须重启后新模型才生效"
             "（控制台会显示 pending_restart）")
    return {"ok": True, "switch_id": switch_id, "model_id": model["id"],
            "policy_version": pol_after.get("version"), "restart_required": True}


def _fail(switch_id: int, fp, error: str, backup_dir: Optional[Path] = None) -> dict:
    _log(fp, f"[switch] 失败：{error} —— 开始回滚")
    if backup_dir is not None and backup_dir.exists():
        _restore(backup_dir, fp)
    else:
        _log(fp, "[switch] 无可回滚备份")
    now = _now()
    db.execute("UPDATE model_switches SET status='failed', error=?, ended_at=? WHERE id=?",
               (error, now, switch_id))
    db.execute("INSERT INTO audit(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
               (now, "system", "model_switch_failed", f"switch:{switch_id}",
                json.dumps({"error": error}, ensure_ascii=False)))
    return {"ok": False, "switch_id": switch_id, "error": error}


# --------------------------------------------------------------------------- 回滚入口
def rollback_target(channel: str) -> Optional[dict]:
    """上一次成功切换之前的模型（用于「回滚到上一代」）。"""
    sw = db.one("SELECT * FROM model_switches WHERE channel=? AND status='ok' "
                "AND from_model_id IS NOT NULL ORDER BY id DESC LIMIT 1", (channel,))
    if not sw:
        return None
    return reg._row_to_model(db.one(  # noqa: SLF001
        "SELECT * FROM model_registry WHERE id=?", (int(sw["from_model_id"]),)))
