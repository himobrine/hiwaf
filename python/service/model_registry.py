"""模型代际登记 / 保留策略 / 当前模型解析。

训练只写 `artifacts/staging/task_<id>/`，本模块把 staging 里的产物快照到
`artifacts/models/<channel>/gen-XXXX-<sha>/`，并登记代次、父代、指标与学习曲线。

现役模型由 `decision_policy.json` 决定：
  * `supervised.artifact` / `artifact_sha1_16`
  * `zero_day.artifact` / `artifact_sha1_16`

模型文件本身仍使用数据面的固定槽位名（见 `config.LIVE_SLOTS`）。切换模型时只替换
槽位内容；采集器用内容 sha1 拒绝“新策略 + 旧内存模型”的混合状态。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import config, db

CHANNELS = ("supervised", "zero_day")
CHANNEL_LABEL = {"supervised": "监督通道", "zero_day": "零日通道"}
MAX_NAME = 64
MAX_NOTES = 2000


# --------------------------------------------------------------------------- 基础
def now_ms() -> int:
    return db.now_ms()


def sha1_16_file(path: os.PathLike | str) -> Optional[str]:
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return None


def _read_json(path: os.PathLike | str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path: os.PathLike | str, payload: Any) -> None:
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _artifact_path(rel: Optional[str]) -> Optional[Path]:
    if not rel:
        return None
    p = Path(rel)
    return p if p.is_absolute() else config.ARTIFACTS / p


def _rel_artifact(path: Path) -> str:
    try:
        return path.resolve().relative_to(config.ARTIFACTS.resolve()).as_posix()
    except ValueError:
        return str(path)


def _audit(actor: str, action: str, target: Optional[str] = None,
           detail: Optional[Any] = None) -> None:
    db.execute(
        "INSERT INTO audit(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
        (now_ms(), actor, action, target,
         json.dumps(detail, ensure_ascii=False) if detail is not None else None),
    )


def ensure_dirs() -> None:
    for p in (config.MODELS, config.STAGING, config.SWITCH_BACKUP, config.CURVES):
        p.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- 设置
def get_settings() -> Dict[str, Any]:
    out = dict(config.MODEL_SETTINGS_DEFAULTS)
    for r in db.rows("SELECT key, value FROM app_settings WHERE key LIKE 'models.%'"):
        k = r["key"].split(".", 1)[1] if "." in r["key"] else r["key"]
        try:
            out[k] = json.loads(r["value"])
        except (TypeError, ValueError):
            pass
    return out


def _validate_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    allowed = set(config.MODEL_SETTINGS_DEFAULTS)
    unknown = sorted(set(patch) - allowed)
    if unknown:
        raise ValueError(f"未知设置：{unknown}")
    out: Dict[str, Any] = {}
    if "max_per_channel" in patch:
        v = int(patch["max_per_channel"])
        if not 1 <= v <= 200:
            raise ValueError("max_per_channel 必须在 1..200")
        out["max_per_channel"] = v
    if "max_total" in patch:
        v = int(patch["max_total"])
        if not 1 <= v <= 500:
            raise ValueError("max_total 必须在 1..500")
        out["max_total"] = v
    if "inherit_mode" in patch:
        v = str(patch["inherit_mode"])
        if v not in ("off", "lineage", "warm_start"):
            raise ValueError("inherit_mode 只支持 off/lineage/warm_start")
        out["inherit_mode"] = v
    for k in ("auto_register", "keep_curves"):
        if k in patch:
            out[k] = bool(patch[k])
    return out


def update_settings(patch: Dict[str, Any], actor: str) -> Dict[str, Any]:
    clean = _validate_settings(patch)
    for k, v in clean.items():
        db.execute(
            "INSERT OR REPLACE INTO app_settings(key, value, updated_at, actor) VALUES(?,?,?,?)",
            (f"models.{k}", json.dumps(v, ensure_ascii=False), now_ms(), actor),
        )
    _audit(actor, "model_settings_update", None, clean)
    return get_settings()


# --------------------------------------------------------------------------- 行转换
def _row_to_model(row: Optional[dict]) -> Optional[dict]:
    if not row:
        return None
    out = dict(row)
    for src, dst in (("metrics_json", "metrics"), ("recipe_json", "recipe"),
                     ("labels_json", "labels")):
        raw = out.pop(src, None)
        try:
            out[dst] = json.loads(raw) if raw else None
        except (TypeError, ValueError):
            out[dst] = None
    out["trainable"] = bool(out.get("trainable"))
    snap = _artifact_path(out.get("snapshot_dir"))
    out["snapshot_available"] = bool(snap and snap.exists())
    meta_p = _artifact_path(out.get("meta_path"))
    out["meta_available"] = bool(meta_p and meta_p.exists())
    curve_p = _artifact_path(out.get("curve_path"))
    out["curve_available"] = bool(curve_p and curve_p.exists())
    return out


def list_models(channel: Optional[str] = None) -> List[dict]:
    if channel:
        rows = db.rows(
            "SELECT * FROM model_registry WHERE channel=? "
            "ORDER BY generation DESC, id DESC", (channel,))
    else:
        rows = db.rows(
            "SELECT * FROM model_registry ORDER BY channel, generation DESC, id DESC")
    return [_row_to_model(r) for r in rows]  # type: ignore[misc]


def get_model(model_id: int) -> Optional[dict]:
    row = _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (model_id,)))
    if not row:
        return None
    chain: List[dict] = []
    seen = {int(row["id"])}
    cur = row
    while cur and cur.get("parent_id") and len(chain) < 50:
        pid = int(cur["parent_id"])
        if pid in seen:
            break
        seen.add(pid)
        parent = _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (pid,)))
        if not parent:
            break
        chain.append(parent)
        cur = parent
    row["lineage"] = chain
    row["children"] = [
        _row_to_model(r) for r in db.rows(
            "SELECT * FROM model_registry WHERE parent_id=? ORDER BY generation", (model_id,))
    ]
    row["switches"] = db.rows(
        "SELECT * FROM model_switches WHERE model_id=? ORDER BY id DESC LIMIT 20", (model_id,))
    return row


def patch_model(model_id: int, display_name: Optional[str], notes: Optional[str],
                actor: str) -> dict:
    row = db.one("SELECT * FROM model_registry WHERE id=?", (model_id,))
    if not row:
        raise ValueError("模型不存在")
    if display_name is None and notes is None:
        raise ValueError("没有要修改的字段")
    fields: Dict[str, Any] = {}
    if display_name is not None:
        name = " ".join(str(display_name).strip().split())
        if not name:
            raise ValueError("名称不能为空")
        if len(name) > MAX_NAME:
            raise ValueError(f"名称最长 {MAX_NAME} 字符")
        if any(ch < " " for ch in name):
            raise ValueError("名称不能包含控制字符")
        fields["display_name"] = name
    if notes is not None:
        text = str(notes)
        if len(text) > MAX_NOTES:
            raise ValueError(f"备注最长 {MAX_NOTES} 字符")
        if any(ord(ch) < 32 and ch not in "\n\t\r" for ch in text):
            raise ValueError("备注不能包含控制字符")
        fields["notes"] = text
    fields["updated_at"] = now_ms()
    sets = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE model_registry SET {sets} WHERE id=?",
               (*fields.values(), model_id))
    _audit(actor, "model_rename" if "display_name" in fields else "model_note_update",
           f"model:{model_id}", {"fields": sorted(fields)})
    return _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (model_id,)))  # type: ignore[return-value]


# --------------------------------------------------------------------------- 父代 / warm start
def eligible_parents(channel: str) -> List[dict]:
    rows = db.rows(
        "SELECT * FROM model_registry WHERE channel=? AND trainable=1 "
        "AND status IN ('candidate','active','archived') AND snapshot_dir IS NOT NULL "
        "ORDER BY generation DESC, id DESC", (channel,))
    out = []
    for r in rows:
        m = _row_to_model(r)
        if m and m.get("snapshot_available"):
            out.append(m)
    return out


def _validate_parent(channel: str, parent: dict,
                     features_version: Optional[str],
                     feature_dim: Optional[int]) -> None:
    if parent.get("channel") != channel:
        raise ValueError("父代模型通道不一致")
    if parent.get("status") == "pruned" or not parent.get("snapshot_available"):
        raise ValueError("父代模型快照已被清理，无法继承")
    if not parent.get("trainable"):
        raise ValueError("父代模型没有可继承的训练件（xgb_model.json / iforest_model.joblib）")
    pv = parent.get("features_version")
    if features_version and pv and pv != features_version:
        raise ValueError(f"父代特征版本 {pv} 与当前 {features_version} 不一致")
    pd = parent.get("feature_dim")
    if feature_dim and pd and int(pd) != int(feature_dim):
        raise ValueError(f"父代特征维度 {pd} 与当前 {feature_dim} 不一致")


def resolve_parent(channel: str, parent_id: Optional[int],
                   features_version: Optional[str] = None,
                   feature_dim: Optional[int] = None) -> Optional[dict]:
    """解析 warm start 父代。默认当前现役；不可继承时退回最近可训练模型。"""
    if parent_id is not None:
        parent = _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (parent_id,)))
        if not parent:
            raise ValueError("父代模型不存在")
        _validate_parent(channel, parent, features_version, feature_dim)
        return parent

    active = _row_to_model(db.one(
        "SELECT * FROM model_registry WHERE channel=? AND status='active' LIMIT 1", (channel,)))
    if active and active.get("trainable") and active.get("snapshot_available"):
        _validate_parent(channel, active, features_version, feature_dim)
        return active

    for cand in eligible_parents(channel):
        try:
            _validate_parent(channel, cand, features_version, feature_dim)
            return cand
        except ValueError:
            continue
    return None


def parent_paths(parent: dict) -> Dict[str, str]:
    snap = _artifact_path(parent.get("snapshot_dir"))
    if not snap:
        return {}
    out: Dict[str, str] = {}
    for name in ("xgb_model.json", "iforest_model.joblib", "xgboost_meta.json",
                 "iforest_meta.json"):
        p = snap / name
        if p.exists():
            out[name] = str(p)
    return out


# --------------------------------------------------------------------------- 登记
def _pick_meta(staging: Path) -> Optional[Path]:
    for name in ("xgboost_meta.json", "iforest_meta.json"):
        p = staging / name
        if p.exists():
            return p
    for p in sorted(staging.glob("*_meta*.json")):
        return p
    return None


def _pick_onnx(staging: Path) -> Optional[Path]:
    p = staging / "model.onnx"
    if p.exists():
        return p
    files = sorted(staging.glob("*.onnx"))
    return files[0] if files else None


def _copy_curves(staging: Path, snap: Path, channel: str, generation: int) -> Optional[Path]:
    dirs = [staging / "curves", staging]
    curve = None
    for d in dirs:
        if not d.exists():
            continue
        cands = sorted(d.glob("*_curve.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if cands:
            curve = cands[0]
            break
    if not curve:
        return None
    dest = snap / "curve.json"
    shutil.copy2(curve, dest)
    for ext in (".csv", ".png"):
        side = curve.with_suffix(ext)
        if side.exists():
            shutil.copy2(side, snap / f"curve{ext}")
    payload = _read_json(dest, None)
    if isinstance(payload, dict):
        payload["run"] = f"{channel}_g{generation}"
        payload.setdefault("meta", {})
        payload["meta"]["generation"] = generation
        payload["meta"]["channel"] = channel
        _write_json(dest, payload)
    return dest


def _copy_if(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    shutil.copy2(src, dst)
    return True


def _metric_summary(meta: dict, channel: str) -> dict:
    if channel == "supervised":
        m = meta.get("metrics") or {}
        out = {}
        for name in ("test", "lexical", "local"):
            block = m.get(name)
            if isinstance(block, dict):
                out[name] = {
                    "n": block.get("n"),
                    "accuracy": block.get("accuracy"),
                    "auc_binary": block.get("auc_binary"),
                    "budgets": block.get("budgets"),
                    "normal_recall": ((block.get("per_class") or {}).get("normal") or {}).get("recall"),
                }
        out["n_trees"] = m.get("n_trees")
        out["n_nodes"] = m.get("n_nodes")
        out["train_seconds"] = m.get("train_seconds")
        return out
    calib = meta.get("zero_day_threshold") or {}
    return {
        "trees": meta.get("trees"),
        "max_samples": meta.get("max_samples"),
        "detect": calib.get("detect"),
        "thresholds": calib.get("thresholds"),
    }


def register_from_staging(task_id: Optional[int], kind: str, actor: str,
                          staging_dir: os.PathLike | str,
                          parent_id: Optional[int] = None,
                          inherit_mode: str = "full",
                          variant: Optional[str] = None) -> Optional[dict]:
    """把 staging 里的训练产物登记为新一代。返回登记行；缺产物时返回 None。"""
    if kind not in config.TRAIN_CHANNELS:
        return None
    channel, default_variant = config.TRAIN_CHANNELS[kind]
    variant = variant or default_variant
    staging = Path(staging_dir)
    onnx = _pick_onnx(staging)
    meta_p = _pick_meta(staging)
    if not onnx or not meta_p:
        _audit(actor, "model_register_failed", f"task:{task_id}",
               {"reason": "staging 缺 ONNX 或 meta", "staging": str(staging)})
        return None

    sha = sha1_16_file(onnx)
    if not sha:
        return None
    existing = db.one(
        "SELECT * FROM model_registry WHERE channel=? AND sha1_16=?", (channel, sha))
    if existing:
        db.execute("UPDATE model_registry SET task_id=?, updated_at=? WHERE id=?",
                   (task_id, now_ms(), existing["id"]))
        try:
            shutil.rmtree(staging)
        except OSError:
            pass
        return _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (existing["id"],)))

    meta = _read_json(meta_p, {}) or {}
    gen = int(db.scalar(
        "SELECT COALESCE(MAX(generation), 0) + 1 FROM model_registry WHERE channel=?",
        (channel,), default=1) or 1)
    label = "XGBoost" if channel == "supervised" else "IForest"
    display = f"{label} g{gen}" + (f" ({variant})" if variant != "official" else "")

    ensure_dirs()
    snap = config.MODELS / channel / f"gen-{gen:04d}-{sha[:12]}"
    if snap.exists():
        shutil.rmtree(snap)
    snap.mkdir(parents=True)

    live = config.LIVE_SLOTS[channel]
    artifact_name = live["onnx"] if variant == "official" else onnx.name
    meta_name = live["meta"] if variant == "official" else meta_p.name
    shutil.copy2(onnx, snap / "model.onnx")
    shutil.copy2(meta_p, snap / meta_name)

    trainable = False
    if channel == "supervised":
        trainable = _copy_if(staging / "xgb_model.json", snap / "xgb_model.json")
        _copy_if(staging / "xgb_trees.json", snap / "xgb_trees.json")
    else:
        trainable = _copy_if(staging / "iforest_model.joblib", snap / "iforest_model.joblib")
    _copy_if(staging / "feature_names_v2.json", snap / "feature_names_v2.json")
    # 上传训练产物：切换时 thresholds.py 要按目标模型自己的池/指纹做校准与污染检查。
    for name in ("calibration_pool.jsonl", "training_keys.txt", "upload_stats.json"):
        _copy_if(staging / name, snap / name)

    curve = _copy_curves(staging, snap, channel, gen)

    # 父代：显式指定则校验；否则记录当前现役（血缘），但不强制可 warm start。
    parent = None
    if parent_id is not None:
        parent = _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (parent_id,)))
        if parent:
            _validate_parent(channel, parent, meta.get("features_version"),
                             len(meta.get("feature_names") or []) or None)
    if parent is None and inherit_mode != "off":
        parent = _row_to_model(db.one(
            "SELECT * FROM model_registry WHERE channel=? AND status='active' LIMIT 1", (channel,)))
    pid = int(parent["id"]) if parent else None

    labels = meta.get("labels") or {}
    feature_names = meta.get("feature_names") or []
    feature_dim = len(feature_names) or meta.get("n_features")
    recipe = meta.get("training_recipe") or {}
    if not isinstance(recipe, dict):
        recipe = {}
    recipe = dict(recipe)
    recipe.update({
        "inherit_mode": inherit_mode,
        "parent_id": pid,
        "parent_sha1_16": (parent or {}).get("sha1_16"),
        "base_trees": meta.get("base_trees"),
        "total_trees": meta.get("total_trees"),
    })
    if meta.get("datasets"):
        recipe["datasets"] = meta.get("datasets")
    if meta.get("upload"):
        recipe["upload"] = meta.get("upload")
    if meta.get("eval_note"):
        recipe["eval_note"] = meta.get("eval_note")

    model_id = db.execute(
        """INSERT INTO model_registry(
             channel, variant, generation, display_name, notes, artifact_name, snapshot_dir,
             sha1_16, bytes, meta_path, curve_path, trainable, parent_id, task_id, inherit_mode,
             features_version, feature_dim, labels_json, metrics_json, recipe_json,
             status, created_at, updated_at, actor)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (channel, variant, gen, display, None, artifact_name, _rel_artifact(snap),
         sha, onnx.stat().st_size, _rel_artifact(snap / meta_name),
         _rel_artifact(curve) if curve else None, 1 if trainable else 0, pid, task_id,
         inherit_mode, meta.get("features_version") or "v2",
         int(feature_dim) if feature_dim else None,
         json.dumps(labels, ensure_ascii=False),
         json.dumps(_metric_summary(meta, channel), ensure_ascii=False),
         json.dumps(recipe, ensure_ascii=False),
         "candidate", now_ms(), now_ms(), actor),
    )
    _audit(actor, "model_register", f"model:{model_id}",
           {"channel": channel, "generation": gen, "sha1_16": sha,
            "parent_id": pid, "inherit_mode": inherit_mode, "variant": variant})
    try:
        shutil.rmtree(staging)
    except OSError:
        pass
    try:
        prune(actor="system")
    except Exception:  # noqa: BLE001 - 清理失败不能影响登记
        pass
    return _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (model_id,)))


def register_live(actor: str, channel: Optional[str] = None) -> Dict[str, Any]:
    """把当前现役槽位文件登记为模型（兼容老产物）。"""
    ensure_dirs()
    out: Dict[str, Any] = {"registered": [], "skipped": []}
    targets = [channel] if channel else list(CHANNELS)
    pol = _read_json(config.POLICY_JSON, {}) or {}
    for ch in targets:
        live = config.LIVE_SLOTS[ch]
        onnx = config.ARTIFACTS / live["onnx"]
        meta = config.ARTIFACTS / live["meta"]
        if not onnx.exists() or not meta.exists():
            out["skipped"].append({"channel": ch, "reason": "现役槽位缺 ONNX 或 meta"})
            continue
        sha = sha1_16_file(onnx)
        existing = db.one(
            "SELECT * FROM model_registry WHERE channel=? AND sha1_16=?", (ch, sha))
        if existing:
            out["skipped"].append({"channel": ch, "reason": "已登记", "id": existing["id"]})
            continue
        tmp = config.STAGING / f"register_live_{ch}_{int(now_ms())}"
        if tmp.exists():
            shutil.rmtree(tmp)
        (tmp / "curves").mkdir(parents=True)
        shutil.copy2(onnx, tmp / "model.onnx")
        shutil.copy2(meta, tmp / live["meta"])
        for key in ("model_json", "trees"):
            name = live.get(key)
            if name and (config.ARTIFACTS / name).exists():
                shutil.copy2(config.ARTIFACTS / name, tmp / name)
        kind = "train_realdata" if ch == "supervised" else "iforest_csic"
        row = register_from_staging(None, kind, actor, tmp, parent_id=None,
                                    inherit_mode="full")
        if not row:
            out["skipped"].append({"channel": ch, "reason": "登记失败"})
            continue
        # 与策略同源 => 现役。
        psha = (pol.get(ch) or {}).get("artifact_sha1_16")
        if psha and psha == row.get("sha1_16"):
            db.execute(
                "UPDATE model_registry SET status='archived', retired_at=? "
                "WHERE channel=? AND status='active' AND id<>?",
                (now_ms(), ch, row["id"]))
            db.execute(
                "UPDATE model_registry SET status='active', activated_at=?, updated_at=? "
                "WHERE id=?", (now_ms(), now_ms(), row["id"]))
            row = _row_to_model(db.one("SELECT * FROM model_registry WHERE id=?", (row["id"],)))
        out["registered"].append(row)
    return out


# --------------------------------------------------------------------------- 保留策略
def _delete_model_files(row: dict, keep_curves: bool) -> Optional[str]:
    """删除快照；返回保留下来的曲线路径（若有）。"""
    snap = _artifact_path(row.get("snapshot_dir"))
    kept_curve = None
    if keep_curves and snap:
        src = snap / "curve.json"
        if src.exists():
            dest = config.CURVES / f"pruned_{row['id']}_curve.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            kept_curve = _rel_artifact(dest)
    if snap and snap.exists():
        shutil.rmtree(snap)
    return kept_curve


def prune(actor: str = "system", dry_run: bool = False) -> Dict[str, Any]:
    s = get_settings()
    per_cap = int(s["max_per_channel"])
    total_cap = int(s["max_total"])
    keep_curves = bool(s["keep_curves"])

    rows = db.rows(
        "SELECT * FROM model_registry WHERE snapshot_dir IS NOT NULL "
        "AND status IN ('candidate','active','archived') ORDER BY created_at, id")
    by_ch: Dict[str, int] = {ch: 0 for ch in CHANNELS}
    for r in rows:
        by_ch[r["channel"]] = by_ch.get(r["channel"], 0) + 1
    total = len(rows)

    deletable = [r for r in rows if r["status"] != "active"]
    planned: List[dict] = []

    def _pick(ch: Optional[str]) -> Optional[dict]:
        for r in deletable:
            if r["id"] in {x["id"] for x in planned}:
                continue
            if ch is None or r["channel"] == ch:
                return r
        return None

    while True:
        over_ch = [ch for ch in CHANNELS if by_ch.get(ch, 0) > per_cap]
        if not over_ch and total <= total_cap:
            break
        victim = _pick(over_ch[0]) if over_ch else _pick(None)
        if not victim:
            break
        planned.append(victim)
        by_ch[victim["channel"]] -= 1
        total -= 1

    result = {
        "dry_run": bool(dry_run),
        "settings": s,
        "counts_before": {"total": len(rows), "by_channel": {
            ch: sum(1 for r in rows if r["channel"] == ch) for ch in CHANNELS}},
        "counts_after": {"total": total, "by_channel": by_ch},
        "models": [{"id": r["id"], "channel": r["channel"], "generation": r["generation"],
                    "display_name": r["display_name"], "sha1_16": r["sha1_16"],
                    "status": r["status"]} for r in planned],
    }
    if dry_run or not planned:
        return result

    for r in planned:
        kept = _delete_model_files(r, keep_curves)
        db.execute(
            "UPDATE model_registry SET status='pruned', snapshot_dir=NULL, meta_path=NULL, "
            "curve_path=?, trainable=0, updated_at=? WHERE id=?",
            (kept, now_ms(), r["id"]),
        )
        _audit(actor, "model_prune", f"model:{r['id']}",
               {"channel": r["channel"], "generation": r["generation"],
                "sha1_16": r["sha1_16"], "kept_curve": kept})
    return result


# --------------------------------------------------------------------------- 代际树
LINEAGE_NODE_KEYS = ("id", "channel", "variant", "generation", "display_name", "sha1_16",
                     "status", "inherit_mode", "trainable", "created_at", "activated_at",
                     "retired_at", "snapshot_available")


def _lineage_node(m: dict) -> Dict[str, Any]:
    node = {k: m.get(k) for k in LINEAGE_NODE_KEYS}
    node["id"] = int(m["id"])
    node["generation"] = int(m.get("generation") or 0)
    node["parent_id"] = int(m["parent_id"]) if m.get("parent_id") else None
    node["children"] = []
    return node


def build_lineage(models: List[dict],
                  active_ids: Optional[Iterable[int]] = None) -> Dict[str, Any]:
    """把登记行整理成「代际传承」树，供前端直接画图。

    **不信任 `parent_id`**：父代缺失 / 自指 / 成环的节点一律降级为根并记进 `orphans`，
    保证前端拿到的永远是可渲染的树 —— 一条脏数据不会让整页白屏。

    每个通道返回：
      * `tree`            嵌套节点（根在前，子代按 generation 升序）
      * `roots`           根节点 id
      * `orphans`         被降级的节点与原因（`missing` / `self` / `cycle`）
      * `current_id`     现役节点 id（可能为 None）
      * `path_to_current` 从根到现役的 id 链（前端用来高亮「现在跑的是哪一支」）
      * `stats`           按状态计数 + 血缘边 / warm start 边统计
    """
    active = {int(i) for i in (active_ids or [])}
    out: Dict[str, Any] = {"channels": {}, "generated_at": now_ms()}

    for ch in CHANNELS:
        nodes: Dict[int, dict] = {
            int(m["id"]): _lineage_node(m)
            for m in models if m.get("channel") == ch
        }
        roots: List[int] = []
        orphans: List[dict] = []

        def detach(nid: int, reason: str, parent_id: Optional[int]) -> None:
            n = nodes[nid]
            if parent_id is not None and parent_id in nodes:
                kids = nodes[parent_id]["children"]
                if nid in kids:
                    kids.remove(nid)
            n["parent_id"] = None
            if nid not in roots:
                roots.append(nid)
            orphans.append({"id": nid, "parent_id": parent_id, "reason": reason})

        # 1) 挂到父代；父代缺失/自指直接降级
        for nid in sorted(nodes):
            pid = nodes[nid]["parent_id"]
            if pid is None:
                roots.append(nid)
            elif pid == nid:
                detach(nid, "self", pid)
            elif pid not in nodes:
                detach(nid, "missing", pid)
            else:
                nodes[pid]["children"].append(nid)

        # 2) 成环：沿父链走，遇到重复就把该节点从环上摘下来（其余环上节点随后各自处理）
        for nid in sorted(nodes):
            seen = set()
            cur: Optional[int] = nid
            while cur is not None and cur not in seen:
                seen.add(cur)
                cur = nodes[cur]["parent_id"]
            if cur is not None:
                detach(nid, "cycle", nodes[nid]["parent_id"])

        for nid in nodes:
            nodes[nid]["children"].sort(key=lambda c: (nodes[c]["generation"], c))
        roots.sort(key=lambda r: (nodes[r]["generation"], r))

        def materialize(nid: int, depth: int = 0) -> dict:
            node = dict(nodes[nid])
            node["depth"] = depth
            node["children"] = [materialize(c, depth + 1)
                                for c in nodes[nid]["children"]]
            return node

        cur_id = next((nid for nid in nodes if nid in active), None)
        path: List[int] = []
        if cur_id is not None:
            walk, guard = cur_id, 0
            while walk is not None and guard <= len(nodes):
                path.append(walk)
                walk = nodes[walk]["parent_id"]
                guard += 1
            path.reverse()

        by_status: Dict[str, int] = {}
        for n in nodes.values():
            by_status[n["status"]] = by_status.get(n["status"], 0) + 1
        edges = [n for n in nodes.values() if n["parent_id"] is not None]
        gens = [nodes[i]["generation"] for i in nodes]
        tree = [materialize(r) for r in roots]

        out["channels"][ch] = {
            "channel": ch,
            "n": len(nodes),
            "tree": tree,
            "roots": roots,
            "orphans": orphans,
            "current_id": cur_id,
            "path_to_current": path,
            "max_generation": max(gens) if gens else 0,
            "stats": {
                "by_status": by_status,
                "edges": len(edges),
                "warm_start_edges": sum(1 for n in edges
                                        if n.get("inherit_mode") == "warm_start"),
                "depth": max((n["depth"] for n in _iter_nodes(tree)), default=0),
            },
            "variants": sorted({str(n.get("variant")) for n in nodes.values()
                                if n.get("variant")}),
        }
    return out


def _iter_nodes(tree: List[dict]) -> Iterable[dict]:
    for n in tree:
        yield n
        yield from _iter_nodes(n.get("children") or [])


# --------------------------------------------------------------------------- 当前模型
def _read_collector() -> Optional[dict]:
    p = config.COLLECTOR_METRICS
    if not p.exists():
        return None
    m = _read_json(p, None)
    return m if isinstance(m, dict) else None


def _state(policy_sha: Optional[str], disk_sha: Optional[str],
           collector_sha: Optional[str], registered: bool,
           score_enabled: Optional[bool]) -> str:
    if not disk_sha:
        return "model_missing"
    if policy_sha and disk_sha != policy_sha:
        return "disk_mismatch"
    if not registered:
        return "unregistered"
    if score_enabled is False:
        return "collector_unknown"
    if not collector_sha:
        return "collector_unknown"
    if collector_sha != disk_sha:
        return "pending_restart"
    return "in_sync"


def current_state() -> Dict[str, Any]:
    pol = _read_json(config.POLICY_JSON, {}) or {}
    metrics = _read_collector()
    score_enabled = metrics.get("score_enabled") if metrics else None
    out: Dict[str, Any] = {"policy_version": pol.get("version"), "channels": {}}
    for ch in CHANNELS:
        p = pol.get(ch) or {}
        live = config.LIVE_SLOTS[ch]
        artifact = p.get("artifact") or live["onnx"]
        policy_sha = p.get("artifact_sha1_16")
        disk_p = config.ARTIFACTS / artifact
        disk_sha = sha1_16_file(disk_p)
        reg = None
        if policy_sha:
            reg = _row_to_model(db.one(
                "SELECT * FROM model_registry WHERE channel=? AND sha1_16=?", (ch, policy_sha)))
        if reg is None and disk_sha:
            reg = _row_to_model(db.one(
                "SELECT * FROM model_registry WHERE channel=? AND sha1_16=?", (ch, disk_sha)))
        if reg is None:
            # 兼容策略里 sha 缺失/旧格式：按槽位文件名匹配。
            reg = _row_to_model(db.one(
                "SELECT * FROM model_registry WHERE channel=? AND artifact_name=? "
                "ORDER BY generation DESC LIMIT 1", (ch, artifact)))
        ckey = "model_xgb_sha1_16" if ch == "supervised" else "model_if_sha1_16"
        cname_key = "model_xgb" if ch == "supervised" else "model_if"
        collector_sha = (metrics or {}).get(ckey)
        state = _state(policy_sha, disk_sha, collector_sha,
                       bool(reg), score_enabled)
        out["channels"][ch] = {
            "channel": ch,
            "label": CHANNEL_LABEL[ch],
            "artifact": artifact,
            "policy_sha1_16": policy_sha,
            "disk_sha1_16": disk_sha,
            "collector_sha1_16": collector_sha,
            "collector_name": (metrics or {}).get(cname_key),
            "score_enabled": score_enabled,
            "threshold": p.get("threshold"),
            "target_fpr": p.get("target_fpr"),
            "policy_version": pol.get("version"),
            "state": state,
            "model": reg,
        }
    return out
