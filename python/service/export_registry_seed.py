"""把本地 `model_registry` 导出成随仓库发布的代次清单 `artifacts/registry_seed.json`。

用途：`console.db` 不入库，而模型代次/血缘存在库里。发布预置模型时把「哪些快照
组成哪一代、父代是谁」固化成一张小 JSON，启动时由
`model_registry.sync_seed()` / `import_seed(merge=True)` 导入（空库完整导入，
非空库只补缺失代次），clone 下来就有完整的代次树。

只导出**快照目录真实存在**的行；sha1 以磁盘文件为准重新计算，与登记值不一致时
打印警告并以磁盘为准（清单必须描述仓库里实际有的东西）。

    cd python
    python -m service.export_registry_seed              # 写 artifacts/registry_seed.json
    python -m service.export_registry_seed --out /tmp/seed.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config, db, model_registry as reg


def build_seed() -> Dict[str, Any]:
    rows = db.rows(
        "SELECT * FROM model_registry WHERE snapshot_dir IS NOT NULL "
        "AND status IN ('candidate','active','archived') ORDER BY channel, generation")
    by_id: Dict[int, dict] = {int(r["id"]): dict(r) for r in rows}
    models: List[dict] = []
    warnings: List[str] = []
    for r in rows:
        snap = reg._artifact_path(r.get("snapshot_dir"))  # noqa: SLF001 - 同模块族的工具脚本
        if not snap or not (snap / "model.onnx").exists():
            warnings.append(f"跳过 {r['channel']} g{r['generation']}：快照不存在 {r['snapshot_dir']}")
            continue
        disk_sha = reg.sha1_16_file(snap / "model.onnx")
        if disk_sha != r.get("sha1_16"):
            warnings.append(
                f"{r['channel']} g{r['generation']} sha1 不一致：登记 {r.get('sha1_16')} "
                f"磁盘 {disk_sha}（以磁盘为准）")
        meta_rel = r.get("meta_path")
        meta_p = reg._artifact_path(meta_rel)
        if not meta_p or not meta_p.exists():
            warnings.append(f"跳过 {r['channel']} g{r['generation']}：meta 缺失 {meta_rel}")
            continue
        curve_rel = r.get("curve_path")
        curve_p = reg._artifact_path(curve_rel)
        parent = by_id.get(int(r["parent_id"])) if r.get("parent_id") else None
        if parent is not None and parent.get("channel") != r.get("channel"):
            parent = None
        models.append({
            "channel": r["channel"],
            "variant": r.get("variant") or "official",
            "generation": int(r["generation"]),
            "display_name": r.get("display_name"),
            "artifact_name": r.get("artifact_name"),
            "snapshot_dir": r.get("snapshot_dir"),
            "sha1_16": disk_sha,
            "bytes": (snap / "model.onnx").stat().st_size,
            "meta_path": meta_rel,
            "curve_path": curve_rel if (curve_p and curve_p.exists()) else None,
            "trainable": bool(r.get("trainable")),
            "parent_generation": int(parent["generation"]) if parent else None,
            "inherit_mode": r.get("inherit_mode") or "full",
            "features_version": r.get("features_version") or "v2",
            "feature_dim": r.get("feature_dim"),
            "labels": json.loads(r["labels_json"]) if r.get("labels_json") else None,
            "metrics": json.loads(r["metrics_json"]) if r.get("metrics_json") else None,
            "recipe": json.loads(r["recipe_json"]) if r.get("recipe_json") else None,
            "status": r["status"],
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at"),
            "activated_at": r.get("activated_at"),
            "retired_at": r.get("retired_at"),
        })
    return {
        "schema": 1,
        "generated_by": "service.export_registry_seed",
        "generated_at": db.now_ms(),
        "note": ("随仓库发布的预置代次清单：只描述 artifacts/models/ 下实际入库的快照。"
                 "启动时由 model_registry.sync_seed() 导入（空库完整导入，"
                 "非空库只补缺失代次并按策略校正 active）；"
                 "schema/字段说明见 model_registry.SEED_MODEL_KEYS。"),
        "models": models,
        "_warnings": warnings,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="导出预置模型代次清单")
    ap.add_argument("--out", default=str(config.REGISTRY_SEED), help="输出路径")
    args = ap.parse_args(argv)
    db.init()
    payload = build_seed()
    warnings = payload.pop("_warnings", [])
    out = Path(args.out)
    tmp = str(out) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, out)
    for w in warnings:
        print("[warn]", w, file=sys.stderr)
    print(f"[ok] {len(payload['models'])} 代 -> {out}")
    for m in payload["models"]:
        parent = m["parent_generation"]
        print(f"  {m['channel']:<10} g{m['generation']}  {m['sha1_16']}  "
              f"{m['status']:<8} parent={parent} trainable={int(m['trainable'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
