"""训练学习曲线记录（每次训练都会产出）。

产出目录 `artifacts/curves/`：
    <run>_curve.json    逐轮/逐点原始指标（含 meta，可程序读取）
    <run>_curve.csv     长表格式 (series,x,value)，便于 Excel / 表格查看
    <run>_curve.png     折线图（matplotlib，Agg 后端，无需显示器）

用法：
    rec = CurveRecorder("xgboost_realdata_v2")
    rec.from_evals_result(clf.evals_result(), names={"validation_0": "train",
                                                     "validation_1": "valid"})
    rec.add_series("if_detect@1%fpr", xs, ys)
    rec.save(meta={"features": "v2"})
"""
from __future__ import annotations

import csv
import json
import os
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
CURVE_DIR = os.path.join(HERE, "artifacts", "curves")


class CurveRecorder:
    def __init__(self, run: str, out_dir: Optional[str] = None):
        self.run = run
        self.out_dir = out_dir or CURVE_DIR
        self.series: Dict[str, List[Tuple[float, float]]] = {}

    # -- 采集 ---------------------------------------------------------------
    def add_series(self, name: str, xs: Sequence[float], ys: Sequence[float]) -> None:
        self.series[name] = [(float(x), float(y)) for x, y in zip(xs, ys)]

    def add_point(self, name: str, x: float, y: float) -> None:
        self.series.setdefault(name, []).append((float(x), float(y)))

    def from_evals_result(self, evals_result: Dict, names: Optional[Dict[str, str]] = None,
                          metrics: Optional[Iterable[str]] = None,
                          x_offset: int = 0) -> None:
        """把 `xgboost.XGBClassifier.evals_result()` 转成曲线系列。

        evals_result 形如 {"validation_0": {"mlogloss": [...], "merror": [...]}, ...}

        `x_offset` 用于 warm start：本轮只训练追加的树，x 轴右移到父代已
        有的树数，这样多代曲线可以在「总树数」维度直接对比。
        """
        names = names or {}
        keys = set(metrics) if metrics else None
        for split, per_metric in evals_result.items():
            label = names.get(split, split)
            for metric, vals in per_metric.items():
                if keys and metric not in keys:
                    continue
                xs = list(range(1 + int(x_offset), len(vals) + 1 + int(x_offset)))
                self.add_series(f"{label}_{metric}", xs, vals)

    # -- 输出 ---------------------------------------------------------------
    def save(self, meta: Optional[Dict] = None) -> Dict[str, str]:
        os.makedirs(self.out_dir, exist_ok=True)
        base = os.path.join(self.out_dir, f"{self.run}_curve")
        payload = {
            "run": self.run,
            "meta": meta or {},
            "series": {k: [[x, y] for x, y in v] for k, v in self.series.items()},
        }
        paths = {}
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        paths["json"] = base + ".json"

        with open(base + ".csv", "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["series", "x", "value"])
            for name, pts in self.series.items():
                for x, y in pts:
                    w.writerow([name, x, y])
        paths["csv"] = base + ".csv"

        png = self._plot(base)
        if png:
            paths["png"] = png
        return paths

    def _plot(self, base: str) -> Optional[str]:
        if not self.series:
            return None
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except Exception as e:  # noqa: BLE001
            print(f"[curve] matplotlib unavailable, skip png: {e}")
            return None

        n = len(self.series)
        fig, axes = plt.subplots(n, 1, figsize=(8, max(2.4 * n, 2.4)), squeeze=False)
        for ax, (name, pts) in zip(axes[:, 0], self.series.items()):
            xs = [p[0] for p in pts]
            ys = [p[1] for p in pts]
            ax.plot(xs, ys, marker="o", markersize=2.5, linewidth=1.2)
            ax.set_title(name, fontsize=9)
            ax.grid(True, alpha=0.3)
            if ys:
                ax.set_ylim(min(ys) - 0.02 * abs(min(ys) or 1), max(ys) + 0.02 * abs(max(ys) or 1))
        axes[-1, 0].set_xlabel("iteration / point")
        fig.suptitle(self.run, fontsize=11)
        fig.tight_layout(rect=(0, 0, 1, 0.97))
        out = base + ".png"
        fig.savefig(out, dpi=110)
        plt.close(fig)
        return out


def iforest_curve(iso_factory, X_neg, X_pos, steps: Sequence[int],
                  budget_fprs: Sequence[float] = (0.01, 0.05),
                  run: str = "iforest_curve") -> CurveRecorder:
    """Isolation Forest 的"学习曲线"：检测率/AUC 随 n_estimators 增长。

    `iso_factory(n, prev)` 返回一个已 fit 的 IsolationForest；建议用
    `warm_start=True` 逐档增加树数，避免重复拟合（见 train_iforest.py）。
    """
    import numpy as np
    from sklearn.metrics import roc_auc_score

    rec = CurveRecorder(run)
    iso = None
    for n in steps:
        iso = iso_factory(n, iso)
        neg = iso.decision_function(X_neg)
        pos = iso.decision_function(X_pos)
        y = np.concatenate([np.zeros(len(neg)), np.ones(len(pos))])
        s = np.concatenate([-neg, -pos])          # 越大越异常
        rec.add_point("iforest_auc", n, roc_auc_score(y, s))
        for fpr in budget_fprs:
            thr = float(np.quantile(-neg, 1.0 - fpr))
            rec.add_point(f"iforest_detect@fpr{fpr:g}", n, float((s >= thr)[len(neg):].mean()))
    return rec
