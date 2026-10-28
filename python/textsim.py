"""载荷文本的重复 / 同源判定。

被 `p0_audit.py`（审计）与 `train_realdata.py`（分组留出）共用，
因此独立成模块以避免循环导入。

定义：
  * 模板：数字掩码为 `#`、空白归一、小写 —— 抓"逐字重复的模板"（如 SQL 行只差常量）
  * 近重复：字符 4-5gram TF-IDF 余弦相似度 ≥ 阈值
  * 同源簇：模板相同 **或** 近重复，用并查集合并
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Tuple

import numpy as np

NUM_RE = re.compile(r"\d+")
WS_RE = re.compile(r"\s+")
NEAR_DUP_THR = 0.90


def template(p: str) -> str:
    """把数字掩码、空白归一，用于识别"模板级"重复。"""
    t = p.lower()
    t = NUM_RE.sub("#", t)
    t = WS_RE.sub(" ", t).strip()
    return t


def payload_of(sample: Dict) -> str:
    """从项目统一请求格式里取回原始载荷（`load_payloads` 会把它包成 `q=<payload>`）。"""
    q = sample.get("query") or ""
    return q[2:] if q.startswith("q=") else q


def leak_clusters(texts: List[str], thr: float = NEAR_DUP_THR
                  ) -> Tuple[List[int], "object"]:
    """并查集聚类：模板相同或余弦相似度 ≥ thr 的文本归为同一簇。

    返回 `(cluster_id_per_text, 相似度矩阵)`。n 较小时直接算稠密相似度矩阵。
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import normalize

    n = len(texts)
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(4, 5), min_df=1)
    X = normalize(vec.fit_transform(texts))
    S = np.asarray((X @ X.T).todense(), dtype=np.float64)

    parent = list(range(n))

    def find(a):
        root = a
        while parent[root] != root:
            root = parent[root]
        while parent[a] != root:
            parent[a], a = root, parent[a]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(n):
        for j in range(i + 1, n):
            if S[i, j] >= thr:
                union(i, j)

    by_tpl = defaultdict(list)
    for i, t in enumerate(texts):
        by_tpl[template(t)].append(i)
    for members in by_tpl.values():
        for k in range(1, len(members)):
            union(members[0], members[k])

    return [find(i) for i in range(n)], S


def group_split(texts: List[str], thr: float = NEAR_DUP_THR):
    """按同源簇切分成 (train_positions, eval_positions)，同簇不跨两侧。

    贪心：簇按大小降序，依次放进当前较小的一侧 —— 两侧条数尽量均衡。
    """
    clusters, _ = leak_clusters(texts, thr)
    groups = defaultdict(list)
    for pos, c in enumerate(clusters):
        groups[c].append(pos)
    glist = sorted(groups.values(), key=len, reverse=True)
    tr, ev = [], []
    for g in glist:
        (tr if len(tr) <= len(ev) else ev).extend(g)
    return sorted(tr), sorted(ev), {"n_clusters": len(glist)}
