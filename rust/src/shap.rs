//! TreeSHAP（path-dependent）的 Rust 移植。
//!
//! 严格对齐 shap 的 `src/tree_shap.h`（`extend_path` / `unwind_path` /
//! `unwound_path_sum` / `tree_shap_recursive` / `compute_expectations`）。
//!
//! 说明：ONNX 的 `TreeEnsemble*` 属性不包含节点 `cover`，而 path-dependent
//! TreeSHAP 需要它作为「未知特征」时的左右分流权重。因此解释器读取训练侧导出的
//! 树件 `artifacts/xgb_trees.json`（与 ONNX 同源、同一个 booster）。
//!
//! 这里只实现 `condition == 0` 的路径（单实例主效应），交互效应 (`condition != 0`)
//! 留作后续扩展。

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
struct RawNode {
    id: i32,
    feature: i32,
    split: f32,
    yes: i32,
    no: i32,
    #[allow(dead_code)]
    missing: i32,
    cover: f32,
    leaf: Option<f32>,
}

#[derive(Deserialize)]
struct RawTree {
    #[allow(dead_code)]
    tree: usize,
    class: usize,
    nodes: Vec<RawNode>,
}

#[derive(Deserialize)]
struct RawForest {
    num_class: usize,
    base_scores: Vec<f32>,
    n_features: usize,
    trees: Vec<RawTree>,
}

/// 单棵树的扁平数组表示（下标 = 节点 id）
struct Tree {
    features: Vec<i32>,
    thresholds: Vec<f32>,
    left: Vec<i32>,
    right: Vec<i32>,
    values: Vec<f32>,
    weights: Vec<f32>,
    max_depth: usize,
}

#[derive(Clone, Copy, Default)]
struct PathElement {
    feature_index: i32,
    zero_fraction: f32,
    one_fraction: f32,
    pweight: f32,
}

pub struct Forest {
    pub num_class: usize,
    pub n_features: usize,
    pub base_scores: Vec<f32>,
    /// (class, tree)
    trees: Vec<(usize, Tree)>,
}

impl Forest {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        let rf: RawForest = serde_json::from_str(&raw).context("parse xgb_trees.json")?;
        let mut trees = Vec::with_capacity(rf.trees.len());
        for rt in &rf.trees {
            let mut t = build_tree(&rt.nodes);
            let d = compute_expectations(&mut t, 0);
            t.max_depth = d;
            trees.push((rt.class, t));
        }
        Ok(Forest {
            num_class: rf.num_class,
            n_features: rf.n_features,
            base_scores: rf.base_scores,
            trees,
        })
    }

    /// 返回 [class][0..n_features] 的特征贡献 + [n_features] 的偏置。
    /// 对每个 class：sum(phi) == raw margin。
    pub fn explain(&self, x: &[f32]) -> Vec<Vec<f32>> {
        let m = self.n_features;
        let mut out = vec![vec![0.0f32; m + 1]; self.num_class];
        for (c, t) in &self.trees {
            tree_shap(t, x, &mut out[*c], m);
        }
        for c in 0..self.num_class {
            out[c][m] += self.base_scores[c];
        }
        out
    }

    pub fn n_trees(&self) -> usize {
        self.trees.len()
    }
}

fn build_tree(nodes: &[RawNode]) -> Tree {
    let n = nodes.iter().map(|x| x.id).max().unwrap_or(-1) as usize + 1;
    let mut t = Tree {
        features: vec![-1; n],
        thresholds: vec![0.0; n],
        left: vec![-1; n],
        right: vec![-1; n],
        values: vec![0.0; n],
        weights: vec![0.0; n],
        max_depth: 0,
    };
    for nd in nodes {
        let i = nd.id as usize;
        t.features[i] = nd.feature;
        t.thresholds[i] = nd.split;
        t.left[i] = nd.yes;
        t.right[i] = nd.no;
        t.weights[i] = nd.cover;
        t.values[i] = nd.leaf.unwrap_or(0.0);
    }
    t
}

/// 把内部节点的 value 改写为其子树的加权期望（对齐 compute_expectations）。
fn compute_expectations(t: &mut Tree, i: usize) -> usize {
    let mut max_depth = 0usize;
    if t.right[i] >= 0 {
        let li = t.left[i] as usize;
        let ri = t.right[i] as usize;
        let dl = compute_expectations(t, li);
        let dr = compute_expectations(t, ri);
        let lw = t.weights[li];
        let rw = t.weights[ri];
        if lw == 0.0 && rw == 0.0 {
            t.values[i] = 0.0;
        } else {
            t.values[i] = (lw * t.values[li] + rw * t.values[ri]) / (lw + rw);
        }
        max_depth = dl.max(dr) + 1;
    }
    max_depth
}

fn extend_path(u: &mut [PathElement], base: usize, d: usize, zero: f32, one: f32, feat: i32) {
    u[base + d] = PathElement {
        feature_index: feat,
        zero_fraction: zero,
        one_fraction: one,
        pweight: if d == 0 { 1.0 } else { 0.0 },
    };
    let mut i = d;
    while i > 0 {
        i -= 1;
        let fi = i as f32;
        let df = d as f32;
        u[base + i + 1].pweight += one * u[base + i].pweight * (fi + 1.0) / (df + 1.0);
        u[base + i].pweight = zero * u[base + i].pweight * (df - fi) / (df + 1.0);
    }
}

fn unwind_path(u: &mut [PathElement], base: usize, d: usize, path_index: usize) {
    let one = u[base + path_index].one_fraction;
    let zero = u[base + path_index].zero_fraction;
    let mut next_one_portion = u[base + d].pweight;
    let mut i = d;
    while i > 0 {
        i -= 1;
        let fi = i as f32;
        let df = d as f32;
        if one != 0.0 {
            let tmp = u[base + i].pweight;
            u[base + i].pweight = next_one_portion * (df + 1.0) / ((fi + 1.0) * one);
            next_one_portion = tmp - u[base + i].pweight * zero * (df - fi) / (df + 1.0);
        } else {
            u[base + i].pweight = u[base + i].pweight * (df + 1.0) / (zero * (df - fi));
        }
    }
    for i in path_index..d {
        u[base + i].feature_index = u[base + i + 1].feature_index;
        u[base + i].zero_fraction = u[base + i + 1].zero_fraction;
        u[base + i].one_fraction = u[base + i + 1].one_fraction;
    }
}

fn unwound_path_sum(u: &[PathElement], base: usize, d: usize, path_index: usize) -> f32 {
    let one = u[base + path_index].one_fraction;
    let zero = u[base + path_index].zero_fraction;
    let mut next_one_portion = u[base + d].pweight;
    let mut total = 0.0f32;
    let mut i = d;
    if one != 0.0 {
        while i > 0 {
            i -= 1;
            let fi = i as f32;
            let df = d as f32;
            let tmp = next_one_portion / ((fi + 1.0) * one);
            total += tmp;
            next_one_portion = u[base + i].pweight - tmp * zero * (df - fi);
        }
    } else {
        while i > 0 {
            i -= 1;
            let fi = i as f32;
            let df = d as f32;
            total += u[base + i].pweight / (zero * (df - fi));
        }
    }
    total * (d as f32 + 1.0)
}

#[allow(clippy::too_many_arguments)]
fn tree_shap_recursive(
    t: &Tree,
    x: &[f32],
    phi: &mut [f32],
    u: &mut [PathElement],
    base: usize,
    unique_depth: usize,
    parent_zero_fraction: f32,
    parent_one_fraction: f32,
    parent_feature_index: i32,
    node_index: usize,
) {
    let nbase = base + unique_depth + 1;
    for k in 0..=unique_depth {
        u[nbase + k] = u[base + k];
    }
    extend_path(
        u,
        nbase,
        unique_depth,
        parent_zero_fraction,
        parent_one_fraction,
        parent_feature_index,
    );

    let split_index = t.features[node_index];

    if t.right[node_index] < 0 {
        // 叶子
        let v = t.values[node_index];
        for i in 1..=unique_depth {
            let w = unwound_path_sum(u, nbase, unique_depth, i);
            let el = u[nbase + i];
            let scale = w * (el.one_fraction - el.zero_fraction);
            phi[el.feature_index as usize] += scale * v;
        }
    } else {
        let si = split_index as usize;
        let left = t.left[node_index];
        let hi = if x[si] < t.thresholds[node_index] {
            left
        } else {
            t.right[node_index]
        };
        let ci = if hi == left {
            t.right[node_index]
        } else {
            left
        };
        let hot = hi as usize;
        let cold = ci as usize;

        let w = t.weights[node_index];
        let hot_zero_fraction = t.weights[hot] / w;
        let cold_zero_fraction = t.weights[cold] / w;
        let mut incoming_zero_fraction = 1.0f32;
        let mut incoming_one_fraction = 1.0f32;

        let mut path_index = 0usize;
        while path_index <= unique_depth {
            if u[nbase + path_index].feature_index == split_index {
                break;
            }
            path_index += 1;
        }
        let mut ud = unique_depth;
        if path_index != unique_depth + 1 {
            incoming_zero_fraction = u[nbase + path_index].zero_fraction;
            incoming_one_fraction = u[nbase + path_index].one_fraction;
            unwind_path(u, nbase, unique_depth, path_index);
            ud -= 1;
        }

        tree_shap_recursive(
            t,
            x,
            phi,
            u,
            nbase,
            ud + 1,
            hot_zero_fraction * incoming_zero_fraction,
            incoming_one_fraction,
            split_index,
            hot,
        );
        tree_shap_recursive(
            t,
            x,
            phi,
            u,
            nbase,
            ud + 1,
            cold_zero_fraction * incoming_zero_fraction,
            0.0,
            split_index,
            cold,
        );
    }
}

/// 单树贡献累加到 `phi`（长度 n_features+1，最后一位是偏置）。
fn tree_shap(t: &Tree, x: &[f32], phi: &mut [f32], m: usize) {
    phi[m] += t.values[0];
    let maxd = t.max_depth + 2;
    let cap = (maxd * (maxd + 1)) / 2 + maxd + 4;
    let mut u = vec![PathElement::default(); cap];
    tree_shap_recursive(t, x, phi, &mut u, 0, 0, 1.0, 1.0, -1, 0);
}

/// 便捷函数：返回最大 |贡献| 的特征下标（不含偏置）
pub fn top_features(phi: &[f32], k: usize) -> Vec<(usize, f32)> {
    let mut v: Vec<(usize, f32)> = phi[..phi.len() - 1].iter().copied().enumerate().collect();
    v.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap());
    v.into_iter().take(k).collect()
}
