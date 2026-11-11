//! 判定引擎：把「原始请求 -> 特征 -> 双通道分数 -> 融合动作」这条链封成一处。
//!
//! 这是 §S7 判定链路在数据面的**唯一**入口。门禁程序 `main.rs` 与采集代理 `waf-collector`
//! 都用它，所以两侧的行为不可能不一致。
//!
//! ⚠️ 关于"能不能报指标"：引擎只负责算，**不负责可信**。上线模型是在
//! payload_train + CSIC 上训的，训练集带 body 的记录是 **0 条**（§8.6.5）。
//! 因此拿它对真实流量算出的分数只能当**诊断**，不能当验收数字 ——
//! 阈值必须在真实本地良性留出流量上重标定（`thresholds.py --pool file:...`）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ort::environment::Environment;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;

use crate::decision::{Action, DecisionConfig, Verdict};
use crate::features;
use crate::hash::sha1_16_file;
use crate::shap;

fn ap<T, E: std::fmt::Display>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| anyhow!("{e}"))
}

/// 默认产物文件名（与 `python/artifacts/` 下的**现役**产物同名）。
pub const XGB_ONNX: &str = "xgboost_v20261015_001.onnx";
pub const IF_ONNX: &str = "iforest_lean_v20261015_001.onnx";
pub const POLICY_JSON: &str = "decision_policy.json";
/// 树件（TreeSHAP 需要节点 `cover`；ONNX 里没有）——可缺失，缺失即不做归因。
pub const XGB_TREES_JSON: &str = "xgb_trees.json";
/// 80 维特征名（`python/export_feature_names.py` 生成）——可缺失，缺失即不做归因。
pub const FEATURE_NAMES_JSON: &str = "feature_names_v2.json";
/// 归因返回的特征数（**诊断展示用**，不参与判定）。
pub const SHAP_TOPK: usize = 8;

/// TreeSHAP 归因的触发策略。
///
/// 归因是**诊断**（详情页回答"为什么给这个分"），不是判定输入；但它是单请求
/// 最贵的一步（g2 实测 ≈1.8ms，占判定总耗时 93%）。所以给三档：
///
/// * `All`：所有请求都算 —— 历史行为，回归/门禁用；
/// * `Flagged`（数据面默认）：只在 `action != allow` 时算 —— allow 是绝大多数流量；
/// * `Off`：完全不算。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapMode {
    All,
    Flagged,
    Off,
}

impl ShapMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Flagged => "flagged",
            Self::Off => "off",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "all" => Ok(Self::All),
            "flagged" | "flagged_only" => Ok(Self::Flagged),
            "off" | "none" => Ok(Self::Off),
            other => Err(anyhow!(
                "shap mode 只支持 all|flagged|off，收到 {other:?}"
            )),
        }
    }
}

/// 单条 TreeSHAP 归因项（Top-K，按 |contribution| 降序）。
///
/// ⚠️ 这是**诊断/可解释性**输出，不是判定输入。控制台详情页据此显示"为什么给这个分"。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShapItem {
    /// 特征名（来自 `feature_names_v2.json`）
    pub feature: String,
    /// 该特征在本请求上的取值
    pub value: f32,
    /// 对**预测类** margin 的贡献（正=推高该类）
    pub contribution: f32,
}

#[derive(serde::Deserialize)]
struct NamesDoc {
    names: Vec<String>,
}

/// 读特征名；缺失或损坏返回 `None`（**不致命**：归因是可选的诊断能力）。
fn load_names(path: &Path) -> Option<Vec<String>> {
    let s = std::fs::read_to_string(path).ok()?;
    let doc: NamesDoc = serde_json::from_str(&s).ok()?;
    if doc.names.is_empty() {
        return None;
    }
    Some(doc.names)
}

fn load_session(env: &Environment, path: &Path) -> Result<Session> {
    let b = ap(Session::builder(env))?;
    let b = ap(b.with_optimization_level(GraphOptimizationLevel::Level3))?;
    let mut b = ap(b.with_intra_threads(1))?;
    ap(b.commit_from_file(path))
        .with_context(|| format!("load {}", path.display()))
}

/// 校验策略记录的模型指纹与实际加载文件一致。
///
/// `expected` 为空（老策略）时只告警不拦 —— 兼容旧产物；一旦策略里写了指纹，
/// 不一致就**拒绝加载**（fail-closed）：宁可起不来，也不能"新阈值 + 旧模型"地跑。
fn check_model_sha(channel: &str, expected: &str, actual: &str) -> Result<()> {
    if expected.is_empty() {
        eprintln!(
            "[engine] ⚠️ 策略的{channel}通道未记录 artifact_sha1_16：无法校验模型是否同源\
             （建议重跑 thresholds.py）"
        );
        return Ok(());
    }
    if expected != actual {
        anyhow::bail!(
            "{channel}通道模型与策略不同源：策略记录 sha1_16={expected}，\
             实际加载文件 sha1_16={actual}。\
             这是『新阈值 + 旧内存模型』（或反之）的错配，拒绝加载。\
             请确认切换流程已跑完并重启采集器。"
        );
    }
    Ok(())
}

/// 单次判定的完整结果（分数、概率、原始零日量都留证）。
#[derive(Debug, Clone)]
pub struct Score {
    pub verdict: Verdict,
    /// 5 类概率（sklearn 类别升序，`normal` 的下标在 `DecisionConfig::normal_class`）
    pub proba: Vec<f32>,
    /// IsolationForest 的 `avg_path_len` 原值（零日 score = `-avg_path_len`）
    pub avg_path_len: f32,
    /// TreeSHAP Top-K 归因（**诊断**）；树件/特征名缺失时为空 Vec。
    pub shap_topk: Vec<ShapItem>,
    /// 分段耗时（ms）。只有压测/定位时才写进记录（`--perf-detail`）。
    pub timings: ScoreTimings,
}

/// 判定各阶段耗时（ms）。默认只用于内部统计/按需落盘，不参与判定。
#[derive(Debug, Clone, Copy, Default)]
pub struct ScoreTimings {
    pub feature_ms: f32,
    pub xgb_ms: f32,
    pub iforest_ms: f32,
    pub shap_ms: f32,
}

/// 归因缓存条目：命中时直接复用（**同特征 → 同归因**，语义不变）。
struct ShapCacheEntry {
    features: Vec<f32>,
    items: Vec<ShapItem>,
}

/// 归因缓存上限（条目）。每条 ~ (80×4B + 8 个 ShapItem)，1024 条约 1–2MB。
const SHAP_CACHE_MAX: usize = 1024;

/// 判定引擎：模型会话 + 策略 + （可选）归因缓存。
pub struct Engine {
    xgb: Session,
    ifo: Session,
    cfg: DecisionConfig,
    /// 树件（TreeSHAP）。缺失则不产出归因。
    forest: Option<shap::Forest>,
    /// 归因触发策略（默认 `All`，数据面按 CLI 覆盖）。
    shap_mode: ShapMode,
    /// 特征名（与特征向量同序）。缺失或长度不符则不产出归因。
    names: Vec<String>,
    /// 产物目录（写进记录，便于回答"这条分数是哪套产物算的"）
    pub artifacts: PathBuf,
    /// 已加载监督模型的**内容**指纹。策略里的 `artifact_sha1_16` 必须与它一致，
    /// 否则就是"新阈值 + 旧内存模型"的静默错配。
    xgb_sha1_16: String,
    /// 已加载零日模型的内容指纹。
    if_sha1_16: String,
    /// TreeSHAP 归因缓存：`(特征 bit 哈希) -> (特征, Top-K)`。
    ///
    /// 归因是**特征向量的纯函数**：同一组 80 维特征、同一个预测类，结果完全一致。
    /// 攻击流量高度重复（扫描器、同一 payload 的洪水），缓存命中时这一段直接归零，
    /// 而且不影响任何未命中的请求。命中时仍逐位比对特征，杜绝哈希碰撞带来错归因。
    shap_cache: HashMap<u64, ShapCacheEntry>,
}

impl Engine {
    /// 单实例加载（门禁程序用）。**每进程只能调用一次**：ORT 只允许一个 Environment。
    pub fn load(artifacts: &Path) -> Result<Self> {
        let env = ap(ort::init().with_name("waf-ai-core").build())?;
        Self::load_in(&env, artifacts)
    }

    /// 同一进程内加载 `n` 个独立引擎（会话池）。
    ///
    /// ORT **每进程只允许一个 Environment**（第二次 `ort::init().build()` 会失败：
    /// "only one environment is allowed per process"），所以环境只建一次、所有会话共享；
    /// 每个 `Engine` 仍持有自己的 `Session`，`run(&mut self)` 才能真并行。
    pub fn load_pool(artifacts: &Path, n: usize) -> Result<Vec<Self>> {
        if n == 0 {
            anyhow::bail!("engine pool 至少需要 1 个实例");
        }
        let env = ap(ort::init().with_name("waf-ai-core").build())?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(Self::load_in(&env, artifacts)?);
        }
        Ok(v)
    }

    fn load_in(env: &Environment, artifacts: &Path) -> Result<Self> {
        let xgb_path = artifacts.join(XGB_ONNX);
        let if_path = artifacts.join(IF_ONNX);
        let xgb = load_session(&env, &xgb_path)?;
        let ifo = load_session(&env, &if_path)?;
        let policy_path = artifacts.join(POLICY_JSON);
        let cfg = DecisionConfig::from_policy(&policy_path.to_string_lossy())?;

        // 模型内容指纹守卫：策略里的 `artifact_sha1_16` 必须与**实际加载的文件**一致。
        // 不一致 = "新阈值配旧内存模型"（或反之），两边都不报错却静默错判。
        // 老策略没有该字段（空串）时只告警，保持向后兼容。
        let xgb_sha1_16 = sha1_16_file(&xgb_path)
            .ok_or_else(|| anyhow!("无法计算监督模型指纹：{}", xgb_path.display()))?;
        let if_sha1_16 = sha1_16_file(&if_path)
            .ok_or_else(|| anyhow!("无法计算零日模型指纹：{}", if_path.display()))?;
        check_model_sha("监督", &cfg.supervised.artifact_sha1_16, &xgb_sha1_16)?;
        check_model_sha("零日", &cfg.zero_day.artifact_sha1_16, &if_sha1_16)?;

        // 归因是可选的诊断能力：素材缺失只是"没有 Top-K"，绝不让它拖垮判定。
        let names = load_names(&artifacts.join(FEATURE_NAMES_JSON)).unwrap_or_default();
        let forest = match shap::Forest::load(&artifacts.join(XGB_TREES_JSON).to_string_lossy()) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("[engine] 归因不可用（{XGB_TREES_JSON} 加载失败）：{e:#}");
                None
            }
        };
        if !names.is_empty() && names.len() != features::FEATURE_DIM {
            eprintln!(
                "[engine] ⚠️ 特征名维度 {} != FEATURE_DIM {}，已禁用归因（防止错位贴名）",
                names.len(),
                features::FEATURE_DIM
            );
        }
        Ok(Self {
            xgb,
            ifo,
            cfg,
            forest,
            shap_mode: ShapMode::All,
            shap_cache: HashMap::new(),
            names,
            artifacts: artifacts.to_path_buf(),
            xgb_sha1_16,
            if_sha1_16,
        })
    }

    /// 已加载监督模型的内容指纹（进指标文件，控制台用来判断"模型是否已生效"）。
    pub fn xgb_sha1_16(&self) -> &str {
        &self.xgb_sha1_16
    }
    /// 已加载零日模型的内容指纹。
    pub fn if_sha1_16(&self) -> &str {
        &self.if_sha1_16
    }
    pub fn xgb_artifact(&self) -> &str {
        &self.cfg.supervised.artifact
    }
    pub fn if_artifact(&self) -> &str {
        &self.cfg.zero_day.artifact
    }

    /// 归因是否可用（树件与特征名都就绪）。
    pub fn has_attribution(&self) -> bool {
        self.forest.is_some() && self.names.len() == features::FEATURE_DIM
    }

    /// 设置归因触发策略（数据面在 `Engine::load` 之后立刻覆盖）。
    pub fn set_shap_mode(&mut self, mode: ShapMode) {
        self.shap_mode = mode;
    }

    pub fn shap_mode(&self) -> ShapMode {
        self.shap_mode
    }

    /// **只热重载策略**（阈值档位 / 零日开关 / 融合策略）。
    ///
    /// 为什么不做模型热重载：重建 ONNX 会话要重新 `ort::init()`，风险与收益完全不成比例
    /// —— 换模型本来就该停机、走门禁，门禁不过不许上线。所以**产物名一变就报错**，
    /// 由调用方保留旧策略并把失败写进指标（fail-safe，绝不半新半旧地跑）。
    pub fn reload_policy(&mut self, artifacts: &Path) -> Result<()> {
        let policy_path = artifacts.join(POLICY_JSON);
        let cfg = DecisionConfig::from_policy(&policy_path.to_string_lossy())?;
        if cfg.supervised.artifact != self.cfg.supervised.artifact
            || cfg.zero_day.artifact != self.cfg.zero_day.artifact
        {
            anyhow::bail!(
                "策略指向的模型产物变了（supervised {:?} -> {:?} / zero_day {:?} -> {:?}）：\
                 热重载不换模型，请停机重启采集器",
                self.cfg.supervised.artifact,
                cfg.supervised.artifact,
                self.cfg.zero_day.artifact,
                cfg.zero_day.artifact
            );
        }
        // 产物**文件名**没变但**内容**变了（切换现役模型正是这种：槽位名固定、内容替换）：
        // 热重载换不了内存里的 ONNX 会话，必须拒绝，否则就是"新阈值 + 旧内存模型"。
        if !cfg.supervised.artifact_sha1_16.is_empty()
            && cfg.supervised.artifact_sha1_16 != self.xgb_sha1_16
        {
            anyhow::bail!(
                "监督模型内容已变（策略 sha1_16={} 已加载 {}）：热重载不换模型，\
                 请停机重启采集器",
                cfg.supervised.artifact_sha1_16,
                self.xgb_sha1_16
            );
        }
        if !cfg.zero_day.artifact_sha1_16.is_empty()
            && cfg.zero_day.artifact_sha1_16 != self.if_sha1_16
        {
            anyhow::bail!(
                "零日模型内容已变（策略 sha1_16={} 已加载 {}）：热重载不换模型，\
                 请停机重启采集器",
                cfg.zero_day.artifact_sha1_16,
                self.if_sha1_16
            );
        }
        self.cfg = cfg;
        Ok(())
    }

    /// 归因缓存的键：预测类 + 特征（按 f32 位模式）。命中后仍会逐位比对，碰撞只会导致
/// 一次未命中重算，不会返回错误的归因。
fn shap_key(f: &[f32], cls: usize) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    cls.hash(&mut h);
    f.len().hash(&mut h);
    for v in f {
        v.to_bits().hash(&mut h);
    }
    h.finish()
}

/// 当前策略修订号（控制台用来核对"采集器加载的是哪一版"）。
    pub fn policy_revision(&self) -> u32 {
        self.cfg.revision
    }
    pub fn policy_schema(&self) -> u32 {
        self.cfg.schema
    }
    pub fn zero_day_enabled(&self) -> bool {
        self.cfg.zero_day_enabled
    }
    pub fn fusion_policy(&self) -> &str {
        &self.cfg.fusion_policy
    }
    pub fn calibration_pool(&self) -> &str {
        &self.cfg.calibration_pool
    }

    /// TreeSHAP Top-K：对**预测类**（argmax）的 margin 取 |贡献| 最大的 K 个特征。
    ///
    /// 只遍历 `cls` 这一类的树（`Forest::explain_class`）：森林是每类一组树，
    /// 全类跑完再丢掉 4/5 是纯浪费。
    fn explain_topk(&mut self, f: &[f32], cls: usize) -> Vec<ShapItem> {
        let fo = match &self.forest {
            Some(x) => x,
            None => return Vec::new(),
        };
        if self.names.len() != f.len() {
            return Vec::new();
        }
        // 先查缓存：命中时只做 80 个 f32 的逐位比对（不做任何树遍历）。
        let key = Self::shap_key(f, cls);
        if let Some(e) = self.shap_cache.get(&key) {
            if e.features.len() == f.len()
                && e.features
                    .iter()
                    .zip(f.iter())
                    .all(|(a, b)| a.to_bits() == b.to_bits())
            {
                return e.items.clone();
            }
        }
        let row = fo.explain_class(cls, f);
        let mut idx: Vec<usize> = (0..f.len()).collect();
        idx.sort_by(|&a, &b| {
            row[b]
                .abs()
                .partial_cmp(&row[a].abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let items: Vec<ShapItem> = idx
            .into_iter()
            .take(SHAP_TOPK)
            .map(|i| ShapItem {
                feature: self.names[i].clone(),
                value: f[i],
                contribution: row[i],
            })
            .collect();
        // 有界缓存：满了就整体清空（简单、无锁、开销可预期），不做 LRU。
        if self.shap_cache.len() >= SHAP_CACHE_MAX {
            self.shap_cache.clear();
        }
        self.shap_cache.insert(
            key,
            ShapCacheEntry {
                features: f.to_vec(),
                items: items.clone(),
            },
        );
        items
    }

    pub fn policy(&self) -> &DecisionConfig {
        &self.cfg
    }

    /// 判定一条请求。与门禁程序走的是**同一套** `features::extract` + 同一份策略。
    ///
    /// 需要 `&mut self`：`ort::Session::run` 本身是 `&mut self`。采集侧因此用
    /// `Mutex` 串行化（dry-run 阶段够用；要并发再上会话池）。
    pub fn score(&mut self, req: &features::Request) -> Result<Score> {
        self.score_with_rules(req, &crate::decision::RuleEvidence::default())
    }

    /// 三通道判定：模型两通道 + 规则证据。
    ///
    /// 规则引擎在采集器里是**另一个** `RwLock`（可独立热重载），所以证据由调用方
    /// 传进来，而不是在这里自己匹配 —— 判定器只做融合，不做匹配。
    /// 证据未被策略认可（通道关闭 / 指纹不符）时，`decide_with_rules` 会把它当 0。
    pub fn score_with_rules(
        &mut self,
        req: &features::Request,
        rule_ev: &crate::decision::RuleEvidence,
    ) -> Result<Score> {
        let t0 = std::time::Instant::now();
        let f = features::extract(req);
        let d = f.len();
        let feature_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let t1 = std::time::Instant::now();
        let inp = Tensor::from_array(([1usize, d], f.clone().into_boxed_slice()))?;
        let outs = ap(self.xgb.run(ort::inputs!["input" => inp]))?;
        let (_s, probs) = outs["probabilities"]
            .try_extract_tensor::<f32>()
            .context("extract xgboost probabilities")?;
        let proba = probs.to_vec();
        drop(outs);
        if proba.len() < 2 {
            anyhow::bail!("xgboost 输出维度异常：期望 ≥2 类，得到 {}", proba.len());
        }
        let xgb_ms = t1.elapsed().as_secs_f64() * 1000.0;

        let t2 = std::time::Instant::now();
        let inp2 = Tensor::from_array(([1usize, d], f.clone().into_boxed_slice()))?;
        let outs2 = ap(self.ifo.run(ort::inputs!["input" => inp2]))?;
        let (_s2, e) = outs2["avg_path_len"]
            .try_extract_tensor::<f32>()
            .context("extract iforest avg_path_len")?;
        let avg_path_len = e.first().copied().unwrap_or(0.0);
        drop(outs2);
        let iforest_ms = t2.elapsed().as_secs_f64() * 1000.0;

        let verdict = self.cfg.decide_with_rules(&proba, avg_path_len, rule_ev);

        // 归因在**判定之后**算：先知道动作，才能按 `ShapMode` 决定要不要算。
        // 它是这条链上最贵的一步（g2 实测 ≈1.8ms / 93%），而 allow 是绝大多数流量 ——
        // 放在判定前无条件算，等于给每个放行请求都付一次诊断成本。
        let want_shap = match self.shap_mode {
            ShapMode::Off => false,
            ShapMode::Flagged => verdict.action != Action::Allow,
            ShapMode::All => true,
        };
        let t3 = std::time::Instant::now();
        let shap_topk = if want_shap {
            self.explain_topk(&f, verdict.label)
        } else {
            Vec::new()
        };
        let shap_ms = t3.elapsed().as_secs_f64() * 1000.0;

        Ok(Score {
            verdict,
            proba,
            avg_path_len,
            shap_topk,
            timings: ScoreTimings {
                feature_ms: feature_ms as f32,
                xgb_ms: xgb_ms as f32,
                iforest_ms: iforest_ms as f32,
                shap_ms: shap_ms as f32,
            },
        })
    }
}
