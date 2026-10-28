//! 判定引擎：把「原始请求 -> 特征 -> 双通道分数 -> 融合动作」这条链封成一处。
//!
//! 这是 §S7 判定链路在数据面的**唯一**入口。门禁程序 `main.rs` 与采集代理 `waf-collector`
//! 都用它，所以两侧的行为不可能不一致。
//!
//! ⚠️ 关于"能不能报指标"：引擎只负责算，**不负责可信**。上线模型是在
//! payload_train + CSIC 上训的，训练集带 body 的记录是 **0 条**（§8.6.5）。
//! 因此拿它对真实流量算出的分数只能当**诊断**，不能当验收数字 ——
//! 阈值必须在真实本地良性留出流量上重标定（`thresholds.py --pool file:...`）。

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ort::environment::Environment;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;

use crate::decision::{DecisionConfig, Verdict};
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
}

pub struct Engine {
    xgb: Session,
    ifo: Session,
    cfg: DecisionConfig,
    /// 树件（TreeSHAP）。缺失则不产出归因。
    forest: Option<shap::Forest>,
    /// 特征名（与特征向量同序）。缺失或长度不符则不产出归因。
    names: Vec<String>,
    /// 产物目录（写进记录，便于回答"这条分数是哪套产物算的"）
    pub artifacts: PathBuf,
    /// 已加载监督模型的**内容**指纹。策略里的 `artifact_sha1_16` 必须与它一致，
    /// 否则就是"新阈值 + 旧内存模型"的静默错配。
    xgb_sha1_16: String,
    /// 已加载零日模型的内容指纹。
    if_sha1_16: String,
}

impl Engine {
    pub fn load(artifacts: &Path) -> Result<Self> {
        let env = ap(ort::init().with_name("waf-ai-core").build())?;
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

    /// TreeSHAP Top-K：对**预测类**（argmax proba）的 margin 取 |贡献| 最大的 K 个特征。
    fn explain_topk(&self, f: &[f32], proba: &[f32]) -> Vec<ShapItem> {
        let fo = match &self.forest {
            Some(x) => x,
            None => return Vec::new(),
        };
        if self.names.len() != f.len() {
            return Vec::new();
        }
        let cls = proba
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let phi = fo.explain(f);
        let row = match phi.get(cls) {
            Some(r) => r,
            None => return Vec::new(),
        };
        let mut idx: Vec<usize> = (0..f.len()).collect();
        idx.sort_by(|&a, &b| {
            row[b]
                .abs()
                .partial_cmp(&row[a].abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        idx.into_iter()
            .take(SHAP_TOPK)
            .map(|i| ShapItem {
                feature: self.names[i].clone(),
                value: f[i],
                contribution: row[i],
            })
            .collect()
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
        let f = features::extract(req);
        let d = f.len();

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

        // 归因在**判定之外**算（同一套特征、同一棵树件），失败不影响判定。
        let shap_topk = self.explain_topk(&f, &proba);

        let inp2 = Tensor::from_array(([1usize, d], f.into_boxed_slice()))?;
        let outs2 = ap(self.ifo.run(ort::inputs!["input" => inp2]))?;
        let (_s2, e) = outs2["avg_path_len"]
            .try_extract_tensor::<f32>()
            .context("extract iforest avg_path_len")?;
        let avg_path_len = e.first().copied().unwrap_or(0.0);
        drop(outs2);

        let verdict = self.cfg.decide_with_rules(&proba, avg_path_len, rule_ev);
        Ok(Score {
            verdict,
            proba,
            avg_path_len,
            shap_topk,
        })
    }
}
