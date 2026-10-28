//! WAF AI 数据面原型 (Rust + ort)
//!
//! 目标：
//!  1. 用 `ort` 加载 Python 导出的 ONNX 模型（XGBoost 分类器 + 精简 Isolation Forest）
//!  2. Rust 侧重算特征并与 Python 逐位比对
//!  3. 推理结果与 Python 比对（验证跨语言一致性）
//!  4. 单样本 / 批量延迟基准

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use ort::environment::Environment;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;
use serde::Deserialize;

// 特征/判定/SHAP/规则 全部来自公共库（门禁与采集代理共用同一份实现）
use waf_ai_proto::{decision, features, rules, shap};

#[derive(Deserialize)]
struct TestVec {
    feature_names: Vec<String>,
    requests: Vec<serde_json::Value>,
    features: Vec<Vec<f32>>,
    labels_true: Vec<i64>,
    xgb_proba: Vec<Vec<f32>>,
    xgb_proba_ort: Vec<Vec<f32>>,
    xgb_sklearn_vs_ort_maxdiff: f32,
    iforest_avg_path_len: Vec<f32>,
    /// S7：阈值决策的 Python 期望值
    decision: Option<DecisionRef>,
}

#[derive(Deserialize)]
struct DecisionRef {
    policy_version: u32,
    #[serde(default)]
    policy_schema: u32,
    fusion_policy: String,
    #[serde(default = "default_true")]
    zero_day_enabled: bool,
    supervised: ChannelRef,
    zero_day: ChannelRef,
    #[serde(default)]
    rules: RulesRef,
    expected_action: Vec<String>,
}

/// testvec 里的规则通道期望值（`thresholds.py::build_decision_block` 产出）。
#[derive(Deserialize, Default)]
struct RulesRef {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ruleset_sha1_16: String,
    #[serde(default)]
    min_weight_to_block: f64,
    /// 逐样本的规则集指纹（**原始**值，屏蔽逻辑两侧各做一次）
    #[serde(default)]
    ruleset_sha1_16_per_sample: Vec<String>,
    /// 逐样本的全部命中权重（证据）
    #[serde(default)]
    weight: Vec<f64>,
    /// 逐样本的 `action=block` 命中权重（阻断预算）
    #[serde(default)]
    block_weight: Vec<f64>,
    #[serde(default)]
    expected_flagged: Vec<bool>,
}

#[derive(Deserialize)]
struct ChannelRef {
    target_fpr: String,
    threshold: f32,
    score: Vec<f32>,
    expected_flagged: Vec<bool>,
    #[serde(default)]
    expected_crossed: Option<Vec<bool>>,
}

fn default_true() -> bool {
    true
}

const XGB_ONNX: &str = "../python/artifacts/xgboost_v20261015_001.onnx";
const IF_ONNX: &str = "../python/artifacts/iforest_lean_v20261015_001.onnx";
const TESTVEC: &str = "../python/artifacts/testvec.json";
const XGB_TREES: &str = "../python/artifacts/xgb_trees.json";
const SHAP_REF: &str = "../python/artifacts/shap_ref.json";
const DECISION_POLICY: &str = "../python/artifacts/decision_policy.json";
const IF_META: &str = "../python/artifacts/iforest_meta.json";
/// 规则通道的同源回归向量（`python/export_rules_testvec.py` 生成）
const RULES_TESTVEC: &str = "../python/artifacts/rules_testvec.json";
/// 向量配套的自检规则集（含 21 条真规则 + 专压边界的合成规则）
const RULES_SELFTEST: &str = "../python/artifacts/rules_selftest.json";

/// `rules_testvec.json`：钉死解码 / 匹配 / 记分 / SHA-1 的跨语言一致性。
#[derive(Deserialize)]
struct RuleTestVec {
    /// 生成向量时 Python `hashlib` 算出的规则集指纹（用来校验 Rust 自写的 SHA-1）
    ruleset_sha1_16: String,
    ruleset_id: String,
    n_rules: usize,
    min_weight_to_block: f64,
    cases: Vec<RuleCase>,
}

#[derive(Deserialize)]
struct RuleCase {
    id: String,
    req: RuleCaseReq,
    /// 期望的 6 个字段解码结果（由 Python 参考实现算出）
    decoded: HashMap<String, String>,
    /// 期望命中的规则 id（已排序去重）
    hits: Vec<String>,
    #[serde(default)]
    hit_detail: Vec<RuleCaseHit>,
    weight: f64,
    block_weight: f64,
    block: bool,
}

#[derive(Deserialize, Default)]
struct RuleCaseReq {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    ua: String,
    #[serde(default)]
    referer: String,
}

impl RuleCaseReq {
    fn to_input(&self) -> rules::RuleInput {
        rules::RuleInput {
            method: self.method.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            body: self.body.clone(),
            ua: self.ua.clone(),
            referer: self.referer.clone(),
        }
    }
}

#[derive(Deserialize)]
struct RuleCaseHit {
    rule: String,
    /// 单字段作用域下，`field` 必须正好等于作用域名（回映射偏移不能张冠李戴）
    #[serde(default)]
    expect_field: Option<String>,
}

/// `iforest_meta.json` 的零日阈值记录（只取交叉校验需要的字段）。
#[derive(Deserialize, Default)]
struct IfMeta {
    #[serde(default)]
    zero_day_threshold: IfThresholds,
}

#[derive(Deserialize, Default)]
struct IfThresholds {
    #[serde(default)]
    thresholds: HashMap<String, f32>,
}

#[derive(Deserialize)]
struct ShapRef {
    n: usize,
    n_features: usize,
    n_class: usize,
    features: Vec<Vec<f32>>,
    contribs: Vec<Vec<Vec<f32>>>,
    margin: Vec<Vec<f32>>,
}

/// ort 的部分错误类型携带不可 `Send` 的构建器，无法直接进 `anyhow`；统一降级为字符串。
fn ap<T, E: std::fmt::Display>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| anyhow!("{e}"))
}

fn load_session(env: &Environment, path: &str) -> Result<Session> {
    let b = ap(Session::builder(env))?;
    let b = ap(b.with_optimization_level(GraphOptimizationLevel::Level3))?;
    let mut b = ap(b.with_intra_threads(1))?;
    ap(b.commit_from_file(path)).with_context(|| format!("load {path}"))
}

fn max_abs_diff(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| (x - y).abs()).fold(0.0, f32::max)
}

fn argmax(row: &[f32]) -> usize {
    row.iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .map(|(i, _)| i)
        .unwrap_or(0)
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    // 子命令：`rules check|replay`（规则通道的权威编译/回放，控制面调用它，不自己实现匹配）。
    if argv.len() > 1 && argv[1] == "rules" {
        return waf_ai_proto::rules_cli::run(&argv[2..]);
    }
    let tv_path = argv.get(1).cloned().unwrap_or_else(|| TESTVEC.to_string());
    let raw = std::fs::read_to_string(&tv_path).with_context(|| format!("read {tv_path}"))?;
    let tv: TestVec = serde_json::from_str(&raw).context("parse testvec.json")?;

    let n = tv.features.len();
    let d = tv.feature_names.len();
    println!("[proto] testvec: {n} samples x {d} features");

    let env = ap(ort::init().with_name("waf-ai-proto").build())?;
    let mut xgb = load_session(&env, XGB_ONNX)?;
    let mut ifo = load_session(&env, IF_ONNX)?;
    println!("[proto] models loaded (xgb + lean iforest)");

    // ---- 1) Rust 特征重算 vs Python ----
    let mut feat_diff = 0.0f32;
    let mut worst = (0usize, 0usize);
    let mut any_diff = false;
    for (i, req) in tv.requests.iter().enumerate() {
        let r = features::Request::from_json(req);
        let f = features::extract(&r);
        assert_eq!(f.len(), d, "feature dim mismatch: {} vs {}", f.len(), d);
        for (j, v) in f.iter().enumerate() {
            let dv = (v - tv.features[i][j]).abs();
            if dv > feat_diff {
                feat_diff = dv;
                worst = (i, j);
                any_diff = true;
            }
        }
    }
    if any_diff {
        println!(
            "[proto] feature max|diff| rust vs python = {feat_diff:.6} (worst sample {}, feature {})",
            worst.0, worst.1
        );
    } else {
        println!("[proto] feature rust vs python = BIT-EXACT (0 diff, {n}x{d})");
    }

    // ---- 2) 批量推理 ----
    let flat: Vec<f32> = tv.features.iter().flatten().copied().collect();
    let shape = [n, d];

    let input = Tensor::from_array((shape, flat.clone().into_boxed_slice()))?;
    let t0 = Instant::now();
    let outs = ap(xgb.run(ort::inputs!["input" => input]))?;
    let xgb_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (_s, probs) = outs["probabilities"]
        .try_extract_tensor::<f32>()
        .context("extract xgboost probs")?;
    let probs = probs.to_vec();
    drop(outs);

    let input2 = Tensor::from_array((shape, flat.into_boxed_slice()))?;
    let t1 = Instant::now();
    let outs2 = ap(ifo.run(ort::inputs!["input" => input2]))?;
    let if_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let (_s2, e) = outs2["avg_path_len"]
        .try_extract_tensor::<f32>()
        .context("extract iforest")?;
    let e = e.to_vec();
    drop(outs2);

    println!("[proto] batch({n}) xgboost={xgb_ms:.2}ms  iforest={if_ms:.2}ms");

    // ---- 3) 与 Python 比对 ----
    let py_flat: Vec<f32> = tv.xgb_proba.iter().flatten().copied().collect();
    let ort_flat: Vec<f32> = tv.xgb_proba_ort.iter().flatten().copied().collect();
    let xgb_diff = max_abs_diff(&probs, &py_flat);
    let xgb_diff_ort = max_abs_diff(&probs, &ort_flat);
    let mut agree = 0usize;
    for i in 0..n {
        if argmax(&probs[i * 5..i * 5 + 5]) == argmax(&tv.xgb_proba[i]) {
            agree += 1;
        }
    }
    let if_diff = max_abs_diff(&e, &tv.iforest_avg_path_len);

    println!("[proto] xgboost proba max|diff| rust-ort vs python-sklearn = {xgb_diff:.6e}");
    println!(
        "[proto] xgboost proba max|diff| rust-ort vs python-ort    = {xgb_diff_ort:.6e}  <-- 跨语言一致性"
    );
    println!(
        "[proto]   参考: python-sklearn vs python-ort max|diff| = {:.6e} (导出/训练噪声)",
        tv.xgb_sklearn_vs_ort_maxdiff
    );
    println!(
        "[proto] xgboost argmax agreement = {agree}/{n} ({:.2}%)",
        100.0 * agree as f64 / n as f64
    );
    println!("[proto] iforest avg_path_len max|diff| rust-ort vs python-ort = {if_diff:.6e}");

    // ---- 3b) 判定策略（S7）：双通道 + 融合 ----
    {
        let cfg = decision::DecisionConfig::from_policy(DECISION_POLICY)?;
        println!(
            "[decide] 策略: 融合={}  监督 score=1-P(normal) (normal_class={})  零日 score=-avg_path_len",
            cfg.fusion_policy, cfg.normal_class
        );
        println!(
            "[decide] 零日通道开关 zero_day_enabled = {}{}",
            cfg.zero_day_enabled,
            if cfg.zero_day_enabled {
                ""
            } else {
                "  <-- **安全降级**：零日分数仍计算留证，但不产生 alert"
            }
        );
        println!("[decide] 标定池: {}", cfg.calibration_pool);

        // 策略文件里记的产物名必须与实际加载的文件一致 ——
        // 否则"策略是旧模型的阈值"，这正是本轮发现过的产物错配 bug 类型。
        let base = |p: &str| {
            std::path::Path::new(p)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        };
        assert_eq!(cfg.supervised.artifact, base(XGB_ONNX),
                   "decision_policy 的监督通道产物与实际加载不符");
        assert_eq!(cfg.zero_day.artifact, base(IF_ONNX),
                   "decision_policy 的零日通道产物与实际加载不符");

        // 零日阈值三方一致性：iforest_meta.json（训练记录）vs decision_policy.json（判定依据）
        match std::fs::read_to_string(IF_META) {
            Ok(s) => match serde_json::from_str::<IfMeta>(&s) {
                Ok(m) => match m.zero_day_threshold.thresholds.get(&cfg.zero_day.target_fpr) {
                    Some(t) => {
                        let d = (t - cfg.zero_day.threshold).abs();
                        println!("[decide] 零日阈值交叉校验(iforest_meta vs policy): \
                                  {t:.6}/{:.6} max|diff|={d:.3e}", cfg.zero_day.threshold);
                        assert!(d < 1e-5,
                                "iforest_meta.json 与 decision_policy.json 的零日阈值不一致：\
                                 换了零日模型后必须重跑 python/thresholds.py");
                    }
                    None => println!("[decide] 警告：iforest_meta.json 无档位 {}，跳过交叉校验",
                                     cfg.zero_day.target_fpr),
                },
                Err(e) => println!("[decide] 警告：iforest_meta.json 解析失败（{e}），跳过交叉校验"),
            },
            Err(_) => println!("[decide] 警告：读不到 iforest_meta.json，跳过零日阈值交叉校验"),
        }
        for (tag, ch) in [("监督", &cfg.supervised), ("零日", &cfg.zero_day)] {
            println!("[decide] {tag}通道产物: {}  (score_def: {})", ch.artifact, ch.score_def);
            print!("[decide] {tag}档位(FPR -> 阈值): ");
            for (f, t) in &ch.thresholds {
                print!("{f}->{t:.6}  ");
            }
            println!("| 采用 {} -> {:.6}", ch.target_fpr, ch.threshold);
        }

        // 档位可切换：同一批请求在不同 FPR 预算下的动作分布
        print!("[decide] 各档位动作分布(可配 FPR 预算): ");
        for fpr in cfg.supervised.thresholds.iter().map(|(a, _)| a.clone()).collect::<Vec<_>>() {
            let c = cfg.with_fpr(&fpr)?;
            let mut cnt = [0usize; 3];
            for i in 0..n {
                let v = c.decide(&probs[i * 5..i * 5 + 5], e[i]);
                cnt[match v.action {
                    decision::Action::Allow => 0,
                    decision::Action::Alert => 1,
                    decision::Action::Block => 2,
                }] += 1;
            }
            print!("{fpr}: allow{a}/alert{l}/block{b}  ", a = cnt[0], l = cnt[1], b = cnt[2]);
        }
        println!();

        // 与 Python 期望值比对（**两条通道 + 融合动作**都纳入一致性校验）
        if let Some(dref) = &tv.decision {
            assert_eq!(dref.supervised.score.len(), n, "decision.supervised.score 长度不符");
            assert_eq!(dref.zero_day.score.len(), n, "decision.zero_day.score 长度不符");
            assert_eq!(dref.expected_action.len(), n, "decision.expected_action 长度不符");
            assert_eq!(
                dref.policy_version, cfg.revision,
                "策略修订号不一致：policy v{} vs testvec v{}；请重跑 thresholds.py + export_testvec.py",
                cfg.revision, dref.policy_version
            );
            assert_eq!(dref.fusion_policy, cfg.fusion_policy, "融合策略标识不符");
            assert_eq!(dref.policy_schema, cfg.schema,
                       "decision_policy 与 testvec 的 schema 不一致（请重跑 export_testvec.py）");
            // 策略文件与 testvec 必须同源，规则通道也要对齐：否则会出现
            // "策略里启用了规则、testvec 却按不启用算" 的静默错配。
            assert_eq!(dref.rules.enabled, cfg.rules.enabled,
                       "decision_policy 与 testvec 的 rules.enabled 不一致");
            assert_eq!(dref.rules.ruleset_sha1_16, cfg.rules.ruleset_sha1_16,
                       "decision_policy 与 testvec 的规则集指纹不一致");
            assert_eq!(dref.rules.ruleset_sha1_16_per_sample.len(), n,
                       "decision.rules.ruleset_sha1_16_per_sample 长度不符");
            assert_eq!(dref.rules.weight.len(), n, "decision.rules.weight 长度不符");
            assert_eq!(dref.rules.block_weight.len(), n, "decision.rules.block_weight 长度不符");
            assert!((dref.rules.min_weight_to_block - cfg.rules.min_weight_to_block).abs() < 1e-9,
                    "decision_policy 与 testvec 的 rules.min_weight_to_block 不一致");
            // 策略文件与 testvec 必须同源，零日开关也一样：否则会出现
            // "策略已降级、testvec 还期望 alert" 的静默错配。
            assert_eq!(dref.zero_day_enabled, cfg.zero_day_enabled,
                       "decision_policy 与 testvec 的 zero_day_enabled 不一致，\
                        请重跑 thresholds.py + export_testvec.py");
            // 策略文件与 testvec 必须同源，否则阈值口径会静默漂移
            let td_s = (cfg.supervised.threshold - dref.supervised.threshold).abs();
            let td_z = (cfg.zero_day.threshold - dref.zero_day.threshold).abs();
            println!(
                "[decide] 阈值来源一致性(策略 vs testvec): 监督 {:.6}/{:.6} 零日 {:.6}/{:.6} \
                 (档位 {}) max|diff|={:.3e}/{:.3e}",
                cfg.supervised.threshold, dref.supervised.threshold,
                cfg.zero_day.threshold, dref.zero_day.threshold,
                dref.supervised.target_fpr, td_s, td_z
            );
            assert!(td_s < 1e-6 && td_z < 1e-6,
                    "decision_policy 与 testvec 阈值不一致，请重跑 thresholds.py + export_testvec.py");
            if cfg.rules.enabled {
                if let Some(t) = cfg.supervised.thresholds.iter()
                    .find(|(k, _)| *k == dref.supervised.target_fpr).map(|(_, v)| *v) {
                    println!(
                        "[decide] 规则通道扣减：监督档位 {}(={:.6}) -> 实际采用 {:.6}（差 {:.3e}）\
                         | 规则 {} 条 / block {} 条 | 阻断线 {:.6}",
                        dref.supervised.target_fpr, t, cfg.supervised.threshold,
                        cfg.supervised.threshold - t,
                        cfg.rules.n_rules, cfg.rules.n_block_rules, cfg.rules.min_weight_to_block
                    );
                }
            }

            let (mut ds, mut dz, mut a_agree, mut l_agree) = (0.0f32, 0.0f32, 0usize, 0usize);
            let mut act = [0usize; 3];
            let mut sup_f = 0usize;
            let mut zd_f = 0usize;
            let mut rule_f = 0usize;
            let mut rule_hit = 0usize;
            let mut zd_cross_agree = 0usize;
            let mut zd_crossed = 0usize;
            let mut tp = 0usize; let mut fp = 0usize; let mut fn_ = 0usize; let mut tn = 0usize;
            for i in 0..n {
                // 规则证据逐样本来自 testvec（由 `waf-ai-proto rules replay` 产出）。
                let rev = decision::RuleEvidence {
                    weight: dref.rules.weight[i],
                    block_weight: dref.rules.block_weight[i],
                    ruleset_sha1_16: dref.rules.ruleset_sha1_16_per_sample[i].clone(),
                };
                let v = cfg.decide_with_rules(&probs[i * 5..i * 5 + 5], e[i], &rev);
                ds = ds.max((v.supervised_score - dref.supervised.score[i]).abs());
                dz = dz.max((v.zero_day_score - dref.zero_day.score[i]).abs());
                if v.supervised_flagged == dref.supervised.expected_flagged[i] { sup_f += 1; }
                if v.zero_day_flagged == dref.zero_day.expected_flagged[i] { zd_f += 1; }
                if v.rules_flagged == dref.rules.expected_flagged[i] { rule_f += 1; }
                if v.rule_weight > 0.0 { rule_hit += 1; }
                // 原始穿阈（不随开关变化）也要与 Python 期望值一致 —— 否则"关闭"
                // 会把真实穿阈证据悄悄吞掉。
                if v.zero_day_score_crossed { zd_crossed += 1; }
                if let Some(exp) = &dref.zero_day.expected_crossed {
                    if v.zero_day_score_crossed == exp[i] { zd_cross_agree += 1; }
                }
                if v.action.as_str() == dref.expected_action[i] { a_agree += 1; }
                act[match v.action {
                    decision::Action::Allow => 0,
                    decision::Action::Alert => 1,
                    decision::Action::Block => 2,
                }] += 1;
                // argmax 只用于攻击类型归类；确认两端口径一致（Python 期望=sklearn argmax）
                if v.label == argmax(&tv.xgb_proba[i]) { l_agree += 1; }
                let truth = tv.labels_true[i] != 0;
                match (v.supervised_flagged, truth) {
                    (true, true) => tp += 1, (true, false) => fp += 1,
                    (false, true) => fn_ += 1, (false, false) => tn += 1,
                }
            }
            println!("[decide] 监督 score max|diff| rust vs python = {ds:.6e}");
            println!("[decide] 零日 score max|diff| rust vs python = {dz:.6e}");
            println!("[decide] 标记一致率: 监督 {sup_f}/{n}  零日 {zd_f}/{n}  规则 {rule_f}/{n}");
            if cfg.rules.enabled {
                println!(
                    "[decide] 规则通道（第三通道）：命中样本 {rule_hit}/{n}，\
                     达阻断线 {}；权重只认 `action=block` 的命中",
                    dref.rules.expected_flagged.iter().filter(|x| **x).count()
                );
            } else if dref.rules.weight.iter().any(|w| *w > 0.0) {
                println!(
                    "[decide] 规则通道**未启用**（全局刹车）：本批有 {} 条样本带规则证据，\
                     但它们对动作的贡献是 0 —— 证据只留档，正是 `rules.enabled=false` 的语义",
                    dref.rules.weight.iter().filter(|w| **w > 0.0).count()
                );
            } else if cfg.rules.enabled || !cfg.rules.ruleset_sha1_16.is_empty() {
                println!(
                    "[decide] 规则通道（第三通道）：未启用（enabled={}，指纹={:?}）",
                    cfg.rules.enabled, cfg.rules.ruleset_sha1_16
                );
            }
            if dref.zero_day.expected_crossed.is_some() {
                println!("[decide] 零日**原始穿阈**一致率 = {zd_cross_agree}/{n}  \
                          （本批穿阈 {zd_crossed} 条；开关={}，故不产生 alert）",
                          cfg.zero_day_enabled);
            }
            println!("[decide] **融合动作**一致率 = {a_agree}/{n} ({:.2}%)  分布 allow{}/alert{}/block{}",
                     100.0 * a_agree as f64 / n as f64, act[0], act[1], act[2]);
            println!("[decide] 类型归类(argmax)一致率 = {l_agree}/{n} ({:.2}%)",
                     100.0 * l_agree as f64 / n as f64);
            println!(
                "[decide] 本批监督通道混淆(仅200样本,非验收集): TP={tp} FP={fp} FN={fn_} TN={tn}  \
                 recall={:.1}%  fpr={:.1}%",
                100.0 * tp as f64 / (tp + fn_).max(1) as f64,
                100.0 * fp as f64 / (fp + tn).max(1) as f64
            );
        } else {
            println!("[decide] 警告：testvec.json 无 decision 字段（请重跑 export_testvec.py）");
        }
        if cfg.zero_day_enabled {
            println!(
                "[decide] 注：零日通道单独告警不阻断；但它**跨分布迁移很差**（在 CSIC 上训练的 IF \
                 对 lexical 困难集良性误报 28.2%、本机真实良性 2.63%），上线前必须用本地流量重标定两条阈值"
            );
        } else {
            println!(
                "[decide] 注：零日通道已**安全降级**（zero_day_enabled=false）：分数与穿阈证据保留，\
                 但不产生 alert；判定等价于\"监督通道单独决策\"。要重启它，必须先拿到真实本地良性流量重训 IF，\
                 再重跑 python/thresholds.py --zero-day on + export_testvec.py + 本门禁"
            );
        }
    }

    // ---- 3c) 规则通道（同源回归向量）----
    //
    // 这是规则通道唯一**不依赖 Python** 的回归保护：门禁在没有 Python、没有 ONNX 的环境里，
    // 用 Rust 自己的实现重放 `rules_testvec.json`（生成时已与 Python 参考实现逐字节对齐）。
    // 它同时校验**自写的 SHA-1** —— 那是采集器热重载"变没变"的唯一判据，算错了会静默永不重载。
    if std::path::Path::new(RULES_TESTVEC).exists() {
        let raw = std::fs::read_to_string(RULES_TESTVEC)
            .with_context(|| format!("read {RULES_TESTVEC}"))?;
        let rtv: RuleTestVec =
            serde_json::from_str(&raw).context("parse rules_testvec.json")?;
        let engine = rules::RuleEngine::from_path(std::path::Path::new(RULES_SELFTEST))
            .context("规则集自检文件编译失败（先跑 python/export_rules_testvec.py）")?;

        assert_eq!(
            engine.sha1_16, rtv.ruleset_sha1_16,
            "规则集 SHA-1 与向量记录不一致：Rust 自写实现错了，或文件被改过"
        );
        assert_eq!(engine.n_rules(), rtv.n_rules, "规则条数与向量记录不一致");
        assert_eq!(engine.ruleset_id, rtv.ruleset_id, "规则集 id 与向量记录不一致");
        assert!(
            (engine.min_weight_to_block - rtv.min_weight_to_block).abs() < 1e-9,
            "阻断线与向量记录不一致"
        );

        let mut hit_cases = 0usize;
        let mut block_cases = 0usize;
        let mut n_fields = 0usize;
        for c in &rtv.cases {
            let req = c.req.to_input();

            // ① 解码：6 个字段逐字节比对（`full` 是拼装串，其余是单字段）
            let got = engine.decoded_fields(&req);
            for (k, want) in &c.decoded {
                let mine = got.get(k.as_str()).map(|s| s.as_str()).unwrap_or("<缺失>");
                assert_eq!(
                    mine, want.as_str(),
                    "用例 {} 字段 {k} 的解码结果与 Python 参考实现分叉", c.id
                );
                n_fields += 1;
            }

            // ② 命中集合（按规则去重、排序）
            let hits = engine.evaluate(&req);
            let mut ids: Vec<String> = hits.iter().map(|h| h.rule.clone()).collect();
            ids.sort();
            ids.dedup();
            assert_eq!(ids, c.hits, "用例 {} 的命中集合不一致", c.id);

            // ③ 记分：`weight` = 证据；`block_weight` = 只有 action=block 的命中
            let w = rules::RuleEngine::weight_of(&hits);
            let bw = rules::RuleEngine::block_weight_of(&hits);
            assert!((w - c.weight).abs() < 1e-6, "用例 {} weight {w} != {}", c.id, c.weight);
            assert!(
                (bw - c.block_weight).abs() < 1e-6,
                "用例 {} block_weight {bw} != {}（alert 规则绝不能消耗阻断预算）",
                c.id, c.block_weight
            );
            assert_eq!(engine.blocks(&hits), c.block, "用例 {} 的阻断判定不一致", c.id);

            // ④ 单字段作用域的 `field` 归属
            for d in &c.hit_detail {
                if let Some(want) = &d.expect_field {
                    let mine = hits.iter().find(|h| h.rule == d.rule).map(|h| h.field.as_str());
                    assert_eq!(
                        mine, Some(want.as_str()),
                        "用例 {} 规则 {} 的 field 归属错了", c.id, d.rule
                    );
                }
            }

            if !hits.is_empty() {
                hit_cases += 1;
            }
            if c.block {
                block_cases += 1;
            }
        }
        println!(
            "[rules] 同源回归向量 OK：{} 条用例 × {} 字段解码 + 命中集 + weight/block_weight \
             + 阻断线 + SHA-1，有命中 {hit_cases}，达阻断线 {block_cases}，\
             规则 {} 条 sha1_16={}",
            rtv.cases.len(), n_fields / rtv.cases.len().max(1), engine.n_rules(), engine.sha1_16
        );
    } else {
        println!(
            "[rules] 跳过同源回归向量：{RULES_TESTVEC} 不存在\
             （跑 python/export_rules_testvec.py 生成）"
        );
    }

    // ---- 4) TreeSHAP 可解释性（Rust 实现，对齐 xgboost pred_contribs）----
    let forest = shap::Forest::load(XGB_TREES)?;
    println!(
        "[shap] forest: {} trees / {} classes, base_scores={:?}",
        forest.n_trees(),
        forest.num_class,
        forest.base_scores
    );
    let sr_raw = std::fs::read_to_string(SHAP_REF).with_context(|| format!("read {SHAP_REF}"))?;
    let sr: ShapRef = serde_json::from_str(&sr_raw).context("parse shap_ref.json")?;

    let mut shap_diff = 0.0f32;
    let mut margin_diff = 0.0f32;
    let mut worst_shap = (0usize, 0usize, 0usize);
    for i in 0..sr.n {
        let mine = forest.explain(&sr.features[i]);
        for c in 0..sr.n_class {
            let mut s = 0.0f32;
            for j in 0..=sr.n_features {
                let dd = (mine[c][j] - sr.contribs[i][c][j]).abs();
                if dd > shap_diff {
                    shap_diff = dd;
                    worst_shap = (i, c, j);
                }
                s += mine[c][j];
            }
            let dm = (s - sr.margin[i][c]).abs();
            if dm > margin_diff {
                margin_diff = dm;
            }
        }
    }
    println!("[shap] phi max|diff| rust vs xgboost pred_contribs = {shap_diff:.3e}  (worst s/c/j = {:?})", worst_shap);
    println!("[shap] sum(phi) vs raw margin max|diff| (self-consistency) = {margin_diff:.3e}");

    // 解释示例（样本 0）
    {
        let phi = forest.explain(&sr.features[0]);
        let cls = (0..sr.n_class)
            .max_by(|&a, &b| {
                sr.margin[0][a]
                    .partial_cmp(&sr.margin[0][b])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(0);
        let top = shap::top_features(&phi[cls], 5);
        print!("[shap] sample0 预测类 c{cls}  Top-5 特征: ");
        for (j, v) in &top {
            print!("{}={:+.4}  ", tv.feature_names[*j], v);
        }
        println!("| 偏置={:+.4}", phi[cls][sr.n_features]);
    }

    // ---- 5) 单样本延迟基准 ----
    let sample = tv.features[0].clone();
    let mk = |data: &[f32]| -> Result<Tensor<f32>> {
        Ok(Tensor::from_array(([1usize, d], data.to_vec().into_boxed_slice()))?)
    };

    let bench = |sess: &mut Session, name: &str, iters: usize| -> Result<()> {
        for _ in 0..30 {
            let x = mk(&sample)?;
            let _ = ap(sess.run(ort::inputs!["input" => x]))?;
        }
        let mut ts = Vec::with_capacity(iters);
        for _ in 0..iters {
            let x = mk(&sample)?;
            let t = Instant::now();
            let _ = ap(sess.run(ort::inputs!["input" => x]))?;
            ts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = ts[ts.len() / 2];
        let p99 = ts[(ts.len() as f64 * 0.99) as usize];
        println!("[bench] {name} single-sample: p50={p50:.4}ms p99={p99:.4}ms (n={iters})");
        Ok(())
    };
    bench(&mut xgb, "xgboost", 5000)?;
    bench(&mut ifo, "iforest", 5000)?;

    // TreeSHAP 延迟
    {
        let x0 = sr.features[0].clone();
        for _ in 0..50 {
            let _ = forest.explain(&x0);
        }
        let iters = 2000usize;
        let mut ts = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let _ = forest.explain(&x0);
            ts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "[bench] treeshap single-sample: p50={:.4}ms p99={:.4}ms (n={iters}, {} trees)",
            ts[iters / 2],
            ts[(iters as f64 * 0.99) as usize],
            forest.n_trees()
        );
    }

    // ---- 6) 特征提取延迟（纯 Rust）----
    {
        let req = features::Request::from_json(&tv.requests[0]);
        for _ in 0..200 {
            let _ = features::extract(&req);
        }
        let iters = 20000usize;
        let mut ts = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let _ = features::extract(&req);
            ts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "[bench] feature-extract single-request: p50={:.4}ms p99={:.4}ms (n={iters}, {d} dims)",
            ts[iters / 2],
            ts[(iters as f64 * 0.99) as usize]
        );
    }

    // ---- 7) 端到端单请求延迟：特征 + XGBoost + IForest + TreeSHAP ----
    {
        let req = features::Request::from_json(&tv.requests[0]);
        let mut run_all = || -> Result<()> {
            let f = features::extract(&req);
            let x1 = Tensor::from_array(([1usize, d], f.clone().into_boxed_slice()))?;
            let _ = ap(xgb.run(ort::inputs!["input" => x1]))?;
            let x2 = Tensor::from_array(([1usize, d], f.clone().into_boxed_slice()))?;
            let _ = ap(ifo.run(ort::inputs!["input" => x2]))?;
            let _ = forest.explain(&f);
            Ok(())
        };
        for _ in 0..30 {
            run_all()?;
        }
        let iters = 2000usize;
        let mut ts = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            run_all()?;
            ts.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "[bench] end-to-end (features+xgb+iforest+treeshap): p50={:.4}ms p99={:.4}ms (n={iters})",
            ts[iters / 2],
            ts[(iters as f64 * 0.99) as usize]
        );
    }

    Ok(())
}
