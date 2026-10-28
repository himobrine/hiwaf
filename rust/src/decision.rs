//! 判定策略（S7）：把两个模型的输出变成"放行 / 告警 / 阻断"的最终动作。
//!
//! ## 为什么不用 `argmax`
//!
//! `REALDATA_EVALUATION.md` §8.2/§8.3 实测：同一模型换评估切分，`argmax` 的误报落点会在
//! **0.8%–3.0%** 之间乱跳 —— 因为 argmax 隐含的阈值是"类别概率互比"，它随
//! 训练集里少数派良性样本的分布漂移，完全不受控。PRD 要求 FPR < 3%，这种规则无法审计。
//!
//! ## 两条通道 + 融合
//!
//! ```text
//! 监督通道 : score = 1 - P(normal)          （XGBoost，有标签）
//! 零日通道 : score = -avg_path_len          （Isolation Forest，无标签）
//! 各自      : flagged = score >= threshold   （阈值在**未参与训练**的良性流量上标定）
//!
//! 动作      : 监督命中          -> Block（阻断 + 告警）
//!             仅零日命中        -> Alert（告警 + 强制人工复核）
//!             都未命中          -> Allow
//! ```
//!
//! 零日通道**不单独阻断**是刻意的：它的误报语义是"没见过"，不是"确认是攻击"，
//! 直接阻断会把误报变成业务中断。
//!
//! ## 零日通道总开关（安全降级）
//!
//! 策略文件顶层 `zero_day_enabled`（缺省 `true`，保持旧文件行为）为 `false` 时：
//! 零日分数**照常计算并留证**，但不参与融合 —— `zero_day_flagged` 恒为 `false`，
//! 因此**永远不会产生 Alert**，判定退化为"监督通道单独决策"。
//! 原始穿阈结果保留在 `zero_day_score_crossed` 里，不丢证据。
//! 关它的实测理由：它在跨分布下会崩（lexical 困难集良性误报 28.2%、本机真实良性 2.63%），
//! 在拿到真实本地良性流量重训之前，它产生的告警只有人工复核成本。
//!
//! ⚠️ **上线前必须用本地留出流量重标定两个阈值**（`python/thresholds.py --pool file:<本地流量>`）。
//! 这不是程序性提醒，而是有实测依据的：
//!   * 标定池混进训练样本 → 估计偏乐观（§8.3 实测可差 8 倍）；
//!   * 零日通道**跨分布迁移极差**：在 CSIC 正常流量上训练的 IF，对 lexical 困难集的
//!     良性误报高达 **28.2%**（`p3_fusion.json`）—— 它的阈值只在同分布流量上有效。
//!     `thresholds.py` 会拒绝包含训练样本的池，但"分布是否接近"必须人工判断。
//!
//! ⚠️ 本模块只做**判定**，不负责阈值标定。策略文件由 `python/thresholds.py` 生成，
//! 数据面只读；阈值档位可热切换（`with_fpr`），换 FPR 预算不需要重训模型。

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

/// 单条通道的配置。
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// 产物文件名（审计用）。
    pub artifact: String,
    /// 产物内容指纹 `sha1_16`（用于校验"策略阈值"与"实际加载的模型"同源）。
    /// 老策略可能为空串；空串表示不校验（向后兼容）。
    pub artifact_sha1_16: String,
    /// 分数定义（校验用，必须与代码里的算法一致）。
    pub score_def: String,
    /// 当前采用档位的目标 FPR（如 "0.01"）。
    pub target_fpr: String,
    /// 当前档位阈值。
    pub threshold: f32,
    /// 全部档位：目标 FPR -> 阈值（按 FPR 升序）。
    pub thresholds: Vec<(String, f32)>,
}

/// 最终动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 两通道都未命中。
    Allow,
    /// 仅零日通道命中：告警，强制人工复核。
    Alert,
    /// 监督通道命中：阻断。
    Block,
}
impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Alert => "alert",
            Action::Block => "block",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 单个请求的判定结果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// 攻击分数 `1 - P(normal)`，用于排序/证据留存。
    pub supervised_score: f32,
    /// 监督通道是否命中（最终阻断依据）。
    pub supervised_flagged: bool,
    /// 零日分数 `-avg_path_len`（越大越异常）。
    pub zero_day_score: f32,
    /// 零日通道是否**生效命中**（`zero_day_enabled=false` 时恒为 `false`）——告警依据。
    pub zero_day_flagged: bool,
    /// 零日分数是否**原始穿阈**（与开关无关，留证用）。
    pub zero_day_score_crossed: bool,
    /// 规则通道**被采纳**的命中权重和（未被策略认可时恒为 0）——告警依据。
    pub rule_weight: f64,
    /// 规则通道**被采纳**的阻断权重和（只有 `action=block` 的命中计入）——阻断依据。
    pub rule_block_weight: f64,
    /// 规则通道是否达到阻断线。
    pub rules_flagged: bool,
    /// 融合动作。
    pub action: Action,
    /// 多分类标签（argmax）——**仅作攻击类型归类**，不用于判定。
    pub label: usize,
}

/// 规则通道在**一次请求**上的证据（判定器只消费规则引擎的输出，不自己匹配）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleEvidence {
    /// 全部命中的权重和（**证据**：控制台据它说"命中了什么"）
    pub weight: f64,
    /// 只有 `action=block` 的命中才计入（**阻断预算**）
    pub block_weight: f64,
    /// 产生这份证据的规则集指纹。与策略记录不一致 ⇒ 整条规则通道视为未启用。
    pub ruleset_sha1_16: String,
}

/// 规则通道（第三通道）的配置。
#[derive(Debug, Clone)]
pub struct RulesConfig {
    /// **全局刹车**：`false` 时规则命中完全不影响动作（证据仍可留，供人看"本来会怎样"）。
    pub enabled: bool,
    /// 预算是对着**特定**规则集算出来的，所以策略里写死它的指纹；
    /// 磁盘上的规则集指纹与之不符 ⇒ 规则通道不参与融合（宁少拦，不多拦）。
    pub ruleset_sha1_16: String,
    /// 阻断线（对应 CRS 的 `anomaly_score_threshold`）。
    pub min_weight_to_block: f64,
    pub n_rules: usize,
    pub n_block_rules: usize,
}

/// 从 `artifacts/decision_policy.json` 读取的判定配置。
#[derive(Debug, Clone)]
pub struct DecisionConfig {
    /// 正常类在概率向量里的下标（从策略文件反查，不写死）。
    pub normal_class: usize,
    pub supervised: ChannelConfig,
    pub zero_day: ChannelConfig,
    /// 零日通道总开关（策略文件顶层 `zero_day_enabled`，缺省 `true`）。
    /// `false` = 安全降级：零日分数仍计算，但不参与融合、不产生 Alert。
    pub zero_day_enabled: bool,
    /// 规则通道（第三通道）。
    pub rules: RulesConfig,
    /// 融合策略标识（`supervised_block__zero_day_alert` 或
    /// `supervised_block__zero_day_alert__rules_block`）。
    pub fusion_policy: String,
    /// 标定池描述（审计用）。
    pub calibration_pool: String,
    /// 策略文件的结构兼容版本。
    pub schema: u32,
    /// 策略文件的**修订号**（控制台每次重标定 +1）；门禁用它核对 policy 与 testvec 同源。
    pub revision: u32,
}

#[derive(Deserialize)]
struct Policy {
    /// **结构兼容版本**（阈值/通道布局变了才 +1）。数据面据此拒绝不认识的策略结构。
    #[serde(default = "default_one")]
    schema: u32,
    /// **策略修订号**（每次 `thresholds.py` 重标定 +1）。仅审计/展示，不参与兼容判断。
    #[serde(default = "default_one")]
    version: u32,
    #[serde(default = "default_true")]
    zero_day_enabled: bool,
    #[serde(default)]
    calibration_pool: PoolInfo,
    supervised: RawChannel,
    zero_day: RawChannel,
    #[serde(default)]
    rules: RawRules,
    #[serde(default)]
    fusion: Fusion,
}

/// 规则通道块（`schema=2` 新增）。`schema=1` 的老策略文件没有它 ⇒ 规则通道不参与。
#[derive(Deserialize)]
struct RawRules {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ruleset_sha1_16: String,
    #[serde(default = "one_f64")]
    min_weight_to_block: f64,
    #[serde(default)]
    n_rules: usize,
    #[serde(default)]
    n_block_rules: usize,
}

impl Default for RawRules {
    /// ⚠️ **手写** Default，不能用 `#[derive(Default)]`。
    ///
    /// 派生出来的 Default 会把 `min_weight_to_block` 填成 `0.0`（f64 的零值），
    /// 而 serde 的 `#[serde(default = "one_f64")]` 填 1.0 —— 两者不一致。
    /// 策略文件缺 `rules` 块时会走 `Default`，阻断线就变成 0，
    /// 于是 `0 + 1e-9 >= 0` 恒真、**每个请求都被阻断**。这是踩过的坑，别改回去。
    fn default() -> Self {
        Self {
            enabled: false,
            ruleset_sha1_16: String::new(),
            min_weight_to_block: 1.0,
            n_rules: 0,
            n_block_rules: 0,
        }
    }
}

fn one_f64() -> f64 {
    1.0
}

/// 数据面认识的结构版本上限。
///
/// v1 = 双通道；v2 = 三通道（新增 `rules` 块）。
/// 守卫写成 `schema > POLICY_SCHEMA → 拒绝`（而不是 `!=`），这样**新数据面能读老策略**
/// （滚动升级不会因为一个 JSON 就起不来），而**老数据面读新策略会明确报错**。
const POLICY_SCHEMA: u32 = 2;

const FUSION_2: &str = "supervised_block__zero_day_alert";
const FUSION_3: &str = "supervised_block__zero_day_alert__rules_block";

fn default_one() -> u32 {
    1
}

/// 老策略文件没有 `zero_day_enabled` 键时，保持历史行为（启用）。
/// 这样升级数据面不会静默改变判定语义；新文件由 `thresholds.py` 显式写入。
fn default_true() -> bool {
    true
}

#[derive(Deserialize, Default)]
struct PoolInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    n: usize,
    #[serde(default)]
    n_overlap: usize,
}

#[derive(Deserialize, Default)]
struct Fusion {
    #[serde(default)]
    policy: String,
}

#[derive(Deserialize)]
struct RawChannel {
    #[serde(default)]
    artifact: String,
    #[serde(default)]
    artifact_sha1_16: String,
    #[serde(default)]
    score_def: String,
    #[serde(default)]
    target_fpr: String,
    #[serde(default)]
    threshold: Option<f32>,
    #[serde(default)]
    thresholds: HashMap<String, f32>,
    #[serde(default)]
    normal_class_index: Option<usize>,
    #[serde(default)]
    labels: HashMap<String, String>,
}

fn fpr_key(s: &str) -> f64 {
    s.parse::<f64>().unwrap_or(0.0)
}

impl ChannelConfig {
    fn from_raw(raw: RawChannel, expect_score_def: &str, channel: &str) -> Result<Self> {
        if !raw.score_def.is_empty() && raw.score_def != expect_score_def {
            anyhow::bail!(
                "策略文件 {channel} 的 score_def = {:?}，本实现只支持 {:?}",
                raw.score_def, expect_score_def
            );
        }
        let mut thresholds: Vec<(String, f32)> = raw.thresholds.into_iter().collect();
        if thresholds.is_empty() {
            anyhow::bail!("策略文件 {channel} 缺 thresholds");
        }
        thresholds.sort_by(|a, b| fpr_key(&a.0).partial_cmp(&fpr_key(&b.0)).unwrap());
        let target_fpr = if raw.target_fpr.is_empty() {
            anyhow::bail!("策略文件 {channel} 缺 target_fpr");
        } else {
            raw.target_fpr
        };
        let threshold = raw.threshold.unwrap_or_else(|| {
            thresholds.iter().find(|(k, _)| *k == target_fpr).map(|(_, v)| *v).unwrap_or(0.5)
        });
        Ok(Self { artifact: raw.artifact, artifact_sha1_16: raw.artifact_sha1_16,
                  score_def: expect_score_def.to_string(),
                  target_fpr, threshold, thresholds })
    }

    /// 用指定档位覆盖阈值（用于对比不同 FPR 预算）。
    pub fn with_fpr(&self, fpr: &str) -> Option<Self> {
        let t = self.thresholds.iter().find(|(k, _)| k == fpr)?.1;
        let mut c = self.clone();
        c.target_fpr = fpr.to_string();
        c.threshold = t;
        Some(c)
    }
}

impl DecisionConfig {
    /// 加载判定策略（数据面只读此文件）。
    pub fn from_policy(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        let p: Policy = serde_json::from_str(&raw)
            .with_context(|| format!("parse {path}（请用 python/thresholds.py 生成）"))?;

        // `schema` 才是结构兼容守卫；`version` 是策略修订号（控制台会把它 +1），
        // 因此这里**不能**用 `version != 1` 去卡 —— 那会把正常重标定判成不兼容。
        if p.schema == 0 || p.schema > POLICY_SCHEMA {
            anyhow::bail!(
                "不支持的 decision_policy schema {}（本数据面支持 1..={POLICY_SCHEMA}）",
                p.schema
            );
        }
        let fusion_policy = if p.fusion.policy.is_empty() {
            FUSION_2.to_string()
        } else {
            p.fusion.policy.clone()
        };
        if fusion_policy != FUSION_2 && fusion_policy != FUSION_3 {
            anyhow::bail!("不支持的 fusion.policy = {fusion_policy:?}");
        }
        // 融合串与规则块必须自洽：说"规则参与"就必须启用规则通道，反之亦然。
        // 这两处不一致一定是手改了策略文件（thresholds.py 不会产出这种组合），
        // 而"手改的策略"是本项目最不希望出现的状态。
        let declares_rules = fusion_policy == FUSION_3;
        if declares_rules != p.rules.enabled {
            anyhow::bail!(
                "策略自相矛盾：fusion.policy={fusion_policy:?} 但 rules.enabled={}；\
                 请用 python/thresholds.py 重新生成（不要手改策略文件）",
                p.rules.enabled
            );
        }
        if p.rules.min_weight_to_block <= 0.0 {
            // 阻断线 ≤0 意味着"任何命中都阻断"，包括缺省值 0.0 —— 那是"默认开火"，
            // 不是策略。无论规则通道是否启用都拒绝。
            anyhow::bail!(
                "rules.min_weight_to_block = {}（≤0）：任何命中都会被判成阻断。拒绝加载。",
                p.rules.min_weight_to_block
            );
        }
        if p.rules.enabled && p.rules.ruleset_sha1_16.is_empty() {
            anyhow::bail!("规则通道已启用但缺 ruleset_sha1_16：预算无法与规则集绑定，拒绝加载");
        }
        let normal_class = p
            .supervised
            .normal_class_index
            .or_else(|| {
                p.supervised
                    .labels
                    .iter()
                    .find(|(_, v)| v.as_str() == "normal")
                    .and_then(|(k, _)| k.parse::<usize>().ok())
            })
            .unwrap_or(0);

        // 标定池必须与训练集无交集；这是 thresholds.py 的守卫写进文件的结论
        if p.calibration_pool.n_overlap > 0 {
            anyhow::bail!(
                "策略文件的标定池含 {} 条训练样本（偏乐观），拒绝加载",
                p.calibration_pool.n_overlap
            );
        }
        let calibration_pool = format!(
            "{}（n={}, 与训练集同源 {} 条）",
            p.calibration_pool.name, p.calibration_pool.n, p.calibration_pool.n_overlap
        );

        Ok(Self {
            normal_class,
            schema: p.schema,
            revision: p.version,
            supervised: ChannelConfig::from_raw(p.supervised, "1 - P(normal)", "supervised")?,
            zero_day: ChannelConfig::from_raw(p.zero_day, "-avg_path_len", "zero_day")?,
            zero_day_enabled: p.zero_day_enabled,
            rules: RulesConfig {
                enabled: p.rules.enabled,
                ruleset_sha1_16: p.rules.ruleset_sha1_16,
                min_weight_to_block: p.rules.min_weight_to_block,
                n_rules: p.rules.n_rules,
                n_block_rules: p.rules.n_block_rules,
            },
            fusion_policy,
            calibration_pool,
        })
    }

    /// 用指定档位覆盖两条通道的阈值。
    pub fn with_fpr(&self, fpr: &str) -> Result<Self> {
        Ok(Self {
            supervised: self
                .supervised
                .with_fpr(fpr)
                .with_context(|| format!("监督通道无档位 {fpr}"))?,
            zero_day: self
                .zero_day
                .with_fpr(fpr)
                .with_context(|| format!("零日通道无档位 {fpr}"))?,
            ..self.clone()
        })
    }

    /// 监督通道攻击分数 `1 - P(normal)`。概率向量须与 labels 同序（sklearn 类别升序）。
    #[inline]
    pub fn supervised_score(&self, proba_row: &[f32]) -> f32 {
        1.0 - proba_row.get(self.normal_class).copied().unwrap_or(1.0)
    }

    /// 零日通道攻击分数 `-avg_path_len`（越大越异常）。
    #[inline]
    pub fn zero_day_score(&self, avg_path_len: f32) -> f32 {
        -avg_path_len
    }

    /// 规则证据是否**被策略认可**。
    ///
    /// 两道门，缺一不可：
    ///   ① 全局刹车 `rules.enabled`（控制台可一键关掉整条通道）；
    ///   ② **指纹一致** —— 预算是对着特定规则集在特定池上算出来的，
    ///      磁盘上的规则集换了就不是同一个预算了。
    ///
    /// 任一不满足 ⇒ 规则通道完全不影响动作（证据仍会落盘，供人看"本来会怎样"）。
    /// 方向永远是**宁少拦、不多拦**：拦错了是业务中断，少拦一次可以事后补。
    pub fn rule_evidence_honored(&self, ev: &RuleEvidence) -> bool {
        self.rules.enabled
            && !self.rules.ruleset_sha1_16.is_empty()
            && ev.ruleset_sha1_16 == self.rules.ruleset_sha1_16
    }

    /// 判定：三通道各自与阈值比较，再按融合策略给出动作（无规则证据）。
    #[inline]
    pub fn decide(&self, proba_row: &[f32], avg_path_len: f32) -> Verdict {
        self.decide_with_rules(proba_row, avg_path_len, &RuleEvidence::default())
    }

    /// 判定：三通道各自与阈值比较，再按融合策略给出动作。
    ///
    /// 融合语义（与 `python/thresholds.py::build_decision_block` 必须逐条一致）：
    /// ```text
    /// 监督命中                      -> block
    /// 规则 block 权重 ≥ 阻断线        -> block
    /// 否则 零日生效命中 或 规则有命中 -> alert
    /// 否则                          -> allow
    /// ```
    #[inline]
    pub fn decide_with_rules(&self, proba_row: &[f32], avg_path_len: f32,
                             rule_ev: &RuleEvidence) -> Verdict {
        let supervised_score = self.supervised_score(proba_row);
        let zero_day_score = self.zero_day_score(avg_path_len);
        let supervised_flagged = supervised_score >= self.supervised.threshold;
        // 原始穿阈与"生效命中"分开：关闭开关时分数与穿阈结果仍然留证，
        // 只是不再参与融合（否则就丢了"本来会告警"的证据）。
        let zero_day_score_crossed = zero_day_score >= self.zero_day.threshold;
        let zero_day_flagged = zero_day_score_crossed && self.zero_day_enabled;

        // 规则通道：未被认可就当 0（证据只留在记录里）。
        let honored = self.rule_evidence_honored(rule_ev);
        let rule_weight = if honored { rule_ev.weight } else { 0.0 };
        let rule_block_weight = if honored { rule_ev.block_weight } else { 0.0 };
        // `rules_flagged` **必须**也挂在 `honored` 上，而不是只比 `min_weight_to_block`。
        // 否则一个缺省的 0.0 阻断线就能让每个请求都命中 —— 判定逻辑里不允许存在
        // "策略没说要拦，但默认开火"的路径。
        let rules_flagged =
            honored && rule_block_weight + 1e-9 >= self.rules.min_weight_to_block;

        Verdict {
            supervised_score,
            supervised_flagged,
            zero_day_score,
            zero_day_flagged,
            zero_day_score_crossed,
            rule_weight,
            rule_block_weight,
            rules_flagged,
            action: if supervised_flagged || rules_flagged {
                Action::Block
            } else if zero_day_flagged || rule_weight > 0.0 {
                Action::Alert
            } else {
                Action::Allow
            },
            label: argmax(proba_row),
        }
    }
}

fn argmax(row: &[f32]) -> usize {
    row.iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(artifact: &str, thr: f32) -> ChannelConfig {
        ChannelConfig {
            artifact: artifact.into(),
            artifact_sha1_16: String::new(),
            score_def: String::new(),
            target_fpr: "0.01".into(),
            threshold: thr,
            thresholds: vec![("0.01".into(), thr)],
        }
    }

    fn cfg(rules_enabled: bool, min_w: f64) -> DecisionConfig {
        DecisionConfig {
            normal_class: 0,
            supervised: ch("xgb", 0.7),
            zero_day: ch("if", -7.0),
            zero_day_enabled: false,
            rules: RulesConfig {
                enabled: rules_enabled,
                ruleset_sha1_16: if rules_enabled { "abc".into() } else { String::new() },
                min_weight_to_block: min_w,
                n_rules: 1,
                n_block_rules: 1,
            },
            fusion_policy: FUSION_2.into(),
            calibration_pool: "unit-test".into(),
            schema: 2,
            revision: 1,
        }
    }

    /// 回归：**规则通道没被认可时，多大的证据都不能产生动作**。
    ///
    /// 这条测试是为一个真踩过的坑写的：`RawRules` 曾用 `#[derive(Default)]`，
    /// 把 `min_weight_to_block` 填成 `0.0`（而 serde 的缺省是 1.0），
    /// 于是 `0 + 1e-9 >= 0` 恒真 —— 每个请求都被 block，而策略里根本没启用规则通道。
    #[test]
    fn unhonored_rule_evidence_never_acts() {
        let p = [0.5f32, 0.5, 0.0, 0.0, 0.0]; // 监督分 0.5 < 0.7，不命中
        let loud = RuleEvidence {
            weight: 99.0,
            block_weight: 99.0,
            ruleset_sha1_16: "abc".into(),
        };

        // ① 全局刹车关着 ⇒ 证据再大也不动。
        let mut c = cfg(false, 1.0);
        let v = c.decide_with_rules(&p, -5.0, &loud);
        assert!(!v.rules_flagged, "未启用时不许达阻断线");
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.rule_weight, 0.0);

        // ② 启用了但**指纹不符** ⇒ 同样不生效（预算是对着特定规则集算的）。
        c.rules.enabled = true;
        c.rules.ruleset_sha1_16 = "abc".into(); // 策略里必然带着它认可的指纹
        let other = RuleEvidence { ruleset_sha1_16: "other".into(), ..loud.clone() };
        let v = c.decide_with_rules(&p, -5.0, &other);
        assert!(!v.rules_flagged, "指纹不符时不许生效");
        assert_eq!(v.action, Action::Allow);

        // ③ 指纹对上且达阻断线 ⇒ block。
        let v = c.decide_with_rules(&p, -5.0, &loud);
        assert!(v.rules_flagged);
        assert_eq!(v.action, Action::Block);

        // ④ 缺省的 0.0 阻断线绝不能让**空证据**命中（"默认开火"）。
        let c0 = cfg(false, 0.0);
        let v = c0.decide_with_rules(&p, -5.0, &RuleEvidence::default());
        assert_eq!(v.action, Action::Allow, "缺省 0.0 阻断线不许让空证据命中");
        assert!(!v.rules_flagged);
    }

    /// `action=alert` 的规则只告警，绝不阻断（权限最小化）。
    #[test]
    fn alert_only_rule_cannot_block() {
        let p = [0.5f32, 0.5, 0.0, 0.0, 0.0];
        let c = cfg(true, 1.0);
        let ev = RuleEvidence {
            weight: 99.0,          // 证据很大
            block_weight: 0.0,     // 但没有 block 规则的权重
            ruleset_sha1_16: "abc".into(),
        };
        let v = c.decide_with_rules(&p, -5.0, &ev);
        assert!(!v.rules_flagged);
        assert_eq!(v.action, Action::Alert, "有命中但不够阻断线 ⇒ 告警");
        assert_eq!(v.rule_weight, 99.0);
    }

    // ------------------------------------------------------------------ 策略文件守卫
    //
    // 这些是**跨版本契约**：老数据面读新策略必须明确失败（而不是猜着跑），
    // 新数据面读老策略必须能起来（滚动升级时不会因为一个 JSON 就整机停摆）。

    fn tmp_policy(tag: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("waf_policy_{}_{}.json", tag, std::process::id()));
        std::fs::write(&p, body).expect("写临时策略");
        p
    }

    fn chan(score_def: &str, thr: f32) -> String {
        format!(
            r#"{{"artifact":"m.onnx","score_def":"{score_def}","target_fpr":"0.01",
                 "threshold":{thr},"thresholds":{{"0.01":{thr}}}}}"#
        )
    }

    fn policy_json(schema: u32, fusion: &str, rules: Option<&str>) -> String {
        // 注意：`"rules": null` 与"键不存在"对 serde 是不同的 —— `null` 不会被
        // `#[serde(default)]` 兜住，会直接反序列化失败。真实的老策略是**缺这个键**。
        let rules_part = match rules {
            Some(r) => format!(r#","rules":{r}"#),
            None => String::new(),
        };
        format!(
            r#"{{"schema":{schema},"version":7,"zero_day_enabled":false,
                 "supervised":{},"zero_day":{}{rules_part},
                 "fusion":{{"policy":"{fusion}"}}}}"#,
            chan("1 - P(normal)", 0.7),
            chan("-avg_path_len", -7.0),
        )
    }

    #[test]
    fn older_schema_without_rules_block_still_loads() {
        // 滚动升级：新数据面必须能读 schema=1 的老策略，且规则通道自动视为未启用。
        let p = tmp_policy("v1", &policy_json(1, FUSION_2, None));
        let c = DecisionConfig::from_policy(&p.to_string_lossy()).expect("schema=1 应当能加载");
        assert_eq!(c.schema, 1);
        assert!(!c.rules.enabled, "老策略没有 rules 块 ⇒ 规则通道不参与");
        // 缺省阻断线必须是 1.0，不是 0.0 —— 0.0 会让空证据也命中（见上面的回归测试）。
        assert_eq!(c.rules.min_weight_to_block, 1.0);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn newer_schema_is_rejected() {
        let p = tmp_policy("v3", &policy_json(3, FUSION_2, None));
        let e = DecisionConfig::from_policy(&p.to_string_lossy())
            .expect_err("schema=3 必须被拒绝")
            .to_string();
        assert!(e.contains("schema"), "错误信息要指明是 schema 问题，实际：{e}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn contradictory_fusion_and_rules_is_rejected() {
        // 融合串说"规则不参与"，rules 块却说"启用" —— 只可能是手改了策略文件。
        let rules = r#"{"enabled":true,"ruleset_sha1_16":"deadbeefdeadbeef","min_weight_to_block":1.0}"#;
        let p = tmp_policy("contra", &policy_json(2, FUSION_2, Some(rules)));
        let e = DecisionConfig::from_policy(&p.to_string_lossy())
            .expect_err("自相矛盾的策略必须被拒绝")
            .to_string();
        assert!(e.contains("矛盾"), "错误信息要指明矛盾，实际：{e}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn zero_block_threshold_is_rejected() {
        let rules = r#"{"enabled":true,"ruleset_sha1_16":"deadbeefdeadbeef","min_weight_to_block":0}"#;
        let p = tmp_policy("zerothr", &policy_json(2, FUSION_3, Some(rules)));
        let e = DecisionConfig::from_policy(&p.to_string_lossy())
            .expect_err("阻断线 0 必须被拒绝")
            .to_string();
        assert!(e.contains("min_weight_to_block"), "实际：{e}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn schema_2_three_channel_loads() {
        let rules = r#"{"enabled":true,"ruleset_sha1_16":"deadbeefdeadbeef",
                        "min_weight_to_block":1.0,"n_rules":7,"n_block_rules":2}"#;
        let p = tmp_policy("v2", &policy_json(2, FUSION_3, Some(rules)));
        let c = DecisionConfig::from_policy(&p.to_string_lossy()).expect("schema=2 三通道应当能加载");
        assert_eq!(c.fusion_policy, FUSION_3);
        assert!(c.rules.enabled);
        assert_eq!(c.rules.n_rules, 7);
        assert_eq!(c.rules.n_block_rules, 2);
        let _ = std::fs::remove_file(&p);
    }
}
