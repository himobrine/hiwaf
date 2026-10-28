//! WAF AI 数据面公共库。
//!
//! 拆出 lib 的目的：**判定代码只有一份**。原来 `features.rs` / `decision.rs` / `shap.rs` 只被
//! `main.rs`（门禁自检程序）使用，采集代理要接判定就只能复制一份 —— 复制必然漂移，
//! 门禁也就失去意义。现在两侧共用同一份：
//!
//!   * `main.rs`（bin `waf-ai-proto`）—— 与 Python 逐位比对的门禁/基准；
//!   * `proxy/`（crate `waf-collector`）—— 真实采集数据面（dry-run 判定）。
//!
//! 特征契约 v2（80 维）的唯一事实来源是 `features.rs`；判定阈值的唯一事实来源是
//! `python/artifacts/decision_policy.json`（由 `thresholds.py` 生成，运行期只读）。

pub mod decision;
pub mod decode;
pub mod engine;
pub mod features;
pub mod hash;
pub mod rules;
pub mod rules_cli;
pub mod shap;
