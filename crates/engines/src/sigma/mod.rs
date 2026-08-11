//! Sigma subset evaluator（TF-SIGMA-1.0）。
//!
//! Phase 5 Sigma 編（T5-010〜T5-017）で実装する。
//! 共通編（T5-001〜T5-003）の [`crate::RuleRegistry`] が読み込んだ raw bytes を
//! [`crate::yaml`] parser へ渡し、Sigma Rule へ変換して評価する。

pub mod condition;
pub mod evaluator;
pub mod fieldmap;
pub mod logsource;
pub mod modifier;
pub mod rule;
