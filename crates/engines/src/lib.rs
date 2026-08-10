//! TraceForge 検知エンジン crate。
//!
//! Phase 5 で 3 経路の検知を実装する:
//! - Sigma: TF-SIGMA-1.0 subset evaluator（互換 §6、規範 §15.1）
//! - YARA-X: verified snapshot scan（互換 §7、規範 §15.2）
//! - Correlation: YAML rule 評価・score 計算（Schema §7、規範 §14）
