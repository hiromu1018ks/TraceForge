//! Correlation Rule 評価エンジン（Schema §7・規範 §14）。
//!
//! Phase 5 Correlation 編（T5-030〜T5-042）で実装する。共通編（T5-001〜T5-003）の
//! [`crate::RuleRegistry`]・[`crate::LoadedRuleFile`] と Sigma 編（T5-010〜T5-017）の
//! [`crate::yaml`] parser を前提とし、raw_bytes() で借りた bytes を YAML parser へ渡す
//! （規範 §14: 同じ bytes を使う）。
//!
//! ## 評価の流れ
//!
//! 1. [`parse_correlation_rule`] が YAML → [`CorrelationRule`] 構造体へ変換する（T5-030）
//! 2. [`validate_correlation_schema`] が JSON Schema へ則ることを検証する（T5-031）
//! 3. [`CompiledCorrelationRule::compile`] が上記を統合し、window 上限なども検査する
//! 4. [`CompiledCorrelationRule::evaluate`] が Event iterator から Match list を生成する
//!    （T5-032〜T5-042）
//!
//! ## 規範対応
//!
//! - §14: 1回読込・raw bytes SHA-256（[`crate::loader`] で担保）
//! - §14.1: 評価の既定値（hostname 不明・不確実時刻・null 厳密比較・未対応 operator skip）
//! - §14.2: Match 重複生成禁止・`max_matches` 打ち切り・Exit Code 1/5
//! - §14.3: Score 計算（base + adjustments・clamp・level 変換）・同一 Evidence 二重加点防止
//! - §6.4: Correlation 時刻規則（不確実時刻は既定で非 match・許可時は記録）

pub mod evaluator;
pub mod fieldresolver;
pub mod predicate;
pub mod rule;

pub use evaluator::{
    CompiledCorrelationRule, CorrelationEvaluationResult, CorrelationEvaluationWarning,
    CorrelationMatchResult, DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
};
pub use predicate::{Operator, Predicate, PredicateValue};
pub use rule::{
    AssertionFilter, CorrelationError, CorrelationRule, PartitionKey, ScoreSpec, Step,
    parse_correlation_rule, validate_correlation_schema,
};
