//! TraceForge 検知エンジン crate。
//!
//! Phase 5 で 3 経路の検知を実装する:
//! - Sigma: TF-SIGMA-1.0 subset evaluator（互換 §6、規範 §15.1）
//! - YARA-X: verified snapshot scan（互換 §7、規範 §15.2）
//! - Correlation: YAML rule 評価・score 計算（Schema §7、規範 §14）
//!
//! 共通編（T5-001〜T5-003）では全経路の前提となる Rule file 取扱基盤を提供する:
//! - Rule file を raw bytes で1回読み込み、SHA-256 を計算する（規範 §14・T5-001）
//! - 同一内容（SHA-256 一致）の再読込を禁止する（規範 §14・T5-001）
//! - Rule directory を正規化相対 path の UTF-8 byte 順で列挙する（規範 §14・T5-002）
//! - Rule validation error を Exit Code 5 へ区分する（規範 §17.2・T5-003）
//!
//! 個別 engine（Sigma/YARA-X/Correlation）は本 module の [`loader`] 基盤を利用し、
//! 取得した raw bytes をそれぞれの parser/compile 処理へ渡す。共通編では
//! YAML parse・Schema 検証は行わず、各 engine の個別 task（T5-010/T5-020/T5-030 等）
//! で実装する。

pub mod loader;
pub mod path_norm;

pub use loader::{
    DiscoveredRuleFile, DiscoveryOutcome, LoadedRuleFile, MAX_RULE_FILES_LIMIT_CODE,
    RuleDiscoveryOptions, RuleFileError, RuleLoadError, RuleLoadOptions, RuleLoadSummary,
    RuleRegistry, SYMLINK_SKIP_CODE, discover_rule_directory,
};
pub use path_norm::{RulePathError, normalize_rule_relative_path};
