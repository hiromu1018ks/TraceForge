//! TraceForge Finding 統合・ATT&CK crate。
//!
//! Phase 6 で 3 検知結果（Sigma・YARA-X・Correlation）の Match を説明可能な Finding へ
//! 統合する（roadmap §5 Phase 6・規範 §16・製品 §10）。
//!
//! ## 主な機能
//!
//! - **Finding merger**（[`merger`]）: Match list を入力とし、各 Match から1件の Finding
//!   を生成する。自動統合は禁止し、明示統合 rule が指定された場合だけ複数 Match を1つの
//!   Finding へ統合する（規範 §16・T6-001〜T6-005）。
//! - **ATT&CK dataset**（[`attack`]）: MITRE ATT&CK STIX dataset の version pin・SHA-256
//!   記録・Technique ID 検証・mapping 生成を行う（互換 §9・規範 §15.3・T6-006〜T6-009）。
//!
//! ## 設計上の制約
//!
//! - 決定性（規範 §13）: Finding 順序・attribute 順序は安定。iterator 順に依存しない。
//! - Finding は `created_at` を持ってはならない（Schema §5.8）。
//! - Finding ID は決定的生成のみ（規範 §12.4）。
//! - 外部通信は禁止（規範 §2）。ATT&CK dataset は手動で取得して与える。

pub mod attack;
pub mod merger;

pub use attack::{AttackDataset, AttackDatasetError, AttackDatasetManifest, UnknownTechniqueError};
pub use merger::{
    FindingBuildError, FindingBuilder, FindingMergeOptions, FindingMergeRule, FindingMergeSummary,
    MergeGroupId, attach_attack_mappings, manual_attack_mapping,
};
