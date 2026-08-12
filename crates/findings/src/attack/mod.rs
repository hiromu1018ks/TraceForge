//! ATT&CK dataset・Technique ID 検証・mapping 生成（T6-006〜T6-009・互換 §9・規範 §15.3）。
//!
//! 3 module で構成される:
//! - [`dataset`]: MITRE ATT&CK STIX dataset の manifest（version・SHA-256・取得元）と
//!   Technique 一覧の load（T6-006）
//! - [`technique`]: Technique ID の形式検証・dataset 存在検証（T6-007）
//! - [`mapping`]: Rule / Sigma tag / built-in / manual からの ATT&CK mapping 生成（T6-008・T6-009）
//!
//! ## 外部通信禁止（規範 §2・互換 §9）
//!
//! 本モジュールは network 経由で ATT&CK dataset を取得しない。呼出側（CLI や CI）が
//! 手動で取得した STIX bundle file への path を渡し、本モジュールはそれを読み込んで
//! 検証する。取得元 URL・取得日・version・SHA-256 は [`AttackDatasetManifest`] へ記録する。

pub mod dataset;
pub mod mapping;
pub mod technique;

pub use dataset::{AttackDataset, AttackDatasetError, AttackDatasetManifest};
pub use mapping::{
    built_in_mappings, extract_attack_tags_from_sigma, from_correlation_rule, from_sigma_rule_tags,
    manual_mapping,
};
pub use technique::{UnknownTechniqueError, validate_technique_id_format, validate_technique_ids};
