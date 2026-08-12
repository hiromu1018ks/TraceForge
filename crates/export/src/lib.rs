//! TraceForge Exporter crate（Phase 7・規範 §19・Schema §5・§6・互換 §8・§10）。
//!
//! 6 種の出力形式を提供する:
//! - [`text`]: Text exporter（制御文字・ESC の可視 escape、規範 §19.1）
//! - [`json`]: JSON exporter（Case JSON Schema §5）
//! - [`jsonl`]: JSONL exporter（固定出力順・Manifest 最終行、Schema §6）
//! - [`csv`]: CSV exporter（RFC 4180・formula injection 対策、規範 §19.2）
//! - [`html`]: HTML exporter（offline・CSP 埋込・text node escape、規範 §19.3）
//! - [`timesketch`]: Timesketch exporter（TF-TIMESKETCH-1.0、互換 §8）
//!
//! 共通の安全性要件（規範 §19）:
//! - JSON / JSONL は UTF-8・LF・NaN/Infinity 禁止（規範 §19.4）
//! - 出力 injection（CSV formula / terminal ESC / HTML script）を防ぐ（規範 §21-11）
//! - 異なる Schema major version の自動変換は禁止する（互換 §10）
//!
//! ## 決定性（規範 §13）
//!
//! 出力順・attribute 順序は安定し、iterator 順に依存しない。 [`case_data::CaseData`] は
//! 出力直前に毎回 sort するため、呼出側の構築順序へ影響されない。

pub mod case_data;
pub mod csv;
pub mod error;
pub mod html;
pub mod json;
pub mod jsonl;
pub mod manifest;
pub mod sanitize;
pub mod schema_check;
pub mod text;
pub mod timesketch;

pub use case_data::CaseData;
pub use error::ExportError;
pub use manifest::{ManifestFinalizationInput, finalize_manifest};
pub use schema_check::{check_case_schema_major, check_jsonl_schema_major};
