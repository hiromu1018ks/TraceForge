//! TraceForge コアデータモデル crate。
//!
//! 全機能が依存する型と Schema を Phase 1 で実装する（roadmap §5 Phase 1）:
//! - 決定的 ID 6 種（規範 §12）
//! - 時刻モデル `EventTime` / `TemporalValue`（規範 §6、Schema §4）
//! - `Event` / `Provenance` / `RecordLocator` / `ProcessRef`（規範 §7）
//! - `WindowsPathValue` と `windows-path-v1` profile（規範 §8）
//! - Case / Evidence / Artifact / Issue / Match / Finding / Manifest 型（Schema §5）
//! - canonical JSON serializer と Schema validator（Schema §2.1、§9）
//! - TOML 設定・Error 型・Exit Code（Schema §8、規範 §17）
//!
//! 仕様書の優先順位（AGENTS.md）: schemas > normative > compatibility > product。
//! 矛盾時は形式は schemas、動作は normative が正本。

pub mod canonical;
pub mod case;
pub mod config;
pub mod error;
pub mod event;
pub mod finding;
pub mod hash;
pub mod id;
pub mod issue;
pub mod jsonl;
pub mod length_prefixed;
pub mod manifest;
#[path = "match_.rs"]
pub mod r#match;
pub mod path;
pub mod schema;
pub mod time;

// よく使う主要型をルートへ再公開。モジュール経由のアクセスも可能。
// `SCHEMA_VERSION` 定数はモジュールごとに存在するためルートへは再公開しない
// （`tf_core::schema::SCHEMA_VERSION` 等で参照すること）。
pub use case::{
    ArtifactInstance, CaseMetadata, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult,
    Severity,
};
pub use config::Config;
pub use error::{ExitCode, StrictMode, StrictScope, StrictScopeParseError, TraceForgeError};
pub use event::{
    ArtifactSource, AssertionKind, Event, EventType, ProcessRef, Provenance, RecordLocator,
};
pub use finding::{AttackMapping, Confidence, ConfidenceLevel, Finding, RuleRef, Score};
pub use issue::{Issue, IssueScope, IssueSeverity};
pub use jsonl::{CaseBundle, JsonlRecord};
pub use manifest::{Manifest, ManifestCounts};
pub use path::WindowsPathValue;
pub use schema::{JsonSchemaValidator, SCHEMA_MAJOR, SchemaError};
pub use time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};
