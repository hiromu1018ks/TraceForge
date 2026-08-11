//! TraceForge Evidence パイプライン crate。
//!
//! Phase 2 で `analyze` 前半（discovery → snapshot → hash → 識別）を実装する
//! （roadmap §5 Phase 2）:
//!
//! - `source_locator` 正規化・決定的 discovery・symlink skip（規範 §5.2–5.3）
//! - read-only snapshot + 同時 SHA-256 + before/after 整合性検証（規範 §5.5）
//! - Evidence ID / Case ID 生成（規範 §4.1、§5.6）
//! - 入出力分離検証と overwrite 保護（規範 §5.4）
//! - Artifact 識別 framework と resource limit（規範 §11、§18）
//!
//! 仕様書の優先順位（AGENTS.md）: schemas > normative > compatibility > product。

pub mod discovery;
pub mod io_safety;
pub mod limit;
pub mod probe;
pub mod snapshot;
pub mod source_locator;

// よく使う主要型をルートへ再公開。
pub use discovery::{
    DiscoveredFile, DiscoveryError, DiscoveryOptions, DiscoveryOutcome, MAX_FILES_LIMIT_CODE,
    SYMLINK_SKIP_CODE, discover, is_non_target_container, max_files_limit_issue,
    symlink_skip_issues,
};
pub use io_safety::{IoSafetyError, verify_io_separation};
pub use limit::{LimitBreach, LimitCheck, LimitKind, LimitTracker};
pub use probe::{
    AMBIGUOUS_SKIP_CODE, MALFORMED_SKIP_CODE, PROBABLE_SKIP_CODE, ProbeInput, ProbeOutcome,
    ProbeResolution, read_header_bytes, resolve_probes,
};
pub use snapshot::{
    FileIdentity, SnapshotError, SnapshotOutcome, failed_evidence, open_snapshot_readonly, snapshot,
};
pub use source_locator::{SourceLocatorError, escape_non_utf8_bytes, normalize_source_locator};
