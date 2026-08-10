//! TraceForge コアデータモデル crate。
//!
//! 全機能が依存する型と Schema を Phase 1 で実装する:
//! - 決定的 ID 6 種（規範 §12）
//! - 時刻モデル `EventTime` / `TemporalValue`（規範 §6、Schema §4）
//! - `Event` / `Provenance` / `RecordLocator` / `ProcessRef`（規範 §7）
//! - `WindowsPathValue` と `windows-path-v1` profile（規範 §8）
//! - Case / Evidence / Artifact / Issue / Match / Finding / Manifest 型（Schema §5）
//! - canonical JSON serializer と Schema validator（Schema §2.1、§9）
