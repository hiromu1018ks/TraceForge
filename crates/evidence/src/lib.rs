//! TraceForge Evidence パイプライン crate。
//!
//! Phase 2 で `analyze` 前半（discovery → snapshot → hash → 識別）を実装する:
//! - `source_locator` 正規化・決定的 discovery・symlink skip（規範 §5.2–5.3）
//! - read-only snapshot + 同時 SHA-256 + before/after 整合性検証（規範 §5.5）
//! - Evidence ID / Case ID 生成（規範 §4.1、§5.6）
//! - 入出力分離検証と overwrite 保護（規範 §5.4）
//! - Artifact 識別 framework と resource limit（規範 §11、§18）
