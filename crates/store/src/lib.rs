//! TraceForge Event Store・Timeline crate。
//!
//! Phase 3 で決定的な Event 永続化・反復の基盤を実装する:
//! - length-delimited spool file Event Store（規範 §10）
//! - timestamp group + Event ID による決定的 iteration（規範 §10）
//! - memory budget 超過時の external merge sort（規範 §10）
//! - Timeline 5 group の順序付け（規範 §6.3）
