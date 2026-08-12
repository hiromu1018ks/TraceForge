//! Exporter の Error 型（規範 §17.2）。
//!
//! Exporter は主に次の3種の error を出す:
//! - `Io`: 書き込み失敗（Exit Code 4 へ寄与）
//! - `Canonical`: canonical JSON 構築失敗（NaN/Infinity 等・Exit Code 4）
//! - `Schema`: 異 Schema major version 等（互換 §10・Exit Code 4）

use tf_core::canonical::CanonicalError;

/// Exporter の error。
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// 出力書き込み時の I/O error。規範 §17.2 の Exit Code 4（出力作成 error）へ寄与する。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// canonical JSON 構築失敗。NaN/Infinity 等の禁止値が含まれた（規範 §19.4）。
    #[error("canonical JSON 変換 error: {0}")]
    Canonical(String),

    /// 異なる Schema major version を自動変換しようとした（互換 §10・禁止）。
    #[error("Schema major version 不一致: {0}")]
    Schema(String),

    /// HTML の CSP 等、出力安全性上の内部不整合。
    #[error("出力安全性 error: {0}")]
    Safety(String),
}

impl From<CanonicalError> for ExportError {
    fn from(value: CanonicalError) -> Self {
        ExportError::Canonical(value.to_string())
    }
}
