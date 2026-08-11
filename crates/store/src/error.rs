//! Event Store と出力の Error 型（規範 §10、§17）。
//!
//! Event Store 関連の error は分析全体の Fatal 扱い（Exit Code 10）へ昇格できる。
//! Event ID 重複・Schema 違反は呼出側で Warning 扱いにする余地を残す。

use tf_core::schema::SchemaError;

/// Event Store の error（規範 §10）。
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// spool file の新規作成に失敗した、または既存 file が上書き対象ではない。
    #[error("Event Store の作成 error: {0}")]
    Create(String),
    /// spool file の open・読み書きに失敗した。
    #[error("Event Store の I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// spool file の magic / version が不正、または形式が壊れている。
    #[error("Event Store の形式 error: {0}")]
    Format(String),
    /// 同一 Event ID を2回書き込もうとした（規範 §10: Event ID 一意制約）。
    #[error("Event ID が既に存在する（一意制約違反）: {0}")]
    DuplicateEventId(String),
    /// Event の Schema 検証が失敗した（規範 §10: Event ごとの Schema validation）。
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// Event の canonical JSON への直列化・復元に失敗した。
    #[error("Event の直列化 error: {0}")]
    Serialize(String),
    /// commit 済み Event Store へ更に Event を書き込もうとした。
    #[error("commit 済み Event Store への追記は禁止: {0}")]
    AlreadyCommitted(String),
    /// 未 commit の Event Store を読み出そうとした（規範 §10: commit marker）。
    #[error("未 commit の Event Store は未完了 Case として扱う: {0}")]
    NotCommitted(String),
    /// external merge sort の作業 file 生成に失敗した。
    #[error("external merge sort error: {0}")]
    ExternalSort(String),
}

/// Timeline・出力の error。
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// 出力先への書き込みに失敗した。
    #[error("出力 I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Event Store から Event を読み出せなかった。
    #[error(transparent)]
    Store(#[from] StoreError),
    /// canonical JSON の構築に失敗した。
    #[error("canonical JSON 構築 error: {0}")]
    Canonical(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_event_id_carries_id() {
        let e = StoreError::DuplicateEventId("tf-event-v1:abc".into());
        assert!(matches!(e, StoreError::DuplicateEventId(_)));
        let msg = format!("{e}");
        assert!(msg.contains("tf-event-v1:abc"));
    }

    #[test]
    fn schema_error_wraps_core() {
        let inner = SchemaError::Validation("bad".into());
        let e = StoreError::Schema(inner);
        assert!(matches!(e, StoreError::Schema(_)));
    }

    #[test]
    fn io_error_wraps_std() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e = StoreError::Io(io);
        assert!(matches!(e, StoreError::Io(_)));
    }
}
