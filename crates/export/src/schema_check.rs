//! Schema version 互換性検証（互換 §10・Schema §2.3・T7-009）。
//!
//! 互換 §10 は「`export` は異なる Schema major version を自動変換してはならない。
//! 明示的 migration component がある場合だけ変換し、変換前後の Schema version を
//! Manifest へ記録する」と定める。
//!
//! 本 module は Case JSON・JSONL の `schema_version` を検証し、major version が
//! `1`（Schema §1）以外の場合は error とする。

use tf_core::schema::{SCHEMA_MAJOR, check_major_version};

use crate::error::ExportError;

/// Case JSON の `schema_version` の major が現行（`1`）と一致するか（互換 §10）。
///
/// `value` は Case JSON の top-level object と想定する。
/// `schema_version` が無い・文字列でない・major が異なる場合は [`ExportError::Schema`]。
pub fn check_case_schema_major(value: &serde_json::Value) -> Result<(), ExportError> {
    let sv = value
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ExportError::Schema("Case JSON に schema_version が無いか文字列ではない".into())
        })?;
    check_major_version(sv, SCHEMA_MAJOR).map_err(|e| ExportError::Schema(e.to_string()))
}

/// JSONL envelope の `schema_version` の major が現行（`1`）と一致するか（互換 §10）。
pub fn check_jsonl_schema_major(value: &serde_json::Value) -> Result<(), ExportError> {
    let sv = value
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ExportError::Schema("JSONL envelope に schema_version が無いか文字列ではない".into())
        })?;
    check_major_version(sv, SCHEMA_MAJOR).map_err(|e| ExportError::Schema(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_current_major() {
        let v = json!({"schema_version": "1.0.0"});
        assert!(check_case_schema_major(&v).is_ok());
        assert!(check_jsonl_schema_major(&v).is_ok());
    }

    #[test]
    fn rejects_future_major() {
        // 互換 §10: 異なる major version は自動変換禁止。
        let v = json!({"schema_version": "2.0.0"});
        assert!(check_case_schema_major(&v).is_err());
        assert!(check_jsonl_schema_major(&v).is_err());
    }

    #[test]
    fn rejects_missing_schema_version() {
        let v = json!({"foo": "bar"});
        assert!(check_case_schema_major(&v).is_err());
    }

    #[test]
    fn accepts_minor_patch_difference_within_same_major() {
        // Schema §2.3: 同一 major 内の未知 field は無視してよい。
        let v = json!({"schema_version": "1.5.7"});
        assert!(check_case_schema_major(&v).is_ok());
    }
}
