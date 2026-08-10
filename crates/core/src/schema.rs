//! Schema 検証（Schema §2.3、§4、§7、§9）。
//!
//! Schema §4（Event Time）と Schema §7（Correlation Rule）は JSON Schema fragment を
//! [`jsonschema`] crate で検証する。Case JSON（Schema §5）は仕様書が fragment を提供
//! しないため、本モジュールで必須 field 検証を独自実装する。
//!
//! Version compatibility 規則（Schema §2.3）:
//! - 同一 major version の未知 field は無視してよい（再出力時は保持）。
//! - 必須 field 欠落・未知の必須 enum・異なる major version は error。

use serde_json::Value;

/// Schema §1 の Schema version 文字列。
pub const SCHEMA_VERSION: &str = "1.0.0";
/// 現行 major version（Schema §2.3）。
pub const SCHEMA_MAJOR: u32 = 1;

/// Schema §4 Event Time の JSON Schema fragment（`schemas/event-time.schema.json`）。
pub const EVENT_TIME_SCHEMA_JSON: &str = include_str!("../schemas/event-time.schema.json");

/// Schema §7 Correlation Rule の JSON Schema fragment（`schemas/correlation-rule.schema.json`）。
pub const CORRELATION_RULE_SCHEMA_JSON: &str =
    include_str!("../schemas/correlation-rule.schema.json");

/// Schema 検証 error。
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// JSON Schema の compile 失敗。
    #[error("JSON Schema compile error: {0}")]
    Compile(String),
    /// 検証対象が Schema へ違反した。違反メッセージの一覧。
    #[error("Schema validation error: {0}")]
    Validation(String),
    /// `schema_version` の形式が不正、または major version が異なる（Schema §2.3）。
    #[error("schema_version error: {0}")]
    Version(String),
}

/// JSON Schema validator の薄 wrapper。
pub struct JsonSchemaValidator {
    inner: jsonschema::Validator,
}

impl JsonSchemaValidator {
    /// JSON Schema 値から validator を compile する。
    pub fn compile(schema: &Value) -> Result<Self, SchemaError> {
        let inner =
            jsonschema::validator_for(schema).map_err(|e| SchemaError::Compile(e.to_string()))?;
        Ok(Self { inner })
    }

    /// 検証対象が Schema へ適合するか。違反時は [`SchemaError::Validation`]。
    pub fn validate(&self, instance: &Value) -> Result<(), SchemaError> {
        if let Err(mut errors) = self.inner.validate(instance) {
            // 最初の違反を採用する（全件出力すると test が煩雑になるため）。
            let first = errors
                .next()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown validation error".to_string());
            return Err(SchemaError::Validation(first));
        }
        Ok(())
    }

    /// 適合するか真偽値で返す。
    pub fn is_valid(&self, instance: &Value) -> bool {
        self.inner.is_valid(instance)
    }
}

/// Event Time Schema validator を構築する（Schema §4）。
pub fn event_time_validator() -> JsonSchemaValidator {
    let schema: Value =
        serde_json::from_str(EVENT_TIME_SCHEMA_JSON).expect("event-time schema parse");
    JsonSchemaValidator::compile(&schema).expect("event-time schema compile")
}

/// Correlation Rule Schema validator を構築する（Schema §7）。
pub fn correlation_rule_validator() -> JsonSchemaValidator {
    let schema: Value =
        serde_json::from_str(CORRELATION_RULE_SCHEMA_JSON).expect("correlation-rule schema parse");
    JsonSchemaValidator::compile(&schema).expect("correlation-rule schema compile")
}

/// `schema_version` 文字列を `(major, minor, patch)` へ parse する。
pub fn parse_schema_version(s: &str) -> Result<(u32, u32, u32), SchemaError> {
    let mut parts = s.split('.');
    let major = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .ok_or_else(|| SchemaError::Version(format!("major が数値ではない: {s}")))?;
    let minor = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .ok_or_else(|| SchemaError::Version(format!("minor が数値ではない: {s}")))?;
    let patch = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .ok_or_else(|| SchemaError::Version(format!("patch が数値ではない: {s}")))?;
    if parts.next().is_some() {
        return Err(SchemaError::Version(format!("余分な component: {s}")));
    }
    Ok((major, minor, patch))
}

/// `schema_version` の major が `expected` と一致するか（Schema §2.3）。
///
/// 異なる major version は error。Reader は同一 major version の未知 field を無視してよい。
pub fn check_major_version(s: &str, expected: u32) -> Result<(), SchemaError> {
    let (major, _, _) = parse_schema_version(s)?;
    if major != expected {
        return Err(SchemaError::Version(format!(
            "major version 不一致: 期待 {expected}, 実際 {major}（{s}）"
        )));
    }
    Ok(())
}

/// Case JSON（Schema §5.1）の top-level 必須 field と基本構造を検証する。
///
/// Schema §5 は JSON Schema fragment を提供しないため、必須 field の有無と
/// `record_type` の値、`schema_version` の major 一致を確認する。
pub fn validate_case_bundle(value: &Value) -> Result<(), SchemaError> {
    let obj = value
        .as_object()
        .ok_or_else(|| SchemaError::Validation("top-level が object ではない".into()))?;
    // Schema §5.1 の top-level 必須 key。
    for key in [
        "schema_version",
        "record_type",
        "case",
        "evidence",
        "artifacts",
        "events",
        "issues",
        "matches",
        "findings",
        "manifest",
    ] {
        if !obj.contains_key(key) {
            return Err(SchemaError::Validation(format!(
                "Case JSON の必須 field 欠落: {key}"
            )));
        }
    }
    // Schema §1 / §5.1: schema_version の major は 1。
    let sv = obj["schema_version"]
        .as_str()
        .ok_or_else(|| SchemaError::Validation("schema_version が文字列ではない".into()))?;
    check_major_version(sv, SCHEMA_MAJOR)?;
    // Schema §5.1: record_type は "case_bundle"。
    let rt = obj["record_type"]
        .as_str()
        .ok_or_else(|| SchemaError::Validation("record_type が文字列ではない".into()))?;
    if rt != "case_bundle" {
        return Err(SchemaError::Validation(format!(
            "record_type は 'case_bundle' のみ許可: {rt}"
        )));
    }
    Ok(())
}

/// JSONL envelope（Schema §6）の `record_type` 列挙値。
pub const JSONL_RECORD_TYPES: &[&str] = &[
    "case", "evidence", "artifact", "event", "issue", "match", "finding", "manifest",
];

/// JSONL envelope（Schema §6）の基本構造を検証する。
pub fn validate_jsonl_envelope(value: &Value) -> Result<(), SchemaError> {
    let obj = value
        .as_object()
        .ok_or_else(|| SchemaError::Validation("JSONL 行が object ではない".into()))?;
    for key in ["schema_version", "record_type", "record"] {
        if !obj.contains_key(key) {
            return Err(SchemaError::Validation(format!(
                "JSONL envelope の必須 field 欠落: {key}"
            )));
        }
    }
    let sv = obj["schema_version"]
        .as_str()
        .ok_or_else(|| SchemaError::Validation("schema_version が文字列ではない".into()))?;
    check_major_version(sv, SCHEMA_MAJOR)?;
    let rt = obj["record_type"]
        .as_str()
        .ok_or_else(|| SchemaError::Validation("record_type が文字列ではない".into()))?;
    if !JSONL_RECORD_TYPES.contains(&rt) {
        return Err(SchemaError::Validation(format!("未知の record_type: {rt}")));
    }
    if !obj["record"].is_object() {
        return Err(SchemaError::Validation("record が object ではない".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_time_validator_compiles() {
        // Schema §4 の fragment が compile 可能であること。
        let _ = event_time_validator();
        let _ = correlation_rule_validator();
    }

    #[test]
    fn event_time_validator_accepts_utc_instant() {
        let v = event_time_validator();
        let sample = serde_json::json!({
            "type": "utc_instant",
            "value": "2026-08-10T01:15:20Z",
            "original": null,
            "kind": "event_logged",
            "precision": "second",
            "timezone_source": "artifact_defined",
            "uncertainty_ms": null
        });
        assert!(v.validate(&sample).is_ok());
    }

    #[test]
    fn event_time_validator_accepts_unknown() {
        // Schema §9 fixture: unknown timezone、range、unknown time。
        let v = event_time_validator();
        let unknown = serde_json::json!({
            "type": "unknown",
            "original": null,
            "kind": "unknown",
            "precision": "unknown",
            "timezone_source": "unknown",
            "uncertainty_ms": null
        });
        assert!(v.validate(&unknown).is_ok());
    }

    #[test]
    fn event_time_validator_rejects_unknown_enum() {
        // Schema §9 fixture: unknown enum。
        let v = event_time_validator();
        let bad = serde_json::json!({
            "type": "utc_instant",
            "value": "2026-08-10T01:15:20Z",
            "original": null,
            "kind": "nonsense",
            "precision": "second",
            "timezone_source": "artifact_defined",
            "uncertainty_ms": null
        });
        assert!(v.validate(&bad).is_err());
    }

    #[test]
    fn event_time_range_rejects_both_null() {
        // Schema §4: Range の start/end 両方 None は禁止。
        let v = event_time_validator();
        let both_null = serde_json::json!({
            "type": "range",
            "start": null,
            "end": null,
            "original": null,
            "kind": "unknown",
            "precision": "unknown",
            "timezone_source": "unknown",
            "uncertainty_ms": null
        });
        assert!(v.validate(&both_null).is_err());
    }

    #[test]
    fn correlation_rule_accepts_valid() {
        let v = correlation_rule_validator();
        let rule = serde_json::json!({
            "id": "TF-CORR-001",
            "version": "1.0.0",
            "title": "Execution shortly after file creation",
            "severity": "high",
            "sequence": [
                {"event_type": "file_create", "assertion": "observed"}
            ],
            "within": "5m",
            "partition_by": ["case_id", "hostname"],
            "score": {"base": 0.75, "adjustments": []}
        });
        assert!(v.validate(&rule).is_ok());
    }

    #[test]
    fn correlation_rule_rejects_unsupported_operator() {
        // Schema §9 fixture: 未対応 operator。
        let v = correlation_rule_validator();
        let rule = serde_json::json!({
            "id": "TF-CORR-002",
            "version": "1.0.0",
            "title": "bad operator",
            "severity": "low",
            "sequence": [{
                "event_type": "x",
                "where": [{"field": "path", "operator": "regex_custom", "value": "a"}]
            }],
            "within": "5m",
            "partition_by": ["case_id"],
            "score": {"base": 0.5, "adjustments": []}
        });
        assert!(v.validate(&rule).is_err());
    }

    #[test]
    fn correlation_rule_rejects_missing_required() {
        // Schema §9 fixture: 必須 field 欠落。
        let v = correlation_rule_validator();
        let rule = serde_json::json!({
            "id": "TF-CORR-003",
            "version": "1.0.0",
            "title": "missing"
            // severity/sequence/within/partition_by/score 欠落
        });
        assert!(v.validate(&rule).is_err());
    }

    #[test]
    fn version_compatibility_major_mismatch() {
        // Schema §2.3: 異なる major version は error。
        assert!(check_major_version("2.0.0", 1).is_err());
        assert!(check_major_version("1.5.3", 1).is_ok());
        assert!(check_major_version("1.0.0", 1).is_ok());
    }

    #[test]
    fn version_parse_rejects_garbage() {
        assert!(parse_schema_version("1.0").is_err());
        assert!(parse_schema_version("1.0.0.0").is_err());
        assert!(parse_schema_version("abc").is_err());
    }

    #[test]
    fn case_bundle_validation() {
        // Schema §5.1: top-level 必須 field。
        let good = serde_json::json!({
            "schema_version": "1.0.0",
            "record_type": "case_bundle",
            "case": {},
            "evidence": [],
            "artifacts": [],
            "events": [],
            "issues": [],
            "matches": [],
            "findings": [],
            "manifest": {}
        });
        assert!(validate_case_bundle(&good).is_ok());

        // 必須 field 欠落（Schema §9 fixture 系）。
        let mut bad = good.clone();
        let obj = bad.as_object_mut().unwrap();
        obj.remove("manifest");
        assert!(validate_case_bundle(&bad).is_err());

        // major version 差（Schema §9 fixture 系）。
        let mut bad_version = good.clone();
        bad_version["schema_version"] = serde_json::json!("2.0.0");
        assert!(validate_case_bundle(&bad_version).is_err());
    }

    #[test]
    fn jsonl_envelope_validation() {
        let good = serde_json::json!({
            "schema_version": "1.0.0",
            "record_type": "event",
            "record": {}
        });
        assert!(validate_jsonl_envelope(&good).is_ok());

        let bad_type = serde_json::json!({
            "schema_version": "1.0.0",
            "record_type": "unknown_type",
            "record": {}
        });
        assert!(validate_jsonl_envelope(&bad_type).is_err());
    }
}
