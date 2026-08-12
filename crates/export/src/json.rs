//! JSON exporter（Schema §5・T7-002）。
//!
//! Case JSON は Schema §5.1 の固定 top-level 構造を持つ。
//! 出力は UTF-8・LF・canonical JSON（key sort 済み・NaN/Infinity 禁止、規範 §19.4）。
//! 異なる Schema major version の自動変換は禁止する（互換 §10）。

use std::io::Write;

use tf_core::canonical::to_canonical_string;
use tf_core::jsonl::SCHEMA_VERSION;

use crate::case_data::CaseData;
use crate::error::ExportError;
use crate::schema_check::check_case_schema_major;

/// Case JSON（Schema §5.1）を構築する。
///
/// top-level は固定（`schema_version` + `record_type: case_bundle` + 各 record list）。
/// 内部の list は Schema §6 の出力順で整列する。
pub fn build_case_json_value(data: &CaseData) -> serde_json::Value {
    let views = data.sorted_views();
    let mut map = serde_json::Map::new();
    map.insert(
        "schema_version".into(),
        serde_json::Value::String(SCHEMA_VERSION.into()),
    );
    map.insert(
        "record_type".into(),
        serde_json::Value::String("case_bundle".into()),
    );
    map.insert("case".into(), data.case.to_canonical_value());
    map.insert(
        "evidence".into(),
        serde_json::Value::Array(
            views
                .evidence
                .iter()
                .map(|e| e.to_canonical_value())
                .collect(),
        ),
    );
    map.insert(
        "artifacts".into(),
        serde_json::Value::Array(
            views
                .artifacts
                .iter()
                .map(|a| a.to_canonical_value())
                .collect(),
        ),
    );
    map.insert(
        "events".into(),
        serde_json::Value::Array(
            views
                .events
                .iter()
                .map(tf_core::event::Event::to_canonical_value)
                .collect(),
        ),
    );
    map.insert(
        "issues".into(),
        serde_json::Value::Array(
            views
                .issues
                .iter()
                .map(|i| i.to_canonical_value())
                .collect(),
        ),
    );
    map.insert(
        "matches".into(),
        serde_json::Value::Array(
            views
                .matches
                .iter()
                .map(|m| m.to_canonical_value())
                .collect(),
        ),
    );
    map.insert(
        "findings".into(),
        serde_json::Value::Array(
            views
                .findings
                .iter()
                .map(|f| f.to_canonical_value())
                .collect(),
        ),
    );
    map.insert("manifest".into(), data.manifest.to_canonical_value());
    serde_json::Value::Object(map)
}

/// Case JSON を `writer` へ出力する（Schema §5.1・規範 §19.4）。
///
/// - UTF-8・LF（規範 §19.4）
/// - canonical JSON（key sort・NaN/Infinity 禁止）
/// - Schema major version を検証（互換 §10）
pub fn write_json(data: &CaseData, writer: &mut impl Write) -> Result<(), ExportError> {
    let value = build_case_json_value(data);
    check_case_schema_major(&value)?;
    let canonical = to_canonical_string(&value)?;
    writer.write_all(canonical.as_bytes())?;
    // 規範 §19.4: 改行は LF。
    writer.write_all(b"\n")?;
    Ok(())
}

/// Case JSON を文字列へ直列化する（テスト・小規模 Case 用）。
pub fn to_json_string(data: &CaseData) -> Result<String, ExportError> {
    let mut buf: Vec<u8> = Vec::new();
    write_json(data, &mut buf)?;
    String::from_utf8(buf).map_err(|e| ExportError::Canonical(format!("UTF-8 変換失敗: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_core::case::CaseMetadata;
    use tf_core::manifest::Manifest;

    fn empty_data() -> CaseData {
        CaseData {
            case: CaseMetadata {
                case_id: "tf-case-v1:x".into(),
                external_case_id: None,
                name: "demo".into(),
                analyst: None,
                description: None,
                default_timezone: None,
                tags: vec![],
            },
            manifest: Manifest {
                traceforge_version: "0.1.0".into(),
                build_commit: "deadbeef".into(),
                target: "x86_64-pc-windows-msvc".into(),
                schema_version: SCHEMA_VERSION.into(),
                compatibility_profile: "TF-WIN-1.0".into(),
                run_started_at: "2026-08-12T00:00:00Z".into(),
                run_finished_at: "2026-08-12T00:01:00Z".into(),
                resolved_config: serde_json::json!({}),
                resolved_config_sha256: "a".repeat(64),
                case_id: "tf-case-v1:x".into(),
                counts: Default::default(),
                components: vec![],
                rules: vec![],
                attack_dataset: None,
                timezone_assumptions: vec![],
                limits: serde_json::json!({}),
                incomplete_reasons: vec![],
                complete: true,
                exit_code: 0,
            },
            ..Default::default()
        }
    }

    #[test]
    fn json_has_fixed_toplevel_and_lf_termination() {
        let data = empty_data();
        let s = to_json_string(&data).unwrap();
        // LF 終端。
        assert!(s.ends_with('\n'));
        // top-level が固定。
        let value: serde_json::Value = serde_json::from_str(&s).unwrap();
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
            assert!(value.as_object().unwrap().contains_key(key));
        }
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["record_type"], "case_bundle");
    }

    #[test]
    fn json_is_canonical_key_sorted() {
        let data = empty_data();
        let s = to_json_string(&data).unwrap();
        // canonical JSON は key が byte 順 sort される（Schema §2.1）。
        // "schema_version" > "record_type" > "case" > "artifacts" > "events"
        //   > "evidence" > "findings" > "issues" > "manifest" > "matches"
        let first_key = s.trim_start_matches('{').split('"').nth(1).unwrap_or("");
        // byte 順最小は "artifacts" ではなく "case" ではない。実際に調べる。
        // 'a' < 'c' < 'e' < 'f' < 'i' < 'm' < 'r' < 's'
        // 'artifacts' が先頭。
        assert_eq!(first_key, "artifacts");
    }

    #[test]
    fn json_does_not_contain_nan_or_infinity() {
        // 規範 §19.4: NaN / Infinity 禁止。
        let data = empty_data();
        let s = to_json_string(&data).unwrap();
        assert!(!s.contains("NaN"));
        assert!(!s.contains("Infinity"));
        assert!(!s.contains("-Infinity"));
    }
}
