//! Schema validation と major version 拒否の統合 test（規範 §21-15・互換 §10・T7-009）。
//!
//! 規範 §21-15 は「JSON / JSONL / Rule / Config の Schema validation」を要求する。
//! 互換 §10 は「異なる Schema major version の自動変換は禁止」と定める。

use tf_core::case::CaseMetadata;
use tf_core::jsonl::JsonlRecord;
use tf_core::manifest::Manifest;
use tf_core::schema::{check_major_version, parse_schema_version};
use tf_export::schema_check::{check_case_schema_major, check_jsonl_schema_major};
use tf_export::{CaseData, json::to_json_string, jsonl::to_jsonl_string};

fn empty_data() -> CaseData {
    CaseData {
        case: CaseMetadata {
            case_id: "tf-case-v1:schema".into(),
            external_case_id: None,
            name: "schema test".into(),
            analyst: None,
            description: None,
            default_timezone: None,
            tags: vec![],
        },
        manifest: Manifest {
            traceforge_version: "0.1.0".into(),
            build_commit: "test".into(),
            target: "test".into(),
            schema_version: "1.0.0".into(),
            compatibility_profile: "TF-WIN-1.0".into(),
            run_started_at: "2026-08-12T00:00:00Z".into(),
            run_finished_at: "2026-08-12T00:01:00Z".into(),
            resolved_config: serde_json::json!({}),
            resolved_config_sha256: "a".repeat(64),
            case_id: "tf-case-v1:schema".into(),
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
fn json_output_passes_case_bundle_schema() {
    // 規範 §21-15: JSON 出力は Schema validation に成功する。
    let data = empty_data();
    let json = to_json_string(&data).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    check_case_schema_major(&value).expect("現行 Schema version へ適合する");
    // top-level 必須 key の検証（Schema §5.1）。
    let obj = value.as_object().unwrap();
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
        assert!(obj.contains_key(key), "必須 key 欠落: {key}");
    }
    assert_eq!(value["schema_version"], "1.0.0");
    assert_eq!(value["record_type"], "case_bundle");
}

#[test]
fn jsonl_output_each_line_passes_envelope_schema() {
    // 規範 §21-15: JSONL 出力の各行は Schema validation に成功する。
    let data = empty_data();
    let jsonl = to_jsonl_string(&data).unwrap();
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        check_jsonl_schema_major(&value).expect("現行 Schema version へ適合する");
        let r = JsonlRecord::parse(line).unwrap();
        assert_eq!(r.schema_version, "1.0.0");
    }
}

#[test]
fn future_major_version_is_rejected() {
    // 互換 §10: 異なる major version は自動変換しない。
    let future = serde_json::json!({
        "schema_version": "2.0.0",
        "record_type": "case_bundle",
    });
    assert!(check_case_schema_major(&future).is_err());

    let future_env = serde_json::json!({
        "schema_version": "3.0.0",
        "record_type": "event",
        "record": {},
    });
    assert!(check_jsonl_schema_major(&future_env).is_err());
}

#[test]
fn same_major_with_higher_minor_is_accepted() {
    // Schema §2.3: 同一 major 内の未知 field は無視してよい。
    let v = serde_json::json!({"schema_version": "1.5.7"});
    assert!(check_case_schema_major(&v).is_ok());
}

#[test]
fn missing_schema_version_is_rejected() {
    let v = serde_json::json!({"foo": "bar"});
    assert!(check_case_schema_major(&v).is_err());
}

#[test]
fn schema_version_parse_handles_edge_cases() {
    // Schema §2.3 の parser 検証。
    assert!(parse_schema_version("1.0.0").is_ok());
    assert!(parse_schema_version("2.0.0").is_ok());
    assert!(parse_schema_version("1.0").is_err());
    assert!(parse_schema_version("1.0.0.0").is_err());
    assert!(parse_schema_version("garbage").is_err());

    assert!(check_major_version("1.5.3", 1).is_ok());
    assert!(check_major_version("2.0.0", 1).is_err());
}

#[test]
fn export_does_not_silently_upgrade_schema_version() {
    // 互換 §10: export は schema_version を勝手に変更しない。
    // 常に Schema §1 の `1.0.0` を出力する。
    let data = empty_data();
    let json = to_json_string(&data).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["schema_version"], "1.0.0",
        "schema_version は 1.0.0 固定"
    );

    let jsonl = to_jsonl_string(&data).unwrap();
    for line in jsonl.lines() {
        let r = JsonlRecord::parse(line).unwrap();
        assert_eq!(r.schema_version, "1.0.0");
    }
}
