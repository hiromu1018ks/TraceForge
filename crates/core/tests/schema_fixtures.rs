//! Schema §9 fixture 検証の統合テスト（T1-055 / T1-056）。
//!
//! `tests/fixtures/schema/` の9種 fixture を読み込み、対応する validator で
//! 期待結果（valid / invalid）を検証する。

use std::fs;
use std::path::Path;

use serde_json::Value;
use tf_core::config::Config;
use tf_core::schema::{
    JsonSchemaValidator, check_major_version, correlation_rule_validator, event_time_validator,
    validate_case_bundle, validate_jsonl_envelope,
};

const FIXTURE_DIR: &str = "tests/fixtures/schema";

/// fixture ファイルを読み込む。
fn load(name: &str) -> String {
    let path = Path::new(FIXTURE_DIR).join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name} の読み込み失敗: {e}"))
}

/// JSON fixture を parse し、`(expect, schema_kind, instance, extra_instances)` を返す。
#[allow(dead_code)]
struct ParsedFixture {
    expect: String,
    schema: Option<String>,
    instance: Option<Value>,
    instances: Vec<Value>,
}

fn parse_json_fixture(text: &str) -> ParsedFixture {
    let v: Value = serde_json::from_str(text).expect("fixture JSON parse");
    let expect = v["expect"].as_str().unwrap_or("valid").to_string();
    let schema = v["schema"].as_str().map(String::from);
    let instance = v.get("instance").cloned();
    let instances = v
        .get("instances")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    ParsedFixture {
        expect,
        schema,
        instance,
        instances,
    }
}

fn is_valid(validator: &JsonSchemaValidator, instance: &Value) -> bool {
    validator.validate(instance).is_ok()
}

/// fixture #1: 最小 valid EventTime。
#[test]
fn fixture_01_minimal_event_time_valid() {
    let f = parse_json_fixture(&load("01_minimal_event_time.json"));
    let v = event_time_validator();
    assert_eq!(f.expect, "valid");
    assert!(is_valid(&v, f.instance.as_ref().unwrap()));
}

/// fixture #2: 全 field EventTime valid。
#[test]
fn fixture_02_full_event_time_valid() {
    let f = parse_json_fixture(&load("02_full_event_time.json"));
    let v = event_time_validator();
    assert_eq!(f.expect, "valid");
    assert!(is_valid(&v, f.instance.as_ref().unwrap()));
}

/// fixture #3: Correlation Rule 必須 field 欠落で invalid。
#[test]
fn fixture_03_missing_required_invalid() {
    let f = parse_json_fixture(&load("03_missing_required.json"));
    let v = correlation_rule_validator();
    assert_eq!(f.expect, "invalid");
    assert!(!is_valid(&v, f.instance.as_ref().unwrap()));
}

/// fixture #4: 異なる major version で invalid（Schema §2.3）。
#[test]
fn fixture_04_major_version_diff_invalid() {
    let f = parse_json_fixture(&load("04_major_version_diff.json"));
    let inst = f.instance.as_ref().unwrap();
    // Case JSON として検証：major version 差で error。
    assert!(validate_case_bundle(inst).is_err());
    // schema_version の major も直接確認。
    let sv = inst["schema_version"].as_str().unwrap();
    assert!(check_major_version(sv, 1).is_err());
}

/// fixture #5: unknown enum で invalid。
#[test]
fn fixture_05_unknown_enum_invalid() {
    let f = parse_json_fixture(&load("05_unknown_enum.json"));
    let v = event_time_validator();
    assert_eq!(f.expect, "invalid");
    assert!(!is_valid(&v, f.instance.as_ref().unwrap()));
}

/// fixture #6: unknown timezone / range / unknown time の複合。
#[test]
fn fixture_06_time_special_forms_mixed() {
    let f = parse_json_fixture(&load("06_time_special_forms.json"));
    let v = event_time_validator();
    assert!(f.instances.len() >= 3, "3つ以上の事例を含む");
    for (idx, inst) in f.instances.iter().enumerate() {
        let expect = inst["expect"].as_str().unwrap_or("valid");
        // `_comment` field は additionalProperties: false に触れないよう除外して検証。
        let mut probe = inst.clone();
        if let Some(obj) = probe.as_object_mut() {
            obj.remove("_comment");
            obj.remove("expect");
        }
        let ok = is_valid(&v, &probe);
        assert_eq!(
            ok,
            expect == "valid",
            "fixture #6[{idx}] 期待 {expect} だが ok={ok}: {probe}"
        );
    }
}

/// fixture #7: JSONL final Manifest 欠落（未完了、Schema §6）。
#[test]
fn fixture_07_jsonl_without_manifest_incomplete() {
    let text = load("07_jsonl_without_manifest.jsonl");
    let mut last_type = String::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record = tf_core::jsonl::JsonlRecord::parse(line).unwrap();
        // 各行は envelope として valid。
        let v: Value = serde_json::from_str(line).unwrap();
        validate_jsonl_envelope(&v).unwrap();
        last_type = record.record_type.clone();
    }
    assert_ne!(
        last_type, "manifest",
        "Schema §6: 最終行が manifest でないため未完了。実際は最終行が {last_type}"
    );
}

/// fixture #8: Correlation Rule 未対応 operator で invalid。
#[test]
fn fixture_08_unsupported_operator_invalid() {
    let f = parse_json_fixture(&load("08_unsupported_operator.json"));
    let v = correlation_rule_validator();
    assert_eq!(f.expect, "invalid");
    assert!(!is_valid(&v, f.instance.as_ref().unwrap()));
}

/// fixture #9: Config limit が 0 で invalid（Schema §8.3）。
#[test]
fn fixture_09_config_limit_zero_invalid() {
    let text = load("09_config_limit_zero.toml");
    let config = Config::from_toml_str(&text).expect("TOML parse は成功する");
    let result = config.validate();
    assert!(
        result.is_err(),
        "max_events=0 は Schema §8.3 で validation error のはず"
    );
}

/// 全9種 fixture が存在すること（整備の確認、T1-055）。
#[test]
fn all_9_fixtures_present() {
    let files = [
        "01_minimal_event_time.json",
        "02_full_event_time.json",
        "03_missing_required.json",
        "04_major_version_diff.json",
        "05_unknown_enum.json",
        "06_time_special_forms.json",
        "07_jsonl_without_manifest.jsonl",
        "08_unsupported_operator.json",
        "09_config_limit_zero.toml",
    ];
    for name in files {
        let path = Path::new(FIXTURE_DIR).join(name);
        assert!(path.exists(), "fixture が存在しない: {name}");
    }
}
