//! Registry Parser の統合テスト（T4-050〜T4-055、互換 §4.7）。
//!
//! 合成 hive fixture（`tests/common/mod.rs` の `build_registry_fixture`）を用いて、
//! base view・recovered view・LOG replay・観測型 Event・Provenance 到達・決定性を検証する。
//! acceptance test 8条件の Registry 版は `acceptance_tests.rs` へ掲載する。

mod common;

use std::io::Cursor;

use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, RecordLocator};
use tf_parsers::framework::{ArtifactParser, ParseContext, ParseSink};
use tf_parsers::registry::{
    HiveType, PARSER_ID, PARSER_VERSION, REGISTRY_KEY_LAST_WRITE_EVENT_TYPE,
    REGISTRY_OBSERVATION_EVENT_TYPE, RegistryParser,
};

/// テスト用 sink。
struct CollectorSink {
    events: Vec<tf_core::event::Event>,
    issues: Vec<tf_core::issue::Issue>,
}

impl CollectorSink {
    fn new() -> Self {
        CollectorSink {
            events: Vec::new(),
            issues: Vec::new(),
        }
    }
}

impl ParseSink for CollectorSink {
    fn emit_event(
        &mut self,
        event: tf_core::event::Event,
    ) -> Result<(), tf_parsers::framework::SinkError> {
        self.events.push(event);
        Ok(())
    }
    fn emit_issue(
        &mut self,
        issue: tf_core::issue::Issue,
    ) -> Result<(), tf_parsers::framework::SinkError> {
        self.issues.push(issue);
        Ok(())
    }
}

/// ParseContext を構築する。
fn make_context(source_locator: &str) -> ParseContext {
    ParseContext {
        evidence: EvidenceItem {
            evidence_id: "tf-evidence-v1:reg-test".to_string(),
            source_locator: source_locator.to_string(),
            size: 200,
            sha256: "ab".repeat(32),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        },
        artifact: ArtifactInstance {
            artifact_id: "tf-artifact-v1:reg-test".to_string(),
            evidence_id: "tf-evidence-v1:reg-test".to_string(),
            artifact_type: ArtifactSource::Registry,
            parser_id: PARSER_ID.to_string(),
            parser_version: PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["regf magic".to_string()],
            parse_status: ParseStatus::Complete,
        },
    }
}

/// 標準的な hive fixture: root + 1 subkey + root 配下に 1 value、subkey 配下に 2 value。
fn standard_hive_fixture() -> common::RegistryKeySpec {
    common::RegistryKeySpec {
        name: "ROOT".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![common::RegistryValueSpec::dword("Count", 42)],
        subkeys: vec![common::RegistryKeySpec {
            name: "Sub".to_string(),
            last_write_filetime: common::filetime_from_unix_offset(60),
            values: vec![
                common::RegistryValueSpec::sz("Name", "alice"),
                common::RegistryValueSpec::binary("Blob", vec![0xDE, 0xAD, 0xBE, 0xEF]),
            ],
            subkeys: vec![],
        }],
    }
}

// ============================================================
// T4-050: hive 構造解析
// ============================================================

#[test]
fn parses_root_subkey_and_values() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();

    let summary = RegistryParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(
        summary.status,
        ParseStatus::Complete,
        "issues: {:?}",
        sink.issues
    );

    // root key (1) + root value (1) + subkey (1) + subkey values (2) = 5 events。
    let mut lw = 0;
    let mut obs = 0;
    for e in &sink.events {
        match e.event_type.as_str() {
            REGISTRY_KEY_LAST_WRITE_EVENT_TYPE => lw += 1,
            REGISTRY_OBSERVATION_EVENT_TYPE => obs += 1,
            _ => {}
        }
    }
    assert_eq!(lw, 2, "key_last_write: root + subkey の2件");
    assert_eq!(obs, 3, "observation: root value 1 + subkey values 2");
}

#[test]
fn key_path_built_recursively() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SOFTWARE");
    let mut sink = CollectorSink::new();
    RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    // subkey 配下の value Event の key_path は "ROOT\Sub" になる。
    let sub_value_event = sink
        .events
        .iter()
        .find(|e| {
            e.event_type.as_str() == REGISTRY_OBSERVATION_EVENT_TYPE
                && e.attributes
                    .get("registry.value_name")
                    .and_then(|v| v.as_str())
                    == Some("Name")
        })
        .expect("Name value event が見つかる");
    assert_eq!(sub_value_event.attributes["registry.key_path"], "ROOT\\Sub");
}

#[test]
fn value_data_decoded_per_type() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    // Count = 42 (DWORD)
    let count_event = sink
        .events
        .iter()
        .find(|e| {
            e.attributes
                .get("registry.value_name")
                .and_then(|v| v.as_str())
                == Some("Count")
        })
        .expect("Count event");
    assert_eq!(count_event.attributes["registry.value_data"], 42);
    assert_eq!(count_event.attributes["registry.value_type"], 4);
    assert_eq!(
        count_event.attributes["registry.value_type_name"],
        "REG_DWORD"
    );

    // Name = "alice" (SZ)
    let name_event = sink
        .events
        .iter()
        .find(|e| {
            e.attributes
                .get("registry.value_name")
                .and_then(|v| v.as_str())
                == Some("Name")
        })
        .expect("Name event");
    assert_eq!(name_event.attributes["registry.value_data"], "alice");

    // Blob = hex (sha256 表現)
    let blob_event = sink
        .events
        .iter()
        .find(|e| {
            e.attributes
                .get("registry.value_name")
                .and_then(|v| v.as_str())
                == Some("Blob")
        })
        .expect("Blob event");
    assert_eq!(blob_event.attributes["registry.value_type"], 3);
    assert_eq!(
        blob_event.attributes["registry.value_type_name"],
        "REG_BINARY"
    );
    let data_str = blob_event.attributes["registry.value_data"]
        .as_str()
        .unwrap();
    assert_eq!(data_str.len(), 64); // sha256 hex
}

#[test]
fn hive_type_detected_from_source_locator() {
    let cases = vec![
        ("SYSTEM", HiveType::System),
        ("SOFTWARE", HiveType::Software),
        ("SAM", HiveType::Sam),
        ("SECURITY", HiveType::Security),
        ("NTUSER.DAT", HiveType::Ntuser),
        ("UsrClass.dat", HiveType::UsrClass),
        ("Amcache.hve", HiveType::Amcache),
    ];
    for (locator, expected) in cases {
        let bytes = common::build_registry_fixture(&standard_hive_fixture());
        let mut cursor = Cursor::new(bytes);
        let context = make_context(locator);
        let mut sink = CollectorSink::new();
        RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        assert!(!sink.events.is_empty());
        let first = &sink.events[0];
        assert_eq!(
            first.attributes["registry.hive_type"],
            expected.as_str(),
            "locator={locator}"
        );
    }
}

// ============================================================
// T4-051: LOG1/LOG2 transaction log replay
// ============================================================

#[test]
fn log_replay_success_emits_recovered_view_events() {
    let (bytes, root_offset) =
        common::build_registry_fixture_with_root_offset(&standard_hive_fixture());
    // root key の last_write_filetime は nk cell 先頭 (size field 4 + signature 2) の次にある。
    // base block が 4096 byte なので絶対 offset は 4096 + root_offset + 6。
    let root_ft_offset = 4096 + root_offset as usize + 4 + 2;
    let new_ft_bytes = common::filetime_from_unix_offset(600).to_le_bytes();
    let log_entry = common::registry_log_entry(root_ft_offset as u32, new_ft_bytes.to_vec());
    let log_bytes = common::build_registry_log_fixture(&[log_entry]);

    // 元の root timestamp を確認。
    let original_ft = u64::from_le_bytes(
        bytes[root_ft_offset..root_ft_offset + 8]
            .try_into()
            .unwrap(),
    );

    let mut cursor = Cursor::new(bytes.clone());
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    let parser = RegistryParser::new().with_log1(log_bytes);
    let summary = parser.parse(&mut cursor, &context, &mut sink);
    assert_eq!(
        summary.status,
        ParseStatus::Complete,
        "issues: {:?}",
        sink.issues
    );

    // base と recovered の2 view 分の Event がある。
    let mut base_count = 0;
    let mut recovered_count = 0;
    for e in &sink.events {
        match e.attributes["registry.view"].as_str().unwrap() {
            "base" => base_count += 1,
            "recovered" => recovered_count += 1,
            _ => {}
        }
    }
    assert_eq!(base_count, 5, "base view は5 event");
    assert_eq!(recovered_count, 5, "recovered view は5 event");

    // recovered 側の root key_last_write の timestamp が新しい値になっている。
    let recovered_root = sink
        .events
        .iter()
        .find(|e| {
            e.attributes["registry.view"] == "recovered"
                && e.event_type.as_str() == REGISTRY_KEY_LAST_WRITE_EVENT_TYPE
                && e.attributes["registry.key_path"] == "ROOT"
        })
        .expect("recovered root event");
    let recovered_ft_attr = recovered_root.attributes["registry.last_write_filetime"]
        .as_u64()
        .unwrap();
    assert_eq!(recovered_ft_attr, common::filetime_from_unix_offset(600));
    assert_ne!(recovered_ft_attr, original_ft);

    // LOG hash が各 Event 属性へ記録されている（互換 §4.7: 使用 log hash を記録）。
    // 成功時は Issue を出さず、代わりに属性へ完全 64 桁 hex を保存する設計。
    assert!(
        sink.events.iter().all(|e| e
            .attributes
            .get("registry.replay_status")
            .and_then(|v| v.as_str())
            == Some("success")),
        "replay_status=success が全 Event へ記録される"
    );
    let log1_hash_attr = sink
        .events
        .iter()
        .find_map(|e| e.attributes.get("registry.log1_sha256").cloned())
        .expect("log1_sha256 が少なくとも1つの Event へ記録される");
    assert_eq!(log1_hash_attr.as_str().unwrap().len(), 64);
}

#[test]
fn log_hvle_is_known_unsupported_makes_partial() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut log_bytes = vec![0u8; 32];
    log_bytes[0..4].copy_from_slice(&common::registry_hvle_magic());

    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    let parser = RegistryParser::new().with_log1(log_bytes);
    let summary = parser.parse(&mut cursor, &context, &mut sink);

    // 既知だが未対応: base のみで partial。
    assert_eq!(summary.status, ParseStatus::Partial);
    // base view の event は生成されている。
    assert!(
        sink.events
            .iter()
            .any(|e| e.attributes["registry.view"] == "base")
    );
    // recovered view の event は無い。
    assert!(
        !sink
            .events
            .iter()
            .any(|e| e.attributes["registry.view"] == "recovered")
    );
    // UNSUPPORTED_VERSION issue がある。
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
}

#[test]
fn log_malformed_makes_partial() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let bad_log = vec![0u8; 32]; // 不正

    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    let parser = RegistryParser::new().with_log1(bad_log);
    let summary = parser.parse(&mut cursor, &context, &mut sink);
    assert_eq!(summary.status, ParseStatus::Partial);
}

#[test]
fn no_log_completes_base_only() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    let summary = RegistryParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(summary.status, ParseStatus::Complete);
    // base view のみ。
    assert!(
        sink.events
            .iter()
            .all(|e| e.attributes["registry.view"] == "base")
    );
}

// ============================================================
// T4-052: dual view と Provenance
// ============================================================

#[test]
fn provenance_records_parser_id_and_byte_range() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let prov = &e.provenance;
        assert_eq!(prov.parser_id, PARSER_ID);
        assert_eq!(prov.parser_version, PARSER_VERSION);
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
        // Evidence ID・source_locator が context のものと一致。
        assert_eq!(prov.evidence_id, context.evidence.evidence_id);
        assert_eq!(prov.source_locator, context.evidence.source_locator);
    }
}

#[test]
fn base_and_recovered_events_have_distinct_ids() {
    let (bytes, root_offset) =
        common::build_registry_fixture_with_root_offset(&standard_hive_fixture());
    let root_ft_offset = (4096 + root_offset as usize + 4 + 2) as u32;
    let new_ft_bytes = common::filetime_from_unix_offset(600).to_le_bytes();
    let log_entry = common::registry_log_entry(root_ft_offset, new_ft_bytes.to_vec());
    let log_bytes = common::build_registry_log_fixture(&[log_entry]);

    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    RegistryParser::new()
        .with_log1(log_bytes)
        .parse(&mut cursor, &context, &mut sink);

    // Event ID は一意（EventStore の制約を満たす）。
    let mut ids: Vec<&str> = sink.events.iter().map(|e| e.id.as_str()).collect();
    ids.sort();
    let total = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), total, "Event ID は重複しない");
}

// ============================================================
// T4-053: replay 不可時は partial
// ============================================================

#[test]
fn replay_failure_sets_artifact_partial() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    // HvLE 形式の LOG。
    let mut hvle_log = vec![0u8; 32];
    hvle_log[0..4].copy_from_slice(&common::registry_hvle_magic());

    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    let summary = RegistryParser::new()
        .with_log1(hvle_log)
        .parse(&mut cursor, &context, &mut sink);

    assert_eq!(summary.status, ParseStatus::Partial);
    // 生成済み Event は破棄されない（規範 §9.2）。
    assert!(!sink.events.is_empty());
}

// ============================================================
// T4-054: 観測型 Event
// ============================================================

#[test]
fn only_observation_event_types() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let t = e.event_type.as_str();
        assert!(
            t == REGISTRY_KEY_LAST_WRITE_EVENT_TYPE || t == REGISTRY_OBSERVATION_EVENT_TYPE,
            "観測型 Event のみ: got {t}"
        );
        assert_ne!(t, "registry_set");
        assert_ne!(t, "registry_delete");
        assert_eq!(e.assertion, AssertionKind::Observed);
        assert_eq!(e.source, ArtifactSource::Registry);
    }
}

// ============================================================
// T4-055: 必須 field・破損耐性・決定性
// ============================================================

#[test]
fn corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8]| {
        let mut cursor = Cursor::new(bytes.to_vec());
        let context = make_context("SYSTEM");
        let mut sink = CollectorSink::new();
        let _ = RegistryParser::new().parse(&mut cursor, &context, &mut sink);
    };

    // 短すぎる
    run(&(0..10).collect::<Vec<u8>>());
    // base block のみ
    run(&vec![0u8; 4096]);
    // magic 壊す
    let mut bad = common::build_registry_fixture(&standard_hive_fixture());
    bad[0] = 0xFF;
    run(&bad);
    // root offset を範囲外へ
    let mut bad2 = common::build_registry_fixture(&standard_hive_fixture());
    bad2[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    run(&bad2);
}

#[test]
fn parser_is_deterministic_across_runs() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let run_once = || -> Vec<String> {
        let mut cursor = Cursor::new(bytes.clone());
        let context = make_context("SYSTEM");
        let mut sink = CollectorSink::new();
        RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        let mut ids: Vec<String> = sink.events.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

#[test]
fn reference_spec_recorded_in_attributes() {
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert!(e.attributes.contains_key("registry.reference_spec"));
        assert_eq!(e.attributes["registry.parser_version"], PARSER_VERSION);
    }
}

#[test]
fn path_field_unused_for_registry_values() {
    // Registry Parser は Event.path を使わない（key は key_path 属性で表現）。
    // 規範 §8「Evidence 内 path に PathBuf を使わない」も、Registry は path 自体
    // 使わないため遵守。
    let bytes = common::build_registry_fixture(&standard_hive_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("SYSTEM");
    let mut sink = CollectorSink::new();
    RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert!(
            e.path.is_none(),
            "Registry Event は path field を使わない（key_path 属性で表現）"
        );
    }
}
