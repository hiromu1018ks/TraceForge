//! Amcache Parser の統合テスト（T4-060〜T4-065、互換 §4.6・§4.7）。
//!
//! 合成 hive fixture（`tests/common/mod.rs` の `build_registry_fixture`）を用いて、
//! schema family 認識・観測型 Event・未知 schema の Warning・Registry Parser との明示的併用・
//! Provenance 到達・決定性を検証する。acceptance test 8条件の Amcache 版は
//! `acceptance_tests.rs` へ掲載する。
//!
//! Amcache.hve は registry hive 形式そのものであるため、本テストでは
//! [`common::RegistryKeySpec`] で Inventory schema 風の key tree を構築する。

mod common;

use std::io::Cursor;

use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, RecordLocator};
use tf_parsers::amcache::{AMCACHE_OBSERVATION_EVENT_TYPE, AMCACHE_REFERENCE, AmcacheParser};
use tf_parsers::framework::{ArtifactParser, ParseContext, ParseSink};
use tf_parsers::{AMCACHE_PARSER_ID, AMCACHE_PARSER_VERSION};

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
            evidence_id: "tf-evidence-v1:amcache-test".to_string(),
            source_locator: source_locator.to_string(),
            size: 200,
            sha256: "ab".repeat(32),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        },
        artifact: ArtifactInstance {
            artifact_id: "tf-artifact-v1:amcache-test".to_string(),
            evidence_id: "tf-evidence-v1:amcache-test".to_string(),
            artifact_type: ArtifactSource::Amcache,
            parser_id: AMCACHE_PARSER_ID.to_string(),
            parser_version: AMCACHE_PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["amcache.hve + regf magic".to_string()],
            parse_status: ParseStatus::Complete,
        },
    }
}

/// Windows 10 22H2 / Windows 11 24H2 の Inventory schema を模した fixture。
///
/// `Root` 配下へ `InventoryApplicationFile` と `DeviceCensus` を置き、
/// `InventoryApplicationFile` の下へ SHA-1 等の file metadata を保持する孫 key を置く。
fn win10_inventory_fixture() -> common::RegistryKeySpec {
    // InventoryApplicationFile 直下の file entry（key 名 = SHA-1 hash のような文字列）。
    let file_entry = common::RegistryKeySpec {
        name: "000061e800b0c814fa2da1c8df6f48501bd43a4d78cd2151".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![
            common::RegistryValueSpec::sz("CompanyName", "Microsoft Corporation"),
            common::RegistryValueSpec::sz("FileName", "notepad.exe"),
            common::RegistryValueSpec::sz("FileVersion", "10.0.22621.1"),
            common::RegistryValueSpec::dword("FileId", 0x1234_5678u32),
        ],
        subkeys: vec![],
    };
    let inventory_application_file = common::RegistryKeySpec {
        name: "InventoryApplicationFile".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(60),
        values: vec![],
        subkeys: vec![file_entry],
    };
    let device_census = common::RegistryKeySpec {
        name: "DeviceCensus".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(120),
        values: vec![
            common::RegistryValueSpec::sz("OSName", "Windows 11 Pro"),
            common::RegistryValueSpec::sz("OSVersion", "10.0.26100.1742"),
        ],
        subkeys: vec![],
    };
    common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(-60),
        values: vec![],
        subkeys: vec![inventory_application_file, device_census],
    }
}

/// Windows 8 / 8.1 legacy schema を模した fixture。`Root\File` を持つ。
fn win8_legacy_fixture() -> common::RegistryKeySpec {
    common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![],
        subkeys: vec![common::RegistryKeySpec {
            name: "File".to_string(),
            last_write_filetime: common::filetime_from_unix_offset(30),
            values: vec![common::RegistryValueSpec::sz(
                "000061e800b0c814fa2da1c8df6f48501bd43a4d78cd2151",
                "notepad.exe",
            )],
            subkeys: vec![],
        }],
    }
}

/// 未知 schema の fixture（Inventory 系でも File/Programs でも無い）。
fn unknown_schema_fixture() -> common::RegistryKeySpec {
    common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![],
        subkeys: vec![common::RegistryKeySpec {
            name: "RandomUnknown".to_string(),
            last_write_filetime: common::filetime_from_unix_offset(0),
            values: vec![],
            subkeys: vec![],
        }],
    }
}

// ============================================================
// T4-060: Win10 22H2 / Win11 24H2 schema family 認識
// ============================================================

#[test]
fn win10_inventory_fixture_emits_events() {
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    let summary = AmcacheParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(
        summary.status,
        ParseStatus::Complete,
        "issues: {:?}",
        sink.issues
    );
    assert!(
        !sink.events.is_empty(),
        "Inventory schema は Event を生成する"
    );
    // 全 Event の schema_family が Win10 Inventory。
    for e in &sink.events {
        assert_eq!(
            e.attributes["amcache.schema_family"],
            "win10-22h2-win11-24h2-inventory"
        );
    }
}

#[test]
fn win8_legacy_fixture_emits_events() {
    let bytes = common::build_registry_fixture(&win8_legacy_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    let summary = AmcacheParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(
        summary.status,
        ParseStatus::Complete,
        "issues: {:?}",
        sink.issues
    );
    assert!(!sink.events.is_empty());
    for e in &sink.events {
        assert_eq!(e.attributes["amcache.schema_family"], "win8-8.1-legacy");
    }
}

// ============================================================
// T4-061: key family と file/program metadata 保持
// ============================================================

#[test]
fn file_metadata_values_preserved() {
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    // file metadata value が保持されている。
    let company = sink
        .events
        .iter()
        .find(|e| {
            e.attributes
                .get("amcache.value_name")
                .and_then(|v| v.as_str())
                == Some("CompanyName")
        })
        .expect("CompanyName value event");
    assert_eq!(
        company.attributes["amcache.value_data"],
        "Microsoft Corporation"
    );
    assert_eq!(company.attributes["amcache.value_type_name"], "REG_SZ");

    // key_path が full path で構築されている。
    assert!(
        company.attributes["amcache.key_path"]
            .as_str()
            .unwrap()
            .contains("InventoryApplicationFile"),
        "key_path に InventoryApplicationFile が含まれる: {}",
        company.attributes["amcache.key_path"]
    );

    // is_file_metadata_key flag が InventoryApplicationFile 配下で true。
    assert_eq!(company.attributes["amcache.is_file_metadata_key"], true);
}

#[test]
fn key_path_built_recursively() {
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    // 深い key (Root\InventoryApplicationFile\<sha1>) の key_path が再帰的に構築される。
    let file_entry_event = sink
        .events
        .iter()
        .find(|e| {
            e.attributes
                .get("amcache.key_name")
                .and_then(|v| v.as_str())
                == Some("000061e800b0c814fa2da1c8df6f48501bd43a4d78cd2151")
        })
        .expect("file entry event");
    let key_path = file_entry_event.attributes["amcache.key_path"]
        .as_str()
        .unwrap();
    assert!(
        key_path.starts_with("Root\\InventoryApplicationFile\\"),
        "key_path が再帰的: {}",
        key_path
    );
}

// ============================================================
// T4-062: amcache_observation Event（process start へ断定しない）
// ============================================================

#[test]
fn only_observation_event_type() {
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    assert!(!sink.events.is_empty());
    for e in &sink.events {
        // event_type は amcache_observation（観測型）のみ。
        assert_eq!(e.event_type.as_str(), AMCACHE_OBSERVATION_EVENT_TYPE);
        // process start 等の断定型ではない。
        let et = e.event_type.as_str();
        assert!(!et.contains("process_start"));
        assert!(!et.contains("launched"));
        assert!(!et.contains("executed"));
        assert!(!et.contains("ran"));
        // assertion は Observed（規範 §7.1）。
        assert_eq!(e.assertion, AssertionKind::Observed);
        // source は Amcache。
        assert_eq!(e.source, ArtifactSource::Amcache);
    }
}

#[test]
fn interpretation_limitation_recorded() {
    // 互換 §5 必須 field「interpretation limitation」が各 Event へ記録される。
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let limitation = e.attributes["amcache.interpretation_limitation"]
            .as_str()
            .unwrap();
        assert!(limitation.contains("process start"));
        assert!(limitation.contains("not"));
    }
}

// ============================================================
// T4-063: 未知 schema は Warning（Generic Registry 自動 fallback 禁止）
// ============================================================

#[test]
fn unknown_schema_emits_warning_and_skips() {
    let bytes = common::build_registry_fixture(&unknown_schema_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    let summary = AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    // 未知 schema は Skip。
    assert_eq!(summary.status, ParseStatus::Skipped);
    // Event 生成無し（Generic Registry への自動 fallback 禁止・互換 §4.6・§4.7）。
    assert!(sink.events.is_empty(), "未知 schema は Event を生成しない");
    // Warning Issue へ記録。
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE),
        "UNSUPPORTED_VERSION Issue が必要: {:?}",
        sink.issues
    );
    // message へ schema_family=unknown が残る（黙殺禁止）。
    let issue = sink
        .issues
        .iter()
        .find(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
        .unwrap();
    assert!(issue.message.contains("unknown"));
    assert!(
        issue.message.contains("fallback"),
        "自動 fallback 禁止の旨が message へ残る"
    );
}

#[test]
fn empty_hive_root_no_subkeys_is_unknown_schema() {
    // subkey 無しの root は schema 認識不能 → Unknown → Warning。
    let root_only = common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![],
        subkeys: vec![],
    };
    let bytes = common::build_registry_fixture(&root_only);
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    let summary = AmcacheParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(summary.status, ParseStatus::Skipped);
    assert!(sink.events.is_empty());
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
}

// ============================================================
// T4-064: Registry Parser との明示的併用
// ============================================================

#[test]
fn registry_parser_also_parses_amcache_hve() {
    // Registry Parser で Amcache.hve を解析した場合も hive_type=amcache で Event 生成可能。
    // これが「明示的併用」（自動 fallback ではなく呼出側が明示的に Registry Parser を起動）。
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = ParseContext {
        evidence: EvidenceItem {
            evidence_id: "tf-evidence-v1:reg-test".to_string(),
            source_locator: "Amcache.hve".to_string(),
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
            parser_id: tf_parsers::REGISTRY_PARSER_ID.to_string(),
            parser_version: tf_parsers::REGISTRY_PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["regf magic".to_string()],
            parse_status: ParseStatus::Complete,
        },
    };
    let mut sink = CollectorSink::new();
    let summary = tf_parsers::RegistryParser::new().parse(&mut cursor, &context, &mut sink);

    assert_eq!(summary.status, ParseStatus::Complete);
    assert!(!sink.events.is_empty());
    // Registry Parser 側は hive_type=amcache で観測 Event を出す。
    let first = &sink.events[0];
    assert_eq!(first.attributes["registry.hive_type"], "amcache");
    assert_eq!(first.source, ArtifactSource::Registry);
}

#[test]
fn amcache_and_registry_parsers_produce_distinct_event_ids() {
    // 同一 Evidence を Amcache Parser と Registry Parser の両方で解析すると、
    // 異なる Event 群（source / event_type / parser_id が異なる）が生成される。
    // これが「明示的併用」の実体。
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());

    // Amcache Parser 側。
    let mut cursor1 = Cursor::new(bytes.clone());
    let amcache_context = make_context("Amcache.hve");
    let mut amcache_sink = CollectorSink::new();
    AmcacheParser::new().parse(&mut cursor1, &amcache_context, &mut amcache_sink);

    // Registry Parser 側。
    let mut cursor2 = Cursor::new(bytes);
    let reg_context = ParseContext {
        evidence: EvidenceItem {
            evidence_id: "tf-evidence-v1:reg-test".to_string(),
            source_locator: "Amcache.hve".to_string(),
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
            parser_id: tf_parsers::REGISTRY_PARSER_ID.to_string(),
            parser_version: tf_parsers::REGISTRY_PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["regf magic".to_string()],
            parse_status: ParseStatus::Complete,
        },
    };
    let mut reg_sink = CollectorSink::new();
    tf_parsers::RegistryParser::new().parse(&mut cursor2, &reg_context, &mut reg_sink);

    // 両 Parser が Event を生成する（明示的併用）。
    assert!(!amcache_sink.events.is_empty());
    assert!(!reg_sink.events.is_empty());
    // source が異なる（Amcache / Registry）。
    assert!(
        amcache_sink
            .events
            .iter()
            .all(|e| e.source == ArtifactSource::Amcache)
    );
    assert!(
        reg_sink
            .events
            .iter()
            .all(|e| e.source == ArtifactSource::Registry)
    );
    // event_type も異なる（amcache_observation / registry_*）。
    assert!(
        amcache_sink
            .events
            .iter()
            .all(|e| e.event_type.as_str() == AMCACHE_OBSERVATION_EVENT_TYPE)
    );
    assert!(reg_sink.events.iter().all(|e| {
        let t = e.event_type.as_str();
        t == tf_parsers::REGISTRY_OBSERVATION_EVENT_TYPE
            || t == tf_parsers::REGISTRY_KEY_LAST_WRITE_EVENT_TYPE
    }));
}

// ============================================================
// T4-065: 破損耐性・Provenance 到達・決定性
// ============================================================

#[test]
fn corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8]| {
        let mut cursor = Cursor::new(bytes.to_vec());
        let context = make_context("Amcache.hve");
        let mut sink = CollectorSink::new();
        let _ = AmcacheParser::new().parse(&mut cursor, &context, &mut sink);
    };

    // 短すぎる
    run(&(0..10).collect::<Vec<u8>>());
    // base block のみ
    run(&vec![0u8; 4096]);
    // magic を壊す
    let mut bad = common::build_registry_fixture(&win10_inventory_fixture());
    bad[0] = 0xFF;
    run(&bad);
    // root offset を範囲外へ
    let mut bad2 = common::build_registry_fixture(&win10_inventory_fixture());
    bad2[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    run(&bad2);
}

#[test]
fn provenance_records_byte_range_and_parser_metadata() {
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let prov = &e.provenance;
        assert_eq!(prov.parser_id, AMCACHE_PARSER_ID);
        assert_eq!(prov.parser_version, AMCACHE_PARSER_VERSION);
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
        // context の Evidence / Artifact 情報が伝播している。
        assert_eq!(prov.evidence_id, context.evidence.evidence_id);
        assert_eq!(prov.source_locator, context.evidence.source_locator);
    }
}

#[test]
fn parser_is_deterministic_across_runs() {
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let run_once = || -> Vec<String> {
        let mut cursor = Cursor::new(bytes.clone());
        let context = make_context("Amcache.hve");
        let mut sink = CollectorSink::new();
        AmcacheParser::new().parse(&mut cursor, &context, &mut sink);
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
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert_eq!(e.attributes["amcache.reference_spec"], AMCACHE_REFERENCE);
        assert_eq!(
            e.attributes["amcache.parser_version"],
            AMCACHE_PARSER_VERSION
        );
    }
}

#[test]
fn path_field_unused_for_amcache() {
    // 規範 §8「Evidence 内 path に PathBuf を使わない」。Amcache は Event.path を
    // 使わず、key_path 属性で表現する。
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert!(
            e.path.is_none(),
            "Amcache Event は path field を使わない（key_path 属性で表現）"
        );
    }
}

#[test]
fn schema_family_recorded_in_every_event() {
    // 互換 §5 必須 field「schema family」が全 Event 属性へ記録される。
    let bytes = common::build_registry_fixture(&win10_inventory_fixture());
    let mut cursor = Cursor::new(bytes);
    let context = make_context("Amcache.hve");
    let mut sink = CollectorSink::new();

    AmcacheParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert!(
            e.attributes.contains_key("amcache.schema_family"),
            "schema_family が必須: event={}",
            e.id
        );
        let family = e.attributes["amcache.schema_family"].as_str().unwrap();
        assert!(
            family == "win10-22h2-win11-24h2-inventory" || family == "win8-8.1-legacy",
            "schema_family は対応済みのいずれか: {family}"
        );
    }
}
