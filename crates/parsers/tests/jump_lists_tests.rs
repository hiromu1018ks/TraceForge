//! Jump Lists Parser の統合テスト（T4-070〜T4-074、互換 §4.5）。
//!
//! 合成 fixture（`tests/common/mod.rs` の builder 群）を用いて、CFB container 解析・
//! DestList 解析・内包 LNK の ArtifactInstance 化・CustomDestinations 解析・
//! Provenance 到達・決定性・3 OS 世代対応を検証する。acceptance test 8条件の
//! Jump Lists 版は `acceptance_tests.rs` へ掲載する。

mod common;

use std::io::Cursor;

use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, RecordLocator};
use tf_parsers::framework::{ArtifactParser, ParseContext, ParseSink};
use tf_parsers::jump_lists::{
    JUMP_LIST_OBSERVATION_EVENT_TYPE, JUMP_LIST_REFERENCE, JumpListParser,
};
use tf_parsers::{JUMP_LIST_PARSER_ID, JUMP_LIST_PARSER_VERSION};

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
            evidence_id: "tf-evidence-v1:jl-test".to_string(),
            source_locator: source_locator.to_string(),
            size: 200,
            sha256: "ab".repeat(32),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        },
        artifact: ArtifactInstance {
            artifact_id: "tf-artifact-v1:jl-test".to_string(),
            evidence_id: "tf-evidence-v1:jl-test".to_string(),
            artifact_type: ArtifactSource::JumpList,
            parser_id: JUMP_LIST_PARSER_ID.to_string(),
            parser_version: JUMP_LIST_PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["jump list extension".to_string()],
            parse_status: ParseStatus::Complete,
        },
    }
}

/// サンプル FILETIME（2026-08-10T01:15:20Z 相当）。
fn ft(offset_secs: i64) -> u64 {
    common::filetime_from_unix_offset(offset_secs)
}

/// v1 AutomaticDestinations fixture（Win7 SP1）: 2 stream × DestList 2 entry。
fn win7_automatic_fixture() -> Vec<u8> {
    let lnk1 = common::build_jump_list_lnk(
        ft(0),
        ft(60),
        ft(120),
        1234,
        Some("C:\\Windows\\System32\\notepad.exe"),
        true,
    );
    let lnk2 = common::build_jump_list_lnk(
        ft(180),
        ft(240),
        ft(300),
        5678,
        Some("C:\\Windows\\System32\\calc.exe"),
        true,
    );
    let destlist = common::build_destlist_v1(&[(ft(100), "1"), (ft(200), "2")]);
    let streams: Vec<(&str, &[u8])> = vec![("DestList", &destlist), ("1", &lnk1), ("2", &lnk2)];
    common::build_automatic_destinations(&streams)
}

/// v3 AutomaticDestinations fixture（Win10 22H2 / Win11 24H2）: 2 stream × DestList 2 entry。
fn win10_automatic_fixture() -> Vec<u8> {
    let lnk1 = common::build_jump_list_lnk(
        ft(0),
        ft(60),
        ft(120),
        1234,
        Some("C:\\Windows\\System32\\notepad.exe"),
        true,
    );
    let lnk2 = common::build_jump_list_lnk(
        ft(180),
        ft(240),
        ft(300),
        5678,
        Some("C:\\Windows\\explorer.exe"),
        true,
    );
    let destlist = common::build_destlist_v3(&[(ft(100), "1"), (ft(200), "2")]);
    let streams: Vec<(&str, &[u8])> = vec![("DestList", &destlist), ("1", &lnk1), ("2", &lnk2)];
    common::build_automatic_destinations(&streams)
}

/// v4 AutomaticDestinations fixture（Win11 24H2）: DestList version 4 を使用。
fn win11_automatic_fixture() -> Vec<u8> {
    let lnk1 = common::build_jump_list_lnk(
        ft(0),
        ft(60),
        ft(120),
        1234,
        Some("C:\\Windows\\System32\\notepad.exe"),
        true,
    );
    let lnk2 = common::build_jump_list_lnk(
        ft(180),
        ft(240),
        ft(300),
        5678,
        Some("C:\\Windows\\explorer.exe"),
        true,
    );
    let destlist = common::build_destlist_v4(&[(ft(100), "1"), (ft(200), "2")]);
    let streams: Vec<(&str, &[u8])> = vec![("DestList", &destlist), ("1", &lnk1), ("2", &lnk2)];
    common::build_automatic_destinations(&streams)
}

/// CustomDestinations fixture: 1 category × 2 entries。
fn custom_fixture() -> Vec<u8> {
    let lnk1 = common::build_jump_list_lnk(
        ft(0),
        ft(60),
        ft(120),
        1234,
        Some("C:\\Windows\\System32\\notepad.exe"),
        true,
    );
    let lnk2 = common::build_jump_list_lnk(
        ft(180),
        ft(240),
        ft(300),
        5678,
        Some("C:\\Windows\\System32\\mspaint.exe"),
        true,
    );
    let entries: Vec<Vec<u8>> = vec![lnk1, lnk2];
    common::build_custom_destinations(&[(0x0000_0001, &entries)])
}

// ============================================================
// T4-070: CFB container 解析（AutomaticDestinations）
// ============================================================

#[test]
fn automatic_destinations_parses_all_streams() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("b9105685df489b5b.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    let summary = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(
        summary.status,
        ParseStatus::Complete,
        "issues: {:?}",
        sink.issues
    );
    // 2 LNK stream → 2 observation events。
    assert_eq!(sink.events.len(), 2);
    assert_eq!(summary.records_seen, 2);
    assert_eq!(summary.events_emitted, 2);
}

#[test]
fn cfb_container_corrupt_does_not_panic() {
    let run = |bytes: &[u8]| {
        let mut cursor = Cursor::new(bytes.to_vec());
        let context = make_context("x.automaticDestinations-ms");
        let mut sink = CollectorSink::new();
        let _ = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
    };
    // header 無し。
    run(&(0..100).collect::<Vec<u8>>());
    // CFB magic 壊し。
    let mut bad = win10_automatic_fixture();
    bad[0] = 0x00;
    run(&bad);
    // FAT chain を自己参照へ。
    let mut bad2 = win10_automatic_fixture();
    bad2[512..516].copy_from_slice(&0u32.to_le_bytes());
    run(&bad2);
}

// ============================================================
// T4-071: DestList 解析（未知 version は Warning）
// ============================================================

#[test]
fn destlist_unknown_version_emits_warning() {
    // 未知 version の DestList を持つ AutomaticDestinations。
    let mut bad_destlist = vec![0u8; 32];
    bad_destlist[0..4].copy_from_slice(&99u32.to_le_bytes()); // version 99
    let lnk1 = common::build_jump_list_lnk(ft(0), ft(0), ft(0), 0, None, true);
    let streams: Vec<(&str, &[u8])> = vec![("DestList", &bad_destlist), ("1", &lnk1)];
    let data = common::build_automatic_destinations(&streams);

    let mut cursor = Cursor::new(data);
    let context = make_context("x.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    let summary = JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    // Partial（DestList 未知 version）。
    assert_eq!(summary.status, ParseStatus::Partial);
    // LNK stream は1件 Event 生成される。
    assert_eq!(sink.events.len(), 1);
    // Warning Issue 発行。
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE),
        "UNSUPPORTED_VERSION Issue が必要: {:?}",
        sink.issues
    );
}

#[test]
fn destlist_v1_emits_events() {
    let data = win7_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    let summary = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 2);
    // 全 Event の destlist_format_version = 1。
    for e in &sink.events {
        assert_eq!(e.attributes["jump_list.destlist_format_version"], 1);
    }
}

#[test]
fn destlist_v3_emits_events() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    let summary = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 2);
    for e in &sink.events {
        assert_eq!(e.attributes["jump_list.destlist_format_version"], 3);
    }
}

// ============================================================
// T4-072: 内包 LNK の ArtifactInstance 化
// ============================================================

#[test]
fn embedded_lnk_record_locator_is_logical_path() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    // 全 Event の record_locator が LogicalPath（stream 名）。
    for e in &sink.events {
        match &e.provenance.record_locator {
            RecordLocator::LogicalPath(parts) => {
                assert!(!parts.is_empty());
                let name = &parts[0];
                assert!(name == "1" || name == "2", "stream 名は 1 or 2: got {name}");
            }
            other => panic!("LogicalPath のみ許可: {other:?}"),
        }
    }
}

#[test]
fn embedded_lnk_target_path_carried_in_attributes() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    let paths: Vec<String> = sink
        .events
        .iter()
        .filter_map(|e| {
            e.attributes
                .get("jump_list.lnk_target_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().any(|p| p.contains("notepad.exe")));
    assert!(paths.iter().any(|p| p.contains("explorer.exe")));
}

#[test]
fn embedded_lnk_is_not_registered_as_physical_evidence() {
    // 内包 LNK は物理 Evidence ではなく Jump List Evidence 内の ArtifactInstance。
    // 全 Event の source が JumpList であり、parser_id が traceforge-jump-lists。
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert_eq!(e.source, ArtifactSource::JumpList);
        assert_eq!(e.provenance.parser_id, JUMP_LIST_PARSER_ID);
        assert_eq!(e.provenance.parser_version, JUMP_LIST_PARSER_VERSION);
        // source が lnk_timestamp ではない（LNK Event の混入を防ぐ）。
        assert_ne!(e.event_type.as_str(), "lnk_timestamp");
    }
}

// ============================================================
// T4-073: CustomDestinations 解析
// ============================================================

#[test]
fn custom_destinations_emits_events() {
    let data = custom_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.customDestinations-ms");
    let mut sink = CollectorSink::new();

    let summary = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
    assert_eq!(
        summary.status,
        ParseStatus::Complete,
        "issues: {:?}",
        sink.issues
    );
    // 1 category / 2 entries → 2 events。
    assert_eq!(sink.events.len(), 2);
    for e in &sink.events {
        assert_eq!(
            e.attributes["jump_list.container_type"],
            "custom_destinations"
        );
        // record_locator は ByteRange（file 内 byte 範囲）。
        assert!(matches!(
            e.provenance.record_locator,
            RecordLocator::ByteRange { .. }
        ));
    }
}

#[test]
fn custom_destinations_corrupt_does_not_panic() {
    let run = |bytes: &[u8]| {
        let mut cursor = Cursor::new(bytes.to_vec());
        let context = make_context("app.customDestinations-ms");
        let mut sink = CollectorSink::new();
        let _ = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
    };
    run(&[]);
    run(&[0u8; 4]);
    let mut truncated = custom_fixture();
    truncated.truncate(truncated.len() - 10);
    run(&truncated);
}

// ============================================================
// T4-074: Provenance 到達・観測型 Event・決定性
// ============================================================

#[test]
fn only_observation_event_type() {
    // 規範 §7.1・互換 §4.5: 観測型 jump_list_observation のみ。
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    assert!(!sink.events.is_empty());
    for e in &sink.events {
        assert_eq!(e.event_type.as_str(), JUMP_LIST_OBSERVATION_EVENT_TYPE);
        assert_eq!(e.assertion, AssertionKind::Observed);
        assert_eq!(e.source, ArtifactSource::JumpList);
        // open/launch 等の断定型ではない。
        let et = e.event_type.as_str();
        assert!(!et.contains("open"));
        assert!(!et.contains("launch"));
        assert!(!et.contains("executed"));
        assert!(!et.contains("ran"));
    }
}

#[test]
fn provenance_reaches_original_record_automatic() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let prov = &e.provenance;
        assert_eq!(prov.parser_id, JUMP_LIST_PARSER_ID);
        assert_eq!(prov.parser_version, JUMP_LIST_PARSER_VERSION);
        assert_eq!(prov.evidence_id, context.evidence.evidence_id);
        assert_eq!(prov.source_locator, context.evidence.source_locator);
        // LogicalPath で stream 名を保持。
        assert!(matches!(prov.record_locator, RecordLocator::LogicalPath(_)));
        // stream_name 属性も記録。
        assert!(e.attributes.contains_key("jump_list.stream_name"));
    }
}

#[test]
fn parser_is_deterministic_across_runs_automatic() {
    let data = win10_automatic_fixture();
    let run_once = || -> Vec<String> {
        let mut cursor = Cursor::new(data.clone());
        let context = make_context("app.automaticDestinations-ms");
        let mut sink = CollectorSink::new();
        JumpListParser::new().parse(&mut cursor, &context, &mut sink);
        let mut ids: Vec<String> = sink.events.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

#[test]
fn parser_is_deterministic_across_runs_custom() {
    let data = custom_fixture();
    let run_once = || -> Vec<String> {
        let mut cursor = Cursor::new(data.clone());
        let context = make_context("app.customDestinations-ms");
        let mut sink = CollectorSink::new();
        JumpListParser::new().parse(&mut cursor, &context, &mut sink);
        let mut ids: Vec<String> = sink.events.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2);
}

#[test]
fn reference_spec_recorded_in_attributes() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert_eq!(
            e.attributes["jump_list.reference_spec"],
            JUMP_LIST_REFERENCE
        );
        assert_eq!(
            e.attributes["jump_list.parser_version"],
            JUMP_LIST_PARSER_VERSION
        );
    }
}

#[test]
fn app_id_recorded_from_filename() {
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("b9105685df489b5b.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        assert_eq!(e.attributes["jump_list.app_id"], "b9105685df489b5b");
    }
}

#[test]
fn interpretation_limitation_recorded() {
    // 互換 §5 必須 field「interpretation limitation」が各 Event へ記録される。
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let limitation = e.attributes["jump_list.interpretation_limitation"]
            .as_str()
            .unwrap();
        assert!(limitation.contains("not"));
        assert!(limitation.contains("opening") || limitation.contains("launching"));
    }
}

#[test]
fn attributes_keys_sorted() {
    // 規範 §13.2: attributes は BTreeMap で決定性。
    let data = win10_automatic_fixture();
    let mut cursor = Cursor::new(data);
    let context = make_context("app.automaticDestinations-ms");
    let mut sink = CollectorSink::new();

    JumpListParser::new().parse(&mut cursor, &context, &mut sink);

    for e in &sink.events {
        let keys: Vec<&str> = e.attributes.keys().map(|k| k.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "attributes の key が sort 済み");
    }
}

#[test]
fn probe_detects_automatic_destinations() {
    let data = win10_automatic_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (evidence, _) = common::make_snapshot("x.automaticDestinations-ms", &data, dir.path());

    let probe = JumpListParser::new().probe(&evidence);
    assert_eq!(probe, ProbeResult::Confirmed);
}

#[test]
fn probe_detects_custom_destinations() {
    let data = custom_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (evidence, _) = common::make_snapshot("x.customDestinations-ms", &data, dir.path());

    let probe = JumpListParser::new().probe(&evidence);
    // CustomDestinations は確証性の低い Probable。
    assert!(probe == ProbeResult::Probable || probe == ProbeResult::Confirmed);
}

#[test]
fn probe_rejects_non_jump_list() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = vec![0xFFu8; 100];
    let (evidence, _) = common::make_snapshot("unknown.bin", &bytes, dir.path());
    let probe = JumpListParser::new().probe(&evidence);
    assert_eq!(probe, ProbeResult::NotThisFormat);
}

#[test]
fn vertical_slice_automatic_to_eventstore() {
    // Automatic → EventStore 縦割り。
    let data = win10_automatic_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (evidence, _) = common::make_snapshot("x.automaticDestinations-ms", &data, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        JUMP_LIST_PARSER_ID,
        JUMP_LIST_PARSER_VERSION,
        ArtifactSource::JumpList,
    );

    use tf_parsers::sink::EventStoreSink;
    use tf_store::EventStore;
    let spool_path = dir.path().join("jl.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact: artifact.clone(),
    };
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        JumpListParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();
    assert!(!store.is_empty(), "Event が生成されている");
}

#[test]
fn three_os_generation_fixtures() {
    // 互換 §4.5: Win 7 SP1 / Win 10 22H2 / Win 11 24H2 の3世代 fixture。
    // 各 OS 世代で DestList version が異なる: v1 (Win7)・v3 (Win10)・v4 (Win11)。
    let win7 = win7_automatic_fixture();
    let win10 = win10_automatic_fixture();
    let win11 = win11_automatic_fixture();

    for (label, data, expected_version) in [
        ("win7", &win7, 1u64),
        ("win10", &win10, 3u64),
        ("win11", &win11, 4u64),
    ] {
        let mut cursor = Cursor::new(data.clone());
        let context = make_context("x.automaticDestinations-ms");
        let mut sink = CollectorSink::new();
        let summary = JumpListParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(
            summary.status,
            ParseStatus::Complete,
            "{label}: issues={:?}",
            sink.issues
        );
        assert!(!sink.events.is_empty(), "{label} は Event 生成");
        // 全 Event の destlist_format_version が期待値。
        for e in &sink.events {
            assert_eq!(
                e.attributes["jump_list.destlist_format_version"], expected_version,
                "{label}: destlist_format_version が一致しない"
            );
        }
    }
}
