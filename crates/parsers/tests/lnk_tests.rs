//! LNK Parser の統合テスト（T4-010〜T4-015、互換 §4.4・§12）。
//!
//! [MS-SHLLINK] に準拠した合成 fixture を使い、各 section の解析と
//! Event 生成（観測型、規範 §7.1）を検証する。acceptance 条件の包括検証は
//! `acceptance_tests.rs` へ。

mod common;

use tf_core::case::{IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::ArtifactSource;
use tf_parsers::LnkParser;
use tf_parsers::framework::{ArtifactParser, ParseContext, ParseSink, SinkError};
use tf_parsers::issue::{MALFORMED_INPUT_CODE, TRUNCATED_RECORD_CODE};
use tf_parsers::lnk::{LNK_TIMESTAMP_EVENT_TYPE, MS_SHLLINK_REFERENCE, PARSER_ID, PARSER_VERSION};

/// Event・Issue を蓄積するテスト用 sink。
struct CollectorSink {
    events: Vec<tf_core::event::Event>,
    issues: Vec<tf_core::issue::Issue>,
}

impl ParseSink for CollectorSink {
    fn emit_event(&mut self, event: tf_core::event::Event) -> Result<(), SinkError> {
        self.events.push(event);
        Ok(())
    }
    fn emit_issue(&mut self, issue: tf_core::issue::Issue) -> Result<(), SinkError> {
        self.issues.push(issue);
        Ok(())
    }
}

fn collector() -> CollectorSink {
    CollectorSink {
        events: Vec::new(),
        issues: Vec::new(),
    }
}

/// snapshot file から EvidenceItem と ArtifactInstance を構築し、ParseContext を作る。
fn make_context_from_snapshot(
    source_locator: &str,
    lnk_bytes: &[u8],
    temp_dir: &std::path::Path,
) -> ParseContext {
    let (evidence, _snapshot_path) = common::make_snapshot(source_locator, lnk_bytes, temp_dir);
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);
    ParseContext { evidence, artifact }
}

/// context を作り、LNK Parser を実行する。
fn parse_lnk(
    lnk_bytes: &[u8],
    temp_dir: &std::path::Path,
) -> (ParseContext, CollectorSink, tf_parsers::ParseSummary) {
    let context = make_context_from_snapshot("test.lnk", lnk_bytes, temp_dir);
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let mut sink = collector();
    let parser = LnkParser::new();
    let summary = parser.parse(&mut file, &context, &mut sink);
    (context, sink, summary)
}

// ============================================================
// T4-010: Shell Link Header 解析（size・CLSID・flags・timestamps 検証）
// ============================================================

#[test]
fn t4_010_header_with_three_timestamps_emits_three_events() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        access_filetime: common::filetime_from_unix_offset(60),
        write_filetime: common::filetime_from_unix_offset(120),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (context, sink, summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 3);
    // 全 Event が LNK source・lnk_timestamp type・Observed assertion。
    for e in &sink.events {
        assert_eq!(e.source, ArtifactSource::Lnk);
        assert_eq!(e.event_type.as_str(), LNK_TIMESTAMP_EVENT_TYPE);
        assert_eq!(e.assertion, tf_core::event::AssertionKind::Observed);
        // header 情報が attributes へ。
        assert!(e.attributes.contains_key("lnk.header_size"));
        assert!(e.attributes.contains_key("lnk.flags"));
        assert!(e.attributes.contains_key("lnk.file_size"));
        // 外部仕様 revision が記録される（互換 §12-6）。
        assert_eq!(e.attributes["lnk.reference_spec"], MS_SHLLINK_REFERENCE);
        assert_eq!(e.attributes["lnk.parser_version"], PARSER_VERSION);
    }
    // Evidence ID が Provenance へ伝播。
    for e in &sink.events {
        assert_eq!(e.provenance.evidence_id, context.evidence.evidence_id);
        assert_eq!(e.provenance.artifact_id, context.artifact.artifact_id);
        assert_eq!(e.provenance.parser_id, PARSER_ID);
        assert_eq!(e.provenance.parser_version, PARSER_VERSION);
    }
}

#[test]
fn t4_010_bad_clsid_is_malformed_and_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions::default();
    let mut bytes = common::build_lnk_fixture(&opts);
    bytes[4] = 0xFF; // CLSID を壊す

    let (_context, sink, summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(summary.status, ParseStatus::Skipped);
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == MALFORMED_INPUT_CODE)
    );
}

#[test]
fn t4_010_unknown_header_size_is_skipped() {
    // 既知形式として推測しない（AGENTS.md 禁止事項）。
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions::default();
    let mut bytes = common::build_lnk_fixture(&opts);
    bytes[0..4].copy_from_slice(&0x0000_0050u32.to_le_bytes()); // 80

    let (_context, sink, summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(summary.status, ParseStatus::Failed);
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == MALFORMED_INPUT_CODE)
    );
}

// ============================================================
// T4-011: LinkTargetIDList 解析（境界検証、未知 item raw 保持）
// ============================================================

#[test]
fn t4_011_idlist_present_does_not_break_parse() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        flags: 0x0000_0001, // HasLinkTargetIDList
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (_context, sink, summary) = parse_lnk(&bytes, dir.path());

    // IDList があっても header の timestamp から Event が生成される。
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1);
}

#[test]
fn t4_011_truncated_idlist_produces_partial_but_events_preserved() {
    // IDList を途中で切断。header 由来の Event は生成、Partial status。
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        flags: 0x0000_0001, // HasLinkTargetIDList
        creation_filetime: common::filetime_from_unix_offset(0),
        with_extra_data: false,
        ..Default::default()
    };
    let mut bytes = common::build_lnk_fixture(&opts);
    // IDListSize だけ宣言し、本体を削る（header 76 byte + IDListSize 2 byte の後を切る）。
    bytes.truncate(common::HEADER_BYTES + 2 + 2); // size 宣言 + 2 byte だけ

    let (_context, sink, summary) = parse_lnk(&bytes, dir.path());

    // 生成済み Event は破棄されない（規範 §9.2）。
    assert_eq!(summary.status, ParseStatus::Partial);
    // header は読めたので timestamp Event は1つ生成される。
    assert_eq!(sink.events.len(), 1);
    assert!(
        sink.issues
            .iter()
            .any(|i| { i.issue_id == tf_parsers::issue::PARTIAL_RECORD_BOUNDARY_CODE })
    );
}

// ============================================================
// T4-012: LinkInfo 解析
// ============================================================

#[test]
fn t4_012_link_info_local_base_path_carried_to_event() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        flags: 0x0000_0002, // HasLinkInfo
        creation_filetime: common::filetime_from_unix_offset(0),
        local_base_path: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (_context, sink, _summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(sink.events.len(), 1);
    let e = &sink.events[0];
    // target_path が attributes へ。
    assert_eq!(
        e.attributes["lnk.target_path"],
        "C:\\Windows\\System32\\notepad.exe"
    );
    // Event の path（WindowsPathValue）へも設定される。
    let path = e.path.as_ref().expect("target path があるべき");
    assert_eq!(path.original, "C:\\Windows\\System32\\notepad.exe");
    assert_eq!(path.normalization_profile, "windows-path-v1");
}

// ============================================================
// T4-013: StringData 解析
// ============================================================

#[test]
fn t4_013_string_data_unicode_name_in_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        flags: 0x0000_0084, // HasName | IsUnicode
        creation_filetime: common::filetime_from_unix_offset(0),
        with_name_string: true,
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (_context, sink, _summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(sink.events.len(), 1);
    let e = &sink.events[0];
    // name が attributes へ。
    assert_eq!(e.attributes["lnk.name"], "shortcut_name");
}

#[test]
fn t4_013_string_data_ansi_ascii() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        flags: 0x0000_0004, // HasName（ANSI）
        creation_filetime: common::filetime_from_unix_offset(0),
        with_name_string: true,
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (_context, sink, _summary) = parse_lnk(&bytes, dir.path());

    let e = &sink.events[0];
    assert_eq!(e.attributes["lnk.name"], "shortcut_name");
}

// ============================================================
// T4-014: ExtraData 解析（既知 block + 未知 block skip）
// ============================================================

#[test]
fn t4_014_extra_data_unknown_block_counted_not_silently_dropped() {
    // 互換 §12-7: 非対応 field・構文・version を黙って無視しない。
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        with_extra_data: false, // 後で手動で ExtraData を追加
        ..Default::default()
    };
    let mut bytes = common::build_lnk_fixture(&opts);
    // 未知 signature block (0xDEAD_BEEF) を追加。
    let unknown_data: &[u8] = &[0x01, 0x02, 0x03];
    let unknown_block_size: u32 = 8 + unknown_data.len() as u32;
    bytes.extend_from_slice(&unknown_block_size.to_le_bytes());
    bytes.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    bytes.extend_from_slice(unknown_data);
    // TerminalBlock。
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let (_context, sink, _summary) = parse_lnk(&bytes, dir.path());

    let e = &sink.events[0];
    // 未知 block 数が記録される（黙って無視しない）。
    assert_eq!(e.attributes["lnk.unknown_extra_block_count"], 1);
    // block 名が extra_blocks へ記録される。
    let blocks = e.attributes["lnk.extra_blocks"].as_array().unwrap();
    assert!(
        blocks
            .iter()
            .any(|v| v.as_str().unwrap().contains("Unknown(0xDEADBEEF)"))
    );
}

#[test]
fn t4_014_extra_data_truncated_yields_partial() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        with_extra_data: false,
        ..Default::default()
    };
    let mut bytes = common::build_lnk_fixture(&opts);
    // TerminalBlock 無しで、中途半端な ExtraData block を追加。
    bytes.extend_from_slice(&100u32.to_le_bytes()); // BlockSize = 100
    bytes.extend_from_slice(&0xA000_0003u32.to_le_bytes()); // TrackerData
    bytes.extend_from_slice(&[0u8; 5]); // data が足りない（truncated）

    let (_context, sink, summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(summary.status, ParseStatus::Partial);
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == TRUNCATED_RECORD_CODE)
    );
}

// ============================================================
// T4-015: timestamp kind と元 field 名の保持（互換 §4.4）
// ============================================================

#[test]
fn t4_015_timestamp_kind_and_source_field_preserved() {
    // 互換 §4.4: LNK timestamp は timestamp kind と元 field 名を保持する。
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        access_filetime: common::filetime_from_unix_offset(60),
        write_filetime: common::filetime_from_unix_offset(120),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (_context, sink, _summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(sink.events.len(), 3);
    // 各 Event の timestamp_field と kind を検証。
    let by_field: std::collections::HashMap<&str, &tf_core::event::Event> = sink
        .events
        .iter()
        .map(|e| (e.attributes["lnk.timestamp_field"].as_str().unwrap(), e))
        .collect();

    let creation = by_field.get("creation").expect("creation があるべき");
    assert_eq!(creation.time.kind, tf_core::time::TimestampKind::Created);
    assert!(
        creation
            .time
            .original
            .as_ref()
            .unwrap()
            .contains("FILETIME(creation=")
    );

    let access = by_field.get("access").expect("access があるべき");
    assert_eq!(access.time.kind, tf_core::time::TimestampKind::Accessed);
    assert!(
        access
            .time
            .original
            .as_ref()
            .unwrap()
            .contains("FILETIME(access=")
    );

    let write = by_field.get("write").expect("write があるべき");
    assert_eq!(write.time.kind, tf_core::time::TimestampKind::Modified);
    assert!(
        write
            .time
            .original
            .as_ref()
            .unwrap()
            .contains("FILETIME(write=")
    );

    // 全 Event が UTC instant・microsecond 精度・ArtifactDefined timezone。
    for e in &sink.events {
        assert_eq!(e.time.precision, tf_core::time::TimePrecision::Microsecond);
        assert_eq!(
            e.time.timezone_source,
            tf_core::time::TimezoneSource::ArtifactDefined
        );
        // filetime.rs で 100ns 精度を保持。
        assert!(matches!(
            e.time.value,
            tf_core::time::TemporalValue::UtcInstant { .. }
        ));
    }

    // 互換 §4.4: timestamp だけから「target を開いた」と断定しない。
    // event_type は lnk_timestamp（観測型）であり、file_opened 等ではない。
    for e in &sink.events {
        assert_eq!(e.event_type.as_str(), LNK_TIMESTAMP_EVENT_TYPE);
        assert!(!e.event_type.as_str().contains("opened"));
        assert!(!e.event_type.as_str().contains("executed"));
    }
}

#[test]
fn t4_015_no_timestamps_yields_single_unknown_event() {
    // 全 timestamp 0 → Unknown time で1 Event（header 観測）。
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: 0,
        access_filetime: 0,
        write_filetime: 0,
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (_context, sink, summary) = parse_lnk(&bytes, dir.path());

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1);
    assert_eq!(
        sink.events[0].time.value,
        tf_core::time::TemporalValue::Unknown
    );
    assert_eq!(sink.events[0].attributes["lnk.timestamp_field"], "none");
}

// ============================================================
// probe（ArtifactParser::probe）
// ============================================================

#[test]
fn lnk_probe_returns_confirmed_for_valid_lnk() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _snapshot_path) = common::make_snapshot("test.lnk", &bytes, dir.path());

    let parser = LnkParser::new();
    assert_eq!(parser.probe(&evidence), ProbeResult::Confirmed);
}

#[test]
fn lnk_probe_returns_not_this_format_for_non_verified() {
    // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions::default();
    let bytes = common::build_lnk_fixture(&opts);
    let (mut evidence, _) = common::make_snapshot("test.lnk", &bytes, dir.path());
    evidence.integrity_status = IntegrityStatus::ChangedDuringSnapshot;

    let parser = LnkParser::new();
    assert_eq!(parser.probe(&evidence), ProbeResult::NotThisFormat);
}
