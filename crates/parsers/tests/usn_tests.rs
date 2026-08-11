//! USN Journal Parser の統合テスト（T4-030〜T4-037、互換 §4.3）。
//!
//! 各 version（V2/V3/V4）の正常 fixture・rename 結合・未知 version skip・truncated・
//! 過大 record length・path reconstruction を検証する。互換 §12 acceptance 条件の
//! USN 版は `acceptance_tests.rs` へ集約している。

mod common;

use std::io::Cursor;

use tf_core::case::ParseStatus;
use tf_core::event::RecordLocator;
use tf_parsers::ParseSink;
use tf_parsers::framework::{ArtifactParser, ParseContext};
use tf_parsers::sink::EventStoreSink;
use tf_parsers::usn::{
    PARSER_ID, PARSER_VERSION, USN_CHANGE_OBSERVED_EVENT_TYPE, USN_REFERENCE, UsnParser,
};
use tf_store::EventStore;

use common::usn_reason;
use common::{build_usn_v2_record, build_usn_v3_record, build_usn_v4_record};

/// Event・Issue を蓄積する test 用 sink。
struct TestSink {
    events: Vec<tf_core::event::Event>,
    issues: Vec<tf_core::issue::Issue>,
}
impl ParseSink for TestSink {
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

fn make_context() -> ParseContext {
    use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ProbeResult};
    use tf_core::event::ArtifactSource;
    ParseContext {
        evidence: EvidenceItem {
            evidence_id: "tf-evidence-v1:usn-int".to_string(),
            source_locator: "$UsnJrnl$J".to_string(),
            size: 300,
            sha256: "ef".repeat(32),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        },
        artifact: ArtifactInstance {
            artifact_id: "tf-artifact-v1:usn-int".to_string(),
            evidence_id: "tf-evidence-v1:usn-int".to_string(),
            artifact_type: ArtifactSource::UsnJournal,
            parser_id: PARSER_ID.to_string(),
            parser_version: PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["common header".to_string()],
            parse_status: ParseStatus::Complete,
        },
    }
}

/// USN 解析を cursor 入力で実行し sink の内容を返す。
fn run_parse(bytes: &[u8]) -> (tf_parsers::ParseSummary, TestSink) {
    let mut cursor = Cursor::new(bytes.to_vec());
    let context = make_context();
    let mut sink = TestSink {
        events: vec![],
        issues: vec![],
    };
    let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
    (summary, sink)
}

/// 2件以上の V2 record を生成する共通 fixture。
fn two_v2_records() -> Vec<u8> {
    let r1 = build_usn_v2_record(
        0x0001_0000_0000_1234,
        0x0005_0000_0000_0001,
        100,
        common::usn_filetime_from_unix_offset(0),
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "create.txt",
    );
    let r2 = build_usn_v2_record(
        0x0001_0000_0000_1235,
        0x0005_0000_0000_0001,
        101,
        common::usn_filetime_from_unix_offset(60),
        usn_reason::DATA_EXTEND,
        0,
        0,
        0x20,
        "extend.txt",
    );
    let mut bytes = r1;
    bytes.extend(r2);
    bytes
}

#[test]
fn parser_metadata_is_stable() {
    let parser = UsnParser::new();
    assert_eq!(parser.parser_id(), PARSER_ID);
    assert_eq!(parser.parser_version(), PARSER_VERSION);
    assert_eq!(
        parser.artifact_type(),
        tf_core::event::ArtifactSource::UsnJournal
    );
}

#[test]
fn v2_two_records_emit_two_events() {
    let (summary, sink) = run_parse(&two_v2_records());
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(summary.records_seen, 2);
    assert_eq!(sink.events.len(), 2);
    for e in &sink.events {
        assert_eq!(e.event_type.as_str(), USN_CHANGE_OBSERVED_EVENT_TYPE);
        assert_eq!(e.source, tf_core::event::ArtifactSource::UsnJournal);
        assert_eq!(e.attributes["usn.major_version"], 2);
        assert_eq!(e.attributes["usn.reference_spec"], USN_REFERENCE);
    }
}

#[test]
fn v3_two_records_preserve_128bit_references() {
    // V3 は 128-bit file reference を切り詰めず保持（互換 §4.3）。
    let r1 = build_usn_v3_record(
        [0xAA; 16],
        [0xBB; 16],
        200,
        common::usn_filetime_from_unix_offset(0),
        usn_reason::FILE_CREATE,
        0,
        0,
        0x10,
        "v3file1.txt",
    );
    let r2 = build_usn_v3_record(
        [0xCC; 16],
        [0xBB; 16],
        201,
        common::usn_filetime_from_unix_offset(60),
        usn_reason::FILE_DELETE,
        0,
        0,
        0x10,
        "v3file2.txt",
    );
    let mut bytes = r1;
    bytes.extend(r2);
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(summary.records_seen, 2);
    assert_eq!(sink.events.len(), 2);
    for e in &sink.events {
        assert_eq!(e.attributes["usn.major_version"], 3);
        // 128-bit reference の文字列表現は "v3v4:" + 32 桁 hex。
        let fr = e.attributes["usn.file_reference"].as_str().unwrap();
        assert!(fr.starts_with("v3v4:"));
        assert_eq!(fr.len(), "v3v4:".len() + 32);
    }
}

#[test]
fn v4_records_recognized_without_event() {
    // V4 は filename 無し。record は認識するが filename 欠落で Event 化しない（互換 §5）。
    let r1 = build_usn_v4_record(
        [0xAA; 16],
        [0xBB; 16],
        300,
        common::usn_filetime_from_unix_offset(0),
        usn_reason::DATA_OVERWRITE,
        0,
        0,
        1,
        0x1000,
        4096,
    );
    let (summary, sink) = run_parse(&r1);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(summary.records_seen, 1, "V4 record は認識した");
    assert_eq!(sink.events.len(), 0, "filename 無しで Event 化しない");
}

#[test]
fn rename_pair_combined_into_one_event() {
    let old = build_usn_v2_record(
        0x0001_0000_0000_7777,
        0x0005_0000_0000_0001,
        500,
        common::usn_filetime_from_unix_offset(0),
        usn_reason::RENAME_OLD_NAME,
        0,
        0,
        0x20,
        "old_name.txt",
    );
    let new = build_usn_v2_record(
        0x0001_0000_0000_7777,
        0x0005_0000_0000_0001,
        500,
        common::usn_filetime_from_unix_offset(0),
        usn_reason::RENAME_NEW_NAME,
        0,
        0,
        0x20,
        "new_name.txt",
    );
    let mut bytes = old;
    bytes.extend(new);
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(summary.records_seen, 2);
    assert_eq!(sink.events.len(), 1, "rename は1 Event へ結合");
    let e = &sink.events[0];
    assert_eq!(e.attributes["usn.rename.combined"], true);
    assert_eq!(e.attributes["usn.rename.old_name"], "old_name.txt");
    assert_eq!(e.attributes["usn.rename.new_name"], "new_name.txt");
}

#[test]
fn rename_not_combined_when_usn_far() {
    let old = build_usn_v2_record(
        0x0001_0000_0000_7777,
        0x0005_0000_0000_0001,
        500,
        0,
        usn_reason::RENAME_OLD_NAME,
        0,
        0,
        0x20,
        "old.txt",
    );
    let new = build_usn_v2_record(
        0x0001_0000_0000_7777,
        0x0005_0000_0000_0001,
        600,
        0,
        usn_reason::RENAME_NEW_NAME,
        0,
        0,
        0x20,
        "new.txt",
    );
    let mut bytes = old;
    bytes.extend(new);
    let (_summary, sink) = run_parse(&bytes);
    assert_eq!(sink.events.len(), 2, "USN 差 100 は結合しない");
    for e in &sink.events {
        assert!(!e.attributes.contains_key("usn.rename.combined"));
    }
}

#[test]
fn rename_not_combined_when_file_reference_differs() {
    let old = build_usn_v2_record(
        0x0001_0000_0000_7777,
        0x0005_0000_0000_0001,
        500,
        0,
        usn_reason::RENAME_OLD_NAME,
        0,
        0,
        0x20,
        "old.txt",
    );
    let new = build_usn_v2_record(
        0x0001_0000_0000_8888, // 別の file reference
        0x0005_0000_0000_0001,
        500,
        0,
        usn_reason::RENAME_NEW_NAME,
        0,
        0,
        0x20,
        "new.txt",
    );
    let mut bytes = old;
    bytes.extend(new);
    let (_summary, sink) = run_parse(&bytes);
    assert_eq!(sink.events.len(), 2, "file reference 違いは結合しない");
}

#[test]
fn unknown_major_version_skipped_with_warning() {
    let mut rec = build_usn_v2_record(0x1, 0x5, 1, 0, usn_reason::FILE_CREATE, 0, 0, 0x20, "x.txt");
    rec[4..6].copy_from_slice(&9u16.to_le_bytes()); // 未知 MajorVersion
    let good = build_usn_v2_record(0x2, 0x5, 2, 0, usn_reason::FILE_CREATE, 0, 0, 0x20, "y.txt");
    let mut bytes = rec;
    bytes.extend(good);
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.records_seen, 1, "未知 version は skip して次を処理");
    assert_eq!(sink.events.len(), 1);
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
}

#[test]
fn truncated_stream_does_not_panic() {
    // header だけあって record_length に満たない。
    let mut bytes = vec![0u8; 8];
    bytes[0..4].copy_from_slice(&100u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    bytes.extend(vec![0u8; 22]); // 100 byte 宣言だが 30 byte しかない
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Partial);
    assert!(!sink.issues.is_empty());
}

#[test]
fn corrupt_record_in_middle_preserves_other_events() {
    // 正常 V2 → record_length 3 の不正 record（境界不明）→ 正常 V2。
    // 不正 record は Partial 終了するが、前に読めた正常 record は Event として保持（§9.2・§21-5）。
    let r1 = build_usn_v2_record(
        0x10,
        0x5,
        1,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "first.txt",
    );
    let mut bad = vec![0u8; 8];
    bad[0..4].copy_from_slice(&3u32.to_le_bytes());
    bad[4..6].copy_from_slice(&2u16.to_le_bytes());
    let r2 = build_usn_v2_record(
        0x11,
        0x5,
        2,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "second.txt",
    );
    let mut bytes = r1;
    bytes.extend(bad);
    bytes.extend(r2);
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Partial);
    assert_eq!(
        sink.events.len(),
        1,
        "境界不明になる前の r1 は Event として保持"
    );
}

#[test]
fn path_resolved_from_in_set_parent_mapping() {
    // 同一ストリーム内に親 dir の記録がある → path に親 dir 名を含める（§4.3）。
    let dir = build_usn_v2_record(
        0x50,
        0x05,
        1,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x10, // DIRECTORY attribute
        "Docs",
    );
    let file = build_usn_v2_record(
        0x100,
        0x50,
        2,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "note.txt",
    );
    let mut bytes = dir;
    bytes.extend(file);
    let (_summary, sink) = run_parse(&bytes);
    let file_event = sink
        .events
        .iter()
        .find(|e| e.attributes["usn.file_reference_mft_number"] == 0x100)
        .expect("file event がある");
    let path = file_event.path.as_ref().expect("path が構築された");
    assert!(path.original.contains("Docs"));
    assert!(path.original.contains("note.txt"));
}

#[test]
fn path_not_reconstructed_from_host_when_parent_missing() {
    // 親 dir が同一ストリーム内に無い → 自身の名前のみ（host 検索禁止、§4.3）。
    let file = build_usn_v2_record(
        0x100,
        0x50, // 0x50 はストリーム内に無い
        2,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "note.txt",
    );
    let (_summary, sink) = run_parse(&file);
    let e = &sink.events[0];
    let path = e.path.as_ref().expect("自身の名前で path を構築");
    assert_eq!(path.original, "note.txt");
    assert!(
        !path.original.contains('\\'),
        "親が解決できないとき勝手に親を付けない"
    );
}

#[test]
fn provenance_byte_range_points_to_record_offset() {
    // 互換 §12-3: Provenance が元 record へ到達する。
    let r1 = build_usn_v2_record(
        0x10,
        0x5,
        1,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "first.txt",
    );
    let r2 = build_usn_v2_record(
        0x11,
        0x5,
        2,
        0,
        usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "second.txt",
    );
    let mut bytes = r1.clone();
    bytes.extend(r2.clone());
    let (_summary, sink) = run_parse(&bytes);
    // 2件目の Event の Provenance は r2 の byte 位置へ到達できる。
    let second = sink
        .events
        .iter()
        .find(|e| e.attributes["usn.file_reference_mft_number"] == 0x11)
        .expect("second event がある");
    match &second.provenance.record_locator {
        RecordLocator::ByteRange { start, end } => {
            assert_eq!(*start, r1.len() as u64, "r2 の offset は r1 の直後");
            assert_eq!(*end, (r1.len() + r2.len()) as u64);
        }
        other => panic!("ByteRange 期待だが {other:?}"),
    }
}

#[test]
fn vertical_slice_usn_to_eventstore() {
    // USN → EventStore への sink 出力（M2 と同経路）。
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("usn.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let context = make_context();
    let bytes = two_v2_records();
    let mut cursor = Cursor::new(bytes);
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
    }
    assert_eq!(store.len(), 2);
    store.commit().unwrap();
    assert!(issues.is_empty());
}

#[test]
fn parser_is_deterministic_across_runs() {
    // 互換 §12-4: 同一入力で Event ID が一致する。
    let bytes = two_v2_records();
    let run_once = || -> Vec<String> {
        let (_summary, sink) = run_parse(&bytes);
        let mut ids: Vec<String> = sink.events.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

#[test]
fn reason_unknown_bits_are_recorded_not_silently_dropped() {
    // 互換 §12-7: 非対応要素を黙殺しない。未知 bit は unknown_bits 属性へ。
    let mut bytes = build_usn_v2_record(
        0x1,
        0x5,
        1,
        0,
        usn_reason::FILE_CREATE | 0x0200_0000, // 0x02000000 は未割当 bit
        0,
        0,
        0x20,
        "unk.txt",
    );
    // 既に上書き済み。record_length は正しい。
    let _ = &mut bytes;
    let (_summary, sink) = run_parse(&bytes);
    assert_eq!(sink.events.len(), 1);
    assert_eq!(
        sink.events[0].attributes["usn.reason_unknown_bits"],
        0x0200_0000u64
    );
}
