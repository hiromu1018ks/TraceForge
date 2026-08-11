//! Prefetch Parser の統合テスト（T4-020〜T4-025、互換 §4.1）。
//!
//! 各 version（17/23/26/30/31）の正常 fixture・MAM 圧縮・異常系（truncated・
//! unknown version・過大 offset）を検証する。互換 §12 acceptance 条件の
//! Prefetch 版は `acceptance_tests.rs` へ集約している。

mod common;

use std::io::Cursor;

use tf_core::case::ParseStatus;
use tf_core::event::RecordLocator;
use tf_parsers::framework::{ArtifactParser, ParseContext};
use tf_parsers::prefetch::{
    PARSER_ID, PARSER_VERSION, PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE, PrefetchParser,
    UNSUPPORTED_VERSION_CODE,
};
use tf_parsers::sink::EventStoreSink;
use tf_store::EventStore;

use common::filetime_from_unix_offset;

/// Event・Issue を蓄積する test 用 sink。
struct TestSink {
    events: Vec<tf_core::event::Event>,
    issues: Vec<tf_core::issue::Issue>,
}
impl tf_parsers::ParseSink for TestSink {
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

/// Prefetch 解析を cursor 入力で実行し sink の内容を返す。
fn run_parse(bytes: &[u8]) -> (tf_parsers::ParseSummary, TestSink) {
    let mut cursor = Cursor::new(bytes.to_vec());
    let context = make_context();
    let mut sink = TestSink {
        events: vec![],
        issues: vec![],
    };
    let summary = PrefetchParser::new().parse(&mut cursor, &context, &mut sink);
    (summary, sink)
}

fn make_context() -> ParseContext {
    use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ProbeResult};
    use tf_core::event::ArtifactSource;
    ParseContext {
        evidence: EvidenceItem {
            evidence_id: "tf-evidence-v1:pf-int".to_string(),
            source_locator: "NOTEPAD.EXE-1234ABCD.pf".to_string(),
            size: 300,
            sha256: "cd".repeat(32),
            integrity_status: IntegrityStatus::VerifiedSnapshot,
            parse_eligible: true,
            snapshot_locator: String::new(),
        },
        artifact: ArtifactInstance {
            artifact_id: "tf-artifact-v1:pf-int".to_string(),
            evidence_id: "tf-evidence-v1:pf-int".to_string(),
            artifact_type: ArtifactSource::Prefetch,
            parser_id: PARSER_ID.to_string(),
            parser_version: PARSER_VERSION.to_string(),
            probe_result: ProbeResult::Confirmed,
            detection_reasons: vec!["version+SCCA".to_string()],
            parse_status: ParseStatus::Complete,
        },
    }
}

/// 共通の参照 file 一覧（v17/v23 用）。
fn sample_referenced_files() -> Vec<String> {
    vec![
        "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL".to_string(),
        "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\KERNEL32.DLL".to_string(),
    ]
}

#[test]
fn parse_v17_emits_one_event_per_run_time() {
    let opts = common::PrefetchFixtureOptions {
        version: 17,
        last_run_filetimes: vec![filetime_from_unix_offset(0)],
        run_count: 1,
        referenced_files: sample_referenced_files(),
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (summary, sink) = run_parse(&bytes);

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1, "v17 は1 run time → 1 event");
    let e = &sink.events[0];
    assert_eq!(
        e.event_type.as_str(),
        PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE
    );
    assert_eq!(e.attributes["prefetch.format_version"], 17);
    assert_eq!(e.attributes["prefetch.run_count"], 1);
    assert_eq!(
        e.attributes["prefetch.referenced_file_count"],
        sample_referenced_files().len() as u64
    );
}

#[test]
fn parse_v23_emits_one_event_per_run_time() {
    let opts = common::PrefetchFixtureOptions {
        version: 23,
        last_run_filetimes: vec![filetime_from_unix_offset(100)],
        run_count: 3,
        referenced_files: sample_referenced_files(),
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (summary, sink) = run_parse(&bytes);

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1);
    assert_eq!(sink.events[0].attributes["prefetch.format_version"], 23);
}

#[test]
fn parse_v26_emits_eight_events() {
    let times: Vec<u64> = (0..8).map(filetime_from_unix_offset).collect();
    let opts = common::PrefetchFixtureOptions {
        version: 26,
        last_run_filetimes: times.clone(),
        run_count: 42,
        referenced_files: sample_referenced_files(),
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (summary, sink) = run_parse(&bytes);

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 8, "v26 は8 run time → 8 event");
    // 全 event の run_index は 0..7。
    let indices: Vec<u64> = sink
        .events
        .iter()
        .map(|e| e.attributes["prefetch.run_index"].as_u64().unwrap())
        .collect();
    assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn parse_v30_and_v31_emit_events() {
    for v in [30, 31] {
        let opts = common::PrefetchFixtureOptions {
            version: v,
            last_run_filetimes: vec![filetime_from_unix_offset(0), filetime_from_unix_offset(60)],
            run_count: 2,
            referenced_files: sample_referenced_files(),
            ..Default::default()
        };
        let bytes = common::build_prefetch_fixture(&opts);
        let (summary, sink) = run_parse(&bytes);
        assert_eq!(summary.status, ParseStatus::Complete, "v{v} 完了");
        assert_eq!(sink.events.len(), 2, "v{v} は2 event");
        assert_eq!(sink.events[0].attributes["prefetch.format_version"], v);
    }
}

#[test]
fn parse_no_run_times_emits_single_unknown_event() {
    // run time 未設定・run_count=0 → Unknown time で1 event。
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![],
        run_count: 0,
        referenced_files: vec![],
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (summary, sink) = run_parse(&bytes);

    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1);
    use tf_core::time::TemporalValue;
    assert_eq!(sink.events[0].time.value, TemporalValue::Unknown);
}

#[test]
fn parse_mam_compressed_uses_same_provenance_chain() {
    // 互換 §4.1: 展開後 bytes を別 Evidence と誤認しない。
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![filetime_from_unix_offset(0)],
        run_count: 1,
        referenced_files: sample_referenced_files(),
        ..Default::default()
    };
    let uncompressed = common::build_prefetch_fixture(&opts);
    let mam = common::build_mam_prefetch_fixture(&uncompressed);

    let (summary, sink) = run_parse(&mam);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1);
    let e = &sink.events[0];
    // MAM 圧縮 flag が記録される。
    assert_eq!(e.attributes["prefetch.mam_compressed"], true);
    // Provenance は元 Evidence へ到達する（別 Evidence になっていない）。
    assert_eq!(e.provenance.evidence_id, "tf-evidence-v1:pf-int");
    assert_eq!(e.provenance.parser_id, PARSER_ID);
    // 展開後の内容が正しく読めている。
    assert_eq!(e.attributes["prefetch.format_version"], 31);
    assert_eq!(e.attributes["prefetch.executable"], "NOTEPAD.EXE");
}

#[test]
fn unknown_version_skips_with_specific_issue() {
    let mut bytes = common::build_prefetch_fixture(&common::PrefetchFixtureOptions {
        version: 31,
        ..Default::default()
    });
    // version を 99 へ書き換え。
    bytes[0..4].copy_from_slice(&99u32.to_le_bytes());

    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Skipped);
    assert!(
        sink.issues
            .iter()
            .any(|i| i.issue_id == UNSUPPORTED_VERSION_CODE)
    );
    assert!(sink.events.is_empty());
}

#[test]
fn truncated_header_does_not_panic() {
    let short = vec![0u8; 10];
    let (summary, sink) = run_parse(&short);
    assert_eq!(summary.status, ParseStatus::Skipped);
    assert!(!sink.issues.is_empty());
}

#[test]
fn truncated_file_info_does_not_panic() {
    // header はあるが file info が途中で切れている。
    let mut bytes = common::build_prefetch_fixture(&common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![filetime_from_unix_offset(0)],
        ..Default::default()
    });
    // file info block（84..304）の途中で切断。
    bytes.truncate(PF_HEADER_OFFSET_DURING_FILEINFO);
    let (summary, _sink) = run_parse(&bytes);
    // panic せず何らかの summary が返ること自体が成功の証。
    assert_ne!(summary.status, ParseStatus::Complete);
}

const PF_HEADER_OFFSET_DURING_FILEINFO: usize = common::PF_HEADER_BYTES + 50;

#[test]
fn oversize_metrics_offset_does_not_panic() {
    let mut bytes = common::build_prefetch_fixture(&common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![filetime_from_unix_offset(0)],
        referenced_files: sample_referenced_files(),
        ..Default::default()
    });
    // metrics offset（file info 先頭の4 byte = 絶対 offset 84）を過大値へ。
    let fi_start = common::PF_HEADER_BYTES;
    bytes[fi_start..fi_start + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let (summary, sink) = run_parse(&bytes);
    // run time 由来の event は生成される（metrics は空になるが header は読めている）。
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 1);
    // 参照 file は0件（過大 offset で安全に skip）。
    assert_eq!(
        sink.events[0].attributes["prefetch.referenced_file_count"],
        0
    );
}

#[test]
fn duplicate_run_times_each_become_event() {
    // 重複 run time（互換 §4.1 必須 fixture: 重複 run time）。
    let t = filetime_from_unix_offset(0);
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![t, t, t],
        run_count: 3,
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(sink.events.len(), 3);
    // 各 event の run_index は異なるため、Event ID も異なる。
    let ids: Vec<&str> = sink.events.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids.len(), 3);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn max_run_count_handled() {
    // 最大 run count（互換 §4.1 必須 fixture: 最大 run count）。
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![filetime_from_unix_offset(0)],
        run_count: u32::MAX,
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (summary, sink) = run_parse(&bytes);
    assert_eq!(summary.status, ParseStatus::Complete);
    assert_eq!(
        sink.events[0].attributes["prefetch.run_count"],
        u32::MAX as u64
    );
}

#[test]
fn provenance_record_locator_points_to_run_time_bytes() {
    // 互換 §12-3: Provenance が元 record へ到達する。
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![filetime_from_unix_offset(0)],
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let (_summary, sink) = run_parse(&bytes);

    let e = &sink.events[0];
    // v31 run time[0] は HEADER(84) + 44 = offset 128。
    match &e.provenance.record_locator {
        RecordLocator::ByteRange { start, end } => {
            assert_eq!(*start, 128);
            assert_eq!(*end, 136);
        }
        other => panic!("ByteRange 期待だが {other:?}"),
    }
}

#[test]
fn probe_detects_uncompressed_prefetch() {
    use tf_core::case::{EvidenceItem, IntegrityStatus};
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);
    let dir = tempfile::tempdir().unwrap();
    let (evidence, _snap) = common::make_snapshot("test.pf", &bytes, dir.path());

    let parser = PrefetchParser::new();
    assert_eq!(
        parser.probe(&evidence),
        tf_core::case::ProbeResult::Confirmed
    );

    // snapshot_locator だけ差し替えた検証用 Evidence（integrity 確認）。
    let bad_integrity = EvidenceItem {
        integrity_status: IntegrityStatus::ChangedDuringSnapshot,
        ..evidence
    };
    assert_eq!(
        parser.probe(&bad_integrity),
        tf_core::case::ProbeResult::NotThisFormat
    );
}

#[test]
fn probe_detects_mam_prefetch() {
    let uncompressed = common::build_prefetch_fixture(&common::PrefetchFixtureOptions {
        version: 31,
        ..Default::default()
    });
    let mam = common::build_mam_prefetch_fixture(&uncompressed);
    let dir = tempfile::tempdir().unwrap();
    let (evidence, _) = common::make_snapshot("test.pf", &mam, dir.path());

    let parser = PrefetchParser::new();
    assert_eq!(
        parser.probe(&evidence),
        tf_core::case::ProbeResult::Confirmed
    );
}

#[test]
fn vertical_slice_prefetch_to_eventstore() {
    // Prefetch → EventStore への sink 出力が成功する（M2 と同経路）。
    let opts = common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![filetime_from_unix_offset(0), filetime_from_unix_offset(60)],
        run_count: 2,
        referenced_files: sample_referenced_files(),
        ..Default::default()
    };
    let bytes = common::build_prefetch_fixture(&opts);

    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("pf.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let context = make_context();

    {
        let mut cursor = Cursor::new(bytes);
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = PrefetchParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
    }
    assert_eq!(store.len(), 2);
    store.commit().unwrap();
    assert!(issues.is_empty());
}
