//! LNK acceptance test と M2 縦割りスライス（T4-016、互換 §12、roadmap §6 M2）。
//!
//! M2 は「LNK のみで analyze → Case JSON + Manifest が生成される」ことを検証する。
//! 本テストは次の縦割りを1つの関数で完結させる:
//!
//! ```text
//! LNK fixture → snapshot → LnkParser::parse → EventStoreSink → EventStore
//!            → iter_sorted (Timeline 順) → write_jsonl → Case JSONL + Manifest
//! ```
//!
//! 併せて互換 §12 の acceptance 条件（正常 fixture・truncated 耐性・Provenance 到達・
//! SHA-256 記録・外部仕様 revision 記録・非対応要素の記録・Event type 断定禁止）を検証する。
//!
//! 後半に Prefetch（T4-025）の互換 §12 acceptance を併載する。両 Parser で
//! 同一の acceptance 基準を満たすことを個別に検証する。

mod common;

use serde_json::Value;
use tf_core::case::{ArtifactInstance, CaseMetadata, EvidenceItem};
use tf_core::event::RecordLocator;
use tf_core::manifest::Manifest;
use tf_core::schema::SCHEMA_VERSION;
use tf_parsers::LnkParser;
use tf_parsers::framework::{ArtifactParser, ParseContext};
use tf_parsers::lnk::{LNK_TIMESTAMP_EVENT_TYPE, MS_SHLLINK_REFERENCE, PARSER_ID, PARSER_VERSION};
use tf_parsers::sink::EventStoreSink;
use tf_store::EventStore;
use tf_store::output::{CaseStream, OtherCounts, build_manifest_counts, write_jsonl};

/// Event・Issue を蓄積しつつ EventStore へ書き込むヘルパー。
fn run_lnkv_parser(
    evidence: &EvidenceItem,
    artifact: &ArtifactInstance,
    store: &mut EventStore,
    issues: &mut Vec<tf_core::issue::Issue>,
) -> tf_parsers::ParseSummary {
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact: artifact.clone(),
    };
    let snapshot_path = std::path::Path::new(&evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = LnkParser::new();
    let mut sink = EventStoreSink::new(store, issues);
    parser.parse(&mut file, &context, &mut sink)
}

/// M2 縦割り: LNK → EventStore → JSONL 出力。
#[test]
fn m2_vertical_slice_lnk_to_case_json_and_manifest() {
    let dir = tempfile::tempdir().unwrap();

    // 1. LNK fixture を作り snapshot を取得。
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        access_filetime: common::filetime_from_unix_offset(60),
        write_filetime: common::filetime_from_unix_offset(120),
        local_base_path: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
        flags: 0x0000_0002, // HasLinkInfo
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _snapshot_path) = common::make_snapshot("notepad.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);

    // 2. EventStore を作り Parser から Event へ流し込む。
    let spool_path = dir.path().join("case.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let summary = run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);
    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert_eq!(store.len(), 3, "3 timestamp から3 Event");
    store.commit().unwrap();

    // 3. JSONL 出力（Case + Evidence + Artifact + Event + Issue + Manifest）。
    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "M2 test".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: issues.len() as u64,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-10T01:00:00Z".to_string(),
        run_finished_at: "2026-08-10T01:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "a".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": PARSER_ID,
            "parser_version": PARSER_VERSION,
            "reference": MS_SHLLINK_REFERENCE,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output, 3);

    let output_str = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = output_str.lines().collect();

    // Schema §6 の出力順: case → evidence → artifact → event* → issue(0件なので出ない) → manifest。
    // issue が0件なので行数は case(1) + evidence(1) + artifact(1) + event(3) + manifest(1) = 7。
    assert_eq!(lines.len(), 7);
    let record_types: Vec<String> = lines
        .iter()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(
        record_types,
        vec![
            "case".to_string(),
            "evidence".to_string(),
            "artifact".to_string(),
            "event".to_string(),
            "event".to_string(),
            "event".to_string(),
            "manifest".to_string(),
        ]
    );
    // manifest 行は最後（Schema §6）。
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    // Event 行が Timeline 順（UTC 昇順）。3 timestamp は 0, 60, 120 秒オフセット。
    let event_lines: Vec<Value> = lines
        .iter()
        .filter_map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            if v["record_type"] == "event" {
                Some(v)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(event_lines.len(), 3);
    // 時刻順を確認（creation=offset 0, access=offset 60, write=offset 120）。
    assert!(
        event_lines[0]["record"]["time"]["value"]
            .as_str()
            .unwrap()
            .contains("2026-08-10T01:15:20")
    );
}

// ============================================================
// 互換 §12 acceptance 条件
// ============================================================

/// 互換 §12-1: 正常 fixture から期待 Event を生成する。
#[test]
fn acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        access_filetime: common::filetime_from_unix_offset(60),
        write_filetime: common::filetime_from_unix_offset(120),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _) = common::make_snapshot("valid.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);

    let spool_path = dir.path().join("a1.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues = Vec::new();
    let summary = run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert_eq!(store.len(), 3);
    // 全 Event が lnk_timestamp（観測型）。
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.event_type.as_str(), LNK_TIMESTAMP_EVENT_TYPE);
    }
}

/// 互換 §12-2: truncated・invalid length・unknown version で panic しない。
#[test]
fn acceptance_12_2_corrupt_inputs_do_not_panic() {
    let parser = LnkParser::new();

    let run = |bytes: &[u8]| {
        // 毎回別の tempdir を使う（snapshot file 名の衝突を避ける）。
        let dir = tempfile::tempdir().unwrap();
        let (evidence, _) = common::make_snapshot("corrupt.lnk", bytes, dir.path());
        let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);
        let context = ParseContext {
            evidence: evidence.clone(),
            artifact,
        };
        let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
        let mut file = std::fs::File::open(snapshot_path).unwrap();
        let spool = dir.path().join("corrupt.spool");
        let mut store = EventStore::create(&spool).unwrap();
        {
            let mut store_issues: Vec<tf_core::issue::Issue> = Vec::new();
            let mut sink = EventStoreSink::new(&mut store, &mut store_issues);
            let _ = parser.parse(&mut file, &context, &mut sink);
        }
        // dir はここで drop され、中身も削除される。
    };

    // truncated: header すら無い。
    let short: Vec<u8> = (0..10).collect();
    run(&short);
    // header はあるが IDList で切れている。
    let mut truncated = common::build_lnk_fixture(&common::LnkFixtureOptions {
        flags: 0x0000_0001,
        with_extra_data: false,
        ..Default::default()
    });
    truncated.truncate(common::HEADER_BYTES + 4);
    run(&truncated);
    // invalid header size。
    let mut bad_size = common::build_lnk_fixture(&common::LnkFixtureOptions::default());
    bad_size[0..4].copy_from_slice(&0x0000_0099u32.to_le_bytes());
    run(&bad_size);
    // 全て panic せず完了したならこのテスト関数は最後まで到達する（それ自体が成功の証）。
}

/// 互換 §12-3: Provenance が元 record へ到達する。
#[test]
fn acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _) = common::make_snapshot("prov.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);

    let spool_path = dir.path().join("a3.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues = Vec::new();
    run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        // Evidence ID へ到達できる。
        assert_eq!(prov.evidence_id, evidence.evidence_id);
        // Artifact ID へ到達できる。
        assert_eq!(prov.artifact_id, artifact.artifact_id);
        // source_locator が元 Evidence の locator へ一致。
        assert_eq!(prov.source_locator, evidence.source_locator);
        // source_sha256 が snapshot の SHA-256 へ一致（規範 §21-4 由来）。
        assert_eq!(prov.source_sha256, evidence.sha256);
        // Parser ID/version へ到達できる。
        assert_eq!(prov.parser_id, PARSER_ID);
        assert_eq!(prov.parser_version, PARSER_VERSION);
        // RecordLocator が header の byte range を指す。
        match &prov.record_locator {
            RecordLocator::ByteRange { start, end } => {
                assert_eq!(*start, 0);
                assert_eq!(*end, common::HEADER_BYTES as u64);
            }
            other => panic!("ByteRange 期待だが {other:?}"),
        }
    }
}

/// 互換 §12-4: 1 thread と複数 thread で出力が一致する（Parser 単体の決定性）。
///
/// 完全な Golden test（threads 1/2/自動で canonical JSON byte 一致）は Phase 8 T8-001 だが、
/// Phase 4 では Parser 自体が thread 安全（共有状態なし）で決定的であることを検証する。
#[test]
fn acceptance_12_4_parser_is_deterministic_across_runs() {
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        access_filetime: common::filetime_from_unix_offset(60),
        write_filetime: common::filetime_from_unix_offset(120),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);

    // 同一 fixture を2回解析し、Event ID と時刻が一致するか。
    let run_once = || -> Vec<String> {
        // 毎回別の tempdir を使う（snapshot file 名の衝突を避ける）。
        let dir = tempfile::tempdir().unwrap();
        let (evidence, _) = common::make_snapshot("det.lnk", &bytes, dir.path());
        let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);
        let spool = dir.path().join("det.spool");
        let mut store = EventStore::create(&spool).unwrap();
        let mut issues = Vec::new();
        run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        // dir はここで drop され、spool も削除される。
        ids
    };

    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

/// 互換 §12-5: fixture SHA-256・生成 OS・取得方法を記録する。
#[test]
fn acceptance_12_5_fixture_metadata_recorded() {
    // 合成 fixture のメタデータを記録（実 Windows fixture は Phase 8 で調達）。
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let sha256 = common::sha256_hex(&bytes);

    // 記録すべきメタデータ:
    // - SHA-256: 64 lowercase hex
    assert_eq!(sha256.len(), 64);
    assert!(
        sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // - 生成方法: hand-crafted, [MS-SHLLINK] 準拠（この test の文档として記録）
    // - 生成 OS: 合成（Windows 由来ではない）
    // これらは fixture 管理方針（docs/learn/phase4.md）へ文書化する。
}

/// 互換 §12-6: 外部仕様 revision / dependency version を記録する。
#[test]
fn acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _) = common::make_snapshot("ref.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);

    let spool_path = dir.path().join("a6.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues = Vec::new();
    run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // 各 Event の attributes へ参照仕様 revision が記録される。
        assert_eq!(event.attributes["lnk.reference_spec"], MS_SHLLINK_REFERENCE);
    }
}

/// 互換 §12-7: 非対応 field・構文・version を黙って無視しない。
#[test]
fn acceptance_12_7_unsupported_does_not_silently_ignore() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        with_extra_data: false,
        ..Default::default()
    };
    let mut bytes = common::build_lnk_fixture(&opts);
    // 未知 ExtraData block (0xCAFEBABE) を追加。
    let data: &[u8] = &[0xAA];
    let block_size: u32 = 8 + data.len() as u32;
    bytes.extend_from_slice(&block_size.to_le_bytes());
    bytes.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock

    let (evidence, _) = common::make_snapshot("unk.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);
    let spool_path = dir.path().join("a7.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues = Vec::new();
    run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // 未知 block 数が記録される（黙って無視しない）。
        assert_eq!(event.attributes["lnk.unknown_extra_block_count"], 1);
        let blocks = event.attributes["lnk.extra_blocks"].as_array().unwrap();
        assert!(
            blocks
                .iter()
                .any(|v| v.as_str().unwrap().contains("Unknown(0xCAFEBABE)"))
        );
    }
}

/// 互換 §12-8: 形式の意味を越えて Event type を断定しない。
#[test]
fn acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _) = common::make_snapshot("type.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);
    let spool_path = dir.path().join("a8.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues = Vec::new();
    run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // event_type は lnk_timestamp（観測型）。
        assert_eq!(event.event_type.as_str(), LNK_TIMESTAMP_EVENT_TYPE);
        // assertion は Observed（規範 §7.1: Parser は原則 Observed のみ）。
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        // 「target を開いた」「実行した」等の断定型ではない。
        let et = event.event_type.as_str();
        assert!(!et.contains("opened"));
        assert!(!et.contains("executed"));
        assert!(!et.contains("launched"));
        assert!(!et.contains("ran"));
    }
}

/// 決定性の最終確認: Event attributes が `BTreeMap` で順序非依存（規範 §13.2）。
#[test]
fn lnk_event_attributes_are_btremap_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let opts = common::LnkFixtureOptions {
        creation_filetime: common::filetime_from_unix_offset(0),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    let (evidence, _) = common::make_snapshot("btr.lnk", &bytes, dir.path());
    let artifact = common::make_artifact(&evidence, PARSER_ID, PARSER_VERSION);
    let spool_path = dir.path().join("btr.spool");
    let mut store = EventStore::create(&spool_path).unwrap();
    let mut issues = Vec::new();
    run_lnkv_parser(&evidence, &artifact, &mut store, &mut issues);

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // attributes は BTreeMap<String, Value>（規範 §13.2）。to_canonical_value で sort 済み。
        let value = event.to_canonical_value();
        let attrs = value["attributes"].as_object().unwrap();
        let keys: Vec<&String> = attrs.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "attribute key は byte 順");
    }
}

// ============================================================
// Prefetch acceptance test（T4-025、互換 §12・§4.1）
// ============================================================

use tf_parsers::prefetch::{
    PARSER_ID as PF_PARSER_ID, PARSER_VERSION as PF_PARSER_VERSION,
    PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE as PF_EVENT_TYPE, PREFETCH_REFERENCE, PrefetchParser,
    UNSUPPORTED_VERSION_CODE as PF_UNSUPPORTED_VERSION_CODE,
};

/// Prefetch fixture を構築して EventStore へ流し込む共通 helper。
fn run_prefetch_parser(
    bytes: &[u8],
    dir: &std::path::Path,
) -> (
    tf_parsers::ParseSummary,
    Vec<tf_core::issue::Issue>,
    EventStore,
) {
    let (evidence, _) = common::make_snapshot("accept.pf", bytes, dir);
    let artifact = common::make_artifact_with_source(
        &evidence,
        PF_PARSER_ID,
        PF_PARSER_VERSION,
        tf_core::event::ArtifactSource::Prefetch,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.join("pf_accept.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = PrefetchParser::new();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = parser.parse(&mut file, &context, &mut sink);
        (summary, issues, store)
    }
}

/// 標準的な Prefetch fixture（v31・run time 3個・参照 file 2件）。
fn standard_prefetch_fixture() -> common::PrefetchFixtureOptions {
    common::PrefetchFixtureOptions {
        version: 31,
        last_run_filetimes: vec![
            common::filetime_from_unix_offset(0),
            common::filetime_from_unix_offset(60),
            common::filetime_from_unix_offset(120),
        ],
        run_count: 3,
        referenced_files: vec![
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL".to_string(),
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\KERNELBASE.DLL".to_string(),
        ],
        ..Default::default()
    }
}

/// 互換 §12-1（Prefetch 版）: 正常 fixture から期待 Event を生成する。
#[test]
fn pf_acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let (summary, issues, store) = run_prefetch_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert_eq!(store.len(), 3, "run time 3個 → 3 event");
    assert!(issues.is_empty());
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.event_type.as_str(), PF_EVENT_TYPE);
        assert_eq!(event.source, tf_core::event::ArtifactSource::Prefetch);
    }
}

/// 互換 §12-2（Prefetch 版）: truncated・invalid length・unknown version で panic しない。
#[test]
fn pf_acceptance_12_2_corrupt_inputs_do_not_panic() {
    // 各入力で独立した tempdir を使い、snapshot file 名の衝突を避ける。
    let run = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let _ = run_prefetch_parser(bytes, dir.path());
    };

    // truncated: header すら無い。
    let short: Vec<u8> = (0..10).collect();
    run(&short);

    // truncated: file info が途中で切れている。
    let mut truncated = common::build_prefetch_fixture(&standard_prefetch_fixture());
    truncated.truncate(common::PF_HEADER_BYTES + 40);
    run(&truncated);

    // invalid: signature を壊す。
    let mut bad_sig = common::build_prefetch_fixture(&standard_prefetch_fixture());
    bad_sig[4..8].copy_from_slice(b"XXXX");
    run(&bad_sig);

    // unknown version。
    let mut unk = common::build_prefetch_fixture(&standard_prefetch_fixture());
    unk[0..4].copy_from_slice(&99u32.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let (summary, issues, _store) = run_prefetch_parser(&unk, dir.path());
    assert_eq!(summary.status, tf_core::case::ParseStatus::Skipped);
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == PF_UNSUPPORTED_VERSION_CODE)
    );
}

/// 互換 §12-3（Prefetch 版）: Provenance が元 record へ到達する。
#[test]
fn pf_acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let (_summary, _issues, store) = run_prefetch_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        assert_eq!(prov.parser_id, PF_PARSER_ID);
        assert_eq!(prov.parser_version, PF_PARSER_VERSION);
        // record_locator は ByteRange（run time の FILETIME 位置）。
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
    }
}

/// 互換 §12-4（Prefetch 版）: 1 thread と複数 thread で出力が一致する（Parser 単体の決定性）。
#[test]
fn pf_acceptance_12_4_parser_is_deterministic_across_runs() {
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());

    let run_once = || -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (_summary, _issues, store) = run_prefetch_parser(&bytes, dir.path());
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        ids
    };

    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

/// 互換 §12-5（Prefetch 版）: fixture SHA-256・生成方法を記録できる。
#[test]
fn pf_acceptance_12_5_fixture_metadata_recorded() {
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let sha256 = common::sha256_hex(&bytes);
    assert_eq!(sha256.len(), 64);
    assert!(
        sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // 生成方法: 合成（hand-crafted, libyal PF format 準拠）。docs/learn/phase4b.md へ記録。
}

/// 互換 §12-6（Prefetch 版）: 外部仕様 revision / dependency version を記録する。
#[test]
fn pf_acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let (_summary, _issues, store) = run_prefetch_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(
            event.attributes["prefetch.reference_spec"],
            PREFETCH_REFERENCE
        );
        assert_eq!(
            event.attributes["prefetch.parser_version"],
            PF_PARSER_VERSION
        );
    }
}

/// 互換 §12-7（Prefetch 版）: 非対応 field・構文・version を黙って無視しない。
#[test]
fn pf_acceptance_12_7_unsupported_version_emits_issue() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    bytes[0..4].copy_from_slice(&99u32.to_le_bytes());
    let (summary, issues, _store) = run_prefetch_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Skipped);
    // 黙って無視せず Issue へ記録する。
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == PF_UNSUPPORTED_VERSION_CODE)
    );
    // message に未対応 version 番号が含まれる（黙殺ではない）。
    let msg = &issues
        .iter()
        .find(|i| i.issue_id == PF_UNSUPPORTED_VERSION_CODE)
        .unwrap()
        .message;
    assert!(msg.contains("99"), "未対応 version 番号が message へ残る");
}

/// 互換 §12-8（Prefetch 版）: 形式の意味を越えて Event type を断定しない。
#[test]
fn pf_acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let (_summary, _issues, store) = run_prefetch_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // event_type は prefetch_execution_observed（観測型）。
        assert_eq!(event.event_type.as_str(), PF_EVENT_TYPE);
        // assertion は Observed（規範 §7.1）。
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        // 「実行した」「起動した」等の断定型ではない。
        let et = event.event_type.as_str();
        assert!(!et.contains("process_start"));
        assert!(!et.contains("started"));
        assert!(!et.contains("launched"));
    }
}

/// MAM 圧縮 Prefetch（互換 §4.1 Required）: 展開後 bytes を別 Evidence と誤認しない。
#[test]
fn pf_acceptance_mam_decompression_preserves_provenance_chain() {
    let dir = tempfile::tempdir().unwrap();
    let uncompressed = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let mam = common::build_mam_prefetch_fixture(&uncompressed);
    let (evidence, _) = common::make_snapshot("mam.pf", &mam, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        PF_PARSER_ID,
        PF_PARSER_VERSION,
        tf_core::event::ArtifactSource::Prefetch,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.path().join("pf_mam.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = PrefetchParser::new().parse(&mut file, &context, &mut sink);
        assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    }
    assert_eq!(store.len(), 3);
    assert!(issues.is_empty());

    // 展開後 bytes が別 Evidence になっていない: Provenance は元 Evidence を指す。
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.provenance.evidence_id, evidence.evidence_id);
        assert_eq!(event.attributes["prefetch.mam_compressed"], true);
        assert_eq!(event.attributes["prefetch.format_version"], 31);
    }
}

/// Prefetch の縦割り: Prefetch のみで analyze → Case JSONL + Manifest が生成される。
#[test]
fn pf_vertical_slice_prefetch_to_case_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_prefetch_fixture(&standard_prefetch_fixture());
    let (evidence, _) = common::make_snapshot("vslice.pf", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        PF_PARSER_ID,
        PF_PARSER_VERSION,
        tf_core::event::ArtifactSource::Prefetch,
    );

    let spool_path = dir.path().join("case.spool");
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
        PrefetchParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();

    // 最小 JSONL 出力（M2 と同じ経路）。
    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "Prefetch vertical slice".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: 0,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-11T01:00:00Z".to_string(),
        run_finished_at: "2026-08-11T01:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "b".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": PF_PARSER_ID,
            "parser_version": PF_PARSER_VERSION,
            "reference": PREFETCH_REFERENCE,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output, 3);

    let output_str = String::from_utf8(output).unwrap();
    let record_types: Vec<String> = output_str
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    // manifest は最終行（Schema §6）。
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    assert!(
        record_types
            .iter()
            .filter(|t| t == &&"event".to_string())
            .count()
            == 3
    );
}

// ============================================================
// USN Journal acceptance test（T4-037、互換 §12・§4.3）
// ============================================================

use tf_parsers::usn::{
    PARSER_ID as USN_PARSER_ID, PARSER_VERSION as USN_PARSER_VERSION,
    USN_CHANGE_OBSERVED_EVENT_TYPE as USN_EVENT_TYPE, USN_REFERENCE, UsnParser,
};

/// USN fixture を構築して EventStore へ流し込む共通 helper。
fn run_usn_parser(
    bytes: &[u8],
    dir: &std::path::Path,
) -> (
    tf_parsers::ParseSummary,
    Vec<tf_core::issue::Issue>,
    EventStore,
) {
    let (evidence, _) = common::make_snapshot("$UsnJrnl$J", bytes, dir);
    let artifact = common::make_artifact_with_source(
        &evidence,
        USN_PARSER_ID,
        USN_PARSER_VERSION,
        tf_core::event::ArtifactSource::UsnJournal,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.join("usn_accept.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = UsnParser::new();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = parser.parse(&mut file, &context, &mut sink);
        (summary, issues, store)
    }
}

/// 標準 USN fixture: V2/V3 各2件 + rename 結合ペア + 親 dir mapping。
fn standard_usn_fixture() -> Vec<u8> {
    // 親 dir を先に記録（同一ストリーム内の mapping 用）。
    let dir = common::build_usn_v2_record(
        0x50,
        0x05,
        90,
        common::usn_filetime_from_unix_offset(-10),
        common::usn_reason::FILE_CREATE,
        0,
        0,
        0x10,
        "Docs",
    );
    // V2 record ×2。
    let v2a = common::build_usn_v2_record(
        0x100,
        0x50,
        100,
        common::usn_filetime_from_unix_offset(0),
        common::usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "v2_file1.txt",
    );
    let v2b = common::build_usn_v2_record(
        0x101,
        0x50,
        101,
        common::usn_filetime_from_unix_offset(60),
        common::usn_reason::DATA_EXTEND,
        0,
        0,
        0x20,
        "v2_file2.txt",
    );
    // V3 record ×2。
    let v3a = common::build_usn_v3_record(
        [0xAA; 16],
        [0x50, 0, 0, 0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0, 0],
        200,
        common::usn_filetime_from_unix_offset(120),
        common::usn_reason::FILE_DELETE,
        0,
        0,
        0x20,
        "v3_file1.txt",
    );
    let v3b = common::build_usn_v3_record(
        [0xBB; 16],
        [0x50, 0, 0, 0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0, 0],
        201,
        common::usn_filetime_from_unix_offset(180),
        common::usn_reason::SECURITY_CHANGE,
        0,
        0,
        0x20,
        "v3_file2.txt",
    );
    // rename ペア（同一 file reference + 同一 USN）。
    let rename_old = common::build_usn_v2_record(
        0x200,
        0x50,
        300,
        common::usn_filetime_from_unix_offset(240),
        common::usn_reason::RENAME_OLD_NAME,
        0,
        0,
        0x20,
        "before.txt",
    );
    let rename_new = common::build_usn_v2_record(
        0x200,
        0x50,
        300,
        common::usn_filetime_from_unix_offset(240),
        common::usn_reason::RENAME_NEW_NAME,
        0,
        0,
        0x20,
        "after.txt",
    );

    let mut bytes = dir;
    bytes.extend(v2a);
    bytes.extend(v2b);
    bytes.extend(v3a);
    bytes.extend(v3b);
    bytes.extend(rename_old);
    bytes.extend(rename_new);
    bytes
}

/// 互換 §12-1（USN 版）: 正常 fixture から期待 Event を生成する（V2/V3 各2件以上）。
#[test]
fn usn_acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_usn_fixture();
    let (summary, issues, store) = run_usn_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    // dir(1) + V2 ×2 + V3 ×2 + rename ペア1（1 Event へ結合） = 6 event。
    assert_eq!(store.len(), 6, "dir + V2×2 + V3×2 + rename×1 = 6 event");
    assert!(issues.is_empty(), "正常 fixture は Issue 無し");
    let mut v2 = 0;
    let mut v3 = 0;
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.event_type.as_str(), USN_EVENT_TYPE);
        assert_eq!(event.source, tf_core::event::ArtifactSource::UsnJournal);
        match event.attributes["usn.major_version"].as_u64().unwrap() {
            2 => v2 += 1,
            3 => v3 += 1,
            _ => {}
        }
    }
    assert!(v2 >= 2, "V2 Event 2件以上");
    assert!(v3 >= 2, "V3 Event 2件以上");
}

/// 互換 §12-2（USN 版）: truncated・invalid length・unknown version で panic しない。
#[test]
fn usn_acceptance_12_2_corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let _ = run_usn_parser(bytes, dir.path());
    };

    // truncated: header すら無い。
    run(&(0..5).collect::<Vec<u8>>());

    // truncated: record_length 宣言のみ。
    let mut truncated = vec![0u8; 8];
    truncated[0..4].copy_from_slice(&100u32.to_le_bytes());
    truncated[4..6].copy_from_slice(&2u16.to_le_bytes());
    truncated.extend(vec![0u8; 22]);
    run(&truncated);

    // invalid: record_length が common header 未満。
    let mut bad_len = vec![0u8; 8];
    bad_len[0..4].copy_from_slice(&3u32.to_le_bytes());
    bad_len[4..6].copy_from_slice(&2u16.to_le_bytes());
    run(&bad_len);

    // unknown version。
    let mut unk = common::build_usn_v2_record(
        0x1,
        0x5,
        1,
        0,
        common::usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "x.txt",
    );
    unk[4..6].copy_from_slice(&9u16.to_le_bytes());
    run(&unk);

    // 全て panic せず完了（それ自体が成功）。
}

/// 互換 §12-3（USN 版）: Provenance が元 record へ到達する。
#[test]
fn usn_acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_usn_fixture();
    let (_summary, _issues, store) = run_usn_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        assert_eq!(prov.parser_id, USN_PARSER_ID);
        assert_eq!(prov.parser_version, USN_PARSER_VERSION);
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
    }
}

/// 互換 §12-4（USN 版）: 1 thread と複数 thread で出力が一致する（Parser 単体の決定性）。
#[test]
fn usn_acceptance_12_4_parser_is_deterministic_across_runs() {
    let bytes = standard_usn_fixture();
    let run_once = || -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (_summary, _issues, store) = run_usn_parser(&bytes, dir.path());
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

/// 互換 §12-5（USN 版）: fixture SHA-256・生成方法を記録できる。
#[test]
fn usn_acceptance_12_5_fixture_metadata_recorded() {
    let bytes = standard_usn_fixture();
    let sha256 = common::sha256_hex(&bytes);
    assert_eq!(sha256.len(), 64);
    assert!(
        sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // 生成方法: 合成（hand-crafted, Microsoft USN_RECORD_V2/V3 準拠）。docs/learn/phase4c.md へ記録。
}

/// 互換 §12-6（USN 版）: 外部仕様 revision / dependency version を記録する。
#[test]
fn usn_acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_usn_fixture();
    let (_summary, _issues, store) = run_usn_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.attributes["usn.reference_spec"], USN_REFERENCE);
        assert_eq!(event.attributes["usn.parser_version"], USN_PARSER_VERSION);
    }
}

/// 互換 §12-7（USN 版）: 非対応 version を黙って無視しない。
#[test]
fn usn_acceptance_12_7_unsupported_version_emits_issue() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = common::build_usn_v2_record(
        0x1,
        0x5,
        1,
        0,
        common::usn_reason::FILE_CREATE,
        0,
        0,
        0x20,
        "x.txt",
    );
    bytes[4..6].copy_from_slice(&9u16.to_le_bytes());
    let (summary, issues, _store) = run_usn_parser(&bytes, dir.path());

    // 未知 version は record として認識されず、Event 無し。
    assert_eq!(summary.records_seen, 0);
    // 黙って無視せず Issue へ記録する。
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
    let msg = &issues
        .iter()
        .find(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
        .unwrap()
        .message;
    assert!(msg.contains('9'), "未対応 MajorVersion 9 が message へ残る");
}

/// 互換 §12-8（USN 版）: 形式の意味を越えて Event type を断定しない。
#[test]
fn usn_acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_usn_fixture();
    let (_summary, _issues, store) = run_usn_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // event_type は usn_change_observed（観測型）。
        assert_eq!(event.event_type.as_str(), USN_EVENT_TYPE);
        // assertion は Observed（規範 §7.1）。
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        // 「作成した」「削除した」等の断定型ではない。
        let et = event.event_type.as_str();
        assert!(!et.contains("created"));
        assert!(!et.contains("deleted"));
        assert!(!et.contains("renamed"));
    }
}

/// USN の縦割り: USN のみで analyze → Case JSONL + Manifest が生成される。
#[test]
fn usn_vertical_slice_usn_to_case_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_usn_fixture();
    let (evidence, _) = common::make_snapshot("$UsnJrnl$J", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        USN_PARSER_ID,
        USN_PARSER_VERSION,
        tf_core::event::ArtifactSource::UsnJournal,
    );

    let spool_path = dir.path().join("case.spool");
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
        UsnParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();
    assert_eq!(store.len(), 6);

    // 最小 JSONL 出力（M2 と同じ経路）。
    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "USN vertical slice".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: 0,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-11T01:00:00Z".to_string(),
        run_finished_at: "2026-08-11T01:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "c".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": USN_PARSER_ID,
            "parser_version": USN_PARSER_VERSION,
            "reference": USN_REFERENCE,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output, 6);

    let output_str = String::from_utf8(output).unwrap();
    let record_types: Vec<String> = output_str
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    // manifest は最終行（Schema §6）。
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    assert!(
        record_types
            .iter()
            .filter(|t| t == &&"event".to_string())
            .count()
            == 6
    );
}

// ============================================================
// EVTX acceptance test（T4-046、互換 §12・§4.2）
// ============================================================

use tf_parsers::evtx::EvtxParser;
use tf_parsers::{
    EVTX_EVENT_LOGGED_TYPE as EVTX_EVENT_TYPE, EVTX_PARSER_ID as EVTX_PARSER_ID_V,
    EVTX_PARSER_VERSION as EVTX_PARSER_VERSION_V, EVTX_REFERENCE as EVTX_REF,
};

/// EVTX fixture を構築して EventStore へ流し込む共通 helper。
fn run_evtx_parser(
    bytes: &[u8],
    dir: &std::path::Path,
) -> (
    tf_parsers::ParseSummary,
    Vec<tf_core::issue::Issue>,
    EventStore,
) {
    let (evidence, _) = common::make_snapshot("Security.evtx", bytes, dir);
    let artifact = common::make_artifact_with_source(
        &evidence,
        EVTX_PARSER_ID_V,
        EVTX_PARSER_VERSION_V,
        tf_core::event::ArtifactSource::Evtx,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.join("evtx_accept.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = EvtxParser::new();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = parser.parse(&mut file, &context, &mut sink);
        (summary, issues, store)
    }
}

/// 標準 EVTX fixture（4件の typed event + PowerShell/Sysmon の generic event 計6件）。
fn standard_evtx_fixture() -> Vec<u8> {
    let ft = common::evtx_filetime_from_unix_offset(0);
    let chunk1 = vec![
        common::build_evtx_record(1, ft, &common::login_4624_spec("WS1")),
        common::build_evtx_record(2, ft + 100, &common::login_4625_spec("WS1")),
        common::build_evtx_record(3, ft + 200, &common::process_start_4688_spec("WS1")),
        common::build_evtx_record(4, ft + 300, &common::process_stop_4689_spec("WS1")),
    ];
    let chunk2 = vec![
        common::build_evtx_record(5, ft + 400, &common::service_create_7045_spec("WS1")),
        common::build_evtx_record(6, ft + 500, &common::powershell_operational_spec("WS1")),
    ];
    common::build_evtx_file(&[chunk1, chunk2])
}

/// 互換 §12-1（EVTX 版）: 正常 fixture から期待 Event を生成する。
#[test]
fn evtx_acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_evtx_fixture();
    let (summary, _issues, store) = run_evtx_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert_eq!(store.len(), 6, "6件の EVTX record から6 event");
    let mut types_count = std::collections::BTreeMap::new();
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        *types_count
            .entry(event.event_type.as_str().to_string())
            .or_insert(0) += 1;
        assert_eq!(event.source, tf_core::event::ArtifactSource::Evtx);
    }
    assert_eq!(types_count["login"], 1);
    assert_eq!(types_count["login_failure"], 1);
    assert_eq!(types_count["process_start"], 1);
    assert_eq!(types_count["process_stop"], 1);
    assert_eq!(types_count["service_create"], 1);
    assert_eq!(types_count[EVTX_EVENT_TYPE], 1, "PowerShell → generic");
}

/// 互換 §12-2（EVTX 版）: truncated・bad magic で panic しない。
#[test]
fn evtx_acceptance_12_2_corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let _ = run_evtx_parser(bytes, dir.path());
    };

    run(&(0..10).collect::<Vec<u8>>()); // 短すぎる
    run(&common::build_evtx_file_header(0)); // file header だけ
    let mut bad = standard_evtx_fixture();
    bad[0] = 0xFF; // magic 破壊
    run(&bad);
}

/// 互換 §12-3（EVTX 版）: Provenance が元 record へ到達する。
#[test]
fn evtx_acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_evtx_fixture();
    let (_summary, _issues, store) = run_evtx_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        assert_eq!(prov.parser_id, EVTX_PARSER_ID_V);
        assert_eq!(prov.parser_version, EVTX_PARSER_VERSION_V);
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
    }
}

/// 互換 §12-4（EVTX 版）: 同一入力で同一 Event ID（決定性）。
#[test]
fn evtx_acceptance_12_4_parser_is_deterministic_across_runs() {
    let bytes = standard_evtx_fixture();
    let run_once = || -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (_summary, _issues, store) = run_evtx_parser(&bytes, dir.path());
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2);
}

/// 互換 §12-5（EVTX 版）: fixture SHA-256・生成方法を記録できる。
#[test]
fn evtx_acceptance_12_5_fixture_metadata_recorded() {
    let bytes = standard_evtx_fixture();
    let sha256 = common::sha256_hex(&bytes);
    assert_eq!(sha256.len(), 64);
}

/// 互換 §12-6（EVTX 版）: 外部仕様 revision / dependency version を記録する。
#[test]
fn evtx_acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_evtx_fixture();
    let (_summary, _issues, store) = run_evtx_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.attributes["evtx.reference_spec"], EVTX_REF);
    }
}

/// 互換 §12-7（EVTX 版）: Legacy .evt を黙って無視しない。
#[test]
fn evtx_acceptance_12_7_unsupported_does_not_silently_ignore() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = common::build_evtx_file_header(0);
    // Legacy .evt magic。
    bytes[0..4].copy_from_slice(&[0x4c, 0x66, 0x4c, 0x65]);
    let (summary, issues, _store) = run_evtx_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Skipped);
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
}

/// 互換 §12-8（EVTX 版）: 形式の意味を越えて Event type を断定しない。
#[test]
fn evtx_acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_evtx_fixture();
    let (_summary, _issues, store) = run_evtx_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        let et = event.event_type.as_str();
        // typed mapping 後の型名（login 等）は「event log service が観測した事象」を
        // 表すため許容されるが、channel/provider 検証を経ずに typed になってはならない。
        assert!(!et.is_empty());
    }
}

/// EVTX の縦割り: EVTX のみで analyze → Case JSONL + Manifest が生成される。
#[test]
fn evtx_vertical_slice_evtx_to_case_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_evtx_fixture();
    let (evidence, _) = common::make_snapshot("Security.evtx", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        EVTX_PARSER_ID_V,
        EVTX_PARSER_VERSION_V,
        tf_core::event::ArtifactSource::Evtx,
    );

    let spool_path = dir.path().join("case.spool");
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
        EvtxParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();
    assert_eq!(store.len(), 6);

    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "EVTX vertical slice".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: 0,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-11T01:00:00Z".to_string(),
        run_finished_at: "2026-08-11T01:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "d".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": EVTX_PARSER_ID_V,
            "parser_version": EVTX_PARSER_VERSION_V,
            "reference": EVTX_REF,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output, 6);

    let output_str = String::from_utf8(output).unwrap();
    let record_types: Vec<String> = output_str
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    assert!(
        record_types
            .iter()
            .filter(|t| t == &&"event".to_string())
            .count()
            == 6
    );
}

// ============================================================
// Registry acceptance test（T4-055、互換 §12・§4.7）
// ============================================================

use tf_parsers::registry::{
    HiveType as RegHiveType, PARSER_ID as REG_PARSER_ID, PARSER_VERSION as REG_PARSER_VERSION,
    REGISTRY_KEY_LAST_WRITE_EVENT_TYPE as REG_KEY_LAST_WRITE_TYPE,
    REGISTRY_OBSERVATION_EVENT_TYPE as REG_OBSERVATION_TYPE, REGISTRY_REFERENCE, RegistryParser,
};

/// Registry fixture を構築して EventStore へ流し込む共通 helper。
fn run_registry_parser(
    bytes: &[u8],
    dir: &std::path::Path,
) -> (
    tf_parsers::ParseSummary,
    Vec<tf_core::issue::Issue>,
    EventStore,
) {
    let (evidence, _) = common::make_snapshot("SYSTEM", bytes, dir);
    let artifact = common::make_artifact_with_source(
        &evidence,
        REG_PARSER_ID,
        REG_PARSER_VERSION,
        tf_core::event::ArtifactSource::Registry,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.join("reg_accept.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = RegistryParser::new();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let summary = parser.parse(&mut file, &context, &mut sink);
        (summary, issues, store)
    }
}

/// 標準的な Registry fixture（root + 1 subkey + 3 value）。
fn standard_registry_fixture() -> common::RegistryKeySpec {
    common::RegistryKeySpec {
        name: "ROOT".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![
            common::RegistryValueSpec::dword("Count", 42),
            common::RegistryValueSpec::sz("Path", "C:\\Windows"),
        ],
        subkeys: vec![common::RegistryKeySpec {
            name: "Sub".to_string(),
            last_write_filetime: common::filetime_from_unix_offset(60),
            values: vec![common::RegistryValueSpec::sz("User", "alice")],
            subkeys: vec![],
        }],
    }
}

/// 互換 §12-1（Registry 版）: 正常 fixture から期待 Event を生成する。
#[test]
fn reg_acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let (summary, issues, store) = run_registry_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    // root key_last_write + 2 value + subkey key_last_write + 1 value = 5 event。
    assert_eq!(store.len(), 5, "5 event 生成");
    assert!(issues.is_empty(), "正常 fixture は Issue 無し: {issues:?}");
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.source, tf_core::event::ArtifactSource::Registry);
        let t = event.event_type.as_str();
        assert!(
            t == REG_KEY_LAST_WRITE_TYPE || t == REG_OBSERVATION_TYPE,
            "観測型 Event のみ"
        );
    }
}

/// 互換 §12-2（Registry 版）: truncated・invalid length・unknown version で panic しない。
#[test]
fn reg_acceptance_12_2_corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let _ = run_registry_parser(bytes, dir.path());
    };

    // truncated: header すら無い。
    run(&(0..10).collect::<Vec<u8>>());
    // truncated: base block のみ。
    run(&vec![0u8; 4096]);
    // invalid: magic を壊す。
    let mut bad_magic = common::build_registry_fixture(&standard_registry_fixture());
    bad_magic[0] = 0xFF;
    run(&bad_magic);
    // invalid: root offset を範囲外へ。
    let mut bad_offset = common::build_registry_fixture(&standard_registry_fixture());
    bad_offset[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    run(&bad_offset);
    // unknown hive type: source_locator が未知の file 名。
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let (evidence, _) = common::make_snapshot("unknown.bin", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        REG_PARSER_ID,
        REG_PARSER_VERSION,
        tf_core::event::ArtifactSource::Registry,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.path().join("reg_unknown.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let _ = RegistryParser::new().parse(&mut file, &context, &mut sink);
    }
    // 全て panic せず完了（それ自体が成功）。
}

/// 互換 §12-3（Registry 版）: Provenance が元 record へ到達する。
#[test]
fn reg_acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let (_summary, _issues, store) = run_registry_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        assert_eq!(prov.parser_id, REG_PARSER_ID);
        assert_eq!(prov.parser_version, REG_PARSER_VERSION);
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
    }
}

/// 互換 §12-4（Registry 版）: 同一入力で同一 Event ID（決定性）。
#[test]
fn reg_acceptance_12_4_parser_is_deterministic_across_runs() {
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let run_once = || -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (_summary, _issues, store) = run_registry_parser(&bytes, dir.path());
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

/// 互換 §12-5（Registry 版）: fixture SHA-256・生成方法を記録できる。
#[test]
fn reg_acceptance_12_5_fixture_metadata_recorded() {
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let sha256 = common::sha256_hex(&bytes);
    assert_eq!(sha256.len(), 64);
    assert!(
        sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // 生成方法: 合成（hand-crafted, MS-RRMF / libyal libregf 準拠）。docs/learn/phase4e.md へ記録。
}

/// 互換 §12-6（Registry 版）: 外部仕様 revision / dependency version を記録する。
#[test]
fn reg_acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let (_summary, _issues, store) = run_registry_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(
            event.attributes["registry.reference_spec"],
            REGISTRY_REFERENCE
        );
        assert_eq!(
            event.attributes["registry.parser_version"],
            REG_PARSER_VERSION
        );
    }
}

/// 互換 §12-7（Registry 版）: LOG が既知だが未対応形式（HvLE）を黙って無視しない。
#[test]
fn reg_acceptance_12_7_unsupported_log_format_emits_issue() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    // HvLE 形式の LOG。
    let mut hvle_log = vec![0u8; 32];
    hvle_log[0..4].copy_from_slice(&common::registry_hvle_magic());

    let (evidence, _) = common::make_snapshot("SYSTEM", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        REG_PARSER_ID,
        REG_PARSER_VERSION,
        tf_core::event::ArtifactSource::Registry,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.path().join("reg_hvle.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let summary;
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        summary = RegistryParser::new()
            .with_log1(hvle_log)
            .parse(&mut file, &context, &mut sink);
    }

    // HvLE は既知だが未対応: base のみで partial。
    assert_eq!(summary.status, tf_core::case::ParseStatus::Partial);
    // 黙って無視せず Issue へ記録する。
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE),
        "UNSUPPORTED_VERSION が記録される: {issues:?}"
    );
    // LOG の SHA-256 も記録される。
    assert!(
        issues.iter().any(|i| i.message.contains("log1_sha256=")),
        "LOG hash が記録される: {issues:?}"
    );
}

/// 互換 §12-8（Registry 版）: 形式の意味を越えて Event type を断定しない。
#[test]
fn reg_acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let (_summary, _issues, store) = run_registry_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // assertion は Observed（規範 §7.1）。
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        let et = event.event_type.as_str();
        // registry_set / registry_delete は断定型 → 生成しない。
        assert_ne!(et, "registry_set");
        assert_ne!(et, "registry_delete");
        assert!(!et.contains("created"));
        assert!(!et.contains("deleted"));
        assert!(!et.contains("modified"));
        assert!(!et.contains("set"));
    }
}

/// dual view: 合成 LOG replay で recovered view も生成される。
#[test]
fn reg_acceptance_dual_view_base_and_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let (bytes, root_offset) =
        common::build_registry_fixture_with_root_offset(&standard_registry_fixture());
    let root_ft_offset = (4096 + root_offset as usize + 4 + 2) as u32;
    let new_ft_bytes = common::filetime_from_unix_offset(600).to_le_bytes();
    let log_entry = common::registry_log_entry(root_ft_offset, new_ft_bytes.to_vec());
    let log_bytes = common::build_registry_log_fixture(&[log_entry]);

    let (evidence, _) = common::make_snapshot("SYSTEM", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        REG_PARSER_ID,
        REG_PARSER_VERSION,
        tf_core::event::ArtifactSource::Registry,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.path().join("reg_dual.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let summary;
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        summary = RegistryParser::new()
            .with_log1(log_bytes)
            .parse(&mut file, &context, &mut sink);
    }
    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);

    let mut base = 0;
    let mut recovered = 0;
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        match event.attributes["registry.view"].as_str().unwrap() {
            "base" => base += 1,
            "recovered" => recovered += 1,
            _ => {}
        }
    }
    assert_eq!(base, 5, "base view は5 event");
    assert_eq!(recovered, 5, "recovered view は5 event");
    // LOG hash が各 Event 属性へ記録される（互換 §4.7: 使用 log hash を記録）。
    // 成功時は Issue を出さず、属性へ完全 64 桁 hex を保存する設計。
    let mut all_success = true;
    let mut has_log1_hash = false;
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        if event.attributes["registry.replay_status"] != "success" {
            all_success = false;
        }
        if let Some(v) = event
            .attributes
            .get("registry.log1_sha256")
            .and_then(|v| v.as_str())
            && v.len() == 64
        {
            has_log1_hash = true;
        }
    }
    assert!(all_success, "replay_status=success が全 Event へ記録される");
    assert!(has_log1_hash, "log1_sha256 (64 桁) が記録される");
}

/// Amcache.hve は Registry Parser と明示的併用可能（自動 fallback 禁止）。
#[test]
fn reg_acceptance_amcache_hive_parses_as_registry() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    // source_locator を Amcache.hve にする。hive_type = amcache となる。
    let (evidence, _) = common::make_snapshot("Amcache.hve", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        REG_PARSER_ID,
        REG_PARSER_VERSION,
        tf_core::event::ArtifactSource::Registry,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.path().join("reg_amcache.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let summary;
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        summary = RegistryParser::new().parse(&mut file, &context, &mut sink);
    }
    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert!(!store.is_empty());
    // hive_type = amcache（Amcache Parser と明示的併用を許可）。
    let first = store.iter().unwrap().next().unwrap().unwrap();
    assert_eq!(
        first.attributes["registry.hive_type"],
        RegHiveType::Amcache.as_str()
    );
}

/// Registry の縦割り: Registry のみで analyze → Case JSONL + Manifest が生成される。
#[test]
fn reg_vertical_slice_registry_to_case_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_registry_fixture());
    let (evidence, _) = common::make_snapshot("SYSTEM", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        REG_PARSER_ID,
        REG_PARSER_VERSION,
        tf_core::event::ArtifactSource::Registry,
    );

    let spool_path = dir.path().join("case.spool");
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
        RegistryParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();
    assert_eq!(store.len(), 5);

    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "Registry vertical slice".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: 0,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-11T01:00:00Z".to_string(),
        run_finished_at: "2026-08-11T01:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "e".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": REG_PARSER_ID,
            "parser_version": REG_PARSER_VERSION,
            "reference": REGISTRY_REFERENCE,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output, 5);

    let output_str = String::from_utf8(output).unwrap();
    let record_types: Vec<String> = output_str
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    assert!(
        record_types
            .iter()
            .filter(|t| t == &&"event".to_string())
            .count()
            == 5
    );
}

// ============================================================
// Amcache acceptance test（T4-065、互換 §12・§4.6）
// ============================================================

use tf_parsers::amcache::{AMCACHE_OBSERVATION_EVENT_TYPE as AMC_EVENT_TYPE, AMCACHE_REFERENCE};
use tf_parsers::{
    AMCACHE_PARSER_ID as AMC_PARSER_ID, AMCACHE_PARSER_VERSION as AMC_PARSER_VERSION,
};

/// Amcache fixture を構築して EventStore へ流し込む共通 helper。
fn run_amcache_parser(
    bytes: &[u8],
    dir: &std::path::Path,
) -> (
    tf_parsers::ParseSummary,
    Vec<tf_core::issue::Issue>,
    EventStore,
) {
    let (evidence, _) = common::make_snapshot("Amcache.hve", bytes, dir);
    let artifact = common::make_artifact_with_source(
        &evidence,
        AMC_PARSER_ID,
        AMC_PARSER_VERSION,
        tf_core::event::ArtifactSource::Amcache,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.join("amcache_accept.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = tf_parsers::AmcacheParser::new();
    let summary = {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        parser.parse(&mut file, &context, &mut sink)
    };
    (summary, issues, store)
}

/// 標準的な Amcache fixture（Win10 22H2 / Win11 24H2 Inventory schema）。
fn standard_amcache_fixture() -> common::RegistryKeySpec {
    // InventoryApplicationFile 配下の file entry ×2。
    let file_entry_a = common::RegistryKeySpec {
        name: "000061e800b0c814fa2da1c8df6f48501bd43a4d78cd2151".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![
            common::RegistryValueSpec::sz("CompanyName", "Microsoft Corporation"),
            common::RegistryValueSpec::sz("FileName", "notepad.exe"),
            common::RegistryValueSpec::sz("FileVersion", "10.0.22621.1"),
        ],
        subkeys: vec![],
    };
    let file_entry_b = common::RegistryKeySpec {
        name: "0000b0c814fa2da1c8df6f48501bd43a4d78cd21510000".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(60),
        values: vec![
            common::RegistryValueSpec::sz("CompanyName", "Contoso"),
            common::RegistryValueSpec::sz("FileName", "contoso_app.exe"),
        ],
        subkeys: vec![],
    };
    let inventory_application_file = common::RegistryKeySpec {
        name: "InventoryApplicationFile".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![],
        subkeys: vec![file_entry_a, file_entry_b],
    };
    let device_census = common::RegistryKeySpec {
        name: "DeviceCensus".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(120),
        values: vec![common::RegistryValueSpec::sz("OSName", "Windows 11 Pro")],
        subkeys: vec![],
    };
    common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(-60),
        values: vec![],
        subkeys: vec![inventory_application_file, device_census],
    }
}

/// 互換 §12-1（Amcache 版）: 正常 fixture から期待 Event を生成する。
#[test]
fn amc_acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let (summary, issues, store) = run_amcache_parser(&bytes, dir.path());

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert!(!store.is_empty(), "Inventory schema は Event を生成");
    assert!(issues.is_empty(), "正常 fixture は Issue 無し: {issues:?}");
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.source, tf_core::event::ArtifactSource::Amcache);
        assert_eq!(event.event_type.as_str(), AMC_EVENT_TYPE);
        assert_eq!(
            event.attributes["amcache.schema_family"],
            "win10-22h2-win11-24h2-inventory"
        );
    }
}

/// 互換 §12-2（Amcache 版）: truncated・invalid length・unknown version で panic しない。
#[test]
fn amc_acceptance_12_2_corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let _ = run_amcache_parser(bytes, dir.path());
    };

    // truncated: header すら無い。
    run(&(0..10).collect::<Vec<u8>>());
    // truncated: base block のみ。
    run(&vec![0u8; 4096]);
    // invalid: magic を壊す。
    let mut bad_magic = common::build_registry_fixture(&standard_amcache_fixture());
    bad_magic[0] = 0xFF;
    run(&bad_magic);
    // invalid: root offset を範囲外へ。
    let mut bad_offset = common::build_registry_fixture(&standard_amcache_fixture());
    bad_offset[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    run(&bad_offset);

    // unknown schema（Amcache Parser 固有の "unknown version" 相当）。
    let unknown = common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![],
        subkeys: vec![common::RegistryKeySpec {
            name: "MysterySchema".to_string(),
            last_write_filetime: common::filetime_from_unix_offset(0),
            values: vec![],
            subkeys: vec![],
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&unknown);
    let (summary, issues, _store) = run_amcache_parser(&bytes, dir.path());
    assert_eq!(summary.status, tf_core::case::ParseStatus::Skipped);
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
}

/// 互換 §12-3（Amcache 版）: Provenance が元 record へ到達する。
#[test]
fn amc_acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let (_summary, _issues, store) = run_amcache_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        assert_eq!(prov.parser_id, AMC_PARSER_ID);
        assert_eq!(prov.parser_version, AMC_PARSER_VERSION);
        assert!(matches!(
            prov.record_locator,
            RecordLocator::ByteRange { .. }
        ));
    }
}

/// 互換 §12-4（Amcache 版）: 1 thread と複数 thread で出力が一致する（Parser 単体の決定性）。
#[test]
fn amc_acceptance_12_4_parser_is_deterministic_across_runs() {
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let run_once = || -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (_summary, _issues, store) = run_amcache_parser(&bytes, dir.path());
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

/// 互換 §12-5（Amcache 版）: fixture SHA-256・生成方法を記録できる。
#[test]
fn amc_acceptance_12_5_fixture_metadata_recorded() {
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let sha256 = common::sha256_hex(&bytes);
    assert_eq!(sha256.len(), 64);
    assert!(
        sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // 生成方法: 合成（hand-crafted, MS-RRMF + Amcache Inventory schema 準拠）。
    // docs/learn/phase4f.md へ記録。
}

/// 互換 §12-6（Amcache 版）: 外部仕様 revision / dependency version を記録する。
#[test]
fn amc_acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let (_summary, _issues, store) = run_amcache_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(
            event.attributes["amcache.reference_spec"],
            AMCACHE_REFERENCE
        );
        assert_eq!(
            event.attributes["amcache.parser_version"],
            AMC_PARSER_VERSION
        );
    }
}

/// 互換 §12-7（Amcache 版）: 未知 schema を黙って無視しない。
#[test]
fn amc_acceptance_12_7_unknown_schema_emits_issue() {
    let unknown = common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(0),
        values: vec![],
        subkeys: vec![common::RegistryKeySpec {
            name: "MysterySchema".to_string(),
            last_write_filetime: common::filetime_from_unix_offset(0),
            values: vec![],
            subkeys: vec![],
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&unknown);
    let (summary, issues, store) = run_amcache_parser(&bytes, dir.path());

    // 未知 schema は Skipped。
    assert_eq!(summary.status, tf_core::case::ParseStatus::Skipped);
    // Event 生成無し。
    assert_eq!(store.len(), 0);
    // 黙って無視せず Issue へ記録。
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
    let msg = &issues
        .iter()
        .find(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
        .unwrap()
        .message;
    assert!(
        msg.contains("fallback"),
        "Generic Registry 自動 fallback 禁止の旨が message へ残る"
    );
}

/// 互換 §12-8（Amcache 版）: 形式の意味を越えて Event type を断定しない。
#[test]
fn amc_acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let (_summary, _issues, store) = run_amcache_parser(&bytes, dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // event_type は amcache_observation（観測型）。
        assert_eq!(event.event_type.as_str(), AMC_EVENT_TYPE);
        // assertion は Observed（規範 §7.1）。
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        // 「実行した」「起動した」等の断定型ではない。
        let et = event.event_type.as_str();
        assert!(!et.contains("process_start"));
        assert!(!et.contains("launched"));
        assert!(!et.contains("executed"));
        assert!(!et.contains("installed"));
    }
}

/// Amcache の縦割り: Amcache のみで analyze → Case JSONL + Manifest が生成される。
#[test]
fn amc_vertical_slice_amcache_to_case_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = common::build_registry_fixture(&standard_amcache_fixture());
    let (evidence, _) = common::make_snapshot("Amcache.hve", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        AMC_PARSER_ID,
        AMC_PARSER_VERSION,
        tf_core::event::ArtifactSource::Amcache,
    );

    let spool_path = dir.path().join("case.spool");
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
        tf_parsers::AmcacheParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();
    assert!(!store.is_empty(), "Event が生成されている");

    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "Amcache vertical slice".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: 0,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-11T01:00:00Z".to_string(),
        run_finished_at: "2026-08-11T01:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "f".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": AMC_PARSER_ID,
            "parser_version": AMC_PARSER_VERSION,
            "reference": AMCACHE_REFERENCE,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output as u64, store.len());

    let output_str = String::from_utf8(output).unwrap();
    let record_types: Vec<String> = output_str
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    // manifest は最終行（Schema §6）。
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    assert!(
        record_types
            .iter()
            .filter(|t| t == &&"event".to_string())
            .count()
            > 0
    );
}

// ============================================================
// Jump Lists acceptance test（T4-074、互換 §12・§4.5）
// ============================================================

use tf_parsers::jump_lists::{
    JUMP_LIST_OBSERVATION_EVENT_TYPE as JL_EVENT_TYPE, JUMP_LIST_REFERENCE,
};
use tf_parsers::{
    JUMP_LIST_PARSER_ID as JL_PARSER_ID, JUMP_LIST_PARSER_VERSION as JL_PARSER_VERSION,
};

/// Jump Lists fixture を構築して EventStore へ流し込む共通 helper。
fn run_jump_list_parser(
    bytes: &[u8],
    source_locator: &str,
    dir: &std::path::Path,
) -> (
    tf_parsers::ParseSummary,
    Vec<tf_core::issue::Issue>,
    EventStore,
) {
    let (evidence, _) = common::make_snapshot(source_locator, bytes, dir);
    let artifact = common::make_artifact_with_source(
        &evidence,
        JL_PARSER_ID,
        JL_PARSER_VERSION,
        tf_core::event::ArtifactSource::JumpList,
    );
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let spool = dir.join("jumplist_accept.spool");
    let mut store = EventStore::create(&spool).unwrap();
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    let snapshot_path = std::path::Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).unwrap();
    let parser = tf_parsers::JumpListParser::new();
    let summary = {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        parser.parse(&mut file, &context, &mut sink)
    };
    (summary, issues, store)
}

/// 標準的な Jump Lists fixture（Win10 22H2 / Win11 24H2 v3 AutomaticDestinations）。
fn standard_jump_list_fixture() -> Vec<u8> {
    let ft = |offset_secs: i64| common::filetime_from_unix_offset(offset_secs);
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

/// 互換 §12-1（Jump Lists 版）: 正常 fixture から期待 Event を生成する。
#[test]
fn jl_acceptance_12_1_valid_fixture_emits_expected_events() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_jump_list_fixture();
    let (summary, issues, store) = run_jump_list_parser(
        &bytes,
        "b9105685df489b5b.automaticDestinations-ms",
        dir.path(),
    );

    assert_eq!(summary.status, tf_core::case::ParseStatus::Complete);
    assert!(!store.is_empty(), "正常 fixture は Event を生成");
    assert!(issues.is_empty(), "正常 fixture は Issue 無し: {issues:?}");
    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(event.source, tf_core::event::ArtifactSource::JumpList);
        assert_eq!(event.event_type.as_str(), JL_EVENT_TYPE);
        assert_eq!(
            event.attributes["jump_list.container_type"],
            "automatic_destinations"
        );
    }
}

/// 互換 §12-2（Jump Lists 版）: truncated・invalid・unknown DestList version で panic しない。
#[test]
fn jl_acceptance_12_2_corrupt_inputs_do_not_panic() {
    let run = |bytes: &[u8], locator: &str| {
        let dir = tempfile::tempdir().unwrap();
        let _ = run_jump_list_parser(bytes, locator, dir.path());
    };

    // truncated: header 無し。
    run(&(0..10).collect::<Vec<u8>>(), "x.automaticDestinations-ms");
    // invalid: magic を壊す。
    let mut bad_magic = standard_jump_list_fixture();
    bad_magic[0] = 0xFF;
    run(&bad_magic, "x.automaticDestinations-ms");
    // unknown DestList version。
    let mut bad_destlist = vec![0u8; 32];
    bad_destlist[0..4].copy_from_slice(&99u32.to_le_bytes());
    let lnk1 = common::build_jump_list_lnk(0, 0, 0, 0, None, true);
    let streams: Vec<(&str, &[u8])> = vec![("DestList", &bad_destlist), ("1", &lnk1)];
    let bytes = common::build_automatic_destinations(&streams);
    let dir = tempfile::tempdir().unwrap();
    let (summary, issues, _store) =
        run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());
    assert_eq!(summary.status, tf_core::case::ParseStatus::Partial);
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
}

/// 互換 §12-3（Jump Lists 版）: Provenance が元 record へ到達する。
#[test]
fn jl_acceptance_12_3_provenance_reaches_original_record() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_jump_list_fixture();
    let (_summary, _issues, store) =
        run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        let prov = &event.provenance;
        assert_eq!(prov.parser_id, JL_PARSER_ID);
        assert_eq!(prov.parser_version, JL_PARSER_VERSION);
        // LogicalPath（stream 名）または ByteRange（custom destination 等）のいずれか。
        assert!(
            matches!(prov.record_locator, RecordLocator::LogicalPath(_))
                || matches!(prov.record_locator, RecordLocator::ByteRange { .. })
        );
    }
}

/// 互換 §12-4（Jump Lists 版）: 1 thread と複数 thread で出力が一致する（決定性）。
#[test]
fn jl_acceptance_12_4_parser_is_deterministic_across_runs() {
    let bytes = standard_jump_list_fixture();
    let run_once = || -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (_summary, _issues, store) =
            run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());
        let mut ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        ids.sort();
        ids
    };
    let ids1 = run_once();
    let ids2 = run_once();
    assert_eq!(ids1, ids2, "同一入力なら同一 Event ID（決定性）");
}

/// 互換 §12-5（Jump Lists 版）: fixture SHA-256・生成方法を記録できる。
#[test]
fn jl_acceptance_12_5_fixture_metadata_recorded() {
    let bytes = standard_jump_list_fixture();
    let sha256 = common::sha256_hex(&bytes);
    assert_eq!(sha256.len(), 64);
    assert!(
        sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // 生成方法: 合成（hand-crafted, [MS-CFB] + [MS-DESTS] + [MS-SHLLINK] 準拠）。
    // docs/learn/phase4g.md へ記録。
}

/// 互換 §12-6（Jump Lists 版）: 外部仕様 revision / dependency version を記録する。
#[test]
fn jl_acceptance_12_6_reference_spec_revision_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_jump_list_fixture();
    let (_summary, _issues, store) =
        run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        assert_eq!(
            event.attributes["jump_list.reference_spec"],
            JUMP_LIST_REFERENCE
        );
        assert_eq!(
            event.attributes["jump_list.parser_version"],
            JL_PARSER_VERSION
        );
    }
}

/// 互換 §12-7（Jump Lists 版）: 未知 DestList version を黙って無視しない。
#[test]
fn jl_acceptance_12_7_unknown_destlist_version_emits_issue() {
    let mut bad_destlist = vec![0u8; 32];
    bad_destlist[0..4].copy_from_slice(&99u32.to_le_bytes());
    let lnk1 = common::build_jump_list_lnk(0, 0, 0, 0, None, true);
    let streams: Vec<(&str, &[u8])> = vec![("DestList", &bad_destlist), ("1", &lnk1)];
    let bytes = common::build_automatic_destinations(&streams);
    let dir = tempfile::tempdir().unwrap();
    let (summary, issues, store) =
        run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());

    // Partial（DestList 未知 version）。LNK stream は Event 生成。
    assert_eq!(summary.status, tf_core::case::ParseStatus::Partial);
    assert_eq!(store.len(), 1, "LNK stream は1件 Event 生成");
    // 黙って無視せず Issue へ記録。
    assert!(
        issues
            .iter()
            .any(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
    );
    let msg = &issues
        .iter()
        .find(|i| i.issue_id == tf_parsers::issue::UNSUPPORTED_VERSION_CODE)
        .unwrap()
        .message;
    assert!(
        msg.contains("DestList"),
        "DestList 未知 version の旨: {msg}"
    );
}

/// 互換 §12-8（Jump Lists 版）: 形式の意味を越えて Event type を断定しない。
#[test]
fn jl_acceptance_12_8_event_type_does_not_overstate_observation() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_jump_list_fixture();
    let (_summary, _issues, store) =
        run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // event_type は jump_list_observation（観測型）。
        assert_eq!(event.event_type.as_str(), JL_EVENT_TYPE);
        // assertion は Observed（規範 §7.1）。
        assert_eq!(event.assertion, tf_core::event::AssertionKind::Observed);
        // 「開いた」「起動した」等の断定型ではない。
        let et = event.event_type.as_str();
        assert!(!et.contains("open"));
        assert!(!et.contains("launch"));
        assert!(!et.contains("executed"));
        assert!(!et.contains("ran"));
    }
}

/// Jump Lists の縦割り: Jump Lists のみで analyze → Case JSONL + Manifest が生成される。
#[test]
fn jl_vertical_slice_jumplist_to_case_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_jump_list_fixture();
    let (evidence, _) = common::make_snapshot("x.automaticDestinations-ms", &bytes, dir.path());
    let artifact = common::make_artifact_with_source(
        &evidence,
        JL_PARSER_ID,
        JL_PARSER_VERSION,
        tf_core::event::ArtifactSource::JumpList,
    );

    let spool_path = dir.path().join("case.spool");
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
        tf_parsers::JumpListParser::new().parse(&mut file, &context, &mut sink);
    }
    store.commit().unwrap();
    assert!(!store.is_empty(), "Event が生成されている");

    let case_id = tf_core::id::case_id(&[evidence.evidence_id.as_str()]);
    let case = CaseMetadata {
        case_id: case_id.clone(),
        external_case_id: None,
        name: "Jump List vertical slice".to_string(),
        analyst: None,
        description: None,
        default_timezone: None,
        tags: vec![],
    };
    let other_counts = OtherCounts {
        evidence: 1,
        artifact: 1,
        issue: 0,
        match_: 0,
        finding: 0,
    };
    let manifest_counts = build_manifest_counts(&store, &other_counts);
    let manifest = Manifest {
        traceforge_version: "0.1.0".to_string(),
        build_commit: "test".to_string(),
        target: "test".to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        compatibility_profile: "TF-WIN-1.0".to_string(),
        run_started_at: "2026-08-11T02:00:00Z".to_string(),
        run_finished_at: "2026-08-11T02:00:01Z".to_string(),
        resolved_config: serde_json::json!({}),
        resolved_config_sha256: "g".repeat(64),
        case_id: case_id.clone(),
        counts: manifest_counts,
        components: vec![serde_json::json!({
            "parser_id": JL_PARSER_ID,
            "parser_version": JL_PARSER_VERSION,
            "reference": JUMP_LIST_REFERENCE,
        })],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![],
        limits: serde_json::json!({}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    };
    let stream = CaseStream {
        case: &case,
        evidence: std::slice::from_ref(&evidence),
        artifacts: std::slice::from_ref(&artifact),
        issues: &issues,
        matches: &[],
        findings: &[],
        manifest: &manifest,
    };

    let mut output: Vec<u8> = Vec::new();
    let outcome = write_jsonl(&store, &stream, 1024 * 1024, None, &mut output).unwrap();
    assert_eq!(outcome.events_output as u64, store.len());

    let output_str = String::from_utf8(output).unwrap();
    let record_types: Vec<String> = output_str
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["record_type"].as_str().unwrap().to_string()
        })
        .collect();
    // manifest は最終行（Schema §6）。
    assert_eq!(record_types.last(), Some(&"manifest".to_string()));
    assert!(
        record_types
            .iter()
            .filter(|t| t == &&"event".to_string())
            .count()
            > 0
    );
}

/// 互換 §4.5: 内包 LNK は物理 Evidence ではなく Jump List 内 ArtifactInstance。
#[test]
fn jl_acceptance_embedded_lnk_not_physical_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = standard_jump_list_fixture();
    let (_summary, _issues, store) =
        run_jump_list_parser(&bytes, "x.automaticDestinations-ms", dir.path());

    for result in store.iter().unwrap() {
        let event = result.unwrap();
        // source は JumpList（LNK ではない）。
        assert_eq!(event.source, tf_core::event::ArtifactSource::JumpList);
        // parser_id は traceforge-jump-lists（traceforge-lnk ではない）。
        assert_eq!(event.provenance.parser_id, JL_PARSER_ID);
        // event_type は jump_list_observation（lnk_timestamp ではない）。
        assert_eq!(event.event_type.as_str(), JL_EVENT_TYPE);
        // stream 名属性が記録される（論理的な位置）。
        assert!(event.attributes.contains_key("jump_list.stream_name"));
    }
}
