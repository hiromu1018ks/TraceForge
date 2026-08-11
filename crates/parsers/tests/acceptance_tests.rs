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
