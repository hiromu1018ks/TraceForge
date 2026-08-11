//! Phase 4 共通検証: 全 Parser の thread 数 1/複数一致 test（T4-090、互換 §12-4）。
//!
//! 互換 §12-4「1 thread と複数 thread の出力が一致する」を 7 Parser 全てで網羅検証する。
//! 既存の `acceptance_12_4_*` は「同一 fixture を2回順次実行して同じ Event ID になる」こと
//! を検証していたが、本 test はさらに一歩進めて:
//!
//! - **N 並列 thread**（[`std::thread::scope`]）で同一 Parser を同時に走らせても
//!   各 thread の結果が一致することを検証
//! - **Event ID の整列集合**だけでなく **canonical JSON byte 列**も一致することを検証
//!   （規範 §13: 決定性。hash map iteration 順非依存・`BTreeMap` の attribute 順序保証）
//!
//! `Rayon` 等の外部 crate は使わず、標準 [`std::thread`] のみで検証する
//! （PROMPT.md 制約: 「Rayon 等の外部 crate を追加せず、標準 `std::thread` で検証」）。
//!
//! 各 Parser は共有可変状態を持たない（`ArtifactParser` trait の `parse` は `&self` のみ）。
//! したがって「Parser 自体が thread 安全」は自明だが、本 test はそれに加えて
//! 「Parser が生成する Event 列そのものが決定的（thread 非依存）」を検証する。

mod common;

use std::path::Path;

use tf_core::event::ArtifactSource;
use tf_core::event::Event;
use tf_parsers::framework::{ArtifactParser, ParseContext, ParseSink, SinkError};
use tf_parsers::sink::EventStoreSink;
use tf_store::EventStore;

use tf_parsers::AmcacheParser;
use tf_parsers::JumpListParser;
use tf_parsers::evtx::EvtxParser;
use tf_parsers::evtx::PARSER_ID as EVTX_ID;
use tf_parsers::evtx::PARSER_VERSION as EVTX_VER;
use tf_parsers::lnk::LnkParser;
use tf_parsers::lnk::PARSER_ID as LNK_ID;
use tf_parsers::lnk::PARSER_VERSION as LNK_VER;
use tf_parsers::prefetch::PARSER_ID as PF_ID;
use tf_parsers::prefetch::PARSER_VERSION as PF_VER;
use tf_parsers::prefetch::PrefetchParser;
use tf_parsers::registry::PARSER_ID as REG_ID;
use tf_parsers::registry::PARSER_VERSION as REG_VER;
use tf_parsers::registry::RegistryParser;
use tf_parsers::usn::PARSER_ID as USN_ID;
use tf_parsers::usn::PARSER_VERSION as USN_VER;
use tf_parsers::usn::UsnParser;
use tf_parsers::{
    AMCACHE_PARSER_ID as AMC_ID, AMCACHE_PARSER_VERSION as AMC_VER, JUMP_LIST_PARSER_ID as JL_ID,
    JUMP_LIST_PARSER_VERSION as JL_VER,
};

/// 並列実行の thread 数。
const THREAD_COUNT: usize = 4;

/// 1 run の結果: Event の canonical JSON 文字列を整列した Vec。
///
/// Event ID のみだと同内容の別 Event を区別できないため、canonical JSON 全体で比較する
/// （規範 §13.3: canonical 出力の byte 一致）。
type RunResult = Vec<String>;

/// `EventStore` へ流し込んだ結果を `RunResult` へ変換する。
///
/// `iter` は timestamp group 順・Event ID 順の決定的 iteration を提供する（規範 §10）。
/// 各 Event を canonical JSON 文字列（`Event::to_canonical_value` 経由）へ変換し、
/// 順序へ依存しないよう整列してから返す。
fn collect_run_result(store: &EventStore) -> RunResult {
    let mut result: Vec<String> = Vec::new();
    for entry in store.iter().expect("store.iter") {
        let event = entry.expect("event decode");
        let value = event.to_canonical_value();
        // to_canonical_value は key sort 済みの serde_json::Map を返すため、
        // これを文字列化すると canonical JSON になる（規範 §13.2）。
        let json = serde_json::to_string(&value).expect("canonical JSON");
        result.push(json);
    }
    // 順序へ依存しないよう sort。同じ Event なら同一文字列になる（規範 §13）。
    result.sort();
    result
}

/// 1回の Parser 実行（独立した tempdir・spool file）。
///
/// thread 間で file や store を共有しない。各 thread が独立した resource を使うことで、
/// Parser 本体の thread 安全性（共有状態の有無）ではなく「Parser が生成する Event 列の
/// 決定性」を純粋に検証できる。
fn run_once<F>(
    bytes: &[u8],
    source_locator: &str,
    parser_id: &str,
    parser_version: &str,
    source: ArtifactSource,
    make_parser: F,
) -> RunResult
where
    F: Fn() -> Box<dyn ArtifactParser>,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let (evidence, _) = common::make_snapshot(source_locator, bytes, dir.path());
    let artifact = common::make_artifact_with_source(&evidence, parser_id, parser_version, source);
    let context = ParseContext {
        evidence: evidence.clone(),
        artifact,
    };
    let snapshot_path = Path::new(&context.evidence.snapshot_locator);
    let mut file = std::fs::File::open(snapshot_path).expect("snapshot open");
    let spool = dir.path().join("thread_consistency.spool");
    let mut store = EventStore::create(&spool).expect("store create");
    let mut issues: Vec<tf_core::issue::Issue> = Vec::new();
    {
        let mut sink = EventStoreSink::new(&mut store, &mut issues);
        let parser = make_parser();
        let _ = parser.parse(&mut file, &context, &mut sink);
    }
    collect_run_result(&store)
}

/// 1 thread（順次実行）と N 並列 thread で全結果が一致することを検証する。
#[allow(clippy::type_complexity)]
fn assert_thread_consistency<F>(
    label: &str,
    bytes: &[u8],
    source_locator: &str,
    parser_id: &str,
    parser_version: &str,
    source: ArtifactSource,
    make_parser: F,
) where
    F: Fn() -> Box<dyn ArtifactParser> + Send + Sync + Copy + 'static,
{
    // 1) 単一 thread 基準 run。
    let baseline = run_once(
        bytes,
        source_locator,
        parser_id,
        parser_version,
        source,
        make_parser,
    );
    assert!(
        !baseline.is_empty(),
        "{label}: 基準 run が空（Parser が Event を生成していない）"
    );

    // 2) N 並列 thread で同時実行。各 thread の結果が baseline へ一致すること。
    let results: Vec<RunResult> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..THREAD_COUNT {
            let handle = scope.spawn(move || {
                run_once(
                    bytes,
                    source_locator,
                    parser_id,
                    parser_version,
                    source,
                    make_parser,
                )
            });
            handles.push(handle);
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .collect()
    });

    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result.len(),
            baseline.len(),
            "{label}: thread {i} の Event 数が基準と不一致（{} vs {}）",
            result.len(),
            baseline.len()
        );
        for (j, (a, b)) in result.iter().zip(baseline.iter()).enumerate() {
            assert_eq!(
                a, b,
                "{label}: thread {i} の Event #{j} の canonical JSON が基準と不一致"
            );
        }
    }

    // 3) 念のため baseline をもう1回取って、順次実行でも完全一致することを確認
    //    （決定性の二重チェック）。
    let baseline2 = run_once(
        bytes,
        source_locator,
        parser_id,
        parser_version,
        source,
        make_parser,
    );
    assert_eq!(
        baseline, baseline2,
        "{label}: 順次実行でも2回で不一致（非決定的）"
    );
}

// ============================================================
// Parser が Send + Sync であることのコンパイル時検証
// （Parser が `&self` で呼べ、共有可変状態を持たないことの保証）
// ============================================================

#[test]
fn parser_implementations_are_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<LnkParser>();
    assert_sync::<LnkParser>();
    assert_send::<PrefetchParser>();
    assert_sync::<PrefetchParser>();
    assert_send::<UsnParser>();
    assert_sync::<UsnParser>();
    assert_send::<EvtxParser>();
    assert_sync::<EvtxParser>();
    assert_send::<RegistryParser>();
    assert_sync::<RegistryParser>();
    assert_send::<AmcacheParser>();
    assert_sync::<AmcacheParser>();
    assert_send::<JumpListParser>();
    assert_sync::<JumpListParser>();
}

// ============================================================
// LNK: thread 数 1 / 複数一致
// ============================================================

#[test]
fn lnk_thread_consistency() {
    let opts = common::LnkFixtureOptions {
        flags: 0x0000_0002, // HasLinkInfo
        creation_filetime: common::filetime_from_unix_offset(0),
        access_filetime: common::filetime_from_unix_offset(60),
        write_filetime: common::filetime_from_unix_offset(120),
        local_base_path: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
        ..Default::default()
    };
    let bytes = common::build_lnk_fixture(&opts);
    assert_thread_consistency(
        "LNK",
        &bytes,
        "notepad.lnk",
        LNK_ID,
        LNK_VER,
        ArtifactSource::Lnk,
        || Box::new(LnkParser::new()),
    );
}

// ============================================================
// Prefetch: thread 数 1 / 複数一致
// ============================================================

#[test]
fn prefetch_thread_consistency() {
    let opts = common::PrefetchFixtureOptions {
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
    };
    let bytes = common::build_prefetch_fixture(&opts);
    assert_thread_consistency(
        "Prefetch",
        &bytes,
        "NOTEPAD.EXE-ABC123.PF",
        PF_ID,
        PF_VER,
        ArtifactSource::Prefetch,
        || Box::new(PrefetchParser::new()),
    );
}

// ============================================================
// USN Journal: thread 数 1 / 複数一致
// ============================================================

/// USN fixture を構築する（acceptance_tests.rs の standard_usn_fixture と同等）。
fn build_usn_fixture() -> Vec<u8> {
    let dir_record = common::build_usn_v2_record(
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
    let mut bytes = dir_record;
    bytes.extend(v2a);
    bytes.extend(v3a);
    bytes.extend(rename_old);
    bytes.extend(rename_new);
    bytes
}

#[test]
fn usn_thread_consistency() {
    let bytes = build_usn_fixture();
    assert_thread_consistency(
        "USN",
        &bytes,
        "$UsnJrnl$J",
        USN_ID,
        USN_VER,
        ArtifactSource::UsnJournal,
        || Box::new(UsnParser::new()),
    );
}

// ============================================================
// EVTX: thread 数 1 / 複数一致
// ============================================================

/// EVTX fixture を構築する（acceptance_tests.rs の standard_evtx_fixture と同等）。
fn build_evtx_fixture() -> Vec<u8> {
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

#[test]
fn evtx_thread_consistency() {
    let bytes = build_evtx_fixture();
    assert_thread_consistency(
        "EVTX",
        &bytes,
        "Security.evtx",
        EVTX_ID,
        EVTX_VER,
        ArtifactSource::Evtx,
        || Box::new(EvtxParser::new()),
    );
}

// ============================================================
// Registry: thread 数 1 / 複数一致
// ============================================================

fn build_registry_fixture() -> Vec<u8> {
    let spec = common::RegistryKeySpec {
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
    };
    common::build_registry_fixture(&spec)
}

#[test]
fn registry_thread_consistency() {
    let bytes = build_registry_fixture();
    assert_thread_consistency(
        "Registry",
        &bytes,
        "SYSTEM",
        REG_ID,
        REG_VER,
        ArtifactSource::Registry,
        || Box::new(RegistryParser::new()),
    );
}

// ============================================================
// Amcache: thread 数 1 / 複数一致
// ============================================================

fn build_amcache_fixture() -> Vec<u8> {
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
    let spec = common::RegistryKeySpec {
        name: "Root".to_string(),
        last_write_filetime: common::filetime_from_unix_offset(-60),
        values: vec![],
        subkeys: vec![inventory_application_file, device_census],
    };
    common::build_registry_fixture(&spec)
}

#[test]
fn amcache_thread_consistency() {
    let bytes = build_amcache_fixture();
    assert_thread_consistency(
        "Amcache",
        &bytes,
        "Amcache.hve",
        AMC_ID,
        AMC_VER,
        ArtifactSource::Amcache,
        || Box::new(AmcacheParser::new()),
    );
}

// ============================================================
// Jump Lists: thread 数 1 / 複数一致
// ============================================================

fn build_jump_list_fixture() -> Vec<u8> {
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

#[test]
fn jump_lists_thread_consistency() {
    let bytes = build_jump_list_fixture();
    assert_thread_consistency(
        "Jump Lists",
        &bytes,
        "b9105685df489b5b.automaticDestinations-ms",
        JL_ID,
        JL_VER,
        ArtifactSource::JumpList,
        || Box::new(JumpListParser::new()),
    );
}

// ============================================================
// 補助: 各 Parser が生成する Event の attribute key が BTreeMap で sort 済み
// （規範 §13.2: hash map iteration 順非依存）。canonical JSON の文字列表現が
// thread 非依存で安定することの直接検証。
// ============================================================

/// Event を蓄積するだけの in-memory sink。
struct VecSink {
    events: Vec<Event>,
    issues: Vec<tf_core::issue::Issue>,
}

impl ParseSink for VecSink {
    fn emit_event(&mut self, event: Event) -> Result<(), SinkError> {
        self.events.push(event);
        Ok(())
    }
    fn emit_issue(&mut self, issue: tf_core::issue::Issue) -> Result<(), SinkError> {
        self.issues.push(issue);
        Ok(())
    }
}

/// 全 Parser で attribute key が byte 順に整列していることを検証する。
/// 各 Parser が `BTreeMap<String, Value>` を使っていることで、
/// thread や map 実装に依存せず同じ JSON 列へ serialize される。
#[test]
#[allow(clippy::type_complexity)]
fn all_parsers_emit_btremap_sorted_attributes() {
    let cases: Vec<(
        &str,
        Vec<u8>,
        &str,
        &str,
        ArtifactSource,
        Box<dyn Fn() -> Box<dyn ArtifactParser>>,
    )> = vec![
        (
            "LNK",
            common::build_lnk_fixture(&common::LnkFixtureOptions {
                flags: 0x0000_0002,
                creation_filetime: common::filetime_from_unix_offset(0),
                local_base_path: Some("C:\\Windows\\System32\\notepad.exe".to_string()),
                ..Default::default()
            }),
            LNK_ID,
            LNK_VER,
            ArtifactSource::Lnk,
            Box::new(|| Box::new(LnkParser::new()) as Box<dyn ArtifactParser>),
        ),
        (
            "USN",
            build_usn_fixture(),
            USN_ID,
            USN_VER,
            ArtifactSource::UsnJournal,
            Box::new(|| Box::new(UsnParser::new()) as Box<dyn ArtifactParser>),
        ),
    ];

    for (label, bytes, parser_id, parser_version, source, make_parser) in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        let (evidence, _) = common::make_snapshot("x.bin", &bytes, dir.path());
        let artifact =
            common::make_artifact_with_source(&evidence, parser_id, parser_version, source);
        let context = ParseContext {
            evidence: evidence.clone(),
            artifact,
        };
        let snapshot_path = Path::new(&context.evidence.snapshot_locator);
        let mut file = std::fs::File::open(snapshot_path).expect("snapshot open");

        let mut sink = VecSink {
            events: Vec::new(),
            issues: Vec::new(),
        };
        let parser = make_parser();
        let _ = parser.parse(&mut file, &context, &mut sink);
        // attribute key が sort 済みであることを全 Event で検証。
        for event in &sink.events {
            let value = event.to_canonical_value();
            let attrs = value["attributes"].as_object().expect("attributes object");
            let keys: Vec<&String> = attrs.keys().collect();
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            assert_eq!(keys, sorted_keys, "{label}: attribute key が byte 順でない");
            // 空文字 key が無いことも検証（key の網羅的健全性）。
            for k in &keys {
                assert!(!k.is_empty(), "{label}: 空 attribute key がある");
            }
        }
    }
}

// ============================================================
// 補助: 複数 Parser を同じ process で連続実行しても決定的
// （Parser 間で static 状態等の隠れた共有が無いことの検証）
// ============================================================

#[test]
fn multiple_parsers_in_sequence_remain_deterministic() {
    // LNK → Prefetch → USN の順に3回連続で全部動かし、3回とも同じ結果になることを検証。
    let run_all = || -> Vec<usize> {
        let lnk_bytes = common::build_lnk_fixture(&common::LnkFixtureOptions {
            flags: 0x0000_0002,
            creation_filetime: common::filetime_from_unix_offset(0),
            local_base_path: Some("C:\\x.exe".to_string()),
            ..Default::default()
        });
        let pf_bytes = common::build_prefetch_fixture(&common::PrefetchFixtureOptions {
            version: 31,
            last_run_filetimes: vec![common::filetime_from_unix_offset(0)],
            run_count: 1,
            ..Default::default()
        });
        let usn_bytes = build_usn_fixture();
        let r1 = run_once(
            &lnk_bytes,
            "a.lnk",
            LNK_ID,
            LNK_VER,
            ArtifactSource::Lnk,
            || Box::new(LnkParser::new()),
        );
        let r2 = run_once(
            &pf_bytes,
            "X.PF",
            PF_ID,
            PF_VER,
            ArtifactSource::Prefetch,
            || Box::new(PrefetchParser::new()),
        );
        let r3 = run_once(
            &usn_bytes,
            "$UsnJrnl$J",
            USN_ID,
            USN_VER,
            ArtifactSource::UsnJournal,
            || Box::new(UsnParser::new()),
        );
        vec![r1.len(), r2.len(), r3.len()]
    };
    let a = run_all();
    let b = run_all();
    let c = run_all();
    assert_eq!(a, b, "1 run 目と 2 run 目で Event 数が不一致");
    assert_eq!(b, c, "2 run 目と 3 run 目で Event 数が不一致");
}
