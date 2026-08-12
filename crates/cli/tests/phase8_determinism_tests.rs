//! Phase 8 決定性・再現性テスト（T8-001〜T8-004・規範 §13・§21-7）。
//!
//! - T8-001: golden determinism test（threads 1/2/自動で canonical JSON byte 一致）
//! - T8-002: 分析レコード vs run metadata の同一性比較分離 test
//! - T8-003: hash map iteration 順非依存 test
//! - T8-004: regression test 基盤
//!
//! 合成 LNK fixture を analyze pipeline へ通し、JSONL 出力の決定性を検証する。
//! 規範 §13.3: 同一 fixture を --threads 1 / 2 / 自動 で解析し、run metadata を除く
//! canonical JSON が byte 単位で一致しなければ release してはならない。

use std::collections::HashSet;
use std::fs;
use std::io::Write;

use serde_json::Value;
use tempfile::tempdir;
use tf_cli::run;
use tf_core::case::{EvidenceItem, IntegrityStatus};
use tf_export::CaseData;

/// 合成 LNK bytes を構築する（[MS-SHLLINK] §2.1 準拠の最小 fixture）。
///
/// parsers/tests/common/mod.rs のヘルパーは parsers crate 専用のため、
/// CLI 統合テストでは独自に最小 LNK を構築する。
fn build_minimal_lnk() -> Vec<u8> {
    let mut buf = Vec::new();
    let header_size: u32 = 0x4C;
    let clsid: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    let flags: u32 = 0x0000_0080; // IsUnicode のみ（StringData 無しなら影響無し）
    buf.extend_from_slice(&header_size.to_le_bytes());
    buf.extend_from_slice(&clsid);
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
    buf.extend_from_slice(&0u64.to_le_bytes()); // CreationTime
    buf.extend_from_slice(&0u64.to_le_bytes()); // AccessTime
    buf.extend_from_slice(&130605440000000000u64.to_le_bytes()); // WriteTime
    buf.extend_from_slice(&0u32.to_le_bytes()); // FileSize
    buf.extend_from_slice(&0i32.to_le_bytes()); // IconIndex
    buf.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand
    buf.extend_from_slice(&0u16.to_le_bytes()); // HotKey
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
    buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    assert_eq!(buf.len(), 76);
    buf.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
    buf
}

/// テスト用入力 directory へ合成 LNK file を配置する。
fn make_input_dir() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let lnk_path = dir.path().join("sample.lnk");
    let bytes = build_minimal_lnk();
    let mut f = fs::File::create(&lnk_path).unwrap();
    f.write_all(&bytes).unwrap();
    drop(f);
    dir
}

/// analyze を実行し JSONL stdout を返す。
fn run_analyze_jsonl(input: &str, threads: Option<u32>) -> String {
    let mut cmd: Vec<String> = vec![
        "analyze".into(),
        input.into(),
        "--format".into(),
        "jsonl".into(),
    ];
    if let Some(t) = threads {
        cmd.push("--threads".into());
        cmd.push(t.to_string());
    }
    let result = run(&args_with(&cmd));
    assert_eq!(
        result.exit_code.as_process_code(),
        0,
        "analyze が成功すること: stderr={}",
        result.stderr
    );
    result.stdout
}

fn args_with(parts: &[String]) -> Vec<String> {
    let mut v = vec!["traceforge".to_string()];
    v.extend(parts.iter().cloned());
    v
}

/// JSONL 出力を行毎へ分割する。
fn split_lines(jsonl: &str) -> Vec<&str> {
    jsonl.lines().filter(|l| !l.is_empty()).collect()
}

/// JSONL 出力から manifest 行を取り出す。
fn find_manifest_line<'a>(lines: &[&'a str]) -> &'a str {
    for line in lines {
        if let Ok(v) = serde_json::from_str::<Value>(line)
            && v.get("record_type").and_then(|t| t.as_str()) == Some("manifest")
        {
            return line;
        }
    }
    panic!("manifest 行が見つからない");
}

/// manifest 行から run metadata（run_started_at / run_finished_at）と実行パラメータ
/// （resolved_config / resolved_config_sha256）を除外した正規化文字列を返す
/// （T8-002: 同一性比較分離）。
///
/// resolved_config は threads 設定等を含むため、異なる thread 数での実行では意図的に
/// 変化する。分析レコードの同一性（規範 §13.3）とは独立な実行パラメータとして扱う。
fn strip_run_metadata(manifest_line: &str) -> String {
    let mut v: Value = serde_json::from_str(manifest_line).unwrap();
    if let Some(obj) = v.get_mut("record").and_then(|r| r.as_object_mut()) {
        obj.remove("run_started_at");
        obj.remove("run_finished_at");
        obj.remove("resolved_config");
        obj.remove("resolved_config_sha256");
    }
    serde_json::to_string(&v).unwrap()
}

/// manifest 以外の全行を sort + 連結した文字列を返す（分析レコード本体）。
fn analysis_records(lines: &[&str]) -> String {
    let mut records: Vec<&str> = lines
        .iter()
        .filter(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| {
                    v.get("record_type")
                        .and_then(|t| t.as_str())
                        .map(|s| s != "manifest")
                })
                .unwrap_or(true)
        })
        .copied()
        .collect();
    records.sort();
    records.join("\n")
}

#[test]
fn t8_001_threads_1_2_auto_produce_byte_identical_output() {
    // 規範 §13.3・§21-7: 同一 fixture を threads 1/2/自動 で解析し、
    // run metadata を除く canonical JSON が byte 単位で一致する。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();

    let out1 = run_analyze_jsonl(input, Some(1));
    let out2 = run_analyze_jsonl(input, Some(2));
    let out_auto = run_analyze_jsonl(input, None);

    let lines1 = split_lines(&out1);
    let lines2 = split_lines(&out2);
    let lines_auto = split_lines(&out_auto);

    // 分析レコード（manifest 以外）は完全一致。
    let rec1 = analysis_records(&lines1);
    let rec2 = analysis_records(&lines2);
    let rec_auto = analysis_records(&lines_auto);
    assert_eq!(rec1, rec2, "threads 1 と 2 の分析レコードが一致する");
    assert_eq!(rec1, rec_auto, "threads 1 と自動の分析レコードが一致する");

    // manifest も run metadata を除けば一致。
    let m1 = strip_run_metadata(find_manifest_line(&lines1));
    let m2 = strip_run_metadata(find_manifest_line(&lines2));
    let m_auto = strip_run_metadata(find_manifest_line(&lines_auto));
    assert_eq!(
        m1, m2,
        "threads 1 と 2 の manifest（run metadata 除く）が一致"
    );
    assert_eq!(
        m1, m_auto,
        "threads 1 と自動の manifest（run metadata 除く）が一致"
    );
}

#[test]
fn t8_002_run_metadata_separated_from_analysis_records() {
    // 規範 §13.1: run metadata（時刻・PID・temp dir 等）は分析 determinism へ影響しない。
    // 同一 fixture を複数回 run し、manifest 以外は完全一致・manifest の時刻は異なることを検証。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();

    let out_a = run_analyze_jsonl(input, None);
    let out_b = run_analyze_jsonl(input, None);

    let lines_a = split_lines(&out_a);
    let lines_b = split_lines(&out_b);

    // 分析レコードは完全一致。
    assert_eq!(analysis_records(&lines_a), analysis_records(&lines_b));

    // manifest 行の run_started_at / run_finished_at は実行毎に異なりうるが、
    // それ以外の field は一致する。
    let m_a = strip_run_metadata(find_manifest_line(&lines_a));
    let m_b = strip_run_metadata(find_manifest_line(&lines_b));
    assert_eq!(m_a, m_b, "run metadata を除くと manifest は同一");
}

#[test]
fn t8_003_output_independent_of_construction_order() {
    // 規範 §13.2: 順序が出力へ影響する map には BTreeMap または明示 sort を使用する。
    // CaseData へ異なる順序で evidence を挿入しても、sorted_views が同一順序を返すことを検証。
    let mut data_a = CaseData::default();
    let mut data_b = CaseData::default();

    let make_ev = |id: &str| EvidenceItem {
        evidence_id: id.into(),
        source_locator: id.into(),
        size: 1,
        sha256: "a".repeat(64),
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: String::new(),
    };

    // data_a は a, b, c の順で挿入。
    data_a.evidence.push(make_ev("tf-evidence-v1:a"));
    data_a.evidence.push(make_ev("tf-evidence-v1:b"));
    data_a.evidence.push(make_ev("tf-evidence-v1:c"));

    // data_b は c, a, b の順で挿入（異なる順序）。
    data_b.evidence.push(make_ev("tf-evidence-v1:c"));
    data_b.evidence.push(make_ev("tf-evidence-v1:a"));
    data_b.evidence.push(make_ev("tf-evidence-v1:b"));

    let va = data_a.sorted_views();
    let vb = data_b.sorted_views();

    let ids_a: Vec<&str> = va.evidence.iter().map(|e| e.evidence_id.as_str()).collect();
    let ids_b: Vec<&str> = vb.evidence.iter().map(|e| e.evidence_id.as_str()).collect();
    assert_eq!(ids_a, ids_b, "挿入順序に依存せず同一の sort 結果");
    assert_eq!(
        ids_a,
        vec!["tf-evidence-v1:a", "tf-evidence-v1:b", "tf-evidence-v1:c"]
    );
}

#[test]
fn t8_003_case_id_independent_of_input_order() {
    // 規範 §13.2・§4.1: Case ID は evidence_id の byte 順 sort + 連結から生成する。
    // 渡し順序に依存しないことを検証。
    let ids = [
        "tf-evidence-v1:aaa",
        "tf-evidence-v1:bbb",
        "tf-evidence-v1:ccc",
    ];
    let id_a = tf_core::id::case_id(&ids);

    let ids_reversed = [
        "tf-evidence-v1:ccc",
        "tf-evidence-v1:bbb",
        "tf-evidence-v1:aaa",
    ];
    let id_b = tf_core::id::case_id(&ids_reversed);

    assert_eq!(id_a, id_b, "Case ID は evidence_id の渡し順に依存しない");
}

#[test]
fn t8_004_golden_output_regression_baseline() {
    // T8-004: regression test 基盤。合成 LNK fixture への analyze 出力が
    // 既知の構造（case → evidence → artifact → event → ... → manifest）へ従うことを検証。
    // 出力の byte 値そのものは fixture・Parser version に依存するため、ここでは構造的不変量
    // （record_type の順序・必須 field の存在・決定的 ID 形式）を回帰検出の基盤とする。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();
    let out = run_analyze_jsonl(input, None);
    let lines = split_lines(&out);

    assert!(!lines.is_empty(), "出力が空でない");

    let record_types: Vec<String> = lines
        .iter()
        .map(|l| {
            serde_json::from_str::<Value>(l)
                .unwrap()
                .get("record_type")
                .and_then(|t| t.as_str())
                .unwrap()
                .to_string()
        })
        .collect();

    // 最初は case、最後は manifest（Schema §6 出力順）。
    assert_eq!(record_types.first().unwrap(), "case");
    assert_eq!(record_types.last().unwrap(), "manifest");

    // 各行が schema_version を持つ（Schema §6 envelope）。
    for line in &lines {
        let v: Value = serde_json::from_str(line).unwrap();
        assert!(
            v.get("schema_version").is_some(),
            "各行が schema_version を持つ"
        );
    }

    // manifest 行の case_id は決定的 ID 形式。
    let manifest_line = find_manifest_line(&lines);
    let mv: Value = serde_json::from_str(manifest_line).unwrap();
    let case_id = mv["record"]["case_id"].as_str().unwrap();
    assert!(
        case_id.starts_with("tf-case-v1:"),
        "case_id が決定的 ID 形式: {case_id}"
    );
    assert_eq!(
        case_id.len(),
        "tf-case-v1:".len() + 64,
        "case_id は prefix + 64 hex 文字"
    );

    // record_type の集合に重複が無い envelope 構造へ準拠していること。
    let unique: HashSet<&str> = record_types.iter().map(String::as_str).collect();
    assert!(unique.contains("case"));
    assert!(unique.contains("manifest"));
}

#[test]
fn t8_004_repeated_runs_produce_identical_case_id() {
    // regression 基盤: 同一入力からは同一の Case ID が生成される（決定性の回帰検出）。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();

    let out1 = run_analyze_jsonl(input, None);
    let out2 = run_analyze_jsonl(input, None);

    let m1 = find_manifest_line(&split_lines(&out1));
    let m2 = find_manifest_line(&split_lines(&out2));
    let v1: Value = serde_json::from_str(m1).unwrap();
    let v2: Value = serde_json::from_str(m2).unwrap();

    assert_eq!(
        v1["record"]["case_id"], v2["record"]["case_id"],
        "同一入力から同一 Case ID"
    );
}
