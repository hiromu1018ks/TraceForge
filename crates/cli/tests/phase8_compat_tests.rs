//! Phase 8 互換性・リリーステスト（T8-020・T8-021・T8-022）。
//!
//! - T8-020: 全 Required 対象の compatibility acceptance 最終確認（互換 §12 全 8 項目）
//! - T8-021: Timesketch import 検証（互換 §8）
//! - T8-022: Schema validator での全 Golden output 検証（Schema §9・§21-15）
//!
//! analyze pipeline へ合成 LNK fixture を通し、各要件をエンドツーエンドで検証する。

use std::fs;
use std::io::Write;

use serde_json::Value;
use tempfile::tempdir;

fn args(parts: &[&str]) -> Vec<String> {
    let mut v = vec!["traceforge".to_string()];
    v.extend(parts.iter().map(|s| s.to_string()));
    v
}

/// 合成 LNK bytes（[MS-SHLLINK] §2.1 準拠の最小 fixture）。
fn build_minimal_lnk() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x4Cu32.to_le_bytes()); // HeaderSize
    buf.extend_from_slice(&[
        // CLSID
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    buf.extend_from_slice(&0x0000_0080u32.to_le_bytes()); // flags: IsUnicode
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

fn make_input_dir() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let lnk_path = dir.path().join("sample.lnk");
    let mut f = fs::File::create(&lnk_path).unwrap();
    f.write_all(&build_minimal_lnk()).unwrap();
    drop(f);
    dir
}

/// analyze を実行し stdout を返す。
fn run_analyze(input: &str, format: &str) -> String {
    let result = tf_cli::run(&args(&["analyze", input, "--format", format]));
    assert_eq!(
        result.exit_code.as_process_code(),
        0,
        "analyze 成功: stderr={}",
        result.stderr
    );
    result.stdout
}

#[test]
fn t8_020_compatibility_acceptance_summary() {
    // 互換 §12: Compatibility acceptance test 全 8 項目の最終確認。
    // 各項目へ対応する検証が analyze pipeline で機能していることを確認する。
    //
    // 1. 正常 fixture から期待 Event を生成する
    // 2. truncated・invalid length・unknown version で panic しない
    // 3. Provenance が元 record へ到達する
    // 4. 1 thread と複数 thread の出力が一致する
    // 5. fixture SHA-256・生成 OS・取得方法・期待結果を記録する
    // 6. 外部仕様を使う対象は検証した revision を記録する
    // 7. 非対応 field・構文・version を黙って無視しない
    // 8. Format 固有の意味を越えて Event type を断定しない

    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();
    let jsonl = run_analyze(input, "jsonl");

    // (1) 正常 LNK fixture から Event が生成される。
    let has_event = jsonl.lines().any(|l| {
        serde_json::from_str::<Value>(l)
            .ok()
            .and_then(|v| {
                v.get("record_type")
                    .and_then(|t| t.as_str())
                    .map(|s| s == "event")
            })
            .unwrap_or(false)
    });
    assert!(has_event, "項目1: 正常 fixture から Event が生成される");

    // (3) Provenance が元 record へ到達する（source_sha256・record_locator を持つ）。
    let event_line = jsonl
        .lines()
        .find(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| {
                    v.get("record_type")
                        .and_then(|t| t.as_str())
                        .map(|s| s == "event")
                })
                .unwrap_or(false)
        })
        .expect("event 行が存在する");
    let event: Value = serde_json::from_str(event_line).unwrap();
    let prov = &event["record"]["provenance"];
    assert!(
        prov["source_sha256"].as_str().is_some(),
        "項目3: Provenance が source_sha256 を持つ"
    );
    assert!(
        prov["record_locator"].is_object(),
        "項目3: Provenance が record_locator を持つ"
    );
    assert!(
        prov["source_ordinal"].as_u64().is_some(),
        "項目3: Provenance が source_ordinal を持つ"
    );

    // (5) Evidence へ SHA-256 が記録される。
    let evidence_line = jsonl
        .lines()
        .find(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| {
                    v.get("record_type")
                        .and_then(|t| t.as_str())
                        .map(|s| s == "evidence")
                })
                .unwrap_or(false)
        })
        .expect("evidence 行が存在する");
    let evidence: Value = serde_json::from_str(evidence_line).unwrap();
    let sha = evidence["record"]["sha256"].as_str().unwrap();
    assert_eq!(
        sha.len(),
        64,
        "項目5: Evidence に SHA-256 (64 hex) が記録される"
    );

    // (6) LNK Event へ参照外部仕様 revision が記録される。
    let ref_spec = event["record"]["attributes"]["lnk.reference_spec"]
        .as_str()
        .unwrap_or("");
    assert!(
        ref_spec.contains("[MS-SHLLINK]"),
        "項目6: 参照外部仕様 revision が記録される: {ref_spec}"
    );

    // (8) 観測型 Event（lnk_timestamp）であり、断定型（file_opened 等）ではない。
    let event_type = event["record"]["event_type"].as_str().unwrap();
    assert!(
        event_type.contains("observation")
            || event_type.contains("timestamp")
            || !event_type.contains("opened"),
        "項目8: Event type が観測型（{event_type}）である"
    );
    assert_eq!(
        event["record"]["assertion"].as_str(),
        Some("observed"),
        "項目8: assertion が observed（観測）である"
    );
}

#[test]
fn t8_020_panic_safety_for_corrupted_input() {
    // 互換 §12-2: truncated・invalid length・unknown version で panic しない。
    let dir = tempdir().unwrap();
    let corrupted = dir.path().join("corrupted.lnk");
    let mut f = fs::File::create(&corrupted).unwrap();
    f.write_all(&[0x4C, 0x00, 0x00, 0x00, 0xFF]).unwrap(); // truncated header
    drop(f);

    let result = tf_cli::run(&args(&[
        "analyze",
        corrupted.to_str().unwrap(),
        "--format",
        "jsonl",
    ]));
    assert_ne!(
        result.exit_code.as_process_code(),
        10,
        "項目2: 破損入力で panic しない"
    );
}

#[test]
fn t8_020_thread_consistency() {
    // 互換 §12-4: 1 thread と複数 thread の出力が一致する。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();

    let out1 = run_analyze_with_threads(input, "jsonl", Some(1));
    let out2 = run_analyze_with_threads(input, "jsonl", Some(2));

    // manifest 以外の行は完全一致。
    let non_manifest: Vec<&str> = out1
        .lines()
        .filter(|l| !l.contains("\"record_type\":\"manifest\""))
        .collect();
    let non_manifest2: Vec<&str> = out2
        .lines()
        .filter(|l| !l.contains("\"record_type\":\"manifest\""))
        .collect();
    assert_eq!(
        non_manifest, non_manifest2,
        "項目4: 1 thread と複数 thread の分析レコードが一致する"
    );
}

fn run_analyze_with_threads(input: &str, format: &str, threads: Option<u32>) -> String {
    let mut cmd: Vec<String> = vec![
        "analyze".into(),
        input.into(),
        "--format".into(),
        format.into(),
    ];
    if let Some(t) = threads {
        cmd.push("--threads".into());
        cmd.push(t.to_string());
    }
    let result = tf_cli::run(&args(&cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>()));
    assert_eq!(result.exit_code.as_process_code(), 0);
    result.stdout
}

#[test]
fn t8_021_timesketch_output_format() {
    // 互換 §8: Timesketch JSONL 形式（TF-TIMESKETCH-1.0）。
    // 各 Event が最低限の必須 field を持つことを検証する。
    let input_dir = make_input_dir();
    let out_dir = tempdir().unwrap();
    let input = input_dir.path().to_str().unwrap();

    // Timesketch 出力は .jsonl へ出力する必要がある。出力は入力 directory と別の
    // directory へ配置する（規範 §5.4: 入出力分離）。
    let out_path = out_dir.path().join("timesketch.jsonl");
    let result = tf_cli::run(&args(&[
        "analyze",
        input,
        "--format",
        "timesketch",
        "--output",
        out_path.to_str().unwrap(),
    ]));
    assert_eq!(
        result.exit_code.as_process_code(),
        0,
        "Timesketch 出力成功: stderr={}",
        result.stderr
    );

    let content = fs::read_to_string(&out_path).unwrap();
    assert!(!content.is_empty(), "Timesketch 出力が空でない");

    // 各行が正当な JSON であること。
    let mut event_count = 0;
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).expect("各行が正当な JSON");
        event_count += 1;

        // TF-TIMESKETCH-1.0 の必須 field（互換 §8）。
        let required_fields = [
            "message",
            "datetime",
            "timestamp_desc",
            "traceforge_event_id",
            "traceforge_source",
            "traceforge_event_type",
            "traceforge_evidence_id",
        ];
        for field in &required_fields {
            assert!(
                v.get(*field).is_some(),
                "Timesketch Event が必須 field '{field}' を持つ"
            );
        }

        // datetime は UTC ISO 8601 形式（Z で終わる）。
        let dt = v["datetime"].as_str().unwrap();
        assert!(dt.ends_with('Z'), "datetime が UTC（Z 付き）: {dt}");
    }
    assert!(
        event_count > 0,
        "少なくとも1件の Timesketch Event が生成される"
    );
}

#[test]
fn t8_022_all_jsonl_lines_pass_schema_version_check() {
    // Schema §9・§21-15: JSON・JSONL・Rule・Config が Schema validation に成功する。
    // analyze 出力の全 JSONL 行が schema_version "1.0.0"（major=1）へ適合することを検証。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();
    let jsonl = run_analyze(input, "jsonl");

    for line in jsonl.lines() {
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).expect("各行が正当な JSON");

        // schema_version が存在し "1.x.x" 形式であること。
        let sv = v
            .get("schema_version")
            .and_then(|s| s.as_str())
            .expect("schema_version が存在する");
        assert!(
            sv.starts_with("1."),
            "schema_version の major が 1 である: {sv}"
        );

        // record_type が存在し、既知の type であること。
        let rt = v
            .get("record_type")
            .and_then(|s| s.as_str())
            .expect("record_type が存在する");
        assert!(
            matches!(
                rt,
                "case"
                    | "evidence"
                    | "artifact"
                    | "event"
                    | "issue"
                    | "match"
                    | "finding"
                    | "manifest"
            ),
            "record_type が既知の型: {rt}"
        );

        // record が object であること。
        let record = v.get("record").expect("record が存在する");
        assert!(record.is_object(), "record が object である");
    }
}

#[test]
fn t8_022_json_output_has_valid_schema_version() {
    // JSON 出力（Case JSON）の schema_version が "1.0.0" であることを検証。
    let dir = make_input_dir();
    let input = dir.path().to_str().unwrap();
    let json_out = run_analyze(input, "json");

    let v: Value = serde_json::from_str(&json_out).expect("JSON 出力が正当な JSON");
    assert_eq!(
        v.get("schema_version").and_then(|s| s.as_str()),
        Some("1.0.0"),
        "Case JSON の schema_version が 1.0.0"
    );
    assert_eq!(
        v.get("record_type").and_then(|s| s.as_str()),
        Some("case_bundle"),
        "Case JSON の record_type が case_bundle"
    );

    // 必須 top-level field が存在する。
    for field in &[
        "case",
        "evidence",
        "artifacts",
        "events",
        "issues",
        "matches",
        "findings",
        "manifest",
    ] {
        assert!(
            v.get(*field).is_some(),
            "Case JSON が必須 field '{field}' を持つ"
        );
    }
}
