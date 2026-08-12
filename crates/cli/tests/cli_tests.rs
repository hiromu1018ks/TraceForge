//! CLI command の統合 test（Phase 7・T7-020〜T7-034）。
//!
//! 各 command を直接呼出し、stdout / stderr / Exit Code を検証する。
//! `--no-hash` 拒否（T7-022）・stdout/stderr 分離（T7-034）・version 表示（T7-030）
//! などを検証する。

use tf_cli::{
    BUILD_COMMIT, COMPATIBILITY_PROFILE, SCHEMA_VERSION_STR, TRACEFORGE_VERSION, parse_args, run,
};

fn args(parts: &[&str]) -> Vec<String> {
    let mut v = vec!["traceforge".to_string()];
    v.extend(parts.iter().map(|s| s.to_string()));
    v
}

/// CliResult の exit code を数値で取り出す（テスト用 helper）。
fn result_exit_code(result: &tf_cli::CliResult) -> i32 {
    result.exit_code.as_process_code()
}

#[test]
fn version_command_outputs_version_info() {
    // T7-030: tool・Schema・compatibility profile の version を出力する。
    let result = run(&args(&["version"]));
    assert_eq!(result.exit_code.as_process_code(), 0);
    assert!(
        result.stdout.contains(TRACEFORGE_VERSION),
        "stdout へ製品 version が含まれる: {}",
        result.stdout
    );
    assert!(result.stdout.contains(SCHEMA_VERSION_STR));
    assert!(result.stdout.contains(COMPATIBILITY_PROFILE));
    let _ = BUILD_COMMIT;
}

#[test]
fn no_hash_option_is_rejected() {
    // T7-022・規範 §2: `--no-hash` を提供してはならない。
    let r = parse_args(&args(&["analyze", "input", "--no-hash"]));
    assert!(r.is_err());
    if let Err(e) = r {
        assert!(matches!(e, tf_cli::CliParseError::NoHashForbidden));
    }
}

#[test]
fn no_hash_alone_is_rejected() {
    let r = parse_args(&args(&["--no-hash", "version"]));
    assert!(r.is_err());
}

#[test]
fn missing_command_returns_cli_error() {
    let r = run(&args(&[]));
    assert_eq!(
        result_exit_code(&r),
        tf_core::error::ExitCode::CliOrConfigError.as_process_code()
    );
    assert!(!r.stderr.is_empty());
}
#[test]
fn unknown_command_returns_cli_error() {
    let r = run(&args(&["unknown-command"]));
    assert_eq!(result_exit_code(&r), 2);
}

#[test]
fn quiet_does_not_suppress_results() {
    // T7-034: `--quiet` は stderr への log を抑制するが、解析結果（stdout）は抑制しない。
    let result = run(&args(&["--quiet", "version"]));
    assert_eq!(result.exit_code.as_process_code(), 0);
    assert!(
        !result.stdout.is_empty(),
        "--quiet でも stdout へ解析結果が出る"
    );
}

#[test]
fn analyze_missing_input_returns_error() {
    let r = run(&args(&["analyze"]));
    assert_eq!(result_exit_code(&r), 2);
}

#[test]
fn analyze_nonexistent_input_returns_error() {
    let r = run(&args(&["analyze", "/nonexistent/path/that/does/not/exist"]));
    assert_eq!(result_exit_code(&r), 3);
}

#[test]
fn export_nonexistent_case_returns_error() {
    let r = run(&args(&["export", "/nonexistent/case.json"]));
    assert_eq!(result_exit_code(&r), 3);
}

#[test]
fn timeline_nonexistent_case_returns_error() {
    let r = run(&args(&["timeline", "/nonexistent/case.json"]));
    assert_eq!(result_exit_code(&r), 3);
}

#[test]
fn inspect_nonexistent_file_returns_error() {
    let r = run(&args(&["inspect", "/nonexistent/file"]));
    assert_eq!(result_exit_code(&r), 3);
}

#[test]
fn rules_nonexistent_dir_returns_error() {
    let r = run(&args(&["rules", "/nonexistent/rules/"]));
    assert_eq!(result_exit_code(&r), 3);
}

#[test]
fn invalid_format_returns_cli_error() {
    let r = run(&args(&["export", "case.json", "--format", "unknown"]));
    assert_eq!(result_exit_code(&r), 2);
}

#[test]
fn inspect_real_file_outputs_summary() {
    use std::io::Write;
    use tempfile::tempdir;
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"hello world").unwrap();
    drop(f);

    let result = run(&args(&["inspect", path.to_str().unwrap()]));
    assert_eq!(result.exit_code.as_process_code(), 0);
    assert!(result.stdout.contains("size:"));
    assert!(result.stdout.contains("sha256:"));
    assert!(result.stdout.contains("read_only: true"));
}

#[test]
fn export_jsonl_to_csv_roundtrip() {
    // 簡易な Case JSON を作り、CSV へ変換する。
    use std::io::Write;
    use tempfile::tempdir;
    let dir = tempdir().unwrap();

    let case_json = format!(
        r#"{{
            "schema_version": "1.0.0",
            "record_type": "case_bundle",
            "case": {{
                "case_id": "tf-case-v1:test",
                "external_case_id": null,
                "name": "roundtrip test",
                "analyst": null,
                "description": null,
                "default_timezone": null,
                "tags": []
            }},
            "evidence": [],
            "artifacts": [],
            "events": [],
            "issues": [],
            "matches": [],
            "findings": [],
            "manifest": {{
                "traceforge_version": "0.1.0",
                "build_commit": "test",
                "target": "test",
                "schema_version": "{schema}",
                "compatibility_profile": "TF-WIN-1.0",
                "run_started_at": "2026-08-12T00:00:00Z",
                "run_finished_at": "2026-08-12T00:01:00Z",
                "resolved_config": {{}},
                "resolved_config_sha256": "{sha}",
                "case_id": "tf-case-v1:test",
                "counts": {{"evidence": 0, "artifact": 0, "event": 0, "issue": 0, "match": 0, "finding": 0}},
                "components": [],
                "rules": [],
                "attack_dataset": null,
                "timezone_assumptions": [],
                "limits": {{}},
                "incomplete_reasons": [],
                "complete": true,
                "exit_code": 0
            }}
        }}"#,
        schema = SCHEMA_VERSION_STR,
        sha = "a".repeat(64),
    );

    let case_path = dir.path().join("case.json");
    let mut f = std::fs::File::create(&case_path).unwrap();
    f.write_all(case_json.as_bytes()).unwrap();
    drop(f);

    let csv_path = dir.path().join("case.csv");
    let result = run(&args(&[
        "export",
        case_path.to_str().unwrap(),
        "--format",
        "csv",
        "--output",
        csv_path.to_str().unwrap(),
    ]));
    assert_eq!(
        result.exit_code.as_process_code(),
        0,
        "stderr: {}",
        result.stderr
    );
    assert!(csv_path.exists(), "CSV file が生成される");
    let csv_content = std::fs::read_to_string(&csv_path).unwrap();
    assert!(csv_content.contains("event_id"));
}

#[test]
fn stdout_contains_results_stderr_contains_log() {
    // T7-034: stdout = 解析結果、stderr = log。
    let result = run(&args(&["version"]));
    assert!(!result.stdout.is_empty(), "stdout に結果");
    // version command は log を出さないので stderr は空。
    assert!(result.stderr.is_empty() || result.stderr.contains("warning"));
}
