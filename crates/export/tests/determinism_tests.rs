//! run metadata が分析 determinism へ影響しないことの test（規範 §13.1・§20・T7-033）。
//!
//! 規範 §13.1 は次を run metadata とし、同一性比較から除外することを定める:
//! - run started/finished time
//! - OS process ID
//! - temporary directory
//! - elapsed time
//! - CPU/RAM usage
//!
//! 同じ Case を2回分析した場合、run metadata 以外の全 field は同一であるべき。
//! 本 test は [`tf_export::manifest::finalize_manifest`] が生成する Manifest から
//! run metadata を取り除いた残りの部分が、異なる run 間で一致することを検証する。

use tf_export::manifest::{
    ManifestFinalizationInput, finalize_manifest, manifest_without_run_metadata,
};

fn sample_input(run_started: &str, run_finished: &str) -> ManifestFinalizationInput {
    ManifestFinalizationInput {
        traceforge_version: "0.1.0".into(),
        build_commit: "abc123".into(),
        target: "x86_64-pc-windows-msvc".into(),
        schema_version: "1.0.0".into(),
        compatibility_profile: "TF-WIN-1.0".into(),
        run_started_at: run_started.into(),
        run_finished_at: run_finished.into(),
        resolved_config: serde_json::json!({"analysis": {"recursive": true}}),
        case_id: "tf-case-v1:test".into(),
        counts: tf_core::manifest::ManifestCounts {
            evidence: 1,
            artifact: 2,
            event: 10,
            issue: 0,
            r#match: 0,
            finding: 0,
        },
        components: vec![serde_json::json!({"component": "tf-core", "version": "0.1.0"})],
        rules: vec![],
        attack_dataset: None,
        timezone_assumptions: vec![serde_json::json!({"assumption": "timezone 指定無し"})],
        limits: serde_json::json!({"max_events": 50_000_000}),
        incomplete_reasons: vec![],
        complete: true,
        exit_code: 0,
    }
}

#[test]
fn run_metadata_does_not_affect_analysis_determinism() {
    // 規範 §13.1: run 時刻・PID・temp dir 等は determinism 比較から除外する。
    let run_a = sample_input("2026-08-12T01:00:00Z", "2026-08-12T01:01:00Z");
    let run_b = sample_input("2026-12-31T23:59:59Z", "2027-01-01T00:00:01Z");

    let manifest_a = finalize_manifest(&run_a);
    let manifest_b = finalize_manifest(&run_b);

    // run 時刻を取り除けば、同一の分析結果であるべき。
    let a = manifest_without_run_metadata(&manifest_a);
    let b = manifest_without_run_metadata(&manifest_b);

    assert_eq!(a, b, "run metadata 以外は同一であるべき（規範 §13.1・§20）");
}

#[test]
fn different_analysis_produces_different_manifest() {
    // 一方で、実際に分析内容（counts・case_id 等）が異なれば Manifest も異なる。
    let run_a = sample_input("2026-08-12T01:00:00Z", "2026-08-12T01:01:00Z");
    let run_b = ManifestFinalizationInput {
        counts: tf_core::manifest::ManifestCounts {
            event: 999,
            ..run_a.counts
        },
        case_id: "tf-case-v1:different".into(),
        ..run_a.clone()
    };

    let manifest_a = finalize_manifest(&run_a);
    let manifest_b = finalize_manifest(&run_b);

    let a = manifest_without_run_metadata(&manifest_a);
    let b = manifest_without_run_metadata(&manifest_b);

    assert_ne!(a, b, "分析内容が異なれば Manifest も異なるべき");
}

#[test]
fn manifest_strips_only_run_metadata_fields() {
    // manifest_without_run_metadata は run_started_at / run_finished_at のみ取り除く。
    // build_commit や target は残す（これらは同じ binary なら同一なべき）。
    let input = sample_input("2026-08-12T01:00:00Z", "2026-08-12T01:01:00Z");
    let manifest = finalize_manifest(&input);
    let stripped = manifest_without_run_metadata(&manifest);

    let obj = stripped.as_object().unwrap();
    assert!(!obj.contains_key("run_started_at"));
    assert!(!obj.contains_key("run_finished_at"));
    // build_commit は残す（determinism 比較へ含む）。
    assert!(obj.contains_key("build_commit"));
    assert!(obj.contains_key("target"));
    assert!(obj.contains_key("traceforge_version"));
    assert!(obj.contains_key("resolved_config_sha256"));
}
