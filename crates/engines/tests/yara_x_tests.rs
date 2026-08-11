//! Phase 5 YARA-X 編の受け入れテスト（T5-020〜T5-027）。
//!
//! 互換 §7（YARA-X Compatibility Profile）・規範 §15.2（YARA-X）・Schema §8.2/8.3 の
//! 受け入れ条件を統合テストとして検証する。unit test と重複する項目もあるが、
//! `tf-engines` の公開 API を通した end-to-end の振る舞いを改めて確認する。
//!
//! 対象:
//! - T5-020: YARA-X crate pin + Cargo.lock checksum（互換 §7）
//! - T5-021: `.yar` / `.yara` file・directory 再帰 load（互換 §7）
//! - T5-022: tags / meta / namespace / matched pattern identifier 保持
//!   （互換 §7・Schema §5.7）
//! - T5-023: compile error 時の file 全体無効化・他 file 継続（規範 §15.2）
//! - T5-024: Verified Snapshot のみ scan・実行時 load 禁止（規範 §15.2）
//! - T5-025: `all` / `suspicious` / `explicit` mode（Schema §8.3・規範 §15.2）
//! - T5-026: suspicious mode の Evidence ID 解決・host path 推測 scan 禁止
//!   （規範 §15.2・§21-13）
//! - T5-027: `max_yara_scan_file_size_bytes` 適用（Schema §8.2）

use std::fs;
use std::path::{Path, PathBuf};

use tf_core::case::{EvidenceItem, IntegrityStatus};
use tf_core::config::YaraMode;
use tf_core::r#match::MatchType;
use tf_engines::yara::scanner::{
    YaraEvidenceScanTarget, YaraScanMode, YaraScanner, select_evidence_for_mode,
};
use tf_engines::{
    CompiledYaraFile, RuleLoadOptions, RuleRegistry, YaraRuleset, YaraRulesetCompileSummary,
    yara_x_engine_version,
};

/// 一時 directory を作成し、その path を返す。
fn make_tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("一時 directory の作成に失敗")
}

/// `dir` 配下へ file を作成し、内容を書き込む。必要な subdirectory も作成する。
fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).unwrap();
    path
}

/// directory 内の全 `.yar`/`.yara` file を registry へ読み込む。
fn load_yara_directory(dir: &Path) -> RuleRegistry {
    let mut registry = RuleRegistry::new();
    registry
        .load_directory(dir, &RuleLoadOptions::default())
        .expect("directory 読込成功");
    registry
}

/// YARA-X の典型的な rule を1 file へ書き出し、compile まで実行するヘルパ。
fn compile_simple_dir(rule_source: &str) -> (tempfile::TempDir, YaraRulesetCompileSummary) {
    let dir = make_tmpdir();
    write_file(dir.path(), "rule.yar", rule_source.as_bytes());
    let registry = load_yara_directory(dir.path());
    let summary = YaraRuleset::compile_from_registry(&registry);
    (dir, summary)
}

fn make_evidence(evidence_id: &str, integrity: IntegrityStatus) -> EvidenceItem {
    EvidenceItem {
        evidence_id: evidence_id.to_string(),
        source_locator: format!("evidence/{evidence_id}"),
        size: 0,
        sha256: "a".repeat(64),
        integrity_status: integrity,
        parse_eligible: integrity == IntegrityStatus::VerifiedSnapshot,
        snapshot_locator: String::new(),
    }
}

// ============================================================================
// T5-020: YARA-X crate pin + Cargo.lock checksum（互換 §7）
// ============================================================================

#[test]
fn acceptance_t5_020_yara_x_engine_version_recorded() {
    // 互換 §7: TraceForge release は使用する YARA-X crate の完全 version と
    // Cargo.lock checksum を Manifest へ記録する。`latest` を使ってはならない。
    let version = yara_x_engine_version();
    assert!(!version.is_empty());
    assert_ne!(version, "latest", "互換 §7: latest 使用禁止");
    // 完全 version は数字始まり（例: "1.19.0"）。
    assert!(
        version.chars().next().unwrap().is_ascii_digit(),
        "完全 version であること: {version}"
    );
}

// ============================================================================
// T5-021: `.yar` / `.yara` file・directory 再帰 load（互換 §7）
// ============================================================================

#[test]
fn acceptance_t5_021_yar_extension_loaded() {
    let dir = make_tmpdir();
    write_file(dir.path(), "rule.yar", b"rule r { condition: true }");

    let registry = load_yara_directory(dir.path());
    assert_eq!(registry.len(), 1);

    let summary = YaraRuleset::compile_from_registry(&registry);
    assert_eq!(summary.compiled_len(), 1);
}

#[test]
fn acceptance_t5_021_yara_extension_loaded() {
    let dir = make_tmpdir();
    write_file(dir.path(), "rule.yara", b"rule r { condition: true }");

    let registry = load_yara_directory(dir.path());
    assert_eq!(registry.len(), 1);

    let summary = YaraRuleset::compile_from_registry(&registry);
    assert_eq!(summary.compiled_len(), 1);
}

#[test]
fn acceptance_t5_021_recursive_directory_load() {
    // directory 再帰走査は共通編の RuleRegistry が実装済み。
    // YARA-X engine は registry が読み込んだ file を全て受け入れる。
    let dir = make_tmpdir();
    write_file(dir.path(), "top.yar", b"rule top { condition: true }");
    write_file(
        dir.path(),
        "sub/child.yar",
        b"rule child { condition: true }",
    );
    write_file(
        dir.path(),
        "sub/deep/grandchild.yar",
        b"rule grandchild { condition: true }",
    );

    let registry = load_yara_directory(dir.path());
    assert_eq!(registry.len(), 3, "再帰的に3 file を読み込む");

    let summary = YaraRuleset::compile_from_registry(&registry);
    assert_eq!(summary.compiled_len(), 3, "全 file が compile 成功");
}

// ============================================================================
// T5-022: tags / meta / namespace / matched pattern identifier 保持
// ============================================================================

#[test]
fn acceptance_t5_022_match_preserves_all_yara_metadata() {
    // 互換 §7: tags・meta・namespace・matched pattern identifier を保持する。
    let (_dir, summary) = compile_simple_dir(
        r#"
        rule traceforge_full : author_tag severity_tag {
            meta:
                author = "TraceForge Test"
                severity = 5
                active = true
            strings:
                $a = "secret"
                $b = { 48 65 6C 6C 6F }
            condition:
                $a or $b
        }
        "#,
    );
    let ruleset = summary.into_ruleset();
    let scanner = YaraScanner::new(ruleset, 1024 * 1024);

    // "secret" を含む snapshot bytes を scan。
    let target = YaraEvidenceScanTarget {
        evidence_id: "tf-evidence-v1:e1".into(),
        snapshot_bytes: b"this is a secret payload",
    };

    let results = scanner.scan(&[target]);
    assert_eq!(results.matches.len(), 1, "1 rule が match");

    let m = &results.matches[0].match_value;
    assert_eq!(m.match_type, MatchType::YaraX);
    assert_eq!(m.rule_id, "traceforge_full");
    assert_eq!(m.evidence_ids, vec!["tf-evidence-v1:e1".to_string()]);
    assert!(m.event_ids.is_empty(), "YARA match は event を参照しない");

    // matched_patterns 拡張 field に tags / namespace / meta / pattern が保持される。
    let mp = m
        .matched_patterns
        .as_ref()
        .expect("YARA match は matched_patterns を持つ");
    let root = mp.as_object().expect("matched_patterns は JSON object");
    let rule = root["rule"].as_object().unwrap();
    assert_eq!(rule["identifier"], "traceforge_full");
    assert_eq!(rule["namespace"], "default");

    let tags = rule["tags"].as_array().unwrap();
    assert_eq!(tags.len(), 2, "tags 2件");
    assert!(tags.iter().any(|t| t == "author_tag"));
    assert!(tags.iter().any(|t| t == "severity_tag"));

    let meta = rule["metadata"].as_object().unwrap();
    assert_eq!(meta["author"], "TraceForge Test");
    assert_eq!(meta["severity"], 5);
    assert_eq!(meta["active"], true);

    // patterns に $a (text) が含まれる（$b hex も match する可能性があるが、
    // いずれか1件以上の pattern identifier を保持する）。
    let patterns = root["patterns"].as_array().unwrap();
    assert!(!patterns.is_empty(), "matched pattern が1件以上");
    let pattern_ids: Vec<&str> = patterns
        .iter()
        .map(|p| p["identifier"].as_str().unwrap())
        .collect();
    assert!(pattern_ids.contains(&"$a"), "$a が含まれる");
}

// ============================================================================
// T5-023: compile error 時の file 全体無効化・他 file 継続（規範 §15.2）
// ============================================================================

#[test]
fn acceptance_t5_023_compile_error_disables_only_that_file() {
    // 規範 §15.2: Rule compile error が1件でもある Rule file は、その file 全体を無効とする。
    // 他の正常 Rule file は strict rules mode でない限り継続できる。
    let dir = make_tmpdir();
    write_file(dir.path(), "good1.yar", b"rule good1 { condition: true }");
    write_file(
        dir.path(),
        "bad.yar",
        b"rule bad { condition: this is invalid syntax }",
    );
    write_file(dir.path(), "good2.yar", b"rule good2 { condition: true }");

    let registry = load_yara_directory(dir.path());
    let summary = YaraRuleset::compile_from_registry(&registry);

    // good1 と good2 は compile 成功、bad は error。
    assert_eq!(summary.compiled_len(), 2, "正常 file 2件は継続");
    assert_eq!(summary.error_len(), 1, "compile error file 1件");
}

#[test]
fn acceptance_t5_023_compile_error_in_file_propagates_to_whole_file() {
    // 規範 §15.2: file 内の1 rule でも compile error があれば file 全体を無効化。
    let dir = make_tmpdir();
    write_file(
        dir.path(),
        "mixed.yar",
        b"
        rule ok1 { condition: true }
        rule ok2 { condition: true }
        rule broken { condition: unknown_identifier }
        ",
    );

    let registry = load_yara_directory(dir.path());
    let summary = YaraRuleset::compile_from_registry(&registry);

    assert_eq!(summary.compiled_len(), 0, "file 全体無効化（部分評価禁止）");
    assert_eq!(summary.error_len(), 1);
}

// ============================================================================
// T5-024: Verified Snapshot のみ scan・実行時 load 禁止（規範 §15.2）
// ============================================================================

#[test]
fn acceptance_t5_024_scanner_uses_only_snapshot_bytes() {
    // 規範 §15.2: scan 対象を実行、load、shell open してはならない。
    // YaraScanner は &[u8] のみを受け取り、file I/O を全く行わない。
    let (_dir, summary) = compile_simple_dir(r#"rule r { strings: $a = "match" condition: $a }"#);
    let scanner = YaraScanner::new(summary.into_ruleset(), 1024 * 1024);

    // bytes のみを渡す。file path ではない。
    let target = YaraEvidenceScanTarget {
        evidence_id: "tf-evidence-v1:e1".into(),
        snapshot_bytes: b"contains match keyword",
    };

    let results = scanner.scan(&[target]);
    assert_eq!(results.matches.len(), 1);
}

// ============================================================================
// T5-025: `all` / `suspicious` / `explicit` mode（Schema §8.3・規範 §15.2）
// ============================================================================

#[test]
fn acceptance_t5_025_mode_all_selects_all_verified() {
    let evidence = vec![
        make_evidence("tf-evidence-v1:ev1", IntegrityStatus::VerifiedSnapshot),
        make_evidence("tf-evidence-v1:ev2", IntegrityStatus::VerifiedSnapshot),
    ];

    let (selected, warnings) = select_evidence_for_mode(YaraScanMode::All, &evidence, &[], &[]);
    assert_eq!(selected.len(), 2);
    assert!(warnings.is_empty());
}

#[test]
fn acceptance_t5_025_mode_suspicious_selects_only_listed() {
    let evidence = vec![
        make_evidence("tf-evidence-v1:ev1", IntegrityStatus::VerifiedSnapshot),
        make_evidence("tf-evidence-v1:ev2", IntegrityStatus::VerifiedSnapshot),
    ];

    let suspicious_ids = vec!["tf-evidence-v1:ev1".to_string()];
    let (selected, _) =
        select_evidence_for_mode(YaraScanMode::Suspicious, &evidence, &suspicious_ids, &[]);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].evidence_id, "tf-evidence-v1:ev1");
}

#[test]
fn acceptance_t5_025_mode_explicit_selects_only_listed() {
    let evidence = vec![
        make_evidence("tf-evidence-v1:ev1", IntegrityStatus::VerifiedSnapshot),
        make_evidence("tf-evidence-v1:ev2", IntegrityStatus::VerifiedSnapshot),
    ];

    let explicit_ids = vec!["tf-evidence-v1:ev2".to_string()];
    let (selected, _) =
        select_evidence_for_mode(YaraScanMode::Explicit, &evidence, &[], &explicit_ids);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].evidence_id, "tf-evidence-v1:ev2");
}

#[test]
fn acceptance_t5_025_yara_mode_to_scan_mode_conversion() {
    // Schema §8.3 の YaraMode enum と内部 YaraScanMode の変換。
    assert_eq!(YaraScanMode::from(YaraMode::All), YaraScanMode::All);
    assert_eq!(
        YaraScanMode::from(YaraMode::Suspicious),
        YaraScanMode::Suspicious
    );
    assert_eq!(
        YaraScanMode::from(YaraMode::Explicit),
        YaraScanMode::Explicit
    );
}

// ============================================================================
// T5-026: suspicious mode の Evidence ID 解決・host path 推測 scan 禁止（§21-13）
// ============================================================================

#[test]
fn acceptance_t5_026_unresolved_evidence_id_does_not_guess_host_path() {
    // 規範 §21-13: Evidence ID へ解決できない path を推測で local filesystem から
    // scan してはならない。本関数は Evidence ID list のみを受け付け、Windows path
    // からの推測は一切行わない。
    let evidence = vec![make_evidence(
        "tf-evidence-v1:ev1",
        IntegrityStatus::VerifiedSnapshot,
    )];

    // ev_unknown は存在しない。Warning となり、推測で scan 対象へは追加されない。
    let suspicious_ids = vec![
        "tf-evidence-v1:ev1".to_string(),
        "tf-evidence-v1:ev_unknown".to_string(),
    ];
    let (selected, warnings) =
        select_evidence_for_mode(YaraScanMode::Suspicious, &evidence, &suspicious_ids, &[]);

    assert_eq!(selected.len(), 1, "解決できた ID のみ");
    assert_eq!(warnings.len(), 1, "未解決 ID は warning");
    assert!(
        warnings[0].message.contains("host path 推測禁止"),
        "推測禁止の旨を明記: {}",
        warnings[0].message
    );
}

#[test]
fn acceptance_t5_026_non_verified_evidence_excluded_in_all_modes() {
    // 規範 §15.2・T5-024: Verified Snapshot 以外の Evidence は全 mode で除外する。
    let evidence = vec![
        make_evidence(
            "tf-evidence-v1:changed",
            IntegrityStatus::ChangedDuringSnapshot,
        ),
        make_evidence("tf-evidence-v1:failed", IntegrityStatus::SnapshotFailed),
        make_evidence("tf-evidence-v1:good", IntegrityStatus::VerifiedSnapshot),
    ];

    // all mode でも VerifiedSnapshot のみ。
    let (selected_all, _) = select_evidence_for_mode(YaraScanMode::All, &evidence, &[], &[]);
    assert_eq!(selected_all.len(), 1);
    assert_eq!(selected_all[0].evidence_id, "tf-evidence-v1:good");

    // suspicious mode で未確認 Evidence を要求しても Warning となる。
    let suspicious_ids = vec![
        "tf-evidence-v1:changed".to_string(),
        "tf-evidence-v1:failed".to_string(),
        "tf-evidence-v1:good".to_string(),
    ];
    let (selected_susp, warnings_susp) =
        select_evidence_for_mode(YaraScanMode::Suspicious, &evidence, &suspicious_ids, &[]);
    assert_eq!(selected_susp.len(), 1, "VerifiedSnapshot のみ");
    assert_eq!(warnings_susp.len(), 2, "未検証 Evidence は warning");
}

// ============================================================================
// T5-027: `max_yara_scan_file_size_bytes` 適用（Schema §8.2）
// ============================================================================

#[test]
fn acceptance_t5_027_oversize_evidence_is_skipped_with_warning() {
    // Schema §8.2: max_yara_scan_file_size_bytes 上限を超える Evidence は skip。
    // 規範 §18: 上限を超えた結果を黙って切り捨てない。
    let (_dir, summary) = compile_simple_dir(r#"rule r { condition: true }"#);
    // 上限を 5 bytes に設定し、簡単に超過させる。
    let scanner = YaraScanner::new(summary.into_ruleset(), 5);

    let oversize_target = YaraEvidenceScanTarget {
        evidence_id: "tf-evidence-v1:big".into(),
        snapshot_bytes: b"0123456789ABCDEF", // 16 bytes > 5
    };

    let results = scanner.scan(&[oversize_target]);
    assert!(results.matches.is_empty(), "oversize は scan しない");
    assert_eq!(results.skipped.len(), 1, "skip を記録");
    assert_eq!(results.skipped[0].evidence_id, "tf-evidence-v1:big");
    assert_eq!(
        results.skipped[0].code,
        "TF-W-LIMIT-MAX-YARA-SCAN-FILE-SIZE-BYTES"
    );
}

#[test]
fn acceptance_t5_027_at_limit_boundary_is_scanned() {
    // size == limit の場合は scan 対象（厳密に「超える」場合のみ skip）。
    let (_dir, summary) = compile_simple_dir(r#"rule r { condition: true }"#);
    let scanner = YaraScanner::new(summary.into_ruleset(), 5);

    let exact_target = YaraEvidenceScanTarget {
        evidence_id: "tf-evidence-v1:exact".into(),
        snapshot_bytes: b"hello", // 5 bytes == limit
    };

    let results = scanner.scan(&[exact_target]);
    assert_eq!(results.matches.len(), 1, "limit と同 size は scan");
    assert!(results.skipped.is_empty());
}

// ============================================================================
// 決定性: 同一入力は同一結果（規範 §13）
// ============================================================================

#[test]
fn acceptance_yara_deterministic_match_id_for_same_input() {
    // 規範 §12.4: 決定的 Match ID 生成。同一 Rule・同一 Evidence は同一 Match ID。
    let dir = make_tmpdir();
    write_file(
        dir.path(),
        "rule.yar",
        b"rule traceforge_det { strings: $a = \"abc\" condition: $a }",
    );
    let registry = load_yara_directory(dir.path());
    let summary = YaraRuleset::compile_from_registry(&registry);
    let scanner = YaraScanner::new(summary.into_ruleset(), 1024);

    let target = YaraEvidenceScanTarget {
        evidence_id: "tf-evidence-v1:e1".into(),
        snapshot_bytes: b"abc abc abc",
    };
    let targets = [target];

    let results1 = scanner.scan(&targets);
    let results2 = scanner.scan(&targets);

    assert_eq!(results1.matches.len(), 1);
    assert_eq!(results2.matches.len(), 1);
    assert_eq!(
        results1.matches[0].match_value.match_id, results2.matches[0].match_value.match_id,
        "決定的 Match ID"
    );
    // Match ID は Schema §3.1 の pattern に合致。
    assert!(tf_core::id::is_valid_id(
        &results1.matches[0].match_value.match_id
    ));
}

// ============================================================================
// 公開 API: CompiledYaraFile accessor
// ============================================================================

#[test]
fn acceptance_yara_compiled_file_rules_accessor() {
    // CompiledYaraFile::rules() は yara-x の Rules への参照を返す。
    let (_dir, summary) = compile_simple_dir(r#"rule r { condition: true }"#);
    let compiled: Vec<&CompiledYaraFile> = summary.compiled_iter().collect();
    assert_eq!(compiled.len(), 1);
    // rules() へ accessor を通じてアクセスできる（scan のために公開）。
    let _rules = compiled[0].rules();
}
