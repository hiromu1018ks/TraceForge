//! Phase 5 共通編の受け入れテスト（T5-001〜T5-003）。
//!
//! 規範 §14（Correlation Rule）・§17.2（Exit Code）の受け入れ条件を統合テストとして
//! 検証する。unit test と重複する項目もあるが、`tf-engines` の公開 API を通した
//! end-to-end の振る舞いを改めて確認する。
//!
//! 対象:
//! - T5-001: Rule file 1回読み込み・raw bytes SHA-256・再読込禁止（規範 §14）
//! - T5-002: Rule directory 列挙順の正規化（UTF-8 byte 順、規範 §14）
//! - T5-003: Rule validation error の Exit Code 5 対応（規範 §17.2）

use std::fs;
use std::path::{Path, PathBuf};

use tf_core::error::ExitCode;
use tf_core::hash::{is_lowercase_sha256_hex, sha256_hex};
use tf_engines::{
    RuleLoadError, RuleLoadOptions, RuleLoadSummary, RulePathError, RuleRegistry,
    discover_rule_directory,
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

// ============================================================================
// T5-001: Rule file 1回読み込み・raw bytes SHA-256・再読込禁止（規範 §14）
// ============================================================================

#[test]
fn acceptance_t5_001_rule_file_is_read_once_and_sha256_computed() {
    // 規範 §14: 「1回だけ bytes として読み込み、その raw bytes の SHA-256 を計算」
    let dir = make_tmpdir();
    let content = b"title: Acceptance\ndetection:\n  condition: selection\n";
    let path = write_file(dir.path(), "rule.yml", content);

    let mut registry = RuleRegistry::new();
    let loaded = registry
        .load(&path, dir.path(), &RuleLoadOptions::default())
        .expect("読込成功")
        .expect("新規 file なので読み込まれる");

    // raw bytes と SHA-256 の整合性。
    assert_eq!(loaded.raw_bytes(), content);
    assert_eq!(loaded.sha256, sha256_hex(content));
    assert!(is_lowercase_sha256_hex(&loaded.sha256));
    assert_eq!(loaded.size, content.len() as u64);
}

#[test]
fn acceptance_t5_001_same_content_in_multiple_paths_loaded_once() {
    // 規範 §14: 同一内容が複数 path へ現れても1回だけ読み込む。
    let dir = make_tmpdir();
    let shared = b"detection:\n  selection:\n    Field: value\n  condition: selection\n";
    write_file(dir.path(), "sigma/a.yml", shared);
    write_file(dir.path(), "sigma/b.yml", shared);
    write_file(dir.path(), "sigma/c.yml", shared);

    let mut registry = RuleRegistry::new();
    let summary = registry
        .load_directory(dir.path(), &RuleLoadOptions::default())
        .unwrap();

    assert_eq!(summary.loaded.len(), 1, "3 file のうち1件のみ新規読込");
    assert_eq!(summary.skipped_duplicates.len(), 2, "2件は重複で skip");
    assert_eq!(registry.len(), 1);
}

#[test]
fn acceptance_t5_001_reload_during_evaluation_prohibited() {
    // 規範 §14: 「評価中に Rule file を再読込してはならない」
    // load_directory を複数回呼んでも、既読 file は再読込されない。
    let dir = make_tmpdir();
    let content = b"rule content";
    write_file(dir.path(), "rule.yml", content);

    let mut registry = RuleRegistry::new();
    let first = registry
        .load_directory(dir.path(), &RuleLoadOptions::default())
        .unwrap();
    let second = registry
        .load_directory(dir.path(), &RuleLoadOptions::default())
        .unwrap();

    assert_eq!(first.loaded.len(), 1);
    assert_eq!(
        second.loaded.len(),
        0,
        "2回目は全件重複で再読込禁止（規範 §14）"
    );
    assert_eq!(second.skipped_duplicates.len(), 1);
    assert_eq!(registry.len(), 1);
}

#[test]
fn acceptance_t5_001_loaded_rule_file_holds_raw_bytes_for_reuse() {
    // 規範 §14: 「同じ bytes を parse または compile しなければならない」
    // LoadedRuleFile.raw_bytes が registry から借用できることを確認。
    let dir = make_tmpdir();
    let content = b"parse target bytes";
    let path = write_file(dir.path(), "rule.yml", content);

    let mut registry = RuleRegistry::new();
    registry
        .load(&path, dir.path(), &RuleLoadOptions::default())
        .unwrap();

    let borrowed: Vec<&[u8]> = registry.iter().map(|r| r.raw_bytes()).collect();
    assert_eq!(borrowed.len(), 1);
    assert_eq!(borrowed[0], content);
}

// ============================================================================
// T5-002: Rule directory 列挙順の正規化（UTF-8 byte 順、規範 §14）
// ============================================================================

#[test]
fn acceptance_t5_002_directory_enumeration_is_utf8_byte_sorted() {
    // 規範 §14: 「Rule directory の列挙順は正規化相対 path の UTF-8 byte 順とする」
    let dir = make_tmpdir();
    // 逆順で作成しても結果は byte 昇順。
    write_file(dir.path(), "zeta.yml", b"z");
    write_file(dir.path(), "alpha.yml", b"a");
    write_file(dir.path(), "middle.yml", b"m");

    let outcome = discover_rule_directory(dir.path(), &Default::default()).unwrap();
    let rels: Vec<&str> = outcome
        .files
        .iter()
        .map(|f| f.relative_path.as_str())
        .collect();
    assert_eq!(
        rels,
        vec!["alpha.yml", "middle.yml", "zeta.yml"],
        "UTF-8 byte 順へ正規化される（規範 §14）"
    );
}

#[test]
fn acceptance_t5_002_enumeration_independent_of_filesystem_order() {
    // 規範 §14: filesystem が返す列挙順には依存しない。
    // 複数回・異なる作成順で結果が同一になることを検証。
    let expected = vec!["a.yml", "b.yml", "c.yml"];

    let dir1 = make_tmpdir();
    write_file(dir1.path(), "c.yml", b"c");
    write_file(dir1.path(), "a.yml", b"a");
    write_file(dir1.path(), "b.yml", b"b");
    let o1 = discover_rule_directory(dir1.path(), &Default::default()).unwrap();

    let dir2 = make_tmpdir();
    write_file(dir2.path(), "a.yml", b"a");
    write_file(dir2.path(), "b.yml", b"b");
    write_file(dir2.path(), "c.yml", b"c");
    let o2 = discover_rule_directory(dir2.path(), &Default::default()).unwrap();

    let r1: Vec<&str> = o1.files.iter().map(|f| f.relative_path.as_str()).collect();
    let r2: Vec<&str> = o2.files.iter().map(|f| f.relative_path.as_str()).collect();
    assert_eq!(r1, expected);
    assert_eq!(r2, expected);
}

#[test]
fn acceptance_t5_002_recursive_subdirectory_order() {
    // subdirectory を含む場合も root からの相対 path で sort される。
    let dir = make_tmpdir();
    write_file(dir.path(), "y.yml", b"y");
    write_file(dir.path(), "a_dir/m.yml", b"m");
    write_file(dir.path(), "a_dir/a.yml", b"a");
    write_file(dir.path(), "b_dir/z.yml", b"z");

    let outcome = discover_rule_directory(dir.path(), &Default::default()).unwrap();
    let rels: Vec<&str> = outcome
        .files
        .iter()
        .map(|f| f.relative_path.as_str())
        .collect();
    // `/` (0x2F) は英字より小さいため "a_dir/a.yml" < "y.yml" だが
    // "a_dir/m.yml" < "a_dir/a.yml" ではない（m > a）。
    assert_eq!(
        rels,
        vec!["a_dir/a.yml", "a_dir/m.yml", "b_dir/z.yml", "y.yml"]
    );
}

#[test]
fn acceptance_t5_002_windows_backslash_normalized() {
    // Windows 上で `\` separator が使われていても `/` へ正規化される。
    let dir = make_tmpdir();
    write_file(dir.path(), "sub\\\\rule.yml", b"x"); // この書き方は意図通りではない可能性
    let outcome = discover_rule_directory(dir.path(), &Default::default()).unwrap();
    // 全ての relative_path が `/` separator を使っていることを検証。
    for f in &outcome.files {
        assert!(
            !f.relative_path.contains('\\'),
            "backslash は slash へ正規化される: {}",
            f.relative_path
        );
    }
}

// ============================================================================
// T5-003: Rule validation error の Exit Code 5 対応（規範 §17.2）
// ============================================================================

#[test]
fn acceptance_t5_003_validation_error_exit_code_5_in_strict_rules_mode() {
    // 規範 §17.2: 「Rule validation または strict rules error」は Exit Code 5。
    let cases: Vec<RuleLoadError> = vec![
        RuleLoadError::TooLarge {
            path: PathBuf::from("big.yml"),
            size: 100,
            limit: 10,
        },
        RuleLoadError::Symlink(PathBuf::from("link.yml")),
        RuleLoadError::NotAFile(PathBuf::from("dir")),
        RuleLoadError::AccessFailed {
            path: PathBuf::from("missing.yml"),
            message: "not found".into(),
        },
        RuleLoadError::PathNormalization(RulePathError::Empty),
    ];
    for err in cases {
        assert_eq!(
            err.exit_code(true),
            ExitCode::RuleValidationOrStrictRulesError,
            "strict rules mode では Exit Code 5（規範 §17.2）: {err:?}"
        );
    }
}

#[test]
fn acceptance_t5_003_validation_error_exit_code_1_in_non_strict_mode() {
    // 非 strict mode では validation error は skip + Warning となり Exit Code 1 へ寄与。
    let err = RuleLoadError::TooLarge {
        path: PathBuf::from("big.yml"),
        size: 100,
        limit: 10,
    };
    assert_eq!(err.exit_code(false), ExitCode::CaseWithWarnings);
}

#[test]
fn acceptance_t5_003_input_root_error_is_exit_code_3_regardless_of_strict() {
    // 入力 root の問題は strict に関わらず Exit Code 3。
    // Parser 起因の入力異常（Exit Code 1）や panic（Exit Code 10）とは区別される。
    let cases: Vec<RuleLoadError> = vec![
        RuleLoadError::RootAccessFailed {
            path: PathBuf::from("/nonexistent"),
            message: "not found".into(),
        },
        RuleLoadError::RootIsSymlink(PathBuf::from("/link")),
    ];
    for err in cases {
        assert_eq!(
            err.exit_code(true),
            ExitCode::InputOrDiscoveryError,
            "strict に関わらず Exit Code 3: {err:?}"
        );
        assert_eq!(
            err.exit_code(false),
            ExitCode::InputOrDiscoveryError,
            "strict に関わらず Exit Code 3: {err:?}"
        );
    }
}

#[test]
fn acceptance_t5_003_load_directory_collects_errors_for_exit_code_aggregation() {
    // load_directory は個別 file の validation error を summary.errors へ蓄積し、
    // 処理を継続する。呼出側は strict_rules に応じて Exit Code を集約する。
    let dir = make_tmpdir();
    write_file(dir.path(), "ok.yml", b"ok");
    write_file(dir.path(), "too_big.yml", b"0123456789"); // 10 bytes
    write_file(dir.path(), "ok2.yml", b"ok2");

    let opts = RuleLoadOptions {
        max_file_size_bytes: 5,
        ..RuleLoadOptions::default()
    };
    let mut registry = RuleRegistry::new();
    let summary: RuleLoadSummary = registry.load_directory(dir.path(), &opts).unwrap();

    // 2件成功・1件 error。
    assert_eq!(summary.loaded.len(), 2);
    assert_eq!(summary.errors.len(), 1);

    // 呼出側の Exit Code 集約（strict rules）。
    let exit_strict = summary.errors.iter().fold(ExitCode::Success, |acc, e| {
        acc.merge(e.error.exit_code(true))
    });
    assert_eq!(exit_strict, ExitCode::RuleValidationOrStrictRulesError);

    // 呼出側の Exit Code 集約（非 strict）。
    let exit_non_strict = summary.errors.iter().fold(ExitCode::Success, |acc, e| {
        acc.merge(e.error.exit_code(false))
    });
    assert_eq!(exit_non_strict, ExitCode::CaseWithWarnings);
}

#[test]
fn acceptance_t5_003_aggregated_exit_code_priority_order() {
    // 規範 §17.2: 複数 error の優先順位は 10 > 6 > 5 > 4 > 3 > 2 > 1 > 0。
    let validation_err = RuleLoadError::TooLarge {
        path: PathBuf::new(),
        size: 0,
        limit: 0,
    };
    let root_err = RuleLoadError::RootIsSymlink(PathBuf::new());

    // validation_err (strict=5) と root_err (3) の集約。
    let strict = validation_err
        .exit_code(true)
        .merge(root_err.exit_code(true));
    assert_eq!(strict, ExitCode::RuleValidationOrStrictRulesError);

    // 逆順でも同じ。
    let reverse = root_err
        .exit_code(true)
        .merge(validation_err.exit_code(true));
    assert_eq!(reverse, ExitCode::RuleValidationOrStrictRulesError);

    // FatalInternalError (10) は常に優先される。
    let with_fatal = ExitCode::FatalInternalError.merge(validation_err.exit_code(true));
    assert_eq!(with_fatal, ExitCode::FatalInternalError);
}
