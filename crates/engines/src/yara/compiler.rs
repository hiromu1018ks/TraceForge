//! YARA-X Rule の compile（T5-020・T5-021・T5-023）。
//!
//! [`crate::RuleRegistry`] が読み込んだ [`crate::LoadedRuleFile`] の raw bytes を
//! `yara-x` crate の [`yara_x::Compiler`] へ渡し、compiled [`yara_x::Rules`] へ変換する。
//!
//! ## T5-020: YARA-X crate pin + Cargo.lock checksum
//!
//! `yara-x` crate は workspace `Cargo.toml` で `=1.19` 相当へ pin され、`Cargo.lock`
//! で再現性が保証される（互換 §7・§11）。本 module は [`yara_x_engine_version`] へ
//! YARA-X engine の完全 version 文字列を公開し、呼出側が Manifest へ記録できるようにする。
//!
//! ## T5-021: `.yar` / `.yara` file・directory 再帰 load
//!
//! file 形式の制限は [`crate::RuleRegistry`] 側で行う設計だが、本 module は
//! registry が読み込んだ全 [`crate::LoadedRuleFile`] を受け入れ、各々の raw bytes
//! を [`yara_x::Compiler::add_source`] へ渡す。directory 再帰走査自体は共通編の
//! [`crate::RuleRegistry::load_directory`] で実装済み。
//!
//! ## T5-023: compile error 時の file 全体無効化
//!
//! 規範 §15.2 は「Rule compile error が1件でもある Rule file は、その file 全体を
//! 無効とする。他の正常 Rule file は strict rules mode でない限り継続できる」とする。
//! 本 module は **file 毎に独立した [`yara_x::Compiler`] を構築** し、compile が
//! 1件でも error となった file の [`yara_x::Rules`] は破棄する。これにより、
//! 同一 file 内の一部 rule だけが採用される「部分評価」を防止する。
//!
//! また [`yara_x::Compiler::enable_includes`] へ `false` を渡し、`include` 文による
//! host file system へのアクセスを全て禁止する（規範 §14: 1回読み込み原則）。

use yara_x::Rules;

use crate::loader::{LoadedRuleFile, RuleRegistry};

/// YARA-X engine の完全 version 文字列（互換 §7・T5-020）。
///
/// `yara-x` crate が公開する [`yara_x::VERSION`] 定数をそのまま返す。
/// 呼出側（Phase 6 Finding 統合・Phase 7 Manifest）は本値を Manifest の
/// `components.yara.engine_version` へ記録する。`latest` 等の曖昧識別子は禁止。
pub fn yara_x_engine_version() -> &'static str {
    yara_x::VERSION
}

/// 1 file 単位の compiled YARA-X Rules（T5-021・T5-023）。
///
/// 各 file は独立した [`yara_x::Compiler`] で compile され、error が1件でもあれば
/// 破棄される（規範 §15.2・T5-023）。本型は compile 成功した file のみ保持する。
#[derive(Debug)]
pub struct CompiledYaraFile {
    /// 当該 file の Rule file raw bytes SHA-256 lowercase hex（規範 §14・T5-020）。
    /// Match ID の `rule_content_sha256` へ用いる。
    pub sha256: String,
    /// 入力 root からの正規化相対 path（規範 §14・traceability 用）。
    pub relative_path: String,
    /// yara-x が compile した Rules。scan 時に [`yara_x::Scanner::new`] へ渡す。
    rules: Rules,
}

impl CompiledYaraFile {
    /// compiled [`Rules`] への accessor。
    ///
    /// scan 時に [`yara_x::Scanner::new`] へ渡すための reference を返す。
    /// [`Rules`] 自体は [`yara_x`] が !Send / !Sync であるため、thread 越しの
    /// 共有はできない点に注意（本 engine は single-thread 利用を前提とする）。
    pub fn rules(&self) -> &Rules {
        &self.rules
    }
}

/// YARA-X compile error の詳細（T5-023）。
///
/// 1件の compile error に付随する情報。YARA-X は複数の error を同時に報告する場合が
/// あるため、`Vec<YaraCompileErrorDetail>` で保持する。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraCompileErrorDetail {
    /// error code（yara-x が付与する文字列識別子。例: `syntax_error`）。
    pub code: String,
    /// 人間可読の error 本文。
    pub message: String,
}

/// 1 file 単位の YARA-X compile error（T5-023）。
///
/// 規範 §15.2・T5-023 に従い、1件でも compile error があれば当該 file 全体を無効化する。
/// 呼出側は strict rules mode の場合は Exit Code 5、それ以外は Exit Code 1 へ寄与させる
/// （規範 §17.2・[`crate::RuleLoadError::exit_code`] と同等の区分）。
#[derive(Clone, Debug)]
pub struct YaraCompileError {
    /// 対象 file の Rule file raw bytes SHA-256 lowercase hex（規範 §14）。
    pub sha256: String,
    /// 対象 file の入力 root からの正規化相対 path（規範 §14）。
    pub relative_path: String,
    /// yara-x が報告した compile error 群。最低1件を含む。
    pub errors: Vec<YaraCompileErrorDetail>,
}

/// [`RuleRegistry`] 全体の compile 結果（T5-021・T5-023）。
///
/// 規範 §15.2 に従い、成功した file の [`CompiledYaraFile`] 群と失敗した file の
/// [`YaraCompileError`] 群を分けて返す。呼出側は strict rules mode かどうかで
/// Exit Code を切り替える（[`crate::RuleLoadError::exit_code`] と同等）。
///
/// `compiled` は [`YaraRulesetCompileSummary::into_ruleset`] で [`YaraRuleset`] へ変換できる。
#[derive(Debug, Default)]
pub struct YaraRulesetCompileSummary {
    /// compile に成功した file 群（registry の SHA-256 順）。
    pub compiled: Vec<CompiledYaraFile>,
    /// compile に失敗した file 群（registry の SHA-256 順）。
    pub errors: Vec<YaraCompileError>,
}

impl YaraRulesetCompileSummary {
    /// compile 成功 file 数。
    pub fn compiled_len(&self) -> usize {
        self.compiled.len()
    }

    /// compile 失敗 file 数。
    pub fn error_len(&self) -> usize {
        self.errors.len()
    }

    /// compile が全て成功したか（= error 0件）。
    pub fn all_succeeded(&self) -> bool {
        self.errors.is_empty()
    }

    /// compile 成功 file 一覧への iterator。
    pub fn compiled_iter(&self) -> impl Iterator<Item = &CompiledYaraFile> {
        self.compiled.iter()
    }

    /// compile 失敗 file 一覧への iterator。
    pub fn errors_iter(&self) -> impl Iterator<Item = &YaraCompileError> {
        self.errors.iter()
    }

    /// [`YaraRuleset`] へ変換する（[`CompiledYaraFile`] の所有権を移動）。
    ///
    /// 呼出側は `YaraScanner::new(summary.into_ruleset(), limit)` のように使う。
    /// `errors` は消費されず、呼出側が別途参照可能（`compiled` の所有権のみ移動）。
    pub fn into_ruleset(self) -> YaraRuleset {
        YaraRuleset {
            files: self.compiled,
        }
    }
}

/// 全 Rule file を束ねた compiled YARA-X Ruleset（T5-020・T5-021）。
///
/// 規範 §15.2 に従い、file 毎に独立して compile した [`CompiledYaraFile`] の集合。
/// scan 時は [`crate::yara::scanner::YaraScanner`] が各 file の [`Rules`] を順に適用する。
///
/// 反復順序は入力 [`RuleRegistry`] の SHA-256 昇順（[`RuleRegistry::iter`]）で安定する。
/// これは scan 結果の決定性（規範 §13）へ寄与する。
#[derive(Debug, Default)]
pub struct YaraRuleset {
    files: Vec<CompiledYaraFile>,
}

impl YaraRuleset {
    /// 空の ruleset を作成する（test や YARA 無効時の placeholder）。
    pub fn empty() -> Self {
        YaraRuleset::default()
    }

    /// compile 成功 file 数。
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// 全 file の compile が成功したか（= error 0件）。本型は error を保持しないため、
    /// 呼出側は [`YaraRulesetCompileSummary::all_succeeded`] で判定する。
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// compile 成功した file 一覧への iterator。
    pub fn files(&self) -> impl Iterator<Item = &CompiledYaraFile> {
        self.files.iter()
    }

    /// [`RuleRegistry`] の全 [`LoadedRuleFile`] を compile する（T5-020・T5-021・T5-023）。
    ///
    /// 規範 §14・§15.2 に従い:
    /// 1. registry の SHA-256 昇順で各 [`LoadedRuleFile`] を取り出す（決定性）。
    /// 2. file 毎に独立した [`yara_x::Compiler`] を構築する（compile error の file 局所化）。
    /// 3. [`yara_x::Compiler::enable_includes`] へ `false` を渡し、host file system
    ///    access を禁止する（規範 §14: 1回読み込み）。
    /// 4. compile error が1件でもあれば当該 file 全体を無効化し、[`YaraCompileError`] へ記録する。
    /// 5. 成功した file のみ [`CompiledYaraFile`] へ追加する。
    ///
    /// 呼出側は次のように使う:
    ///
    /// ```ignore
    /// let summary = YaraRuleset::compile_from_registry(&registry);
    /// if !summary.all_succeeded() { /* strict rules なら Exit Code 5 */ }
    /// let ruleset = summary.into_ruleset();
    /// let scanner = YaraScanner::new(ruleset, limit);
    /// ```
    pub fn compile_from_registry(registry: &RuleRegistry) -> YaraRulesetCompileSummary {
        let mut compiled: Vec<CompiledYaraFile> = Vec::with_capacity(registry.len());
        let mut errors: Vec<YaraCompileError> = Vec::new();

        for loaded in registry.iter() {
            match compile_single_file(loaded) {
                Ok(file_rules) => compiled.push(file_rules),
                Err(err) => errors.push(err),
            }
        }

        YaraRulesetCompileSummary { compiled, errors }
    }
}

/// 1 file を独立した [`yara_x::Compiler`] で compile する（規範 §15.2・T5-023）。
///
/// 戻り値:
/// - `Ok(CompiledYaraFile)`: compile 成功。全 rule が有効。
/// - `Err(YaraCompileError)`: compile error が1件以上あるため file 全体を無効化。
///
/// `include` 文は host file system access を引き起こすため無効化する（規範 §14）。
fn compile_single_file(loaded: &LoadedRuleFile) -> Result<CompiledYaraFile, YaraCompileError> {
    let mut compiler = yara_x::Compiler::new();
    // include 文は解析 host file system へアクセスするため無効化（規範 §14: 1回読み込み）。
    compiler.enable_includes(false);

    // 規範 §14: registry が読み込んだ同一 raw bytes を渡す。
    // add_source は &str / &[u8] / SourceCode のいずれかを受け取る。
    // 非 UTF-8 の YARA file は yara-x 側で compile error となる（panic しない）。
    let source_bytes = loaded.raw_bytes();

    // add_source の戻り値は無視し、最終的に compiler.errors() で全 error を取り出す。
    // これは「1件でも error があれば file 全体無効化」（規範 §15.2）を実装するため。
    let _ = compiler.add_source(source_bytes);

    let compile_errors: Vec<YaraCompileErrorDetail> = compiler
        .errors()
        .iter()
        .map(|e| YaraCompileErrorDetail {
            code: e.code().to_string(),
            message: e.to_string(),
        })
        .collect();

    if !compile_errors.is_empty() {
        return Err(YaraCompileError {
            sha256: loaded.sha256.clone(),
            relative_path: loaded.relative_path.clone(),
            errors: compile_errors,
        });
    }

    let rules = compiler.build();
    Ok(CompiledYaraFile {
        sha256: loaded.sha256.clone(),
        relative_path: loaded.relative_path.clone(),
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    fn write_rule_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn load_into_registry(dir: &Path) -> RuleRegistry {
        let mut registry = RuleRegistry::new();
        registry
            .load_directory(dir, &crate::loader::RuleLoadOptions::default())
            .unwrap();
        registry
    }

    // ===== T5-020: YARA-X engine version =====

    #[test]
    fn yara_x_engine_version_is_nonempty_and_not_latest() {
        // 互換 §7: latest 使用禁止。完全 version 文字列であること。
        let v = yara_x_engine_version();
        assert!(!v.is_empty());
        assert_ne!(v, "latest");
        // version は少なくとも数字で始まる（例: "1.19.0"）。
        assert!(
            v.chars().next().unwrap().is_ascii_digit(),
            "version は数字始まり: {v}"
        );
    }

    // ===== T5-021: 単純な .yar file の compile =====

    #[test]
    fn compile_single_yara_rule() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(
            dir.path(),
            "test.yar",
            r#"
            rule traceforge_test_rule {
                strings:
                    $a = "TraceForge"
                condition:
                    $a
            }
            "#,
        );

        let registry = load_into_registry(dir.path());
        assert_eq!(registry.len(), 1);

        let summary = YaraRuleset::compile_from_registry(&registry);
        assert_eq!(summary.compiled_len(), 1);
        assert!(summary.errors.is_empty());
        let ruleset = summary.into_ruleset();
        assert_eq!(ruleset.len(), 1);
    }

    #[test]
    fn compile_yara_rule_with_yara_extension() {
        // .yara 拡張子も受理する（共通編の loader は拡張子で絞り込まない）。
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(dir.path(), "alt.yara", r#"rule r { condition: true }"#);

        let registry = load_into_registry(dir.path());
        let summary = YaraRuleset::compile_from_registry(&registry);
        assert_eq!(summary.compiled_len(), 1);
        assert_eq!(summary.into_ruleset().len(), 1);
    }

    #[test]
    fn compile_multiple_rule_files() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(dir.path(), "a.yar", r#"rule r_a { condition: true }"#);
        write_rule_file(dir.path(), "b.yar", r#"rule r_b { condition: true }"#);

        let registry = load_into_registry(dir.path());
        assert_eq!(registry.len(), 2);

        let summary = YaraRuleset::compile_from_registry(&registry);
        assert_eq!(summary.compiled_len(), 2);
        assert!(summary.errors.is_empty());
        assert_eq!(summary.into_ruleset().len(), 2);
    }

    // ===== T5-023: compile error 時の file 全体無効化・他 file 継続 =====

    #[test]
    fn compile_error_disables_only_that_file() {
        // 規範 §15.2: compile error の file 全体無効化・他 file 継続。
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(dir.path(), "good.yar", r#"rule good { condition: true }"#);
        // syntax error の bad.yar
        write_rule_file(dir.path(), "bad.yar", r#"rule bad { condition: true"#);

        let registry = load_into_registry(dir.path());
        let summary = YaraRuleset::compile_from_registry(&registry);

        assert_eq!(summary.compiled_len(), 1, "good のみ成功");
        assert_eq!(summary.error_len(), 1, "bad は compile error");

        let err = &summary.errors[0];
        assert_eq!(err.relative_path, "bad.yar");
        assert!(!err.errors.is_empty(), "error 詳細を保持");
    }

    #[test]
    fn compile_error_in_one_rule_disables_entire_file() {
        // 規範 §15.2: file 内の1 rule の error で file 全体を無効化する。
        // 1 file に3 rule（2件正常・1件 error）を含め、file 全体が無効化されることを検証。
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(
            dir.path(),
            "mixed.yar",
            r#"
            rule ok1 { condition: true }
            rule ok2 { condition: true }
            rule broken { condition: this is not valid }
            "#,
        );

        let registry = load_into_registry(dir.path());
        let summary = YaraRuleset::compile_from_registry(&registry);

        // file 全体が無効化されるため ruleset は空。
        assert_eq!(summary.compiled_len(), 0, "file 全体無効化");
        assert_eq!(summary.error_len(), 1);
    }

    #[test]
    fn compile_error_detail_has_code_and_message() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(dir.path(), "bad.yar", r#"rule { condition: true }"#);

        let registry = load_into_registry(dir.path());
        let summary = YaraRuleset::compile_from_registry(&registry);
        assert_eq!(summary.error_len(), 1);

        let detail = &summary.errors[0].errors[0];
        assert!(!detail.code.is_empty(), "code は空でない");
        assert!(!detail.message.is_empty(), "message は空でない");
    }

    // ===== T5-023: include 文の禁止（規範 §14: 1回読み込み）=====

    #[test]
    fn include_statement_is_disabled() {
        // 規範 §14: Rule file は1回だけ読み込む。include による host file system
        // access は原則違反のため、本 engine は include を無効化する。
        let dir = tempfile::tempdir().unwrap();
        // include 文を含む file。include 自体が error 扱いとなる。
        write_rule_file(
            dir.path(),
            "with_include.yar",
            r#"include "other.yar"
            rule r { condition: true }"#,
        );

        let registry = load_into_registry(dir.path());
        let summary = YaraRuleset::compile_from_registry(&registry);

        // include を無効化しているため、この file は compile error となる。
        assert_eq!(summary.compiled_len(), 0, "include 文は error");
        assert_eq!(summary.error_len(), 1);
    }

    // ===== T5-022: 空 file は compile error とは限らない（YARA 仕様）=====

    #[test]
    fn empty_file_does_not_panic() {
        // 共通編の loader は空 file も読み込む。yara-x は空 source を0 rule として扱い、
        // compile error にはならない（panic もしない）。各 engine が内容を検証して
        // 拒否する設計（規範 §14・共通編の設計）。
        // いずれにせよ ruleset が空（0 rule）であることを確認する。
        let dir = tempfile::tempdir().unwrap();
        write_rule_file(dir.path(), "empty.yar", "");

        let registry = load_into_registry(dir.path());
        let summary = YaraRuleset::compile_from_registry(&registry);

        // 空 source は yara-x 仕様で compile error にならない（0 rule の Rules を生成）。
        // したがって compiled_len=1 だが、実際の rule 数は0。panic しないことが本質。
        let ruleset = summary.into_ruleset();
        // file は1つだが、中身の rules は空。
        // （注: 将来 yara-x 仕様が変わり空 source が error になる場合は compiled_len=0 となる）
        assert!(
            ruleset.len() <= 1,
            "空 file は高々1つの空 rules を生成（panic しない）"
        );
    }

    // ===== T5-021: 非 UTF-8 file で panic しない =====

    #[test]
    fn non_utf8_file_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        // yara-x は bytes から source を受け取る。非 UTF-8 は compile error となるが
        // panic しないことを検証（規範 §9.4: 最終安全網）。
        let path = dir.path().join("binary.yar");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&[0xFF, 0xFE, 0x00, 0x42, 0x80]).unwrap();
        drop(f);

        let mut registry = RuleRegistry::new();
        registry
            .load(
                &path,
                dir.path(),
                &crate::loader::RuleLoadOptions::default(),
            )
            .unwrap();

        let _ = YaraRuleset::compile_from_registry(&registry);
        // panic しなければ test 通過。
    }

    // ===== 決定性: 同一 registry は同一 ruleset 構成 =====

    #[test]
    fn compile_from_registry_is_deterministic_in_order() {
        // registry の SHA-256 昇順で compile するため、file 追加順に依存しない。
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        let content_a = r#"rule a { condition: true }"#;
        let content_b = r#"rule b { condition: true }"#;

        // dir1 は a → b 順、dir2 は b → a 順で作成（内容は同一）。
        write_rule_file(dir1.path(), "a.yar", content_a);
        write_rule_file(dir1.path(), "b.yar", content_b);
        write_rule_file(dir2.path(), "b.yar", content_b);
        write_rule_file(dir2.path(), "a.yar", content_a);

        let reg1 = load_into_registry(dir1.path());
        let reg2 = load_into_registry(dir2.path());

        let summary1 = YaraRuleset::compile_from_registry(&reg1);
        let summary2 = YaraRuleset::compile_from_registry(&reg2);

        // 同一 SHA-256 順で compile されるため、relative_path も同一順序。
        let paths1: Vec<_> = summary1
            .compiled_iter()
            .map(|f| f.relative_path.clone())
            .collect();
        let paths2: Vec<_> = summary2
            .compiled_iter()
            .map(|f| f.relative_path.clone())
            .collect();
        assert_eq!(paths1, paths2, "作成順に依存しない決定的順序");
    }
}
