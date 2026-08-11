//! Rule file 読込基盤（規範 §14・§17.2、T5-001〜T5-003）。
//!
//! Sigma・YARA-X・Correlation 全ての前提となる Rule file 取扱基盤を提供する。
//!
//! ## T5-001: 1回読み込み・raw bytes SHA-256・再読込禁止
//!
//! 規範 §14 は「Rule file を1回だけ bytes として読み込み、その raw bytes の SHA-256
//! を計算し、同じ bytes を parse または compile しなければならない。評価中に Rule
//! file を再読込してはならない」とする。本 module の [`RuleRegistry`] は SHA-256 で
//! 重複検出し、同一内容の再読込を禁止する。
//!
//! ## T5-002: directory 列挙順の正規化（UTF-8 byte 順）
//!
//! 規範 §14 は「Rule directory の列挙順は正規化相対 path の UTF-8 byte 順とする」
//! とする。本 module の [`discover_rule_directory`] と [`RuleRegistry::load_directory`]
//! は相対 path を正規化（[`crate::path_norm`]）した上で UTF-8 byte 順へ sort する。
//! filesystem が返す列挙順には依存しない。
//!
//! ## T5-003: validation error の Exit Code 5 対応
//!
//! 規範 §17.2 は「Rule validation または strict rules error」を Exit Code 5 へ区分する。
//! strict rules mode の場合は validation error を即時 fatal とし（Exit Code 5）、
//! そうでない場合は当該 Rule を skip して Exit Code 1（Warning/partial/skip）へ寄与
//! させる。本 module は [`RuleLoadError::exit_code`] でこの区分を提供する。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use tf_core::error::ExitCode;
use tf_core::hash::sha256_hex;

use crate::path_norm::{RulePathError, normalize_rule_relative_path, relative_path_key};

/// symlink skip 時に記録する Issue code（規範 §2: symlink 非追跡）。
pub const SYMLINK_SKIP_CODE: &str = "TF-W-RULE-SYMLINK";

/// `max_rule_files` limit 到達時に記録する Issue code（規範 §18）。
pub const MAX_RULE_FILES_LIMIT_CODE: &str = "TF-W-LIMIT-MAX-RULE-FILES";

/// Schema §8.2 `[limits]` の既定値。`Config` が無い場面での test や default 構築で使用。
const DEFAULT_MAX_RULE_FILES: u64 = 100_000;
const DEFAULT_MAX_RULE_FILE_SIZE_BYTES: u64 = 16_777_216;
const DEFAULT_MAX_RECURSION_DEPTH: u64 = 64;

/// Rule file を1回読み込んだ結果。
///
/// raw bytes を保持し、SHA-256 lowercase hex を算出済み。各 engine は [`LoadedRuleFile`]
/// から raw bytes を借りて parse/compile へ渡す。file を再読込せず、同じ bytes を
/// 使い回すことが規範 §14 の要件である。
#[derive(Clone, Debug)]
pub struct LoadedRuleFile {
    /// host filesystem 上の絶対 path。再読込や再 open には使わない。
    pub host_path: PathBuf,
    /// 入力 root からの正規化相対 path（sort key・traceability 用、規範 §14）。
    pub relative_path: String,
    /// 1回だけ読み込んだ raw bytes（規範 §14）。
    pub raw_bytes: Vec<u8>,
    /// `raw_bytes` の SHA-256 lowercase hex（規範 §14・Schema §2.1）。
    /// Match ID・Finding ID・Manifest の `rule_content_sha256` へ用いる。
    pub sha256: String,
    /// `raw_bytes` の size（byte 数）。
    pub size: u64,
}

impl LoadedRuleFile {
    /// raw bytes への accessor。各 engine はこの slice を parse/compile へ渡す。
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }
}

/// 読み込み済み Rule file の registry。
///
/// SHA-256 を key として重複検出を行い、同一内容の Rule file が複数回指定されたり
/// 複数 directory へ現れた場合でも1回だけ読み込む（規範 §14）。
///
/// registry は SHA-256 の昇順で iteration する。これは読込順ではなく content hash
/// 順であり、directory 列挙順（規範 §14: UTF-8 byte 順）とは独立した決定的順序である。
#[derive(Default)]
pub struct RuleRegistry {
    by_sha256: BTreeMap<String, LoadedRuleFile>,
}

impl RuleRegistry {
    /// 空の registry を作成する。
    pub fn new() -> Self {
        RuleRegistry::default()
    }

    /// 読み込み済み Rule file 数。
    pub fn len(&self) -> usize {
        self.by_sha256.len()
    }

    /// registry が空か。
    pub fn is_empty(&self) -> bool {
        self.by_sha256.is_empty()
    }

    /// 指定した SHA-256 の Rule file が既に読み込み済みか。
    pub fn contains_sha256(&self, sha256: &str) -> bool {
        self.by_sha256.contains_key(sha256)
    }

    /// 読み込み済みの SHA-256 一覧（昇順）。
    pub fn sha256_iter(&self) -> impl Iterator<Item = &str> {
        self.by_sha256.keys().map(String::as_str)
    }

    /// 読み込み済み Rule file 一覧（SHA-256 昇順）。
    pub fn iter(&self) -> impl Iterator<Item = &LoadedRuleFile> {
        self.by_sha256.values()
    }

    /// 読み込み済み Rule file 一覧から所有権付きで取り出す（消費）。
    pub fn into_iter_owned(self) -> impl Iterator<Item = LoadedRuleFile> {
        self.by_sha256.into_values()
    }

    /// 1 件の Rule file を読み込み、registry へ追加する（規範 §14: 1回読み込み）。
    ///
    /// `path` は読み込む Rule file（file のみ許可・symlink 拒否・size 上限で検査）。
    /// `root` は相対 path 計算の基準 directory（`path` と同じでもよい）。
    ///
    /// 戻り値:
    /// - `Ok(Some(loaded))`: 新規に読み込んで追加した。
    /// - `Ok(None)`: 同一 SHA-256 が既に存在し、再読込を skip した（規範 §14）。
    /// - `Err(...)`: file 読込時の validation error（規範 §17.2: Exit Code 5/1）。
    pub fn load(
        &mut self,
        path: &Path,
        root: &Path,
        options: &RuleLoadOptions,
    ) -> Result<Option<LoadedRuleFile>, RuleLoadError> {
        load_single(path, root, options, self)
    }

    /// directory を再帰走査し、発見した全 Rule file を registry へ読み込む。
    ///
    /// 既に同一 SHA-256 が読み込み済みの file は skip する（規範 §14: 再読込禁止）。
    /// 個別 file の validation error は `summary.errors` へ蓄積し、処理は継続する。
    /// 呼出側は strict rules mode かどうかに応じて `summary.errors` から Exit Code を
    /// 集約する（規範 §17.2・T5-003）。
    pub fn load_directory(
        &mut self,
        root: &Path,
        options: &RuleLoadOptions,
    ) -> Result<RuleLoadSummary, RuleLoadError> {
        let discovery = discover_rule_directory(root, &options.as_discovery_options())?;
        let mut summary = RuleLoadSummary {
            loaded: Vec::new(),
            skipped_duplicates: Vec::new(),
            symlink_skipped: discovery.symlink_skipped,
            truncated: discovery.truncated,
            errors: Vec::new(),
            max_files_limit: if discovery.truncated {
                Some(options.max_files)
            } else {
                None
            },
        };

        for discovered in discovery.files {
            match load_single(&discovered.host_path, root, options, self) {
                Ok(Some(loaded)) => summary.loaded.push(loaded),
                Ok(None) => summary.skipped_duplicates.push(discovered.host_path),
                Err(error) => summary.errors.push(RuleFileError {
                    path: discovered.host_path,
                    error,
                }),
            }
        }

        // 読込順によらず決定的な順序へ sort（呼出側の集約を安定にするため）。
        summary.skipped_duplicates.sort();
        summary.errors.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(summary)
    }
}

/// directory 再帰走査の設定。
#[derive(Clone, Debug)]
pub struct RuleDiscoveryOptions {
    /// recursive traversal（既定 ON）。
    pub recursive: bool,
    /// 再帰の最大深度。root 直下は深度 0（既定 64・Schema §8.2）。
    pub max_recursion_depth: u64,
    /// 発見する file 数の上限（既定 100_000・Schema §8.2 `max_rule_files`）。
    pub max_files: u64,
}

impl Default for RuleDiscoveryOptions {
    fn default() -> Self {
        RuleDiscoveryOptions {
            recursive: true,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
            max_files: DEFAULT_MAX_RULE_FILES,
        }
    }
}

/// Rule file 読込の設定。
#[derive(Clone, Debug)]
pub struct RuleLoadOptions {
    /// recursive traversal（既定 ON）。
    pub recursive: bool,
    /// 再帰の最大深度。root 直下は深度 0（既定 64・Schema §8.2）。
    pub max_recursion_depth: u64,
    /// 発見する file 数の上限（既定 100_000・Schema §8.2 `max_rule_files`）。
    pub max_files: u64,
    /// 1 file の size 上限（既定 16_777_216 = 16 MiB・Schema §8.2 `max_rule_file_size_bytes`）。
    pub max_file_size_bytes: u64,
}

impl Default for RuleLoadOptions {
    fn default() -> Self {
        RuleLoadOptions {
            recursive: true,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
            max_files: DEFAULT_MAX_RULE_FILES,
            max_file_size_bytes: DEFAULT_MAX_RULE_FILE_SIZE_BYTES,
        }
    }
}

impl RuleLoadOptions {
    /// [`tf_core::Config`] の `[limits]` から既定値を構築する。
    pub fn from_config(config: &tf_core::Config) -> Self {
        RuleLoadOptions {
            recursive: true,
            max_recursion_depth: config.limits.max_recursion_depth,
            max_files: config.limits.max_rule_files,
            max_file_size_bytes: config.limits.max_rule_file_size_bytes,
        }
    }

    /// 読込用設定から discovery 用設定への変換。
    fn as_discovery_options(&self) -> RuleDiscoveryOptions {
        RuleDiscoveryOptions {
            recursive: self.recursive,
            max_recursion_depth: self.max_recursion_depth,
            max_files: self.max_files,
        }
    }
}

/// 発見した1件の Rule file 候補（未読み込み）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredRuleFile {
    /// host filesystem 上の絶対 path。
    pub host_path: PathBuf,
    /// 入力 root からの正規化相対 path（sort key・規範 §14）。
    pub relative_path: String,
}

/// directory 走査の結果。
#[derive(Clone, Debug, Default)]
pub struct DiscoveryOutcome {
    /// 正規化相対 path の UTF-8 byte 昇順で sort 済みの Rule file 一覧（規範 §14）。
    pub files: Vec<DiscoveredRuleFile>,
    /// symlink として skip した path の一覧。Issue 生成に使用する。
    pub symlink_skipped: Vec<PathBuf>,
    /// `max_files` limit 到達で打ち切ったか（規範 §18）。
    pub truncated: bool,
}

/// directory 単位の読込結果。
#[derive(Clone, Debug, Default)]
pub struct RuleLoadSummary {
    /// 新規に読み込んだ Rule file 一覧（discovery 順）。
    pub loaded: Vec<LoadedRuleFile>,
    /// 既読の SHA-256 で再読込を skip した host path 一覧（規範 §14）。
    pub skipped_duplicates: Vec<PathBuf>,
    /// symlink として skip した path 一覧（規範 §2）。
    pub symlink_skipped: Vec<PathBuf>,
    /// `max_files` limit 到達で打ち切ったか（規範 §18）。
    pub truncated: bool,
    /// 個別 file の validation error（skip したもの）。
    pub errors: Vec<RuleFileError>,
    /// 到達した `max_files` 上限（truncated 時のみ）。
    pub max_files_limit: Option<u64>,
}

/// 個別 Rule file の validation error。
#[derive(Clone, Debug)]
pub struct RuleFileError {
    /// 対象 file の host path。
    pub path: PathBuf,
    /// 発生した error。
    pub error: RuleLoadError,
}

/// Rule load / validation error（規範 §17.2: Exit Code 5/1 区分）。
///
/// 共通編では file 読込時に発生しうる error を定義する。content level の検証
/// （YAML parse・Schema 違反・anchor/alias 検出）は各 engine の個別 task
/// （T5-010 Sigma・T5-030 Correlation 等）で追加する。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleLoadError {
    /// Rule file への access に失敗した（permission・不存在等）。
    #[error("Rule file への access に失敗した: {path}: {message}")]
    AccessFailed { path: PathBuf, message: String },
    /// Rule file が symlink である（規範 §2: symlink 非追跡）。
    #[error("Rule file が symlink である: {0}")]
    Symlink(PathBuf),
    /// Rule path が file でない（directory 等）。
    #[error("Rule path が file でない: {0}")]
    NotAFile(PathBuf),
    /// Rule file size が上限を超過（Schema §8.2: `max_rule_file_size_bytes`）。
    #[error("Rule file size {size} が上限 {limit} を超過: {path}")]
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    /// Rule directory の再帰深度が上限に到達（Schema §8.2: `max_recursion_depth`）。
    #[error("Rule directory の再帰深度が上限に到達した: {0}")]
    MaxRecursionDepth(PathBuf),
    /// path の正規化に失敗した（`.`/`..`・絶対 path・非 UTF-8 等）。
    #[error("Rule path の正規化に失敗した: {0}")]
    PathNormalization(#[from] RulePathError),
    /// 入力 root への access に失敗した（permission・不存在等）。
    #[error("入力 root への access に失敗した: {path}: {message}")]
    RootAccessFailed { path: PathBuf, message: String },
    /// 入力 root 自体が symlink である（規範 §2: symlink 非追跡）。
    #[error("入力 root 自体が symlink である: {0}")]
    RootIsSymlink(PathBuf),
}

impl RuleLoadError {
    /// 規範 §17.2 の Exit Code を返す（T5-003）。
    ///
    /// - 入力 root の access 失敗・symlink は [`ExitCode::InputOrDiscoveryError`] (3)。
    ///   rule directory が存在しない場合は CLI/input error として扱う。
    /// - 個別 file の validation error は strict rules mode なら
    ///   [`ExitCode::RuleValidationOrStrictRulesError`] (5)、それ以外は
    ///   [`ExitCode::CaseWithWarnings`] (1) へ寄与する（skip + Warning）。
    /// - parser 起因の入力異常（Exit Code 1）や panic（Exit Code 10）とは区別する。
    pub fn exit_code(&self, strict_rules: bool) -> ExitCode {
        match self {
            // 入力 root の問題は CLI/input error（Exit Code 3）。
            RuleLoadError::RootAccessFailed { .. } | RuleLoadError::RootIsSymlink(_) => {
                ExitCode::InputOrDiscoveryError
            }
            // 個別 file の問題は strict rules なら Exit Code 5、それ以外は Exit Code 1。
            _ => self.validation_exit_code(strict_rules),
        }
    }

    fn validation_exit_code(&self, strict_rules: bool) -> ExitCode {
        if strict_rules {
            ExitCode::RuleValidationOrStrictRulesError
        } else {
            ExitCode::CaseWithWarnings
        }
    }
}

/// 入力 root 配下を決定的順序で走査する（規範 §14: UTF-8 byte 順）。
///
/// `input_root` は directory または単一 file のいずれか。
/// directory の場合は `options.recursive` に従って再帰走査する。
/// 単一 file の場合は relative_path を file 名のみへ正規化する。
///
/// symlink は全て skip し、`outcome.symlink_skipped` へ記録する（規範 §2）。
/// 結果の `files` は相対 path の UTF-8 byte 昇順で sort 済みである。
pub fn discover_rule_directory(
    input_root: &Path,
    options: &RuleDiscoveryOptions,
) -> Result<DiscoveryOutcome, RuleLoadError> {
    // 入力 root が symlink でないことを確認（規範 §2）。
    let root_meta =
        fs::symlink_metadata(input_root).map_err(|e| RuleLoadError::RootAccessFailed {
            path: input_root.to_path_buf(),
            message: e.to_string(),
        })?;
    if root_meta.is_symlink() {
        return Err(RuleLoadError::RootIsSymlink(input_root.to_path_buf()));
    }

    let mut outcome = DiscoveryOutcome::default();

    if root_meta.is_dir() {
        walk_directory(input_root, input_root, 0, options, &mut outcome)?;
    } else if root_meta.is_file() {
        // 単一 file の場合: relative_path は file 名のみ。root 親 context がないため
        // 親方向への相対化はできず、file 名そのものを sort key として使う。
        // file_name は `/` を含まない最終 component だが、念のため normalize も通す。
        let name = file_name_or_fallback(input_root);
        let relative_path = normalize_rule_relative_path(&name).unwrap_or(name);
        if options.max_files >= 1 {
            outcome.files.push(DiscoveredRuleFile {
                host_path: input_root.to_path_buf(),
                relative_path,
            });
        }
    } else {
        // socket・FIFO 等（file でも directory でもない）。
        return Err(RuleLoadError::NotAFile(input_root.to_path_buf()));
    }

    // 規範 §14: 正規化相対 path の UTF-8 byte 順で sort。
    // filesystem 列挙順には依存しない（決定性）。
    outcome
        .files
        .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    outcome.symlink_skipped.sort();

    Ok(outcome)
}

/// 1 directory を再帰走査する内部関数。
fn walk_directory(
    dir: &Path,
    root: &Path,
    depth: u64,
    options: &RuleDiscoveryOptions,
    outcome: &mut DiscoveryOutcome,
) -> Result<(), RuleLoadError> {
    // 深度制限の確認（Schema §8.2: max_recursion_depth）。
    if options.recursive && depth > options.max_recursion_depth {
        return Ok(());
    }
    if !options.recursive && depth > 0 {
        return Ok(());
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return Err(RuleLoadError::AccessFailed {
                path: dir.to_path_buf(),
                message: e.to_string(),
            });
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // 個別 entry の読取失敗は skip
        };

        // max_files limit の確認（規範 §18: 1件追加する直前に検査）。
        if outcome.files.len() as u64 >= options.max_files {
            outcome.truncated = true;
            return Ok(());
        }

        let path = entry.path();

        // symlink_metadata を使って symlink を検出する（規範 §2）。
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // symlink は追跡しない（規範 §2・規範 §14 暗黙: 安全プロファイル）。
        if meta.is_symlink() {
            outcome.symlink_skipped.push(path);
            continue;
        }

        if meta.is_dir() {
            if options.recursive {
                walk_directory(&path, root, depth + 1, options, outcome)?;
            }
            // recursive でない場合は subdirectory を無視する。
        } else if meta.is_file() {
            // 通常 file として候補へ追加。path 正規化に失敗した場合は skip。
            match relative_path_key(&path, root) {
                Ok(relative) => outcome.files.push(DiscoveredRuleFile {
                    host_path: path,
                    relative_path: relative,
                }),
                Err(_) => continue, // 非 UTF-8 等の正規化失敗は skip
            }
        }
        // file でも directory でもない（socket・FIFO 等）は無視する。
    }

    Ok(())
}

/// `registry` の既読 SHA-256 を参照しつつ1 file を読み込む。
///
/// 重複検出・size 上限・symlink 拒否を行う。重複時は `Ok(None)` を返す（規範 §14）。
fn load_single(
    path: &Path,
    root: &Path,
    options: &RuleLoadOptions,
    registry: &mut RuleRegistry,
) -> Result<Option<LoadedRuleFile>, RuleLoadError> {
    // symlink でないことを確認（規範 §2）。
    let meta = fs::symlink_metadata(path).map_err(|e| RuleLoadError::AccessFailed {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    if meta.is_symlink() {
        return Err(RuleLoadError::Symlink(path.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(RuleLoadError::NotAFile(path.to_path_buf()));
    }

    // Schema §8.2: max_rule_file_size_bytes の事前検査（規範 §18: 処理開始前に検査）。
    let size = meta.len();
    if size > options.max_file_size_bytes {
        return Err(RuleLoadError::TooLarge {
            path: path.to_path_buf(),
            size,
            limit: options.max_file_size_bytes,
        });
    }

    // 規範 §14: 1回だけ bytes として読み込む。
    let raw_bytes = fs::read(path).map_err(|e| RuleLoadError::AccessFailed {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    // 規範 §14: raw bytes の SHA-256 を計算する。
    let sha256 = sha256_hex(&raw_bytes);

    // 規範 §14: 同一内容（SHA-256 一致）の再読込禁止。
    if registry.contains_sha256(&sha256) {
        return Ok(None);
    }

    // relative_path の正規化（規範 §14: 列挙順 sort key）。
    let relative_path = relative_path_key(path, root)?;

    let loaded = LoadedRuleFile {
        host_path: path.to_path_buf(),
        relative_path,
        raw_bytes,
        sha256,
        size,
    };

    // registry へ追加（SHA-256 key で重複なしを保証済み）。
    registry
        .by_sha256
        .insert(loaded.sha256.clone(), loaded.clone());

    Ok(Some(loaded))
}

/// Path の file 名部分を取得する。取得できない場合は fallback 文字列を返す。
fn file_name_or_fallback(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("_unnamed")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tf_core::hash::is_lowercase_sha256_hex;

    fn create_test_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("一時 directory の作成に失敗")
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    // ===== T5-001: 1回読み込み・raw bytes SHA-256・再読込禁止 =====

    #[test]
    fn load_single_rule_file_computes_sha256() {
        // 規範 §14: raw bytes の SHA-256 を計算する。
        let dir = create_test_dir();
        let content = b"title: Test\ndetection:\n  condition: selection\n";
        let path = write_file(dir.path(), "rule.yml", content);

        let mut registry = RuleRegistry::new();
        let loaded = registry
            .load(&path, dir.path(), &RuleLoadOptions::default())
            .expect("読込成功")
            .expect("新規 file なので読み込まれる");
        assert_eq!(loaded.size, content.len() as u64);
        assert_eq!(loaded.raw_bytes, content);
        assert!(is_lowercase_sha256_hex(&loaded.sha256));
        // raw_bytes と sha256 の整合性。
        assert_eq!(loaded.sha256, sha256_hex(content));
    }

    #[test]
    fn load_single_rule_file_relative_path() {
        let dir = create_test_dir();
        let path = write_file(dir.path(), "sigma/auth.yml", b"x");

        let mut registry = RuleRegistry::new();
        let loaded = registry
            .load(&path, dir.path(), &RuleLoadOptions::default())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.relative_path, "sigma/auth.yml");
    }

    #[test]
    fn duplicate_sha256_not_reloaded_same_path() {
        // 規範 §14: 同一 file の再読込禁止。
        let dir = create_test_dir();
        let path = write_file(dir.path(), "rule.yml", b"same");

        let mut registry = RuleRegistry::new();
        let first = registry
            .load(&path, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        let second = registry
            .load(&path, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        assert!(first.is_some(), "1回目は読み込まれる");
        assert!(second.is_none(), "2回目は再読込禁止で skip");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn duplicate_sha256_not_reloaded_different_path() {
        // 規範 §14: 異なる path でも同一 content なら再読込禁止。
        let dir = create_test_dir();
        let content = b"title: Same content";
        let path1 = write_file(dir.path(), "rule1.yml", content);
        let path2 = write_file(dir.path(), "rule2.yml", content);

        let mut registry = RuleRegistry::new();
        let first = registry
            .load(&path1, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        let second = registry
            .load(&path2, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        assert!(first.is_some());
        assert!(
            second.is_none(),
            "異なる path でも SHA-256 一致なら再読込禁止"
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn different_sha256_both_loaded() {
        let dir = create_test_dir();
        let path1 = write_file(dir.path(), "rule1.yml", b"content A");
        let path2 = write_file(dir.path(), "rule2.yml", b"content B");

        let mut registry = RuleRegistry::new();
        let first = registry
            .load(&path1, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        let second = registry
            .load(&path2, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        assert!(first.is_some());
        assert!(second.is_some());
        assert_eq!(registry.len(), 2);
        assert_ne!(
            first.as_ref().unwrap().sha256,
            second.as_ref().unwrap().sha256
        );
    }

    #[test]
    fn registry_iteration_is_sha256_sorted() {
        // registry は SHA-256 昇順で iterate する（読込順に依存しない決定性）。
        let dir = create_test_dir();
        let _p_z = write_file(dir.path(), "z.yml", b"z-content");
        let _p_a = write_file(dir.path(), "a.yml", b"a-content");

        let mut registry = RuleRegistry::new();
        registry
            .load_directory(dir.path(), &RuleLoadOptions::default())
            .unwrap();

        let sha256s: Vec<&str> = registry.sha256_iter().collect();
        assert_eq!(sha256s.len(), 2);
        // SHA-256 順は内容依存だが、sort されていることを検証。
        let mut expected = sha256s.to_vec();
        expected.sort();
        assert_eq!(sha256s, expected);
    }

    #[test]
    fn empty_file_is_loaded_with_known_sha256() {
        // 共通編では content validation を行わないため、空 file も読み込まれる。
        // 各 engine の parser が Schema 違反として拒否する。
        let dir = create_test_dir();
        let path = write_file(dir.path(), "empty.yml", b"");

        let mut registry = RuleRegistry::new();
        let loaded = registry
            .load(&path, dir.path(), &RuleLoadOptions::default())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.size, 0);
        assert!(loaded.raw_bytes.is_empty());
        // 空入力の SHA-256 は既知の定数値。
        assert_eq!(
            loaded.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ===== T5-001: file size 上限・symlink 拒否 =====

    #[test]
    fn file_size_limit_rejected() {
        // Schema §8.2: max_rule_file_size_bytes。
        let dir = create_test_dir();
        let path = write_file(dir.path(), "big.yml", b"0123456789"); // 10 bytes

        let opts = RuleLoadOptions {
            max_file_size_bytes: 5,
            ..RuleLoadOptions::default()
        };
        let mut registry = RuleRegistry::new();
        let err = registry.load(&path, dir.path(), &opts).unwrap_err();
        assert!(matches!(
            err,
            RuleLoadError::TooLarge {
                size: 10,
                limit: 5,
                ..
            }
        ));
    }

    #[test]
    fn symlink_rejected() {
        // 規範 §2: symlink は追跡しない。
        let dir = create_test_dir();
        let real = write_file(dir.path(), "real.yml", b"content");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = dir.path().join("link.yml");
            symlink(&real, &link).unwrap();

            let mut registry = RuleRegistry::new();
            let err = registry
                .load(&link, dir.path(), &RuleLoadOptions::default())
                .unwrap_err();
            assert!(matches!(err, RuleLoadError::Symlink(_)));
        }
        #[cfg(not(unix))]
        {
            // Windows では symlink test を省略（管理者権限が必要なため）。
            let _real = real;
        }
    }

    #[test]
    fn directory_path_rejected_as_not_a_file() {
        let dir = create_test_dir();
        let subdir = write_file(dir.path(), "subdir/.keep", b"");
        let mut registry = RuleRegistry::new();
        let err = registry
            .load(
                subdir.parent().unwrap(),
                dir.path(),
                &RuleLoadOptions::default(),
            )
            .unwrap_err();
        assert!(matches!(err, RuleLoadError::NotAFile(_)));
    }

    // ===== T5-002: directory 列挙順の正規化（UTF-8 byte 順） =====

    #[test]
    fn discover_directory_utf8_byte_order() {
        // 規範 §14: 正規化相対 path の UTF-8 byte 順。
        let dir = create_test_dir();
        write_file(dir.path(), "zebra.yml", b"z");
        write_file(dir.path(), "alpha.yml", b"a");
        write_file(dir.path(), "mango.yml", b"m");

        let outcome =
            discover_rule_directory(dir.path(), &RuleDiscoveryOptions::default()).unwrap();
        let rels: Vec<&str> = outcome
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert_eq!(rels, vec!["alpha.yml", "mango.yml", "zebra.yml"]);
    }

    #[test]
    fn discover_directory_utf8_byte_order_independent_of_creation_order() {
        // filesystem 列挙順に依存しない（決定性）。
        let dir1 = create_test_dir();
        let dir2 = create_test_dir();
        // dir1 は逆順、dir2 は正順で作成。
        write_file(dir1.path(), "z.yml", b"z");
        write_file(dir1.path(), "a.yml", b"a");
        write_file(dir2.path(), "a.yml", b"a");
        write_file(dir2.path(), "z.yml", b"z");

        let o1 = discover_rule_directory(dir1.path(), &RuleDiscoveryOptions::default()).unwrap();
        let o2 = discover_rule_directory(dir2.path(), &RuleDiscoveryOptions::default()).unwrap();
        let r1: Vec<&str> = o1.files.iter().map(|f| f.relative_path.as_str()).collect();
        let r2: Vec<&str> = o2.files.iter().map(|f| f.relative_path.as_str()).collect();
        assert_eq!(r1, r2, "作成順によらず同一の列挙順");
    }

    #[test]
    fn discover_recursive_subdir() {
        let dir = create_test_dir();
        write_file(dir.path(), "root.yml", b"r");
        write_file(dir.path(), "sub/child.yml", b"c");
        write_file(dir.path(), "sub/deep/grandchild.yml", b"g");

        let outcome =
            discover_rule_directory(dir.path(), &RuleDiscoveryOptions::default()).unwrap();
        let rels: Vec<&str> = outcome
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert_eq!(
            rels,
            vec!["root.yml", "sub/child.yml", "sub/deep/grandchild.yml"]
        );
    }

    #[test]
    fn discover_non_recursive_ignores_subdirs() {
        let dir = create_test_dir();
        write_file(dir.path(), "root.yml", b"r");
        write_file(dir.path(), "sub/child.yml", b"c");

        let opts = RuleDiscoveryOptions {
            recursive: false,
            ..RuleDiscoveryOptions::default()
        };
        let outcome = discover_rule_directory(dir.path(), &opts).unwrap();
        assert_eq!(outcome.files.len(), 1);
        assert_eq!(outcome.files[0].relative_path, "root.yml");
    }

    #[test]
    fn discover_max_recursion_depth() {
        let dir = create_test_dir();
        write_file(dir.path(), "l0.yml", b"0");
        write_file(dir.path(), "d1/l1.yml", b"1");
        write_file(dir.path(), "d1/d2/l2.yml", b"2");

        let opts = RuleDiscoveryOptions {
            recursive: true,
            max_recursion_depth: 1, // root=0, sub=1 まで。孫=2 は不可。
            ..RuleDiscoveryOptions::default()
        };
        let outcome = discover_rule_directory(dir.path(), &opts).unwrap();
        let rels: Vec<&str> = outcome
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert!(rels.contains(&"l0.yml"));
        assert!(rels.contains(&"d1/l1.yml"));
        assert!(!rels.contains(&"d1/d2/l2.yml"));
    }

    #[test]
    fn discover_max_files_limit_truncates() {
        let dir = create_test_dir();
        write_file(dir.path(), "a.yml", b"a");
        write_file(dir.path(), "b.yml", b"b");
        write_file(dir.path(), "c.yml", b"c");

        let opts = RuleDiscoveryOptions {
            max_files: 2,
            ..RuleDiscoveryOptions::default()
        };
        let outcome = discover_rule_directory(dir.path(), &opts).unwrap();
        assert!(outcome.truncated, "max_files 到達で truncated");
        assert_eq!(outcome.files.len(), 2);
    }

    #[test]
    fn discover_single_file_input() {
        let dir = create_test_dir();
        let path = write_file(dir.path(), "single.yml", b"x");

        let outcome = discover_rule_directory(&path, &RuleDiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.files.len(), 1);
        assert_eq!(outcome.files[0].relative_path, "single.yml");
    }

    #[test]
    fn discover_empty_directory() {
        let dir = create_test_dir();
        let outcome =
            discover_rule_directory(dir.path(), &RuleDiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.files.len(), 0);
        assert!(!outcome.truncated);
    }

    #[test]
    fn discover_symlink_root_rejected() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = create_test_dir();
            let real = write_file(dir.path(), "real.yml", b"x");
            let link = dir.path().join("link_to_real");
            symlink(&real, &link).unwrap();

            let err = discover_rule_directory(&link, &RuleDiscoveryOptions::default()).unwrap_err();
            assert!(matches!(err, RuleLoadError::RootIsSymlink(_)));
        }
    }

    #[test]
    fn discover_symlink_inside_skipped() {
        // 規範 §2: symlink は追跡しない。
        let dir = create_test_dir();
        write_file(dir.path(), "real.yml", b"x");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(dir.path().join("real.yml"), dir.path().join("link.yml")).unwrap();
        }

        let outcome =
            discover_rule_directory(dir.path(), &RuleDiscoveryOptions::default()).unwrap();

        #[cfg(unix)]
        {
            assert_eq!(outcome.files.len(), 1, "real のみ files へ");
            assert_eq!(outcome.files[0].relative_path, "real.yml");
            assert_eq!(
                outcome.symlink_skipped.len(),
                1,
                "link は symlink_skipped へ"
            );
        }
        #[cfg(not(unix))]
        {
            assert_eq!(outcome.files.len(), 1);
            assert_eq!(outcome.symlink_skipped.len(), 0);
        }
    }

    // ===== T5-002: load_directory による統合 =====

    #[test]
    fn load_directory_utf8_byte_order() {
        let dir = create_test_dir();
        write_file(dir.path(), "zebra.yml", b"z");
        write_file(dir.path(), "alpha.yml", b"a");
        write_file(dir.path(), "mango.yml", b"m");

        let mut registry = RuleRegistry::new();
        let summary = registry
            .load_directory(dir.path(), &RuleLoadOptions::default())
            .unwrap();
        assert_eq!(summary.loaded.len(), 3);
        let rels: Vec<&str> = summary
            .loaded
            .iter()
            .map(|r| r.relative_path.as_str())
            .collect();
        assert_eq!(rels, vec!["alpha.yml", "mango.yml", "zebra.yml"]);
    }

    #[test]
    fn load_directory_dedup_across_subdirs() {
        // 異なる subdirectory 内の同一内容 file は1回だけ読み込まれる。
        let dir = create_test_dir();
        let content = b"shared rule content";
        write_file(dir.path(), "sigma/a.yml", content);
        write_file(dir.path(), "yara/b.yml", content);
        write_file(dir.path(), "corr/c.yml", b"unique");

        let mut registry = RuleRegistry::new();
        let summary = registry
            .load_directory(dir.path(), &RuleLoadOptions::default())
            .unwrap();
        assert_eq!(summary.loaded.len(), 2, "3 file 中2件が新規（1件は重複）");
        assert_eq!(summary.skipped_duplicates.len(), 1, "重複1件");
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn load_directory_continues_after_error() {
        // 個別 file の validation error は summary.errors へ蓄積し、処理は継続する。
        let dir = create_test_dir();
        write_file(dir.path(), "ok1.yml", b"ok1");
        let too_big = write_file(dir.path(), "big.yml", b"01234567890"); // 11 bytes
        write_file(dir.path(), "ok2.yml", b"ok2");

        let opts = RuleLoadOptions {
            max_file_size_bytes: 5,
            ..RuleLoadOptions::default()
        };
        let mut registry = RuleRegistry::new();
        let summary = registry.load_directory(dir.path(), &opts).unwrap();

        assert_eq!(summary.loaded.len(), 2, "ok1・ok2 は読み込まれる");
        assert_eq!(summary.errors.len(), 1, "big は size 超過で error");
        assert_eq!(summary.errors[0].path, too_big);
        assert!(matches!(
            summary.errors[0].error,
            RuleLoadError::TooLarge { .. }
        ));
    }

    #[test]
    fn load_directory_caller_can_detect_max_files_truncation() {
        // max_files 到達時は summary.truncated=true・max_files_limit=Some(n)。
        let dir = create_test_dir();
        write_file(dir.path(), "a.yml", b"a");
        write_file(dir.path(), "b.yml", b"b");
        write_file(dir.path(), "c.yml", b"c");

        let opts = RuleLoadOptions {
            max_files: 2,
            ..RuleLoadOptions::default()
        };
        let mut registry = RuleRegistry::new();
        let summary = registry.load_directory(dir.path(), &opts).unwrap();
        assert!(summary.truncated);
        assert_eq!(summary.max_files_limit, Some(2));
    }

    // ===== T5-003: validation error の Exit Code 5 =====

    #[test]
    fn exit_code_strict_rules_returns_5_for_validation_error() {
        // 規範 §17.2: strict rules mode なら Exit Code 5。
        let cases = vec![
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
            RuleLoadError::MaxRecursionDepth(PathBuf::from("deep")),
            RuleLoadError::PathNormalization(RulePathError::Empty),
        ];
        for err in cases {
            assert_eq!(
                err.exit_code(true),
                ExitCode::RuleValidationOrStrictRulesError,
                "strict rules なら Exit Code 5: {err:?}"
            );
        }
    }

    #[test]
    fn exit_code_non_strict_returns_1_for_validation_error() {
        // 規範 §17.2: 非 strict なら skip + Warning（Exit Code 1 へ寄与）。
        let err = RuleLoadError::TooLarge {
            path: PathBuf::from("big.yml"),
            size: 100,
            limit: 10,
        };
        assert_eq!(err.exit_code(false), ExitCode::CaseWithWarnings);
    }

    #[test]
    fn exit_code_input_error_for_root_problems() {
        // 入力 root の問題は Exit Code 3（strict に関わらず）。
        let cases = vec![
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
                "入力 root の問題は Exit Code 3: {err:?}"
            );
            assert_eq!(
                err.exit_code(false),
                ExitCode::InputOrDiscoveryError,
                "strict に関わらず Exit Code 3: {err:?}"
            );
        }
    }

    #[test]
    fn exit_code_aggregation_via_merge() {
        // 規範 §17.2: 複数 error は優先順位 `10 > 6 > 5 > 4 > 3 > 2 > 1 > 0` で集約。
        let validation = RuleLoadError::TooLarge {
            path: PathBuf::new(),
            size: 0,
            limit: 0,
        };
        let root_err = RuleLoadError::RootIsSymlink(PathBuf::new());

        // strict rules の validation error は Exit Code 5。
        let strict_exit = validation.exit_code(true);
        // root 問題は Exit Code 3。
        let root_exit = root_err.exit_code(true);

        // 優先順位: 5 > 3 なので strict_exit が勝つ。
        let merged = strict_exit.merge(root_exit);
        assert_eq!(merged, ExitCode::RuleValidationOrStrictRulesError);
    }

    #[test]
    fn rule_load_options_from_config() {
        // Config の limits から既定値を構築できる。
        let config = tf_core::Config::defaults();
        let opts = RuleLoadOptions::from_config(&config);
        assert_eq!(opts.max_files, config.limits.max_rule_files);
        assert_eq!(
            opts.max_file_size_bytes,
            config.limits.max_rule_file_size_bytes
        );
        assert_eq!(opts.max_recursion_depth, config.limits.max_recursion_depth);
        assert!(opts.recursive);
    }

    #[test]
    fn registry_handles_multiple_directories_with_shared_state() {
        // 複数 directory をまたいでも registry は重複検出する。
        let dir1 = create_test_dir();
        let dir2 = create_test_dir();
        let shared = b"shared content";
        write_file(dir1.path(), "a.yml", shared);
        write_file(dir2.path(), "b.yml", shared);

        let mut registry = RuleRegistry::new();
        let s1 = registry
            .load_directory(dir1.path(), &RuleLoadOptions::default())
            .unwrap();
        let s2 = registry
            .load_directory(dir2.path(), &RuleLoadOptions::default())
            .unwrap();

        assert_eq!(s1.loaded.len(), 1);
        assert_eq!(s2.loaded.len(), 0, "2 つ目は同一内容なので新規0件");
        assert_eq!(s2.skipped_duplicates.len(), 1);
        assert_eq!(registry.len(), 1);
    }
}
