//! 決定的 Evidence discovery（規範 §5.3、互換 §3）。
//!
//! 入力 root 配下の Evidence 候補を `source_locator` の UTF-8 byte 昇順で列挙する
//! （規範 §5.3）。filesystem が返す列挙順には依存しない。
//!
//! 既定の安全プロファイル（規範 §2）:
//! - symlink は追跡せず `TF-W-DISCOVERY-SYMLINK` を記録する
//! - directory traversal は recursive（既定 ON）
//! - depth 制限は `max_recursion_depth`
//!
//! 対象外入力（互換 §3: disk image・container・archive）の自動展開は行わない。

use std::fs;
use std::path::{Path, PathBuf};

use tf_core::issue::{Issue, IssueScope, IssueSeverity};

use crate::source_locator::{escape_non_utf8_bytes, normalize_source_locator};

/// symlink skip 時に記録する Issue code（規範 §5.3）。
pub const SYMLINK_SKIP_CODE: &str = "TF-W-DISCOVERY-SYMLINK";

/// `max_files` limit 到達時に記録する Issue code（規範 §18）。
pub const MAX_FILES_LIMIT_CODE: &str = "TF-W-LIMIT-MAX-FILES";

/// 発見された1件の Evidence 候補。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredFile {
    /// 正規化済み source_locator（規範 §5.2）。
    pub source_locator: String,
    /// 解析 host 上の絶対 path。snapshot 作成時に使用する。
    pub host_path: PathBuf,
}

/// discovery の実行結果。
#[derive(Clone, Debug, Default)]
pub struct DiscoveryOutcome {
    /// `source_locator` の UTF-8 byte 昇順で sort 済みの Evidence 一覧（規範 §5.3）。
    pub files: Vec<DiscoveredFile>,
    /// symlink として skip した source_locator の一覧。Issue 生成に使用する。
    pub symlink_skipped: Vec<String>,
    /// `max_files` limit 到達で打ち切ったか。
    pub truncated: bool,
}

/// discovery の設定。
#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    /// recursive traversal（規範 §2: 既定 ON）。
    pub recursive: bool,
    /// 再帰の最大深度。root 直下は深度 0（Schema §8.2: 既定 64）。
    pub max_recursion_depth: u64,
    /// 処理する file 数の上限（Schema §8.2: 既定 100000）。
    pub max_files: u64,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        DiscoveryOptions {
            recursive: true,
            max_recursion_depth: 64,
            max_files: 100_000,
        }
    }
}

/// discovery の失敗。
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// 入力 root が存在しない、または読み取れない。
    #[error("入力 root へのアクセスに失敗した: {0}: {1}")]
    AccessFailed(PathBuf, String),
    /// 入力 root 自体が symlink（規範 §5.3: symlink は追跡しない）。
    #[error("入力 root 自体が symlink である: {0}")]
    RootIsSymlink(PathBuf),
    /// source_locator の正規化に失敗した（規範 §5.2）。
    #[error(transparent)]
    LocatorError(#[from] crate::source_locator::SourceLocatorError),
}

/// 入力 root 配下を決定的順序で走査する（規範 §5.3）。
///
/// `input_root` は directory または単一 file のいずれか。
/// directory の場合は `options.recursive` に従って再帰走査する。
/// 単一 file の場合は source_locator を file 名のみへ正規化する。
///
/// symlink は全て skip し、`outcome.symlink_skipped` へ記録する（規範 §5.3）。
/// 結果の `files` は `source_locator` の UTF-8 byte 昇順で sort 済みである。
pub fn discover(
    input_root: &Path,
    options: &DiscoveryOptions,
) -> Result<DiscoveryOutcome, DiscoveryError> {
    // 入力 root が symlink でないことを確認（規範 §5.3）。
    let root_meta = fs::symlink_metadata(input_root)
        .map_err(|e| DiscoveryError::AccessFailed(input_root.to_path_buf(), e.to_string()))?;
    if root_meta.is_symlink() {
        return Err(DiscoveryError::RootIsSymlink(input_root.to_path_buf()));
    }

    let mut outcome = DiscoveryOutcome::default();

    if root_meta.is_dir() {
        // directory の場合: recursive 走査
        walk_directory(input_root, input_root, 0, options, &mut outcome)?;
    } else {
        // 単一 file の場合: source_locator は file 名のみ
        let name = file_name_or_fallback(input_root);
        let locator = normalize_source_locator(&name)?;
        if options.max_files >= 1 {
            outcome.files.push(DiscoveredFile {
                source_locator: locator,
                host_path: input_root.to_path_buf(),
            });
        }
    }

    // 規範 §5.3: source_locator の UTF-8 byte 昇順で sort。
    // filesystem 列挙順には依存しない（決定性）。
    outcome
        .files
        .sort_by(|a, b| a.source_locator.cmp(&b.source_locator));
    outcome.symlink_skipped.sort();

    Ok(outcome)
}

/// 1 directory を再帰走査する内部関数。
fn walk_directory(
    dir: &Path,
    root: &Path,
    depth: u64,
    options: &DiscoveryOptions,
    outcome: &mut DiscoveryOutcome,
) -> Result<(), DiscoveryError> {
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
            return Err(DiscoveryError::AccessFailed(
                dir.to_path_buf(),
                e.to_string(),
            ));
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

        // symlink_metadata を使って symlink を検出する（規範 §5.3）。
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // symlink は追跡しない（規範 §2・§5.3）。
        if meta.is_symlink() {
            let rel = relative_locator(&path, root);
            outcome.symlink_skipped.push(rel);
            continue;
        }

        if meta.is_dir() {
            if options.recursive {
                walk_directory(&path, root, depth + 1, options, outcome)?;
            }
            // recursive でない場合は subdirectory を無視する。
        } else {
            // 通常 file として候補へ追加。
            let locator = relative_locator(&path, root);
            match normalize_source_locator(&locator) {
                Ok(normalized) => {
                    outcome.files.push(DiscoveredFile {
                        source_locator: normalized,
                        host_path: path,
                    });
                }
                Err(_) => continue, // 正規化失敗は skip
            }
        }
    }

    Ok(())
}

/// `path` の `root` からの相対 path 文字列を構築する。
///
/// file 名が valid UTF-8 でない場合は `%XX` escape する（規範 §5.2）。
fn relative_locator(path: &Path, root: &Path) -> String {
    let rel_components: Vec<String> = path
        .strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| match c.as_os_str().to_str() {
            Some(s) => s.to_string(),
            None => {
                // 非 UTF-8 file 名は %XX escape する（規範 §5.2）。
                let bytes = c.as_os_str().to_string_lossy().into_owned();
                escape_non_utf8_bytes(bytes.as_bytes())
            }
        })
        .collect();
    rel_components.join("/")
}

/// Path の file 名部分を取得する。取得できない場合は fallback 文字列を返す。
fn file_name_or_fallback(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("_unnamed")
        .to_string()
}

/// symlink skip から Issue を生成する（規範 §5.3: `TF-W-DISCOVERY-SYMLINK`）。
pub fn symlink_skip_issues(outcome: &DiscoveryOutcome) -> Vec<Issue> {
    outcome
        .symlink_skipped
        .iter()
        .map(|locator| Issue {
            issue_id: SYMLINK_SKIP_CODE.to_string(),
            severity: IssueSeverity::Warning,
            scope: IssueScope::Evidence,
            evidence_id: None,
            artifact_id: None,
            record_locator: None,
            source_ordinal: None,
            message: format!("symlink を追跡せず skip した: {locator}"),
        })
        .collect()
}

/// `max_files` limit 到達の Issue を生成する（規範 §18: `TF-W-LIMIT-MAX-FILES`）。
pub fn max_files_limit_issue(limit: u64) -> Issue {
    Issue {
        issue_id: MAX_FILES_LIMIT_CODE.to_string(),
        severity: IssueSeverity::Warning,
        scope: IssueScope::Case,
        evidence_id: None,
        artifact_id: None,
        record_locator: None,
        source_ordinal: None,
        message: format!("file 数が上限 {limit} に到達したため処理を打ち切った"),
    }
}

/// 入力 root が対象外入力（disk image・container・archive）か簡易検査する（互換 §3）。
///
/// magic byte（先頭数 byte）で既知の container 形式を検出する。
/// 対象外入力を検出した場合は `true` を返す。内包 file を推測で探索してはならない
/// （互換 §3: "対象外入力を検出した場合、内包 file を推測で探索してはならない"）。
pub fn is_non_target_container(header: &[u8]) -> bool {
    // E01 (EnCase) signature
    header.starts_with(b"LV\r\n\x7f\x00\x00\x00")
    // VMDK descriptor
    || header.starts_with(b"# Disk DescriptorFile")
    // 7z
    || header.starts_with(b"7z\xbc\xaf'\x1c")
    // RAR4
    || header.starts_with(b"Rar!\x1a\x07\x00")
    // RAR5
    || header.starts_with(b"Rar!\x1a\x07\x01\x00")
    // ZIP (PK)
    || header.starts_with(b"PK\x03\x04")
    // gzip
    || header.starts_with(b"\x1f\x8b")
    // OVF/OVA は tar であり、tar は offset 257 の magic で判定
    || (header.len() >= 263 && &header[257..262] == b"ustar")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn create_test_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("一時 directory の作成に失敗")
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
    }

    #[test]
    fn discover_single_file() {
        let dir = create_test_dir();
        let input = dir.path().join("Security.evtx");
        fs::write(&input, b"data").unwrap();

        let outcome = discover(&input, &DiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.files.len(), 1);
        assert_eq!(outcome.files[0].source_locator, "Security.evtx");
    }

    #[test]
    fn discover_directory_flat() {
        let dir = create_test_dir();
        write_file(dir.path(), "a.evtx", b"a");
        write_file(dir.path(), "b.evtx", b"b");
        write_file(dir.path(), "c.evtx", b"c");

        let outcome = discover(dir.path(), &DiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.files.len(), 3);
        // 規範 §5.3: source_locator の UTF-8 byte 昇順。
        assert_eq!(outcome.files[0].source_locator, "a.evtx");
        assert_eq!(outcome.files[1].source_locator, "b.evtx");
        assert_eq!(outcome.files[2].source_locator, "c.evtx");
    }

    #[test]
    fn discover_recursive() {
        let dir = create_test_dir();
        write_file(dir.path(), "root.evtx", b"r");
        write_file(dir.path(), "sub/child.evtx", b"c");
        write_file(dir.path(), "sub/deep/grandchild.evtx", b"g");

        let outcome = discover(dir.path(), &DiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.files.len(), 3);
        // sort 済み
        assert_eq!(outcome.files[0].source_locator, "root.evtx");
        assert_eq!(outcome.files[1].source_locator, "sub/child.evtx");
        assert_eq!(outcome.files[2].source_locator, "sub/deep/grandchild.evtx");
    }

    #[test]
    fn discover_non_recursive_ignores_subdirs() {
        let dir = create_test_dir();
        write_file(dir.path(), "root.evtx", b"r");
        write_file(dir.path(), "sub/child.evtx", b"c");

        let opts = DiscoveryOptions {
            recursive: false,
            ..DiscoveryOptions::default()
        };
        let outcome = discover(dir.path(), &opts).unwrap();
        assert_eq!(outcome.files.len(), 1);
        assert_eq!(outcome.files[0].source_locator, "root.evtx");
    }

    #[test]
    fn discover_sort_order_independent_of_fs() {
        // 規範 §5.3: filesystem 列挙順に依存しない。
        let dir = create_test_dir();
        // 逆順で作成しても結果は byte 昇順。
        write_file(dir.path(), "zebra.evtx", b"z");
        write_file(dir.path(), "alpha.evtx", b"a");
        write_file(dir.path(), "mango.evtx", b"m");

        let outcome = discover(dir.path(), &DiscoveryOptions::default()).unwrap();
        let locators: Vec<&str> = outcome
            .files
            .iter()
            .map(|f| f.source_locator.as_str())
            .collect();
        assert_eq!(locators, vec!["alpha.evtx", "mango.evtx", "zebra.evtx"]);
    }

    #[test]
    fn discover_skips_symlinks() {
        // 規範 §5.3・§2: symlink は skip して Warning。
        let dir = create_test_dir();
        write_file(dir.path(), "real.evtx", b"data");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(dir.path().join("real.evtx"), dir.path().join("link.evtx")).unwrap();
        }

        let outcome = discover(dir.path(), &DiscoveryOptions::default()).unwrap();

        #[cfg(unix)]
        {
            // symlink は files に含まれない。
            assert_eq!(outcome.files.len(), 1);
            assert_eq!(outcome.files[0].source_locator, "real.evtx");
            // symlink は symlink_skipped に記録される。
            assert_eq!(outcome.symlink_skipped.len(), 1);
            assert_eq!(outcome.symlink_skipped[0], "link.evtx");
        }

        // symlink skip Issue の生成。
        let issues = symlink_skip_issues(&outcome);
        #[cfg(unix)]
        assert_eq!(issues.len(), 1);
        #[cfg(not(unix))]
        assert_eq!(issues.len(), 0);
    }

    #[test]
    fn discover_symlink_loop_not_followed() {
        // 規範 §21-10: symlink loop を追跡しない。
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = create_test_dir();
            write_file(dir.path(), "real.evtx", b"data");

            // loop: dir/loop -> dir
            symlink(dir.path(), dir.path().join("loop")).unwrap();

            let outcome = discover(dir.path(), &DiscoveryOptions::default()).unwrap();
            // loop symlink 自体が skip され、 infinite recursion は起きない。
            assert!(
                outcome
                    .files
                    .iter()
                    .all(|f| !f.source_locator.contains("loop"))
            );
        }
    }

    #[test]
    fn discover_max_files_limit() {
        let dir = create_test_dir();
        write_file(dir.path(), "a.evtx", b"a");
        write_file(dir.path(), "b.evtx", b"b");
        write_file(dir.path(), "c.evtx", b"c");

        let opts = DiscoveryOptions {
            max_files: 2,
            ..DiscoveryOptions::default()
        };
        let outcome = discover(dir.path(), &opts).unwrap();
        // 規範 §18: max_files 到達で打ち切り。
        assert!(outcome.truncated);
        assert_eq!(outcome.files.len(), 2);
    }

    #[test]
    fn discover_max_recursion_depth() {
        let dir = create_test_dir();
        write_file(dir.path(), "l0.evtx", b"0");
        write_file(dir.path(), "d1/l1.evtx", b"1");
        write_file(dir.path(), "d1/d2/l2.evtx", b"2");

        let opts = DiscoveryOptions {
            recursive: true,
            max_recursion_depth: 1, // root=0, sub=1 まで。孫=2 は不可。
            ..DiscoveryOptions::default()
        };
        let outcome = discover(dir.path(), &opts).unwrap();
        // 深度 1 までなので l0.evtx と l1.evtx は発見、l2.evtx は未発見。
        let locators: Vec<&str> = outcome
            .files
            .iter()
            .map(|f| f.source_locator.as_str())
            .collect();
        assert!(locators.contains(&"l0.evtx"));
        assert!(locators.contains(&"d1/l1.evtx"));
        assert!(!locators.contains(&"d1/d2/l2.evtx"));
    }

    #[test]
    fn discover_rejects_symlink_root() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = create_test_dir();
            write_file(dir.path(), "real.evtx", b"data");
            let link = dir.path().join("link_to_real");
            symlink(dir.path().join("real.evtx"), &link).unwrap();

            let result = discover(&link, &DiscoveryOptions::default());
            assert!(matches!(result, Err(DiscoveryError::RootIsSymlink(_))));
        }
    }

    #[test]
    fn is_non_target_container_detects_formats() {
        // 互換 §3: disk image・container・archive の magic byte 検出。
        assert!(is_non_target_container(b"PK\x03\x04...")); // ZIP
        assert!(is_non_target_container(b"7z\xbc\xaf'\x1c...")); // 7z
        assert!(is_non_target_container(b"Rar!\x1a\x07\x00...")); // RAR4
        assert!(is_non_target_container(b"\x1f\x8b...")); // gzip
        assert!(is_non_target_container(b"LV\r\n\x7f\x00\x00\x00")); // E01

        // 通常 file は非対象外。
        assert!(!is_non_target_container(b"ElfFile\x01\x00\x00\x00"));
        assert!(!is_non_target_container(b""));
    }

    #[test]
    fn discover_empty_directory() {
        let dir = create_test_dir();
        let outcome = discover(dir.path(), &DiscoveryOptions::default()).unwrap();
        assert_eq!(outcome.files.len(), 0);
        assert!(!outcome.truncated);
    }
}
