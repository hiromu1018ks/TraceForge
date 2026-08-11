//! Rule file 用の相対 path 正規化（規範 §14: 「正規化相対pathのUTF-8 byte順」）。
//!
//! 規範 §14 は Rule directory 列挙順を「正規化相対pathのUTF-8 byte順」と規定する。
//! 本 module はその「正規化」を扱う。Evidence source_locator（規範 §5.2）と同じ
//! `/` separator への統一と安全な component 抽出を行うが、Evidence 固有の NFC
//! 正規化は行わない（Rule directory は ASCII file 名が多く、規範 §14 は明示的に
//! NFC を要求しないため）。
//!
//! 適用する正規化規則:
//! 1. OS 依存 separator（`\` on Windows）を `/` へ統一する。
//! 2. 先頭 separator・末尾 separator・連続 separator を無視する。
//! 3. `.` および `..` component を拒否する（解決ではなく拒否・規範 §2 安全プロファイル）。
//! 4. 絶対 path（先頭 `/` または Windows drive letter `C:` 等）を拒否する。
//! 5. 非 UTF-8 byte を含む file 名は `%XX`（大文字 hex）escape する（規範 §5.2 準拠）。
//!
//! 大文字小文字は変更しない（case-sensitive filesystem と case-insensitive filesystem
//! 両方で決定性を保つため）。sort key としては得られた文字列の UTF-8 byte 列を用いる。

use std::path::Path;

/// 相対 path 正規化の失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RulePathError {
    /// 相対 path が空、または component が1つもない。
    #[error("Rule の相対 path が空である")]
    Empty,
    /// `.` または `..` component が含まれる（規範 §2: 安全プロファイル）。
    #[error("Rule の相対 path に '.' または '..' component が含まれる: {0}")]
    DotOrParentComponent(String),
    /// 絶対 path のように見える（先頭 `/` または Windows drive letter）。
    #[error("Rule の相対 path が絶対 path のように見える: {0}")]
    AbsolutePath(String),
}

/// 入力 root からの相対 path 文字列を、Rule directory 列挙順の sort key へ正規化する。
///
/// 入力 `relative` は OS 依存の separator（`\` on Windows）を含んでよい。
/// 出力は常に `/` 区切り・`.`/`..` なしの文字列となる。
///
/// # 例
/// ```
/// # use tf_engines::path_norm::normalize_rule_relative_path;
/// assert_eq!(
///     normalize_rule_relative_path(r"sigma\rule.yml").unwrap(),
///     "sigma/rule.yml"
/// );
/// ```
pub fn normalize_rule_relative_path(relative: &str) -> Result<String, RulePathError> {
    if relative.is_empty() {
        return Err(RulePathError::Empty);
    }

    // 規範 §14: separator は `/` へ統一する（Windows `\` も受け付ける）。
    let unified = relative.replace('\\', "/");

    // 絶対 path の検出: 先頭 `/` または Windows drive letter (`C:` 等)。
    if unified.starts_with('/') {
        return Err(RulePathError::AbsolutePath(relative.into()));
    }
    if unified.len() >= 2 && unified.as_bytes()[1] == b':' {
        // 2 文字目が `:` の場合は Windows drive letter とみなす（例: `C:`、`z:`）。
        return Err(RulePathError::AbsolutePath(relative.into()));
    }

    let mut components: Vec<&str> = Vec::new();
    for comp in unified.split('/') {
        match comp {
            "" => continue, // 連続 separator・先頭/末尾 separator は無視
            "." | ".." => {
                return Err(RulePathError::DotOrParentComponent(relative.into()));
            }
            _ => components.push(comp),
        }
    }

    if components.is_empty() {
        return Err(RulePathError::Empty);
    }

    Ok(components.join("/"))
}

/// `Path` の `root` からの相対 path を正規化する。
///
/// file 名が valid UTF-8 でない場合は `%XX`（大文字 hex）escape する（規範 §5.2 準拠）。
pub fn relative_path_key(path: &Path, root: &Path) -> Result<String, RulePathError> {
    let components: Vec<String> = path
        .strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| {
            let os_str = c.as_os_str();
            match os_str.to_str() {
                Some(s) => s.to_string(),
                None => escape_non_utf8_bytes(os_str.as_encoded_bytes()),
            }
        })
        .collect();
    let joined = components.join("/");
    normalize_rule_relative_path(&joined)
}

/// 非 UTF-8 byte 列を `%XX`（大文字 hex）escape しつつ String へ変換する（規範 §5.2 準拠）。
pub fn escape_non_utf8_bytes(bytes: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        match std::str::from_utf8(&bytes[i..]) {
            Ok(s) => {
                result.push_str(s);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                if valid > 0 {
                    // safety: valid_up_to() までは有効な UTF-8 であることが保証されている。
                    result.push_str(
                        std::str::from_utf8(&bytes[i..i + valid]).expect("有効な UTF-8 区間"),
                    );
                }
                result.push_str(&format!("%{:02X}", bytes[i + valid]));
                i += valid + 1;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_basic_relative() {
        assert_eq!(
            normalize_rule_relative_path("sigma/rule.yml").unwrap(),
            "sigma/rule.yml"
        );
    }

    #[test]
    fn normalize_backslash_to_slash() {
        assert_eq!(
            normalize_rule_relative_path(r"sigma\rule.yml").unwrap(),
            "sigma/rule.yml"
        );
    }

    #[test]
    fn normalize_preserves_case() {
        // case-sensitive filesystem と case-insensitive filesystem 両方で
        // 決定性を保つため、大文字小文字は保持する。
        assert_eq!(
            normalize_rule_relative_path("Sigma/Rule.YML").unwrap(),
            "Sigma/Rule.YML"
        );
    }

    #[test]
    fn normalize_collapses_redundant_separators() {
        assert_eq!(normalize_rule_relative_path("a//b///c").unwrap(), "a/b/c");
    }

    #[test]
    fn normalize_trims_trailing_separator() {
        assert_eq!(normalize_rule_relative_path("a/b/").unwrap(), "a/b");
    }

    #[test]
    fn normalize_rejects_dot_component() {
        assert!(matches!(
            normalize_rule_relative_path("a/./b"),
            Err(RulePathError::DotOrParentComponent(_))
        ));
    }

    #[test]
    fn normalize_rejects_parent_component() {
        assert!(matches!(
            normalize_rule_relative_path("a/../b"),
            Err(RulePathError::DotOrParentComponent(_))
        ));
    }

    #[test]
    fn normalize_rejects_absolute_unix_path() {
        assert!(matches!(
            normalize_rule_relative_path("/etc/rule.yml"),
            Err(RulePathError::AbsolutePath(_))
        ));
    }

    #[test]
    fn normalize_rejects_windows_drive_letter() {
        assert!(matches!(
            normalize_rule_relative_path(r"C:\rules\rule.yml"),
            Err(RulePathError::AbsolutePath(_))
        ));
    }

    #[test]
    fn normalize_rejects_empty() {
        assert_eq!(normalize_rule_relative_path(""), Err(RulePathError::Empty));
    }

    #[test]
    fn normalize_rejects_only_separators() {
        // `///` は先頭 `/` のため絶対 path 扱い。
        assert!(matches!(
            normalize_rule_relative_path("///"),
            Err(RulePathError::AbsolutePath(_))
        ));
    }

    #[test]
    fn escape_valid_utf8_unchanged() {
        assert_eq!(escape_non_utf8_bytes(b"hello"), "hello");
        assert_eq!(escape_non_utf8_bytes(b""), "");
    }

    #[test]
    fn escape_invalid_byte() {
        assert_eq!(escape_non_utf8_bytes(&[0xFF]), "%FF");
    }

    #[test]
    fn escape_multibyte_utf8_preserved() {
        // 3 byte UTF-8 文字（日本語「あ」= E3 81 82）はそのまま保持。
        assert_eq!(escape_non_utf8_bytes("あ".as_bytes()), "あ");
    }
}
