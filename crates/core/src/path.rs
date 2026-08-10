//! Windows path と `windows-path-v1` normalization profile（規範 §8）。
//!
//! Evidence 内に記録された Windows path へ `PathBuf` を使ってはならない（規範 §8、
//! AGENTS.md 禁止事項）。代わりに [`WindowsPathValue`] を使う。
//!
//! 既定 profile `windows-path-v1`（規範 §8）は次の6規則だけを行う:
//!
//! 1. `/` を `\` へ変換する。
//! 2. 重複 separator を1つにする。ただし UNC 先頭 `\\` は保持する。
//! 3. ASCII drive letter を大文字へ変換する。
//! 4. 比較 key（`comparison_key`）だけを Unicode case fold する。
//! 5. `.` component を削除する。
//! 6. root を越えない `..` を解決する。
//!
//! 環境変数展開・drive mapping・8.3 名展開・Volume GUID 変換・device path 変換は、
//! Case 固有 mapping が明示された場合だけ行う（本 profile では行わない）。

/// 既定 normalization profile 名（規範 §8）。
pub const WINDOWS_PATH_V1: &str = "windows-path-v1";

/// Evidence 内の Windows path 表現（規範 §8、Schema §5.5）。
///
/// `original` は Evidence 内の元表現そのまま。`comparison_key` は正規化済みの
/// 比較鍵（[`normalize_windows_path_v1`] で計算）。`normalization_notes` は
/// 適用した規則の記録。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsPathValue {
    pub original: String,
    pub comparison_key: Option<String>,
    pub normalization_profile: String,
    pub normalization_notes: Vec<String>,
}

impl WindowsPathValue {
    /// `original` から [`windows-path-v1`] で正規化した [`WindowsPathValue`] を作る。
    ///
    /// [`windows-path-v1`]: WINDOWS_PATH_V1
    pub fn new(original: impl Into<String>) -> WindowsPathValue {
        let original = original.into();
        let (comparison_key, notes) = normalize_windows_path_v1(&original);
        WindowsPathValue {
            original,
            comparison_key,
            normalization_profile: WINDOWS_PATH_V1.to_string(),
            normalization_notes: notes,
        }
    }

    /// Schema §5.5 形式の [`serde_json::Value`] を構築する。
    pub fn to_canonical_value(&self) -> serde_json::Value {
        serde_json::json!({
            "original": self.original,
            "comparison_key": self.comparison_key,
            "normalization_profile": self.normalization_profile,
            "normalization_notes": self.normalization_notes,
        })
    }

    /// [`to_canonical_value`] の結果を canonical JSON 文字列へ変換する。
    ///
    /// [`to_canonical_value`]: WindowsPathValue::to_canonical_value
    pub fn to_canonical_json(&self) -> String {
        crate::canonical::to_canonical_string_or_panic(&self.to_canonical_value())
    }
}

/// Windows path の root 種別。
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathRoot {
    /// UNC path（先頭 `\\`）。`\\server\share\...`。
    Unc,
    /// Drive letter 付き絶対 path。`C:\...` または `C:...`。
    Drive(char),
    /// Drive なし絶対 path（先頭 `\` のみ）。
    AbsSlash,
    /// 相対 path（root なし）。
    None,
}

/// 先頭形態を判定し、root 以降の文字列を返す。
fn parse_root(s: &str) -> (PathRoot, &str) {
    if let Some(rest) = s.strip_prefix("\\\\") {
        return (PathRoot::Unc, rest);
    }
    let bytes = s.as_bytes();
    // drive letter: ASCII alphabet + ':'。規則3で大文字へ正規化する。
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let drive = bytes[0].to_ascii_uppercase() as char;
        // `C:\...` の場合は `\` を separator として消費。`C:...` の場合はそのまま。
        let rest = if bytes.len() >= 3 && bytes[2] == b'\\' {
            &s[3..]
        } else {
            &s[2..]
        };
        return (PathRoot::Drive(drive), rest);
    }
    if let Some(rest) = s.strip_prefix('\\') {
        return (PathRoot::AbsSlash, rest);
    }
    (PathRoot::None, s)
}

/// root と component 列から正規化済み（case fold 前）の path 文字列を組み立てる。
fn join_with_root(root: &PathRoot, components: &[String]) -> String {
    let body = components.join("\\");
    match root {
        PathRoot::Unc => {
            if body.is_empty() {
                "\\\\".to_string()
            } else {
                format!("\\\\{body}")
            }
        }
        PathRoot::Drive(c) => {
            if body.is_empty() {
                format!("{c}:")
            } else {
                format!("{}:\\{body}", c)
            }
        }
        PathRoot::AbsSlash => {
            if body.is_empty() {
                "\\".to_string()
            } else {
                format!("\\{body}")
            }
        }
        PathRoot::None => body,
    }
}

/// `windows-path-v1` normalization profile（規範 §8）。
///
/// 戻り値は `(comparison_key, 適用規則の note 一覧)`。
/// `comparison_key` は case fold 済みの比較鍵。空入力に対しても `Some("")` を返す。
pub fn normalize_windows_path_v1(original: &str) -> (Option<String>, Vec<String>) {
    let mut notes = Vec::new();

    // 規則1: `/` を `\` へ変換。
    let converted: String = original
        .chars()
        .map(|c| if c == '/' { '\\' } else { c })
        .collect();
    if converted != original {
        notes.push("forward_slash_converted".into());
    }

    let (root, rest) = parse_root(&converted);

    // rest を component へ分解。空 component（重複 separator）は規則2で無視。
    let mut components: Vec<String> = Vec::new();
    for part in rest.split('\\') {
        if part.is_empty() {
            // 規則2: 重複 separator を1つに。
            continue;
        }
        if part == "." {
            // 規則5: `.` component を削除。
            notes.push("dot_component_removed".into());
            continue;
        }
        components.push(part.to_string());
    }

    // 規則6: `..` を解決（root を越えない）。
    let mut resolved: Vec<String> = Vec::new();
    for part in components {
        if part == ".." {
            // 直前の component が「pop 可能」か（root marker でない・`..` でない）。
            let poppable = resolved.last().map(|last| last != "..").unwrap_or(false);
            if poppable {
                resolved.pop();
                notes.push("parent_component_resolved".into());
            } else {
                match &root {
                    PathRoot::None => {
                        // 相対 path の先頭 `..` は文脈がないため保持する（root 越えではない）。
                        resolved.push("..".to_string());
                        notes.push("parent_component_kept_relative".into());
                    }
                    _ => {
                        // 絶対/UNC/Drive の root を越える `..` は安全のため削除する。
                        notes.push("parent_component_dropped_at_root".into());
                    }
                }
            }
        } else {
            resolved.push(part);
        }
    }

    // root + components を組み立て（規則2/3 反映済み）。
    let joined = join_with_root(&root, &resolved);

    // 規則4: 比較 key だけ Unicode case fold する（`String::to_lowercase`: simple case fold）。
    let comparison = joined.to_lowercase();
    if comparison != joined {
        notes.push("comparison_key_case_folded".into());
    }

    (Some(comparison), notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_slash_converted() {
        // 規則1: / → \
        let p = WindowsPathValue::new("C:/Users/alice/file.exe");
        assert_eq!(
            p.comparison_key.as_deref(),
            Some("c:\\users\\alice\\file.exe")
        );
        assert!(
            p.normalization_notes
                .contains(&"forward_slash_converted".into())
        );
    }

    #[test]
    fn drive_letter_uppercased() {
        // 規則3: ASCII drive letter を大文字。
        let lower = WindowsPathValue::new("c:\\users\\alice");
        let upper = WindowsPathValue::new("C:\\Users\\alice");
        assert_eq!(lower.comparison_key, upper.comparison_key);
        assert_eq!(lower.comparison_key.as_deref(), Some("c:\\users\\alice"));
    }

    #[test]
    fn comparison_key_case_folded_only() {
        // 規則4: 比較 key だけ case fold。original は保持。
        let p = WindowsPathValue::new("C:\\Users\\Alice\\File.exe");
        assert_eq!(p.original, "C:\\Users\\Alice\\File.exe");
        assert_eq!(
            p.comparison_key.as_deref(),
            Some("c:\\users\\alice\\file.exe")
        );
    }

    #[test]
    fn dot_component_removed() {
        // 規則5: `.` component を削除。
        let p = WindowsPathValue::new("C:\\Users\\.\\alice");
        assert_eq!(p.comparison_key.as_deref(), Some("c:\\users\\alice"));
    }

    #[test]
    fn parent_resolved_within_root() {
        // 規則6: root を越えない `..` を解決。
        let p = WindowsPathValue::new("C:\\Users\\..\\Users\\alice");
        assert_eq!(p.comparison_key.as_deref(), Some("c:\\users\\alice"));
    }

    #[test]
    fn parent_at_root_dropped() {
        // 規則6: root を越える `..` は削除（安全側）。
        let p = WindowsPathValue::new("C:\\..\\..\\Windows");
        assert_eq!(p.comparison_key.as_deref(), Some("c:\\windows"));
    }

    #[test]
    fn parent_in_relative_path_kept() {
        // 相対 path の先頭 `..` は文脈がないため保持する。
        let p = WindowsPathValue::new("..\\bar");
        assert_eq!(p.comparison_key.as_deref(), Some("..\\bar"));
    }

    #[test]
    fn duplicate_separators_collapsed() {
        // 規則2: 重複 separator を1つに。
        let p = WindowsPathValue::new("C:\\\\Users\\\\alice");
        assert_eq!(p.comparison_key.as_deref(), Some("c:\\users\\alice"));
    }

    #[test]
    fn unc_double_slash_preserved() {
        // 規則2: UNC 先頭 `\\` は保持。
        let p = WindowsPathValue::new("\\\\server\\share\\file");
        assert_eq!(p.comparison_key.as_deref(), Some("\\\\server\\share\\file"));
    }

    #[test]
    fn unc_duplicate_separators_collapsed_after_root() {
        // UNC の先頭 \\ は保持しつつ、それ以降の重複 sep を1つに。
        let p = WindowsPathValue::new("\\\\server\\\\share\\file");
        assert_eq!(p.comparison_key.as_deref(), Some("\\\\server\\share\\file"));
    }

    #[test]
    fn unc_with_dots_and_parent() {
        let p = WindowsPathValue::new("\\\\srv\\share\\.\\dir\\..\\file");
        assert_eq!(p.comparison_key.as_deref(), Some("\\\\srv\\share\\file"));
    }

    #[test]
    fn empty_path_yields_empty_key() {
        let p = WindowsPathValue::new("");
        assert_eq!(p.comparison_key.as_deref(), Some(""));
    }

    #[test]
    fn canonical_json_includes_all_fields() {
        let p = WindowsPathValue::new("C:/Users/alice");
        let v = p.to_canonical_value();
        assert_eq!(v["normalization_profile"], "windows-path-v1");
        assert_eq!(v["comparison_key"], "c:\\users\\alice");
        assert!(v["normalization_notes"].is_array());
    }

    #[test]
    fn root_only_drive_letter() {
        let p = WindowsPathValue::new("C:");
        assert_eq!(p.comparison_key.as_deref(), Some("c:"));
    }

    #[test]
    fn root_only_unc() {
        let p = WindowsPathValue::new("\\\\");
        assert_eq!(p.comparison_key.as_deref(), Some("\\\\"));
    }
}
