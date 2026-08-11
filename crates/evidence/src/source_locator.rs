//! Source locator の正規化（規範 §5.2）。
//!
//! `source_locator` は入力 root からの相対 path である（規範 §5.2）。これにより
//! 入力 directory 全体を別の場所へ移動しても Evidence ID が変化しない。
//!
//! 正規化規則（規範 §5.2）:
//! 1. separator は `/` へ正規化する（`\` → `/`）。
//! 2. `.` と `..` component を含めてはならない（解決ではなく拒否）。
//! 3. Unicode は NFC へ正規化する。
//! 4. UTF-8 へ変換できない byte は各 byte を大文字 hex `%XX` で表現する。
//! 5. 大文字小文字は変更しない。

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// source_locator 正規化の失敗（規範 §5.2 違反）。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SourceLocatorError {
    /// source_locator が空、または component が1つもない。
    #[error("source_locator が空である")]
    Empty,
    /// `.` または `..` component が含まれる（規範 §5.2）。
    #[error("source_locator に '.' または '..' component が含まれる: {0}")]
    DotOrParentComponent(String),
    /// 絶対 path のように見える（先頭 `/` または Windows drive letter）。
    #[error("source_locator が絶対 path のように見える: {0}")]
    AbsolutePath(String),
}

/// 入力 root からの相対 path 文字列を source_locator へ正規化する（規範 §5.2）。
///
/// 入力 `relative` は OS 依存の separator（`\` on Windows）を含んでよい。
/// 出力は常に `/` 区切り・NFC 正規化済み・`.`/`..` なしの文字列となる。
///
/// # 例
/// ```
/// # use tf_evidence::source_locator::normalize_source_locator;
/// assert_eq!(
///     normalize_source_locator(r"evtx\Security.evtx").unwrap(),
///     "evtx/Security.evtx"
/// );
/// ```
pub fn normalize_source_locator(relative: &str) -> Result<String, SourceLocatorError> {
    if relative.is_empty() {
        return Err(SourceLocatorError::Empty);
    }

    // 規範 §5.2: separator は `/` へ正規化する。
    let unified = relative.replace('\\', "/");

    // 絶対 path の検出: 先頭 `/` または Windows drive letter (`C:` 等)。
    if unified.starts_with('/') {
        return Err(SourceLocatorError::AbsolutePath(relative.into()));
    }
    if unified.len() >= 2 && unified.as_bytes()[1] == b':' {
        return Err(SourceLocatorError::AbsolutePath(relative.into()));
    }

    // 規範 §5.2: Unicode は NFC へ正規化する。
    let nfc: String = unified.nfc().collect();

    // 規範 §5.2: `.` と `..` を含めてはならない（解決ではなく拒否）。
    let mut components: Vec<&str> = Vec::new();
    for comp in nfc.split('/') {
        match comp {
            "" => continue, // 連続 separator・先頭/末尾 separator は無視
            "." | ".." => {
                return Err(SourceLocatorError::DotOrParentComponent(relative.into()));
            }
            _ => components.push(comp),
        }
    }

    if components.is_empty() {
        return Err(SourceLocatorError::Empty);
    }

    Ok(components.join("/"))
}

/// 非 UTF-8 byte 列を `%XX`（大文字 hex）escape しつつ String へ変換する（規範 §5.2）。
///
/// filesystem から取得した file 名 byte 列が valid UTF-8 でない場合、各無効 byte を
/// `%XX` 形式（大文字 hex）で表現する。有効な UTF-8 部分はそのまま文字列へ変換する。
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
                // 規範 §5.2: 変換できない byte を大文字 hex %XX で表現する。
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
            normalize_source_locator("evtx/Security.evtx").unwrap(),
            "evtx/Security.evtx"
        );
    }

    #[test]
    fn normalize_backslash_to_slash() {
        // 規範 §5.2: separator は `/` へ正規化。
        assert_eq!(
            normalize_source_locator(r"evtx\Security.evtx").unwrap(),
            "evtx/Security.evtx"
        );
    }

    #[test]
    fn normalize_preserves_case() {
        // 規範 §5.2: 大文字小文字は変更しない。
        assert_eq!(
            normalize_source_locator("EVTX/Security.EVTX").unwrap(),
            "EVTX/Security.EVTX"
        );
    }

    #[test]
    fn normalize_collapses_redundant_separators() {
        assert_eq!(normalize_source_locator("a//b///c").unwrap(), "a/b/c");
    }

    #[test]
    fn normalize_trims_trailing_separator() {
        assert_eq!(normalize_source_locator("a/b/").unwrap(), "a/b");
    }

    #[test]
    fn normalize_rejects_dot_component() {
        // 規範 §5.2: `.` を含めてはならない。
        assert_eq!(
            normalize_source_locator("a/./b"),
            Err(SourceLocatorError::DotOrParentComponent("a/./b".into()))
        );
    }

    #[test]
    fn normalize_rejects_parent_component() {
        // 規範 §5.2: `..` を含めてはならない。
        assert_eq!(
            normalize_source_locator("a/../b"),
            Err(SourceLocatorError::DotOrParentComponent("a/../b".into()))
        );
    }

    #[test]
    fn normalize_rejects_absolute_unix_path() {
        assert!(matches!(
            normalize_source_locator("/etc/passwd"),
            Err(SourceLocatorError::AbsolutePath(_))
        ));
    }

    #[test]
    fn normalize_rejects_windows_drive_letter() {
        assert!(matches!(
            normalize_source_locator(r"C:\Users\alice"),
            Err(SourceLocatorError::AbsolutePath(_))
        ));
    }

    #[test]
    fn normalize_rejects_empty() {
        assert_eq!(normalize_source_locator(""), Err(SourceLocatorError::Empty));
    }

    #[test]
    fn normalize_rejects_only_separators() {
        // `"///"` は先頭 `/` のため絶対 path 扱い。
        assert!(matches!(
            normalize_source_locator("///"),
            Err(SourceLocatorError::AbsolutePath(_))
        ));
    }

    #[test]
    fn normalize_nfc_unicode() {
        // 規範 §5.2: Unicode は NFC へ正規化。
        // U+0041 (A) + U+0300 (Combining Grave Accent) → U+00C0 (À) [NFC]
        let decomposed = "A\u{0300}";
        let result = normalize_source_locator(decomposed).unwrap();
        assert_eq!(result, "\u{00C0}");
        // NFC でなければ composited 1 文字にならない。
        assert_eq!(result.chars().count(), 1);
    }

    #[test]
    fn escape_valid_utf8_unchanged() {
        assert_eq!(escape_non_utf8_bytes(b"hello"), "hello");
        assert_eq!(escape_non_utf8_bytes(b""), "");
    }

    #[test]
    fn escape_invalid_byte() {
        // 0xFF は valid UTF-8 ではない。
        assert_eq!(escape_non_utf8_bytes(&[0xFF]), "%FF");
    }

    #[test]
    fn escape_mixed_valid_invalid() {
        // "abc" + 0xFF + "def"
        let bytes: &[u8] = &[b'a', b'b', b'c', 0xFF, b'd', b'e', b'f'];
        assert_eq!(escape_non_utf8_bytes(bytes), "abc%FFdef");
    }

    #[test]
    fn escape_multiple_invalid_bytes() {
        // 連続する無効 byte は各々 %XX で表現。
        assert_eq!(escape_non_utf8_bytes(&[0xFF, 0xFE, 0xFD]), "%FF%FE%FD");
    }

    #[test]
    fn escape_multibyte_utf8_preserved() {
        // 3 byte UTF-8 文字（日本語「あ」= E3 81 82）はそのまま保持。
        assert_eq!(escape_non_utf8_bytes("あ".as_bytes()), "あ");
    }
}
