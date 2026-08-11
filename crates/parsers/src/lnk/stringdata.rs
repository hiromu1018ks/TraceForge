//! StringData 解析（[MS-SHLLINK] §2.4、互換 §4.4）。
//!
//! LinkFlags の有効 bit に応じて次の順で文字列が並ぶ:
//!
//! 1. NAME_STRING (HasName)
//! 2. RELATIVE_PATH (HasRelativePath)
//! 3. WORKING_DIR (HasWorkingDir)
//! 4. ARGUMENTS (HasArguments)
//! 5. ICON_LOCATION (HasIconLocation)
//!
//! 各 StringData は次の構造を持つ:
//!
//! ```text
//! Offset  Size  Field
//! 0       2     CountCharacters (u16 LE) ── 文字数（Unicode は UTF-16 code unit、ANSI は byte）
//! 2       ?     String ── IsUnicode なら UTF-16LE、ANSI なら CP_ACP
//! ```
//!
//! ANSI (CP_ACP) 文字列はコードページ非依存の安全な UTF-8 変換が困難なため、
//! 本 Parser は **lossy 変換**（無効 byte は `U+FFFD`）で UTF-8 へ復元する。
//! これは情報欠損の可能性があるため、`ansi_lossy` フラグで記録する。

use crate::framework::ReadSeek;
use crate::lnk::header::LinkFlags;

/// 1 個の StringData（復元済み UTF-8 文字列と符号化情報）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringData {
    /// 復元した UTF-8 文字列。
    pub value: String,
    /// Unicode (UTF-16LE) だったか。false なら ANSI (CP_ACP) lossy 変換。
    pub is_unicode: bool,
    /// ANSI で lossy 変換した（無効 byte があった）か。Unicode の場合は常に false。
    pub ansi_lossy: bool,
}

/// StringData 全体（5 種の文字列をまとめたもの）。
#[derive(Clone, Debug, Default)]
pub struct StringDataSection {
    pub name: Option<StringData>,
    pub relative_path: Option<StringData>,
    pub working_dir: Option<StringData>,
    pub arguments: Option<StringData>,
    pub icon_location: Option<StringData>,
}

/// StringData 読み取りの error。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringDataError {
    /// CountCharacters を読む前に EOF。
    TruncatedCount,
    /// 文字列本体が短い（CountCharacters 分無い）。
    TruncatedString,
}

/// 1 個の StringData を読む。
///
/// `is_unicode` が true なら UTF-16LE、false なら ANSI (CP_ACP) として解釈する。
fn read_one_string_data(
    reader: &mut dyn ReadSeek,
    is_unicode: bool,
) -> Result<StringData, StringDataError> {
    let mut count_buf = [0u8; 2];
    reader
        .read_exact(&mut count_buf)
        .map_err(|_| StringDataError::TruncatedCount)?;
    let count_chars = u16::from_le_bytes(count_buf);

    if is_unicode {
        // UTF-16LE: count_chars code unit = count_chars * 2 byte。
        let byte_len = (count_chars as usize).saturating_mul(2);
        let mut buf = vec![0u8; byte_len];
        reader
            .read_exact(&mut buf)
            .map_err(|_| StringDataError::TruncatedString)?;
        // UTF-16LE → UTF-8。途中で奇数 byte になった場合（truncated surrogate）は
        // lossy で U+FFFD へ置換する（safe側）。
        let value = decode_utf16le_lossy(&buf);
        Ok(StringData {
            value,
            is_unicode: true,
            ansi_lossy: false,
        })
    } else {
        // ANSI (CP_ACP): count_chars byte。コードページ非依存の安全な UTF-8 変換は
        // できないため、UTF-8 として妥当な範囲を保ちつつ lossy 変換する。
        // ここでは「バイト列を UTF-8 として解釈し、無効 byte は U+FFFD」で扱う。
        // 厳密な CP_ACP 変換は Phase 8 で encoding_rs 等の導入を検討する。
        let mut buf = vec![0u8; count_chars as usize];
        reader
            .read_exact(&mut buf)
            .map_err(|_| StringDataError::TruncatedString)?;
        let (cow, had_errors) = string_from_bytes_lossy(&buf);
        Ok(StringData {
            value: cow,
            is_unicode: false,
            ansi_lossy: had_errors,
        })
    }
}

/// UTF-16LE byte 列を UTF-8 文字列へ lossy 変換する。
///
/// 末尾の奇数 byte（truncated surrogate）や lone surrogate は `U+FFFD` へ置換する。
fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    // 奇数 byte の場合、末尾 1 byte を切り捨てる。
    let even_len = bytes.len() & !1;
    let units: Vec<u16> = (0..even_len)
        .step_by(2)
        .map(|i| u16::from_le_bytes([bytes[i], bytes[i + 1]]))
        .collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// バイト列を UTF-8 文字列へ lossy 変換する（`std::str::from_utf8` の lossy 版）。
/// 戻り値は (文字列, 無効 byte があったか)。
fn string_from_bytes_lossy(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    }
}

/// LinkFlags に従い StringData section を順に読む。
///
/// reader は StringData section の先頭に位置していること。
/// 読み飛ばし（skip）は行わず、flags で有効になった文字列だけを読む。
pub fn read_string_data_section(
    reader: &mut dyn ReadSeek,
    flags: LinkFlags,
) -> Result<StringDataSection, StringDataError> {
    let is_unicode = flags.is_unicode();
    let mut section = StringDataSection::default();

    if flags.has_name() {
        section.name = Some(read_one_string_data(reader, is_unicode)?);
    }
    if flags.has_relative_path() {
        section.relative_path = Some(read_one_string_data(reader, is_unicode)?);
    }
    if flags.has_working_dir() {
        section.working_dir = Some(read_one_string_data(reader, is_unicode)?);
    }
    if flags.has_arguments() {
        section.arguments = Some(read_one_string_data(reader, is_unicode)?);
    }
    if flags.has_icon_location() {
        section.icon_location = Some(read_one_string_data(reader, is_unicode)?);
    }

    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cursor(data: Vec<u8>) -> Cursor<Vec<u8>> {
        Cursor::new(data)
    }

    #[test]
    fn read_unicode_string() {
        // CountCharacters = 5, "Hello" in UTF-16LE。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&5u16.to_le_bytes());
        for ch in "Hello".encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        let mut c = cursor(buf);
        let s = read_one_string_data(&mut c, true).unwrap();
        assert_eq!(s.value, "Hello");
        assert!(s.is_unicode);
        assert!(!s.ansi_lossy);
    }

    #[test]
    fn read_unicode_japanese() {
        // 「資料」の UTF-16LE。
        let text = "資料";
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(text.encode_utf16().count() as u16).to_le_bytes());
        for ch in text.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        let mut c = cursor(buf);
        let s = read_one_string_data(&mut c, true).unwrap();
        assert_eq!(s.value, text);
    }

    #[test]
    fn read_ansi_ascii_string() {
        // ANSI でも ASCII 部分はそのまま。
        let text = "cmd.exe";
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(text.len() as u16).to_le_bytes());
        buf.extend_from_slice(text.as_bytes());
        let mut c = cursor(buf);
        let s = read_one_string_data(&mut c, false).unwrap();
        assert_eq!(s.value, text);
        assert!(!s.is_unicode);
        assert!(!s.ansi_lossy);
    }

    #[test]
    fn read_truncated_count() {
        // 規範 §9.2: truncated で panic しない。
        let mut c = cursor(vec![0u8; 1]);
        let err = read_one_string_data(&mut c, true).unwrap_err();
        assert_eq!(err, StringDataError::TruncatedCount);
    }

    #[test]
    fn read_truncated_string_body() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&10u16.to_le_bytes()); // 10 文字を宣言
        buf.extend_from_slice(&[0x41, 0x00]); // 実際は 1 文字分（UTF-16LE）
        let mut c = cursor(buf);
        let err = read_one_string_data(&mut c, true).unwrap_err();
        assert_eq!(err, StringDataError::TruncatedString);
    }

    #[test]
    fn read_section_with_name_only() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&5u16.to_le_bytes());
        for ch in "Hello".encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        let mut c = cursor(buf);
        let flags = LinkFlags(0x0000_0084); // HasName | IsUnicode
        let section = read_string_data_section(&mut c, flags).unwrap();
        assert_eq!(section.name.as_ref().unwrap().value, "Hello");
        assert!(section.relative_path.is_none());
    }

    #[test]
    fn read_section_empty_when_no_flags() {
        let mut c = cursor(vec![]);
        let flags = LinkFlags(0); // 全 flag OFF
        let section = read_string_data_section(&mut c, flags).unwrap();
        assert!(section.name.is_none());
        assert!(section.relative_path.is_none());
        assert!(section.working_dir.is_none());
        assert!(section.arguments.is_none());
        assert!(section.icon_location.is_none());
    }

    #[test]
    fn lone_surrogate_utf16_is_handled_safely() {
        // lone surrogate（単独サロゲート）を含む UTF-16。lossy で U+FFFD へ置換。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&2u16.to_le_bytes()); // 2 code unit 宣言
        // DC00 (low surrogate, lone) + 0x0041 ('A')。4 byte。
        buf.extend_from_slice(&[0x00, 0xDC, 0x41, 0x00]);
        let mut c = cursor(buf);
        let s = read_one_string_data(&mut c, true).unwrap();
        // lone surrogate は U+FFFD へ。'A' はそのまま。
        assert!(s.value.contains('A'));
    }
}
