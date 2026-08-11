//! Prefetch file header（libyal PF format 仕様、互換 §4.1、T4-020）。
//!
//! ファイル header は全 version 共通で 84 byte:
//!
//! | offset | size | 内容 |
//! |--------|------|------|
//! | 0  | 4 | Format version（17/23/26/30/31）|
//! | 4  | 4 | Signature "SCCA"（0x53 0x43 0x43 0x41）|
//! | 8  | 4 | 不明 |
//! | 12 | 4 | File size |
//! | 16 | 60 | Executable filename（UTF-16LE・終端 null）|
//! | 76 | 4 | Prefetch hash |
//! | 80 | 4 | 不明（flags）|
//!
//! MAM 圧縮 Prefetch は先頭が "MAM\x04" で始まり、圧縮前の size が続く（[`is_mam`]）。

/// ファイル header の固定長（byte）。全 version 共通。
pub const HEADER_BYTES: usize = 84;

/// "SCCA" シグネチャ（little-endian byte 列）。
pub const SCCA_SIGNATURE: [u8; 4] = *b"SCCA";

/// MAM 圧縮 file の先頭 magic（`b"MAM"`）。4 byte 目は flag/version byte。
pub const MAM_MAGIC: &[u8; 3] = b"MAM";

/// MAM header の固定長（magic 4 byte + 圧縮前 size 4 byte）。
pub const MAM_HEADER_BYTES: usize = 8;

/// 対応する Prefetch format version の一覧（互換 §4.1）。
pub const SUPPORTED_VERSIONS: &[u32] = &[17, 23, 26, 30, 31];

/// Prefetch header 解析時の error。
#[derive(Clone, Debug)]
pub enum HeaderError {
    /// snapshot が header（84 byte）に満たない。
    Truncated,
    /// "SCCA" シグネチャが一致しない（Prefetch 形式ではない）。
    SignatureMismatch,
    /// header size / reserved 等の形式異常。
    Malformed,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::Truncated => write!(f, "snapshot が Prefetch header (84 byte) に満たない"),
            HeaderError::SignatureMismatch => {
                write!(f, "Prefetch signature 'SCCA' が一致しない")
            }
            HeaderError::Malformed => write!(f, "Prefetch header の形式が不正"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// 解析済みの Prefetch ファイル header（全 version 共通部分）。
#[derive(Clone, Debug)]
pub struct PrefetchHeader {
    /// Format version（17/23/26/30/31）。
    pub format_version: u32,
    /// Header に記録された file size（byte）。上限検証に使う。
    pub file_size: u32,
    /// Executable filename（UTF-16LE → UTF-8 lossy 変換）。
    /// 終端 null は除去済み。unpaired surrogate は U+FFFD へ置換される。
    pub executable: String,
    /// Prefetch hash。
    pub prefetch_hash: u32,
}

impl PrefetchHeader {
    /// 84 byte の buffer から header を解析する。
    ///
    /// `buf` は [`HEADER_BYTES`] 以上の長さを前提とする（呼出側で検証済み）。
    /// signature・version の検証を行う。
    pub fn parse(buf: &[u8]) -> Result<PrefetchHeader, HeaderError> {
        if buf.len() < HEADER_BYTES {
            return Err(HeaderError::Truncated);
        }

        let format_version = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let signature = [buf[4], buf[5], buf[6], buf[7]];
        if signature != SCCA_SIGNATURE {
            return Err(HeaderError::SignatureMismatch);
        }
        let file_size = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let prefetch_hash = u32::from_le_bytes([buf[76], buf[77], buf[78], buf[79]]);

        // Executable filename: offset 16, 60 byte の UTF-16LE。
        let executable = decode_utf16_name(&buf[16..76]);

        Ok(PrefetchHeader {
            format_version,
            file_size,
            executable,
            prefetch_hash,
        })
    }
}

/// UTF-16LE byte 列（終端 null 含む可能性）を文字列へ変換する。
///
/// Prefetch の filename は unpaired surrogate を含む場合がある（libyal 注記）。
/// ここでは [`u16::from_le_bytes`] で code unit へ直し、[`String::from_utf16_lossy`]
/// で安全へ変換する。最初の null code unit で打ち切る。
pub fn decode_utf16_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// `buf` の先頭が MAM 圧縮 Prefetch の magic か判定する。
///
/// MAM 圧縮 file は先頭 3 byte が `b"MAM"`（4 byte 目は flag/version）。
/// 通常の Prefetch は先頭が小さな version DWORD のため、両者は容易に区別できる。
pub fn is_mam(buf: &[u8]) -> bool {
    buf.len() >= 3 && &buf[..3] == MAM_MAGIC as &[u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(version: u32, sig_ok: bool, exec: &str) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_BYTES];
        buf[0..4].copy_from_slice(&version.to_le_bytes());
        let sig: [u8; 4] = if sig_ok { SCCA_SIGNATURE } else { *b"XXXX" };
        buf[4..8].copy_from_slice(&sig);
        buf[12..16].copy_from_slice(&1234u32.to_le_bytes());
        // executable at 16..76
        let units: Vec<u16> = exec.encode_utf16().collect();
        for (i, u) in units.iter().take(29).enumerate() {
            buf[16 + 2 * i..16 + 2 * i + 2].copy_from_slice(&u.to_le_bytes());
        }
        buf[76..80].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf
    }

    #[test]
    fn parse_valid_header_v31() {
        let buf = build_header(31, true, "NOTEPAD.EXE");
        let h = PrefetchHeader::parse(&buf).unwrap();
        assert_eq!(h.format_version, 31);
        assert_eq!(h.file_size, 1234);
        assert_eq!(h.executable, "NOTEPAD.EXE");
        assert_eq!(h.prefetch_hash, 0xDEAD_BEEF);
    }

    #[test]
    fn parse_rejects_bad_signature() {
        let buf = build_header(17, false, "X");
        assert!(matches!(
            PrefetchHeader::parse(&buf),
            Err(HeaderError::SignatureMismatch)
        ));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let buf = vec![0u8; 10];
        assert!(matches!(
            PrefetchHeader::parse(&buf),
            Err(HeaderError::Truncated)
        ));
    }

    #[test]
    fn decode_utf16_truncates_at_null() {
        let mut bytes = vec![0u8; 60];
        let s = "ABC";
        for (i, u) in s.encode_utf16().collect::<Vec<_>>().iter().enumerate() {
            bytes[2 * i..2 * i + 2].copy_from_slice(&u.to_le_bytes());
        }
        // null の後ろにゴミ
        bytes[8..10].copy_from_slice(&0x5A5Au16.to_le_bytes());
        assert_eq!(decode_utf16_name(&bytes), "ABC");
    }

    #[test]
    fn is_mam_detects_magic() {
        assert!(is_mam(b"MAM\x04AAAA"));
        assert!(!is_mam(b"\x1F\x00\x00\x00SCCA"));
        assert!(!is_mam(b"MA"));
    }

    #[test]
    fn supported_versions_listed() {
        assert!(SUPPORTED_VERSIONS.contains(&17));
        assert!(SUPPORTED_VERSIONS.contains(&23));
        assert!(SUPPORTED_VERSIONS.contains(&26));
        assert!(SUPPORTED_VERSIONS.contains(&30));
        assert!(SUPPORTED_VERSIONS.contains(&31));
        assert!(!SUPPORTED_VERSIONS.contains(&99));
    }
}
