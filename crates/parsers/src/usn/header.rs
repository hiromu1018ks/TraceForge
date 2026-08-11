//! `USN_RECORD_COMMON_HEADER` の解析と MajorVersion 検出（互換 §4.3、T4-030）。
//!
//! Microsoft 公式の `USN_RECORD_COMMON_HEADER`（ntifs.h）は全 record の先頭 8 byte:
//!
//! ```text
//! DWORD RecordLength;   // 4 byte（当該 record 全体の byte 長。0 は終端扱い）
//! WORD   MajorVersion;  // 2 byte（2/3/4 が既知）
//! WORD   MinorVersion;  // 2 byte
//! ```
//!
//! 互換 §4.3 はこの `MajorVersion` で形式判定することを求める。
//! 本 module は header の parse と、未対応 MajorVersion の安全な取扱を担う。

/// Common header の固定長（byte）。
pub const COMMON_HEADER_BYTES: usize = 8;

/// 互換 §4.3 で対応する MajorVersion 一覧。
pub const SUPPORTED_MAJOR_VERSIONS: &[u16] = &[2, 3, 4];

/// `USN_RECORD_COMMON_HEADER` の parse 結果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonHeader {
    /// 当該 record 全体の byte 長。後続 record の境界を得るために使う。
    pub record_length: u32,
    /// 形式識別子（2/3/4 が既知）。
    pub major_version: u16,
    /// 形式の副番号。
    pub minor_version: u16,
}

/// Header parse の失敗理由。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// 残り byte 数が header 自体（8 byte）に満たない（record 末端・truncated）。
    #[error("common header ({COMMON_HEADER_BYTES} byte) に満たない: 残り {0} byte")]
    TooShort(usize),
}

/// `USN_RECORD_COMMON_HEADER` を parse する。
///
/// `buf` は少なくとも [`COMMON_HEADER_BYTES`] byte を含むこと。
pub fn parse_common_header(buf: &[u8]) -> Result<CommonHeader, HeaderError> {
    if buf.len() < COMMON_HEADER_BYTES {
        return Err(HeaderError::TooShort(buf.len()));
    }
    let record_length = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let major_version = u16::from_le_bytes([buf[4], buf[5]]);
    let minor_version = u16::from_le_bytes([buf[6], buf[7]]);
    Ok(CommonHeader {
        record_length,
        major_version,
        minor_version,
    })
}

/// `major_version` が [`SUPPORTED_MAJOR_VERSIONS`] に含まれるか。
pub fn is_supported_major_version(major: u16) -> bool {
    SUPPORTED_MAJOR_VERSIONS.contains(&major)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v2_header() {
        let buf = sample_header(60, 2, 0);
        let h = parse_common_header(&buf).unwrap();
        assert_eq!(h.record_length, 60);
        assert_eq!(h.major_version, 2);
        assert_eq!(h.minor_version, 0);
    }

    #[test]
    fn parse_v3_header() {
        let buf = sample_header(96, 3, 0);
        let h = parse_common_header(&buf).unwrap();
        assert_eq!(h.major_version, 3);
    }

    #[test]
    fn parse_v4_header() {
        let buf = sample_header(88, 4, 0);
        let h = parse_common_header(&buf).unwrap();
        assert_eq!(h.major_version, 4);
    }

    #[test]
    fn parse_unknown_major_version() {
        let buf = sample_header(40, 9, 0);
        let h = parse_common_header(&buf).unwrap();
        // header 自体は読めるが、未対応 major version であることを判定できる。
        assert_eq!(h.major_version, 9);
        assert!(!is_supported_major_version(h.major_version));
    }

    #[test]
    fn too_short_buf_returns_err() {
        let buf = [0u8; 3];
        let e = parse_common_header(&buf).unwrap_err();
        assert_eq!(e, HeaderError::TooShort(3));
    }

    fn sample_header(len: u32, major: u16, minor: u16) -> [u8; COMMON_HEADER_BYTES] {
        let mut buf = [0u8; COMMON_HEADER_BYTES];
        buf[0..4].copy_from_slice(&len.to_le_bytes());
        buf[4..6].copy_from_slice(&major.to_le_bytes());
        buf[6..8].copy_from_slice(&minor.to_le_bytes());
        buf
    }
}
