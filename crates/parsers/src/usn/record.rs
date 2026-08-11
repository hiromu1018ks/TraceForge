//! USN_RECORD V2 / V3 / V4 の解析（互換 §4.3、T4-031〜T4-033）。
//!
//! Microsoft 公式の各 version 構造体（winioctl.h）を byte 並びで解読する。
//!
//! ## 構造（byte size）
//!
//! ### USN_RECORD_V2（固定 60 byte + FileName）
//! ```text
//! DWORD     RecordLength;             //  4
//! WORD      MajorVersion;             //  2 (== 2)
//! WORD      MinorVersion;             //  2 (== 0)
//! DWORDLONG FileReferenceNumber;      //  8  (MFT reference: 低48bit=number, 高16bit=sequence)
//! DWORDLONG ParentFileReferenceNumber;//  8
//! USN       Usn;                      //  8  (signed 64-bit update sequence number)
//! LARGE_INTEGER Time;                 //  8  (FILETIME, UTC)
//! DWORD     Reason;                   //  4
//! DWORD     SourceInfo;               //  4
//! DWORD     SecurityId;               //  4
//! DWORD     FileAttributes;           //  4
//! WORD      FileNameLength;           //  2  (bytes, not chars)
//! WORD      FileNameOffset;           //  2  (先頭からの byte offset)
//! WCHAR     FileName[1];              //  可変（FileNameLength byte）
//! ```
//!
//! ### USN_RECORD_V3（固定 60 byte + FileName、ただし reference が 128 bit）
//! ```text
//! DWORD      RecordLength;             //  4
//! WORD       MajorVersion;             //  2 (== 3)
//! WORD       MinorVersion;             //  2 (== 0)
//! FILE_ID_128 FileReferenceNumber;     // 16  (128-bit file reference)
//! FILE_ID_128 ParentFileReferenceNumber;// 16
//! USN        Usn;                      //  8
//! LARGE_INTEGER Time;                  //  8
//! DWORD      Reason;                   //  4
//! DWORD      SourceInfo;               //  4
//! DWORD      SecurityId;               //  4
//! DWORD      FileAttributes;           //  4
//! WORD       FileNameLength;           //  2
//! WORD       FileNameOffset;           //  2
//! WCHAR      FileName[1];              //  可変
//! ```
//!
//! ### USN_RECORD_V4（固定 88 byte、filename 無し）
//! ```text
//! DWORD       RecordLength;             //  4
//! WORD        MajorVersion;             //  2 (== 4)
//! WORD        MinorVersion;             //  2
//! FILE_ID_128 FileReferenceNumber;      // 16
//! FILE_ID_128 ParentFileReferenceNumber;// 16
//! USN         Usn;                      //  8
//! LARGE_INTEGER Time;                   //  8
//! DWORD       Reason;                   //  4
//! DWORD       SourceInfo;               //  4
//! WORD        RemainingExtents;         //  2  (V4 only)
//! WORD        NumberOfExtents;          //  2  (V4 only)
//! DWORD64     ExtentLocation;           //  8  (cluster offset)
//! DWORD64     ExtentLength;             //  8  (byte length)
//! ```
//!
//! ## 128-bit file reference の取扱（互換 §4.3）
//!
//! V3/V4 の `FILE_ID_128` は 16 byte 配列。本 module はこれを 16 byte すべて保持し、
//! 文字列表現は 32 桁の lowercase hex とする（**切り詰め禁止**）。

use crate::usn::header::CommonHeader;

/// V2 固定部の byte 長。
pub const V2_FIXED_BYTES: usize = 60;
/// V3 固定部の byte 長（filename 領域を含まない）。
pub const V3_FIXED_BYTES: usize = 76;
/// V4 固定部の byte 長。
pub const V4_FIXED_BYTES: usize = 84;

/// `FILE_ID_128`（128-bit file reference）。16 byte すべて保持し切り詰めない。
pub type FileId128 = [u8; 16];

/// USN file reference の version 非依存表現。
///
/// V2 は 64 bit（MFT reference）、V3/V4 は 128 bit（`FILE_ID_128`）。
/// 異なる version 間で同一か否かは判定できない（表現が異なるため）。
/// 同一 version 内でのみ比較できるよう、[`FileReference::as_comparison_key`] で一意な文字列へ直す。
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileReference {
    /// V2 の 64 bit MFT reference。raw 値をそのまま保持（low 48 = number, high 16 = sequence）。
    V2(u64),
    /// V3/V4 の 128 bit file reference。16 byte すべて保持。
    V3V4(FileId128),
}

impl FileReference {
    /// V2 reference を「`v2:<16桁 hex>`」形式の文字列へ。
    /// V2 であることと、64 bit 値を取り出せることを兼ねる。
    pub fn as_comparison_key(&self) -> String {
        match self {
            FileReference::V2(raw) => format!("v2:{raw:016x}"),
            FileReference::V3V4(raw) => {
                let mut s = String::from("v3v4:");
                for b in raw {
                    s.push_str(&format!("{b:02x}"));
                }
                s
            }
        }
    }

    /// V2 なら MFT segment number（low 48 bit）を返す。V3/V4 は None。
    pub fn mft_segment_number(&self) -> Option<u64> {
        match self {
            FileReference::V2(raw) => Some(raw & 0x0000_FFFF_FFFF_FFFF),
            FileReference::V3V4(_) => None,
        }
    }

    /// V2 なら sequence number（high 16 bit）を返す。V3/V4 は None。
    pub fn sequence_number(&self) -> Option<u16> {
        match self {
            FileReference::V2(raw) => Some((raw >> 48) as u16),
            FileReference::V3V4(_) => None,
        }
    }
}

/// USN（符号付き 64 bit update sequence number）。
/// 通常単調増加するが、符号付きで扱う（Microsoft 仕様）。
pub type Usn = i64;

/// USN record 共通の中間表現。
/// V2/V3/V4 いずれもこの形へ正規化する。filename は V4 では None。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsnRecord {
    /// Common header（record length / major / minor）。
    pub header: CommonHeader,
    /// 変更対象の file reference。
    pub file_reference: FileReference,
    /// 親 directory の file reference。
    pub parent_reference: FileReference,
    /// Update Sequence Number（符号付き）。
    pub usn: Usn,
    /// 変更時刻（FILETIME, UTC）。0 は「未設定」。
    pub time_filetime: u64,
    /// Reason bit field。
    pub reason: u32,
    /// SourceInfo（ユーザー起因・システム起因の付与情報）。
    pub source_info: u32,
    /// SecurityId（V2/V3 のみ。V4 は 0）。
    pub security_id: u32,
    /// FileAttributes（V2/V3 のみ。V4 は 0）。
    pub file_attributes: u32,
    /// Filename（UTF-16LE から UTF-8 string へ decode 済み）。V4 は None。
    pub file_name: Option<String>,
    /// V4 の range tracking（filename 無し）。V2/V3 は None。
    pub range_tracking: Option<RangeTracking>,
    /// record 先頭からの byte offset（`$J` ストリーム内）。
    pub record_offset: u64,
}

/// V4 の extent / range tracking 情報（互換 §4.3）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeTracking {
    /// 残り extent 数（同じ USN で続きの V4 record があるかを示す）。
    pub remaining_extents: u16,
    /// 当該 record に含まれる extent 数（通常 1）。
    pub number_of_extents: u16,
    /// Extent の開始 cluster 位置。
    pub extent_location: u64,
    /// Extent の byte 長。
    pub extent_length: u64,
}

/// record parse の失敗理由。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// record length が固定部に満たない。
    #[error("record length {declared} は V{version} 固定部 ({fixed} byte) 未満")]
    ShortRecord {
        version: u16,
        declared: u32,
        fixed: usize,
    },
    /// 実際の byte 数が record length に満たない（途中で切れている）。
    #[error("実 byte 数 {actual} が record length {declared} に満たない（truncated）")]
    Truncated { declared: u32, actual: usize },
    /// record length が異常に大きい。
    #[error("record length {0} が上限を超えた")]
    Oversize(u32),
    /// filename 領域が record の外を指している。
    #[error(
        "filename offset/length が record 外を指す: offset={offset}, length={length}, record_len={record_len}"
    )]
    BadFileNameRange {
        offset: u32,
        length: u32,
        record_len: u32,
    },
    /// filename が UTF-16LE として不正。
    #[error("filename の UTF-16LE decode 失敗: {0}")]
    BadFileNameEncoding(String),
}

/// record length の安全上限（byte）。USN_RECORD は通常数百 byte 程度。
/// 異常入力からの過大 alloc を防ぐための上限。
pub const MAX_RECORD_LENGTH: u32 = 64 * 1024;

/// byte 列から record を1件 parse する。
///
/// `buf` は `$J` ストリーム内の当該 record の先頭から最大 `record_length` byte を含む
/// 切り出し。本関数は `header` で示された version に応じて V2/V3/V4 のいずれかとして解読する。
pub fn parse_record(
    buf: &[u8],
    header: &CommonHeader,
    record_offset: u64,
) -> Result<UsnRecord, RecordError> {
    if header.record_length > MAX_RECORD_LENGTH {
        return Err(RecordError::Oversize(header.record_length));
    }
    let declared = header.record_length as usize;
    if buf.len() < declared {
        return Err(RecordError::Truncated {
            declared: header.record_length,
            actual: buf.len(),
        });
    }
    let body = &buf[..declared];
    match header.major_version {
        2 => parse_v2(body, header, record_offset),
        3 => parse_v3(body, header, record_offset),
        4 => parse_v4(body, header, record_offset),
        // 未対応 version はここへ来ない（呼出側で事前 check）。
        v => Err(RecordError::ShortRecord {
            version: v,
            declared: header.record_length,
            fixed: 0,
        }),
    }
}

/// USN_RECORD_V2 を parse する。
fn parse_v2(
    body: &[u8],
    header: &CommonHeader,
    record_offset: u64,
) -> Result<UsnRecord, RecordError> {
    if body.len() < V2_FIXED_BYTES {
        return Err(RecordError::ShortRecord {
            version: 2,
            declared: header.record_length,
            fixed: V2_FIXED_BYTES,
        });
    }
    let file_ref = u64::from_le_bytes(body[8..16].try_into().unwrap());
    let parent_ref = u64::from_le_bytes(body[16..24].try_into().unwrap());
    let usn = i64::from_le_bytes(body[24..32].try_into().unwrap());
    let time = u64::from_le_bytes(body[32..40].try_into().unwrap());
    let reason = u32::from_le_bytes(body[40..44].try_into().unwrap());
    let source_info = u32::from_le_bytes(body[44..48].try_into().unwrap());
    let security_id = u32::from_le_bytes(body[48..52].try_into().unwrap());
    let file_attributes = u32::from_le_bytes(body[52..56].try_into().unwrap());
    let file_name_length = u16::from_le_bytes(body[56..58].try_into().unwrap()) as u32;
    let file_name_offset = u16::from_le_bytes(body[58..60].try_into().unwrap()) as u32;
    let file_name = parse_file_name(
        body,
        file_name_offset,
        file_name_length,
        header.record_length,
    )?;

    Ok(UsnRecord {
        header: header.clone(),
        file_reference: FileReference::V2(file_ref),
        parent_reference: FileReference::V2(parent_ref),
        usn,
        time_filetime: time,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name,
        range_tracking: None,
        record_offset,
    })
}

/// USN_RECORD_V3 を parse する。128-bit file reference を切り詰めず保持（互換 §4.3）。
fn parse_v3(
    body: &[u8],
    header: &CommonHeader,
    record_offset: u64,
) -> Result<UsnRecord, RecordError> {
    if body.len() < V3_FIXED_BYTES {
        return Err(RecordError::ShortRecord {
            version: 3,
            declared: header.record_length,
            fixed: V3_FIXED_BYTES,
        });
    }
    let mut file_ref: FileId128 = [0; 16];
    file_ref.copy_from_slice(&body[8..24]);
    let mut parent_ref: FileId128 = [0; 16];
    parent_ref.copy_from_slice(&body[24..40]);
    let usn = i64::from_le_bytes(body[40..48].try_into().unwrap());
    let time = u64::from_le_bytes(body[48..56].try_into().unwrap());
    let reason = u32::from_le_bytes(body[56..60].try_into().unwrap());
    let source_info = u32::from_le_bytes(body[60..64].try_into().unwrap());
    let security_id = u32::from_le_bytes(body[64..68].try_into().unwrap());
    let file_attributes = u32::from_le_bytes(body[68..72].try_into().unwrap());
    let file_name_length = u16::from_le_bytes(body[72..74].try_into().unwrap()) as u32;
    let file_name_offset = u16::from_le_bytes(body[74..76].try_into().unwrap()) as u32;
    let file_name = parse_file_name(
        body,
        file_name_offset,
        file_name_length,
        header.record_length,
    )?;

    Ok(UsnRecord {
        header: header.clone(),
        file_reference: FileReference::V3V4(file_ref),
        parent_reference: FileReference::V3V4(parent_ref),
        usn,
        time_filetime: time,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name,
        range_tracking: None,
        record_offset,
    })
}

/// USN_RECORD_V4 を parse する（filename 無し、range tracking 保持）。
fn parse_v4(
    body: &[u8],
    header: &CommonHeader,
    record_offset: u64,
) -> Result<UsnRecord, RecordError> {
    if body.len() < V4_FIXED_BYTES {
        return Err(RecordError::ShortRecord {
            version: 4,
            declared: header.record_length,
            fixed: V4_FIXED_BYTES,
        });
    }
    let mut file_ref: FileId128 = [0; 16];
    file_ref.copy_from_slice(&body[8..24]);
    let mut parent_ref: FileId128 = [0; 16];
    parent_ref.copy_from_slice(&body[24..40]);
    let usn = i64::from_le_bytes(body[40..48].try_into().unwrap());
    let time = u64::from_le_bytes(body[48..56].try_into().unwrap());
    let reason = u32::from_le_bytes(body[56..60].try_into().unwrap());
    let source_info = u32::from_le_bytes(body[60..64].try_into().unwrap());
    let remaining_extents = u16::from_le_bytes(body[64..66].try_into().unwrap());
    let number_of_extents = u16::from_le_bytes(body[66..68].try_into().unwrap());
    let extent_location = u64::from_le_bytes(body[68..76].try_into().unwrap());
    let extent_length = u64::from_le_bytes(body[76..84].try_into().unwrap());

    Ok(UsnRecord {
        header: header.clone(),
        file_reference: FileReference::V3V4(file_ref),
        parent_reference: FileReference::V3V4(parent_ref),
        usn,
        time_filetime: time,
        reason,
        source_info,
        // V4 は security_id / file_attributes を持たない。0 で保持する。
        security_id: 0,
        file_attributes: 0,
        // V4 は filename を持たない（互換 §4.3: filename 非前提で処理）。
        file_name: None,
        range_tracking: Some(RangeTracking {
            remaining_extents,
            number_of_extents,
            extent_location,
            extent_length,
        }),
        record_offset,
    })
}

/// filename 領域を UTF-16LE として decode する。
/// offset と length は record 先頭からの byte 位置。安全に境界検証する。
fn parse_file_name(
    body: &[u8],
    offset: u32,
    length: u32,
    record_length: u32,
) -> Result<Option<String>, RecordError> {
    if length == 0 {
        return Ok(None);
    }
    let start = offset as usize;
    let end = start
        .checked_add(length as usize)
        .ok_or(RecordError::BadFileNameRange {
            offset,
            length,
            record_len: record_length,
        })?;
    if start < V2_FIXED_BYTES || end > body.len() || end > record_length as usize {
        return Err(RecordError::BadFileNameRange {
            offset,
            length,
            record_len: record_length,
        });
    }
    let bytes = &body[start..end];
    // UTF-16LE unit 数は偶数でなければならない。
    if !bytes.len().is_multiple_of(2) {
        return Err(RecordError::BadFileNameEncoding(format!(
            "奇数 byte の filename: {} byte",
            bytes.len()
        )));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // 終端 NUL は取り除く。
    let trimmed: Vec<u16> = units.into_iter().take_while(|&u| u != 0).collect();
    String::from_utf16(&trimmed)
        .map(Some)
        .map_err(|e| RecordError::BadFileNameEncoding(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u16, length: u32) -> CommonHeader {
        CommonHeader {
            record_length: length,
            major_version: version,
            minor_version: 0,
        }
    }

    #[test]
    fn file_reference_v2_key_is_stable() {
        let r = FileReference::V2(0x0001_0000_0000_1234);
        let key = r.as_comparison_key();
        assert_eq!(key, "v2:0001000000001234");
        assert_eq!(r.mft_segment_number(), Some(0x1234));
        assert_eq!(r.sequence_number(), Some(1));
    }

    #[test]
    fn file_reference_v3v4_key_preserves_full_128bit() {
        let raw = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let r = FileReference::V3V4(raw);
        // 16 byte すべて32桁 hex へ。切り詰めなし（互換 §4.3）。
        assert_eq!(
            r.as_comparison_key(),
            "v3v4:0102030405060708090a0b0c0d0e0f10"
        );
        assert_eq!(r.mft_segment_number(), None);
        assert_eq!(r.sequence_number(), None);
    }

    #[test]
    fn parse_v2_basic_fields() {
        let mut buf = vec![0u8; V2_FIXED_BYTES];
        // record length は固定部 + filename "AB" (4 byte)
        let total = V2_FIXED_BYTES as u32 + 4;
        buf[0..4].copy_from_slice(&total.to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[8..16].copy_from_slice(&0x0001_0000_0000_ABCDu64.to_le_bytes());
        buf[16..24].copy_from_slice(&0x0005_0000_0000_0001u64.to_le_bytes());
        buf[24..32].copy_from_slice(&1234i64.to_le_bytes());
        buf[32..40].copy_from_slice(&132_548_480_000_000_000u64.to_le_bytes());
        buf[40..44].copy_from_slice(&0x0000_1000u32.to_le_bytes()); // RENAME_OLD_NAME
        buf[44..48].copy_from_slice(&0u32.to_le_bytes());
        buf[48..52].copy_from_slice(&0u32.to_le_bytes());
        buf[52..56].copy_from_slice(&0x0000_0020u32.to_le_bytes()); // ARCHIVE
        buf[56..58].copy_from_slice(&4u16.to_le_bytes()); // 4 byte = 2 chars
        buf[58..60].copy_from_slice(&(V2_FIXED_BYTES as u16).to_le_bytes()); // filename offset
        // filename
        buf.extend_from_slice(&[b'A', 0, b'B', 0]);
        let hdr = header(2, total);
        let rec = parse_record(&buf, &hdr, 0).unwrap();
        assert_eq!(rec.header.major_version, 2);
        assert_eq!(rec.file_reference, FileReference::V2(0x0001_0000_0000_ABCD));
        assert_eq!(rec.usn, 1234);
        assert_eq!(rec.reason, 0x0000_1000);
        assert_eq!(rec.file_name.as_deref(), Some("AB"));
        assert_eq!(rec.record_offset, 0);
    }

    #[test]
    fn parse_v3_preserves_128bit_references() {
        let mut buf = vec![0u8; V3_FIXED_BYTES];
        // V3 固定部 60 byte。filename 無しで最小限。
        let total = V3_FIXED_BYTES as u32;
        buf[0..4].copy_from_slice(&total.to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        let file_id: [u8; 16] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        buf[8..24].copy_from_slice(&file_id);
        buf[24..40].copy_from_slice(&file_id);
        buf[40..48].copy_from_slice(&42i64.to_le_bytes());
        let hdr = header(3, total);
        let rec = parse_record(&buf, &hdr, 100).unwrap();
        assert_eq!(rec.file_reference, FileReference::V3V4(file_id));
        assert_eq!(rec.usn, 42);
        assert_eq!(rec.record_offset, 100);
        assert!(rec.file_name.is_none());
    }

    #[test]
    fn parse_v4_has_range_tracking_no_filename() {
        let mut buf = vec![0u8; V4_FIXED_BYTES];
        let total = V4_FIXED_BYTES as u32;
        buf[0..4].copy_from_slice(&total.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        let file_id: [u8; 16] = [0xFF; 16];
        buf[8..24].copy_from_slice(&file_id);
        buf[24..40].copy_from_slice(&file_id);
        buf[40..48].copy_from_slice(&99i64.to_le_bytes());
        buf[64..66].copy_from_slice(&0u16.to_le_bytes()); // remaining
        buf[66..68].copy_from_slice(&1u16.to_le_bytes()); // number
        buf[68..76].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[76..84].copy_from_slice(&4096u64.to_le_bytes());
        let hdr = header(4, total);
        let rec = parse_record(&buf, &hdr, 0).unwrap();
        assert!(rec.file_name.is_none());
        let rt = rec.range_tracking.expect("V4 は range tracking を持つ");
        assert_eq!(rt.remaining_extents, 0);
        assert_eq!(rt.number_of_extents, 1);
        assert_eq!(rt.extent_location, 0x1000);
        assert_eq!(rt.extent_length, 4096);
    }

    #[test]
    fn truncated_record_returns_err() {
        let hdr = header(2, V2_FIXED_BYTES as u32 + 8);
        let buf = vec![0u8; 20]; // 宣言長に満たない
        let e = parse_record(&buf, &hdr, 0).unwrap_err();
        assert!(matches!(e, RecordError::Truncated { .. }));
    }

    #[test]
    fn oversize_record_returns_err() {
        let hdr = header(2, MAX_RECORD_LENGTH + 1);
        let buf = vec![0u8; 10];
        let e = parse_record(&buf, &hdr, 0).unwrap_err();
        assert!(matches!(e, RecordError::Oversize(_)));
    }

    #[test]
    fn bad_filename_offset_returns_err() {
        let mut buf = vec![0u8; V2_FIXED_BYTES];
        buf[0..4].copy_from_slice(&(V2_FIXED_BYTES as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[56..58].copy_from_slice(&4u16.to_le_bytes()); // length
        buf[58..60].copy_from_slice(&0xFFFFu16.to_le_bytes()); // 不正 offset
        let hdr = header(2, V2_FIXED_BYTES as u32);
        let e = parse_record(&buf, &hdr, 0).unwrap_err();
        assert!(matches!(e, RecordError::BadFileNameRange { .. }));
    }
}
