//! EVTX record の解析（libyal libevtx 仕様、互換 §4.2、T4-040・T4-042）。
//!
//! EVTX chunk の records 領域（offset 512 以降）へ並ぶ個別 record。各 record:
//!
//! ```text
//! offset  size  内容
//! 0       2     magic 0x2a 0x2a
//! 2       4     record_size (i32 LE: 全体 byte 長から magic 2 byte を引いたもの。
//!                負値は空き領域を意味する)
//! 6       8     event_record_identifier (u64 LE: 通番)
//! 14      8     event_record_timestamp (u64 LE: FILETIME)
//! 22      ...   binxml 本体 (record_size - 24 byte)
//! (末尾)  4     record_size の繰り返し (i32 LE)
//! ```
//!
//! **record_size の意味**: `record_size` は magic 2 byte を含まない。record 全体の byte 長は
//! `2 + record_size`。binxml 本体は `record_size - 24` byte（4 + 8 + 8 + 4 = 24 byte が
//! size/id/timestamp/size_copy の固定部）。
//!
//! ## partial recovery
//!
//! - magic 不一致 → 残り record を信頼できない。呼出側は chunk の解析を打ち切る。
//! - record_size < 0 → 空き領域。chunk 末尾とみなす。
//! - record_size が異常に大きい → 信頼できない。呼出側は chunk の解析を打ち切る。
//! - 先頭と末尾の size 不一致 → 破損。Warning を出して skip。

use crate::evtx::binxml;

/// EVTX record magic（2 byte）。
pub const RECORD_MAGIC: [u8; 2] = [0x2a, 0x2a];

/// record の固定 header 部（magic 2 + size 4 + id 8 + timestamp 8 = 22 byte）。
pub const RECORD_HEADER_BYTES: usize = 22;
/// record size の安全上限（byte）。EVTX record は通常 64 KB 未満。
/// 1 chunk が 65536 byte なので、実質的に 65534 byte を超える record は存在し得ない。
pub const MAX_RECORD_SIZE: u32 = 65_534;
/// record size の最小値（22 byte header + 4 byte size_copy = 26 byte）。
pub const MIN_RECORD_SIZE: u32 = 26;

/// record の parse 結果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    /// record_size（magic 2 byte を含まない）。record 全体は `2 + size` byte。
    pub size: u32,
    /// event record identifier（通番）。
    pub event_record_id: u64,
    /// event timestamp（FILETIME, UTC）。
    pub timestamp_filetime: u64,
}

/// record parse の失敗理由。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// record 固定 header（22 byte）に満たない。
    #[error("record header ({RECORD_HEADER_BYTES} byte) に満たない: {0} byte")]
    TooShort(usize),
    /// magic が 0x2a2a でない。
    #[error("record magic が 0x2a2a ではない: 0x{0:02x}{1:02x}")]
    MagicMismatch(u8, u8),
    /// record_size が負（空き領域）。
    #[error("record_size が負: {0}（空き領域）")]
    Empty(i32),
    /// record_size が最小値に満たない。
    #[error("record_size {0} が最小値 ({MIN_RECORD_SIZE}) 未満")]
    TooSmallSize(u32),
    /// record_size が上限を超える。
    #[error("record_size {0} が上限 ({MAX_RECORD_SIZE}) を超える")]
    Oversize(u32),
    /// 宣言 size が chunk 残り byte 数を超える（truncated）。
    #[error("record_size {declared} だが残り {actual} byte しかない")]
    Truncated { declared: u32, actual: usize },
    /// 先頭 size と末尾 size copy が不一致。
    #[error("先頭 size {head} と末尾 size copy {tail} が不一致")]
    SizeMismatch { head: u32, tail: i32 },
    /// binxml 本体の decode 失敗。
    #[error("binxml decode 失敗: {0}")]
    BinxmlDecode(binxml::DecodeError),
}

impl From<binxml::DecodeError> for RecordError {
    fn from(e: binxml::DecodeError) -> Self {
        RecordError::BinxmlDecode(e)
    }
}

/// EVTX record 1件 の parse 結果（header + binxml で抽出した event 内容）。
#[derive(Clone, Debug)]
pub struct ParsedRecord {
    pub header: RecordHeader,
    /// binxml 本体から抽出した event 内容（provider/channel/computer/event_id 等）。
    pub content: binxml::EventContent,
}

/// records 領域（chunk の 512 byte 以降）から1 record を parse する。
///
/// `buf` は chunk records 領域全体（先頭から）。`offset` は record 先頭位置。
/// 戻り値は `(parse 結果, 次の record の offset)`。
///
/// `offset` が `buf` の範囲外の場合は `Err(TooShort)`。
pub fn parse_record_at(buf: &[u8], offset: usize) -> Result<(ParsedRecord, usize), RecordError> {
    if offset + RECORD_HEADER_BYTES > buf.len() {
        return Err(RecordError::TooShort(buf.len().saturating_sub(offset)));
    }
    let head = &buf[offset..];
    if head[0..2] != RECORD_MAGIC {
        return Err(RecordError::MagicMismatch(head[0], head[1]));
    }
    let size_raw = i32::from_le_bytes(head[2..6].try_into().unwrap());
    if size_raw < 0 {
        return Err(RecordError::Empty(size_raw));
    }
    let size = size_raw as u32;
    if size < MIN_RECORD_SIZE {
        return Err(RecordError::TooSmallSize(size));
    }
    if size > MAX_RECORD_SIZE {
        return Err(RecordError::Oversize(size));
    }
    // record 全体 = 2 (magic) + size。magic 2 byte を足した範囲が buf 内にあること。
    let record_total = 2u32.checked_add(size).ok_or(RecordError::Oversize(size))?;
    if offset + record_total as usize > buf.len() {
        return Err(RecordError::Truncated {
            declared: record_total,
            actual: buf.len().saturating_sub(offset),
        });
    }
    let event_record_id = u64::from_le_bytes(head[6..14].try_into().unwrap());
    let timestamp_filetime = u64::from_le_bytes(head[14..22].try_into().unwrap());

    // 末尾 size copy の検証。
    let tail_offset = 2 + size as usize - 4;
    let tail_size_raw = i32::from_le_bytes(
        buf[offset + tail_offset..offset + tail_offset + 4]
            .try_into()
            .unwrap(),
    );
    if tail_size_raw < 0 || tail_size_raw as u32 != size {
        return Err(RecordError::SizeMismatch {
            head: size,
            tail: tail_size_raw,
        });
    }

    // binxml 本体（offset + 22 .. offset + 2 + size - 4）。
    let binxml_start = offset + 22;
    let binxml_end = offset + 2 + size as usize - 4;
    let binxml_bytes = buf
        .get(binxml_start..binxml_end)
        .ok_or(RecordError::Truncated {
            declared: record_total,
            actual: buf.len().saturating_sub(offset),
        })?;
    let content = binxml::decode_record(binxml_bytes)?;

    let next_offset = offset + record_total as usize;
    Ok((
        ParsedRecord {
            header: RecordHeader {
                size,
                event_record_id,
                timestamp_filetime,
            },
            content,
        },
        next_offset,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evtx::binxml::{BinXmlBuilder, EventContentSpec, ev_data};

    /// テスト用の最小 binxml を構築する。
    fn sample_binxml() -> Vec<u8> {
        let mut builder = BinXmlBuilder::new();
        builder.start_event(&EventContentSpec {
            provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
            provider_guid: Some("{54849625-5478-4994-A5BA-3E3B0328C30D}".to_string()),
            event_id: 4624,
            version: Some(0),
            level: Some(0),
            channel: "Security".to_string(),
            computer: "WORKSTATION1".to_string(),
            event_data: vec![ev_data("TargetUserName", "alice")],
        });
        builder.finish()
    }

    fn build_record(record_id: u64, timestamp: u64, binxml: &[u8]) -> Vec<u8> {
        let size = 4 + 8 + 8 + binxml.len() + 4; // size+id+ts+binxml+size_copy
        let mut buf = Vec::with_capacity(2 + size);
        buf.extend_from_slice(&RECORD_MAGIC);
        buf.extend_from_slice(&(size as i32).to_le_bytes());
        buf.extend_from_slice(&record_id.to_le_bytes());
        buf.extend_from_slice(&timestamp.to_le_bytes());
        buf.extend_from_slice(binxml);
        buf.extend_from_slice(&(size as i32).to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_record() {
        let binxml = sample_binxml();
        let record = build_record(42, 132_548_480_000_000_000, &binxml);
        let (parsed, next) = parse_record_at(&record, 0).unwrap();
        assert_eq!(parsed.header.event_record_id, 42);
        assert_eq!(parsed.header.timestamp_filetime, 132_548_480_000_000_000);
        assert_eq!(parsed.content.event_id, Some(4624));
        assert_eq!(next, record.len());
    }

    #[test]
    fn rejects_short_buf() {
        let buf = vec![0u8; 10];
        assert!(matches!(
            parse_record_at(&buf, 0).unwrap_err(),
            RecordError::TooShort(_)
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; 26];
        buf[0] = 0x11;
        buf[1] = 0x22;
        assert!(matches!(
            parse_record_at(&buf, 0).unwrap_err(),
            RecordError::MagicMismatch(_, _)
        ));
    }

    #[test]
    fn detects_empty_marker() {
        // size = -1（空き領域）
        let mut buf = vec![0u8; 26];
        buf[0..2].copy_from_slice(&RECORD_MAGIC);
        buf[2..6].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(matches!(
            parse_record_at(&buf, 0).unwrap_err(),
            RecordError::Empty(_)
        ));
    }

    #[test]
    fn detects_too_small_size() {
        let mut buf = vec![0u8; 30];
        buf[0..2].copy_from_slice(&RECORD_MAGIC);
        buf[2..6].copy_from_slice(&10i32.to_le_bytes()); // size = 10 < MIN
        assert!(matches!(
            parse_record_at(&buf, 0).unwrap_err(),
            RecordError::TooSmallSize(_)
        ));
    }

    #[test]
    fn detects_truncated_record() {
        let binxml = sample_binxml();
        let mut record = build_record(1, 0, &binxml);
        record.truncate(record.len() - 5); // 末尾を削って truncated
        assert!(matches!(
            parse_record_at(&record, 0).unwrap_err(),
            RecordError::Truncated { .. }
        ));
    }

    #[test]
    fn detects_size_mismatch() {
        let binxml = sample_binxml();
        let mut record = build_record(1, 0, &binxml);
        // 末尾 size copy を書き換える。
        let tail_pos = record.len() - 4;
        let wrong_size = (record.len() as i32) + 100;
        record[tail_pos..tail_pos + 4].copy_from_slice(&wrong_size.to_le_bytes());
        assert!(matches!(
            parse_record_at(&record, 0).unwrap_err(),
            RecordError::SizeMismatch { .. }
        ));
    }
}
