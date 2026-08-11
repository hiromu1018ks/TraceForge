//! EVTX chunk（65536 byte block）の解析（libyal libevtx 仕様、互換 §4.2、T4-040・T4-045）。
//!
//! EVTX file は file header（4096 byte）の直後から 0 個以上の chunk が並ぶ。
//! 各 chunk は 65536 byte（`0x10000`）固定。chunk header は先頭 512 byte:
//!
//! ```text
//! offset  size  内容
//! 0       8     magic "ElfChnk\x00"
//! 8       8     first_event_record_number (u64 LE)
//! 16      8     last_event_record_number (u64 LE)
//! 24      8     first_event_record_identifier (u64 LE)
//! 32      8     last_event_record_identifier (u64 LE)
//! 40      4     header_size (u32 LE, 512)
//! 44      4     last_event_record_data_offset (u32 LE)
//! 48      4     free_space_offset (u32 LE: 未使用領域の開始位置 = records 終端)
//! 52      4     event_records_checksum (u32 LE: bytes [512..free_space_offset] の CRC-32)
//! 56      4     unknown (chunk flags)
//! 60      4     unknown
//! 64      256   strings hash table (64 entries × 4 byte)
//! 320     128   template hash table (32 entries × 4 byte)
//! 448     48    unknown
//! 496     4     chunk header checksum 1 (CRC-32 of bytes [0..120] + [128..504])
//! 500     4     unknown
//! 504     4     chunk header checksum 2 (CRC-32 of bytes [0..120] + [128..512])
//! 508     4     unknown
//! ```
//!
//! chunk 内の records 領域は offset 512 から `free_space_offset` まで。各 record は
//! 先頭 0x2a2a magic を持つ（`record.rs` 参照）。
//!
//! ## partial recovery（規範 §9.2・§21-5・互換 §4.2）
//!
//! - chunk magic が不一致 → chunk を解析対象外へ（Warning を発して次 chunk へ）
//! - chunk header checksum 不一致 → Warning を発しつつ records の解析を試みる
//! - records checksum 不一致 → Warning を発しつつ records の解析を試みる
//! - records 内の個別 record 破損 → 当該 record を skip して次 record へ

/// 1 chunk の固定 size（byte）。
pub const CHUNK_BYTES: usize = 65_536;
/// chunk header の size（byte）。
pub const CHUNK_HEADER_BYTES: usize = 512;
/// records 領域の開始 offset（chunk 先頭からの byte offset）。
pub const CHUNK_RECORDS_OFFSET: usize = 512;
/// chunk magic（8 byte）。
pub const CHUNK_MAGIC: [u8; 8] = *b"ElfChnk\x00";

/// chunk header checksum が cover する先頭領域の終端。
const HEADER_CKSUM_FIRST_END: usize = 120;

/// 解析済みの chunk header。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkHeader {
    pub first_event_record_number: u64,
    pub last_event_record_number: u64,
    pub first_event_record_identifier: u64,
    pub last_event_record_identifier: u64,
    pub header_size: u32,
    pub last_event_record_data_offset: u32,
    pub free_space_offset: u32,
    pub event_records_checksum: u32,
    /// offset 496 の header checksum 1。
    pub stored_header_checksum_1: u32,
    /// offset 504 の header checksum 2。
    pub stored_header_checksum_2: u32,
}

/// chunk 解析の失敗理由。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    /// `buf` が 1 chunk size（65536 byte）に満たない。
    #[error("chunk が {0} byte しかない（{CHUNK_BYTES} byte 必要）")]
    Truncated(usize),
    /// chunk magic が "ElfChnk\x00" でない。
    #[error("chunk magic が ElfChnk\\x00 ではない")]
    MagicMismatch,
    /// `free_space_offset` が chunk size を超えている等の明らかな形式異常。
    #[error("free_space_offset {0} が chunk size を超える")]
    BadFreeSpaceOffset(u32),
}

/// chunk 全体（65536 byte）から header を parse する。
///
/// 呼出側は `buf.len() == CHUNK_BYTES` を保証することが望ましいが、短すぎる場合は
/// [`ChunkError::Truncated`] を返す。
pub fn parse_chunk_header(buf: &[u8]) -> Result<ChunkHeader, ChunkError> {
    if buf.len() < CHUNK_HEADER_BYTES {
        return Err(ChunkError::Truncated(buf.len()));
    }
    if buf[0..8] != CHUNK_MAGIC {
        return Err(ChunkError::MagicMismatch);
    }
    let first_event_record_number = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let last_event_record_number = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let first_event_record_identifier = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let last_event_record_identifier = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let header_size = u32::from_le_bytes(buf[40..44].try_into().unwrap());
    let last_event_record_data_offset = u32::from_le_bytes(buf[44..48].try_into().unwrap());
    let free_space_offset = u32::from_le_bytes(buf[48..52].try_into().unwrap());
    let event_records_checksum = u32::from_le_bytes(buf[52..56].try_into().unwrap());
    let stored_header_checksum_1 = u32::from_le_bytes(buf[496..500].try_into().unwrap());
    let stored_header_checksum_2 = u32::from_le_bytes(buf[504..508].try_into().unwrap());

    if free_space_offset as usize > CHUNK_BYTES {
        return Err(ChunkError::BadFreeSpaceOffset(free_space_offset));
    }

    Ok(ChunkHeader {
        first_event_record_number,
        last_event_record_number,
        first_event_record_identifier,
        last_event_record_identifier,
        header_size,
        last_event_record_data_offset,
        free_space_offset,
        event_records_checksum,
        stored_header_checksum_1,
        stored_header_checksum_2,
    })
}

impl ChunkHeader {
    /// chunk header checksum 1（offset 496）の検証。
    /// bytes [0..120] + [128..504] を cover するが、checksum field [496..500] は
    /// 計算時に 0 扱いする（CRC の自己再帰性を避けるため）。
    pub fn header_checksum_1_matches(&self, buf: &[u8]) -> bool {
        if buf.len() < 504 {
            return false;
        }
        let computed = compute_chunk_header_cksum_1(buf);
        computed == self.stored_header_checksum_1
    }

    /// chunk header checksum 2（offset 504）の検証。
    /// bytes [0..120] + [128..512] を cover する。checksum fields [496..500] と [504..508]
    /// は計算時に 0 扱いする。
    pub fn header_checksum_2_matches(&self, buf: &[u8]) -> bool {
        if buf.len() < 512 {
            return false;
        }
        let computed = compute_chunk_header_cksum_2(buf);
        computed == self.stored_header_checksum_2
    }

    /// records 領域（bytes [512..free_space_offset]）の checksum 検証（offset 52 の値）。
    /// この checksum が実データ整合性の主要指標。chunk header checksum より優先する。
    pub fn records_checksum_matches(&self, buf: &[u8]) -> bool {
        let end = (self.free_space_offset as usize).min(buf.len());
        if end < CHUNK_RECORDS_OFFSET {
            return false;
        }
        let computed = crate::evtx::crc32::crc32(&buf[CHUNK_RECORDS_OFFSET..end]);
        computed == self.event_records_checksum
    }

    /// records 領域（bytes [512..free_space_offset]）を取り出す。
    /// `free_space_offset` が chunk size を超える場合は安全に切り詰める。
    pub fn records_slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = (self.free_space_offset as usize).min(buf.len());
        if end < CHUNK_RECORDS_OFFSET {
            return &[];
        }
        buf.get(CHUNK_RECORDS_OFFSET..end).unwrap_or(&[])
    }
}

/// chunk header checksum 1 を計算する（[0..120] + [128..504]・[496..500] は 0 扱い）。
fn compute_chunk_header_cksum_1(buf: &[u8]) -> u32 {
    let mut copy = Vec::with_capacity(504 - 8);
    copy.extend_from_slice(&buf[0..HEADER_CKSUM_FIRST_END]);
    copy.extend_from_slice(&buf[128..496]);
    // bytes [496..500] は checksum field なので 0 扱い（4 byte の zero を挿入）。
    copy.extend_from_slice(&[0u8; 4]);
    copy.extend_from_slice(&buf[500..504]);
    crate::evtx::crc32::crc32(&copy)
}

/// chunk header checksum 2 を計算する（[0..120] + [128..512]・[496..500]・[504..508] は 0 扱い）。
fn compute_chunk_header_cksum_2(buf: &[u8]) -> u32 {
    let mut copy = Vec::with_capacity(512 - 8);
    copy.extend_from_slice(&buf[0..HEADER_CKSUM_FIRST_END]);
    copy.extend_from_slice(&buf[128..496]);
    copy.extend_from_slice(&[0u8; 4]); // [496..500]
    copy.extend_from_slice(&buf[500..504]);
    copy.extend_from_slice(&[0u8; 4]); // [504..508]
    copy.extend_from_slice(&buf[508..512]);
    crate::evtx::crc32::crc32(&copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小限の chunk header を構築する。records 領域は空（free_space_offset = 512）。
    fn build_chunk_header(free_space_offset: u32, records: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; CHUNK_BYTES];
        buf[0..8].copy_from_slice(&CHUNK_MAGIC);
        buf[40..44].copy_from_slice(&512u32.to_le_bytes());
        buf[44..48].copy_from_slice(&free_space_offset.to_le_bytes()); // last_event_record_data_offset
        buf[48..52].copy_from_slice(&free_space_offset.to_le_bytes()); // free_space_offset
        // records を配置（free_space_offset より前）。
        let records_end = 512 + records.len();
        if records_end <= CHUNK_BYTES {
            buf[512..records_end].copy_from_slice(records);
        }
        // records checksum: bytes [512..free_space_offset] の CRC-32。
        let end = (free_space_offset as usize).min(CHUNK_BYTES);
        let records_crc = crate::evtx::crc32::crc32(&buf[512..end]);
        buf[52..56].copy_from_slice(&records_crc.to_le_bytes());
        // header checksum 1: bytes [0..120] + [128..504]・[496..500] は 0 扱い。
        let cksum1 = compute_chunk_header_cksum_1(&buf);
        buf[496..500].copy_from_slice(&cksum1.to_le_bytes());
        // header checksum 2: bytes [0..120] + [128..512]・[496..500] と [504..508] は 0 扱い。
        let cksum2 = compute_chunk_header_cksum_2(&buf);
        buf[504..508].copy_from_slice(&cksum2.to_le_bytes());
        buf
    }

    #[test]
    fn parses_minimal_chunk_header() {
        let buf = build_chunk_header(512, &[]);
        let h = parse_chunk_header(&buf).unwrap();
        assert_eq!(h.free_space_offset, 512);
        assert!(h.header_checksum_1_matches(&buf));
        assert!(h.header_checksum_2_matches(&buf));
        assert!(h.records_checksum_matches(&buf));
    }

    #[test]
    fn detects_records_checksum_mismatch() {
        // 正しい header を作った後、records を書き換えて checksum を再計算しない。
        let mut buf = build_chunk_header(520, &[0xAA]);
        // records の先頭を破壊。
        buf[512] = 0x55;
        let h = parse_chunk_header(&buf).unwrap();
        assert!(!h.records_checksum_matches(&buf), "checksum が不一致を検出");
    }

    #[test]
    fn detects_header_checksum_1_mismatch() {
        let mut buf = build_chunk_header(512, &[]);
        buf[40] = 0xFF; // header_size を破壊 → checksum 1 が合わなくなる
        let h = parse_chunk_header(&buf).unwrap();
        assert!(!h.header_checksum_1_matches(&buf));
    }

    #[test]
    fn rejects_truncated_buf() {
        let buf = vec![0u8; 100];
        assert_eq!(
            parse_chunk_header(&buf).unwrap_err(),
            ChunkError::Truncated(100)
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; CHUNK_BYTES];
        buf[0..8].copy_from_slice(b"ElfFile\x00"); // file magic を誤使用
        assert_eq!(
            parse_chunk_header(&buf).unwrap_err(),
            ChunkError::MagicMismatch
        );
    }

    #[test]
    fn rejects_oversize_free_space_offset() {
        let mut buf = vec![0u8; CHUNK_BYTES];
        buf[0..8].copy_from_slice(&CHUNK_MAGIC);
        buf[48..52].copy_from_slice(&((CHUNK_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            parse_chunk_header(&buf).unwrap_err(),
            ChunkError::BadFreeSpaceOffset(_)
        ));
    }

    #[test]
    fn records_slice_handles_bounds() {
        let h = ChunkHeader {
            first_event_record_number: 0,
            last_event_record_number: 0,
            first_event_record_identifier: 0,
            last_event_record_identifier: 0,
            header_size: 512,
            last_event_record_data_offset: 512,
            free_space_offset: 600,
            event_records_checksum: 0,
            stored_header_checksum_1: 0,
            stored_header_checksum_2: 0,
        };
        let buf = vec![0u8; CHUNK_BYTES];
        let slice = h.records_slice(&buf);
        assert_eq!(slice.len(), 88);
    }
}
