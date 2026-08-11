//! EVTX file header の解析（libyal libevtx 仕様、互換 §4.2、T4-040）。
//!
//! EVTX file は先頭 4096 byte の file header から始まる:
//!
//! ```text
//! offset  size  内容
//! 0       8     magic "ElfFile\x00"
//! 8       8     first_chunk_number (u64 LE)
//! 16      8     last_chunk_number (u64 LE)
//! 24      8     next_record_identifier (u64 LE)
//! 32      4     header_size (u32 LE, 通常 128)
//! 36      2     minor_version (u16 LE, 通常 1)
//! 38      2     major_version (u16 LE, 通常 3)
//! 40      2     header_block_size (u16 LE, 通常 4096)
//! 42      2     unknown
//! 44      2     chunk_count (u16 LE)
//! 46      2     unknown
//! 48      4     flags (bit 0 = is_dirty, bit 1 = is_full)
//! ...
//! 120     8     unknown
//! 128     3968  (chunk 内容の占有的ではなく、file format 上は 0 padding)
//! ```
//!
//! 互換 §4.2 は standalone `.evtx` を必須対応とし、Legacy `.evt` は Unsupported とする。
//! 本 module は file 先頭 magic と基本 metadata を取り出す。

use crate::evtx::crc32::crc32_sequential;

/// EVTX file header の固定長（byte）。EVTX は 4096 byte block 単位で管理される。
pub const FILE_HEADER_BYTES: usize = 4096;

/// EVTX file magic（8 byte）。`ElfFile\x00`。
pub const EVTX_FILE_MAGIC: [u8; 8] = *b"ElfFile\x00";

/// EVTX major version（libyal libevtx 既定値）。
pub const EVTX_MAJOR_VERSION: u16 = 3;
/// EVTX minor version（libyal libevtx 既定値）。
pub const EVTX_MINOR_VERSION: u16 = 1;

/// file header checksum が cover する先頭 byte 数。
const HEADER_CHECKSUM_FIRST_END: usize = 120;
/// file header 内 checksum が skip する領域の終端（offset 128 まで unknown 領域）。
const HEADER_CHECKSUM_SECOND_START: usize = 128;
/// file header 内 checksum の格納 offset。
const HEADER_CHECKSUM_OFFSET: usize = 124;

/// 解析済みの EVTX file header。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    /// 最初の chunk 番号（通常 0）。
    pub first_chunk_number: u64,
    /// 最後の chunk 番号。
    pub last_chunk_number: u64,
    /// 次に割り当てられる record identifier。
    pub next_record_identifier: u64,
    /// header 構造体の size（通常 128）。
    pub header_size: u32,
    /// major version（通常 3）。
    pub major_version: u16,
    /// minor version（通常 1）。
    pub minor_version: u16,
    /// header block 全体の size（通常 4096）。
    pub header_block_size: u16,
    /// file 内の chunk 数。
    pub chunk_count: u16,
    /// flags（bit 0 = dirty, bit 1 = full）。
    pub flags: u32,
    /// header に記録された checksum。
    pub stored_checksum: u32,
    /// 本 header から計算した checksum。
    pub computed_checksum: u32,
}

/// header 解析の失敗理由。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// `buf` が file header 固定長（4096 byte）に満たない。
    #[error("file header が {0} byte しかない（{FILE_HEADER_BYTES} byte 必要）")]
    TooShort(usize),
    /// 先頭 magic が "ElfFile\x00" でない（EVTX ではない・Legacy .evt の可能性）。
    ///
    /// 互換 §4.2: Legacy `.evt` は EVTX として解析しない。本 error を起点に
    /// 呼出側が Unsupported 扱いへ分岐する。
    #[error("magic が ElfFile\\x00 ではない（Legacy .evt の可能性）")]
    MagicMismatch,
}

/// file header を解析する。
///
/// `buf` は [`FILE_HEADER_BYTES`] 以上を推奨。短すぎる場合は [`HeaderError::TooShort`]。
/// magic 不一致は [`HeaderError::MagicMismatch`]（呼出側で Legacy `.evt` 等の扱いへ）。
pub fn parse_file_header(buf: &[u8]) -> Result<FileHeader, HeaderError> {
    if buf.len() < FILE_HEADER_BYTES {
        // header 自体が短すぎる場合は明確に error。
        // 呼出側は skipped へ。
        if buf.len() < HEADER_CHECKSUM_OFFSET + 4 {
            return Err(HeaderError::TooShort(buf.len()));
        }
        // 4096 未満だが最低限の header field は読める場合も TooShort 扱い。
        return Err(HeaderError::TooShort(buf.len()));
    }
    if buf[0..8] != EVTX_FILE_MAGIC {
        return Err(HeaderError::MagicMismatch);
    }
    let first_chunk_number = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let last_chunk_number = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let next_record_identifier = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let header_size = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let minor_version = u16::from_le_bytes(buf[36..38].try_into().unwrap());
    let major_version = u16::from_le_bytes(buf[38..40].try_into().unwrap());
    let header_block_size = u16::from_le_bytes(buf[40..42].try_into().unwrap());
    let chunk_count = u16::from_le_bytes(buf[44..46].try_into().unwrap());
    let flags = u32::from_le_bytes(buf[48..52].try_into().unwrap());
    let stored_checksum = u32::from_le_bytes(
        buf[HEADER_CHECKSUM_OFFSET..HEADER_CHECKSUM_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let computed_checksum = crc32_sequential(
        &buf[0..HEADER_CHECKSUM_FIRST_END],
        &buf[HEADER_CHECKSUM_SECOND_START..FILE_HEADER_BYTES],
    );
    Ok(FileHeader {
        first_chunk_number,
        last_chunk_number,
        next_record_identifier,
        header_size,
        major_version,
        minor_version,
        header_block_size,
        chunk_count,
        flags,
        stored_checksum,
        computed_checksum,
    })
}

impl FileHeader {
    /// header に記録された checksum と計算値が一致するか（規範 §9.2: 破損検出）。
    ///
    /// 不一致でも解析を諦めるわけではない（partial recovery）。呼出側は
    /// 不一致の場合でも chunk へ進み、Warning を発する。
    pub fn checksum_matches(&self) -> bool {
        self.stored_checksum == self.computed_checksum
    }

    /// dirty flag が立っているか（bit 0）。dirty な file は書込み途中で閉じた可能性。
    pub fn is_dirty(&self) -> bool {
        self.flags & 0x1 != 0
    }

    /// full flag が立っているか（bit 1）。chunk が全て使用済み。
    pub fn is_full(&self) -> bool {
        self.flags & 0x2 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小限の有効な file header（4096 byte）を構築する。
    fn build_header(chunk_count: u16, flags: u32, corrupt_checksum: bool) -> Vec<u8> {
        let mut buf = vec![0u8; FILE_HEADER_BYTES];
        buf[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
        buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // first chunk
        buf[16..24].copy_from_slice(&(chunk_count as u64).to_le_bytes()); // last chunk
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());
        buf[32..36].copy_from_slice(&128u32.to_le_bytes());
        buf[36..38].copy_from_slice(&EVTX_MINOR_VERSION.to_le_bytes());
        buf[38..40].copy_from_slice(&EVTX_MAJOR_VERSION.to_le_bytes());
        buf[40..42].copy_from_slice(&4096u16.to_le_bytes());
        buf[44..46].copy_from_slice(&chunk_count.to_le_bytes());
        buf[48..52].copy_from_slice(&flags.to_le_bytes());
        let cksum = crc32_sequential(&buf[0..120], &buf[128..4096]);
        let to_store = if corrupt_checksum { !cksum } else { cksum };
        buf[124..128].copy_from_slice(&to_store.to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_header() {
        let buf = build_header(2, 0, false);
        let h = parse_file_header(&buf).unwrap();
        assert_eq!(h.chunk_count, 2);
        assert_eq!(h.major_version, EVTX_MAJOR_VERSION);
        assert_eq!(h.minor_version, EVTX_MINOR_VERSION);
        assert!(h.checksum_matches());
        assert!(!h.is_dirty());
    }

    #[test]
    fn detects_dirty_flag() {
        let buf = build_header(1, 0x1, false);
        let h = parse_file_header(&buf).unwrap();
        assert!(h.is_dirty());
        assert!(!h.is_full());
    }

    #[test]
    fn detects_full_flag() {
        let buf = build_header(1, 0x2, false);
        let h = parse_file_header(&buf).unwrap();
        assert!(!h.is_dirty());
        assert!(h.is_full());
    }

    #[test]
    fn detects_checksum_mismatch() {
        let buf = build_header(1, 0, true);
        let h = parse_file_header(&buf).unwrap();
        assert!(!h.checksum_matches());
    }

    #[test]
    fn rejects_short_buf() {
        let buf = vec![0u8; 100];
        assert_eq!(
            parse_file_header(&buf).unwrap_err(),
            HeaderError::TooShort(100)
        );
    }

    #[test]
    fn rejects_non_evtx_magic() {
        let mut buf = vec![0u8; FILE_HEADER_BYTES];
        buf[0..8].copy_from_slice(b"ElfChnk\x00"); // chunk magic
        assert_eq!(
            parse_file_header(&buf).unwrap_err(),
            HeaderError::MagicMismatch
        );
    }

    #[test]
    fn legacy_evt_magic_is_rejected() {
        // Legacy .evt の先頭は異なる magic を持つ。本 Parser はこれを弾く。
        let mut buf = vec![0u8; FILE_HEADER_BYTES];
        buf[0..4].copy_from_slice(&0x654c664cu32.to_le_bytes()); // "LfLe"
        assert_eq!(
            parse_file_header(&buf).unwrap_err(),
            HeaderError::MagicMismatch
        );
    }
}
