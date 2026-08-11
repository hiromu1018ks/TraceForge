//! Windows Registry hive 形式の parser（互換 §4.7・T4-050）。
//!
//! hive file は次の構造を持つ:
//!
//! ```text
//! ┌─────────────────────────────┐
//! │ base block (4096 byte)      │  magic "regf"・sequence・root_cell_offset・checksum
//! ├─────────────────────────────┤
//! │ hbin 0 (通常 4096 byte 境界) │  magic "hbin"・bin_size・cells...
//! ├─────────────────────────────┤
//! │ hbin 1                      │
//! ├─────────────────────────────┤
//! │ ...                         │
//! └─────────────────────────────┘
//! ```
//!
//! 各 cell の先頭4 byte は signed size（負 = 使用中・正 = 空き）。
//! 主な cell 種別:
//!
//! - `nk` (0x6B6E): key node。key 名・subkey list・value list・last_write timestamp を持つ。
//! - `vk` (0x764B): key value。value 名・型・data を持つ。
//! - `lf`/`lh`: subkey list（名前 hint 付き）
//! - `li`: subkey list（hint 無し）
//! - `ri`: subkey list の list（複数 list への参照）
//! - `val`: value list（vk offset の配列・ signature 無し）
//!
//! 本 parser は全ての key/value を走査し、[`KeyNode`]・[`KeyValue`] へ復元する。
//! 中間 cell の破損は Issue 化し、前後の正常 cell から継続する（規範 §9.2・§21-5）。
//! 循環参照・過深さ対策で訪問済み offset と depth 上限を管理する。

use std::collections::HashSet;

/// hive base block (regf header) の size（byte）。
pub const BASE_BLOCK_BYTES: usize = 4096;

/// hive bin の magic（"hbin"）。
pub const HBIN_MAGIC: [u8; 4] = *b"hbin";

/// hive base block の magic（"regf"）。
pub const REGF_MAGIC: [u8; 4] = *b"regf";

/// nk (key node) signature。
const NK_SIGNATURE: [u8; 2] = *b"nk";
/// vk (key value) signature。
const VK_SIGNATURE: [u8; 2] = *b"vk";
/// lf (fast leaf) signature。
const LF_SIGNATURE: [u8; 2] = *b"lf";
/// lh (hash leaf) signature。
const LH_SIGNATURE: [u8; 2] = *b"lh";
/// li (index leaf) signature。
const LI_SIGNATURE: [u8; 2] = *b"li";
/// ri (index root) signature。
const RI_SIGNATURE: [u8; 2] = *b"ri";

/// key の再帰 depth 上限。異常入力の stack overflow 防止。
pub const MAX_KEY_DEPTH: u32 = 512;
/// 1 hive あたりの key 数上限。異常入力からの無限 loop 回避。
pub const MAX_KEYS: u32 = 2_000_000;
/// 1 hive あたりの value 数上限。
pub const MAX_VALUES: u32 = 10_000_000;

/// hive の base block (regf header) から取り出した metadata。
#[derive(Clone, Debug)]
pub struct HiveHeader {
    /// root cell offset（hive bins data 先頭からの相対 offset）。
    pub root_cell_offset: u32,
    /// hive bins data の size。
    pub hive_bins_data_size: u32,
    /// major version（通常 1）。
    pub major_version: u32,
    /// minor version（通常 3 または 5）。
    pub minor_version: u32,
    /// base block の checksum（offset 508 の u32）。
    pub stored_checksum: u32,
    /// base block から計算した checksum（offset 0..508 を u32 LE ぇ分割して XOR）。
    pub computed_checksum: u32,
}

impl HiveHeader {
    /// base block の checksum が一致するか。
    pub fn checksum_matches(&self) -> bool {
        self.stored_checksum == self.computed_checksum
    }
}

/// hive header の parse error。
#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    /// magic が "regf" ではない。
    #[error("magic が regf ではない")]
    MagicMismatch,
    /// base block size に満たない。
    #[error("base block が短かすぎる: {0} byte（{1} byte 必要）")]
    TooShort(usize, usize),
}

/// hive base block (4096 byte) を parse する。
pub fn parse_base_block(buf: &[u8]) -> Result<HiveHeader, HeaderError> {
    if buf.len() < BASE_BLOCK_BYTES {
        return Err(HeaderError::TooShort(buf.len(), BASE_BLOCK_BYTES));
    }
    if buf[0..4] != REGF_MAGIC {
        return Err(HeaderError::MagicMismatch);
    }
    let major_version = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let minor_version = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    let root_cell_offset = u32::from_le_bytes(buf[36..40].try_into().unwrap());
    let hive_bins_data_size = u32::from_le_bytes(buf[40..44].try_into().unwrap());
    let stored_checksum = u32::from_le_bytes(buf[508..512].try_into().unwrap());

    // checksum: 先頭 508 byte を 127 個の u32 LE へ分割して XOR。
    let mut computed: u32 = 0;
    for i in 0..127 {
        let off = i * 4;
        let v = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        computed ^= v;
    }

    Ok(HiveHeader {
        root_cell_offset,
        hive_bins_data_size,
        major_version,
        minor_version,
        stored_checksum,
        computed_checksum: computed,
    })
}

/// key node（nk cell）。
#[derive(Clone, Debug)]
pub struct KeyNode {
    /// この nk cell の先頭 offset（hive bins data 先頭からの相対）。
    pub cell_offset: u32,
    /// cell の size（byte・絶対値）。
    pub cell_size: u32,
    /// 最終書き込み時刻（FILETIME）。
    pub last_write_filetime: u64,
    /// 直下の subkey 数。
    pub subkey_count: u32,
    /// subkey list cell offset（hive bins data 先頭からの相対）。
    pub subkey_list_offset: u32,
    /// 直下の value 数。
    pub value_count: u32,
    /// value list cell offset。
    pub value_list_offset: u32,
    /// key 名（UTF-16LE → String 復元。UTF-16 error 時は lossy）。
    pub key_name: String,
}

/// key value（vk cell）。
#[derive(Clone, Debug)]
pub struct KeyValue {
    /// この vk cell の先頭 offset（hive bins data 先頭からの相対）。
    pub cell_offset: u32,
    /// cell の size（byte・絶対値）。
    pub cell_size: u32,
    /// value 名（UTF-16LE → String。名前無し value は空文字列）。
    pub value_name: String,
    /// data 型（REG_* 定数）。代表的な値は [`registry_value_type_name`] へよる。
    pub data_type: u32,
    /// data 本体（byte 列そのまま）。
    pub data: Vec<u8>,
}

/// hive 内の cell 種別の parse 失敗。
#[derive(Debug, thiserror::Error)]
pub enum CellError {
    /// cell が hive bins data の範囲外を指す。
    #[error("cell offset {0} が hive bins data 範囲外")]
    OutOfRange(u32),
    /// cell size が読取れない・負でない（空き cell）。
    #[error("cell offset {0} は空き cell または size 不正")]
    EmptyOrFree(u32),
    /// cell size が hive 範囲を超える。
    #[error("cell offset {0} の size {1} が大きすぎる")]
    SizeTooLarge(u32, u32),
    /// signature が不一致。
    #[error("cell offset {0} の signature が不一致: {1:?}")]
    BadSignature(u32, [u8; 2]),
    /// cell body が短かすぎる。
    #[error("cell offset {0} の body が短かすぎる: {1} byte")]
    Truncated(u32, usize),
}

/// hive bins data への access を提供する。
#[derive(Clone)]
pub struct HiveBins<'a> {
    data: &'a [u8],
}

impl<'a> HiveBins<'a> {
    /// base block を除いた hive bins data から構築。
    pub fn new(data: &'a [u8]) -> Self {
        HiveBins { data }
    }

    /// 全体の byte 長。
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 指定 offset の cell size（4 byte signed LE）を読む。
    /// 正の場合は空き cell なので None、負の場合は絶対値を返す。
    pub fn cell_size_at(&self, offset: u32) -> Option<u32> {
        let off = offset as usize;
        if off + 4 > self.data.len() {
            return None;
        }
        let raw = i32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
        if raw >= 0 {
            // 空き cell。使用中ではない。
            return None;
        }
        // 絶対値へ。size には size field 自身 (4 byte) を含む hive 実装と含まない実装がある。
        // 本 parser では「size field を含まない cell body の長さ」へ統一するため 4 引く。
        let abs = (-(raw as i64)) as u32;
        if abs < 4 {
            return None;
        }
        Some(abs - 4)
    }

    /// offset から `body_size` byte の cell body slice を取り出す。
    fn cell_body(&self, offset: u32, body_size: u32) -> Result<&'a [u8], CellError> {
        let start = offset as usize;
        if start + 4 > self.data.len() {
            return Err(CellError::OutOfRange(offset));
        }
        let end = start + 4 + body_size as usize;
        if end > self.data.len() {
            return Err(CellError::Truncated(offset, self.data.len() - start - 4));
        }
        Ok(&self.data[start + 4..end])
    }

    /// nk cell を parse。
    pub fn parse_key_node(&self, offset: u32) -> Result<KeyNode, CellError> {
        let size = self
            .cell_size_at(offset)
            .ok_or(CellError::EmptyOrFree(offset))?;
        // nk 最小要件: signature(2) + timestamp(8) + ... + name_length(2) = 76 byte。
        // これを下回る場合は明らかに不正。
        let min_body = 76;
        let body_size = size.min(min_body as u32);
        let body = self.cell_body(offset, body_size)?;
        if body.len() < min_body {
            return Err(CellError::Truncated(offset, body.len()));
        }
        if body[0..2] != NK_SIGNATURE {
            return Err(CellError::BadSignature(offset, [body[0], body[1]]));
        }
        let last_write_filetime = u64::from_le_bytes(body[2..10].try_into().unwrap());
        let subkey_count = u32::from_le_bytes(body[18..22].try_into().unwrap());
        let subkey_list_offset = u32::from_le_bytes(body[22..26].try_into().unwrap());
        let value_count = u32::from_le_bytes(body[28..32].try_into().unwrap());
        let value_list_offset = u32::from_le_bytes(body[32..36].try_into().unwrap());
        let key_name_length = u16::from_le_bytes(body[68..70].try_into().unwrap()) as u32;

        // 名前は body の続きから読む。先頭 min_body byte の直後 (offset + 4 + 70) に続く。
        // name_length field が body offset 68..70 にあるため、name 本体は 70 から。
        let name_abs_start = offset as usize + 4 + 70;
        let name_abs_end = name_abs_start + key_name_length as usize;
        let key_name = if name_abs_end <= self.data.len() {
            decode_utf16le_lossy(&self.data[name_abs_start..name_abs_end])
        } else {
            // 切れている分だけ取り出す。
            let avail = self.data.len().saturating_sub(name_abs_start);
            decode_utf16le_lossy(&self.data[name_abs_start..name_abs_start + avail])
        };

        Ok(KeyNode {
            cell_offset: offset,
            cell_size: size,
            last_write_filetime,
            subkey_count,
            subkey_list_offset,
            value_count,
            value_list_offset,
            key_name,
        })
    }

    /// vk cell を parse。
    pub fn parse_key_value(&self, offset: u32) -> Result<KeyValue, CellError> {
        let size = self
            .cell_size_at(offset)
            .ok_or(CellError::EmptyOrFree(offset))?;
        // vk 最小要件: signature(2) + name_len(2) + data_size(4) + data_offset(4) + type(4) + flags(2) + spare(2) = 20 byte。
        let min_body = 20;
        let body_size = size.min(min_body as u32);
        let body = self.cell_body(offset, body_size)?;
        if body.len() < min_body {
            return Err(CellError::Truncated(offset, body.len()));
        }
        if body[0..2] != VK_SIGNATURE {
            return Err(CellError::BadSignature(offset, [body[0], body[1]]));
        }
        let value_name_length = u16::from_le_bytes(body[2..4].try_into().unwrap()) as u32;
        let data_size_raw = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let data_offset_raw = u32::from_le_bytes(body[8..12].try_into().unwrap());
        let data_type = u32::from_le_bytes(body[12..16].try_into().unwrap());
        let flags = u16::from_le_bytes(body[16..18].try_into().unwrap());

        // value name の取り出し（flags bit0 = ASCII、それ以外は UTF-16LE）。
        let name_abs_start = offset as usize + 4 + 20;
        let name_abs_end = name_abs_start + value_name_length as usize;
        let value_name = if name_abs_end <= self.data.len() {
            let name_bytes = &self.data[name_abs_start..name_abs_end];
            if flags & 0x0001 != 0 {
                // ASCII (Latin-1 扱いで安全へ復元)。
                name_bytes.iter().map(|b| *b as char).collect::<String>()
            } else {
                decode_utf16le_lossy(name_bytes)
            }
        } else {
            String::new()
        };

        // data の取り出し。data_size の MSB が set なら inline (data_offset field 内)。
        let data = if data_size_raw & 0x8000_0000 != 0 {
            // inline: data_offset の 4 byte がそのまま data。
            // size は下位 31 bit。本実装では最大 16344 byte だが、実際は 4 byte に切り詰め。
            let inline_size = (data_size_raw & 0x7FFF_FFFF) as usize;
            let bytes = data_offset_raw.to_le_bytes();
            bytes[..inline_size.min(4)].to_vec()
        } else {
            // 外部 cell: data_offset は cell 先頭（size field 含む）を指す。
            // cell body は +4 した位置から始まる。
            let data_cell_offset = data_offset_raw;
            let data_len = data_size_raw as usize;
            let abs_body_start = (data_cell_offset as usize).saturating_add(4);
            let abs_end = abs_body_start.saturating_add(data_len);
            if abs_end <= self.data.len() {
                self.data[abs_body_start..abs_end].to_vec()
            } else {
                // 範囲外: 取れる分だけ。
                let body_end = self.data.len();
                if abs_body_start < body_end {
                    self.data[abs_body_start..body_end].to_vec()
                } else {
                    Vec::new()
                }
            }
        };

        Ok(KeyValue {
            cell_offset: offset,
            cell_size: size,
            value_name,
            data_type,
            data,
        })
    }

    /// value list（連続する vk_offset の u32 配列）を列挙する。
    /// `count` 個の value を指す list を parse し、各 vk_offset を返す。
    pub fn value_list_offsets(&self, list_offset: u32, count: u32) -> Vec<u32> {
        let mut out = Vec::with_capacity(count as usize);
        let count = count.min(MAX_VALUES);
        let base = list_offset as usize;
        // value list cell にも size field がある前提で +4 する。
        let start = base.saturating_add(4);
        for i in 0..count as usize {
            let off = start + i * 4;
            if off + 4 > self.data.len() {
                break;
            }
            let vk_off = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
            out.push(vk_off);
        }
        out
    }

    /// subkey list を parse し、全 subkey の nk offset を列挙する。
    /// `ri` は再帰的に結合する。
    pub fn subkey_offsets(&self, list_offset: u32, visited: &mut HashSet<u32>) -> Vec<u32> {
        let mut out = Vec::new();
        self.collect_subkey_offsets(list_offset, &mut out, visited);
        out
    }

    fn collect_subkey_offsets(
        &self,
        list_offset: u32,
        out: &mut Vec<u32>,
        visited: &mut HashSet<u32>,
    ) {
        if !visited.insert(list_offset) {
            // 循環参照防止。
            return;
        }
        let start = list_offset as usize;
        // size field(4) + signature(2) + count(2) = 最低 8 byte。
        if start + 8 > self.data.len() {
            return;
        }
        let sig = [self.data[start + 4], self.data[start + 5]];
        let count = u16::from_le_bytes(self.data[start + 6..start + 8].try_into().unwrap()) as u32;

        match sig {
            LF_SIGNATURE | LH_SIGNATURE => {
                // 各 entry: nk_offset(4) + hint(4) = 8 byte。
                let entries_start = start + 8;
                for i in 0..count as usize {
                    let off = entries_start + i * 8;
                    if off + 4 > self.data.len() {
                        break;
                    }
                    let nk_off = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                    out.push(nk_off);
                }
            }
            LI_SIGNATURE => {
                // 各 entry: nk_offset(4) のみ。
                let entries_start = start + 8;
                for i in 0..count as usize {
                    let off = entries_start + i * 4;
                    if off + 4 > self.data.len() {
                        break;
                    }
                    let nk_off = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                    out.push(nk_off);
                }
            }
            RI_SIGNATURE => {
                // 各 entry: subkey_list_offset(4)。再帰的に結合。
                let entries_start = start + 8;
                for i in 0..count as usize {
                    let off = entries_start + i * 4;
                    if off + 4 > self.data.len() {
                        break;
                    }
                    let child = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                    self.collect_subkey_offsets(child, out, visited);
                }
            }
            _ => {
                // 不正 signature は無視。呼出側で件数が合わなければ Issue 化される。
            }
        }
    }
}

/// UTF-16LE byte 列を String へ復元（UTF-16 surrogate error 時は lossy）。
pub fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// REG_* data 型の代表値を人間可読な文字列へ。
pub fn registry_value_type_name(data_type: u32) -> &'static str {
    match data_type {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cell(buf: &mut [u8], offset: usize, size: u32, body: &[u8]) {
        // size field: 負値（使用中）。絶対値は size + 4（field 自身を含むhive 形式へ揃える）。
        let size_field: i32 = -((size as i32) + 4);
        buf[offset..offset + 4].copy_from_slice(&size_field.to_le_bytes());
        // body は size の範囲で copy（余白はそのまま 0）。
        let body_end = (offset + 4 + body.len()).min(offset + 4 + size as usize);
        buf[offset + 4..body_end].copy_from_slice(&body[..body_end - offset - 4]);
    }

    fn make_nk_body(name: &str, last_write: u64, subkey_count: u32, value_count: u32) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        // nk 最小部 70 byte (68 + name_length field 2) + name 本体。
        let mut body = vec![0u8; 70 + name_bytes.len()];
        body[0..2].copy_from_slice(&NK_SIGNATURE);
        body[2..10].copy_from_slice(&last_write.to_le_bytes());
        body[18..22].copy_from_slice(&subkey_count.to_le_bytes());
        // subkey_list_offset は後で設定するため 0 のまま
        body[28..32].copy_from_slice(&value_count.to_le_bytes());
        // value_list_offset も後で設定
        let name_len = name_bytes.len() as u16;
        body[68..70].copy_from_slice(&name_len.to_le_bytes());
        body[70..70 + name_bytes.len()].copy_from_slice(&name_bytes);
        body
    }

    #[test]
    fn parse_base_block_valid() {
        let mut buf = vec![0u8; BASE_BLOCK_BYTES];
        buf[0..4].copy_from_slice(&REGF_MAGIC);
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // major
        buf[24..28].copy_from_slice(&3u32.to_le_bytes()); // minor
        buf[36..40].copy_from_slice(&0x1000u32.to_le_bytes()); // root cell offset
        buf[40..44].copy_from_slice(&0x10000u32.to_le_bytes()); // bins size
        // checksum 計算: 先頭 508 byte を u32 で XOR。
        let mut cksum: u32 = 0;
        for i in 0..127 {
            let off = i * 4;
            let v = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            cksum ^= v;
        }
        buf[508..512].copy_from_slice(&cksum.to_le_bytes());

        let header = parse_base_block(&buf).unwrap();
        assert_eq!(header.major_version, 1);
        assert_eq!(header.minor_version, 3);
        assert_eq!(header.root_cell_offset, 0x1000);
        assert!(header.checksum_matches());
    }

    #[test]
    fn parse_base_block_rejects_bad_magic() {
        let mut buf = vec![0u8; BASE_BLOCK_BYTES];
        buf[0..4].copy_from_slice(b"xxxx");
        let err = parse_base_block(&buf).unwrap_err();
        assert!(matches!(err, HeaderError::MagicMismatch));
    }

    #[test]
    fn parse_base_block_rejects_short() {
        let buf = vec![0u8; 100];
        let err = parse_base_block(&buf).unwrap_err();
        assert!(matches!(err, HeaderError::TooShort(100, BASE_BLOCK_BYTES)));
    }

    #[test]
    fn cell_size_at_handles_free_cell() {
        let mut buf = vec![0u8; 32];
        // 空き cell: size = +100。
        buf[0..4].copy_from_slice(&100i32.to_le_bytes());
        let bins = HiveBins::new(&buf);
        assert!(bins.cell_size_at(0).is_none());
    }

    #[test]
    fn cell_size_at_used_cell() {
        let mut buf = vec![0u8; 32];
        // 使用中: size = -80 → abs 80 → 80 - 4 = 76。
        buf[0..4].copy_from_slice(&(-80i32).to_le_bytes());
        let bins = HiveBins::new(&buf);
        assert_eq!(bins.cell_size_at(0), Some(76));
    }

    #[test]
    fn parse_key_node_basic() {
        // hive bins: offset 0 に nk cell を置く。
        let mut bins_buf = vec![0u8; 256];
        let body = make_nk_body("SOFTWARE", 132_548_480_000_000_000, 0, 0);
        write_cell(&mut bins_buf, 0, body.len() as u32, &body);
        let bins = HiveBins::new(&bins_buf);
        let nk = bins.parse_key_node(0).unwrap();
        assert_eq!(nk.key_name, "SOFTWARE");
        assert_eq!(nk.last_write_filetime, 132_548_480_000_000_000);
        assert_eq!(nk.subkey_count, 0);
    }

    #[test]
    fn parse_key_node_rejects_bad_sig() {
        let mut bins_buf = vec![0u8; 256];
        let mut body = vec![0u8; 76];
        body[0..2].copy_from_slice(b"xx");
        write_cell(&mut bins_buf, 0, body.len() as u32, &body);
        let bins = HiveBins::new(&bins_buf);
        let err = bins.parse_key_node(0).unwrap_err();
        assert!(matches!(err, CellError::BadSignature(0, _)));
    }

    #[test]
    fn subkey_offsets_lf_list() {
        // root nk + lf subkey list + 2個の child nk。
        let mut bins_buf = vec![0u8; 1024];

        // root nk at 0
        let mut root_body = make_nk_body("ROOT", 0, 2, 0);
        root_body[22..26].copy_from_slice(&0x100u32.to_le_bytes()); // subkey_list_offset
        write_cell(&mut bins_buf, 0, root_body.len() as u32, &root_body);

        // lf list at 0x100
        let mut lf_body = vec![0u8; 8 + 16];
        lf_body[0..2].copy_from_slice(&LF_SIGNATURE);
        lf_body[2..4].copy_from_slice(&2u16.to_le_bytes()); // count
        // entry0: nk_offset=0x200, hint=0
        lf_body[4..8].copy_from_slice(&0x200u32.to_le_bytes());
        // entry1: nk_offset=0x300, hint=0
        lf_body[12..16].copy_from_slice(&0x300u32.to_le_bytes());
        write_cell(&mut bins_buf, 0x100, lf_body.len() as u32, &lf_body);

        // children nk at 0x200, 0x300
        let c1 = make_nk_body("Child1", 0, 0, 0);
        write_cell(&mut bins_buf, 0x200, c1.len() as u32, &c1);
        let c2 = make_nk_body("Child2", 0, 0, 0);
        write_cell(&mut bins_buf, 0x300, c2.len() as u32, &c2);

        let bins = HiveBins::new(&bins_buf);
        let mut visited = HashSet::new();
        let offsets = bins.subkey_offsets(0x100, &mut visited);
        assert_eq!(offsets, vec![0x200, 0x300]);
    }

    #[test]
    fn subkey_offsets_ri_recursive() {
        let mut bins_buf = vec![0u8; 8192];

        // ri list at 0x1000 → 2個の lf list へ参照
        let mut ri_body = vec![0u8; 8 + 8];
        ri_body[0..2].copy_from_slice(&RI_SIGNATURE);
        ri_body[2..4].copy_from_slice(&2u16.to_le_bytes());
        ri_body[4..8].copy_from_slice(&0x200u32.to_le_bytes());
        ri_body[8..12].copy_from_slice(&0x400u32.to_le_bytes());
        write_cell(&mut bins_buf, 0x1000, ri_body.len() as u32, &ri_body);

        // lf at 0x200 → 1個の nk
        let mut lf1 = vec![0u8; 8 + 8];
        lf1[0..2].copy_from_slice(&LF_SIGNATURE);
        lf1[2..4].copy_from_slice(&1u16.to_le_bytes());
        lf1[4..8].copy_from_slice(&0x600u32.to_le_bytes());
        write_cell(&mut bins_buf, 0x200, lf1.len() as u32, &lf1);

        // lf at 0x400 → 1個の nk
        let mut lf2 = vec![0u8; 8 + 8];
        lf2[0..2].copy_from_slice(&LF_SIGNATURE);
        lf2[2..4].copy_from_slice(&1u16.to_le_bytes());
        lf2[4..8].copy_from_slice(&0x800u32.to_le_bytes());
        write_cell(&mut bins_buf, 0x400, lf2.len() as u32, &lf2);

        let bins = HiveBins::new(&bins_buf);
        let mut visited = HashSet::new();
        let offsets = bins.subkey_offsets(0x1000, &mut visited);
        assert_eq!(offsets, vec![0x600, 0x800]);
    }

    #[test]
    fn subkey_offsets_prevents_cycle() {
        // ri → ri（自分自身）。循環を検出して空になる。
        let mut bins_buf = vec![0u8; 256];
        let mut ri_body = vec![0u8; 8 + 4];
        ri_body[0..2].copy_from_slice(&RI_SIGNATURE);
        ri_body[2..4].copy_from_slice(&1u16.to_le_bytes());
        ri_body[4..8].copy_from_slice(&0x0u32.to_le_bytes()); // 自分自身（0 は size field と衝突するので別位置）
        write_cell(&mut bins_buf, 0x10, ri_body.len() as u32, &ri_body);
        // entry が自分自身（0x10）を指すように上書き。
        bins_buf[0x10 + 4 + 4..0x10 + 4 + 8].copy_from_slice(&0x10u32.to_le_bytes());

        let bins = HiveBins::new(&bins_buf);
        let mut visited = HashSet::new();
        let offsets = bins.subkey_offsets(0x10, &mut visited);
        // 循環検出で2回目は空。1件だけ（0x10 自体が挿入されるが、それ以上は進まない）。
        assert!(offsets.len() <= 1);
    }

    #[test]
    fn parse_key_value_with_inline_data() {
        let mut bins_buf = vec![0u8; 256];
        // vk with data_size = 0x80000004 (inline 4 byte), data_offset = 0xDEADBEEF
        let mut body = vec![0u8; 20];
        body[0..2].copy_from_slice(&VK_SIGNATURE);
        body[2..4].copy_from_slice(&0u16.to_le_bytes()); // 名前無し
        body[4..8].copy_from_slice(&0x8000_0004u32.to_le_bytes()); // inline 4 byte
        body[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // data_offset に data 本体
        body[12..16].copy_from_slice(&4u32.to_le_bytes()); // REG_DWORD
        write_cell(&mut bins_buf, 0, body.len() as u32, &body);

        let bins = HiveBins::new(&bins_buf);
        let vk = bins.parse_key_value(0).unwrap();
        assert_eq!(vk.value_name, "");
        assert_eq!(vk.data_type, 4);
        assert_eq!(vk.data, vec![0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn parse_key_value_with_external_data() {
        let mut bins_buf = vec![0u8; 256];
        // vk at 0, data cell at 0x40
        // vk body は 20 byte 固定部 + value_name 分（ここでは "AB" UTF-16LE で 4 byte）。
        let mut body = vec![0u8; 20 + 4];
        body[0..2].copy_from_slice(&VK_SIGNATURE);
        body[2..4].copy_from_slice(&4u16.to_le_bytes()); // "AB" UTF-16LE で 4 byte
        body[4..8].copy_from_slice(&8u32.to_le_bytes()); // data_size = 8
        body[8..12].copy_from_slice(&0x40u32.to_le_bytes()); // data_offset
        body[12..16].copy_from_slice(&3u32.to_le_bytes()); // REG_BINARY
        // "AB" UTF-16LE
        body[20..24].copy_from_slice(&[0x41, 0x00, 0x42, 0x00]);
        write_cell(&mut bins_buf, 0, body.len() as u32, &body);

        // data cell at 0x40 (8 byte の data)
        let data_bytes: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        write_cell(&mut bins_buf, 0x40, data_bytes.len() as u32, &data_bytes);

        let bins = HiveBins::new(&bins_buf);
        let vk = bins.parse_key_value(0).unwrap();
        assert_eq!(vk.value_name, "AB");
        assert_eq!(vk.data_type, 3);
        // data cell の body が読める。
        assert!(!vk.data.is_empty());
    }

    #[test]
    fn value_type_names() {
        assert_eq!(registry_value_type_name(1), "REG_SZ");
        assert_eq!(registry_value_type_name(4), "REG_DWORD");
        assert_eq!(registry_value_type_name(11), "REG_QWORD");
        assert_eq!(registry_value_type_name(99), "REG_UNKNOWN");
    }

    #[test]
    fn utf16le_decode_lossy() {
        let bytes: Vec<u8> = vec![0x41, 0x00, 0x42, 0x00]; // "AB"
        assert_eq!(decode_utf16le_lossy(&bytes), "AB");
        // 奇数 byte は最後の1 byte が無視される。
        let bytes2: Vec<u8> = vec![0x41, 0x00, 0x42];
        assert_eq!(decode_utf16le_lossy(&bytes2), "A");
    }
}
