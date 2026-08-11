//! Compound File Binary (CFB) container parser の最小実装（[MS-CFB]、互換 §4.5・T4-070）。
//!
//! AutomaticDestinations-ms file は CFB 形式の container で、内部へ複数の stream を保持する。
//! 各 stream は1つの内包 LNK file、または `DestList` と呼ばれる Jump List metadata となる。
//!
//! ## 本実装の範囲
//!
//! - CFB header（512 byte）の解析・version 3 (sector size 512) と version 4 (sector size 4096) 両対応
//! - DIFAT chain（header 内 109 entry + 追加 DIFAT sector）
//! - FAT chain（FAT sector 群から全 FAT entry を構築）
//! - Directory entry chain（4 sector あたり 1 entry × 4 で 32 entry / sector... 実際は 128 byte × N）
//! - MiniFAT chain（mini stream cutoff 未満の小 stream を 64 byte 単位で格納）
//! - 各 stream の byte 列を取り出し（通常 stream は FAT 経由、mini stream は root entry 配下）
//!
//! ## 安全性
//!
//! - いかなる破損入力でも panic しない（規範 §9.4・互換 §12-2）
//! - sector 番号の循環参照は検出した時点で打ち切り
//! - 巨大 sector 数からの過大 memory 確保を防ぐため、FAT entry 数上限を設ける

use std::collections::HashSet;

/// CFB signature（[MS-CFB] §2.2: 先頭 8 byte 固定）。
pub const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// CFB header の byte 長（[MS-CFB] §2.2）。
pub const CFB_HEADER_BYTES: usize = 512;

/// DIFAT 配列の header 内 entry 数（[MS-CFB] §2.2: 109 個固定）。
const DIFAT_HEADER_ENTRIES: usize = 109;

/// FAT chain の特殊値（[MS-CFB] §2.2: SAT sector 値）。
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// FAT sector 自身を表す特殊値（[MS-CFB] §2.2）。本 parser では特に分岐させず読み飛ばす。
#[allow(dead_code)]
const FATSECT: u32 = 0xFFFF_FFFD;
/// DIFAT sector を表す特殊値（[MS-CFB] §2.2）。本 parser では特に分岐させず読み飛ばす。
#[allow(dead_code)]
const DIFSECT: u32 = 0xFFFF_FFFC;
const FREESECT: u32 = 0xFFFF_FFFF;

/// Directory entry の byte 長（[MS-CFB] §2.6.1: 128 byte 固定）。
const DIR_ENTRY_BYTES: usize = 128;

/// object type: stream（[MS-CFB] §2.6.1）。
const OBJECT_TYPE_STREAM: u8 = 2;
/// object type: root storage（[MS-CFB] §2.6.1）。
const OBJECT_TYPE_ROOT: u8 = 5;

/// FAT entry 数の安全上限（異常入力からの過大 memory 確保防止）。
/// 1 GiB / 512 byte = 2,097,152 sector。10 倍の余裕を見る。
const MAX_FAT_ENTRIES: usize = 25_000_000;

/// CFB 解析の error（規範 §9.2: 破損時は panic しない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfbError {
    /// snapshot が header に満たない。
    TooShort(usize),
    /// CFB signature が一致しない（この形式ではない）。
    SignatureMismatch,
    /// sector size power が異常（9也未満等）。
    InvalidSectorSize(u16),
    /// FAT chain が循環・範囲外等で構築できない。
    FatChainError(String),
    /// directory chain が破損。
    DirectoryChainError(String),
}

impl std::fmt::Display for CfbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CfbError::TooShort(n) => write!(
                f,
                "snapshot が CFB header ({CFB_HEADER_BYTES}) に満たない: {n} byte"
            ),
            CfbError::SignatureMismatch => write!(f, "CFB signature が一致しない"),
            CfbError::InvalidSectorSize(p) => {
                write!(f, "CFB sector size power が異常: {p}")
            }
            CfbError::FatChainError(m) => write!(f, "CFB FAT chain 構築失敗: {m}"),
            CfbError::DirectoryChainError(m) => {
                write!(f, "CFB directory chain 破損: {m}")
            }
        }
    }
}

impl std::error::Error for CfbError {}

/// CFB header（512 byte）から取り出した metadata。
#[derive(Clone, Debug)]
struct CfbHeader {
    /// sector size（byte）。通常 512 (v3) または 4096 (v4)。
    sector_size: usize,
    /// mini sector size（byte）。通常 64。
    mini_sector_size: usize,
    /// mini stream cutoff（byte）。これ未満の size の stream は mini stream へ格納。
    mini_cutoff: u64,
    /// first directory sector location。
    first_dir_sector: u32,
    /// first mini FAT sector location。
    first_mini_fat_sector: u32,
    /// first DIFAT sector location（追加 DIFAT sector）。
    first_difat_sector: u32,
    /// DIFAT 配列（header 内 109 entry + 追加 sector 分）。
    difat: Vec<u32>,
}

/// directory entry（[MS-CFB] §2.6.1: 128 byte）。
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// entry 名（UTF-16LE から復元・null 終端は除去）。
    pub name: String,
    /// object type（0=unknown, 1=storage, 2=stream, 5=root）。
    pub object_type: u8,
    /// starting sector location。
    pub starting_sector: u32,
    /// stream size（byte）。root entry の場合は mini stream 全体の size。
    pub stream_size: u64,
}

/// 取り出された stream（名前・内容・開始 byte offset の目安）。
#[derive(Clone, Debug)]
pub struct CfbStream {
    /// stream 名（directory entry の name）。
    pub name: String,
    /// object type（通常 2 = stream）。
    pub object_type: u8,
    /// stream の byte 列。
    pub data: Vec<u8>,
    /// starting sector（debug / Provenance 記録用）。
    pub starting_sector: u32,
    /// 通常 stream の場合、file 先頭からの byte offset（最初の sector の先頭）。
    /// mini stream の場合は None（mini FAT 経由で分散しているため単一 offset 無し）。
    pub file_byte_offset: Option<u64>,
}

/// CFB container 全体の解析結果。
#[derive(Clone, Debug)]
pub struct CfbContainer {
    /// 取り出された stream 一覧（root entry を含まない）。
    pub streams: Vec<CfbStream>,
    /// root entry（mini stream 参照用）。
    pub root_entry: Option<DirEntry>,
}

/// snapshot bytes から CFB container を解析する。
pub fn parse_cfb(data: &[u8]) -> Result<CfbContainer, CfbError> {
    if data.len() < CFB_HEADER_BYTES {
        return Err(CfbError::TooShort(data.len()));
    }
    if data[0..8] != CFB_SIGNATURE {
        return Err(CfbError::SignatureMismatch);
    }

    let header = parse_header(data)?;

    // DIFAT を構築（header 内 109 entry + 追加 DIFAT sector chain）。
    let difat = build_difat(data, &header)?;

    // FAT を構築（DIFAT が指す FAT sector から全 entry を集める）。
    let fat = build_fat(data, &header, &difat)?;

    // directory chain を辿って directory entry 一覧を取得。
    let dir_entries = read_directory_entries(data, &header, &fat)?;

    // root entry を取り出す（mini stream の実体を指す）。
    let mut root_entry: Option<DirEntry> = None;
    for entry in &dir_entries {
        if entry.object_type == OBJECT_TYPE_ROOT {
            root_entry = Some(entry.clone());
            break;
        }
    }

    // mini FAT を構築（root entry が存在する場合）。
    let mini_fat = if root_entry.is_some() {
        build_mini_fat(data, &header, &fat)?
    } else {
        Vec::new()
    };
    // mini stream の実体（root entry が指す通常 stream chain）。
    let mini_stream_bytes: Vec<u8> = if let Some(root) = root_entry.as_ref() {
        read_chain_bytes(data, &header, &fat, root.starting_sector, root.stream_size)?
    } else {
        Vec::new()
    };

    // 各 stream の内容を取り出す。
    let mut streams = Vec::new();
    for entry in &dir_entries {
        if entry.object_type != OBJECT_TYPE_STREAM {
            continue;
        }
        let stream_bytes = if entry.stream_size < header.mini_cutoff {
            // mini stream から取り出す。
            read_mini_stream_bytes(
                &mini_stream_bytes,
                &header,
                &mini_fat,
                entry.starting_sector,
                entry.stream_size,
            )?
        } else {
            // 通常 FAT chain。
            read_chain_bytes(
                data,
                &header,
                &fat,
                entry.starting_sector,
                entry.stream_size,
            )?
        };

        // 通常 stream の場合は file 上の先頭 byte offset を計算。
        let file_byte_offset = if entry.stream_size >= header.mini_cutoff {
            sector_byte_offset(&header, entry.starting_sector)
        } else {
            None
        };

        streams.push(CfbStream {
            name: entry.name.clone(),
            object_type: entry.object_type,
            data: stream_bytes,
            starting_sector: entry.starting_sector,
            file_byte_offset,
        });
    }

    Ok(CfbContainer {
        streams,
        root_entry,
    })
}

/// CFB header（先頭 512 byte）を解析する。
fn parse_header(data: &[u8]) -> Result<CfbHeader, CfbError> {
    // sector size power（u16 LE）。
    let sector_shift = u16::from_le_bytes([data[30], data[31]]);
    if !(9..=12).contains(&sector_shift) {
        return Err(CfbError::InvalidSectorSize(sector_shift));
    }
    let sector_size = 1usize << sector_shift;

    // mini sector size power。
    let mini_sector_shift = u16::from_le_bytes([data[32], data[33]]);
    if mini_sector_shift > sector_shift || mini_sector_shift < 6 {
        return Err(CfbError::InvalidSectorSize(mini_sector_shift));
    }
    let mini_sector_size = 1usize << mini_sector_shift;

    // first directory sector。
    let first_dir_sector = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
    // mini stream cutoff。
    let mini_cutoff = u32::from_le_bytes([data[56], data[57], data[58], data[59]]) as u64;
    // first mini FAT sector。
    let first_mini_fat_sector = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
    // first DIFAT sector（追加 chain 用）。
    let first_difat_sector = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);

    // header 内 109 個の DIFAT entry。
    let mut difat = Vec::with_capacity(DIFAT_HEADER_ENTRIES);
    for i in 0..DIFAT_HEADER_ENTRIES {
        let off = 76 + i * 4;
        difat.push(u32::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
        ]));
    }

    Ok(CfbHeader {
        sector_size,
        mini_sector_size,
        mini_cutoff: if mini_cutoff == 0 { 4096 } else { mini_cutoff },
        first_dir_sector,
        first_mini_fat_sector,
        first_difat_sector,
        difat,
    })
}

/// DIFAT 配列を構築する（header 内 109 entry + 追加 DIFAT sector chain）。
fn build_difat(data: &[u8], header: &CfbHeader) -> Result<Vec<u32>, CfbError> {
    let mut difat = header.difat.clone();
    let mut visited: HashSet<u32> = HashSet::new();

    let mut next_difat_sector = header.first_difat_sector;
    let entries_per_sector = header.sector_size / 4;

    while next_difat_sector != ENDOFCHAIN
        && next_difat_sector != FREESECT
        && next_difat_sector < total_sectors(data, header)
    {
        // 循環参照防止。
        if !visited.insert(next_difat_sector) {
            break;
        }
        let sector_off = sector_byte_offset(header, next_difat_sector)
            .ok_or_else(|| CfbError::FatChainError("DIFAT sector の offset 異常".to_string()))?;
        let sector_end = sector_off as usize + header.sector_size;
        if sector_end > data.len() {
            break;
        }
        // 末尾の 4 byte は次の DIFAT sector への link。
        for i in 0..(entries_per_sector.saturating_sub(1)) {
            let off = sector_off as usize + i * 4;
            let v = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if v != FREESECT && v != ENDOFCHAIN {
                difat.push(v);
            }
        }
        let link_off = sector_off as usize + (entries_per_sector - 1) * 4;
        next_difat_sector = u32::from_le_bytes([
            data[link_off],
            data[link_off + 1],
            data[link_off + 2],
            data[link_off + 3],
        ]);
    }

    // 安全上限。
    if difat.len() > MAX_FAT_ENTRIES {
        difat.truncate(MAX_FAT_ENTRIES);
    }
    Ok(difat)
}

/// FAT 配列を構築する（DIFAT が指す FAT sector から全 entry を集める）。
fn build_fat(data: &[u8], header: &CfbHeader, difat: &[u32]) -> Result<Vec<u32>, CfbError> {
    let entries_per_sector = header.sector_size / 4;
    let mut fat = Vec::with_capacity(difat.len() * entries_per_sector);

    for &fat_sector in difat {
        if fat_sector == FREESECT || fat_sector == ENDOFCHAIN {
            continue;
        }
        let total = total_sectors(data, header);
        if fat_sector >= total {
            // 範囲外の FAT sector 指定。打ち切り。
            break;
        }
        let sector_off = sector_byte_offset(header, fat_sector)
            .ok_or_else(|| CfbError::FatChainError("FAT sector の offset 異常".to_string()))?;
        let sector_end = sector_off as usize + header.sector_size;
        if sector_end > data.len() {
            break;
        }
        for i in 0..entries_per_sector {
            let off = sector_off as usize + i * 4;
            fat.push(u32::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]));
        }
        if fat.len() > MAX_FAT_ENTRIES {
            return Err(CfbError::FatChainError(format!(
                "FAT entry 数が上限 ({MAX_FAT_ENTRIES}) を超えた"
            )));
        }
    }
    Ok(fat)
}

/// mini FAT 配列を構築する。
fn build_mini_fat(data: &[u8], header: &CfbHeader, fat: &[u32]) -> Result<Vec<u32>, CfbError> {
    let entries_per_sector = header.sector_size / 4;
    let mut mini_fat = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();

    let mut next = header.first_mini_fat_sector;
    while next != ENDOFCHAIN && next != FREESECT {
        // 循環参照防止。
        if !visited.insert(next) {
            break;
        }
        if (next as usize) >= fat.len() {
            break;
        }
        let sector_off = sector_byte_offset(header, next)
            .ok_or_else(|| CfbError::FatChainError("mini FAT sector の offset 異常".to_string()))?;
        let sector_end = sector_off as usize + header.sector_size;
        if sector_end > data.len() {
            break;
        }
        for i in 0..entries_per_sector {
            let off = sector_off as usize + i * 4;
            mini_fat.push(u32::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]));
        }
        if (next as usize) < fat.len() {
            next = fat[next as usize];
        } else {
            break;
        }
    }
    Ok(mini_fat)
}

/// directory chain を辿って directory entry 一覧を取得する。
fn read_directory_entries(
    data: &[u8],
    header: &CfbHeader,
    fat: &[u32],
) -> Result<Vec<DirEntry>, CfbError> {
    // directory chain 全体の byte 列を取り出す。
    let dir_bytes = read_chain_bytes(data, header, fat, header.first_dir_sector, u64::MAX)?;
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset + DIR_ENTRY_BYTES <= dir_bytes.len() {
        let entry = parse_dir_entry(&dir_bytes[offset..offset + DIR_ENTRY_BYTES]);
        if entry.object_type != 0 {
            entries.push(entry);
        }
        offset += DIR_ENTRY_BYTES;
    }
    Ok(entries)
}

/// directory entry（128 byte）を解析する。
fn parse_dir_entry(bytes: &[u8]) -> DirEntry {
    // name length（u16 LE・byte 数・null 終端含む）。
    let name_len_bytes = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let object_type = bytes[2];

    // name は UTF-16LE（最大 64 byte = 32 UTF-16 code unit）。
    let name_len_utf16 = if name_len_bytes > 0 {
        (name_len_bytes / 2).saturating_sub(1).min(32)
    } else {
        0
    };
    let mut name_units = Vec::with_capacity(name_len_utf16);
    for i in 0..name_len_utf16 {
        let off = 4 + i * 2;
        if off + 2 > bytes.len() {
            break;
        }
        let unit = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
        if unit == 0 {
            break;
        }
        name_units.push(unit);
    }
    let name = String::from_utf16_lossy(&name_units);

    // starting sector location（offset 52-56）。
    let starting_sector = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]);
    // stream size（low 32 bit + high 32 bit）。
    let size_low = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]) as u64;
    let size_high = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as u64;
    let stream_size = (size_high << 32) | size_low;

    DirEntry {
        name,
        object_type,
        starting_sector,
        stream_size,
    }
}

/// FAT chain を辿って stream の byte 列を取り出す。
///
/// `max_bytes` は取り出す上限。`u64::MAX` なら chain が尽きるまで。
fn read_chain_bytes(
    data: &[u8],
    header: &CfbHeader,
    fat: &[u32],
    start_sector: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, CfbError> {
    let mut out = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut current = start_sector;
    let total = total_sectors(data, header);

    while current != ENDOFCHAIN && current != FREESECT {
        // 循環参照検出。
        if !visited.insert(current) {
            break;
        }
        if (current as usize) >= fat.len() {
            break;
        }
        if current >= total {
            break;
        }
        let Some(sector_off) = sector_byte_offset(header, current) else {
            break;
        };
        let sector_end = sector_off as usize + header.sector_size;
        if sector_end > data.len() {
            // truncated sector。
            let take = data.len().saturating_sub(sector_off as usize);
            if take > 0 {
                out.extend_from_slice(&data[sector_off as usize..sector_off as usize + take]);
            }
            break;
        }
        out.extend_from_slice(&data[sector_off as usize..sector_end]);
        if (out.len() as u64) >= max_bytes {
            out.truncate(max_bytes as usize);
            break;
        }
        current = fat[current as usize];
    }
    Ok(out)
}

/// mini stream から stream の byte 列を取り出す。
fn read_mini_stream_bytes(
    mini_stream: &[u8],
    header: &CfbHeader,
    mini_fat: &[u32],
    start_mini_sector: u32,
    stream_size: u64,
) -> Result<Vec<u8>, CfbError> {
    let mut out = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut current = start_mini_sector;
    let mini_sector_size = header.mini_sector_size;

    while current != ENDOFCHAIN && current != FREESECT {
        if !visited.insert(current) {
            break;
        }
        if (current as usize) >= mini_fat.len() {
            break;
        }
        let off = (current as usize) * mini_sector_size;
        if off >= mini_stream.len() {
            break;
        }
        let end = (off + mini_sector_size).min(mini_stream.len());
        out.extend_from_slice(&mini_stream[off..end]);
        if (out.len() as u64) >= stream_size {
            out.truncate(stream_size as usize);
            break;
        }
        current = mini_fat[current as usize];
    }
    // size で切り詰め（mini sector 境界で余分に読んだ分を除去）。
    if (out.len() as u64) > stream_size {
        out.truncate(stream_size as usize);
    }
    Ok(out)
}

/// sector 番号から file 先頭の byte offset を計算する。
///
/// sector 0 は header (512 byte) の直後から開始する。
fn sector_byte_offset(header: &CfbHeader, sector: u32) -> Option<u64> {
    let header_size = CFB_HEADER_BYTES as u64;
    Some(header_size + (sector as u64) * (header.sector_size as u64))
}

/// snapshot 全体から取り得る sector 数の上限を返す。
fn total_sectors(data: &[u8], header: &CfbHeader) -> u32 {
    let available = (data.len() as u64).saturating_sub(CFB_HEADER_BYTES as u64);
    ((available / (header.sector_size as u64)) as u32).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// sector size 512 の最小 CFB container を構築する。
    fn build_minimal_cfb() -> Vec<u8> {
        let sector_size: usize = 512;
        let mut buf = vec![0u8; 2048];

        // header
        buf[0..8].copy_from_slice(&CFB_SIGNATURE);
        buf[30..32].copy_from_slice(&9u16.to_le_bytes()); // sector_shift = 9 (512)
        buf[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini_shift = 6 (64)
        buf[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini_cutoff
        // FAT sector 0 を指す DIFAT[0]
        buf[76..80].copy_from_slice(&0u32.to_le_bytes()); // FAT at sector 0
        // directory を sector 1 へ。
        buf[48..52].copy_from_slice(&1u32.to_le_bytes());

        // sector 0: FAT。sector 1 (directory) → ENDOFCHAIN、sector 2 (root data) → ENDOFCHAIN。
        let fat_off = 512;
        let mut fat = vec![0xFFFF_FFFFu32; sector_size / 4];
        fat[0] = 0xFFFF_FFFD; // sector 0 自身は FAT sector
        fat[1] = 0xFFFF_FFFE; // sector 1 (directory) ENDOFCHAIN
        fat[2] = 0xFFFF_FFFE; // sector 2 (mini stream) ENDOFCHAIN
        for (i, v) in fat.iter().enumerate() {
            buf[fat_off + i * 4..fat_off + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }

        // sector 1: directory entry 0 = root entry。
        // root entry: object_type=5, starting_sector=2, size=mini_stream_size。
        let dir_off = 1024;
        buf[dir_off + 2] = OBJECT_TYPE_ROOT; // type = root
        buf[dir_off + 4..dir_off + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // left
        buf[dir_off + 8..dir_off + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // right
        buf[dir_off + 12..dir_off + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // child
        buf[dir_off + 52..dir_off + 56].copy_from_slice(&2u32.to_le_bytes()); // starting sector
        buf[dir_off + 56..dir_off + 60].copy_from_slice(&0u32.to_le_bytes()); // size low
        buf[dir_off + 60..dir_off + 64].copy_from_slice(&0u32.to_le_bytes()); // size high

        // sector 2: 空 mini stream data。

        buf
    }

    #[test]
    fn parse_minimal_cfb_succeeds() {
        let data = build_minimal_cfb();
        let container = parse_cfb(&data).unwrap();
        // stream 無し（root のみ）。
        assert!(container.streams.is_empty());
        assert!(container.root_entry.is_some());
    }

    #[test]
    fn rejects_short_input() {
        let err = parse_cfb(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, CfbError::TooShort(100)));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut data = build_minimal_cfb();
        data[0] = 0x00;
        let err = parse_cfb(&data).unwrap_err();
        assert_eq!(err, CfbError::SignatureMismatch);
    }

    #[test]
    fn corrupt_does_not_panic() {
        // 循環 FAT chain 等の異常入力で panic しない。
        let mut data = build_minimal_cfb();
        // FAT を自己参照へ壊す。
        data[512..516].copy_from_slice(&0u32.to_le_bytes());
        let _ = parse_cfb(&data);
    }
}
