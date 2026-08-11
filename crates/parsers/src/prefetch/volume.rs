//! Volume information entry（libyal PF format、T4-021）。
//!
//! Volumes information は「実行対象の file が属する volume」の一覧。
//! 各 entry は volume device path・作成時刻・serial 番号等を持つ。
//! version 毎に entry size が異なるが、本 Parser が観測する先頭 36 byte は共通:
//!
//! | offset | size | 内容 |
//! |--------|------|------|
//! | 0  | 4 | volume device path offset（volumes info 先頭から）|
//! | 4  | 4 | volume device path 文字数 |
//! | 8  | 8 | volume 作成時刻（FILETIME）|
//! | 16 | 4 | volume serial number |
//! | 20 | 4 | file references offset |
//! | 24 | 4 | file references size |
//! | 28 | 4 | directory strings offset |
//! | 32 | 4 | directory strings count |

/// 全 version 共通の先頭 field 長（byte）。これ以降は version 毎に異なるため読まない。
pub const VOLUME_COMMON_LEN: usize = 40;

/// Volume 情報の正規化表現。
#[derive(Clone, Debug)]
pub struct VolumeInfo {
    /// Volume device path（例: `\DEVICE\HARDDISKVOLUME1`）。
    /// 取得できなかった場合は `None`。
    pub device_path: Option<String>,
    /// Volume 作成時刻（FILETIME）。0 は「未設定」。
    pub creation_time: u64,
    /// Volume serial number。
    pub serial_number: u32,
}

/// volumes information block から最初の volume を取り出す。
///
/// 複数 volume が存在する場合も、Prefetch の実行痕跡 Event には最初の volume 情報を
/// 代表値として記録する（全 volume の網羅は Event の肥大化を招くため）。
///
/// - `volumes_buf`: volumes information block 全体（file 先頭からの offset で切り出し済み）。
/// - `entry_size`: version に応じた1 entry の想定 size（境界検証用）。
pub fn first_volume(volumes_buf: &[u8], entry_size: usize) -> Option<VolumeInfo> {
    if volumes_buf.len() < VOLUME_COMMON_LEN {
        return None;
    }
    let entry = &volumes_buf[..VOLUME_COMMON_LEN.min(volumes_buf.len())];
    let path_offset = rd_u32(entry, 0)?;
    let path_chars = rd_u32(entry, 4)?;
    let creation_time = rd_u64(entry, 8)?;
    let serial_number = rd_u32(entry, 16)?;

    let device_path = read_device_path(volumes_buf, path_offset, path_chars);

    // entry_size は境界検証の参考値。実 data が短くても先頭 40 byte が読めれば採用する。
    let _ = entry_size;

    Some(VolumeInfo {
        device_path,
        creation_time,
        serial_number,
    })
}

/// version に応じた volume entry size を返す。
pub fn entry_size_for(version: u32) -> Option<usize> {
    match version {
        17 => Some(40),
        23 | 26 => Some(104),
        30 | 31 => Some(96),
        _ => None,
    }
}

/// volumes block 内の device path 文字列を読む。
///
/// `path_offset` は volumes_buf 先頭からの byte offset。
/// `path_chars` は UTF-16 code unit 数（終端 null 含まない）。
fn read_device_path(volumes_buf: &[u8], path_offset: u32, path_chars: u32) -> Option<String> {
    let start = usize::try_from(path_offset).ok()?;
    let char_count = usize::try_from(path_chars).ok()?;
    let byte_len = char_count.checked_mul(2)?;
    let end = start.checked_add(byte_len)?;
    let slice = volumes_buf.get(start..end)?;
    let units: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed: Vec<u16> = units.into_iter().take_while(|&u| u != 0).collect();
    Some(String::from_utf16_lossy(&trimmed))
}

fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_volumes_block(device_path: &str) -> (Vec<u8>, u32, u32) {
        // entry (40 byte) + 続いて device path 文字列。
        let mut buf = vec![0u8; VOLUME_COMMON_LEN];
        let path_bytes: Vec<u8> = device_path
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let path_offset = VOLUME_COMMON_LEN as u32;
        let path_chars = device_path.encode_utf16().count() as u32;
        buf[0..4].copy_from_slice(&path_offset.to_le_bytes());
        buf[4..8].copy_from_slice(&path_chars.to_le_bytes());
        buf[8..16].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
        buf[16..20].copy_from_slice(&0xAABBCCDDu32.to_le_bytes());
        buf.extend_from_slice(&path_bytes);
        (buf, path_offset, path_chars)
    }

    #[test]
    fn first_volume_decodes_device_path() {
        let (buf, _, _) = build_volumes_block("\\DEVICE\\HARDDISKVOLUME1");
        let vol = first_volume(&buf, 40).unwrap();
        assert_eq!(
            vol.device_path.as_deref(),
            Some("\\DEVICE\\HARDDISKVOLUME1")
        );
        assert_eq!(vol.creation_time, 0x1122334455667788);
        assert_eq!(vol.serial_number, 0xAABBCCDD);
    }

    #[test]
    fn first_volume_missing_path_returns_none_path() {
        // 過大 offset を仕込む。
        let mut buf = vec![0u8; VOLUME_COMMON_LEN];
        buf[0..4].copy_from_slice(&999_999u32.to_le_bytes());
        buf[4..8].copy_from_slice(&5u32.to_le_bytes());
        buf[8..16].copy_from_slice(&42u64.to_le_bytes());
        let vol = first_volume(&buf, 40).unwrap();
        assert!(vol.device_path.is_none());
        assert_eq!(vol.creation_time, 42);
    }

    #[test]
    fn first_volume_returns_none_if_too_short() {
        let short = vec![0u8; 10];
        assert!(first_volume(&short, 40).is_none());
    }

    #[test]
    fn entry_size_for_versions() {
        assert_eq!(entry_size_for(17), Some(40));
        assert_eq!(entry_size_for(23), Some(104));
        assert_eq!(entry_size_for(26), Some(104));
        assert_eq!(entry_size_for(30), Some(96));
        assert_eq!(entry_size_for(31), Some(96));
        assert_eq!(entry_size_for(99), None);
    }
}
