//! DestList stream 解析（[MS-DESTS]、互換 §4.5・T4-071）。
//!
//! AutomaticDestinations-ms 内の `DestList` stream は、Jump List entry の metadata を保持する。
//! 各 entry は stream 名（"1", "2", ...）で内包 LNK stream へ対応付けられ、最終利用時刻・
//! 作成時刻・最終更新時刻等を持つ。
//!
//! ## 対応 version
//!
//! - v1: Windows 7 SP1（header 32 byte・entry 固定部 74 byte + stream name 変長）
//! - v3: Windows 10 22H2（header 32 byte・entry 固定部 80 byte + stream name 変長）
//! - v4: Windows 11 24H2（header 32 byte・entry 固定部 80 byte + stream name 変長・v3 と同等）
//!
//! 未知 version は [`ParseOutcome::UnsupportedVersion`] となり、呼出側で Warning Issue へ記録する
//! （互換 §4.5: container 全体を誤解析せず Warning）。
//!
//! ## 安全性
//!
//! - いかなる破損入力でも panic しない（規範 §9.4・互換 §12-2）
//! - truncated entry はそこまでの解析結果を採用し、残りを打ち切る（部分成功）

/// 既知 DestList version（[MS-DESTS]）。
pub const VERSION_V1: u32 = 1;
/// 既知 DestList version（v3 系・Win10/Win11）。
pub const VERSION_V3: u32 = 3;
/// 既知 DestList version（v4 系・Win11 24H2 で観察）。
pub const VERSION_V4: u32 = 4;

/// header 共通部の byte 長（version 1/3/4 共通）。
const COMMON_HEADER_BYTES: usize = 32;

/// DestList 解析の結果。
#[derive(Clone, Debug)]
pub enum ParseOutcome {
    /// 既知 version で正常解析した。
    Parsed {
        /// DestList format version。
        version: u32,
        /// 宣言された entry 数（header 由来）。
        declared_entry_count: u32,
        /// 実際に読み取れた entry 一覧。
        entries: Vec<DestListEntry>,
        /// header 由来の最終 revision FILETIME（0 の場合あり）。
        last_revision_filetime: u64,
        /// 解析途中で打ち切ったか（truncated 等）。
        truncated: bool,
    },
    /// 未知 version（互換 §4.5: Warning のみ）。
    UnsupportedVersion {
        /// 検出された version。
        version: u32,
    },
}

/// 1件の DestList entry。
#[derive(Clone, Debug)]
pub struct DestListEntry {
    /// 対応する stream 名（"1", "2", ...）。
    pub stream_name: String,
    /// 最終利用時刻 FILETIME（0 の場合あり）。
    pub last_used_filetime: u64,
    /// 作成時刻 FILETIME（0 の場合あり）。
    pub created_filetime: u64,
    /// 最終更新時刻 FILETIME（0 の場合あり）。
    pub last_modified_filetime: u64,
    /// entry 内の stream name length（UTF-16 code unit 数。debug 用）。
    pub stream_name_length_units: u32,
}

/// DestList stream bytes を解析する。
pub fn parse_destlist(data: &[u8]) -> ParseOutcome {
    if data.len() < 4 {
        return ParseOutcome::UnsupportedVersion { version: 0 };
    }
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != VERSION_V1 && version != VERSION_V3 && version != VERSION_V4 {
        return ParseOutcome::UnsupportedVersion { version };
    }

    if data.len() < COMMON_HEADER_BYTES {
        return ParseOutcome::Parsed {
            version,
            declared_entry_count: 0,
            entries: Vec::new(),
            last_revision_filetime: 0,
            truncated: true,
        };
    }

    let declared_entry_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let last_revision_filetime = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);

    // version 毎の entry 固定部 byte 数。
    let entry_fixed_bytes: usize = if version == VERSION_V1 { 74 } else { 80 };
    let mut entries = Vec::new();
    let mut cursor = COMMON_HEADER_BYTES;
    let mut truncated = false;

    while cursor < data.len() {
        let remaining = data.len() - cursor;
        if remaining < entry_fixed_bytes {
            truncated = true;
            break;
        }
        let chunk = &data[cursor..cursor + entry_fixed_bytes];
        // 共通 field:
        // offset 0..8:  last_used_filetime (FILETIME u64 LE)
        // offset 8..12: unknown u32
        // offset 12..16: unknown u32
        // offset 16..24: unknown u64 (v1 では access time 等の可能性もあるが、ここでは unknown 扱い)
        // offset 24..28: unknown u32
        // version 毎の stream name length field:
        //   v1: offset 28..30 (u16 LE)
        //   v3/v4: offset 28..32 (u32 LE) + offset 32..34 (u16 LE)
        // 以降: offset entry_fixed_bytes..entry_fixed_bytes+name_bytes: UTF-16LE stream name
        let last_used_filetime = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        let created_filetime = u64::from_le_bytes([
            chunk[40], chunk[41], chunk[42], chunk[43], chunk[44], chunk[45], chunk[46], chunk[47],
        ]);
        let last_modified_filetime = u64::from_le_bytes([
            chunk[48], chunk[49], chunk[50], chunk[51], chunk[52], chunk[53], chunk[54], chunk[55],
        ]);

        let stream_name_length_units: u32 = if version == VERSION_V1 {
            u16::from_le_bytes([chunk[28], chunk[29]]) as u32
        } else {
            u32::from_le_bytes([chunk[28], chunk[29], chunk[30], chunk[31]])
        };

        // UTF-16 code unit 数 → byte 数。
        let name_bytes = (stream_name_length_units as usize).saturating_mul(2);
        let name_total_bytes = if version == VERSION_V1 {
            // v1: name は null 終端付きで長さ分全体が格納されている。
            name_bytes
        } else {
            // v3/v4: 同様に name_bytes 分。null 終端が length に含まれる場合と含まれない場合がある。
            name_bytes
        };

        // entry 全体（固定部 + name + 末尾 4 byte unknown）。
        let entry_total = entry_fixed_bytes + name_total_bytes + 4;
        if cursor + entry_total > data.len() {
            // entry 途中で truncated。
            truncated = true;
            // 取れる分だけ name を復元して格納する。
            let avail_name_bytes = (data.len() - cursor - entry_fixed_bytes).min(name_total_bytes);
            let avail_end = cursor + entry_fixed_bytes + avail_name_bytes;
            let name = decode_utf16le_lossy(&data[cursor + entry_fixed_bytes..avail_end]);
            entries.push(DestListEntry {
                stream_name: name,
                last_used_filetime,
                created_filetime,
                last_modified_filetime,
                stream_name_length_units,
            });
            break;
        }

        let name_start = cursor + entry_fixed_bytes;
        let name_end = name_start + name_total_bytes;
        let name = decode_utf16le_lossy(&data[name_start..name_end]);

        entries.push(DestListEntry {
            stream_name: name,
            last_used_filetime,
            created_filetime,
            last_modified_filetime,
            stream_name_length_units,
        });

        cursor += entry_total;
    }

    ParseOutcome::Parsed {
        version,
        declared_entry_count,
        entries,
        last_revision_filetime,
        truncated,
    }
}

/// UTF-16LE byte 列を UTF-8 文字列へ lossy 変換する（奇数 byte の末尾は切り捨て）。
fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let even_len = bytes.len() & !1;
    let units: Vec<u16> = (0..even_len)
        .step_by(2)
        .map(|i| u16::from_le_bytes([bytes[i], bytes[i + 1]]))
        .collect();
    char::decode_utf16(units.iter().copied().take_while(|&u| u != 0))
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1 (Win7) DestList を1件構築する。
    fn build_v1_destlist(last_used_ft: u64, stream_name: &str) -> Vec<u8> {
        let name_units: Vec<u16> = stream_name.encode_utf16().collect();
        let name_units_with_null = name_units.len() + 1;
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut buf = Vec::new();
        // header (32 byte)
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
        buf.extend_from_slice(&28u32.to_le_bytes()); // following size
        buf.extend_from_slice(&1u32.to_le_bytes()); // entry count
        buf.extend_from_slice(&1u32.to_le_bytes()); // unknown
        buf.extend_from_slice(&last_used_ft.to_le_bytes()); // last revision
        buf.extend_from_slice(&0u64.to_le_bytes()); // unknown
        assert_eq!(buf.len(), COMMON_HEADER_BYTES);
        // entry (74 byte + name + 4 byte)
        let mut entry = vec![0u8; 74];
        entry[0..8].copy_from_slice(&last_used_ft.to_le_bytes()); // last_used
        entry[40..48].copy_from_slice(&(last_used_ft + 1).to_le_bytes()); // created
        entry[48..56].copy_from_slice(&(last_used_ft + 2).to_le_bytes()); // modified
        let name_len_units = name_units_with_null as u32;
        entry[28..30].copy_from_slice(&(name_len_units as u16).to_le_bytes());
        buf.extend_from_slice(&entry);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(&0u16.to_le_bytes()); // null 終端
        // 末尾 4 byte unknown
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    /// v3 (Win10) DestList を1件構築する。
    fn build_v3_destlist(last_used_ft: u64, stream_name: &str) -> Vec<u8> {
        let name_units: Vec<u16> = stream_name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut buf = Vec::new();
        // header
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&last_used_ft.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(buf.len(), COMMON_HEADER_BYTES);
        // entry (80 byte + name + 4 byte)
        let mut entry = vec![0u8; 80];
        entry[0..8].copy_from_slice(&last_used_ft.to_le_bytes());
        entry[40..48].copy_from_slice(&(last_used_ft + 1).to_le_bytes());
        entry[48..56].copy_from_slice(&(last_used_ft + 2).to_le_bytes());
        let name_len_units = name_units.len() as u32;
        entry[28..32].copy_from_slice(&name_len_units.to_le_bytes());
        buf.extend_from_slice(&entry);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    #[test]
    fn parse_v1_single_entry() {
        let data = build_v1_destlist(132_000_000_000_000_000, "1");
        let outcome = parse_destlist(&data);
        match outcome {
            ParseOutcome::Parsed {
                version,
                entries,
                declared_entry_count,
                truncated,
                ..
            } => {
                assert_eq!(version, VERSION_V1);
                assert_eq!(declared_entry_count, 1);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].stream_name, "1");
                assert!(!truncated);
            }
            _ => panic!("v1 は Parsed になるべき"),
        }
    }

    #[test]
    fn parse_v3_single_entry() {
        let data = build_v3_destlist(132_000_000_000_000_000, "1");
        let outcome = parse_destlist(&data);
        match outcome {
            ParseOutcome::Parsed {
                version, entries, ..
            } => {
                assert_eq!(version, VERSION_V3);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].stream_name, "1");
            }
            _ => panic!("v3 は Parsed になるべき"),
        }
    }

    #[test]
    fn unknown_version_emits_unsupported() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&99u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 28]);
        let outcome = parse_destlist(&buf);
        match outcome {
            ParseOutcome::UnsupportedVersion { version } => assert_eq!(version, 99),
            _ => panic!("未知 version は UnsupportedVersion"),
        }
    }

    #[test]
    fn truncated_entry_does_not_panic() {
        let mut data = build_v1_destlist(0, "1");
        // 末尾を切り捨て。
        data.truncate(data.len() - 5);
        let outcome = parse_destlist(&data);
        match outcome {
            ParseOutcome::Parsed { truncated, .. } => assert!(truncated),
            _ => panic!("truncated は Parsed(truncated=true)"),
        }
    }

    #[test]
    fn empty_input_does_not_panic() {
        let _ = parse_destlist(&[]);
        let _ = parse_destlist(&[0u8; 2]);
    }
}
