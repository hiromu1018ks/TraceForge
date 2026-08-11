//! CustomDestinations-ms 形式の parser（互換 §4.5・T4-073）。
//!
//! `.customDestinations-ms` file はユーザが明示的に pin 等で追加した Jump List entry を保持する。
//! CFB container ではなく独自の binary format で、category header + 内包 LNK 群から成る。
//!
//! ## 形式の概観（リバースエンジニアリングに基づく）
//!
//! ```text
//! ┌────────────────────────────────────┐
//! │ File header (可変)                  │  category count 等。本 parser は先頭
//! │                                    │  byte が 0x00 になるまで読み飛ばす。
//! ├────────────────────────────────────┤
//! │ Category block 0                   │  type 4 byte・count 4 byte・entry...
//! │ Category block 1                   │
//! │ ...                                │
//! ├────────────────────────────────────┤
//! │ Terminator (4 byte: 0x00000000)     │
//! └────────────────────────────────────┘
//! ```
//!
//! 各 category block:
//!
//! ```text
//! 0  4  CategoryType (u32 LE)  ── 0 で終端（file の末尾を意味する）
//! 4  4  EntryCount (u32 LE)
//! 8  ?  Entries（entry が連続）
//! ```
//!
//! 各 entry（内包 LNK）:
//!
//! ```text
//! 0  4  EntryPointType (u32 LE)  ── 通常 0x00000003
//! 4  ?  SHLLINK bytes（[MS-SHLLINK] と同一形式）
//! ```
//!
//! 本 parser は各 LNK の境界を EntryPointType + LNK HeaderSize で特定する。
//! LNK の長さは [MS-SHLLINK] §2.1 ShellLinkHeader の各 flag と可変 section で決まるため、
//! 既存の [`crate::lnk`] machinery で stream から読み取る。
//!
//! ## 安全性
//!
//! - 破損入力で panic しない（規範 §9.4・互換 §12-2）
//! - category 終端を検出できない場合は残りを1 category として扱い、安全な境界で打ち切る
//! - 部分成功（規範 §9.2・§21-5）

use crate::framework::ReadSeek;
use crate::lnk::extradata;
use crate::lnk::header::{HEADER_BYTES as LNK_HEADER_BYTES, ShellLinkHeader};
use crate::lnk::idlist;
use crate::lnk::linkinfo;
use crate::lnk::stringdata;

/// entry point type: 通常 0x00000003。
const ENTRY_POINT_TYPE_NORMAL: u32 = 0x0000_0003;

/// category 終端の type 値（0x00000000）。
const CATEGORY_TERMINATOR: u32 = 0x0000_0000;

/// CustomDestinations の category。
#[derive(Clone, Debug)]
pub struct CustomCategory {
    /// category type（例: known folder ID 等。0 は終端を意味する）。
    pub category_type: u32,
    /// category 内の entry 一覧。
    pub entries: Vec<CustomEntry>,
}

/// CustomDestinations の entry（内包 LNK）。
#[derive(Clone, Debug)]
pub struct CustomEntry {
    /// LNK が始まる file 先頭からの byte offset。
    pub lnk_offset: u64,
    /// LNK 全体の byte 長（終端 TerminalBlock 含む）。
    pub lnk_size: u64,
    /// entry point type（通常 0x00000003）。
    pub entry_point_type: u32,
    /// 内包 LNK から抽出した target 情報。
    pub lnk: ExtractedLnk,
}

/// 内包 LNK から抽出した target 情報（[`crate::lnk::LnkParser`] と同じ論理で抽出）。
///
/// `lnk` は省略可能（[`Option`] では無く構造体で表現し、解析失敗時は初期値を使う）。
#[derive(Clone, Debug, Default)]
pub struct ExtractedLnk {
    /// LNK header の flags。
    pub flags_raw: u32,
    /// target path（LocalBasePath・StringData・ExtraData EnvironmentVariable から復元）。
    pub target_path: Option<String>,
    /// CreationTime FILETIME。
    pub creation_filetime: u64,
    /// AccessTime FILETIME。
    pub access_filetime: u64,
    /// WriteTime FILETIME。
    pub write_filetime: u64,
    /// file size。
    pub file_size: u32,
    /// LNK が IsUnicode か。
    pub is_unicode: bool,
    /// LNK name string（あれば）。
    pub name: Option<String>,
    /// LNK relative path（あれば）。
    pub relative_path: Option<String>,
    /// LNK working dir（あれば）。
    pub working_dir: Option<String>,
    /// LNK arguments（あれば）。
    pub arguments: Option<String>,
    /// LNK icon location（あれば）。
    pub icon_location: Option<String>,
}

/// CustomDestinations の解析結果。
#[derive(Clone, Debug)]
pub struct CustomDestinations {
    /// 読み取った category 一覧（終端 category を含まない）。
    pub categories: Vec<CustomCategory>,
    /// 解析途中で打ち切ったか（部分成功）。
    pub partial: bool,
}

/// snapshot 全体を一度読み込んだ byte 列から、CustomDestinations を解析する。
///
/// `data` は `.customDestinations-ms` file 全体を想定。
pub fn parse_custom_destinations(data: &[u8]) -> CustomDestinations {
    let mut categories = Vec::new();
    let mut partial = false;

    // 16 byte file header を読み飛ばす（CustomDestinations の先頭固定部）。
    // 実際の file では先頭 16 byte に file 全体の metadata が入る。
    // 各 category は 4 byte type で始まるため、category_type=0 (terminator) で
    // 判定できる。本 parser は file 先頭 16 byte を読み飛ばす。
    if data.len() < 16 {
        return CustomDestinations {
            categories,
            partial: true,
        };
    }
    let mut cursor: usize = 16;

    while cursor + 8 <= data.len() {
        let category_type = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        if category_type == CATEGORY_TERMINATOR {
            break;
        }
        let entry_count = u32::from_le_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]);
        cursor += 8;

        let mut entries = Vec::new();
        // entry_count は信頼できない可能性があるため、実際に読める範囲で制限する。
        let max_entries = entry_count.min(10_000);
        for _ in 0..max_entries {
            if cursor + 4 > data.len() {
                partial = true;
                break;
            }
            let entry_point_type = u32::from_le_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]);
            if entry_point_type != ENTRY_POINT_TYPE_NORMAL {
                // 未知 entry point type。安全のため終了。
                partial = true;
                break;
            }
            // entry の開始 byte offset（LNK 本体の直前）。
            cursor += 4;

            // LNK を cursor から読む。reader へ cursor を seek した状態で渡す。
            let mut reader = std::io::Cursor::new(data);
            use std::io::Seek;
            let _ = reader.seek(std::io::SeekFrom::Start(cursor as u64));
            let lnk_start = cursor as u64;
            let (lnk_size, lnk) = read_one_lnk(&mut reader);
            let lnk_end = reader.stream_position().unwrap_or(lnk_start);

            // LNK size が取れなかった場合でも cursor を進めるため、少なくとも header 分は進める。
            let consumed = (lnk_end as usize)
                .saturating_sub(cursor)
                .max(LNK_HEADER_BYTES);
            cursor = (lnk_end as usize).max(cursor + consumed);

            entries.push(CustomEntry {
                lnk_offset: lnk_start,
                lnk_size: lnk_size.unwrap_or(consumed as u64),
                entry_point_type,
                lnk,
            });

            if cursor >= data.len() {
                partial = true;
                break;
            }
        }
        categories.push(CustomCategory {
            category_type,
            entries,
        });
        if partial {
            break;
        }
    }

    CustomDestinations {
        categories,
        partial,
    }
}

/// reader から1つの LNK を読み取る。戻り値は (LNK 全体 byte 長, 抽出した target 情報)。
///
/// reader は LNK の先頭（ShellLinkHeader の HeaderSize field）へ位置していること。
fn read_one_lnk(reader: &mut dyn ReadSeek) -> (Option<u64>, ExtractedLnk) {
    let lnk_start = reader.stream_position().unwrap_or(0);

    // 1. Header。
    let mut header_buf = vec![0u8; LNK_HEADER_BYTES];
    if read_exact_or_truncate(reader, &mut header_buf).is_err() {
        return (None, ExtractedLnk::default());
    }
    let header = match ShellLinkHeader::parse(&header_buf) {
        Ok(h) => h,
        Err(_) => {
            // Header 不正。ここまでを LNK size とする。
            let end = reader.stream_position().unwrap_or(lnk_start);
            return (Some(end.saturating_sub(lnk_start)), ExtractedLnk::default());
        }
    };

    // 2. LinkTargetIDList（flag があれば）。
    if header.flags.has_link_target_id_list() {
        let _ = idlist::read_link_target_id_list(reader);
    }

    // 3. LinkInfo（flag があれば、force_no_link_info が無ければ）。
    let mut target_path: Option<String> = None;
    if header.flags.has_link_info()
        && !header.flags.force_no_link_info()
        && let Ok(li) = linkinfo::read_link_info(reader)
    {
        target_path = linkinfo::reconstruct_target_path(&li);
    }

    // 4. StringData（flag があれば）。
    let string_section = stringdata::read_string_data_section(reader, header.flags).ok();

    // 5. ExtraData。
    let extra_section = extradata::read_extra_data(reader);

    let resolved_target = extra_section
        .environment_variable_target
        .clone()
        .or(target_path.clone());

    let end = reader.stream_position().unwrap_or(lnk_start);
    let lnk_size = end.saturating_sub(lnk_start);

    let extracted = ExtractedLnk {
        flags_raw: header.flags.raw(),
        target_path: resolved_target,
        creation_filetime: header.creation_time,
        access_filetime: header.access_time,
        write_filetime: header.write_time,
        file_size: header.file_size,
        is_unicode: header.flags.is_unicode(),
        name: string_section
            .as_ref()
            .and_then(|s| s.name.as_ref().map(|d| d.value.clone())),
        relative_path: string_section
            .as_ref()
            .and_then(|s| s.relative_path.as_ref().map(|d| d.value.clone())),
        working_dir: string_section
            .as_ref()
            .and_then(|s| s.working_dir.as_ref().map(|d| d.value.clone())),
        arguments: string_section
            .as_ref()
            .and_then(|s| s.arguments.as_ref().map(|d| d.value.clone())),
        icon_location: string_section
            .as_ref()
            .and_then(|s| s.icon_location.as_ref().map(|d| d.value.clone())),
    };

    (Some(lnk_size), extracted)
}

/// `read_exact` の失敗を truncated 判定へ変換する補助関数。
fn read_exact_or_truncate(
    reader: &mut dyn ReadSeek,
    buf: &mut Vec<u8>,
) -> Result<(), std::io::Error> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if filled < buf.len() {
        buf.truncate(filled);
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lnk::header::LINK_CLSID;
    /// 最小 LNK bytes（76 byte header のみ・flag 無し・TerminalBlock 付き）。
    fn build_minimal_lnk() -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&0x4Cu32.to_le_bytes()); // HeaderSize
        buf.extend_from_slice(&LINK_CLSID);
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        buf.extend_from_slice(&0u64.to_le_bytes()); // CreationTime
        buf.extend_from_slice(&0u64.to_le_bytes()); // AccessTime
        buf.extend_from_slice(&0u64.to_le_bytes()); // WriteTime
        buf.extend_from_slice(&1234u32.to_le_bytes()); // FileSize
        buf.extend_from_slice(&0i32.to_le_bytes()); // IconIndex
        buf.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand
        buf.extend_from_slice(&0u16.to_le_bytes()); // HotKey
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
        buf.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        assert_eq!(buf.len(), 80);
        buf
    }

    /// 1 category / 1 entry の CustomDestinations bytes を構築する。
    fn build_simple_custom(category_type: u32, lnk: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // 16 byte file header。
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        // category header。
        buf.extend_from_slice(&category_type.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // entry count
        // entry。
        buf.extend_from_slice(&ENTRY_POINT_TYPE_NORMAL.to_le_bytes());
        buf.extend_from_slice(lnk);
        // terminator。
        buf.extend_from_slice(&CATEGORY_TERMINATOR.to_le_bytes());
        buf
    }

    #[test]
    fn parses_one_category_one_entry() {
        let lnk = build_minimal_lnk();
        let data = build_simple_custom(0x0000_0001, &lnk);
        let result = parse_custom_destinations(&data);
        assert!(!result.partial, "should not be partial");
        assert_eq!(result.categories.len(), 1);
        assert_eq!(result.categories[0].category_type, 1);
        assert_eq!(result.categories[0].entries.len(), 1);
        let entry = &result.categories[0].entries[0];
        assert_eq!(entry.entry_point_type, ENTRY_POINT_TYPE_NORMAL);
        assert_eq!(entry.lnk.file_size, 1234);
    }

    #[test]
    fn empty_input_does_not_panic() {
        let result = parse_custom_destinations(&[]);
        assert!(result.partial);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let lnk = build_minimal_lnk();
        let mut data = build_simple_custom(1, &lnk);
        // 末尾を切り捨て。
        data.truncate(data.len() - 5);
        let _ = parse_custom_destinations(&data);
    }
}
