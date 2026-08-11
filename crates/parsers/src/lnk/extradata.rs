//! ExtraData 解析（[MS-SHLLINK] §2.5、互換 §4.4）。
//!
//! ExtraData section は可変長 block の列。各 block は次の構造を持つ:
//!
//! ```text
//! Offset  Size  Field
//! 0       4     BlockSize      (u32 LE) ── Block 全体の byte 長（size field 含む）
//! 4       4     BlockSignature (u32 LE) ── block 種別
//! 8       ?     BlockData      ── (BlockSize - 8) byte
//! ```
//!
//! TerminalBlock: `BlockSize = 0x00000000`（4 byte のみ）で終端を表す。
//!
//! 既知 signature は認識して名前を記録し、未知 signature は **BlockSize で安全に skip** する
//! （未知 block を黙って無視せず、生 signature を記録する、互換 §12-7）。

use crate::framework::ReadSeek;

/// 既知 block signature 一覧（[MS-SHLLINK] §2.5）。
pub mod signature {
    pub const CONSOLE_DATA: u32 = 0xA000_0002;
    pub const TRACKER_DATA: u32 = 0xA000_0003;
    pub const CONSOLE_FE_DATA: u32 = 0xA000_0004;
    pub const ENVIRONMENT_VARIABLE_DATA: u32 = 0xA000_0005;
    pub const DARWIN_ID_LIST: u32 = 0xA000_0006;
    pub const ICON_ENVIRONMENT_DATA: u32 = 0xA000_0007;
    pub const SHIM_DATA: u32 = 0xA000_0008;
    pub const PROPERTY_STORE_DATA: u32 = 0xA000_0009;
    pub const SPECIAL_FOLDER_DATA: u32 = 0xA000_000A;
    pub const KNOWN_FOLDER_DATA: u32 = 0xA000_000B;
    pub const VISTA_AND_ABOVE_ID_LIST_DATA: u32 = 0xA000_000C;
}

/// 既知 signature の人間可読な名前を返す。未知なら `None`。
pub fn known_signature_name(sig: u32) -> Option<&'static str> {
    Some(match sig {
        signature::CONSOLE_DATA => "ConsoleData",
        signature::TRACKER_DATA => "TrackerData",
        signature::CONSOLE_FE_DATA => "ConsoleFeData",
        signature::ENVIRONMENT_VARIABLE_DATA => "EnvironmentVariableData",
        signature::DARWIN_ID_LIST => "DarwinIDList",
        signature::ICON_ENVIRONMENT_DATA => "IconEnvironmentData",
        signature::SHIM_DATA => "ShimData",
        signature::PROPERTY_STORE_DATA => "PropertyStoreData",
        signature::SPECIAL_FOLDER_DATA => "SpecialFolderData",
        signature::KNOWN_FOLDER_DATA => "KnownFolderData",
        signature::VISTA_AND_ABOVE_ID_LIST_DATA => "VistaAndAboveIDListData",
        _ => return None,
    })
}

/// 1 個の ExtraData block（raw byte 付き）。
#[derive(Clone, Debug)]
pub struct ExtraDataBlock {
    /// Block 全体の byte 長。
    pub block_size: u32,
    /// Block signature。
    pub signature: u32,
    /// 既知 block の名前。未知なら `None`。
    pub known_name: Option<&'static str>,
    /// BlockData（BlockSize - 8 byte）。最小限の解析用。
    pub data: Vec<u8>,
}

/// ExtraData section 全体の解析結果。
#[derive(Clone, Debug, Default)]
pub struct ExtraDataSection {
    /// 出現順の block 一覧（TerminalBlock を含まない）。
    pub blocks: Vec<ExtraDataBlock>,
    /// EnvironmentVariableData があればその ANSI 文字列（target path の環境変数表現）。
    pub environment_variable_target: Option<String>,
    /// 終端 TerminalBlock が見つかったか。
    pub saw_terminal: bool,
    /// ExtraData section が truncated 等で途中終了したか。
    pub truncated: bool,
    /// 未知 signature の block 数（互換 §12-7: 黙って無視しない記録用）。
    pub unknown_block_count: u32,
}

/// ExtraData section を読む。EOF へ到達するか TerminalBlock を読むまで続ける。
///
/// reader は ExtraData section の先頭に位置していること。
pub fn read_extra_data(reader: &mut dyn ReadSeek) -> ExtraDataSection {
    let mut section = ExtraDataSection::default();

    loop {
        let mut size_buf = [0u8; 4];
        match reader.read_exact(&mut size_buf) {
            Ok(()) => {}
            Err(_) => {
                // EOF（TerminalBlock 無しで終了）。これは truncated 扱い。
                section.truncated = !section.blocks.is_empty();
                break;
            }
        }
        let block_size = u32::from_le_bytes(size_buf);

        // TerminalBlock（BlockSize = 0）。
        if block_size == 0 {
            section.saw_terminal = true;
            break;
        }

        // BlockSize は少なくとも signature (4 byte) を含む必要がある。
        if block_size < 8 {
            // 形式異常。安全のためここで打ち切る。
            section.truncated = true;
            break;
        }

        let mut sig_buf = [0u8; 4];
        if reader.read_exact(&mut sig_buf).is_err() {
            section.truncated = true;
            break;
        }
        let signature = u32::from_le_bytes(sig_buf);

        let data_len = (block_size as usize).saturating_sub(8);
        let mut data = vec![0u8; data_len];
        if reader.read_exact(&mut data).is_err() {
            section.truncated = true;
            break;
        }

        let known_name = known_signature_name(signature);
        if known_name.is_none() {
            section.unknown_block_count += 1;
        }

        // EnvironmentVariableData から target path を取り出す。
        if signature == signature::ENVIRONMENT_VARIABLE_DATA {
            section.environment_variable_target = parse_env_var_target(&data);
        }

        section.blocks.push(ExtraDataBlock {
            block_size,
            signature,
            known_name,
            data,
        });
    }

    section
}

/// EnvironmentVariableData の BlockData から target path を取り出す（[MS-SHLLINK] §2.5.4）。
///
/// Layout:
/// - TargetAnsi: null-terminated ANSI string
/// - TargetUnicode: null-terminated UTF-16LE string
///
/// ここでは TargetAnsi を優先し、無ければ TargetUnicode を試みる。
fn parse_env_var_target(data: &[u8]) -> Option<String> {
    // TargetAnsi: 先頭から null まで。
    let ansi_end = data.iter().position(|&b| b == 0)?;
    let ansi = &data[..ansi_end];
    let ansi_string = String::from_utf8_lossy(ansi).into_owned();
    if !ansi_string.is_empty() {
        return Some(ansi_string);
    }
    // TargetUnicode: TargetAnsi の null の次から。
    let uni_start = ansi_end + 1;
    if uni_start >= data.len() {
        return None;
    }
    let uni_bytes = &data[uni_start..];
    let even_len = uni_bytes.len() & !1;
    let units: Vec<u16> = (0..even_len)
        .step_by(2)
        .map(|i| u16::from_le_bytes([uni_bytes[i], uni_bytes[i + 1]]))
        .take_while(|&u| u != 0)
        .collect();
    let decoded: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cursor(data: Vec<u8>) -> Cursor<Vec<u8>> {
        Cursor::new(data)
    }

    fn build_block(signature: u32, data: &[u8]) -> Vec<u8> {
        let block_size = 8 + data.len() as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&block_size.to_le_bytes());
        buf.extend_from_slice(&signature.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn read_terminal_only() {
        let mut c = cursor(vec![0u8; 4]); // TerminalBlock
        let section = read_extra_data(&mut c);
        assert!(section.saw_terminal);
        assert!(section.blocks.is_empty());
        assert!(!section.truncated);
    }

    #[test]
    fn read_known_block_then_terminal() {
        let mut buf = build_block(signature::TRACKER_DATA, &[1, 2, 3, 4]);
        buf.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        let mut c = cursor(buf);
        let section = read_extra_data(&mut c);
        assert_eq!(section.blocks.len(), 1);
        assert_eq!(section.blocks[0].known_name, Some("TrackerData"));
        assert!(section.saw_terminal);
        assert_eq!(section.unknown_block_count, 0);
    }

    #[test]
    fn read_unknown_block_skipped_safely() {
        // 未知 signature 0xDEAD_BEEF。
        let mut buf = build_block(0xDEAD_BEEF, &[9, 9, 9]);
        buf.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        let mut c = cursor(buf);
        let section = read_extra_data(&mut c);
        assert_eq!(section.blocks.len(), 1);
        assert!(section.blocks[0].known_name.is_none());
        assert_eq!(section.unknown_block_count, 1);
        assert!(section.saw_terminal);
    }

    #[test]
    fn read_env_var_block_extracts_target() {
        // EnvironmentVariableData: TargetAnsi = "%SystemRoot%\notepad.exe" + null。
        let target = "%SystemRoot%\\notepad.exe";
        let mut data = Vec::new();
        data.extend_from_slice(target.as_bytes());
        data.push(0); // null terminator
        // TargetUnicode は空でも可。
        let mut buf = build_block(signature::ENVIRONMENT_VARIABLE_DATA, &data);
        buf.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
        let mut c = cursor(buf);
        let section = read_extra_data(&mut c);
        assert_eq!(
            section.environment_variable_target.as_deref(),
            Some("%SystemRoot%\\notepad.exe")
        );
    }

    #[test]
    fn read_empty_extra_data_is_truncated() {
        // 何も無い（EOF）。truncated 扱い（block が1つも無ければ無害）。
        let mut c = cursor(vec![]);
        let section = read_extra_data(&mut c);
        assert!(!section.saw_terminal);
        // blocks が空なら truncated は false。
        assert!(!section.truncated);
    }

    #[test]
    fn read_oversize_block_truncates_safely() {
        // BlockSize = 100 を宣言するが、data が足りない。
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes()); // BlockSize
        buf.extend_from_slice(&signature::SHIM_DATA.to_le_bytes()); // Signature
        buf.extend_from_slice(&[0u8; 5]); // data が足りない
        let mut c = cursor(buf);
        let section = read_extra_data(&mut c);
        assert!(section.truncated);
        assert!(!section.saw_terminal);
    }

    #[test]
    fn known_signature_name_lookup() {
        assert_eq!(
            known_signature_name(signature::TRACKER_DATA),
            Some("TrackerData")
        );
        assert_eq!(
            known_signature_name(signature::PROPERTY_STORE_DATA),
            Some("PropertyStoreData")
        );
        assert_eq!(known_signature_name(0x1234_5678), None);
    }
}
