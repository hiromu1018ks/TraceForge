//! Shell Link Header 解析（[MS-SHLLINK] §2.1、互換 §4.4）。
//!
//! Header は固定 76 byte。全 multi-byte 整数は little-endian。
//!
//! ```text
//! Offset  Size  Field
//! 0       4     HeaderSize      (u32 LE) ── 0x4C (76) 固定
//! 4       16    LinkCLSID       (16 byte) ── {00021401-0000-0000-C000-000000000046}
//! 20      4     LinkFlags       (u32 LE)
//! 24      4     FileAttributes  (u32 LE)
//! 28      8     CreationTime    (FILETIME u64 LE)
//! 36      8     AccessTime      (FILETIME u64 LE)
//! 44      8     WriteTime       (FILETIME u64 LE)
//! 52      4     FileSize        (u32 LE)
//! 56      4     IconIndex       (i32 LE)
//! 60      4     ShowCommand     (u32 LE)
//! 64      2     HotKey          (u16 LE)
//! 66      2     Reserved1       (u16 LE) ── 0 でなければならない
//! 68      4     Reserved2       (u32 LE) ── 0 でなければならない
//! 72      4     Reserved3       (u32 LE) ── 0 でなければならない
//! ```

use chrono::{DateTime, Utc};

use crate::lnk::filetime::filetime_to_datetime;

/// HeaderSize の期待値（[MS-SHLLINK] §2.1: 0x0000004C = 76）。
pub const EXPECTED_HEADER_SIZE: u32 = 0x0000_004C;

/// Header 全体の byte 長。
pub const HEADER_BYTES: usize = 76;

/// Shell Link Header の CLSID（[MS-SHLLINK] §2.1）。
/// `{00021401-0000-0000-C000-000000000046}` をバイト列へ直したもの（little-endian GUID）。
pub const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// LinkFlags の bit 定義（[MS-SHLLINK] §2.1.1）。
///
/// 仕様上の意味（全て必須で遵守するわけではなく、Parser は出現有無へ従って section を読む）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkFlags(pub u32);

impl LinkFlags {
    pub fn from_le_bytes(bytes: [u8; 4]) -> Self {
        LinkFlags(u32::from_le_bytes(bytes))
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    /// Section の有無判定。
    pub fn has_link_target_id_list(self) -> bool {
        self.0 & 0x0000_0001 != 0
    }
    pub fn has_link_info(self) -> bool {
        self.0 & 0x0000_0002 != 0
    }
    pub fn has_name(self) -> bool {
        self.0 & 0x0000_0004 != 0
    }
    pub fn has_relative_path(self) -> bool {
        self.0 & 0x0000_0008 != 0
    }
    pub fn has_working_dir(self) -> bool {
        self.0 & 0x0000_0010 != 0
    }
    pub fn has_arguments(self) -> bool {
        self.0 & 0x0000_0020 != 0
    }
    pub fn has_icon_location(self) -> bool {
        self.0 & 0x0000_0040 != 0
    }
    /// StringData が Unicode (UTF-16LE) か。false なら ANSI (CP_ACP)。
    pub fn is_unicode(self) -> bool {
        self.0 & 0x0000_0080 != 0
    }
    /// LinkInfo を強制的に無視する（[MS-SHLLINK] §2.1.1）。
    pub fn force_no_link_info(self) -> bool {
        self.0 & 0x0000_0100 != 0
    }
    /// Win10+: target metadata (PropertyStoreData) の有無ヒント。
    pub fn enable_target_metadata(self) -> bool {
        self.0 & 0x0008_0000 != 0
    }

    /// 既知の flag bit の一覧。未知 bit を出力記録するために使う。
    pub fn known_flag_names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.has_link_target_id_list() {
            names.push("has_link_target_idlist");
        }
        if self.has_link_info() {
            names.push("has_link_info");
        }
        if self.has_name() {
            names.push("has_name");
        }
        if self.has_relative_path() {
            names.push("has_relative_path");
        }
        if self.has_working_dir() {
            names.push("has_working_dir");
        }
        if self.has_arguments() {
            names.push("has_arguments");
        }
        if self.has_icon_location() {
            names.push("has_icon_location");
        }
        if self.is_unicode() {
            names.push("is_unicode");
        }
        if self.force_no_link_info() {
            names.push("force_no_link_info");
        }
        if self.enable_target_metadata() {
            names.push("enable_target_metadata");
        }
        names
    }

    /// 仕様で定義されない bit（将来拡張や未知 flag）。0 なら未知 bit なし。
    pub fn unknown_bits(self) -> u32 {
        // 既知 flag の mask。
        const KNOWN: u32 = 0x0000_01FF | 0x0008_0000;
        self.0 & !KNOWN
    }
}

/// FileAttributes の bit 定義（[MS-SHLLINK] §2.1.2）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub fn from_le_bytes(bytes: [u8; 4]) -> Self {
        FileAttributes(u32::from_le_bytes(bytes))
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn known_flag_names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.0 & 0x0000_0001 != 0 {
            names.push("read_only");
        }
        if self.0 & 0x0000_0002 != 0 {
            names.push("hidden");
        }
        if self.0 & 0x0000_0004 != 0 {
            names.push("system");
        }
        if self.0 & 0x0000_0020 != 0 {
            names.push("archive");
        }
        if self.0 & 0x0000_0080 != 0 {
            names.push("normal");
        }
        if self.0 & 0x0000_0100 != 0 {
            names.push("temporary");
        }
        if self.0 & 0x0000_0200 != 0 {
            names.push("sparse_file");
        }
        if self.0 & 0x0000_0400 != 0 {
            names.push("reparse_point");
        }
        if self.0 & 0x0000_0800 != 0 {
            names.push("compressed");
        }
        if self.0 & 0x0000_1000 != 0 {
            names.push("offline");
        }
        if self.0 & 0x0000_2000 != 0 {
            names.push("not_content_indexed");
        }
        if self.0 & 0x0000_4000 != 0 {
            names.push("encrypted");
        }
        names
    }
}

/// ShowCommand（[MS-SHLLINK] §2.1.4）。
///
/// Windows の SW_* 定数に相当。未知値は文字列化せず数値で記録する。
pub fn show_command_name(cmd: u32) -> &'static str {
    match cmd {
        1 => "normal",
        3 => "maximized",
        7 => "min_no_active",
        _ => "unknown",
    }
}

/// Header 解析の error（規範 §9.2: 破損時は panic しない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// snapshot が Header サイズに満たない（truncated）。
    TooShort,
    /// HeaderSize が期待値と異なる（[MS-SHLLINK] §2.1）。
    UnexpectedHeaderSize(u32),
    /// LinkCLSID が一致しない（[MS-SHLLINK] §2.1: この形式ではない）。
    ClsidMismatch,
    /// Reserved1/2/3 が非ゼロ（[MS-SHLLINK] §2.1: 0 でなければならない）。
    ReservedFieldNonZero,
}

/// 解析済みの Shell Link Header。
#[derive(Clone, Debug)]
pub struct ShellLinkHeader {
    pub header_size: u32,
    pub flags: LinkFlags,
    pub file_attributes: FileAttributes,
    pub creation_time: u64,
    pub access_time: u64,
    pub write_time: u64,
    pub file_size: u32,
    pub icon_index: i32,
    pub show_command: u32,
    pub hot_key: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl ShellLinkHeader {
    /// 先頭 76 byte から Header を解析する。
    pub fn parse(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes.len() < HEADER_BYTES {
            return Err(HeaderError::TooShort);
        }

        let header_size = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if header_size != EXPECTED_HEADER_SIZE {
            // 拡張 Header の可能性もあるが、[MS-SHLLINK] v10.0 では 0x4C 固定。
            return Err(HeaderError::UnexpectedHeaderSize(header_size));
        }

        let clsid: [u8; 16] = bytes[4..20].try_into().unwrap();
        if clsid != LINK_CLSID {
            return Err(HeaderError::ClsidMismatch);
        }

        let flags = LinkFlags::from_le_bytes(bytes[20..24].try_into().unwrap());
        let file_attributes = FileAttributes::from_le_bytes(bytes[24..28].try_into().unwrap());
        let creation_time = u64::from_le_bytes(bytes[28..36].try_into().unwrap());
        let access_time = u64::from_le_bytes(bytes[36..44].try_into().unwrap());
        let write_time = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
        let file_size = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let icon_index = i32::from_le_bytes(bytes[56..60].try_into().unwrap());
        let show_command = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
        let hot_key = u16::from_le_bytes(bytes[64..66].try_into().unwrap());
        let reserved1 = u16::from_le_bytes(bytes[66..68].try_into().unwrap());
        let reserved2 = u32::from_le_bytes(bytes[68..72].try_into().unwrap());
        let reserved3 = u32::from_le_bytes(bytes[72..76].try_into().unwrap());

        // Reserved は仕様で 0 固定。非ゼロは形式異常とみなす（既知形式として推測しない）。
        if reserved1 != 0 || reserved2 != 0 || reserved3 != 0 {
            return Err(HeaderError::ReservedFieldNonZero);
        }

        Ok(ShellLinkHeader {
            header_size,
            flags,
            file_attributes,
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_command,
            hot_key,
            reserved1,
            reserved2,
            reserved3,
        })
    }

    /// CreationTime を `DateTime<Utc>` へ。`0` は `None`。
    pub fn creation_datetime(&self) -> Option<DateTime<Utc>> {
        filetime_to_datetime(self.creation_time)
    }
    /// AccessTime を `DateTime<Utc>` へ。`0` は `None`。
    pub fn access_datetime(&self) -> Option<DateTime<Utc>> {
        filetime_to_datetime(self.access_time)
    }
    /// WriteTime を `DateTime<Utc>` へ。`0` は `None`。
    pub fn write_datetime(&self) -> Option<DateTime<Utc>> {
        filetime_to_datetime(self.write_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 正常 Header の byte 列を構築する。
    fn build_header(flags: u32) -> Vec<u8> {
        let creation_dt: chrono::DateTime<chrono::Utc> = "2026-08-10T01:15:20Z".parse().unwrap();
        let creation_ft = (creation_dt.timestamp() + 11_644_473_600) as u64 * 10_000_000;
        let mut buf = Vec::with_capacity(HEADER_BYTES);
        buf.extend_from_slice(&EXPECTED_HEADER_SIZE.to_le_bytes()); // HeaderSize
        buf.extend_from_slice(&LINK_CLSID); // CLSID
        buf.extend_from_slice(&flags.to_le_bytes()); // Flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        buf.extend_from_slice(&creation_ft.to_le_bytes()); // CreationTime
        buf.extend_from_slice(&0u64.to_le_bytes()); // AccessTime
        buf.extend_from_slice(&0u64.to_le_bytes()); // WriteTime
        buf.extend_from_slice(&1234u32.to_le_bytes()); // FileSize
        buf.extend_from_slice(&0i32.to_le_bytes()); // IconIndex
        buf.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand (normal)
        buf.extend_from_slice(&0u16.to_le_bytes()); // HotKey
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
        assert_eq!(buf.len(), HEADER_BYTES);
        buf
    }

    #[test]
    fn parse_valid_header() {
        let bytes = build_header(0x0000_0083); // HasLinkTargetIDList | HasLinkInfo | IsUnicode
        let header = ShellLinkHeader::parse(&bytes).unwrap();
        assert_eq!(header.header_size, EXPECTED_HEADER_SIZE);
        assert!(header.flags.has_link_target_id_list());
        assert!(header.flags.has_link_info());
        assert!(header.flags.is_unicode());
        assert_eq!(header.file_size, 1234);
        assert_eq!(header.show_command, 1);
        assert_eq!(
            header
                .creation_datetime()
                .unwrap()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            "2026-08-10T01:15:20Z"
        );
        assert!(header.access_datetime().is_none());
        assert!(header.write_datetime().is_none());
    }

    #[test]
    fn parse_too_short() {
        // 規範 §9.2: truncated で panic しない。
        let bytes = [0u8; 50];
        let err = ShellLinkHeader::parse(&bytes).unwrap_err();
        assert_eq!(err, HeaderError::TooShort);
    }

    #[test]
    fn parse_bad_header_size() {
        // 既知形式として推測しない（AGENTS.md 禁止事項）。
        let mut bytes = build_header(0);
        bytes[0..4].copy_from_slice(&0x0000_0050u32.to_le_bytes()); // 80
        let err = ShellLinkHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, HeaderError::UnexpectedHeaderSize(0x50)));
    }

    #[test]
    fn parse_bad_clsid() {
        let mut bytes = build_header(0);
        bytes[4] = 0xFF; // CLSID を壊す
        let err = ShellLinkHeader::parse(&bytes).unwrap_err();
        assert_eq!(err, HeaderError::ClsidMismatch);
    }

    #[test]
    fn parse_nonzero_reserved() {
        let mut bytes = build_header(0);
        bytes[66..68].copy_from_slice(&1u16.to_le_bytes()); // Reserved1
        let err = ShellLinkHeader::parse(&bytes).unwrap_err();
        assert_eq!(err, HeaderError::ReservedFieldNonZero);
    }

    #[test]
    fn linkflags_unknown_bits_detected() {
        // 未知 bit は検出される。
        let flags = LinkFlags(0xFFFF_FFFF);
        assert_ne!(flags.unknown_bits(), 0);
        // 既知 bit だけなら unknown_bits は 0。
        let known = LinkFlags(0x0000_01FF | 0x0008_0000);
        assert_eq!(known.unknown_bits(), 0);
    }

    #[test]
    fn show_command_name_known_values() {
        assert_eq!(show_command_name(1), "normal");
        assert_eq!(show_command_name(3), "maximized");
        assert_eq!(show_command_name(7), "min_no_active");
        assert_eq!(show_command_name(99), "unknown");
    }

    #[test]
    fn file_attributes_decode() {
        let attrs = FileAttributes(0x0000_0021); // read_only | archive
        let names = attrs.known_flag_names();
        assert!(names.contains(&"read_only"));
        assert!(names.contains(&"archive"));
    }
}
