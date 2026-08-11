//! USN Reason bit flag（`USN_RECORD_*::Reason`）の解釈（互換 §4.3）。
//!
//! Microsoft 公式の `USN_RECORD_V2` / `USN_RECORD_V3` / `USN_RECORD_V4` は共通の
//! `Reason` bit field（`DWORD` = `u32`）を持ち、各 bit がファイルシステム変更の
//! 種別を示す。本 module は bit 値を人の読める flag 名の配列へ変換する。
//!
//! V4 でのみ現れる bit（`USN_REASON_TRANSACTED_CHANGE` 等）も含むが、V2/V3 で
//! これらの bit が立っていた場合でも「未知の bit」として黙って無視せず、
//! bit 値を16進で残す設計とはしない（互換 §12-7: 非対応要素を黙殺しない）。
//! 代わりに既知の bit のみ名前付きで列挙し、未知 bit は合計値を `unknown_bits` 属性へ別途保存する。

/// Reason bit field の各 flag 定義。
pub mod flags {
    /// `0x00000001` — ファイルの user data stream（未名前）上書き。
    pub const DATA_OVERWRITE: u32 = 0x0000_0001;
    /// `0x00000002` — ファイルの user data stream（未名前）拡張。
    pub const DATA_EXTEND: u32 = 0x0000_0002;
    /// `0x00000004` — ファイルの user data stream（未名前）切り詰め。
    pub const DATA_TRUNCATION: u32 = 0x0000_0004;
    /// `0x00000010` — 名前付き data stream（ADS）上書き。
    pub const NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
    /// `0x00000020` — 名前付き data stream（ADS）拡張。
    pub const NAMED_DATA_EXTEND: u32 = 0x0000_0020;
    /// `0x00000040` — 名前付き data stream（ADS）切り詰め。
    pub const NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
    /// `0x00000100` — ファイル作成。
    pub const FILE_CREATE: u32 = 0x0000_0100;
    /// `0x00000200` — ファイル削除。
    pub const FILE_DELETE: u32 = 0x0000_0200;
    /// `0x00000400` — 拡張属性 (EA) 変更。
    pub const EA_CHANGE: u32 = 0x0000_0400;
    /// `0x00000800` — セキュリティ記述子変更。
    pub const SECURITY_CHANGE: u32 = 0x0000_0800;
    /// `0x00001000` — rename 元名前（OLD_NAME）。rename 結合で NEW_NAME と対応づける。
    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
    /// `0x00002000` — rename 先名前（NEW_NAME）。
    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
    /// `0x00004000` — インデックス可能 flag 変更。
    pub const INDEXABLE_CHANGE: u32 = 0x0000_4000;
    /// `0x00008000` — 基本情報（属性・時刻等）変更。
    pub const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    /// `0x00010000` — ハードリンク変更。
    pub const HARD_LINK_CHANGE: u32 = 0x0001_0000;
    /// `0x00020000` — 圧縮状態変更。
    pub const COMPRESSION_CHANGE: u32 = 0x0002_0000;
    /// `0x00040000` — 暗号化状態変更。
    pub const ENCRYPTION_CHANGE: u32 = 0x0004_0000;
    /// `0x00080000` — Object ID 変更。
    pub const OBJECT_ID_CHANGE: u32 = 0x0008_0000;
    /// `0x00100000` — Reparse point 変更。
    pub const REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
    /// `0x00200000` — 名前付き stream 変更。
    pub const STREAM_CHANGE: u32 = 0x0020_0000;
    /// `0x00400000` — トランザクション変更（V4 でのみ現れる）。
    pub const TRANSACTED_CHANGE: u32 = 0x0040_0000;
    /// `0x00800000` — 整合性 (integrity) 変更（V4 でのみ現れる）。
    pub const INTEGRITY_CHANGE: u32 = 0x0080_0000;
    /// `0x01000000` — Desired storage class 変更（V4 でのみ現れる）。
    pub const DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x0100_0000;
    /// `0x80000000` — ファイルを閉じたときに USN が close したことを示す。
    pub const CLOSE: u32 = 0x8000_0000;
}

/// 既知 flag の一覧（bit 値・flag 名の組）。bit 値の昇順。
const KNOWN_FLAGS: &[(u32, &str)] = &[
    (flags::DATA_OVERWRITE, "DATA_OVERWRITE"),
    (flags::DATA_EXTEND, "DATA_EXTEND"),
    (flags::DATA_TRUNCATION, "DATA_TRUNCATION"),
    (flags::NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
    (flags::NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND"),
    (flags::NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION"),
    (flags::FILE_CREATE, "FILE_CREATE"),
    (flags::FILE_DELETE, "FILE_DELETE"),
    (flags::EA_CHANGE, "EA_CHANGE"),
    (flags::SECURITY_CHANGE, "SECURITY_CHANGE"),
    (flags::RENAME_OLD_NAME, "RENAME_OLD_NAME"),
    (flags::RENAME_NEW_NAME, "RENAME_NEW_NAME"),
    (flags::INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
    (flags::BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
    (flags::HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
    (flags::COMPRESSION_CHANGE, "COMPRESSION_CHANGE"),
    (flags::ENCRYPTION_CHANGE, "ENCRYPTION_CHANGE"),
    (flags::OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE"),
    (flags::REPARSE_POINT_CHANGE, "REPARSE_POINT_CHANGE"),
    (flags::STREAM_CHANGE, "STREAM_CHANGE"),
    (flags::TRANSACTED_CHANGE, "TRANSACTED_CHANGE"),
    (flags::INTEGRITY_CHANGE, "INTEGRITY_CHANGE"),
    (
        flags::DESIRED_STORAGE_CLASS_CHANGE,
        "DESIRED_STORAGE_CLASS_CHANGE",
    ),
    (flags::CLOSE, "CLOSE"),
];

/// 全既知 bit の OR 和。これ以外の bit が立っていた場合は未知 bit として取り扱う。
const ALL_KNOWN_MASK: u32 = {
    let mut m = 0u32;
    let mut i = 0;
    while i < KNOWN_FLAGS.len() {
        m |= KNOWN_FLAGS[i].0;
        i += 1;
    }
    m
};

/// `Reason` bit field の解釈結果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReasonInterpretation {
    /// 立っていた既知 flag の名前（昇順・重複なし）。
    pub flags: Vec<&'static str>,
    /// 既知 flag のいずれにも属さない bit の OR 和（互換 §12-7: 黙殺しない）。
    pub unknown_bits: u32,
}

/// `Reason` bit field を解釈する。
pub fn interpret(reason: u32) -> ReasonInterpretation {
    let mut flags = Vec::new();
    for (bit, name) in KNOWN_FLAGS {
        if reason & bit != 0 {
            flags.push(*name);
        }
    }
    let unknown_bits = reason & !ALL_KNOWN_MASK;
    ReasonInterpretation {
        flags,
        unknown_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reason_has_no_flags() {
        let r = interpret(0);
        assert!(r.flags.is_empty());
        assert_eq!(r.unknown_bits, 0);
    }

    #[test]
    fn rename_old_new_combined() {
        let r = interpret(flags::RENAME_OLD_NAME | flags::RENAME_NEW_NAME);
        // bit 値昇順: RENAME_OLD_NAME (0x1000) → RENAME_NEW_NAME (0x2000)。
        assert_eq!(r.flags, vec!["RENAME_OLD_NAME", "RENAME_NEW_NAME"]);
        assert_eq!(r.unknown_bits, 0);
    }

    #[test]
    fn unknown_bits_preserved() {
        // bit 11 と bit 22 は予約/未使用。
        let unknown_only = 0x0000_0800;
        let _ = unknown_only;
        let r = interpret(0x0080_0000 | flags::CLOSE);
        // 0x0080_0000 は INTEGRITY_CHANGE として既知。
        assert!(r.flags.contains(&"INTEGRITY_CHANGE"));
        assert!(r.flags.contains(&"CLOSE"));
        assert_eq!(r.unknown_bits, 0);
    }

    #[test]
    fn truly_unknown_bit_is_reported() {
        // bit 0x02000000 は現在の Microsoft 仕様で未割当。
        let r = interpret(flags::FILE_CREATE | 0x0200_0000);
        assert!(r.flags.contains(&"FILE_CREATE"));
        assert_eq!(r.unknown_bits, 0x0200_0000);
    }
}
