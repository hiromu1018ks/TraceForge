//! 統合テスト共通ヘルパー。
//!
//! 合成 LNK fixture の生成、EvidenceItem / ArtifactInstance の構築、
//! M2 縦割り（snapshot → parse → EventStore → JSONL 出力）の補助を提供する。
//!
//! 各統合テストファイルが独立 crate としてコンパイルされるため、ファイル毎に
//! 使われない要素が出る。そのため本モジュール全体で `dead_code` を許可する。

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::ArtifactSource;
use tf_core::id;
use tf_evidence::snapshot::{self, SnapshotOutcome};

/// テスト用 LNK HeaderSize 定数（[MS-SHLLINK] §2.1: 0x4C = 76）。
pub const HEADER_BYTES: usize = 76;
/// LNK CLSID（[MS-SHLLINK] §2.1）。
pub const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
pub const MS_SHLLINK_REFERENCE: &str = "[MS-SHLLINK] v10.0";

/// 合成 LNK fixture の構築オプション。
#[derive(Clone, Debug)]
pub struct LnkFixtureOptions {
    pub flags: u32,
    pub creation_filetime: u64,
    pub access_filetime: u64,
    pub write_filetime: u64,
    pub file_size: u32,
    /// StringData を付加するか（name のみ最小）。
    pub with_name_string: bool,
    /// LinkInfo を付加するか（local base path 含む）。flags の HasLinkInfo bit と合わせて使う。
    pub local_base_path: Option<String>,
    /// ExtraData terminal block を付加するか。
    pub with_extra_data: bool,
}

impl Default for LnkFixtureOptions {
    fn default() -> Self {
        LnkFixtureOptions {
            flags: 0,
            creation_filetime: 0,
            access_filetime: 0,
            write_filetime: 0,
            file_size: 0,
            with_name_string: false,
            local_base_path: None,
            with_extra_data: true,
        }
    }
}

/// 与えた filetime が「2026-08-10T01:15:20Z + offset_seconds」へ相当するものを返す。
pub fn filetime_from_unix_offset(offset_seconds: i64) -> u64 {
    let dt: chrono::DateTime<chrono::Utc> = "2026-08-10T01:15:20Z".parse().unwrap();
    ((dt.timestamp() + offset_seconds) + 11_644_473_600) as u64 * 10_000_000
}

/// 合成 LNK bytes を構築する。
///
/// 仕様 [MS-SHLLINK] へ準拠した hand-crafted データ。実 Windows 環境の生成物ではないため、
/// fixture 管理方針へは「合成（hand-crafted, [MS-SHLLINK] 準拠）」として記録する。
pub fn build_lnk_fixture(opts: &LnkFixtureOptions) -> Vec<u8> {
    let mut buf = Vec::new();

    // --- Shell Link Header (76 byte) ---
    buf.extend_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    buf.extend_from_slice(&LINK_CLSID);
    buf.extend_from_slice(&opts.flags.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
    buf.extend_from_slice(&opts.creation_filetime.to_le_bytes());
    buf.extend_from_slice(&opts.access_filetime.to_le_bytes());
    buf.extend_from_slice(&opts.write_filetime.to_le_bytes());
    buf.extend_from_slice(&opts.file_size.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes()); // IconIndex
    buf.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand (normal)
    buf.extend_from_slice(&0u16.to_le_bytes()); // HotKey
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
    buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    assert_eq!(buf.len(), HEADER_BYTES);

    // --- LinkTargetIDList (flag があれば) ---
    if opts.flags & 0x0000_0001 != 0 {
        // 最小 IDList: ItemID 1個 + TerminalID。
        let item_id: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let id_list_size: u16 = (2 + item_id.len() as u16) + 2; // ItemIDSize + item + TerminalID
        buf.extend_from_slice(&id_list_size.to_le_bytes());
        buf.extend_from_slice(&(item_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(item_id);
        buf.extend_from_slice(&0u16.to_le_bytes()); // TerminalID
    }

    // --- LinkInfo (flag があれば、force_no_link_info が無ければ) ---
    if opts.flags & 0x0000_0002 != 0 && opts.flags & 0x0000_0100 == 0 {
        if let Some(base) = &opts.local_base_path {
            // 最小 v1 LinkInfo: header 28 byte + VolumeID(4) + LocalBasePath(null) + CommonPathSuffix(null)
            let header_size: u32 = 0x1C;
            let volume_id_offset: u32 = header_size;
            let volume_id_size: u32 = 4;
            let local_base_offset: u32 = volume_id_offset + volume_id_size;
            let local_base_with_null = format!("{base}\0");
            let suffix_offset: u32 = local_base_offset + local_base_with_null.len() as u32;
            let suffix_with_null = "\0"; // 空 CommonPathSuffix
            let total_size: u32 = suffix_offset + suffix_with_null.len() as u32;

            buf.extend_from_slice(&total_size.to_le_bytes());
            buf.extend_from_slice(&header_size.to_le_bytes());
            buf.extend_from_slice(&0x01u32.to_le_bytes()); // Flags: VolumeIDAndLocalBasePath
            buf.extend_from_slice(&volume_id_offset.to_le_bytes());
            buf.extend_from_slice(&local_base_offset.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
            buf.extend_from_slice(&suffix_offset.to_le_bytes());
            buf.extend_from_slice(&volume_id_size.to_le_bytes()); // VolumeID dummy
            buf.extend_from_slice(local_base_with_null.as_bytes());
            buf.extend_from_slice(suffix_with_null.as_bytes());
        } else {
            // LocalBasePath 無しの最小 LinkInfo（header のみ + 空 CommonPathSuffix）。
            let header_size: u32 = 0x1C;
            let suffix_offset: u32 = header_size;
            let suffix_with_null = "\0";
            let total_size: u32 = suffix_offset + suffix_with_null.len() as u32;
            buf.extend_from_slice(&total_size.to_le_bytes());
            buf.extend_from_slice(&header_size.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // Flags: なし
            buf.extend_from_slice(&0u32.to_le_bytes()); // VolumeIDOffset
            buf.extend_from_slice(&0u32.to_le_bytes()); // LocalBasePathOffset
            buf.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
            buf.extend_from_slice(&suffix_offset.to_le_bytes());
            buf.extend_from_slice(suffix_with_null.as_bytes());
        }
    }

    // --- StringData (flags に応じて) ---
    if opts.with_name_string || opts.flags & 0x0000_0004 != 0 {
        // NAME_STRING。IsUnicode なら UTF-16LE。
        let is_unicode = opts.flags & 0x0000_0080 != 0;
        let name = "shortcut_name";
        if is_unicode {
            buf.extend_from_slice(&(name.encode_utf16().count() as u16).to_le_bytes());
            for ch in name.encode_utf16() {
                buf.extend_from_slice(&ch.to_le_bytes());
            }
        } else {
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
        }
    }
    // 他の StringData（relative_path 等）は最小 fixture では省略。

    // --- ExtraData terminal block ---
    if opts.with_extra_data {
        buf.extend_from_slice(&0u32.to_le_bytes()); // TerminalBlock
    }

    buf
}

/// snapshot を作成し、EvidenceItem と snapshot path を返す。
pub fn make_snapshot(
    source_locator: &str,
    lnk_bytes: &[u8],
    temp_dir: &Path,
) -> (EvidenceItem, PathBuf) {
    let source_dir = temp_dir.join("source");
    let snapshot_dir = temp_dir.join("snapshots");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&snapshot_dir).unwrap();

    let source_name = source_locator.rsplit('/').next().unwrap_or("test.lnk");
    let source_path = source_dir.join(source_name);
    std::fs::write(&source_path, lnk_bytes).unwrap();

    let outcome: SnapshotOutcome =
        snapshot::snapshot(source_locator, &source_path, &snapshot_dir).unwrap();
    (outcome.evidence, outcome.snapshot_path)
}

/// EvidenceItem と Parser 情報から ArtifactInstance を構築する。
pub fn make_artifact(
    evidence: &EvidenceItem,
    parser_id: &str,
    parser_version: &str,
) -> ArtifactInstance {
    let artifact_id = id::artifact_id(
        &evidence.evidence_id,
        ArtifactSource::Lnk.as_str(),
        parser_id,
        parser_version,
    );
    ArtifactInstance {
        artifact_id,
        evidence_id: evidence.evidence_id.clone(),
        artifact_type: ArtifactSource::Lnk,
        parser_id: parser_id.to_string(),
        parser_version: parser_version.to_string(),
        probe_result: ProbeResult::Confirmed,
        detection_reasons: vec!["clsid".to_string()],
        parse_status: ParseStatus::Complete,
    }
}

/// fixture bytes の SHA-256 lowercase hex を計算する（互換 §12-5: 記録用）。
pub fn sha256_hex(bytes: &[u8]) -> String {
    tf_core::hash::sha256_hex(bytes)
}

/// テスト用 VerifiedSnapshot EvidenceItem を手構築する（snapshot file を使わない簡易版）。
///
/// 主に probe の単体検証用。`parse` の検証では [`make_snapshot`] を使うこと。
#[allow(dead_code)]
pub fn dummy_evidence(snapshot_locator: &str, size: u64, sha256: &str) -> EvidenceItem {
    EvidenceItem {
        evidence_id: id::evidence_id("dummy.lnk", size, sha256),
        source_locator: "dummy.lnk".to_string(),
        size,
        sha256: sha256.to_string(),
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: snapshot_locator.to_string(),
    }
}
