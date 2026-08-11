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
    make_artifact_with_source(evidence, parser_id, parser_version, ArtifactSource::Lnk)
}

/// ArtifactSource を明示指定する版の [`make_artifact`]。
pub fn make_artifact_with_source(
    evidence: &EvidenceItem,
    parser_id: &str,
    parser_version: &str,
    source: ArtifactSource,
) -> ArtifactInstance {
    let artifact_id = id::artifact_id(
        &evidence.evidence_id,
        source.as_str(),
        parser_id,
        parser_version,
    );
    ArtifactInstance {
        artifact_id,
        evidence_id: evidence.evidence_id.clone(),
        artifact_type: source,
        parser_id: parser_id.to_string(),
        parser_version: parser_version.to_string(),
        probe_result: ProbeResult::Confirmed,
        detection_reasons: vec!["fixture".to_string()],
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

// ============================================================
// Prefetch fixture（合成・libyal PF format 準拠）
// ============================================================

/// Prefetch header 固定長（byte・全 version 共通）。
pub const PF_HEADER_BYTES: usize = 84;

/// 合成 Prefetch fixture の構築 option。
#[derive(Clone, Debug)]
pub struct PrefetchFixtureOptions {
    /// Format version（17/23/26/30/31）。
    pub version: u32,
    /// Executable filename。
    pub executable: String,
    /// Prefetch hash。
    pub prefetch_hash: u32,
    /// Last run time（FILETIME）。v17/v23 は [0] のみ使用。v26+ は先頭8個。
    pub last_run_filetimes: Vec<u64>,
    /// Run count。
    pub run_count: u32,
    /// 参照 file/directory 一覧（filename strings へ生成）。
    pub referenced_files: Vec<String>,
    /// Volume device path（例: `\DEVICE\HARDDISKVOLUME1`）。None で volume 無し。
    pub volume_device_path: Option<String>,
    /// Volume serial number。
    pub volume_serial: u32,
}

impl Default for PrefetchFixtureOptions {
    fn default() -> Self {
        PrefetchFixtureOptions {
            version: 31,
            executable: "NOTEPAD.EXE".to_string(),
            prefetch_hash: 0x1234ABCD,
            last_run_filetimes: vec![],
            run_count: 0,
            referenced_files: vec![],
            volume_device_path: Some("\\DEVICE\\HARDDISKVOLUME1".to_string()),
            volume_serial: 0xAABBCCDD,
        }
    }
}

/// version に応じた file information block の想定 size（byte）。
fn pf_fileinfo_len(version: u32) -> usize {
    match version {
        17 => 68,
        23 => 156,
        26 | 30 | 31 => 220,
        _ => 220,
    }
}

/// version に応じた file metrics entry size。
fn pf_metrics_entry_len(version: u32) -> usize {
    match version {
        17 => 20,
        _ => 32,
    }
}

/// version に応じた volume entry size。
fn pf_volume_entry_len(version: u32) -> usize {
    match version {
        17 => 40,
        23 | 26 => 104,
        30 | 31 => 96,
        _ => 96,
    }
}

/// 合成 Prefetch bytes を構築する（libyal PF format 準拠・hand-crafted）。
///
/// 実 Windows 環境の生成物ではないため、fixture 管理方針へは
/// 「合成（hand-crafted, libyal PF format 準拠）」として記録する。
pub fn build_prefetch_fixture(opts: &PrefetchFixtureOptions) -> Vec<u8> {
    let version = opts.version;
    let fileinfo_len = pf_fileinfo_len(version);
    let entry_len = pf_metrics_entry_len(version);
    let vol_entry_len = pf_volume_entry_len(version);

    // === filename strings block を構築（参照 file 一覧） ===
    let mut strings_block: Vec<u8> = Vec::new();
    let mut filename_offsets: Vec<u32> = Vec::with_capacity(opts.referenced_files.len());
    for f in &opts.referenced_files {
        filename_offsets.push(strings_block.len() as u32);
        for u in f.encode_utf16() {
            strings_block.extend_from_slice(&u.to_le_bytes());
        }
        strings_block.extend_from_slice(&0u16.to_le_bytes()); // null 終端
    }
    let filename_chars: Vec<u32> = opts
        .referenced_files
        .iter()
        .map(|f| f.encode_utf16().count() as u32)
        .collect();

    // === volume device path 文字列 ===
    let device_path_units: Vec<u16> = opts
        .volume_device_path
        .as_deref()
        .map(|p| p.encode_utf16().collect())
        .unwrap_or_default();
    let device_path_bytes: Vec<u8> = device_path_units
        .iter()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let has_volume = opts.volume_device_path.is_some();

    // === offset 計算 ===
    let metrics_offset = (PF_HEADER_BYTES + fileinfo_len) as u32;
    let metrics_block_len = (opts.referenced_files.len() * entry_len) as u32;
    let filename_strings_offset = metrics_offset + metrics_block_len;
    let filename_strings_size = strings_block.len() as u32;
    let volumes_offset = filename_strings_offset + filename_strings_size;
    let volumes_block_len = if has_volume {
        (vol_entry_len + device_path_bytes.len()) as u32
    } else {
        0
    };
    let volumes_size = volumes_block_len;
    let file_size = volumes_offset + volumes_block_len;

    let mut buf: Vec<u8> = Vec::new();

    // === header (84 byte) ===
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(b"SCCA");
    buf.extend_from_slice(&0u32.to_le_bytes()); // unknown
    buf.extend_from_slice(&file_size.to_le_bytes());
    // executable filename (60 byte UTF-16LE)
    let mut exec_buf = [0u8; 60];
    for (i, u) in opts.executable.encode_utf16().take(29).enumerate() {
        exec_buf[2 * i..2 * i + 2].copy_from_slice(&u.to_le_bytes());
    }
    buf.extend_from_slice(&exec_buf);
    buf.extend_from_slice(&opts.prefetch_hash.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // unknown flags
    assert_eq!(buf.len(), PF_HEADER_BYTES);

    // === file information block ===
    let fi_start = buf.len();
    buf.resize(buf.len() + fileinfo_len, 0);
    let fi = &mut buf[fi_start..fi_start + fileinfo_len];
    // 共通 field
    fi[0..4].copy_from_slice(&metrics_offset.to_le_bytes());
    fi[4..8].copy_from_slice(&(opts.referenced_files.len() as u32).to_le_bytes());
    // trace chains offset = metrics_offset の直後ではなく、filename strings の後等。
    // 本 fixture では trace chain は空でよいが、offset は妥当値へ。
    fi[8..12].copy_from_slice(&filename_strings_offset.to_le_bytes()); // trace chains offset（参考）
    fi[12..16].copy_from_slice(&0u32.to_le_bytes()); // trace chains count
    fi[16..20].copy_from_slice(&filename_strings_offset.to_le_bytes());
    fi[20..24].copy_from_slice(&filename_strings_size.to_le_bytes());
    fi[24..28].copy_from_slice(&volumes_offset.to_le_bytes());
    fi[28..32].copy_from_slice(&(if has_volume { 1u32 } else { 0u32 }).to_le_bytes());
    fi[32..36].copy_from_slice(&volumes_size.to_le_bytes());
    // last run time と run count は version 毎に offset が異なる。
    match version {
        17 => {
            if let Some(&t) = opts.last_run_filetimes.first() {
                fi[36..44].copy_from_slice(&t.to_le_bytes());
            }
            fi[60..64].copy_from_slice(&opts.run_count.to_le_bytes());
        }
        23 => {
            if let Some(&t) = opts.last_run_filetimes.first() {
                fi[44..52].copy_from_slice(&t.to_le_bytes());
            }
            fi[68..72].copy_from_slice(&opts.run_count.to_le_bytes());
        }
        _ => {
            // v26/v30/v31: offset 44 に8個。
            for (i, &t) in opts.last_run_filetimes.iter().take(8).enumerate() {
                let o = 44 + i * 8;
                fi[o..o + 8].copy_from_slice(&t.to_le_bytes());
            }
            fi[124..128].copy_from_slice(&opts.run_count.to_le_bytes());
        }
    }

    // === file metrics array ===
    for (i, _) in opts.referenced_files.iter().enumerate() {
        let entry_start = buf.len();
        buf.resize(buf.len() + entry_len, 0);
        let e = &mut buf[entry_start..entry_start + entry_len];
        let foff = filename_offsets[i];
        let fchars = filename_chars[i];
        if version == 17 {
            // [0..4] trace chain idx, [4..8] trace count, [8..12] filename off, [12..16] chars, [16..20] flags
            e[8..12].copy_from_slice(&foff.to_le_bytes());
            e[12..16].copy_from_slice(&fchars.to_le_bytes());
        } else {
            // [12..16] filename off, [16..20] chars
            e[12..16].copy_from_slice(&foff.to_le_bytes());
            e[16..20].copy_from_slice(&fchars.to_le_bytes());
        }
    }

    // === filename strings block ===
    buf.extend_from_slice(&strings_block);

    // === volumes information block ===
    if has_volume {
        let vol_entry_start = buf.len();
        buf.resize(buf.len() + vol_entry_len, 0);
        let ve = &mut buf[vol_entry_start..vol_entry_start + vol_entry_len];
        let path_offset = vol_entry_len as u32; // entry の直後
        let path_chars = device_path_units.len() as u32;
        ve[0..4].copy_from_slice(&path_offset.to_le_bytes());
        ve[4..8].copy_from_slice(&path_chars.to_le_bytes());
        ve[8..16].copy_from_slice(
            &(opts.last_run_filetimes.first().copied().unwrap_or(0)).to_le_bytes(),
        );
        ve[16..20].copy_from_slice(&opts.volume_serial.to_le_bytes());
        // device path 文字列
        buf.extend_from_slice(&device_path_bytes);
    }

    assert_eq!(buf.len() as u32, file_size, "file_size と実 size が一致");
    buf
}

/// MAM 圧縮 Prefetch fixture を構築する（literal-only XPRESS Huffman）。
///
/// `uncompressed`（非圧縮 Prefetch bytes）を literal-only で圧縮し、MAM header で包む。
/// 本圧縮器は test 用の literal-only 実装（match を使わない）。
pub fn build_mam_prefetch_fixture(uncompressed: &[u8]) -> Vec<u8> {
    let compressed = compress_literal_only_xpress_huffman(uncompressed);
    let mut mam = Vec::with_capacity(8 + compressed.len());
    mam.extend_from_slice(b"MAM\x04");
    mam.extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
    mam.extend_from_slice(&compressed);
    mam
}

/// literal-only XPRESS Huffman 圧縮（test 用）。
///
/// 全256 literal へ code 長8を割り当て、各 byte を8 bit で符号化する。
/// match symbol（256-511）は code 長0（不使用）。展開器の literal path と完全対応する。
fn compress_literal_only_xpress_huffman(input: &[u8]) -> Vec<u8> {
    let mut writer = XpressBitWriter::new();
    // 表（256 byte = 512 nibble）: symbol 0-255 は長さ8、256-511 は長さ0。
    for _ in 0..128 {
        writer.write_bits(4, 8);
        writer.write_bits(4, 8);
    }
    for _ in 0..128 {
        writer.write_bits(4, 0);
        writer.write_bits(4, 0);
    }
    for &b in input {
        writer.write_bits(8, b as u32);
    }
    writer.finish()
}

/// MSB-first で 16-bit LE word へ bit を詰める writer。
struct XpressBitWriter {
    out: Vec<u8>,
    word: u16,
    bit_pos: u8,
}

impl XpressBitWriter {
    fn new() -> Self {
        XpressBitWriter {
            out: Vec::new(),
            word: 0,
            bit_pos: 0,
        }
    }
    fn write_bits(&mut self, n: u8, value: u32) {
        for i in (0..n).rev() {
            let bit = (value >> i) & 1;
            self.word |= (bit as u16) << (15 - self.bit_pos);
            self.bit_pos += 1;
            if self.bit_pos == 16 {
                self.out.extend_from_slice(&self.word.to_le_bytes());
                self.word = 0;
                self.bit_pos = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.out.extend_from_slice(&self.word.to_le_bytes());
        }
        self.out
    }
}

// ============================================================
// USN Journal fixture（合成・Microsoft USN_RECORD 準拠）
// ============================================================

/// USN_RECORD_V2 固定部（filename 領域を含まない）。
pub const USN_V2_FIXED_BYTES: usize = 60;
/// USN_RECORD_V3 固定部（filename 領域を含まない）。
pub const USN_V3_FIXED_BYTES: usize = 76;
/// USN_RECORD_V4 固定部（filename 無し）。
pub const USN_V4_FIXED_BYTES: usize = 84;

/// 合成 USN_RECORD_V2 を1件構築する（hand-crafted・Microsoft 仕様準拠）。
///
/// `name` は UTF-16LE + null 終端で格納される。record_length は固定部 + name を自動計算。
#[allow(clippy::too_many_arguments)]
pub fn build_usn_v2_record(
    file_ref: u64,
    parent_ref: u64,
    usn: i64,
    time_filetime: u64,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    name: &str,
) -> Vec<u8> {
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let name_len_with_null = (name_bytes.len() + 2) as u16;
    let total = USN_V2_FIXED_BYTES + name_bytes.len() + 2;
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&2u16.to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..16].copy_from_slice(&file_ref.to_le_bytes());
    buf[16..24].copy_from_slice(&parent_ref.to_le_bytes());
    buf[24..32].copy_from_slice(&usn.to_le_bytes());
    buf[32..40].copy_from_slice(&time_filetime.to_le_bytes());
    buf[40..44].copy_from_slice(&reason.to_le_bytes());
    buf[44..48].copy_from_slice(&source_info.to_le_bytes());
    buf[48..52].copy_from_slice(&security_id.to_le_bytes());
    buf[52..56].copy_from_slice(&file_attributes.to_le_bytes());
    buf[56..58].copy_from_slice(&name_len_with_null.to_le_bytes());
    buf[58..60].copy_from_slice(&(USN_V2_FIXED_BYTES as u16).to_le_bytes());
    buf[USN_V2_FIXED_BYTES..USN_V2_FIXED_BYTES + name_bytes.len()].copy_from_slice(&name_bytes);
    buf
}

/// 合成 USN_RECORD_V3 を1件構築する。128-bit file reference を切り詰めず保持。
#[allow(clippy::too_many_arguments)]
pub fn build_usn_v3_record(
    file_ref: [u8; 16],
    parent_ref: [u8; 16],
    usn: i64,
    time_filetime: u64,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    name: &str,
) -> Vec<u8> {
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let name_len_with_null = (name_bytes.len() + 2) as u16;
    let total = USN_V3_FIXED_BYTES + name_bytes.len() + 2;
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&3u16.to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..24].copy_from_slice(&file_ref);
    buf[24..40].copy_from_slice(&parent_ref);
    buf[40..48].copy_from_slice(&usn.to_le_bytes());
    buf[48..56].copy_from_slice(&time_filetime.to_le_bytes());
    buf[56..60].copy_from_slice(&reason.to_le_bytes());
    buf[60..64].copy_from_slice(&source_info.to_le_bytes());
    buf[64..68].copy_from_slice(&security_id.to_le_bytes());
    buf[68..72].copy_from_slice(&file_attributes.to_le_bytes());
    buf[72..74].copy_from_slice(&name_len_with_null.to_le_bytes());
    buf[74..76].copy_from_slice(&(USN_V3_FIXED_BYTES as u16).to_le_bytes());
    buf[USN_V3_FIXED_BYTES..USN_V3_FIXED_BYTES + name_bytes.len()].copy_from_slice(&name_bytes);
    buf
}

/// 合成 USN_RECORD_V4 を1件構築する（filename 無し、range tracking 保持）。
#[allow(clippy::too_many_arguments)]
pub fn build_usn_v4_record(
    file_ref: [u8; 16],
    parent_ref: [u8; 16],
    usn: i64,
    time_filetime: u64,
    reason: u32,
    source_info: u32,
    remaining_extents: u16,
    number_of_extents: u16,
    extent_location: u64,
    extent_length: u64,
) -> Vec<u8> {
    let total = USN_V4_FIXED_BYTES;
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&4u16.to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..24].copy_from_slice(&file_ref);
    buf[24..40].copy_from_slice(&parent_ref);
    buf[40..48].copy_from_slice(&usn.to_le_bytes());
    buf[48..56].copy_from_slice(&time_filetime.to_le_bytes());
    buf[56..60].copy_from_slice(&reason.to_le_bytes());
    buf[60..64].copy_from_slice(&source_info.to_le_bytes());
    buf[64..66].copy_from_slice(&remaining_extents.to_le_bytes());
    buf[66..68].copy_from_slice(&number_of_extents.to_le_bytes());
    buf[68..76].copy_from_slice(&extent_location.to_le_bytes());
    buf[76..84].copy_from_slice(&extent_length.to_le_bytes());
    buf
}

/// USN reason bit field（`USN_RECORD_*::Reason`）の test 用定数。
pub mod usn_reason {
    pub const DATA_OVERWRITE: u32 = 0x0000_0001;
    pub const DATA_EXTEND: u32 = 0x0000_0002;
    pub const DATA_TRUNCATION: u32 = 0x0000_0004;
    pub const FILE_CREATE: u32 = 0x0000_0100;
    pub const FILE_DELETE: u32 = 0x0000_0200;
    pub const SECURITY_CHANGE: u32 = 0x0000_0800;
    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
    pub const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    pub const CLOSE: u32 = 0x8000_0000;
}

/// 与えた filetime が「2026-08-10T01:15:20Z + offset_seconds」へ相当するものを返す。
/// （`filetime_from_unix_offset` と同一。USN test 用の別名。）
pub fn usn_filetime_from_unix_offset(offset_seconds: i64) -> u64 {
    filetime_from_unix_offset(offset_seconds)
}
