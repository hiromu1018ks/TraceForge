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

// ============================================================
// EVTX fixture（合成・libyal libevtx 仕様準拠）
// ============================================================

pub use tf_parsers::evtx::binxml::{
    BinXmlBuilder, EventContentSpec, EventDataEntry, ValueKind, ev_data,
};
pub use tf_parsers::evtx::chunk::{
    CHUNK_BYTES as EVTX_CHUNK_BYTES, CHUNK_MAGIC as EVTX_CHUNK_MAGIC,
};
pub use tf_parsers::evtx::header::{EVTX_FILE_MAGIC, FILE_HEADER_BYTES as EVTX_FILE_HEADER_BYTES};
pub use tf_parsers::evtx::record::RECORD_MAGIC as EVTX_RECORD_MAGIC;

/// EVTX file header を構築する。chunk_count 個の chunk が続く前提。
pub fn build_evtx_file_header(chunk_count: u16) -> Vec<u8> {
    use tf_parsers::evtx::crc32::crc32_sequential;
    use tf_parsers::evtx::header::{EVTX_MAJOR_VERSION, EVTX_MINOR_VERSION};
    let mut buf = vec![0u8; EVTX_FILE_HEADER_BYTES];
    buf[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
    buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // first chunk
    buf[16..24].copy_from_slice(&(chunk_count as u64).to_le_bytes()); // last chunk
    buf[24..32].copy_from_slice(&0u64.to_le_bytes());
    buf[32..36].copy_from_slice(&128u32.to_le_bytes());
    buf[36..38].copy_from_slice(&EVTX_MINOR_VERSION.to_le_bytes());
    buf[38..40].copy_from_slice(&EVTX_MAJOR_VERSION.to_le_bytes());
    buf[40..42].copy_from_slice(&(EVTX_FILE_HEADER_BYTES as u16).to_le_bytes());
    buf[44..46].copy_from_slice(&chunk_count.to_le_bytes());
    let cksum = crc32_sequential(&buf[0..120], &buf[128..EVTX_FILE_HEADER_BYTES]);
    buf[124..128].copy_from_slice(&cksum.to_le_bytes());
    buf
}

/// 1件の EVTX record bytes を構築する。
pub fn build_evtx_record(record_id: u64, timestamp_ft: u64, spec: &EventContentSpec) -> Vec<u8> {
    let mut builder = BinXmlBuilder::new();
    builder.start_event(spec);
    let binxml = builder.finish();
    let size = 4 + 8 + 8 + binxml.len() + 4;
    let mut buf = Vec::with_capacity(2 + size);
    buf.extend_from_slice(&EVTX_RECORD_MAGIC);
    buf.extend_from_slice(&(size as i32).to_le_bytes());
    buf.extend_from_slice(&record_id.to_le_bytes());
    buf.extend_from_slice(&timestamp_ft.to_le_bytes());
    buf.extend_from_slice(&binxml);
    buf.extend_from_slice(&(size as i32).to_le_bytes());
    buf
}

/// 1 chunk bytes を構築する。records は可変長で、free_space_offset は自動計算。
pub fn build_evtx_chunk(records: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = vec![0u8; EVTX_CHUNK_BYTES];
    buf[0..8].copy_from_slice(&EVTX_CHUNK_MAGIC);
    buf[40..44].copy_from_slice(&512u32.to_le_bytes());
    let records_total: usize = records.iter().map(|r| r.len()).sum();
    let free_space_offset = 512 + records_total;
    buf[48..52].copy_from_slice(&(free_space_offset as u32).to_le_bytes());
    let mut records_region = Vec::new();
    for r in records {
        records_region.extend_from_slice(r);
    }
    buf[512..512 + records_region.len()].copy_from_slice(&records_region);
    let records_crc = tf_parsers::evtx::crc32::crc32(&buf[512..free_space_offset]);
    buf[52..56].copy_from_slice(&records_crc.to_le_bytes());
    buf
}

/// file 全体（header + chunks）を構築する。
pub fn build_evtx_file(records_per_chunk: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut file = build_evtx_file_header(records_per_chunk.len() as u16);
    for chunk_records in records_per_chunk {
        let chunk = build_evtx_chunk(chunk_records);
        file.extend_from_slice(&chunk);
    }
    file
}

/// Security 4624 login event の spec（test 用の代表値）。
pub fn login_4624_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
        provider_guid: None,
        event_id: 4624,
        version: Some(0),
        level: Some(0),
        channel: "Security".to_string(),
        computer: computer.to_string(),
        event_data: vec![
            ev_data("TargetUserName", "alice"),
            ev_data("LogonType", "3"),
        ],
    }
}

/// Security 4625 login_failure event の spec。
pub fn login_4625_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
        provider_guid: None,
        event_id: 4625,
        version: Some(0),
        level: Some(0),
        channel: "Security".to_string(),
        computer: computer.to_string(),
        event_data: vec![
            ev_data("TargetUserName", "attacker"),
            ev_data("LogonType", "10"),
        ],
    }
}

/// Security 4688 process_start event の spec。
pub fn process_start_4688_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
        provider_guid: None,
        event_id: 4688,
        version: Some(0),
        level: Some(0),
        channel: "Security".to_string(),
        computer: computer.to_string(),
        event_data: vec![
            ev_data("NewProcessName", "C:\\Windows\\System32\\cmd.exe"),
            ev_data("CommandLine", "/c calc.exe"),
        ],
    }
}

/// Security 4689 process_stop event の spec。
pub fn process_stop_4689_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
        provider_guid: None,
        event_id: 4689,
        version: Some(0),
        level: Some(0),
        channel: "Security".to_string(),
        computer: computer.to_string(),
        event_data: vec![ev_data("ProcessName", "C:\\Windows\\System32\\cmd.exe")],
    }
}

/// System 7045 service_create event の spec。
pub fn service_create_7045_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Service Control Manager".to_string(),
        provider_guid: None,
        event_id: 7045,
        version: None,
        level: None,
        channel: "System".to_string(),
        computer: computer.to_string(),
        event_data: vec![
            EventDataEntry {
                name: "ServiceName".into(),
                value: "MaliciousSvc".into(),
                kind: ValueKind::String,
            },
            EventDataEntry {
                name: "ImagePath".into(),
                value: "C:\\Users\\Public\\svc.exe".into(),
                kind: ValueKind::String,
            },
        ],
    }
}

/// PowerShell Operational channel の event spec（T4-044: typed mapping しない）。
pub fn powershell_operational_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Microsoft-Windows-PowerShell".to_string(),
        provider_guid: None,
        event_id: 4103,
        version: None,
        level: None,
        channel: "Microsoft-Windows-PowerShell/Operational".to_string(),
        computer: computer.to_string(),
        event_data: vec![
            ev_data("ContextInfo", "powershell context"),
            ev_data("Payload", "command data"),
        ],
    }
}

/// Sysmon Operational channel の event spec（T4-044: typed mapping しない）。
pub fn sysmon_operational_spec(computer: &str) -> EventContentSpec {
    EventContentSpec {
        provider_name: "Microsoft-Windows-Sysmon".to_string(),
        provider_guid: None,
        event_id: 1,
        version: None,
        level: None,
        channel: "Microsoft-Windows-Sysmon/Operational".to_string(),
        computer: computer.to_string(),
        event_data: vec![
            ev_data("Image", "C:\\Users\\alice\\tool.exe"),
            ev_data("CommandLine", "tool.exe -arg"),
        ],
    }
}

/// EVTX filetime helper: 2026-08-10T01:15:20Z + offset_seconds を FILETIME へ。
pub fn evtx_filetime_from_unix_offset(offset_seconds: i64) -> u64 {
    filetime_from_unix_offset(offset_seconds)
}

// ============================================================
// Registry hive fixture（合成・MS-RRMF / libyal libregf 準拠）
// ============================================================

pub use tf_parsers::registry::hive::REGF_MAGIC as REGISTRY_REGF_MAGIC;
pub use tf_parsers::registry::log::{
    LogEntry as RegistryLogEntry, build_synthetic_log as build_registry_synthetic_log,
};

/// HvLE 形式の magic（テストで "既知だが未対応" LOG の偽造に使う）。
pub fn registry_hvle_magic() -> [u8; 4] {
    *b"HvLE"
}

/// 合成 registry hive の key 仕様（再帰的な subkey を持てる）。
#[derive(Clone, Debug)]
pub struct RegistryKeySpec {
    pub name: String,
    pub last_write_filetime: u64,
    pub values: Vec<RegistryValueSpec>,
    pub subkeys: Vec<RegistryKeySpec>,
}

/// 合成 registry hive の value 仕様。
#[derive(Clone, Debug)]
pub struct RegistryValueSpec {
    pub name: String,
    pub data_type: u32,
    pub data: Vec<u8>,
}

impl RegistryValueSpec {
    /// REG_DWORD inline 値を作る（名前付き）。
    pub fn dword(name: &str, value: u32) -> Self {
        RegistryValueSpec {
            name: name.to_string(),
            data_type: 4,
            data: value.to_le_bytes().to_vec(),
        }
    }

    /// REG_SZ（UTF-16LE）値を作る。
    pub fn sz(name: &str, value: &str) -> Self {
        let bytes: Vec<u8> = value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        RegistryValueSpec {
            name: name.to_string(),
            data_type: 1,
            data: bytes,
        }
    }

    /// REG_BINARY 値を作る。
    pub fn binary(name: &str, bytes: Vec<u8>) -> Self {
        RegistryValueSpec {
            name: name.to_string(),
            data_type: 3,
            data: bytes,
        }
    }
}

impl Default for RegistryKeySpec {
    fn default() -> Self {
        RegistryKeySpec {
            name: "ROOT".to_string(),
            last_write_filetime: filetime_from_unix_offset(0),
            values: vec![],
            subkeys: vec![],
        }
    }
}

/// 合成 registry hive bytes を構築する。
///
/// base block (4096 byte) + hive bins data（key tree を直列化したもの）。
/// 実 Windows 環境の生成物ではないため、fixture 管理方針へは
/// 「合成（hand-crafted, MS-RRMF / libyal libregf 準拠）」として記録する。
pub fn build_registry_fixture(root: &RegistryKeySpec) -> Vec<u8> {
    let mut builder = RegistryFixtureBuilder::new();
    let root_offset = builder.write_subtree(root);
    builder.into_bytes_with_root(root_offset)
}

/// 合成 hive を構築し、root nk の cell offset（hive bins data 先頭からの相対）も返す。
/// LOG entry で root key の timestamp を書き換える test 等で利用する。
pub fn build_registry_fixture_with_root_offset(root: &RegistryKeySpec) -> (Vec<u8>, u32) {
    let mut builder = RegistryFixtureBuilder::new();
    let root_offset = builder.write_subtree(root);
    (builder.into_bytes_with_root(root_offset), root_offset)
}

/// 合成 LOG file bytes を構築する（replay 可能・テスト用）。
///
/// base hive bytes と同じ長さの vectr を用意し、指定した位置へ patch を当てた
/// recovered view を構築できるよう、entries を作る。
pub fn build_registry_log_fixture(entries: &[RegistryLogEntry]) -> Vec<u8> {
    build_registry_synthetic_log(entries)
}

/// 合成 hive の LOG entry を1件構築する helper。
pub fn registry_log_entry(target_offset: u32, data: Vec<u8>) -> RegistryLogEntry {
    RegistryLogEntry {
        target_offset,
        data,
    }
}

/// hive bins 内の cell 配置を順次計算する builder。
struct RegistryFixtureBuilder {
    /// base block + bins。base block は最後に先頭へ prepend する。
    bins: Vec<u8>,
    /// 書き込み cursor（次の cell の開始 offset）。4 byte 境界へ整列。
    cursor: usize,
}

impl RegistryFixtureBuilder {
    fn new() -> Self {
        // bins は 0x1000 (4096) byte 確保。必要に応じて拡張する。
        RegistryFixtureBuilder {
            bins: vec![0u8; 0x4000],
            cursor: 0,
        }
    }

    /// 4 byte 境界へ整列。
    fn align4(&mut self) {
        while !self.cursor.is_multiple_of(4) {
            self.cursor += 1;
        }
    }

    /// bins の必要 size へ拡張する。
    fn ensure(&mut self, need: usize) {
        if self.cursor + need > self.bins.len() {
            self.bins.resize(self.cursor + need + 0x1000, 0);
        }
    }

    /// cell を書き込む（size field 負値 + body）。戻り値は cell の offset。
    fn write_cell(&mut self, body: &[u8]) -> u32 {
        self.align4();
        let offset = self.cursor;
        let total_size = 4 + body.len();
        self.ensure(total_size);
        let size_field: i32 = -((body.len() as i32) + 4);
        self.bins[offset..offset + 4].copy_from_slice(&size_field.to_le_bytes());
        self.bins[offset + 4..offset + 4 + body.len()].copy_from_slice(body);
        self.cursor = offset + 4 + body.len();
        offset as u32
    }

    /// subtree を直列化し、root の nk offset を返す。
    fn write_subtree(&mut self, spec: &RegistryKeySpec) -> u32 {
        // まず values を書く。
        let mut vk_offsets: Vec<u32> = Vec::new();
        for v in &spec.values {
            let vk_offset = self.write_value(v);
            vk_offsets.push(vk_offset);
        }
        // subkeys を先に再帰的に書く（nk offset が必要）。
        let mut child_nk_offsets: Vec<u32> = Vec::new();
        for child in &spec.subkeys {
            let off = self.write_subtree(child);
            child_nk_offsets.push(off);
        }
        // value list を書く（vk_offset の配列）。
        let value_list_offset = if vk_offsets.is_empty() {
            0xFFFF_FFFF
        } else {
            let mut vlist_body = Vec::with_capacity(vk_offsets.len() * 4);
            for off in &vk_offsets {
                vlist_body.extend_from_slice(&off.to_le_bytes());
            }
            self.write_cell(&vlist_body)
        };
        // subkey list を書く（lf 形式）。
        let subkey_list_offset = if child_nk_offsets.is_empty() {
            0xFFFF_FFFF
        } else {
            let mut lf_body = vec![0u8; 4 + child_nk_offsets.len() * 8];
            lf_body[0..2].copy_from_slice(b"lf");
            lf_body[2..4].copy_from_slice(&(child_nk_offsets.len() as u16).to_le_bytes());
            for (i, off) in child_nk_offsets.iter().enumerate() {
                lf_body[4 + i * 8..4 + i * 8 + 4].copy_from_slice(&off.to_le_bytes());
                // hint 4 byte は 0 のまま
            }
            self.write_cell(&lf_body)
        };

        // 最後に root の nk を書く。
        let name_bytes: Vec<u8> = spec
            .name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut nk_body = vec![0u8; 70 + name_bytes.len()];
        nk_body[0..2].copy_from_slice(b"nk");
        nk_body[2..10].copy_from_slice(&spec.last_write_filetime.to_le_bytes());
        nk_body[18..22].copy_from_slice(&(spec.subkeys.len() as u32).to_le_bytes());
        nk_body[22..26].copy_from_slice(&subkey_list_offset.to_le_bytes());
        nk_body[28..32].copy_from_slice(&(spec.values.len() as u32).to_le_bytes());
        nk_body[32..36].copy_from_slice(&value_list_offset.to_le_bytes());
        let name_len = name_bytes.len() as u16;
        nk_body[68..70].copy_from_slice(&name_len.to_le_bytes());
        nk_body[70..70 + name_bytes.len()].copy_from_slice(&name_bytes);
        self.write_cell(&nk_body)
    }

    /// value（vk cell）を1件書く。
    fn write_value(&mut self, spec: &RegistryValueSpec) -> u32 {
        let name_bytes: Vec<u8> = spec
            .name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        // data が 4 byte 以下なら inline、それ以外は外部 data cell。
        let (data_size_raw, data_offset_raw, data_cell_offset) = if spec.data.len() <= 4 {
            // inline: data_size の MSB を立て、data_offset field へ data を pack。
            let inline_size = spec.data.len() as u32;
            let size_raw = 0x8000_0000 | inline_size;
            let mut off_bytes = [0u8; 4];
            off_bytes[..spec.data.len()].copy_from_slice(&spec.data);
            (size_raw, u32::from_le_bytes(off_bytes), None)
        } else {
            // 外部 data cell。
            let data_off = self.write_cell(&spec.data);
            (spec.data.len() as u32, data_off, Some(data_off))
        };

        let mut vk_body = vec![0u8; 20 + name_bytes.len()];
        vk_body[0..2].copy_from_slice(b"vk");
        vk_body[2..4].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        vk_body[4..8].copy_from_slice(&data_size_raw.to_le_bytes());
        vk_body[8..12].copy_from_slice(&data_offset_raw.to_le_bytes());
        vk_body[12..16].copy_from_slice(&spec.data_type.to_le_bytes());
        vk_body[20..20 + name_bytes.len()].copy_from_slice(&name_bytes);
        let vk_offset = self.write_cell(&vk_body);
        let _ = data_cell_offset;
        vk_offset
    }

    /// base block + bins bytes を構築する。root_offset は write_subtree が返した値。
    fn into_bytes_with_root(self, root_offset: u32) -> Vec<u8> {
        let bins_size = self.bins.len() as u32;
        let mut base = vec![0u8; 4096];
        base[0..4].copy_from_slice(&REGISTRY_REGF_MAGIC);
        base[20..24].copy_from_slice(&1u32.to_le_bytes()); // major
        base[24..28].copy_from_slice(&5u32.to_le_bytes()); // minor
        base[36..40].copy_from_slice(&root_offset.to_le_bytes());
        base[40..44].copy_from_slice(&bins_size.to_le_bytes());
        // checksum: 先頭 508 byte を u32 で XOR。
        let mut cksum: u32 = 0;
        for i in 0..127 {
            let off = i * 4;
            let v = u32::from_le_bytes(base[off..off + 4].try_into().unwrap());
            cksum ^= v;
        }
        base[508..512].copy_from_slice(&cksum.to_le_bytes());

        let mut out = base;
        out.extend_from_slice(&self.bins);
        out
    }
}

// ============================================================
// Jump Lists fixture（合成・[MS-CFB] + [MS-DESTS] + [MS-SHLLINK] 準拠）
// ============================================================

/// 合成 LNK bytes を構築する（Jump Lists 内包 LNK 用・LNK header + TerminalBlock の最小構成）。
///
/// 既存の [`build_lnk_fixture`] との違いは、file_size 引数・target base path を明示指定
/// できる点と、`with_extra_data = true`（TerminalBlock 付き）を既定とする点。
pub fn build_jump_list_lnk(
    creation_ft: u64,
    access_ft: u64,
    write_ft: u64,
    file_size: u32,
    target_base_path: Option<&str>,
    is_unicode: bool,
) -> Vec<u8> {
    // flags: HasLinkInfo + IsUnicode（unicode 指定時）。target 無しの場合は HasLinkInfo 無し。
    let has_link_info = target_base_path.is_some();
    let flags: u32 =
        (if has_link_info { 0x0000_0002 } else { 0 }) | (if is_unicode { 0x0000_0080 } else { 0 });

    let opts = LnkFixtureOptions {
        flags,
        creation_filetime: creation_ft,
        access_filetime: access_ft,
        write_filetime: write_ft,
        file_size,
        with_name_string: false,
        local_base_path: target_base_path.map(|s| s.to_string()),
        with_extra_data: true,
    };
    build_lnk_fixture(&opts)
}

/// 合成 v1 (Win7 SP1) DestList bytes を構築する（[MS-DESTS]・hand-crafted）。
pub fn build_destlist_v1(entries: &[(u64, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    // header (32 byte)
    buf.extend_from_slice(&1u32.to_le_bytes()); // version
    buf.extend_from_slice(&28u32.to_le_bytes()); // following size
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes()); // entry count
    buf.extend_from_slice(&1u32.to_le_bytes()); // unknown
    buf.extend_from_slice(&0u64.to_le_bytes()); // last revision (FILETIME)
    buf.extend_from_slice(&0u64.to_le_bytes()); // unknown
    assert_eq!(buf.len(), 32);
    // entries
    for &(last_used_ft, stream_name) in entries {
        let name_units: Vec<u16> = stream_name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut entry = vec![0u8; 74];
        entry[0..8].copy_from_slice(&last_used_ft.to_le_bytes()); // last_used
        entry[40..48].copy_from_slice(&(last_used_ft + 1).to_le_bytes()); // created
        entry[48..56].copy_from_slice(&(last_used_ft + 2).to_le_bytes()); // modified
        // v1: name length in UTF-16 code units (with null)
        let name_units_with_null = (name_units.len() + 1) as u16;
        entry[28..30].copy_from_slice(&name_units_with_null.to_le_bytes());
        buf.extend_from_slice(&entry);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(&0u16.to_le_bytes()); // null 終端
        buf.extend_from_slice(&0u32.to_le_bytes()); // trailing unknown
    }
    buf
}

/// 合成 v3 (Win10 22H2) DestList bytes を構築する。
pub fn build_destlist_v3(entries: &[(u64, &str)]) -> Vec<u8> {
    build_destlist_v3_like(3, entries)
}

/// 合成 v4 (Win11 24H2) DestList bytes を構築する。v3 と同一構造・version 値のみ相違。
pub fn build_destlist_v4(entries: &[(u64, &str)]) -> Vec<u8> {
    build_destlist_v3_like(4, entries)
}

fn build_destlist_v3_like(version: u32, entries: &[(u64, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(buf.len(), 32);
    for &(last_used_ft, stream_name) in entries {
        let name_units: Vec<u16> = stream_name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut entry = vec![0u8; 80];
        entry[0..8].copy_from_slice(&last_used_ft.to_le_bytes());
        entry[40..48].copy_from_slice(&(last_used_ft + 1).to_le_bytes());
        entry[48..56].copy_from_slice(&(last_used_ft + 2).to_le_bytes());
        let name_units_only = name_units.len() as u32;
        entry[28..32].copy_from_slice(&name_units_only.to_le_bytes());
        buf.extend_from_slice(&entry);
        buf.extend_from_slice(&name_bytes);
        buf.extend_from_slice(&0u32.to_le_bytes());
    }
    buf
}

/// 合成 CFB container bytes を構築する（AutomaticDestinations-ms 形式・hand-crafted）。
///
/// 指定した stream 群を mini stream cutoff (4096 byte) 未満で格納する前提。
/// sector size は 512 byte（CFB v3）。
pub fn build_automatic_destinations(streams: &[(&str, &[u8])]) -> Vec<u8> {
    let sector_size: usize = 512;
    let mini_sector_size: usize = 64;
    let mini_cutoff: u32 = 4096;

    // 1. directory entry 数（root + N stream）と必要 sector 計算。
    // 各 stream は mini stream へ格納（< 4096 byte を前提）。
    let mut mini_stream_bytes: Vec<u8> = Vec::new();
    let mut stream_start_mini_sector: Vec<u32> = Vec::with_capacity(streams.len());
    for (_, data) in streams {
        // align to mini sector size.
        while !mini_stream_bytes.len().is_multiple_of(mini_sector_size) {
            mini_stream_bytes.push(0);
        }
        stream_start_mini_sector.push((mini_stream_bytes.len() / mini_sector_size) as u32);
        mini_stream_bytes.extend_from_slice(data);
    }
    // pad mini stream to sector size multiple.
    while !mini_stream_bytes.len().is_multiple_of(sector_size) {
        mini_stream_bytes.push(0);
    }
    let mini_stream_sectors = if mini_stream_bytes.is_empty() {
        0
    } else {
        mini_stream_bytes.len() / sector_size
    };

    // 2. FAT sector 配置を計算。
    // sector 割当:
    //   sector 0: FAT sector 自身
    //   sector 1: directory sector 0
    //   sector 2: directory sector 1 (必要なら)
    //   sector 3..: mini FAT sector (1 つで十分)
    //   sector N..: mini stream sectors
    //
    // directory entries: root + streams。各 128 byte。1 sector (512 byte) に 4 entry。
    let total_dir_entries = 1 + streams.len();
    let dir_sectors_needed = (total_dir_entries * DIR_ENTRY_BYTES)
        .div_ceil(sector_size)
        .max(1);
    let mini_fat_sectors_needed: u32 = if streams.is_empty() { 0 } else { 1 };

    // sector 割当開始:
    //   0 = FAT 自身
    //   1..1+dir_sectors = directory
    //   次に mini FAT sectors
    //   次に mini stream sectors
    let fat_sector: u32 = 0;
    let dir_sector_start: u32 = 1;
    let mini_fat_sector_start: u32 = dir_sector_start + dir_sectors_needed as u32;
    let mini_stream_sector_start: u32 = mini_fat_sector_start + mini_fat_sectors_needed;
    let total_sectors: u32 = mini_stream_sector_start + mini_stream_sectors as u32;

    // 3. FAT 配列を構築。
    let fat_entries = total_sectors as usize;
    let mut fat = vec![0xFFFF_FFFFu32; fat_entries];
    fat[fat_sector as usize] = 0xFFFF_FFFD; // FATSECT
    // directory chain (1..1+dir_sectors).
    for i in 0..dir_sectors_needed {
        let s = (dir_sector_start as usize) + i;
        fat[s] = if i + 1 < dir_sectors_needed {
            (s + 1) as u32
        } else {
            0xFFFF_FFFE
        };
    }
    // mini FAT chain (1 sector 固定).
    if mini_fat_sectors_needed > 0 {
        fat[mini_fat_sector_start as usize] = 0xFFFF_FFFE;
    }
    // mini stream chain.
    for i in 0..mini_stream_sectors {
        let s = (mini_stream_sector_start as usize) + i;
        fat[s] = if i + 1 < mini_stream_sectors {
            (s + 1) as u32
        } else {
            0xFFFF_FFFE
        };
    }

    // 4. mini FAT 配列を構築（1 sector = 128 entry）。
    let mut mini_fat = vec![0xFFFF_FFFFu32; sector_size / 4];
    // stream の mini sector chain は ENDOFCHAIN（1 stream = 連続 mini sector 数 byte）。
    for (idx, (_, data)) in streams.iter().enumerate() {
        let start = stream_start_mini_sector[idx];
        let stream_byte_len = data.len();
        let n_mini_sectors = stream_byte_len.div_ceil(mini_sector_size);
        for i in 0..n_mini_sectors {
            let m = (start as usize) + i;
            if m >= mini_fat.len() {
                break;
            }
            mini_fat[m] = if i + 1 < n_mini_sectors {
                (m + 1) as u32
            } else {
                0xFFFF_FFFE
            };
        }
    }

    // 5. 全体 bytes を構築。
    let total_bytes = CFB_HEADER_BYTES + (total_sectors as usize) * sector_size;
    let mut buf = vec![0u8; total_bytes];

    // --- header (512 byte) ---
    buf[0..8].copy_from_slice(&CFB_SIGNATURE);
    buf[26..28].copy_from_slice(&3u16.to_le_bytes()); // major version 3
    buf[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes()); // byte order
    buf[30..32].copy_from_slice(&9u16.to_le_bytes()); // sector_shift = 9 (512)
    buf[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini_shift = 6 (64)
    buf[40..44].copy_from_slice(&0u32.to_le_bytes()); // total dir sectors (v3 では 0)
    buf[44..48].copy_from_slice(&1u32.to_le_bytes()); // total FAT sectors
    buf[48..52].copy_from_slice(&dir_sector_start.to_le_bytes()); // first dir sector
    buf[56..60].copy_from_slice(&mini_cutoff.to_le_bytes()); // mini cutoff
    buf[60..64].copy_from_slice(&mini_fat_sector_start.to_le_bytes()); // first mini FAT sector
    buf[64..68].copy_from_slice(&mini_fat_sectors_needed.to_le_bytes()); // total mini FAT sectors
    buf[68..72].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // first DIFAT (ENDOFCHAIN)
    buf[72..76].copy_from_slice(&0u32.to_le_bytes()); // total DIFAT sectors
    buf[76..80].copy_from_slice(&fat_sector.to_le_bytes()); // DIFAT[0] = FAT sector
    for i in 1..109 {
        let off = 76 + i * 4;
        buf[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // FREESECT
    }

    // --- FAT sector (sector 0) ---
    let fat_off = CFB_HEADER_BYTES + (fat_sector as usize) * sector_size;
    for (i, v) in fat.iter().enumerate() {
        buf[fat_off + i * 4..fat_off + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }

    // --- directory sectors (sector 1..) ---
    let dir_off = CFB_HEADER_BYTES + (dir_sector_start as usize) * sector_size;
    // entry 0 = root entry.
    buf[dir_off + 2] = 5; // type = root
    buf[dir_off + 4..dir_off + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // left
    buf[dir_off + 8..dir_off + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // right
    buf[dir_off + 12..dir_off + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // child
    // root entry name = "Root Entry"
    let root_name: &[u16] = &[
        'R' as u32 as u16,
        'o' as u32 as u16,
        'o' as u32 as u16,
        't' as u32 as u16,
        ' ' as u32 as u16,
        'E' as u32 as u16,
        'n' as u32 as u16,
        't' as u32 as u16,
        'r' as u32 as u16,
        'y' as u32 as u16,
    ];
    let root_name_bytes: Vec<u8> = root_name.iter().flat_map(|u| u.to_le_bytes()).collect();
    buf[dir_off + 4..dir_off + 4 + root_name_bytes.len()].copy_from_slice(&root_name_bytes);
    let root_name_len_bytes = ((root_name.len() + 1) * 2) as u16;
    buf[dir_off..dir_off + 2].copy_from_slice(&root_name_len_bytes.to_le_bytes());
    // root entry: starting sector = mini stream sector start, size = mini stream bytes。
    buf[dir_off + 52..dir_off + 56].copy_from_slice(&mini_stream_sector_start.to_le_bytes());
    let mini_stream_size = mini_stream_bytes.len() as u64;
    buf[dir_off + 56..dir_off + 60]
        .copy_from_slice(&((mini_stream_size & 0xFFFF_FFFF) as u32).to_le_bytes());
    buf[dir_off + 60..dir_off + 64]
        .copy_from_slice(&(((mini_stream_size >> 32) & 0xFFFF_FFFF) as u32).to_le_bytes());

    // entries 1.. = stream entries.
    for (idx, (name, data)) in streams.iter().enumerate() {
        let entry_off = dir_off + (idx + 1) * DIR_ENTRY_BYTES;
        buf[entry_off + 2] = 2; // type = stream
        buf[entry_off + 4..entry_off + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf[entry_off + 8..entry_off + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf[entry_off + 12..entry_off + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // stream name (UTF-16LE・null 終端)。
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let name_len_with_null_bytes = ((name_units.len() + 1) * 2) as u16;
        buf[entry_off..entry_off + 2].copy_from_slice(&name_len_with_null_bytes.to_le_bytes());
        let name_field_off = entry_off + 4;
        buf[name_field_off..name_field_off + name_bytes.len()].copy_from_slice(&name_bytes);
        // starting mini sector.
        buf[entry_off + 52..entry_off + 56]
            .copy_from_slice(&stream_start_mini_sector[idx].to_le_bytes());
        // size。
        let size = data.len() as u64;
        buf[entry_off + 56..entry_off + 60]
            .copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
        buf[entry_off + 60..entry_off + 64]
            .copy_from_slice(&(((size >> 32) & 0xFFFF_FFFF) as u32).to_le_bytes());
    }

    // --- mini FAT sector ---
    if mini_fat_sectors_needed > 0 {
        let mini_fat_off = CFB_HEADER_BYTES + (mini_fat_sector_start as usize) * sector_size;
        for (i, v) in mini_fat.iter().enumerate() {
            buf[mini_fat_off + i * 4..mini_fat_off + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
    }

    // --- mini stream sectors ---
    if !mini_stream_bytes.is_empty() {
        let mini_stream_off = CFB_HEADER_BYTES + (mini_stream_sector_start as usize) * sector_size;
        buf[mini_stream_off..mini_stream_off + mini_stream_bytes.len()]
            .copy_from_slice(&mini_stream_bytes);
    }

    buf
}

/// CFB signature（[MS-CFB] §2.2）。
pub const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// CFB header の byte 長（[MS-CFB] §2.2）。
pub const CFB_HEADER_BYTES: usize = 512;
/// directory entry の byte 長。
const DIR_ENTRY_BYTES: usize = 128;

/// 合成 CustomDestinations-ms bytes を構築する（hand-crafted）。
pub fn build_custom_destinations(categories: &[(u32, &[Vec<u8>])]) -> Vec<u8> {
    let mut buf = Vec::new();
    // 16 byte file header。
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0xC4D2_D89Eu32.to_le_bytes());
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    for &(category_type, entries) in categories {
        buf.extend_from_slice(&category_type.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for lnk in entries {
            buf.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // entry point type
            buf.extend_from_slice(lnk);
        }
    }
    // terminator。
    buf.extend_from_slice(&0x0000_0000u32.to_le_bytes());
    buf
}
