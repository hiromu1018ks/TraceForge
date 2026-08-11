//! Windows Registry Parser（SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT /
//! UsrClass.dat / Amcache.hve、互換 §4.7・T4-050〜T4-055）。
//!
//! ## 対象形式
//!
//! registry hive file（`regf` magic の base block + `hbin` bin 群）。LOG1 / LOG2 の
//! transaction log を併用して dual view（base / recovered）を構築する。
//!
//! ## 観測型 Event の方針（規範 §7.1・互換 §4.7）
//!
//! Registry snapshot の key/value は「ある時点の観測」であって、操作の直接観測ではない。
//! したがって:
//!
//! - key の last-write → [`REGISTRY_KEY_LAST_WRITE_EVENT_TYPE`]（`registry_key_last_write`）
//! - value の存在 → [`REGISTRY_OBSERVATION_EVENT_TYPE`]（`registry_observation`）
//!
//! `registry_set` / `registry_delete` は生成しない（AGENTS.md 禁止事項）。
//!
//! ## dual view と replay（互換 §4.7）
//!
//! - **base view**: hive 本体のみを解析。
//! - **recovered view**: base hive bytes へ LOG1/LOG2 の entry を適用した recovered bytes
//!   を再解析。view 属性へ `recovered` を記録。
//!
//! LOG file が与えられているのに replay できない（既知未対応形式・破損・範囲外）場合は
//! base のみとし、ParseStatus を `Partial` とする（互換 §4.7）。
//!
//! ## 部分成功（規範 §9.2・§21-5）
//!
//! 中間 cell の破損・空き cell・循環参照は Issue 化し、前後の正常 cell から継続する。
//! 境界を特定できない破損（base block 不正等）だけ `Skipped` や `Partial` へ倒す。

use std::collections::BTreeMap;
use std::io::Read;

use serde_json::Value;

use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{
    MALFORMED_INPUT_CODE, PARTIAL_RECORD_BOUNDARY_CODE, TRUNCATED_RECORD_CODE,
    UNSUPPORTED_VERSION_CODE, artifact_issue, record_issue,
};
use crate::lnk::filetime::filetime_to_datetime;
use crate::registry::hive::{
    HiveBins, HiveHeader, MAX_KEY_DEPTH, MAX_KEYS, MAX_VALUES, registry_value_type_name,
};
use crate::registry::log::{ReplayOutcome, parse_log, replay_logs};

pub mod hive;
pub mod log;

/// Registry Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-registry";
/// Registry Parser の version（SemVer）。
pub const PARSER_VERSION: &str = "1.0.0";

/// key の最終書き込み時刻を表す観測 Event type（規範 §7.1・互換 §4.7）。
pub const REGISTRY_KEY_LAST_WRITE_EVENT_TYPE: &str = "registry_key_last_write";
/// value の存在観測を表す Event type（規範 §7.1・互換 §4.7）。
pub const REGISTRY_OBSERVATION_EVENT_TYPE: &str = "registry_observation";

/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
///
/// Microsoft `[MS-RRMF]` Windows Registry File format と libyal libregf 仕様へ基づく。
/// LOG1/LOG2 の HvLE 形式は本 Parser では検出のみ行い、完全 replay は将来へ委ねる。
pub const REGISTRY_REFERENCE: &str = "MS-RRMF registry hive format + libyal libregf";

/// snapshot 1回分の読取上限（byte）。巨大 hive からの過大 memory 確保を防ぐ。
/// registry hive は数十〜数百 MB 程度が現実的。
const SNAPSHOT_READ_CAP: u64 = 1024 * 1024 * 1024;

/// LOG replay の解析結果（互換 §4.7: 「replay の成否と使用 log hash を記録」）。
///
/// 各 Event の属性 `registry.replay_status` / `registry.log1_sha256` /
/// `registry.log2_sha256` へ記録するための metadata。`log*_sha256` は LOG file が
/// 与えられたときのみ `Some` となる（完全 64 桁 lowercase hex）。
#[derive(Clone, Debug, Default)]
struct ReplayMeta {
    /// LOG1 file の SHA-256 lowercase hex（LOG1 が与えられた場合のみ）。
    log1_sha256: Option<String>,
    /// LOG2 file の SHA-256 lowercase hex（LOG2 が与えられた場合のみ）。
    log2_sha256: Option<String>,
    /// replay 結果 status（`none` / `success` / `failed-hvle` / `failed-legacy` /
    /// `failed` / `failed-malformed`）。
    replay_status: &'static str,
}

/// snapshot 全読みの結果。
enum ReadAllOutcome {
    /// 全読み完了（`Vec<u8>` は snapshot 全体）。
    Complete(Vec<u8>),
    /// I/O error。
    Error(std::io::Error),
}

/// `reader` から最大 `cap` byte まで全読みする。
fn read_all(reader: &mut dyn ReadSeek, cap: u64) -> ReadAllOutcome {
    let mut buf: Vec<u8> = Vec::new();
    let mut limited = cap;
    let mut tmp = [0u8; 65536];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(limited as usize);
                buf.extend_from_slice(&tmp[..take]);
                if (limited as usize) < n {
                    // 上限到達。
                    break;
                }
                limited -= take as u64;
            }
            Err(e) => return ReadAllOutcome::Error(e),
        }
    }
    ReadAllOutcome::Complete(buf)
}

/// Registry Parser 本体。
///
/// LOG1 / LOG2 は [`RegistryParser::with_log1`] / [`RegistryParser::with_log2`] で
/// 指定する。指定しなければ base view のみを解析する。
pub struct RegistryParser {
    log1: Option<Vec<u8>>,
    log2: Option<Vec<u8>>,
}

impl Default for RegistryParser {
    fn default() -> Self {
        RegistryParser::new()
    }
}

impl RegistryParser {
    pub fn new() -> Self {
        RegistryParser {
            log1: None,
            log2: None,
        }
    }

    /// LOG1 file の snapshot bytes を設定する。
    pub fn with_log1(mut self, bytes: Vec<u8>) -> Self {
        self.log1 = Some(bytes);
        self
    }

    /// LOG2 file の snapshot bytes を設定する。
    pub fn with_log2(mut self, bytes: Vec<u8>) -> Self {
        self.log2 = Some(bytes);
        self
    }

    /// base hive bytes を解析し、Event・Issue を sink へ流す。
    /// `view` は base / recovered の区別。`replay_meta` は各 Event 属性へ反映される
    /// （互換 §4.7: replay の成否と使用 log hash を記録）。
    #[allow(clippy::too_many_arguments)]
    fn walk_and_emit(
        &self,
        hive_bytes: &[u8],
        view: &str,
        replay_meta: &ReplayMeta,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
        ordinal: &mut u64,
        records_seen: &mut u64,
        events_emitted: &mut u64,
        issues_emitted: &mut u64,
    ) -> ViewWalkResult {
        let header = match crate::registry::hive::parse_base_block(hive_bytes) {
            Ok(h) => h,
            Err(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("hive base block の parse 失敗: {e}"),
                ));
                *issues_emitted += 1;
                return ViewWalkResult {
                    partial: true,
                    abort: false,
                };
            }
        };

        // bins 領域は base block (4096 byte) の直後。
        let bins_start = crate::registry::hive::BASE_BLOCK_BYTES;
        let bins_end = hive_bytes
            .len()
            .min(bins_start + header.hive_bins_data_size as usize);
        if bins_start >= hive_bytes.len() || bins_end <= bins_start {
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!(
                    "hive_bins_data_size {} が file 長 {} に満たない",
                    header.hive_bins_data_size,
                    hive_bytes.len()
                ),
            ));
            *issues_emitted += 1;
            return ViewWalkResult {
                partial: true,
                abort: false,
            };
        }
        let bins_bytes = &hive_bytes[bins_start..bins_end];
        let bins = HiveBins::new(bins_bytes);

        let mut visited_cells: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut visited_subkey_lists: std::collections::HashSet<u32> =
            std::collections::HashSet::new();
        let hive_type = detect_hive_type(&context.evidence.source_locator);

        // root key の last_write は base block の timestamp ではなく root nk 自身のもの。
        let mut total_keys: u32 = 0;
        let root_result = self.walk_subtree(
            &bins,
            header.root_cell_offset,
            String::new(),
            0,
            view,
            hive_type,
            &header,
            replay_meta,
            context,
            sink,
            ordinal,
            records_seen,
            events_emitted,
            issues_emitted,
            &mut visited_cells,
            &mut visited_subkey_lists,
            &mut total_keys,
        );
        if root_result.abort {
            return root_result;
        }
        ViewWalkResult {
            partial: root_result.partial,
            abort: false,
        }
    }

    /// 1つの key subtree を再帰的に走査し、Event・Issue を生成する。
    #[allow(clippy::too_many_arguments)]
    fn walk_subtree(
        &self,
        bins: &HiveBins,
        nk_offset: u32,
        parent_path: String,
        depth: u32,
        view: &str,
        hive_type: HiveType,
        header: &HiveHeader,
        replay_meta: &ReplayMeta,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
        ordinal: &mut u64,
        records_seen: &mut u64,
        events_emitted: &mut u64,
        issues_emitted: &mut u64,
        visited_cells: &mut std::collections::HashSet<u32>,
        visited_subkey_lists: &mut std::collections::HashSet<u32>,
        total_keys: &mut u32,
    ) -> ViewWalkResult {
        let mut partial = false;

        // depth 上限・key 数上限。
        if depth >= MAX_KEY_DEPTH {
            let _ = sink.emit_issue(record_issue(
                PARTIAL_RECORD_BOUNDARY_CODE,
                tf_core::issue::IssueSeverity::Recoverable,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::ByteOffset(nk_offset as u64)),
                Some(*records_seen),
                &format!("key depth が上限 ({MAX_KEY_DEPTH}) へ到達したため打ち切り"),
            ));
            *issues_emitted += 1;
            return ViewWalkResult {
                partial: true,
                abort: false,
            };
        }
        if *total_keys >= MAX_KEYS {
            let _ = sink.emit_issue(artifact_issue(
                PARTIAL_RECORD_BOUNDARY_CODE,
                tf_core::issue::IssueSeverity::Recoverable,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!("key 数が上限 ({MAX_KEYS}) へ到達したため打ち切り"),
            ));
            *issues_emitted += 1;
            return ViewWalkResult {
                partial: true,
                abort: true,
            };
        }

        // 循環参照防止: 既に訪問した nk offset は再訪しない。
        if !visited_cells.insert(nk_offset) {
            return ViewWalkResult {
                partial: false,
                abort: false,
            };
        }
        *total_keys += 1;
        *records_seen += 1;

        let nk = match bins.parse_key_node(nk_offset) {
            Ok(n) => n,
            Err(e) => {
                let _ = sink.emit_issue(record_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(nk_offset as u64)),
                    Some(*records_seen),
                    &format!("nk cell の parse 失敗: {e}"),
                ));
                *issues_emitted += 1;
                return ViewWalkResult {
                    partial: true,
                    abort: false,
                };
            }
        };

        // key path を構築。root は空文字列になるので "<root>" 扱い。
        let key_path = if parent_path.is_empty() {
            nk.key_name.clone()
        } else {
            format!("{}\\{}", parent_path, nk.key_name)
        };

        // === key_last_write Event を1件生成 ===
        let last_write_event = build_key_last_write_event(
            &nk,
            &key_path,
            view,
            hive_type,
            header,
            replay_meta,
            context,
            *ordinal,
        );
        *ordinal += 1;
        if sink.emit_event(last_write_event).is_err() {
            return ViewWalkResult {
                partial: true,
                abort: true,
            };
        }
        *events_emitted += 1;

        // === value list を処理 ===
        if nk.value_count > 0 && nk.value_list_offset != 0xFFFF_FFFF && nk.value_list_offset != 0 {
            let value_offsets = bins.value_list_offsets(nk.value_list_offset, nk.value_count);
            let mut value_count_seen: u32 = 0;
            for vk_offset in value_offsets
                .into_iter()
                .take((MAX_VALUES as usize).saturating_sub(0))
            {
                *records_seen += 1;
                value_count_seen += 1;
                match bins.parse_key_value(vk_offset) {
                    Ok(vk) => {
                        let observation_event = build_observation_event(
                            &vk,
                            &nk,
                            &key_path,
                            view,
                            hive_type,
                            header,
                            replay_meta,
                            context,
                            *ordinal,
                        );
                        *ordinal += 1;
                        if sink.emit_event(observation_event).is_err() {
                            return ViewWalkResult {
                                partial: true,
                                abort: true,
                            };
                        }
                        *events_emitted += 1;
                    }
                    Err(e) => {
                        let _ = sink.emit_issue(record_issue(
                            MALFORMED_INPUT_CODE,
                            tf_core::issue::IssueSeverity::Warning,
                            &context.evidence.evidence_id,
                            &context.artifact.artifact_id,
                            Some(RecordLocator::ByteOffset(vk_offset as u64)),
                            Some(*records_seen),
                            &format!("vk cell の parse 失敗: {e}"),
                        ));
                        *issues_emitted += 1;
                        partial = true;
                    }
                }
                if value_count_seen >= MAX_VALUES {
                    let _ = sink.emit_issue(record_issue(
                        PARTIAL_RECORD_BOUNDARY_CODE,
                        tf_core::issue::IssueSeverity::Recoverable,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteOffset(nk_offset as u64)),
                        Some(*records_seen),
                        &format!("value 数が上限 ({MAX_VALUES}) へ到達"),
                    ));
                    *issues_emitted += 1;
                    partial = true;
                    break;
                }
            }
        }

        // === subkey list を処理 ===
        if nk.subkey_count > 0 && nk.subkey_list_offset != 0xFFFF_FFFF && nk.subkey_list_offset != 0
        {
            let subkey_offsets = bins.subkey_offsets(nk.subkey_list_offset, visited_subkey_lists);
            let declared = nk.subkey_count as usize;
            let actual = subkey_offsets.len();
            if actual < declared {
                // subkey list の一部が読めなかった。Warning で継続。
                let _ = sink.emit_issue(record_issue(
                    TRUNCATED_RECORD_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(nk.subkey_list_offset as u64)),
                    Some(*records_seen),
                    &format!(
                        "subkey list の一部が読めなかった: declared={declared}, actual={actual}"
                    ),
                ));
                *issues_emitted += 1;
                partial = true;
            }
            for child_offset in subkey_offsets {
                let child_result = self.walk_subtree(
                    bins,
                    child_offset,
                    key_path.clone(),
                    depth + 1,
                    view,
                    hive_type,
                    header,
                    replay_meta,
                    context,
                    sink,
                    ordinal,
                    records_seen,
                    events_emitted,
                    issues_emitted,
                    visited_cells,
                    visited_subkey_lists,
                    total_keys,
                );
                if child_result.abort {
                    return ViewWalkResult {
                        partial: true,
                        abort: true,
                    };
                }
                if child_result.partial {
                    partial = true;
                }
            }
        }

        ViewWalkResult {
            partial,
            abort: false,
        }
    }
}

/// 1 view の走査結果。
struct ViewWalkResult {
    partial: bool,
    abort: bool,
}

impl ArtifactParser for RegistryParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Registry
    }

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
        // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
        if evidence.integrity_status != tf_core::case::IntegrityStatus::VerifiedSnapshot {
            return ProbeResult::NotThisFormat;
        }
        let path = std::path::Path::new(&evidence.snapshot_locator);
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return ProbeResult::NotThisFormat,
        };
        let mut buf = [0u8; 4];
        let n = file.read(&mut buf).unwrap_or(0);
        if n < 4 {
            return ProbeResult::NotThisFormat;
        }
        // registry hive: 先頭 4 byte が "regf"。
        if buf == crate::registry::hive::REGF_MAGIC {
            return ProbeResult::Confirmed;
        }
        ProbeResult::NotThisFormat
    }

    fn parse(
        &self,
        snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        let mut records_seen: u64 = 0;
        let mut events_emitted: u64 = 0;
        let mut issues_emitted: u64 = 0;
        let mut ordinal: u64 = 0;
        let mut partial = false;

        // === snapshot を全読み ===
        let base_bytes = match read_all(snapshot, SNAPSHOT_READ_CAP) {
            ReadAllOutcome::Complete(bytes) => bytes,
            ReadAllOutcome::Error(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("snapshot 読取に失敗: {e}"),
                ));
                issues_emitted += 1;
                return ParseSummary {
                    status: ParseStatus::Skipped,
                    records_seen,
                    events_emitted,
                    issues_emitted,
                    bytes_consumed: 0,
                };
            }
        };
        let bytes_consumed = base_bytes.len() as u64;

        // base_bytes が短すぎる場合は即 skip。
        if base_bytes.len() < crate::registry::hive::BASE_BLOCK_BYTES {
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!(
                    "snapshot が base block ({} byte) に満たない: {} byte",
                    crate::registry::hive::BASE_BLOCK_BYTES,
                    base_bytes.len()
                ),
            ));
            issues_emitted += 1;
            return ParseSummary {
                status: ParseStatus::Skipped,
                records_seen,
                events_emitted,
                issues_emitted,
                bytes_consumed,
            };
        }

        // === LOG1 / LOG2 の hash を先に計算（各 Event 属性へ記録するため） ===
        let log1_hash: Option<String> = self.log1.as_ref().map(|b| parse_log(b).sha256_hex);
        let log2_hash: Option<String> = self.log2.as_ref().map(|b| parse_log(b).sha256_hex);
        let has_logs = self.log1.is_some() || self.log2.is_some();

        // === replay を先に判定し、recovered bytes と status を確定 ===
        let mut recovered_bytes: Option<Vec<u8>> = None;
        let replay_status: &'static str;

        if !has_logs {
            replay_status = "none";
        } else {
            let outcome = replay_logs(&base_bytes, self.log1.as_deref(), self.log2.as_deref());
            match outcome {
                ReplayOutcome::NoLog => {
                    replay_status = "none";
                }
                ReplayOutcome::Recovered { bytes, .. } => {
                    replay_status = "success";
                    recovered_bytes = Some(bytes);
                }
                ReplayOutcome::KnownUnsupported { format } => {
                    replay_status = match format {
                        crate::registry::log::LogFormat::HvLe => "failed-hvle",
                        crate::registry::log::LogFormat::Legacy => "failed-legacy",
                        _ => "failed",
                    };
                    let detail = match format {
                        crate::registry::log::LogFormat::HvLe => {
                            "HvLE 形式は v1.0 では完全 replay 未対応"
                        }
                        crate::registry::log::LogFormat::Legacy => {
                            "RC11/DLOG 形式は v1.0 では完全 replay 未対応"
                        }
                        _ => "LOG 形式が未対応",
                    };
                    // 失敗時は当件の issue へ完全 hash を含める（互換 §4.7・§12-7）。
                    let mut msg =
                        format!("LOG replay 不可のため recovered view を構築しなかった: {detail}");
                    append_hash_to_message(&mut msg, "log1_sha256", log1_hash.as_deref());
                    append_hash_to_message(&mut msg, "log2_sha256", log2_hash.as_deref());
                    let _ = sink.emit_issue(artifact_issue(
                        UNSUPPORTED_VERSION_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        &msg,
                    ));
                    issues_emitted += 1;
                    partial = true;
                }
                ReplayOutcome::Malformed => {
                    replay_status = "failed-malformed";
                    let mut msg = String::from("LOG が破損または範囲外のため replay できなかった");
                    append_hash_to_message(&mut msg, "log1_sha256", log1_hash.as_deref());
                    append_hash_to_message(&mut msg, "log2_sha256", log2_hash.as_deref());
                    let _ = sink.emit_issue(artifact_issue(
                        MALFORMED_INPUT_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        &msg,
                    ));
                    issues_emitted += 1;
                    partial = true;
                }
            }
        }

        let replay_meta = ReplayMeta {
            log1_sha256: log1_hash,
            log2_sha256: log2_hash,
            replay_status,
        };

        // === base view の走査 ===
        let base_result = self.walk_and_emit(
            &base_bytes,
            "base",
            &replay_meta,
            context,
            sink,
            &mut ordinal,
            &mut records_seen,
            &mut events_emitted,
            &mut issues_emitted,
        );
        if base_result.abort || base_result.partial {
            partial = true;
        }

        // === recovered view の走査（replay 成功時のみ） ===
        if let Some(rec_bytes) = recovered_bytes.as_ref() {
            let recovered_result = self.walk_and_emit(
                rec_bytes,
                "recovered",
                &replay_meta,
                context,
                sink,
                &mut ordinal,
                &mut records_seen,
                &mut events_emitted,
                &mut issues_emitted,
            );
            if recovered_result.abort || recovered_result.partial {
                partial = true;
            }
        }

        let status = if partial {
            ParseStatus::Partial
        } else {
            ParseStatus::Complete
        };
        ParseSummary {
            status,
            records_seen,
            events_emitted,
            issues_emitted,
            bytes_consumed,
        }
    }
}

/// Issue message へ ` <key>=<value>` を追加する（hash が None なら何もしない）。
fn append_hash_to_message(msg: &mut String, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        msg.push(' ');
        msg.push_str(key);
        msg.push('=');
        msg.push_str(v);
    }
}

/// registry hive の種別（互換 §4.7・§5 必須 field「hive type」）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiveType {
    System,
    Software,
    Sam,
    Security,
    Ntuser,
    UsrClass,
    Amcache,
    Unknown,
}

impl HiveType {
    /// Schema 上の lowercase 文字列表現。
    pub fn as_str(&self) -> &'static str {
        match self {
            HiveType::System => "system",
            HiveType::Software => "software",
            HiveType::Sam => "sam",
            HiveType::Security => "security",
            HiveType::Ntuser => "ntuser",
            HiveType::UsrClass => "usrclass",
            HiveType::Amcache => "amcache",
            HiveType::Unknown => "unknown",
        }
    }
}

/// source_locator から hive type を推定する（互換 §4.7・§5「hive type」）。
fn detect_hive_type(source_locator: &str) -> HiveType {
    // 末尾の file 名部分を取り出す（区切り文字は / または \）。
    let name = source_locator
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(source_locator);
    // case-insensitive で照合。
    if name.eq_ignore_ascii_case("system") || name.eq_ignore_ascii_case("system.dat") {
        HiveType::System
    } else if name.eq_ignore_ascii_case("software") || name.eq_ignore_ascii_case("software.dat") {
        HiveType::Software
    } else if name.eq_ignore_ascii_case("sam") {
        HiveType::Sam
    } else if name.eq_ignore_ascii_case("security") {
        HiveType::Security
    } else if name.eq_ignore_ascii_case("ntuser.dat") {
        HiveType::Ntuser
    } else if name.eq_ignore_ascii_case("usrclass.dat") {
        HiveType::UsrClass
    } else if name.eq_ignore_ascii_case("amcache.hve") {
        HiveType::Amcache
    } else {
        HiveType::Unknown
    }
}

/// `registry_key_last_write` Event を構築する。
#[allow(clippy::too_many_arguments)]
fn build_key_last_write_event(
    nk: &crate::registry::hive::KeyNode,
    key_path: &str,
    view: &str,
    hive_type: HiveType,
    header: &HiveHeader,
    replay_meta: &ReplayMeta,
    context: &ParseContext,
    event_ordinal: u64,
) -> tf_core::event::Event {
    let event_time = make_event_time(nk.last_write_filetime, TimestampKind::Modified);

    // record_locator は nk cell の byte range。hive bins data 先頭からの相対 offset。
    // 互換 §12-3: Provenance が元 record へ到達できる。
    let cell_abs_start = nk.cell_offset as u64;
    let record_locator = RecordLocator::ByteRange {
        start: cell_abs_start,
        end: cell_abs_start + nk.cell_size as u64,
    };
    let provenance = context.make_provenance(record_locator, event_ordinal);

    let mut attrs = BTreeMap::new();
    attrs.insert("registry.hive_type".into(), Value::from(hive_type.as_str()));
    attrs.insert("registry.view".into(), Value::from(view));
    attrs.insert(
        "registry.key_path".into(),
        Value::String(key_path.to_string()),
    );
    attrs.insert(
        "registry.key_name".into(),
        Value::String(nk.key_name.clone()),
    );
    attrs.insert(
        "registry.key_node_offset".into(),
        Value::from(nk.cell_offset),
    );
    attrs.insert("registry.subkey_count".into(), Value::from(nk.subkey_count));
    attrs.insert("registry.value_count".into(), Value::from(nk.value_count));
    attrs.insert(
        "registry.hive_major_version".into(),
        Value::from(header.major_version),
    );
    attrs.insert(
        "registry.hive_minor_version".into(),
        Value::from(header.minor_version),
    );
    attrs.insert(
        "registry.last_write_filetime".into(),
        Value::from(nk.last_write_filetime),
    );
    attrs.insert(
        "registry.reference_spec".into(),
        Value::String(REGISTRY_REFERENCE.to_string()),
    );
    attrs.insert(
        "registry.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );
    insert_replay_attrs(&mut attrs, replay_meta);

    let message = format!(
        "Registry key 最終書き込み観測: hive={} view={} key={}",
        hive_type.as_str(),
        view,
        key_path
    );

    let mut event = tf_core::event::Event {
        id: String::new(),
        time: event_time,
        source: ArtifactSource::Registry,
        event_type: EventType::new(REGISTRY_KEY_LAST_WRITE_EVENT_TYPE),
        assertion: AssertionKind::Observed,
        hostname: None,
        user: None,
        path: None,
        program: None,
        process: None,
        message,
        attributes: attrs,
        provenance,
    };
    event.id = event.compute_id(event_ordinal);
    event
}

/// `registry_observation` Event（value の存在観測）を構築する。
#[allow(clippy::too_many_arguments)]
fn build_observation_event(
    vk: &crate::registry::hive::KeyValue,
    parent_nk: &crate::registry::hive::KeyNode,
    key_path: &str,
    view: &str,
    hive_type: HiveType,
    header: &HiveHeader,
    replay_meta: &ReplayMeta,
    context: &ParseContext,
    event_ordinal: u64,
) -> tf_core::event::Event {
    // value 自体に timestamp は無い。親 key の last_write を観測時刻の上限として使う。
    let event_time = make_event_time(parent_nk.last_write_filetime, TimestampKind::Modified);

    let cell_abs_start = vk.cell_offset as u64;
    let record_locator = RecordLocator::ByteRange {
        start: cell_abs_start,
        end: cell_abs_start + vk.cell_size as u64,
    };
    let provenance = context.make_provenance(record_locator, event_ordinal);

    let mut attrs = BTreeMap::new();
    attrs.insert("registry.hive_type".into(), Value::from(hive_type.as_str()));
    attrs.insert("registry.view".into(), Value::from(view));
    attrs.insert(
        "registry.key_path".into(),
        Value::String(key_path.to_string()),
    );
    attrs.insert(
        "registry.value_name".into(),
        Value::String(vk.value_name.clone()),
    );
    attrs.insert("registry.value_type".into(), Value::from(vk.data_type));
    attrs.insert(
        "registry.value_type_name".into(),
        Value::String(registry_value_type_name(vk.data_type).to_string()),
    );
    attrs.insert("registry.value_offset".into(), Value::from(vk.cell_offset));
    attrs.insert(
        "registry.value_data_size".into(),
        Value::from(vk.data.len()),
    );
    // data は JSON value へ。binary は hex lowercase 文字列へ、文字列型は UTF-16 → UTF-8 へ。
    attrs.insert(
        "registry.value_data".into(),
        value_data_to_json(vk.data_type, &vk.data),
    );
    attrs.insert(
        "registry.hive_major_version".into(),
        Value::from(header.major_version),
    );
    attrs.insert(
        "registry.hive_minor_version".into(),
        Value::from(header.minor_version),
    );
    attrs.insert(
        "registry.reference_spec".into(),
        Value::String(REGISTRY_REFERENCE.to_string()),
    );
    attrs.insert(
        "registry.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );
    insert_replay_attrs(&mut attrs, replay_meta);

    let message = format!(
        "Registry value 観測: hive={} view={} key={} name={} type={}",
        hive_type.as_str(),
        view,
        key_path,
        vk.value_name,
        registry_value_type_name(vk.data_type)
    );

    let mut event = tf_core::event::Event {
        id: String::new(),
        time: event_time,
        source: ArtifactSource::Registry,
        event_type: EventType::new(REGISTRY_OBSERVATION_EVENT_TYPE),
        assertion: AssertionKind::Observed,
        hostname: None,
        user: None,
        path: None,
        program: None,
        process: None,
        message,
        attributes: attrs,
        provenance,
    };
    event.id = event.compute_id(event_ordinal);
    event
}

/// `registry.replay_status` / `registry.log1_sha256` / `registry.log2_sha256` を
/// Event 属性へ追加する（互換 §4.7: replay の成否と使用 log hash を記録）。
/// `log*_sha256` は LOG file が与えられたときのみ追加される。
fn insert_replay_attrs(attrs: &mut BTreeMap<String, Value>, meta: &ReplayMeta) {
    attrs.insert(
        "registry.replay_status".into(),
        Value::String(meta.replay_status.to_string()),
    );
    if let Some(h) = &meta.log1_sha256 {
        attrs.insert("registry.log1_sha256".into(), Value::String(h.clone()));
    }
    if let Some(h) = &meta.log2_sha256 {
        attrs.insert("registry.log2_sha256".into(), Value::String(h.clone()));
    }
}

/// FILETIME → EventTime へ変換。0 は Unknown。
fn make_event_time(filetime: u64, kind: TimestampKind) -> EventTime {
    if filetime == 0 {
        return EventTime::unknown(kind);
    }
    match filetime_to_datetime(filetime) {
        Some(dt) => EventTime::utc_instant(
            dt,
            Some(format!("FILETIME({filetime})")),
            kind,
            TimePrecision::Microsecond,
            TimezoneSource::ArtifactDefined,
        ),
        None => EventTime::unknown(kind),
    }
}

/// registry value data を JSON value へ変換する。
fn value_data_to_json(data_type: u32, data: &[u8]) -> Value {
    match data_type {
        1 | 2 => {
            // REG_SZ / REG_EXPAND_SZ: UTF-16LE。
            Value::String(crate::registry::hive::decode_utf16le_lossy(data))
        }
        4 => {
            // REG_DWORD: u32 LE。
            if data.len() >= 4 {
                Value::from(u32::from_le_bytes(data[..4].try_into().unwrap()))
            } else {
                Value::Null
            }
        }
        5 => {
            // REG_DWORD_BIG_ENDIAN: u32 BE。
            if data.len() >= 4 {
                Value::from(u32::from_be_bytes(data[..4].try_into().unwrap()))
            } else {
                Value::Null
            }
        }
        7 => {
            // REG_MULTI_SZ: UTF-16LE・null で区切られた文字列リスト。
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let mut parts = Vec::new();
            let mut buf: Vec<u16> = Vec::new();
            for u in units {
                if u == 0 {
                    if !buf.is_empty() {
                        parts.push(String::from_utf16_lossy(&buf));
                        buf.clear();
                    }
                } else {
                    buf.push(u);
                }
            }
            if !buf.is_empty() {
                parts.push(String::from_utf16_lossy(&buf));
            }
            Value::Array(parts.into_iter().map(Value::String).collect())
        }
        11 => {
            // REG_QWORD: u64 LE。
            if data.len() >= 8 {
                Value::from(u64::from_le_bytes(data[..8].try_into().unwrap()))
            } else {
                Value::Null
            }
        }
        _ => {
            // REG_BINARY その他: hex lowercase 文字列。
            Value::String(tf_core::hash::sha256_hex(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::hive::BASE_BLOCK_BYTES;
    use std::io::Cursor;

    struct TestSink {
        events: Vec<tf_core::event::Event>,
        issues: Vec<tf_core::issue::Issue>,
    }
    impl ParseSink for TestSink {
        fn emit_event(
            &mut self,
            event: tf_core::event::Event,
        ) -> Result<(), crate::framework::SinkError> {
            self.events.push(event);
            Ok(())
        }
        fn emit_issue(
            &mut self,
            issue: tf_core::issue::Issue,
        ) -> Result<(), crate::framework::SinkError> {
            self.issues.push(issue);
            Ok(())
        }
    }

    fn make_context(locator: &str) -> ParseContext {
        use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ProbeResult};
        ParseContext {
            evidence: EvidenceItem {
                evidence_id: "tf-evidence-v1:reg-test".to_string(),
                source_locator: locator.to_string(),
                size: 200,
                sha256: "ab".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:reg-test".to_string(),
                evidence_id: "tf-evidence-v1:reg-test".to_string(),
                artifact_type: ArtifactSource::Registry,
                parser_id: PARSER_ID.to_string(),
                parser_version: PARSER_VERSION.to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["regf magic".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    /// hive bins 領域に cell を書き込む（size field + body）。
    fn write_cell(buf: &mut [u8], offset: usize, body: &[u8]) {
        let size_field: i32 = -((body.len() as i32) + 4);
        buf[offset..offset + 4].copy_from_slice(&size_field.to_le_bytes());
        let body_end = (offset + 4 + body.len()).min(buf.len());
        let copy_len = body_end - (offset + 4);
        buf[offset + 4..body_end].copy_from_slice(&body[..copy_len]);
    }

    /// nk body を構築（最小 76 byte + name）。
    fn make_nk_body(
        name: &str,
        last_write: u64,
        subkey_count: u32,
        subkey_list_offset: u32,
        value_count: u32,
        value_list_offset: u32,
    ) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut body = vec![0u8; 70 + name_bytes.len()];
        body[0..2].copy_from_slice(b"nk");
        body[2..10].copy_from_slice(&last_write.to_le_bytes());
        body[18..22].copy_from_slice(&subkey_count.to_le_bytes());
        body[22..26].copy_from_slice(&subkey_list_offset.to_le_bytes());
        body[28..32].copy_from_slice(&value_count.to_le_bytes());
        body[32..36].copy_from_slice(&value_list_offset.to_le_bytes());
        let name_len = name_bytes.len() as u16;
        body[68..70].copy_from_slice(&name_len.to_le_bytes());
        body[70..70 + name_bytes.len()].copy_from_slice(&name_bytes);
        body
    }

    /// base block を構築。root_offset は hive bins data 先頭からの相対。
    fn make_base_block(root_offset: u32, bins_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; BASE_BLOCK_BYTES];
        buf[0..4].copy_from_slice(&crate::registry::hive::REGF_MAGIC);
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..28].copy_from_slice(&5u32.to_le_bytes());
        buf[36..40].copy_from_slice(&root_offset.to_le_bytes());
        buf[40..44].copy_from_slice(&bins_size.to_le_bytes());
        let mut cksum: u32 = 0;
        for i in 0..127 {
            let off = i * 4;
            let v = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            cksum ^= v;
        }
        buf[508..512].copy_from_slice(&cksum.to_le_bytes());
        buf
    }

    /// 小さな hive を構築: root nk + 1 subkey + root 配下に 1 value。
    fn make_small_hive() -> Vec<u8> {
        // bins: 0x1000 byte 確保。
        let mut bins = vec![0u8; 0x1000];
        // root nk at offset 0
        let root = make_nk_body("ROOT", 132_548_480_000_000_000, 1, 0x100, 1, 0x200);
        write_cell(&mut bins, 0, &root);
        // lf list at 0x100 → child nk at 0x300
        let mut lf = vec![0u8; 8 + 8];
        lf[0..2].copy_from_slice(b"lf");
        lf[2..4].copy_from_slice(&1u16.to_le_bytes());
        lf[4..8].copy_from_slice(&0x300u32.to_le_bytes());
        write_cell(&mut bins, 0x100, &lf);
        // value list at 0x200 → vk at 0x400
        let mut vlist = vec![0u8; 4];
        vlist[0..4].copy_from_slice(&0x400u32.to_le_bytes());
        write_cell(&mut bins, 0x200, &vlist);
        // child nk at 0x300 (leaf)
        let child = make_nk_body("Child", 132_548_480_000_000_000, 0, 0xFFFF_FFFF, 0, 0);
        write_cell(&mut bins, 0x300, &child);
        // vk at 0x400 (REG_DWORD inline)
        let mut vk = vec![0u8; 20];
        vk[0..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&0u16.to_le_bytes()); // 名前無し
        vk[4..8].copy_from_slice(&0x8000_0004u32.to_le_bytes()); // inline 4 byte
        vk[8..12].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        vk[12..16].copy_from_slice(&4u32.to_le_bytes()); // REG_DWORD
        write_cell(&mut bins, 0x400, &vk);

        let mut buf = make_base_block(0, bins.len() as u32);
        buf.extend_from_slice(&bins);
        buf
    }

    #[test]
    fn parser_metadata_is_stable() {
        let p = RegistryParser::new();
        assert_eq!(p.parser_id(), "traceforge-registry");
        assert_eq!(p.parser_version(), "1.0.0");
        assert_eq!(p.artifact_type(), ArtifactSource::Registry);
    }

    #[test]
    fn empty_stream_skipped() {
        let mut cursor = Cursor::new(Vec::new());
        let context = make_context("SYSTEM");
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Skipped);
        assert_eq!(sink.events.len(), 0);
    }

    #[test]
    fn parses_small_hive_emits_key_last_write_and_observation() {
        let hive = make_small_hive();
        let mut cursor = Cursor::new(hive);
        let context = make_context("SYSTEM");
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(
            summary.status,
            ParseStatus::Complete,
            "issues: {:?}",
            sink.issues
        );
        // root key (last_write) + root value (observation) + child key (last_write)
        // child は value 無し → observation 無し。
        let mut lw = 0;
        let mut obs = 0;
        for e in &sink.events {
            match e.event_type.as_str() {
                REGISTRY_KEY_LAST_WRITE_EVENT_TYPE => lw += 1,
                REGISTRY_OBSERVATION_EVENT_TYPE => obs += 1,
                _ => {}
            }
        }
        assert_eq!(lw, 2, "key_last_write は root + child の2件");
        assert_eq!(obs, 1, "observation は root 配下の value 1件");
    }

    #[test]
    fn provenance_byte_range_points_to_cells() {
        let hive = make_small_hive();
        let mut cursor = Cursor::new(hive);
        let context = make_context("SYSTEM");
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        for e in &sink.events {
            assert!(matches!(
                e.provenance.record_locator,
                RecordLocator::ByteRange { .. }
            ));
            assert_eq!(e.provenance.parser_id, PARSER_ID);
            assert_eq!(e.provenance.parser_version, PARSER_VERSION);
            assert_eq!(e.attributes["registry.view"], "base");
            assert_eq!(e.attributes["registry.hive_type"], "system");
        }
    }

    #[test]
    fn corrupt_input_does_not_panic() {
        let run = |bytes: &[u8]| {
            let mut cursor = Cursor::new(bytes.to_vec());
            let context = make_context("SYSTEM");
            let mut sink = TestSink {
                events: vec![],
                issues: vec![],
            };
            let _ = RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        };

        // 短すぎる
        run(&(0..10).collect::<Vec<u8>>());
        // magic 壊す
        let mut bad = make_small_hive();
        bad[0] = 0xFF;
        run(&bad);
        // root offset を範囲外へ
        let mut bad2 = make_small_hive();
        bad2[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        run(&bad2);
    }

    #[test]
    fn no_set_or_delete_event_types() {
        let hive = make_small_hive();
        let mut cursor = Cursor::new(hive);
        let context = make_context("SYSTEM");
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        RegistryParser::new().parse(&mut cursor, &context, &mut sink);
        for e in &sink.events {
            let t = e.event_type.as_str();
            assert_ne!(t, "registry_set");
            assert_ne!(t, "registry_delete");
        }
    }

    #[test]
    fn detect_hive_type_from_locator() {
        assert_eq!(detect_hive_type("C:/path/SYSTEM"), HiveType::System);
        assert_eq!(detect_hive_type("/x/SOFTWARE"), HiveType::Software);
        assert_eq!(detect_hive_type("/x/SAM"), HiveType::Sam);
        assert_eq!(detect_hive_type("/x/SECURITY"), HiveType::Security);
        assert_eq!(detect_hive_type("/x/NTUSER.DAT"), HiveType::Ntuser);
        assert_eq!(detect_hive_type("/x/UsrClass.dat"), HiveType::UsrClass);
        assert_eq!(detect_hive_type("/x/Amcache.hve"), HiveType::Amcache);
        assert_eq!(detect_hive_type("/x/unknown.bin"), HiveType::Unknown);
    }

    #[test]
    fn value_data_dword_to_json() {
        let v = value_data_to_json(4, &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(v, Value::from(0x1234_5678u32));
    }

    #[test]
    fn value_data_qword_to_json() {
        let v = value_data_to_json(11, &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(v, Value::from(0x0000_0001_0000_0000u64));
    }

    #[test]
    fn value_data_sz_to_json() {
        let bytes: Vec<u8> = "AB".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let v = value_data_to_json(1, &bytes);
        assert_eq!(v, Value::String("AB".to_string()));
    }
}
