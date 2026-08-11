//! Prefetch Parser（Windows PF 形式・libyal 仕様、互換 §4.1、T4-020〜T4-025）。
//!
//! Prefetch file は Windows の実行最適化機構が記録する「実行痕跡」。executable 名・
//! run count・last run time（最大8個）・volume・参照 file/directory を保持する。
//!
//! ## 観測型 Event の方針（規範 §7.1・互換 §4.1）
//!
//! Prefetch の存在は「その host 上で実行痕跡が記録された」ことの観測として扱う。
//! 直接観測した process start Event へ変換してはならない。そのため event_type は
//! [`PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE`]（`prefetch_execution_observed`）とし、
//! assertion は [`AssertionKind::Observed`] とする。
//!
//! ## 対応範囲（互換 §4.1）
//!
//! - format version 17 / 23 / 26 / 30 / 31（全て Required）
//! - MAM 圧縮（XPRESS Huffman）の展開。同一 Provenance chain で解析する
//! - 未知 version は `TF-W-PREFETCH-UNSUPPORTED-VERSION` で skip

use std::collections::BTreeMap;
use std::io::Read;

use chrono::{DateTime, Utc};
use serde_json::Value;

use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{MALFORMED_INPUT_CODE, TRUNCATED_RECORD_CODE, artifact_issue};
use crate::lnk::filetime::filetime_to_datetime;
use crate::prefetch::fileinfo::FileInfo;
use crate::prefetch::header::{HEADER_BYTES, PrefetchHeader, SUPPORTED_VERSIONS, is_mam};
use crate::prefetch::mam::decompress_mam;
use crate::prefetch::metrics::{MetricsFields, ReferencedFile, collect_referenced_files};
use crate::prefetch::volume::{VolumeInfo, first_volume};

pub mod fileinfo;
pub mod header;
pub mod mam;
pub mod metrics;
pub mod volume;

/// snapshot を一括で読み込む際の安全上限（byte）。Prefetch は通常数百 KB 以下。
/// MAM 圧縮 file の圧縮前 size 上限（[`mam::MAX_UNCOMPRESSED_BYTES`]）より十分大きく、
/// かつ異常入力からの過大 memory 確保を防ぐ値。
const SNAPSHOT_READ_CAP: usize = 32 * 1024 * 1024;

/// Prefetch Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-prefetch";
/// Prefetch Parser の version（SemVer）。
///
/// Event の意味（生成する Event type・attribute 構成）が変わる変更で version を上げる。
pub const PARSER_VERSION: &str = "1.0.0";
/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
///
/// libyal libscca "Windows Prefetch File (PF) format" 文書（revision 0.0.24）へ基づく。
pub const PREFETCH_REFERENCE: &str = "libyal libscca PF format spec 0.0.24";

/// Prefetch 由来の観測 Event type（規範 §7.1・互換 §4.1: 実行痕跡の観測）。
///
/// process_start 等の断定型ではなく、観測型を用いる（AGENTS.md 禁止事項）。
pub const PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE: &str = "prefetch_execution_observed";

/// 未知 version の Prefetch を skip する際の安定 Issue code（互換 §4.1）。
pub const UNSUPPORTED_VERSION_CODE: &str = "TF-W-PREFETCH-UNSUPPORTED-VERSION";

/// Event の attributes へ記録する参照 file の最大件数。
/// Prefetch は数千件の参照を持つ場合があり、全件を attribute へ入れると Event が肥大化する。
/// 上限を超えた分は件数だけ記録し、一覧は切り詰める。
const MAX_REFERENCED_FILES_IN_ATTRS: usize = 64;

/// Prefetch Parser 本体。
#[derive(Default)]
pub struct PrefetchParser;

impl PrefetchParser {
    pub fn new() -> Self {
        PrefetchParser
    }
}

impl ArtifactParser for PrefetchParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Prefetch
    }

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
        // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
        if evidence.integrity_status != tf_core::case::IntegrityStatus::VerifiedSnapshot {
            return ProbeResult::NotThisFormat;
        }

        // snapshot 先頭 8 byte を読む。
        let path = std::path::Path::new(&evidence.snapshot_locator);
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return ProbeResult::NotThisFormat,
        };
        let mut buf = [0u8; 8];
        let n = file.read(&mut buf).unwrap_or(0);

        // MAM 圧縮 Prefetch: 先頭が "MAM"。
        if n >= 3 && &buf[..3] == b"MAM" {
            return ProbeResult::Confirmed;
        }
        // 非圧縮 Prefetch: 先頭4 byte が対応 version、次が "SCCA"。
        if n >= 8 {
            let version = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if SUPPORTED_VERSIONS.contains(&version) && &buf[4..8] == b"SCCA" {
                return ProbeResult::Confirmed;
            }
            // version は既知だが signature が違う、等は Malformed 扱い。
            if SUPPORTED_VERSIONS.contains(&version) {
                return ProbeResult::Malformed;
            }
        }
        ProbeResult::NotThisFormat
    }

    fn parse(
        &self,
        snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        let start_pos = snapshot.stream_position().unwrap_or(0);

        // 1. snapshot を一括読込（Prefetch は小さい。MAM 展開にも全体が必要）。
        let raw = match read_snapshot_capped(snapshot, SNAPSHOT_READ_CAP) {
            Ok(b) => b,
            Err(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    TRUNCATED_RECORD_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("snapshot の読取に失敗した: {e}"),
                ));
                return ParseSummary::skipped();
            }
        };

        // 2. MAM 圧縮なら展開。展開後 bytes を別 Evidence とせず同じ context で扱う（互換 §4.1）。
        let mam_compressed = is_mam(&raw);
        let pf_bytes: Vec<u8> = if mam_compressed {
            match decompress_mam(&raw) {
                Ok(decompressed) => decompressed,
                Err(e) => {
                    let _ = sink.emit_issue(artifact_issue(
                        MALFORMED_INPUT_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        &format!("MAM 圧縮の展開に失敗した: {e}"),
                    ));
                    return ParseSummary::skipped();
                }
            }
        } else {
            raw
        };

        // 3. Prefetch header 解析。
        if pf_bytes.len() < HEADER_BYTES {
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!(
                    "snapshot が Prefetch header ({HEADER_BYTES} byte) に満たない: {} byte",
                    pf_bytes.len()
                ),
            ));
            return ParseSummary::skipped();
        }
        let header = match PrefetchHeader::parse(&pf_bytes[..HEADER_BYTES]) {
            Ok(h) => h,
            Err(header::HeaderError::SignatureMismatch) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    "Prefetch signature 'SCCA' が一致しない",
                ));
                return ParseSummary::skipped();
            }
            Err(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("Prefetch header の解析失敗: {e}"),
                ));
                return ParseSummary::failed();
            }
        };

        // 4. version 検証（互換 §4.1: 未知 version は推測せず skip）。
        if !SUPPORTED_VERSIONS.contains(&header.format_version) {
            let _ = sink.emit_issue(artifact_issue(
                UNSUPPORTED_VERSION_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!(
                    "未対応の Prefetch format version: {}（対応: {:?}）",
                    header.format_version, SUPPORTED_VERSIONS
                ),
            ));
            return ParseSummary::skipped();
        }

        // 5. file information block 解析。
        let Some(file_info) = parse_file_info(&pf_bytes, header.format_version) else {
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                "file information block が短すぎる（truncated）",
            ));
            return ParseSummary::partial(1, 0, 1);
        };

        // 6. file metrics → 参照 file 一覧（境界安全・過大件数は属性で切り詰め）。
        let referenced = collect_referenced(&pf_bytes, header.format_version, &file_info);

        // 7. volume 情報（代表で最初の1件）。
        let volume = read_first_volume(&pf_bytes, header.format_version, &file_info);

        // 8. Event 生成（観測型・各 run time 毎）。実際の出力件数を正確に集計する。
        let events_emitted = emit_events(
            &header,
            &file_info,
            &referenced,
            &volume,
            mam_compressed,
            context,
            sink,
        );

        let bytes_consumed = snapshot
            .stream_position()
            .unwrap_or(0)
            .saturating_sub(start_pos);
        ParseSummary {
            status: ParseStatus::Complete,
            records_seen: 1,
            events_emitted,
            issues_emitted: 0,
            bytes_consumed,
        }
    }
}

/// version に応じて file information block を解析する。
fn parse_file_info(pf_bytes: &[u8], version: u32) -> Option<FileInfo> {
    type FileInfoParser = fn(&[u8]) -> Option<FileInfo>;
    let start = HEADER_BYTES;
    // version 毎に必要な byte 数を確保して切り出す。
    let (used_len, parse_fn): (usize, FileInfoParser) = match version {
        17 => (68, FileInfo::parse_v17),
        23 => (156, FileInfo::parse_v23),
        // v26/v30/v31 は共通の先頭 136 byte を使うため、全 block size を要求せず
        // parse_v26 が必要とする 136 byte だけ確実に読む。
        26 | 30 | 31 => (136, FileInfo::parse_v26),
        _ => return None,
    };
    let buf = pf_bytes.get(start..start + used_len)?;
    parse_fn(buf)
}

/// file metrics array と filename strings から参照 file 一覧を構築する。
fn collect_referenced(pf_bytes: &[u8], version: u32, fi: &FileInfo) -> Vec<ReferencedFile> {
    let Some(entry_size) = metrics::entry_size_for(version) else {
        return Vec::new();
    };
    let parse_fn: fn(&[u8]) -> Option<MetricsFields> = if version == 17 {
        MetricsFields::parse_v17
    } else {
        MetricsFields::parse_v23
    };

    // metrics array を安全に切り出し（過大 offset は空 slice へ）。
    let metrics_start = usize::try_from(fi.metrics_offset).unwrap_or(usize::MAX);
    let metrics_count = usize::try_from(fi.metrics_count).unwrap_or(0);
    let metrics_len = metrics_count.checked_mul(entry_size).unwrap_or(0);
    let metrics_end = metrics_start.saturating_add(metrics_len);
    let metrics_buf = pf_bytes.get(metrics_start..metrics_end).unwrap_or(&[]);

    // filename strings block を安全に切り出し。
    let fs_start = usize::try_from(fi.filename_strings_offset).unwrap_or(usize::MAX);
    let fs_size = usize::try_from(fi.filename_strings_size).unwrap_or(0);
    let fs_end = fs_start.saturating_add(fs_size);
    let strings_buf = pf_bytes.get(fs_start..fs_end).unwrap_or(&[]);

    collect_referenced_files(metrics_buf, strings_buf, entry_size, parse_fn)
}

/// volumes information block から最初の volume を取り出す。
fn read_first_volume(pf_bytes: &[u8], version: u32, fi: &FileInfo) -> Option<VolumeInfo> {
    let vol_start = usize::try_from(fi.volumes_offset).ok()?;
    let entry_size = volume::entry_size_for(version)?;
    // volumes block の先頭から残り全てを渡す。first_volume 側で境界安全に切り出す。
    let rest = pf_bytes.get(vol_start..)?;
    first_volume(rest, entry_size)
}

/// run time 毎の観測 Event を生成し sink へ流す。実際に流し込んだ件数を返す。
#[allow(clippy::too_many_arguments)]
fn emit_events(
    header: &PrefetchHeader,
    file_info: &FileInfo,
    referenced: &[ReferencedFile],
    volume: &Option<VolumeInfo>,
    mam_compressed: bool,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
) -> u64 {
    let base_attrs = build_base_attributes(header, file_info, referenced, volume, mam_compressed);

    let mut events_emitted: u64 = 0;
    let mut event_ordinal: u64 = 0;
    let mut any_emitted = false;

    for (i, &ft) in file_info.last_run_times.iter().enumerate() {
        if ft == 0 {
            continue;
        }
        let Some(dt) = filetime_to_datetime(ft) else {
            continue;
        };
        any_emitted = true;

        let run_time_offset = run_time_byte_offset(header.format_version, i);
        let record_locator = RecordLocator::ByteRange {
            start: run_time_offset,
            end: run_time_offset + 8,
        };
        let provenance = context.make_provenance(record_locator, i as u64);

        let mut attrs = base_attrs.clone();
        attrs.insert("prefetch.run_index".to_string(), Value::from(i as u64));

        let event_time = EventTime::utc_instant(
            dt,
            Some(format!("FILETIME(last_run[{i}]={ft})")),
            TimestampKind::Executed,
            TimePrecision::Microsecond,
            TimezoneSource::ArtifactDefined,
        );

        let mut event = tf_core::event::Event {
            id: String::new(),
            time: event_time,
            source: ArtifactSource::Prefetch,
            event_type: EventType::new(PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: build_executable_path(volume, &header.executable),
            program: Some(header.executable.clone()),
            process: None,
            message: format!(
                "Prefetch 実行痕跡の観測: {} (run #{}, run_count={})",
                header.executable, i, file_info.run_count
            ),
            attributes: attrs,
            provenance,
        };
        event.id = event.compute_id(event_ordinal);
        event_ordinal += 1;

        if sink.emit_event(event).is_err() {
            return events_emitted;
        }
        events_emitted += 1;
    }

    // run time が1つも無い場合でも、Prefetch 記録の存在を観測 Event として1件残す。
    if !any_emitted {
        let rc_offset = run_count_byte_offset(header.format_version);
        let record_locator = RecordLocator::ByteRange {
            start: rc_offset,
            end: rc_offset + 4,
        };
        let provenance = context.make_provenance(record_locator, 0);
        let mut attrs = base_attrs.clone();
        attrs.insert("prefetch.run_index".to_string(), Value::Null);

        let event_time = EventTime::unknown(TimestampKind::Observed);
        let mut event = tf_core::event::Event {
            id: String::new(),
            time: event_time,
            source: ArtifactSource::Prefetch,
            event_type: EventType::new(PREFETCH_EXECUTION_OBSERVED_EVENT_TYPE),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: build_executable_path(volume, &header.executable),
            program: Some(header.executable.clone()),
            process: None,
            message: format!(
                "Prefetch 記録の観測（run time 未設定）: {} (run_count={})",
                header.executable, file_info.run_count
            ),
            attributes: attrs,
            provenance,
        };
        event.id = event.compute_id(0);
        if sink.emit_event(event).is_ok() {
            events_emitted += 1;
        }
    }

    events_emitted
}

/// version と run index から、last run time FILETIME の絶対 byte offset を返す。
fn run_time_byte_offset(version: u32, run_index: usize) -> u64 {
    // file information は HEADER_BYTES(84) から開始。
    let fi_start = HEADER_BYTES as u64;
    let within = match version {
        17 => 36, // 単一 run time
        23 => 44,
        26 | 30 | 31 => 44 + (run_index * 8),
        _ => 44,
    };
    fi_start + within as u64
}

/// version から run count field の絶対 byte offset を返す。
fn run_count_byte_offset(version: u32) -> u64 {
    let fi_start = HEADER_BYTES as u64;
    let within = match version {
        17 => 60,
        23 => 68,
        26 | 30 | 31 => 124,
        _ => 124,
    };
    fi_start + within as u64
}

/// executable の推定 path（volume device path + executable 名）を構築する。
/// volume device path が無い場合は `None`（path を推測しない、規範 §8）。
fn build_executable_path(
    volume: &Option<VolumeInfo>,
    executable: &str,
) -> Option<tf_core::WindowsPathValue> {
    let dev = volume.as_ref()?.device_path.as_ref()?;
    if dev.is_empty() {
        return None;
    }
    let combined = if dev.ends_with('\\') {
        format!("{dev}{executable}")
    } else {
        format!("{dev}\\{executable}")
    };
    Some(tf_core::WindowsPathValue::new(combined))
}

/// Prefetch Event 共通の attributes を構築する（BTreeMap・規範 §13.2 決定性）。
fn build_base_attributes(
    header: &PrefetchHeader,
    file_info: &FileInfo,
    referenced: &[ReferencedFile],
    volume: &Option<VolumeInfo>,
    mam_compressed: bool,
) -> BTreeMap<String, Value> {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        "prefetch.executable".into(),
        Value::String(header.executable.clone()),
    );
    attrs.insert(
        "prefetch.format_version".into(),
        Value::from(header.format_version),
    );
    attrs.insert(
        "prefetch.run_count".into(),
        Value::from(file_info.run_count),
    );
    attrs.insert("prefetch.hash".into(), Value::from(header.prefetch_hash));
    attrs.insert("prefetch.file_size".into(), Value::from(header.file_size));
    attrs.insert(
        "prefetch.reference_spec".into(),
        Value::String(PREFETCH_REFERENCE.to_string()),
    );
    attrs.insert(
        "prefetch.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );
    attrs.insert(
        "prefetch.mam_compressed".into(),
        Value::Bool(mam_compressed),
    );

    // 参照 file 一覧（上限で切り詰め）。
    attrs.insert(
        "prefetch.referenced_file_count".into(),
        Value::from(referenced.len() as u64),
    );
    let files_array: Vec<Value> = referenced
        .iter()
        .take(MAX_REFERENCED_FILES_IN_ATTRS)
        .map(|r| Value::String(r.name.clone()))
        .collect();
    attrs.insert(
        "prefetch.referenced_files".into(),
        Value::Array(files_array),
    );
    if referenced.len() > MAX_REFERENCED_FILES_IN_ATTRS {
        attrs.insert(
            "prefetch.referenced_files_truncated".into(),
            Value::Bool(true),
        );
    }

    // volume 情報（代表1件）。
    if let Some(vol) = volume {
        if let Some(dev) = &vol.device_path {
            attrs.insert(
                "prefetch.volume_device_path".into(),
                Value::String(dev.clone()),
            );
        }
        attrs.insert(
            "prefetch.volume_serial".into(),
            Value::from(vol.serial_number),
        );
        if vol.creation_time != 0 {
            attrs.insert(
                "prefetch.volume_creation_filetime".into(),
                Value::from(vol.creation_time),
            );
            if let Some(dt) = filetime_to_datetime(vol.creation_time) {
                attrs.insert(
                    "prefetch.volume_creation_iso".into(),
                    Value::String(format_iso_z(&dt)),
                );
            }
        }
    }

    attrs
}

/// ISO 8601 UTC 文字列へ整形（`time.rs` の内部関数と同等の形式）。
fn format_iso_z(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// snapshot を上限付きで一括読込する。
fn read_snapshot_capped(reader: &mut dyn ReadSeek, cap: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65_536];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "snapshot が size 上限を超えた",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

// MAM 圧縮判定のフラグは `is_mam(&raw)` で直接求める（nightly API を避ける）。

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefetch::fileinfo::MAX_RUN_TIMES;
    use std::io::Cursor;

    /// Event と Issue を蓄積する test 用 sink。
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

    fn make_context() -> ParseContext {
        use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ProbeResult};
        ParseContext {
            evidence: EvidenceItem {
                evidence_id: "tf-evidence-v1:pf-test".to_string(),
                source_locator: "test.pf".to_string(),
                size: 200,
                sha256: "ab".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:pf-test".to_string(),
                evidence_id: "tf-evidence-v1:pf-test".to_string(),
                artifact_type: ArtifactSource::Prefetch,
                parser_id: PARSER_ID.to_string(),
                parser_version: PARSER_VERSION.to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["version+SCCA".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    #[test]
    fn parser_metadata_is_stable() {
        let parser = PrefetchParser::new();
        assert_eq!(parser.parser_id(), "traceforge-prefetch");
        assert_eq!(parser.parser_version(), "1.0.0");
        assert_eq!(parser.artifact_type(), ArtifactSource::Prefetch);
    }

    #[test]
    fn unsupported_version_emits_specific_issue() {
        // version 99（未対応）+ SCCA。
        let mut buf = vec![0u8; HEADER_BYTES];
        buf[0..4].copy_from_slice(&99u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        let mut cursor = Cursor::new(buf);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let summary = PrefetchParser::new().parse(&mut cursor, &context, &mut sink);

        assert_eq!(summary.status, ParseStatus::Skipped);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == UNSUPPORTED_VERSION_CODE)
        );
        assert!(sink.events.is_empty());
    }

    #[test]
    fn truncated_header_emits_truncated_issue() {
        let buf = vec![0u8; 10];
        let mut cursor = Cursor::new(buf);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let summary = PrefetchParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Skipped);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == TRUNCATED_RECORD_CODE)
        );
    }

    #[test]
    fn bad_signature_emits_malformed_issue() {
        let mut buf = vec![0u8; HEADER_BYTES];
        buf[0..4].copy_from_slice(&31u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"XXXX"); // signature 不一致
        let mut cursor = Cursor::new(buf);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let summary = PrefetchParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Skipped);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == MALFORMED_INPUT_CODE)
        );
    }

    #[test]
    fn run_time_offset_calculations() {
        // v17: header(84) + 36 = 120
        assert_eq!(run_time_byte_offset(17, 0), 120);
        // v23: header(84) + 44 = 128
        assert_eq!(run_time_byte_offset(23, 0), 128);
        // v26: header(84) + 44 + i*8
        assert_eq!(run_time_byte_offset(26, 0), 128);
        assert_eq!(run_time_byte_offset(26, 3), 128 + 24);
        assert_eq!(run_time_byte_offset(31, 7), 128 + 56);

        // run count offset
        assert_eq!(run_count_byte_offset(17), 84 + 60);
        assert_eq!(run_count_byte_offset(23), 84 + 68);
        assert_eq!(run_count_byte_offset(31), 84 + 124);
    }

    #[test]
    fn executable_path_built_from_volume() {
        let vol = VolumeInfo {
            device_path: Some("\\DEVICE\\HARDDISKVOLUME1".to_string()),
            creation_time: 0,
            serial_number: 0,
        };
        let p = build_executable_path(&Some(vol), "NOTEPAD.EXE").unwrap();
        assert_eq!(p.original, "\\DEVICE\\HARDDISKVOLUME1\\NOTEPAD.EXE");
    }

    #[test]
    fn executable_path_none_without_volume() {
        assert!(build_executable_path(&None, "X.EXE").is_none());
        let vol = VolumeInfo {
            device_path: None,
            creation_time: 0,
            serial_number: 0,
        };
        assert!(build_executable_path(&Some(vol), "X.EXE").is_none());
    }

    #[test]
    fn base_attributes_contain_required_fields() {
        let header = PrefetchHeader {
            format_version: 31,
            file_size: 1000,
            executable: "NOTEPAD.EXE".to_string(),
            prefetch_hash: 0x1234,
        };
        let fi = FileInfo {
            metrics_offset: 0,
            metrics_count: 0,
            filename_strings_offset: 0,
            filename_strings_size: 0,
            volumes_offset: 0,
            volumes_count: 0,
            last_run_times: [0; MAX_RUN_TIMES],
            run_count: 5,
        };
        let attrs = build_base_attributes(&header, &fi, &[], &None, false);
        // 互換 §5 必須 field の確認。
        assert_eq!(attrs["prefetch.executable"], "NOTEPAD.EXE");
        assert_eq!(attrs["prefetch.format_version"], 31);
        assert_eq!(attrs["prefetch.run_count"], 5);
        assert_eq!(attrs["prefetch.reference_spec"], PREFETCH_REFERENCE);
        assert_eq!(attrs["prefetch.mam_compressed"], false);
    }
}
