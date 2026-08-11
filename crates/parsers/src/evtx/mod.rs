//! EVTX（Windows Event Log）Parser（libyal libevtx 仕様、互換 §4.2、T4-040〜T4-046）。
//!
//! EVTX file は Windows Vista 以降の event log 形式。standalone `.evtx` file を対象とする
//! （互換 §4.2: Required）。Legacy `.evt` は Unsupported とし、EVTX として解析しない。
//!
//! ## file 構造
//!
//! ```text
//! ┌──────────────────────────┐
//! │ file header (4096 byte)  │  magic "ElfFile\x00"・chunk_count・checksum
//! ├──────────────────────────┤
//! │ chunk 0 (65536 byte)     │  magic "ElfChnk\x00"・chunk header・records
//! ├──────────────────────────┤
//! │ chunk 1 (65536 byte)     │  ...
//! ├──────────────────────────┤
//! │ ...                      │
//! └──────────────────────────┘
//! ```
//!
//! 各 chunk は 512 byte の chunk header と 65024 byte の records 領域から成る。
//! records 領域へは可変長の record が順に並び、各 record は magic `0x2a2a` で始まる。
//!
//! ## 観測型 Event と typed mapping（規範 §7.1・互換 §4.2）
//!
//! EVTX record は「event log service が記録した事象の観測」である。本 Parser は
//! 基本的に [`EVENT_LOGGED_TYPE`]（`event_logged`）の観測型 Event を生成する。
//! ただし互換 §4.2 が定める5種（4624/4625/4688/4689/7045）については、
//! **channel + provider + 必須 field を同時検証**した上で typed event type
//! （`login`/`login_failure`/`process_start`/`process_stop`/`service_create`）へ mapping する。
//! Event ID 単独では mapping しない（AGENTS.md 禁止事項）。
//!
//! ## partial recovery（規範 §9.2・§21-5・互換 §4.2）
//!
//! - chunk magic 不一致 → chunk を解析対象外とし、Warning を発して次 chunk へ
//! - chunk checksum 不一致 → Warning を発しつつ records の解析を試みる
//! - record 破損 → 当該 record を Issue 化して次 record へ
//! - binxml decode 失敗 → 必須 field 欠落扱いで Event 化せず Issue 化
//!
//! 生成済み Event は sink へ既に流れているため、後続の破損で破棄されることはない。

use std::io::Read;

use serde_json::Value;

use tf_core::WindowsPathValue;
use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::evtx::binxml::{EventContent, EventDataValue};
use crate::evtx::chunk::{
    CHUNK_BYTES, CHUNK_HEADER_BYTES, CHUNK_RECORDS_OFFSET, ChunkError, ChunkHeader,
};
use crate::evtx::header::{EVTX_FILE_MAGIC, FILE_HEADER_BYTES, FileHeader, HeaderError};
use crate::evtx::mapping::{EVENT_LOGGED_TYPE, map_event_type};
use crate::evtx::record::{ParsedRecord, RecordError, parse_record_at};
use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{
    INVALID_LENGTH_CODE, MALFORMED_INPUT_CODE, MISSING_REQUIRED_FIELD_CODE,
    PARTIAL_RECORD_BOUNDARY_CODE, TRUNCATED_RECORD_CODE, UNSUPPORTED_VERSION_CODE, artifact_issue,
    record_issue,
};
use crate::lnk::filetime::filetime_to_datetime;

pub mod binxml;
pub mod chunk;
pub mod crc32;
pub mod header;
pub mod mapping;
pub mod record;

/// EVTX Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-evtx";
/// EVTX Parser の version（SemVer）。
pub const PARSER_VERSION: &str = "1.0.0";
/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
///
/// libyal libevtx "Windows Event Log (EVTX) format" 仕様と Microsoft [MS-EVEN6] へ基づく。
pub const EVTX_REFERENCE: &str = "libyal libevtx EVTX format spec + MS-EVEN6";

/// 1 file あたり chunk 数の安全上限。異常入力からの無限 loop 回避。
const MAX_CHUNKS: u32 = 65_536;
/// 1 chunk あたり record 数の安全上限。異常入力からの無限 loop 回避。
const MAX_RECORDS_PER_CHUNK: usize = 65_536;

/// EVTX Parser 本体。
#[derive(Default)]
pub struct EvtxParser;

impl EvtxParser {
    pub fn new() -> Self {
        EvtxParser
    }
}

impl ArtifactParser for EvtxParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Evtx
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
        let mut buf = [0u8; 8];
        let n = file.read(&mut buf).unwrap_or(0);
        if n < 8 {
            return ProbeResult::NotThisFormat;
        }
        // EVTX: 先頭 8 byte が "ElfFile\x00"。
        if buf == EVTX_FILE_MAGIC {
            return ProbeResult::Confirmed;
        }
        // Legacy .evt: 先頭4 byte が 0x654c664c ("LfLe")。
        if buf[0..4] == [0x4c, 0x66, 0x4c, 0x65] {
            // Unsupported（互換 §4.2）。
            return ProbeResult::NotThisFormat;
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
        let mut records_seen: u64 = 0;
        let mut events_emitted: u64 = 0;
        let mut issues_emitted: u64 = 0;
        let mut event_ordinal: u64 = 0;
        let mut partial = false;

        // === file header を読む ===
        let mut header_buf = vec![0u8; FILE_HEADER_BYTES];
        let header_read = read_exact_or_eof(snapshot, &mut header_buf);
        match header_read {
            ReadOutcome::Complete => {}
            ReadOutcome::Eof => {
                let _ = sink.emit_issue(artifact_issue(
                    TRUNCATED_RECORD_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("snapshot が EVTX file header ({FILE_HEADER_BYTES} byte) に満たない"),
                ));
                return ParseSummary {
                    status: ParseStatus::Skipped,
                    records_seen: 0,
                    events_emitted: 0,
                    issues_emitted: 1,
                    bytes_consumed: 0,
                };
            }
            ReadOutcome::Error(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("snapshot 読取に失敗: {e}"),
                ));
                return ParseSummary {
                    status: ParseStatus::Skipped,
                    records_seen: 0,
                    events_emitted: 0,
                    issues_emitted: 1,
                    bytes_consumed: 0,
                };
            }
        }

        let header = match parse_file_header_or_skip(
            &header_buf,
            &context.evidence.evidence_id,
            &context.artifact.artifact_id,
            sink,
            &mut issues_emitted,
        ) {
            HeaderParseOutcome::Ok(h) => h,
            HeaderParseOutcome::Skipped => {
                return ParseSummary {
                    status: ParseStatus::Skipped,
                    records_seen: 0,
                    events_emitted: 0,
                    issues_emitted,
                    bytes_consumed: 0,
                };
            }
        };

        if !header.checksum_matches() {
            let _ = sink.emit_issue(artifact_issue(
                MALFORMED_INPUT_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                "EVTX file header の checksum が不一致（解析は継続）",
            ));
            issues_emitted += 1;
            partial = true;
        }

        let chunk_count = (header.chunk_count as u32).min(MAX_CHUNKS) as usize;
        let mut bytes_consumed = FILE_HEADER_BYTES as u64;

        for chunk_index in 0..chunk_count as usize {
            if bytes_consumed >= SNAPSHOT_READ_CAP {
                let _ = sink.emit_issue(artifact_issue(
                    PARTIAL_RECORD_BOUNDARY_CODE,
                    tf_core::issue::IssueSeverity::Recoverable,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("snapshot size 上限 ({SNAPSHOT_READ_CAP} byte) を超えたため打ち切り"),
                ));
                issues_emitted += 1;
                partial = true;
                break;
            }
            let mut chunk_buf = vec![0u8; CHUNK_BYTES];
            let chunk_read = read_exact_or_eof(snapshot, &mut chunk_buf);
            match chunk_read {
                ReadOutcome::Complete => {}
                ReadOutcome::Eof => {
                    // 最終 chunk が無い・途中で切れた。file header の chunk_count 宣言と
                    // 実際の file size が不一致のケース。Warning して終了。
                    let _ = sink.emit_issue(artifact_issue(
                        TRUNCATED_RECORD_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        &format!(
                            "chunk {chunk_index} の読取に失敗（file が chunk_count 宣言に満たない）"
                        ),
                    ));
                    issues_emitted += 1;
                    partial = true;
                    break;
                }
                ReadOutcome::Error(e) => {
                    let _ = sink.emit_issue(artifact_issue(
                        MALFORMED_INPUT_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        &format!("chunk {chunk_index} の読取に失敗: {e}"),
                    ));
                    issues_emitted += 1;
                    partial = true;
                    break;
                }
            }
            bytes_consumed += CHUNK_BYTES as u64;

            let chunk_offset_in_file =
                FILE_HEADER_BYTES as u64 + chunk_index as u64 * CHUNK_BYTES as u64;
            let outcome = parse_one_chunk(
                &chunk_buf,
                chunk_index,
                chunk_offset_in_file,
                context,
                sink,
                &mut records_seen,
                &mut events_emitted,
                &mut issues_emitted,
                &mut event_ordinal,
            );
            if outcome.chunk_partial {
                partial = true;
            }
            if outcome.abort_file {
                break;
            }
        }

        let bytes_consumed = snapshot
            .stream_position()
            .unwrap_or(0)
            .saturating_sub(start_pos);
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

/// snapshot を1回で読み込む byte 上限。EVTX は数 MB〜数十 MB 程度が現実的。
const SNAPSHOT_READ_CAP: u64 = 1024 * 1024 * 1024;

/// `read_exact` の結果を3通りへ分ける。
enum ReadOutcome {
    Complete,
    Eof,
    Error(std::io::Error),
}

fn read_exact_or_eof(reader: &mut dyn ReadSeek, buf: &mut [u8]) -> ReadOutcome {
    if buf.is_empty() {
        return ReadOutcome::Complete;
    }
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return ReadOutcome::Error(e),
        }
    }
    if filled < buf.len() {
        ReadOutcome::Eof
    } else {
        ReadOutcome::Complete
    }
}

/// file header の parse 結果。
enum HeaderParseOutcome {
    Ok(FileHeader),
    Skipped,
}

/// file header を parse する。失敗時は Issue を発行して Skipped を返す。
fn parse_file_header_or_skip(
    buf: &[u8],
    evidence_id: &str,
    artifact_id: &str,
    sink: &mut dyn ParseSink,
    issues_emitted: &mut u64,
) -> HeaderParseOutcome {
    match crate::evtx::header::parse_file_header(buf) {
        Ok(h) => HeaderParseOutcome::Ok(h),
        Err(HeaderError::MagicMismatch) => {
            // Legacy .evt 等の可能性。Unsupported 扱い。
            let _ = sink.emit_issue(artifact_issue(
                UNSUPPORTED_VERSION_CODE,
                tf_core::issue::IssueSeverity::Warning,
                evidence_id,
                artifact_id,
                "EVTX file magic が ElfFile\\x00 ではない（Legacy .evt の可能性）",
            ));
            *issues_emitted += 1;
            HeaderParseOutcome::Skipped
        }
        Err(HeaderError::TooShort(n)) => {
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                evidence_id,
                artifact_id,
                &format!("file header が {n} byte しかない（{FILE_HEADER_BYTES} byte 必要）"),
            ));
            *issues_emitted += 1;
            HeaderParseOutcome::Skipped
        }
    }
}

/// 1 chunk の解析結果。
struct ChunkOutcome {
    /// chunk 内で何らかの破損・truncation があった。
    chunk_partial: bool,
    /// file 全体の解析を打ち切るべき（chunk が file 終端を越えていた等）。
    abort_file: bool,
}

#[allow(clippy::too_many_arguments)]
fn parse_one_chunk(
    chunk_buf: &[u8],
    chunk_index: usize,
    chunk_offset_in_file: u64,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
    records_seen: &mut u64,
    events_emitted: &mut u64,
    issues_emitted: &mut u64,
    event_ordinal: &mut u64,
) -> ChunkOutcome {
    let mut chunk_partial = false;

    let header = match crate::evtx::chunk::parse_chunk_header(chunk_buf) {
        Ok(h) => h,
        Err(ChunkError::MagicMismatch) => {
            // chunk magic 不一致 → chunk を解析対象外にする。次 chunk へ。
            let _ = sink.emit_issue(record_issue(
                MALFORMED_INPUT_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::ByteOffset(chunk_offset_in_file)),
                Some(chunk_index as u64),
                &format!("chunk {chunk_index} の magic が ElfChnk ではない"),
            ));
            *issues_emitted += 1;
            return ChunkOutcome {
                chunk_partial: true,
                abort_file: false,
            };
        }
        Err(ChunkError::Truncated(n)) => {
            let _ = sink.emit_issue(record_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::ByteOffset(chunk_offset_in_file)),
                Some(chunk_index as u64),
                &format!("chunk {chunk_index} が {n} byte しかない"),
            ));
            *issues_emitted += 1;
            return ChunkOutcome {
                chunk_partial: true,
                abort_file: false,
            };
        }
        Err(ChunkError::BadFreeSpaceOffset(off)) => {
            let _ = sink.emit_issue(record_issue(
                INVALID_LENGTH_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::ByteOffset(chunk_offset_in_file)),
                Some(chunk_index as u64),
                &format!("chunk {chunk_index} の free_space_offset {off} が chunk size を超える"),
            ));
            *issues_emitted += 1;
            chunk_partial = true;
            // free_space_offset を chunk size へ切り詰めて継続を試みる。
            ChunkHeader {
                first_event_record_number: 0,
                last_event_record_number: 0,
                first_event_record_identifier: 0,
                last_event_record_identifier: 0,
                header_size: CHUNK_HEADER_BYTES as u32,
                last_event_record_data_offset: 0,
                free_space_offset: CHUNK_BYTES as u32,
                event_records_checksum: 0,
                stored_header_checksum_1: 0,
                stored_header_checksum_2: 0,
            }
        }
    };

    // records checksum の検証（chunk header checksum より優先）。不一致でも Warning で継続。
    if !header.records_checksum_matches(chunk_buf) {
        let _ = sink.emit_issue(record_issue(
            MALFORMED_INPUT_CODE,
            tf_core::issue::IssueSeverity::Warning,
            &context.evidence.evidence_id,
            &context.artifact.artifact_id,
            Some(RecordLocator::ByteRange {
                start: chunk_offset_in_file + CHUNK_RECORDS_OFFSET as u64,
                end: chunk_offset_in_file + header.free_space_offset as u64,
            }),
            Some(chunk_index as u64),
            &format!("chunk {chunk_index} の records checksum が不一致（解析は継続）"),
        ));
        *issues_emitted += 1;
        chunk_partial = true;
    }

    // records 領域を取り出し、record を順に parse。
    let records = header.records_slice(chunk_buf);
    if records.is_empty() {
        return ChunkOutcome {
            chunk_partial,
            abort_file: false,
        };
    }
    let mut offset = 0usize;
    let mut chunk_records_count = 0usize;
    while offset < records.len() {
        if chunk_records_count >= MAX_RECORDS_PER_CHUNK {
            let _ = sink.emit_issue(record_issue(
                PARTIAL_RECORD_BOUNDARY_CODE,
                tf_core::issue::IssueSeverity::Recoverable,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::ByteOffset(
                    chunk_offset_in_file + CHUNK_RECORDS_OFFSET as u64 + offset as u64,
                )),
                Some(*records_seen),
                &format!(
                    "chunk {chunk_index} 内の record 数が上限 ({MAX_RECORDS_PER_CHUNK}) へ到達"
                ),
            ));
            *issues_emitted += 1;
            chunk_partial = true;
            break;
        }
        let record_offset_in_file =
            chunk_offset_in_file + CHUNK_RECORDS_OFFSET as u64 + offset as u64;
        match parse_record_at(records, offset) {
            Ok((parsed, next_offset)) => {
                *records_seen += 1;
                chunk_records_count += 1;
                if let Some(event) = build_event(
                    &parsed,
                    record_offset_in_file,
                    chunk_index,
                    context,
                    *event_ordinal,
                ) {
                    *event_ordinal += 1;
                    if sink.emit_event(event).is_err() {
                        // sink 側の事情で継続不能。
                        return ChunkOutcome {
                            chunk_partial: true,
                            abort_file: true,
                        };
                    }
                    *events_emitted += 1;
                } else {
                    // 必須 field 欠落で Event 化せず。Issue 化（互換 §5）。
                    let _ = sink.emit_issue(record_issue(
                        MISSING_REQUIRED_FIELD_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteRange {
                            start: record_offset_in_file,
                            end: record_offset_in_file + parsed.header.size as u64,
                        }),
                        Some(*records_seen),
                        "EVTX record の必須 field 欠落（event_id または timestamp 未設定）のため Event 化せず",
                    ));
                    *issues_emitted += 1;
                }
                offset = next_offset;
            }
            Err(RecordError::Empty(_)) => {
                // 空き領域マーカー。chunk 末尾とみなす。
                break;
            }
            Err(RecordError::MagicMismatch(_, _)) => {
                // 残り records が信頼できない。chunk 末尾扱い。
                let _ = sink.emit_issue(record_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(record_offset_in_file)),
                    Some(*records_seen),
                    &format!(
                        "chunk {chunk_index} 内で record magic 不一致（以降の records を打ち切り）"
                    ),
                ));
                *issues_emitted += 1;
                chunk_partial = true;
                break;
            }
            Err(RecordError::TooShort(_)) => {
                // chunk 末尾の端数。Warning せずそのまま break。
                break;
            }
            Err(e) => {
                // その他の破損：1 record skip 可能か確認。
                let _ = sink.emit_issue(record_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(record_offset_in_file)),
                    Some(*records_seen),
                    &format!("chunk {chunk_index} 内の record parse 失敗: {e}"),
                ));
                *issues_emitted += 1;
                chunk_partial = true;
                // 次の record magic を探索して継続を試みる。
                if let Some(next) = find_next_record_magic(records, offset + 1) {
                    offset = next;
                } else {
                    break;
                }
            }
        }
    }

    ChunkOutcome {
        chunk_partial,
        abort_file: false,
    }
}

/// `from` 以降で次の record magic（0x2a2a）の位置を探す。見つからなければ None。
fn find_next_record_magic(records: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < records.len() {
        if records[i] == 0x2a && records[i + 1] == 0x2a {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 1 EVTX record から Event を構築する。
///
/// 必須 field（record id・timestamp・event_id・provider・channel）のいずれかが欠落している
/// 場合は `None` を返し、呼出側で Issue 化する（互換 §5）。
fn build_event(
    parsed: &ParsedRecord,
    record_offset_in_file: u64,
    chunk_index: usize,
    context: &ParseContext,
    event_ordinal: u64,
) -> Option<tf_core::event::Event> {
    let header = &parsed.header;
    let content = &parsed.content;

    // 互換 §5 必須 field: event_record_id・timestamp・event_id・provider・channel。
    if header.event_record_id == 0 {
        return None;
    }
    if header.timestamp_filetime == 0 {
        return None;
    }
    let _event_id = content.event_id?;
    let _provider = content.provider_name.as_deref()?;
    let _channel = content.channel.as_deref()?;

    // 時刻: FILETIME → DateTime<Utc>。0 は呼出側で弾いているが、filetime_to_datetime の
    // 失敗も考慮し Unknown へフォールバックする（規範 §6.2: 不明時刻は補完しない）。
    let event_time = match filetime_to_datetime(header.timestamp_filetime) {
        Some(dt) => EventTime::utc_instant(
            dt,
            Some(format!("FILETIME({})", header.timestamp_filetime)),
            TimestampKind::EventLogged,
            TimePrecision::Microsecond,
            TimezoneSource::ArtifactDefined,
        ),
        None => EventTime::unknown(TimestampKind::EventLogged),
    };

    // typed mapping（互換 §4.2: channel + provider + 必須 field 同時検証）。
    let event_type_str = map_event_type(content);
    let event_type = EventType::new(event_type_str);

    // Provenance: ByteRange で元 record 位置へ到達できる（規範 §7.3・互換 §12-3）。
    let record_locator = RecordLocator::ByteRange {
        start: record_offset_in_file,
        end: record_offset_in_file + 2 + header.size as u64,
    };
    let provenance = context.make_provenance(record_locator, event_ordinal);

    // path と process は typed mapping 結果に応じて設定。
    let (path, process) = build_path_and_process(content, event_type_str);

    let hostname = content.computer.clone();
    let user = extract_user(content);
    let message = build_message(content, event_type_str);

    let mut attrs = build_base_attributes(parsed, content, chunk_index);

    // EventData を attribute へ保存（raw field 保持・互換 §4.2）。
    for (k, v) in &content.event_data {
        attrs.insert(format!("evtx.event_data.{k}"), event_data_value_to_json(v));
    }

    let mut event = tf_core::event::Event {
        id: String::new(),
        time: event_time,
        source: ArtifactSource::Evtx,
        event_type,
        assertion: AssertionKind::Observed,
        hostname,
        user,
        path,
        program: None,
        process,
        message,
        attributes: attrs,
        provenance,
    };
    event.id = event.compute_id(event_ordinal);
    Some(event)
}

/// typed mapping 結果に応じて path / process を設定する。
fn build_path_and_process(
    content: &EventContent,
    event_type_str: &str,
) -> (Option<WindowsPathValue>, Option<tf_core::event::ProcessRef>) {
    let process_path = match event_type_str {
        "process_start" | "process_stop" => {
            find_first_data(content, &["NewProcessName", "ProcessName", "Image"])
        }
        "service_create" => find_first_data(content, &["ImagePath"]),
        _ => None,
    };
    if let Some(p) = process_path {
        let path = Some(WindowsPathValue::new(p));
        let process = Some(tf_core::event::ProcessRef {
            pid: find_first_data_i64(content, &["NewProcessId", "ProcessId"]),
            ppid: None,
            process_guid: find_first_data(content, &["ProcessGuid"]).map(String::from),
            parent_process_guid: None,
            image_path: Some(WindowsPathValue::new(p)),
            command_line: find_first_data(content, &["CommandLine"]).map(String::from),
        });
        return (path, process);
    }
    (None, None)
}

fn find_first_data<'a>(content: &'a EventContent, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        for (name, value) in &content.event_data {
            if name.eq_ignore_ascii_case(k)
                && let EventDataValue::Str(s) = value
            {
                return Some(s.as_str());
            }
        }
    }
    None
}

fn find_first_data_i64(content: &EventContent, keys: &[&str]) -> Option<u64> {
    for k in keys {
        for (name, value) in &content.event_data {
            if name.eq_ignore_ascii_case(k)
                && let Some(n) = value.as_i64()
                && n >= 0
            {
                return Some(n as u64);
            }
        }
    }
    None
}

fn extract_user(content: &EventContent) -> Option<String> {
    find_first_data(content, &["TargetUserName", "SubjectUserName", "User"]).map(String::from)
}

fn build_message(content: &EventContent, event_type_str: &str) -> String {
    let id = content.event_id.unwrap_or(-1);
    let channel = content.channel.as_deref().unwrap_or("?");
    let provider = content.provider_name.as_deref().unwrap_or("?");
    if event_type_str == EVENT_LOGGED_TYPE {
        format!("EVTX event 観測: EventID={id} channel={channel} provider={provider}")
    } else {
        format!(
            "EVTX typed event: type={event_type_str} EventID={id} channel={channel} provider={provider}"
        )
    }
}

/// Event 共通の attributes を構築する（BTreeMap・規範 §13.2 決定性）。
fn build_base_attributes(
    parsed: &ParsedRecord,
    content: &EventContent,
    chunk_index: usize,
) -> std::collections::BTreeMap<String, Value> {
    let mut attrs = std::collections::BTreeMap::new();
    attrs.insert(
        "evtx.event_record_id".into(),
        Value::from(parsed.header.event_record_id),
    );
    attrs.insert(
        "evtx.timestamp_filetime".into(),
        Value::from(parsed.header.timestamp_filetime),
    );
    attrs.insert("evtx.chunk_index".into(), Value::from(chunk_index as u64));
    attrs.insert("evtx.record_size".into(), Value::from(parsed.header.size));
    if let Some(id) = content.event_id {
        attrs.insert("evtx.event_id".into(), Value::from(id));
    }
    if let Some(v) = content.version {
        attrs.insert("evtx.version".into(), Value::from(v));
    }
    if let Some(v) = content.level {
        attrs.insert("evtx.level".into(), Value::from(v));
    }
    if let Some(v) = content.opcode {
        attrs.insert("evtx.opcode".into(), Value::from(v));
    }
    if let Some(v) = content.task {
        attrs.insert("evtx.task".into(), Value::from(v));
    }
    if let Some(v) = content.keywords {
        attrs.insert("evtx.keywords".into(), Value::from(v));
    }
    if let Some(s) = &content.provider_name {
        attrs.insert("evtx.provider".into(), Value::String(s.clone()));
    }
    if let Some(s) = &content.provider_guid {
        attrs.insert("evtx.provider_guid".into(), Value::String(s.clone()));
    }
    if let Some(s) = &content.channel {
        attrs.insert("evtx.channel".into(), Value::String(s.clone()));
    }
    attrs.insert(
        "evtx.reference_spec".into(),
        Value::String(EVTX_REFERENCE.to_string()),
    );
    attrs.insert(
        "evtx.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );
    attrs
}

fn event_data_value_to_json(v: &EventDataValue) -> Value {
    match v {
        EventDataValue::Null => Value::Null,
        EventDataValue::Str(s) => Value::String(s.clone()),
        EventDataValue::Int(n) => Value::from(*n),
        EventDataValue::UInt(n) => Value::from(*n),
        EventDataValue::Bool(b) => Value::Bool(*b),
        EventDataValue::FileTime(ft) => Value::from(*ft),
        EventDataValue::Other(s) => Value::String(s.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evtx::binxml::{
        BinXmlBuilder, EventContentSpec, EventDataEntry, ValueKind, ev_data,
    };
    use crate::evtx::chunk::{CHUNK_BYTES, CHUNK_MAGIC};
    use crate::evtx::crc32::crc32_sequential;
    use crate::evtx::header::{EVTX_MAJOR_VERSION, EVTX_MINOR_VERSION};
    use std::io::Cursor;

    /// テスト用 sink: Event と Issue を蓄積。
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
                evidence_id: "tf-evidence-v1:evtx-test".to_string(),
                source_locator: "Security.evtx".to_string(),
                size: 200,
                sha256: "ab".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:evtx-test".to_string(),
                evidence_id: "tf-evidence-v1:evtx-test".to_string(),
                artifact_type: ArtifactSource::Evtx,
                parser_id: PARSER_ID.to_string(),
                parser_version: PARSER_VERSION.to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["ElfFile magic".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    /// file header を構築する。
    fn build_file_header(chunk_count: u16) -> Vec<u8> {
        let mut buf = vec![0u8; FILE_HEADER_BYTES];
        buf[0..8].copy_from_slice(&EVTX_FILE_MAGIC);
        buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // first chunk
        buf[16..24].copy_from_slice(&(chunk_count as u64).to_le_bytes());
        buf[24..32].copy_from_slice(&0u64.to_le_bytes());
        buf[32..36].copy_from_slice(&128u32.to_le_bytes());
        buf[36..38].copy_from_slice(&EVTX_MINOR_VERSION.to_le_bytes());
        buf[38..40].copy_from_slice(&EVTX_MAJOR_VERSION.to_le_bytes());
        buf[40..42].copy_from_slice(&4096u16.to_le_bytes());
        buf[44..46].copy_from_slice(&chunk_count.to_le_bytes());
        let cksum = crc32_sequential(&buf[0..120], &buf[128..4096]);
        buf[124..128].copy_from_slice(&cksum.to_le_bytes());
        buf
    }

    /// 1件の EVTX record bytes を構築する。
    fn build_record(record_id: u64, timestamp_ft: u64, spec: &EventContentSpec) -> Vec<u8> {
        let mut builder = BinXmlBuilder::new();
        builder.start_event(spec);
        let binxml = builder.finish();
        let size = 4 + 8 + 8 + binxml.len() + 4;
        let mut buf = Vec::with_capacity(2 + size);
        buf.extend_from_slice(&[0x2a, 0x2a]); // magic
        buf.extend_from_slice(&(size as i32).to_le_bytes());
        buf.extend_from_slice(&record_id.to_le_bytes());
        buf.extend_from_slice(&timestamp_ft.to_le_bytes());
        buf.extend_from_slice(&binxml);
        buf.extend_from_slice(&(size as i32).to_le_bytes());
        buf
    }

    /// 1件の record を含む chunk bytes を構築する。
    fn build_chunk_with_records(records: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = vec![0u8; CHUNK_BYTES];
        buf[0..8].copy_from_slice(&CHUNK_MAGIC);
        buf[40..44].copy_from_slice(&512u32.to_le_bytes()); // header_size
        let records_total: usize = records.iter().map(|r| r.len()).sum();
        let free_space_offset = 512 + records_total;
        buf[48..52].copy_from_slice(&(free_space_offset as u32).to_le_bytes());
        // records checksum: bytes [512..free_space_offset]
        let mut records_region = Vec::new();
        for r in records {
            records_region.extend_from_slice(r);
        }
        buf[512..512 + records_region.len()].copy_from_slice(&records_region);
        let records_crc = crate::evtx::crc32::crc32(&buf[512..free_space_offset]);
        buf[52..56].copy_from_slice(&records_crc.to_le_bytes());
        // header checksum 1: bytes [0..120] + [128..504]
        let cksum1 = crc32_sequential(&buf[0..120], &buf[128..504]);
        buf[496..500].copy_from_slice(&cksum1.to_le_bytes());
        // header checksum 2: bytes [0..120] + [128..512]
        let cksum2 = crc32_sequential(&buf[0..120], &buf[128..512]);
        buf[504..508].copy_from_slice(&cksum2.to_le_bytes());
        buf
    }

    fn build_evtx_file(records_per_chunk: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let mut file = build_file_header(records_per_chunk.len() as u16);
        for chunk_records in records_per_chunk {
            let chunk = build_chunk_with_records(chunk_records);
            file.extend_from_slice(&chunk);
        }
        file
    }

    fn login_4624_spec(computer: &str) -> EventContentSpec {
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

    fn service_7045_spec() -> EventContentSpec {
        EventContentSpec {
            provider_name: "Service Control Manager".to_string(),
            provider_guid: None,
            event_id: 7045,
            version: None,
            level: None,
            channel: "System".to_string(),
            computer: "HOST".to_string(),
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

    #[test]
    fn parser_metadata_is_stable() {
        let p = EvtxParser::new();
        assert_eq!(p.parser_id(), "traceforge-evtx");
        assert_eq!(p.parser_version(), "1.0.0");
        assert_eq!(p.artifact_type(), ArtifactSource::Evtx);
    }

    #[test]
    fn empty_stream_completes_with_no_events() {
        let mut cursor = Cursor::new(Vec::new());
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Skipped);
        assert_eq!(sink.events.len(), 0);
    }

    #[test]
    fn parses_single_4624_event() {
        let ft = 132_548_480_000_000_000u64;
        let record = build_record(1, ft, &login_4624_spec("WS1"));
        let file = build_evtx_file(&[vec![record]]);
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(sink.events.len(), 1);
        let e = &sink.events[0];
        assert_eq!(e.event_type.as_str(), "login");
        assert_eq!(e.source, ArtifactSource::Evtx);
        assert_eq!(e.hostname.as_deref(), Some("WS1"));
        assert_eq!(e.user.as_deref(), Some("alice"));
        assert_eq!(e.attributes["evtx.event_id"], 4624);
        assert_eq!(e.attributes["evtx.channel"], "Security");
    }

    #[test]
    fn parses_multiple_events_across_chunks() {
        let ft = 132_548_480_000_000_000u64;
        let r1 = build_record(1, ft, &login_4624_spec("WS1"));
        let r2 = build_record(2, ft + 100, &service_7045_spec());
        let file = build_evtx_file(&[vec![r1], vec![r2]]);
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(
            summary.status,
            ParseStatus::Complete,
            "issues: {:?}",
            sink.issues
        );
        assert_eq!(sink.events.len(), 2);
        assert_eq!(summary.records_seen, 2);
    }

    #[test]
    fn truncated_file_header_skipped() {
        let short = vec![0u8; 100];
        let mut cursor = Cursor::new(short);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Skipped);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == TRUNCATED_RECORD_CODE)
        );
    }

    #[test]
    fn legacy_evt_magic_skipped_with_unsupported_version_issue() {
        // 先頭4 byte を Legacy .evt の値へ。file header は 4096 byte 用意する。
        let mut buf = vec![0u8; FILE_HEADER_BYTES];
        buf[0..4].copy_from_slice(&[0x4c, 0x66, 0x4c, 0x65]); // "LfLe"
        let mut cursor = Cursor::new(buf);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Skipped);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == UNSUPPORTED_VERSION_CODE),
            "Legacy .evt は Unsupported で記録"
        );
    }

    #[test]
    fn corrupt_chunk_magic_emits_warning_and_skips_chunk() {
        // 1件の正常 record を含む chunk を作り、その chunk の magic を破壊。
        let ft = 132_548_480_000_000_000u64;
        let r1 = build_record(1, ft, &login_4624_spec("WS1"));
        let r2 = build_record(2, ft + 100, &login_4624_spec("WS2"));
        let mut file = build_evtx_file(&[vec![r1], vec![r2]]);
        // 2個目の chunk (offset = 4096 + 65536) の magic を破壊。
        let bad_offset = FILE_HEADER_BYTES + CHUNK_BYTES;
        file[bad_offset..bad_offset + 8].copy_from_slice(b"BADBADAD");
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Partial);
        // 1個目の chunk から1 event 生成、2個目は skip。
        assert_eq!(sink.events.len(), 1);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == MALFORMED_INPUT_CODE)
        );
    }

    #[test]
    fn corrupt_record_in_middle_preserves_other_events() {
        // 正常 record → 破損 record → 正常 record を同じ chunk へ。
        let ft = 132_548_480_000_000_000u64;
        let r1 = build_record(1, ft, &login_4624_spec("WS1"));
        let r3 = build_record(3, ft + 200, &login_4624_spec("WS3"));
        // 破損 record: magic は正しいが size が矛盾。
        let mut bad = vec![0x2a, 0x2a];
        bad.extend_from_slice(&100i32.to_le_bytes());
        bad.extend_from_slice(&[0u8; 30]);

        let file = build_evtx_file(&[vec![r1, bad, r3]]);
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        // partial recovery により r1 は必ず1 event 生成。
        assert!(
            !sink.events.is_empty(),
            "partial recovery で最低1 event 生成 (got {})",
            sink.events.len()
        );
        assert_eq!(summary.status, ParseStatus::Partial);
    }

    #[test]
    fn provenance_record_locator_points_to_record_bytes() {
        let ft = 132_548_480_000_000_000u64;
        let record = build_record(1, ft, &login_4624_spec("WS1"));
        let file = build_evtx_file(&[vec![record]]);
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        let e = &sink.events[0];
        match &e.provenance.record_locator {
            RecordLocator::ByteRange { start, end } => {
                // chunk 0・records 領域の先頭 (offset 4096 + 512) へ一致。
                assert_eq!(*start, (FILE_HEADER_BYTES + 512) as u64);
                assert!(end > start);
            }
            other => panic!("ByteRange 期待だが {other:?}"),
        }
        assert_eq!(e.provenance.parser_id, PARSER_ID);
        assert_eq!(e.provenance.parser_version, PARSER_VERSION);
    }

    #[test]
    fn all_typed_mappings_produce_distinct_types() {
        let ft = 132_548_480_000_000_000u64;
        let specs_and_expected = vec![
            (
                EventContentSpec {
                    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                    provider_guid: None,
                    event_id: 4624,
                    version: Some(0),
                    level: Some(0),
                    channel: "Security".to_string(),
                    computer: "H".to_string(),
                    event_data: vec![ev_data("TargetUserName", "u1")],
                },
                "login",
            ),
            (
                EventContentSpec {
                    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                    provider_guid: None,
                    event_id: 4625,
                    version: Some(0),
                    level: Some(0),
                    channel: "Security".to_string(),
                    computer: "H".to_string(),
                    event_data: vec![ev_data("TargetUserName", "u1")],
                },
                "login_failure",
            ),
            (
                EventContentSpec {
                    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                    provider_guid: None,
                    event_id: 4688,
                    version: Some(0),
                    level: Some(0),
                    channel: "Security".to_string(),
                    computer: "H".to_string(),
                    event_data: vec![ev_data("NewProcessName", "C:\\Windows\\System32\\cmd.exe")],
                },
                "process_start",
            ),
            (
                EventContentSpec {
                    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                    provider_guid: None,
                    event_id: 4689,
                    version: Some(0),
                    level: Some(0),
                    channel: "Security".to_string(),
                    computer: "H".to_string(),
                    event_data: vec![ev_data("ProcessName", "C:\\Windows\\System32\\cmd.exe")],
                },
                "process_stop",
            ),
            (service_7045_spec(), "service_create"),
        ];
        for (spec, expected_type) in specs_and_expected {
            let record = build_record(1, ft, &spec);
            let file = build_evtx_file(&[vec![record]]);
            let mut cursor = Cursor::new(file);
            let context = make_context();
            let mut sink = TestSink {
                events: vec![],
                issues: vec![],
            };
            let _ = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
            assert_eq!(sink.events.len(), 1, "event for {:?}", spec);
            assert_eq!(
                sink.events[0].event_type.as_str(),
                expected_type,
                "expected type for {:?}",
                spec
            );
        }
    }

    #[test]
    fn fallback_to_generic_when_channel_mismatches() {
        // 4624 だが channel が Security 以外。
        let ft = 132_548_480_000_000_000u64;
        let mut spec = login_4624_spec("H");
        spec.channel = "Application".to_string();
        let record = build_record(1, ft, &spec);
        let file = build_evtx_file(&[vec![record]]);
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let _ = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].event_type.as_str(), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn unknown_event_id_yields_generic_event_logged() {
        let ft = 132_548_480_000_000_000u64;
        let spec = EventContentSpec {
            provider_name: "SomeProvider".to_string(),
            provider_guid: None,
            event_id: 9999,
            version: None,
            level: None,
            channel: "Application".to_string(),
            computer: "H".to_string(),
            event_data: vec![],
        };
        let record = build_record(1, ft, &spec);
        let file = build_evtx_file(&[vec![record]]);
        let mut cursor = Cursor::new(file);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let _ = EvtxParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].event_type.as_str(), EVENT_LOGGED_TYPE);
    }
}
