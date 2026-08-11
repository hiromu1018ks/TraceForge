//! USN Journal Parser（Windows NTFS Update Sequence Journal、互換 §4.3、T4-030〜T4-037）。
//!
//! ## 対象形式
//!
//! NTFS ボリュームの `$UsnJrnl:$J` Alternate Data Stream。`USN_RECORD_COMMON_HEADER`
//! の `MajorVersion` で V2 / V3 / V4 を判定する（互換 §4.3）。各レコードは可変長で、
//! `RecordLength` で後続レコードの境界を知る。
//!
//! ## 観測型 Event の方針（規範 §7.1・互換 §4.3）
//!
//! USN record は「ファイルシステム変更の観測」を表す。`file_created`・`file_deleted` 等の
//! 断定型 Event type へ変換してはならない。本 Parser は [`USN_CHANGE_OBSERVED_EVENT_TYPE`]
//! （`usn_change_observed`）を生成する。rename 結合も観測の1形態であり、断定ではない。
//!
//! ## 部分成功（規範 §9.2・§21-5）
//!
//! USN $J は record-stream 型。中間 record の破損は Issue 化し、前後の正常 record から
//! Event を生成し続ける。境界（record_length）を特定できない破損だけ `Partial` 終了する。
//!
//! ## path reconstruction（互換 §4.3・§8）
//!
//! 同一 Evidence set 内の安全な親 directory mapping のみで path を組み立てる。
//! host filesystem へ検索しに行かない。
//!
//! ## 参照外部仕様
//!
//! Microsoft `winioctl.h`（USN_RECORD_V2/V3/V4）と `ntifs.h`（USN_RECORD_COMMON_HEADER）。
//! URL は互換 §4.3 の参照リストを参照。

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read};

use serde_json::Value;

use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{
    INVALID_LENGTH_CODE, MALFORMED_INPUT_CODE, PARTIAL_RECORD_BOUNDARY_CODE, TRUNCATED_RECORD_CODE,
    UNSUPPORTED_VERSION_CODE, artifact_issue, record_issue,
};
use crate::lnk::filetime::filetime_to_datetime;
use crate::usn::combine::{UsnObservation, combine_records};
use crate::usn::header::{COMMON_HEADER_BYTES, is_supported_major_version, parse_common_header};
use crate::usn::path::PathResolver;
use crate::usn::reason::{ReasonInterpretation, interpret};
use crate::usn::record::{FileReference, MAX_RECORD_LENGTH, UsnRecord, parse_record};

pub mod combine;
pub mod header;
pub mod path;
pub mod reason;
pub mod record;

/// 1ストリームあたりの安全上限（record 数）。これを超えると `Partial` で打ち切る。
/// 現実的な USN $J では数十万〜数百万 record 程度。異常入力からの無限 loop を防ぐ。
const MAX_RECORDS: usize = 5_000_000;

/// snapshot 1回分の読取上限（byte）。巨大すぎる file からの過大 memory 確保を防ぐ。
/// USN $J は数 GB になることがあるため、上限は大きめ（256 MiB）。
const SNAPSHOT_READ_CAP: u64 = 256 * 1024 * 1024;

/// USN Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-usn";
/// USN Parser の version（SemVer）。
pub const PARSER_VERSION: &str = "1.0.0";

/// USN $J 由来の観測 Event type（規範 §7.1・互換 §4.3）。
///
/// USN record の存在は「ファイルシステム変更の観測」であり、`file_created`・`file_deleted`
/// 等の断定型へ変換しない（AGENTS.md 禁止事項）。
pub const USN_CHANGE_OBSERVED_EVENT_TYPE: &str = "usn_change_observed";

/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
///
/// Microsoft `winioctl.h`（USN_RECORD_V2/V3/V4）・`ntifs.h`（USN_RECORD_COMMON_HEADER）。
pub const USN_REFERENCE: &str =
    "Microsoft winioctl.h USN_RECORD_V2/V3/V4 + ntifs.h USN_RECORD_COMMON_HEADER";

/// USN Parser 本体。
#[derive(Default)]
pub struct UsnParser;

impl UsnParser {
    pub fn new() -> Self {
        UsnParser
    }
}

impl ArtifactParser for UsnParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::UsnJournal
    }

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
        // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
        if evidence.integrity_status != tf_core::case::IntegrityStatus::VerifiedSnapshot {
            return ProbeResult::NotThisFormat;
        }

        // snapshot 先頭 8 byte（= COMMON_HEADER_BYTES）を読む。
        let path = std::path::Path::new(&evidence.snapshot_locator);
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return ProbeResult::NotThisFormat,
        };
        let mut buf = [0u8; COMMON_HEADER_BYTES];
        let n = file.read(&mut buf).unwrap_or(0);
        if n < COMMON_HEADER_BYTES {
            return ProbeResult::NotThisFormat;
        }
        // USN $J は file 先頭が即 USN_RECORD_COMMON_HEADER。
        let header = match parse_common_header(&buf) {
            Ok(h) => h,
            Err(_) => return ProbeResult::NotThisFormat,
        };
        if !is_supported_major_version(header.major_version) {
            return ProbeResult::NotThisFormat;
        }
        // record_length が明らかにおかしい場合は Malformed 扱い。
        if header.record_length < COMMON_HEADER_BYTES as u32
            || header.record_length > MAX_RECORD_LENGTH
        {
            return ProbeResult::Malformed;
        }
        ProbeResult::Confirmed
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
        let mut bytes_consumed: u64 = 0;
        let mut collected: Vec<UsnRecord> = Vec::new();
        let mut partial = false;

        loop {
            // === Common header (8 byte) を読む。===
            let mut header_buf = [0u8; COMMON_HEADER_BYTES];
            match read_exact_or_eof(snapshot, &mut header_buf) {
                ReadOutcome::Complete => {}
                ReadOutcome::Eof => break, // 正常終端
                ReadOutcome::Error(e) => {
                    let _ = sink.emit_issue(artifact_issue(
                        MALFORMED_INPUT_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        &format!("snapshot 読取に失敗した: {e}"),
                    ));
                    issues_emitted += 1;
                    partial = true;
                    break;
                }
            }

            // サイズ上限監視: USN $J が巨大な場合の安全装置。
            if bytes_consumed > SNAPSHOT_READ_CAP {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!(
                        "snapshot size 上限 ({SNAPSHOT_READ_CAP} byte) を超えたため打ち切った"
                    ),
                ));
                issues_emitted += 1;
                partial = true;
                break;
            }

            let header = match parse_common_header(&header_buf) {
                Ok(h) => h,
                Err(_) => {
                    // header 8 byte を読めた時点で parse_common_header は成功するはず。
                    // ここへ来ることは非現実的だが、安全のため打ち切る。
                    partial = true;
                    break;
                }
            };

            // record_length == 0 は終端扱い（一部の $J 実装）。
            if header.record_length == 0 {
                break;
            }

            // record_length < COMMON_HEADER_BYTES は境界が分からないため Partial 終了。
            if (header.record_length as usize) < COMMON_HEADER_BYTES {
                let _ = sink.emit_issue(record_issue(
                    INVALID_LENGTH_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(bytes_consumed)),
                    Some(records_seen),
                    &format!(
                        "record_length {} が common header ({COMMON_HEADER_BYTES} byte) 未満",
                        header.record_length
                    ),
                ));
                issues_emitted += 1;
                partial = true;
                break;
            }

            // record_length が異常に大きい場合は境界を信頼できないため Partial 終了。
            if header.record_length > MAX_RECORD_LENGTH {
                let _ = sink.emit_issue(record_issue(
                    INVALID_LENGTH_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(bytes_consumed)),
                    Some(records_seen),
                    &format!(
                        "record_length {} が上限 ({MAX_RECORD_LENGTH}) を超えた",
                        header.record_length
                    ),
                ));
                issues_emitted += 1;
                partial = true;
                break;
            }

            // 未対応 MajorVersion: record_length が安全なら skip して継続（T4-036）。
            if !is_supported_major_version(header.major_version) {
                // skip 分を reader から進める。
                let advance = header.record_length as u64 - COMMON_HEADER_BYTES as u64;
                let skip_outcome = skip_bytes(snapshot, advance);
                if let Err(e) = skip_outcome {
                    let _ = sink.emit_issue(record_issue(
                        UNSUPPORTED_VERSION_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteOffset(bytes_consumed)),
                        Some(records_seen),
                        &format!(
                            "MajorVersion {} の skip 中に reader が終端に達した: {e}",
                            header.major_version
                        ),
                    ));
                    issues_emitted += 1;
                    bytes_consumed += header.record_length as u64;
                    partial = true;
                    break;
                }
                let _ = sink.emit_issue(record_issue(
                    UNSUPPORTED_VERSION_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteRange {
                        start: bytes_consumed,
                        end: bytes_consumed + header.record_length as u64,
                    }),
                    Some(records_seen),
                    &format!(
                        "未対応 MajorVersion {} (MinorVersion {}) を skip した",
                        header.major_version, header.minor_version
                    ),
                ));
                issues_emitted += 1;
                bytes_consumed += header.record_length as u64;
                continue;
            }

            // === record_length 分の buffer を読む。===
            let mut body_buf = vec![0u8; header.record_length as usize];
            body_buf[..COMMON_HEADER_BYTES].copy_from_slice(&header_buf);
            match read_exact_or_eof(snapshot, &mut body_buf[COMMON_HEADER_BYTES..]) {
                ReadOutcome::Complete => {}
                ReadOutcome::Eof => {
                    // record_length だけ宣言したのに途中で切れた。
                    let _ = sink.emit_issue(record_issue(
                        TRUNCATED_RECORD_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteOffset(bytes_consumed)),
                        Some(records_seen),
                        &format!(
                            "record_length {} だが snapshot が途中で終わった",
                            header.record_length
                        ),
                    ));
                    issues_emitted += 1;
                    partial = true;
                    break;
                }
                ReadOutcome::Error(e) => {
                    let _ = sink.emit_issue(record_issue(
                        MALFORMED_INPUT_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteOffset(bytes_consumed)),
                        Some(records_seen),
                        &format!("record 読取に失敗した: {e}"),
                    ));
                    issues_emitted += 1;
                    partial = true;
                    break;
                }
            }

            let record_offset = bytes_consumed;
            bytes_consumed += header.record_length as u64;

            // === record を parse（境界は安全なので、失敗しても継続可能）。===
            match parse_record(&body_buf, &header, record_offset) {
                Ok(rec) => {
                    records_seen += 1;
                    collected.push(rec);
                }
                Err(e) => {
                    // 境界は record_length で分かるため、次 record へ進める。
                    let _ = sink.emit_issue(record_issue(
                        MALFORMED_INPUT_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteRange {
                            start: record_offset,
                            end: record_offset + header.record_length as u64,
                        }),
                        Some(records_seen),
                        &format!("record parse 失敗: {e}"),
                    ));
                    issues_emitted += 1;
                }
            }

            // record 数上限（異常入力からの無限 loop 回避）。
            if collected.len() >= MAX_RECORDS {
                let _ = sink.emit_issue(artifact_issue(
                    PARTIAL_RECORD_BOUNDARY_CODE,
                    tf_core::issue::IssueSeverity::Recoverable,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("record 数上限 ({MAX_RECORDS}) へ到達したため打ち切った"),
                ));
                issues_emitted += 1;
                partial = true;
                break;
            }
        }

        // === rename 結合 ===
        let observations = combine_records(collected);

        // === path resolver を構築（同一 Evidence set 内の mapping のみ）===
        let resolver = PathResolver::from_records(
            observations
                .iter()
                .flat_map(|o| o.records.iter())
                .collect::<Vec<_>>()
                .into_iter(),
        );

        // === 各 observation を Event へ変換して sink へ流す。===
        let mut event_ordinal: u64 = 0;
        for observation in &observations {
            let event = match build_event(observation, &resolver, context, event_ordinal) {
                Some(e) => e,
                None => continue,
            };
            event_ordinal += 1;
            if sink.emit_event(event).is_err() {
                // sink 側の事情（EventStore の I/O エラー等）で継続不能。
                partial = true;
                break;
            }
            events_emitted += 1;
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

/// `read_exact` の結果を「完全読取・EOF・エラー」の3通りへ分ける。
enum ReadOutcome {
    /// 完全に読めた。
    Complete,
    /// EOF（1 byte も読めなかった、または途中で切れた）。
    Eof,
    /// I/O エラー。
    Error(std::io::Error),
}

fn read_exact_or_eof(reader: &mut dyn ReadSeek, buf: &mut [u8]) -> ReadOutcome {
    if buf.is_empty() {
        return ReadOutcome::Complete;
    }
    match reader.read(buf) {
        Ok(0) => ReadOutcome::Eof,
        Ok(n) if n == buf.len() => ReadOutcome::Complete,
        Ok(n) => {
            // 部分的にしか読めなかった → EOF 扱い（truncated）。
            // buf の残りは 0 のままで呼出側が判断する。
            let _ = n;
            ReadOutcome::Eof
        }
        Err(e) => ReadOutcome::Error(e),
    }
}

/// `reader` から `n` byte 進める。seek 不可環境でも動くよう read で消費する。
fn skip_bytes(reader: &mut dyn ReadSeek, n: u64) -> Result<(), std::io::Error> {
    let mut remaining = n;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n_read = reader.read(&mut buf[..want])?;
        if n_read == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "skip 中に EOF",
            ));
        }
        remaining -= n_read as u64;
    }
    Ok(())
}

/// observation から USN Event を構築する。
/// V4 で filename が無く、Event 化できない場合は `None` を返す（互換 §5: 必須 field 欠落）。
fn build_event(
    observation: &UsnObservation,
    resolver: &PathResolver,
    context: &ParseContext,
    event_ordinal: u64,
) -> Option<tf_core::event::Event> {
    let first = observation.first();
    // 互換 §5 必須 field: USN には「filename」が含まれる（V2/V3）。
    // V4 は filename が無いため、filename 無し record のみから成る observation は Event 化しない。
    // ただし rename 結合時は first が OLD_NAME（filename あり）になるため、ここへ来ない。
    first.file_name.as_ref()?;

    let header = &first.header;
    let interpretation = interpret(first.reason);

    // Provenance: ByteRange で元 record 位置へ到達できる（規範 §7.3・互換 §12-3）。
    let record_locator = RecordLocator::ByteRange {
        start: first.record_offset,
        end: first.record_offset + header.record_length as u64,
    };
    let provenance = context.make_provenance(record_locator, event_ordinal);

    // 時刻: FILETIME → DateTime<Utc>。0 は Unknown（規範 §6.2: 不明時刻は補完しない）。
    let event_time = if first.time_filetime == 0 {
        EventTime::unknown(TimestampKind::EventLogged)
    } else {
        match filetime_to_datetime(first.time_filetime) {
            Some(dt) => EventTime::utc_instant(
                dt,
                Some(format!("FILETIME({})", first.time_filetime)),
                TimestampKind::EventLogged,
                TimePrecision::Microsecond,
                TimezoneSource::ArtifactDefined,
            ),
            None => EventTime::unknown(TimestampKind::EventLogged),
        }
    };

    // path: 同一 Evidence set 内の mapping で安全に構築できる場合のみ。
    let path = resolver.resolve(observation);

    let message = build_message(observation, &interpretation);

    let mut attrs = build_base_attributes(first, &interpretation);
    if observation.rename_combined {
        add_rename_attributes(&mut attrs, observation);
    }

    let mut event = tf_core::event::Event {
        id: String::new(),
        time: event_time,
        source: ArtifactSource::UsnJournal,
        event_type: EventType::new(USN_CHANGE_OBSERVED_EVENT_TYPE),
        assertion: AssertionKind::Observed,
        hostname: None,
        user: None,
        path,
        program: None,
        process: None,
        message,
        attributes: attrs,
        provenance,
    };
    event.id = event.compute_id(event_ordinal);
    Some(event)
}

/// Event の message を構築する。
fn build_message(observation: &UsnObservation, interpretation: &ReasonInterpretation) -> String {
    let first = observation.first();
    let name = first.file_name.as_deref().unwrap_or("(filename 無し)");
    let flags = interpretation.flags.join("|");
    if observation.rename_combined {
        // rename 結合時は OLD_NAME → NEW_NAME を1行へ。
        let old = observation.records[0]
            .file_name
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string());
        let new = observation.records[1]
            .file_name
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string());
        format!("USN 変更観測 (rename): {old} → {new} (reason: {flags})")
    } else {
        format!("USN 変更観測: {name} (reason: {flags}, usn: {})", first.usn)
    }
}

/// USN Event 共通の attributes を構築する（BTreeMap・規範 §13.2 決定性）。
fn build_base_attributes(
    record: &UsnRecord,
    interpretation: &ReasonInterpretation,
) -> BTreeMap<String, Value> {
    let mut attrs = BTreeMap::new();
    attrs.insert(
        "usn.major_version".into(),
        Value::from(record.header.major_version),
    );
    attrs.insert(
        "usn.minor_version".into(),
        Value::from(record.header.minor_version),
    );
    attrs.insert("usn.usn".into(), Value::from(record.usn));
    attrs.insert("usn.reason".into(), Value::from(record.reason));
    attrs.insert(
        "usn.reason_flags".into(),
        Value::Array(
            interpretation
                .flags
                .iter()
                .map(|s| Value::String((*s).to_string()))
                .collect(),
        ),
    );
    if interpretation.unknown_bits != 0 {
        attrs.insert(
            "usn.reason_unknown_bits".into(),
            Value::from(interpretation.unknown_bits),
        );
    }
    attrs.insert(
        "usn.file_reference".into(),
        Value::String(file_reference_attr(&record.file_reference)),
    );
    attrs.insert(
        "usn.parent_reference".into(),
        Value::String(file_reference_attr(&record.parent_reference)),
    );
    if let Some(seg) = record.file_reference.mft_segment_number() {
        attrs.insert("usn.file_reference_mft_number".into(), Value::from(seg));
    }
    if let Some(seq) = record.file_reference.sequence_number() {
        attrs.insert("usn.file_reference_sequence".into(), Value::from(seq));
    }
    attrs.insert("usn.source_info".into(), Value::from(record.source_info));
    attrs.insert("usn.security_id".into(), Value::from(record.security_id));
    attrs.insert(
        "usn.file_attributes".into(),
        Value::from(record.file_attributes),
    );
    attrs.insert(
        "usn.record_offset".into(),
        Value::from(record.record_offset),
    );
    attrs.insert(
        "usn.record_length".into(),
        Value::from(record.header.record_length),
    );
    attrs.insert(
        "usn.reference_spec".into(),
        Value::String(USN_REFERENCE.to_string()),
    );
    attrs.insert(
        "usn.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );
    // V4 の range tracking 情報（互換 §4.3: 保持必須）。
    if let Some(rt) = &record.range_tracking {
        attrs.insert(
            "usn.range_tracking".into(),
            serde_json::json!({
                "remaining_extents": rt.remaining_extents,
                "number_of_extents": rt.number_of_extents,
                "extent_location": rt.extent_location,
                "extent_length": rt.extent_length,
            }),
        );
    }
    attrs
}

/// rename 結合 observation の属性を追加する。
fn add_rename_attributes(attrs: &mut BTreeMap<String, Value>, observation: &UsnObservation) {
    attrs.insert("usn.rename.combined".into(), Value::Bool(true));
    if let Some(old) = &observation.records[0].file_name {
        attrs.insert("usn.rename.old_name".into(), Value::String(old.clone()));
    }
    if let Some(new) = &observation.records[1].file_name {
        attrs.insert("usn.rename.new_name".into(), Value::String(new.clone()));
    }
    attrs.insert(
        "usn.rename.old_usn".into(),
        Value::from(observation.records[0].usn),
    );
    attrs.insert(
        "usn.rename.new_usn".into(),
        Value::from(observation.records[1].usn),
    );
}

/// file reference を attribute へ格納する文字列へ。
/// version 別に一意に識別できる文字列（`v2:<16桁 hex>` / `v3v4:<32桁 hex>`）を返す。
fn file_reference_attr(reference: &FileReference) -> String {
    reference.as_comparison_key()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::header::CommonHeader;
    use crate::usn::reason::flags;
    use crate::usn::record::{FileId128, FileReference, RangeTracking, UsnRecord, V2_FIXED_BYTES};
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
                evidence_id: "tf-evidence-v1:usn-test".to_string(),
                source_locator: "$UsnJrnl$J".to_string(),
                size: 200,
                sha256: "ab".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:usn-test".to_string(),
                evidence_id: "tf-evidence-v1:usn-test".to_string(),
                artifact_type: ArtifactSource::UsnJournal,
                parser_id: PARSER_ID.to_string(),
                parser_version: PARSER_VERSION.to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["common header".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    /// テスト用の最小 V2 record bytes を構築する（record_length は自動計算）。
    fn v2_record(
        file_ref: u64,
        parent_ref: u64,
        usn: i64,
        time_ft: u64,
        reason: u32,
        name: &str,
    ) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let name_len_with_null = (name_bytes.len() + 2) as u16; // null 終端分 +2
        let total = V2_FIXED_BYTES + name_bytes.len() + 2;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[8..16].copy_from_slice(&file_ref.to_le_bytes());
        buf[16..24].copy_from_slice(&parent_ref.to_le_bytes());
        buf[24..32].copy_from_slice(&usn.to_le_bytes());
        buf[32..40].copy_from_slice(&time_ft.to_le_bytes());
        buf[40..44].copy_from_slice(&reason.to_le_bytes());
        buf[44..48].copy_from_slice(&0u32.to_le_bytes()); // source_info
        buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // security_id
        buf[52..56].copy_from_slice(&0u32.to_le_bytes()); // file_attributes
        buf[56..58].copy_from_slice(&name_len_with_null.to_le_bytes());
        buf[58..60].copy_from_slice(&(V2_FIXED_BYTES as u16).to_le_bytes());
        buf[60..60 + name_bytes.len()].copy_from_slice(&name_bytes);
        // null 終端は 0 のまま
        buf
    }

    /// V4 record を構築する（record_length は固定長）。
    fn v4_record(
        file_ref: FileId128,
        parent_ref: FileId128,
        usn: i64,
        time_ft: u64,
        reason: u32,
    ) -> Vec<u8> {
        let total = V4_FIXED_BYTES;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[8..24].copy_from_slice(&file_ref);
        buf[24..40].copy_from_slice(&parent_ref);
        buf[40..48].copy_from_slice(&usn.to_le_bytes());
        buf[48..56].copy_from_slice(&time_ft.to_le_bytes());
        buf[56..60].copy_from_slice(&reason.to_le_bytes());
        buf[60..64].copy_from_slice(&0u32.to_le_bytes()); // source_info
        buf[64..66].copy_from_slice(&0u16.to_le_bytes()); // remaining_extents
        buf[66..68].copy_from_slice(&1u16.to_le_bytes()); // number_of_extents
        buf[68..76].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[76..84].copy_from_slice(&4096u64.to_le_bytes());
        buf
    }

    const V4_FIXED_BYTES: usize = 84;

    #[test]
    fn parser_metadata_is_stable() {
        let p = UsnParser::new();
        assert_eq!(p.parser_id(), "traceforge-usn");
        assert_eq!(p.parser_version(), "1.0.0");
        assert_eq!(p.artifact_type(), ArtifactSource::UsnJournal);
    }

    #[test]
    fn empty_stream_completes_with_no_events() {
        let mut cursor = Cursor::new(Vec::new());
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(summary.records_seen, 0);
        assert_eq!(sink.events.len(), 0);
    }

    #[test]
    fn single_v2_record_emits_one_event() {
        let bytes = v2_record(
            0x0001_0000_0000_1234,
            0x0005_0000_0000_0001,
            100,
            132_548_480_000_000_000,
            flags::FILE_CREATE,
            "test.txt",
        );
        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(summary.records_seen, 1);
        assert_eq!(sink.events.len(), 1);
        let e = &sink.events[0];
        assert_eq!(e.event_type.as_str(), USN_CHANGE_OBSERVED_EVENT_TYPE);
        assert_eq!(e.source, ArtifactSource::UsnJournal);
        assert_eq!(e.attributes["usn.major_version"], 2);
        assert_eq!(e.attributes["usn.usn"], 100);
        assert!(e.attributes["usn.reason_flags"].is_array());
    }

    #[test]
    fn v2_and_v3_each_emit_events() {
        // V2 record 1件 + V3 record 1件 を連結。
        let mut v2 = v2_record(
            0x0001_0000_0000_1234,
            0x0005_0000_0000_0001,
            100,
            0,
            flags::DATA_EXTEND,
            "a.txt",
        );
        let actual_len = v2.len() as u32;
        v2[0..4].copy_from_slice(&actual_len.to_le_bytes());

        // V3 record: 固定 76 byte + filename "b"
        let v3_len: u32 = 76 + 4;
        let mut v3 = vec![0u8; v3_len as usize];
        v3[0..4].copy_from_slice(&v3_len.to_le_bytes());
        v3[4..6].copy_from_slice(&3u16.to_le_bytes());
        v3[6..8].copy_from_slice(&0u16.to_le_bytes());
        let file_id: [u8; 16] = [0xAA; 16];
        v3[8..24].copy_from_slice(&file_id);
        v3[24..40].copy_from_slice(&file_id);
        v3[40..48].copy_from_slice(&200i64.to_le_bytes());
        v3[56..60].copy_from_slice(&flags::FILE_DELETE.to_le_bytes());
        let name_bytes: Vec<u8> = "b".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_len = name_bytes.len() as u16 + 2;
        v3[72..74].copy_from_slice(&name_len.to_le_bytes());
        v3[74..76].copy_from_slice(&76u16.to_le_bytes());
        v3[76..76 + name_bytes.len()].copy_from_slice(&name_bytes);

        let mut bytes = v2;
        bytes.extend_from_slice(&v3);
        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(summary.records_seen, 2);
        assert_eq!(sink.events.len(), 2);
        let majors: Vec<&Value> = sink
            .events
            .iter()
            .map(|e| &e.attributes["usn.major_version"])
            .collect();
        assert_eq!(majors[0], 2);
        assert_eq!(majors[1], 3);
    }

    #[test]
    fn v4_record_without_filename_skips_event_emission() {
        // V4 は filename 無し。必須 field 欠落で Event 化しない（互換 §5）。
        let v4 = v4_record(
            [0xAA; 16],
            [0xBB; 16],
            300,
            132_548_480_000_000_000,
            flags::DATA_OVERWRITE,
        );
        let mut cursor = Cursor::new(v4);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(summary.records_seen, 1, "record は認識した");
        assert_eq!(sink.events.len(), 0, "filename 欠落で Event 化しない");
    }

    #[test]
    fn rename_pair_is_combined() {
        let old = v2_record(
            0x0001_0000_0000_7777,
            0x0005_0000_0000_0001,
            500,
            132_548_480_000_000_000,
            flags::RENAME_OLD_NAME,
            "old.txt",
        );
        let new = v2_record(
            0x0001_0000_0000_7777,
            0x0005_0000_0000_0001,
            500,
            132_548_480_000_000_000,
            flags::RENAME_NEW_NAME,
            "new.txt",
        );
        let mut bytes = old;
        bytes.extend_from_slice(&new);

        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(summary.records_seen, 2);
        assert_eq!(sink.events.len(), 1, "rename は1 Event へ結合");
        let e = &sink.events[0];
        assert_eq!(e.attributes["usn.rename.combined"], true);
        assert_eq!(e.attributes["usn.rename.old_name"], "old.txt");
        assert_eq!(e.attributes["usn.rename.new_name"], "new.txt");
    }

    #[test]
    fn rename_not_combined_when_far_usn() {
        let old = v2_record(
            0x0001_0000_0000_7777,
            0x0005_0000_0000_0001,
            500,
            0,
            flags::RENAME_OLD_NAME,
            "old.txt",
        );
        let new = v2_record(
            0x0001_0000_0000_7777,
            0x0005_0000_0000_0001,
            999,
            0,
            flags::RENAME_NEW_NAME,
            "new.txt",
        );
        let mut bytes = old;
        bytes.extend_from_slice(&new);

        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let _ = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(sink.events.len(), 2, "USN 差 499 は結合しない");
        for e in &sink.events {
            assert_ne!(
                e.attributes.get("usn.rename.combined"),
                Some(&Value::Bool(true))
            );
        }
    }

    #[test]
    fn unknown_major_version_skipped_with_warning() {
        // 未知 MajorVersion へ書き換えた record。
        let mut rec = v2_record(0x1, 0x5, 1, 0, flags::FILE_CREATE, "x.txt");
        rec[4..6].copy_from_slice(&9u16.to_le_bytes());
        // 後ろに正常な V2 を1件。
        let good = v2_record(0x2, 0x5, 2, 0, flags::FILE_CREATE, "y.txt");

        let mut bytes = rec;
        bytes.extend_from_slice(&good);

        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.records_seen, 1, "未知 version は skip して次を処理");
        assert_eq!(
            sink.events.len(),
            1,
            "未知 version 後も正常 record から Event を生成"
        );
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == UNSUPPORTED_VERSION_CODE),
            "未知 version を Warning で記録"
        );
    }

    #[test]
    fn truncated_record_does_not_panic() {
        // header だけあって record_length に満たない。
        let mut bytes = vec![0u8; 8];
        bytes[0..4].copy_from_slice(&100u32.to_le_bytes()); // 100 byte 宣言
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        // 30 byte しか置かない。
        bytes.extend(vec![0u8; 22]);

        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Partial, "truncated は Partial");
        assert!(!sink.issues.is_empty());
    }

    #[test]
    fn corrupt_record_in_middle_preserves_other_events() {
        // 正常 V2 → record_length が短すぎる不正 record → 正常 V2。
        // 不正 record は record_length < COMMON_HEADER_BYTES のため Partial 終了するが、
        // その前に読めた正常 record は保持される（規範 §9.2・§21-5）。
        let r1 = v2_record(0x10, 0x5, 1, 0, flags::FILE_CREATE, "a.txt");

        // 不正: record_length = 3 (< COMMON_HEADER_BYTES)
        let mut bad = vec![0u8; 8];
        bad[0..4].copy_from_slice(&3u32.to_le_bytes());
        bad[4..6].copy_from_slice(&2u16.to_le_bytes());

        let r2 = v2_record(0x11, 0x5, 2, 0, flags::FILE_CREATE, "b.txt");

        let mut bytes = r1;
        bytes.extend_from_slice(&bad);
        bytes.extend_from_slice(&r2);

        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let summary = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        assert_eq!(summary.status, ParseStatus::Partial);
        // r1 は1件 Event 化されている（生成済み Event を破棄しない、規範 §9.2）。
        assert_eq!(sink.events.len(), 1);
    }

    #[test]
    fn provenance_record_locator_points_to_record_bytes() {
        // 互換 §12-3: Provenance が元 record へ到達する。
        let bytes = v2_record(0x42, 0x5, 7, 0, flags::FILE_CREATE, "p.txt");
        let mut cursor = Cursor::new(bytes.clone());
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let _ = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        let e = &sink.events[0];
        match &e.provenance.record_locator {
            RecordLocator::ByteRange { start, end } => {
                assert_eq!(*start, 0);
                assert_eq!(*end, bytes.len() as u64);
            }
            other => panic!("ByteRange 期待だが {other:?}"),
        }
    }

    #[test]
    fn path_resolved_from_in_set_parent_mapping() {
        // 親 dir が同一ストリーム内に記録されている → path に親名を含める。
        let dir = v2_record(0x50, 0x5, 1, 0, flags::FILE_CREATE, "Docs");
        let file = v2_record(0x100, 0x50, 2, 0, flags::FILE_CREATE, "note.txt");

        let mut bytes = dir;
        bytes.extend_from_slice(&file);
        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let _ = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        // 直近（file）の Event の path に「Docs\note.txt」が入る。
        let file_event = sink
            .events
            .iter()
            .find(|e| e.attributes["usn.file_reference_mft_number"] == 0x100u64);
        let e = file_event.expect("file event がある");
        let path = e.path.as_ref().expect("path が構築された");
        assert!(
            path.original.contains("Docs"),
            "path に親 dir 名: {}",
            path.original
        );
        assert!(path.original.contains("note.txt"));
    }

    // ============================================================
    // PathResolver / build_event が使用する内部型を触る unit test
    // ============================================================

    #[test]
    fn build_event_skips_v4_only_observation() {
        // V4 record を直に作って build_event が None を返すことを確認。
        let ctx = make_context();
        let v4 = UsnRecord {
            header: CommonHeader {
                record_length: 88,
                major_version: 4,
                minor_version: 0,
            },
            file_reference: FileReference::V3V4([0; 16]),
            parent_reference: FileReference::V3V4([0; 16]),
            usn: 1,
            time_filetime: 0,
            reason: flags::DATA_EXTEND,
            source_info: 0,
            security_id: 0,
            file_attributes: 0,
            file_name: None,
            range_tracking: Some(RangeTracking {
                remaining_extents: 0,
                number_of_extents: 1,
                extent_location: 0,
                extent_length: 0,
            }),
            record_offset: 0,
        };
        let observation = UsnObservation::single(v4);
        let resolver = PathResolver::default();
        let event = build_event(&observation, &resolver, &ctx, 0);
        assert!(event.is_none(), "filename 無しの V4 は Event 化しない");
    }

    #[test]
    fn reason_zero_filetime_yields_unknown_time() {
        // FILETIME=0 は Unknown time（規範 §6.2）。
        let bytes = v2_record(0x1, 0x5, 1, 0, flags::FILE_CREATE, "z.txt");
        let mut cursor = Cursor::new(bytes);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };
        let _ = UsnParser::new().parse(&mut cursor, &context, &mut sink);
        use tf_core::time::TemporalValue;
        assert_eq!(sink.events[0].time.value, TemporalValue::Unknown);
    }
}
