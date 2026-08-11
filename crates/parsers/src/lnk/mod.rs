//! LNK（Shell Link）Parser（[MS-SHLLINK]、互換 §4.4、T4-010〜T4-016）。
//!
//! LNK ファイルは Windows のショートカット。構造は [MS-SHLLINK] で定義され、
//! Header / LinkTargetIDList / LinkInfo / StringData / ExtraData の5 section から成る。
//!
//! 本 Parser は header の3 timestamp（Creation/Access/Write）を観測型 Event として生成する
//! （規範 §7.1・互換 §4.4: timestamp のみで「target を開いた」と断定しない）。各 timestamp は
//! 独立 Event となり、Timeline へ現れる。timestamp 0（未設定）は Event 化しない。全て 0 の
//! 場合は `Unknown` time で1 Event を生成し、header の観測を記録する。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{MALFORMED_INPUT_CODE, TRUNCATED_RECORD_CODE, artifact_issue, record_issue};
use crate::lnk::header::{HEADER_BYTES, ShellLinkHeader, show_command_name};
use crate::lnk::linkinfo::reconstruct_target_path;
use crate::lnk::stringdata::StringDataSection;

pub mod extradata;
pub mod filetime;
pub mod header;
pub mod idlist;
pub mod linkinfo;
pub mod stringdata;

/// LNK Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-lnk";
/// LNK Parser の version（SemVer）。
///
/// Event の意味（生成する Event type・attribute 構成）が変わる変更で version を上げる。
pub const PARSER_VERSION: &str = "1.0.0";
/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
pub const MS_SHLLINK_REFERENCE: &str = "[MS-SHLLINK] v10.0";

/// LNK 由来の観測 Event type（規範 §7.1: timestamp の観測、実行断定なし）。
pub const LNK_TIMESTAMP_EVENT_TYPE: &str = "lnk_timestamp";

/// LNK Parser 本体。
#[derive(Default)]
pub struct LnkParser;

impl LnkParser {
    pub fn new() -> Self {
        LnkParser
    }
}

impl ArtifactParser for LnkParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Lnk
    }

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
        // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
        if evidence.integrity_status != tf_core::case::IntegrityStatus::VerifiedSnapshot {
            return ProbeResult::NotThisFormat;
        }

        // snapshot file の先頭 HEADER_BYTES を読む。
        let path = std::path::Path::new(&evidence.snapshot_locator);
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return ProbeResult::NotThisFormat,
        };
        let mut buf = vec![0u8; HEADER_BYTES];
        use std::io::Read;
        let n = file.read(&mut buf).unwrap_or(0);
        buf.truncate(n);

        if buf.len() < HEADER_BYTES {
            // 短すぎる。Header すら無い。
            return ProbeResult::NotThisFormat;
        }

        match ShellLinkHeader::parse(&buf) {
            Ok(_) => ProbeResult::Confirmed,
            // header が読めるが CLSID 不一致なら別形式。
            Err(header::HeaderError::ClsidMismatch) => ProbeResult::NotThisFormat,
            // 形式異常（size 不正・reserved 非ゼロ等）は Malformed。
            Err(_) => ProbeResult::Malformed,
        }
    }

    fn parse(
        &self,
        snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        // 先頭位置を記録（byte 消費量計算用）。
        let start_pos = snapshot.stream_position().unwrap_or(0);

        // 1. Header を読む。
        let mut header_buf = vec![0u8; HEADER_BYTES];
        if let Err(e) = read_exact_or_truncate(snapshot, &mut header_buf) {
            // snapshot が Header すら読めない（truncated）。
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!("snapshot が Header ({HEADER_BYTES} byte) に満たない: {e}"),
            ));
            return ParseSummary::skipped();
        }
        let header = match ShellLinkHeader::parse(&header_buf) {
            Ok(h) => h,
            Err(header::HeaderError::ClsidMismatch) => {
                // CLSID 不一致は LNK ではない。probe と矛盾する異常。
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    "LinkCLSID が一致しない（LNK 形式ではない可能性）",
                ));
                return ParseSummary::skipped();
            }
            Err(e) => {
                // 形式異常。Malformed。
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("Shell Link Header の解析失敗: {e:?}"),
                ));
                return ParseSummary::failed();
            }
        };

        // 2. LinkTargetIDList（flag があれば）。
        if header.flags.has_link_target_id_list() {
            match idlist::read_link_target_id_list(snapshot) {
                Ok(_list) => { /* 読み飛ばす（raw は attributes へ記録しない、過剰情報を避ける） */
                }
                Err(e) => {
                    // IDList の境界が壊れている。Partial だが Header は読めているので続行。
                    let _ = sink.emit_issue(record_issue(
                        crate::issue::PARTIAL_RECORD_BOUNDARY_CODE,
                        tf_core::issue::IssueSeverity::Recoverable,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        Some(RecordLocator::ByteOffset(HEADER_BYTES as u64)),
                        Some(0),
                        &format!("LinkTargetIDList の境界特定失敗: {e:?}"),
                    ));
                    // IDList の境界が分からない場合、以降の section 読み取り位置がずれる。
                    // 安全のためここで Partial 終了。ただし Header 由来の Event は生成する。
                    return self.finish_with_header_events(
                        &header,
                        None,
                        None,
                        None,
                        snapshot,
                        start_pos,
                        context,
                        sink,
                        ParseStatus::Partial,
                        1,
                    );
                }
            }
        }

        // 3. LinkInfo（flag があれば）。
        let mut target_path: Option<String> = None;
        if header.flags.has_link_info() && !header.flags.force_no_link_info() {
            match linkinfo::read_link_info(snapshot) {
                Ok(li) => {
                    target_path = reconstruct_target_path(&li);
                }
                Err(e) => {
                    // LinkInfo が壊れていても StringData 以降は独立している場合がある。
                    // ただし、LinkInfo section のサイズ分だけ seek できないと位置がずれる。
                    // LinkInfoSize を読めなかった場合、以降の読み取り位置が不明。
                    // 安全のため Partial 扱いとし、Header 由来 Event のみ生成。
                    let _ = sink.emit_issue(record_issue(
                        crate::issue::PARTIAL_RECORD_BOUNDARY_CODE,
                        tf_core::issue::IssueSeverity::Recoverable,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        None,
                        Some(0),
                        &format!("LinkInfo の境界特定失敗: {e:?}"),
                    ));
                    return self.finish_with_header_events(
                        &header,
                        None,
                        None,
                        None,
                        snapshot,
                        start_pos,
                        context,
                        sink,
                        ParseStatus::Partial,
                        1,
                    );
                }
            }
        }

        // 4. StringData（flag があれば）。
        let string_section: StringDataSection =
            match stringdata::read_string_data_section(snapshot, header.flags) {
                Ok(s) => s,
                Err(e) => {
                    // StringData の境界が壊れている。Partial。
                    let _ = sink.emit_issue(record_issue(
                        crate::issue::PARTIAL_RECORD_BOUNDARY_CODE,
                        tf_core::issue::IssueSeverity::Recoverable,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        None,
                        Some(0),
                        &format!("StringData の解析失敗: {e:?}"),
                    ));
                    return self.finish_with_header_events(
                        &header,
                        target_path.as_deref(),
                        None,
                        None,
                        snapshot,
                        start_pos,
                        context,
                        sink,
                        ParseStatus::Partial,
                        1,
                    );
                }
            };

        // 5. ExtraData（必須ではない。読み取り失敗は warning に留める）。
        let extra_section = extradata::read_extra_data(snapshot);
        // ExtraData の truncated は warning。
        if extra_section.truncated {
            let _ = sink.emit_issue(record_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                None,
                Some(0),
                "ExtraData section が truncated（TerminalBlock なし）",
            ));
        }

        // EnvironmentVariableData の target path があれば優先。
        let resolved_target = extra_section
            .environment_variable_target
            .clone()
            .or(target_path.clone());

        // ExtraData が truncated なら Partial、それ以外は Complete。
        let final_status = if extra_section.truncated {
            ParseStatus::Partial
        } else {
            ParseStatus::Complete
        };

        // 全 section 読了。Header timestamp から Event を生成。
        self.finish_with_header_events(
            &header,
            resolved_target.as_deref(),
            Some(&string_section),
            Some(&extra_section),
            snapshot,
            start_pos,
            context,
            sink,
            final_status,
            5,
        )
    }
}

impl LnkParser {
    /// Header の3 timestamp から Event を生成し sink へ流す（共通終端処理）。
    ///
    /// - 各 timestamp（0 以外）毎に1 Event。
    /// - 全て 0 の場合は `Unknown` time で1 Event。
    /// - `string_section` と `extra_section` があれば attributes へ記録。
    ///
    /// 戻り値は [`ParseSummary`]。`status_hint` は呼出側が指定（Complete/Partial）。
    #[allow(clippy::too_many_arguments)]
    fn finish_with_header_events(
        &self,
        header: &ShellLinkHeader,
        target_path: Option<&str>,
        string_section: Option<&StringDataSection>,
        extra_section: Option<&extradata::ExtraDataSection>,
        snapshot: &mut dyn ReadSeek,
        start_pos: u64,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
        status_hint: ParseStatus,
        records_seen: u64,
    ) -> ParseSummary {
        // 共通 attributes を構築。
        let base_attrs =
            build_header_attributes(header, target_path, string_section, extra_section);

        // 各 timestamp の (datetime, kind, field_name, ordinal)。
        let timestamps: [(Option<DateTime<Utc>>, TimestampKind, &'static str); 3] = [
            (
                header.creation_datetime(),
                TimestampKind::Created,
                "creation",
            ),
            (header.access_datetime(), TimestampKind::Accessed, "access"),
            (header.write_datetime(), TimestampKind::Modified, "write"),
        ];

        let mut events_emitted: u64 = 0;
        let mut event_ordinal: u64 = 0;
        let mut any_timestamp_present = false;

        for (dt, kind, field_name) in timestamps {
            let Some(dt) = dt else { continue };
            any_timestamp_present = true;

            let event_time = EventTime::utc_instant(
                dt,
                Some(filetime_original(header, field_name)),
                kind,
                TimePrecision::Microsecond, // FILETIME は 100ns 単位
                TimezoneSource::ArtifactDefined,
            );

            let mut attrs = base_attrs.clone();
            attrs.insert(
                "lnk.timestamp_field".to_string(),
                Value::String(field_name.to_string()),
            );

            let message = format!("LNK {field_name} timestamp の観測");
            let record_locator = RecordLocator::ByteRange {
                start: 0,
                end: HEADER_BYTES as u64,
            };
            let provenance = context.make_provenance(record_locator, 0);

            let event = tf_core::event::Event {
                id: String::new(),
                time: event_time,
                source: ArtifactSource::Lnk,
                event_type: EventType::new(LNK_TIMESTAMP_EVENT_TYPE),
                assertion: AssertionKind::Observed,
                hostname: None,
                user: None,
                path: target_path.map(tf_core::WindowsPathValue::new),
                program: None,
                process: None,
                message,
                attributes: attrs,
                provenance,
            };
            // Event ID を決定的に計算して設定（規範 §12.3）。
            let mut event = event;
            event.id = event.compute_id(event_ordinal);
            event_ordinal += 1;

            if sink.emit_event(event).is_err() {
                // sink error（EventStore の I/O 等）。安全のため中断。
                return ParseSummary::partial(records_seen, events_emitted, 0);
            }
            events_emitted += 1;
        }

        // timestamp が1つも無い場合、Unknown time で header 観測 Event を1つ生成。
        if !any_timestamp_present {
            let event_time = EventTime::unknown(TimestampKind::Observed);
            let mut attrs = base_attrs.clone();
            attrs.insert(
                "lnk.timestamp_field".to_string(),
                Value::String("none".to_string()),
            );
            let record_locator = RecordLocator::ByteRange {
                start: 0,
                end: HEADER_BYTES as u64,
            };
            let provenance = context.make_provenance(record_locator, 0);
            let event = tf_core::event::Event {
                id: String::new(),
                time: event_time,
                source: ArtifactSource::Lnk,
                event_type: EventType::new(LNK_TIMESTAMP_EVENT_TYPE),
                assertion: AssertionKind::Observed,
                hostname: None,
                user: None,
                path: target_path.map(tf_core::WindowsPathValue::new),
                program: None,
                process: None,
                message: "LNK header の観測（timestamp 未設定）".to_string(),
                attributes: attrs,
                provenance,
            };
            let mut event = event;
            event.id = event.compute_id(0);
            if sink.emit_event(event).is_err() {
                return ParseSummary::partial(records_seen, events_emitted, 0);
            }
            events_emitted += 1;
        }

        let bytes_consumed = snapshot
            .stream_position()
            .unwrap_or(0)
            .saturating_sub(start_pos);
        ParseSummary {
            status: status_hint,
            records_seen,
            events_emitted,
            issues_emitted: 0, // 上位が sink の issue 数を集計
            bytes_consumed,
        }
    }
}

/// Header 起因の attributes（`BTreeMap` 決定性、規範 §13.2）を構築する。
#[allow(clippy::too_many_arguments)]
fn build_header_attributes(
    header: &ShellLinkHeader,
    target_path: Option<&str>,
    string_section: Option<&StringDataSection>,
    extra_section: Option<&extradata::ExtraDataSection>,
) -> BTreeMap<String, Value> {
    let mut attrs = BTreeMap::new();
    attrs.insert("lnk.header_size".into(), Value::from(header.header_size));
    attrs.insert("lnk.flags".into(), Value::from(header.flags.raw()));
    let flag_names: Vec<Value> = header
        .flags
        .known_flag_names()
        .into_iter()
        .map(|n| Value::String(n.to_string()))
        .collect();
    attrs.insert("lnk.flag_names".into(), Value::Array(flag_names));
    let unknown_bits = header.flags.unknown_bits();
    if unknown_bits != 0 {
        attrs.insert("lnk.unknown_flag_bits".into(), Value::from(unknown_bits));
    }
    attrs.insert(
        "lnk.file_attributes".into(),
        Value::from(header.file_attributes.raw()),
    );
    let fa_names: Vec<Value> = header
        .file_attributes
        .known_flag_names()
        .into_iter()
        .map(|n| Value::String(n.to_string()))
        .collect();
    attrs.insert("lnk.file_attribute_names".into(), Value::Array(fa_names));
    attrs.insert("lnk.file_size".into(), Value::from(header.file_size));
    attrs.insert("lnk.icon_index".into(), Value::from(header.icon_index));
    attrs.insert(
        "lnk.show_command".into(),
        Value::String(show_command_name(header.show_command).to_string()),
    );
    attrs.insert("lnk.hot_key".into(), Value::from(header.hot_key));
    // 元 FILETIME 値（u64）も保持し、変換の追跡可能性を担保する。
    attrs.insert(
        "lnk.creation_filetime".into(),
        Value::from(header.creation_time),
    );
    attrs.insert(
        "lnk.access_filetime".into(),
        Value::from(header.access_time),
    );
    attrs.insert("lnk.write_filetime".into(), Value::from(header.write_time));
    attrs.insert(
        "lnk.reference_spec".into(),
        Value::String(MS_SHLLINK_REFERENCE.to_string()),
    );
    attrs.insert(
        "lnk.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );

    if let Some(tp) = target_path {
        attrs.insert("lnk.target_path".into(), Value::String(tp.to_string()));
    }

    if let Some(s) = string_section {
        if let Some(name) = &s.name {
            attrs.insert("lnk.name".into(), Value::String(name.value.clone()));
        }
        if let Some(rp) = &s.relative_path {
            attrs.insert("lnk.relative_path".into(), Value::String(rp.value.clone()));
        }
        if let Some(wd) = &s.working_dir {
            attrs.insert("lnk.working_dir".into(), Value::String(wd.value.clone()));
        }
        if let Some(args) = &s.arguments {
            attrs.insert("lnk.arguments".into(), Value::String(args.value.clone()));
        }
        if let Some(il) = &s.icon_location {
            attrs.insert("lnk.icon_location".into(), Value::String(il.value.clone()));
        }
        // ANSI lossy 変換が1つでもあれば記録（情報欠損の可能性）。
        let ansi_lossy = [
            &s.name,
            &s.relative_path,
            &s.working_dir,
            &s.arguments,
            &s.icon_location,
        ]
        .iter()
        .any(|opt| opt.as_ref().is_some_and(|sd| sd.ansi_lossy));
        if ansi_lossy {
            attrs.insert("lnk.ansi_lossy".into(), Value::Bool(true));
        }
    }

    if let Some(extra) = extra_section {
        if extra.unknown_block_count > 0 {
            attrs.insert(
                "lnk.unknown_extra_block_count".into(),
                Value::from(extra.unknown_block_count),
            );
        }
        // 既知 block の出現を names へ記録（未知を黙って無視しない、互換 §12-7）。
        let block_names: Vec<Value> = extra
            .blocks
            .iter()
            .map(|b| {
                Value::String(
                    b.known_name
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| format!("Unknown(0x{:08X})", b.signature)),
                )
            })
            .collect();
        attrs.insert("lnk.extra_blocks".into(), Value::Array(block_names));
    }

    attrs
}

/// FILETIME の元表現（original）文字列を作る。
fn filetime_original(header: &ShellLinkHeader, field: &str) -> String {
    let raw = match field {
        "creation" => header.creation_time,
        "access" => header.access_time,
        "write" => header.write_time,
        _ => 0,
    };
    format!("FILETIME({field}={raw})")
}

/// snapshot から `buf.len()` byte を正確に読む。不足時は `buf` を切り詰めて Err を返す。
fn read_exact_or_truncate(
    reader: &mut dyn ReadSeek,
    buf: &mut Vec<u8>,
) -> Result<(), std::io::Error> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if filled < buf.len() {
        buf.truncate(filled);
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "snapshot が短すぎる",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tf_core::time::TemporalValue;

    /// テスト用 LNK バイナリを構築する。
    fn build_minimal_lnk(creation_ft: u64, access_ft: u64, write_ft: u64, flags: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header (76 byte)
        buf.extend_from_slice(&HEADER_BYTES_U32.to_le_bytes());
        buf.extend_from_slice(&header::LINK_CLSID);
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        buf.extend_from_slice(&creation_ft.to_le_bytes());
        buf.extend_from_slice(&access_ft.to_le_bytes());
        buf.extend_from_slice(&write_ft.to_le_bytes());
        buf.extend_from_slice(&1234u32.to_le_bytes()); // FileSize
        buf.extend_from_slice(&0i32.to_le_bytes()); // IconIndex
        buf.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand
        buf.extend_from_slice(&0u16.to_le_bytes()); // HotKey
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
        assert_eq!(buf.len(), HEADER_BYTES);
        buf
    }

    const HEADER_BYTES_U32: u32 = 0x0000_004C;

    /// filetime を作る。
    fn ft(unix_secs: i64) -> u64 {
        (unix_secs + 11_644_473_600) as u64 * 10_000_000
    }

    /// Event と Issue を蓄積するテスト用 sink。
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
                evidence_id: "tf-evidence-v1:lnk-test".to_string(),
                source_locator: "shortcut.lnk".to_string(),
                size: 76,
                sha256: "cd".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:lnk-test".to_string(),
                evidence_id: "tf-evidence-v1:lnk-test".to_string(),
                artifact_type: ArtifactSource::Lnk,
                parser_id: PARSER_ID.to_string(),
                parser_version: PARSER_VERSION.to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["clsid".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    #[test]
    fn parse_three_timestamps_emits_three_events() {
        let data = build_minimal_lnk(ft(1_785_887_720), ft(1_785_887_721), ft(1_785_887_722), 0);
        let mut cursor = Cursor::new(data);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let parser = LnkParser::new();
        let summary = parser.parse(&mut cursor, &context, &mut sink);

        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(sink.events.len(), 3);
        // 各 Event は異なる Event ID。
        let ids: Vec<&str> = sink.events.iter().map(|e| e.id.as_str()).collect();
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        // 全 Event が lnk_timestamp type。
        for e in &sink.events {
            assert_eq!(e.event_type.as_str(), LNK_TIMESTAMP_EVENT_TYPE);
            assert_eq!(e.assertion, AssertionKind::Observed);
        }
        // timestamp_field が creation/access/write の何れか。
        let fields: Vec<&str> = sink
            .events
            .iter()
            .map(|e| e.attributes["lnk.timestamp_field"].as_str().unwrap())
            .collect();
        assert!(fields.contains(&"creation"));
        assert!(fields.contains(&"access"));
        assert!(fields.contains(&"write"));
    }

    #[test]
    fn parse_no_timestamps_emits_single_unknown_event() {
        // 全 timestamp 0 → Unknown time で1 Event。
        let data = build_minimal_lnk(0, 0, 0, 0);
        let mut cursor = Cursor::new(data);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let parser = LnkParser::new();
        let summary = parser.parse(&mut cursor, &context, &mut sink);

        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(sink.events.len(), 1);
        assert_eq!(sink.events[0].time.value, TemporalValue::Unknown);
    }

    #[test]
    fn parse_truncated_snapshot_does_not_panic() {
        // 規範 §9.4・互換 §12-2: truncated で panic しない。
        let truncated: Vec<u8> = (0..30).collect(); // Header より短い
        let mut cursor = Cursor::new(truncated);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let parser = LnkParser::new();
        let summary = parser.parse(&mut cursor, &context, &mut sink);

        // truncated で skipped。
        assert_eq!(summary.status, ParseStatus::Skipped);
        // Issue が1つ（truncated 記録）。
        assert_eq!(sink.issues.len(), 1);
        assert_eq!(sink.issues[0].issue_id, TRUNCATED_RECORD_CODE);
    }

    #[test]
    fn parse_bad_clsid_is_skipped() {
        let mut data = build_minimal_lnk(0, 0, 0, 0);
        data[4] = 0xFF; // CLSID を壊す
        let mut cursor = Cursor::new(data);
        let context = make_context();
        let mut sink = TestSink {
            events: vec![],
            issues: vec![],
        };

        let parser = LnkParser::new();
        let summary = parser.parse(&mut cursor, &context, &mut sink);

        assert_eq!(summary.status, ParseStatus::Skipped);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.issue_id == MALFORMED_INPUT_CODE)
        );
    }

    #[test]
    fn parse_target_path_carried_in_attributes() {
        // StringData section 付きで target path 相当を attributes へ。
        // ここでは最小限、target_path 引数経由で attributes 構築を検証。
        let header = ShellLinkHeader::parse(&build_minimal_lnk(ft(1), 0, 0, 0)).unwrap();
        let attrs = build_header_attributes(&header, Some("C:\\target.exe"), None, None);
        assert_eq!(attrs["lnk.target_path"], "C:\\target.exe");
    }

    #[test]
    fn parser_id_and_version_are_stable() {
        let parser = LnkParser::new();
        assert_eq!(parser.parser_id(), "traceforge-lnk");
        assert_eq!(parser.parser_version(), "1.0.0");
        assert_eq!(parser.artifact_type(), ArtifactSource::Lnk);
    }
}
