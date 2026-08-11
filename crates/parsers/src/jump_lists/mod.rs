//! Windows Jump Lists Parser（AutomaticDestinations / CustomDestinations、互換 §4.5・T4-070〜T4-074）。
//!
//! ## 対象形式
//!
//! - **AutomaticDestinations-ms**: CFB container。内部へ `DestList` stream と複数の内包 LNK
//!   stream を持つ。各 LNK stream は1つの Jump List entry を表す。
//! - **CustomDestinations-ms**: 独自 binary format。category 群 + 内包 LNK 群から成る。
//!   ユーザが明示的に pin 等で追加した entry を保持する。
//!
//! ## 観測型 Event の方針（規範 §7.1・互換 §4.5）
//!
//! Jump List entry の存在や timestamp だけから「利用者がその時刻に target を開いた」と
//! 断定してはならない（互換 §4.5）。そのため本 Parser は
//! [`JUMP_LIST_OBSERVATION_EVENT_TYPE`]（`jump_list_observation`）のみを生成し、
//! `file_opened`・`application_launched` 等の断定型 Event は生成しない。
//!
//! ## 内包 LNK の取り扱い（互換 §4.5・T4-072）
//!
//! 内包 LNK は新しい物理 Evidence へ登録せず、Jump List Evidence 内の ArtifactInstance として
//! 扱う。compound stream 名（例: "1"）と stream 内の offset を Provenance へ保存する。
//! 内包 LNK から抽出した target path・timestamp は全て Jump List Event の属性として保持し、
//! 別の `lnk_timestamp` Event は生成しない（source 混同を避けるため）。
//!
//! ## 部分成功（規範 §9.2・§21-5）
//!
//! - CFB 構造が破損: container 全体を誤解析せず、Warning Issue + Skipped
//! - DestList 未知 version: Warning Issue を発行し、LNK stream のみ解析する
//! - 一部 LNK stream が破損: Warning Issue を発行し、残りの stream を解析する

use std::collections::BTreeMap;
use std::io::Read;

use serde_json::Value;

use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{
    MALFORMED_INPUT_CODE, TRUNCATED_RECORD_CODE, UNSUPPORTED_VERSION_CODE, artifact_issue,
    record_issue,
};
use crate::jump_lists::cfb::{CfbStream, parse_cfb};
use crate::jump_lists::custom::parse_custom_destinations;
use crate::jump_lists::destlist::{DestListEntry, ParseOutcome, parse_destlist};
use crate::lnk::filetime::filetime_to_datetime;

pub mod cfb;
pub mod custom;
pub mod destlist;

/// Jump Lists Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-jump-lists";
/// Jump Lists Parser の version（SemVer）。
pub const PARSER_VERSION: &str = "1.0.0";
/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
///
/// AutomaticDestinations は [MS-CFB] Compound File Binary + [MS-DESTS] DestList + 内包
/// [MS-SHLLINK] の組合せ。CustomDestinations は [MS-SHLLINK] 内包の独自 container。
pub const JUMP_LIST_REFERENCE: &str =
    "[MS-CFB] Compound File Binary + [MS-DESTS] DestList + [MS-SHLLINK]";
/// 観測 Event type（規範 §7.1・互換 §4.5: Jump List entry の観測、実行断定なし）。
pub const JUMP_LIST_OBSERVATION_EVENT_TYPE: &str = "jump_list_observation";

/// AutomaticDestinations file 名の拡張子（lowercase 統一・case-insensitive 比較のため）。
const AUTOMATIC_DESTINATIONS_EXT: &str = ".automaticdestinations-ms";
/// CustomDestinations file 名の拡張子（lowercase 統一・case-insensitive 比較のため）。
const CUSTOM_DESTINATIONS_EXT: &str = ".customdestinations-ms";

/// 「実行 / 利用を断定しない」旨の制約注記。
const INTERPRETATION_LIMITATION: &str =
    "entry existence in jump list only; not direct evidence of opening/launching target";

/// snapshot 全読み上限（byte）。Jump List file は通常数十 KB 以下。
const SNAPSHOT_READ_CAP: u64 = 64 * 1024 * 1024;

/// Jump Lists Parser 本体。
#[derive(Default)]
pub struct JumpListParser;

impl JumpListParser {
    pub fn new() -> Self {
        JumpListParser
    }
}

/// snapshot 全読みの結果。
enum ReadAllOutcome {
    Complete(Vec<u8>),
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
                    break;
                }
                limited -= take as u64;
            }
            Err(e) => return ReadAllOutcome::Error(e),
        }
    }
    ReadAllOutcome::Complete(buf)
}

/// source_locator の末尾要素を取り出す。
fn basename(source_locator: &str) -> &str {
    source_locator
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(source_locator)
}

/// source_locator から AppID 文字列を取り出す。
/// AutomaticDestinations file 名は `<AppID>.automaticDestinations-ms`。
/// CustomDestinations file 名は `<AppID>.customDestinations-ms`。
fn extract_app_id(source_locator: &str) -> Option<String> {
    let name = basename(source_locator);
    let lower = name.to_ascii_lowercase();
    let stripped = lower
        .strip_suffix(AUTOMATIC_DESTINATIONS_EXT)
        .or_else(|| lower.strip_suffix(CUSTOM_DESTINATIONS_EXT))?;
    // 拡張子を除去した部分は元の case を保持する。
    let prefix_len = stripped.len();
    if prefix_len == 0 || prefix_len > name.len() {
        None
    } else {
        Some(name[..prefix_len].to_string())
    }
}

impl ArtifactParser for JumpListParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::JumpList
    }

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
        // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
        if evidence.integrity_status != tf_core::case::IntegrityStatus::VerifiedSnapshot {
            return ProbeResult::NotThisFormat;
        }
        let name = basename(&evidence.source_locator);
        let lower = name.to_ascii_lowercase();
        let is_automatic = lower.ends_with(AUTOMATIC_DESTINATIONS_EXT);
        let is_custom = lower.ends_with(CUSTOM_DESTINATIONS_EXT);
        if !is_automatic && !is_custom {
            return ProbeResult::NotThisFormat;
        }
        // snapshot file の先頭 bytes から magic を確認。
        let path = std::path::Path::new(&evidence.snapshot_locator);
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return ProbeResult::NotThisFormat,
        };
        let mut buf = [0u8; 8];
        let n = file.read(&mut buf).unwrap_or(0);
        if n < 4 {
            return ProbeResult::NotThisFormat;
        }
        if is_automatic {
            // CFB signature を確認。
            if buf[..8.min(n)] == cfb::CFB_SIGNATURE[..n.min(8)] {
                ProbeResult::Confirmed
            } else {
                ProbeResult::Malformed
            }
        } else {
            // CustomDestinations: 特定の magic が無い。先頭 byte が 0x01 等（file header）を
            // 大まかな指標とするが、信頼性は低い。Probable に留める。
            if n >= 4 {
                ProbeResult::Probable
            } else {
                ProbeResult::NotThisFormat
            }
        }
    }

    fn parse(
        &self,
        snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary {
        let start_pos = snapshot.stream_position().unwrap_or(0);

        // snapshot を全読み。
        let data = match read_all(snapshot, SNAPSHOT_READ_CAP) {
            ReadAllOutcome::Complete(b) => b,
            ReadAllOutcome::Error(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("snapshot 読取に失敗: {e}"),
                ));
                return ParseSummary::skipped();
            }
        };
        let bytes_consumed = data.len() as u64;
        let app_id = extract_app_id(&context.evidence.source_locator);

        let name = basename(&context.evidence.source_locator);
        let is_automatic = name
            .to_ascii_lowercase()
            .ends_with(AUTOMATIC_DESTINATIONS_EXT);
        let is_custom = name.to_ascii_lowercase().ends_with(CUSTOM_DESTINATIONS_EXT);

        if is_automatic {
            parse_automatic(
                &data,
                app_id.as_deref(),
                context,
                sink,
                bytes_consumed,
                start_pos,
            )
        } else if is_custom {
            parse_custom(
                &data,
                app_id.as_deref(),
                context,
                sink,
                bytes_consumed,
                start_pos,
            )
        } else {
            // 拡張子不明。CFB signature を見て Automatic 扱いを試みる。
            if data.len() >= 8 && data[..8] == cfb::CFB_SIGNATURE {
                parse_automatic(
                    &data,
                    app_id.as_deref(),
                    context,
                    sink,
                    bytes_consumed,
                    start_pos,
                )
            } else {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    "Jump Lists 形式を識別できない（拡張子・CFB magic 何れでも無い）",
                ));
                ParseSummary::skipped()
            }
        }
    }
}

/// AutomaticDestinations-ms を解析する。
fn parse_automatic(
    data: &[u8],
    app_id: Option<&str>,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
    bytes_consumed: u64,
    _start_pos: u64,
) -> ParseSummary {
    let mut records_seen: u64 = 0;
    let mut events_emitted: u64 = 0;
    let mut issues_emitted: u64 = 0;
    let mut partial = false;

    // CFB container を解析。
    let container = match parse_cfb(data) {
        Ok(c) => c,
        Err(e) => {
            let _ = sink.emit_issue(artifact_issue(
                MALFORMED_INPUT_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!("CFB container の解析失敗: {e}"),
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
    };

    // DestList stream を探す。
    let destlist_stream: Option<&CfbStream> =
        container.streams.iter().find(|s| s.name == "DestList");
    let destlist_outcome: Option<ParseOutcome> = destlist_stream.map(|s| parse_destlist(&s.data));

    // DestList version の検証。
    let mut destlist_version: Option<u32> = None;
    let mut destlist_last_revision: u64 = 0;
    let mut destlist_entries: Vec<DestListEntry> = Vec::new();
    if let Some(outcome) = destlist_outcome {
        match outcome {
            ParseOutcome::Parsed {
                version,
                entries,
                last_revision_filetime,
                truncated,
                ..
            } => {
                destlist_version = Some(version);
                destlist_last_revision = last_revision_filetime;
                destlist_entries = entries;
                if truncated {
                    partial = true;
                    let _ = sink.emit_issue(artifact_issue(
                        TRUNCATED_RECORD_CODE,
                        tf_core::issue::IssueSeverity::Warning,
                        &context.evidence.evidence_id,
                        &context.artifact.artifact_id,
                        "DestList stream が truncated したため一部 entry のみ解析した",
                    ));
                    issues_emitted += 1;
                }
            }
            ParseOutcome::UnsupportedVersion { version } => {
                partial = true;
                let _ = sink.emit_issue(artifact_issue(
                    UNSUPPORTED_VERSION_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!(
                        "DestList 未知 version ({version}) のため DestList entry 解析を skip した（内包 LNK のみ解析を継続）"
                    ),
                ));
                issues_emitted += 1;
            }
        }
    } else {
        // DestList 無しは Warning 扱いとはせず、単に destlist 属性無しで Event を出す。
        // （小さな AutomaticDestinations で DestList が無い場合もあり得るため）
    }

    // 内包 LNK stream 群を名前順（stream 名で自然順序）に処理する。
    // stream 名は "1", "2", "3"... のように数値文字列。数値順で sort する。
    let mut lnk_streams: Vec<&CfbStream> = container
        .streams
        .iter()
        .filter(|s| {
            s.name != "DestList" && !s.name.is_empty() && s.name.chars().all(|c| c.is_ascii_digit())
        })
        .collect();
    lnk_streams.sort_by(|a, b| {
        let na: u64 = a.name.parse().unwrap_or(u64::MAX);
        let nb: u64 = b.name.parse().unwrap_or(u64::MAX);
        na.cmp(&nb)
    });

    for (event_ordinal, stream) in (0_u64..).zip(lnk_streams.iter()) {
        records_seen += 1;
        // 対応する DestList entry を名前で lookup。
        let destlist_entry: Option<&DestListEntry> = destlist_entries
            .iter()
            .find(|e| e.stream_name == stream.name);

        // 内包 LNK を byte 列から抽出。
        let lnk = extract_lnk_from_bytes(&stream.data);

        // record_locator: stream 名を LogicalPath へ。file 上の byte offset は属性へ。
        let record_locator = RecordLocator::LogicalPath(vec![stream.name.clone()]);
        let provenance = context.make_provenance(record_locator, event_ordinal);

        let event_time = make_event_time(
            destlist_entry
                .map(|e| e.last_used_filetime)
                .unwrap_or(lnk.write_filetime),
            TimestampKind::Accessed,
        );

        let mut attrs = BTreeMap::new();
        attrs.insert(
            "jump_list.container_type".into(),
            Value::String("automatic_destinations".to_string()),
        );
        if let Some(v) = destlist_version {
            attrs.insert("jump_list.destlist_format_version".into(), Value::from(v));
        }
        attrs.insert(
            "jump_list.destlist_last_revision_filetime".into(),
            Value::from(destlist_last_revision),
        );
        attrs.insert(
            "jump_list.stream_name".into(),
            Value::String(stream.name.clone()),
        );
        attrs.insert(
            "jump_list.stream_starting_sector".into(),
            Value::from(stream.starting_sector),
        );
        if let Some(off) = stream.file_byte_offset {
            attrs.insert("jump_list.stream_file_byte_offset".into(), Value::from(off));
        }
        attrs.insert(
            "jump_list.stream_size".into(),
            Value::from(stream.data.len() as u64),
        );

        if let Some(app_id) = app_id {
            attrs.insert("jump_list.app_id".into(), Value::String(app_id.to_string()));
        }
        attrs.insert("jump_list.entry_index".into(), Value::from(records_seen));
        if let Some(d) = destlist_entry {
            attrs.insert(
                "jump_list.destlist_last_used_filetime".into(),
                Value::from(d.last_used_filetime),
            );
            attrs.insert(
                "jump_list.destlist_created_filetime".into(),
                Value::from(d.created_filetime),
            );
            attrs.insert(
                "jump_list.destlist_last_modified_filetime".into(),
                Value::from(d.last_modified_filetime),
            );
        }

        // 内包 LNK からの属性。
        attrs.insert("jump_list.lnk_flags".into(), Value::from(lnk.flags_raw));
        if let Some(tp) = &lnk.target_path {
            attrs.insert(
                "jump_list.lnk_target_path".into(),
                Value::String(tp.clone()),
            );
        }
        attrs.insert(
            "jump_list.lnk_creation_filetime".into(),
            Value::from(lnk.creation_filetime),
        );
        attrs.insert(
            "jump_list.lnk_access_filetime".into(),
            Value::from(lnk.access_filetime),
        );
        attrs.insert(
            "jump_list.lnk_write_filetime".into(),
            Value::from(lnk.write_filetime),
        );
        attrs.insert("jump_list.lnk_file_size".into(), Value::from(lnk.file_size));
        attrs.insert(
            "jump_list.lnk_is_unicode".into(),
            Value::Bool(lnk.is_unicode),
        );
        if let Some(s) = &lnk.name {
            attrs.insert("jump_list.lnk_name".into(), Value::String(s.clone()));
        }
        if let Some(s) = &lnk.relative_path {
            attrs.insert(
                "jump_list.lnk_relative_path".into(),
                Value::String(s.clone()),
            );
        }
        if let Some(s) = &lnk.working_dir {
            attrs.insert("jump_list.lnk_working_dir".into(), Value::String(s.clone()));
        }
        if let Some(s) = &lnk.arguments {
            attrs.insert("jump_list.lnk_arguments".into(), Value::String(s.clone()));
        }
        if let Some(s) = &lnk.icon_location {
            attrs.insert(
                "jump_list.lnk_icon_location".into(),
                Value::String(s.clone()),
            );
        }
        attrs.insert(
            "jump_list.interpretation_limitation".into(),
            Value::String(INTERPRETATION_LIMITATION.to_string()),
        );
        attrs.insert(
            "jump_list.reference_spec".into(),
            Value::String(JUMP_LIST_REFERENCE.to_string()),
        );
        attrs.insert(
            "jump_list.parser_version".into(),
            Value::String(PARSER_VERSION.to_string()),
        );

        let message = format!(
            "Jump List entry 観測: container=automatic app_id={} stream={}",
            app_id.unwrap_or("(unknown)"),
            stream.name
        );

        let mut event = tf_core::event::Event {
            id: String::new(),
            time: event_time,
            source: ArtifactSource::JumpList,
            event_type: EventType::new(JUMP_LIST_OBSERVATION_EVENT_TYPE),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: lnk.target_path.as_ref().map(tf_core::WindowsPathValue::new),
            program: None,
            process: None,
            message,
            attributes: attrs,
            provenance,
        };
        event.id = event.compute_id(event_ordinal);

        if sink.emit_event(event).is_err() {
            partial = true;
            break;
        }
        events_emitted += 1;
    }

    // DestList にのみ存在する stream（LNK 無し）があれば記録。
    for dl_entry in &destlist_entries {
        if !lnk_streams.iter().any(|s| s.name == dl_entry.stream_name) {
            let _ = sink.emit_issue(record_issue(
                crate::issue::MISSING_REQUIRED_FIELD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::LogicalPath(vec!["DestList".to_string()])),
                Some(records_seen),
                &format!(
                    "DestList entry が内包 LNK stream 無し: stream_name={}",
                    dl_entry.stream_name
                ),
            ));
            issues_emitted += 1;
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

/// CustomDestinations-ms を解析する。
fn parse_custom(
    data: &[u8],
    app_id: Option<&str>,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
    bytes_consumed: u64,
    _start_pos: u64,
) -> ParseSummary {
    let mut records_seen: u64 = 0;
    let mut events_emitted: u64 = 0;
    let mut issues_emitted: u64 = 0;
    let mut entry_index: u64 = 0;
    let mut partial = false;

    let parsed = parse_custom_destinations(data);
    if parsed.partial {
        partial = true;
        let _ = sink.emit_issue(artifact_issue(
            TRUNCATED_RECORD_CODE,
            tf_core::issue::IssueSeverity::Warning,
            &context.evidence.evidence_id,
            &context.artifact.artifact_id,
            "CustomDestinations の一部 entry が読み取れなかった（truncated・未知 entry point type 等）",
        ));
        issues_emitted += 1;
    }

    let entries_flat: Vec<(&custom::CustomCategory, &custom::CustomEntry)> = parsed
        .categories
        .iter()
        .flat_map(|c| c.entries.iter().map(move |e| (c, e)))
        .collect();
    for (event_ordinal, (category, entry)) in (0_u64..).zip(entries_flat.iter().copied()) {
        records_seen += 1;
        entry_index += 1;
        let record_locator = RecordLocator::ByteRange {
            start: entry.lnk_offset,
            end: entry.lnk_offset + entry.lnk_size,
        };
        let provenance = context.make_provenance(record_locator, event_ordinal);

        // Event 時刻は LNK write timestamp を観測時刻とする（LNK header が entry の metadata）。
        let event_time = make_event_time(entry.lnk.write_filetime, TimestampKind::Modified);

        let mut attrs = BTreeMap::new();
        attrs.insert(
            "jump_list.container_type".into(),
            Value::String("custom_destinations".to_string()),
        );
        if let Some(app_id) = app_id {
            attrs.insert("jump_list.app_id".into(), Value::String(app_id.to_string()));
        }
        attrs.insert(
            "jump_list.category_type".into(),
            Value::from(category.category_type),
        );
        attrs.insert("jump_list.entry_index".into(), Value::from(entry_index));
        attrs.insert(
            "jump_list.entry_point_type".into(),
            Value::from(entry.entry_point_type),
        );
        attrs.insert("jump_list.lnk_offset".into(), Value::from(entry.lnk_offset));
        attrs.insert("jump_list.lnk_size".into(), Value::from(entry.lnk_size));

        // 内包 LNK からの属性。
        attrs.insert(
            "jump_list.lnk_flags".into(),
            Value::from(entry.lnk.flags_raw),
        );
        if let Some(tp) = &entry.lnk.target_path {
            attrs.insert(
                "jump_list.lnk_target_path".into(),
                Value::String(tp.clone()),
            );
        }
        attrs.insert(
            "jump_list.lnk_creation_filetime".into(),
            Value::from(entry.lnk.creation_filetime),
        );
        attrs.insert(
            "jump_list.lnk_access_filetime".into(),
            Value::from(entry.lnk.access_filetime),
        );
        attrs.insert(
            "jump_list.lnk_write_filetime".into(),
            Value::from(entry.lnk.write_filetime),
        );
        attrs.insert(
            "jump_list.lnk_file_size".into(),
            Value::from(entry.lnk.file_size),
        );
        attrs.insert(
            "jump_list.lnk_is_unicode".into(),
            Value::Bool(entry.lnk.is_unicode),
        );
        if let Some(s) = &entry.lnk.name {
            attrs.insert("jump_list.lnk_name".into(), Value::String(s.clone()));
        }
        if let Some(s) = &entry.lnk.relative_path {
            attrs.insert(
                "jump_list.lnk_relative_path".into(),
                Value::String(s.clone()),
            );
        }
        if let Some(s) = &entry.lnk.working_dir {
            attrs.insert("jump_list.lnk_working_dir".into(), Value::String(s.clone()));
        }
        if let Some(s) = &entry.lnk.arguments {
            attrs.insert("jump_list.lnk_arguments".into(), Value::String(s.clone()));
        }
        if let Some(s) = &entry.lnk.icon_location {
            attrs.insert(
                "jump_list.lnk_icon_location".into(),
                Value::String(s.clone()),
            );
        }
        attrs.insert(
            "jump_list.interpretation_limitation".into(),
            Value::String(INTERPRETATION_LIMITATION.to_string()),
        );
        attrs.insert(
            "jump_list.reference_spec".into(),
            Value::String(JUMP_LIST_REFERENCE.to_string()),
        );
        attrs.insert(
            "jump_list.parser_version".into(),
            Value::String(PARSER_VERSION.to_string()),
        );

        let message = format!(
            "Jump List entry 観測: container=custom app_id={} category={}",
            app_id.unwrap_or("(unknown)"),
            category.category_type
        );

        let mut event = tf_core::event::Event {
            id: String::new(),
            time: event_time,
            source: ArtifactSource::JumpList,
            event_type: EventType::new(JUMP_LIST_OBSERVATION_EVENT_TYPE),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: entry
                .lnk
                .target_path
                .as_ref()
                .map(tf_core::WindowsPathValue::new),
            program: None,
            process: None,
            message,
            attributes: attrs,
            provenance,
        };
        event.id = event.compute_id(event_ordinal);

        if sink.emit_event(event).is_err() {
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

/// 内包 LNK bytes（CFB stream の内容）から target 情報を抽出する。
///
/// 既存の [`crate::lnk`] machinery（header / idlist / linkinfo / stringdata / extradata）を
/// そのまま呼び出し、target path・timestamp・strings を取り出す。破損 LNK の場合は
/// 取得できた範囲で [`crate::jump_lists::custom::ExtractedLnk`] を返す（panic しない）。
fn extract_lnk_from_bytes(data: &[u8]) -> crate::jump_lists::custom::ExtractedLnk {
    use crate::lnk::extradata;
    use crate::lnk::header::{HEADER_BYTES as LNK_HEADER_BYTES, ShellLinkHeader};
    use crate::lnk::idlist;
    use crate::lnk::linkinfo;
    use crate::lnk::stringdata;

    if data.len() < LNK_HEADER_BYTES {
        return crate::jump_lists::custom::ExtractedLnk::default();
    }
    let header = match ShellLinkHeader::parse(&data[..LNK_HEADER_BYTES]) {
        Ok(h) => h,
        Err(_) => return crate::jump_lists::custom::ExtractedLnk::default(),
    };

    let mut reader = std::io::Cursor::new(data);
    use std::io::Seek;
    let _ = reader.seek(std::io::SeekFrom::Start(LNK_HEADER_BYTES as u64));

    // LinkTargetIDList。
    if header.flags.has_link_target_id_list() {
        let _ = idlist::read_link_target_id_list(&mut reader);
    }

    // LinkInfo。
    let mut target_path: Option<String> = None;
    if header.flags.has_link_info()
        && !header.flags.force_no_link_info()
        && let Ok(li) = linkinfo::read_link_info(&mut reader)
    {
        target_path = linkinfo::reconstruct_target_path(&li);
    }

    // StringData。
    let string_section = stringdata::read_string_data_section(&mut reader, header.flags).ok();

    // ExtraData。
    let extra_section = extradata::read_extra_data(&mut reader);

    let resolved_target = extra_section
        .environment_variable_target
        .clone()
        .or(target_path);

    crate::jump_lists::custom::ExtractedLnk {
        flags_raw: header.flags.raw(),
        target_path: resolved_target,
        creation_filetime: header.creation_time,
        access_filetime: header.access_time,
        write_filetime: header.write_time,
        file_size: header.file_size,
        is_unicode: header.flags.is_unicode(),
        name: string_section
            .as_ref()
            .and_then(|s| s.name.as_ref().map(|d| d.value.clone())),
        relative_path: string_section
            .as_ref()
            .and_then(|s| s.relative_path.as_ref().map(|d| d.value.clone())),
        working_dir: string_section
            .as_ref()
            .and_then(|s| s.working_dir.as_ref().map(|d| d.value.clone())),
        arguments: string_section
            .as_ref()
            .and_then(|s| s.arguments.as_ref().map(|d| d.value.clone())),
        icon_location: string_section
            .as_ref()
            .and_then(|s| s.icon_location.as_ref().map(|d| d.value.clone())),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_metadata_is_stable() {
        let p = JumpListParser::new();
        assert_eq!(p.parser_id(), "traceforge-jump-lists");
        assert_eq!(p.parser_version(), "1.0.0");
        assert_eq!(p.artifact_type(), ArtifactSource::JumpList);
    }

    #[test]
    fn observation_event_type_is_observed_only() {
        // 規範 §7.1・互換 §4.5: 観測型 `jump_list_observation` のみ。open/launch 等の断定禁止。
        assert_eq!(JUMP_LIST_OBSERVATION_EVENT_TYPE, "jump_list_observation");
        assert!(!JUMP_LIST_OBSERVATION_EVENT_TYPE.contains("open"));
        assert!(!JUMP_LIST_OBSERVATION_EVENT_TYPE.contains("launch"));
        assert!(!JUMP_LIST_OBSERVATION_EVENT_TYPE.contains("executed"));
    }

    #[test]
    fn reference_spec_recorded() {
        // 互換 §12-6: 参照外部仕様 revision が必要。
        assert!(!JUMP_LIST_REFERENCE.is_empty());
        assert!(JUMP_LIST_REFERENCE.contains("MS-CFB"));
        assert!(JUMP_LIST_REFERENCE.contains("MS-SHLLINK"));
    }

    #[test]
    fn app_id_extraction() {
        assert_eq!(
            extract_app_id("C:/foo/b9105685df489b5b.automaticDestinations-ms"),
            Some("b9105685df489b5b".to_string())
        );
        assert_eq!(
            extract_app_id("xxx.customDestinations-ms"),
            Some("xxx".to_string())
        );
        assert_eq!(extract_app_id("notjump.bin"), None);
        // case-insensitive。
        assert_eq!(
            extract_app_id("X.AUTOMATICDESTINATIONS-MS"),
            Some("X".to_string())
        );
    }

    #[test]
    fn interpretation_limitation_mentions_no_assertion() {
        assert!(INTERPRETATION_LIMITATION.contains("not"));
        assert!(
            INTERPRETATION_LIMITATION.contains("opening")
                || INTERPRETATION_LIMITATION.contains("launching")
        );
    }
}
