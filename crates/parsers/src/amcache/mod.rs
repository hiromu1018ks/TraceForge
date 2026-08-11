//! Windows Amcache Parser（`Amcache.hve`、互換 §4.6・T4-060〜T4-065）。
//!
//! ## 対象形式
//!
//! `Amcache.hve` は registry hive 形式（`regf` base block + `hbin` bins）そのものであり、
//! 本 Parser は [`crate::registry::hive`] module の cell parser を再利用して hive 構造を
//! 読む。Amcache 固有の課題は「key path から実行 file の metadata を復元する点」と
//! 「schema family（Win10 22H2 / Win11 24H2 Inventory）を認識する点」にある。
//!
//! ## 観測型 Event の方針（規範 §7.1・互換 §4.6）
//!
//! Amcache.hve への record の存在は「その program / file が当該 host 上で認識されていた」
//! ことの観測であって、「実行された」「起動した」ことの直接観測ではない。したがって
//! 本 Parser は [`AMCACHE_OBSERVATION_EVENT_TYPE`]（`amcache_observation`）のみを生成し、
//! process start 等 へ断定する Event type は生成しない（規範 §7.1・互換 §4.6）。
//! 実行を示す別 Evidence との Correlation でのみ実行 Finding を作成できる。
//!
//! ## schema family 認識（互換 §4.6・T4-060）
//!
//! root key 直下の subkey 名前一覧から [`SchemaFamily`] を決定する。
//! [`SchemaFamily::Win10Inventory`]（Win10 22H2 / Win11 24H2）と
//! [`SchemaFamily::Win8Legacy`]（Win 8/8.1）が対応済み。未知 schema は
//! Warning Issue のみとなり、Event 生成は行わない。**Generic Registry Parser
//! への自動 fallback は禁止**（互換 §4.6・§4.7）。Amcache.hve を汎用 registry として
//! 扱いたい場合は利用者が明示的に Registry Parser（[`crate::registry::RegistryParser`]）
//! を起動する（明示的併用・互換 §4.7）。
//!
//! ## 部分成功（規範 §9.2・§21-5）
//!
//! 中間 cell の破損・空き cell・循環参照は Issue 化し、前後の正常 cell から継続する。
//! 境界を特定できない破損（base block 不正等）だけ `Skipped` や `Partial` へ倒す。

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io::Read;

use serde_json::Value;

use tf_core::case::{EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

use crate::amcache::schema::{SchemaFamily, detect_schema_family, is_file_metadata_path};
use crate::framework::{ArtifactParser, ParseContext, ParseSink, ParseSummary, ReadSeek};
use crate::issue::{
    MALFORMED_INPUT_CODE, PARTIAL_RECORD_BOUNDARY_CODE, TRUNCATED_RECORD_CODE,
    UNSUPPORTED_VERSION_CODE, artifact_issue, record_issue,
};
use crate::lnk::filetime::filetime_to_datetime;
use crate::registry::hive::{
    BASE_BLOCK_BYTES, HiveBins, HiveHeader, KeyNode, MAX_KEY_DEPTH, MAX_KEYS, MAX_VALUES,
    REGF_MAGIC, registry_value_type_name,
};

pub mod schema;

/// Amcache Parser の安定識別子（Manifest・Provenance へ記録）。
pub const PARSER_ID: &str = "traceforge-amcache";
/// Amcache Parser の version（SemVer）。
pub const PARSER_VERSION: &str = "1.0.0";

/// Amcache の観測 Event type（規範 §7.1・互換 §4.6）。
///
/// `amcache_observation` のみ生成し、`process_start` 等の断定型は生成しない。
pub const AMCACHE_OBSERVATION_EVENT_TYPE: &str = "amcache_observation";

/// 参照外部仕様 revision（互換 §12-6: 記録が必要）。
///
/// Amcache.hve は MS-RRMF registry hive 形式をそのまま使う。schema family の分類は
/// Windows 10 (1607+) / Windows 11 で観察される Inventory 系 subkey 構造へ基づく。
/// 完全な Microsoft 公式仕様は公開されていないため、libyal libamcache 等の
/// リバースエンジニアリング成果を補助資料とする。
pub const AMCACHE_REFERENCE: &str =
    "MS-RRMF registry hive + Amcache Inventory schema (Win10 22H2 / Win11 24H2)";

/// snapshot 1回分の読取上限（byte）。registry Parser と同じ上限値。
const SNAPSHOT_READ_CAP: u64 = 1024 * 1024 * 1024;

/// 「process start へは断定しない」旨の制約注記（互換 §5 必須 field
/// 「interpretation limitation」へ記録）。
const INTERPRETATION_LIMITATION: &str =
    "record existence only; not direct evidence of process start";

/// Amcache Parser 本体。
///
/// [`AmcacheParser::new`] で構築する。LOG1/LOG2 replay は本 Parser では行わず、
/// 必要なら利用者が Registry Parser（[`crate::registry::RegistryParser`]）で
/// 別途解析できる（明示的併用・互換 §4.7）。
#[derive(Default)]
pub struct AmcacheParser;

impl AmcacheParser {
    pub fn new() -> Self {
        AmcacheParser
    }
}

/// snapshot 全読みの結果。
enum ReadAllOutcome {
    Complete(Vec<u8>),
    Error(std::io::Error),
}

/// `reader` から最大 `cap` byte まで全読みする（registry Parser と同一実装）。
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

/// 1 view の走査結果。
struct WalkResult {
    partial: bool,
    abort: bool,
}

impl ArtifactParser for AmcacheParser {
    fn parser_id(&self) -> &'static str {
        PARSER_ID
    }

    fn parser_version(&self) -> &'static str {
        PARSER_VERSION
    }

    fn artifact_type(&self) -> ArtifactSource {
        ArtifactSource::Amcache
    }

    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult {
        // 規範 §5.5: VerifiedSnapshot 以外は解析しない。
        if evidence.integrity_status != tf_core::case::IntegrityStatus::VerifiedSnapshot {
            return ProbeResult::NotThisFormat;
        }
        // source_locator の末尾要素が Amcache.hve（case-insensitive）なら Probable。
        // hive magic は Registry Parser と共通のため、file 名で Amcache らしいかを判定する。
        let name = evidence
            .source_locator
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&evidence.source_locator);
        if !name.eq_ignore_ascii_case("Amcache.hve") {
            return ProbeResult::NotThisFormat;
        }
        // さらに先頭 magic が regf であることを確認（Snapshot file を開いて読む）。
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
        if buf == REGF_MAGIC {
            // file 名と magic の両方から Amcache らしいと判断。Confirmed ではなく
            // Probable に留める（registry hive 全般と重複するため、呼出側で
            // Registry Parser との使い分けを明示的に行う設計・互換 §4.7）。
            ProbeResult::Probable
        } else {
            ProbeResult::NotThisFormat
        }
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
        let hive_bytes = match read_all(snapshot, SNAPSHOT_READ_CAP) {
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
        let bytes_consumed = hive_bytes.len() as u64;

        if hive_bytes.len() < BASE_BLOCK_BYTES {
            let _ = sink.emit_issue(artifact_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!(
                    "snapshot が base block ({} byte) に満たない: {} byte",
                    BASE_BLOCK_BYTES,
                    hive_bytes.len()
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

        // === base block を parse ===
        let header = match crate::registry::hive::parse_base_block(&hive_bytes) {
            Ok(h) => h,
            Err(e) => {
                let _ = sink.emit_issue(artifact_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    &format!("hive base block の parse 失敗: {e}"),
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

        // === bins 領域を取り出す ===
        let bins_start = BASE_BLOCK_BYTES;
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
            issues_emitted += 1;
            return ParseSummary {
                status: ParseStatus::Skipped,
                records_seen,
                events_emitted,
                issues_emitted,
                bytes_consumed,
            };
        }
        let bins_bytes = &hive_bytes[bins_start..bins_end];
        let bins = HiveBins::new(bins_bytes);

        // === root key を読み、subkey 名前一覧から schema family を判定 ===
        let root_nk = match bins.parse_key_node(header.root_cell_offset) {
            Ok(n) => n,
            Err(e) => {
                let _ = sink.emit_issue(record_issue(
                    MALFORMED_INPUT_CODE,
                    tf_core::issue::IssueSeverity::Warning,
                    &context.evidence.evidence_id,
                    &context.artifact.artifact_id,
                    Some(RecordLocator::ByteOffset(header.root_cell_offset as u64)),
                    Some(records_seen),
                    &format!("root nk cell の parse 失敗: {e}"),
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
        records_seen += 1;

        let schema_family = match collect_root_subkey_names(&bins, &root_nk) {
            Some(names) => detect_schema_family(&names),
            None => SchemaFamily::Unknown,
        };

        if !schema_family.is_supported() {
            // 未知 schema: Warning Issue のみ。Generic Registry への自動 fallback 禁止（互換 §4.6）。
            let _ = sink.emit_issue(artifact_issue(
                UNSUPPORTED_VERSION_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                &format!(
                    "未知 Amcache schema family のため解析を skip した（Generic Registry Parser \
                     への自動 fallback は行わない・互換 §4.6・§4.7）。schema_family={}",
                    schema_family.as_str()
                ),
            ));
            issues_emitted += 1;
            // Event 生成無し。Skipped で返す。
            return ParseSummary {
                status: ParseStatus::Skipped,
                records_seen,
                events_emitted,
                issues_emitted,
                bytes_consumed,
            };
        }

        // === root から再帰的に走査し、amcache_observation Event を生成 ===
        let mut visited_cells: HashSet<u32> = HashSet::new();
        let mut visited_subkey_lists: HashSet<u32> = HashSet::new();
        let mut total_keys: u32 = 0;
        let walk_result = walk_subtree(
            &bins,
            header.root_cell_offset,
            String::new(),
            0,
            schema_family,
            &header,
            context,
            sink,
            &mut ordinal,
            &mut records_seen,
            &mut events_emitted,
            &mut issues_emitted,
            &mut visited_cells,
            &mut visited_subkey_lists,
            &mut total_keys,
        );
        if walk_result.abort || walk_result.partial {
            partial = true;
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

/// root key の subkey 名前一覧を取り出す。schema family 判定に使う。
///
/// `root_nk.subkey_list_offset` から subkey の nk offset 一覧を得て、各々の key 名を
/// 読む。破損等で読めない場合は `None` を返す（この場合は Unknown 扱い）。
fn collect_root_subkey_names(bins: &HiveBins, root_nk: &KeyNode) -> Option<Vec<String>> {
    if root_nk.subkey_count == 0
        || root_nk.subkey_list_offset == 0xFFFF_FFFF
        || root_nk.subkey_list_offset == 0
    {
        return Some(Vec::new());
    }
    let mut visited: HashSet<u32> = HashSet::new();
    let offsets = bins.subkey_offsets(root_nk.subkey_list_offset, &mut visited);
    let mut names = Vec::with_capacity(offsets.len());
    for off in offsets {
        match bins.parse_key_node(off) {
            Ok(nk) => names.push(nk.key_name.clone()),
            Err(_) => {
                // 読めない subkey は名前無しとして扱う（schema family 判定から外す）。
                continue;
            }
        }
    }
    Some(names)
}

/// 1つの key subtree を再帰的に走査し、`amcache_observation` Event を生成する。
///
/// 各 key について:
///
/// - key 自体の last_write 観測を1件の observation Event へ。
/// - 各 value の存在観測を1件ずつの observation Event へ。
///
/// 循環参照防止・depth 上限・key/value 数上限は registry Parser と同じ定数で管理する。
#[allow(clippy::too_many_arguments)]
fn walk_subtree(
    bins: &HiveBins,
    nk_offset: u32,
    parent_path: String,
    depth: u32,
    schema_family: SchemaFamily,
    header: &HiveHeader,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
    ordinal: &mut u64,
    records_seen: &mut u64,
    events_emitted: &mut u64,
    issues_emitted: &mut u64,
    visited_cells: &mut HashSet<u32>,
    visited_subkey_lists: &mut HashSet<u32>,
    total_keys: &mut u32,
) -> WalkResult {
    let mut partial = false;

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
        return WalkResult {
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
        return WalkResult {
            partial: true,
            abort: true,
        };
    }

    // 循環参照防止: 既に訪問した nk offset は再訪しない（root も含む）。
    if !visited_cells.insert(nk_offset) {
        return WalkResult {
            partial: false,
            abort: false,
        };
    }
    *total_keys += 1;

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
            return WalkResult {
                partial: true,
                abort: false,
            };
        }
    };

    // key path を構築。root（depth 0）は自身の key_name をそのまま使う。
    let key_path = if parent_path.is_empty() {
        nk.key_name.clone()
    } else {
        format!("{}\\{}", parent_path, nk.key_name)
    };

    // === key 自体の observation Event を1件生成 ===
    let key_event = build_key_observation_event(
        &nk,
        &key_path,
        depth,
        schema_family,
        header,
        context,
        *ordinal,
    );
    *ordinal += 1;
    if sink.emit_event(key_event).is_err() {
        return WalkResult {
            partial: true,
            abort: true,
        };
    }
    *events_emitted += 1;

    // === value list を処理 ===
    if nk.value_count > 0 && nk.value_list_offset != 0xFFFF_FFFF && nk.value_list_offset != 0 {
        let value_offsets = bins.value_list_offsets(nk.value_list_offset, nk.value_count);
        let mut value_count_seen: u32 = 0;
        for vk_offset in value_offsets {
            *records_seen += 1;
            value_count_seen += 1;
            match bins.parse_key_value(vk_offset) {
                Ok(vk) => {
                    let value_event = build_value_observation_event(
                        &vk,
                        &nk,
                        &key_path,
                        schema_family,
                        header,
                        context,
                        *ordinal,
                    );
                    *ordinal += 1;
                    if sink.emit_event(value_event).is_err() {
                        return WalkResult {
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
    if nk.subkey_count > 0 && nk.subkey_list_offset != 0xFFFF_FFFF && nk.subkey_list_offset != 0 {
        let subkey_offsets = bins.subkey_offsets(nk.subkey_list_offset, visited_subkey_lists);
        let declared = nk.subkey_count as usize;
        let actual = subkey_offsets.len();
        if actual < declared {
            let _ = sink.emit_issue(record_issue(
                TRUNCATED_RECORD_CODE,
                tf_core::issue::IssueSeverity::Warning,
                &context.evidence.evidence_id,
                &context.artifact.artifact_id,
                Some(RecordLocator::ByteOffset(nk.subkey_list_offset as u64)),
                Some(*records_seen),
                &format!("subkey list の一部が読めなかった: declared={declared}, actual={actual}"),
            ));
            *issues_emitted += 1;
            partial = true;
        }
        for child_offset in subkey_offsets {
            let child_result = walk_subtree(
                bins,
                child_offset,
                key_path.clone(),
                depth + 1,
                schema_family,
                header,
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
                return WalkResult {
                    partial: true,
                    abort: true,
                };
            }
            if child_result.partial {
                partial = true;
            }
        }
    }

    WalkResult {
        partial,
        abort: false,
    }
}

/// key 自体の `amcache_observation` Event を構築する。
#[allow(clippy::too_many_arguments)]
fn build_key_observation_event(
    nk: &KeyNode,
    key_path: &str,
    depth: u32,
    schema_family: SchemaFamily,
    header: &HiveHeader,
    context: &ParseContext,
    event_ordinal: u64,
) -> tf_core::event::Event {
    let event_time = make_event_time(nk.last_write_filetime, TimestampKind::Modified);

    let cell_abs_start = nk.cell_offset as u64;
    let record_locator = RecordLocator::ByteRange {
        start: cell_abs_start,
        end: cell_abs_start + nk.cell_size as u64,
    };
    let provenance = context.make_provenance(record_locator, event_ordinal);

    let mut attrs = BTreeMap::new();
    attrs.insert(
        "amcache.schema_family".into(),
        Value::String(schema_family.as_str().to_string()),
    );
    attrs.insert(
        "amcache.key_path".into(),
        Value::String(key_path.to_string()),
    );
    attrs.insert(
        "amcache.key_name".into(),
        Value::String(nk.key_name.clone()),
    );
    attrs.insert("amcache.key_depth".into(), Value::from(depth));
    attrs.insert("amcache.subkey_count".into(), Value::from(nk.subkey_count));
    attrs.insert("amcache.value_count".into(), Value::from(nk.value_count));
    attrs.insert(
        "amcache.hive_major_version".into(),
        Value::from(header.major_version),
    );
    attrs.insert(
        "amcache.hive_minor_version".into(),
        Value::from(header.minor_version),
    );
    attrs.insert(
        "amcache.last_write_filetime".into(),
        Value::from(nk.last_write_filetime),
    );
    attrs.insert(
        "amcache.is_file_metadata_key".into(),
        Value::Bool(is_file_metadata_path(key_path)),
    );
    attrs.insert(
        "amcache.interpretation_limitation".into(),
        Value::String(INTERPRETATION_LIMITATION.to_string()),
    );
    attrs.insert(
        "amcache.reference_spec".into(),
        Value::String(AMCACHE_REFERENCE.to_string()),
    );
    attrs.insert(
        "amcache.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );

    let message = format!(
        "Amcache key 観測: schema={} key={}",
        schema_family.as_str(),
        key_path
    );

    let mut event = tf_core::event::Event {
        id: String::new(),
        time: event_time,
        source: ArtifactSource::Amcache,
        event_type: EventType::new(AMCACHE_OBSERVATION_EVENT_TYPE),
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

/// value の `amcache_observation` Event を構築する。
#[allow(clippy::too_many_arguments)]
fn build_value_observation_event(
    vk: &crate::registry::hive::KeyValue,
    parent_nk: &KeyNode,
    key_path: &str,
    schema_family: SchemaFamily,
    header: &HiveHeader,
    context: &ParseContext,
    event_ordinal: u64,
) -> tf_core::event::Event {
    // value 自体に timestamp は無い。親 key の last_write を観測時刻の上限として使う
    // （registry Parser と同じ方針）。
    let event_time = make_event_time(parent_nk.last_write_filetime, TimestampKind::Modified);

    let cell_abs_start = vk.cell_offset as u64;
    let record_locator = RecordLocator::ByteRange {
        start: cell_abs_start,
        end: cell_abs_start + vk.cell_size as u64,
    };
    let provenance = context.make_provenance(record_locator, event_ordinal);

    let mut attrs = BTreeMap::new();
    attrs.insert(
        "amcache.schema_family".into(),
        Value::String(schema_family.as_str().to_string()),
    );
    attrs.insert(
        "amcache.key_path".into(),
        Value::String(key_path.to_string()),
    );
    attrs.insert(
        "amcache.key_name".into(),
        Value::String(parent_nk.key_name.clone()),
    );
    attrs.insert(
        "amcache.value_name".into(),
        Value::String(vk.value_name.clone()),
    );
    attrs.insert("amcache.value_type".into(), Value::from(vk.data_type));
    attrs.insert(
        "amcache.value_type_name".into(),
        Value::String(registry_value_type_name(vk.data_type).to_string()),
    );
    attrs.insert("amcache.value_offset".into(), Value::from(vk.cell_offset));
    attrs.insert("amcache.value_data_size".into(), Value::from(vk.data.len()));
    attrs.insert(
        "amcache.value_data".into(),
        value_data_to_json(vk.data_type, &vk.data),
    );
    attrs.insert(
        "amcache.hive_major_version".into(),
        Value::from(header.major_version),
    );
    attrs.insert(
        "amcache.hive_minor_version".into(),
        Value::from(header.minor_version),
    );
    attrs.insert(
        "amcache.last_write_filetime".into(),
        Value::from(parent_nk.last_write_filetime),
    );
    attrs.insert(
        "amcache.is_file_metadata_key".into(),
        Value::Bool(is_file_metadata_path(key_path)),
    );
    attrs.insert(
        "amcache.interpretation_limitation".into(),
        Value::String(INTERPRETATION_LIMITATION.to_string()),
    );
    attrs.insert(
        "amcache.reference_spec".into(),
        Value::String(AMCACHE_REFERENCE.to_string()),
    );
    attrs.insert(
        "amcache.parser_version".into(),
        Value::String(PARSER_VERSION.to_string()),
    );

    let message = format!(
        "Amcache value 観測: schema={} key={} name={} type={}",
        schema_family.as_str(),
        key_path,
        vk.value_name,
        registry_value_type_name(vk.data_type)
    );

    let mut event = tf_core::event::Event {
        id: String::new(),
        time: event_time,
        source: ArtifactSource::Amcache,
        event_type: EventType::new(AMCACHE_OBSERVATION_EVENT_TYPE),
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
///
/// registry Parser の `value_data_to_json` と同等だが、本 module は registry Parser
/// の内部関数を直接参照しないため独立実装する（`REG_BINARY` 等の汎用 data は
/// 大きくなり得るため SHA-256 hex へ要約して保持する）。
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
            // REG_BINARY その他: hex lowercase 文字列（registry Parser と同じく SHA-256 hex）。
            Value::String(tf_core::hash::sha256_hex(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_metadata_is_stable() {
        let p = AmcacheParser::new();
        assert_eq!(p.parser_id(), "traceforge-amcache");
        assert_eq!(p.parser_version(), "1.0.0");
        assert_eq!(p.artifact_type(), ArtifactSource::Amcache);
    }

    #[test]
    fn observation_event_type_is_observed_only() {
        // 規範 §7.1・互換 §4.6: 観測型 `amcache_observation` のみ。process start 等の断定禁止。
        assert_eq!(AMCACHE_OBSERVATION_EVENT_TYPE, "amcache_observation");
        assert!(!AMCACHE_OBSERVATION_EVENT_TYPE.contains("process_start"));
        assert!(!AMCACHE_OBSERVATION_EVENT_TYPE.contains("launched"));
        assert!(!AMCACHE_OBSERVATION_EVENT_TYPE.contains("executed"));
    }

    #[test]
    fn reference_spec_is_recorded() {
        // 互換 §12-6: 参照外部仕様 revision が必要。
        assert!(!AMCACHE_REFERENCE.is_empty());
        assert!(AMCACHE_REFERENCE.contains("MS-RRMF"));
    }

    #[test]
    fn interpretation_limitation_mentions_process_start_constraint() {
        // 互換 §5 必須 field「interpretation limitation」へ記録する制約注記。
        assert!(INTERPRETATION_LIMITATION.contains("not"));
        assert!(INTERPRETATION_LIMITATION.contains("process start"));
    }
}
