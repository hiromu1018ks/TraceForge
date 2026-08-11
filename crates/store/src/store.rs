//! length-delimited spool file Event Store（規範 §10）。
//!
//! Runtime の Case へ `Vec<Event>` を保持してはならない（規範 §10）。本 EventStore は
//! Event を逐次 spool file へ保存し、必要時に iterator で読み出す。
//!
//! spool file 形式（length-delimited binary）:
//!
//! ```text
//! magic: "TFES"（4 byte）
//! format_version: 1（1 byte）
//! records: 繰り返し {
//!   record_kind: 1 byte
//!     0x01 = Event
//!     0x02 = Commit marker
//!   payload_len: 4 byte big-endian
//!   payload: payload_len bytes（Event は canonical JSON UTF-8 bytes）
//! }
//! ```
//!
//! 満たす要件（規範 §10）:
//! - Event ごとの Schema validation（[`EventStore::store_event`]）
//! - Event ID による一意制約（[`EventStore::store_event`]）
//! - 途中停止時に未完了 Case と判別できる commit marker（[`EventStore::commit`]）
//! - timestamp group と Event ID による決定的 iteration（[`EventStore::iter_sorted`]
//!   が [`crate::timeline::TimelineKey`] で sort して返す）
//! - 最終出力完了まで自動削除しない（drop しても file は残る）
//! - permission を所有者だけに制限する（Unix では 0o600、directory は 0o700）

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tf_core::canonical::to_canonical_string;
use tf_core::event::Event;
use tf_core::schema::{SchemaError, event_time_validator, validate_jsonl_envelope};

use crate::error::StoreError;

/// spool file の magic bytes。
const MAGIC: &[u8; 4] = b"TFES";
/// spool file 形式 version。
const FORMAT_VERSION: u8 = 1;
/// Event record の kind tag。
const RECORD_EVENT: u8 = 0x01;
/// Commit marker record の kind tag。
const RECORD_COMMIT: u8 = 0x02;
/// commit marker の payload 内容（将来の拡張で内容を変えられるよう独立定数化）。
const COMMIT_PAYLOAD: &[u8] = b"COMMIT-V1";

/// length-delimited spool file Event Store（規範 §10）。
///
/// [`EventStore::create`] で新規作成、[`EventStore::open`] で既存 file を開く。
/// どちらも所有者限定 permission を設定する（規範 §10）。
pub struct EventStore {
    path: PathBuf,
    writer: BufWriter<File>,
    /// Event ID の一覧。一意制約（規範 §10）と重複検出に使う。
    event_ids: BTreeSet<String>,
    committed: bool,
    event_count: u64,
}

impl EventStore {
    /// 新規 spool file を作成する（規範 §10）。
    ///
    /// 既存 file が存在する場合は error とする（上書きしない）。header を書き込み、
    /// 所有者限定 permission を設定する。
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        apply_owner_only_permissions(&file, &path)?;

        let mut writer = BufWriter::new(file);
        writer.write_all(MAGIC)?;
        writer.write_all(&[FORMAT_VERSION])?;
        writer.flush()?;

        Ok(EventStore {
            path,
            writer,
            event_ids: BTreeSet::new(),
            committed: false,
            event_count: 0,
        })
    }

    /// 既存 spool file を開き、末尾へ追記可能にする（規範 §10）。
    ///
    /// 既存 record を走査して Event ID 一覧と commit 状態を復元する。
    /// commit 済みの file への追記は [`EventStore::store_event`] が error で拒否する。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        apply_owner_only_permissions(&file, &path)?;

        // header 検証。
        let mut header = [0u8; MAGIC.len() + 1];
        file.read_exact(&mut header)?;
        if &header[..MAGIC.len()] != MAGIC {
            return Err(StoreError::Format("spool file の magic が不正".into()));
        }
        if header[MAGIC.len()] != FORMAT_VERSION {
            return Err(StoreError::Format(format!(
                "spool file の version が不正: 期待 {}, 実際 {}",
                FORMAT_VERSION,
                header[MAGIC.len()]
            )));
        }

        // 既存 record を走査して Event ID と commit 状態を復元する。
        let mut event_ids = BTreeSet::new();
        let mut event_count: u64 = 0;
        let mut committed = false;
        while let Ok(kind) = read_u8(&mut file) {
            let payload_len = read_u32_be(&mut file)? as usize;
            let mut payload = vec![0u8; payload_len];
            file.read_exact(&mut payload)?;
            match kind {
                RECORD_EVENT => {
                    let event = decode_event(&payload)?;
                    if !event_ids.insert(event.id.clone()) {
                        return Err(StoreError::Format(format!(
                            "spool file 内に重複 Event ID が存在する: {}",
                            event.id
                        )));
                    }
                    event_count += 1;
                }
                RECORD_COMMIT => committed = true,
                other => {
                    return Err(StoreError::Format(format!(
                        "未知の record kind です: {other:#x}"
                    )));
                }
            }
        }

        // 末尾へ seek して追記可能にする。
        file.seek(SeekFrom::End(0))?;

        Ok(EventStore {
            path,
            writer: BufWriter::new(file),
            event_ids,
            committed,
            event_count,
        })
    }

    /// spool file の path。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Event 件数。
    pub fn len(&self) -> u64 {
        self.event_count
    }

    /// Event 0 件か。
    pub fn is_empty(&self) -> bool {
        self.event_count == 0
    }

    /// commit 済みか（規範 §10: commit marker）。
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// 既に同じ Event ID が存在するか（規範 §10: Event ID 一意制約）。
    pub fn contains(&self, event_id: &str) -> bool {
        self.event_ids.contains(event_id)
    }

    /// Event を1件書き込む（規範 §10）。
    ///
    /// 次を順に検査する:
    /// 1. commit 済みでないこと（[`StoreError::AlreadyCommitted`]）
    /// 2. Event の Schema validation（[`StoreError::Schema`]）
    /// 3. Event ID の一意制約（[`StoreError::DuplicateEventId`]）
    ///
    /// 検査通過後、canonical JSON bytes を length-delimited record として追記し、
    /// flush して耐障害性を確保する。
    pub fn store_event(&mut self, event: &Event) -> Result<(), StoreError> {
        if self.committed {
            return Err(StoreError::AlreadyCommitted(
                self.path.display().to_string(),
            ));
        }
        // 規範 §10: Event ごとの Schema validation。
        validate_event(event)?;
        // 規範 §10: Event ID 一意制約。
        if !self.event_ids.insert(event.id.clone()) {
            return Err(StoreError::DuplicateEventId(event.id.clone()));
        }

        let payload = encode_event(event)?;
        self.writer.write_all(&[RECORD_EVENT])?;
        self.writer
            .write_all(&(payload.len() as u32).to_be_bytes())?;
        self.writer.write_all(&payload)?;
        // 規範 §10: commit marker が無くても個々の Event は durable であること。
        self.writer.flush()?;

        self.event_count += 1;
        Ok(())
    }

    /// commit marker を書き込み、Case が完了したことを記録する（規範 §10）。
    ///
    /// commit 後は [`store_event`](Self::store_event) が [`StoreError::AlreadyCommitted`] を返す。
    /// 二重 commit は可能（既に commit 済みなら何もしない）。
    pub fn commit(&mut self) -> Result<(), StoreError> {
        if self.committed {
            return Ok(());
        }
        self.writer.write_all(&[RECORD_COMMIT])?;
        self.writer
            .write_all(&(COMMIT_PAYLOAD.len() as u32).to_be_bytes())?;
        self.writer.write_all(COMMIT_PAYLOAD)?;
        self.writer.flush()?;
        self.committed = true;
        Ok(())
    }

    /// 全 Event を格納順に読み出す iterator を返す（規範 §10: 決定的 iteration）。
    ///
    /// Timeline 順で読み出す場合は [`EventStore::iter_sorted`] を使う。
    /// [`Vec`] を返さないため、100万 Event でも一度に全件をメモリへ載せない（規範 §21-6）。
    pub fn iter(&self) -> Result<EventIter, StoreError> {
        EventIter::open(&self.path)
    }

    /// 全 Event を Timeline 順（[`crate::timeline::TimelineKey`] sort）で読み出す
    /// iterator を返す（規範 §6.3、§10）。
    ///
    /// `memory_budget_bytes` を超える場合は external merge sort へ切り替える
    /// （規範 §10: memory 内 sort だけに依存してはならない）。
    /// [`Vec`] を返さない（規範 §21-6）。
    pub fn iter_sorted(&self, memory_budget_bytes: usize) -> Result<SortedEventIter, StoreError> {
        crate::external_sort::sorted_iter(self, memory_budget_bytes)
    }
}

impl Drop for EventStore {
    fn drop(&mut self) {
        // 規範 §10: 最終出力完了まで自動削除しない。drop では file を残す。
        let _ = self.writer.flush();
    }
}

/// Event を canonical JSON へ直列化する。
fn encode_event(event: &Event) -> Result<Vec<u8>, StoreError> {
    let value = event.to_canonical_value();
    let json = to_canonical_string(&value).map_err(|e| StoreError::Serialize(e.to_string()))?;
    Ok(json.into_bytes())
}

/// canonical JSON bytes から Event を復元する。
fn decode_event(bytes: &[u8]) -> Result<Event, StoreError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| StoreError::Serialize(e.to_string()))?;
    event_from_canonical_value(&value)
}

/// canonical JSON [`serde_json::Value`] から [`Event`] を復元する。
pub(crate) fn event_from_canonical_value(value: &serde_json::Value) -> Result<Event, StoreError> {
    let obj = value
        .as_object()
        .ok_or_else(|| StoreError::Serialize("Event record が object ではない".into()))?;
    let id = obj
        .get("event_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("event_id が文字列ではない".into()))?
        .to_string();
    let time = tf_core_time_from_value(&obj["time"])?;
    let source_str = obj
        .get("source")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("source が文字列ではない".into()))?;
    let source = tf_core::event::ArtifactSource::from_schema_str(source_str)
        .ok_or_else(|| StoreError::Serialize(format!("未知の source: {source_str}")))?;
    let event_type = obj
        .get("event_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("event_type が文字列ではない".into()))?;
    let assertion_str = obj
        .get("assertion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("assertion が文字列ではない".into()))?;
    let assertion = tf_core::event::AssertionKind::from_schema_str(assertion_str)
        .ok_or_else(|| StoreError::Serialize(format!("未知の assertion: {assertion_str}")))?;
    let hostname = obj
        .get("hostname")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let user = obj
        .get("user")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let path = obj
        .get("path")
        .filter(|v| v.is_object())
        .map(tf_core_path_from_value);
    let program = obj
        .get("program")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let process = obj
        .get("process")
        .filter(|v| v.is_object())
        .map(tf_core_process_from_value);
    let message = obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let attributes = obj
        .get("attributes")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let provenance = tf_core_provenance_from_value(&obj["provenance"])?;

    Ok(Event {
        id,
        time,
        source,
        event_type: tf_core::event::EventType::new(event_type),
        assertion,
        hostname,
        user,
        path,
        program,
        process,
        message,
        attributes,
        provenance,
    })
}

/// canonical JSON から [`tf_core::time::EventTime`] を復元する。
fn tf_core_time_from_value(
    value: &serde_json::Value,
) -> Result<tf_core::time::EventTime, StoreError> {
    use chrono::{DateTime, NaiveDateTime};
    use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};

    let obj = value
        .as_object()
        .ok_or_else(|| StoreError::Serialize("time が object ではない".into()))?;
    let type_str = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("time.type が文字列ではない".into()))?;
    let original = obj
        .get("original")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let kind_str = obj
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("time.kind が文字列ではない".into()))?;
    let kind = TimestampKind::from_schema_str(kind_str)
        .ok_or_else(|| StoreError::Serialize(format!("未知の kind: {kind_str}")))?;
    let precision_str = obj
        .get("precision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("time.precision が文字列ではない".into()))?;
    let precision = TimePrecision::from_schema_str(precision_str)
        .ok_or_else(|| StoreError::Serialize(format!("未知の precision: {precision_str}")))?;
    let tz_source_str = obj
        .get("timezone_source")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("time.timezone_source が文字列ではない".into()))?;
    let timezone_source = TimezoneSource::from_schema_str(tz_source_str)
        .ok_or_else(|| StoreError::Serialize(format!("未知の timezone_source: {tz_source_str}")))?;
    let uncertainty_ms = obj.get("uncertainty_ms").and_then(|v| v.as_u64());

    let temporal = match type_str {
        "utc_instant" => {
            let v = obj
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| StoreError::Serialize("utc_instant.value が無い".into()))?;
            let dt: DateTime<chrono::Utc> = v
                .parse()
                .map_err(|e| StoreError::Serialize(format!("utc_instant の parse 失敗: {e}")))?;
            TemporalValue::UtcInstant { value: dt }
        }
        "local_time" => {
            let v = obj
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| StoreError::Serialize("local_time.value が無い".into()))?;
            let naive: NaiveDateTime = v
                .parse()
                .map_err(|e| StoreError::Serialize(format!("local_time の parse 失敗: {e}")))?;
            let timezone = obj
                .get("timezone")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            TemporalValue::LocalTime {
                value: naive,
                timezone,
            }
        }
        "range" => {
            let start = obj
                .get("start")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<DateTime<chrono::Utc>>().ok());
            let end = obj
                .get("end")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<DateTime<chrono::Utc>>().ok());
            TemporalValue::Range { start, end }
        }
        "unknown" => TemporalValue::Unknown,
        other => {
            return Err(StoreError::Serialize(format!("未知の time type: {other}")));
        }
    };

    Ok(EventTime {
        value: temporal,
        original,
        kind,
        precision,
        timezone_source,
        uncertainty_ms,
    })
}

/// canonical JSON から [`tf_core::WindowsPathValue`] を復元する。
fn tf_core_path_from_value(value: &serde_json::Value) -> tf_core::WindowsPathValue {
    let obj = value.as_object();
    let original = obj
        .and_then(|o| o.get("original"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let comparison_key = obj
        .and_then(|o| o.get("comparison_key"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let normalization_profile = obj
        .and_then(|o| o.get("normalization_profile"))
        .and_then(|v| v.as_str())
        .unwrap_or("windows-path-v1")
        .to_string();
    let normalization_notes = obj
        .and_then(|o| o.get("normalization_notes"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    tf_core::WindowsPathValue {
        original,
        comparison_key,
        normalization_profile,
        normalization_notes,
    }
}

/// canonical JSON から [`tf_core::event::Provenance`] を復元する。
fn tf_core_provenance_from_value(
    value: &serde_json::Value,
) -> Result<tf_core::event::Provenance, StoreError> {
    use tf_core::event::Provenance;

    let obj = value
        .as_object()
        .ok_or_else(|| StoreError::Serialize("provenance が object ではない".into()))?;
    let evidence_id = obj
        .get("evidence_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("provenance.evidence_id が無い".into()))?
        .to_string();
    let artifact_id = obj
        .get("artifact_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("provenance.artifact_id が無い".into()))?
        .to_string();
    let source_locator = obj
        .get("source_locator")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("provenance.source_locator が無い".into()))?
        .to_string();
    let source_sha256 = obj
        .get("source_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("provenance.source_sha256 が無い".into()))?
        .to_string();
    let parser_id = obj
        .get("parser_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("provenance.parser_id が無い".into()))?
        .to_string();
    let parser_version = obj
        .get("parser_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("provenance.parser_version が無い".into()))?
        .to_string();
    let source_ordinal = obj
        .get("source_ordinal")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| StoreError::Serialize("provenance.source_ordinal が無い".into()))?;
    let record_locator = record_locator_from_value(&obj["record_locator"])?;

    Ok(Provenance {
        evidence_id,
        artifact_id,
        source_locator,
        source_sha256,
        parser_id,
        parser_version,
        record_locator,
        source_ordinal,
    })
}

/// canonical JSON から [`tf_core::event::ProcessRef`] を復元する。
fn tf_core_process_from_value(value: &serde_json::Value) -> tf_core::event::ProcessRef {
    use tf_core::event::ProcessRef;

    let obj = value.as_object();
    let pid = obj.and_then(|o| o.get("pid")).and_then(|v| v.as_u64());
    let ppid = obj.and_then(|o| o.get("ppid")).and_then(|v| v.as_u64());
    let process_guid = obj
        .and_then(|o| o.get("process_guid"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let parent_process_guid = obj
        .and_then(|o| o.get("parent_process_guid"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let image_path = obj
        .and_then(|o| o.get("image_path"))
        .filter(|v| v.is_object())
        .map(tf_core_path_from_value);
    let command_line = obj
        .and_then(|o| o.get("command_line"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    ProcessRef {
        pid,
        ppid,
        process_guid,
        parent_process_guid,
        image_path,
        command_line,
    }
}

/// canonical JSON から [`tf_core::event::RecordLocator`] を復元する。
fn record_locator_from_value(
    value: &serde_json::Value,
) -> Result<tf_core::event::RecordLocator, StoreError> {
    use tf_core::event::RecordLocator;

    let obj = value
        .as_object()
        .ok_or_else(|| StoreError::Serialize("record_locator が object ではない".into()))?;
    let kind = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Serialize("record_locator.type が無い".into()))?;
    let locator = match kind {
        "record_id" => {
            let v = obj
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| StoreError::Serialize("record_id.value が無い".into()))?;
            RecordLocator::RecordId(v.to_string())
        }
        "byte_offset" => {
            let v = obj
                .get("value")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| StoreError::Serialize("byte_offset.value が無い".into()))?;
            RecordLocator::ByteOffset(v)
        }
        "byte_range" => {
            let start = obj
                .get("start")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| StoreError::Serialize("byte_range.start が無い".into()))?;
            let end = obj
                .get("end")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| StoreError::Serialize("byte_range.end が無い".into()))?;
            RecordLocator::ByteRange { start, end }
        }
        "logical_path" => {
            let arr = obj
                .get("value")
                .and_then(|v| v.as_array())
                .ok_or_else(|| StoreError::Serialize("logical_path.value が配列ではない".into()))?;
            let parts: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            RecordLocator::LogicalPath(parts)
        }
        "source_ordinal" => RecordLocator::SourceOrdinal,
        other => {
            return Err(StoreError::Serialize(format!(
                "未知の record_locator type: {other}"
            )));
        }
    };
    Ok(locator)
}

/// Event の Schema validation（規範 §10: Event ごとの Schema validation）。
///
/// Phase 3 では EventTime（Schema §4）の検証と、必須 field の存在確認を行う。
/// Schema §5.5 の完全 fragment による検証は Phase 7 / Phase 8 で強化する。
fn validate_event(event: &Event) -> Result<(), StoreError> {
    let value = event.to_canonical_value();
    // Schema §5.5 の必須 field を確認する。
    let obj = value
        .as_object()
        .ok_or_else(|| SchemaError::Validation("Event が object ではない".into()))?;
    for key in [
        "event_id",
        "time",
        "source",
        "event_type",
        "assertion",
        "message",
        "attributes",
        "provenance",
    ] {
        if !obj.contains_key(key) {
            return Err(StoreError::Schema(SchemaError::Validation(format!(
                "Event の必須 field 欠落: {key}"
            ))));
        }
    }
    // EventTime（Schema §4）を JSON Schema へかける。
    let time_validator = event_time_validator();
    time_validator.validate(&obj["time"])?;
    // Event 全体を JSONL envelope と同等の構造へ包んで、record としての基本検査を併用する。
    // envelope は record_type = event とし、record が object であることを確認する。
    let envelope = serde_json::json!({
        "schema_version": tf_core::schema::SCHEMA_VERSION,
        "record_type": "event",
        "record": value,
    });
    validate_jsonl_envelope(&envelope)?;
    Ok(())
}

/// Event を格納順に読み出す iterator（規範 §10: 決定的 iteration）。
pub struct EventIter {
    reader: BufReader<File>,
    finished: bool,
}

impl EventIter {
    fn open(path: &Path) -> Result<Self, StoreError> {
        let mut reader = BufReader::new(File::open(path)?);
        // header を読み飛ばす。
        let mut header = [0u8; MAGIC.len() + 1];
        reader.read_exact(&mut header)?;
        if &header[..MAGIC.len()] != MAGIC {
            return Err(StoreError::Format("spool file の magic が不正".into()));
        }
        if header[MAGIC.len()] != FORMAT_VERSION {
            return Err(StoreError::Format(format!(
                "spool file の version が不正: {}",
                header[MAGIC.len()]
            )));
        }
        Ok(EventIter {
            reader,
            finished: false,
        })
    }
}

impl Iterator for EventIter {
    type Item = Result<Event, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let kind = match read_u8(&mut self.reader) {
            Ok(k) => k,
            Err(_) => {
                self.finished = true;
                return None;
            }
        };
        let payload_len = match read_u32_be(&mut self.reader) {
            Ok(n) => n as usize,
            Err(e) => {
                self.finished = true;
                return Some(Err(StoreError::Io(e)));
            }
        };
        let mut payload = vec![0u8; payload_len];
        if let Err(e) = self.reader.read_exact(&mut payload) {
            self.finished = true;
            return Some(Err(StoreError::Io(e)));
        }
        match kind {
            RECORD_EVENT => Some(decode_event(&payload)),
            RECORD_COMMIT => {
                // commit marker は読み飛ばして次へ。
                self.next()
            }
            other => {
                self.finished = true;
                Some(Err(StoreError::Format(format!(
                    "未知の record kind です: {other:#x}"
                ))))
            }
        }
    }
}

/// Timeline 順で Event を読み出す iterator（規範 §6.3、§10）。
///
/// [`EventStore::iter_sorted`] から返る。memory budget 内なら in-memory sort、
/// 超過時は external merge sort へ切り替える（規範 §10）。
pub struct SortedEventIter {
    inner: SortedEventIterInner,
}

impl SortedEventIter {
    /// in-memory sort 版（小規模・予算内）。
    pub(crate) fn from_memory(sorted: std::vec::IntoIter<Event>) -> Self {
        SortedEventIter {
            inner: SortedEventIterInner::Memory(sorted),
        }
    }

    /// external merge sort 版（大規模・予算超過）。
    pub(crate) fn from_external(run_files: Vec<PathBuf>) -> Result<Self, StoreError> {
        let merger = crate::external_sort::KWayMerger::new(run_files)?;
        Ok(SortedEventIter {
            inner: SortedEventIterInner::External(merger),
        })
    }
}

enum SortedEventIterInner {
    Memory(std::vec::IntoIter<Event>),
    External(crate::external_sort::KWayMerger),
}

impl Iterator for SortedEventIter {
    type Item = Result<Event, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            SortedEventIterInner::Memory(it) => it.next().map(Ok),
            SortedEventIterInner::External(merger) => merger.next_event(),
        }
    }
}

/// 1 byte を読む。EOF は error。
fn read_u8(reader: &mut impl Read) -> Result<u8, std::io::Error> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// 4 byte big-endian u32 を読む。
fn read_u32_be(reader: &mut impl Read) -> Result<u32, std::io::Error> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// 所有者限定 permission を適用する（規範 §10）。
///
/// - Unix: file は `0o600`。親 directory は呼出側が private（`tempfile::TempDir` 等）へ配置する。
/// - Windows: std では ACL を操作できないため、親 directory が user private
///   （`tempfile::TempDir` 等）であることを前提とする。best-effort で現状維持する。
#[cfg(unix)]
fn apply_owner_only_permissions(file: &File, _path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(StoreError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_owner_only_permissions(_file: &File, _path: &Path) -> Result<(), StoreError> {
    // Windows: std では ACL 制御ができない。tempfile 等の user private directory
    // へ配置されることを前提とする。Phase 8 で ACL 強化を検討する。
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use tf_core::WindowsPathValue;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

    fn sample_event(id: &str, time_value: DateTime<Utc>) -> Event {
        let time = EventTime::utc_instant(
            time_value,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        );
        Event {
            id: id.to_string(),
            time,
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some("host01".to_string()),
            user: None,
            path: Some(WindowsPathValue::new("C:\\Windows\\System32\\cmd.exe")),
            program: None,
            process: None,
            message: "test event".to_string(),
            attributes: BTreeMap::new(),
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:test".to_string(),
                artifact_id: "tf-artifact-v1:test".to_string(),
                source_locator: "Security.evtx".to_string(),
                source_sha256: "ab".repeat(32),
                parser_id: "traceforge-test".to_string(),
                parser_version: "1.0.0".to_string(),
                record_locator: RecordLocator::RecordId("1".to_string()),
                source_ordinal: 0,
            },
        }
    }

    #[test]
    fn create_and_store_event() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        assert!(store.is_empty());
        assert!(!store.is_committed());

        let event = sample_event("tf-event-v1:a", "2026-08-10T01:00:00Z".parse().unwrap());
        store.store_event(&event).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.contains("tf-event-v1:a"));
    }

    #[test]
    fn create_rejects_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let _ = EventStore::create(&path).unwrap();
        let second = EventStore::create(&path);
        assert!(second.is_err());
    }

    #[test]
    fn duplicate_event_id_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        let event = sample_event("tf-event-v1:same", "2026-08-10T01:00:00Z".parse().unwrap());
        store.store_event(&event).unwrap();
        let err = store
            .store_event(&event)
            .expect_err("重複 Event ID は拒否されるべき");
        assert!(matches!(err, StoreError::DuplicateEventId(_)));
    }

    #[test]
    fn commit_writes_marker() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        store.commit().unwrap();
        assert!(store.is_committed());

        // commit 後の追記は不可。
        let event = sample_event("tf-event-v1:a", "2026-08-10T01:00:00Z".parse().unwrap());
        let err = store.store_event(&event).unwrap_err();
        assert!(matches!(err, StoreError::AlreadyCommitted(_)));
    }

    #[test]
    fn open_restores_committed_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        {
            let mut store = EventStore::create(&path).unwrap();
            store
                .store_event(&sample_event(
                    "tf-event-v1:a",
                    "2026-08-10T01:00:00Z".parse().unwrap(),
                ))
                .unwrap();
            store.commit().unwrap();
        }
        let reopened = EventStore::open(&path).unwrap();
        assert!(reopened.is_committed());
        assert_eq!(reopened.len(), 1);
        assert!(reopened.contains("tf-event-v1:a"));
    }

    #[test]
    fn open_uncommitted_preserves_events() {
        // 規範 §10: commit marker が無ければ未完了 Case として扱う。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        {
            let mut store = EventStore::create(&path).unwrap();
            store
                .store_event(&sample_event(
                    "tf-event-v1:a",
                    "2026-08-10T01:00:00Z".parse().unwrap(),
                ))
                .unwrap();
            // commit せずに閉じる。
        }
        let reopened = EventStore::open(&path).unwrap();
        assert!(!reopened.is_committed(), "commit marker が無ければ未完了");
        // Event 自体は durable（規範 §10: 個々の Event は durable）。
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn iter_reads_events_in_storage_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        for i in 0..5 {
            let id = format!("tf-event-v1:{i}");
            let dt: DateTime<Utc> = "2026-08-10T01:00:00Z".parse().unwrap();
            let mut event = sample_event(&id, dt);
            event.provenance.source_ordinal = i;
            event.id = format!("tf-event-v1:{i:032x}");
            store.store_event(&event).unwrap();
        }
        let ids: Vec<String> = store.iter().unwrap().map(|r| r.unwrap().id).collect();
        assert_eq!(ids.len(), 5);
        // 格納順と同じ。
        assert_eq!(ids[0], "tf-event-v1:00000000000000000000000000000000");
        assert_eq!(ids[4], "tf-event-v1:00000000000000000000000000000004");
    }

    #[test]
    fn spool_file_remains_after_drop() {
        // 規範 §10: 最終出力完了まで自動削除しない。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        {
            let mut store = EventStore::create(&path).unwrap();
            store
                .store_event(&sample_event(
                    "tf-event-v1:a",
                    "2026-08-10T01:00:00Z".parse().unwrap(),
                ))
                .unwrap();
            // drop する。
        }
        assert!(path.exists(), "drop 後も spool file は残るべき");
    }

    #[test]
    fn invalid_magic_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.spool");
        // magic(4) + version(1) の長さを用意し、magic を不正にする。
        std::fs::write(&path, b"XXXX\x01").unwrap();
        let result = EventStore::open(&path);
        assert!(matches!(result, Err(StoreError::Format(_))));
    }

    #[test]
    fn encode_decode_roundtrip_preserves_event() {
        let event = sample_event(
            "tf-event-v1:roundtrip",
            "2026-08-10T01:00:00Z".parse().unwrap(),
        );
        let bytes = encode_event(&event).unwrap();
        let decoded = decode_event(&bytes).unwrap();
        assert_eq!(decoded.id, event.id);
        assert_eq!(decoded.source, event.source);
        assert_eq!(decoded.event_type.as_str(), event.event_type.as_str());
        assert_eq!(decoded.assertion, event.assertion);
        assert_eq!(decoded.provenance.evidence_id, event.provenance.evidence_id);
        assert_eq!(
            decoded.provenance.source_ordinal,
            event.provenance.source_ordinal
        );
    }

    #[test]
    fn encode_decode_roundtrip_with_process() {
        // process field クラスの復元を検証する。
        use tf_core::event::ProcessRef;
        let mut event = sample_event("tf-event-v1:proc", "2026-08-10T01:00:00Z".parse().unwrap());
        event.process = Some(ProcessRef {
            pid: Some(1234),
            ppid: Some(5678),
            process_guid: Some("{abc-123}".to_string()),
            parent_process_guid: None,
            image_path: Some(WindowsPathValue::new("C:\\Windows\\System32\\cmd.exe")),
            command_line: Some("cmd.exe /c dir".to_string()),
        });
        let bytes = encode_event(&event).unwrap();
        let decoded = decode_event(&bytes).unwrap();
        assert_eq!(decoded.process.as_ref().unwrap().pid, Some(1234));
        assert_eq!(decoded.process.as_ref().unwrap().ppid, Some(5678));
        assert_eq!(
            decoded.process.as_ref().unwrap().process_guid.as_deref(),
            Some("{abc-123}")
        );
        assert_eq!(
            decoded.process.as_ref().unwrap().command_line.as_deref(),
            Some("cmd.exe /c dir")
        );
    }

    #[test]
    #[cfg(unix)]
    fn owner_only_permissions_on_unix() {
        // 規範 §10: permission を所有者だけに制限する。
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let _store = EventStore::create(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "所有者限定（0o600）であるべき: got {:o}",
            mode
        );
    }
}
