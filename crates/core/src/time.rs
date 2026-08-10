//! 時刻モデル（規範 §6、Schema §4）。
//!
//! Event は単一の `DateTime<Utc>` を持たず、[`EventTime`] / [`TemporalValue`] で
//! 「観測された時刻の意味」を保持する（規範 §6.1）。これにより:
//!
//! - timezone 不明の local time を UTC へ勝手に変換しない（規範 §6.2、受け入れ条件 #1）
//! - timestamp 不明の Event を `Unknown` として保持し、Timeline 末尾へ出力する（#2）
//! - DST の不存在時刻・2義的時刻を情報欠損なく扱う（規範 §6.2）
//!
//! 現在時刻や file mtime で「不明時刻」を補完してはならない（規範 §6.2）。本モジュールの
//! どの関数も現在時刻を参照しない。

use chrono::{DateTime, LocalResult, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::{Map, Value};

/// Event 時刻の値の種類（規範 §6.1、Schema §4）。
#[derive(Clone, Debug, PartialEq)]
pub enum TemporalValue {
    /// UTC instant。Artifact が UTC を明示する場合だけ使用する（規範 §6.2）。
    UtcInstant { value: DateTime<Utc> },
    /// Local time と任意の IANA timezone。`timezone` が `None` の場合は timezone 不明。
    LocalTime {
        value: NaiveDateTime,
        timezone: Option<String>,
    },
    /// UTC instant の区間。両端とも `None` は禁止（Schema §4 の `oneOf` 制約）。
    /// 片方だけ `None` の場合は開区間として扱う。
    Range {
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    },
    /// 時刻を取得できなかった（規範 §6.2: 現在時刻・mtime で補完禁止）。
    Unknown,
}

impl TemporalValue {
    /// Schema §4 の `type` 列挙値（lowercase）。
    pub fn type_str(&self) -> &'static str {
        match self {
            TemporalValue::UtcInstant { .. } => "utc_instant",
            TemporalValue::LocalTime { .. } => "local_time",
            TemporalValue::Range { .. } => "range",
            TemporalValue::Unknown => "unknown",
        }
    }
}

/// 時刻の精度（規範 §6.1、Schema §4 の `precision` enum）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimePrecision {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
    Minute,
    Day,
    Unknown,
}

impl TimePrecision {
    /// Schema §4 の `precision` enum 値（lowercase）。
    pub fn as_str(&self) -> &'static str {
        match self {
            TimePrecision::Nanosecond => "nanosecond",
            TimePrecision::Microsecond => "microsecond",
            TimePrecision::Millisecond => "millisecond",
            TimePrecision::Second => "second",
            TimePrecision::Minute => "minute",
            TimePrecision::Day => "day",
            TimePrecision::Unknown => "unknown",
        }
    }
}

/// timezone の根拠（規範 §6.1、Schema §4 の `timezone_source` enum）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimezoneSource {
    /// Artifact 自身が timezone を定義している（例: UTC 明示の EVTX）。
    ArtifactDefined,
    /// 入力が明示的な offset を持っていた。
    ExplicitOffset,
    /// Case 既定 timezone を適用した。
    CaseDefault,
    /// CLI `--timezone` override を適用した。
    CliOverride,
    /// 証拠から推定した timezone。
    Inferred,
    /// timezone 不明（[`TemporalValue::Unknown`] と組み合わせる）。
    Unknown,
}

impl TimezoneSource {
    /// Schema §4 の `timezone_source` enum 値（lowercase）。
    pub fn as_str(&self) -> &'static str {
        match self {
            TimezoneSource::ArtifactDefined => "artifact_defined",
            TimezoneSource::ExplicitOffset => "explicit_offset",
            TimezoneSource::CaseDefault => "case_default",
            TimezoneSource::CliOverride => "cli_override",
            TimezoneSource::Inferred => "inferred",
            TimezoneSource::Unknown => "unknown",
        }
    }
}

/// timestamp の意味（Schema §4 の `kind` enum）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampKind {
    Created,
    Modified,
    Accessed,
    Executed,
    EventLogged,
    RegistryModified,
    Observed,
    Unknown,
}

impl TimestampKind {
    /// Schema §4 の `kind` enum 値（lowercase）。
    pub fn as_str(&self) -> &'static str {
        match self {
            TimestampKind::Created => "created",
            TimestampKind::Modified => "modified",
            TimestampKind::Accessed => "accessed",
            TimestampKind::Executed => "executed",
            TimestampKind::EventLogged => "event_logged",
            TimestampKind::RegistryModified => "registry_modified",
            TimestampKind::Observed => "observed",
            TimestampKind::Unknown => "unknown",
        }
    }
}

/// Event の時刻表現（規範 §6.1、Schema §4）。
#[derive(Clone, Debug, PartialEq)]
pub struct EventTime {
    pub value: TemporalValue,
    pub original: Option<String>,
    pub kind: TimestampKind,
    pub precision: TimePrecision,
    pub timezone_source: TimezoneSource,
    pub uncertainty_ms: Option<u64>,
}

impl EventTime {
    /// 「時刻取得不可」の [`EventTime`] を作る（規範 §6.2: 現在時刻・mtime で補完禁止）。
    ///
    /// Parser が時刻を記録できなかった場合にのみ使用する。本関数は現在時刻を一切参照しない。
    pub fn unknown(kind: TimestampKind) -> Self {
        EventTime {
            value: TemporalValue::Unknown,
            original: None,
            kind,
            precision: TimePrecision::Unknown,
            timezone_source: TimezoneSource::Unknown,
            uncertainty_ms: None,
        }
    }

    /// UTC instant から [`EventTime`] を作る。
    /// `timezone_source` は `ArtifactDefined` または `ExplicitOffset` を想定（規範 §6.2）。
    pub fn utc_instant(
        value: DateTime<Utc>,
        original: Option<String>,
        kind: TimestampKind,
        precision: TimePrecision,
        timezone_source: TimezoneSource,
    ) -> Self {
        EventTime {
            value: TemporalValue::UtcInstant { value },
            original,
            kind,
            precision,
            timezone_source,
            uncertainty_ms: None,
        }
    }

    /// Schema §4 の oneOf 形式へ従う [`serde_json::Value`] を構築する。
    ///
    /// canonical JSON（key の UTF-8 byte 順 sort）は [`Self::to_canonical_json`] で行う。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "type".into(),
            Value::String(self.value.type_str().to_string()),
        );
        match &self.value {
            TemporalValue::UtcInstant { value } => {
                map.insert("value".into(), Value::String(format_utc_z(value)));
            }
            TemporalValue::LocalTime { value, timezone } => {
                map.insert("value".into(), Value::String(naive_to_string(value)));
                map.insert(
                    "timezone".into(),
                    timezone.clone().map(Value::String).unwrap_or(Value::Null),
                );
            }
            TemporalValue::Range { start, end } => {
                map.insert(
                    "start".into(),
                    start
                        .as_ref()
                        .map(format_utc_z)
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                );
                map.insert(
                    "end".into(),
                    end.as_ref()
                        .map(format_utc_z)
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                );
            }
            TemporalValue::Unknown => {}
        }
        map.insert(
            "original".into(),
            self.original
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert("kind".into(), Value::String(self.kind.as_str().into()));
        map.insert(
            "precision".into(),
            Value::String(self.precision.as_str().into()),
        );
        map.insert(
            "timezone_source".into(),
            Value::String(self.timezone_source.as_str().into()),
        );
        map.insert(
            "uncertainty_ms".into(),
            self.uncertainty_ms.map(Value::from).unwrap_or(Value::Null),
        );
        Value::Object(map)
    }

    /// [`to_canonical_value`] の結果を canonical JSON 文字列へ変換する。
    ///
    /// Event ID の hash 入力（規範 §12.3 #11）として使う。float は有限値のみ。
    ///
    /// [`to_canonical_value`]: EventTime::to_canonical_value
    pub fn to_canonical_json(&self) -> String {
        crate::canonical::to_canonical_string_or_panic(&self.to_canonical_value())
    }
}

/// `DateTime<Utc>` を Schema §4 準拠の RFC 3339 UTC 表現（`Z` suffix）へ変換する。
///
/// `to_rfc3339_opts(SecondsFormat::AutoSi, true)` は小数秒を必要最小限で出し、
/// UTC を `Z` で表す。例: `2026-08-10T01:15:20Z`, `2026-08-10T01:15:20.123Z`。
pub fn format_utc_z(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

/// `NaiveDateTime` を Schema §4 の local time `value` 形式へ変換する。
///
/// 形式: `YYYY-MM-DDTHH:MM:SS[.fraction]`（`T` 区切り、timezone なし）。
/// `NaiveDateTime` の `Display` はスペース区切りになるため、`T` 区切りへ明示的に format する。
/// `%.f` は小数秒 0 のとき空文字列、それ以外は `.` + 数字となる。
pub fn naive_to_string(dt: &NaiveDateTime) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.f").to_string()
}

/// local time と IANA timezone から UTC instant への変換結果（規範 §6.2 DST 規則）。
#[derive(Clone, Debug, PartialEq)]
pub enum LocalToUtcOutcome {
    /// 一意に変換できた。
    Single(DateTime<Utc>),
    /// DST により2通りに解釈できる（規範 §6.2: 明示選択がない限り Range/LocalTime のまま保持）。
    Ambiguous {
        first: DateTime<Utc>,
        second: DateTime<Utc>,
    },
    /// DST gap で存在しない local time（規範 §6.2: 変換せず Warning とする）。
    NonExistent,
}

/// local time と IANA timezone を UTC instant へ変換する（規範 §6.2）。
///
/// DST の扱い:
/// - `Single`: 一意に変換可能
/// - `Ambiguous`: 2通りに解釈できる（呼出側は Range または LocalTime のまま保持すること）
/// - `NonExistent`: 存在しない local time（呼出側は Warning を出し、変換しないこと）
///
/// `Tz`（[`chrono_tz::Tz`]）は `Copy` なので値渡しで受け取る。
pub fn local_to_utc_outcome(naive: NaiveDateTime, tz: Tz) -> LocalToUtcOutcome {
    match tz.from_local_datetime(&naive) {
        LocalResult::None => LocalToUtcOutcome::NonExistent,
        LocalResult::Single(dt) => LocalToUtcOutcome::Single(dt.with_timezone(&Utc)),
        LocalResult::Ambiguous(a, b) => LocalToUtcOutcome::Ambiguous {
            first: a.with_timezone(&Utc),
            second: b.with_timezone(&Utc),
        },
    }
}

/// 文字列が IANA timezone 名として有効か検証する（Schema §8.3、T1-015）。
///
/// `chrono_tz::Tz::from_str` で解決できるかを判定する。`""`（timezone 指定なし）は
/// 無効とする（Schema §8.3 で `""` は「指定なし」と別途扱う）。
pub fn is_valid_iana_timezone(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.parse::<Tz>().is_ok()
}

/// IANA timezone 名を [`chrono_tz::Tz`] へ解決する。
pub fn parse_iana_timezone(s: &str) -> Result<Tz, TzParseError> {
    s.parse::<Tz>().map_err(|_| TzParseError {
        input: s.to_string(),
    })
}

/// IANA timezone 名の解決失敗。
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("不正な IANA timezone 名: {input}")]
pub struct TzParseError {
    pub input: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_time_does_not_reference_now() {
        // 規範 §6.2: 不明時刻は Unknown。現在時刻で補完しない。
        let t = EventTime::unknown(TimestampKind::Unknown);
        assert_eq!(t.value, TemporalValue::Unknown);
        assert_eq!(t.timezone_source, TimezoneSource::Unknown);
    }

    #[test]
    fn utc_instant_canonical_json_has_z_suffix() {
        // Schema §4: utc_instant の value は Z suffix。
        let dt = "2026-08-10T01:15:20Z".parse::<DateTime<Utc>>().unwrap();
        let t = EventTime::utc_instant(
            dt,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        );
        let json = t.to_canonical_value();
        assert_eq!(json["type"], "utc_instant");
        assert_eq!(json["value"], "2026-08-10T01:15:20Z");
        assert_eq!(json["timezone_source"], "artifact_defined");
    }

    #[test]
    fn local_time_without_timezone_keeps_null() {
        // 規範 §6.2: timezone 不明の local time は LocalTime{timezone:None}。
        // 受け入れ条件 #1: UTC へ勝手に変換しない。
        let naive = "2026-08-10T01:15:20".parse::<NaiveDateTime>().unwrap();
        let t = EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: None,
            },
            original: None,
            kind: TimestampKind::Observed,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::Unknown,
            uncertainty_ms: None,
        };
        let json = t.to_canonical_value();
        assert_eq!(json["type"], "local_time");
        assert_eq!(json["timezone"], Value::Null);
        assert_eq!(json["value"], "2026-08-10T01:15:20");
    }

    #[test]
    fn range_requires_at_least_one_bound() {
        // Schema §4: Range の start/end 両方 None は禁止。これは型レベルでは保証できないため、
        // canonical JSON 構築時に両方 None でも出力する（検証は Schema validator へ委ねる）。
        let t = EventTime {
            value: TemporalValue::Range {
                start: None,
                end: None,
            },
            original: None,
            kind: TimestampKind::Unknown,
            precision: TimePrecision::Unknown,
            timezone_source: TimezoneSource::Unknown,
            uncertainty_ms: None,
        };
        let json = t.to_canonical_value();
        assert_eq!(json["type"], "range");
        assert_eq!(json["start"], Value::Null);
        assert_eq!(json["end"], Value::Null);
    }

    #[test]
    fn dst_nonexistent_time_detected() {
        // America/New_York は 2024-03-10 02:30 が存在しない（spring forward）。
        let naive = "2024-03-10T02:30:00".parse::<NaiveDateTime>().unwrap();
        let tz = parse_iana_timezone("America/New_York").unwrap();
        assert_eq!(
            local_to_utc_outcome(naive, tz),
            LocalToUtcOutcome::NonExistent
        );
    }

    #[test]
    fn dst_ambiguous_time_detected() {
        // America/New_York は 2024-11-03 01:30 が2通りに解釈される（fall back）。
        let naive = "2024-11-03T01:30:00".parse::<NaiveDateTime>().unwrap();
        let tz = parse_iana_timezone("America/New_York").unwrap();
        match local_to_utc_outcome(naive, tz) {
            LocalToUtcOutcome::Ambiguous { first, second } => {
                assert_ne!(first, second);
            }
            other => panic!("Ambable 期待だが {other:?}"),
        }
    }

    #[test]
    fn dst_single_conversion_correct() {
        // Standard time（冬季）の New York は UTC-5。
        let naive = "2024-01-15T12:00:00".parse::<NaiveDateTime>().unwrap();
        let tz = parse_iana_timezone("America/New_York").unwrap();
        match local_to_utc_outcome(naive, tz) {
            LocalToUtcOutcome::Single(utc) => {
                assert_eq!(format_utc_z(&utc), "2024-01-15T17:00:00Z");
            }
            other => panic!("Single 期待だが {other:?}"),
        }
    }

    #[test]
    fn iana_timezone_validation() {
        // Schema §8.3: timezone 指定時は IANA name のみ。
        assert!(is_valid_iana_timezone("Asia/Tokyo"));
        assert!(is_valid_iana_timezone("America/New_York"));
        assert!(is_valid_iana_timezone("UTC"));
        assert!(!is_valid_iana_timezone(""));
        assert!(!is_valid_iana_timezone("JST"));
        assert!(!is_valid_iana_timezone("Asia/Tokyo/Extra"));
    }

    #[test]
    fn canonical_json_keys_sorted() {
        // canonical JSON は key が byte 順 sort される。
        let dt = "2026-08-10T01:15:20Z".parse::<DateTime<Utc>>().unwrap();
        let t = EventTime::utc_instant(
            dt,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        );
        let json = t.to_canonical_json();
        // "kind" < "original" < "precision" < "timezone_source" < "type" < "uncertainty_ms" < "value"
        let keys_start = json.find('{').unwrap();
        let after = &json[keys_start + 1..];
        let first_key = after.split('"').nth(1).unwrap();
        assert_eq!(first_key, "kind", "最初の key は byte 順最小");
    }
}
