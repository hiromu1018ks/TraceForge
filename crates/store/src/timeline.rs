//! Timeline 順序付けと filter / summary（規範 §6.3、製品 §9、F-009）。
//!
//! Timeline は次の5 group 順へ出力する（規範 §6.3）。
//!
//! 1. `UtcInstant` および UTC へ確定変換された時刻
//! 2. timezone 付きだが UTC へ変換できなかった `LocalTime`
//! 3. timezone 不明の `LocalTime`
//! 4. `Range`
//! 5. `Unknown`
//!
//! Group 1 は UTC timestamp 昇順、同一 timestamp は Event ID 昇順。
//! Group 2・3 は timezone・local value・Event ID の順。
//! Range は start・end・Event ID の順（欠損境界は末尾）。
//! Unknown は Event ID 昇順。
//!
//! Group をまたぐ因果順序を TraceForge が断定してはならない（規範 §6.3）。
//! 本モジュールの [`TimelineKey`] は表示順のための全順序を与えるが、
//! それは因果関係を主張しない。

use std::cmp::Ordering;

use tf_core::event::Event;
use tf_core::time::{
    EventTime, LocalToUtcOutcome, TemporalValue, format_utc_z, local_to_utc_outcome,
    naive_to_string, parse_iana_timezone,
};

/// Timeline の5 group（規範 §6.3）。番号が小さいほど先頭へ出力される。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineGroup {
    /// `UtcInstant` および UTC へ確定変換できた時刻。
    UtcInstant = 1,
    /// timezone 付きだが UTC へ確定変換できなかった `LocalTime`（DST Ambiguous 等）。
    LocalTimeWithTimezone = 2,
    /// timezone 不明の `LocalTime`。
    LocalTimeUnknownTimezone = 3,
    /// `Range`。
    Range = 4,
    /// `Unknown`。
    Unknown = 5,
}

impl TimelineGroup {
    /// group 番号（規範 §6.3）。昇順が Timeline 出力順。
    pub fn rank(self) -> u8 {
        self as u8
    }
}

/// Timeline 出力順のための sort key（規範 §6.3）。
///
/// [`TimelineKey::from_event`] で [`Event`] から計算する。
/// [`Ord`] 実装は group 番号 → 各 group の比較 key → Event ID の順で全順序を与える。
///
/// **group 間の順序は表示順であり、因果関係ではない**（規範 §6.3）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelineKey {
    group: TimelineGroup,
    /// group 内比較 key 1（group 共通で最先頭の比較要素）。
    primary: Option<String>,
    /// group 内比較 key 2。
    secondary: Option<String>,
    /// Event ID（最終 tie-break key）。
    event_id: String,
}

impl TimelineKey {
    /// [`Event`] から sort key を計算する（規範 §6.3）。
    ///
    /// `LocalTime { timezone: Some(tz) }` のうち UTC へ確定変換できるもの
    /// （[`local_to_utc_outcome`] が [`LocalToUtcOutcome::Single`]）は group 1 へ昇格する。
    /// DST により Ambiguous または NonExistent のものは group 2 のまま保持する。
    pub fn from_event(event: &Event) -> Self {
        timeline_key_from_time(&event.time, &event.id)
    }

    /// 属する group（規範 §6.3）。
    pub fn group(&self) -> TimelineGroup {
        self.group
    }

    /// Event ID。
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}

impl PartialOrd for TimelineKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimelineKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.group
            .rank()
            .cmp(&other.group.rank())
            .then_with(|| cmp_opt_last(&self.primary, &other.primary))
            .then_with(|| cmp_opt_last(&self.secondary, &other.secondary))
            .then_with(|| self.event_id.cmp(&other.event_id))
    }
}

/// `Option<String>` を比較する。`None` を「末尾」として扱う（規範 §6.3: 欠損境界は末尾）。
///
/// std の `Option::cmp` は `None < Some` だが、Timeline は欠損を末尾へ置くため逆転させる。
fn cmp_opt_last(a: &Option<String>, b: &Option<String>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    }
}

/// [`EventTime`] と Event ID から [`TimelineKey`] を計算する。
fn timeline_key_from_time(time: &EventTime, event_id: &str) -> TimelineKey {
    match &time.value {
        TemporalValue::UtcInstant { value } => TimelineKey {
            group: TimelineGroup::UtcInstant,
            primary: Some(format_utc_z(value)),
            secondary: None,
            event_id: event_id.to_string(),
        },
        TemporalValue::LocalTime { value, timezone } => match timezone {
            Some(tz) => {
                // UTC へ確定変換を試みる（規範 §6.3 group 1 昇格判定）。
                match parse_iana_timezone(tz) {
                    Ok(tz_parsed) => match local_to_utc_outcome(*value, tz_parsed) {
                        LocalToUtcOutcome::Single(utc) => TimelineKey {
                            group: TimelineGroup::UtcInstant,
                            primary: Some(format_utc_z(&utc)),
                            secondary: None,
                            event_id: event_id.to_string(),
                        },
                        // Ambiguous・NonExistent は UTC へ確定変換不可 → group 2。
                        LocalToUtcOutcome::Ambiguous { .. } | LocalToUtcOutcome::NonExistent => {
                            TimelineKey {
                                group: TimelineGroup::LocalTimeWithTimezone,
                                primary: Some(tz.clone()),
                                secondary: Some(naive_to_string(value)),
                                event_id: event_id.to_string(),
                            }
                        }
                    },
                    // 無効な timezone 文字列は group 2 として保持（Schema 検証で別途警告）。
                    Err(_) => TimelineKey {
                        group: TimelineGroup::LocalTimeWithTimezone,
                        primary: Some(tz.clone()),
                        secondary: Some(naive_to_string(value)),
                        event_id: event_id.to_string(),
                    },
                }
            }
            None => TimelineKey {
                group: TimelineGroup::LocalTimeUnknownTimezone,
                primary: Some(naive_to_string(value)),
                secondary: None,
                event_id: event_id.to_string(),
            },
        },
        TemporalValue::Range { start, end } => TimelineKey {
            group: TimelineGroup::Range,
            // start が None のものは末尾へ（cmp_opt_last で扱う）。
            primary: start.as_ref().map(format_utc_z),
            secondary: end.as_ref().map(format_utc_z),
            event_id: event_id.to_string(),
        },
        TemporalValue::Unknown => TimelineKey {
            group: TimelineGroup::Unknown,
            primary: None,
            secondary: None,
            event_id: event_id.to_string(),
        },
    }
}

/// Timeline 表示用の filter 条件（F-009、F-030）。
///
/// 指定しなかった条件は絞り込みへ影響しない。Phase 3 では最小実装として
/// 時刻範囲（UTC instant group のみ対象）・Event type・hostname を提供する。
/// Phase 7 の `timeline` command で本格的に利用する。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimelineFilter {
    /// UTC instant の下限（含む）。group 1 の Event のみ適用する。
    pub utc_from: Option<String>,
    /// UTC instant の上限（含む）。group 1 の Event のみ適用する。
    pub utc_to: Option<String>,
    /// Event type の完全一致。複数指定時はいずれかへ一致すれば保持。
    pub event_types: Vec<String>,
    /// hostname の完全一致。複数指定時はいずれかへ一致すれば保持。
    pub hostnames: Vec<String>,
}

impl TimelineFilter {
    /// 全て通す filter（条件未指定）。
    pub fn pass_all() -> Self {
        TimelineFilter::default()
    }

    /// [`TimelineKey`] と [`Event`] から filter を通るか判定する。
    ///
    /// 時刻範囲は UTC instant へ確定変換できる group 1 のみへ適用し、
    /// それ以外の group は時刻範囲では絞り込まない（規範 §6.3: 比較可能な時刻だけを順序付け）。
    pub fn matches(&self, key: &TimelineKey, event: &Event) -> bool {
        // UTC instant group（group 1）以外は時刻範囲 filter を適用しない。
        if self.utc_from.is_some()
            || self.utc_to.is_some() && key.group() == TimelineGroup::UtcInstant
        {
            if let Some(ref from) = self.utc_from
                && let Some(ref primary) = key.primary
                && primary.as_str() < from.as_str()
            {
                return false;
            }
            if let Some(ref to) = self.utc_to
                && let Some(ref primary) = key.primary
                && primary.as_str() > to.as_str()
            {
                return false;
            }
        }
        if !self.event_types.is_empty()
            && !self
                .event_types
                .iter()
                .any(|t| t == event.event_type.as_str())
        {
            return false;
        }
        if !self.hostnames.is_empty()
            && event
                .hostname
                .as_ref()
                .map(|h| !self.hostnames.iter().any(|allowed| allowed == h))
                .unwrap_or(true)
        {
            return false;
        }
        true
    }
}

/// Timeline の集計結果（F-009 summary）。各 group の件数を持つ。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimelineSummary {
    pub utc_instant: u64,
    pub local_time_with_timezone: u64,
    pub local_time_unknown_timezone: u64,
    pub range: u64,
    pub unknown: u64,
}

impl TimelineSummary {
    /// 全 group の合計件数。
    pub fn total(&self) -> u64 {
        self.utc_instant
            + self.local_time_with_timezone
            + self.local_time_unknown_timezone
            + self.range
            + self.unknown
    }

    /// [`TimelineGroup`] の件数を1つ加算する。
    pub fn add_group(&mut self, group: TimelineGroup) {
        match group {
            TimelineGroup::UtcInstant => self.utc_instant += 1,
            TimelineGroup::LocalTimeWithTimezone => self.local_time_with_timezone += 1,
            TimelineGroup::LocalTimeUnknownTimezone => self.local_time_unknown_timezone += 1,
            TimelineGroup::Range => self.range += 1,
            TimelineGroup::Unknown => self.unknown += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use chrono::{DateTime, NaiveDateTime, Utc};
    use tf_core::WindowsPathValue;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::time::{EventTime, TemporalValue, TimePrecision, TimestampKind, TimezoneSource};

    /// test 用 Event を作る。時刻だけ差し替え可能。
    fn make_event(id: &str, time: EventTime) -> Event {
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
            message: String::new(),
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

    fn utc_time(dt: DateTime<Utc>) -> EventTime {
        EventTime::utc_instant(
            dt,
            None,
            TimestampKind::EventLogged,
            TimePrecision::Second,
            TimezoneSource::ArtifactDefined,
        )
    }

    fn local_tz_time(naive: NaiveDateTime, tz: &str) -> EventTime {
        EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: Some(tz.to_string()),
            },
            original: None,
            kind: TimestampKind::EventLogged,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::CaseDefault,
            uncertainty_ms: None,
        }
    }

    fn local_no_tz_time(naive: NaiveDateTime) -> EventTime {
        EventTime {
            value: TemporalValue::LocalTime {
                value: naive,
                timezone: None,
            },
            original: None,
            kind: TimestampKind::EventLogged,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::Unknown,
            uncertainty_ms: None,
        }
    }

    fn range_time(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> EventTime {
        EventTime {
            value: TemporalValue::Range { start, end },
            original: None,
            kind: TimestampKind::Unknown,
            precision: TimePrecision::Second,
            timezone_source: TimezoneSource::Unknown,
            uncertainty_ms: None,
        }
    }

    fn unknown_time() -> EventTime {
        EventTime::unknown(TimestampKind::Unknown)
    }

    #[test]
    fn group_ordering_matches_spec() {
        // 規範 §6.3: UtcInstant < LocalTime(tz) < LocalTime(no tz) < Range < Unknown。
        let utc = TimelineKey::from_event(&make_event("e1", utc_time(Utc::now())));
        let local_tz = TimelineKey::from_event(&make_event(
            "e2",
            // DST Ambiguous で UTC 変換不可 → group 2。
            local_tz_time("2024-11-03T01:30:00".parse().unwrap(), "America/New_York"),
        ));
        let local_no_tz = TimelineKey::from_event(&make_event(
            "e3",
            local_no_tz_time("2024-01-01T00:00:00".parse().unwrap()),
        ));
        let range = TimelineKey::from_event(&make_event(
            "e4",
            range_time(Some(Utc::now()), Some(Utc::now())),
        ));
        let unknown = TimelineKey::from_event(&make_event("e5", unknown_time()));

        assert!(utc < local_tz);
        assert!(local_tz < local_no_tz);
        assert!(local_no_tz < range);
        assert!(range < unknown);
    }

    #[test]
    fn same_utc_timestamp_stable_by_event_id() {
        // 規範 §21-8: 同一 timestamp の Event 順が Event ID で安定する。
        let dt: DateTime<Utc> = "2026-08-10T01:15:20Z".parse().unwrap();
        let time = utc_time(dt);
        let mut keys: Vec<TimelineKey> = ["tf-event-v1:zzz", "tf-event-v1:aaa", "tf-event-v1:mmm"]
            .iter()
            .map(|id| TimelineKey::from_event(&make_event(id, time.clone())))
            .collect();
        keys.sort();
        assert_eq!(keys[0].event_id(), "tf-event-v1:aaa");
        assert_eq!(keys[1].event_id(), "tf-event-v1:mmm");
        assert_eq!(keys[2].event_id(), "tf-event-v1:zzz");
    }

    #[test]
    fn utc_timestamps_sorted_chronologically() {
        // 規範 §6.3 group 1: UTC timestamp 昇順。
        let earlier: DateTime<Utc> = "2020-01-01T00:00:00Z".parse().unwrap();
        let later: DateTime<Utc> = "2026-08-10T01:15:20Z".parse().unwrap();
        let k1 = TimelineKey::from_event(&make_event("a", utc_time(earlier)));
        let k2 = TimelineKey::from_event(&make_event("b", utc_time(later)));
        assert!(k1 < k2);
    }

    #[test]
    fn local_time_with_tz_promoted_to_utc_when_unambiguous() {
        // 規範 §6.3 group 1: UTC へ確定変換できる LocalTime{Some(tz)} は group 1 へ昇格。
        // 2024-01-15T12:00:00 Asia/Tokyo = 2024-01-15T03:00:00Z（standard time、非 DST）。
        let tz_time = local_tz_time("2024-01-15T12:00:00".parse().unwrap(), "Asia/Tokyo");
        let key = TimelineKey::from_event(&make_event("e1", tz_time));
        assert_eq!(key.group(), TimelineGroup::UtcInstant);
        // UTC 変換値が primary へ入る。
        assert_eq!(key.primary.as_deref(), Some("2024-01-15T03:00:00Z"));
    }

    #[test]
    fn local_time_with_tz_stays_group2_when_ambiguous() {
        // 規範 §6.3 group 2: DST Ambiguous は UTC へ確定変換不可。
        let tz_time = local_tz_time("2024-11-03T01:30:00".parse().unwrap(), "America/New_York");
        let key = TimelineKey::from_event(&make_event("e1", tz_time));
        assert_eq!(key.group(), TimelineGroup::LocalTimeWithTimezone);
        assert_eq!(key.primary.as_deref(), Some("America/New_York"));
        assert_eq!(key.secondary.as_deref(), Some("2024-11-03T01:30:00"));
    }

    #[test]
    fn local_time_unknown_tz_is_group3() {
        let t = local_no_tz_time("2024-01-01T00:00:00".parse().unwrap());
        let key = TimelineKey::from_event(&make_event("e1", t));
        assert_eq!(key.group(), TimelineGroup::LocalTimeUnknownTimezone);
        assert_eq!(key.primary.as_deref(), Some("2024-01-01T00:00:00"));
    }

    #[test]
    fn range_missing_start_goes_last() {
        // 規範 §6.3 group 4: 欠損境界は末尾。start=None は start=Some より後。
        let dt: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let with_start = TimelineKey::from_event(&make_event("a", range_time(Some(dt), None)));
        let no_start = TimelineKey::from_event(&make_event("b", range_time(None, Some(dt))));
        assert!(with_start < no_start, "start=Some が start=None より前");
    }

    #[test]
    fn unknown_group_only_event_id_matters() {
        // 規範 §6.3 group 5: Unknown は Event ID 順。
        let k1 = TimelineKey::from_event(&make_event("aaa", unknown_time()));
        let k2 = TimelineKey::from_event(&make_event("zzz", unknown_time()));
        assert!(k1 < k2);
    }

    #[test]
    fn groups_do_not_imply_causality() {
        // 規範 §6.3: Group をまたぐ因果順序を断定してはならない。
        // 設計上の表明として、Unknown Event が UTC Event より「後」に並ぶが、
        // それは「時刻が後」という意味ではない。
        let utc = TimelineKey::from_event(&make_event(
            "a",
            utc_time("2020-01-01T00:00:00Z".parse().unwrap()),
        ));
        let unknown = TimelineKey::from_event(&make_event("b", unknown_time()));
        assert!(utc < unknown);
        // 両者は比較不能な時刻であり、順序は表示のためのみ。
    }

    #[test]
    fn filter_event_type_matches() {
        let time = utc_time("2026-01-01T00:00:00Z".parse().unwrap());
        let mut event = make_event("e1", time);
        event.event_type = EventType::new("file_create");
        let key = TimelineKey::from_event(&event);

        let pass = TimelineFilter {
            event_types: vec!["file_create".to_string()],
            ..Default::default()
        };
        assert!(pass.matches(&key, &event));

        let block = TimelineFilter {
            event_types: vec!["registry_observation".to_string()],
            ..Default::default()
        };
        assert!(!block.matches(&key, &event));
    }

    #[test]
    fn filter_hostname_matches() {
        let time = utc_time("2026-01-01T00:00:00Z".parse().unwrap());
        let event = make_event("e1", time);
        let key = TimelineKey::from_event(&event);

        let pass = TimelineFilter {
            hostnames: vec!["host01".to_string()],
            ..Default::default()
        };
        assert!(pass.matches(&key, &event));

        let block = TimelineFilter {
            hostnames: vec!["other".to_string()],
            ..Default::default()
        };
        assert!(!block.matches(&key, &event));
    }

    #[test]
    fn filter_utc_range_only_applies_to_utc_group() {
        // 時刻範囲 filter は group 1（UTC instant）のみへ適用する。
        let dt: DateTime<Utc> = "2026-06-01T00:00:00Z".parse().unwrap();
        let utc_event = make_event("e1", utc_time(dt));
        let utc_key = TimelineKey::from_event(&utc_event);

        // group 1 は時刻範囲外なら落とす。
        let filter = TimelineFilter {
            utc_to: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&utc_key, &utc_event));

        // Unknown group は時刻範囲 filter を受けない。
        let unknown_event = make_event("e2", unknown_time());
        let unknown_key = TimelineKey::from_event(&unknown_event);
        assert!(filter.matches(&unknown_key, &unknown_event));
    }

    #[test]
    fn summary_counts_per_group() {
        let mut s = TimelineSummary::default();
        s.add_group(TimelineGroup::UtcInstant);
        s.add_group(TimelineGroup::UtcInstant);
        s.add_group(TimelineGroup::Unknown);
        s.add_group(TimelineGroup::Range);
        assert_eq!(s.utc_instant, 2);
        assert_eq!(s.unknown, 1);
        assert_eq!(s.range, 1);
        assert_eq!(s.total(), 4);
    }

    #[test]
    fn timezone_change_does_not_affect_event_id_sort() {
        // 同じ timestamp で timezone だけ違う LocalTime は、変換結果が同じ UTC なら
        // group 1 内で Event ID 順になる（規範 §21-8 関連）。
        let dt_str = "2024-01-15T03:00:00Z";
        let utc_dt: DateTime<Utc> = dt_str.parse().unwrap();
        let utc_time_val = utc_time(utc_dt);
        let mut keys: Vec<TimelineKey> = ["tf-event-v1:m", "tf-event-v1:a"]
            .iter()
            .map(|id| TimelineKey::from_event(&make_event(id, utc_time_val.clone())))
            .collect();
        keys.sort();
        assert_eq!(keys[0].event_id(), "tf-event-v1:a");
        assert_eq!(keys[1].event_id(), "tf-event-v1:m");
    }

    #[test]
    fn tokyo_timezone_dst_free_always_promotes() {
        // Asia/Tokyo は DST が無いため、常に Single へ変換できる → group 1。
        let t = local_tz_time("2024-07-15T09:00:00".parse().unwrap(), "Asia/Tokyo");
        let key = TimelineKey::from_event(&make_event("e", t));
        assert_eq!(key.group(), TimelineGroup::UtcInstant);
        assert_eq!(key.primary.as_deref(), Some("2024-07-15T00:00:00Z"));
    }

    #[test]
    fn invalid_timezone_falls_to_group2() {
        // 無効な timezone 文字列は group 2 として保持（Schema 検査で別途警告される想定）。
        let t = local_tz_time("2024-01-01T00:00:00".parse().unwrap(), "Invalid/Zone");
        let key = TimelineKey::from_event(&make_event("e", t));
        assert_eq!(key.group(), TimelineGroup::LocalTimeWithTimezone);
    }

    #[test]
    fn utc_with_nanoseconds_sorts_correctly() {
        // ナノ秒精度の UTC は文字列の byte 順 = 時系列順になる（RFC 3339 fixed-width）。
        let a: DateTime<Utc> = "2026-08-10T01:15:20.123Z".parse().unwrap();
        let b: DateTime<Utc> = "2026-08-10T01:15:20.456Z".parse().unwrap();
        let ka = TimelineKey::from_event(&make_event("a", utc_time(a)));
        let kb = TimelineKey::from_event(&make_event("b", utc_time(b)));
        assert!(ka < kb);
    }
}
