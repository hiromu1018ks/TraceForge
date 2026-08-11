//! Windows FILETIME → `DateTime<Utc>` 変換（[MS-SHLLINK] §2.1.3、[MS-DTYP] §2.3.1）。
//!
//! FILETIME は 1601-01-01 00:00:00 UTC からの 100 ナノ秒間隔を表す 64 bit 符号なし整数。
//! 0 は「時刻未設定」を意味する（LNK header の CreationTime/AccessTime/WriteTime で未設定可）。

use chrono::{DateTime, Utc};

/// Windows epoch（1601-01-01 00:00:00 UTC）と Unix epoch（1970-01-01 00:00:00 UTC）の差（秒）。
const WINDOWS_EPOCH_DIFF: i64 = 11_644_473_600;

/// FILETIME 1 単位あたりのナノ秒（100ns = 100ns）。
const FILETIME_INTERVAL_NANOS: i64 = 100;

/// 1 秒あたりの FILETIME 単位数（10,000,000）。
const FILETIME_INTERVALS_PER_SECOND: i64 = 10_000_000;

/// FILETIME（u64）を `DateTime<Utc>` へ変換する。
///
/// `0` の場合は `None` を返す（[MS-SHLLINK] で「時刻未設定」を意味する）。
/// 値が大きすぎて chrono の表現範囲へ収まらない場合も `None` を返す。
pub fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let intervals = filetime as i64;
    let seconds = intervals.div_euclid(FILETIME_INTERVALS_PER_SECOND);
    let sub_intervals = intervals.rem_euclid(FILETIME_INTERVALS_PER_SECOND);
    let nanos = sub_intervals * FILETIME_INTERVAL_NANOS;

    let unix_seconds = seconds.checked_sub(WINDOWS_EPOCH_DIFF)?;

    // chrono の from_timestamp は負の秒も受け付けるが、表現範囲外なら None。
    DateTime::<Utc>::from_timestamp(unix_seconds, nanos as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_filetime_is_none() {
        // MS-SHLLINK: 0 は「時刻未設定」。
        assert_eq!(filetime_to_datetime(0), None);
    }

    #[test]
    fn unix_epoch_filetime() {
        // 1970-01-01 00:00:00 UTC = 11644473600 秒 * 10^7 = 116444736000000000。
        let ft = 11_644_473_600 * 10_000_000u64;
        let dt = filetime_to_datetime(ft).unwrap();
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn sample_filetime_round_trip() {
        // 2026-08-10T01:15:20Z へ相当する FILETIME。Unix 秒は chrono で確実に算出する。
        let dt: DateTime<Utc> = "2026-08-10T01:15:20Z".parse().unwrap();
        let unix_secs = dt.timestamp();
        let ft = (unix_secs + WINDOWS_EPOCH_DIFF) as u64 * 10_000_000;
        let parsed = filetime_to_datetime(ft).unwrap();
        assert_eq!(parsed, dt);
    }

    #[test]
    fn sub_second_precision_preserved() {
        // 1234 * 100ns の小数部分がナノ秒へ反映される。
        let dt: DateTime<Utc> = "2026-08-10T01:15:20Z".parse().unwrap();
        let unix_secs = dt.timestamp();
        let sub_intervals: i64 = 1234; // 123400 ns = 123.4 us
        let ft = ((unix_secs + WINDOWS_EPOCH_DIFF) as u64 * 10_000_000) + sub_intervals as u64;
        let parsed = filetime_to_datetime(ft).unwrap();
        // 123400 ns = 0.0001234 秒。
        assert_eq!(
            parsed.timestamp_nanos_opt().unwrap() % 1_000_000_000,
            123_400
        );
    }

    #[test]
    fn far_future_filetime_within_range() {
        // chrono の表現範囲内の遠未来（年 9999）。
        // 9999-12-31 23:59:59 UTC ≒ Unix 秒 253402300799。
        let unix_secs: i64 = 253_402_300_799;
        let ft = (unix_secs + WINDOWS_EPOCH_DIFF) as u64 * 10_000_000;
        let dt = filetime_to_datetime(ft).unwrap();
        assert_eq!(dt.format("%Y").to_string(), "9999");
    }
}
