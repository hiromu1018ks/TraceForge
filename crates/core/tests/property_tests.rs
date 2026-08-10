//! Property-based test（T1-008 / T1-016 / T1-032 等）。
//!
//! 決定的 ID・canonical JSON・Windows path 正規化・時刻変換の性質を `proptest` で検証する。
//! 主な性質:
//! - 決定性: 同一入力から同一結果（規範 §13.1）。
//! - べき等性: 正規化の繰り返しで結果が変わらない。
//! - 安全性: 任意入力で panic しない（規範: 破損入力で panic しない）。

use proptest::prelude::*;
use tf_core::canonical::to_canonical_string;
use tf_core::id;
use tf_core::path::WindowsPathValue;
use tf_core::time;

// T1-008: Evidence ID は同一入力で常に同一（決定性、規範 §13.1）。
#[test]
fn evidence_id_deterministic() {
    proptest!(|(locator in "[a-z]{0,20}", size in 0u64..100_000)| {
        let digest = "a".repeat(64);
        let a = id::evidence_id(&locator, size, &digest);
        let b = id::evidence_id(&locator, size, &digest);
        prop_assert!(id::is_valid_id(&a));
        prop_assert_eq!(a, b);
    });
}

// T1-008: Case ID は evidence_id の渡し順序に依存しない（規範 §4.1）。
#[test]
fn case_id_independent_of_order() {
    proptest!(|(a in "[a-z]{1,10}", b in "[a-z]{1,10}")| {
        let ev_a = id::evidence_id(&a, 1, &"a".repeat(64));
        let ev_b = id::evidence_id(&b, 2, &"b".repeat(64));
        let ab = id::case_id(&[ev_a.as_str(), ev_b.as_str()]);
        let ba = id::case_id(&[ev_b.as_str(), ev_a.as_str()]);
        prop_assert_eq!(ab, ba);
    });
}

// T1-050: canonical JSON はべき等（正規化の繰り返しで変わらない）。
#[test]
fn canonical_json_idempotent() {
    proptest!(|(keys in prop::collection::vec("[a-z]{1,5}", 0..8),
                vals in prop::collection::vec(0u64..1000, 0..8))| {
        let mut map = serde_json::Map::new();
        for (k, v) in keys.iter().zip(vals.iter()) {
            map.insert(k.clone(), serde_json::Value::from(*v));
        }
        let value = serde_json::Value::Object(map);
        let once = to_canonical_string(&value).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&once).unwrap();
        let twice = to_canonical_string(&parsed).unwrap();
        prop_assert_eq!(once, twice);
    });
}

// T1-032: Windows path 正規化はべき等（比較 key の再正規化で変わらない）。
#[test]
fn path_normalization_idempotent() {
    proptest!(|(input in "[A-Za-z0-9_./\\\\]{0,40}")| {
        let p = WindowsPathValue::new(&input);
        let key1 = p.comparison_key.clone().unwrap_or_default();
        let p2 = WindowsPathValue::new(&key1);
        let key2 = p2.comparison_key.clone().unwrap_or_default();
        prop_assert_eq!(key1, key2);
    });
}

// T1-032: 大文字小文字違いの drive letter は同一 comparison_key（規範 §8 規則3/4）。
#[test]
fn drive_letter_case_insensitive() {
    proptest!(|(rest in "[a-z]{1,10}")| {
        let upper = format!("C:\\{rest}");
        let lower = format!("c:\\{rest}");
        let ku = WindowsPathValue::new(&upper).comparison_key;
        let kl = WindowsPathValue::new(&lower).comparison_key;
        prop_assert_eq!(ku, kl);
    });
}

// T1-016: local_to_utc_outcome は任意の有効 NaiveDateTime で panic しない。
#[test]
fn local_to_utc_never_panics() {
    proptest!(|(year in 1970i32..2100,
                month in 1u32..13,
                day in 1u32..29,
                hour in 0u32..24,
                min in 0u32..60)| {
        if let Some(n) = chrono::NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour % 24, min % 60, 0))
            && let Ok(tz) = time::parse_iana_timezone("America/New_York")
        {
            let outcome = time::local_to_utc_outcome(n, tz);
            // panic しないことだけが主眼。3種のいずれかであることを網羅確認。
            match outcome {
                time::LocalToUtcOutcome::Single(_) => {}
                time::LocalToUtcOutcome::Ambiguous { .. } => {}
                time::LocalToUtcOutcome::NonExistent => {}
            }
        }
    });
}

// T1-014: EventTime::unknown は現在時刻を参照しない（規範 §6.2）。
#[test]
fn unknown_time_stable() {
    let a = time::EventTime::unknown(time::TimestampKind::Unknown);
    let b = time::EventTime::unknown(time::TimestampKind::Unknown);
    assert_eq!(a.value, b.value);
    assert_eq!(a.value, time::TemporalValue::Unknown);
}
