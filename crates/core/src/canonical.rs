//! Canonical JSON serializer（Schema §2.1）。
//!
//! 出力規則（Schema §2.1）:
//! - object の key を UTF-8 byte 順で再帰的に sort する。
//! - number は NaN と Infinity を禁止し、同じ値を常に同じ最短 decimal 表現で出力する。
//! - sequence を表す array は元の順序を保持する。
//!   意味上 set である array は呼出側が各 Schema の sort key で事前に sort しておく。
//!
//! float の最短 decimal 表現は `serde_json`（`ryu`）へ委ねる。`serde_json::Number` は
//! `from_f64` で NaN/Infinity を拒否するため、本 serializer も有限値のみ扱う。

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// canonical JSON 変換時の error。
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    /// NaN または Infinity が含まれていた（Schema §2.1 で禁止）。
    #[error("canonical JSON は NaN/Infinity を許可しない")]
    NonFiniteNumber,
    /// 直列化に失敗した。
    #[error("直列化に失敗した: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// 任意の `Serialize` 値を canonical JSON 文字列へ変換する（Schema §2.1）。
///
/// 一度 `serde_json::Value` へ直列化し、object key を再帰 sort した上で文字列化する。
/// float の最短 decimal 表現は serde_json（ryu）が担うため、同じ値は常に同じ文字列になる。
pub fn to_canonical_string<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let value = serde_json::to_value(value)?;
    let canonical = canonicalize_value(&value)?;
    Ok(serde_json::to_string(&canonical)?)
}

/// 任意の `Serialize` 値を canonical JSON 文字列へ変換する。失敗時は panic する。
///
/// 主に ID 計算など「入力が必ず有限値であることが自明」な場面で使う便利関数。
/// 外部入力を扱う場合は [`to_canonical_string`] を使うこと。
pub fn to_canonical_string_or_panic<T: Serialize>(value: &T) -> String {
    to_canonical_string(value).expect("canonical JSON 変換で有限値・直列化が失敗した")
}

/// `serde_json::Value` を canonical 形式へ正規化する（object key の再帰 sort）。
///
/// array は元順序を保持し、object は key を UTF-8 byte 順で sort する。
/// number が有限でなければ [`CanonicalError::NonFiniteNumber`] を返す。
pub fn canonicalize_value(value: &Value) -> Result<Value, CanonicalError> {
    match value {
        Value::Object(map) => {
            // BTreeMap<String, _> は key を UTF-8 byte 順で保持する（Schema §2.1）。
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let mut result = serde_json::Map::new();
            for (k, v) in sorted {
                result.insert(k.clone(), canonicalize_value(v)?);
            }
            Ok(Value::Object(result))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(canonicalize_value(v)?);
            }
            Ok(Value::Array(out))
        }
        Value::Number(n) => {
            // serde_json::Number は有限値のみ保持するが、念のため検証する。
            if let Some(f) = n.as_f64()
                && !f.is_finite()
            {
                return Err(CanonicalError::NonFiniteNumber);
            }
            Ok(Value::Number(n.clone()))
        }
        _ => Ok(value.clone()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn object_keys_sorted_by_utf8_bytes() {
        // Schema §2.1: object key を UTF-8 byte 順で再帰 sort。
        // 'b' < 'a' は false だが、出力は byte 順なので "a" が先。
        let value = json!({"b": 1, "a": 2, "c": {"z": 1, "y": 2}});
        let s = to_canonical_string(&value).unwrap();
        assert_eq!(s, r#"{"a":2,"b":1,"c":{"y":2,"z":1}}"#);
    }

    #[test]
    fn array_order_preserved() {
        // Schema §2.1: sequence を表す array は元順序を保持。
        let value = json!([3, 1, 2]);
        let s = to_canonical_string(&value).unwrap();
        assert_eq!(s, "[3,1,2]");
    }

    #[test]
    fn same_float_same_string() {
        // Schema §2.1: 同じ値を常に同じ最短 decimal 表現。
        let a = to_canonical_string(&json!(0.1)).unwrap();
        let b = to_canonical_string(&json!(0.1)).unwrap();
        assert_eq!(a, b);
        // 整数値の float は ".0" 付きで出力される（serde_json の既定）。
        assert_eq!(to_canonical_string(&json!(1.0)).unwrap(), "1.0");
    }

    #[test]
    fn deterministic_across_construction_order() {
        // 挿入順が異なっても canonical 出力は同一。
        let a = json!({"z": 1, "a": 2});
        let b = json!({"a": 2, "z": 1});
        assert_eq!(
            to_canonical_string(&a).unwrap(),
            to_canonical_string(&b).unwrap()
        );
    }
}
