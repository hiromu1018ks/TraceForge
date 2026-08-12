//! Predicate operator と評価（T5-033）。
//!
//! Schema §7 `$defs/predicate` が定義する8種の operator を実装する:
//! `eq` / `neq` / `contains` / `starts_with` / `ends_with` / `regex` / `exists` / `in`。
//!
//! 規範 §14.1:
//! - `null` は空文字列と等しくない。
//! - 型が違う値を暗黙変換しない（例: `5` (number) と `"5"` (string) は等しくない）。
//!
//! 文字列比較の規準:
//! - `case_sensitive=false`（既定）のときは Unicode simple case fold（`to_lowercase`）で比較する。
//! - `case_sensitive=true` のときはそのまま比較する。
//! - integer・boolean の `eq` は型も一致する必要がある（number vs string は `false`）。

use serde_json::Value;

use tf_core::event::Event;

use crate::correlation::fieldresolver::resolve_field_path;

/// Schema §7 の operator 8種。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    Eq,
    Neq,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Exists,
    In,
}

impl Operator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operator::Eq => "eq",
            Operator::Neq => "neq",
            Operator::Contains => "contains",
            Operator::StartsWith => "starts_with",
            Operator::EndsWith => "ends_with",
            Operator::Regex => "regex",
            Operator::Exists => "exists",
            Operator::In => "in",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Operator::Eq,
            "neq" => Operator::Neq,
            "contains" => Operator::Contains,
            "starts_with" => Operator::StartsWith,
            "ends_with" => Operator::EndsWith,
            "regex" => Operator::Regex,
            "exists" => Operator::Exists,
            "in" => Operator::In,
            _ => return None,
        })
    }
}

/// Predicate 値の種別（Schema §7 `value` / `variable` / なし）。
#[derive(Clone, Debug)]
pub enum PredicateValue {
    /// Schema の `value` field。任意の JSON 値（scalar・array 等）。
    Literal(Value),
    /// Schema の `variable` field。bind 済みの変数名を参照する。
    Variable(String),
    /// `operator: exists`。値は持たない。
    Exists,
}

/// 1つの predicate（Schema §7 `$defs/predicate`）。
#[derive(Clone, Debug)]
pub struct Predicate {
    /// `^[a-z][a-z0-9_.]*$`。Event 上の field path。
    pub field: String,
    pub operator: Operator,
    pub value: PredicateValue,
    /// 既定 `false`。`true` のとき文字列比較で大文字小文字を区別する。
    pub case_sensitive: bool,
    /// 例: `windows-path-v1`。現状は将来拡張用として保持し、評価では無視する。
    pub normalization_profile: Option<String>,
}

/// 変数 bindings。変数名 → 値（[`Value`]）。
///
/// bind は step match 時に event の field から値を取り出して変数へ束縛する。
/// 同一変数名の再束縛は許されない（Rule 内で duplicate となるため Schema が拒否する）。
pub type Bindings = Vec<(String, Value)>;

/// bindings から変数値を取り出す。
pub fn lookup_binding<'a>(bindings: &'a Bindings, name: &str) -> Option<&'a Value> {
    bindings.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Event と bindings の下で predicate を評価する。
///
/// 戻り値:
/// - `Ok(true)`: predicate が満たされた。
/// - `Ok(false)`: predicate が満たされなかった（field 不在・比較不一致等）。
/// - `Err(_)`: predicate 評価中に異常が発生した（例: regex compile 失敗）。
pub fn evaluate_predicate(
    predicate: &Predicate,
    event: &Event,
    bindings: &Bindings,
) -> Result<bool, PredicateError> {
    let field_value = resolve_field_path(&predicate.field, event);

    match predicate.operator {
        Operator::Exists => {
            // exists: field が存在する（None でない）かどうか。
            // field が存在しても値が null の場合は「存在する」と扱う（Schema §7: null も値）。
            Ok(field_value.is_some())
        }
        Operator::Eq => {
            let rhs = resolve_rhs(predicate, bindings)?;
            Ok(strict_eq_with_field(
                &field_value,
                &rhs,
                predicate.case_sensitive,
            ))
        }
        Operator::Neq => {
            let rhs = resolve_rhs(predicate, bindings)?;
            Ok(!strict_eq_with_field(
                &field_value,
                &rhs,
                predicate.case_sensitive,
            ))
        }
        Operator::Contains => {
            let lhs = match field_value {
                Some(v) => v,
                None => return Ok(false),
            };
            let rhs = resolve_rhs(predicate, bindings)?;
            Ok(string_contains(&lhs, &rhs, predicate.case_sensitive))
        }
        Operator::StartsWith => {
            let lhs = match field_value {
                Some(v) => v,
                None => return Ok(false),
            };
            let rhs = resolve_rhs(predicate, bindings)?;
            Ok(string_starts_with(&lhs, &rhs, predicate.case_sensitive))
        }
        Operator::EndsWith => {
            let lhs = match field_value {
                Some(v) => v,
                None => return Ok(false),
            };
            let rhs = resolve_rhs(predicate, bindings)?;
            Ok(string_ends_with(&lhs, &rhs, predicate.case_sensitive))
        }
        Operator::Regex => {
            let lhs = match field_value {
                Some(v) => v,
                None => return Ok(false),
            };
            let rhs = resolve_rhs(predicate, bindings)?;
            let pattern = match rhs_as_string(&rhs) {
                Some(s) => s,
                None => return Ok(false),
            };
            let text = match rhs_as_string(&lhs) {
                Some(s) => s,
                None => return Ok(false),
            };
            match regex::Regex::new(&pattern) {
                Ok(re) => Ok(re.is_match(&text)),
                Err(e) => Err(PredicateError::RegexCompile(format!(
                    "invalid regex '{pattern}': {e}"
                ))),
            }
        }
        Operator::In => {
            let lhs = match field_value {
                Some(v) => v,
                None => return Ok(false),
            };
            let rhs = resolve_rhs(predicate, bindings)?;
            let candidates = match &rhs {
                Value::Array(items) => items,
                _ => return Ok(false),
            };
            // 厳密比較（規範 §14.1: null・型の暗黙変換禁止）。
            Ok(candidates
                .iter()
                .any(|c| strict_eq_value(&lhs, c, predicate.case_sensitive)))
        }
    }
}

/// predicate の右辺（value / variable）を取り出す。
fn resolve_rhs(predicate: &Predicate, bindings: &Bindings) -> Result<Value, PredicateError> {
    match &predicate.value {
        PredicateValue::Literal(v) => Ok(v.clone()),
        PredicateValue::Variable(name) => Ok(lookup_binding(bindings, name)
            .cloned()
            .ok_or_else(|| PredicateError::UnboundVariable(name.clone()))?),
        PredicateValue::Exists => Err(PredicateError::InvalidRhs(
            "operator `exists` should not have a right-hand side".into(),
        )),
    }
}

/// field 値（`Option<Value>`）と右辺値の厳密等価（規範 §14.1）。
///
/// - field 不在（None）は全ての値と等しくない（null リテラルとも等しくない）。
///   ただし右辺が JSON `null` の場合に限り「field が null と等しい」という SEMANTICS は
///   持たせず、単純に「不在 ≠ null」として扱う（規範 §14.1: null は空文字列と等しくない）。
/// - 型が異なる値は等しくない（`5` ≠ `"5"`）。
/// - 文字列の `eq` は `case_sensitive` flag を尊重する（既定は case-insensitive）。
fn strict_eq_with_field(field: &Option<Value>, rhs: &Value, case_sensitive: bool) -> bool {
    match field {
        None => false,
        Some(lhs) => strict_eq_value(lhs, rhs, case_sensitive),
    }
}

/// 2つの JSON 値の厳密等価（型と値が完全に一致）。
///
/// 文字列同士の比較のみ `case_sensitive=false` のとき `to_lowercase` で case fold する。
/// ただし整数と浮動小数は数値として比較しない（型が違えば等しくない）。
/// 異なる JSON 型（`5` vs `"5"`）は常に等しくない。
fn strict_eq_value(lhs: &Value, rhs: &Value, case_sensitive: bool) -> bool {
    match (lhs, rhs) {
        // null 同士は等しい。null と他の型は等しくない。
        (Value::Null, Value::Null) => true,
        (Value::Null, _) | (_, Value::Null) => false,
        // boolean は型が一致し値が同じときのみ等しい。
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Bool(_), _) | (_, Value::Bool(_)) => false,
        // 数値は integer 同士・float 同士で型が一致すれば値比較。integer vs float は暗黙変換しない。
        (Value::Number(a), Value::Number(b)) => {
            // serde_json は i64/u64/f64 を区別する。本 evaluator では「表示形式が異なれば
            // 等しくない」とする（例: `5` と `5.0` は異なる）。
            a == b
        }
        (Value::Number(_), _) | (_, Value::Number(_)) => false,
        // 文字列は case_sensitive flag を尊重。
        (Value::String(a), Value::String(b)) => {
            if case_sensitive {
                a == b
            } else {
                a.to_lowercase() == b.to_lowercase()
            }
        }
        (Value::String(_), _) | (_, Value::String(_)) => false,
        // array・object は要素・key を再帰的に比較。
        // 本 evaluator では array/object の eq は通常使われないが、安全のため深度再帰する。
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| strict_eq_value(x, y, case_sensitive))
        }
        (Value::Array(_), _) | (_, Value::Array(_)) => false,
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter().all(|(k, v)| {
                    b.get(k)
                        .is_some_and(|bv| strict_eq_value(v, bv, case_sensitive))
                })
        }
    }
}

/// `case_sensitive` flag を考慮した文字列 contains。
fn string_contains(lhs: &Value, rhs: &Value, case_sensitive: bool) -> bool {
    let (Some(a), Some(b)) = (rhs_as_string(lhs), rhs_as_string(rhs)) else {
        return false;
    };
    if case_sensitive {
        a.contains(&b)
    } else {
        a.to_lowercase().contains(&b.to_lowercase())
    }
}

fn string_starts_with(lhs: &Value, rhs: &Value, case_sensitive: bool) -> bool {
    let (Some(a), Some(b)) = (rhs_as_string(lhs), rhs_as_string(rhs)) else {
        return false;
    };
    if case_sensitive {
        a.starts_with(&b)
    } else {
        a.to_lowercase().starts_with(&b.to_lowercase())
    }
}

fn string_ends_with(lhs: &Value, rhs: &Value, case_sensitive: bool) -> bool {
    let (Some(a), Some(b)) = (rhs_as_string(lhs), rhs_as_string(rhs)) else {
        return false;
    };
    if case_sensitive {
        a.ends_with(&b)
    } else {
        a.to_lowercase().ends_with(&b.to_lowercase())
    }
}

/// JSON 値を文字列表現へ変換する（string はそのまま・number/bool は `to_string`）。
/// null・array・object は `None`（これらは文字列 operator では match しない）。
fn rhs_as_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Predicate 評価 error。
#[derive(Debug, Clone, thiserror::Error)]
pub enum PredicateError {
    /// `variable` で指定された変数が bind されていない（Schema 検査で16step 間で catch されるが、
    /// 実行時にも safety net として扱う）。
    #[error("unbound variable '{0}' in predicate")]
    UnboundVariable(String),
    /// regex compile 失敗。
    #[error("regex compile error: {0}")]
    RegexCompile(String),
    /// predicate の右辺指定が不正（`exists` に value 等Schema 違反）。
    #[error("invalid predicate rhs: {0}")]
    InvalidRhs(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::path::WindowsPathValue;
    use tf_core::time::{EventTime, TimestampKind};

    fn make_event_with_attrs(attrs: &[(&str, &str)]) -> Event {
        let mut attributes = BTreeMap::new();
        for (k, v) in attrs {
            attributes.insert((*k).to_string(), Value::String((*v).to_string()));
        }
        Event {
            id: "tf-event-v1:test".into(),
            time: EventTime::unknown(TimestampKind::EventLogged),
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: None,
            program: None,
            process: None,
            message: String::new(),
            attributes,
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:test".into(),
                artifact_id: "tf-artifact-v1:test".into(),
                source_locator: "Security.evtx".into(),
                source_sha256: "a".repeat(64),
                parser_id: "traceforge-evtx".into(),
                parser_version: "1.0.0".into(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    /// Event.user を設定した Event を作る（eq/regex 等のテストで使用）。
    fn make_event_with_user(user: &str) -> Event {
        let mut event = make_event_with_attrs(&[]);
        event.user = Some(user.to_string());
        event
    }

    fn make_event_with_path(path: &str) -> Event {
        let mut event = make_event_with_attrs(&[]);
        event.path = Some(WindowsPathValue::new(path));
        event
    }

    fn lit_predicate(field: &str, op: Operator, value: Value) -> Predicate {
        Predicate {
            field: field.to_string(),
            operator: op,
            value: PredicateValue::Literal(value),
            case_sensitive: false,
            normalization_profile: None,
        }
    }

    // ===== eq / neq =====

    #[test]
    fn eq_string_match() {
        let event = make_event_with_user("alice");
        let p = lit_predicate("user", Operator::Eq, Value::String("alice".into()));
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn eq_string_case_insensitive_default() {
        let event = make_event_with_user("Alice");
        let p = lit_predicate("user", Operator::Eq, Value::String("alice".into()));
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn eq_string_case_sensitive() {
        let event = make_event_with_user("Alice");
        let mut p = lit_predicate("user", Operator::Eq, Value::String("alice".into()));
        p.case_sensitive = true;
        assert!(!evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn eq_strict_type_no_implicit_conversion() {
        // 規範 §14.1: 型が違う値を暗黙変換しない。
        // integer 5 と string "5" は等しくない。
        let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
        attrs.insert("evtx.event_id".into(), Value::from(4624i64));
        let mut event = make_event_with_attrs(&[]);
        event.attributes = attrs;

        let p_str = lit_predicate(
            "attributes.evtx.event_id",
            Operator::Eq,
            Value::String("4624".into()),
        );
        assert!(
            !evaluate_predicate(&p_str, &event, &Vec::new()).unwrap(),
            "string '4624' != number 4624"
        );

        let p_num = lit_predicate(
            "attributes.evtx.event_id",
            Operator::Eq,
            Value::from(4624i64),
        );
        assert!(
            evaluate_predicate(&p_num, &event, &Vec::new()).unwrap(),
            "number 4624 == number 4624"
        );
    }

    #[test]
    fn eq_field_missing_returns_false() {
        let event = make_event_with_attrs(&[]);
        let p = lit_predicate(
            "attributes.unknown",
            Operator::Eq,
            Value::String("x".into()),
        );
        assert!(!evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn neq_negates_eq() {
        let event = make_event_with_user("alice");
        let p = lit_predicate("user", Operator::Neq, Value::String("bob".into()));
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
        let p_eq = lit_predicate("user", Operator::Neq, Value::String("alice".into()));
        assert!(!evaluate_predicate(&p_eq, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn eq_null_vs_empty_string_distinct() {
        // 規範 §14.1: null は空文字列と等しくない。
        let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
        attrs.insert("attributes.k".into(), Value::String("".into()));
        let mut event = make_event_with_attrs(&[]);
        event.attributes = attrs;

        let p = lit_predicate("attributes.k", Operator::Eq, Value::Null);
        assert!(
            !evaluate_predicate(&p, &event, &Vec::new()).unwrap(),
            "null != empty string"
        );
    }

    // ===== contains / starts_with / ends_with =====

    #[test]
    fn contains_substring() {
        let event = make_event_with_user("alice");
        let p = lit_predicate("user", Operator::Contains, Value::String("lic".into()));
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn starts_with_prefix() {
        let event = make_event_with_user("alice");
        let p = lit_predicate("user", Operator::StartsWith, Value::String("AL".into()));
        assert!(
            evaluate_predicate(&p, &event, &Vec::new()).unwrap(),
            "case insensitive by default"
        );
    }

    #[test]
    fn ends_with_suffix() {
        let event = make_event_with_user("alice");
        let p = lit_predicate("user", Operator::EndsWith, Value::String("CE".into()));
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    // ===== regex =====

    #[test]
    fn regex_match() {
        let event = make_event_with_user("alice123");
        let p = lit_predicate(
            "user",
            Operator::Regex,
            Value::String("^alice[0-9]+$".into()),
        );
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn regex_no_match() {
        let event = make_event_with_user("bob");
        let p = lit_predicate("user", Operator::Regex, Value::String("^alice".into()));
        assert!(!evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn regex_invalid_pattern_returns_err() {
        let event = make_event_with_user("alice");
        let p = lit_predicate("user", Operator::Regex, Value::String("(".into()));
        assert!(evaluate_predicate(&p, &event, &Vec::new()).is_err());
    }

    // ===== exists =====

    #[test]
    fn exists_field_present() {
        let event = make_event_with_user("alice");
        let p = Predicate {
            field: "user".into(),
            operator: Operator::Exists,
            value: PredicateValue::Exists,
            case_sensitive: false,
            normalization_profile: None,
        };
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn exists_field_missing() {
        let event = make_event_with_attrs(&[]);
        let p = Predicate {
            field: "attributes.nonexistent".into(),
            operator: Operator::Exists,
            value: PredicateValue::Exists,
            case_sensitive: false,
            normalization_profile: None,
        };
        assert!(!evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    // ===== in =====

    #[test]
    fn in_operator_matches_list_member() {
        let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
        attrs.insert("evtx.event_id".into(), Value::from(4624i64));
        let mut event = make_event_with_attrs(&[]);
        event.attributes = attrs;

        let p = lit_predicate(
            "attributes.evtx.event_id",
            Operator::In,
            Value::Array(vec![Value::from(4624i64), Value::from(4625i64)]),
        );
        assert!(evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    #[test]
    fn in_operator_strict_type() {
        // integer field と string list は match しない（規範 §14.1）。
        let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
        attrs.insert("evtx.event_id".into(), Value::from(4624i64));
        let mut event = make_event_with_attrs(&[]);
        event.attributes = attrs;

        let p = lit_predicate(
            "attributes.evtx.event_id",
            Operator::In,
            Value::Array(vec![
                Value::String("4624".into()),
                Value::String("4625".into()),
            ]),
        );
        assert!(!evaluate_predicate(&p, &event, &Vec::new()).unwrap());
    }

    // ===== variable 参照 =====

    #[test]
    fn variable_reference_uses_binding() {
        let event = make_event_with_path("C:\\Users\\alice\\file.exe");
        let bindings: Bindings = vec![(
            "file_path".into(),
            Value::String("c:\\users\\alice\\file.exe".into()),
        )];
        let p = Predicate {
            field: "path.comparison_key".into(),
            operator: Operator::Eq,
            value: PredicateValue::Variable("file_path".into()),
            case_sensitive: false,
            normalization_profile: Some("windows-path-v1".into()),
        };
        assert!(evaluate_predicate(&p, &event, &bindings).unwrap());
    }

    #[test]
    fn variable_unbound_returns_error() {
        let event = make_event_with_path("C:\\file.exe");
        let p = Predicate {
            field: "path.comparison_key".into(),
            operator: Operator::Eq,
            value: PredicateValue::Variable("missing_var".into()),
            case_sensitive: false,
            normalization_profile: None,
        };
        let result = evaluate_predicate(&p, &event, &Vec::new());
        assert!(matches!(result, Err(PredicateError::UnboundVariable(_))));
    }

    // ===== operator from_schema_str =====

    #[test]
    fn operator_roundtrip() {
        for op in [
            Operator::Eq,
            Operator::Neq,
            Operator::Contains,
            Operator::StartsWith,
            Operator::EndsWith,
            Operator::Regex,
            Operator::Exists,
            Operator::In,
        ] {
            assert_eq!(Operator::from_schema_str(op.as_str()), Some(op));
        }
        assert!(Operator::from_schema_str("nonsense").is_none());
    }
}
