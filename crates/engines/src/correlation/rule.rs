//! Correlation Rule の構造体・YAML parser・Schema validation（T5-030・T5-031）。
//!
//! [`crate::yaml`] parser が変換した [`YamlValue`] tree から [`CorrelationRule`] 構造体へ
//! 変換する。YAML の禁止要素（anchor/alias/tag/duplicate key/multi-doc/block scalar/tab）は
//! [`crate::yaml::parse`] の時点で検出され error となる（規範 §14・Schema §7）。
//!
//! T5-031 の Schema validation は [`tf_core::schema::correlation_rule_validator`] が
//! `crates/core/schemas/correlation-rule.schema.json` へ則ることを検証する。

use tf_core::case::Severity;
use tf_core::event::AssertionKind;
use tf_core::finding::{Score, ScoreAdjustment};
use tf_core::schema::correlation_rule_validator;

use crate::correlation::predicate::{Operator, Predicate, PredicateValue};
use crate::yaml::YamlValue;

/// Schema §8.3 の既定値。Config が無い場面での test や default 構築で使用。
///
/// `max_correlation_window_seconds = 86400`（1日）。`within` がこれを超える Rule は
/// validation error となる（Schema §8.3）。
pub const DEFAULT_MAX_CORRELATION_WINDOW_SECONDS: u64 = 86_400;

/// Correlation Rule のコンパイル済み表現（Schema §7）。
#[derive(Clone, Debug)]
pub struct CorrelationRule {
    /// `^TF-CORR-[0-9]{3,}$`。
    pub id: String,
    /// `^[0-9]+\.[0-9]+\.[0-9]+$`。
    pub version: String,
    /// 1〜200 文字。
    pub title: String,
    /// 最大 4000 文字。
    pub description: Option<String>,
    /// 既定 `true`。
    pub enabled: bool,
    pub severity: Severity,
    /// 1〜16 step。
    pub sequence: Vec<Step>,
    /// `^[1-9][0-9]*(ms|s|m|h|d)$` を parse した millisecond 表現。
    pub within_ms: u64,
    /// `within` の元文字列表現（canonical JSON 等でそのまま出力する場合に使用）。
    pub within_str: String,
    /// 既定 `[case_id, hostname]`。
    pub partition_by: Vec<PartitionKey>,
    /// 既定 `false`。`true` のとき不確実時刻の match を許可する（規範 §6.4）。
    pub allow_uncertain_time: bool,
    /// 不確実時刻の最大許容誤差（millisecond）。`null` は上限なしを意味しない点に注意
    /// （`allow_uncertain_time=false` なら不確実時刻は全て拒否される）。
    pub max_uncertainty_ms: Option<u64>,
    /// 1〜1,000,000。既定 100,000。
    pub max_matches: u64,
    pub score: ScoreSpec,
    /// `^T[0-9]{4}(\.[0-9]{3})?$`。
    pub mitre_attack: Vec<String>,
    pub tags: Vec<String>,
    /// URI 文字列。
    pub references: Vec<String>,
}

/// Correlation Rule の1 step（Schema §7 `$defs/step`）。
#[derive(Clone, Debug)]
pub struct Step {
    /// 必須。`minLength: 1`。Event の event_type と一致する必要がある。
    pub event_type: String,
    /// 任意。Event の source（`ArtifactSource` の lowercase 文字列）と一致する場合のみ match。
    pub source: Option<String>,
    /// 任意。Event の assertion（observed / inferred）と一致する場合のみ match。
    pub assertion: Option<AssertionFilter>,
    /// 任意。全て満たす必要がある（AND）。
    pub where_predicates: Vec<Predicate>,
    /// 任意。変数名 → field path。step が match した Event から field 値を取り出し、
    /// 以後の step の `where` で `variable` 参照できる。
    pub bind: Vec<(String, String)>,
}

/// Schema §7 `assertion` enum に対応する filter。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionFilter {
    Observed,
    Inferred,
}

impl AssertionFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssertionFilter::Observed => "observed",
            AssertionFilter::Inferred => "inferred",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        match s {
            "observed" => Some(AssertionFilter::Observed),
            "inferred" => Some(AssertionFilter::Inferred),
            _ => None,
        }
    }

    /// [`AssertionKind`] と一致するか。
    pub fn matches(self, kind: AssertionKind) -> bool {
        match self {
            AssertionFilter::Observed => kind == AssertionKind::Observed,
            AssertionFilter::Inferred => kind == AssertionKind::Inferred,
        }
    }
}

/// Schema §7 `partition_by` の要素 enum。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionKey {
    CaseId,
    Hostname,
    User,
}

impl PartitionKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            PartitionKey::CaseId => "case_id",
            PartitionKey::Hostname => "hostname",
            PartitionKey::User => "user",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        match s {
            "case_id" => Some(PartitionKey::CaseId),
            "hostname" => Some(PartitionKey::Hostname),
            "user" => Some(PartitionKey::User),
            _ => None,
        }
    }
}

/// Schema §7 `$defs/score`（[`Score`] と同じ形だが Rule 上の定義として区別）。
#[derive(Clone, Debug, PartialEq)]
pub struct ScoreSpec {
    pub base: f64,
    pub adjustments: Vec<ScoreAdjustment>,
}

impl ScoreSpec {
    /// [`tf_core::finding::Score`] へ変換する。score 計算は [`Score::total`] へ一任する。
    pub fn to_score(&self) -> Score {
        Score {
            base: self.base,
            adjustments: self.adjustments.to_vec(),
        }
    }
}

/// Correlation Rule の parse・validation error（規範 §17.2: Exit Code 5/1 区分）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum CorrelationError {
    /// YAML parse error（規範 §14・Schema §7 の禁止要素検出を含む）。
    #[error("Correlation YAML parse error: {0}")]
    Yaml(#[from] crate::yaml::YamlError),

    /// Rule file が UTF-8 ではなかった。
    #[error("Correlation rule file is not valid UTF-8: {0}")]
    NotUtf8(String),

    /// JSON Schema 違反（T5-031・Schema §7）。
    #[error("Correlation rule schema validation error: {0}")]
    SchemaValidation(String),

    /// Rule 構造の不正（必須 field 欠落・型違い等）。
    #[error("Correlation rule structure error: {0}")]
    InvalidStructure(String),

    /// `within` が parse 不能、または [`max_correlation_window_seconds`] を超過
    /// （規範 §14.1・Schema §8.3）。
    ///
    /// [`max_correlation_window_seconds`]: super::evaluator::DEFAULT_MAX_CORRELATION_WINDOW_SECONDS
    #[error("Correlation `within` error: {0}")]
    WithinInvalid(String),

    /// 未対応 operator を含む（規範 §14.1: Rule 全体 skip・部分評価禁止）。
    /// Schema validation で既に拒否されるため、通常は [`CorrelationError::SchemaValidation`] に
    /// 帰着する。本 variant は evaluator が将来部分対応する場合の予備である。
    #[error("Correlation unsupported operator: {0}")]
    UnsupportedOperator(String),
}

impl CorrelationError {
    /// この error が未対応要素による skip かを判定する（規範 §14.1）。
    ///
    /// 現状の実装は Schema §7 の operator enum へ厳密に従うため、未対応 operator は
    /// Schema validation で拒否される。本メソッドは呼出側が skip 扱いを判定する便宜を
    /// 持たせるもので、`SchemaValidation` のうち operator 由来のものを広く含める。
    pub fn is_unsupported_skip(&self) -> bool {
        matches!(
            self,
            CorrelationError::UnsupportedOperator(_) | CorrelationError::SchemaValidation(_)
        )
    }
}

/// [`YamlValue`] tree から [`CorrelationRule`] へ変換する（T5-030）。
///
/// 事前に [`crate::yaml::parse`] で YAML を parse 済みの [`YamlValue`] を渡す。
/// 本関数は Schema §7 の必須 field・型・enum を構造的に検証しつつ、強型 struct を構築する。
/// YAML の禁止要素検出は [`crate::yaml::parse`] の責務であり、本関数では再検査しない。
pub fn parse_correlation_rule(yaml: &YamlValue) -> Result<CorrelationRule, CorrelationError> {
    let map = yaml.as_map().ok_or_else(|| {
        CorrelationError::InvalidStructure("Correlation rule root must be a mapping".into())
    })?;

    let id = get_required_str(map, "id")?.to_string();
    let version = get_required_str(map, "version")?.to_string();
    let title = get_required_str(map, "title")?.to_string();
    let description = get_optional_str(map, "description").map(String::from);

    let enabled = match map.iter().find(|(k, _)| k == "enabled") {
        Some((_, v)) => v
            .as_bool()
            .ok_or_else(|| CorrelationError::InvalidStructure("enabled must be boolean".into()))?,
        None => true,
    };

    let severity_str = get_required_str(map, "severity")?;
    let severity = Severity::from_schema_str(severity_str).ok_or_else(|| {
        CorrelationError::InvalidStructure(format!("unknown severity: {severity_str}"))
    })?;

    let within_str = get_required_str(map, "within")?.to_string();
    let within_ms = parse_within_ms(&within_str)?;

    let partition_by = parse_partition_by(map)?;
    let allow_uncertain_time = match map.iter().find(|(k, _)| k == "allow_uncertain_time") {
        Some((_, v)) => v.as_bool().ok_or_else(|| {
            CorrelationError::InvalidStructure("allow_uncertain_time must be boolean".into())
        })?,
        None => false,
    };
    let max_uncertainty_ms = match map.iter().find(|(k, _)| k == "max_uncertainty_ms") {
        Some((_, v)) => match v {
            YamlValue::Null => None,
            YamlValue::Int(n) => {
                if *n < 0 {
                    return Err(CorrelationError::InvalidStructure(
                        "max_uncertainty_ms must be >= 0".into(),
                    ));
                }
                Some(*n as u64)
            }
            _ => {
                return Err(CorrelationError::InvalidStructure(
                    "max_uncertainty_ms must be integer or null".into(),
                ));
            }
        },
        None => None,
    };

    let max_matches = match map.iter().find(|(k, _)| k == "max_matches") {
        Some((_, v)) => {
            let n = v.as_int().ok_or_else(|| {
                CorrelationError::InvalidStructure("max_matches must be integer".into())
            })?;
            if n < 1 {
                return Err(CorrelationError::InvalidStructure(
                    "max_matches must be >= 1".into(),
                ));
            }
            n as u64
        }
        None => 100_000,
    };

    let sequence_yaml = map
        .iter()
        .find(|(k, _)| k == "sequence")
        .map(|(_, v)| v)
        .ok_or_else(|| {
            CorrelationError::InvalidStructure("missing required field: sequence".into())
        })?;
    let sequence = parse_sequence(sequence_yaml)?;

    let score_yaml = map
        .iter()
        .find(|(k, _)| k == "score")
        .map(|(_, v)| v)
        .ok_or_else(|| {
            CorrelationError::InvalidStructure("missing required field: score".into())
        })?;
    let score = parse_score(score_yaml)?;

    let mitre_attack = get_string_list(map, "mitre_attack");
    let tags = get_string_list(map, "tags");
    let references = get_string_list(map, "references");

    Ok(CorrelationRule {
        id,
        version,
        title,
        description,
        enabled,
        severity,
        sequence,
        within_ms,
        within_str,
        partition_by,
        allow_uncertain_time,
        max_uncertainty_ms,
        max_matches,
        score,
        mitre_attack,
        tags,
        references,
    })
}

/// Schema §7 の JSON Schema へ則ることを検証する（T5-031）。
///
/// [`tf_core::schema::correlation_rule_validator`] は `correlation-rule.schema.json` の
/// `$id` を持つ JSON Schema から構築された validator である。YAML 互換 data model へ
/// 変換した [`serde_json::Value`] を渡すことで、Schema 違反（必須 field 欠落・未知 enum・
/// 型違い・未対応 operator 等）を検出する。
pub fn validate_correlation_schema(yaml: &YamlValue) -> Result<(), CorrelationError> {
    let validator = correlation_rule_validator();
    let json_value = yaml.to_json();
    validator.validate(&json_value).map_err(|e| {
        CorrelationError::SchemaValidation(format!(
            "rule {id_hint} violates Schema §7: {msg}",
            id_hint = yaml
                .get("id")
                .and_then(YamlValue::as_str)
                .unwrap_or("(unknown)"),
            msg = e
        ))
    })
}

// ============================================================================
// 内部 helper
// ============================================================================

/// `within` 文字列を millisecond へ変換する（Schema §7: `^[1-9][0-9]*(ms|s|m|h|d)$`）。
fn parse_within_ms(s: &str) -> Result<u64, CorrelationError> {
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400_000)
    } else {
        return Err(CorrelationError::WithinInvalid(format!(
            "within '{s}' must match ^[1-9][0-9]*(ms|s|m|h|d)$"
        )));
    };
    let n: u64 = num_str.parse().map_err(|_| {
        CorrelationError::WithinInvalid(format!("within '{s}' has non-numeric magnitude"))
    })?;
    if n == 0 || num_str.starts_with('0') {
        return Err(CorrelationError::WithinInvalid(format!(
            "within '{s}' must start with [1-9]"
        )));
    }
    multiplier
        .checked_mul(n)
        .ok_or_else(|| CorrelationError::WithinInvalid(format!("within '{s}' overflows u64")))
}

/// `partition_by` を parse する。省略時の既定値は `[case_id, hostname]`。
fn parse_partition_by(map: &[(String, YamlValue)]) -> Result<Vec<PartitionKey>, CorrelationError> {
    match map.iter().find(|(k, _)| k == "partition_by") {
        Some((_, v)) => {
            let seq = v.as_seq().ok_or_else(|| {
                CorrelationError::InvalidStructure("partition_by must be array".into())
            })?;
            let mut result = Vec::with_capacity(seq.len());
            let mut seen: Vec<PartitionKey> = Vec::new();
            for item in seq {
                let s = item.as_str().ok_or_else(|| {
                    CorrelationError::InvalidStructure("partition_by items must be strings".into())
                })?;
                let key = PartitionKey::from_schema_str(s).ok_or_else(|| {
                    CorrelationError::InvalidStructure(format!("unknown partition_by key: {s}"))
                })?;
                if seen.contains(&key) {
                    return Err(CorrelationError::InvalidStructure(format!(
                        "partition_by duplicate key: {s}"
                    )));
                }
                seen.push(key);
                result.push(key);
            }
            Ok(result)
        }
        None => Ok(vec![PartitionKey::CaseId, PartitionKey::Hostname]),
    }
}

/// `sequence` を parse する。
fn parse_sequence(yaml: &YamlValue) -> Result<Vec<Step>, CorrelationError> {
    let seq = yaml
        .as_seq()
        .ok_or_else(|| CorrelationError::InvalidStructure("sequence must be array".into()))?;
    if seq.is_empty() {
        return Err(CorrelationError::InvalidStructure(
            "sequence must have at least 1 step".into(),
        ));
    }
    if seq.len() > 16 {
        return Err(CorrelationError::InvalidStructure(format!(
            "sequence must have at most 16 steps (got {})",
            seq.len()
        )));
    }
    let mut result = Vec::with_capacity(seq.len());
    for item in seq {
        result.push(parse_step(item)?);
    }
    Ok(result)
}

/// 1 step を parse する（Schema §7 `$defs/step`）。
fn parse_step(yaml: &YamlValue) -> Result<Step, CorrelationError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| CorrelationError::InvalidStructure("step must be a mapping".into()))?;

    let event_type = get_required_str(map, "event_type")?.to_string();
    if event_type.is_empty() {
        return Err(CorrelationError::InvalidStructure(
            "step.event_type must not be empty".into(),
        ));
    }
    let source = get_optional_str(map, "source").map(String::from);
    let assertion = match get_optional_str(map, "assertion") {
        Some(s) => Some(AssertionFilter::from_schema_str(s).ok_or_else(|| {
            CorrelationError::InvalidStructure(format!("unknown assertion: {s}"))
        })?),
        None => None,
    };

    let where_predicates = match map.iter().find(|(k, _)| k == "where") {
        Some((_, v)) => parse_where(v)?,
        None => Vec::new(),
    };

    let bind = match map.iter().find(|(k, _)| k == "bind") {
        Some((_, v)) => parse_bind(v)?,
        None => Vec::new(),
    };

    Ok(Step {
        event_type,
        source,
        assertion,
        where_predicates,
        bind,
    })
}

/// `where` block を parse して predicate list を構築する。
fn parse_where(yaml: &YamlValue) -> Result<Vec<Predicate>, CorrelationError> {
    let seq = yaml
        .as_seq()
        .ok_or_else(|| CorrelationError::InvalidStructure("where must be array".into()))?;
    let mut result = Vec::with_capacity(seq.len());
    for item in seq {
        result.push(parse_predicate(item)?);
    }
    Ok(result)
}

/// 1 predicate を parse する（Schema §7 `$defs/predicate`）。
fn parse_predicate(yaml: &YamlValue) -> Result<Predicate, CorrelationError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| CorrelationError::InvalidStructure("predicate must be a mapping".into()))?;

    let field = get_required_str(map, "field")?.to_string();
    let operator_str = get_required_str(map, "operator")?;
    let operator = Operator::from_schema_str(operator_str).ok_or_else(|| {
        CorrelationError::UnsupportedOperator(format!(
            "unsupported operator '{operator_str}' on field {field}"
        ))
    })?;

    let case_sensitive = match map.iter().find(|(k, _)| k == "case_sensitive") {
        Some((_, v)) => v.as_bool().unwrap_or(false),
        None => false,
    };
    let normalization_profile = match map.iter().find(|(k, _)| k == "normalization_profile") {
        Some((_, v)) => match v {
            YamlValue::Null => None,
            YamlValue::Str(s) => Some(s.clone()),
            _ => {
                return Err(CorrelationError::InvalidStructure(
                    "normalization_profile must be string or null".into(),
                ));
            }
        },
        None => None,
    };

    let has_value = map.iter().any(|(k, _)| k == "value");
    let has_variable = map.iter().any(|(k, _)| k == "variable");

    let value = match operator {
        Operator::Exists => {
            if has_value || has_variable {
                return Err(CorrelationError::InvalidStructure(
                    "operator `exists` must not have value or variable".into(),
                ));
            }
            PredicateValue::Exists
        }
        _ => {
            if has_value && has_variable {
                return Err(CorrelationError::InvalidStructure(format!(
                    "predicate on field {field} has both value and variable (Schema §7 oneOf)"
                )));
            }
            if has_variable {
                let var = get_required_str(map, "variable")?.to_string();
                PredicateValue::Variable(var)
            } else if has_value {
                let value_yaml = map
                    .iter()
                    .find(|(k, _)| k == "value")
                    .map(|(_, v)| v)
                    .ok_or_else(|| {
                        CorrelationError::InvalidStructure("missing predicate value".into())
                    })?;
                let json = value_yaml.to_json();
                PredicateValue::Literal(json)
            } else {
                return Err(CorrelationError::InvalidStructure(format!(
                    "predicate on field {field} is missing value/variable (Schema §7)"
                )));
            }
        }
    };

    Ok(Predicate {
        field,
        operator,
        value,
        case_sensitive,
        normalization_profile,
    })
}

/// `bind` block を parse して (variable_name, field_path) list を構築する。
fn parse_bind(yaml: &YamlValue) -> Result<Vec<(String, String)>, CorrelationError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| CorrelationError::InvalidStructure("bind must be a mapping".into()))?;
    let mut result = Vec::with_capacity(map.len());
    let mut seen_keys: Vec<String> = Vec::new();
    for (k, v) in map {
        // 重複変数名は yaml parser で検出済みだが念のため assert。
        if seen_keys.iter().any(|s| s == k) {
            return Err(CorrelationError::InvalidStructure(format!(
                "duplicate bind variable: {k}"
            )));
        }
        seen_keys.push(k.clone());
        let field_path = v.as_str().ok_or_else(|| {
            CorrelationError::InvalidStructure(format!(
                "bind.{k} must be a string field path, got {v:?}"
            ))
        })?;
        result.push((k.clone(), field_path.to_string()));
    }
    // 決定的順序で保持する（map は挿入順だが、評価順序に影響がないよう field path 昇順へ sort）。
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

/// `score` block を parse する。
fn parse_score(yaml: &YamlValue) -> Result<ScoreSpec, CorrelationError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| CorrelationError::InvalidStructure("score must be a mapping".into()))?;
    let base = match map.iter().find(|(k, _)| k == "base") {
        Some((_, v)) => v.as_float().ok_or_else(|| {
            CorrelationError::InvalidStructure(
                "score.base must be a number (integer or float)".into(),
            )
        })?,
        None => {
            return Err(CorrelationError::InvalidStructure(
                "missing required field: score.base".into(),
            ));
        }
    };
    // Schema: 0.0 <= base <= 1.0
    if !(0.0..=1.0).contains(&base) {
        return Err(CorrelationError::InvalidStructure(format!(
            "score.base must be in [0.0, 1.0], got {base}"
        )));
    }

    let adjustments_yaml = map
        .iter()
        .find(|(k, _)| k == "adjustments")
        .map(|(_, v)| v)
        .ok_or_else(|| {
            CorrelationError::InvalidStructure("missing required field: score.adjustments".into())
        })?;
    let adjustments_seq = adjustments_yaml.as_seq().ok_or_else(|| {
        CorrelationError::InvalidStructure("score.adjustments must be array".into())
    })?;
    let mut adjustments = Vec::with_capacity(adjustments_seq.len());
    for item in adjustments_seq {
        let item_map = item.as_map().ok_or_else(|| {
            CorrelationError::InvalidStructure("adjustment must be a mapping".into())
        })?;
        let reason = get_required_str(item_map, "reason")?.to_string();
        let value = match item_map.iter().find(|(k, _)| k == "value") {
            Some((_, v)) => v.as_float().ok_or_else(|| {
                CorrelationError::InvalidStructure("adjustment.value must be a number".into())
            })?,
            None => {
                return Err(CorrelationError::InvalidStructure(
                    "missing required field: adjustment.value".into(),
                ));
            }
        };
        if !(-1.0..=1.0).contains(&value) {
            return Err(CorrelationError::InvalidStructure(format!(
                "adjustment.value must be in [-1.0, 1.0], got {value}"
            )));
        }
        if reason.is_empty() || reason.len() > 200 {
            return Err(CorrelationError::InvalidStructure(
                "adjustment.reason must be 1..200 chars".into(),
            ));
        }
        adjustments.push(ScoreAdjustment { reason, value });
    }

    Ok(ScoreSpec { base, adjustments })
}

// ============================================================================
// YAML access helpers
// ============================================================================

fn get_required_str<'a>(
    map: &'a [(String, YamlValue)],
    key: &str,
) -> Result<&'a str, CorrelationError> {
    map.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| CorrelationError::InvalidStructure(format!("missing required field: {key}")))
}

fn get_optional_str<'a>(map: &'a [(String, YamlValue)], key: &str) -> Option<&'a str> {
    map.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_str())
}

fn get_string_list(map: &[(String, YamlValue)], key: &str) -> Vec<String> {
    map.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.to_string_list())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::parse as parse_yaml;

    fn parse_rule(yaml: &str) -> Result<CorrelationRule, CorrelationError> {
        let v = parse_yaml(yaml).map_err(CorrelationError::Yaml)?;
        let rule = parse_correlation_rule(&v)?;
        validate_correlation_schema(&v)?;
        Ok(rule)
    }

    fn minimal_rule_yaml() -> &'static str {
        r#"
id: TF-CORR-001
version: 1.0.0
title: Execution shortly after file creation
severity: high
sequence:
  - event_type: file_create
    bind:
      file_path: path.comparison_key
  - event_type: program_execution
    where:
      - field: path.comparison_key
        operator: eq
        variable: file_path
within: 5m
partition_by: [case_id, hostname]
score:
  base: 0.75
  adjustments:
    - reason: Exact normalized path match
      value: 0.10
"#
    }

    // ===== T5-030: YAML parser =====

    #[test]
    fn parse_minimal_rule() {
        let rule = parse_rule(minimal_rule_yaml()).expect("parse 成功");
        assert_eq!(rule.id, "TF-CORR-001");
        assert_eq!(rule.version, "1.0.0");
        assert_eq!(rule.title, "Execution shortly after file creation");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.sequence.len(), 2);
        assert_eq!(rule.sequence[0].event_type, "file_create");
        assert_eq!(rule.sequence[1].event_type, "program_execution");
        assert_eq!(rule.within_ms, 300_000);
        assert_eq!(rule.partition_by.len(), 2);
        assert_eq!(rule.partition_by[0], PartitionKey::CaseId);
        assert_eq!(rule.partition_by[1], PartitionKey::Hostname);
        assert_eq!(rule.score.base, 0.75);
        assert_eq!(rule.score.adjustments.len(), 1);
        assert!(rule.enabled, "enabled の既定は true");
    }

    #[test]
    fn within_units_parsed_correctly() {
        let cases = [
            ("1ms", 1u64),
            ("100ms", 100),
            ("30s", 30_000),
            ("5m", 300_000),
            ("1h", 3_600_000),
            ("1d", 86_400_000),
            ("2d", 172_800_000),
        ];
        for (s, expected) in cases {
            assert_eq!(parse_within_ms(s).unwrap(), expected, "within={s}");
        }
    }

    #[test]
    fn within_rejects_invalid() {
        assert!(parse_within_ms("0m").is_err(), "0 magnitude");
        assert!(parse_within_ms("5x").is_err(), "unknown unit");
        assert!(parse_within_ms("5").is_err(), "no unit");
        assert!(parse_within_ms("abc").is_err());
        assert!(parse_within_ms("01s").is_err(), "leading zero");
        assert!(parse_within_ms("-5s").is_err(), "negative");
    }

    #[test]
    fn anchor_rejected_by_yaml_parser() {
        // 規範 §14: anchor/alias は禁止。yaml parser が error を返す。
        let yaml = r#"
id: TF-CORR-002
version: 1.0.0
title: bad
severity: low
sequence:
  - event_type: &a file_create
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(matches!(err, crate::yaml::YamlError::Anchor { .. }));
    }

    #[test]
    fn alias_rejected_by_yaml_parser() {
        let yaml = r#"
id: TF-CORR-003
version: 1.0.0
title: bad
severity: low
sequence:
  - event_type: file_create
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
extra: *anchor
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(matches!(err, crate::yaml::YamlError::Alias { .. }));
    }

    #[test]
    fn tag_rejected_by_yaml_parser() {
        let yaml = r#"
id: TF-CORR-004
version: 1.0.0
title: bad
severity: low
sequence:
  - event_type: file_create
within: 5m
partition_by: [case_id]
score: !str {base: 0.5, adjustments: []}
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(matches!(err, crate::yaml::YamlError::Tag { .. }));
    }

    #[test]
    fn duplicate_key_rejected_by_yaml_parser() {
        let yaml = r#"
id: TF-CORR-005
version: 1.0.0
title: bad
title: duplicate
severity: low
sequence:
  - event_type: file_create
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(matches!(err, crate::yaml::YamlError::DuplicateKey { .. }));
    }

    #[test]
    fn multi_doc_marker_rejected_by_yaml_parser() {
        let yaml = "---\nid: TF-CORR-006\n";
        let err = parse_yaml(yaml).unwrap_err();
        assert!(matches!(err, crate::yaml::YamlError::MultiDocument { .. }));
    }

    // ===== T5-031: Schema validation =====

    #[test]
    fn schema_validates_minimal_rule() {
        let v = parse_yaml(minimal_rule_yaml()).unwrap();
        validate_correlation_schema(&v).expect("valid rule");
    }

    #[test]
    fn schema_rejects_missing_required_field() {
        // partition_by 欠落は不可（Schema では required）。
        let yaml = r#"
id: TF-CORR-007
version: 1.0.0
title: missing partition_by
severity: low
sequence:
  - event_type: file_create
within: 5m
score: {base: 0.5, adjustments: []}
"#;
        let v = parse_yaml(yaml).unwrap();
        assert!(validate_correlation_schema(&v).is_err());
    }

    #[test]
    fn schema_rejects_unknown_operator() {
        let yaml = r#"
id: TF-CORR-008
version: 1.0.0
title: bad operator
severity: low
sequence:
  - event_type: x
    where:
      - field: path
        operator: regex_custom
        value: foo
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
        let v = parse_yaml(yaml).unwrap();
        assert!(validate_correlation_schema(&v).is_err());
    }

    #[test]
    fn schema_rejects_bad_severity() {
        let yaml = r#"
id: TF-CORR-009
version: 1.0.0
title: bad severity
severity: catastrophic
sequence:
  - event_type: x
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
        let v = parse_yaml(yaml).unwrap();
        assert!(validate_correlation_schema(&v).is_err());
    }

    #[test]
    fn schema_rejects_too_many_steps() {
        let mut yaml = String::from(
            r#"
id: TF-CORR-010
version: 1.0.0
title: too many steps
severity: low
sequence:
"#,
        );
        for _ in 0..17 {
            yaml.push_str("  - event_type: x\n");
        }
        yaml.push_str("within: 5m\npartition_by: [case_id]\nscore: {base: 0.5, adjustments: []}\n");
        let v = parse_yaml(&yaml).unwrap();
        assert!(validate_correlation_schema(&v).is_err());
    }

    #[test]
    fn schema_rejects_predicate_with_both_value_and_variable() {
        let yaml = r#"
id: TF-CORR-011
version: 1.0.0
title: both value and variable
severity: low
sequence:
  - event_type: x
    where:
      - field: path
        operator: eq
        value: foo
        variable: bar
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
        let v = parse_yaml(yaml).unwrap();
        assert!(validate_correlation_schema(&v).is_err());
    }

    #[test]
    fn schema_rejects_exists_with_value() {
        let yaml = r#"
id: TF-CORR-012
version: 1.0.0
title: exists with value
severity: low
sequence:
  - event_type: x
    where:
      - field: path
        operator: exists
        value: foo
within: 5m
partition_by: [case_id]
score: {base: 0.5, adjustments: []}
"#;
        let v = parse_yaml(yaml).unwrap();
        assert!(validate_correlation_schema(&v).is_err());
    }

    #[test]
    fn all_field_optional_metadata_parsed() {
        let yaml = r#"
id: TF-CORR-013
version: 1.0.0
title: full rule
description: A correlation rule.
enabled: false
severity: critical
sequence:
  - event_type: x
within: 1h
allow_uncertain_time: true
max_uncertainty_ms: 500
max_matches: 50
partition_by: [user]
mitre_attack: [T1059.001]
tags: [execution, lateral]
references:
  - https://example.com/ref
score:
  base: 0.9
  adjustments:
    - reason: bonus
      value: 0.05
"#;
        let rule = parse_rule(yaml).expect("parse");
        assert_eq!(rule.description.as_deref(), Some("A correlation rule."));
        assert!(!rule.enabled);
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.within_ms, 3_600_000);
        assert!(rule.allow_uncertain_time);
        assert_eq!(rule.max_uncertainty_ms, Some(500));
        assert_eq!(rule.max_matches, 50);
        assert_eq!(rule.partition_by, vec![PartitionKey::User]);
        assert_eq!(rule.mitre_attack, vec!["T1059.001".to_string()]);
        assert_eq!(rule.tags.len(), 2);
        assert_eq!(rule.references[0], "https://example.com/ref");
    }

    #[test]
    fn max_uncertainty_null_parsed() {
        let yaml = r#"
id: TF-CORR-014
version: 1.0.0
title: null max_uncertainty
severity: low
sequence:
  - event_type: x
within: 5m
partition_by: [case_id]
max_uncertainty_ms: null
score: {base: 0.5, adjustments: []}
"#;
        let rule = parse_rule(yaml).expect("parse");
        assert_eq!(rule.max_uncertainty_ms, None);
    }

    #[test]
    fn parse_within_overflow_rejected() {
        // u64 max = ~18.4 * 10^18。days multiplier = 86_400_000。
        // 999_999_999_999_999 days で確実に overflow。
        let s = "999999999999999d";
        assert!(parse_within_ms(s).is_err());
    }

    #[test]
    fn parse_score_base_out_of_range_rejected() {
        let yaml = r#"
id: TF-CORR-015
version: 1.0.0
title: bad base
severity: low
sequence:
  - event_type: x
within: 5m
partition_by: [case_id]
score: {base: 1.5, adjustments: []}
"#;
        let v = parse_yaml(yaml).unwrap();
        // Schema validation も reject するが、parser 単体でも拒否されることを確認。
        assert!(parse_correlation_rule(&v).is_err());
    }
}
