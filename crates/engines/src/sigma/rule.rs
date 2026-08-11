//! SigmaRule 構造体と YAML → struct 変換（T5-010・T5-011）。
//!
//! [`crate::yaml`] が parse した [`YamlValue`] tree から Sigma Rule への変換を行う。
//! 変換過程で未対応要素（modifier・condition・correlation・filter）を検出した場合は
//! [`SigmaError::UnsupportedFeature`] を返し、呼出側が Rule を全体 skip する
//! （規範 §15.1: 部分評価禁止）。

use crate::sigma::condition::{Condition, ConditionError, parse_condition};
use crate::sigma::modifier::{Modifier, parse_modifier};
use crate::yaml::YamlValue;

/// Sigma Rule のコンパイル済み表現。
#[derive(Clone, Debug)]
pub struct SigmaRule {
    /// Rule のタイトル（必須）。
    pub title: String,
    /// Rule の UUID（Sigma 仕様。オプショナル）。
    pub id: Option<String>,
    /// Rule status（`experimental`・`stable` 等）。
    pub status: Option<String>,
    /// 説明文。
    pub description: Option<String>,
    /// 参照 URL list。
    pub references: Vec<String>,
    /// MITRE ATT&CK 等 の tag list。
    pub tags: Vec<String>,
    /// 重要度（`low`・`medium`・`high`・`critical` 等）。
    pub level: Option<String>,
    /// false positives 説明 list。
    pub falsepositives: Vec<String>,
    /// logsource 定義。
    pub logsource: LogsourceSpec,
    /// 検知 block から抽出した選択肢群（名前 → 選択肢）。
    pub selections: Vec<(String, Selection)>,
    /// condition 式。
    pub condition: Condition,
}

/// Sigma logsource 定義（互換 §6.1）。
#[derive(Clone, Debug, Default)]
pub struct LogsourceSpec {
    /// `product: windows` 等。
    pub product: Option<String>,
    /// `category: process_creation` 等。
    pub category: Option<String>,
    /// `service: security` 等。
    pub service: Option<String>,
    /// logsource の定義文（ Sigma 仕様上はメモ書き）。
    pub definition: Option<String>,
}

/// 1つの選択肢（名前付き detection block）。
///
/// Sigma では選択肢は field→value の mapping または mapping list であり、
/// list の場合は各要素が OR で結合される。
#[derive(Clone, Debug)]
pub struct Selection {
    /// OR group の list。各 group は AND で結合された field 制約の list。
    /// 単一 mapping なら1要素の list。
    pub groups: Vec<Vec<FieldConstraint>>,
}

/// 1つの field 制約（field 名 + modifier 群 + 値群）。
#[derive(Clone, Debug)]
pub struct FieldConstraint {
    /// Sigma field 名（例: `EventID`・`CommandLine`）。
    pub sigma_field: String,
    /// 適用する modifier 群（順序保持）。
    pub modifiers: Vec<Modifier>,
    /// match 対象値の list。OR（既定）または AND（`all` modifier 時）で評価。
    pub values: Vec<ScalarValue>,
}

/// Sigma 値の scalar 表現。
#[derive(Clone, Debug, PartialEq)]
pub enum ScalarValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
}

impl ScalarValue {
    /// 文字列表現へ（case-insensitive 比較用）。
    pub fn as_string(&self) -> String {
        match self {
            ScalarValue::Str(s) => s.clone(),
            ScalarValue::Int(n) => n.to_string(),
            ScalarValue::Bool(b) => b.to_string(),
            ScalarValue::Null => String::new(),
        }
    }
}

/// Sigma Rule のコンパイル error。
#[derive(Debug, Clone, thiserror::Error)]
pub enum SigmaError {
    /// YAML parse error。
    #[error("Sigma YAML parse error: {0}")]
    Yaml(#[from] crate::yaml::YamlError),

    /// 必須 field 欠落。
    #[error("Sigma rule missing required field: {0}")]
    MissingField(String),

    /// 構造が不正（型違い等）。
    #[error("Sigma rule structure error: {0}")]
    InvalidStructure(String),

    /// 未対応要素を含む（規範 §15.1: Rule 全体 skip・部分評価禁止）。
    #[error("Sigma unsupported feature: {feature}: {detail}")]
    UnsupportedFeature { feature: String, detail: String },

    /// condition 式の parse error。
    #[error("Sigma condition error: {0}")]
    Condition(#[from] ConditionError),
}

impl SigmaError {
    /// この error が未対応要素による skip かを判定する。
    ///
    /// `true` の場合、呼出側は Rule を Warning + skip 扱いとし、
    /// Exit Code 5（strict rules）ではなく Exit Code 1（Warning）へ寄与させる。
    pub fn is_unsupported_skip(&self) -> bool {
        matches!(
            self,
            SigmaError::UnsupportedFeature { .. }
                | SigmaError::Condition(ConditionError::Unsupported(_))
        )
    }
}

/// [`YamlValue`] tree から [`SigmaRule`] へ変換する。
///
/// 未対応要素（modifier・condition・correlation・filter）を検出した場合は
/// [`SigmaError::UnsupportedFeature`] を返す（規範 §15.1）。
pub fn parse_sigma_rule(yaml: &YamlValue) -> Result<SigmaRule, SigmaError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| SigmaError::InvalidStructure("Sigma rule root must be a mapping".into()))?;

    // Sigma Correlation Rule・Filter の検出
    check_correlation_or_filter(map)?;

    // title（必須）
    let title = map
        .iter()
        .find(|(k, _)| k == "title")
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| SigmaError::MissingField("title".into()))?
        .to_string();

    // id（オプショナル）
    let id = get_optional_str(map, "id").map(String::from);
    let status = get_optional_str(map, "status").map(String::from);
    let description = get_optional_str(map, "description").map(String::from);
    let level = get_optional_str(map, "level").map(String::from);

    let references = get_string_list(map, "references");
    let tags = get_string_list(map, "tags");
    let falsepositives = get_string_list(map, "falsepositives");

    // logsource（必須）
    let logsource_yaml = map
        .iter()
        .find(|(k, _)| k == "logsource")
        .map(|(_, v)| v)
        .ok_or_else(|| SigmaError::MissingField("logsource".into()))?;
    let logsource = parse_logsource(logsource_yaml)?;

    // detection（必須）
    let detection_yaml = map
        .iter()
        .find(|(k, _)| k == "detection")
        .map(|(_, v)| v)
        .ok_or_else(|| SigmaError::MissingField("detection".into()))?;
    let (selections, condition) = parse_detection(detection_yaml)?;

    Ok(SigmaRule {
        title,
        id,
        status,
        description,
        references,
        tags,
        level,
        falsepositives,
        logsource,
        selections,
        condition,
    })
}

/// Sigma Correlation Rule または Filter specification を検出する（互換 §6.2）。
fn check_correlation_or_filter(map: &[(String, YamlValue)]) -> Result<(), SigmaError> {
    // Sigma Correlation Rule は `correlation:` top-level key を持つ
    if map.iter().any(|(k, _)| k == "correlation") {
        return Err(SigmaError::UnsupportedFeature {
            feature: "correlation".into(),
            detail: "Sigma Correlation Rule is not supported".into(),
        });
    }
    // Sigma Filter は `filter:` top-level key を持つ
    // ※ Sigma 仕様上、filter は `detection` 内ではなく top-level に来る
    //   ただし一部実装では `detection` 内の条件に `filter` を含める。
    //   top-level `filter` のみ検出する。
    //   (detection 内の選択肢名に filter が含まれるのは通常の名前参照)
    // → Sigma post-processing filter は別形式（`category: filter` 等）。
    //   検出基準を明確にするため、top-level `filter` key を検査する。
    if map.iter().any(|(k, _)| k == "filter") {
        return Err(SigmaError::UnsupportedFeature {
            feature: "filter".into(),
            detail: "Sigma Filter specification is not supported".into(),
        });
    }
    Ok(())
}

/// logsource block を parse する。
fn parse_logsource(yaml: &YamlValue) -> Result<LogsourceSpec, SigmaError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| SigmaError::InvalidStructure("logsource must be a mapping".into()))?;

    Ok(LogsourceSpec {
        product: get_optional_str(map, "product").map(String::from),
        category: get_optional_str(map, "category").map(String::from),
        service: get_optional_str(map, "service").map(String::from),
        definition: get_optional_str(map, "definition").map(String::from),
    })
}

/// detection block を parse し、(selections, condition) を返す。
fn parse_detection(yaml: &YamlValue) -> Result<(Vec<(String, Selection)>, Condition), SigmaError> {
    let map = yaml
        .as_map()
        .ok_or_else(|| SigmaError::InvalidStructure("detection must be a mapping".into()))?;

    // timeframe の検出（未対応・Rule 全体 skip）
    if map.iter().any(|(k, _)| k == "timeframe") {
        return Err(SigmaError::UnsupportedFeature {
            feature: "timeframe".into(),
            detail: "timeframe in detection is not supported".into(),
        });
    }

    // `fields` は無視可能（出力用 field list・評価に影響しない）
    // `condition` を抽出
    let condition_str = map
        .iter()
        .find(|(k, _)| k == "condition")
        .and_then(|(_, v)| v.as_str())
        .ok_or_else(|| SigmaError::MissingField("detection.condition".into()))?;
    let condition = parse_condition(condition_str)?;

    // 選択肢群を抽出（condition 以外の key）
    let mut selections = Vec::new();
    for (key, value) in map {
        if key == "condition" || key == "timeframe" || key == "fields" {
            continue;
        }
        let selection = parse_selection(value)?;
        selections.push((key.clone(), selection));
    }

    if selections.is_empty() {
        return Err(SigmaError::InvalidStructure(
            "detection must contain at least one selection".into(),
        ));
    }

    Ok((selections, condition))
}

/// 1つの選択肢（mapping または mapping list）を parse する。
fn parse_selection(yaml: &YamlValue) -> Result<Selection, SigmaError> {
    match yaml {
        YamlValue::Map(_) => {
            // 単一 mapping: 1 group
            let constraints = parse_constraint_map(yaml)?;
            Ok(Selection {
                groups: vec![constraints],
            })
        }
        YamlValue::Seq(items) => {
            // list of mappings: OR semantics
            let mut groups = Vec::new();
            for item in items {
                match item {
                    YamlValue::Map(_) => {
                        let constraints = parse_constraint_map(item)?;
                        groups.push(constraints);
                    }
                    YamlValue::Null => {
                        // `null` item → empty group (always matches)
                        groups.push(Vec::new());
                    }
                    _ => {
                        return Err(SigmaError::InvalidStructure(format!(
                            "selection list items must be mappings, got {item:?}"
                        )));
                    }
                }
            }
            if groups.is_empty() {
                return Err(SigmaError::InvalidStructure(
                    "selection list is empty".into(),
                ));
            }
            Ok(Selection { groups })
        }
        YamlValue::Null => {
            // null selection → empty group (always matches)
            Ok(Selection {
                groups: vec![Vec::new()],
            })
        }
        _ => Err(SigmaError::InvalidStructure(format!(
            "selection must be a mapping or list, got {yaml:?}"
        ))),
    }
}

/// field→value の mapping から制約 list を抽出する。
fn parse_constraint_map(yaml: &YamlValue) -> Result<Vec<FieldConstraint>, SigmaError> {
    let map = yaml.as_map().unwrap();
    let mut constraints = Vec::new();
    for (raw_key, value) in map {
        let (field, modifiers) = parse_field_key(raw_key)?;
        let values = parse_values(value)?;
        constraints.push(FieldConstraint {
            sigma_field: field,
            modifiers,
            values,
        });
    }
    Ok(constraints)
}

/// `Field|contains|cased` 形式の key を (field_name, modifiers) へ分割する。
fn parse_field_key(raw: &str) -> Result<(String, Vec<Modifier>), SigmaError> {
    let parts: Vec<&str> = raw.split('|').collect();
    let field = parts[0].to_string();
    let mut modifiers = Vec::new();
    for &mod_name in &parts[1..] {
        match parse_modifier(mod_name) {
            Ok(m) => modifiers.push(m),
            Err(name) => {
                return Err(SigmaError::UnsupportedFeature {
                    feature: "modifier".into(),
                    detail: format!("unsupported modifier |{name}| on field {field}"),
                });
            }
        }
    }
    Ok((field, modifiers))
}

/// 値を `Vec<ScalarValue>` へ変換する。
fn parse_values(yaml: &YamlValue) -> Result<Vec<ScalarValue>, SigmaError> {
    match yaml {
        YamlValue::Null => Ok(vec![ScalarValue::Null]),
        YamlValue::Str(s) => Ok(vec![ScalarValue::Str(s.clone())]),
        YamlValue::Int(n) => Ok(vec![ScalarValue::Int(*n)]),
        YamlValue::Bool(b) => Ok(vec![ScalarValue::Bool(*b)]),
        YamlValue::Seq(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                values.push(yaml_to_scalar(item)?);
            }
            Ok(values)
        }
        YamlValue::Map(_) => Err(SigmaError::InvalidStructure(
            "field value cannot be a mapping".into(),
        )),
    }
}

/// 単一 YAML 値を [`ScalarValue`] へ変換する。
fn yaml_to_scalar(yaml: &YamlValue) -> Result<ScalarValue, SigmaError> {
    match yaml {
        YamlValue::Null => Ok(ScalarValue::Null),
        YamlValue::Str(s) => Ok(ScalarValue::Str(s.clone())),
        YamlValue::Int(n) => Ok(ScalarValue::Int(*n)),
        YamlValue::Bool(b) => Ok(ScalarValue::Bool(*b)),
        _ => Err(SigmaError::InvalidStructure(format!(
            "expected scalar value, got {yaml:?}"
        ))),
    }
}

// ============================================================================
// YAML access helpers
// ============================================================================

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

    fn parse_rule(yaml: &str) -> Result<SigmaRule, SigmaError> {
        let v = parse_yaml(yaml).map_err(SigmaError::Yaml)?;
        parse_sigma_rule(&v)
    }

    fn minimal_rule_yaml() -> &'static str {
        r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#
    }

    #[test]
    fn parse_minimal_rule() {
        let rule = parse_rule(minimal_rule_yaml()).unwrap();
        assert_eq!(rule.title, "Test");
        assert_eq!(rule.logsource.product.as_deref(), Some("windows"));
        assert_eq!(rule.logsource.service.as_deref(), Some("security"));
        assert_eq!(rule.selections.len(), 1);
        assert_eq!(rule.selections[0].0, "selection");
    }

    #[test]
    fn missing_title_rejected() {
        let yaml = r#"
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"#;
        assert!(parse_rule(yaml).is_err());
    }

    #[test]
    fn missing_logsource_rejected() {
        let yaml = r#"
title: Test
detection:
    selection:
        EventID: 1
    condition: selection
"#;
        assert!(parse_rule(yaml).is_err());
    }

    #[test]
    fn missing_detection_rejected() {
        let yaml = r#"
title: Test
logsource:
    product: windows
"#;
        assert!(parse_rule(yaml).is_err());
    }

    #[test]
    fn missing_condition_rejected() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        EventID: 1
"#;
        assert!(parse_rule(yaml).is_err());
    }

    #[test]
    fn unsupported_modifier_rejected() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        Field|base64: value
    condition: selection
"#;
        let err = parse_rule(yaml).unwrap_err();
        assert!(
            err.is_unsupported_skip(),
            "should be unsupported skip: {err}"
        );
    }

    #[test]
    fn unsupported_condition_rejected() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: "count() by Field > 5"
"#;
        let err = parse_rule(yaml).unwrap_err();
        assert!(
            err.is_unsupported_skip(),
            "should be unsupported skip: {err}"
        );
    }

    #[test]
    fn correlation_rule_rejected() {
        let yaml = r#"
title: Test
correlation:
    type: event_count
    rules: [rule1]
    group-by: [field]
    timespan: 1m
    condition: gt 10
"#;
        let err = parse_rule(yaml).unwrap_err();
        assert!(
            err.is_unsupported_skip(),
            "should be unsupported skip: {err}"
        );
    }

    #[test]
    fn timeframe_rejected() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    timeframe: 1h
    condition: selection
"#;
        let err = parse_rule(yaml).unwrap_err();
        assert!(
            err.is_unsupported_skip(),
            "should be unsupported skip: {err}"
        );
    }

    #[test]
    fn field_key_with_modifier() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: "-enc"
    condition: selection
"#;
        let rule = parse_rule(yaml).unwrap();
        let sel = &rule.selections[0].1;
        let c = &sel.groups[0][0];
        assert_eq!(c.sigma_field, "CommandLine");
        assert_eq!(c.modifiers, vec![Modifier::Contains]);
        assert_eq!(c.values, vec![ScalarValue::Str("-enc".into())]);
    }

    #[test]
    fn field_key_with_chained_modifiers() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        Image|endswith|cased: ".exe"
    condition: selection
"#;
        let rule = parse_rule(yaml).unwrap();
        let c = &rule.selections[0].1.groups[0][0];
        assert_eq!(c.modifiers, vec![Modifier::EndsWith, Modifier::Cased]);
    }

    #[test]
    fn list_value_in_selection() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        EventID:
            - 4624
            - 4625
    condition: selection
"#;
        let rule = parse_rule(yaml).unwrap();
        let c = &rule.selections[0].1.groups[0][0];
        assert_eq!(c.values.len(), 2);
        assert_eq!(c.values[0], ScalarValue::Int(4624));
        assert_eq!(c.values[1], ScalarValue::Int(4625));
    }

    #[test]
    fn selection_list_of_maps() {
        let yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        - EventID: 1
          Channel: Security
        - EventID: 2
          Channel: System
    condition: selection
"#;
        let rule = parse_rule(yaml).unwrap();
        let sel = &rule.selections[0].1;
        assert_eq!(sel.groups.len(), 2, "list of 2 maps → 2 OR groups");
    }

    #[test]
    fn metadata_fields_parsed() {
        let yaml = r#"
title: Full Rule
id: abc-123
status: experimental
description: Detects something
level: high
references:
    - https://example.com
tags:
    - attack.execution
    - attack.t1059
falsepositives:
    - Admin activity
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.id.as_deref(), Some("abc-123"));
        assert_eq!(rule.status.as_deref(), Some("experimental"));
        assert_eq!(rule.level.as_deref(), Some("high"));
        assert_eq!(rule.references, vec!["https://example.com".to_string()]);
        assert_eq!(rule.tags.len(), 2);
        assert_eq!(rule.falsepositives.len(), 1);
    }
}
