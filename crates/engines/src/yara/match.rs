//! YARA-X scan 結果 → Match 型 変換（T5-022）。
//!
//! 互換 §7・Schema §5.7 に従い、YARA-X scan 結果から Match 型（`match_type=yara_x`）
//! を構築する。tags / meta / namespace / matched pattern identifier を保持する。
//!
//! ## 保持する情報（Schema §5.7）
//!
//! 共通 field:
//! - `match_id`（決定的生成・規範 §12.4）
//! - `match_type = "yara_x"`
//! - `rule_id`（YARA Rule 名）
//! - `rule_sha256`（Rule file raw bytes の SHA-256・規範 §14）
//! - `event_ids`（YARA match は event を参照しないため空 list）
//! - `evidence_ids`（scan 対象の Evidence ID 1件）
//! - `reasons`（人間可読の理由文字列）
//!
//! YARA-X 拡張 field（Schema §5.7: `matched_patterns`）:
//! - rule identifier（YARA Rule 名）
//! - namespace
//! - tags（YARA Rule の tags）
//! - meta（YARA Rule の metadata key-value）
//! - matched pattern identifier list（例: `["$a", "$b"]`）

use serde_json::{Map, Value};

use tf_core::id::match_id;
use tf_core::r#match::{Match, MatchType};

use crate::yara::compiler::CompiledYaraFile;

/// YARA-X が scan 中に検出した pattern 毎の match 情報（T5-022）。
///
/// YARA Rule の各 pattern（`$a`, `$b` 等）毎に、scan 対象内で match したかを記録する。
/// `kind` は [`yara_x::PatternKind`] の文字列表現（`text` / `regex` / `hex` 等）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraPatternInfo {
    /// pattern 識別子（例: `$a`, `$b`）。
    pub identifier: String,
    /// pattern 種別の文字列表現（`text` / `regex` / `hex` 等）。
    pub kind: String,
}

/// YARA-X scan 結果の1件分（T5-022）。
///
/// [`crate::yara::scanner::YaraScanner`] が scan した結果、1件以上の YARA Rule が
/// match した場合、各 match 毎に本型を生成する。`match_value` が Schema §5.7 の
/// Match 表現へ変換済みの値を持つ。
#[derive(Clone, Debug)]
pub struct YaraMatchResult {
    /// Schema §5.7 の Match（`match_type=YaraX`）。
    pub match_value: Match,
}

/// YARA-X scan 結果から [`Match`] を構築する（T5-022・規範 §12.4・Schema §5.7）。
///
/// 引数:
/// - `evidence_id`: scan 対象 Evidence の ID。`event_ids` ではなく `evidence_ids` へ入る。
/// - `compiled`: 当該 YARA Rule を含む [`CompiledYaraFile`]。
///   `sha256` を `rule_sha256` と Match ID 計算へ使う（規範 §14）。
/// - `rule_identifier`: YARA Rule 名（例: `traceforge_test_rule`）。
/// - `namespace`: YARA Rule の namespace。YARA-X は default namespace を空文字列とする。
/// - `tags`: YARA Rule の tags。
/// - `metadata`: YARA Rule の metadata key-value list（挿入順保存）。
/// - `matched_patterns`: match した pattern 識別子と種別の list（T5-022）。
///
/// Match ID は `match_id(rule_id, rule_content_sha256, &[])` で決定的生成する
/// （規範 §12.4）。YARA match は特定の Event を参照しないため `ordered_event_ids`
/// は空 list とし、Evidence ID は `evidence_ids` のみへ保持する。
pub fn build_yara_match(
    evidence_id: &str,
    compiled: &CompiledYaraFile,
    rule_identifier: &str,
    namespace: &str,
    tags: &[String],
    metadata: &[(String, MetadataValue)],
    matched_patterns: &[YaraPatternInfo],
) -> Match {
    // 規範 §12.4: 決定的 Match ID 生成。YARA match は event を参照しないため空 list。
    let match_id_str = match_id(rule_identifier, &compiled.sha256, &[]);

    let reasons = build_reasons(rule_identifier, namespace, matched_patterns);

    Match {
        match_id: match_id_str,
        match_type: MatchType::YaraX,
        rule_id: rule_identifier.to_string(),
        rule_sha256: compiled.sha256.clone(),
        event_ids: Vec::new(),
        evidence_ids: vec![evidence_id.to_string()],
        reasons,
        score: None,
        ordered_event_ids: None,
        logsource_mapping: None,
        matched_patterns: Some(build_matched_patterns(
            rule_identifier,
            namespace,
            tags,
            metadata,
            matched_patterns,
        )),
    }
}

/// [`Match::reasons`] の内容を構築する。
///
/// 決定的出力（規範 §13）のため、要素順序を固定する。
fn build_reasons(
    rule_identifier: &str,
    namespace: &str,
    matched_patterns: &[YaraPatternInfo],
) -> Vec<String> {
    let mut reasons = Vec::with_capacity(2);

    if namespace.is_empty() {
        reasons.push(format!(
            "YARA-X rule '{rule_identifier}' matched (patterns: {n})",
            n = matched_patterns.len()
        ));
    } else {
        reasons.push(format!(
            "YARA-X rule '{namespace}::{rule_identifier}' matched (patterns: {n})",
            n = matched_patterns.len()
        ));
    }

    // pattern 識別子を alphabetical 順で列挙（決定性）。
    let mut ids: Vec<&str> = matched_patterns
        .iter()
        .map(|p| p.identifier.as_str())
        .collect();
    ids.sort_unstable();
    reasons.push(format!("matched patterns: {}", ids.join(", ")));

    reasons
}

/// Schema §5.7 の `matched_patterns` JSON を構築する。
///
/// `matched_patterns` は YARA-X 固有の拡張 field であり、YARA Rule の詳細情報を保持する。
/// 出力 key 順は固定し、canonical JSON の決定性を担保する（規範 §13）。
fn build_matched_patterns(
    rule_identifier: &str,
    namespace: &str,
    tags: &[String],
    metadata: &[(String, MetadataValue)],
    matched_patterns: &[YaraPatternInfo],
) -> Value {
    let mut root = Map::new();

    // rule 詳細
    let mut rule_obj = Map::new();
    rule_obj.insert(
        "identifier".into(),
        Value::String(rule_identifier.to_string()),
    );
    rule_obj.insert("namespace".into(), Value::String(namespace.to_string()));
    rule_obj.insert(
        "tags".into(),
        Value::Array(tags.iter().cloned().map(Value::String).collect()),
    );

    // metadata は挿入順保存の Vec<(String, MetadataValue)> を JSON object へ変換。
    // BTreeMap で key sort すると canonical になるが、metadata は YARA Rule 内の
    // 宣言順を保持するため Map::new() + insert の挿入順とする（preserve_order 有効）。
    let mut meta_obj = Map::new();
    for (k, v) in metadata {
        meta_obj.insert(k.clone(), v.to_json_value());
    }
    rule_obj.insert("metadata".into(), Value::Object(meta_obj));

    root.insert("rule".into(), Value::Object(rule_obj));

    // matched pattern identifier list（alphabetical 順・決定性）
    let mut sorted_patterns = matched_patterns.to_vec();
    sorted_patterns.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    let patterns_array: Vec<Value> = sorted_patterns
        .iter()
        .map(|p| {
            let mut m = Map::new();
            m.insert("identifier".into(), Value::String(p.identifier.clone()));
            m.insert("kind".into(), Value::String(p.kind.clone()));
            Value::Object(m)
        })
        .collect();
    root.insert("patterns".into(), Value::Array(patterns_array));

    Value::Object(root)
}

/// YARA Rule の metadata 値（[`yara_x::MetaValue`] に対応）。
///
/// YARA-X が公開する [`yara_x::MetaValue`] から変換する。YARA 仕様上の metadata 値型は
/// 整数・浮動小数点・真偽値・文字列・バイト列の5種類。
#[derive(Clone, Debug, PartialEq)]
pub enum MetadataValue {
    /// YARA の integer metadata。
    Integer(i64),
    /// YARA の float metadata。
    Float(f64),
    /// YARA の boolean metadata。
    Bool(bool),
    /// YARA の string metadata（有効な UTF-8）。
    Str(String),
    /// YARA の bytes metadata（無効な UTF-8 を含む可能性のあるバイト列）。
    /// lower-case hex 文字列へ変換して保持する（canonical 表現・決定性）。
    Bytes(String),
}

impl MetadataValue {
    /// [`serde_json::Value`] へ変換する。
    ///
    /// `Float` は JSON number へ変換する。`NaN` / `Infinity` は YARA 仕様上発生しないが、
    /// 念のため `0.0` へ fallback する（規範 §19.4: JSON へ NaN/Infinity を出力しない）。
    /// `Bytes` は lower-case hex 文字列へ変換済みのため、JSON string として出力する。
    pub fn to_json_value(&self) -> Value {
        match self {
            MetadataValue::Integer(n) => Value::from(*n),
            MetadataValue::Float(f) => {
                if f.is_finite() {
                    serde_json::Number::from_f64(*f)
                        .map(Value::Number)
                        .unwrap_or_else(|| Value::Null)
                } else {
                    // NaN / Infinity は YARA 仕様上発生しないが、発生時は null へ fallback
                    // （規範 §19.4: JSON へ NaN/Infinity を出力しない）。
                    Value::Null
                }
            }
            MetadataValue::Bool(b) => Value::Bool(*b),
            MetadataValue::Str(s) => Value::String(s.clone()),
            MetadataValue::Bytes(hex_str) => Value::String(hex_str.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yara::compiler::{YaraRuleset, YaraRulesetCompileSummary};
    use std::fs;
    use std::io::Write;

    fn compile_simple_rule(rule_source: &str) -> YaraRulesetCompileSummary {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yar");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(rule_source.as_bytes()).unwrap();
        drop(f);

        let mut registry = crate::loader::RuleRegistry::new();
        registry
            .load(
                &path,
                dir.path(),
                &crate::loader::RuleLoadOptions::default(),
            )
            .unwrap();

        YaraRuleset::compile_from_registry(&registry)
    }

    // ===== T5-022: Match 型基本構造 =====

    #[test]
    fn yara_match_has_correct_match_type() {
        let summary = compile_simple_rule(r#"rule t { condition: true }"#);
        assert_eq!(summary.compiled_len(), 1);
        let compiled = &summary.compiled[0];

        let m = build_yara_match("tf-evidence-v1:abc", compiled, "t", "", &[], &[], &[]);

        assert_eq!(m.match_type, MatchType::YaraX);
    }

    #[test]
    fn yara_match_keeps_evidence_id() {
        let summary = compile_simple_rule(r#"rule t { condition: true }"#);
        let compiled = &summary.compiled[0];

        let m = build_yara_match("tf-evidence-v1:abc", compiled, "t", "", &[], &[], &[]);

        // YARA match は event を参照しないため event_ids は空。
        assert!(m.event_ids.is_empty());
        // evidence_ids に対象 Evidence ID 1件。
        assert_eq!(m.evidence_ids, vec!["tf-evidence-v1:abc".to_string()]);
    }

    #[test]
    fn yara_match_rule_id_and_sha256() {
        let summary = compile_simple_rule(r#"rule my_rule { condition: true }"#);
        let compiled = &summary.compiled[0];

        let m = build_yara_match("tf-evidence-v1:x", compiled, "my_rule", "", &[], &[], &[]);

        assert_eq!(m.rule_id, "my_rule");
        assert_eq!(m.rule_sha256, compiled.sha256);
        assert!(tf_core::hash::is_lowercase_sha256_hex(&m.rule_sha256));
    }

    // ===== T5-022: 決定的 Match ID（規範 §12.4）=====

    #[test]
    fn match_id_is_deterministic() {
        let summary_a = compile_simple_rule(r#"rule same { condition: true }"#);
        let compiled_a = &summary_a.compiled[0];

        // 同一 Rule を再度 compile して SHA-256 も同一であることを確認。
        let summary_b = compile_simple_rule(r#"rule same { condition: true }"#);
        let compiled_b = &summary_b.compiled[0];
        assert_eq!(compiled_a.sha256, compiled_b.sha256);

        let m1 = build_yara_match("tf-evidence-v1:ev1", compiled_a, "same", "", &[], &[], &[]);
        let m2 = build_yara_match("tf-evidence-v1:ev1", compiled_b, "same", "", &[], &[], &[]);

        assert_eq!(m1.match_id, m2.match_id, "決定的 Match ID");
        // ID 形式
        assert!(tf_core::id::is_valid_id(&m1.match_id));
    }

    #[test]
    fn match_id_reflects_rule_id_and_sha256() {
        let summary = compile_simple_rule(r#"rule r1 { condition: true }"#);
        let compiled = &summary.compiled[0];

        let m1 = build_yara_match("tf-evidence-v1:e1", compiled, "r1", "", &[], &[], &[]);
        // 異なる rule_id で生成すると異なる ID。
        let m2 = build_yara_match("tf-evidence-v1:e1", compiled, "r2", "", &[], &[], &[]);
        assert_ne!(m1.match_id, m2.match_id);
    }

    // ===== T5-022: matched_patterns JSON 構造 =====

    #[test]
    fn matched_patterns_includes_rule_namespace_tags_meta() {
        let summary = compile_simple_rule(r#"rule r { condition: true }"#);
        let compiled = &summary.compiled[0];

        let tags = vec!["attack.execution".to_string(), "attack.t1059".to_string()];
        let meta = vec![
            (
                "author".to_string(),
                MetadataValue::Str("TraceForge".to_string()),
            ),
            ("severity".to_string(), MetadataValue::Integer(5)),
            ("enabled".to_string(), MetadataValue::Bool(true)),
        ];
        let patterns = vec![
            YaraPatternInfo {
                identifier: "$a".into(),
                kind: "text".into(),
            },
            YaraPatternInfo {
                identifier: "$b".into(),
                kind: "hex".into(),
            },
        ];

        let m = build_yara_match(
            "tf-evidence-v1:e1",
            compiled,
            "r",
            "default",
            &tags,
            &meta,
            &patterns,
        );

        let mp = m
            .matched_patterns
            .as_ref()
            .expect("matched_patterns is Some");
        let root = mp.as_object().expect("matched_patterns is object");

        // rule 詳細
        let rule = root["rule"].as_object().unwrap();
        assert_eq!(rule["identifier"], "r");
        assert_eq!(rule["namespace"], "default");
        let tags_arr = rule["tags"].as_array().unwrap();
        assert_eq!(tags_arr.len(), 2);

        // metadata
        let meta_obj = rule["metadata"].as_object().unwrap();
        assert_eq!(meta_obj["author"], "TraceForge");
        assert_eq!(meta_obj["severity"], 5);
        assert_eq!(meta_obj["enabled"], true);

        // patterns（alphabetical 順・決定性）
        let patterns_arr = root["patterns"].as_array().unwrap();
        assert_eq!(patterns_arr.len(), 2);
        assert_eq!(patterns_arr[0]["identifier"], "$a");
        assert_eq!(patterns_arr[0]["kind"], "text");
        assert_eq!(patterns_arr[1]["identifier"], "$b");
        assert_eq!(patterns_arr[1]["kind"], "hex");
    }

    #[test]
    fn reasons_are_deterministic_regardless_of_input_order() {
        let summary = compile_simple_rule(r#"rule r { condition: true }"#);
        let compiled = &summary.compiled[0];

        // patterns を異なる順序で渡しても、出力 reasons は同一（決定性）。
        let patterns_a = vec![
            YaraPatternInfo {
                identifier: "$a".into(),
                kind: "text".into(),
            },
            YaraPatternInfo {
                identifier: "$b".into(),
                kind: "hex".into(),
            },
        ];
        let patterns_b = vec![
            YaraPatternInfo {
                identifier: "$b".into(),
                kind: "hex".into(),
            },
            YaraPatternInfo {
                identifier: "$a".into(),
                kind: "text".into(),
            },
        ];

        let m_a = build_yara_match(
            "tf-evidence-v1:e1",
            compiled,
            "r",
            "",
            &[],
            &[],
            &patterns_a,
        );
        let m_b = build_yara_match(
            "tf-evidence-v1:e1",
            compiled,
            "r",
            "",
            &[],
            &[],
            &patterns_b,
        );

        assert_eq!(m_a.reasons, m_b.reasons, "入力順によらない決定的 reasons");
    }

    #[test]
    fn score_and_ordered_event_ids_are_none_for_yara() {
        let summary = compile_simple_rule(r#"rule r { condition: true }"#);
        let compiled = &summary.compiled[0];

        let m = build_yara_match("tf-evidence-v1:e1", compiled, "r", "", &[], &[], &[]);

        // YARA match は Correlation ではないため score / ordered_event_ids は None。
        assert!(m.score.is_none());
        assert!(m.ordered_event_ids.is_none());
        // Sigma 拡張 field も持たない。
        assert!(m.logsource_mapping.is_none());
        // YARA 拡張 field は必ず持つ。
        assert!(m.matched_patterns.is_some());
    }

    // ===== MetadataValue 変換 =====

    #[test]
    fn metadata_value_to_json() {
        assert_eq!(MetadataValue::Integer(42).to_json_value(), Value::from(42));
        assert_eq!(MetadataValue::Bool(true).to_json_value(), Value::Bool(true));
        assert_eq!(
            MetadataValue::Str("hello".into()).to_json_value(),
            Value::String("hello".into())
        );
        // Float は JSON number へ変換。
        let f = MetadataValue::Float(1.5).to_json_value();
        assert_eq!(f.as_f64(), Some(1.5));
        // Bytes は hex string へ変換。
        assert_eq!(
            MetadataValue::Bytes("0102ff".into()).to_json_value(),
            Value::String("0102ff".into())
        );
    }

    // ===== empty ruleset からの構築は呼出側で防止 =====

    #[test]
    fn empty_ruleset_compiles_to_empty() {
        let registry = crate::loader::RuleRegistry::new();
        let summary = YaraRuleset::compile_from_registry(&registry);
        assert!(summary.compiled.is_empty());
        assert!(summary.errors.is_empty());
        assert!(summary.into_ruleset().is_empty());
    }
}
