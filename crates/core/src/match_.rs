//! Match 型（Schema §5.7）。
//!
//! Sigma・YARA-X・Correlation の検知結果を表す。`match_type` で経路を区別し、
//! 共通 field に加えて各経路固有の拡張 field を持てる（Schema §5.7）。
//!
//! - Correlation: `score` と `ordered_event_ids` を追加できる。
//! - Sigma: `logsource_mapping` を追加できる。
//! - YARA-X: `matched_patterns` を追加できる。

use serde_json::{Map, Value};

use crate::finding::Score;

/// Schema §5.7 の `match_type`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    Correlation,
    Sigma,
    YaraX,
}

impl MatchType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchType::Correlation => "correlation",
            MatchType::Sigma => "sigma",
            MatchType::YaraX => "yara_x",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "correlation" => MatchType::Correlation,
            "sigma" => MatchType::Sigma,
            "yara_x" => MatchType::YaraX,
            _ => return None,
        })
    }
}

/// Schema §5.7 の Match。
///
/// Phase 1 では共通 field を強型で持ち、各経路固有の拡張 field は対応する型または
/// [`serde_json::Value`] で保持する。Phase 5 で各 engine 実装時に強型化する。
#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    pub match_id: String,
    pub match_type: MatchType,
    pub rule_id: String,
    pub rule_sha256: String,
    pub event_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub reasons: Vec<String>,
    /// Correlation のみ。score と順序付き Event ID list。
    pub score: Option<Score>,
    pub ordered_event_ids: Option<Vec<String>>,
    /// Sigma のみ。logsource mapping の詳細（Phase 5 で強型化）。
    pub logsource_mapping: Option<Value>,
    /// YARA-X のみ。matched pattern の詳細（Phase 5 で強型化）。
    pub matched_patterns: Option<Value>,
}

impl Match {
    /// Schema §5.7 の Match 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("match_id".into(), Value::String(self.match_id.clone()));
        map.insert(
            "match_type".into(),
            Value::String(self.match_type.as_str().into()),
        );
        map.insert("rule_id".into(), Value::String(self.rule_id.clone()));
        map.insert(
            "rule_sha256".into(),
            Value::String(self.rule_sha256.clone()),
        );
        map.insert(
            "event_ids".into(),
            Value::Array(self.event_ids.iter().cloned().map(Value::String).collect()),
        );
        map.insert(
            "evidence_ids".into(),
            Value::Array(
                self.evidence_ids
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert(
            "reasons".into(),
            Value::Array(self.reasons.iter().cloned().map(Value::String).collect()),
        );
        if let Some(s) = &self.score {
            map.insert("score".into(), s.to_canonical_value());
        }
        if let Some(ordered) = &self.ordered_event_ids {
            map.insert(
                "ordered_event_ids".into(),
                Value::Array(ordered.iter().cloned().map(Value::String).collect()),
            );
        }
        if let Some(lm) = &self.logsource_mapping {
            map.insert("logsource_mapping".into(), lm.clone());
        }
        if let Some(mp) = &self.matched_patterns {
            map.insert("matched_patterns".into(), mp.clone());
        }
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::ScoreAdjustment;

    #[test]
    fn correlation_match_emits_score_and_ordered_event_ids() {
        let m = Match {
            match_id: "tf-match-v1:x".into(),
            match_type: MatchType::Correlation,
            rule_id: "TF-CORR-001".into(),
            rule_sha256: "a".repeat(64),
            event_ids: vec!["e1".into(), "e2".into()],
            evidence_ids: vec!["ev1".into()],
            reasons: vec!["path match".into()],
            score: Some(Score {
                base: 0.7,
                adjustments: vec![ScoreAdjustment {
                    reason: "exact".into(),
                    value: 0.1,
                }],
            }),
            ordered_event_ids: Some(vec!["e1".into(), "e2".into()]),
            logsource_mapping: None,
            matched_patterns: None,
        };
        let v = m.to_canonical_value();
        assert!(v.as_object().unwrap().contains_key("score"));
        assert!(v.as_object().unwrap().contains_key("ordered_event_ids"));
        assert!(!v.as_object().unwrap().contains_key("matched_patterns"));
    }

    #[test]
    fn yara_match_emits_matched_patterns_only() {
        let m = Match {
            match_id: "tf-match-v1:y".into(),
            match_type: MatchType::YaraX,
            rule_id: "rule1".into(),
            rule_sha256: "b".repeat(64),
            event_ids: vec![],
            evidence_ids: vec!["ev2".into()],
            reasons: vec![],
            score: None,
            ordered_event_ids: None,
            logsource_mapping: None,
            matched_patterns: Some(serde_json::json!([{"pattern": "$a"}])),
        };
        let v = m.to_canonical_value();
        assert!(v.as_object().unwrap().contains_key("matched_patterns"));
        assert!(!v.as_object().unwrap().contains_key("score"));
    }

    #[test]
    fn match_type_roundtrip() {
        for t in [MatchType::Correlation, MatchType::Sigma, MatchType::YaraX] {
            assert_eq!(MatchType::from_schema_str(t.as_str()), Some(t));
        }
    }
}
