//! Finding と Confidence（Schema §5.8、規範 §14.3、§16）。
//!
//! Finding は検知エンジン（Sigma/YARA-X/Correlation）の結果を人間が説明できる形へ
//! 統合したもの。`created_at` を持ってはならない（Schema §5.8）。生成時刻は
//! Manifest の `run_started_at` へ保存する。

use serde_json::{Map, Value};

use crate::case::Severity;

/// Confidence level（規範 §14.3）。score から決定論的に導かれる。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidenceLevel {
    /// `0.00 <= score < 0.50`
    Low,
    /// `0.50 <= score < 0.80`
    Medium,
    /// `0.80 <= score <= 1.00`
    High,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidenceLevel::Low => "low",
            ConfidenceLevel::Medium => "medium",
            ConfidenceLevel::High => "high",
        }
    }

    /// 規範 §14.3 の閾値で score から level を導く。score は事前に [0.0, 1.0] へ clamp する。
    pub fn from_score(score: f64) -> Self {
        let clamped = score.clamp(0.0, 1.0);
        if clamped < 0.50 {
            ConfidenceLevel::Low
        } else if clamped < 0.80 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::High
        }
    }
}

/// Correlation Rule の score 構成（Schema §7 / 規範 §14.3）。
///
/// base と adjustments の和を [0.0, 1.0] へ clamp したものが最終 score。
#[derive(Clone, Debug, PartialEq)]
pub struct Score {
    pub base: f64,
    pub adjustments: Vec<ScoreAdjustment>,
}

/// score の加減点要素（Schema §7）。
#[derive(Clone, Debug, PartialEq)]
pub struct ScoreAdjustment {
    pub reason: String,
    /// `-1.0 <= value <= 1.0`。
    pub value: f64,
}

impl Score {
    /// base + adjustments を [0.0, 1.0] へ clamp した最終 score（規範 §14.3）。
    pub fn total(&self) -> f64 {
        let mut s = self.base;
        for a in &self.adjustments {
            s += a.value;
        }
        s.clamp(0.0, 1.0)
    }

    /// Schema §7 の `score` 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut adj_arr = Vec::with_capacity(self.adjustments.len());
        for a in &self.adjustments {
            adj_arr.push(serde_json::json!({
                "reason": a.reason,
                "value": a.value,
            }));
        }
        serde_json::json!({
            "base": self.base,
            "adjustments": adj_arr,
        })
    }
}

/// Confidence の理由付き評価（Schema §5.8）。
#[derive(Clone, Debug, PartialEq)]
pub struct Confidence {
    pub score: f64,
    pub level: ConfidenceLevel,
    pub reasons: Vec<String>,
}

impl Confidence {
    /// score から level を導いて Confidence を作る（規範 §14.3）。
    pub fn new(score: f64, reasons: Vec<String>) -> Self {
        let clamped = score.clamp(0.0, 1.0);
        Confidence {
            score: clamped,
            level: ConfidenceLevel::from_score(clamped),
            reasons,
        }
    }

    /// Schema §5.8 の `confidence` 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        serde_json::json!({
            "score": self.score,
            "level": self.level.as_str(),
            "reasons": self.reasons,
        })
    }
}

/// Finding が参照する rule（Schema §5.8 `rule_refs` 要素）。
#[derive(Clone, Debug, PartialEq)]
pub struct RuleRef {
    pub rule_id: String,
    pub rule_sha256: String,
}

impl RuleRef {
    pub fn to_canonical_value(&self) -> Value {
        serde_json::json!({
            "rule_id": self.rule_id,
            "rule_sha256": self.rule_sha256,
        })
    }
}

/// ATT&CK mapping（Schema §5.8 `attack_mappings` 要素、規範 §15.3）。
///
/// Phase 1 では technique_id と表示名のみ。Phase 6 で dataset 版数・hash を追加する。
#[derive(Clone, Debug, PartialEq)]
pub struct AttackMapping {
    /// `T<4 桁>(.<3 桁>)?`（例: `T1059.001`）。
    pub technique_id: String,
    pub technique_name: Option<String>,
}

impl AttackMapping {
    pub fn to_canonical_value(&self) -> Value {
        serde_json::json!({
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
        })
    }
}

/// Schema §5.8 の Finding。
///
/// `created_at` を持ってはならない（Schema §5.8）。
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub finding_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub event_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub match_ids: Vec<String>,
    pub rule_refs: Vec<RuleRef>,
    pub attack_mappings: Vec<AttackMapping>,
    /// 観測された事実の説明。推測を含めない（規範 §16、製品 §10）。
    pub observed_evidence: Vec<String>,
    /// 推論の説明。観測事実と分けて記載する（規範 §16）。
    pub inference: Vec<String>,
}

impl Finding {
    /// Schema §5.8 の Finding 形式の [`Value`] を構築する。`created_at` は出力しない。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("finding_id".into(), Value::String(self.finding_id.clone()));
        map.insert("title".into(), Value::String(self.title.clone()));
        map.insert(
            "description".into(),
            Value::String(self.description.clone()),
        );
        map.insert(
            "severity".into(),
            Value::String(self.severity.as_str().into()),
        );
        map.insert("confidence".into(), self.confidence.to_canonical_value());
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
            "match_ids".into(),
            Value::Array(self.match_ids.iter().cloned().map(Value::String).collect()),
        );
        map.insert(
            "rule_refs".into(),
            Value::Array(
                self.rule_refs
                    .iter()
                    .map(|r| r.to_canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "attack_mappings".into(),
            Value::Array(
                self.attack_mappings
                    .iter()
                    .map(|m| m.to_canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "observed_evidence".into(),
            Value::Array(
                self.observed_evidence
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert(
            "inference".into(),
            Value::Array(self.inference.iter().cloned().map(Value::String).collect()),
        );
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_level_thresholds() {
        // 規範 §14.3 の閾値。
        assert_eq!(ConfidenceLevel::from_score(0.0), ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::from_score(0.49), ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::from_score(0.5), ConfidenceLevel::Medium);
        assert_eq!(ConfidenceLevel::from_score(0.79), ConfidenceLevel::Medium);
        assert_eq!(ConfidenceLevel::from_score(0.8), ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::from_score(1.0), ConfidenceLevel::High);
    }

    #[test]
    fn confidence_clamps_and_levels() {
        let c = Confidence::new(1.5, vec!["x".into()]);
        assert_eq!(c.score, 1.0);
        assert_eq!(c.level, ConfidenceLevel::High);
        let c = Confidence::new(-0.3, vec![]);
        assert_eq!(c.score, 0.0);
        assert_eq!(c.level, ConfidenceLevel::Low);
    }

    #[test]
    fn score_total_clamps_to_unit() {
        let s = Score {
            base: 0.7,
            adjustments: vec![
                ScoreAdjustment {
                    reason: "bonus".into(),
                    value: 0.5,
                },
                ScoreAdjustment {
                    reason: "penalty".into(),
                    value: -0.2,
                },
            ],
        };
        // 0.7 + 0.5 - 0.2 = 1.0
        assert!((s.total() - 1.0).abs() < f64::EPSILON);
        let s = Score {
            base: 0.1,
            adjustments: vec![ScoreAdjustment {
                reason: "x".into(),
                value: -0.9,
            }],
        };
        assert!((s.total() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn finding_has_no_created_at() {
        // Schema §5.8: Finding は created_at を持ってはならない。
        let f = Finding {
            finding_id: "tf-finding-v1:x".into(),
            title: "t".into(),
            description: "d".into(),
            severity: Severity::Medium,
            confidence: Confidence::new(0.6, vec![]),
            event_ids: vec![],
            evidence_ids: vec![],
            match_ids: vec![],
            rule_refs: vec![],
            attack_mappings: vec![],
            observed_evidence: vec![],
            inference: vec![],
        };
        let v = f.to_canonical_value();
        assert!(!v.as_object().unwrap().contains_key("created_at"));
    }
}
