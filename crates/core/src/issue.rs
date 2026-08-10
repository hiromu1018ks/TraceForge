//! Issue 型（Schema §5.6、規範 §9.3）。
//!
//! Parse Issue のほか、limit 到達・入出力安全・strict mode 違反等、Case 全体の
//! 「完全ではない理由」を記録する。`message` へ Evidence の巨大値や未 escape の
//! 制御文字をそのまま含めてはならない（規範 §9.3）。

use serde_json::{Map, Value};

use crate::event::RecordLocator;

/// Schema §5.6 の Issue severity。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueSeverity {
    /// 処理は継続可能。Exit Code 1 へ寄与。
    Warning,
    /// 後続処理で部分的回復の可能性。strict でなければ継続。
    Recoverable,
    /// この scope は中止。process 全体は Exit Code 10 や strict 対応へ。
    Fatal,
}

impl IssueSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            IssueSeverity::Warning => "warning",
            IssueSeverity::Recoverable => "recoverable",
            IssueSeverity::Fatal => "fatal",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "warning" => IssueSeverity::Warning,
            "recoverable" => IssueSeverity::Recoverable,
            "fatal" => IssueSeverity::Fatal,
            _ => return None,
        })
    }
}

/// Schema §5.6 の Issue scope。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueScope {
    Case,
    Evidence,
    Artifact,
    Record,
    Rule,
    Output,
}

impl IssueScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            IssueScope::Case => "case",
            IssueScope::Evidence => "evidence",
            IssueScope::Artifact => "artifact",
            IssueScope::Record => "record",
            IssueScope::Rule => "rule",
            IssueScope::Output => "output",
        }
    }

    pub fn from_schema_str(s: &str) -> Option<Self> {
        Some(match s {
            "case" => IssueScope::Case,
            "evidence" => IssueScope::Evidence,
            "artifact" => IssueScope::Artifact,
            "record" => IssueScope::Record,
            "rule" => IssueScope::Rule,
            "output" => IssueScope::Output,
            _ => return None,
        })
    }
}

/// Schema §5.6 / 規範 §9.3 / §18 の Issue。
///
/// `issue_id` には安定した code（例: `TF-W-EVTX-PARTIAL-RECORD`）を格納する。
/// 同一 Issue の出力順は `evidence_id` → `artifact_id` → `source_ordinal` → `code`
/// の順とする（規範 §9.3）。
#[derive(Clone, Debug, PartialEq)]
pub struct Issue {
    /// 安定 code（例: `TF-W-EVTX-PARTIAL-RECORD`、`TF-W-LIMIT-MAX-EVENTS`）。
    pub issue_id: String,
    pub severity: IssueSeverity,
    pub scope: IssueScope,
    pub evidence_id: Option<String>,
    pub artifact_id: Option<String>,
    pub record_locator: Option<RecordLocator>,
    pub source_ordinal: Option<u64>,
    pub message: String,
}

impl Issue {
    /// Schema §5.6 の Issue 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("issue_id".into(), Value::String(self.issue_id.clone()));
        map.insert(
            "severity".into(),
            Value::String(self.severity.as_str().into()),
        );
        map.insert("scope".into(), Value::String(self.scope.as_str().into()));
        map.insert(
            "evidence_id".into(),
            self.evidence_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "artifact_id".into(),
            self.artifact_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "record_locator".into(),
            self.record_locator
                .as_ref()
                .map(|r| r.to_canonical_value())
                .unwrap_or(Value::Null),
        );
        map.insert(
            "source_ordinal".into(),
            self.source_ordinal.map(Value::from).unwrap_or(Value::Null),
        );
        map.insert("message".into(), Value::String(self.message.clone()));
        Value::Object(map)
    }

    /// 規範 §9.3 の出力順 sort key を返す。
    /// `(evidence_id, artifact_id, source_ordinal, code)` の昇順。
    pub fn sort_key(&self) -> (&str, &Option<String>, &Option<String>, Option<u64>) {
        (
            &self.issue_id,
            &self.evidence_id,
            &self.artifact_id,
            self.source_ordinal,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_canonical_shape() {
        let i = Issue {
            issue_id: "TF-W-EVTX-PARTIAL-RECORD".into(),
            severity: IssueSeverity::Warning,
            scope: IssueScope::Record,
            evidence_id: Some("tf-evidence-v1:x".into()),
            artifact_id: None,
            record_locator: Some(RecordLocator::RecordId("5".into())),
            source_ordinal: Some(4),
            message: "Record was truncated".into(),
        };
        let v = i.to_canonical_value();
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["scope"], "record");
        assert_eq!(v["source_ordinal"], 4);
        assert_eq!(v["record_locator"]["type"], "record_id");
    }

    #[test]
    fn severities_and_scopes_roundtrip() {
        for s in [
            IssueSeverity::Warning,
            IssueSeverity::Recoverable,
            IssueSeverity::Fatal,
        ] {
            assert_eq!(IssueSeverity::from_schema_str(s.as_str()), Some(s));
        }
        for s in [
            IssueScope::Case,
            IssueScope::Evidence,
            IssueScope::Artifact,
            IssueScope::Record,
            IssueScope::Rule,
            IssueScope::Output,
        ] {
            assert_eq!(IssueScope::from_schema_str(s.as_str()), Some(s));
        }
    }
}
