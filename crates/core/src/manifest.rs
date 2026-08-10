//! Analysis Manifest（Schema §5.9、規範 §20）。
//!
//! Manifest は分析の再現性と完全性を保証する run metadata を保持する。
//! run 時刻は Event ID・Finding ID・分析内容の determinism へ影響してはならない
//! （規範 §20）。

use serde_json::{Map, Value};

/// Schema §5.9 `counts` の各 record type 件数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManifestCounts {
    pub evidence: u64,
    pub artifact: u64,
    pub event: u64,
    pub issue: u64,
    pub r#match: u64,
    pub finding: u64,
}

impl ManifestCounts {
    /// Schema §5.9 の `counts` 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        serde_json::json!({
            "evidence": self.evidence,
            "artifact": self.artifact,
            "event": self.event,
            "issue": self.issue,
            "match": self.r#match,
            "finding": self.finding,
        })
    }
}

/// Schema §5.9 / 規範 §20 の Analysis Manifest。
///
/// Phase 1 では型の枠組みを定義する。実際の集計（counts・components・rules 等）は
/// Phase 7 で実装する。柔軟な field は [`serde_json::Value`] で保持する。
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Manifest {
    pub traceforge_version: String,
    pub build_commit: String,
    pub target: String,
    pub schema_version: String,
    pub compatibility_profile: String,
    /// RFC 3339 UTC 文字列。run metadata（determinism 比較から除外、規範 §13.1）。
    pub run_started_at: String,
    /// RFC 3339 UTC 文字列。
    pub run_finished_at: String,
    /// resolved configuration の canonical JSON。
    pub resolved_config: Value,
    /// `resolved_config` の SHA-256 lowercase hex。
    pub resolved_config_sha256: String,
    pub case_id: String,
    pub counts: ManifestCounts,
    /// parser/Sigma/YARA-X engine 等の構成要素一覧。
    pub components: Vec<Value>,
    /// 使用した rule の一覧（rule_id・file・sha256 等）。Phase 5/6 で詳細化。
    pub rules: Vec<Value>,
    /// ATT&CK dataset の version・hash。Phase 6 で設定。
    pub attack_dataset: Option<Value>,
    /// timezone 仮定の記録。
    pub timezone_assumptions: Vec<Value>,
    /// 適用した resource limit と到達状況。
    pub limits: Value,
    /// `complete=false` の理由（partial/skip/limit 到達等）。
    pub incomplete_reasons: Vec<String>,
    /// 全工程が完全に成功したか。limit 到達・partial・skip があれば false（規範 §18）。
    pub complete: bool,
    /// 規範 §17.2 の Exit Code。
    pub exit_code: i32,
}

impl Manifest {
    /// Schema §5.9 の Manifest 形式の [`Value`] を構築する。
    pub fn to_canonical_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "traceforge_version".into(),
            Value::String(self.traceforge_version.clone()),
        );
        map.insert(
            "build_commit".into(),
            Value::String(self.build_commit.clone()),
        );
        map.insert("target".into(), Value::String(self.target.clone()));
        map.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        map.insert(
            "compatibility_profile".into(),
            Value::String(self.compatibility_profile.clone()),
        );
        map.insert(
            "run_started_at".into(),
            Value::String(self.run_started_at.clone()),
        );
        map.insert(
            "run_finished_at".into(),
            Value::String(self.run_finished_at.clone()),
        );
        map.insert("resolved_config".into(), self.resolved_config.clone());
        map.insert(
            "resolved_config_sha256".into(),
            Value::String(self.resolved_config_sha256.clone()),
        );
        map.insert("case_id".into(), Value::String(self.case_id.clone()));
        map.insert("counts".into(), self.counts.to_canonical_value());
        map.insert("components".into(), Value::Array(self.components.clone()));
        map.insert("rules".into(), Value::Array(self.rules.clone()));
        map.insert(
            "attack_dataset".into(),
            self.attack_dataset.clone().unwrap_or(Value::Null),
        );
        map.insert(
            "timezone_assumptions".into(),
            Value::Array(self.timezone_assumptions.clone()),
        );
        map.insert("limits".into(), self.limits.clone());
        map.insert(
            "incomplete_reasons".into(),
            Value::Array(
                self.incomplete_reasons
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        map.insert("complete".into(), Value::Bool(self.complete));
        map.insert("exit_code".into(), Value::from(self.exit_code));
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_uses_match_key() {
        // Schema §5.9: counts は "match" key を使う（Rust の予約語とは無関係）。
        let c = ManifestCounts {
            event: 10,
            r#match: 3,
            ..Default::default()
        };
        let v = c.to_canonical_value();
        assert_eq!(v["match"], 3);
        assert_eq!(v["event"], 10);
    }

    #[test]
    fn manifest_complete_shape() {
        let m = Manifest {
            traceforge_version: "0.1.0".into(),
            build_commit: "deadbeef".into(),
            target: "x86_64-pc-windows-msvc".into(),
            schema_version: "1.0.0".into(),
            compatibility_profile: "traceforge-compat-v1".into(),
            run_started_at: "2026-08-10T01:00:00Z".into(),
            run_finished_at: "2026-08-10T01:01:00Z".into(),
            resolved_config: serde_json::json!({}),
            resolved_config_sha256: "a".repeat(64),
            case_id: "tf-case-v1:x".into(),
            counts: ManifestCounts::default(),
            components: vec![],
            rules: vec![],
            attack_dataset: None,
            timezone_assumptions: vec![],
            limits: serde_json::json!({}),
            incomplete_reasons: vec![],
            complete: true,
            exit_code: 0,
        };
        let v = m.to_canonical_value();
        for key in [
            "traceforge_version",
            "build_commit",
            "target",
            "schema_version",
            "compatibility_profile",
            "run_started_at",
            "run_finished_at",
            "resolved_config",
            "resolved_config_sha256",
            "case_id",
            "counts",
            "components",
            "rules",
            "attack_dataset",
            "timezone_assumptions",
            "limits",
            "incomplete_reasons",
            "complete",
            "exit_code",
        ] {
            assert!(v.as_object().unwrap().contains_key(key), "欠落: {key}");
        }
    }
}
