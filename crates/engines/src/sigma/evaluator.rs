//! Sigma Rule の評価器と Match 変換（T5-013・T5-014・T5-015・T5-016）。
//!
//! コンパイル済み [`SigmaRule`] を [`tf_core::Event`] へ対して評価し、
//! match した場合に `tf_core::match_::Match`（`match_type=Sigma`）を生成する。

use serde_json::{Map, Value};

use tf_core::event::Event;
use tf_core::id::match_id;
use tf_core::r#match::{Match, MatchType};

use crate::sigma::condition::{Condition, SelectorScope};
use crate::sigma::fieldmap::map_sigma_field;
use crate::sigma::logsource::{LogsourceRouting, build_routing, matches_event};
use crate::sigma::modifier::Modifier;
use crate::sigma::rule::{
    FieldConstraint, ScalarValue, Selection, SigmaError, SigmaRule, parse_sigma_rule,
};
use crate::yaml::YamlValue;

/// コンパイル済み Sigma Rule。
#[derive(Clone, Debug)]
pub struct CompiledSigmaRule {
    /// parse 済み Sigma Rule。
    pub rule: SigmaRule,
    /// logsource routing 条件。
    pub routing: LogsourceRouting,
    /// Rule file raw bytes の SHA-256 lowercase hex（規範 §14）。
    pub sha256: String,
    /// Rule ID（Sigma `id` field があればそれ、なければ title）。
    pub rule_id: String,
}

/// Sigma 評価結果。
#[derive(Clone, Debug)]
pub struct SigmaMatchResult {
    /// Schema §5.7 の Match（match_type=Sigma）。
    pub match_value: Match,
}

impl CompiledSigmaRule {
    /// [`crate::LoadedRuleFile`] の raw bytes から Sigma Rule をコンパイルする。
    ///
    /// `sha256` は [`crate::LoadedRuleFile::sha256`] を渡す（規範 §14: 同じ bytes）。
    pub fn compile(raw_bytes: &[u8], sha256: &str) -> Result<Self, SigmaError> {
        let yaml: YamlValue = crate::yaml::parse(std::str::from_utf8(raw_bytes).map_err(|e| {
            SigmaError::InvalidStructure(format!("rule file is not valid UTF-8: {e}"))
        })?)?;
        let rule = parse_sigma_rule(&yaml)?;
        let routing = build_routing(&rule.logsource);
        let rule_id = rule.id.clone().unwrap_or_else(|| rule.title.clone());

        Ok(CompiledSigmaRule {
            rule,
            routing,
            sha256: sha256.to_string(),
            rule_id,
        })
    }

    /// 単一 Event に対する評価。
    ///
    /// logsource routing を満たし、condition 式が true の場合に match を返す。
    /// logsource routing を満たさない Event は `None`（高速な事前 filter）。
    pub fn evaluate(&self, event: &Event) -> Option<SigmaMatchResult> {
        // logsource routing の事前 filter
        if !matches_event(&self.routing, &event.attributes, event.event_type.as_str()) {
            return None;
        }

        // 各 selection を評価（名前 → bool）
        let selection_results: Vec<(String, bool)> = self
            .rule
            .selections
            .iter()
            .map(|(name, sel)| {
                let matched = evaluate_selection(sel, event);
                (name.clone(), matched)
            })
            .collect();

        // condition 式を評価
        let condition_met = evaluate_condition(&self.rule.condition, &selection_results);
        if !condition_met {
            return None;
        }

        // Match を構築
        let match_value = self.build_match(event, &selection_results);
        Some(SigmaMatchResult { match_value })
    }

    /// match した Event から [`Match`] を構築する。
    fn build_match(&self, event: &Event, selection_results: &[(String, bool)]) -> Match {
        let matched_selections: Vec<&str> = selection_results
            .iter()
            .filter(|(_, m)| *m)
            .map(|(n, _)| n.as_str())
            .collect();

        let event_ids: Vec<&str> = vec![event.id.as_str()];
        let evidence_ids: Vec<&str> = vec![event.provenance.evidence_id.as_str()];

        // match_id の決定的生成（規範 §12.4）
        let match_id_str = match_id(&self.rule_id, &self.sha256, &event_ids);

        let reasons = vec![format!(
            "Sigma rule '{}' matched (selections: {})",
            self.rule.title,
            matched_selections.join(", ")
        )];

        Match {
            match_id: match_id_str,
            match_type: MatchType::Sigma,
            rule_id: self.rule_id.clone(),
            rule_sha256: self.sha256.clone(),
            event_ids: event_ids.iter().map(|s| s.to_string()).collect(),
            evidence_ids: evidence_ids.iter().map(|s| s.to_string()).collect(),
            reasons,
            score: None,
            ordered_event_ids: None,
            logsource_mapping: Some(self.build_logsource_mapping()),
            matched_patterns: None,
        }
    }

    /// Schema §5.7 の `logsource_mapping` 拡張 field を構築する。
    fn build_logsource_mapping(&self) -> Value {
        let mut map = Map::new();
        let ls = &self.rule.logsource;
        if let Some(p) = &ls.product {
            map.insert("product".into(), Value::String(p.clone()));
        }
        if let Some(c) = &ls.category {
            map.insert("category".into(), Value::String(c.clone()));
        }
        if let Some(s) = &ls.service {
            map.insert("service".into(), Value::String(s.clone()));
        }
        if let Some(ch) = &self.routing.channel {
            map.insert("resolved_channel".into(), Value::String(ch.clone()));
        }
        if let Some(et) = &self.routing.event_type {
            map.insert("resolved_event_type".into(), Value::String(et.clone()));
        }
        map.insert(
            "routing_reason".into(),
            Value::String(self.routing.routing_reason.clone()),
        );
        Value::Object(map)
    }
}

// ============================================================================
// selection 評価
// ============================================================================

/// 1つの selection を Event に対して評価する。
///
/// selection は OR group の list。各 group は AND で結合された field 制約の list。
/// いずれかの group が全制約を満たせば true。
fn evaluate_selection(selection: &Selection, event: &Event) -> bool {
    selection.groups.iter().any(|group| {
        group
            .iter()
            .all(|constraint| evaluate_constraint(constraint, event))
    })
}

/// 1つの field 制約を評価する。
fn evaluate_constraint(constraint: &FieldConstraint, event: &Event) -> bool {
    // exists modifier の特殊処理
    if constraint.modifiers.contains(&Modifier::Exists) {
        let exists_expected = constraint
            .values
            .first()
            .map(|v| matches!(v, ScalarValue::Bool(true)))
            .unwrap_or(false);
        let field_exists = resolve_field(constraint.sigma_field.as_str(), event).is_some();
        return field_exists == exists_expected;
    }

    // Null 値の処理: Null 値は field が不在または null の場合に match
    if constraint.values.len() == 1
        && let ScalarValue::Null = constraint.values[0]
    {
        return matches!(
            resolve_field(constraint.sigma_field.as_str(), event),
            None | Some(Value::Null)
        );
    }

    let field_value = match resolve_field(constraint.sigma_field.as_str(), event) {
        Some(v) => v,
        None => return false,
    };
    let field_str = value_to_string(&field_value);

    let cased = constraint.modifiers.contains(&Modifier::Cased);
    let all_modifier = constraint.modifiers.contains(&Modifier::All);

    let match_single = |sigma_value: &ScalarValue| -> bool {
        let value_str = sigma_value.as_string();
        match_single_value(&field_str, &value_str, &constraint.modifiers, cased)
    };

    if all_modifier {
        // 全ての値が match する必要がある
        constraint.values.iter().all(match_single)
    } else {
        // 何れかの値が match すればよい（OR）
        constraint.values.iter().any(match_single)
    }
}

/// 単一値の match を評価する。
fn match_single_value(field: &str, value: &str, modifiers: &[Modifier], cased: bool) -> bool {
    let has_contains = modifiers.contains(&Modifier::Contains);
    let has_starts = modifiers.contains(&Modifier::StartsWith);
    let has_ends = modifiers.contains(&Modifier::EndsWith);

    let (field_cmp, value_cmp) = if cased {
        (field.to_string(), value.to_string())
    } else {
        (field.to_lowercase(), value.to_lowercase())
    };

    if has_contains {
        field_cmp.contains(&value_cmp)
    } else if has_starts {
        field_cmp.starts_with(&value_cmp)
    } else if has_ends {
        field_cmp.ends_with(&value_cmp)
    } else {
        // exact match: wildcard を考慮
        glob_match(&value_cmp, &field_cmp)
    }
}

// ============================================================================
// condition 評価
// ============================================================================

/// condition 式を評価する。
fn evaluate_condition(condition: &Condition, selection_results: &[(String, bool)]) -> bool {
    match condition {
        Condition::And(a, b) => {
            evaluate_condition(a, selection_results) && evaluate_condition(b, selection_results)
        }
        Condition::Or(a, b) => {
            evaluate_condition(a, selection_results) || evaluate_condition(b, selection_results)
        }
        Condition::Not(inner) => !evaluate_condition(inner, selection_results),
        Condition::Selector(name) => selection_results
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, m)| *m)
            .unwrap_or(false),
        Condition::OneOf(scope) => {
            let matched = count_matching(scope, selection_results);
            matched >= 1
        }
        Condition::AllOf(scope) => {
            let total = count_scope_total(scope, selection_results);
            total > 0 && count_matching(scope, selection_results) == total
        }
    }
}

/// scope に合致する選択肢のうち、true のものを数える。
fn count_matching(scope: &SelectorScope, selection_results: &[(String, bool)]) -> usize {
    selection_results
        .iter()
        .filter(|(name, m)| *m && scope_matches(scope, name))
        .count()
}

/// scope に合致する選択肢の総数を数える。
fn count_scope_total(scope: &SelectorScope, selection_results: &[(String, bool)]) -> usize {
    selection_results
        .iter()
        .filter(|(name, _)| scope_matches(scope, name))
        .count()
}

/// 選択肢名が scope に合致するか。
fn scope_matches(scope: &SelectorScope, name: &str) -> bool {
    match scope {
        SelectorScope::All => true,
        SelectorScope::Wildcard(prefix) => name.starts_with(prefix.as_str()),
    }
}

// ============================================================================
// field resolver
// ============================================================================

/// Sigma field 名から Event 上の値を取り出す。
///
/// 1. `map_sigma_field` で TF field path へ mapping
/// 2. TF field path で Event から値を取得
/// 3. mapping がない場合は `attributes.<sigma_field>` (lowercase) を探す
fn resolve_field(sigma_field: &str, event: &Event) -> Option<Value> {
    if let Some(tf_path) = map_sigma_field(sigma_field)
        && let Some(v) = resolve_tf_path(tf_path, event)
    {
        return Some(v);
    }
    // Fallback: attributes から直接探す
    // Sigma field 名を lowercase にして attribute key と照合
    let lower = sigma_field.to_lowercase();
    // 1. evtx.event_data.<field> を探す
    let data_key = format!("evtx.event_data.{sigma_field}");
    if let Some(v) = event.attributes.get(&data_key) {
        return Some(v.clone());
    }
    // 2. evtx.<lower> を探す
    let evtx_key = format!("evtx.{lower}");
    if let Some(v) = event.attributes.get(&evtx_key) {
        return Some(v.clone());
    }
    // 3. そのまま attribute key として探す
    event.attributes.get(sigma_field).cloned()
}

/// TF field path から Event 上の値を取得する。
fn resolve_tf_path(path: &str, event: &Event) -> Option<Value> {
    match path {
        "hostname" => event.hostname.clone().map(Value::String),
        "user" => event.user.clone().map(Value::String),
        "program" => event.program.clone().map(Value::String),
        "message" => Some(Value::String(event.message.clone())),
        "path.original" => event
            .path
            .as_ref()
            .map(|p| Value::String(p.original.clone())),
        "path.comparison_key" => event
            .path
            .as_ref()
            .and_then(|p| p.comparison_key.clone())
            .map(Value::String),
        "process.image_path.original" => event
            .process
            .as_ref()
            .and_then(|p| p.image_path.as_ref())
            .map(|ip| Value::String(ip.original.clone())),
        "process.command_line" => event
            .process
            .as_ref()
            .and_then(|p| p.command_line.clone())
            .map(Value::String),
        "process.pid" => event.process.as_ref().and_then(|p| p.pid).map(Value::from),
        "process.ppid" => event.process.as_ref().and_then(|p| p.ppid).map(Value::from),
        other if other.starts_with("attributes.") => {
            let key = &other["attributes.".len()..];
            event.attributes.get(key).cloned()
        }
        _ => None,
    }
}

// ============================================================================
// utilities
// ============================================================================

/// `serde_json::Value` を文字列へ変換する（比較用）。
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => v.to_string(),
    }
}

/// glob パターン（`*` = 0文字以上・`?` = 1文字）で match を判定する。
///
/// `*`・`?` 以外の文字は literal として扱う。pattern・text 共に小文字化済みを前提。
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    // 過度な再帰を防ぐため pattern 長で制限
    if pat.len() > 1024 {
        return pattern == text;
    }
    glob_match_impl(&pat[..], &txt[..])
}

fn glob_match_impl(pat: &[char], txt: &[char]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == txt[ti] || pat[pi] == '?') {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(spi) = star_pi {
            pi = spi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }

    pi == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::parse as parse_yaml;
    use std::collections::BTreeMap;
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, Provenance, RecordLocator};
    use tf_core::path::WindowsPathValue;
    use tf_core::time::{EventTime, TimestampKind};

    fn compile(yaml: &str) -> CompiledSigmaRule {
        let v = parse_yaml(yaml).unwrap();
        let rule = parse_sigma_rule(&v).unwrap();
        let routing = build_routing(&rule.logsource);
        let rule_id = rule.id.clone().unwrap_or_else(|| rule.title.clone());
        CompiledSigmaRule {
            rule,
            routing,
            sha256: "a".repeat(64),
            rule_id,
        }
    }

    fn make_event(event_id: i64, channel: &str, computer: &str) -> Event {
        let mut attrs = BTreeMap::new();
        attrs.insert("evtx.event_id".into(), Value::from(event_id));
        attrs.insert("evtx.channel".into(), Value::String(channel.into()));
        attrs.insert(
            "evtx.provider".into(),
            Value::String("Microsoft-Windows-Security-Auditing".into()),
        );

        Event {
            id: "tf-event-v1:test".into(),
            time: EventTime::unknown(TimestampKind::EventLogged),
            source: ArtifactSource::Evtx,
            event_type: EventType::new("event_logged"),
            assertion: AssertionKind::Observed,
            hostname: Some(computer.into()),
            user: None,
            path: None,
            program: None,
            process: None,
            message: String::new(),
            attributes: attrs,
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:test".into(),
                artifact_id: "tf-artifact-v1:test".into(),
                source_locator: "Security.evtx".into(),
                source_sha256: "b".repeat(64),
                parser_id: "traceforge-evtx".into(),
                parser_version: "1.0.0".into(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    fn make_process_event(command_line: &str, image_path: &str) -> Event {
        let mut attrs = BTreeMap::new();
        attrs.insert("evtx.event_id".into(), Value::from(4688));
        attrs.insert("evtx.channel".into(), Value::String("Security".into()));

        Event {
            id: "tf-event-v1:proc".into(),
            time: EventTime::unknown(TimestampKind::EventLogged),
            source: ArtifactSource::Evtx,
            event_type: EventType::new("process_start"),
            assertion: AssertionKind::Observed,
            hostname: Some("HOST".into()),
            user: Some("alice".into()),
            path: Some(WindowsPathValue::new(image_path)),
            program: None,
            process: Some(tf_core::event::ProcessRef {
                pid: Some(1234),
                ppid: Some(500),
                process_guid: None,
                parent_process_guid: None,
                image_path: Some(WindowsPathValue::new(image_path)),
                command_line: Some(command_line.into()),
            }),
            message: String::new(),
            attributes: attrs,
            provenance: Provenance {
                evidence_id: "tf-evidence-v1:proc".into(),
                artifact_id: "tf-artifact-v1:proc".into(),
                source_locator: "Security.evtx".into(),
                source_sha256: "b".repeat(64),
                parser_id: "traceforge-evtx".into(),
                parser_version: "1.0.0".into(),
                record_locator: RecordLocator::SourceOrdinal,
                source_ordinal: 0,
            },
        }
    }

    // ===== T5-012: logsource routing =====

    #[test]
    fn logsource_routing_filters_by_channel() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
        );
        let security_event = make_event(4624, "Security", "HOST");
        let system_event = make_event(4624, "System", "HOST");

        assert!(rule.evaluate(&security_event).is_some());
        assert!(
            rule.evaluate(&system_event).is_none(),
            "channel mismatch → no match"
        );
    }

    #[test]
    fn non_windows_product_no_match() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: linux
detection:
    selection:
        EventID: 1
    condition: selection
"#,
        );
        let event = make_event(1, "System", "HOST");
        assert!(
            rule.evaluate(&event).is_none(),
            "non-windows product → no match"
        );
    }

    // ===== T5-013: selection / condition =====

    #[test]
    fn simple_selection_match() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
        );
        let matching = make_event(4624, "Security", "HOST");
        let non_matching = make_event(4625, "Security", "HOST");

        assert!(rule.evaluate(&matching).is_some());
        assert!(rule.evaluate(&non_matching).is_none());
    }

    #[test]
    fn condition_and() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    sel1:
        EventID: 4624
    sel2:
        Channel: Security
    condition: sel1 and sel2
"#,
        );
        let event = make_event(4624, "Security", "HOST");
        assert!(rule.evaluate(&event).is_some());
    }

    #[test]
    fn condition_or() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    sel1:
        EventID: 4624
    sel2:
        EventID: 4625
    condition: sel1 or sel2
"#,
        );
        assert!(rule.evaluate(&make_event(4624, "Security", "H")).is_some());
        assert!(rule.evaluate(&make_event(4625, "Security", "H")).is_some());
        assert!(rule.evaluate(&make_event(9999, "Security", "H")).is_none());
    }

    #[test]
    fn condition_not() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    sel:
        EventID: 4624
    condition: not sel
"#,
        );
        assert!(rule.evaluate(&make_event(4625, "Security", "H")).is_some());
        assert!(rule.evaluate(&make_event(4624, "Security", "H")).is_none());
    }

    #[test]
    fn condition_one_of_wildcard() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    sel_a:
        EventID: 4624
    sel_b:
        Channel: Security
    condition: 1 of sel_*
"#,
        );
        // 4624 + Security → both sel_a and sel_b match → 1 of sel_* is true
        assert!(rule.evaluate(&make_event(4624, "Security", "H")).is_some());
    }

    #[test]
    fn condition_all_of_them() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    sel_a:
        EventID: 4624
    sel_b:
        Channel: Security
    condition: all of them
"#,
        );
        // Both match
        assert!(rule.evaluate(&make_event(4624, "Security", "H")).is_some());
        // Only sel_b matches (EventID != 4624)
        assert!(rule.evaluate(&make_event(9999, "Security", "H")).is_none());
    }

    // ===== T5-014: modifier =====

    #[test]
    fn modifier_contains() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        CommandLine|contains: -enc
    condition: selection
"#,
        );
        // CommandLine は process.command_line へ mapping
        let mut event = make_event(4688, "Security", "HOST");
        event.process = Some(tf_core::event::ProcessRef {
            pid: Some(1),
            ppid: None,
            process_guid: None,
            parent_process_guid: None,
            image_path: None,
            command_line: Some("powershell -enc AAAA".into()),
        });
        assert!(rule.evaluate(&event).is_some());
    }

    #[test]
    fn modifier_startswith() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        Image|startswith: "C:\\Users\\"
    condition: selection
"#,
        );
        let event = make_process_event("cmd", "C:\\Users\\alice\\run.exe");
        assert!(rule.evaluate(&event).is_some());
    }

    #[test]
    fn modifier_endswith() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        Image|endswith: ".exe"
    condition: selection
"#,
        );
        let event = make_process_event("cmd", "C:\\test\\run.exe");
        assert!(rule.evaluate(&event).is_some());
    }

    #[test]
    fn modifier_cased_case_sensitive() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        User|cased: "alice"
    condition: selection
"#,
        );
        let mut matching = make_process_event("cmd", "C:\\test.exe");
        matching.user = Some("alice".into());
        let mut non_matching = make_process_event("cmd", "C:\\test.exe");
        non_matching.user = Some("Alice".into());

        assert!(rule.evaluate(&matching).is_some(), "exact case match");
        assert!(
            rule.evaluate(&non_matching).is_none(),
            "cased modifier → case mismatch"
        );
    }

    #[test]
    fn modifier_exists_true() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        Computer|exists: true
    condition: selection
"#,
        );
        let event = make_event(1, "Security", "HOST");
        assert!(rule.evaluate(&event).is_some(), "hostname exists → match");
    }

    #[test]
    fn modifier_all_with_list() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - "-enc"
            - "-window"
    condition: selection
"#,
        );
        let mut event = make_event(4688, "Security", "HOST");
        event.process = Some(tf_core::event::ProcessRef {
            pid: Some(1),
            ppid: None,
            process_guid: None,
            parent_process_guid: None,
            image_path: None,
            command_line: Some("powershell -enc AAAA -window hidden".into()),
        });
        assert!(
            rule.evaluate(&event).is_some(),
            "contains both -enc and -window"
        );
    }

    // ===== T5-015: field mapping =====

    #[test]
    fn event_id_field_mapping() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
        );
        assert!(rule.evaluate(&make_event(4624, "Security", "H")).is_some());
    }

    #[test]
    fn list_value_or_semantics() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4624
            - 4625
    condition: selection
"#,
        );
        assert!(rule.evaluate(&make_event(4624, "Security", "H")).is_some());
        assert!(rule.evaluate(&make_event(4625, "Security", "H")).is_some());
        assert!(rule.evaluate(&make_event(9999, "Security", "H")).is_none());
    }

    // ===== T5-016: Match 変換 =====

    #[test]
    fn match_type_is_sigma() {
        let rule = compile(
            r#"
title: Test
id: abc-123
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
        );
        let event = make_event(4624, "Security", "HOST");
        let result = rule.evaluate(&event).unwrap();

        assert_eq!(result.match_value.match_type, MatchType::Sigma);
        assert_eq!(result.match_value.rule_id, "abc-123");
        assert_eq!(result.match_value.rule_sha256, "a".repeat(64));
        assert_eq!(
            result.match_value.event_ids,
            vec!["tf-event-v1:test".to_string()]
        );
        assert!(result.match_value.logsource_mapping.is_some());
    }

    #[test]
    fn match_id_is_deterministic() {
        let rule = compile(
            r#"
title: Test
id: abc-123
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
        );
        let event = make_event(4624, "Security", "HOST");
        let r1 = rule.evaluate(&event).unwrap();
        let r2 = rule.evaluate(&event).unwrap();
        assert_eq!(r1.match_value.match_id, r2.match_value.match_id);
    }

    #[test]
    fn logsource_mapping_includes_routing_info() {
        let rule = compile(
            r#"
title: Test
logsource:
    product: windows
    category: process_creation
    service: security
detection:
    selection:
        EventID: 4688
    condition: selection
"#,
        );
        // category: process_creation → event_type = process_start
        let event = make_process_event("cmd", "C:\\test.exe");
        let result = rule.evaluate(&event).unwrap();
        let lm = result.match_value.logsource_mapping.unwrap();
        let obj = lm.as_object().unwrap();
        assert_eq!(obj["product"], "windows");
        assert_eq!(obj["category"], "process_creation");
        assert_eq!(obj["service"], "security");
        assert_eq!(obj["resolved_channel"], "Security");
    }

    // ===== glob match =====

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abd"));
    }

    #[test]
    fn glob_star_match() {
        assert!(glob_match("*.exe", "test.exe"));
        assert!(glob_match("*.exe", ".exe"));
        assert!(!glob_match("*.exe", "test.txt"));
    }

    #[test]
    fn glob_question_match() {
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("a?c", "abbc"));
    }
}
