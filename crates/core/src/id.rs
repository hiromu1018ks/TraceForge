//! 決定的 ID 6 種の生成（規範 §12、Schema §3.1）。
//!
//! TraceForge の ID は全て決定的生成で、UUID・乱数・実行時刻由来を禁止する
//! （規範 §12.1、AGENTS.md 禁止事項）。形式は次の共通形:
//!
//! ```text
//! tf-<type>-v1:<lowercase SHA-256 hex 64 文字>
//! ```
//!
//! 各 ID の hash 入力 field 順序と符号化規則は規範 §12.2〜12.4 に従う。
//! 全 field は [`LengthPrefixed`]（4 byte big-endian length + bytes）で連結する。

use crate::hash::sha256_hex;
use crate::length_prefixed::LengthPrefixed;

/// 6 種の ID 共通 prefix（規範 §12.1）。
pub const CASE_ID_PREFIX: &str = "tf-case-v1:";
pub const EVIDENCE_ID_PREFIX: &str = "tf-evidence-v1:";
pub const ARTIFACT_ID_PREFIX: &str = "tf-artifact-v1:";
pub const EVENT_ID_PREFIX: &str = "tf-event-v1:";
pub const MATCH_ID_PREFIX: &str = "tf-match-v1:";
pub const FINDING_ID_PREFIX: &str = "tf-finding-v1:";

/// Schema version（Schema §1: `1.0.0`）。Event ID の hash field #2。
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Evidence ID の hash 入力先頭 literal（規範 §5.6）。
const EVIDENCE_ID_LITERAL: &str = "TRACEFORGE-EVIDENCE-ID-V1";
/// Event ID の hash 入力先頭 literal（規範 §12.3）。
const EVENT_ID_LITERAL: &str = "TRACEFORGE-EVENT-ID-V1";

/// Evidence ID を生成する（規範 §5.6）。
///
/// hash field 順: `literal` / `source_locator` / decimal `size` / lowercase `sha256`。
/// `source_locator` は入力 root からの相対 path（規範 §5.2）、`sha256` は
/// snapshot 検証後の lowercase hex。
pub fn evidence_id(source_locator: &str, size: u64, sha256: &str) -> String {
    let mut buf = LengthPrefixed::new();
    buf.append_str(EVIDENCE_ID_LITERAL);
    buf.append_str(source_locator);
    buf.append_u64(size);
    buf.append_str(sha256);
    format!("{EVIDENCE_ID_PREFIX}{}", sha256_hex(buf.as_bytes()))
}

/// Case ID を生成する（規範 §4.1）。
///
/// hash 入力は `evidence_id` を UTF-8 byte 順で sort し、各々を length-prefixed で
/// 連結したもの。Case 名・external ID・analyst・実行時刻・絶対 path は含めない（規範 §4.1）。
///
/// `evidence_ids` の渡し順序に依存しない（内部で sort する）。
pub fn case_id(evidence_ids: &[&str]) -> String {
    // 規範 §4.1: evidence_id を byte 順で sort する。渡し順序に非依存（決定性）。
    let mut sorted: Vec<&str> = evidence_ids.to_vec();
    sorted.sort_unstable();
    let mut buf = LengthPrefixed::new();
    for id in &sorted {
        buf.append_str(id);
    }
    format!("{CASE_ID_PREFIX}{}", sha256_hex(buf.as_bytes()))
}

/// Artifact ID を生成する（規範 §12.4）。
///
/// hash field 順: `evidence_id` / `artifact_type` / `parser_id` / `parser_version`。
/// `artifact_type` は Schema §3.4 の lowercase 文字列（`evtx` / `lnk` 等）。
pub fn artifact_id(
    evidence_id: &str,
    artifact_type: &str,
    parser_id: &str,
    parser_version: &str,
) -> String {
    let mut buf = LengthPrefixed::new();
    buf.append_str(evidence_id);
    buf.append_str(artifact_type);
    buf.append_str(parser_id);
    buf.append_str(parser_version);
    format!("{ARTIFACT_ID_PREFIX}{}", sha256_hex(buf.as_bytes()))
}

/// Event ID を生成する（規範 §12.3）。
///
/// hash field は12個をこの順で連結する:
/// 1. literal `TRACEFORGE-EVENT-ID-V1`
/// 2. Schema version
/// 3. Evidence ID
/// 4. Artifact ID
/// 5. Parser ID
/// 6. Parser version
/// 7. canonical Record Locator（[`crate::event::RecordLocator`] の canonical JSON 文字列）
/// 8. `source_ordinal`（decimal ASCII）
/// 9. Event type
/// 10. Assertion kind（`observed` / `inferred`）
/// 11. canonical EventTime（[`crate::time::EventTime`] の canonical JSON 文字列）
/// 12. `event_ordinal`（同一 source record から複数 Event を生成する場合の番号）
///
/// `message`・`hostname` 等は ID へ含めない（Parser の表示文変更だけで ID が変わるのを防ぐ）。
#[allow(clippy::too_many_arguments)] // 規範 §12.3 が12 field を固定順で要求するため
pub fn event_id(
    evidence_id: &str,
    artifact_id: &str,
    parser_id: &str,
    parser_version: &str,
    record_locator_canonical: &str,
    source_ordinal: u64,
    event_type: &str,
    assertion_kind: &str,
    event_time_canonical: &str,
    event_ordinal: u64,
) -> String {
    let mut buf = LengthPrefixed::new();
    buf.append_str(EVENT_ID_LITERAL);
    buf.append_str(SCHEMA_VERSION);
    buf.append_str(evidence_id);
    buf.append_str(artifact_id);
    buf.append_str(parser_id);
    buf.append_str(parser_version);
    buf.append_str(record_locator_canonical);
    buf.append_u64(source_ordinal);
    buf.append_str(event_type);
    buf.append_str(assertion_kind);
    buf.append_str(event_time_canonical);
    buf.append_u64(event_ordinal);
    format!("{EVENT_ID_PREFIX}{}", sha256_hex(buf.as_bytes()))
}

/// Match ID を生成する（規範 §12.4）。
///
/// hash field: `rule_id` / `rule_content_sha256` / ordered `event_ids`（list）。
/// `ordered_event_ids` は順序付き（同一 Rule・同一順序で重複 match を禁止するため）。
pub fn match_id(rule_id: &str, rule_content_sha256: &str, ordered_event_ids: &[&str]) -> String {
    let mut buf = LengthPrefixed::new();
    buf.append_str(rule_id);
    buf.append_str(rule_content_sha256);
    buf.append_str_list(ordered_event_ids);
    format!("{MATCH_ID_PREFIX}{}", sha256_hex(buf.as_bytes()))
}

/// Finding ID を生成する（規範 §12.4）。
///
/// hash field: `finding_type` / `rule_content_sha256_list`（list） /
/// `sorted_event_ids`（list） / `sorted_evidence_ids`（list）。
///
/// 各 list は事前に sort 済みであること。`finding_type` は当該 Finding の由来区分
/// （`correlation` / `sigma` / `yara_x` 等）を示す lowercase 文字列。
pub fn finding_id(
    finding_type: &str,
    rule_content_sha256_list: &[&str],
    sorted_event_ids: &[&str],
    sorted_evidence_ids: &[&str],
) -> String {
    let mut buf = LengthPrefixed::new();
    buf.append_str(finding_type);
    buf.append_str_list(rule_content_sha256_list);
    buf.append_str_list(sorted_event_ids);
    buf.append_str_list(sorted_evidence_ids);
    format!("{FINDING_ID_PREFIX}{}", sha256_hex(buf.as_bytes()))
}

/// 文字列が Schema §3.1 の ID pattern に合致するか検証する。
///
/// pattern: `^tf-(case|evidence|artifact|event|match|finding)-v1:[0-9a-f]{64}$`
pub fn is_valid_id(s: &str) -> bool {
    let rest = match s.split_once("-v1:") {
        Some((
            "tf-case" | "tf-evidence" | "tf-artifact" | "tf-event" | "tf-match" | "tf-finding",
            rest,
        )) => rest,
        _ => return false,
    };
    crate::hash::is_lowercase_sha256_hex(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成した ID が全て Schema §3.1 の pattern に合致すること。
    #[test]
    fn generated_ids_match_pattern() {
        let ev = evidence_id("Security.evtx", 1024, &"a".repeat(64));
        let case = case_id(&[ev.as_str()]);
        let art = artifact_id(&ev, "evtx", "traceforge-evtx", "1.0.0");
        let evt = event_id(
            &ev,
            &art,
            "traceforge-evtx",
            "1.0.0",
            r#"{"type":"source_ordinal"}"#,
            7,
            "event_logged",
            "observed",
            r#"{"type":"utc_instant"}"#,
            0,
        );
        let m = match_id("TF-CORR-001", &"b".repeat(64), &[evt.as_str()]);
        let f = finding_id(
            "correlation",
            &[&"b".repeat(64)],
            &[evt.as_str()],
            &[ev.as_str()],
        );

        for id in [&ev, &case, &art, &evt, &m, &f] {
            assert!(is_valid_id(id), "{id} が ID pattern に合致しない");
        }
    }

    /// 決定性（規範 §13.1）: 同一入力は同一 ID。
    #[test]
    fn evidence_id_deterministic() {
        let a = evidence_id("foo/bar.evtx", 100, &"a".repeat(64));
        let b = evidence_id("foo/bar.evtx", 100, &"a".repeat(64));
        assert_eq!(a, b);
    }

    /// Evidence ID は入力違いで変わる。
    #[test]
    fn evidence_id_changes_on_input_change() {
        let base = evidence_id("foo/bar.evtx", 100, &"a".repeat(64));
        assert_ne!(base, evidence_id("foo/baz.evtx", 100, &"a".repeat(64)));
        assert_ne!(base, evidence_id("foo/bar.evtx", 101, &"a".repeat(64)));
        assert_ne!(base, evidence_id("foo/bar.evtx", 100, &"b".repeat(64)));
    }

    /// Case ID は evidence_id の渡し順序に依存しない（規範 §4.1）。
    #[test]
    fn case_id_independent_of_input_order() {
        let ev1 = evidence_id("a", 1, &"a".repeat(64));
        let ev2 = evidence_id("b", 2, &"b".repeat(64));
        let ab = case_id(&[ev1.as_str(), ev2.as_str()]);
        let ba = case_id(&[ev2.as_str(), ev1.as_str()]);
        assert_eq!(ab, ba);
    }

    /// Case ID は evidence 構成が異なれば変わる（規範 §4.1）。
    #[test]
    fn case_id_changes_on_evidence_set_change() {
        let ev1 = evidence_id("a", 1, &"a".repeat(64));
        let ev2 = evidence_id("b", 2, &"b".repeat(64));
        assert_ne!(
            case_id(&[ev1.as_str()]),
            case_id(&[ev1.as_str(), ev2.as_str()])
        );
    }

    /// Event ID は message 変更で不変（message は hash field に含まれない、規範 §12.3）。
    #[test]
    fn event_id_invariant_to_message_change() {
        let common = |time: &str| {
            event_id(
                "tf-evidence-v1:x",
                "tf-artifact-v1:y",
                "traceforge-evtx",
                "1.0.0",
                r#"{"type":"source_ordinal"}"#,
                3,
                "event_logged",
                "observed",
                time,
                0,
            )
        };
        // message は引数にないため、同じ引数なら常に同じ ID。決定性確認。
        let a = common(r#"{"type":"utc_instant"}"#);
        let b = common(r#"{"type":"utc_instant"}"#);
        assert_eq!(a, b);
        // EventTime canonical が異なれば Event ID も変わる。
        let c = common(r#"{"type":"unknown"}"#);
        assert_ne!(a, c);
    }

    /// Event ID は source_ordinal 変更で変わる（順序の決定性）。
    #[test]
    fn event_id_reflects_source_ordinal() {
        let mk = |ord: u64| {
            event_id(
                "tf-evidence-v1:x",
                "tf-artifact-v1:y",
                "traceforge-evtx",
                "1.0.0",
                r#"{"type":"source_ordinal"}"#,
                ord,
                "event_logged",
                "observed",
                r#"{"type":"utc_instant"}"#,
                0,
            )
        };
        assert_ne!(mk(1), mk(2));
    }

    /// event_ordinal が同一 source record からの複数 Event を区別する（規範 §12.3）。
    #[test]
    fn event_id_distinguishes_event_ordinal() {
        let mk = |ord: u64| {
            event_id(
                "tf-evidence-v1:x",
                "tf-artifact-v1:y",
                "traceforge-evtx",
                "1.0.0",
                r#"{"type":"source_ordinal"}"#,
                1,
                "event_logged",
                "observed",
                r#"{"type":"utc_instant"}"#,
                ord,
            )
        };
        assert_ne!(mk(0), mk(1));
    }

    /// Match ID は順序付き Event ID list を反映する（規範 §12.4）。
    #[test]
    fn match_id_reflects_ordered_event_ids() {
        let rule_sha = "b".repeat(64);
        let a = match_id("TF-CORR-001", &rule_sha, &["e1", "e2"]);
        let b = match_id("TF-CORR-001", &rule_sha, &["e2", "e1"]);
        assert_ne!(a, b, "順序が異なれば異なる Match ID");
        let c = match_id("TF-CORR-001", &rule_sha, &["e1", "e2"]);
        assert_eq!(a, c, "順序が同一なら同一 Match ID");
    }

    /// Finding ID は sort 済み list を反映する（規範 §12.4）。
    #[test]
    fn finding_id_reflects_sorted_lists() {
        let sha = "b".repeat(64);
        let a = finding_id("correlation", &[sha.as_str()], &["e1", "e2"], &["ev1"]);
        let b = finding_id("correlation", &[sha.as_str()], &["e1", "e2"], &["ev1"]);
        assert_eq!(a, b);
        let c = finding_id("sigma", &[sha.as_str()], &["e1", "e2"], &["ev1"]);
        assert_ne!(a, c, "finding_type が異なれば異なる Finding ID");
    }

    /// ID pattern 検証（Schema §3.1）。
    #[test]
    fn is_valid_id_checks() {
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("tf-case-v1:abc"));
        assert!(!is_valid_id("tf-unknown-v1:abc"));
        assert!(!is_valid_id("tf-case-v1:ABCDEF"));
        let ev = evidence_id("a", 1, &"a".repeat(64));
        assert!(is_valid_id(&ev));
    }
}
