//! [`EventStore`] への [`ParseSink`] 適応（規範 §9.1・§10）。
//!
//! Parser が生成した Event を [`tf_store::EventStore`] へ逐次保存し、Issue を
//! [`Vec<Issue>`] へ蓄積する [`ParseSink`] 実装を提供する。
//!
//! これにより Parser framework と Event Store が「sink 型 interface」で結合し、
//! 100万 Event でも Parser API が `Vec` を要求しない（規範 §21-6）。

use tf_core::event::Event;
use tf_core::issue::Issue;
use tf_store::EventStore;

use crate::framework::{ParseSink, SinkError};

/// [`EventStore`] と [`Vec<Issue>`] を束ねた [`ParseSink`]（規範 §9.1・§10）。
///
/// - [`ParseSink::emit_event`]: [`EventStore::store_event`] へ委譲。Schema validation・
///   Event ID 一意制約・commit marker の各検証は EventStore 側が行う（規範 §10）。
/// - [`ParseSink::emit_issue`]: `issues` vector へ蓄積。呼出側が整列・出力する。
///
/// `issues` は参照で受け取るため、呼出側が所有権を保持したまま複数 Parser へ使い回せる。
pub struct EventStoreSink<'a> {
    store: &'a mut EventStore,
    issues: &'a mut Vec<Issue>,
}

impl<'a> EventStoreSink<'a> {
    /// EventStore と Issue 蓄積先を束ねた sink を作る。
    pub fn new(store: &'a mut EventStore, issues: &'a mut Vec<Issue>) -> Self {
        EventStoreSink { store, issues }
    }
}

impl<'a> ParseSink for EventStoreSink<'a> {
    fn emit_event(&mut self, event: Event) -> Result<(), SinkError> {
        self.store.store_event(&event)?;
        Ok(())
    }

    fn emit_issue(&mut self, issue: Issue) -> Result<(), SinkError> {
        self.issues.push(issue);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::ParseContext;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use tf_core::case::{
        ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult,
    };
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
    use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

    fn sample_context() -> ParseContext {
        ParseContext {
            evidence: EvidenceItem {
                evidence_id: "tf-evidence-v1:sink-test".to_string(),
                source_locator: "test.lnk".to_string(),
                size: 1,
                sha256: "ab".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:sink-test".to_string(),
                evidence_id: "tf-evidence-v1:sink-test".to_string(),
                artifact_type: ArtifactSource::Lnk,
                parser_id: "traceforge-lnk".to_string(),
                parser_version: "1.0.0".to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["test".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    fn sample_event(context: &ParseContext) -> Event {
        let mut event = Event {
            id: String::new(),
            time: EventTime::utc_instant(
                "2026-08-10T01:00:00Z".parse().unwrap(),
                None,
                TimestampKind::Created,
                TimePrecision::Second,
                TimezoneSource::ArtifactDefined,
            ),
            source: ArtifactSource::Lnk,
            event_type: EventType::new("lnk_timestamp"),
            assertion: AssertionKind::Observed,
            hostname: None,
            user: None,
            path: None,
            program: None,
            process: None,
            message: "sink test".to_string(),
            attributes: BTreeMap::new(),
            provenance: context.make_provenance(RecordLocator::SourceOrdinal, 0),
        };
        event.id = event.compute_id(0);
        event
    }

    #[test]
    fn event_store_sink_emits_event_to_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        let mut issues: Vec<Issue> = Vec::new();
        let context = sample_context();

        {
            let mut sink = EventStoreSink::new(&mut store, &mut issues);
            let event = sample_event(&context);
            sink.emit_event(event).unwrap();
        }

        assert_eq!(store.len(), 1);
        assert!(issues.is_empty());
    }

    #[test]
    fn event_store_sink_accumulates_issues() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        let mut issues: Vec<Issue> = Vec::new();

        {
            let mut sink = EventStoreSink::new(&mut store, &mut issues);
            let issue = Issue {
                issue_id: "TF-W-PARSER-TEST".to_string(),
                severity: tf_core::issue::IssueSeverity::Warning,
                scope: tf_core::issue::IssueScope::Record,
                evidence_id: Some("tf-evidence-v1:x".to_string()),
                artifact_id: None,
                record_locator: None,
                source_ordinal: Some(0),
                message: "test issue".to_string(),
            };
            sink.emit_issue(issue).unwrap();
        }

        assert_eq!(store.len(), 0);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue_id, "TF-W-PARSER-TEST");
    }

    #[test]
    fn duplicate_event_id_reports_sink_error() {
        // 規範 §10: Event ID 一意制約。EventStoreSink は StoreError を伝える。
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.spool");
        let mut store = EventStore::create(&path).unwrap();
        let mut issues: Vec<Issue> = Vec::new();
        let context = sample_context();
        let event = sample_event(&context);

        {
            let mut sink = EventStoreSink::new(&mut store, &mut issues);
            sink.emit_event(event.clone()).unwrap();
            // 同一 Event ID を再送。
            let result = sink.emit_event(event);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SinkError::Store(_)));
        }
    }
}
