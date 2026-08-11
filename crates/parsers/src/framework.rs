//! Parser 契約の共通 framework（規範 §9）。
//!
//! ここで定義する trait・型は全 Parser が従う契約を定める:
//!
//! - [`ArtifactParser`]: Parser の本体 interface（規範 §9.1）
//! - [`ParseSink`]: Event・Issue を1件ずつ流し込む sink（規範 §9.1: `Vec` 全件返却禁止）
//! - [`ParseContext`]: Parser が参照する Evidence・Artifact 情報
//! - [`ParseSummary`] / [`ParseStatus`]: 解析結果の集計（規範 §9.2）
//! - [`run_parser_catching_panic`]: Parser 境界の panic 捕捉 → Fatal 記録（規範 §9.4）
//!
//! 規範 §9.2「1 record の破損は [`ParseIssue`](crate::issue) として出力し、次 record の境界を
//! 安全に特定できる場合だけ継続する。境界を安全に特定できない場合、その ArtifactInstance を
//! [`ParseStatus::Partial`] で終了する。生成済み Event を破棄してはならない」は、
//! 各 Parser 実装が [`ParseSink`] へ1件ずつ出力することで自然に満たす。

use std::io::{Read, Seek};

use tf_core::case::{ArtifactInstance, EvidenceItem, ParseStatus, ProbeResult};
use tf_core::event::ArtifactSource;
use tf_core::event::Event;
use tf_core::issue::Issue;

use crate::issue::PANIC_FATAL_CODE;

/// `Read + Seek` を表す project 内 trait alias（規範 §9.1）。
///
/// Parser は元 Evidence ではなく snapshot（不変 copy）をこの trait 経由で読む（規範 §5.5）。
/// `Seek` が必要なのは、record 境界へ jump する際や、破損 record を飛ばす際のため。
pub trait ReadSeek: Read + Seek {}

/// 標準の `Read + Seek` 実装は全て [`ReadSeek`] を満たす（blanket impl）。
impl<T: Read + Seek> ReadSeek for T {}

/// Parser へ渡す実行時 context（規範 §9.1 の `ParseContext` に相当）。
///
/// Evidence と Artifact の metadata を保持し、Parser が [`Provenance`] や
/// [`Event::compute_id`] へ必要な値へアクセスできるようにする。
///
/// [`Provenance`]: tf_core::event::Provenance
#[derive(Clone, Debug)]
pub struct ParseContext {
    /// snapshot 検証済みの Evidence。`source_locator`・`evidence_id`・`source_sha256` を持つ。
    pub evidence: EvidenceItem,
    /// 識別済み Artifact instance。`artifact_id`・`parser_id`・`parser_version` を持つ。
    pub artifact: ArtifactInstance,
}

impl ParseContext {
    /// [`tf_core::event::Provenance`] を構築する（規範 §7.3）。
    ///
    /// Parser は各 record へ対応する Provenance をこの helper で作り、Event へ設定する。
    /// `record_locator` と `source_ordinal` は record 毎に指定する。
    pub fn make_provenance(
        &self,
        record_locator: tf_core::event::RecordLocator,
        source_ordinal: u64,
    ) -> tf_core::event::Provenance {
        tf_core::event::Provenance {
            evidence_id: self.evidence.evidence_id.clone(),
            artifact_id: self.artifact.artifact_id.clone(),
            source_locator: self.evidence.source_locator.clone(),
            source_sha256: self.evidence.sha256.clone(),
            parser_id: self.artifact.parser_id.clone(),
            parser_version: self.artifact.parser_version.clone(),
            record_locator,
            source_ordinal,
        }
    }
}

/// Event・Issue を1件ずつ受け取る sink（規範 §9.1）。
///
/// **全 Event を `Vec` で返してはならない**（規範 §9.1、AGENTS.md 禁止事項）。
/// Parser は1件生成するたびに [`ParseSink::emit_event`] / [`ParseSink::emit_issue`] を呼び、
/// [`SinkError`] が出たら安全な境界で解析を打ち切る。
///
/// この設計により、100万 Event でも Parser API が `Vec` を要求しない（規範 §21-6）。
pub trait ParseSink {
    /// Event を1件流し込む。Event ID は呼出側（Parser）が [`Event::compute_id`] で設定済みであること。
    fn emit_event(&mut self, event: Event) -> Result<(), SinkError>;

    /// Issue を1件流し込む（規範 §9.3）。
    fn emit_issue(&mut self, issue: Issue) -> Result<(), SinkError>;
}

/// [`ParseSink`] への書き込み失敗（規範 §9.1）。
///
/// Event Store の I/O error・Schema 違反・Event ID 重複等を包む。
/// 呼出側（Parser）はこの error を受けて安全な境界で解析を終える。
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// Event Store の書き込み失敗（規範 §10）。
    #[error("Event Store への書き込み失敗: {0}")]
    Store(#[from] tf_store::StoreError),
    /// その他の I/O error（snapshot 読取等）。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// 解析結果の集計（規範 §9.2）。
///
/// Parser は [`ArtifactParser::parse`] の戻り値として返す。[`ParseStatus::Partial`] の場合も
/// 生成済み Event は sink へ残り、破棄されない（規範 §9.2）。
///
/// [`Default`] 実装は [`ParseStatus::Skipped`]・件数 0 を返す（[`ParseSummary::skipped`] と同等）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseSummary {
    /// 解析の成否（規範 §9.2）。
    pub status: ParseStatus,
    /// 読み取った record 数。
    pub records_seen: u64,
    /// sink へ流し込んだ Event 数。
    pub events_emitted: u64,
    /// sink へ流し込んだ Issue 数。
    pub issues_emitted: u64,
    /// 消費した byte 数（snapshot の先頭からの累積）。
    pub bytes_consumed: u64,
}

impl Default for ParseSummary {
    fn default() -> Self {
        ParseSummary {
            status: ParseStatus::Skipped,
            records_seen: 0,
            events_emitted: 0,
            issues_emitted: 0,
            bytes_consumed: 0,
        }
    }
}

impl ParseSummary {
    /// 完全成功の summary を作る。
    pub fn complete(records_seen: u64, events_emitted: u64, issues_emitted: u64) -> Self {
        ParseSummary {
            status: ParseStatus::Complete,
            records_seen,
            events_emitted,
            issues_emitted,
            bytes_consumed: 0,
        }
    }

    /// 部分成功の summary を作る（規範 §9.2: 境界を特定できない破損）。
    pub fn partial(records_seen: u64, events_emitted: u64, issues_emitted: u64) -> Self {
        ParseSummary {
            status: ParseStatus::Partial,
            records_seen,
            events_emitted,
            issues_emitted,
            bytes_consumed: 0,
        }
    }

    /// 未対応形式・未対応 version 等で skip した summary。
    pub fn skipped() -> Self {
        ParseSummary {
            status: ParseStatus::Skipped,
            ..Default::default()
        }
    }

    /// 致命的失敗の summary を作る。
    pub fn failed() -> Self {
        ParseSummary {
            status: ParseStatus::Failed,
            ..Default::default()
        }
    }
}

/// 全 Parser が従う契約（規範 §9.1）。
///
/// 実装側は次を守ること:
///
/// - `parse` は全 Event を `Vec` で返さず、[`ParseSink`] へ1件ずつ出力する（規範 §9.1）。
/// - 入力起因の異常を panic で処理しない（規範 §9.4）。[`run_parser_catching_panic`] が
///   最終安全網となるが、Parser 自身は境界検証で [`ParseSummary::partial`] 等を返すべき。
/// - 観測していない行為を [`EventType`] で断定しない（規範 §7.1）。
/// - 必須 field 欠落 record は Event 化せず Issue 化する（互換 §5）。
///
/// [`EventType`]: tf_core::event::EventType
pub trait ArtifactParser {
    /// Parser の安定識別子（例: `traceforge-lnk`）。Provenance・Manifest へ記録される。
    fn parser_id(&self) -> &'static str;

    /// Parser の version（SemVer）。Event ID へ含まれる（規範 §12.3）。
    /// Event の意味が変わる変更で version を上げなければならない。
    fn parser_version(&self) -> &'static str;

    /// 対応する Artifact 種別（Schema §3.4）。
    fn artifact_type(&self) -> ArtifactSource;

    /// Evidence がこの Parser の対象形式か識別する（規範 §9.1・§11）。
    ///
    /// Evidence の snapshot file（`evidence.snapshot_locator`）の先頭 bytes から判定する。
    /// `evidence.integrity_status` が [`IntegrityStatus::VerifiedSnapshot`] 以外の場合は
    /// [`ProbeResult::NotThisFormat`] を返すのが安全（規範 §5.5: VerifiedSnapshot 以外は解析しない）。
    ///
    /// [`IntegrityStatus::VerifiedSnapshot`]: tf_core::case::IntegrityStatus::VerifiedSnapshot
    fn probe(&self, evidence: &EvidenceItem) -> ProbeResult;

    /// snapshot を解析し、Event・Issue を sink へ1件ずつ出力する（規範 §9.1）。
    ///
    /// `snapshot` は [`ReadSeek`]（`Read + Seek`）へ抽象化された不変 snapshot（規範 §5.5）。
    /// Parser はこの handle からのみ bytes を読む。元 Evidence を直接開いてはならない。
    fn parse(
        &self,
        snapshot: &mut dyn ReadSeek,
        context: &ParseContext,
        sink: &mut dyn ParseSink,
    ) -> ParseSummary;
}

/// Parser 境界の panic を捕捉し、Fatal issue と [`ParseSummary::failed`] を生成する（規範 §9.4）。
///
/// 規範 §9.4「入力起因の異常を panic で処理してはならない。Parser 境界では panic を検出して
/// 内部 Fatal error として記録し、process を Exit Code 10 で停止する。panic 後に解析結果を
/// 正常結果として出力してはならない」。
///
/// この関数は [`ArtifactParser::parse`] を [`std::panic::catch_unwind`] で包み、panic を
/// [`ParseStatus::Failed`] へ変換する。panic の message は [`SinkError`] 経由ではなく、
/// Fatal issue として sink へ記録される。呼出側は戻り値の [`ParseSummary`] と sink へ蓄積
/// された issue から Exit Code 10 を最終的に判定する。
///
/// なお、Rust の panic は `catch_unwind` で全て捕捉できるとは限らない（`abort` 設定時や
/// 一部の FFI panic）。本関数は `unwind` 既定動作を前提とする。
pub fn run_parser_catching_panic(
    parser: &dyn ArtifactParser,
    snapshot: &mut dyn ReadSeek,
    context: &ParseContext,
    sink: &mut dyn ParseSink,
) -> ParseSummary {
    let parser_id = parser.parser_id();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parser.parse(snapshot, context, sink)
    }));

    match result {
        Ok(summary) => summary,
        Err(panic_payload) => {
            // panic message を取り出す（任意の型が渡されるため best-effort）。
            let message = panic_payload
                .downcast_ref::<&'static str>()
                .map(|s| s.to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic（message 取得不可）".to_string());

            // 規範 §9.4: panic は Fatal issue として記録。
            let issue = Issue {
                issue_id: PANIC_FATAL_CODE.to_string(),
                severity: tf_core::issue::IssueSeverity::Fatal,
                scope: tf_core::issue::IssueScope::Artifact,
                evidence_id: Some(context.evidence.evidence_id.clone()),
                artifact_id: Some(context.artifact.artifact_id.clone()),
                record_locator: None,
                source_ordinal: None,
                message: crate::issue::sanitize_issue_message(&format!(
                    "Parser '{parser_id}' が panic した: {message}"
                )),
            };
            // sink への issue 出力が更に失敗しても、ParseSummary::failed で伝える。
            let _ = sink.emit_issue(issue);
            ParseSummary::failed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use tf_core::case::{IntegrityStatus, ProbeResult};
    use tf_core::event::{ArtifactSource, AssertionKind, EventType, RecordLocator};
    use tf_core::time::{EventTime, TimePrecision, TimestampKind, TimezoneSource};

    /// テスト用の最小 ParseContext。
    fn sample_context() -> ParseContext {
        ParseContext {
            evidence: EvidenceItem {
                evidence_id: "tf-evidence-v1:test".to_string(),
                source_locator: "sample.lnk".to_string(),
                size: 100,
                sha256: "ab".repeat(32),
                integrity_status: IntegrityStatus::VerifiedSnapshot,
                parse_eligible: true,
                snapshot_locator: String::new(),
            },
            artifact: ArtifactInstance {
                artifact_id: "tf-artifact-v1:test".to_string(),
                evidence_id: "tf-evidence-v1:test".to_string(),
                artifact_type: ArtifactSource::Lnk,
                parser_id: "traceforge-test".to_string(),
                parser_version: "1.0.0".to_string(),
                probe_result: ProbeResult::Confirmed,
                detection_reasons: vec!["test".to_string()],
                parse_status: ParseStatus::Complete,
            },
        }
    }

    /// テスト用の Event を作る。
    fn sample_event(context: &ParseContext, ordinal: u64) -> Event {
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
            message: "test".to_string(),
            attributes: BTreeMap::new(),
            provenance: context.make_provenance(RecordLocator::SourceOrdinal, 0),
        };
        event.id = event.compute_id(ordinal);
        event
    }

    /// sink の代わりに Event と Issue を蓄積するテスト用 collector。
    struct CollectorSink {
        events: Vec<Event>,
        issues: Vec<Issue>,
        fail_after: Option<usize>,
    }

    impl CollectorSink {
        fn new() -> Self {
            CollectorSink {
                events: Vec::new(),
                issues: Vec::new(),
                fail_after: None,
            }
        }
    }

    impl ParseSink for CollectorSink {
        fn emit_event(&mut self, event: Event) -> Result<(), SinkError> {
            if let Some(limit) = self.fail_after
                && self.events.len() >= limit
            {
                return Err(SinkError::Io(std::io::Error::other("sink limit")));
            }
            self.events.push(event);
            Ok(())
        }

        fn emit_issue(&mut self, issue: Issue) -> Result<(), SinkError> {
            self.issues.push(issue);
            Ok(())
        }
    }

    /// 1 Event を生成して完了するテスト用 Parser。
    struct OneEventParser;

    impl ArtifactParser for OneEventParser {
        fn parser_id(&self) -> &'static str {
            "traceforge-test-one"
        }
        fn parser_version(&self) -> &'static str {
            "1.0.0"
        }
        fn artifact_type(&self) -> ArtifactSource {
            ArtifactSource::Lnk
        }
        fn probe(&self, _evidence: &EvidenceItem) -> ProbeResult {
            ProbeResult::Confirmed
        }
        fn parse(
            &self,
            _snapshot: &mut dyn ReadSeek,
            context: &ParseContext,
            sink: &mut dyn ParseSink,
        ) -> ParseSummary {
            let event = sample_event(context, 0);
            sink.emit_event(event).expect("emit_event");
            ParseSummary::complete(1, 1, 0)
        }
    }

    /// 必ず panic するテスト用 Parser（規範 §9.4 検証）。
    struct PanickingParser;

    impl ArtifactParser for PanickingParser {
        fn parser_id(&self) -> &'static str {
            "traceforge-test-panic"
        }
        fn parser_version(&self) -> &'static str {
            "1.0.0"
        }
        fn artifact_type(&self) -> ArtifactSource {
            ArtifactSource::Lnk
        }
        fn probe(&self, _evidence: &EvidenceItem) -> ProbeResult {
            ProbeResult::Confirmed
        }
        fn parse(
            &self,
            _snapshot: &mut dyn ReadSeek,
            _context: &ParseContext,
            _sink: &mut dyn ParseSink,
        ) -> ParseSummary {
            panic!("意図的な panic（テスト）");
        }
    }

    #[test]
    fn readseek_blanket_impl_for_cursor() {
        // Cursor<Vec<u8>> は Read + Seek を実装するため ReadSeek を満たす。
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let _reader: &mut dyn ReadSeek = &mut cursor;
    }

    #[test]
    fn parse_context_make_provenance_carries_ids() {
        let context = sample_context();
        let prov = context.make_provenance(RecordLocator::ByteOffset(10), 3);
        assert_eq!(prov.evidence_id, "tf-evidence-v1:test");
        assert_eq!(prov.artifact_id, "tf-artifact-v1:test");
        assert_eq!(prov.source_locator, "sample.lnk");
        assert_eq!(prov.parser_id, "traceforge-test");
        assert_eq!(prov.parser_version, "1.0.0");
        assert_eq!(prov.source_ordinal, 3);
        assert!(matches!(prov.record_locator, RecordLocator::ByteOffset(10)));
    }

    #[test]
    fn artifact_parser_emits_via_sink() {
        let parser = OneEventParser;
        let mut cursor = Cursor::new(Vec::new());
        let context = sample_context();
        let mut sink = CollectorSink::new();

        let summary = parser.parse(&mut cursor, &context, &mut sink);

        assert_eq!(summary.status, ParseStatus::Complete);
        assert_eq!(summary.events_emitted, 1);
        assert_eq!(sink.events.len(), 1);
        // Event ID が compute_id で設定されている。
        assert!(sink.events[0].id.starts_with("tf-event-v1:"));
    }

    #[test]
    fn panic_is_caught_and_converted_to_failed() {
        // 規範 §9.4: Parser 境界の panic は Fatal issue + Failed summary。
        let parser = PanickingParser;
        let mut cursor = Cursor::new(Vec::new());
        let context = sample_context();
        let mut sink = CollectorSink::new();

        let summary = run_parser_catching_panic(&parser, &mut cursor, &context, &mut sink);

        assert_eq!(summary.status, ParseStatus::Failed);
        // Fatal issue が1件記録される。
        assert_eq!(sink.issues.len(), 1);
        assert_eq!(sink.issues[0].issue_id, PANIC_FATAL_CODE);
        assert_eq!(
            sink.issues[0].severity,
            tf_core::issue::IssueSeverity::Fatal
        );
        assert!(sink.issues[0].message.contains("traceforge-test-panic"));
    }

    #[test]
    fn sink_error_aborts_parser() {
        // Parser は SinkError を受けたら安全に終了する設計。この test は
        // sink が限界へ達した際の挙動を検証する。
        let parser = OneEventParser;
        let mut cursor = Cursor::new(Vec::new());
        let context = sample_context();
        let mut sink = CollectorSink::new();
        sink.fail_after = Some(0); // 即座に失敗。

        // Parser 実装が expect しているため panic するが、これは Parser 実装の責務。
        // 実運用では Result で処理する。ここでは trait 契約の確認のみ。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            parser.parse(&mut cursor, &context, &mut sink)
        }));
        assert!(
            result.is_err(),
            "sink 失敗時は Parser 側で panic しない設計が望ましいが、テスト用 Parser は expect している"
        );
    }

    #[test]
    fn parse_summary_constructors() {
        let complete = ParseSummary::complete(3, 2, 1);
        assert_eq!(complete.status, ParseStatus::Complete);
        assert_eq!(complete.records_seen, 3);

        let partial = ParseSummary::partial(5, 3, 2);
        assert_eq!(partial.status, ParseStatus::Partial);

        let skipped = ParseSummary::skipped();
        assert_eq!(skipped.status, ParseStatus::Skipped);

        let failed = ParseSummary::failed();
        assert_eq!(failed.status, ParseStatus::Failed);
    }
}
