// Amcache Parser fuzz target（T4-092、F-025、互換 §12-2）。
//
// libFuzzer が生成した raw bytes を Amcache.hve（registry hive 形式）と見なして
// Parser へ投げ、破損入力で panic しないことを検証する。
// `run_parser_catching_panic` が最終安全網。

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::ArtifactSource;
use tf_core::id;
use tf_parsers::amcache::{AmcacheParser, PARSER_ID, PARSER_VERSION};
use tf_parsers::framework::{
    ParseContext, ParseSink, ReadSeek, SinkError, run_parser_catching_panic,
};

struct NullSink;

impl ParseSink for NullSink {
    fn emit_event(&mut self, _event: tf_core::event::Event) -> Result<(), SinkError> {
        Ok(())
    }
    fn emit_issue(&mut self, _issue: tf_core::issue::Issue) -> Result<(), SinkError> {
        Ok(())
    }
}

fn make_context(data_len: u64) -> ParseContext {
    let sha = "0".repeat(64);
    let evidence = EvidenceItem {
        evidence_id: id::evidence_id("Amcache.hve", data_len, &sha),
        source_locator: "Amcache.hve".to_string(),
        size: data_len,
        sha256: sha,
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: String::new(),
    };
    let artifact_id = id::artifact_id(
        &evidence.evidence_id,
        ArtifactSource::Amcache.as_str(),
        PARSER_ID,
        PARSER_VERSION,
    );
    let artifact = ArtifactInstance {
        artifact_id,
        evidence_id: evidence.evidence_id.clone(),
        artifact_type: ArtifactSource::Amcache,
        parser_id: PARSER_ID.to_string(),
        parser_version: PARSER_VERSION.to_string(),
        probe_result: ProbeResult::Confirmed,
        detection_reasons: Vec::new(),
        parse_status: ParseStatus::Complete,
    };
    ParseContext { evidence, artifact }
}

fuzz_target!(|data: &[u8]| {
    let context = make_context(data.len() as u64);
    let parser = AmcacheParser::new();
    let mut cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut sink = NullSink;
    let snapshot: &mut dyn ReadSeek = &mut cursor;
    let _ = run_parser_catching_panic(&parser, snapshot, &context, &mut sink);
});
