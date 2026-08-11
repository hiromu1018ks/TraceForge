// Jump Lists Parser fuzz target（T4-092、F-025、互換 §12-2）。
//
// libFuzzer が生成した raw bytes を AutomaticDestinations / CustomDestinations
// 形式と見なして Parser へ投げ、破損入力で panic しないことを検証する。
// `run_parser_catching_panic` が最終安全網。

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::ArtifactSource;
use tf_core::id;
use tf_parsers::framework::{
    ParseContext, ParseSink, ReadSeek, SinkError, run_parser_catching_panic,
};
use tf_parsers::jump_lists::{JumpListParser, PARSER_ID, PARSER_VERSION};

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
    let locator = "b9105685df489b5b.automaticDestinations-ms";
    let evidence = EvidenceItem {
        evidence_id: id::evidence_id(locator, data_len, &sha),
        source_locator: locator.to_string(),
        size: data_len,
        sha256: sha,
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: String::new(),
    };
    let artifact_id = id::artifact_id(
        &evidence.evidence_id,
        ArtifactSource::JumpList.as_str(),
        PARSER_ID,
        PARSER_VERSION,
    );
    let artifact = ArtifactInstance {
        artifact_id,
        evidence_id: evidence.evidence_id.clone(),
        artifact_type: ArtifactSource::JumpList,
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
    let parser = JumpListParser::new();
    let mut cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut sink = NullSink;
    let snapshot: &mut dyn ReadSeek = &mut cursor;
    let _ = run_parser_catching_panic(&parser, snapshot, &context, &mut sink);
});
