// LNK Parser fuzz target（T4-092、F-025、互換 §12-2）。
//
// libFuzzer が生成した raw bytes を LNK 形式と見なして Parser へ投げ、
// 破損入力で panic しないことを継続的 fuzzing で検証する。
//
// `run_parser_catching_panic` が Parser 内部の panic を最終安全網として捕捉する
// （規範 §9.4）。本 target が promise するのは「panic で process が落ちはしない」こと。
// fuzzing の実行は Linux CI のみで行う（Windows MSVC では libfuzzer-sys の link が
// 失敗するため、本プロジェクトでは `cargo check --manifest-path fuzz/Cargo.toml` で
// ビルド検証する）。

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use tf_core::case::{ArtifactInstance, EvidenceItem, IntegrityStatus, ParseStatus, ProbeResult};
use tf_core::event::ArtifactSource;
use tf_core::id;
use tf_parsers::framework::{
    ParseContext, ParseSink, ReadSeek, SinkError, run_parser_catching_panic,
};
use tf_parsers::lnk::{LnkParser, PARSER_ID, PARSER_VERSION};

/// Event・Issue を全て捨てるだけの sink（fuzz では Parser が生成した中身の正確性は
/// 検証せず、panic しないことだけを検証する）。
struct NullSink;

impl ParseSink for NullSink {
    fn emit_event(&mut self, _event: tf_core::event::Event) -> Result<(), SinkError> {
        Ok(())
    }
    fn emit_issue(&mut self, _issue: tf_core::issue::Issue) -> Result<(), SinkError> {
        Ok(())
    }
}

/// fuzz 用の最小 `ParseContext` を構築する。
///
/// 決定的 ID 生成（規範 §12）を守るため、`evidence_id` は size から決める。
/// SHA-256 は固定値とする（fuzz では Provenance 検証が主目的ではない）。
fn make_context(data_len: u64) -> ParseContext {
    let sha = "0".repeat(64);
    let evidence = EvidenceItem {
        evidence_id: id::evidence_id("test.lnk", data_len, &sha),
        source_locator: "test.lnk".to_string(),
        size: data_len,
        sha256: sha,
        integrity_status: IntegrityStatus::VerifiedSnapshot,
        parse_eligible: true,
        snapshot_locator: String::new(),
    };
    let artifact_id = id::artifact_id(
        &evidence.evidence_id,
        ArtifactSource::Lnk.as_str(),
        PARSER_ID,
        PARSER_VERSION,
    );
    let artifact = ArtifactInstance {
        artifact_id,
        evidence_id: evidence.evidence_id.clone(),
        artifact_type: ArtifactSource::Lnk,
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
    let parser = LnkParser::new();
    let mut cursor: Cursor<&[u8]> = Cursor::new(data);
    let mut sink = NullSink;
    let snapshot: &mut dyn ReadSeek = &mut cursor;
    let _ = run_parser_catching_panic(&parser, snapshot, &context, &mut sink);
});
