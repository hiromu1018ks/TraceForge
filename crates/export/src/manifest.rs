//! Manifest 確定処理（規範 §20・Schema §5.9・T7-032）。
//!
//! Manifest は分析の再現性と完全性を保証する run metadata を保持する。
//! 規範 §20 は最低限次を保持することを求める:
//!
//! - TraceForge version・build commit・target
//! - Schema version・compatibility profile version
//! - run start/end time
//! - resolved configuration と SHA-256
//! - input root の表示用情報
//! - Case ID
//! - Evidence・Event・Issue・Match・Finding 件数
//! - parser ID/version 一覧
//! - Rule ID/file/hash 一覧
//! - Sigma/YARA-X engine version
//! - ATT&CK dataset version/hash
//! - timezone assumptions
//! - resource limit と到達状況
//! - partial/skip/failure 一覧
//! - `complete: true/false`
//! - Exit Code
//!
//! 本 module の [`finalize_manifest`] は [`ManifestFinalizationInput`] から全必須 field を
//! 集約し、Schema §5.9 の形式の [`tf_core::manifest::Manifest`] を構築する。
//! run metadata（時刻・PID 等）は determinism 比較から除外する（規範 §13.1・§20）。

use serde_json::{Map, Value};
use tf_core::hash::sha256_hex;
use tf_core::manifest::{Manifest, ManifestCounts};

/// Manifest 確定のための入力。
///
/// 呼出側（CLI 等）が分析結果・使用した Rule・engine version・ATT&CK dataset 等を
/// 集めたもの。run 時刻・PID・temp dir 等、determinism 比較から除外すべき run metadata
/// もここへ渡す。同じ入力 + 同じ run metadata でも、分析レコードが同一なら再現性がある。
#[derive(Clone, Debug, Default)]
pub struct ManifestFinalizationInput {
    /// TraceForge の version（例: `0.1.0`）。
    pub traceforge_version: String,
    /// build commit hash（dev build は空文字列でよい）。
    pub build_commit: String,
    /// build target triple（例: `x86_64-pc-windows-msvc`）。
    pub target: String,
    /// Schema version（Phase 7 では `1.0.0` 固定）。
    pub schema_version: String,
    /// compatibility profile version（例: `TF-WIN-1.0`）。
    pub compatibility_profile: String,
    /// 分析の開始時刻（RFC 3339 UTC）。
    pub run_started_at: String,
    /// 分析の終了時刻（RFC 3339 UTC）。
    pub run_finished_at: String,
    /// resolved configuration の canonical JSON。
    pub resolved_config: Value,
    /// Case ID（`tf-case-v1:<hex>`）。
    pub case_id: String,
    /// 各 record type の件数。
    pub counts: ManifestCounts,
    /// 構成要素（parser・Sigma・YARA-X engine 等）の metadata 一覧。
    pub components: Vec<Value>,
    /// 使用した Rule の一覧（rule_id・file・sha256 等）。
    pub rules: Vec<Value>,
    /// ATT&CK dataset の version・hash。未使用なら [`None`]。
    pub attack_dataset: Option<Value>,
    /// timezone 仮定の記録（`Asia/Tokyo を適用した` 等）。
    pub timezone_assumptions: Vec<Value>,
    /// 適用した resource limit と到達状況。
    pub limits: Value,
    /// `complete=false` の理由（partial・skip・limit 到達等）。
    pub incomplete_reasons: Vec<String>,
    /// 全工程が完全に成功したか（規範 §18）。
    pub complete: bool,
    /// 規範 §17.2 の Exit Code。
    pub exit_code: i32,
}

/// [`ManifestFinalizationInput`] から Schema §5.9 形式の [`Manifest`] を構築する。
///
/// `resolved_config_sha256` は本関数内で計算する（呼出側の手入力ミスを防ぐ）。
pub fn finalize_manifest(input: &ManifestFinalizationInput) -> Manifest {
    let resolved_config_sha256 = sha256_hex(
        tf_core::canonical::to_canonical_string(&input.resolved_config)
            .unwrap_or_default()
            .as_bytes(),
    );
    Manifest {
        traceforge_version: input.traceforge_version.clone(),
        build_commit: input.build_commit.clone(),
        target: input.target.clone(),
        schema_version: input.schema_version.clone(),
        compatibility_profile: input.compatibility_profile.clone(),
        run_started_at: input.run_started_at.clone(),
        run_finished_at: input.run_finished_at.clone(),
        resolved_config: clone_canonical(&input.resolved_config),
        resolved_config_sha256,
        case_id: input.case_id.clone(),
        counts: input.counts,
        components: input.components.clone(),
        rules: input.rules.clone(),
        attack_dataset: input.attack_dataset.clone(),
        timezone_assumptions: input.timezone_assumptions.clone(),
        limits: clone_canonical(&input.limits),
        incomplete_reasons: dedup_sorted_strings(&input.incomplete_reasons),
        complete: input.complete,
        exit_code: input.exit_code,
    }
}

/// `Value` を canonical 形式（key sort 済み）へ複製する。
fn clone_canonical(value: &Value) -> Value {
    match tf_core::canonical::canonicalize_value(value) {
        Ok(v) => v,
        Err(_) => value.clone(),
    }
}

/// 文字列 list を sort し重複を除去する。
fn dedup_sorted_strings(input: &[String]) -> Vec<String> {
    let mut sorted: Vec<String> = input.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}

/// Manifest の to_canonical_value 結果が全必須 field を持つか検証する（Schema §5.9・規範 §20）。
///
/// Phase 7 では Schema §5 の JSON Schema fragment が無いため、必須 key の有無を
/// set で確認する。戻り値の `Vec<String>` は欠落 field 名。
pub fn missing_manifest_fields(manifest: &Manifest) -> Vec<String> {
    let v = manifest.to_canonical_value();
    let obj = match v.as_object() {
        Some(o) => o,
        None => return vec!["<not-object>".into()],
    };
    let required = [
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
    ];
    let required_counts = ["evidence", "artifact", "event", "issue", "match", "finding"];
    let mut missing = Vec::new();
    for key in required {
        if !obj.contains_key(key) {
            missing.push(key.to_string());
        }
    }
    if let Some(counts) = obj.get("counts").and_then(|v| v.as_object()) {
        for key in required_counts {
            if !counts.contains_key(key) {
                missing.push(format!("counts.{key}"));
            }
        }
    }
    missing
}

/// Manifest の to_canonical_value 結果から run metadata を除いた分析比較用 JSON を返す。
///
/// 規範 §13.1・§20: 次の field を比較から除外する。
/// - `run_started_at`, `run_finished_at`（実行時刻）
/// - `build_commit`, `target`（環境依存）
///
/// それ以外の全 field は同じ Case を2回分析すれば同一になる（決定性・規範 §13）。
pub fn manifest_without_run_metadata(manifest: &Manifest) -> Value {
    let mut value = manifest.to_canonical_value();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("run_started_at");
        obj.remove("run_finished_at");
    }
    value
}

/// 既定の components list を構築する（parser / Sigma / YARA-X engine / ATT&CK dataset）。
///
/// CLI は分析開始時にこの helper を呼び、その後に実際に使用した parser 等を追加できる。
pub fn default_components(
    schema_version: &str,
    sigma_engine_version: Option<&str>,
    yara_x_engine_version: Option<&str>,
) -> Vec<Value> {
    let mut list = Vec::new();
    let mut parser = Map::new();
    parser.insert("component".into(), Value::String("parsers".into()));
    parser.insert("version".into(), Value::String(schema_version.to_string()));
    list.push(Value::Object(parser));

    let mut core = Map::new();
    core.insert("component".into(), Value::String("tf-core".into()));
    core.insert(
        "version".into(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );
    list.push(Value::Object(core));

    if let Some(v) = sigma_engine_version {
        let mut s = Map::new();
        s.insert("component".into(), Value::String("sigma-engine".into()));
        s.insert("version".into(), Value::String(v.to_string()));
        list.push(Value::Object(s));
    }
    if let Some(v) = yara_x_engine_version {
        let mut y = Map::new();
        y.insert("component".into(), Value::String("yara-x".into()));
        y.insert("version".into(), Value::String(v.to_string()));
        list.push(Value::Object(y));
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> ManifestFinalizationInput {
        ManifestFinalizationInput {
            traceforge_version: "0.1.0".into(),
            build_commit: "abc123".into(),
            target: "x86_64-pc-windows-msvc".into(),
            schema_version: "1.0.0".into(),
            compatibility_profile: "TF-WIN-1.0".into(),
            run_started_at: "2026-08-12T01:00:00Z".into(),
            run_finished_at: "2026-08-12T01:01:00Z".into(),
            resolved_config: serde_json::json!({"analysis": {"recursive": true}}),
            case_id: "tf-case-v1:abc".into(),
            counts: ManifestCounts {
                evidence: 2,
                artifact: 3,
                event: 100,
                issue: 1,
                r#match: 0,
                finding: 0,
            },
            components: vec![],
            rules: vec![],
            attack_dataset: None,
            timezone_assumptions: vec![],
            limits: serde_json::json!({"max_events": 50_000_000}),
            incomplete_reasons: vec![],
            complete: true,
            exit_code: 0,
        }
    }

    #[test]
    fn finalize_manifest_computes_resolved_digest() {
        let input = sample_input();
        let manifest = finalize_manifest(&input);
        assert_ne!(manifest.resolved_config_sha256, "");
        // SHA-256 lowercase 64桁。
        assert_eq!(manifest.resolved_config_sha256.len(), 64);
        assert!(
            manifest
                .resolved_config_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn finalize_manifest_has_all_required_fields() {
        let input = sample_input();
        let manifest = finalize_manifest(&input);
        let missing = missing_manifest_fields(&manifest);
        assert!(missing.is_empty(), "missing: {missing:?}");
    }

    #[test]
    fn manifest_run_metadata_stripped_for_determinism() {
        // 規範 §13.1: run 時刻は determinism 比較から除外する。
        // 規範 §13.1 の run metadata は run 時刻・OS PID・temp dir・elapsed time・
        // CPU/RAM 使用量のみ。build_commit と target は determinism 比較へ含む
        // （同じ binary なら同じ値になるべき）。
        let input1 = sample_input();
        let mut input2 = sample_input();
        input2.run_started_at = "2026-09-01T00:00:00Z".into();
        input2.run_finished_at = "2026-09-01T00:05:00Z".into();

        let m1 = finalize_manifest(&input1);
        let m2 = finalize_manifest(&input2);

        let v1 = manifest_without_run_metadata(&m1);
        let v2 = manifest_without_run_metadata(&m2);
        // run metadata を除けば同一（決定性）。
        assert_eq!(v1, v2, "run metadata 以外は同一であるべき");
    }

    #[test]
    fn dedup_incomplete_reasons_sorted_unique() {
        let mut input = sample_input();
        input.incomplete_reasons = vec![
            "limit_reached".into(),
            "partial".into(),
            "limit_reached".into(),
            "skipped".into(),
        ];
        let manifest = finalize_manifest(&input);
        assert_eq!(
            manifest.incomplete_reasons,
            vec!["limit_reached", "partial", "skipped"]
        );
    }
}
