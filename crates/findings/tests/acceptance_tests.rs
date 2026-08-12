//! Phase 6 Finding 統合と ATT&CK の統合テスト（T6-001〜T6-009）。
//!
//! 規範 §16（Finding）・§15.3（ATT&CK mapping）・§12.4（Finding ID）・製品 §10
//! （Correlation と Finding の説明可能性要件）・互換 §9（ATT&CK dataset）の
//! 受け入れ条件を end-to-end で検証する。

use std::collections::BTreeSet;

use tf_core::case::Severity;
use tf_core::finding::{AttackMappingSource, ConfidenceLevel, Score, ScoreAdjustment};
use tf_core::id::{finding_id, match_id};
use tf_core::r#match::{Match, MatchType};
use tf_findings::attack::{
    AttackDataset, AttackDatasetManifest, UnknownTechniqueError, built_in_mappings,
    extract_attack_tags_from_sigma, from_correlation_rule, from_sigma_rule_tags, manual_mapping,
    validate_technique_id_format, validate_technique_ids,
};
use tf_findings::{
    FindingBuilder, FindingMergeOptions, FindingMergeRule, MergeGroupId, attach_attack_mappings,
};

// ============================================================================
// helpers
// ============================================================================

fn sha64(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn make_match(
    match_type: MatchType,
    rule_id: &str,
    rule_sha: &str,
    event_ids: &[&str],
    evidence_ids: &[&str],
    score: Option<Score>,
) -> Match {
    let ordered: Vec<&str> = event_ids.to_vec();
    let mid = match_id(rule_id, rule_sha, &ordered);
    Match {
        match_id: mid,
        match_type,
        rule_id: rule_id.to_string(),
        rule_sha256: rule_sha.to_string(),
        event_ids: event_ids.iter().map(|s| s.to_string()).collect(),
        evidence_ids: evidence_ids.iter().map(|s| s.to_string()).collect(),
        reasons: vec![format!("test match for {rule_id}")],
        score,
        ordered_event_ids: Some(event_ids.iter().map(|s| s.to_string()).collect()),
        logsource_mapping: None,
        matched_patterns: None,
    }
}

fn make_dataset_with(technique_ids: &[&str]) -> AttackDataset {
    let mut bundle = String::from(r#"{"type":"bundle","id":"bundle--x","objects":["#);
    for (i, tid) in technique_ids.iter().enumerate() {
        if i > 0 {
            bundle.push(',');
        }
        bundle.push_str(&format!(
            r#"{{"type":"attack-pattern","id":"attack-pattern--{i:032x}","name":"name-{tid}","external_references":[{{"source_name":"mitre-attack","external_id":"{tid}"}}],"kill_chain_phases":[{{"kill_chain_name":"mitre-attack","phase_name":"execution"}}]}}"#
        ));
    }
    bundle.push_str("]}");
    let bytes = bundle.into_bytes();
    let manifest = AttackDatasetManifest {
        version: "15.1".into(),
        sha256: String::new(),
        source_url: "https://example.com/attack-stix".into(),
        retrieved_at: "2026-08-12T00:00:00Z".into(),
    };
    AttackDataset::from_stix_bytes(&bytes, manifest).expect("dataset parse")
}

// ============================================================================
// T6-001: Finding merger（match 喪失なし）
// ============================================================================

#[test]
fn t6_001_finding_merger_no_match_loss() {
    let matches = vec![
        make_match(
            MatchType::Sigma,
            "sigma-rule-1",
            &sha64('a'),
            &["tf-event-v1:e1"],
            &["tf-evidence-v1:ev1"],
            None,
        ),
        make_match(
            MatchType::YaraX,
            "yara-rule-1",
            &sha64('b'),
            &[],
            &["tf-evidence-v1:ev2"],
            None,
        ),
        make_match(
            MatchType::Correlation,
            "TF-CORR-001",
            &sha64('c'),
            &["tf-event-v1:e1", "tf-event-v1:e2"],
            &["tf-evidence-v1:ev1"],
            Some(Score {
                base: 0.8,
                adjustments: vec![],
            }),
        ),
    ];

    let summary = FindingBuilder::default().build(&matches).expect("build ok");

    // T6-001: match 喪失なし。入力 Match 全てが Finding の match_ids へ出現する。
    let input_ids: BTreeSet<String> = matches.iter().map(|m| m.match_id.clone()).collect();
    assert!(
        summary.all_matches_referenced(&input_ids),
        "全 Match が Finding へ統合されている（match 喪失なし）"
    );
    assert_eq!(summary.input_match_count, 3);
    // 統合 rule 無し → 1:1 変換で 3 Finding。
    assert_eq!(summary.findings.len(), 3);
}

// ============================================================================
// T6-002: 自動統合禁止（明示統合 rule のみ）
// ============================================================================

#[test]
fn t6_002_no_automatic_merge_on_shared_events() {
    // 2 Match が同じ Event と Evidence を参照していても自動統合しない。
    let matches = vec![
        make_match(
            MatchType::Sigma,
            "sigma-A",
            &sha64('a'),
            &["tf-event-v1:shared"],
            &["tf-evidence-v1:shared"],
            None,
        ),
        make_match(
            MatchType::YaraX,
            "yara-A",
            &sha64('b'),
            &[],
            &["tf-evidence-v1:shared"],
            None,
        ),
    ];

    let summary = FindingBuilder::default().build(&matches).expect("build ok");

    assert_eq!(
        summary.findings.len(),
        2,
        "共通 Event/Evidence を理由に自動統合してはならない（規範 §16）"
    );
    for f in &summary.findings {
        assert_eq!(f.match_ids.len(), 1, "各 Finding は独立");
    }
}

#[test]
fn t6_002_explicit_merge_rule_combines_only_listed_rules() {
    let matches = vec![
        make_match(
            MatchType::Sigma,
            "sigma-A",
            &sha64('a'),
            &["tf-event-v1:e1"],
            &["tf-evidence-v1:ev1"],
            None,
        ),
        make_match(
            MatchType::YaraX,
            "yara-A",
            &sha64('b'),
            &[],
            &["tf-evidence-v1:ev2"],
            None,
        ),
        make_match(
            MatchType::Correlation,
            "TF-CORR-001",
            &sha64('c'),
            &["tf-event-v1:e1"],
            &["tf-evidence-v1:ev1"],
            None,
        ),
    ];

    let options = FindingMergeOptions {
        merge_rules: vec![FindingMergeRule {
            group_id: MergeGroupId::new("TF-FINDING-MERGE-001"),
            rule_ids: vec!["sigma-A".into(), "yara-A".into()],
            title: "Suspicious cluster".into(),
            description: "Combined detection".into(),
            severity: Severity::High,
            confidence_score: 0.85,
            inference: vec![],
        }],
        default_severity: None,
        default_confidence_score: None,
    };
    let summary = FindingBuilder::new(options)
        .build(&matches)
        .expect("build ok");

    // 統合 rule が sigma-A と yara-A を1つにまとめ、TF-CORR-001 は独立。
    assert_eq!(summary.findings.len(), 2);
    assert_eq!(summary.merged_match_count, 2);
    let merged = summary
        .findings
        .iter()
        .find(|f| f.match_ids.len() == 2)
        .expect("統合 Finding がある");
    assert_eq!(merged.title, "Suspicious cluster");

    // 全 Match が参照されている。
    let input_ids: BTreeSet<String> = matches.iter().map(|m| m.match_id.clone()).collect();
    assert!(summary.all_matches_referenced(&input_ids));
}

// ============================================================================
// T6-003: Finding 必須 field
// ============================================================================

#[test]
fn t6_003_finding_required_fields_populated() {
    let matches = vec![make_match(
        MatchType::Correlation,
        "TF-CORR-001",
        &sha64('a'),
        &["tf-event-v1:e1", "tf-event-v1:e2"],
        &["tf-evidence-v1:ev1"],
        Some(Score {
            base: 0.75,
            adjustments: vec![ScoreAdjustment {
                reason: "exact".into(),
                value: 0.1,
            }],
        }),
    )];

    let summary = FindingBuilder::default().build(&matches).expect("build ok");
    let f = &summary.findings[0];

    // Schema §5.8 の必須 field 群（規範 §16）
    assert!(
        tf_core::id::is_valid_id(&f.finding_id),
        "finding_id は valid pattern"
    );
    assert!(!f.title.is_empty());
    assert!(!f.description.is_empty());
    // severity / confidence
    let _ = f.severity;
    assert!(f.confidence.score >= 0.0 && f.confidence.score <= 1.0);
    // 参照 ID 群: event_ids / evidence_ids / match_ids / rule_refs
    assert!(!f.event_ids.is_empty());
    assert!(!f.evidence_ids.is_empty());
    assert!(!f.match_ids.is_empty());
    assert!(!f.rule_refs.is_empty());
    assert_eq!(f.rule_refs[0].rule_sha256, sha64('a'));
    // 観測事実 / 推論
    assert!(!f.observed_evidence.is_empty());
    assert!(!f.inference.is_empty());
    // created_at を持ってはならない（Schema §5.8）
    assert!(
        !f.to_canonical_value()
            .as_object()
            .unwrap()
            .contains_key("created_at")
    );
}

// ============================================================================
// T6-004: observed_evidence と inference の分離
// ============================================================================

#[test]
fn t6_004_observed_evidence_does_not_contain_inferences() {
    let matches = vec![
        make_match(
            MatchType::Sigma,
            "sigma-X",
            &sha64('a'),
            &["tf-event-v1:e1"],
            &["tf-evidence-v1:ev1"],
            None,
        ),
        make_match(
            MatchType::YaraX,
            "yara-X",
            &sha64('b'),
            &[],
            &["tf-evidence-v1:ev2"],
            None,
        ),
    ];
    let summary = FindingBuilder::default().build(&matches).expect("build ok");

    for f in &summary.findings {
        // observed_evidence は客観的情報のみ。
        for obs in &f.observed_evidence {
            // 推論語（"should investigate"・"likely incident" 等）を含まない。
            let lower = obs.to_ascii_lowercase();
            assert!(
                !lower.contains("investigate")
                    && !lower.contains("likely incident")
                    && !lower.contains("may indicate"),
                "observed_evidence に推論が混入: {obs}"
            );
        }
        // inference は推論を含む。
        assert!(
            f.inference
                .iter()
                .any(|i| i.contains("Investigate") || i.contains("matches merged")),
            "inference に推論文がある: {:?}",
            f.inference
        );
    }
}

// ============================================================================
// T6-005: 参照検証（製品 §10）
// ============================================================================

#[test]
fn t6_005_finding_references_all_originals() {
    let matches = vec![
        make_match(
            MatchType::Sigma,
            "sigma-1",
            &sha64('a'),
            &["tf-event-v1:e1", "tf-event-v1:e2"],
            &["tf-evidence-v1:ev1"],
            None,
        ),
        make_match(
            MatchType::YaraX,
            "yara-1",
            &sha64('b'),
            &[],
            &["tf-evidence-v1:ev2"],
            None,
        ),
        make_match(
            MatchType::Correlation,
            "TF-CORR-001",
            &sha64('c'),
            &["tf-event-v1:e1", "tf-event-v1:e3"],
            &["tf-evidence-v1:ev1", "tf-evidence-v1:ev3"],
            None,
        ),
    ];

    let summary = FindingBuilder::default().build(&matches).expect("build ok");

    // 全 Event ID が Finding の event_ids へ到達できる。
    let mut all_event_ids: BTreeSet<String> = BTreeSet::new();
    let mut all_evidence_ids: BTreeSet<String> = BTreeSet::new();
    let mut all_rule_shas: BTreeSet<String> = BTreeSet::new();
    let mut all_match_ids: BTreeSet<String> = BTreeSet::new();
    for m in &matches {
        for e in &m.event_ids {
            all_event_ids.insert(e.clone());
        }
        for e in &m.evidence_ids {
            all_evidence_ids.insert(e.clone());
        }
        all_rule_shas.insert(m.rule_sha256.clone());
        all_match_ids.insert(m.match_id.clone());
    }

    let mut finding_event_ids: BTreeSet<String> = BTreeSet::new();
    let mut finding_evidence_ids: BTreeSet<String> = BTreeSet::new();
    let mut finding_rule_shas: BTreeSet<String> = BTreeSet::new();
    let mut finding_match_ids: BTreeSet<String> = BTreeSet::new();
    for f in &summary.findings {
        for e in &f.event_ids {
            finding_event_ids.insert(e.clone());
        }
        for e in &f.evidence_ids {
            finding_evidence_ids.insert(e.clone());
        }
        for r in &f.rule_refs {
            finding_rule_shas.insert(r.rule_sha256.clone());
        }
        for m in &f.match_ids {
            finding_match_ids.insert(m.clone());
        }
    }

    // 製品 §10: Finding から全元 Event・Evidence・Rule hash へ参照が到達できる。
    assert_eq!(finding_event_ids, all_event_ids, "全 Event ID が到達可能");
    assert_eq!(
        finding_evidence_ids, all_evidence_ids,
        "全 Evidence ID が到達可能"
    );
    assert_eq!(
        finding_rule_shas, all_rule_shas,
        "全 Rule SHA-256 が到達可能"
    );
    assert_eq!(finding_match_ids, all_match_ids, "全 Match ID が到達可能");
}

// ============================================================================
// T6-006: ATT&CK STIX dataset の version pin・SHA-256・取得元記録
// ============================================================================

#[test]
fn t6_006_attack_dataset_manifest_records_version_sha_and_source() {
    let bundle_bytes = r#"{
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                "name": "PowerShell",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ]
            }
        ]
    }"#
    .as_bytes()
    .to_vec();

    let manifest = AttackDatasetManifest {
        version: "15.1".into(),
        sha256: String::new(), // 自動計算させる
        source_url: "https://github.com/mitre/cti/releases/tag/15.1".into(),
        retrieved_at: "2026-08-12T00:00:00Z".into(),
    };
    let ds = AttackDataset::from_stix_bytes(&bundle_bytes, manifest).expect("dataset load ok");

    // version・SHA-256・source_url が manifest へ記録されている。
    assert_eq!(ds.manifest.version, "15.1");
    assert!(tf_core::hash::is_lowercase_sha256_hex(&ds.manifest.sha256));
    assert_eq!(
        ds.manifest.source_url,
        "https://github.com/mitre/cti/releases/tag/15.1"
    );

    // Schema §5.9 の attack_dataset field 形式へ出力できる。
    let v = ds.manifest.to_canonical_value();
    let obj = v.as_object().unwrap();
    assert_eq!(obj["version"], "15.1");
    assert!(obj["sha256"].is_string());
    assert_eq!(
        obj["source_url"],
        "https://github.com/mitre/cti/releases/tag/15.1"
    );
    assert_eq!(obj["retrieved_at"], "2026-08-12T00:00:00Z");
}

// ============================================================================
// T6-007: Technique ID の dataset 存在検証
// ============================================================================

#[test]
fn t6_007_unknown_technique_id_is_validation_error() {
    let ds = make_dataset_with(&["T1059", "T1059.001"]);

    // 形式検証
    assert!(validate_technique_id_format("T1059").is_ok());
    assert!(validate_technique_id_format("T1059.001").is_ok());
    assert!(validate_technique_id_format("bad-format").is_err());

    // 存在検証: dataset に無い ID は error（互換 §9）。
    let result = validate_technique_ids(&["T9999".to_string()], &ds);
    assert!(
        matches!(result, Err(UnknownTechniqueError::NotInDataset { id, version }) if id == "T9999" && version == "15.1"),
        "不在 ID は NotInDataset error"
    );

    // 存在する ID は通る。
    validate_technique_ids(&["T1059".to_string(), "T1059.001".to_string()], &ds)
        .expect("known IDs pass");
}

// ============================================================================
// T6-008: ATT&CK mapping 生成（Rule / Sigma tag / built-in / manual）
// ============================================================================

#[test]
fn t6_008_attack_mapping_from_correlation_rule() {
    let ds = make_dataset_with(&["T1059", "T1059.001"]);
    let mappings =
        from_correlation_rule("TF-CORR-001", &["T1059.001".to_string()], Some(&ds)).expect("ok");

    assert_eq!(mappings.len(), 1);
    let m = &mappings[0];
    assert_eq!(m.technique_id, "T1059.001");
    assert_eq!(m.source, AttackMappingSource::Rule);
    assert_eq!(m.technique_name.as_deref(), Some("name-T1059.001"));
    assert_eq!(m.tactic.as_deref(), Some("execution"));
}

#[test]
fn t6_008_attack_mapping_from_sigma_tags() {
    let ds = make_dataset_with(&["T1059", "T1059.001", "T1548.002"]);
    let tags = vec![
        "attack.execution".into(),
        "attack.t1059.001".into(),
        "attack.t1548.002".into(),
        "noise-tag".into(),
    ];
    let mappings = from_sigma_rule_tags(&tags, Some(&ds)).expect("ok");

    // technique 形式の tag だけが mapping へ変換される。
    assert_eq!(mappings.len(), 2);
    let ids: Vec<&str> = mappings.iter().map(|m| m.technique_id.as_str()).collect();
    assert!(ids.contains(&"T1059.001"));
    assert!(ids.contains(&"T1548.002"));
    for m in &mappings {
        assert_eq!(m.source, AttackMappingSource::SigmaTag);
    }
}

#[test]
fn t6_008_attack_mapping_built_in_returns_empty_in_phase6() {
    assert!(built_in_mappings().is_empty());
}

#[test]
fn t6_008_attack_mapping_manual() {
    let ds = make_dataset_with(&["T1059.001"]);
    let m = manual_mapping("T1059.001", None, Some(&ds));
    assert_eq!(m.source, AttackMappingSource::Manual);
    assert_eq!(m.technique_id, "T1059.001");
    assert_eq!(m.technique_name.as_deref(), Some("name-T1059.001"));
}

#[test]
fn t6_008_extract_attack_tags_normalizes_case() {
    // Sigma tag は大文字小文字混在可能。technique ID は大文字へ正規化。
    let tags = vec![
        "attack.t1059".to_string(),
        "ATTACK.T1059.001".to_string(),
        "Attack.T1548.002".to_string(),
    ];
    let result = extract_attack_tags_from_sigma(&tags);
    assert_eq!(result, vec!["T1059", "T1059.001", "T1548.002"]);
}

// ============================================================================
// T6-009: ATT&CK mapping への dataset version + hash 記録
// ============================================================================

#[test]
fn t6_009_mappings_include_dataset_version_and_sha() {
    let ds = make_dataset_with(&["T1059", "T1059.001", "T1548.002"]);

    // 全4経路（Rule / SigmaTag / BuiltIn / Manual）の内、dataset を使う3経路で確認。
    let rule_m =
        from_correlation_rule("TF-CORR-001", &["T1059".to_string()], Some(&ds)).expect("ok");
    let sigma_m = from_sigma_rule_tags(&["attack.t1059.001".into()], Some(&ds)).expect("ok");
    let manual_m = manual_mapping("T1548.002", None, Some(&ds));

    for m in rule_m
        .iter()
        .chain(sigma_m.iter())
        .chain(std::iter::once(&manual_m))
    {
        // T6-009: dataset version と SHA-256 が記録される（規範 §15.3）。
        assert_eq!(m.dataset_version.as_deref(), Some("15.1"));
        assert!(
            m.dataset_sha256
                .as_ref()
                .map(|s| tf_core::hash::is_lowercase_sha256_hex(s))
                .unwrap_or(false)
        );
    }
}

#[test]
fn t6_009_mapping_without_dataset_has_no_version_or_sha() {
    // dataset が与えられない場合は dataset_version / dataset_sha256 は None になる。
    let m = manual_mapping("T1059.001", None, None);
    assert!(m.dataset_version.is_none());
    assert!(m.dataset_sha256.is_none());
    // それでも technique_id・source は必ず持つ。
    assert_eq!(m.technique_id, "T1059.001");
    assert_eq!(m.source, AttackMappingSource::Manual);
}

// ============================================================================
// 統合: ATT&CK mapping を含む完全な Finding 構築
// ============================================================================

#[test]
fn integration_finding_with_attack_mappings() {
    // Sigma Match を Finding へ変換 → ATT&CK mapping を attach する完全フロー。
    let matches = vec![make_match(
        MatchType::Sigma,
        "sigma-powershell",
        &sha64('a'),
        &["tf-event-v1:e1"],
        &["tf-evidence-v1:ev1"],
        None,
    )];
    let ds = make_dataset_with(&["T1059.001"]);

    let mut summary = FindingBuilder::default().build(&matches).expect("build ok");
    let finding = &mut summary.findings[0];

    // Sigma tag 由来の mapping を attach。
    let mappings =
        from_sigma_rule_tags(&["attack.t1059.001".to_string()], Some(&ds)).expect("mapping ok");
    attach_attack_mappings(finding, mappings);

    // Finding が attack_mappings を持ち、dataset version・hash が記録されている。
    assert_eq!(finding.attack_mappings.len(), 1);
    let m = &finding.attack_mappings[0];
    assert_eq!(m.technique_id, "T1059.001");
    assert_eq!(m.source, AttackMappingSource::SigmaTag);
    assert_eq!(m.dataset_version.as_deref(), Some("15.1"));

    // Finding の canonical JSON に attack_mappings が出力される。
    let v = finding.to_canonical_value();
    let am = v["attack_mappings"].as_array().unwrap();
    assert_eq!(am.len(), 1);
    assert_eq!(am[0]["technique_id"], "T1059.001");
    assert_eq!(am[0]["source"], "sigma_tag");
    assert_eq!(am[0]["dataset_version"], "15.1");
}

// ============================================================================
// 決定性: 入力順序によらない安定出力（規範 §13）
// ============================================================================

#[test]
fn finding_list_order_is_deterministic_regardless_of_input() {
    let mk_matches = |swap: bool| {
        let mut v = vec![
            make_match(
                MatchType::Sigma,
                "s-low",
                &sha64('a'),
                &["tf-event-v1:e1"],
                &["tf-evidence-v1:ev1"],
                None,
            ),
            make_match(
                MatchType::Correlation,
                "TF-CORR-high",
                &sha64('b'),
                &["tf-event-v1:e2"],
                &["tf-evidence-v1:ev2"],
                Some(Score {
                    base: 0.9,
                    adjustments: vec![],
                }),
            ),
            make_match(
                MatchType::YaraX,
                "y-med",
                &sha64('c'),
                &[],
                &["tf-evidence-v1:ev3"],
                None,
            ),
        ];
        if swap {
            v.reverse();
        }
        v
    };

    let s1 = FindingBuilder::default()
        .build(&mk_matches(false))
        .expect("build ok");
    let s2 = FindingBuilder::default()
        .build(&mk_matches(true))
        .expect("build ok");

    // finding_id list が完全一致する。
    let ids1: Vec<_> = s1.findings.iter().map(|f| f.finding_id.clone()).collect();
    let ids2: Vec<_> = s2.findings.iter().map(|f| f.finding_id.clone()).collect();
    assert_eq!(ids1, ids2, "入力順序によらず同一 Finding list（規範 §13）");
}

// ============================================================================
// Schema §6 出力順: Severity 降順・finding_id 昇順
// ============================================================================

#[test]
fn findings_sorted_by_severity_desc_then_finding_id_asc() {
    // Severity が異なる3 Finding を生成し、Schema §6 の順序で並ぶことを検証。
    let matches = vec![
        make_match(
            MatchType::Sigma,
            "sigma-low",
            &sha64('a'),
            &["tf-event-v1:e1"],
            &["tf-evidence-v1:ev1"],
            None,
        ),
        make_match(
            MatchType::Correlation,
            "TF-CORR-high",
            &sha64('b'),
            &["tf-event-v1:e2"],
            &["tf-evidence-v1:ev2"],
            Some(Score {
                base: 0.95,
                adjustments: vec![],
            }),
        ),
        make_match(
            MatchType::Correlation,
            "TF-CORR-med",
            &sha64('c'),
            &["tf-event-v1:e3"],
            &["tf-evidence-v1:ev3"],
            Some(Score {
                base: 0.6,
                adjustments: vec![],
            }),
        ),
    ];

    let summary = FindingBuilder::default().build(&matches).expect("build ok");

    // high > medium > low の順。
    let mut prev_rank = u8::MAX;
    for f in &summary.findings {
        let rank = severity_rank_for_test(f.severity);
        assert!(
            rank <= prev_rank,
            "Severity 降順になっていない: prev={prev_rank} cur={rank}"
        );
        prev_rank = rank;
    }
}

fn severity_rank_for_test(s: Severity) -> u8 {
    match s {
        Severity::Informational => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

// ============================================================================
// Finding ID の決定性（規範 §12.4）
// ============================================================================

#[test]
fn finding_id_is_deterministic_from_sorted_references() {
    // finding_id は sorted_event_ids と sorted_evidence_ids と rule_content_sha256_list から
    // 決定的に導かれる（規範 §12.4）。同一入力 → 同一 ID。
    let sha = sha64('a');
    let sorted_events = vec!["tf-event-v1:e1", "tf-event-v1:e2"];
    let sorted_evidence = vec!["tf-evidence-v1:ev1"];

    let id1 = finding_id("sigma", &[sha.as_str()], &sorted_events, &sorted_evidence);
    let id2 = finding_id("sigma", &[sha.as_str()], &sorted_events, &sorted_evidence);
    assert_eq!(id1, id2);

    // 渡し順を変えても sorted list なので同じ ID（呼出側が sort 済みを渡す前提）。
    let reversed_events = vec!["tf-event-v1:e2", "tf-event-v1:e1"];
    let id3 = finding_id("sigma", &[sha.as_str()], &reversed_events, &sorted_evidence);
    // 注: finding_id 関数は sort せず、渡された順序のまま hash する。
    // そのため呼出側は sort 済み list を渡す必要がある（merger.rs で担保済み）。
    assert_ne!(id1, id3, "sorted list を渡さないと異なる ID（仕様通り）");
}

// ============================================================================
// YARA-X Match は event_ids 無しでも Finding 生成可能（Schema §5.7）
// ============================================================================

#[test]
fn yara_match_produces_finding_without_event_ids() {
    let matches = vec![make_match(
        MatchType::YaraX,
        "yara-sig",
        &sha64('a'),
        &[],
        &["tf-evidence-v1:ev1"],
        None,
    )];
    let summary = FindingBuilder::default().build(&matches).expect("build ok");

    let f = &summary.findings[0];
    // YARA Match は Event を参照しないが Evidence を参照する。
    assert!(f.event_ids.is_empty());
    assert_eq!(f.evidence_ids.len(), 1);
    // confidence level が default で medium (0.5) になる。
    assert_eq!(f.confidence.level, ConfidenceLevel::Medium);
}
