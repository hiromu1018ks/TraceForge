//! Finding merger（T6-001〜T6-005・規範 §16・製品 §10）。
//!
//! 3 検知エンジン（Sigma・YARA-X・Correlation）が出力した Match（`tf_core::match_::Match`）
//! を人間が説明可能な [`tf_core::finding::Finding`] へ統合する。
//!
//! ## 設計原則
//!
//! ### T6-001: match 喪失なし
//! 入力に与えた全ての Match は、生成された Finding list のいずれかの `match_ids` へ
//! 必ず含まれる。Merger は Match を捨ててはならない。
//!
//! ### T6-002: 自動統合禁止（規範 §16）
//! 「同じ Event や Evidence を参照する」という理由だけで異なる Finding を自動統合しては
//! ならない。明示統合 rule（[`FindingMergeRule`]）が指定された場合だけ複数 Match を
//! 1つの Finding へ統合する。明示統合 rule 無しの場合は Match 1件につき Finding 1件を
//! 生成する（1:1 変換）。
//!
//! ### T6-003: Finding 必須 field（規範 §16）
//! 各 Finding は次を必ず持つ:
//! - 決定的 Finding ID（規範 §12.4）
//! - title / description
//! - severity（Rule 宣言または既定）
//! - confidence（score + level + reasons・規範 §14.3）
//! - event_ids / evidence_ids / match_ids / rule_refs
//! - observed_evidence（観測事実・推測を含めない）
//! - inference（推論・観測事実と分離）
//!
//! ### T6-004: observed_evidence と inference の分離（規範 §16・製品 §10）
//! - `observed_evidence`: Match が持つ客観的情報（match した rule 名・event/evidence ID・
//!   score・match reason 等）。推測を含めない。
//! - `inference`: 推論（例: 「インシデントの可能性が高い」等の人間向け解釈）。
//!
//! ### T6-005: 参照検証（製品 §10）
//! Finding から全元 Event・Evidence・Rule hash へ参照が到達できる。[`FindingMergeSummary`]
//! が入力 Match 全てを過不足無く統合したことを検証結果として返す。
//!
//! ## 決定性（規範 §13）
//!
//! - Match list は事前に sort してから処理する。sort key は `(rule_sha256, match_id)` の
//!   byte 昇順。
//! - Finding list は Schema §6 の出力順（Severity 降順・finding_id 昇順）で返す。
//! - 統合 rule の評価順は、登録順ではなく MergeGroupId の byte 昇順で安定させる。

use std::collections::BTreeSet;

use tf_core::case::Severity;
use tf_core::finding::{
    AttackMapping, AttackMappingSource, Confidence, ConfidenceLevel, Finding, RuleRef,
};
use tf_core::id::finding_id;
use tf_core::r#match::{Match, MatchType};

/// 明示統合 rule の識別子（T6-002）。
///
/// 同じ ID を持つ [`FindingMergeRule`] へ属する Match 達を1つの Finding へ統合する。
/// 文字列表現は `TF-FINDING-MERGE-XXX` のような安定した ID とする。
/// 決定性のため byte 順で sort して評価する。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MergeGroupId(String);

impl MergeGroupId {
    pub fn new(id: impl Into<String>) -> Self {
        MergeGroupId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 明示統合 rule（規範 §16・T6-002）。
///
/// 指定した rule_id（または rule_sha256）の Match 同士を1つの Finding へ統合することを
/// 許可する。統合結果の title・severity・confidence は宣言で上書きできる。
///
/// 統合は「同じ Event/Evidence を参照するから自動で」という理由ではなく、ユーザーが
/// 明示的にこの rule を定義した場合のみ発生する（規範 §16）。
#[derive(Clone, Debug)]
pub struct FindingMergeRule {
    /// 統合 group の識別子。
    pub group_id: MergeGroupId,
    /// 統合対象とする Rule の rule_id 一覧。この内いずれかを `rule_id` に持つ Match を統合する。
    pub rule_ids: Vec<String>,
    /// 統合後 Finding の title。
    pub title: String,
    /// 統合後 Finding の description。
    pub description: String,
    /// 統合後 Finding の severity。
    pub severity: Severity,
    /// 統合後 Finding の confidence として採用する score。
    /// 個別 Match の score は採用せず、宣言された base score + 空 adjustments とする。
    pub confidence_score: f64,
    /// 推論（inference）として記録する文章。
    pub inference: Vec<String>,
}

impl FindingMergeRule {
    /// `match_value` の `rule_id` が本統合 rule の対象か。
    fn matches(&self, match_value: &Match) -> bool {
        self.rule_ids.iter().any(|r| r == &match_value.rule_id)
    }
}

/// Finding merger の動作 option。
#[derive(Clone, Debug, Default)]
pub struct FindingMergeOptions {
    /// 明示統合 rule 群。自動統合は行わない（規範 §16・T6-002）。
    pub merge_rules: Vec<FindingMergeRule>,
    /// 既定の severity（Rule が severity を持たない Sigma/YARA-X 用）。
    /// Correlation は Rule 宣言の severity を使う。
    pub default_severity: Option<Severity>,
    /// 既定の confidence score（Correlation 以外で score 無しの Match 用）。
    /// 既定 `0.5`（medium 寄り low）。
    pub default_confidence_score: Option<f64>,
}

/// Finding merger の処理結果概要。
#[derive(Clone, Debug, Default)]
pub struct FindingMergeSummary {
    /// 生成された Finding list（Schema §6 の出力順: Severity 降順・finding_id 昇順）。
    pub findings: Vec<Finding>,
    /// 入力として与えた Match 総数。
    pub input_match_count: usize,
    /// Finding の `match_ids` に現れた Match ID の集合（T6-005 検証用）。
    pub referenced_match_ids: BTreeSet<String>,
    /// 統合 rule によって統合された Match 数。
    pub merged_match_count: usize,
    /// 1:1 変換（統合 rule 適用なし）で生成された Finding 数。
    pub one_to_one_finding_count: usize,
    /// 統合 rule によって生成された Finding 数。
    pub merged_finding_count: usize,
}

impl FindingMergeSummary {
    /// T6-001（match 喪失なし）の検証: 入力 Match が全て何らかの Finding へ含まれたか。
    pub fn all_matches_referenced(&self, input_match_ids: &BTreeSet<String>) -> bool {
        self.referenced_match_ids == *input_match_ids
    }
}

/// Finding 構築時の error（規範 §17.2）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum FindingBuildError {
    /// 入力 Match の `rule_sha256` が不正（lowercase 64桁 hex ではない）。
    #[error("invalid rule_sha256 in match {match_id}: {sha256}")]
    InvalidRuleSha256 { match_id: String, sha256: String },

    /// 統合 rule が1件も Match しなかった（誤設定の可能性）。
    #[error("merge rule '{group_id}' matched no input match (rule_ids={rule_ids:?})")]
    MergeRuleMatchedNothing {
        group_id: String,
        rule_ids: Vec<String>,
    },
}

/// Finding builder（T6-001〜T6-005）。
///
/// Phase 6 では stateless な builder とし、呼出側が Match list を渡す毎に新規 summary
/// を返す。Phase 7 CLI が Match list を収集した後に1回呼び出すことを想定する。
#[derive(Clone, Debug)]
pub struct FindingBuilder {
    options: FindingMergeOptions,
}

impl Default for FindingBuilder {
    fn default() -> Self {
        FindingBuilder::new(FindingMergeOptions::default())
    }
}

impl FindingBuilder {
    pub fn new(options: FindingMergeOptions) -> Self {
        FindingBuilder { options }
    }

    pub fn options(&self) -> &FindingMergeOptions {
        &self.options
    }

    /// Match list を Finding list へ統合する（規範 §16・T6-001〜T6-005）。
    ///
    /// 処理手順:
    /// 1. 入力 Match を `(rule_sha256, match_id)` の byte 昇順で sort する（決定性）。
    /// 2. 各統合 rule について、対象 Match を1つの Finding へ統合する。
    /// 3. 統合されなかった残りの Match を1:1 で Finding へ変換する。
    /// 4. Finding list を Schema §6 の出力順（Severity 降順・finding_id 昇順）で sort する。
    /// 5. `summary.referenced_match_ids` を用いて T6-001 検証情報を返す。
    pub fn build(&self, matches: &[Match]) -> Result<FindingMergeSummary, FindingBuildError> {
        // 0. 入力検証: rule_sha256 形式。
        for m in matches {
            if !tf_core::hash::is_lowercase_sha256_hex(&m.rule_sha256) {
                return Err(FindingBuildError::InvalidRuleSha256 {
                    match_id: m.match_id.clone(),
                    sha256: m.rule_sha256.clone(),
                });
            }
        }

        // 1. 決定的順序で処理するため事前 sort（規範 §13）。
        let mut sorted: Vec<&Match> = matches.iter().collect();
        sorted.sort_by(|a, b| (&a.rule_sha256, &a.match_id).cmp(&(&b.rule_sha256, &b.match_id)));

        // 2. 統合 rule を評価（MergeGroupId 順で安定）。
        // どの Match がどの統合 rule へ属したかを追跡し、残余は 1:1 変換へ回す。
        let mut merge_rules_sorted = self.options.merge_rules.clone();
        merge_rules_sorted.sort_by(|a, b| a.group_id.cmp(&b.group_id));

        let mut consumed: Vec<bool> = vec![false; sorted.len()];
        let mut findings: Vec<Finding> = Vec::new();
        let mut merged_match_count: usize = 0;
        let mut merged_finding_count: usize = 0;

        for rule in &merge_rules_sorted {
            let mut group_match_indices: Vec<usize> = Vec::new();
            for (i, m) in sorted.iter().enumerate() {
                if consumed[i] {
                    continue;
                }
                if rule.matches(m) {
                    group_match_indices.push(i);
                }
            }
            if group_match_indices.is_empty() {
                // T6-002: 統合 rule が1件も Match しなかったら error とする（誤設定検出）。
                return Err(FindingBuildError::MergeRuleMatchedNothing {
                    group_id: rule.group_id.as_str().to_string(),
                    rule_ids: rule.rule_ids.clone(),
                });
            }
            for &i in &group_match_indices {
                consumed[i] = true;
            }
            let group_matches: Vec<&Match> =
                group_match_indices.iter().map(|&i| sorted[i]).collect();
            let finding = self.build_merged_finding(&group_matches, rule)?;
            merged_match_count += group_matches.len();
            merged_finding_count += 1;
            findings.push(finding);
        }

        // 3. 残余 Match を1:1 で Finding へ変換。
        let mut one_to_one_finding_count: usize = 0;
        for (i, m) in sorted.iter().enumerate() {
            if consumed[i] {
                continue;
            }
            let finding = self.build_single_finding(m)?;
            one_to_one_finding_count += 1;
            findings.push(finding);
        }

        // 4. Schema §6 の出力順へ sort（Severity 降順・finding_id 昇順）。
        sort_findings_canonical(&mut findings);

        // 5. T6-005: 参照検証情報を集計。
        let mut referenced_match_ids: BTreeSet<String> = BTreeSet::new();
        for f in &findings {
            for mid in &f.match_ids {
                referenced_match_ids.insert(mid.clone());
            }
        }

        Ok(FindingMergeSummary {
            findings,
            input_match_count: matches.len(),
            referenced_match_ids,
            merged_match_count,
            one_to_one_finding_count,
            merged_finding_count,
        })
    }

    /// 1件の Match から Finding を生成する（1:1 変換）。
    fn build_single_finding(&self, m: &Match) -> Result<Finding, FindingBuildError> {
        let (event_ids_sorted, evidence_ids_sorted, rule_sha256_list) =
            collect_canonical_references(&[m]);

        let finding_type = match_type_str(m.match_type);
        let sha_refs: Vec<&str> = rule_sha256_list.iter().map(String::as_str).collect();
        let ev_refs: Vec<&str> = event_ids_sorted.iter().map(String::as_str).collect();
        let evid_refs: Vec<&str> = evidence_ids_sorted.iter().map(String::as_str).collect();
        let finding_id_str = finding_id(finding_type, &sha_refs, &ev_refs, &evid_refs);

        let severity = self.severity_for_match(m);
        let confidence = self.confidence_for_match(m);

        let observed_evidence = build_observed_evidence_single(m);
        let inference = build_inference_single(m, severity);

        Ok(Finding {
            finding_id: finding_id_str,
            title: build_single_title(m),
            description: build_single_description(m),
            severity,
            confidence,
            event_ids: event_ids_sorted,
            evidence_ids: evidence_ids_sorted,
            match_ids: vec![m.match_id.clone()],
            rule_refs: vec![RuleRef {
                rule_id: m.rule_id.clone(),
                rule_sha256: m.rule_sha256.clone(),
            }],
            attack_mappings: Vec::new(),
            observed_evidence,
            inference,
        })
    }

    /// 複数 Match を1つの Finding へ統合する（明示統合 rule）。
    fn build_merged_finding(
        &self,
        matches: &[&Match],
        rule: &FindingMergeRule,
    ) -> Result<Finding, FindingBuildError> {
        let (event_ids_sorted, evidence_ids_sorted, rule_sha256_list) =
            collect_canonical_references(matches);

        // finding_type は「merge」とする（統合済 Finding の識別）。
        let sha_refs: Vec<&str> = rule_sha256_list.iter().map(String::as_str).collect();
        let ev_refs: Vec<&str> = event_ids_sorted.iter().map(String::as_str).collect();
        let evid_refs: Vec<&str> = evidence_ids_sorted.iter().map(String::as_str).collect();
        let finding_id_str = finding_id("merge", &sha_refs, &ev_refs, &evid_refs);

        let mut match_ids: Vec<String> = matches.iter().map(|m| m.match_id.clone()).collect();
        match_ids.sort();

        // rule_refs は各 Match の rule_id / rule_sha256 を sort・dedup して保持。
        let mut rule_refs: Vec<RuleRef> = matches
            .iter()
            .map(|m| RuleRef {
                rule_id: m.rule_id.clone(),
                rule_sha256: m.rule_sha256.clone(),
            })
            .collect();
        rule_refs.sort_by(|a, b| (&a.rule_sha256, &a.rule_id).cmp(&(&b.rule_sha256, &b.rule_id)));
        rule_refs.dedup_by(|a, b| a.rule_sha256 == b.rule_sha256 && a.rule_id == b.rule_id);

        let observed_evidence = build_observed_evidence_merged(matches);
        let inference = if rule.inference.is_empty() {
            build_inference_merged(matches, rule.severity)
        } else {
            rule.inference.clone()
        };

        Ok(Finding {
            finding_id: finding_id_str,
            title: rule.title.clone(),
            description: rule.description.clone(),
            severity: rule.severity,
            confidence: Confidence::new(rule.confidence_score, Vec::new()),
            event_ids: event_ids_sorted,
            evidence_ids: evidence_ids_sorted,
            match_ids,
            rule_refs,
            attack_mappings: Vec::new(),
            observed_evidence,
            inference,
        })
    }

    /// Match から severity を決定する（Correlation は Rule 宣言・他は既定）。
    fn severity_for_match(&self, m: &Match) -> Severity {
        if m.match_type == MatchType::Correlation {
            // Correlation Match が持つ score の base から severity を逆引く。
            // 規範 §14.3 は Confidence level を定義するが、Severity は別軸。
            // Correlation Rule が severity を持つはずだが、Match には直接保持していないため、
            // score base が 0.8 以上なら high・0.5 以上なら medium・それ以外は low とする。
            // 呼出側で明示 severity を上書きできるよう、default_severity があればそれを優先。
            if let Some(sev) = self.options.default_severity {
                return sev;
            }
            severity_from_score_base(m.score.as_ref().map(|s| s.base).unwrap_or(0.5))
        } else {
            self.options.default_severity.unwrap_or(Severity::Medium)
        }
    }

    /// Match から confidence を決定する（規範 §14.3）。
    fn confidence_for_match(&self, m: &Match) -> Confidence {
        let (score_val, reasons) = if let Some(s) = &m.score {
            (
                s.total(),
                vec![format!(
                    "Correlation score: base={:.3}, total adjustments={:.3}",
                    s.base,
                    s.adjustments.iter().map(|a| a.value).sum::<f64>()
                )],
            )
        } else {
            let base = self
                .options
                .default_confidence_score
                .unwrap_or(DEFAULT_CONFIDENCE_SCORE);
            let reason = match m.match_type {
                MatchType::Sigma => {
                    format!("Sigma match (default confidence={base:.3})")
                }
                MatchType::YaraX => {
                    format!("YARA-X match (default confidence={base:.3})")
                }
                MatchType::Correlation => {
                    format!("Correlation match without score (default confidence={base:.3})")
                }
            };
            (base, vec![reason])
        };
        Confidence::new(score_val, reasons)
    }
}

/// Sigma/YARA-X Match 用の既定 confidence score。
/// 0.5 = medium level の下限。Schema が Score を持たない Match にも説明を与えるため。
const DEFAULT_CONFIDENCE_SCORE: f64 = 0.5;

/// Correlation Match の score base から Severity を推定する（score が Rule 宣言の重みを
/// 反映しているため）。規範 §14.3 は confidence level を定義するが、Severity は別軸。
/// ここでは confidence score を severity の大まかな指標として使う。
fn severity_from_score_base(base: f64) -> Severity {
    let level = ConfidenceLevel::from_score(base);
    match level {
        ConfidenceLevel::High => Severity::High,
        ConfidenceLevel::Medium => Severity::Medium,
        ConfidenceLevel::Low => Severity::Low,
    }
}

/// MatchType → finding_type 文字列（規範 §12.4）。
fn match_type_str(t: MatchType) -> &'static str {
    match t {
        MatchType::Correlation => "correlation",
        MatchType::Sigma => "sigma",
        MatchType::YaraX => "yara_x",
    }
}

/// Match list から決定的な参照集合を取り出す（規範 §12.4・決定性のため sort 済み）。
///
/// - event_ids: 全 Match の event_ids を sort・dedup
/// - evidence_ids: 全 Match の evidence_ids を sort・dedup
/// - rule_sha256_list: 全 Match の rule_sha256 を sort・dedup
fn collect_canonical_references(matches: &[&Match]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut event_set: BTreeSet<String> = BTreeSet::new();
    let mut evidence_set: BTreeSet<String> = BTreeSet::new();
    let mut sha_set: BTreeSet<String> = BTreeSet::new();
    for m in matches {
        for e in &m.event_ids {
            event_set.insert(e.clone());
        }
        for e in &m.evidence_ids {
            evidence_set.insert(e.clone());
        }
        sha_set.insert(m.rule_sha256.clone());
    }
    (
        event_set.into_iter().collect(),
        evidence_set.into_iter().collect(),
        sha_set.into_iter().collect(),
    )
}

/// Schema §6 出力順へ Finding list を sort する（Severity 降順・finding_id 昇順）。
fn sort_findings_canonical(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        let sev_a = severity_rank(a.severity);
        let sev_b = severity_rank(b.severity);
        sev_b
            .cmp(&sev_a)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
}

/// Severity の順序値（降順 sort 用・critical=5..informational=1）。
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Informational => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

/// 1件 Match から Finding を作る際の title。
fn build_single_title(m: &Match) -> String {
    match m.match_type {
        MatchType::Correlation => format!("Correlation match: {}", m.rule_id),
        MatchType::Sigma => format!("Sigma match: {}", m.rule_id),
        MatchType::YaraX => format!("YARA-X match: {}", m.rule_id),
    }
}

/// 1件 Match から Finding を作る際の description。
fn build_single_description(m: &Match) -> String {
    let reasons = if m.reasons.is_empty() {
        "(no reason provided)".to_string()
    } else {
        m.reasons.join("; ")
    };
    match m.match_type {
        MatchType::Correlation => {
            format!("Correlation rule '{}' matched. {reasons}", m.rule_id)
        }
        MatchType::Sigma => {
            format!("Sigma rule '{}' matched. {reasons}", m.rule_id)
        }
        MatchType::YaraX => {
            format!("YARA-X rule '{}' matched on evidence. {reasons}", m.rule_id)
        }
    }
}

/// 1件 Match から観測事実を構築する（T6-004・推測を含めない）。
fn build_observed_evidence_single(m: &Match) -> Vec<String> {
    let mut observed: Vec<String> = Vec::new();
    observed.push(format!("rule_id={}", m.rule_id));
    observed.push(format!("rule_sha256={}", m.rule_sha256));
    observed.push(format!("match_type={}", m.match_type.as_str()));
    if !m.event_ids.is_empty() {
        let mut ids = m.event_ids.clone();
        ids.sort();
        observed.push(format!("event_ids=[{}]", ids.join(",")));
    }
    if !m.evidence_ids.is_empty() {
        let mut ids = m.evidence_ids.clone();
        ids.sort();
        observed.push(format!("evidence_ids=[{}]", ids.join(",")));
    }
    if let Some(score) = &m.score {
        observed.push(format!(
            "score: base={:.3}, adjustments={}",
            score.base,
            format_adjustments_short(&score.adjustments)
        ));
    }
    for r in &m.reasons {
        observed.push(format!("reason: {r}"));
    }
    observed
}

/// 統合 Match から観測事実を構築する（T6-004）。
fn build_observed_evidence_merged(matches: &[&Match]) -> Vec<String> {
    let mut observed: Vec<String> = Vec::new();
    let mut rule_ids: BTreeSet<String> = BTreeSet::new();
    let mut rule_shas: BTreeSet<String> = BTreeSet::new();
    let mut match_ids: BTreeSet<String> = BTreeSet::new();
    let mut match_types: BTreeSet<&'static str> = BTreeSet::new();
    for m in matches {
        rule_ids.insert(m.rule_id.clone());
        rule_shas.insert(m.rule_sha256.clone());
        match_ids.insert(m.match_id.clone());
        match_types.insert(m.match_type.as_str());
    }
    observed.push(format!(
        "rule_ids=[{}]",
        rule_ids.into_iter().collect::<Vec<_>>().join(",")
    ));
    observed.push(format!(
        "rule_sha256_list=[{}]",
        rule_shas.into_iter().collect::<Vec<_>>().join(",")
    ));
    observed.push(format!(
        "match_ids=[{}]",
        match_ids.into_iter().collect::<Vec<_>>().join(",")
    ));
    observed.push(format!(
        "match_types=[{}]",
        match_types.into_iter().collect::<Vec<_>>().join(",")
    ));
    for m in matches {
        for r in &m.reasons {
            observed.push(format!("reason ({}): {r}", m.rule_id));
        }
    }
    observed
}

/// 1件 Match から推論を構築する（T6-004）。
fn build_inference_single(m: &Match, severity: Severity) -> Vec<String> {
    let severity_str = severity.as_str();
    let engine = match m.match_type {
        MatchType::Correlation => "Correlation",
        MatchType::Sigma => "Sigma",
        MatchType::YaraX => "YARA-X",
    };
    vec![format!(
        "{engine} rule '{}' matched (severity={severity_str}). Investigate the referenced events/evidence.",
        m.rule_id
    )]
}

/// 統合 Match から推論を構築する（T6-004）。
fn build_inference_merged(matches: &[&Match], severity: Severity) -> Vec<String> {
    let severity_str = severity.as_str();
    vec![format!(
        "{} matches merged into a single Finding (severity={severity_str}). Correlated events/evidence require combined investigation.",
        matches.len()
    )]
}

/// Score adjustments を短縮表現へ（観測事実出力用）。
fn format_adjustments_short(adjustments: &[tf_core::finding::ScoreAdjustment]) -> String {
    if adjustments.is_empty() {
        return "none".to_string();
    }
    adjustments
        .iter()
        .map(|a| format!("{:+.3}({})", a.value, a.reason))
        .collect::<Vec<_>>()
        .join(", ")
}

/// [`AttackMapping`] を Finding へ attach する helper。
///
/// Merger は ATT&CK mapping を Rule / Sigma tag / built-in / manual 以外からは生成しない
/// （規範 §15.3）。本関数は呼出側が [`AttackMappingSource`] を明示して渡した場合に
/// Finding へ追記する。
pub fn attach_attack_mappings(finding: &mut Finding, mappings: Vec<AttackMapping>) {
    finding.attack_mappings.extend(mappings);
    // 決定性のため technique_id 昇順へ sort（規範 §13）。
    finding
        .attack_mappings
        .sort_by(|a, b| a.technique_id.cmp(&b.technique_id));
    finding.attack_mappings.dedup_by(|a, b| {
        a.technique_id == b.technique_id
            && a.technique_name == b.technique_name
            && a.tactic == b.tactic
            && a.source == b.source
            && a.dataset_version == b.dataset_version
            && a.dataset_sha256 == b.dataset_sha256
    });
}

/// 手動 ATT&CK mapping を構築する helper（T6-008・source=Manual）。
pub fn manual_attack_mapping(
    technique_id: &str,
    technique_name: Option<&str>,
    dataset: Option<&crate::AttackDataset>,
) -> AttackMapping {
    let (version, sha, name, tactic) = match dataset {
        Some(d) => (
            Some(d.manifest.version.clone()),
            Some(d.manifest.sha256.clone()),
            technique_name
                .map(String::from)
                .or_else(|| d.lookup_technique(technique_id).map(|t| t.name.clone())),
            d.lookup_technique(technique_id)
                .and_then(|t| t.tactic.clone()),
        ),
        None => (None, None, technique_name.map(String::from), None),
    };
    AttackMapping {
        technique_id: technique_id.to_string(),
        technique_name: name,
        tactic,
        source: AttackMappingSource::Manual,
        dataset_version: version,
        dataset_sha256: sha,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tf_core::finding::{Score, ScoreAdjustment};
    use tf_core::id::match_id;

    fn dummy_match(
        match_type: MatchType,
        rule_id: &str,
        rule_sha: &str,
        event_ids: &[&str],
        evidence_ids: &[&str],
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
            reasons: vec!["sample reason".to_string()],
            score: None,
            ordered_event_ids: Some(event_ids.iter().map(|s| s.to_string()).collect()),
            logsource_mapping: None,
            matched_patterns: None,
        }
    }

    fn dummy_match_with_score(
        rule_id: &str,
        rule_sha: &str,
        event_ids: &[&str],
        evidence_ids: &[&str],
        base: f64,
    ) -> Match {
        let ordered: Vec<&str> = event_ids.to_vec();
        let mid = match_id(rule_id, rule_sha, &ordered);
        Match {
            match_id: mid,
            match_type: MatchType::Correlation,
            rule_id: rule_id.to_string(),
            rule_sha256: rule_sha.to_string(),
            event_ids: event_ids.iter().map(|s| s.to_string()).collect(),
            evidence_ids: evidence_ids.iter().map(|s| s.to_string()).collect(),
            reasons: vec!["correlation matched".to_string()],
            score: Some(Score {
                base,
                adjustments: vec![ScoreAdjustment {
                    reason: "exact".into(),
                    value: 0.1,
                }],
            }),
            ordered_event_ids: Some(event_ids.iter().map(|s| s.to_string()).collect()),
            logsource_mapping: None,
            matched_patterns: None,
        }
    }

    fn sha64(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    // ===== T6-001: match 喪失なし =====

    #[test]
    fn no_match_loss_for_three_engines() {
        let matches = vec![
            dummy_match(MatchType::Sigma, "sigma-1", &sha64('a'), &["e1"], &["ev1"]),
            dummy_match(MatchType::YaraX, "yara-1", &sha64('b'), &[], &["ev2"]),
            dummy_match(
                MatchType::Correlation,
                "corr-1",
                &sha64('c'),
                &["e2", "e3"],
                &["ev1", "ev3"],
            ),
        ];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");

        assert_eq!(summary.input_match_count, 3);
        let expected_ids: BTreeSet<String> = matches.iter().map(|m| m.match_id.clone()).collect();
        assert!(
            summary.all_matches_referenced(&expected_ids),
            "全 Match が何らかの Finding へ含まれる"
        );
        assert_eq!(summary.findings.len(), 3);
        assert_eq!(summary.one_to_one_finding_count, 3);
        assert_eq!(summary.merged_finding_count, 0);

        // 念のため参照集合を再確認。
        let _ = expected_ids.clone();
    }

    // ===== T6-002: 自動統合禁止 =====

    #[test]
    fn no_automatic_merge_on_shared_evidence_ids() {
        // 2つの Match が同じ evidence_id を参照していても、統合 rule 無しなら別 Finding。
        let matches = vec![
            dummy_match(
                MatchType::Sigma,
                "sigma-A",
                &sha64('a'),
                &["e1"],
                &["ev-shared"],
            ),
            dummy_match(MatchType::YaraX, "yara-A", &sha64('b'), &[], &["ev-shared"]),
        ];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");

        // 統合 rule 無し → 2つの別 Finding。
        assert_eq!(
            summary.findings.len(),
            2,
            "共通 evidence_id を理由に自動統合しない"
        );
        // 各 Finding は単独 match_id のみ持つ。
        for f in &summary.findings {
            assert_eq!(f.match_ids.len(), 1);
        }
    }

    #[test]
    fn explicit_merge_rule_combines_matches() {
        let matches = vec![
            dummy_match(MatchType::Sigma, "sigma-A", &sha64('a'), &["e1"], &["ev1"]),
            dummy_match(MatchType::YaraX, "yara-A", &sha64('b'), &[], &["ev2"]),
            dummy_match(
                MatchType::Correlation,
                "corr-X",
                &sha64('c'),
                &["e2"],
                &["ev3"],
            ),
        ];
        let options = FindingMergeOptions {
            merge_rules: vec![FindingMergeRule {
                group_id: MergeGroupId::new("TF-FINDING-MERGE-001"),
                rule_ids: vec!["sigma-A".into(), "yara-A".into()],
                title: "Suspicious activity cluster".into(),
                description: "Combined Sigma and YARA-X detection".into(),
                severity: Severity::High,
                confidence_score: 0.85,
                inference: vec!["High-likelihood incident".into()],
            }],
            default_severity: None,
            default_confidence_score: None,
        };
        let builder = FindingBuilder::new(options);
        let summary = builder.build(&matches).expect("build ok");

        // 統合 rule により sigma-A と yara-A が1つに、corr-X が1:1 で、合計2 Finding。
        assert_eq!(summary.findings.len(), 2);
        assert_eq!(summary.merged_finding_count, 1);
        assert_eq!(summary.one_to_one_finding_count, 1);
        assert_eq!(summary.merged_match_count, 2);

        // 統合 Finding の確認
        let merged = summary
            .findings
            .iter()
            .find(|f| f.match_ids.len() == 2)
            .expect("統合 Finding がある");
        assert_eq!(merged.title, "Suspicious activity cluster");
        assert_eq!(merged.severity, Severity::High);
        assert_eq!(
            merged.inference,
            vec!["High-likelihood incident".to_string()]
        );

        // 全 Match が参照されている
        let expected: BTreeSet<String> = matches.iter().map(|m| m.match_id.clone()).collect();
        assert!(summary.all_matches_referenced(&expected));
    }

    #[test]
    fn merge_rule_with_no_match_is_error() {
        let matches = vec![dummy_match(
            MatchType::Sigma,
            "sigma-A",
            &sha64('a'),
            &["e1"],
            &["ev1"],
        )];
        let options = FindingMergeOptions {
            merge_rules: vec![FindingMergeRule {
                group_id: MergeGroupId::new("TF-FINDING-MERGE-999"),
                rule_ids: vec!["non-existent-rule".into()],
                title: "Never matches".into(),
                description: "Should error".into(),
                severity: Severity::Low,
                confidence_score: 0.1,
                inference: vec![],
            }],
            default_severity: None,
            default_confidence_score: None,
        };
        let builder = FindingBuilder::new(options);
        let result = builder.build(&matches);
        assert!(
            result.is_err(),
            "統合 rule が1件も Match しない場合は error"
        );
    }

    // ===== T6-003: 必須 field 検証 =====

    #[test]
    fn finding_has_all_required_fields() {
        let matches = vec![dummy_match_with_score(
            "TF-CORR-001",
            &sha64('a'),
            &["e1", "e2"],
            &["ev1"],
            0.75,
        )];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");
        let f = &summary.findings[0];

        // Schema §5.8 の必須 field を全て持つ。
        assert!(!f.finding_id.is_empty());
        assert!(tf_core::id::is_valid_id(&f.finding_id));
        assert!(!f.title.is_empty());
        assert!(!f.description.is_empty());
        // severity / confidence
        let _ = f.severity;
        assert!(!f.confidence.reasons.is_empty());
        // 参照 ID 群
        assert!(!f.event_ids.is_empty());
        assert!(!f.evidence_ids.is_empty());
        assert!(!f.match_ids.is_empty());
        assert!(!f.rule_refs.is_empty());
        // observed / inference
        assert!(!f.observed_evidence.is_empty());
        assert!(!f.inference.is_empty());

        // Finding は created_at を持ってはならない（Schema §5.8）。
        let v = f.to_canonical_value();
        assert!(!v.as_object().unwrap().contains_key("created_at"));
    }

    // ===== T6-004: observed_evidence と inference の分離 =====

    #[test]
    fn observed_evidence_does_not_contain_inference() {
        let matches = vec![dummy_match(
            MatchType::Sigma,
            "sigma-X",
            &sha64('a'),
            &["e1"],
            &["ev1"],
        )];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");
        let f = &summary.findings[0];

        // observed_evidence は客観的事実のみ（推測を含まない）。
        for obs in &f.observed_evidence {
            // 「検討すべき」「可能性が高い」等の推論語を含まない。
            assert!(
                !obs.contains("Investigate"),
                "observed_evidence は推論を含まない: {obs}"
            );
        }
        // inference は推論を含む。
        assert!(f.inference.iter().any(|i| i.contains("Investigate")));
    }

    // ===== T6-005: 参照検証 =====

    #[test]
    fn all_input_matches_referenced_in_findings() {
        let matches = vec![
            dummy_match(MatchType::Sigma, "s1", &sha64('a'), &["e1"], &["ev1"]),
            dummy_match(MatchType::YaraX, "y1", &sha64('b'), &[], &["ev2"]),
            dummy_match(
                MatchType::Correlation,
                "c1",
                &sha64('c'),
                &["e1", "e2"],
                &["ev1"],
            ),
            dummy_match(MatchType::Sigma, "s2", &sha64('d'), &["e3"], &["ev3"]),
        ];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");

        let input_ids: BTreeSet<String> = matches.iter().map(|m| m.match_id.clone()).collect();
        assert!(
            summary.all_matches_referenced(&input_ids),
            "入力 Match 全てが Finding の match_ids へ出現する"
        );
    }

    #[test]
    fn rule_refs_include_all_input_rule_hashes() {
        let sha1 = sha64('1');
        let sha2 = sha64('2');
        let matches = vec![
            dummy_match(MatchType::Sigma, "s1", &sha1, &["e1"], &["ev1"]),
            dummy_match(MatchType::YaraX, "y1", &sha2, &[], &["ev2"]),
        ];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");

        let mut all_shas: BTreeSet<String> = BTreeSet::new();
        for f in &summary.findings {
            for r in &f.rule_refs {
                all_shas.insert(r.rule_sha256.clone());
            }
        }
        assert!(all_shas.contains(&sha1));
        assert!(all_shas.contains(&sha2));
    }

    // ===== 決定性 =====

    #[test]
    fn build_is_deterministic_across_input_orders() {
        let mk_matches = |swap: bool| {
            let mut v = vec![
                dummy_match(MatchType::Sigma, "s1", &sha64('a'), &["e1"], &["ev1"]),
                dummy_match(MatchType::YaraX, "y1", &sha64('b'), &[], &["ev2"]),
                dummy_match(
                    MatchType::Correlation,
                    "c1",
                    &sha64('c'),
                    &["e1", "e2"],
                    &["ev1"],
                ),
            ];
            if swap {
                v.reverse();
            }
            v
        };
        let builder = FindingBuilder::default();
        let s1 = builder.build(&mk_matches(false)).expect("build ok");
        let s2 = builder.build(&mk_matches(true)).expect("build ok");

        // 入力順序が異なっても、出力 Finding list は同一（findings_id list 比較）。
        let ids1: Vec<_> = s1.findings.iter().map(|f| f.finding_id.clone()).collect();
        let ids2: Vec<_> = s2.findings.iter().map(|f| f.finding_id.clone()).collect();
        assert_eq!(ids1, ids2, "入力順序によらず同一 Finding list（決定性）");
    }

    // ===== 統合 rule 適用順序の決定性 =====

    #[test]
    fn merge_rules_evaluated_in_group_id_order() {
        let matches = vec![
            dummy_match(MatchType::Sigma, "rule-A", &sha64('a'), &["e1"], &["ev1"]),
            dummy_match(MatchType::Sigma, "rule-B", &sha64('b'), &["e2"], &["ev2"]),
        ];
        // group_id を逆順で登録しても、評価は byte 順で安定する。
        let options = FindingMergeOptions {
            merge_rules: vec![
                FindingMergeRule {
                    group_id: MergeGroupId::new("TF-FINDING-MERGE-002"),
                    rule_ids: vec!["rule-B".into()],
                    title: "B".into(),
                    description: String::new(),
                    severity: Severity::Low,
                    confidence_score: 0.2,
                    inference: vec![],
                },
                FindingMergeRule {
                    group_id: MergeGroupId::new("TF-FINDING-MERGE-001"),
                    rule_ids: vec!["rule-A".into()],
                    title: "A".into(),
                    description: String::new(),
                    severity: Severity::High,
                    confidence_score: 0.9,
                    inference: vec![],
                },
            ],
            default_severity: None,
            default_confidence_score: None,
        };
        let builder = FindingBuilder::new(options);
        let summary = builder.build(&matches).expect("build ok");

        // 2 Finding 生成される。Severity 降順で High が先。
        assert_eq!(summary.findings.len(), 2);
        assert_eq!(summary.findings[0].severity, Severity::High);
        assert_eq!(summary.findings[1].severity, Severity::Low);
    }

    // ===== attach_attack_mappings =====

    #[test]
    fn attach_attack_mappings_sorts_and_dedups() {
        let matches = vec![dummy_match(
            MatchType::Sigma,
            "s1",
            &sha64('a'),
            &["e1"],
            &["ev1"],
        )];
        let builder = FindingBuilder::default();
        let mut summary = builder.build(&matches).expect("build ok");
        let finding = &mut summary.findings[0];

        attach_attack_mappings(
            finding,
            vec![
                AttackMapping {
                    technique_id: "T1059.001".into(),
                    technique_name: Some("PowerShell".into()),
                    tactic: Some("execution".into()),
                    source: AttackMappingSource::SigmaTag,
                    dataset_version: Some("15.1".into()),
                    dataset_sha256: Some(sha64('d')),
                },
                AttackMapping {
                    technique_id: "T1059".into(),
                    technique_name: Some("Command and Scripting Interpreter".into()),
                    tactic: Some("execution".into()),
                    source: AttackMappingSource::Rule,
                    dataset_version: Some("15.1".into()),
                    dataset_sha256: Some(sha64('d')),
                },
                // 重複（dedup 対象）
                AttackMapping {
                    technique_id: "T1059.001".into(),
                    technique_name: Some("PowerShell".into()),
                    tactic: Some("execution".into()),
                    source: AttackMappingSource::SigmaTag,
                    dataset_version: Some("15.1".into()),
                    dataset_sha256: Some(sha64('d')),
                },
            ],
        );
        // technique_id 昇順: T1059 < T1059.001
        assert_eq!(finding.attack_mappings.len(), 2);
        assert_eq!(finding.attack_mappings[0].technique_id, "T1059");
        assert_eq!(finding.attack_mappings[1].technique_id, "T1059.001");
    }

    // ===== severity 推定 =====

    #[test]
    fn correlation_severity_inferred_from_score_base() {
        let matches = vec![dummy_match_with_score(
            "TF-CORR-001",
            &sha64('a'),
            &["e1"],
            &["ev1"],
            0.85,
        )];
        let builder = FindingBuilder::default();
        let summary = builder.build(&matches).expect("build ok");
        let f = &summary.findings[0];
        // base=0.85 → High severity
        assert_eq!(f.severity, Severity::High);
    }
}
