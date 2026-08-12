//! 出力対象となる Case 全体の in-memory 表現。
//!
//! [`CaseData`] は Evidence・Artifact・Event・Issue・Match・Finding・Manifest を束ね、
//! 6 種の exporter へ共通の入力となる。各 exporter は [`CaseData`] を受け取り、
//! 安全性変換（規範 §19）と Schema §6 の出力順 sort を毎回適用するため、呼出側の
//! 構築順序に依存しない。
//!
//! Phase 7 の範囲では Event を `Vec` で保持する。これは Phase 3 の streaming 出力
//! （`tf_store::output::write_jsonl`・規範 §21-6）と併存する。streaming が必要な
//! 巨大 Case は Phase 3 の経路を使い、Phase 7 の [`CaseData`] は検出結果の確認や
//! export 形式変換等の in-memory ユースケースを想定する。

use tf_core::case::{ArtifactInstance, CaseMetadata, EvidenceItem};
use tf_core::event::Event;
use tf_core::finding::Finding;
use tf_core::issue::Issue;
use tf_core::manifest::Manifest;
use tf_core::r#match::Match;

/// 全 exporter へ共通の入力（Case 全体）。
#[derive(Clone, Debug, Default)]
pub struct CaseData {
    pub case: CaseMetadata,
    pub evidence: Vec<EvidenceItem>,
    pub artifacts: Vec<ArtifactInstance>,
    pub events: Vec<Event>,
    pub issues: Vec<Issue>,
    pub matches: Vec<Match>,
    pub findings: Vec<Finding>,
    pub manifest: Manifest,
}

impl CaseData {
    /// 各要素を Schema §6 の出力順へ整列した参照 slice を返す（event は Timeline 順）。
    ///
    /// 戻り値の `Vec` は整列済みの所有権付き list。元の [`CaseData`] は変更しない。
    pub fn sorted_views(&self) -> SortedViews<'_> {
        let mut evidence: Vec<&EvidenceItem> = self.evidence.iter().collect();
        evidence.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));

        let mut artifacts: Vec<&ArtifactInstance> = self.artifacts.iter().collect();
        artifacts.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));

        let mut events: Vec<Event> = self.events.clone();
        events.sort_by(|a, b| {
            let ka = tf_store::timeline::TimelineKey::from_event(a);
            let kb = tf_store::timeline::TimelineKey::from_event(b);
            ka.cmp(&kb)
        });

        let mut issues: Vec<&Issue> = self.issues.iter().collect();
        issues.sort_by(|a, b| {
            a.evidence_id
                .cmp(&b.evidence_id)
                .then_with(|| a.artifact_id.cmp(&b.artifact_id))
                .then_with(|| a.source_ordinal.cmp(&b.source_ordinal))
                .then_with(|| a.issue_id.cmp(&b.issue_id))
        });

        let mut matches: Vec<&Match> = self.matches.iter().collect();
        matches.sort_by(|a, b| a.match_id.cmp(&b.match_id));

        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by(|a, b| {
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| a.finding_id.cmp(&b.finding_id))
        });

        SortedViews {
            evidence,
            artifacts,
            events,
            issues,
            matches,
            findings,
        }
    }

    /// Event 件数。
    pub fn event_count(&self) -> u64 {
        self.events.len() as u64
    }

    /// Evidence 件数。
    pub fn evidence_count(&self) -> u64 {
        self.evidence.len() as u64
    }

    /// Issue 件数。
    pub fn issue_count(&self) -> u64 {
        self.issues.len() as u64
    }

    /// Match 件数。
    pub fn match_count(&self) -> u64 {
        self.matches.len() as u64
    }

    /// Finding 件数。
    pub fn finding_count(&self) -> u64 {
        self.findings.len() as u64
    }

    /// Artifact 件数。
    pub fn artifact_count(&self) -> u64 {
        self.artifacts.len() as u64
    }
}

/// 整列済みの参照 slice の集合。[`CaseData::sorted_views`] が返す。
///
/// `events` だけ所有権付き [`Vec`]<[`Event`]> になっている。これは Timeline 順 sort が
/// [`tf_store::timeline::TimelineKey`] を都度計算するため、参照で sort すると借用が
/// 衝突するからである。実用上の events 件数は Memory に載る範囲を想定する
/// （Phase 7・[`CaseData`] の用途）。100万 Event 規模の streaming は Phase 3 経路を使う。
pub struct SortedViews<'a> {
    pub evidence: Vec<&'a EvidenceItem>,
    pub artifacts: Vec<&'a ArtifactInstance>,
    pub events: Vec<Event>,
    pub issues: Vec<&'a Issue>,
    pub matches: Vec<&'a Match>,
    pub findings: Vec<&'a Finding>,
}

/// Schema §6 出力順の Severity 降順ランク（critical=5..informational=1）。
fn severity_rank(s: tf_core::case::Severity) -> u8 {
    use tf_core::case::Severity;
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_views_sorts_evidence_by_id() {
        let data = CaseData {
            evidence: vec![
                EvidenceItem {
                    evidence_id: "tf-evidence-v1:b".into(),
                    source_locator: "b".into(),
                    size: 1,
                    sha256: "b".repeat(64),
                    integrity_status: tf_core::case::IntegrityStatus::VerifiedSnapshot,
                    parse_eligible: true,
                    snapshot_locator: String::new(),
                },
                EvidenceItem {
                    evidence_id: "tf-evidence-v1:a".into(),
                    source_locator: "a".into(),
                    size: 1,
                    sha256: "a".repeat(64),
                    integrity_status: tf_core::case::IntegrityStatus::VerifiedSnapshot,
                    parse_eligible: true,
                    snapshot_locator: String::new(),
                },
            ],
            ..Default::default()
        };
        let v = data.sorted_views();
        assert_eq!(v.evidence[0].evidence_id, "tf-evidence-v1:a");
        assert_eq!(v.evidence[1].evidence_id, "tf-evidence-v1:b");
    }
}
