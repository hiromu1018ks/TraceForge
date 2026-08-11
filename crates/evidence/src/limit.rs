//! Resource limit framework（規範 §18、Schema §8.2）。
//!
//! 2種類の limit を管理する:
//!
//! - **事前 limit**: file size や Rule 数など、処理開始前に判定できるもの。
//!   処理開始前に検査する（規範 §18）。
//! - **逐次 limit**: Event 数や match 数など、1件ずつ増加するもの。
//!   1件追加する直前に検査する（規範 §18）。
//!
//! limit 到達時は次の5動作を行う（規範 §18）:
//!
//! 1. 対象処理を安全な境界で停止する
//! 2. `TF-W-LIMIT-*` Issue を出力する
//! 3. Analysis Manifest の `complete` を `false` にする
//! 4. strict limits でなければ Exit Code 1、strict limits なら Exit Code 6
//! 5. 上限を超えた結果を黙って切り捨てない

use tf_core::config::LimitsConfig;
use tf_core::error::ExitCode;
use tf_core::issue::{Issue, IssueScope, IssueSeverity};

/// limit の種別（Schema §8.2 の全項目）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// 処理する file 数の上限（Schema §8.2: `max_files`）。
    MaxFiles,
    /// 再帰の最大深度（Schema §8.2: `max_recursion_depth`）。
    MaxRecursionDepth,
    /// 1件の Evidence file の最大 size（Schema §8.2: `max_evidence_file_size_bytes`）。
    MaxEvidenceFileSizeBytes,
    /// snapshot 合計 size の上限（Schema §8.2: `max_snapshot_total_bytes`、規範 §5.5）。
    MaxSnapshotTotalBytes,
    /// Event 数の上限（Schema §8.2: `max_events`）。
    MaxEvents,
    /// Issue 数の上限（Schema §8.2: `max_issues`）。
    MaxIssues,
    /// Evidence 1件あたりの Issue 数上限（Schema §8.2: `max_issues_per_evidence`）。
    MaxIssuesPerEvidence,
    /// Finding 数の上限（Schema §8.2: `max_findings`）。
    MaxFindings,
    /// Correlation Rule 1件あたりの match 数上限（Schema §8.2: `max_correlation_matches_per_rule`）。
    MaxCorrelationMatchesPerRule,
    /// Correlation window の最大秒数（Schema §8.2: `max_correlation_window_seconds`）。
    MaxCorrelationWindowSeconds,
    /// YARA-X scan 対象 file の最大 size（Schema §8.2: `max_yara_scan_file_size_bytes`）。
    MaxYaraScanFileSizeBytes,
    /// Rule file 数の上限（Schema §8.2: `max_rule_files`）。
    MaxRuleFiles,
    /// Rule file 1件の最大 size（Schema §8.2: `max_rule_file_size_bytes`）。
    MaxRuleFileSizeBytes,
    /// memory 使用量の上限（Schema §8.2: `max_memory_bytes`）。
    MaxMemoryBytes,
}

impl LimitKind {
    /// limit に対応する Issue code（`TF-W-LIMIT-*`、規範 §18-2）を返す。
    pub fn issue_code(&self) -> &'static str {
        match self {
            LimitKind::MaxFiles => "TF-W-LIMIT-MAX-FILES",
            LimitKind::MaxRecursionDepth => "TF-W-LIMIT-MAX-RECURSION-DEPTH",
            LimitKind::MaxEvidenceFileSizeBytes => "TF-W-LIMIT-MAX-EVIDENCE-FILE-SIZE-BYTES",
            LimitKind::MaxSnapshotTotalBytes => "TF-W-LIMIT-MAX-SNAPSHOT-TOTAL-BYTES",
            LimitKind::MaxEvents => "TF-W-LIMIT-MAX-EVENTS",
            LimitKind::MaxIssues => "TF-W-LIMIT-MAX-ISSUES",
            LimitKind::MaxIssuesPerEvidence => "TF-W-LIMIT-MAX-ISSUES-PER-EVIDENCE",
            LimitKind::MaxFindings => "TF-W-LIMIT-MAX-FINDINGS",
            LimitKind::MaxCorrelationMatchesPerRule => {
                "TF-W-LIMIT-MAX-CORRELATION-MATCHES-PER-RULE"
            }
            LimitKind::MaxCorrelationWindowSeconds => "TF-W-LIMIT-MAX-CORRELATION-WINDOW-SECONDS",
            LimitKind::MaxYaraScanFileSizeBytes => "TF-W-LIMIT-MAX-YARA-SCAN-FILE-SIZE-BYTES",
            LimitKind::MaxRuleFiles => "TF-W-LIMIT-MAX-RULE-FILES",
            LimitKind::MaxRuleFileSizeBytes => "TF-W-LIMIT-MAX-RULE-FILE-SIZE-BYTES",
            LimitKind::MaxMemoryBytes => "TF-W-LIMIT-MAX-MEMORY-BYTES",
        }
    }

    /// Schema §8.2 の設定値を返す。
    pub fn configured_value(&self, limits: &LimitsConfig) -> u64 {
        match self {
            LimitKind::MaxFiles => limits.max_files,
            LimitKind::MaxRecursionDepth => limits.max_recursion_depth,
            LimitKind::MaxEvidenceFileSizeBytes => limits.max_evidence_file_size_bytes,
            LimitKind::MaxSnapshotTotalBytes => limits.max_snapshot_total_bytes,
            LimitKind::MaxEvents => limits.max_events,
            LimitKind::MaxIssues => limits.max_issues,
            LimitKind::MaxIssuesPerEvidence => limits.max_issues_per_evidence,
            LimitKind::MaxFindings => limits.max_findings,
            LimitKind::MaxCorrelationMatchesPerRule => limits.max_correlation_matches_per_rule,
            LimitKind::MaxCorrelationWindowSeconds => limits.max_correlation_window_seconds,
            LimitKind::MaxYaraScanFileSizeBytes => limits.max_yara_scan_file_size_bytes,
            LimitKind::MaxRuleFiles => limits.max_rule_files,
            LimitKind::MaxRuleFileSizeBytes => limits.max_rule_file_size_bytes,
            LimitKind::MaxMemoryBytes => limits.max_memory_bytes,
        }
    }
}

/// limit 到達の記録（規範 §18-2/3/4）。
#[derive(Clone, Debug)]
pub struct LimitBreach {
    /// 到達した limit の種別。
    pub kind: LimitKind,
    /// 到達時の現在値。
    pub current: u64,
    /// 設定された上限値。
    pub limit: u64,
    /// 到達に伴う Issue（規範 §18-2: `TF-W-LIMIT-*`）。
    pub issue: Issue,
}

/// 逐次 limit の検査結果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitCheck {
    /// 追加を許可する。
    Allowed,
    /// limit に到達したため、これ以上追加できない。
    Reached(LimitKind),
}

/// 事前・逐次 limit の統合管理（規範 §18）。
#[derive(Clone, Debug)]
pub struct LimitTracker {
    limits: LimitsConfig,
    /// snapshot 合計 size の累積（規範 §5.5・Schema §8.2: max_snapshot_total_bytes）。
    snapshot_total_bytes: u64,
    /// 到達した limit の一覧。Manifest の `complete=false` と incomplete_reasons へ反映する。
    breaches: Vec<LimitBreach>,
}

impl LimitTracker {
    /// 設定値から tracker を作成する。
    pub fn new(limits: LimitsConfig) -> Self {
        LimitTracker {
            limits,
            snapshot_total_bytes: 0,
            breaches: Vec::new(),
        }
    }

    /// 到達した limit があるか（規範 §18-3: `complete` を false にする根拠）。
    pub fn has_breach(&self) -> bool {
        !self.breaches.is_empty()
    }

    /// 到達した limit の一覧を取得する。
    pub fn breaches(&self) -> &[LimitBreach] {
        &self.breaches
    }

    /// limit 到達時の Exit Code（規範 §18-4: strict なら 6、そうでなければ 1）。
    pub fn exit_code(&self, strict_limits: bool) -> ExitCode {
        if self.has_breach() {
            if strict_limits {
                ExitCode::StrictParserOrStrictLimitsError
            } else {
                ExitCode::CaseWithWarnings
            }
        } else {
            ExitCode::Success
        }
    }

    /// 到達した limit の Issue 一覧を取得する（規範 §18-2: `TF-W-LIMIT-*`）。
    pub fn limit_issues(&self) -> Vec<Issue> {
        self.breaches.iter().map(|b| b.issue.clone()).collect()
    }

    // ===== 事前 limit（規範 §18: 処理開始前に検査）=====

    /// Evidence file size が事前 limit 内か検査する（Schema §8.2: `max_evidence_file_size_bytes`）。
    ///
    /// 超過する場合は `false` を返し、`breaches` へ記録する。
    /// 該当 Evidence は snapshot 対象から外す（規範 §18-1: 安全な境界で停止）。
    pub fn check_evidence_file_size(&mut self, file_size: u64, evidence_id: &str) -> bool {
        let limit = self.limits.max_evidence_file_size_bytes;
        if file_size > limit {
            self.record_breach(
                LimitKind::MaxEvidenceFileSizeBytes,
                file_size,
                limit,
                Some(evidence_id),
                &format!(
                    "Evidence file size ({file_size} bytes) が上限 ({limit} bytes) を超えるため処理を skip した"
                ),
            );
            false
        } else {
            true
        }
    }

    /// YARA-X scan 対象 file size が事前 limit 内か検査する（Schema §8.2）。
    pub fn check_yara_scan_file_size(&mut self, file_size: u64, evidence_id: &str) -> bool {
        let limit = self.limits.max_yara_scan_file_size_bytes;
        if file_size > limit {
            self.record_breach(
                LimitKind::MaxYaraScanFileSizeBytes,
                file_size,
                limit,
                Some(evidence_id),
                &format!(
                    "YARA scan 対象 size ({file_size} bytes) が上限 ({limit} bytes) を超えるため scan を skip した"
                ),
            );
            false
        } else {
            true
        }
    }

    /// snapshot 合計 size に新規分を追加できるか検査する（規範 §5.5・Schema §8.2）。
    ///
    /// 追加可能な場合は累積へ加算して `true` を返す。
    /// 超過する場合は `false` を返し、その Evidence の snapshot を skip する。
    pub fn try_add_snapshot_bytes(&mut self, additional: u64, evidence_id: &str) -> bool {
        let limit = self.limits.max_snapshot_total_bytes;
        let new_total = self.snapshot_total_bytes.saturating_add(additional);
        if new_total > limit {
            self.record_breach(
                LimitKind::MaxSnapshotTotalBytes,
                new_total,
                limit,
                Some(evidence_id),
                &format!(
                    "snapshot 合計 size ({new_total} bytes) が上限 ({limit} bytes) に到達したため snapshot を skip した"
                ),
            );
            false
        } else {
            self.snapshot_total_bytes = new_total;
            true
        }
    }

    // ===== 逐次 limit（規範 §18: 1件追加する直前に検査）=====

    /// 逐次 limit を1件追加する直前に検査する（規範 §18）。
    ///
    /// `kind` で指定した limit について、`current_count` が上限に達しているかを確認する。
    /// 到達している場合は `LimitCheck::Reached` を返し、breaches へ記録する。
    /// 未到達の場合は `LimitCheck::Allowed` を返す。
    ///
    /// 呼出側は `Allowed` を受けてから実際に1件追加すること（規範 §18: 1件追加する直前に検査）。
    pub fn check_incremental(
        &mut self,
        kind: LimitKind,
        current_count: u64,
        evidence_id: Option<&str>,
    ) -> LimitCheck {
        let limit = kind.configured_value(&self.limits);
        if current_count >= limit {
            // 規範 §18-5: 上限を超えた結果を黙って切り捨てない。
            // 既に同じ kind で breach が記録済みなら重複記録しない。
            let already = self.breaches.iter().any(|b| b.kind == kind);
            if !already {
                self.record_breach(
                    kind,
                    current_count,
                    limit,
                    evidence_id,
                    &format!(
                        "{} ({current_count}) が上限 ({limit}) に到達したため処理を打ち切った",
                        kind.issue_code()
                    ),
                );
            }
            LimitCheck::Reached(kind)
        } else {
            LimitCheck::Allowed
        }
    }

    /// breach を記録する内部 helper。
    fn record_breach(
        &mut self,
        kind: LimitKind,
        current: u64,
        limit: u64,
        evidence_id: Option<&str>,
        message: &str,
    ) {
        let issue = Issue {
            issue_id: kind.issue_code().to_string(),
            severity: IssueSeverity::Warning,
            scope: IssueScope::Case,
            evidence_id: evidence_id.map(|s| s.to_string()),
            artifact_id: None,
            record_locator: None,
            source_ordinal: None,
            message: message.to_string(),
        };
        self.breaches.push(LimitBreach {
            kind,
            current,
            limit,
            issue,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_limits() -> LimitsConfig {
        LimitsConfig {
            max_files: 100,
            max_recursion_depth: 10,
            max_evidence_file_size_bytes: 1_000,
            max_snapshot_total_bytes: 10_000,
            max_events: 50,
            max_issues: 100,
            max_issues_per_evidence: 10,
            max_findings: 10,
            max_correlation_matches_per_rule: 5,
            max_correlation_window_seconds: 3600,
            max_yara_scan_file_size_bytes: 500,
            max_rule_files: 100,
            max_rule_file_size_bytes: 1_000,
            max_memory_bytes: 1_000_000,
        }
    }

    #[test]
    fn no_breach_means_success_exit() {
        let tracker = LimitTracker::new(LimitsConfig::default());
        assert!(!tracker.has_breach());
        assert_eq!(tracker.exit_code(false), ExitCode::Success);
        assert_eq!(tracker.exit_code(true), ExitCode::Success);
    }

    #[test]
    fn breach_in_non_strict_is_exit_code_1() {
        // 規範 §18-4: strict limits でなければ Exit Code 1。
        let mut tracker = LimitTracker::new(small_limits());
        tracker.check_evidence_file_size(2_000, "tf-evidence-v1:x");
        assert_eq!(tracker.exit_code(false), ExitCode::CaseWithWarnings);
    }

    #[test]
    fn breach_in_strict_is_exit_code_6() {
        // 規範 §18-4: strict limits なら Exit Code 6。
        let mut tracker = LimitTracker::new(small_limits());
        tracker.check_evidence_file_size(2_000, "tf-evidence-v1:x");
        assert_eq!(
            tracker.exit_code(true),
            ExitCode::StrictParserOrStrictLimitsError
        );
    }

    #[test]
    fn pre_check_evidence_file_size() {
        // 規範 §18: 事前 limit。
        let mut tracker = LimitTracker::new(small_limits());
        assert!(tracker.check_evidence_file_size(500, "ev1"));
        assert!(!tracker.has_breach());

        assert!(!tracker.check_evidence_file_size(2_000, "ev2"));
        assert!(tracker.has_breach());
        assert_eq!(tracker.breaches().len(), 1);
        assert_eq!(
            tracker.breaches()[0].kind,
            LimitKind::MaxEvidenceFileSizeBytes
        );
    }

    #[test]
    fn pre_check_yara_scan_size() {
        let mut tracker = LimitTracker::new(small_limits());
        assert!(tracker.check_yara_scan_file_size(400, "ev1"));
        assert!(!tracker.check_yara_scan_file_size(600, "ev2"));
        assert!(tracker.has_breach());
    }

    #[test]
    fn snapshot_total_accumulates() {
        // 規範 §5.5・Schema §8.2: max_snapshot_total_bytes。
        let mut tracker = LimitTracker::new(small_limits());
        assert!(tracker.try_add_snapshot_bytes(4_000, "ev1"));
        assert!(tracker.try_add_snapshot_bytes(4_000, "ev2")); // total = 8000 < 10000
        assert!(tracker.try_add_snapshot_bytes(1_500, "ev3")); // total = 9500 < 10000
        assert!(!tracker.try_add_snapshot_bytes(1_000, "ev4")); // total would be 10500 > 10000
        assert!(tracker.has_breach());
        assert_eq!(tracker.breaches()[0].kind, LimitKind::MaxSnapshotTotalBytes);
    }

    #[test]
    fn incremental_check_allows_under_limit() {
        // 規範 §18: 1件追加する直前に検査。
        let mut tracker = LimitTracker::new(small_limits());
        for i in 0..49 {
            assert_eq!(
                tracker.check_incremental(LimitKind::MaxEvents, i, None),
                LimitCheck::Allowed
            );
        }
        assert!(!tracker.has_breach());
    }

    #[test]
    fn incremental_check_blocks_at_limit() {
        // 規範 §18-1: 安全な境界で停止。
        let mut tracker = LimitTracker::new(small_limits());
        assert_eq!(
            tracker.check_incremental(LimitKind::MaxEvents, 50, None),
            LimitCheck::Reached(LimitKind::MaxEvents)
        );
        assert!(tracker.has_breach());
        // TF-W-LIMIT-MAX-EVENTS Issue が生成されている。
        assert_eq!(tracker.limit_issues().len(), 1);
        assert_eq!(tracker.limit_issues()[0].issue_id, "TF-W-LIMIT-MAX-EVENTS");
    }

    #[test]
    fn incremental_does_not_duplicate_breach() {
        // 規範 §18: 同じ kind の breach を重複記録しない。
        let mut tracker = LimitTracker::new(small_limits());
        tracker.check_incremental(LimitKind::MaxEvents, 50, None);
        tracker.check_incremental(LimitKind::MaxEvents, 51, None);
        assert_eq!(tracker.breaches().len(), 1);
    }

    #[test]
    fn limit_issues_for_manifest() {
        // 規範 §18-2/3: TF-W-LIMIT-* Issue と complete=false の根拠。
        let mut tracker = LimitTracker::new(small_limits());
        tracker.check_evidence_file_size(2_000, "ev1");
        tracker.check_incremental(LimitKind::MaxEvents, 50, None);
        let issues = tracker.limit_issues();
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(|i| i.issue_id.starts_with("TF-W-LIMIT-")));
    }

    #[test]
    fn all_limit_kinds_have_issue_codes() {
        // 規範 §18-2: 全 limit 種別が TF-W-LIMIT-* code を持つ。
        let kinds = [
            LimitKind::MaxFiles,
            LimitKind::MaxRecursionDepth,
            LimitKind::MaxEvidenceFileSizeBytes,
            LimitKind::MaxSnapshotTotalBytes,
            LimitKind::MaxEvents,
            LimitKind::MaxIssues,
            LimitKind::MaxIssuesPerEvidence,
            LimitKind::MaxFindings,
            LimitKind::MaxCorrelationMatchesPerRule,
            LimitKind::MaxCorrelationWindowSeconds,
            LimitKind::MaxYaraScanFileSizeBytes,
            LimitKind::MaxRuleFiles,
            LimitKind::MaxRuleFileSizeBytes,
            LimitKind::MaxMemoryBytes,
        ];
        for kind in kinds {
            assert!(
                kind.issue_code().starts_with("TF-W-LIMIT-"),
                "{kind:?} の code が不正: {}",
                kind.issue_code()
            );
        }
    }
}
