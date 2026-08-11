//! YARA-X scanner と mode handling（T5-024・T5-025・T5-026・T5-027）。
//!
//! 互換 §7・規範 §15.2・Schema §8.2/8.3 に従い、verified snapshot bytes への
//! YARA-X scan と対象 Evidence 選択を実装する。
//!
//! ## T5-024: Verified Snapshot のみ scan
//!
//! 規範 §15.2 は「YARA-X は Verified Snapshot だけを scan する。scan 対象を実行、load、
//! shell open してはならない」とする。本 scanner は [`YaraEvidenceScanTarget`] の
//! `snapshot_bytes: &[u8]` を受け取り、file I/O を全く行わない。
//! 呼出側（Phase 7 CLI・Phase 6 Finding pipeline）が verified snapshot bytes を用意する。
//!
//! ## T5-025: `all` / `suspicious` / `explicit` mode
//!
//! Schema §8.3 の `yara.mode` へ従い scan 対象 Evidence を制御する。
//! [`select_evidence_for_mode`] が各 mode に応じた Evidence 一覧を返す。
//!
//! ## T5-026: suspicious mode の Evidence ID 解決（host path 推測禁止）
//!
//! 規範 §15.2・§21-13 は「suspicious mode は Event 内 Windows path ではなく、
//! Finding または Correlation が参照する Evidence ID から snapshot を解決する。
//! Evidence ID へ解決できない path を推測で local filesystem から scan してはならない」
//! とする。本 module は Evidence ID のみを受け付け、Windows path からの推測は一切行わない。
//!
//! ## T5-027: `max_yara_scan_file_size_bytes` 適用
//!
//! Schema §8.2 の `max_yara_scan_file_size_bytes` を scan 対象の byte 数へ適用する。
//! 上限を超える Evidence は skip し、Warning を記録する（規範 §18: 上限を超えた結果を
//! 黙って切り捨てない）。

use tf_core::case::EvidenceItem;
use tf_core::config::YaraMode;

use crate::yara::YaraRuleset;
use crate::yara::compiler::CompiledYaraFile;
use crate::yara::r#match::{MetadataValue, YaraMatchResult, YaraPatternInfo, build_yara_match};

/// YARA-X scan 対象の Evidence 1件（T5-024）。
///
/// 規範 §15.2 に従い verified snapshot の bytes のみを受け取る。
/// 呼出側は [`EvidenceItem::integrity_status`] が `VerifiedSnapshot` の Evidence のみを
/// 対象とし、file path ではなく snapshot の内容 bytes を渡す。
#[derive(Clone, Debug)]
pub struct YaraEvidenceScanTarget<'a> {
    /// 対象 Evidence の ID（[`EvidenceItem::evidence_id`]）。
    pub evidence_id: String,
    /// Verified Snapshot の byte 内容。YARA-X はこの bytes へ対して pattern match を行う。
    /// file I/O は行わない（規範 §15.2: 実行・load・shell open 禁止）。
    pub snapshot_bytes: &'a [u8],
}

/// YARA-X scan の結果（T5-022・T5-024・T5-027）。
///
/// 全対象 Evidence への scan を完了した後の集計結果。各 Evidence 毎の match を集約し、
/// skip した Evidence とその理由（上限超過・mode 不一致等）を記録する。
#[derive(Clone, Debug, Default)]
pub struct YaraScanResults {
    /// 全 Evidence の全 match を集約した list（決定的順序: evidence_id → rule_id → pattern 順）。
    pub matches: Vec<YaraMatchResult>,
    /// scan を skip した Evidence ID とその理由（規範 §18: 黙って切り捨てない）。
    pub skipped: Vec<YaraScanSkip>,
}

/// scan skip の記録（規範 §18・T5-027）。
#[derive(Clone, Debug)]
pub struct YaraScanSkip {
    /// 対象 Evidence ID。
    pub evidence_id: String,
    /// skip 理由のコード（`TF-W-LIMIT-MAX-YARA-SCAN-FILE-SIZE-BYTES` 等）。
    pub code: String,
    /// 人間可読の詳細メッセージ。
    pub message: String,
}

/// [`YaraMode`] の解決時に出力される Warning（T5-025・T5-026）。
///
/// `suspicious` / `explicit` mode で対象 Evidence ID が case 内に存在しない場合等に
/// 記録する。規範 §18（黙って切り捨てない）への準拠。
#[derive(Clone, Debug)]
pub struct ModeResolutionWarning {
    /// Warning を発した Evidence ID または参照文字列。
    pub reference: String,
    /// Warning の内容。
    pub message: String,
}

/// YARA-X scanner（T5-020・T5-024・T5-027）。
///
/// [`YaraRuleset`] へ対して scan を行う。scan は single-thread（yara-x の `Rules` が
/// `!Send` / `!Sync` のため）。
pub struct YaraScanner {
    ruleset: YaraRuleset,
    /// Schema §8.2: `max_yara_scan_file_size_bytes`。上限を超える Evidence は skip する。
    max_scan_file_size_bytes: u64,
}

impl YaraScanner {
    /// 新しい scanner を構築する。
    ///
    /// `max_scan_file_size_bytes` は Schema §8.2 の `max_yara_scan_file_size_bytes`
    /// （既定 1 GiB）。1 以上必須（Schema §8.3）。
    pub fn new(ruleset: YaraRuleset, max_scan_file_size_bytes: u64) -> Self {
        assert!(
            max_scan_file_size_bytes >= 1,
            "max_yara_scan_file_size_bytes は 1 以上必須（Schema §8.3）"
        );
        YaraScanner {
            ruleset,
            max_scan_file_size_bytes,
        }
    }

    /// 全対象 Evidence へ scan を実行する（T5-022・T5-024・T5-027）。
    ///
    /// 規範 §15.2・Schema §8.2 に従い:
    /// 1. 各 [`YaraEvidenceScanTarget`] 毎に byte size を検査する（T5-027）。
    ///    上限を超える場合は skip し [`YaraScanSkip`] へ記録する（規範 §18）。
    /// 2. 各 [`CompiledYaraFile`] 毎に独立した [`yara_x::Scanner`] で scan する。
    ///    YARA-X の `Rules` は `!Send` / `!Sync` のため thread 越し共有しない。
    /// 3. match した YARA Rule 毎に Schema §5.7 の Match を構築し、決定的順序で集約する。
    ///
    /// 出力順序は evidence_id 昇順 → rule SHA-256 昇順 → YARA Rule 内宣言順で安定する
    /// （規範 §13: 決定性）。
    pub fn scan(&self, targets: &[YaraEvidenceScanTarget<'_>]) -> YaraScanResults {
        let mut results = YaraScanResults::default();

        // evidence_id 昇順で処理順序を安定化（規範 §13）。
        // 元の targets 順序に依存しないよう、sort 済み index list を作る。
        let mut order: Vec<usize> = (0..targets.len()).collect();
        order.sort_by(|&a, &b| targets[a].evidence_id.cmp(&targets[b].evidence_id));

        for &target_idx in &order {
            let target = &targets[target_idx];

            // T5-027: max_yara_scan_file_size_bytes の事前検査（規範 §18）。
            let size = target.snapshot_bytes.len() as u64;
            if size > self.max_scan_file_size_bytes {
                results.skipped.push(YaraScanSkip {
                    evidence_id: target.evidence_id.clone(),
                    code: "TF-W-LIMIT-MAX-YARA-SCAN-FILE-SIZE-BYTES".into(),
                    message: format!(
                        "YARA scan 対象 size ({size} bytes) が上限 ({limit} bytes) を超えるため scan を skip した",
                        limit = self.max_scan_file_size_bytes
                    ),
                });
                continue;
            }

            // file 毎に scan（ruleset は SHA-256 昇順で安定順序）。
            for compiled in self.ruleset.files() {
                let matches = scan_with_file(compiled, target);
                results.matches.extend(matches);
            }
        }

        results
    }

    /// scanner が保持する ruleset の file 数。
    pub fn ruleset_file_count(&self) -> usize {
        self.ruleset.len()
    }
}

/// 1 file の [`CompiledYaraFile`] で1 Evidence を scan する。
///
/// 規範 §15.2・T5-022 に従い、match した YARA Rule 毎に [`Match`] を構築する。
fn scan_with_file(
    compiled: &CompiledYaraFile,
    target: &YaraEvidenceScanTarget<'_>,
) -> Vec<YaraMatchResult> {
    let rules = compiled.rules();
    let mut scanner = yara_x::Scanner::new(rules);

    // scan は Result を返すが、入力 bytes のみなので通常成功する。
    // error 時は panic せず空 list を返す（規範 §9.4: 最終安全網）。
    let scan_results = match scanner.scan(target.snapshot_bytes) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // YARA-X が報告した matching rules を順に処理。
    // yara-x は !Send / !Sync だが、scan_results から所有権を移動できるデータは
    // drop 境界を越えて安全にコピーできる（String・整数等のみ）。
    let mut out = Vec::new();
    for matching_rule in scan_results.matching_rules() {
        let rule_identifier = matching_rule.identifier().to_string();
        let namespace = matching_rule.namespace().to_string();

        // T5-022: tags・metadata・matched pattern identifier を抽出。
        let tags: Vec<String> = matching_rule
            .tags()
            .map(|t| t.identifier().to_string())
            .collect();
        let metadata: Vec<(String, MetadataValue)> = matching_rule
            .metadata()
            .map(|(k, v)| (k.to_string(), convert_meta_value(v)))
            .collect();

        // T5-022: matched pattern identifier（例: $a, $b）と種別を抽出。
        let mut patterns: Vec<YaraPatternInfo> = Vec::new();
        for pattern in matching_rule.patterns() {
            // match が1件以上ある pattern のみを記録（match しなかった pattern は除外）。
            if pattern.matches().next().is_some() {
                patterns.push(YaraPatternInfo {
                    identifier: pattern.identifier().to_string(),
                    kind: pattern_kind_str(pattern.kind()).to_string(),
                });
            }
        }

        // patterns を alphabetical 順へ sort（決定性・規範 §13）。
        patterns.sort_by(|a, b| a.identifier.cmp(&b.identifier));

        let match_value = build_yara_match(
            &target.evidence_id,
            compiled,
            &rule_identifier,
            &namespace,
            &tags,
            &metadata,
            &patterns,
        );

        out.push(YaraMatchResult { match_value });
    }
    out
}

/// [`yara_x::MetaValue`] から [`MetadataValue`] への変換。
fn convert_meta_value(value: yara_x::MetaValue) -> MetadataValue {
    match value {
        yara_x::MetaValue::Integer(n) => MetadataValue::Integer(n),
        yara_x::MetaValue::Float(f) => MetadataValue::Float(f),
        yara_x::MetaValue::Bool(b) => MetadataValue::Bool(b),
        yara_x::MetaValue::String(s) => MetadataValue::Str(s.to_string()),
        yara_x::MetaValue::Bytes(b) => {
            // BStr は bytes として扱い、lower-case hex 文字列へ変換する（決定的表現）。
            MetadataValue::Bytes(hex::encode(b))
        }
    }
}

/// [`yara_x::PatternKind`] を文字列表現へ変換（T5-022）。
fn pattern_kind_str(kind: yara_x::PatternKind) -> &'static str {
    match kind {
        yara_x::PatternKind::Text => "text",
        yara_x::PatternKind::Hex => "hex",
        yara_x::PatternKind::Regexp => "regex",
    }
}

/// YARA scan mode（Schema §8.3・規範 §15.2・T5-025・T5-026）。
///
/// [`tf_core::config::YaraMode`] と同等だが、scan 対象選択の文脈で明示的な型を持つ。
/// `select_evidence_for_mode` の引数として用いる。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YaraScanMode {
    /// 全 Verified Snapshot を scan する（Schema §8.3: `all`）。
    All,
    /// Finding / Correlation が参照する Evidence ID のみを scan する（`suspicious`）。
    /// Evidence ID へ解決できない host path は scan しない（規範 §15.2・§21-13・T5-026）。
    Suspicious,
    /// 利用者が明示した Evidence ID のみを scan する（`explicit`）。
    Explicit,
}

impl From<YaraMode> for YaraScanMode {
    fn from(mode: YaraMode) -> Self {
        match mode {
            YaraMode::All => YaraScanMode::All,
            YaraMode::Suspicious => YaraScanMode::Suspicious,
            YaraMode::Explicit => YaraScanMode::Explicit,
        }
    }
}

/// mode に応じて scan 対象 Evidence を選択する（T5-025・T5-026）。
///
/// 引数:
/// - `mode`: scan mode。
/// - `all_evidence`: case 内の全 Evidence。`VerifiedSnapshot` 以外は事前除外する。
/// - `suspicious_evidence_ids`: Finding / Correlation が参照する Evidence ID 一覧。
///   `suspicious` mode のみ使用。
/// - `explicit_evidence_ids`: 利用者が明示した Evidence ID 一覧。
///   `explicit` mode のみ使用。
///
/// 戻り値:
/// - `(selected, warnings)`: 選択された Evidence 一覧と、解決失敗等の Warning list。
///
/// 規範 §15.2・§21-13（T5-026）: suspicious / explicit mode で Evidence ID が
/// `all_evidence` 内に見つからない場合、Warning を返し、推測で local filesystem から
/// scan することはしない。
///
/// 規範 §15.2・T5-024: `integrity_status` が `VerifiedSnapshot` 以外の Evidence は
/// 全 mode で除外する。
pub fn select_evidence_for_mode<'a>(
    mode: YaraScanMode,
    all_evidence: &'a [EvidenceItem],
    suspicious_evidence_ids: &[String],
    explicit_evidence_ids: &[String],
) -> (Vec<&'a EvidenceItem>, Vec<ModeResolutionWarning>) {
    // T5-024: Verified Snapshot のみを選択（規範 §15.2）。
    // 決定性のため evidence_id 順で処理する。
    let verified: Vec<&EvidenceItem> = all_evidence
        .iter()
        .filter(|e| tf_core::case::IntegrityStatus::VerifiedSnapshot == e.integrity_status)
        .collect();

    match mode {
        YaraScanMode::All => {
            // T5-025: 全 Verified Snapshot を scan 対象とする。
            (verified, Vec::new())
        }
        YaraScanMode::Suspicious => {
            // T5-026: suspicious_evidence_ids のみ。Evidence ID へ解決できない場合は
            // 推測で local filesystem から scan しない（規範 §15.2・§21-13）。
            resolve_evidence_subset(verified, suspicious_evidence_ids)
        }
        YaraScanMode::Explicit => resolve_evidence_subset(verified, explicit_evidence_ids),
    }
}

/// Evidence ID list から Verified Snapshot のみを解決するヘルパー。
///
/// Evidence ID が case 内に存在しない、または Verified Snapshot でない場合は
/// Warning を発し、推測による scan 対象の追加は行わない（規範 §15.2・§21-13・T5-026）。
fn resolve_evidence_subset<'a>(
    verified: Vec<&'a EvidenceItem>,
    requested_ids: &[String],
) -> (Vec<&'a EvidenceItem>, Vec<ModeResolutionWarning>) {
    // 決定的順序のため requested_ids を sort してから処理する。
    let mut sorted_requested: Vec<&String> = requested_ids.iter().collect();
    sorted_requested.sort();

    let mut selected: Vec<&EvidenceItem> = Vec::new();
    let mut warnings = Vec::new();

    for req_id in sorted_requested {
        match verified.iter().find(|e| &e.evidence_id == req_id) {
            Some(evidence) => selected.push(*evidence),
            None => warnings.push(ModeResolutionWarning {
                reference: req_id.to_string(),
                message: format!(
                    "Evidence ID '{req_id}' は Verified Snapshot 内に見つからないため YARA scan 対象から除外した（規範 §15.2・§21-13: host path 推測禁止）"
                ),
            }),
        }
    }

    (selected, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tf_core::case::{EvidenceItem, IntegrityStatus};
    use tf_core::r#match::MatchType;

    use crate::loader::RuleLoadOptions;
    use crate::loader::RuleRegistry;

    /// test 用: 1つの YARA Rule file から registry・ruleset を構築。
    fn compile_ruleset(rule_source: &str) -> YaraRuleset {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yar");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(rule_source.as_bytes()).unwrap();
        drop(f);

        let mut registry = RuleRegistry::new();
        registry
            .load(&path, dir.path(), &RuleLoadOptions::default())
            .unwrap();

        let summary = YaraRuleset::compile_from_registry(&registry);
        summary.into_ruleset()
    }

    fn make_evidence(evidence_id: &str, integrity: IntegrityStatus) -> EvidenceItem {
        EvidenceItem {
            evidence_id: evidence_id.to_string(),
            source_locator: format!("evidence/{evidence_id}"),
            size: 0,
            sha256: "a".repeat(64),
            integrity_status: integrity,
            parse_eligible: integrity == IntegrityStatus::VerifiedSnapshot,
            snapshot_locator: String::new(),
        }
    }

    // ===== T5-024: scanner は snapshot bytes のみを受け取る =====

    #[test]
    fn scan_uses_snapshot_bytes_only_no_file_io() {
        // 規範 §15.2: 実行・load・shell open 禁止。scanner は bytes のみ。
        let ruleset = compile_ruleset(r#"rule r { strings: $a = "Hello" condition: $a }"#);
        let scanner = YaraScanner::new(ruleset, 1024 * 1024);

        let bytes = b"Hello, World!";
        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:test".into(),
            snapshot_bytes: bytes,
        };

        let results = scanner.scan(&[target]);
        assert_eq!(results.matches.len(), 1, "Hello を含む bytes で match");
        assert!(results.skipped.is_empty());
    }

    #[test]
    fn scan_returns_empty_when_no_match() {
        let ruleset = compile_ruleset(r#"rule r { strings: $a = "TraceForge" condition: $a }"#);
        let scanner = YaraScanner::new(ruleset, 1024 * 1024);

        let bytes = b"nothing of interest here";
        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:ev1".into(),
            snapshot_bytes: bytes,
        };

        let results = scanner.scan(&[target]);
        assert!(results.matches.is_empty());
        assert!(results.skipped.is_empty());
    }

    // ===== T5-022: Match 型へ tags/meta/namespace/matched pattern が入る =====

    #[test]
    fn scan_match_preserves_tags_meta_patterns() {
        let ruleset = compile_ruleset(
            r#"
            rule traceforge_tagged : tag1 tag2 {
                meta:
                    author = "TraceForge"
                    severity = 5
                strings:
                    $a = "match me"
                condition:
                    $a
            }
            "#,
        );
        let scanner = YaraScanner::new(ruleset, 1024 * 1024);

        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:e1".into(),
            snapshot_bytes: b"please match me now",
        };

        let results = scanner.scan(&[target]);
        assert_eq!(results.matches.len(), 1);

        let m = &results.matches[0].match_value;
        assert_eq!(m.match_type, MatchType::YaraX);
        assert_eq!(m.rule_id, "traceforge_tagged");
        assert_eq!(m.evidence_ids, vec!["tf-evidence-v1:e1".to_string()]);
        assert_eq!(m.event_ids.len(), 0);

        // matched_patterns 拡張 field に tags / meta / pattern が保持される。
        let mp = m.matched_patterns.as_ref().unwrap();
        let root = mp.as_object().unwrap();
        let rule = root["rule"].as_object().unwrap();
        let tags = rule["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0], "tag1");
        assert_eq!(tags[1], "tag2");

        let meta = rule["metadata"].as_object().unwrap();
        assert_eq!(meta["author"], "TraceForge");
        assert_eq!(meta["severity"], 5);

        let patterns = root["patterns"].as_array().unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0]["identifier"], "$a");
    }

    // ===== T5-027: max_yara_scan_file_size_bytes =====

    #[test]
    fn scan_skips_oversize_evidence() {
        // Schema §8.2: max_yara_scan_file_size_bytes 上限を超える Evidence は skip。
        let ruleset = compile_ruleset(r#"rule r { condition: true }"#);
        // 上限を小さく設定し、簡単に超過させる。
        let scanner = YaraScanner::new(ruleset, 10);

        let oversize_bytes = b"0123456789ABCDEF"; // 16 bytes > 10 上限
        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:big".into(),
            snapshot_bytes: oversize_bytes,
        };

        let results = scanner.scan(&[target]);
        assert!(results.matches.is_empty(), "oversize は scan しない");
        assert_eq!(results.skipped.len(), 1);
        assert_eq!(results.skipped[0].evidence_id, "tf-evidence-v1:big");
        assert_eq!(
            results.skipped[0].code,
            "TF-W-LIMIT-MAX-YARA-SCAN-FILE-SIZE-BYTES"
        );
    }

    #[test]
    fn scan_includes_at_limit_boundary() {
        // size == limit の場合は skip しない（上限は「超える」場合に skip）。
        let ruleset = compile_ruleset(r#"rule r { condition: true }"#);
        let limit: u64 = 5;
        let scanner = YaraScanner::new(ruleset, limit);

        let exact_bytes = b"hello"; // 5 bytes == limit
        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:exact".into(),
            snapshot_bytes: exact_bytes,
        };

        let results = scanner.scan(&[target]);
        assert_eq!(results.matches.len(), 1, "limit と同 size は scan 対象");
        assert!(results.skipped.is_empty());
    }

    #[test]
    fn scan_continues_after_oversize_evidence() {
        // 規範 §18: 安全な境界で停止。oversize 1件を skip し、他は継続。
        let ruleset = compile_ruleset(r#"rule r { condition: true }"#);
        let scanner = YaraScanner::new(ruleset, 5);

        let small = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:small".into(),
            snapshot_bytes: b"hi",
        };
        let big = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:big".into(),
            snapshot_bytes: b"0123456789",
        };
        let small2 = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:small2".into(),
            snapshot_bytes: b"ok",
        };

        let results = scanner.scan(&[small, big, small2]);
        // small・small2 は match、big は skip。
        assert_eq!(results.matches.len(), 2);
        assert_eq!(results.skipped.len(), 1);
    }

    // ===== T5-025: mode 解決 =====

    #[test]
    fn mode_all_selects_all_verified_snapshots() {
        let evidence = vec![
            make_evidence("tf-evidence-v1:ev1", IntegrityStatus::VerifiedSnapshot),
            make_evidence("tf-evidence-v1:ev2", IntegrityStatus::VerifiedSnapshot),
            make_evidence("tf-evidence-v1:ev3", IntegrityStatus::ChangedDuringSnapshot),
        ];

        let (selected, warnings) = select_evidence_for_mode(YaraScanMode::All, &evidence, &[], &[]);

        assert_eq!(selected.len(), 2, "VerifiedSnapshot のみ");
        assert!(warnings.is_empty());
        let ids: Vec<&str> = selected.iter().map(|e| e.evidence_id.as_str()).collect();
        assert!(ids.contains(&"tf-evidence-v1:ev1"));
        assert!(ids.contains(&"tf-evidence-v1:ev2"));
    }

    #[test]
    fn mode_suspicious_resolves_only_given_ids() {
        let evidence = vec![
            make_evidence("tf-evidence-v1:ev1", IntegrityStatus::VerifiedSnapshot),
            make_evidence("tf-evidence-v1:ev2", IntegrityStatus::VerifiedSnapshot),
            make_evidence("tf-evidence-v1:ev3", IntegrityStatus::VerifiedSnapshot),
        ];

        // suspicious mode: ev2 と ev3 のみ
        let suspicious_ids = vec![
            "tf-evidence-v1:ev2".to_string(),
            "tf-evidence-v1:ev3".to_string(),
        ];
        let (selected, warnings) =
            select_evidence_for_mode(YaraScanMode::Suspicious, &evidence, &suspicious_ids, &[]);

        assert_eq!(selected.len(), 2);
        assert!(warnings.is_empty());
        let ids: Vec<&str> = selected.iter().map(|e| e.evidence_id.as_str()).collect();
        assert!(ids.contains(&"tf-evidence-v1:ev2"));
        assert!(ids.contains(&"tf-evidence-v1:ev3"));
    }

    #[test]
    fn mode_explicit_resolves_only_given_ids() {
        let evidence = vec![
            make_evidence("tf-evidence-v1:ev1", IntegrityStatus::VerifiedSnapshot),
            make_evidence("tf-evidence-v1:ev2", IntegrityStatus::VerifiedSnapshot),
        ];

        let explicit_ids = vec!["tf-evidence-v1:ev1".to_string()];
        let (selected, _warnings) =
            select_evidence_for_mode(YaraScanMode::Explicit, &evidence, &[], &explicit_ids);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].evidence_id, "tf-evidence-v1:ev1");
    }

    // ===== T5-026: suspicious mode で未解決 ID は推測しない（§21-13）=====

    #[test]
    fn mode_suspicious_unresolved_id_is_warning_not_guess() {
        // 規範 §21-13: Evidence ID へ解決できない path を推測で local filesystem
        // から scan してはならない。
        let evidence = vec![make_evidence(
            "tf-evidence-v1:ev1",
            IntegrityStatus::VerifiedSnapshot,
        )];

        // ev1 は存在するが、ev_unknown は存在しない。
        let suspicious_ids = vec![
            "tf-evidence-v1:ev1".to_string(),
            "tf-evidence-v1:ev_unknown".to_string(),
        ];
        let (selected, warnings) =
            select_evidence_for_mode(YaraScanMode::Suspicious, &evidence, &suspicious_ids, &[]);

        assert_eq!(selected.len(), 1, "解決できた ID のみ");
        assert_eq!(warnings.len(), 1, "未解決 ID は warning");
        assert_eq!(warnings[0].reference, "tf-evidence-v1:ev_unknown");
        assert!(
            warnings[0].message.contains("host path 推測禁止"),
            "推測禁止の旨を warning へ明記"
        );
    }

    #[test]
    fn mode_suspicious_excludes_non_verified_evidence() {
        // Verified Snapshot 以外の Evidence は suspicious mode でも除外する（規範 §15.2・T5-024）。
        let evidence = vec![
            make_evidence("tf-evidence-v1:bad", IntegrityStatus::ChangedDuringSnapshot),
            make_evidence("tf-evidence-v1:good", IntegrityStatus::VerifiedSnapshot),
        ];

        let suspicious_ids = vec![
            "tf-evidence-v1:bad".to_string(),
            "tf-evidence-v1:good".to_string(),
        ];
        let (selected, warnings) =
            select_evidence_for_mode(YaraScanMode::Suspicious, &evidence, &suspicious_ids, &[]);

        // good のみ選択、bad は warning（Verified でないため）。
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].evidence_id, "tf-evidence-v1:good");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].reference, "tf-evidence-v1:bad");
    }

    // ===== YaraMode → YaraScanMode 変換 =====

    #[test]
    fn yara_mode_to_scan_mode_conversion() {
        assert_eq!(YaraScanMode::from(YaraMode::All), YaraScanMode::All);
        assert_eq!(
            YaraScanMode::from(YaraMode::Suspicious),
            YaraScanMode::Suspicious
        );
        assert_eq!(
            YaraScanMode::from(YaraMode::Explicit),
            YaraScanMode::Explicit
        );
    }

    // ===== 決定性: 複数 Evidence の処理順序 =====

    #[test]
    fn scan_results_are_ordered_by_evidence_id() {
        // 規範 §13: 決定的順序。targets の入力順によらず evidence_id 昇順。
        let ruleset = compile_ruleset(r#"rule r { condition: true }"#);
        let scanner = YaraScanner::new(ruleset, 1024);

        // 意図的に逆順で渡す。
        let targets = vec![
            YaraEvidenceScanTarget {
                evidence_id: "tf-evidence-v1:zzz".into(),
                snapshot_bytes: b"a",
            },
            YaraEvidenceScanTarget {
                evidence_id: "tf-evidence-v1:aaa".into(),
                snapshot_bytes: b"a",
            },
            YaraEvidenceScanTarget {
                evidence_id: "tf-evidence-v1:mmm".into(),
                snapshot_bytes: b"a",
            },
        ];

        let results = scanner.scan(&targets);
        assert_eq!(results.matches.len(), 3);
        // evidence_id 昇順で並ぶ
        assert_eq!(
            results.matches[0].match_value.evidence_ids[0],
            "tf-evidence-v1:aaa"
        );
        assert_eq!(
            results.matches[1].match_value.evidence_ids[0],
            "tf-evidence-v1:mmm"
        );
        assert_eq!(
            results.matches[2].match_value.evidence_ids[0],
            "tf-evidence-v1:zzz"
        );
    }

    // ===== 空 ruleset =====

    #[test]
    fn empty_ruleset_scan_returns_no_matches() {
        let ruleset = YaraRuleset::empty();
        let scanner = YaraScanner::new(ruleset, 1024);
        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:e1".into(),
            snapshot_bytes: b"data",
        };
        let results = scanner.scan(&[target]);
        assert!(results.matches.is_empty());
        assert!(results.skipped.is_empty());
    }

    // ===== 複数 file にまたがる scan =====

    #[test]
    fn scan_with_multiple_rule_files_aggregates_matches() {
        // 2 file それぞれ別の YARA Rule を含む。同じ bytes へ対して両方 match する。
        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("a.yar");
        let mut f1 = fs::File::create(&path1).unwrap();
        f1.write_all(br#"rule r_a { strings: $a = "common" condition: $a }"#)
            .unwrap();
        drop(f1);
        let path2 = dir.path().join("b.yar");
        let mut f2 = fs::File::create(&path2).unwrap();
        f2.write_all(br#"rule r_b { strings: $a = "common" condition: $a }"#)
            .unwrap();
        drop(f2);

        let mut registry = RuleRegistry::new();
        registry
            .load(&path1, dir.path(), &RuleLoadOptions::default())
            .unwrap();
        registry
            .load(&path2, dir.path(), &RuleLoadOptions::default())
            .unwrap();

        let summary = YaraRuleset::compile_from_registry(&registry);
        let scanner = YaraScanner::new(summary.into_ruleset(), 1024);

        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:e1".into(),
            snapshot_bytes: b"this is common text",
        };
        let results = scanner.scan(&[target]);
        assert_eq!(results.matches.len(), 2, "両 file の rule が match");
    }

    // ===== T5-027: assert max >= 1 =====

    #[test]
    #[should_panic(expected = "max_yara_scan_file_size_bytes は 1 以上必須")]
    fn scanner_panics_on_zero_limit() {
        // Schema §8.3: limit は 1 以上。本実装は呼出側の事前検査を前提とするが、
        // 念のため assertion で保護する（規範 §9.4: 最終安全網）。
        let _ = YaraScanner::new(YaraRuleset::empty(), 0);
    }

    // ===== 危険な入力で panic しない =====

    #[test]
    fn scan_does_not_panic_on_empty_bytes() {
        let ruleset = compile_ruleset(r#"rule r { condition: true }"#);
        let scanner = YaraScanner::new(ruleset, 1024);

        let target = YaraEvidenceScanTarget {
            evidence_id: "tf-evidence-v1:empty".into(),
            snapshot_bytes: b"",
        };
        let results = scanner.scan(&[target]);
        // 空 bytes でも condition: true なので match する。
        assert_eq!(results.matches.len(), 1);
    }
}
