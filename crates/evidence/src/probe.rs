//! Artifact 識別 framework（規範 §11）。
//!
//! Artifact type は拡張子だけで決定してはならない（規範 §11）。
//! `filename / known path / magic / header / parser probe` の組み合わせで識別する。
//!
//! `probe` は次の5値のいずれかを返す（規範 §11）:
//!
//! - `Confirmed`: この形式であることが確定
//! - `Probable`: この形式の可能性が高いが確定できない
//! - `UnsupportedVersion`: 形式は識別したが対応外の version
//! - `NotThisFormat`: この形式ではない
//! - `Malformed`: 形式の判定自体ができないほど壊れている
//!
//! 複数 Parser が `Confirmed` を返した場合、互換性仕様書で許可された組み合わせだけを
//! 実行する。それ以外は ambiguous として skip する。`Probable` だけの場合は既定で
//! 解析せず Warning とする。

use std::path::Path;

use tf_core::case::ProbeResult;
use tf_core::event::ArtifactSource;
use tf_core::issue::{Issue, IssueScope, IssueSeverity};

/// Probe 実行時の入力情報。
#[derive(Clone, Debug)]
pub struct ProbeInput<'a> {
    /// 正規化済み source_locator（規範 §5.2）。
    pub source_locator: &'a str,
    /// 解析 host 上の file path。
    pub host_path: &'a Path,
    /// file 先頭の bytes（magic / header 判定に使用）。通常は先頭 512 byte 程度。
    pub header_bytes: &'a [u8],
    /// file size（byte）。
    pub file_size: u64,
}

/// 個別 Parser の probe 結果。
#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    /// 識別結果（規範 §11 の5値）。
    pub result: ProbeResult,
    /// 識別に至った理由の記録（`detection_reasons` へ格納される）。
    pub detection_reasons: Vec<String>,
    /// Parser ID（例: `traceforge-evtx`）。
    pub parser_id: String,
    /// Parser version（SemVer）。
    pub parser_version: String,
    /// Artifact 種別（Schema §3.4）。
    pub artifact_type: ArtifactSource,
}

/// ambiguous skip の Issue code。
pub const AMBIGUOUS_SKIP_CODE: &str = "TF-W-PROBE-AMBIGUOUS";

/// Probable-only skip の Issue code（規範 §11）。
pub const PROBABLE_SKIP_CODE: &str = "TF-W-PROBE-PROBABLE-ONLY";

/// 不正 extension や Malformed の skip Issue code。
pub const MALFORMED_SKIP_CODE: &str = "TF-W-PROBE-MALFORMED";

/// 複数 Parser の probe 結果を解決し、解析すべき Parser 一覧を決定する（規範 §11）。
///
/// 解決規則:
/// 1. `Confirmed` が1つのみ → その Parser を実行する。
/// 2. `Confirmed` が複数 → 許可された組み合わせ（Amcache.hve の Registry + Amcache 等）
///    なら両方を実行。それ以外は ambiguous として全て skip。
/// 3. `Confirmed` がなく `Probable` のみ → 既定で skip + Warning。
/// 4. `Malformed` が1つ以上 → Warning を出力し、その Evidence は解析しない。
/// 5. 全て `NotThisFormat` → 何もしない（未識別 Evidence）。
pub struct ProbeResolution {
    /// 解析すべき probe 結果一覧。
    pub selected: Vec<ProbeOutcome>,
    /// 解析を skip したことに伴う Issue 一覧。
    pub issues: Vec<Issue>,
}

/// 複数の probe 結果から解析対象を決定する（規範 §11）。
pub fn resolve_probes(outcomes: Vec<ProbeOutcome>, evidence_id: &str) -> ProbeResolution {
    let mut issues = Vec::new();

    // Malformed が1つでもあれば Warning + 解析しない。
    let has_malformed = outcomes.iter().any(|o| o.result == ProbeResult::Malformed);
    if has_malformed {
        issues.push(Issue {
            issue_id: MALFORMED_SKIP_CODE.to_string(),
            severity: IssueSeverity::Warning,
            scope: IssueScope::Evidence,
            evidence_id: Some(evidence_id.to_string()),
            artifact_id: None,
            record_locator: None,
            source_ordinal: None,
            message: "Artifact の形式識別ができないほど入力が壊れている".to_string(),
        });
        return ProbeResolution {
            selected: Vec::new(),
            issues,
        };
    }

    // Confirmed のものを抽出。
    let confirmed: Vec<&ProbeOutcome> = outcomes
        .iter()
        .filter(|o| o.result == ProbeResult::Confirmed)
        .collect();

    match confirmed.len() {
        0 => {
            // Confirmed なし。Probable のみなら Warning（規範 §11）。
            let probables: Vec<&ProbeOutcome> = outcomes
                .iter()
                .filter(|o| o.result == ProbeResult::Probable)
                .collect();
            if !probables.is_empty() {
                let names: Vec<&str> = probables.iter().map(|p| p.parser_id.as_str()).collect();
                issues.push(Issue {
                    issue_id: PROBABLE_SKIP_CODE.to_string(),
                    severity: IssueSeverity::Warning,
                    scope: IssueScope::Evidence,
                    evidence_id: Some(evidence_id.to_string()),
                    artifact_id: None,
                    record_locator: None,
                    source_ordinal: None,
                    message: format!("Probable のみのため既定で skip した: {}", names.join(", ")),
                });
            }
            ProbeResolution {
                selected: Vec::new(),
                issues,
            }
        }
        1 => {
            // Confirmed が1つ → その Parser を実行。
            let selected = confirmed.into_iter().cloned().collect();
            ProbeResolution { selected, issues }
        }
        _ => {
            // Confirmed が複数 → 許可された組み合わせか確認（規範 §11）。
            let parser_ids: Vec<&str> = confirmed.iter().map(|c| c.parser_id.as_str()).collect();
            if is_allowed_confirmed_combination(&parser_ids) {
                let selected = confirmed.into_iter().cloned().collect();
                ProbeResolution { selected, issues }
            } else {
                // ambiguous → 全て skip。
                issues.push(Issue {
                    issue_id: AMBIGUOUS_SKIP_CODE.to_string(),
                    severity: IssueSeverity::Warning,
                    scope: IssueScope::Evidence,
                    evidence_id: Some(evidence_id.to_string()),
                    artifact_id: None,
                    record_locator: None,
                    source_ordinal: None,
                    message: format!(
                        "複数 Parser が Confirmed を返したが許可された組み合わせではないため ambiguous skip: {}",
                        parser_ids.join(", ")
                    ),
                });
                ProbeResolution {
                    selected: Vec::new(),
                    issues,
                }
            }
        }
    }
}

/// 互換性仕様書で許可された Confirmed の組み合わせ（規範 §11）。
///
/// 現状、Amcache.hve は Registry と Amcache の両 Parser 候補になり得る（規範 §5.1）。
/// それ以外の複数 Confirmed は ambiguous として扱う。
const ALLOWED_CONFIRMED_PAIRS: &[&[&str]] = &[
    // Amcache.hve: Registry + Amcache（互換 §4.6/4.7）
    &["traceforge-amcache", "traceforge-registry"],
];

/// 複数の Confirmed Parser ID が許可された組み合わせか判定する。
fn is_allowed_confirmed_combination(parser_ids: &[&str]) -> bool {
    let mut sorted: Vec<&str> = parser_ids.to_vec();
    sorted.sort_unstable();
    for pair in ALLOWED_CONFIRMED_PAIRS {
        let mut expected: Vec<&str> = pair.to_vec();
        expected.sort_unstable();
        if sorted == expected {
            return true;
        }
    }
    false
}

/// file 先頭の bytes を読み込む（probe 実行前に呼び出す）。
///
/// 既定で先頭 512 byte を読む。file がそれより短い場合は全内容を読む。
pub fn read_header_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    const HEADER_SIZE: usize = 512;
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; HEADER_SIZE];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_outcome(
        parser_id: &str,
        artifact: ArtifactSource,
        result: ProbeResult,
    ) -> ProbeOutcome {
        ProbeOutcome {
            result,
            detection_reasons: vec!["test".to_string()],
            parser_id: parser_id.to_string(),
            parser_version: "1.0.0".to_string(),
            artifact_type: artifact,
        }
    }

    #[test]
    fn single_confirmed_is_selected() {
        // 規範 §11: Confirmed が1つ → その Parser を実行。
        let outcomes = vec![probe_outcome(
            "traceforge-evtx",
            ArtifactSource::Evtx,
            ProbeResult::Confirmed,
        )];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 1);
        assert!(res.issues.is_empty());
    }

    #[test]
    fn allowed_confirmed_pair_is_selected() {
        // 規範 §11・§5.1: Amcache+Registry は許可された組み合わせ。
        let outcomes = vec![
            probe_outcome(
                "traceforge-amcache",
                ArtifactSource::Amcache,
                ProbeResult::Confirmed,
            ),
            probe_outcome(
                "traceforge-registry",
                ArtifactSource::Registry,
                ProbeResult::Confirmed,
            ),
        ];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 2);
        assert!(res.issues.is_empty());
    }

    #[test]
    fn ambiguous_confirmed_is_skipped() {
        // 規範 §11: 許可されていない複数 Confirmed → ambiguous skip。
        let outcomes = vec![
            probe_outcome(
                "traceforge-evtx",
                ArtifactSource::Evtx,
                ProbeResult::Confirmed,
            ),
            probe_outcome(
                "traceforge-prefetch",
                ArtifactSource::Prefetch,
                ProbeResult::Confirmed,
            ),
        ];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 0);
        assert_eq!(res.issues.len(), 1);
        assert_eq!(res.issues[0].issue_id, AMBIGUOUS_SKIP_CODE);
    }

    #[test]
    fn probable_only_is_skipped_with_warning() {
        // 規範 §11: Probable のみ → 既定で skip + Warning。
        let outcomes = vec![probe_outcome(
            "traceforge-evtx",
            ArtifactSource::Evtx,
            ProbeResult::Probable,
        )];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 0);
        assert_eq!(res.issues.len(), 1);
        assert_eq!(res.issues[0].issue_id, PROBABLE_SKIP_CODE);
    }

    #[test]
    fn malformed_skips_all() {
        // 規範 §11: Malformed が1つでもあれば解析しない。
        let outcomes = vec![
            probe_outcome(
                "traceforge-evtx",
                ArtifactSource::Evtx,
                ProbeResult::Malformed,
            ),
            probe_outcome(
                "traceforge-prefetch",
                ArtifactSource::Prefetch,
                ProbeResult::Confirmed,
            ),
        ];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 0);
        assert_eq!(res.issues.len(), 1);
        assert_eq!(res.issues[0].issue_id, MALFORMED_SKIP_CODE);
    }

    #[test]
    fn all_not_this_format_selects_none() {
        let outcomes = vec![
            probe_outcome(
                "traceforge-evtx",
                ArtifactSource::Evtx,
                ProbeResult::NotThisFormat,
            ),
            probe_outcome(
                "traceforge-prefetch",
                ArtifactSource::Prefetch,
                ProbeResult::NotThisFormat,
            ),
        ];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 0);
        assert!(res.issues.is_empty());
    }

    #[test]
    fn confirmed_takes_precedence_over_probable() {
        // Confirmed が1つと Probable が1つ → Confirmed を選択。
        let outcomes = vec![
            probe_outcome(
                "traceforge-evtx",
                ArtifactSource::Evtx,
                ProbeResult::Confirmed,
            ),
            probe_outcome(
                "traceforge-prefetch",
                ArtifactSource::Prefetch,
                ProbeResult::Probable,
            ),
        ];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 1);
        assert_eq!(res.selected[0].parser_id, "traceforge-evtx");
    }

    #[test]
    fn unsupported_version_alone_is_not_selected() {
        // UnsupportedVersion のみ → 選択されない。
        let outcomes = vec![probe_outcome(
            "traceforge-prefetch",
            ArtifactSource::Prefetch,
            ProbeResult::UnsupportedVersion,
        )];
        let res = resolve_probes(outcomes, "tf-evidence-v1:x");
        assert_eq!(res.selected.len(), 0);
        // UnsupportedVersion は Warning なし（Parser が別途 issue を出す想定）。
    }

    #[test]
    fn read_header_bytes_short_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small");
        std::fs::write(&path, b"abc").unwrap();
        let header = read_header_bytes(&path).unwrap();
        assert_eq!(header, b"abc");
    }

    #[test]
    fn read_header_bytes_truncates_to_512() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large");
        let content: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        std::fs::write(&path, &content).unwrap();
        let header = read_header_bytes(&path).unwrap();
        assert_eq!(header.len(), 512);
        assert_eq!(&header[..10], &content[..10]);
    }
}
