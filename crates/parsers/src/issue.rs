//! Parse Issue の helper と安定 code 定数（規範 §9.3、Schema §5.6）。
//!
//! 規範 §9.3 は各 Issue へ次を求める:
//!
//! - 安定した code（[`code`] module の定数として提供）
//! - severity・Evidence ID・Artifact ID・record locator・短い message
//! - message へ Evidence の巨大な値または未 escape 制御文字をそのまま含めてはならない
//! - 同一 Issue の出力順は `evidence_id` → `artifact_id` → `source_ordinal` → `code` の順
//!
//! 本モジュールは [`sanitize_issue_message`] で message を安全へ変換し、
//! Parser 実装が安心して record 起因の値を message へ埋め込めるようにする。

use tf_core::event::RecordLocator;
use tf_core::issue::{Issue, IssueScope, IssueSeverity};

/// message の最大長（byte）。これを超える場合は切り詰めて省略記号を付ける（規範 §9.3）。
pub const MAX_ISSUE_MESSAGE_BYTES: usize = 512;

/// message 切り詰め時の省略記号。
const ELLIPSIS: &str = "...(truncated)";

/// 安定した Issue code の namespace（規範 §9.3）。
///
/// code 命名規則: `TF-<SEV>-<PARSER>-<REASON>`
/// - `<SEV>`: `W`（Warning）/ `R`（Recoverable）/ `F`（Fatal）
/// - `<PARSER>`: Parser 識別子の短縮形（`LNK` / `EVTX` / `PREFETCH` 等）
/// - `<REASON>`: 内容の短縮記述
///
/// 汎用の code（Parser 種別を含まない）は `TF-<SEV>-PARSER-*` 形式とする。
pub mod code {
    /// Parser 実装が panic した（規範 §9.4）。Fatal。
    pub const PANIC_FATAL: &str = "TF-F-PARSER-PANIC";

    /// record の必須 field 欠落（互換 §5）。Warning。
    pub const MISSING_REQUIRED_FIELD: &str = "TF-W-PARSER-MISSING-REQUIRED-FIELD";

    /// record が truncated（途中で切れている）。Warning。
    pub const TRUNCATED_RECORD: &str = "TF-W-PARSER-TRUNCATED-RECORD";

    /// record の長さ情報が不正（負・巨大・矛盾）。Warning。
    pub const INVALID_LENGTH: &str = "TF-W-PARSER-INVALID-LENGTH";

    /// 未知の version（既知形式として推測しない）。Warning。
    pub const UNSUPPORTED_VERSION: &str = "TF-W-PARSER-UNSUPPORTED-VERSION";

    /// record 内の境界を安全に特定できず、その ArtifactInstance を Partial で終了（規範 §9.2）。Recoverable。
    pub const PARTIAL_RECORD_BOUNDARY: &str = "TF-R-PARSER-PARTIAL-BOUNDARY";

    /// 解析継続不能な破損（header 不正・magic 不一致等）。Warning。
    pub const MALFORMED_INPUT: &str = "TF-W-PARSER-MALFORMED-INPUT";
}

/// 再公開（テストや外部参照で短名を使えるようにする）。
pub const PANIC_FATAL_CODE: &str = code::PANIC_FATAL;
pub const MISSING_REQUIRED_FIELD_CODE: &str = code::MISSING_REQUIRED_FIELD;
pub const TRUNCATED_RECORD_CODE: &str = code::TRUNCATED_RECORD;
pub const INVALID_LENGTH_CODE: &str = code::INVALID_LENGTH;
pub const UNSUPPORTED_VERSION_CODE: &str = code::UNSUPPORTED_VERSION;
pub const PARTIAL_RECORD_BOUNDARY_CODE: &str = code::PARTIAL_RECORD_BOUNDARY;
pub const MALFORMED_INPUT_CODE: &str = code::MALFORMED_INPUT;

/// Issue message を安全へ変換する（規範 §9.3）。
///
/// 次を行う:
/// 1. C0/C1 制御文字と ESC を可視 escape（`\n`・`\t` 等の escape sequence、それ以外は `\xXX`）。
/// 2. [`MAX_ISSUE_MESSAGE_BYTES`] を超える場合は byte 数で切り詰め、`...(truncated)` を付ける。
///
/// これにより、Evidence 起因の巨大な値や未 escape 制御文字がそのまま Manifest へ出力されるのを防ぐ。
/// escape 後の文字列の**文字数**ではなく、UTF-8 **byte 数**で上限を見る（Schema §2.1 の文字 code 規則）。
pub fn sanitize_issue_message(raw: &str) -> String {
    let escaped = escape_control_chars(raw);
    truncate_bytes(&escaped, MAX_ISSUE_MESSAGE_BYTES)
}

/// C0/C1 制御文字・ESC・その他非表示文字を escape sequence へ変換する。
///
/// - `\t` / `\n` / `\r` はよく知られた escape のまま。
/// - それ以外の C0 (U+0000..U+001F)、DEL (U+007F)、C1 (U+0080..U+009F) は `\xXX`（2 桁 hex）へ。
/// - ESC (U+001B) も `\x1b` へ。
fn escape_control_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            // 制御文字（C0 / DEL / C1）。可視 escape の `\xXX` 形式。
            c if (c as u32) <= 0x1F || c == '\u{7F}' || (0x80..=0x9F).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// 文字列を UTF-8 byte 上限で切り詰める。char 境界で切る（UTF-8 の整合性を保つ）。
fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // `max_bytes` - ELLIPSIS.len() まで切り詰める。
    let budget = max_bytes.saturating_sub(ELLIPSIS.len());
    // char 境界を探す。
    let mut end = budget;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = String::with_capacity(end + ELLIPSIS.len());
    result.push_str(&s[..end]);
    result.push_str(ELLIPSIS);
    result
}

/// record 起因の Issue を構築する（Parser 実装の便利 helper）。
///
/// `evidence_id`・`artifact_id`・`record_locator`・`source_ordinal` を埋めた [`Issue`] を作る。
/// `raw_message` は [`sanitize_issue_message`] で安全化される。
#[allow(clippy::too_many_arguments)]
pub fn record_issue(
    code: &str,
    severity: IssueSeverity,
    evidence_id: &str,
    artifact_id: &str,
    record_locator: Option<RecordLocator>,
    source_ordinal: Option<u64>,
    raw_message: &str,
) -> Issue {
    Issue {
        issue_id: code.to_string(),
        severity,
        scope: IssueScope::Record,
        evidence_id: Some(evidence_id.to_string()),
        artifact_id: Some(artifact_id.to_string()),
        record_locator,
        source_ordinal,
        message: sanitize_issue_message(raw_message),
    }
}

/// Artifact 全体の Issue を構築する（record 単位ではない問題、例: header 不正）。
pub fn artifact_issue(
    code: &str,
    severity: IssueSeverity,
    evidence_id: &str,
    artifact_id: &str,
    raw_message: &str,
) -> Issue {
    Issue {
        issue_id: code.to_string(),
        severity,
        scope: IssueScope::Artifact,
        evidence_id: Some(evidence_id.to_string()),
        artifact_id: Some(artifact_id.to_string()),
        record_locator: None,
        source_ordinal: None,
        message: sanitize_issue_message(raw_message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_control_chars() {
        // 規範 §9.3: 未 escape 制御文字を message へそのまま含めない。
        let s = sanitize_issue_message("hello\x1b[2J world\n");
        assert!(!s.contains('\x1b'));
        assert!(s.contains("\\x1b"));
        assert!(s.contains("\\n"));
        assert!(s.contains("hello"));
    }

    #[test]
    fn sanitize_truncates_long_message() {
        // 規範 §9.3: 巨大な値をそのまま含めない。
        let huge = "A".repeat(10_000);
        let s = sanitize_issue_message(&huge);
        assert!(s.len() <= MAX_ISSUE_MESSAGE_BYTES + ELLIPSIS.len());
        assert!(s.ends_with("...(truncated)"));
    }

    #[test]
    fn sanitize_preserves_short_message() {
        let s = sanitize_issue_message("record 5 が truncated");
        assert_eq!(s, "record 5 が truncated");
    }

    #[test]
    fn sanitize_handles_unicode_without_break() {
        // マルチ byte 文字の途中で切らない（UTF-8 char 境界）。
        let raw = "あ".repeat(200); // 3 byte/char * 200 = 600 byte
        let s = sanitize_issue_message(&raw);
        // UTF-8 として正しい（from_utf8 が成功する）。
        assert!(String::from_utf8(s.into_bytes()).is_ok());
    }

    #[test]
    fn record_issue_carries_all_fields() {
        let issue = record_issue(
            TRUNCATED_RECORD_CODE,
            IssueSeverity::Warning,
            "tf-evidence-v1:x",
            "tf-artifact-v1:y",
            Some(RecordLocator::ByteOffset(100)),
            Some(5),
            "長さ情報が不正: declared=100, actual=20",
        );
        assert_eq!(issue.issue_id, "TF-W-PARSER-TRUNCATED-RECORD");
        assert_eq!(issue.severity, IssueSeverity::Warning);
        assert_eq!(issue.scope, IssueScope::Record);
        assert_eq!(issue.evidence_id.as_deref(), Some("tf-evidence-v1:x"));
        assert_eq!(issue.source_ordinal, Some(5));
        assert!(issue.message.contains("declared=100"));
    }

    #[test]
    fn artifact_issue_scope_is_artifact() {
        let issue = artifact_issue(
            MALFORMED_INPUT_CODE,
            IssueSeverity::Warning,
            "tf-evidence-v1:x",
            "tf-artifact-v1:y",
            "header が短すぎる",
        );
        assert_eq!(issue.scope, IssueScope::Artifact);
        assert!(issue.record_locator.is_none());
    }

    #[test]
    fn code_namespace_is_stable() {
        // 規範 §9.3: 安定 code。変更は互換性へ影響する。
        assert_eq!(code::PANIC_FATAL, "TF-F-PARSER-PANIC");
        assert_eq!(
            code::MISSING_REQUIRED_FIELD,
            "TF-W-PARSER-MISSING-REQUIRED-FIELD"
        );
        assert_eq!(code::TRUNCATED_RECORD, "TF-W-PARSER-TRUNCATED-RECORD");
        assert_eq!(code::INVALID_LENGTH, "TF-W-PARSER-INVALID-LENGTH");
        assert_eq!(code::UNSUPPORTED_VERSION, "TF-W-PARSER-UNSUPPORTED-VERSION");
        assert_eq!(
            code::PARTIAL_RECORD_BOUNDARY,
            "TF-R-PARSER-PARTIAL-BOUNDARY"
        );
        assert_eq!(code::MALFORMED_INPUT, "TF-W-PARSER-MALFORMED-INPUT");
    }
}
