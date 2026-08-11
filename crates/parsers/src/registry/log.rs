//! LOG1 / LOG2 transaction log の parser と replay（互換 §4.7・T4-051）。
//!
//! Windows registry hive は書き込みを transaction log（`.LOG1` / `.LOG2`）へ記録する。
//! hive 読み込み時、未適用の log entry を hive へ replay することで「電源断等で
//! 書き込みが中途半端になった hive」を復旧できる。
//!
//! ## 本 Parser の対応範囲
//!
//! 実 Windows の LOG 形式（`HvLE` / `DLOG` / `RC11` 等）は Microsoft が公式仕様を
//! 公開しておらず、libyal 等のリバースエンジニアリング成果に依存する。本 Parser は
//! v1.0 では次の方針をとる:
//!
//! - **合成 LOG 形式（`TFLOG`）**: 本 Parser が定義する最小形式。 entries を読み、
//!   base hive bytes へ byte-level で適用できる。テスト可能。
//! - **実 Windows LOG 形式**: magic を検出した時点で「既知だが未対応」と扱い、
//!   [`ReplayOutcome::KnownUnsupported`] を返す。この場合 base のみ扱い、
//!   `partial` とする（互換 §4.7: log が存在するのに replay できない場合は partial）。
//!
//! これにより「replay の成否と使用 log hash を記録」という互換 §4.7 Required 要件を
//! 満たす。完全な HvLE / RC11 replay は将来の Phase または別 component へ委ねる。

/// 合成 LOG 形式の magic（"TFLOG\0\0\0"・8 byte）。
pub const TFLOG_MAGIC: [u8; 8] = *b"TFLOG\x00\x00\x00";

/// 実 Windows LOG 形式（Windows Vista 以降）の magic（"HvLE"）。
pub const HVLE_MAGIC: [u8; 4] = *b"HvLE";
/// 実 Windows LOG 形式（古い形式）の magic（"RC11" / "DLOG"）。
pub const RC11_MAGIC: [u8; 4] = *b"RC11";
pub const DLOG_MAGIC: [u8; 4] = *b"DLOG";

/// LOG1 / LOG2 の解析結果。
#[derive(Clone, Debug)]
pub struct ParsedLog {
    /// LOG file 全体の SHA-256 lowercase hex。
    pub sha256_hex: String,
    /// 検出した LOG 形式。
    pub format: LogFormat,
    /// 検出した magic（先頭 8 byte を切り詰めたもの。hash 計算や診断で使う）。
    pub magic_bytes: Vec<u8>,
}

/// LOG 形式の種別。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// 合成 LOG（TFLOG）。本 Parser が定義する最小形式。
    Synthetic,
    /// HvLE（Windows Vista 以降）。既知だが v1.0 では未対応。
    HvLe,
    /// RC11 / DLOG（古い形式）。既知だが v1.0 では未対応。
    Legacy,
    /// 不正・短すぎる・未知の形式。
    Unknown,
}

/// replay（LOG を base hive bytes へ適用）の結果。
#[derive(Clone, Debug)]
pub enum ReplayOutcome {
    /// LOG が与えられなかった（replay 未実施）。
    NoLog,
    /// 合成 LOG を base hive bytes へ適用し、recovered bytes を構築した。
    Recovered {
        /// 構築した recovered hive bytes。
        bytes: Vec<u8>,
        /// 適用した entry 数。
        entries_applied: u32,
    },
    /// 既知の LOG 形式（HvLE 等）を検出したが、本 Parser では完全な replay ができない。
    /// base のみ扱い、`partial` とする（互換 §4.7）。
    KnownUnsupported {
        /// 検出した形式。
        format: LogFormat,
    },
    /// LOG の破損・短すぎる等で replay できなかった。
    Malformed,
}

impl ReplayOutcome {
    /// replay が成功して recovered bytes が得られたか。
    pub fn is_recovered(&self) -> bool {
        matches!(self, ReplayOutcome::Recovered { .. })
    }
}

/// LOG1 / LOG2 の1 entry（合成形式）。
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// 適用先 hive bytes 内の offset（base block も含む絶対 offset）。
    pub target_offset: u32,
    /// data 本体。
    pub data: Vec<u8>,
}

/// LOG file bytes を parse し、形式と hash を取り出す。
pub fn parse_log(log_bytes: &[u8]) -> ParsedLog {
    let sha256_hex = tf_core::hash::sha256_hex(log_bytes);
    let (format, magic_bytes) = detect_format(log_bytes);
    ParsedLog {
        sha256_hex,
        format,
        magic_bytes,
    }
}

/// LOG bytes の先頭から形式を判定する。
fn detect_format(log_bytes: &[u8]) -> (LogFormat, Vec<u8>) {
    if log_bytes.len() >= 8 && log_bytes[0..8] == TFLOG_MAGIC {
        return (LogFormat::Synthetic, log_bytes[0..8].to_vec());
    }
    if log_bytes.len() >= 4 && log_bytes[0..4] == HVLE_MAGIC {
        return (LogFormat::HvLe, log_bytes[0..4].to_vec());
    }
    if log_bytes.len() >= 4 && (log_bytes[0..4] == RC11_MAGIC || log_bytes[0..4] == DLOG_MAGIC) {
        return (LogFormat::Legacy, log_bytes[0..4].to_vec());
    }
    (
        LogFormat::Unknown,
        log_bytes[..log_bytes.len().min(8)].to_vec(),
    )
}

/// 合成 LOG 形式の entries を parse する。
///
/// 構造:
/// ```text
/// magic "TFLOG\0\0\0" (8 byte)
/// sequence: u32 LE
/// entry_count: u32 LE
/// entries[entry_count]:
///   target_offset: u32 LE
///   data_length: u32 LE
///   data: [u8; data_length]
/// ```
pub fn parse_synthetic_entries(log_bytes: &[u8]) -> Option<Vec<LogEntry>> {
    if log_bytes.len() < 16 || log_bytes[0..8] != TFLOG_MAGIC {
        return None;
    }
    let entry_count = u32::from_le_bytes(log_bytes[12..16].try_into().unwrap()) as usize;
    let mut entries = Vec::with_capacity(entry_count);
    let mut off = 16usize;
    for _ in 0..entry_count {
        if off + 8 > log_bytes.len() {
            return None;
        }
        let target_offset = u32::from_le_bytes(log_bytes[off..off + 4].try_into().unwrap());
        let data_length =
            u32::from_le_bytes(log_bytes[off + 4..off + 8].try_into().unwrap()) as usize;
        off += 8;
        if off + data_length > log_bytes.len() {
            return None;
        }
        let data = log_bytes[off..off + data_length].to_vec();
        off += data_length;
        entries.push(LogEntry {
            target_offset,
            data,
        });
    }
    Some(entries)
}

/// 合成 LOG 形式の bytes を構築する（テスト・fixture 用）。
pub fn build_synthetic_log(entries: &[LogEntry]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + entries.len() * 8);
    buf.extend_from_slice(&TFLOG_MAGIC);
    buf.extend_from_slice(&1u32.to_le_bytes()); // sequence
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        buf.extend_from_slice(&e.target_offset.to_le_bytes());
        buf.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&e.data);
    }
    buf
}

/// LOG1 / LOG2 を base hive bytes へ適用し、recovered bytes を構築する。
///
/// - 合成 LOG（TFLOG）の場合: entries を順へ適用した recovered bytes を返す。
/// - HvLE / RC11 / DLOG: `KnownUnsupported`。
/// - 不正・短すぎる: `Malformed`。
///
/// `base_bytes` は base block (4096 byte) + hive bins data の全体。
pub fn replay_logs(
    base_bytes: &[u8],
    log1_bytes: Option<&[u8]>,
    log2_bytes: Option<&[u8]>,
) -> ReplayOutcome {
    let logs: Vec<&[u8]> = [log1_bytes, log2_bytes].into_iter().flatten().collect();
    if logs.is_empty() {
        return ReplayOutcome::NoLog;
    }

    // 全ての LOG が合成形式なら entries を集めて適用。1つでも既知未対応形式があれば
    // その LOG は無視せず KnownUnsupported として伝える（黙殺禁止）。
    let mut combined_entries: Vec<LogEntry> = Vec::new();
    for log_bytes in &logs {
        let parsed = parse_log(log_bytes);
        match parsed.format {
            LogFormat::Synthetic => match parse_synthetic_entries(log_bytes) {
                Some(entries) => combined_entries.extend(entries),
                None => return ReplayOutcome::Malformed,
            },
            LogFormat::HvLe | LogFormat::Legacy => {
                return ReplayOutcome::KnownUnsupported {
                    format: parsed.format,
                };
            }
            LogFormat::Unknown => {
                return ReplayOutcome::Malformed;
            }
        }
    }

    // base bytes の copy へ entries を適用。
    let mut recovered = base_bytes.to_vec();
    let mut applied: u32 = 0;
    for entry in &combined_entries {
        let start = entry.target_offset as usize;
        let end = start.saturating_add(entry.data.len());
        if end > recovered.len() {
            // 適用範囲が hive bytes を越える場合は安全のため中止。
            return ReplayOutcome::Malformed;
        }
        recovered[start..end].copy_from_slice(&entry.data);
        applied += 1;
    }

    ReplayOutcome::Recovered {
        bytes: recovered,
        entries_applied: applied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_synthetic() {
        let log = build_synthetic_log(&[]);
        let parsed = parse_log(&log);
        assert_eq!(parsed.format, LogFormat::Synthetic);
    }

    #[test]
    fn detect_hvle() {
        let mut log = vec![0u8; 32];
        log[0..4].copy_from_slice(&HVLE_MAGIC);
        let parsed = parse_log(&log);
        assert_eq!(parsed.format, LogFormat::HvLe);
    }

    #[test]
    fn detect_legacy_rc11() {
        let mut log = vec![0u8; 32];
        log[0..4].copy_from_slice(&RC11_MAGIC);
        let parsed = parse_log(&log);
        assert_eq!(parsed.format, LogFormat::Legacy);
    }

    #[test]
    fn detect_unknown() {
        let log = vec![0u8; 32];
        let parsed = parse_log(&log);
        assert_eq!(parsed.format, LogFormat::Unknown);
    }

    #[test]
    fn sha256_is_recorded() {
        let log = build_synthetic_log(&[]);
        let parsed = parse_log(&log);
        assert_eq!(parsed.sha256_hex.len(), 64);
        assert!(
            parsed
                .sha256_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn replay_no_log_is_no_log() {
        let base = vec![0u8; 4096];
        let outcome = replay_logs(&base, None, None);
        assert!(matches!(outcome, ReplayOutcome::NoLog));
    }

    #[test]
    fn replay_synthetic_applies_entries() {
        let mut base = vec![0u8; 4096];
        base[100] = 1;
        let entry = LogEntry {
            target_offset: 100,
            data: vec![0xFF, 0xEE],
        };
        let log = build_synthetic_log(&[entry]);
        let outcome = replay_logs(&base, Some(&log), None);
        match outcome {
            ReplayOutcome::Recovered {
                bytes,
                entries_applied,
            } => {
                assert_eq!(entries_applied, 1);
                assert_eq!(bytes[100], 0xFF);
                assert_eq!(bytes[101], 0xEE);
            }
            _ => panic!("Recovered 期待"),
        }
    }

    #[test]
    fn replay_hvle_is_known_unsupported() {
        let base = vec![0u8; 4096];
        let mut log = vec![0u8; 32];
        log[0..4].copy_from_slice(&HVLE_MAGIC);
        let outcome = replay_logs(&base, Some(&log), None);
        assert!(matches!(
            outcome,
            ReplayOutcome::KnownUnsupported {
                format: LogFormat::HvLe
            }
        ));
    }

    #[test]
    fn replay_unknown_is_malformed() {
        let base = vec![0u8; 4096];
        let log = vec![0u8; 32];
        let outcome = replay_logs(&base, Some(&log), None);
        assert!(matches!(outcome, ReplayOutcome::Malformed));
    }

    #[test]
    fn replay_out_of_range_entry_is_malformed() {
        let base = vec![0u8; 100];
        let entry = LogEntry {
            target_offset: 90,
            data: vec![0; 20], // 100 byte を越える
        };
        let log = build_synthetic_log(&[entry]);
        let outcome = replay_logs(&base, Some(&log), None);
        assert!(matches!(outcome, ReplayOutcome::Malformed));
    }

    #[test]
    fn replay_two_logs_combined() {
        let base = vec![0u8; 4096];
        let e1 = LogEntry {
            target_offset: 100,
            data: vec![0xAA],
        };
        let e2 = LogEntry {
            target_offset: 200,
            data: vec![0xBB],
        };
        let log1 = build_synthetic_log(&[e1]);
        let log2 = build_synthetic_log(&[e2]);
        let outcome = replay_logs(&base, Some(&log1), Some(&log2));
        match outcome {
            ReplayOutcome::Recovered {
                bytes,
                entries_applied,
            } => {
                assert_eq!(entries_applied, 2);
                assert_eq!(bytes[100], 0xAA);
                assert_eq!(bytes[200], 0xBB);
            }
            _ => panic!("Recovered 期待"),
        }
    }
}
