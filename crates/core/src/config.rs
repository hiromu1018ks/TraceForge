//! TOML 設定（Schema §8、規範 §17.1）。
//!
//! 優先順位（Schema §8.1）: `CLI > explicit config file > default config file > built-in defaults`。
//! 確定後の configuration 全体を canonical JSON へ変換し、SHA-256 を Manifest へ保存する。
//!
//! Phase 1 では TOML load・built-in defaults・validation・resolved digest を実装する。
//! CLI override の parse は Phase 7 で実装する。

use serde::{Deserialize, Serialize};

use crate::canonical::to_canonical_string;
use crate::error::{ExitCode, StrictMode, TraceForgeError};
use crate::hash::sha256_hex;

/// Schema §8.3 で許可される YARA-X scan mode。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraMode {
    All,
    Suspicious,
    Explicit,
}

/// Schema §8.3 で許可される出力形式。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Csv,
    Html,
    Timesketch,
}

/// Schema §8.2 `[analysis]`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub recursive: bool,
    /// v1.0 では `"always"` のみ許可（Schema §8.3）。
    pub snapshot_mode: String,
    /// `""` は timezone 指定なし。指定時は IANA timezone name（Schema §8.3）。
    pub timezone: String,
    /// `0` は自動、`1` 以上は明示値（Schema §8.3）。
    pub threads: u32,
    /// v1.0 では必ず `false`。`true` は validation error（Schema §8.3、将来予約）。
    pub follow_symlinks: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            recursive: true,
            snapshot_mode: "always".to_string(),
            timezone: String::new(),
            threads: 0,
            follow_symlinks: false,
        }
    }
}

/// Schema §8.2 `[strict]`。規範 §17.1 の strict mode 設定。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StrictConfig {
    pub parser: bool,
    pub rules: bool,
    pub limits: bool,
}

impl From<StrictConfig> for StrictMode {
    fn from(s: StrictConfig) -> Self {
        StrictMode {
            parser: s.parser,
            rules: s.rules,
            limits: s.limits,
        }
    }
}

/// Schema §8.2 `[correlation]`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CorrelationConfig {
    pub enabled: bool,
    pub rule_dirs: Vec<String>,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        CorrelationConfig {
            enabled: true,
            rule_dirs: vec!["./rules/correlation".to_string()],
        }
    }
}

/// Schema §8.2 `[sigma]`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SigmaConfig {
    pub enabled: bool,
    pub rule_dirs: Vec<String>,
}

impl Default for SigmaConfig {
    fn default() -> Self {
        SigmaConfig {
            enabled: true,
            rule_dirs: vec!["./rules/sigma".to_string()],
        }
    }
}

/// Schema §8.2 `[yara]`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct YaraConfig {
    pub enabled: bool,
    pub mode: YaraMode,
    pub rule_dirs: Vec<String>,
}

impl Default for YaraConfig {
    fn default() -> Self {
        YaraConfig {
            enabled: true,
            mode: YaraMode::Suspicious,
            rule_dirs: vec!["./rules/yara".to_string()],
        }
    }
}

/// Schema §8.2 `[output]`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub include_provenance: bool,
    pub overwrite: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        OutputConfig {
            format: OutputFormat::Text,
            include_provenance: true,
            overwrite: false,
        }
    }
}

/// Schema §8.2 `[limits]`。全項目 `1` 以上必須（Schema §8.3、0 を unlimited 扱いしない）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_files: u64,
    pub max_recursion_depth: u64,
    pub max_evidence_file_size_bytes: u64,
    pub max_snapshot_total_bytes: u64,
    pub max_events: u64,
    pub max_issues: u64,
    pub max_issues_per_evidence: u64,
    pub max_findings: u64,
    pub max_correlation_matches_per_rule: u64,
    pub max_correlation_window_seconds: u64,
    pub max_yara_scan_file_size_bytes: u64,
    pub max_rule_files: u64,
    pub max_rule_file_size_bytes: u64,
    pub max_memory_bytes: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        // Schema §8.2 の全値。`0` を unlimited として扱わない（Schema §8.3）。
        LimitsConfig {
            max_files: 100_000,
            max_recursion_depth: 64,
            max_evidence_file_size_bytes: 34_359_738_368,
            max_snapshot_total_bytes: 1_099_511_627_776,
            max_events: 50_000_000,
            max_issues: 100_000,
            max_issues_per_evidence: 10_000,
            max_findings: 1_000_000,
            max_correlation_matches_per_rule: 100_000,
            max_correlation_window_seconds: 86_400,
            max_yara_scan_file_size_bytes: 1_073_741_824,
            max_rule_files: 100_000,
            max_rule_file_size_bytes: 16_777_216,
            max_memory_bytes: 2_147_483_648,
        }
    }
}

/// Schema §8 の設定全体。
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub analysis: AnalysisConfig,
    pub strict: StrictConfig,
    pub correlation: CorrelationConfig,
    pub sigma: SigmaConfig,
    pub yara: YaraConfig,
    pub output: OutputConfig,
    pub limits: LimitsConfig,
}

impl Config {
    /// Schema §8.2 の built-in defaults を返す。
    pub fn defaults() -> Self {
        Config::default()
    }

    /// TOML 文字列から設定を読み込む。欠落 field は built-in defaults で補完する。
    ///
    /// explicit config file の読み込みを想定する。CLI override のマージは
    /// [`Config::apply_overrides`]（Phase 7 拡張点）へ委ねる。
    pub fn from_toml_str(s: &str) -> Result<Self, TraceForgeError> {
        toml::from_str(s)
            .map_err(|e| TraceForgeError::CliOrConfig(format!("TOML parse error: {e}")))
    }

    /// Schema §8.3 の validation 規則を適用する。違反時は [`TraceForgeError::CliOrConfig`]。
    pub fn validate(&self) -> Result<(), TraceForgeError> {
        // snapshot_mode は v1.0 では "always" のみ（Schema §8.3）。
        if self.analysis.snapshot_mode != "always" {
            return Err(TraceForgeError::CliOrConfig(format!(
                "snapshot_mode は v1.0 では 'always' のみ許可される（got {:?}）",
                self.analysis.snapshot_mode
            )));
        }
        // follow_symlinks=true は v1.0 では unsupported として error（Schema §8.3）。
        if self.analysis.follow_symlinks {
            return Err(TraceForgeError::CliOrConfig(
                "follow_symlinks=true は v1.0 では未サポート（将来予約 field）".into(),
            ));
        }
        // timezone 指定時は IANA timezone name のみ（Schema §8.3）。
        if !self.analysis.timezone.is_empty()
            && !crate::time::is_valid_iana_timezone(&self.analysis.timezone)
        {
            return Err(TraceForgeError::CliOrConfig(format!(
                "timezone は IANA timezone name のみ許可される（got {:?}）",
                self.analysis.timezone
            )));
        }
        // limit は全て 1 以上（Schema §8.3: 0 を unlimited 扱いしない）。
        self.validate_limits()?;

        Ok(())
    }

    /// 全 limit 項目が 1 以上であることを検証する（Schema §8.3）。
    fn validate_limits(&self) -> Result<(), TraceForgeError> {
        let l = &self.limits;
        let pairs: [(&str, u64); 14] = [
            ("max_files", l.max_files),
            ("max_recursion_depth", l.max_recursion_depth),
            (
                "max_evidence_file_size_bytes",
                l.max_evidence_file_size_bytes,
            ),
            ("max_snapshot_total_bytes", l.max_snapshot_total_bytes),
            ("max_events", l.max_events),
            ("max_issues", l.max_issues),
            ("max_issues_per_evidence", l.max_issues_per_evidence),
            ("max_findings", l.max_findings),
            (
                "max_correlation_matches_per_rule",
                l.max_correlation_matches_per_rule,
            ),
            (
                "max_correlation_window_seconds",
                l.max_correlation_window_seconds,
            ),
            (
                "max_yara_scan_file_size_bytes",
                l.max_yara_scan_file_size_bytes,
            ),
            ("max_rule_files", l.max_rule_files),
            ("max_rule_file_size_bytes", l.max_rule_file_size_bytes),
            ("max_memory_bytes", l.max_memory_bytes),
        ];
        for (name, value) in pairs {
            if value < 1 {
                return Err(TraceForgeError::CliOrConfig(format!(
                    "limit {name} は 1 以上必須（0 や負数は不可、Schema §8.3）: got {value}"
                )));
            }
        }
        Ok(())
    }

    /// resolved configuration 全体の canonical JSON を返す（Schema §8.1）。
    pub fn to_canonical_json(&self) -> String {
        // Serialize で field 挿入順は固定されるが、canonical 側で key sort する。
        to_canonical_string(self).unwrap_or_else(|e| {
            // Config は有限の数値と文字列のみで NaN/Infinity は存在しない。
            panic!("Config の canonical JSON 変換に失敗した: {e}")
        })
    }

    /// resolved configuration の SHA-256 lowercase hex（Schema §8.1）。
    pub fn resolved_digest(&self) -> String {
        sha256_hex(self.to_canonical_json().as_bytes())
    }

    /// CLI override を適用する（Phase 7 拡張点）。
    ///
    /// Phase 1 では何もしない。CLI option の parse は Phase 7 で実装する。
    pub fn apply_overrides(&mut self, _overrides: &ConfigOverrides) {
        // Phase 7 で実装する。
    }
}

/// CLI からの override 指定（Phase 7 拡張点）。
///
/// Phase 1 では空。Phase 7 で `--timezone` / `--threads` / `--output` 等を追加する。
#[derive(Clone, Debug, Default)]
pub struct ConfigOverrides {}

/// 設定 validation 失敗を Exit Code へ mapping する補助。
impl TraceForgeError {
    /// 設定 error は規範 §17.2 で Exit Code 2。
    pub fn config_exit_code(&self) -> ExitCode {
        ExitCode::CliOrConfigError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_schema_8_2() {
        // Schema §8.2 の built-in defaults を検証する。
        let c = Config::defaults();
        assert!(c.analysis.recursive);
        assert_eq!(c.analysis.snapshot_mode, "always");
        assert_eq!(c.analysis.timezone, "");
        assert_eq!(c.analysis.threads, 0);
        assert!(!c.analysis.follow_symlinks);
        assert!(c.correlation.enabled);
        assert_eq!(c.yara.mode, YaraMode::Suspicious);
        assert_eq!(c.output.format, OutputFormat::Text);
        assert_eq!(c.limits.max_events, 50_000_000);
        assert_eq!(c.limits.max_correlation_window_seconds, 86_400);
    }

    #[test]
    fn from_toml_str_fills_missing_fields() {
        // explicit TOML に無い field は defaults で補完される。
        let toml = r#"
[analysis]
timezone = "Asia/Tokyo"
"#;
        let c = Config::from_toml_str(toml).unwrap();
        assert_eq!(c.analysis.timezone, "Asia/Tokyo");
        assert!(c.analysis.recursive, "欠落 field は default");
        assert_eq!(c.analysis.snapshot_mode, "always");
        assert_eq!(c.yara.mode, YaraMode::Suspicious);
    }

    #[test]
    fn from_toml_str_empty_uses_all_defaults() {
        let c = Config::from_toml_str("").unwrap();
        assert_eq!(c, Config::defaults());
    }

    #[test]
    fn validate_rejects_non_always_snapshot_mode() {
        // Schema §8.3: snapshot_mode は "always" のみ。
        let mut c = Config::defaults();
        c.analysis.snapshot_mode = "never".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_follow_symlinks_true() {
        // Schema §8.3: follow_symlinks=true は error。
        let mut c = Config::defaults();
        c.analysis.follow_symlinks = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_timezone() {
        let mut c = Config::defaults();
        c.analysis.timezone = "JST".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_iana_timezone() {
        let mut c = Config::defaults();
        c.analysis.timezone = "Asia/Tokyo".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_limit() {
        // Schema §8.3: limit は 1 以上（0 を unlimited 扱いしない）。
        let mut c = Config::defaults();
        c.limits.max_events = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn resolved_digest_is_deterministic() {
        // 同一設定なら同一 digest（規範 §13.1）。
        let a = Config::defaults();
        let b = Config::defaults();
        assert_eq!(a.resolved_digest(), b.resolved_digest());
    }

    #[test]
    fn resolved_digest_changes_on_change() {
        let a = Config::defaults();
        let mut b = Config::defaults();
        b.analysis.timezone = "UTC".into();
        assert_ne!(a.resolved_digest(), b.resolved_digest());
    }

    #[test]
    fn resolved_digest_is_64_lowercase_hex() {
        let c = Config::defaults();
        let d = c.resolved_digest();
        assert!(crate::hash::is_lowercase_sha256_hex(&d));
    }

    #[test]
    fn canonical_json_is_key_sorted() {
        let c = Config::defaults();
        let json = c.to_canonical_json();
        // 最初の object key が "analysis"（byte 順で最小）。
        assert!(json.starts_with(r#"{"analysis":"#));
    }
}
