//! Error 型階層・Exit Code・scope 付き strict mode（規範 §17）。
//!
//! Exit Code の優先順位は数値の大小ではなく `10 > 6 > 5 > 4 > 3 > 2 > 1 > 0`
//! （規範 §17.2）。複数の error が同時に発生した場合はこの優先順位で最大のものを
//! process の終了 code とする。

/// 規範 §17.2 の Exit Code。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// 完全成功。Warning・skip・limit 到達なし。
    Success = 0,
    /// Case は生成されたが Warning・partial・skip・limit 到達あり。
    CaseWithWarnings = 1,
    /// CLI または設定 error。
    CliOrConfigError = 2,
    /// 入力 path または Evidence discovery error。
    InputOrDiscoveryError = 3,
    /// 出力作成・安全検証・overwrite error。
    OutputOrSafetyError = 4,
    /// Rule validation または strict rules error。
    RuleValidationOrStrictRulesError = 5,
    /// strict parser または strict limits error。
    StrictParserOrStrictLimitsError = 6,
    /// TraceForge 内部 Fatal error または panic（規範 §9.4）。
    FatalInternalError = 10,
}

impl ExitCode {
    /// 優先順位値（規範 §17.2: `10 > 6 > 5 > 4 > 3 > 2 > 1 > 0`）。
    ///
    /// 数値の大小ではなく、この順序で最大のものを選ぶ。`FatalInternalError` が最高。
    pub fn precedence(self) -> u8 {
        match self {
            ExitCode::Success => 0,
            ExitCode::CaseWithWarnings => 1,
            ExitCode::CliOrConfigError => 2,
            ExitCode::InputOrDiscoveryError => 3,
            ExitCode::OutputOrSafetyError => 4,
            ExitCode::RuleValidationOrStrictRulesError => 5,
            ExitCode::StrictParserOrStrictLimitsError => 6,
            ExitCode::FatalInternalError => 7,
        }
    }

    /// 規範 §17.2 の優先順位で大きい方を選ぶ。
    pub fn merge(self, other: ExitCode) -> ExitCode {
        if self.precedence() >= other.precedence() {
            self
        } else {
            other
        }
    }

    /// process の終了 code へ変換する。
    pub fn as_process_code(self) -> i32 {
        self as i32
    }
}

/// `--strict parser / rules / limits / all` の scope（規範 §17.1）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictScope {
    Parser,
    Rules,
    Limits,
    /// bare `--strict` と同じ。全 scope を有効化。
    All,
}

impl StrictScope {
    /// 全 scope を有効化した [`StrictMode`] を返す。
    pub fn to_mode(self) -> StrictMode {
        match self {
            StrictScope::Parser => StrictMode {
                parser: true,
                rules: false,
                limits: false,
            },
            StrictScope::Rules => StrictMode {
                parser: false,
                rules: true,
                limits: false,
            },
            StrictScope::Limits => StrictMode {
                parser: false,
                rules: false,
                limits: true,
            },
            StrictScope::All => StrictMode {
                parser: true,
                rules: true,
                limits: true,
            },
        }
    }

    /// `--strict <value>` の文字列から復元する。`""` や未知値は Err。
    pub fn parse(s: &str) -> Result<Self, StrictScopeParseError> {
        match s {
            "parser" => Ok(StrictScope::Parser),
            "rules" => Ok(StrictScope::Rules),
            "limits" => Ok(StrictScope::Limits),
            "all" => Ok(StrictScope::All),
            _ => Err(StrictScopeParseError {
                input: s.to_string(),
            }),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StrictScope::Parser => "parser",
            StrictScope::Rules => "rules",
            StrictScope::Limits => "limits",
            StrictScope::All => "all",
        }
    }
}

/// `--strict <value>` の parse 失敗。
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("不正な strict scope: {input}（parser / rules / limits / all のいずれか）")]
pub struct StrictScopeParseError {
    pub input: String,
}

/// 有効化された strict scope の集合（規範 §17.1）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StrictMode {
    pub parser: bool,
    pub rules: bool,
    pub limits: bool,
}

impl StrictMode {
    /// strict mode が一切無効。
    pub fn none() -> Self {
        StrictMode::default()
    }

    /// 全 scope 有効（bare `--strict` と同じ）。
    pub fn all() -> Self {
        StrictScope::All.to_mode()
    }

    /// いずれかの scope が有効か。
    pub fn is_any_active(&self) -> bool {
        self.parser || self.rules || self.limits
    }
}

/// TraceForge の error 型階層（規範 §17.2）。
#[derive(Debug, thiserror::Error)]
pub enum TraceForgeError {
    /// CLI 引数または設定（Exit Code 2）。
    #[error("CLI または設定 error: {0}")]
    CliOrConfig(String),
    /// 入力 path または Evidence discovery（Exit Code 3）。
    #[error("入力 path または Evidence discovery error: {0}")]
    InputOrDiscovery(String),
    /// 出力作成・安全検証・overwrite（Exit Code 4）。
    #[error("出力作成・安全検証・overwrite error: {0}")]
    OutputOrSafety(String),
    /// Rule validation または strict rules（Exit Code 5）。
    #[error("Rule validation または strict rules error: {0}")]
    RuleValidation(String),
    /// strict parser または strict limits（Exit Code 6）。
    #[error("strict parser または strict limits error: {0}")]
    Strict(String),
    /// TraceForge 内部 Fatal または panic（Exit Code 10、規範 §9.4）。
    #[error("TraceForge 内部 Fatal error: {0}")]
    Fatal(String),
    /// I/O error。文脈で他 code へ昇格できる。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl TraceForgeError {
    /// この error に対応する規定 Exit Code（規範 §17.2）。
    ///
    /// 文脈によって呼出側で上書きしてよい（例: I/O error を出力安全 violation 扱いにする等）。
    pub fn default_exit_code(&self) -> ExitCode {
        match self {
            TraceForgeError::CliOrConfig(_) => ExitCode::CliOrConfigError,
            TraceForgeError::InputOrDiscovery(_) => ExitCode::InputOrDiscoveryError,
            TraceForgeError::OutputOrSafety(_) => ExitCode::OutputOrSafetyError,
            TraceForgeError::RuleValidation(_) => ExitCode::RuleValidationOrStrictRulesError,
            TraceForgeError::Strict(_) => ExitCode::StrictParserOrStrictLimitsError,
            TraceForgeError::Fatal(_) => ExitCode::FatalInternalError,
            TraceForgeError::Io(_) => ExitCode::FatalInternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_precedence_order() {
        // 規範 §17.2: 10 > 6 > 5 > 4 > 3 > 2 > 1 > 0
        assert!(
            ExitCode::FatalInternalError.precedence()
                > ExitCode::StrictParserOrStrictLimitsError.precedence()
        );
        assert!(
            ExitCode::StrictParserOrStrictLimitsError.precedence()
                > ExitCode::RuleValidationOrStrictRulesError.precedence()
        );
        assert!(
            ExitCode::RuleValidationOrStrictRulesError.precedence()
                > ExitCode::OutputOrSafetyError.precedence()
        );
        assert!(
            ExitCode::OutputOrSafetyError.precedence()
                > ExitCode::InputOrDiscoveryError.precedence()
        );
        assert!(
            ExitCode::InputOrDiscoveryError.precedence() > ExitCode::CliOrConfigError.precedence()
        );
        assert!(ExitCode::CliOrConfigError.precedence() > ExitCode::CaseWithWarnings.precedence());
        assert!(ExitCode::CaseWithWarnings.precedence() > ExitCode::Success.precedence());
    }

    #[test]
    fn merge_picks_higher_precedence() {
        // 複数 error の merge は優先順位の大きい方（規範 §17.2）。
        assert_eq!(
            ExitCode::Success.merge(ExitCode::FatalInternalError),
            ExitCode::FatalInternalError
        );
        assert_eq!(
            ExitCode::FatalInternalError.merge(ExitCode::Success),
            ExitCode::FatalInternalError
        );
        // CaseWithWarnings(1) と InputOrDiscovery(3) なら 3。
        assert_eq!(
            ExitCode::CaseWithWarnings.merge(ExitCode::InputOrDiscoveryError),
            ExitCode::InputOrDiscoveryError
        );
        // Strict(6) と Fatal(10) なら Fatal。
        assert_eq!(
            ExitCode::StrictParserOrStrictLimitsError.merge(ExitCode::FatalInternalError),
            ExitCode::FatalInternalError
        );
    }

    #[test]
    fn as_process_code_matches_enum_value() {
        assert_eq!(ExitCode::Success.as_process_code(), 0);
        assert_eq!(ExitCode::CaseWithWarnings.as_process_code(), 1);
        assert_eq!(ExitCode::CliOrConfigError.as_process_code(), 2);
        assert_eq!(ExitCode::InputOrDiscoveryError.as_process_code(), 3);
        assert_eq!(ExitCode::OutputOrSafetyError.as_process_code(), 4);
        assert_eq!(
            ExitCode::RuleValidationOrStrictRulesError.as_process_code(),
            5
        );
        assert_eq!(
            ExitCode::StrictParserOrStrictLimitsError.as_process_code(),
            6
        );
        assert_eq!(ExitCode::FatalInternalError.as_process_code(), 10);
    }

    #[test]
    fn strict_scope_parse_and_mode() {
        assert_eq!(StrictScope::parse("parser").unwrap(), StrictScope::Parser);
        assert_eq!(StrictScope::parse("rules").unwrap(), StrictScope::Rules);
        assert_eq!(StrictScope::parse("limits").unwrap(), StrictScope::Limits);
        assert_eq!(StrictScope::parse("all").unwrap(), StrictScope::All);
        assert!(StrictScope::parse("nonsense").is_err());

        let all = StrictScope::All.to_mode();
        assert!(all.parser && all.rules && all.limits);
        let parser_only = StrictScope::Parser.to_mode();
        assert!(parser_only.parser && !parser_only.rules && !parser_only.limits);
    }

    #[test]
    fn strict_mode_all_equals_individual_toggles() {
        let all = StrictMode::all();
        assert!(all.is_any_active());
        assert!(all.parser && all.rules && all.limits);
        let none = StrictMode::none();
        assert!(!none.is_any_active());
    }

    #[test]
    fn error_variants_default_exit_code() {
        assert_eq!(
            TraceForgeError::CliOrConfig("x".into()).default_exit_code(),
            ExitCode::CliOrConfigError
        );
        assert_eq!(
            TraceForgeError::Fatal("x".into()).default_exit_code(),
            ExitCode::FatalInternalError
        );
    }
}
