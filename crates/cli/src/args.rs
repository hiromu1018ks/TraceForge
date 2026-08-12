//! CLI 引数の最小 parser（Phase 7・製品 §12）。
//!
//! 外部 crate（clap 等）を使わず、`traceforge <COMMAND> [OPTIONS]` 形式を自前で parse する。
//! `--key value` と `--key=value` の両方を受け付ける。`--no-hash` は明示的に拒否する
//! （規範 §2・T7-022）。

use tf_core::error::ExitCode;

/// CLI へ渡される command 種別。
#[derive(Clone, Debug)]
pub enum Command {
    /// `traceforge analyze <input> [OPTIONS]`。
    Analyze(AnalyzeArgs),
    /// `traceforge timeline <case> [OPTIONS]`。
    Timeline(TimelineArgs),
    /// `traceforge correlate <case> --rules <dir>`。
    Correlate(CorrelateArgs),
    /// `traceforge sigma <case> --rules <dir>`。
    Sigma(SigmaArgs),
    /// `traceforge yara <evidence> --rules <dir> --mode <m>`。
    Yara(YaraArgs),
    /// `traceforge export <case> [--format <fmt>] [--output <path>]`。
    Export(ExportArgs),
    /// `traceforge rules <dir> [--validate]`。
    Rules(RulesArgs),
    /// `traceforge inspect <file>`。
    Inspect(InspectArgs),
    /// `traceforge version`。
    Version,
}

/// `analyze` command の引数。
#[derive(Clone, Debug, Default)]
pub struct AnalyzeArgs {
    /// 解析対象の入力 path（file または directory）。
    pub input: String,
    /// 出力 path。省略時は stdout へ Text 出力。
    pub output: Option<String>,
    /// 出力形式。省略時は `text`（または path 拡張子から推定）。
    pub format: Option<OutputFormatArg>,
    /// explicit config file の path。
    pub config: Option<String>,
    /// `--timezone` override（IANA timezone name）。
    pub timezone: Option<String>,
    /// `--threads` override（0 = 自動）。
    pub threads: Option<u32>,
    /// `--rules <dir>`（Sigma + Correlation + YARA を全て読み込む場合）。
    pub rules_dir: Option<String>,
    /// `--attack-dataset <path>`（STIX bundle file）。
    pub attack_dataset: Option<String>,
    /// `--attack-version <ver>`（ATT&CK release version・例: `15.1`）。
    pub attack_version: Option<String>,
    /// `--attack-source-url <url>`（取得元 URL・Manifest 記録用）。
    pub attack_source_url: Option<String>,
}

/// `timeline` command の引数。
#[derive(Clone, Debug, Default)]
pub struct TimelineArgs {
    /// Case JSON file または JSONL file の path。
    pub case: String,
    /// UTC instant の下限（含む）。
    pub utc_from: Option<String>,
    /// UTC instant の上限（含む）。
    pub utc_to: Option<String>,
    /// Event type で絞り込み（複数指定可）。
    pub event_types: Vec<String>,
    /// hostname で絞り込み（複数指定可）。
    pub hostnames: Vec<String>,
}

/// `correlate` command の引数。
#[derive(Clone, Debug, Default)]
pub struct CorrelateArgs {
    pub case: String,
    pub rules_dir: String,
    pub output: Option<String>,
    pub format: Option<OutputFormatArg>,
}

/// `sigma` command の引数。
#[derive(Clone, Debug, Default)]
pub struct SigmaArgs {
    pub case: String,
    pub rules_dir: String,
    pub output: Option<String>,
    pub format: Option<OutputFormatArg>,
}

/// `yara` command の引数。
#[derive(Clone, Debug, Default)]
pub struct YaraArgs {
    /// Evidence file または directory の path。
    pub evidence: String,
    pub rules_dir: String,
    /// `all` / `suspicious` / `explicit`（既定 `suspicious`）。
    pub mode: Option<String>,
    pub output: Option<String>,
    pub format: Option<OutputFormatArg>,
}

/// `export` command の引数。
#[derive(Clone, Debug, Default)]
pub struct ExportArgs {
    pub case: String,
    pub format: Option<OutputFormatArg>,
    pub output: Option<String>,
}

/// `rules` command の引数。
#[derive(Clone, Debug, Default)]
pub struct RulesArgs {
    pub rules_dir: String,
    /// `--validate`: 構文検証のみ実行して終了。
    pub validate: bool,
    /// `--list`: 読み込んだ Rule 一覧を表示。
    pub list: bool,
}

/// `inspect` command の引数。
#[derive(Clone, Debug, Default)]
pub struct InspectArgs {
    pub file: String,
}

/// 出力形式の CLI 文字列値。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormatArg {
    Text,
    Json,
    Jsonl,
    Csv,
    Html,
    Timesketch,
}

impl OutputFormatArg {
    /// 文字列から復元。未知値は [`None`]。
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "text" => OutputFormatArg::Text,
            "json" => OutputFormatArg::Json,
            "jsonl" => OutputFormatArg::Jsonl,
            "csv" => OutputFormatArg::Csv,
            "html" => OutputFormatArg::Html,
            "timesketch" => OutputFormatArg::Timesketch,
            _ => return None,
        })
    }

    /// ファイル拡張子から推定。
    pub fn from_extension(ext: &str) -> Option<Self> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "txt" => OutputFormatArg::Text,
            "json" => OutputFormatArg::Json,
            "jsonl" => OutputFormatArg::Jsonl,
            "csv" => OutputFormatArg::Csv,
            "html" | "htm" => OutputFormatArg::Html,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormatArg::Text => "text",
            OutputFormatArg::Json => "json",
            OutputFormatArg::Jsonl => "jsonl",
            OutputFormatArg::Csv => "csv",
            OutputFormatArg::Html => "html",
            OutputFormatArg::Timesketch => "timesketch",
        }
    }
}

/// 全 command 共通の global option。
#[derive(Clone, Debug, Default)]
pub struct GlobalArgs {
    /// `--quiet`: log を stderr へ出さない。解析結果（stdout）は出す。
    pub quiet: bool,
    /// `--strict <scope>`（複数回指定可）。
    pub strict: Vec<String>,
}

/// parse 済みの CLI args 全体。
#[derive(Clone, Debug)]
pub struct CliArgs {
    pub command: Command,
    pub global: GlobalArgs,
}

/// CLI parse error。
#[derive(Debug, Clone, thiserror::Error)]
pub enum CliParseError {
    #[error("usage: traceforge <COMMAND> [OPTIONS]（command 無し）")]
    NoCommand,
    #[error("未知の command です: {0}")]
    UnknownCommand(String),
    #[error("引数が不足しています: {0}")]
    MissingArgument(&'static str),
    #[error("--no-hash は提供されていません（規範 §2: SHA-256 は必須）")]
    NoHashForbidden,
    #[error("不正な引数: {0}")]
    InvalidValue(String),
    #[error(
        "--format の値が不正です: {0}（text / json / jsonl / csv / html / timesketch のいずれか）"
    )]
    InvalidFormat(String),
    #[error("--mode の値が不正です: {0}（all / suspicious / explicit のいずれか）")]
    InvalidMode(String),
}

impl CliParseError {
    /// 対応する Exit Code（規範 §17.2）。
    pub fn exit_code(&self) -> ExitCode {
        match self {
            CliParseError::NoHashForbidden => ExitCode::CliOrConfigError,
            _ => ExitCode::CliOrConfigError,
        }
    }
}

/// `args[0]` は program 名（`traceforge`）と想定する。`args[1..]` を parse する。
pub fn parse_args(args: &[String]) -> Result<CliArgs, CliParseError> {
    if args.len() < 2 {
        return Err(CliParseError::NoCommand);
    }
    // `--no-hash` が引数のどこかに現れたら即座に拒否する（規範 §2・T7-022）。
    for a in &args[1..] {
        if a == "--no-hash" || a.starts_with("--no-hash=") {
            return Err(CliParseError::NoHashForbidden);
        }
    }

    // global option は全 command 前に出ても後に出てもよい。ここでは command 名より前に
    // 出た `--quiet` / `--strict` を拾い、command 名を後続から探す。
    let mut iter = args[1..].iter().peekable();
    let mut global = GlobalArgs::default();
    let mut command_name: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();

    while let Some(arg) = iter.next() {
        let (key, inline_value) = split_key_value(arg);
        match key.as_str() {
            "--quiet" => global.quiet = true,
            "--strict" => {
                let v = take_value(&mut iter, inline_value, "--strict")?;
                global.strict.push(v);
            }
            _ => {
                if command_name.is_none() && !key.starts_with('-') {
                    command_name = Some(key);
                } else {
                    rest.push(arg.clone());
                    if inline_value.is_none()
                        && needs_inline_capture(&key)
                        && let Some(next) = iter.next()
                    {
                        rest.push(next.clone());
                    }
                }
            }
        }
    }

    let command_name = command_name.ok_or(CliParseError::NoCommand)?;

    let command = match command_name.as_str() {
        "analyze" => Command::Analyze(parse_analyze(&rest)?),
        "timeline" => Command::Timeline(parse_timeline(&rest)?),
        "correlate" => Command::Correlate(parse_correlate(&rest)?),
        "sigma" => Command::Sigma(parse_sigma(&rest)?),
        "yara" => Command::Yara(parse_yara(&rest)?),
        "export" => Command::Export(parse_export(&rest)?),
        "rules" => Command::Rules(parse_rules(&rest)?),
        "inspect" => Command::Inspect(parse_inspect(&rest)?),
        "version" => Command::Version,
        other => return Err(CliParseError::UnknownCommand(other.to_string())),
    };

    Ok(CliArgs { command, global })
}

/// `--key=value` を (`--key`, Some(`value`)) へ、`--key` を (`--key`, None) へ分割。
fn split_key_value(arg: &str) -> (String, Option<String>) {
    if let Some(idx) = arg.find('=') {
        (arg[..idx].to_string(), Some(arg[idx + 1..].to_string()))
    } else {
        (arg.to_string(), None)
    }
}

/// `--key value` 形式で value を次の引数から取り出す。
fn take_value(
    iter: &mut std::iter::Peekable<std::slice::Iter<String>>,
    inline: Option<String>,
    flag: &'static str,
) -> Result<String, CliParseError> {
    if let Some(v) = inline {
        return Ok(v);
    }
    iter.next()
        .cloned()
        .ok_or(CliParseError::MissingArgument(flag))
}

/// `--key value` 形式の flag なら true を返す（`--quiet` のような boolean flag は false）。
fn needs_inline_capture(key: &str) -> bool {
    !matches!(key, "--quiet" | "--validate" | "--list" | "--help" | "-h")
}

fn parse_analyze(args: &[String]) -> Result<AnalyzeArgs, CliParseError> {
    let mut a = AnalyzeArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, val) = split_key_value(&args[i]);
        match key.as_str() {
            "--output" | "-o" => {
                a.output = Some(take_value_from(args, &mut i, val, "--output")?);
            }
            "--format" => {
                let v = take_value_from(args, &mut i, val, "--format")?;
                a.format = Some(OutputFormatArg::parse(&v).ok_or(CliParseError::InvalidFormat(v))?);
            }
            "--config" | "-c" => {
                a.config = Some(take_value_from(args, &mut i, val, "--config")?);
            }
            "--timezone" => {
                a.timezone = Some(take_value_from(args, &mut i, val, "--timezone")?);
            }
            "--threads" => {
                let v = take_value_from(args, &mut i, val, "--threads")?;
                a.threads =
                    Some(v.parse().map_err(|_| {
                        CliParseError::InvalidValue(format!("--threads は数値: {v}"))
                    })?);
            }
            "--rules" => {
                a.rules_dir = Some(take_value_from(args, &mut i, val, "--rules")?);
            }
            "--attack-dataset" => {
                a.attack_dataset = Some(take_value_from(args, &mut i, val, "--attack-dataset")?);
            }
            "--attack-version" => {
                a.attack_version = Some(take_value_from(args, &mut i, val, "--attack-version")?);
            }
            "--attack-source-url" => {
                a.attack_source_url =
                    Some(take_value_from(args, &mut i, val, "--attack-source-url")?);
            }
            _ if !key.starts_with('-') && a.input.is_empty() => {
                a.input = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "analyze: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if a.input.is_empty() {
        return Err(CliParseError::MissingArgument("analyze <input>"));
    }
    Ok(a)
}

fn parse_timeline(args: &[String]) -> Result<TimelineArgs, CliParseError> {
    let mut t = TimelineArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, val) = split_key_value(&args[i]);
        match key.as_str() {
            "--from" => t.utc_from = Some(take_value_from(args, &mut i, val, "--from")?),
            "--to" => t.utc_to = Some(take_value_from(args, &mut i, val, "--to")?),
            "--type" => t
                .event_types
                .push(take_value_from(args, &mut i, val, "--type")?),
            "--host" => t
                .hostnames
                .push(take_value_from(args, &mut i, val, "--host")?),
            _ if !key.starts_with('-') && t.case.is_empty() => {
                t.case = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "timeline: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if t.case.is_empty() {
        return Err(CliParseError::MissingArgument("timeline <case>"));
    }
    Ok(t)
}

fn parse_correlate(args: &[String]) -> Result<CorrelateArgs, CliParseError> {
    let mut c = CorrelateArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, val) = split_key_value(&args[i]);
        match key.as_str() {
            "--rules" => c.rules_dir = take_value_from(args, &mut i, val, "--rules")?,
            "--output" | "-o" => c.output = Some(take_value_from(args, &mut i, val, "--output")?),
            "--format" => {
                let v = take_value_from(args, &mut i, val, "--format")?;
                c.format = Some(OutputFormatArg::parse(&v).ok_or(CliParseError::InvalidFormat(v))?);
            }
            _ if !key.starts_with('-') && c.case.is_empty() => {
                c.case = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "correlate: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if c.case.is_empty() {
        return Err(CliParseError::MissingArgument("correlate <case>"));
    }
    if c.rules_dir.is_empty() {
        return Err(CliParseError::MissingArgument("correlate --rules <dir>"));
    }
    Ok(c)
}

fn parse_sigma(args: &[String]) -> Result<SigmaArgs, CliParseError> {
    let mut s = SigmaArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, val) = split_key_value(&args[i]);
        match key.as_str() {
            "--rules" => s.rules_dir = take_value_from(args, &mut i, val, "--rules")?,
            "--output" | "-o" => s.output = Some(take_value_from(args, &mut i, val, "--output")?),
            "--format" => {
                let v = take_value_from(args, &mut i, val, "--format")?;
                s.format = Some(OutputFormatArg::parse(&v).ok_or(CliParseError::InvalidFormat(v))?);
            }
            _ if !key.starts_with('-') && s.case.is_empty() => {
                s.case = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "sigma: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if s.case.is_empty() {
        return Err(CliParseError::MissingArgument("sigma <case>"));
    }
    if s.rules_dir.is_empty() {
        return Err(CliParseError::MissingArgument("sigma --rules <dir>"));
    }
    Ok(s)
}

fn parse_yara(args: &[String]) -> Result<YaraArgs, CliParseError> {
    let mut y = YaraArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, val) = split_key_value(&args[i]);
        match key.as_str() {
            "--rules" => y.rules_dir = take_value_from(args, &mut i, val, "--rules")?,
            "--mode" => {
                let v = take_value_from(args, &mut i, val, "--mode")?;
                y.mode = Some(
                    match v.as_str() {
                        "all" | "suspicious" | "explicit" => v,
                        _ => return Err(CliParseError::InvalidMode(v)),
                    }
                    .to_string(),
                );
            }
            "--output" | "-o" => y.output = Some(take_value_from(args, &mut i, val, "--output")?),
            "--format" => {
                let v = take_value_from(args, &mut i, val, "--format")?;
                y.format = Some(OutputFormatArg::parse(&v).ok_or(CliParseError::InvalidFormat(v))?);
            }
            _ if !key.starts_with('-') && y.evidence.is_empty() => {
                y.evidence = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "yara: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if y.evidence.is_empty() {
        return Err(CliParseError::MissingArgument("yara <evidence>"));
    }
    if y.rules_dir.is_empty() {
        return Err(CliParseError::MissingArgument("yara --rules <dir>"));
    }
    Ok(y)
}

fn parse_export(args: &[String]) -> Result<ExportArgs, CliParseError> {
    let mut e = ExportArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, val) = split_key_value(&args[i]);
        match key.as_str() {
            "--format" => {
                let v = take_value_from(args, &mut i, val, "--format")?;
                e.format = Some(OutputFormatArg::parse(&v).ok_or(CliParseError::InvalidFormat(v))?);
            }
            "--output" | "-o" => e.output = Some(take_value_from(args, &mut i, val, "--output")?),
            _ if !key.starts_with('-') && e.case.is_empty() => {
                e.case = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "export: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if e.case.is_empty() {
        return Err(CliParseError::MissingArgument("export <case>"));
    }
    Ok(e)
}

fn parse_rules(args: &[String]) -> Result<RulesArgs, CliParseError> {
    let mut r = RulesArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, _val) = split_key_value(&args[i]);
        match key.as_str() {
            "--validate" => r.validate = true,
            "--list" => r.list = true,
            _ if !key.starts_with('-') && r.rules_dir.is_empty() => {
                r.rules_dir = key;
            }
            other => {
                return Err(CliParseError::InvalidValue(format!(
                    "rules: 未知の引数 {other}"
                )));
            }
        }
        i += 1;
    }
    if r.rules_dir.is_empty() {
        return Err(CliParseError::MissingArgument("rules <dir>"));
    }
    Ok(r)
}

fn parse_inspect(args: &[String]) -> Result<InspectArgs, CliParseError> {
    let mut in_args = InspectArgs::default();
    let mut i = 0;
    while i < args.len() {
        let (key, _val) = split_key_value(&args[i]);
        if !key.starts_with('-') && in_args.file.is_empty() {
            in_args.file = key;
        } else {
            return Err(CliParseError::InvalidValue(format!(
                "inspect: 未知の引数 {key}"
            )));
        }
        i += 1;
    }
    if in_args.file.is_empty() {
        return Err(CliParseError::MissingArgument("inspect <file>"));
    }
    Ok(in_args)
}

/// `--key value` 形式の引数から value を取り出す。inline (`--key=value`) と split (`--key value`) の両方を許可。
fn take_value_from(
    args: &[String],
    i: &mut usize,
    inline: Option<String>,
    flag: &'static str,
) -> Result<String, CliParseError> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or(CliParseError::MissingArgument(flag))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        let mut v = vec!["traceforge".to_string()];
        v.extend(parts.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn rejects_no_hash() {
        let r = parse_args(&args(&["analyze", "input", "--no-hash"]));
        assert!(matches!(r, Err(CliParseError::NoHashForbidden)));
    }

    #[test]
    fn parses_analyze_basic() {
        let r = parse_args(&args(&["analyze", "/some/dir"])).unwrap();
        if let Command::Analyze(a) = r.command {
            assert_eq!(a.input, "/some/dir");
        } else {
            panic!("Analyze 期待");
        }
    }

    #[test]
    fn parses_analyze_with_format_and_output() {
        let r = parse_args(&args(&[
            "analyze", "input", "--format", "json", "--output", "out.json",
        ]))
        .unwrap();
        if let Command::Analyze(a) = r.command {
            assert_eq!(a.format, Some(OutputFormatArg::Json));
            assert_eq!(a.output.as_deref(), Some("out.json"));
        } else {
            panic!("Analyze 期待");
        }
    }

    #[test]
    fn parses_version_command() {
        let r = parse_args(&args(&["version"])).unwrap();
        assert!(matches!(r.command, Command::Version));
    }

    #[test]
    fn parses_quiet_global() {
        let r = parse_args(&args(&["--quiet", "version"])).unwrap();
        assert!(r.global.quiet);
    }

    #[test]
    fn parses_export_format_inline() {
        let r = parse_args(&args(&["export", "case.json", "--format=csv"])).unwrap();
        if let Command::Export(e) = r.command {
            assert_eq!(e.format, Some(OutputFormatArg::Csv));
        } else {
            panic!("Export 期待");
        }
    }

    #[test]
    fn rejects_unknown_format() {
        let r = parse_args(&args(&["export", "case.json", "--format", "yaml"]));
        assert!(matches!(r, Err(CliParseError::InvalidFormat(_))));
    }

    #[test]
    fn parses_yara_mode() {
        let r = parse_args(&args(&[
            "yara", "evidence", "--rules", "rules/", "--mode", "all",
        ]))
        .unwrap();
        if let Command::Yara(y) = r.command {
            assert_eq!(y.mode.as_deref(), Some("all"));
        } else {
            panic!("Yara 期待");
        }
    }

    #[test]
    fn rejects_invalid_mode() {
        let r = parse_args(&args(&[
            "yara", "evidence", "--rules", "rules/", "--mode", "invalid",
        ]));
        assert!(matches!(r, Err(CliParseError::InvalidMode(_))));
    }

    #[test]
    fn rules_validate_flag() {
        let r = parse_args(&args(&["rules", "rules/", "--validate"])).unwrap();
        if let Command::Rules(r) = r.command {
            assert!(r.validate);
        } else {
            panic!("Rules 期待");
        }
    }

    #[test]
    fn timeline_supports_multiple_type_filters() {
        let r = parse_args(&args(&[
            "timeline",
            "case.json",
            "--type",
            "login",
            "--type",
            "process_start",
        ]))
        .unwrap();
        if let Command::Timeline(t) = r.command {
            assert_eq!(t.event_types, vec!["login", "process_start"]);
        } else {
            panic!("Timeline 期待");
        }
    }

    #[test]
    fn missing_command_returns_error() {
        let r = parse_args(&args(&[]));
        assert!(matches!(r, Err(CliParseError::NoCommand)));
    }
}
