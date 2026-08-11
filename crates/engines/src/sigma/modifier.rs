//! Sigma modifier（互換 §6.1・§6.2、T5-014）。
//!
//! TF-SIGMA-1.0 が対応する modifier は次の6種:
//! - `contains`: 値が field 値の部分文字列
//! - `startswith`: field 値が値で始まる
//! - `endswith`: field 値が値で終わる
//! - `cased`: 大文字小文字を区別する（既定は区別しない）
//! - `exists`: field の存在を検査する
//! - `all`: list 値の全てが match する必要がある（既定は何れか一つ = OR）
//!
//! 互換 §6.2 が禁止する modifier を含む Rule は全体 skip する（規範 §15.1）。

/// Sigma field に付与する modifier（互換 §6.1）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Modifier {
    /// 値が field 値の部分文字列（大文字小文字区別なし既定）。
    Contains,
    /// field 値が指定値で始まる。
    StartsWith,
    /// field 値が指定値で終わる。
    EndsWith,
    /// 大文字小文字を区別する（他の modifier と併用可能）。
    Cased,
    /// field の存在/不在を検査する。値は `true`（存在）/ `false`（不在）。
    Exists,
    /// list 値の全てが match する必要がある（既定は OR = 何れか一つ）。
    All,
}

/// TF-SIGMA-1.0 が対応する modifier 名の一覧（互換 §6.1）。
pub const SUPPORTED_MODIFIER_NAMES: &[&str] = &[
    "contains",
    "startswith",
    "endswith",
    "cased",
    "exists",
    "all",
];

/// modifier 名を [`Modifier`] へ変換する。
///
/// 戻り値:
/// - `Ok(Modifier)`: 対応 modifier。
/// - `Err(name)`: 未対応 modifier。呼出側で Rule 全体 skip とする（規範 §15.1）。
pub fn parse_modifier(name: &str) -> Result<Modifier, String> {
    match name {
        "contains" => Ok(Modifier::Contains),
        "startswith" => Ok(Modifier::StartsWith),
        "endswith" => Ok(Modifier::EndsWith),
        "cased" => Ok(Modifier::Cased),
        "exists" => Ok(Modifier::Exists),
        "all" => Ok(Modifier::All),
        other => Err(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_supported_modifiers() {
        assert_eq!(parse_modifier("contains"), Ok(Modifier::Contains));
        assert_eq!(parse_modifier("startswith"), Ok(Modifier::StartsWith));
        assert_eq!(parse_modifier("endswith"), Ok(Modifier::EndsWith));
        assert_eq!(parse_modifier("cased"), Ok(Modifier::Cased));
        assert_eq!(parse_modifier("exists"), Ok(Modifier::Exists));
        assert_eq!(parse_modifier("all"), Ok(Modifier::All));
    }

    #[test]
    fn parse_unsupported_modifier() {
        assert_eq!(parse_modifier("base64"), Err("base64".into()));
        assert_eq!(parse_modifier("re"), Err("re".into()));
        assert_eq!(parse_modifier("windash"), Err("windash".into()));
        assert_eq!(parse_modifier("unknown"), Err("unknown".into()));
    }
}
