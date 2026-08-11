//! Sigma condition 式の parser（互換 §6.1、T5-013）。
//!
//! Sigma `detection.condition` 文字列を再帰降下 parser で [`Condition`] tree へ変換する。
//!
//! ## 対応構文
//!
//! - 選択肢名参照: `selection`
//! - 論理演算: `and`, `or`, `not`
//! - 括弧: `( ... )`
//! - 量化子: `1 of selection*`, `all of selection*`, `1 of them`, `all of them`
//!
//! ## 未対応構文（Rule 全体 skip・規範 §15.1・互換 §6.2）
//!
//! - aggregation: `count()`, `min()`, `max()`, `avg()`, `sum()` ... `by` ... `> N`
//! - timeframe キーワード
//! - `near` 演算子
//! - placeholder（`%var%`）

/// condition 式の AST node。
#[derive(Clone, Debug, PartialEq)]
pub enum Condition {
    /// `A and B`
    And(Box<Condition>, Box<Condition>),
    /// `A or B`
    Or(Box<Condition>, Box<Condition>),
    /// `not A`
    Not(Box<Condition>),
    /// 選択肢名参照（`selection` 等）
    Selector(String),
    /// `1 of <pattern>` — pattern に合致する選択肢の少なくとも1つが true
    OneOf(SelectorScope),
    /// `all of <pattern>` — pattern に合致する選択肢が全て true
    AllOf(SelectorScope),
}

/// 量化子の対象範囲。
#[derive(Clone, Debug, PartialEq)]
pub enum SelectorScope {
    /// `them` — 全ての選択肢。
    All,
    /// `<prefix>*` — 指定 prefix で始まる選択肢。
    Wildcard(String),
}

/// condition 文字列の parse 結果。
pub type ConditionResult = Result<Condition, ConditionError>;

/// condition parse error。未対応構文を含む。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConditionError {
    /// 構文 error（token 不備・括弧不一致等）。
    #[error("Sigma condition parse error: {0}")]
    Syntax(String),
    /// 未対応構文を含む（aggregation・timeframe・`near`・placeholder）。Rule 全体 skip。
    #[error("Sigma unsupported condition feature: {0}")]
    Unsupported(String),
}

/// condition 文字列を parse する。
pub fn parse_condition(input: &str) -> ConditionResult {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ConditionError::Syntax("empty condition".into()));
    }

    // 未対応構文の事前検出（部分評価禁止・規範 §15.1）。
    check_unsupported(trimmed)?;

    let tokens = tokenize(trimmed)?;
    let mut parser = CondParser { tokens, pos: 0 };
    let expr = parser.parse_or()?;

    if parser.pos < parser.tokens.len() {
        return Err(ConditionError::Syntax(format!(
            "unexpected trailing tokens: {:?}",
            &parser.tokens[parser.pos..]
        )));
    }

    Ok(expr)
}

/// 未対応構文を検出する（aggregation・timeframe・near・placeholder）。
fn check_unsupported(s: &str) -> Result<(), ConditionError> {
    let lower = s.to_lowercase();

    // aggregation 関数
    for func in ["count(", "min(", "max(", "avg(", "sum("] {
        if lower.contains(func) {
            return Err(ConditionError::Unsupported(format!(
                "aggregation function '{func} ...)' is not supported"
            )));
        }
    }

    // timeframe キーワード（condition 内に現れる）
    // Sigma では timeframe は detection 直下の別 field だが、condition 内の
    // `keyword` も安全のため検出する。
    // → detection 直下の timeframe は rule.rs で別途検出する。

    // `near` 演算子
    // token として独立した `near` を検出
    for word in lower.split_whitespace() {
        if word == "near" {
            return Err(ConditionError::Unsupported(
                "'near' operator is not supported".into(),
            ));
        }
    }

    // placeholder（`%var%`）
    if s.contains('%') {
        return Err(ConditionError::Unsupported(
            "placeholder expansion (%var%) is not supported".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// tokenizer
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),    // selection 名・キーワード以外の識別子
    Wildcard(String), // `prefix*`（prefix 部分）
    Keyword(Keyword),
    LParen,
    RParen,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Keyword {
    And,
    Or,
    Not,
    Of,
    Them,
    All, // `all of`
    One, // `1 of`（数字 1 は特別扱い）
}

fn tokenize(s: &str) -> Result<Vec<Token>, ConditionError> {
    let mut tokens = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            '1' => {
                // `1 of` の `1`（他の数字は未対応 → aggregation の可能性）
                chars.next();
                // 直後が ` of ` のみ許可
                let rest: String = chars.clone().collect();
                let rest_trimmed = rest.trim_start();
                if rest_trimmed.to_lowercase().starts_with("of ") || rest_trimmed == "of" {
                    tokens.push(Token::Keyword(Keyword::One));
                } else {
                    return Err(ConditionError::Unsupported(format!(
                        "numeric literal '1' not followed by 'of' (possible aggregation): '1{rest}'"
                    )));
                }
            }
            _ if c.is_alphabetic() || c == '_' => {
                let mut ident = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' || ch == '*' {
                        ident.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }

                // wildcard 末尾の検出
                if ident.ends_with('*') && ident.len() > 1 {
                    let prefix = ident[..ident.len() - 1].to_string();
                    // `*` は prefix の最後でのみ許可（中間や複数は未対応）
                    if prefix.contains('*') {
                        return Err(ConditionError::Syntax(format!(
                            "unsupported wildcard pattern: {ident}"
                        )));
                    }
                    tokens.push(Token::Wildcard(prefix));
                    continue;
                }

                // キーワード判定（case-insensitive）
                match ident.to_lowercase().as_str() {
                    "and" => tokens.push(Token::Keyword(Keyword::And)),
                    "or" => tokens.push(Token::Keyword(Keyword::Or)),
                    "not" => tokens.push(Token::Keyword(Keyword::Not)),
                    "of" => tokens.push(Token::Keyword(Keyword::Of)),
                    "them" => tokens.push(Token::Keyword(Keyword::Them)),
                    "all" => tokens.push(Token::Keyword(Keyword::All)),
                    _ => tokens.push(Token::Ident(ident)),
                }
            }
            _ => {
                return Err(ConditionError::Syntax(format!(
                    "unexpected character {c:?} in condition"
                )));
            }
        }
    }

    Ok(tokens)
}

// ============================================================================
// recursive descent parser
// ============================================================================

struct CondParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl CondParser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let t = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(t)
        } else {
            None
        }
    }

    /// `or_expr := and_expr ("or" and_expr)*`
    fn parse_or(&mut self) -> ConditionResult {
        let mut left = self.parse_and()?;
        while let Some(Token::Keyword(Keyword::Or)) = self.peek() {
            self.advance();
            let right = self.parse_and()?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `and_expr := not_expr ("and" not_expr)*`
    fn parse_and(&mut self) -> ConditionResult {
        let mut left = self.parse_not()?;
        while let Some(Token::Keyword(Keyword::And)) = self.peek() {
            self.advance();
            let right = self.parse_not()?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    /// `not_expr := "not" not_expr | atom`
    fn parse_not(&mut self) -> ConditionResult {
        if let Some(Token::Keyword(Keyword::Not)) = self.peek() {
            self.advance();
            let inner = self.parse_not()?;
            return Ok(Condition::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    /// `atom := "(" or_expr ")" | quantifier | selector`
    fn parse_atom(&mut self) -> ConditionResult {
        match self.peek() {
            Some(Token::LParen) => {
                self.advance(); // consume '('
                let expr = self.parse_or()?;
                match self.advance() {
                    Some(Token::RParen) => {}
                    other => {
                        return Err(ConditionError::Syntax(format!(
                            "expected ')', got {other:?}"
                        )));
                    }
                }
                Ok(expr)
            }
            Some(Token::Keyword(Keyword::One)) => {
                self.advance();
                self.parse_quantifier(QuantKind::OneOf)
            }
            Some(Token::Keyword(Keyword::All)) => {
                self.advance();
                self.parse_quantifier(QuantKind::AllOf)
            }
            Some(Token::Ident(name)) => {
                let name = name.clone();
                self.advance();
                Ok(Condition::Selector(name))
            }
            other => Err(ConditionError::Syntax(format!(
                "unexpected token in condition: {other:?}"
            ))),
        }
    }

    /// `quantifier := "of" (pattern | "them")`
    fn parse_quantifier(&mut self, kind: QuantKind) -> ConditionResult {
        match self.advance() {
            Some(Token::Keyword(Keyword::Of)) => {}
            other => {
                return Err(ConditionError::Syntax(format!(
                    "expected 'of' after quantifier, got {other:?}"
                )));
            }
        }
        let scope = match self.advance() {
            Some(Token::Keyword(Keyword::Them)) => SelectorScope::All,
            Some(Token::Wildcard(prefix)) => SelectorScope::Wildcard(prefix),
            other => {
                return Err(ConditionError::Syntax(format!(
                    "expected wildcard pattern or 'them' after 'of', got {other:?}"
                )));
            }
        };
        Ok(match kind {
            QuantKind::OneOf => Condition::OneOf(scope),
            QuantKind::AllOf => Condition::AllOf(scope),
        })
    }
}

#[derive(Clone, Copy)]
enum QuantKind {
    OneOf,
    AllOf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_selector() {
        let c = parse_condition("selection").unwrap();
        assert_eq!(c, Condition::Selector("selection".into()));
    }

    #[test]
    fn and_expression() {
        let c = parse_condition("sel1 and sel2").unwrap();
        assert_eq!(
            c,
            Condition::And(
                Box::new(Condition::Selector("sel1".into())),
                Box::new(Condition::Selector("sel2".into()))
            )
        );
    }

    #[test]
    fn or_expression() {
        let c = parse_condition("sel1 or sel2").unwrap();
        assert_eq!(
            c,
            Condition::Or(
                Box::new(Condition::Selector("sel1".into())),
                Box::new(Condition::Selector("sel2".into()))
            )
        );
    }

    #[test]
    fn not_expression() {
        let c = parse_condition("not sel1").unwrap();
        assert_eq!(
            c,
            Condition::Not(Box::new(Condition::Selector("sel1".into())))
        );
    }

    #[test]
    fn complex_expression() {
        let c = parse_condition("sel1 and not sel2 or sel3").unwrap();
        // precedence: and > or → (sel1 and (not sel2)) or sel3
        assert_eq!(
            c,
            Condition::Or(
                Box::new(Condition::And(
                    Box::new(Condition::Selector("sel1".into())),
                    Box::new(Condition::Not(Box::new(Condition::Selector("sel2".into()))))
                )),
                Box::new(Condition::Selector("sel3".into()))
            )
        );
    }

    #[test]
    fn parentheses_override_precedence() {
        let c = parse_condition("sel1 and (sel2 or sel3)").unwrap();
        assert_eq!(
            c,
            Condition::And(
                Box::new(Condition::Selector("sel1".into())),
                Box::new(Condition::Or(
                    Box::new(Condition::Selector("sel2".into())),
                    Box::new(Condition::Selector("sel3".into()))
                ))
            )
        );
    }

    #[test]
    fn one_of_wildcard() {
        let c = parse_condition("1 of sel*").unwrap();
        assert_eq!(c, Condition::OneOf(SelectorScope::Wildcard("sel".into())));
    }

    #[test]
    fn all_of_wildcard() {
        let c = parse_condition("all of sel*").unwrap();
        assert_eq!(c, Condition::AllOf(SelectorScope::Wildcard("sel".into())));
    }

    #[test]
    fn one_of_them() {
        let c = parse_condition("1 of them").unwrap();
        assert_eq!(c, Condition::OneOf(SelectorScope::All));
    }

    #[test]
    fn all_of_them() {
        let c = parse_condition("all of them").unwrap();
        assert_eq!(c, Condition::AllOf(SelectorScope::All));
    }

    // ===== 未対応構文の検出 =====

    #[test]
    fn aggregation_rejected() {
        assert!(parse_condition("selection | count() > 5").is_err());
        assert!(parse_condition("count() by Field > 1").is_err());
    }

    #[test]
    fn near_rejected() {
        assert!(parse_condition("sel1 near sel2").is_err());
    }

    #[test]
    fn placeholder_rejected() {
        assert!(parse_condition("selection and %var%").is_err());
    }

    #[test]
    fn numeric_other_than_one_rejected() {
        // `2 of sel*` は数字 2 が来るため、unsupported または syntax error
        assert!(parse_condition("2 of sel*").is_err());
    }

    #[test]
    fn case_insensitive_keywords() {
        let c = parse_condition("sel1 AND sel2").unwrap();
        assert_eq!(
            c,
            Condition::And(
                Box::new(Condition::Selector("sel1".into())),
                Box::new(Condition::Selector("sel2".into()))
            )
        );
    }
}
