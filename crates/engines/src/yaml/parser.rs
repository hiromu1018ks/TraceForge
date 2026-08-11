//! YAML subset parser の実装。
//!
//! アルゴリズム概要:
//! 1. 前処理で入力を行列へ分解し、禁止要素（anchor/alias/tag/multi-doc）を検出
//! 2. block parser で再帰降下により block mapping・block sequence・scalar を構築
//! 3. flow parser で flow mapping・flow sequence・quoted string を構築
//!
//! 決定性のため、mapping は挿入順を保持する `Vec<(String, YamlValue)>` で表現し、
//! duplicate key を構築時に検出する。

use super::{YamlError, YamlValue};

/// 前処理済みの1行（indent 量・内容・行番号）。
struct Line {
    indent: usize,
    content: String,
    line_no: usize,
}

/// raw YAML 文字列を [`YamlValue`] tree へ parse する。
///
/// 空入力は [`YamlValue::Null`] を返す（Sigma validation で別途拒否される）。
pub fn parse(input: &str) -> Result<YamlValue, YamlError> {
    let lines = preprocess(input)?;
    if lines.is_empty() {
        return Ok(YamlValue::Null);
    }

    let mut pos = 0;
    let base_indent = lines[0].indent;
    let value = parse_node(&lines, &mut pos, base_indent)?;

    // 余剰行がないか確認（indent の不整合等で取り残された行）。
    if pos < lines.len() {
        let line = &lines[pos];
        return Err(YamlError::ParseError {
            line: line.line_no,
            message: format!(
                "unexpected indentation at column {}: {:?}",
                line.indent + 1,
                &line.content[..line.content.len().min(40)]
            ),
        });
    }

    Ok(value)
}

// ============================================================================
// 前処理: raw text → Line 列
// ============================================================================

/// raw text を [`Line`] 列へ変換する。
///
/// - 空行・comment 行（`# ...`）を除外
/// - 禁止要素（anchor/alias/tag/directive/multi-doc/block scalar）を検出
/// - tab indentation を検出
/// - `- key: value` を2行へ分割し、後続行の virtual indent を整える
fn preprocess(input: &str) -> Result<Vec<Line>, YamlError> {
    let mut result = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let line_no = i + 1;

        // leading space を数える。tab は indentation へ使用不可。
        let mut indent = 0;
        let mut found_tab = false;
        for b in raw.bytes() {
            match b {
                b' ' => indent += 1,
                b'\t' => {
                    found_tab = true;
                    break;
                }
                _ => break,
            }
        }
        if found_tab {
            return Err(YamlError::ParseError {
                line: line_no,
                message: "tab character in indentation is not allowed".into(),
            });
        }

        let trimmed_start = &raw[indent..];
        let trimmed_end = trimmed_start.trim_end_matches([' ', '\t']);

        // 空行・comment 行を skip
        if trimmed_end.is_empty() {
            continue;
        }
        if trimmed_end.starts_with('#') {
            continue;
        }

        // 禁止要素の検出
        if trimmed_end.starts_with("---") {
            return Err(YamlError::MultiDocument { line: line_no });
        }
        if trimmed_end.starts_with("...") {
            return Err(YamlError::MultiDocument { line: line_no });
        }
        if trimmed_end.starts_with('&') {
            return Err(YamlError::Anchor { line: line_no });
        }
        if trimmed_end.starts_with('*') {
            return Err(YamlError::Alias { line: line_no });
        }
        if trimmed_end.starts_with('!') {
            return Err(YamlError::Tag { line: line_no });
        }
        if trimmed_end.starts_with('%') {
            return Err(YamlError::Directive { line: line_no });
        }

        // block scalar marker（`key: |` や `key: >`）を検出
        if is_block_scalar_line(trimmed_end) {
            return Err(YamlError::BlockScalar { line: line_no });
        }

        // mapping value や sequence item 内の anchor/alias/tag を検出
        check_forbidden_in_value(trimmed_end, line_no)?;

        let content = trimmed_end.to_string();

        // `- key: value` を2行へ分割:
        //   (1) indent, content = "-"
        //   (2) virtual_indent, content = "key: value"
        // これにより block sequence parser が後続行を mapping として扱える。
        if content.starts_with('-') && content.len() > 1 {
            let after_dash = &content[1..];
            if after_dash.starts_with(' ') {
                let rest_trimmed = after_dash.trim_start();
                let dash_spaces = after_dash.len() - rest_trimmed.len();
                if !rest_trimmed.is_empty() && split_key_value(rest_trimmed).is_some() {
                    let virtual_indent = indent + 1 + dash_spaces;
                    result.push(Line {
                        indent,
                        content: "-".into(),
                        line_no,
                    });
                    result.push(Line {
                        indent: virtual_indent,
                        content: rest_trimmed.to_string(),
                        line_no,
                    });
                    continue;
                }
            }
        }

        result.push(Line {
            indent,
            content,
            line_no,
        });
    }

    Ok(result)
}

/// 行が block scalar（`key: |` または `key: >`）かを判定する。
fn is_block_scalar_line(s: &str) -> bool {
    if let Some((_, value)) = split_key_value(s) {
        let v = value.trim();
        if v == "|" || v == ">" {
            return true;
        }
        if v.starts_with('|') || v.starts_with('>') {
            let rest = &v[1..];
            if rest
                .chars()
                .all(|c| c.is_ascii_digit() || c == '+' || c == '-')
            {
                return true;
            }
        }
    }
    false
}

/// mapping value や sequence item 中の anchor（`&`）・alias（`*`）・tag（`!`）を検出する。
///
/// これらは YAML value の先頭（`key: ` の直後・`- ` の直後・flow node の先頭）に
/// 現れる。quote 内や URL 中の `&`・`*` は誤検出しないよう、value の最初の非空白文字
/// のみを検査する。
fn check_forbidden_in_value(line_content: &str, line_no: usize) -> Result<(), YamlError> {
    // mapping value の検査
    if let Some((_, value)) = split_key_value(line_content) {
        check_value_prefix(value.trim_start(), line_no)?;
    }

    // sequence item 値の検査（`- value` 形式）
    if line_content.starts_with("- ") {
        let after = line_content.strip_prefix("- ").unwrap().trim_start();
        // さらに mapping が inline で始まる場合は再帰的に検査
        if let Some((_, sub_value)) = split_key_value(after) {
            check_value_prefix(sub_value.trim_start(), line_no)?;
        } else {
            check_value_prefix(after, line_no)?;
        }
    }

    Ok(())
}

/// 値文字列の先頭が anchor/alias/tag か検査する。quote で囲まれた値は除外。
fn check_value_prefix(value: &str, line_no: usize) -> Result<(), YamlError> {
    if value.is_empty() {
        return Ok(());
    }
    // quote で始まる値は許可（文字列中の `&` 等は通常文字）
    if value.starts_with('\'') || value.starts_with('"') {
        return Ok(());
    }
    // flow collection 内の先頭要素も許可
    if value.starts_with('{') || value.starts_with('[') {
        // flow 内の各要素を簡易検査（最初の `&`/`*`/`!` を探す）
        return check_flow_forbidden(value, line_no);
    }
    match value.as_bytes()[0] {
        b'&' => Err(YamlError::Anchor { line: line_no }),
        b'*' => Err(YamlError::Alias { line: line_no }),
        b'!' => Err(YamlError::Tag { line: line_no }),
        _ => Ok(()),
    }
}

/// flow collection 文字列内の anchor/alias/tag を簡易検査する。
fn check_flow_forbidden(s: &str, line_no: usize) -> Result<(), YamlError> {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_delim = true; // 直前が区切り文字（`,`・`{`・`[`・`:`・space）か

    for &b in bytes.iter() {
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            prev_delim = false;
            continue;
        }
        if in_double {
            if b == b'\\' {
                // skip next
            }
            if b == b'"' {
                in_double = false;
            }
            prev_delim = false;
            continue;
        }
        match b {
            b'\'' => {
                in_single = true;
                prev_delim = false;
            }
            b'"' => {
                in_double = true;
                prev_delim = false;
            }
            b' ' | b'\t' | b',' | b'{' | b'[' | b':' => {
                prev_delim = true;
            }
            b'&' if prev_delim => {
                return Err(YamlError::Anchor { line: line_no });
            }
            b'*' if prev_delim => {
                return Err(YamlError::Alias { line: line_no });
            }
            b'!' if prev_delim => {
                return Err(YamlError::Tag { line: line_no });
            }
            _ => {
                prev_delim = false;
            }
        }
    }
    Ok(())
}

// ============================================================================
// block parser: 再帰降下
// ============================================================================

/// 指定 indent から開始する node を1つ parse する。
fn parse_node(lines: &[Line], pos: &mut usize, indent: usize) -> Result<YamlValue, YamlError> {
    if *pos >= lines.len() {
        return Ok(YamlValue::Null);
    }

    let line = &lines[*pos];
    if line.indent != indent {
        return Ok(YamlValue::Null);
    }

    // flow collection（`{...}` / `[...]`）は mapping 判定より優先する。
    // `{a: 1, b: 2}` のような flow mapping が `key: value` と誤検出されるのを防ぐ。
    if line.content.starts_with('{') || line.content.starts_with('[') {
        let value = parse_flow_value(&line.content, line.line_no)?;
        *pos += 1;
        return Ok(value);
    }

    // sequence item（`-` で始まる）
    if line.content == "-" || line.content.starts_with("- ") {
        return parse_block_sequence(lines, pos, indent);
    }

    // mapping entry（`key: value` パターン）
    if split_key_value(&line.content).is_some() {
        return parse_block_mapping(lines, pos, indent);
    }

    // scalar（1行のみ）
    let value = parse_flow_value(&line.content, line.line_no)?;
    *pos += 1;
    Ok(value)
}

/// block mapping（`key: value` の繰り返し）を parse する。
fn parse_block_mapping(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
) -> Result<YamlValue, YamlError> {
    let mut entries: Vec<(String, YamlValue)> = Vec::new();

    while *pos < lines.len() {
        let line = &lines[*pos];

        if line.indent != indent {
            break;
        }
        if line.content == "-" || line.content.starts_with("- ") {
            break;
        }

        let (key, inline_value) = match split_key_value(&line.content) {
            Some(kv) => kv,
            None => break,
        };

        let current_line_no = line.line_no;

        // duplicate key 検出（Schema §7）
        if entries.iter().any(|(k, _)| k == &key) {
            return Err(YamlError::DuplicateKey {
                line: current_line_no,
                key,
            });
        }

        *pos += 1;

        let value = if inline_value.trim().is_empty() {
            // 値は次行以降（より深い indent）
            if *pos < lines.len() && lines[*pos].indent > indent {
                let child_indent = lines[*pos].indent;
                parse_node(lines, pos, child_indent)?
            } else {
                YamlValue::Null
            }
        } else {
            parse_flow_value(&inline_value, current_line_no)?
        };

        entries.push((key, value));
    }

    Ok(YamlValue::Map(entries))
}

/// block sequence（`- item` の繰り返し）を parse する。
fn parse_block_sequence(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
) -> Result<YamlValue, YamlError> {
    let mut items = Vec::new();

    while *pos < lines.len() {
        let line = &lines[*pos];

        if line.indent != indent {
            break;
        }
        if line.content != "-" && !line.content.starts_with("- ") {
            break;
        }

        let current_line_no = line.line_no;

        if line.content == "-" {
            // 値は次行以降
            *pos += 1;
            if *pos < lines.len() && lines[*pos].indent > indent {
                let child_indent = lines[*pos].indent;
                let value = parse_node(lines, pos, child_indent)?;
                items.push(value);
            } else {
                items.push(YamlValue::Null);
            }
        } else {
            // `- value` の形式（前処理で `key:` は2行分割済みのため、
            // ここは scalar・flow・quoted のみ）
            let after_dash = &line.content[1..];
            let rest = after_dash.trim_start();
            *pos += 1;
            let value = parse_flow_value(rest, current_line_no)?;
            items.push(value);
        }
    }

    Ok(YamlValue::Seq(items))
}

// ============================================================================
// flow / scalar parser
// ============================================================================

/// inline 値（scalar・flow collection・quoted string）を parse する。
///
/// 入力 `s` の先頭から値を1つ parse する。行末 comment は strip 済みの前提。
fn parse_flow_value(s: &str, line_no: usize) -> Result<YamlValue, YamlError> {
    let s = strip_trailing_comment(s).trim();
    if s.is_empty() {
        return Ok(YamlValue::Null);
    }

    match s.as_bytes()[0] {
        b'{' => {
            let (value, rest) = parse_flow_mapping(s, line_no)?;
            let rest = strip_trailing_comment(rest).trim();
            if !rest.is_empty() {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: format!("unexpected content after flow mapping: {rest:?}"),
                });
            }
            Ok(value)
        }
        b'[' => {
            let (value, rest) = parse_flow_sequence(s, line_no)?;
            let rest = strip_trailing_comment(rest).trim();
            if !rest.is_empty() {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: format!("unexpected content after flow sequence: {rest:?}"),
                });
            }
            Ok(value)
        }
        b'\'' => {
            let (s2, rest) = consume_single_quoted(s, line_no)?;
            let rest = strip_trailing_comment(rest).trim();
            if !rest.is_empty() {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: format!("unexpected content after quoted string: {rest:?}"),
                });
            }
            Ok(YamlValue::Str(s2))
        }
        b'"' => {
            let (s2, rest) = consume_double_quoted(s, line_no)?;
            let rest = strip_trailing_comment(rest).trim();
            if !rest.is_empty() {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: format!("unexpected content after quoted string: {rest:?}"),
                });
            }
            Ok(YamlValue::Str(s2))
        }
        _ => Ok(parse_plain_scalar(s)),
    }
}

/// flow mapping `{key: value, ...}` を parse し、(value, 残り文字列) を返す。
fn parse_flow_mapping(s: &str, line_no: usize) -> Result<(YamlValue, &str), YamlError> {
    let s = s.trim_start();
    let rest = s.strip_prefix('{').ok_or(YamlError::ParseError {
        line: line_no,
        message: "expected '{'".into(),
    })?;

    let mut entries = Vec::new();
    let mut rest = rest.trim_start();

    if let Some(after) = rest.strip_prefix('}') {
        return Ok((YamlValue::Map(entries), after));
    }

    loop {
        // key を parse
        let (key, after_key) = parse_flow_token(rest, line_no)?;
        rest = after_key.trim_start();

        // `:` で key と value を区切る
        if rest.starts_with(':') {
            rest = rest[1..].trim_start();
        }

        // value を parse
        let (value, after_value) = parse_flow_node(rest, line_no)?;
        rest = after_value.trim_start();

        // duplicate key 検出
        if entries.iter().any(|(k, _)| k == &key) {
            return Err(YamlError::DuplicateKey { line: line_no, key });
        }
        entries.push((key, value));

        match rest.chars().next() {
            Some(',') => {
                rest = rest[1..].trim_start();
                if rest.starts_with('}') {
                    rest = &rest[1..];
                    break;
                }
            }
            Some('}') => {
                rest = &rest[1..];
                break;
            }
            Some(c) => {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: format!("expected ',' or '}}' in flow mapping, got {c:?}"),
                });
            }
            None => {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: "unterminated flow mapping".into(),
                });
            }
        }
    }

    Ok((YamlValue::Map(entries), rest))
}

/// flow sequence `[item, ...]` を parse し、(value, 残り文字列) を返す。
fn parse_flow_sequence(s: &str, line_no: usize) -> Result<(YamlValue, &str), YamlError> {
    let s = s.trim_start();
    let rest = s.strip_prefix('[').ok_or(YamlError::ParseError {
        line: line_no,
        message: "expected '['".into(),
    })?;

    let mut items = Vec::new();
    let mut rest = rest.trim_start();

    if let Some(after) = rest.strip_prefix(']') {
        return Ok((YamlValue::Seq(items), after));
    }

    loop {
        let (value, after_value) = parse_flow_node(rest, line_no)?;
        rest = after_value.trim_start();
        items.push(value);

        match rest.chars().next() {
            Some(',') => {
                rest = rest[1..].trim_start();
                if rest.starts_with(']') {
                    rest = &rest[1..];
                    break;
                }
            }
            Some(']') => {
                rest = &rest[1..];
                break;
            }
            Some(c) => {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: format!("expected ',' or ']' in flow sequence, got {c:?}"),
                });
            }
            None => {
                return Err(YamlError::ParseError {
                    line: line_no,
                    message: "unterminated flow sequence".into(),
                });
            }
        }
    }

    Ok((YamlValue::Seq(items), rest))
}

/// flow collection 内の1 node を parse し、(value, 残り文字列) を返す。
fn parse_flow_node(s: &str, line_no: usize) -> Result<(YamlValue, &str), YamlError> {
    let s = s.trim_start();
    match s.chars().next() {
        Some('{') => parse_flow_mapping(s, line_no),
        Some('[') => parse_flow_sequence(s, line_no),
        Some('\'') => {
            let (val, rest) = consume_single_quoted(s, line_no)?;
            Ok((YamlValue::Str(val), rest))
        }
        Some('"') => {
            let (val, rest) = consume_double_quoted(s, line_no)?;
            Ok((YamlValue::Str(val), rest))
        }
        _ => {
            let (scalar, rest) = consume_plain_flow(s);
            Ok((parse_plain_scalar(scalar), rest))
        }
    }
}

/// flow collection 内の token（key 等）を parse し、(token, 残り文字列) を返す。
fn parse_flow_token(s: &str, line_no: usize) -> Result<(String, &str), YamlError> {
    let s = s.trim_start();
    match s.chars().next() {
        Some('\'') => {
            let (val, rest) = consume_single_quoted(s, line_no)?;
            Ok((val, rest))
        }
        Some('"') => {
            let (val, rest) = consume_double_quoted(s, line_no)?;
            Ok((val, rest))
        }
        _ => {
            let (scalar, rest) = consume_plain_flow(s);
            Ok((scalar.trim().to_string(), rest))
        }
    }
}

/// plain scalar を `,`・`}`・`]`・`: `（colon + space/EOL）まで読み取る。
///
/// 引用符は YAML では scalar 先頭でのみ意味を持つため、plain scalar 中の引用符は
/// 通常文字として扱う（`parse_flow_node` が引用符付き scalar を別経路で処理する）。
fn consume_plain_flow(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b',' | b'}' | b']' => break,
            b':' => {
                let next = bytes.get(i + 1).copied();
                if next.is_none() || next == Some(b' ') || next == Some(b'\t') {
                    break;
                }
            }
            b'#' if i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') => break,
            _ => {}
        }
        i += 1;
    }
    let consumed = s[..i].trim_end();
    (&s[..consumed.len()], &s[i..])
}

/// single-quoted string を消費し、(中身, 残り文字列) を返す。
fn consume_single_quoted(s: &str, line_no: usize) -> Result<(String, &str), YamlError> {
    let rest = s.strip_prefix('\'').ok_or(YamlError::ParseError {
        line: line_no,
        message: "expected single quote".into(),
    })?;

    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut result = String::new();

    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                result.push('\'');
                i += 2;
                continue;
            }
            return Ok((result, &rest[i + 1..]));
        }
        // UTF-8 境界に注意して push
        let ch = rest[i..].chars().next().unwrap();
        result.push(ch);
        i += ch.len_utf8();
    }

    Err(YamlError::ParseError {
        line: line_no,
        message: "unterminated single-quoted string".into(),
    })
}

/// double-quoted string を消費し、(unescape 済み中身, 残り文字列) を返す。
fn consume_double_quoted(s: &str, line_no: usize) -> Result<(String, &str), YamlError> {
    let rest = s.strip_prefix('"').ok_or(YamlError::ParseError {
        line: line_no,
        message: "expected double quote".into(),
    })?;

    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut raw = String::new();

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // escape sequence: `\` と次の文字をそのまま記録
            raw.push('\\');
            raw.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            let unescaped = unescape_double_quoted(&raw)?;
            return Ok((unescaped, &rest[i + 1..]));
        }
        // UTF-8 境界に注意
        let ch = rest[i..].chars().next().unwrap();
        raw.push(ch);
        i += ch.len_utf8();
    }

    Err(YamlError::ParseError {
        line: line_no,
        message: "unterminated double-quoted string".into(),
    })
}

/// double-quoted string の escape sequence を展開する。
fn unescape_double_quoted(s: &str) -> Result<String, YamlError> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            result.push(c);
            continue;
        }
        match chars.next() {
            None => {
                return Err(YamlError::ParseError {
                    line: 0,
                    message: "trailing backslash in double-quoted string".into(),
                });
            }
            Some('n') => result.push('\n'),
            Some('t') => result.push('\t'),
            Some('r') => result.push('\r'),
            Some('\\') => result.push('\\'),
            Some('"') => result.push('"'),
            Some('\'') => result.push('\''),
            Some('0') => result.push('\0'),
            Some('a') => result.push('\u{07}'),
            Some('b') => result.push('\u{08}'),
            Some('f') => result.push('\u{0C}'),
            Some('v') => result.push('\u{0B}'),
            Some('/') => result.push('/'),
            Some(' ') => result.push(' '),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                let n = u32::from_str_radix(&hex, 16).map_err(|_| YamlError::ParseError {
                    line: 0,
                    message: format!("invalid \\x escape: \\x{hex}"),
                })?;
                if let Some(ch) = char::from_u32(n) {
                    result.push(ch);
                } else {
                    return Err(YamlError::ParseError {
                        line: 0,
                        message: format!("invalid Unicode codepoint from \\x{hex}"),
                    });
                }
            }
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let n = u32::from_str_radix(&hex, 16).map_err(|_| YamlError::ParseError {
                    line: 0,
                    message: format!("invalid \\u escape: \\u{hex}"),
                })?;
                if let Some(ch) = char::from_u32(n) {
                    result.push(ch);
                } else {
                    return Err(YamlError::ParseError {
                        line: 0,
                        message: format!("invalid Unicode codepoint from \\u{hex}"),
                    });
                }
            }
            Some(other) => result.push(other),
        }
    }
    Ok(result)
}

/// plain scalar を型推論して [`YamlValue`] へ変換する。
fn parse_plain_scalar(s: &str) -> YamlValue {
    let s = s.trim();
    if s.is_empty() || s == "~" || s.eq_ignore_ascii_case("null") {
        return YamlValue::Null;
    }
    if s == "true" || s == "True" || s == "TRUE" {
        return YamlValue::Bool(true);
    }
    if s == "false" || s == "False" || s == "FALSE" {
        return YamlValue::Bool(false);
    }
    if let Ok(n) = s.parse::<i64>() {
        return YamlValue::Int(n);
    }
    // 8進数表現 `0o...`
    if s.len() > 2
        && s.starts_with("0o")
        && let Ok(n) = i64::from_str_radix(&s[2..], 8)
    {
        return YamlValue::Int(n);
    }
    YamlValue::Str(s.to_string())
}

/// 行末の comment（`# ...`）を取り除く。quote 内の `#` は保持する。
fn strip_trailing_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev = b' ';

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double && (prev == b' ' || prev == b'\t') => {
                return s[..i].trim_end();
            }
            _ => {}
        }
        prev = b;
    }
    s.trim_end()
}

/// `key: value` 行から (key, inline_value) を抽出する。
///
/// `key` は plain・single-quoted・double-quoted の何れか。
/// `:` の後に space または EOL がある場合のみ key-value とみなす
/// （URL 中の `:` を誤検出しない）。
fn split_key_value(s: &str) -> Option<(String, String)> {
    let s = s.trim_end();
    if s.is_empty() {
        return None;
    }

    // `{...}` / `[...]` で始まる行は flow collection であり mapping key ではない。
    if s.starts_with('{') || s.starts_with('[') {
        return None;
    }

    // single-quoted key
    if s.starts_with('\'') {
        let (key, rest) = split_quoted_key(s, '\'')?;
        return finalize_split(key, rest);
    }

    // double-quoted key
    if s.starts_with('"') {
        let (key, rest) = split_quoted_key(s, '"')?;
        return finalize_split(key, rest);
    }

    // plain key: `:` (space or EOL) を探す
    for (i, c) in s.char_indices() {
        if c == ':' {
            let after = &s[i + 1..];
            if after.is_empty() || after.starts_with(' ') || after.starts_with('\t') {
                let key = s[..i].trim().to_string();
                if key.is_empty() || key.starts_with('-') {
                    return None;
                }
                let value = after.trim_start().to_string();
                return Some((key, value));
            }
        }
    }

    None
}

/// quoted key の分割ヘルパー。`(unescape 済み key, 残り文字列)` を返す。
fn split_quoted_key(s: &str, quote: char) -> Option<(String, &str)> {
    let bytes = s.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == quote as u8 {
            if quote == '\'' && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            if quote == '"' && i > 0 && bytes[i - 1] == b'\\' {
                // escape された quote
                i += 1;
                continue;
            }
            let key = &s[1..i];
            let rest = &s[i + 1..];
            let key_str = match quote {
                '\'' => key.replace("''", "'"),
                '"' => unescape_double_quoted(key).ok()?,
                _ => return None,
            };
            return Some((key_str, rest));
        }
        i += 1;
    }
    None
}

/// split_key_value の終了処理（rest から `:` を確認して value を抽出）。
fn finalize_split(key: String, rest: &str) -> Option<(String, String)> {
    let rest = rest.trim_start();
    if let Some(after) = rest.strip_prefix(':')
        && (after.is_empty() || after.starts_with(' ') || after.starts_with('\t'))
    {
        return Some((key, after.trim_start().to_string()));
    }
    None
}
