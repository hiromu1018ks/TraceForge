//! 出力安全性の共通 helper（規範 §19）。
//!
//! 3 種の出力 injection 対策を提供する（規範 §21-11）:
//! - [`escape_control_chars`]: C0/C1 制御文字と ESC を可視 escape へ変換（規範 §19.1・Text 用）
//! - [`needs_csv_formula_sanitization`]: cell 先頭文字が formula 介入の危険があるか（規範 §19.2）
//! - [`sanitize_csv_cell`]: RFC 4180 準拠の quoting と formula injection 対策を同時適用
//! - [`html_text_escape`]: text node 用 escape（規範 §19.3・HTML 用）

/// C0/C1 制御文字と ESC（0x1B）を可視 escape 表現へ変換する（規範 §19.1）。
///
/// 端末制御を悪用した攻撃（terminal ESC injection）を防ぐため、Evidence 起源の文字列を
/// stdout / Text exporter へ出力する前に必ず適用する。次の文字を置換する:
/// - `0x00`..=`0x1F`（C0）: `^@`..`^_`（caret notation）。ただし LF（`0x0A`）と
///   CR（`0x0D`）は Text 出力ではそのまま残す（行構造を保持）。
/// - `0x1B`（ESC）: `^[`
/// - `0x7F`（DEL）: `^?`
/// - `0x80`..=`0x9F`（C1）: `\u<code>`（可視 Unicode escape）
///
/// 制御文字を取り除いて内容を変えることはしない。可視表現へ置き換えるだけ。
pub fn escape_control_chars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let u = c as u32;
        match c {
            '\n' | '\r' => out.push(c),
            '\x1B' => out.push_str("^["),
            '\x7F' => out.push_str("^?"),
            c if ('\x00'..='\x1F').contains(&c) => {
                let letter = (b'@' + (u as u8)) as char;
                out.push('^');
                out.push(letter);
            }
            _ if (0x80..=0x9F).contains(&u) => {
                out.push_str(&format!("\\u{u:04x}"));
            }
            _ => out.push(c),
        }
    }
    out
}

/// cell の最初の非空白文字が CSV formula injection の危険があるか（規範 §19.2）。
///
/// 危険文字: `=`, `+`, `-`, `@`, TAB（`\t`）, CR（`\r`）。
/// これらが先頭にある場合、単一 quote（`'`）を前置して formula 評価を無効化する。
pub fn needs_csv_formula_sanitization(cell: &str) -> bool {
    for c in cell.chars() {
        match c {
            // 空白（SPACE のみ）は読み飛ばす。規範 §19.2 は「最初の非空白文字」と規定。
            ' ' => continue,
            // TAB と CR は formula injection 経路になるため、空白扱いせず危険とする。
            '=' | '+' | '-' | '@' | '\t' | '\r' => return true,
            _ => return false,
        }
    }
    false
}

/// CSV cell へ RFC 4180 準拠の quoting を適用する（規範 §19.2・Schema 互換 §10）。
///
/// 次のいずれかの文字を含む場合は `"` で囲む:
/// - `,`（区切り文字）
/// - `"`（quote 文字・`""` へ重ねて escape）
/// - `\r` または `\n`（改行）
///
/// さらに formula injection 対策として、cell の最初の非空白文字が
/// `=`, `+`, `-`, `@`, TAB, CR のいずれかの場合、先頭へ `'` を1つ前置する。
///
/// 戻り値は1つの cell 表現。呼出側で `,` で連結して1行にする。
pub fn sanitize_csv_cell(cell: &str) -> String {
    let needs_quote = cell
        .chars()
        .any(|c| c == ',' || c == '"' || c == '\r' || c == '\n');
    let needs_formula_prefix = needs_csv_formula_sanitization(cell);

    let body: String = if needs_quote {
        let mut out = String::with_capacity(cell.len() + 2);
        for c in cell.chars() {
            match c {
                '"' => out.push_str("\"\""),
                _ => out.push(c),
            }
        }
        out
    } else {
        cell.to_string()
    };

    if needs_formula_prefix {
        // formula 評価を無効化するため、先頭へ単一 quote を前置する。
        // 既に quoting が必要な場合は quote の内側へ置く（Excel 等の挙動に合わせる）。
        if needs_quote {
            format!("\"'{body}\"")
        } else {
            format!("'{body}")
        }
    } else if needs_quote {
        format!("\"{body}\"")
    } else {
        body
    }
}

/// HTML text node 用の escape（規範 §19.3）。
///
/// 次の5文字を entity 参照へ置換する:
/// - `&` -> `&amp;`（最初に処理・他の `&` と衝突させない）
/// - `<` -> `&lt;`
/// - `>` -> `&gt;`
/// - `"` -> `&quot;`
/// - `'` -> `&#39;`
///
/// この関数を通した文字列は HTML text node へ安全に埋め込める。`innerHTML` 連結は
/// 引き続き禁止する（規範 §19.3）。
pub fn html_text_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// HTML の `attribute` 値へ安全に埋め込めるよう escape する。
///
/// [`html_text_escape`] に加え、改行・TAB も escape する（属性値へ改行が入ると
/// parser 挙動が環境依存になるのを防ぐ）。
pub fn html_attribute_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_control_chars_replaces_esc_and_c0() {
        // 規範 §19.1: 制御文字と ESC を可視 escape へ。
        let s = "a\x1Bb\x00c\x7Fd";
        let escaped = escape_control_chars(s);
        assert!(!escaped.contains('\x1B'));
        assert!(escaped.contains("^["));
        assert!(escaped.contains("^?"));
        // 制御文字は可視表現へ変換される。
        assert!(!escaped.contains('\x00'));
        assert!(!escaped.contains('\x7F'));
    }

    #[test]
    fn escape_control_chars_preserves_lf_cr() {
        let s = "line1\nline2\r\nline3";
        let escaped = escape_control_chars(s);
        assert_eq!(escaped, s);
    }

    #[test]
    fn escape_control_chars_replaces_c1() {
        // C1 制御文字（0x80..=0x9F）も \u<code> へ置換する。
        let s = "x\u{0080}y\u{009F}z";
        let escaped = escape_control_chars(s);
        assert!(escaped.contains("\\u0080"));
        assert!(escaped.contains("\\u009f"));
    }

    #[test]
    fn csv_formula_detection() {
        // 規範 §19.2: 先頭の = + - @ TAB CR を危険と判定する。
        assert!(needs_csv_formula_sanitization("=cmd|' /C calc'!A1"));
        assert!(needs_csv_formula_sanitization("+1234"));
        assert!(needs_csv_formula_sanitization("-1+2|3"));
        assert!(needs_csv_formula_sanitization("@SUM(A1)"));
        assert!(needs_csv_formula_sanitization("\tfoobar"));
        assert!(needs_csv_formula_sanitization("\rfoobar"));
        // 空白の後の危険文字も検出する。
        assert!(needs_csv_formula_sanitization("  =cmd"));
        assert!(!needs_csv_formula_sanitization("hello world"));
        assert!(!needs_csv_formula_sanitization(""));
        assert!(!needs_csv_formula_sanitization("   "));
        // マイナス記号でも数字だけのセルは前置しない（危険文字の直後でなければ）。
        // ただし `-1+2|3` のように演算子が続く場合は前置する。
    }

    #[test]
    fn csv_quote_when_comma_or_quote_or_newline() {
        // RFC 4180: , " \r \n を含む場合は quote する。
        assert_eq!(sanitize_csv_cell("hello"), "hello");
        assert_eq!(sanitize_csv_cell("a,b"), "\"a,b\"");
        assert_eq!(sanitize_csv_cell("a\"b"), "\"a\"\"b\"");
        assert_eq!(sanitize_csv_cell("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_formula_sanitization_adds_quote_prefix() {
        // 規範 §19.2: 先頭へ単一 quote を前置する。
        let cell = "=cmd|' /C calc'!A1";
        let sanitized = sanitize_csv_cell(cell);
        assert!(sanitized.starts_with("'") || sanitized.starts_with("\"'"));
        // 元の危険な式がそのまま残らないよう、' が前に付く。
        assert!(sanitized.contains("'=cmd"));
    }

    #[test]
    fn csv_formula_sanitization_with_quoted_cell() {
        // quoting 必要 + formula 危険: quote の内側へ ' を置く。
        let cell = "=SUM(A1,\"x\")";
        let sanitized = sanitize_csv_cell(cell);
        assert!(sanitized.starts_with("\"'="));
        assert!(sanitized.ends_with("\""));
    }

    #[test]
    fn html_text_escape_replaces_dangerous_chars() {
        // 規範 §19.3: & < > " ' を escape。
        let s = "<script>alert('xss')</script>";
        let escaped = html_text_escape(s);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(escaped.contains("&#39;"));
    }

    #[test]
    fn html_attribute_escape_replaces_whitespace() {
        let s = "a\nb\tc";
        let escaped = html_attribute_escape(s);
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\t'));
    }

    #[test]
    fn html_ampersand_first() {
        // `&` を先に処理しないと `&lt;` が `&amp;lt;` へ二重 escape される。
        let s = "<a&b>";
        let escaped = html_text_escape(s);
        assert_eq!(escaped, "&lt;a&amp;b&gt;");
    }
}
