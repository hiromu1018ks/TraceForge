//! YAML subset parser の unit test。

use super::*;

#[test]
fn empty_input_returns_null() {
    assert_eq!(parse("").unwrap(), YamlValue::Null);
}

#[test]
fn simple_string() {
    assert_eq!(parse("hello").unwrap(), YamlValue::Str("hello".into()));
}

#[test]
fn integer() {
    assert_eq!(parse("42").unwrap(), YamlValue::Int(42));
    assert_eq!(parse("-7").unwrap(), YamlValue::Int(-7));
}

#[test]
fn boolean() {
    assert_eq!(parse("true").unwrap(), YamlValue::Bool(true));
    assert_eq!(parse("false").unwrap(), YamlValue::Bool(false));
}

#[test]
fn null_variants() {
    assert_eq!(parse("null").unwrap(), YamlValue::Null);
    assert_eq!(parse("~").unwrap(), YamlValue::Null);
    assert_eq!(parse("Null").unwrap(), YamlValue::Null);
    assert_eq!(parse("NULL").unwrap(), YamlValue::Null);
}

#[test]
fn simple_mapping() {
    let v = parse("a: 1\nb: 2\n").unwrap();
    let m = v.as_map().unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0], ("a".into(), YamlValue::Int(1)));
    assert_eq!(m[1], ("b".into(), YamlValue::Int(2)));
}

#[test]
fn mapping_preserves_insertion_order() {
    let v = parse("z: 1\na: 2\nm: 3\n").unwrap();
    let m = v.as_map().unwrap();
    let keys: Vec<&str> = m.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["z", "a", "m"]);
}

#[test]
fn nested_mapping() {
    let v = parse("outer:\n  inner: value\n").unwrap();
    let inner = v.get("outer").unwrap();
    assert_eq!(inner.get("inner").unwrap(), &YamlValue::Str("value".into()));
}

#[test]
fn block_sequence() {
    let v = parse("- a\n- b\n- c\n").unwrap();
    let s = v.as_seq().unwrap();
    assert_eq!(s.len(), 3);
    assert_eq!(s[0], YamlValue::Str("a".into()));
    assert_eq!(s[2], YamlValue::Str("c".into()));
}

#[test]
fn sequence_of_mappings() {
    let yaml = "- key1: v1\n  key2: v2\n- key1: v3\n  key2: v4\n";
    let v = parse(yaml).unwrap();
    let s = v.as_seq().unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].get("key1").unwrap(), &YamlValue::Str("v1".into()));
    assert_eq!(s[1].get("key2").unwrap(), &YamlValue::Str("v4".into()));
}

#[test]
fn flow_sequence() {
    let v = parse("[a, b, c]").unwrap();
    let s = v.as_seq().unwrap();
    assert_eq!(s.len(), 3);
}

#[test]
fn flow_mapping() {
    let v = parse("{a: 1, b: 2}").unwrap();
    let m = v.as_map().unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0], ("a".into(), YamlValue::Int(1)));
}

#[test]
fn nested_flow() {
    let v = parse("{list: [1, 2], map: {x: y}}").unwrap();
    assert!(v.get("list").unwrap().as_seq().is_some());
    assert!(v.get("map").unwrap().as_map().is_some());
}

#[test]
fn single_quoted_string() {
    assert_eq!(
        parse("'hello world'").unwrap(),
        YamlValue::Str("hello world".into())
    );
    // '' escape
    assert_eq!(
        parse("'it''s ok'").unwrap(),
        YamlValue::Str("it's ok".into())
    );
}

#[test]
fn double_quoted_string() {
    assert_eq!(parse("\"hello\"").unwrap(), YamlValue::Str("hello".into()));
    // escape
    assert_eq!(
        parse("\"a\\tb\\nc\"").unwrap(),
        YamlValue::Str("a\tb\nc".into())
    );
    assert_eq!(parse("\"\\u0041\"").unwrap(), YamlValue::Str("A".into()));
}

#[test]
fn inline_comment_stripped() {
    let v = parse("key: value # comment\n").unwrap();
    assert_eq!(v.get("key").unwrap(), &YamlValue::Str("value".into()));
}

#[test]
fn url_value_not_split() {
    // URL の `:` は space が続かないため mapping key として誤検出されない
    let v = parse("url: http://example.com\n").unwrap();
    assert_eq!(
        v.get("url").unwrap(),
        &YamlValue::Str("http://example.com".into())
    );
}

#[test]
fn sigma_rule_basic() {
    let yaml = r#"
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: experimental
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#;
    let v = parse(yaml).unwrap();
    assert_eq!(v.get("title").unwrap(), &YamlValue::Str("Test Rule".into()));
    let ls = v.get("logsource").unwrap();
    assert_eq!(
        ls.get("product").unwrap(),
        &YamlValue::Str("windows".into())
    );
    let det = v.get("detection").unwrap();
    let sel = det.get("selection").unwrap();
    assert_eq!(sel.get("EventID").unwrap(), &YamlValue::Int(4624));
    assert_eq!(
        det.get("condition").unwrap(),
        &YamlValue::Str("selection".into())
    );
}

// ===== 禁止要素の検出 =====

#[test]
fn anchor_rejected() {
    let err = parse("key: &anchor value\n").unwrap_err();
    assert!(matches!(err, YamlError::Anchor { line: 1 }));
}

#[test]
fn alias_rejected() {
    let err = parse("key: *alias\n").unwrap_err();
    assert!(matches!(err, YamlError::Alias { line: 1 }));
}

#[test]
fn tag_rejected() {
    let err = parse("key: !tag value\n").unwrap_err();
    assert!(matches!(err, YamlError::Tag { line: 1 }));
}

#[test]
fn directive_rejected() {
    let err = parse("%YAML 1.2\n---\n").unwrap_err();
    assert!(matches!(err, YamlError::Directive { line: 1 }));
}

#[test]
fn multi_document_marker_rejected() {
    let err = parse("---\nkey: value\n").unwrap_err();
    assert!(matches!(err, YamlError::MultiDocument { line: 1 }));
    let err = parse("...\n").unwrap_err();
    assert!(matches!(err, YamlError::MultiDocument { line: 1 }));
}

#[test]
fn duplicate_key_rejected() {
    let err = parse("a: 1\na: 2\n").unwrap_err();
    assert!(matches!(err, YamlError::DuplicateKey { line: 2, key } if key == "a"));
}

#[test]
fn block_scalar_rejected() {
    let err = parse("key: |\n  value\n").unwrap_err();
    assert!(matches!(err, YamlError::BlockScalar { line: 1 }));
    let err = parse("key: >\n  value\n").unwrap_err();
    assert!(matches!(err, YamlError::BlockScalar { line: 1 }));
}

#[test]
fn tab_indentation_rejected() {
    let err = parse("key:\n\tvalue\n").unwrap_err();
    assert!(matches!(err, YamlError::ParseError { line: 2, .. }));
}

// ===== 侵入テスト: 破損入力で panic しない =====

#[test]
fn unterminated_flow_mapping() {
    assert!(parse("{a: 1").is_err());
}

#[test]
fn unterminated_flow_sequence() {
    assert!(parse("[a, b").is_err());
}

#[test]
fn unterminated_quoted_string() {
    assert!(parse("'unterminated").is_err());
    assert!(parse("\"unterminated").is_err());
}

#[test]
fn garbage_input_no_panic() {
    let _ = parse("}}}}");
    let _ = parse("::::");
    assert!(parse("----").is_err()); // multi-doc marker
    let _ = parse("- - - -");
}

#[test]
fn deeply_nested_no_panic() {
    let mut yaml = String::from("a:\n");
    for _ in 0..50 {
        yaml.push_str("b:\n  ");
    }
    yaml.push_str("c: value");
    let _ = parse(&yaml);
}
