//! Sigma・Correlation Rule 用の最小 YAML subset parser（規範 §14・Schema §7）。
//!
//! ## 目的
//!
//! Phase 5 共通編（T5-001〜T5-003）が読み込んだ raw bytes を YAML として parse し、
//! 決定的かつ安全な [`YamlValue`] tree へ変換する。Sigma subset evaluator
//! （T5-010〜T5-017）と Correlation Rule parser（T5-030〜T5-031）の両方で利用する。
//!
//! ## 対応範囲
//!
//! Sigma Rule・Correlation Rule で必要な YAML subset のみを扱う:
//! - block mapping（`key: value`）
//! - block sequence（`- item`）
//! - flow mapping（`{key: value}`）
//! - flow sequence（`[a, b, c]`）
//! - plain scalar・single-quoted・double-quoted string
//! - integer・boolean・null の型推論
//! - 行末 comment（`# ...`）
//!
//! ## 禁止要素（検出次第 error）
//!
//! 規範 §14・Schema §7 が YAML anchor・alias・custom tag・duplicate key を禁止する:
//! - `&anchor`・`*alias`・`!tag`・`%directive`（error）
//! - multi-document marker（`---`・`...`）（error）
//! - block scalar（`|`・`>`）（error・未対応）
//! - mapping の duplicate key（error）
//! - tab 文字の indentation（error）
//!
//! ## 安全性
//!
//! 破損入力・不正 YAML で panic しない。全ての error は [`YamlError`] として返す。

pub mod parser;

use std::collections::BTreeMap;

pub use parser::parse;

/// YAML scalar・mapping・sequence を表す汎用値（決定性のため Map は `Vec` で保持）。
///
/// `Map` の内部表現に `Vec<(String, YamlValue)>` を用いる理由:
/// 1. Sigma `detection:` block での key 出現順を維持するため
/// 2. duplicate key を構築時に検出するため
/// 3. `BTreeMap` の上書きで duplicate が暗黙に失われるのを防ぐため
#[derive(Clone, Debug, PartialEq)]
pub enum YamlValue {
    /// YAML `null`・`~`・空値。
    Null,
    /// YAML `true` / `false`。
    Bool(bool),
    /// YAML 整数（小数は未対応・Sigma subset では不要）。
    Int(i64),
    /// YAML 文字列（plain・single-quoted・double-quoted の何れか）。
    Str(String),
    /// YAML sequence（block style `- item` または flow style `[a, b]`）。
    Seq(Vec<YamlValue>),
    /// YAML mapping（`Vec` で挿入順を保持・duplicate なし保証済み）。
    Map(Vec<(String, YamlValue)>),
}

impl YamlValue {
    /// `Map` として参照する。`Map` でなければ `None`。
    pub fn as_map(&self) -> Option<&Vec<(String, YamlValue)>> {
        match self {
            YamlValue::Map(m) => Some(m),
            _ => None,
        }
    }

    /// `Seq` として参照する。`Seq` でなければ `None`。
    pub fn as_seq(&self) -> Option<&Vec<YamlValue>> {
        match self {
            YamlValue::Seq(s) => Some(s),
            _ => None,
        }
    }

    /// `Str` として参照する。`Str` でなければ `None`。
    pub fn as_str(&self) -> Option<&str> {
        match self {
            YamlValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// `Int` として参照する。
    pub fn as_int(&self) -> Option<i64> {
        match self {
            YamlValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// `Bool` として参照する。
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            YamlValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// `Null` か。
    pub fn is_null(&self) -> bool {
        matches!(self, YamlValue::Null)
    }

    /// `Map` の指定 key へ参照する。
    pub fn get(&self, key: &str) -> Option<&YamlValue> {
        match self {
            YamlValue::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// 文字列値へ変換する（`Str`・`Int`・`Bool` を文字列化、`Null`/`Seq`/`Map` は `None`）。
    pub fn to_string_value(&self) -> Option<String> {
        match self {
            YamlValue::Str(s) => Some(s.clone()),
            YamlValue::Int(n) => Some(n.to_string()),
            YamlValue::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// 文字列の list へ変換する（scalar は1要素 list・seq は各要素を文字列化）。
    /// `Null` は空 list。
    pub fn to_string_list(&self) -> Option<Vec<String>> {
        match self {
            YamlValue::Null => Some(Vec::new()),
            YamlValue::Str(s) => Some(vec![s.clone()]),
            YamlValue::Int(n) => Some(vec![n.to_string()]),
            YamlValue::Bool(b) => Some(vec![b.to_string()]),
            YamlValue::Seq(items) => {
                let mut result = Vec::with_capacity(items.len());
                for item in items {
                    result.push(item.to_string_value()?);
                }
                Some(result)
            }
            YamlValue::Map(_) => None,
        }
    }

    /// `Map` を `BTreeMap` へ変換する（決定的順序・canonical JSON 用）。
    pub fn to_btremap(&self) -> Option<BTreeMap<String, YamlValue>> {
        match self {
            YamlValue::Map(m) => Some(m.iter().cloned().collect()),
            _ => None,
        }
    }
}

/// YAML parse error（規範 §14・Schema §7 の安全性要件）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum YamlError {
    /// YAML 構文 error（不正 indentation・未対応 block scalar 等）。
    #[error("YAML parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },

    /// YAML anchor は禁止（規範 §14・Schema §7）。
    #[error("YAML anchor is forbidden at line {line} (規範 §14・Schema §7)")]
    Anchor { line: usize },

    /// YAML alias は禁止（規範 §14・Schema §7）。
    #[error("YAML alias is forbidden at line {line} (規範 §14・Schema §7)")]
    Alias { line: usize },

    /// YAML tag は禁止（規範 §14・Schema §7）。
    #[error("YAML tag is forbidden at line {line} (規範 §14・Schema §7)")]
    Tag { line: usize },

    /// YAML directive（`%YAML` 等）は禁止。
    #[error("YAML directive is forbidden at line {line}")]
    Directive { line: usize },

    /// duplicate key は禁止（Schema §7: 後勝ち上書きせず error）。
    #[error("YAML duplicate key '{key}' at line {line} (Schema §7)")]
    DuplicateKey { line: usize, key: String },

    /// multi-document marker（`---`・`...`）は未対応。
    #[error("YAML multi-document marker at line {line} is not supported")]
    MultiDocument { line: usize },

    /// block scalar（`|`・`>`）は未対応。
    #[error("YAML block scalar ('|' or '>') at line {line} is not supported")]
    BlockScalar { line: usize },
}

#[cfg(test)]
mod tests;
