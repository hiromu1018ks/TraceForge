//! ATT&CK mapping 生成（T6-008・T6-009・規範 §15.3）。
//!
//! 規範 §15.3 は「ATT&CK mapping は Correlation Rule・Sigma tag・built-in mapping・
//! manual mapping からのみ生成する」と定める。本モジュールは4経路の helper 関数を提供する。
//!
//! ## 4経路
//!
//! 1. **Rule**: Correlation Rule の `mitre_attack` field。[`from_correlation_rule`]
//! 2. **Sigma tag**: Sigma Rule の `tags` 内 `attack.tXXXX` 形式。[`from_sigma_rule_tags`]
//! 3. **Built-in**: TraceForge が組み込みで持つ既定 mapping。[`built_in_mappings`]
//! 4. **Manual**: ユーザーが明示的に指定。[`manual_mapping`]
//!
//! 各 mapping は [`tf_core::finding::AttackMappingSource`] で生成元を明示し、
//! dataset 由来の場合は version と SHA-256 を添える（T6-009）。
//!
//! ## 禁止事項（規範 §15.3）
//!
//! - 自動推測による mapping 生成（Rule が無いのに Event 内容から technique を推定等）
//! - 外部サービスへの問合せ（規範 §2）
//! - 自由記述名称の正本採用（互換 §9: 名称は dataset から解決する）

use tf_core::finding::{AttackMapping, AttackMappingSource};

use crate::attack::dataset::AttackDataset;
use crate::attack::technique::{TechniqueInfo, validate_technique_id_format};

/// Correlation Rule の `mitre_attack` field から mapping を生成する（T6-008・source=Rule）。
///
/// Correlation Rule は Schema §7 で `mitre_attack: [T1059.001, ...]` を宣言できる。
/// 本関数は各 Technique ID を dataset へ照合し、名称・tactic を解決した mapping を返す。
///
/// 不在 ID があれば [`crate::attack::technique::UnknownTechniqueError`] を返す（T6-007）。
/// dataset 無し（`None`）の場合は ID と source だけの mapping を返す（名称解決無し）。
pub fn from_correlation_rule(
    rule_id: &str,
    mitre_attack_ids: &[String],
    dataset: Option<&AttackDataset>,
) -> Result<Vec<AttackMapping>, crate::attack::technique::UnknownTechniqueError> {
    // 形式検証を先に。
    let mut sorted: Vec<&String> = mitre_attack_ids.iter().collect();
    sorted.sort();
    for id in &sorted {
        validate_technique_id_format(id)?;
    }

    let mut mappings: Vec<AttackMapping> = Vec::with_capacity(mitre_attack_ids.len());
    for id in &sorted {
        let (technique_name, tactic, dataset_version, dataset_sha) = match dataset {
            Some(ds) => {
                // dataset 存在検証（T6-007）。
                if !ds.contains_technique(id) {
                    return Err(
                        crate::attack::technique::UnknownTechniqueError::NotInDataset {
                            id: id.to_string(),
                            version: ds.manifest.version.clone(),
                        },
                    );
                }
                let info: &TechniqueInfo = ds.lookup_technique(id).unwrap();
                (
                    Some(info.name.clone()),
                    info.tactic.clone(),
                    Some(ds.manifest.version.clone()),
                    Some(ds.manifest.sha256.clone()),
                )
            }
            None => (None, None, None, None),
        };
        mappings.push(AttackMapping {
            technique_id: id.to_string(),
            technique_name,
            tactic,
            source: AttackMappingSource::Rule,
            dataset_version,
            dataset_sha256: dataset_sha,
        });
    }
    // 呼出側へ渡す元の rule_id は attach 時の traceability 用（mapping 自体へは持たない）。
    let _ = rule_id;
    Ok(mappings)
}

/// Sigma Rule tags から `attack.tXXXX` 形式の technique を抽出する（T6-008・source=SigmaTag）。
///
/// Sigma は `tags:` へ `attack.execution`・`attack.t1059`・`attack.t1059.001` 等を
/// 列挙できる。本関数はその内 `attack.t<数字>` 形式のものだけを取り出す。
/// `attack.execution` 等、tactic 名の tag は無視する（technique ID ではないため）。
pub fn extract_attack_tags_from_sigma(tags: &[String]) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for tag in tags {
        let lower = tag.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("attack.") {
            // attack.tXXXX or attack.tXXXX.YYY 形式のみ。
            // 大文字小文字は Sigma 仕様上一定しないが、technique ID は大文字へ正規化する。
            if let Some(normalized) = normalize_technique_tag(rest) {
                result.push(normalized);
            }
        }
    }
    result.sort();
    result.dedup();
    result
}

/// `t1059` / `t1059.001` 形式の文字列を `T1059` / `T1059.001` へ正規化する。
/// 形式が合わなければ `None`。
fn normalize_technique_tag(s: &str) -> Option<String> {
    // 先頭は 't' または 'T'。
    let first = s.chars().next()?;
    if first != 't' && first != 'T' {
        return None;
    }
    let normalized = format!("T{}", &s[1..]);
    if validate_technique_id_format(&normalized).is_ok() {
        Some(normalized)
    } else {
        None
    }
}

/// Sigma Rule tags から ATT&CK mapping を生成する（T6-008・source=SigmaTag）。
///
/// [`extract_attack_tags_from_sigma`] で抽出した Technique ID を dataset へ照合する。
/// dataset が `None` の場合は ID だけの mapping を返す。
pub fn from_sigma_rule_tags(
    tags: &[String],
    dataset: Option<&AttackDataset>,
) -> Result<Vec<AttackMapping>, crate::attack::technique::UnknownTechniqueError> {
    let technique_ids = extract_attack_tags_from_sigma(tags);
    // 形式検証（extract 時に正規化しているので全て OK なはずだが念のため）。
    for id in &technique_ids {
        validate_technique_id_format(id)?;
    }
    let mut mappings: Vec<AttackMapping> = Vec::with_capacity(technique_ids.len());
    for id in &technique_ids {
        let (technique_name, tactic, dataset_version, dataset_sha) = match dataset {
            Some(ds) => {
                if !ds.contains_technique(id) {
                    return Err(
                        crate::attack::technique::UnknownTechniqueError::NotInDataset {
                            id: id.to_string(),
                            version: ds.manifest.version.clone(),
                        },
                    );
                }
                let info = ds.lookup_technique(id).unwrap();
                (
                    Some(info.name.clone()),
                    info.tactic.clone(),
                    Some(ds.manifest.version.clone()),
                    Some(ds.manifest.sha256.clone()),
                )
            }
            None => (None, None, None, None),
        };
        mappings.push(AttackMapping {
            technique_id: id.to_string(),
            technique_name,
            tactic,
            source: AttackMappingSource::SigmaTag,
            dataset_version,
            dataset_sha256: dataset_sha,
        });
    }
    Ok(mappings)
}

/// TraceForge 組み込みの既定 ATT&CK mapping（T6-008・source=BuiltIn）。
///
/// Phase 6 では空 list を返す（本フェーズで組み込む既定 mapping は無い）。
/// Phase 7 以降で Parser が検出した挙動と technique を結びつける既定 mapping を
/// 追加する場合、本関数を拡張する。規範 §15.3 が許可する4経路の1つ。
pub fn built_in_mappings() -> Vec<AttackMapping> {
    // Phase 6 では空。将来的な拡張ポイント。
    Vec::new()
}

/// 手動指定の ATT&CK mapping（T6-008・source=Manual）。
///
/// ユーザーが明示的に technique を指定した場合に使う。dataset があれば名称・tactic・
/// version・sha を解決する。dataset が無ければ ID と source だけの mapping になる。
pub fn manual_mapping(
    technique_id: &str,
    technique_name: Option<&str>,
    dataset: Option<&AttackDataset>,
) -> AttackMapping {
    // 形式検証（呼出側の誤入力検出）。
    let _ = validate_technique_id_format(technique_id);

    let (resolved_name, tactic, dataset_version, dataset_sha) = match dataset {
        Some(ds) => {
            let info = ds.lookup_technique(technique_id);
            (
                technique_name
                    .map(String::from)
                    .or_else(|| info.map(|i| i.name.clone())),
                info.and_then(|i| i.tactic.clone()),
                Some(ds.manifest.version.clone()),
                Some(ds.manifest.sha256.clone()),
            )
        }
        None => (technique_name.map(String::from), None, None, None),
    };
    AttackMapping {
        technique_id: technique_id.to_string(),
        technique_name: resolved_name,
        tactic,
        source: AttackMappingSource::Manual,
        dataset_version,
        dataset_sha256: dataset_sha,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::dataset::AttackDatasetManifest;

    fn make_dataset_with(technique_ids: &[&str]) -> AttackDataset {
        let mut bundle = String::from(r#"{"type":"bundle","id":"bundle--x","objects":["#);
        for (i, tid) in technique_ids.iter().enumerate() {
            if i > 0 {
                bundle.push(',');
            }
            bundle.push_str(&format!(
                r#"{{"type":"attack-pattern","id":"attack-pattern--{i:032x}","name":"name-{tid}","external_references":[{{"source_name":"mitre-attack","external_id":"{tid}"}}],"kill_chain_phases":[{{"kill_chain_name":"mitre-attack","phase_name":"execution"}}]}}"#
            ));
        }
        bundle.push_str("]}");
        let bytes = bundle.into_bytes();
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        AttackDataset::from_stix_bytes(&bytes, manifest).expect("dataset parse")
    }

    // ===== T6-008: Rule 生成元（Correlation Rule mitre_attack）=====

    #[test]
    fn from_correlation_rule_with_dataset() {
        let ds = make_dataset_with(&["T1059", "T1059.001"]);
        let mappings = from_correlation_rule("TF-CORR-001", &["T1059.001".to_string()], Some(&ds))
            .expect("ok");
        assert_eq!(mappings.len(), 1);
        let m = &mappings[0];
        assert_eq!(m.technique_id, "T1059.001");
        assert_eq!(m.technique_name.as_deref(), Some("name-T1059.001"));
        assert_eq!(m.tactic.as_deref(), Some("execution"));
        assert_eq!(m.source, AttackMappingSource::Rule);
        // T6-009: dataset version + hash が記録される。
        assert_eq!(m.dataset_version.as_deref(), Some("15.1"));
        assert!(m.dataset_sha256.is_some());
    }

    #[test]
    fn from_correlation_rule_without_dataset() {
        let mappings =
            from_correlation_rule("TF-CORR-001", &["T1059.001".to_string()], None).expect("ok");
        let m = &mappings[0];
        assert_eq!(m.technique_id, "T1059.001");
        assert!(m.technique_name.is_none());
        assert!(m.tactic.is_none());
        assert!(m.dataset_version.is_none());
        assert!(m.dataset_sha256.is_none());
    }

    #[test]
    fn from_correlation_rule_unknown_id_is_error() {
        let ds = make_dataset_with(&["T1059"]);
        let result = from_correlation_rule("TF-CORR-001", &["T9999".to_string()], Some(&ds));
        assert!(result.is_err());
    }

    #[test]
    fn from_correlation_rule_bad_format_is_error() {
        let ds = make_dataset_with(&["T1059"]);
        let result = from_correlation_rule("TF-CORR-001", &["bad-format".to_string()], Some(&ds));
        assert!(result.is_err());
    }

    // ===== T6-008: Sigma tag 生成元 =====

    #[test]
    fn extract_attack_tags_picks_only_technique_ids() {
        let tags = vec![
            "attack.execution".to_string(),
            "attack.t1059".to_string(),
            "attack.t1059.001".to_string(),
            "custom-tag".to_string(),
            "ATTACK.T1548.002".to_string(), // 大文字混在
        ];
        let result = extract_attack_tags_from_sigma(&tags);
        // sort・dedup 済み。大文字小文字は正規化される。
        assert_eq!(result, vec!["T1059", "T1059.001", "T1548.002"]);
    }

    #[test]
    fn extract_attack_tags_ignores_tactic_only_tags() {
        let tags = vec![
            "attack.execution".to_string(),
            "attack.persistence".to_string(),
        ];
        let result = extract_attack_tags_from_sigma(&tags);
        assert!(result.is_empty(), "tactic 名の tag は無視");
    }

    #[test]
    fn from_sigma_rule_tags_with_dataset() {
        let ds = make_dataset_with(&["T1059.001"]);
        let tags = vec![
            "attack.execution".to_string(),
            "attack.t1059.001".to_string(),
        ];
        let mappings = from_sigma_rule_tags(&tags, Some(&ds)).expect("ok");
        assert_eq!(mappings.len(), 1);
        let m = &mappings[0];
        assert_eq!(m.technique_id, "T1059.001");
        assert_eq!(m.source, AttackMappingSource::SigmaTag);
        assert_eq!(m.dataset_version.as_deref(), Some("15.1"));
    }

    #[test]
    fn from_sigma_rule_tags_unknown_is_error() {
        let ds = make_dataset_with(&["T1059"]);
        let tags = vec!["attack.t9999".to_string()];
        let result = from_sigma_rule_tags(&tags, Some(&ds));
        assert!(result.is_err());
    }

    // ===== T6-008: Built-in 生成元 =====

    #[test]
    fn built_in_mappings_empty_in_phase6() {
        assert!(built_in_mappings().is_empty());
    }

    // ===== T6-008: Manual 生成元 =====

    #[test]
    fn manual_mapping_with_dataset() {
        let ds = make_dataset_with(&["T1059.001"]);
        let m = manual_mapping("T1059.001", None, Some(&ds));
        assert_eq!(m.technique_id, "T1059.001");
        assert_eq!(m.technique_name.as_deref(), Some("name-T1059.001"));
        assert_eq!(m.tactic.as_deref(), Some("execution"));
        assert_eq!(m.source, AttackMappingSource::Manual);
        assert_eq!(m.dataset_version.as_deref(), Some("15.1"));
    }

    #[test]
    fn manual_mapping_overrides_name() {
        let ds = make_dataset_with(&["T1059.001"]);
        let m = manual_mapping("T1059.001", Some("My Custom Name"), Some(&ds));
        // ユーザー指定名を優先する（dataset 名より優先）。
        assert_eq!(m.technique_name.as_deref(), Some("My Custom Name"));
    }

    #[test]
    fn manual_mapping_without_dataset() {
        let m = manual_mapping("T1059.001", None, None);
        assert_eq!(m.technique_id, "T1059.001");
        assert!(m.technique_name.is_none());
        assert!(m.dataset_version.is_none());
        assert_eq!(m.source, AttackMappingSource::Manual);
    }

    // ===== T6-009: dataset version + hash が記録される（統合確認）=====

    #[test]
    fn mappings_record_dataset_version_and_hash() {
        let ds = make_dataset_with(&["T1059", "T1059.001", "T1548.002"]);

        // 3経路（Rule・SigmaTag・Manual）全てで dataset 由来なら version+hash が付く。
        let rule_mappings =
            from_correlation_rule("TF-CORR-001", &["T1059".to_string()], Some(&ds)).expect("ok");
        let sigma_mappings =
            from_sigma_rule_tags(&["attack.t1059.001".to_string()], Some(&ds)).expect("ok");
        let manual = manual_mapping("T1548.002", None, Some(&ds));

        for m in rule_mappings
            .iter()
            .chain(sigma_mappings.iter())
            .chain(std::iter::once(&manual))
        {
            assert_eq!(m.dataset_version.as_deref(), Some("15.1"));
            assert!(
                m.dataset_sha256
                    .as_ref()
                    .map(|s| tf_core::hash::is_lowercase_sha256_hex(s))
                    .unwrap_or(false)
            );
        }
    }

    #[test]
    fn mappings_canonical_value_includes_all_fields() {
        let ds = make_dataset_with(&["T1059"]);
        let m = manual_mapping("T1059", None, Some(&ds));
        let v = m.to_canonical_value();
        let obj = v.as_object().unwrap();
        // T6-009: dataset_version・dataset_sha256 が出力される。
        assert!(obj.contains_key("dataset_version"));
        assert!(obj.contains_key("dataset_sha256"));
        assert_eq!(obj["source"], "manual");
        assert!(obj.contains_key("tactic"));
    }
}
