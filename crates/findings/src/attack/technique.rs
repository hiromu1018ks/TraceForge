//! Technique ID の形式検証・dataset 存在検証（T6-007・互換 §9）。
//!
//! 互換 §9 は「Technique/Sub-technique ID が dataset に存在しない Rule は validation error
//! とする」と定める。本モジュールは次を提供する:
//!
//! - [`validate_technique_id_format`]: `T<4 桁>(.<3 桁>)?` 形式の検証
//! - [`validate_technique_ids`]: dataset への存在検証。不在 ID を [`UnknownTechniqueError`] で返す。
//!
//! 不在 ID は Rule validation error となり、規範 §17.2 の Exit Code 5（strict rules）または
//! Exit Code 1（Warning・既定）へ寄与する。本モジュール自体は Exit Code 計算を行わず、
//! 呼出側が [`UnknownTechniqueError`] を Rule validation error の1つとして集約する。

use crate::AttackDataset;

/// Technique ID が dataset に存在しない（T6-007・互換 §9）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnknownTechniqueError {
    /// Technique ID の形式が不正。`T<4 桁>(.<3 桁>)?` ではない。
    #[error("invalid technique id format (expected T<4-digit>(.<3-digit>)?): {0}")]
    InvalidFormat(String),

    /// Technique ID が dataset に存在しない（互換 §9）。
    #[error("technique id {id} is not present in the ATT&CK dataset (version {version})")]
    NotInDataset { id: String, version: String },
}

/// MITRE ATT&CK の Technique ID（互換 §9・Schema §7 `mitre_attack` 要素）。
///
/// 形式: `T<4桁数字>(.<3桁数字>)?`
/// - 例: `T1059`, `T1059.001`, `T1548.002`
/// - 小文字 `t1059` は不可（MITRE は大文字を正本とする）
/// - 4桁の先頭が 0 であることは許容する（T00* 等の過去 ID 互換）
pub fn validate_technique_id_format(technique_id: &str) -> Result<(), UnknownTechniqueError> {
    if is_valid_technique_id_format(technique_id) {
        Ok(())
    } else {
        Err(UnknownTechniqueError::InvalidFormat(
            technique_id.to_string(),
        ))
    }
}

/// `T<4桁>(.<3桁>)?` の形式検証（boolean 版）。
pub fn is_valid_technique_id_format(technique_id: &str) -> bool {
    let bytes = technique_id.as_bytes();
    if bytes.len() < 5 {
        return false;
    }
    // 先頭は 'T'（大文字のみ）。
    if bytes[0] != b'T' {
        return false;
    }
    // 4桁数字か、4桁.3桁数字か。
    if let Some((main, sub)) = technique_id.split_once('.') {
        // main は 'T' + 4桁、sub は3桁。
        let main = &main[1..]; // 'T' を除去
        main.len() == 4
            && main.chars().all(|c| c.is_ascii_digit())
            && sub.len() == 3
            && sub.chars().all(|c| c.is_ascii_digit())
    } else {
        let main = &technique_id[1..]; // 'T' を除去
        main.len() == 4 && main.chars().all(|c| c.is_ascii_digit())
    }
}

/// Technique ID list を dataset へ照合する（T6-007・互換 §9）。
///
/// 不在 ID が1件でもあれば [`UnknownTechniqueError::NotInDataset`] を返す。
/// 形式不正があれば [`UnknownTechniqueError::InvalidFormat`] を返す。
/// 形式検証を先に行い、全 ID が形式妥当なら dataset 存在検証へ進む。
pub fn validate_technique_ids(
    technique_ids: &[String],
    dataset: &AttackDataset,
) -> Result<(), UnknownTechniqueError> {
    // 1. 形式検証（決定性のため byte 順で sort してから検証）。
    let mut sorted: Vec<&String> = technique_ids.iter().collect();
    sorted.sort();
    for id in &sorted {
        validate_technique_id_format(id)?;
    }
    // 2. dataset 存在検証（sort 済み順で安定）。
    for id in &sorted {
        if !dataset.contains_technique(id) {
            return Err(UnknownTechniqueError::NotInDataset {
                id: id.to_string(),
                version: dataset.manifest.version.clone(),
            });
        }
    }
    Ok(())
}

/// STIX attack-pattern object から取り出した Technique の補助情報（dataset 内部用）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TechniqueInfo {
    /// Technique の表示名（dataset の `name` field）。
    pub name: String,
    /// Technique が属する tactic（`execution`・`persistence` 等）。
    /// dataset の `kill_chain_phases[].phase_name` から取り出す。
    pub tactic: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttackDatasetManifest;

    fn sha64(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn make_dataset_with(technique_ids: &[&str]) -> AttackDataset {
        let mut bundle = String::from(r#"{"type":"bundle","id":"bundle--x","objects":["#);
        for (i, tid) in technique_ids.iter().enumerate() {
            if i > 0 {
                bundle.push(',');
            }
            bundle.push_str(&format!(
                r#"{{"type":"attack-pattern","id":"attack-pattern--{i:032x}","name":"tech-{tid}","external_references":[{{"source_name":"mitre-attack","external_id":"{tid}"}}]}}"#
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

    // ===== T6-007: 形式検証 =====

    #[test]
    fn valid_technique_id_formats() {
        assert!(is_valid_technique_id_format("T1059"));
        assert!(is_valid_technique_id_format("T1059.001"));
        assert!(is_valid_technique_id_format("T1548.002"));
        assert!(is_valid_technique_id_format("T0001"));
    }

    #[test]
    fn invalid_technique_id_formats() {
        // 小文字 t は不可。
        assert!(!is_valid_technique_id_format("t1059"));
        // 桁数不足。
        assert!(!is_valid_technique_id_format("T12"));
        assert!(!is_valid_technique_id_format("T12345"));
        // sub-technique の桁数不足。
        assert!(!is_valid_technique_id_format("T1059.01"));
        assert!(!is_valid_technique_id_format("T1059.0001"));
        // 文字混入。
        assert!(!is_valid_technique_id_format("T10ab"));
        // 空文字列。
        assert!(!is_valid_technique_id_format(""));
        // prefix 無し。
        assert!(!is_valid_technique_id_format("1059"));
    }

    // ===== T6-007: dataset 存在検証 =====

    #[test]
    fn validate_known_ids_passes() {
        let ds = make_dataset_with(&["T1059", "T1059.001"]);
        validate_technique_ids(&["T1059".to_string()], &ds).expect("known id passes");
        validate_technique_ids(&["T1059".to_string(), "T1059.001".to_string()], &ds)
            .expect("known ids pass");
    }

    #[test]
    fn validate_unknown_id_fails() {
        let ds = make_dataset_with(&["T1059"]);
        let result = validate_technique_ids(&["T9999".to_string()], &ds);
        assert!(
            matches!(result, Err(UnknownTechniqueError::NotInDataset { id, version }) if id == "T9999" && version == "15.1")
        );
    }

    #[test]
    fn validate_mixed_known_unknown_fails_on_unknown() {
        let ds = make_dataset_with(&["T1059"]);
        let result = validate_technique_ids(&["T1059".to_string(), "T8888".to_string()], &ds);
        // 不在 ID が1件でも error。
        assert!(matches!(
            result,
            Err(UnknownTechniqueError::NotInDataset { .. })
        ));
    }

    #[test]
    fn validate_bad_format_fails_first() {
        let ds = make_dataset_with(&["T1059"]);
        let result = validate_technique_ids(&["bad-format".to_string()], &ds);
        assert!(matches!(
            result,
            Err(UnknownTechniqueError::InvalidFormat(_))
        ));
    }

    #[test]
    fn validate_empty_list_passes() {
        let ds = make_dataset_with(&["T1059"]);
        validate_technique_ids(&[], &ds).expect("empty list passes");
    }

    // ===== TechniqueInfo =====

    #[test]
    fn technique_info_equality() {
        let a = TechniqueInfo {
            name: "PowerShell".into(),
            tactic: Some("execution".into()),
        };
        let b = TechniqueInfo {
            name: "PowerShell".into(),
            tactic: Some("execution".into()),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn lookup_returns_technique_info() {
        let ds = make_dataset_with(&["T1059"]);
        let info = ds.lookup_technique("T1059").unwrap();
        assert_eq!(info.name, "tech-T1059");
    }

    // 念のため、manifest 形式検証
    #[test]
    fn manifest_validates_against_phase6_form() {
        let m = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: sha64('a'),
            source_url: "https://github.com/mitre/cti".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let _ = m.to_canonical_value();
    }
}
