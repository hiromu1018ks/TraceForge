//! ATT&CK STIX dataset の manifest と load（T6-006・互換 §9）。
//!
//! MITRE ATT&CK は STIX 2.x bundle 形式で dataset を公開する。本モジュールは次を行う:
//!
//! - **T6-006**: dataset file の version pin・SHA-256・取得元 URL・取得日 を
//!   [`AttackDatasetManifest`] へ記録する（互換 §9・規範 §20 の Manifest `attack_dataset`）
//! - dataset から technique 一覧を抽出し、[`AttackDataset`] として保持する
//! - 外部通信は行わない（規範 §2）。呼出側が file へ読込んだ bytes を渡す設計。
//!
//! ## STIX bundle の扱い
//!
//! STIX bundle は JSON であり、次の構造を持つ:
//! ```json
//! {
//!   "type": "bundle",
//!   "id": "bundle--...",
//!   "objects": [
//!     {
//!       "type": "attack-pattern",
//!       "id": "attack-pattern--...",
//!       "name": "PowerShell",
//!       "external_references": [
//!         { "source_name": "mitre-attack", "external_id": "T1059.001" }
//!       ],
//!       "kill_chain_phases": [
//!         { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
//!       ]
//!     },
//!     ...
//!   ]
//! }
//! ```
//!
//! 本フェーズでは STIX 全体を parse するのではなく、`attack-pattern` object の
//! `external_references` 経由で Technique ID を取り出す最小実装とする。
//! Revoked・deprecated の technique は除外しない（互換 §9 が禁止していないため）が、
//! Revoked された technique を Rule が参照した場合は別途 warning 扱いとすることを
//! 呼出側へ任せる（本フェーズでは実装しない）。

use std::collections::BTreeMap;

use serde_json::Value;

use crate::attack::technique::TechniqueInfo;

/// ATT&CK dataset の manifest（T6-006・互換 §9・規範 §20）。
///
/// 外部通信で取得した dataset の再現性を保証するため、次を記録する:
/// - `version`: ATT&CK release version（例: `15.1`）
/// - `sha256`: STIX bundle bytes の SHA-256 lowercase hex
/// - `source_url`: 取得元 URL（例: `https://github.com/mitre/cti/releases/...`）
/// - `retrieved_at`: 取得日（RFC 3339 UTC。手動登録）
#[derive(Clone, Debug, PartialEq)]
pub struct AttackDatasetManifest {
    /// ATT&CK release version（例: `15.1`）。互換 §9 が release 時の pin を要求。
    pub version: String,
    /// STIX bundle raw bytes の SHA-256 lowercase hex（規範 §20・Schema §2.1）。
    pub sha256: String,
    /// 取得元 URL（互換 §9）。
    pub source_url: String,
    /// 取得日（RFC 3339 UTC 文字列・手動登録。run metadata 扱い、規範 §13.1）。
    pub retrieved_at: String,
}

impl AttackDatasetManifest {
    /// Schema §5.9 `attack_dataset` field へ出力する [`Value`] を構築する（規範 §20）。
    pub fn to_canonical_value(&self) -> Value {
        serde_json::json!({
            "version": self.version,
            "sha256": self.sha256,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
        })
    }
}

/// ATT&CK dataset の load 失敗（T6-006）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum AttackDatasetError {
    /// STIX bundle の JSON parse 失敗。
    #[error("ATT&CK STIX bundle JSON parse error: {0}")]
    InvalidJson(String),

    /// SHA-256 の形式が不正。
    #[error("ATT&CK dataset sha256 is not lowercase 64-char hex: {0}")]
    InvalidSha256(String),

    /// bundle が STIX 形式ではない（`type: bundle` を持たない等）。
    #[error("ATT&CK dataset is not a STIX bundle: {0}")]
    NotStixBundle(String),

    /// bundle 内に attack-pattern object が1件も無い。
    #[error("ATT&CK dataset contains zero attack-pattern objects")]
    NoTechniques,
}

/// ATT&CK STIX dataset の load 済み表現（T6-006）。
///
/// dataset の manifest と、technique ID → [`TechniqueInfo`] の map を持つ。
/// [`AttackDataset::lookup_technique`] で Technique の名前・tactic を引ける。
/// [`AttackDataset::contains_technique`] で存在検証（T6-007）を行う。
#[derive(Clone, Debug)]
pub struct AttackDataset {
    pub manifest: AttackDatasetManifest,
    /// Technique ID（`T1059.001` 等）→ [`TechniqueInfo`]。
    techniques: BTreeMap<String, TechniqueInfo>,
}

impl AttackDataset {
    /// dataset の technique 数。
    pub fn technique_count(&self) -> usize {
        self.techniques.len()
    }

    /// 指定した Technique ID が dataset に存在するか（T6-007）。
    pub fn contains_technique(&self, technique_id: &str) -> bool {
        self.techniques.contains_key(technique_id)
    }

    /// 指定した Technique ID の情報を引く。
    pub fn lookup_technique(&self, technique_id: &str) -> Option<&TechniqueInfo> {
        self.techniques.get(technique_id)
    }

    /// 全 Technique ID の iterator（byte 昇順・決定性）。
    pub fn technique_ids(&self) -> impl Iterator<Item = &str> {
        self.techniques.keys().map(String::as_str)
    }

    /// STIX bundle raw bytes から [`AttackDataset`] を構築する（T6-006）。
    ///
    /// - `bundle_bytes`: STIX bundle の raw bytes。SHA-256 を計算して manifest へ記録する。
    /// - `manifest`: dataset の version・取得元 URL・取得日。`sha256` は本関数で上書きする。
    ///
    /// 外部通信は行わない（規範 §2）。呼出側が file から読込んだ bytes を渡すこと。
    pub fn from_stix_bytes(
        bundle_bytes: &[u8],
        mut manifest: AttackDatasetManifest,
    ) -> Result<Self, AttackDatasetError> {
        // SHA-256 を計算して manifest へ上書き（呼出側の手入力ミスを防ぐ）。
        let sha = tf_core::hash::sha256_hex(bundle_bytes);
        manifest.sha256 = sha.clone();

        // manifest.sha256 の形式検証（念のため）。
        if !tf_core::hash::is_lowercase_sha256_hex(&sha) {
            return Err(AttackDatasetError::InvalidSha256(sha));
        }

        // JSON parse。
        let bundle: Value = serde_json::from_slice(bundle_bytes)
            .map_err(|e| AttackDatasetError::InvalidJson(e.to_string()))?;

        // STIX bundle 形式の確認。
        let bundle_type = bundle.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if bundle_type != "bundle" {
            return Err(AttackDatasetError::NotStixBundle(format!(
                "expected type=bundle, got type={bundle_type:?}"
            )));
        }

        // attack-pattern object を取り出す。
        let objects = bundle
            .get("objects")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                AttackDatasetError::NotStixBundle("missing or non-array 'objects' field".into())
            })?;

        let mut techniques: BTreeMap<String, TechniqueInfo> = BTreeMap::new();
        for obj in objects {
            let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if obj_type != "attack-pattern" {
                continue;
            }
            // external_references から mitre-attack の external_id を探す。
            let ext_refs = obj.get("external_references").and_then(|v| v.as_array());
            let technique_id = ext_refs.and_then(|arr| {
                arr.iter().find_map(|r| {
                    let source = r.get("source_name").and_then(|v| v.as_str()).unwrap_or("");
                    if source == "mitre-attack" {
                        r.get("external_id")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    } else {
                        None
                    }
                })
            });
            let Some(technique_id) = technique_id else {
                continue;
            };
            let name = obj.get("name").and_then(|v| v.as_str()).map(String::from);
            let tactic = extract_first_phase_name(obj);
            techniques.insert(
                technique_id,
                TechniqueInfo {
                    name: name.unwrap_or_default(),
                    tactic,
                },
            );
        }
        if techniques.is_empty() {
            return Err(AttackDatasetError::NoTechniques);
        }

        Ok(AttackDataset {
            manifest,
            techniques,
        })
    }
}

/// STIX attack-pattern object の `kill_chain_phases` から最初の phase_name を取り出す。
fn extract_first_phase_name(obj: &Value) -> Option<String> {
    let phases = obj.get("kill_chain_phases").and_then(|v| v.as_array())?;
    for phase in phases {
        let kill_chain = phase
            .get("kill_chain_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if (kill_chain == "mitre-attack" || kill_chain == "mitre-attack-ics")
            && let Some(name) = phase.get("phase_name").and_then(|v| v.as_str())
        {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha64(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn minimal_bundle() -> Vec<u8> {
        // 2 technique を持つ最小 STIX bundle。
        r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000000",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                    "name": "Command and Scripting Interpreter",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                    ]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--00000000-0000-4000-8000-000000000002",
                    "name": "PowerShell",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059.001"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                    ]
                },
                {
                    "type": "identity",
                    "id": "identity--00000000-0000-4000-8000-000000000003",
                    "name": "The MITRE Corporation"
                }
            ]
        }"#
        .as_bytes()
        .to_vec()
    }

    // ===== T6-006: version pin・SHA-256・取得元記録 =====

    #[test]
    fn manifest_to_canonical_value_has_required_fields() {
        let m = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: sha64('a'),
            source_url: "https://github.com/mitre/cti".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let v = m.to_canonical_value();
        let obj = v.as_object().unwrap();
        assert_eq!(obj["version"], "15.1");
        assert_eq!(obj["sha256"], sha64('a'));
        assert_eq!(obj["source_url"], "https://github.com/mitre/cti");
        assert_eq!(obj["retrieved_at"], "2026-08-12T00:00:00Z");
    }

    #[test]
    fn dataset_computes_sha256_from_bytes() {
        let bundle = minimal_bundle();
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let ds = AttackDataset::from_stix_bytes(&bundle, manifest).expect("parse ok");
        // SHA-256 は bytes から計算されていおり、64桁 hex である。
        assert_eq!(ds.manifest.sha256.len(), 64);
        assert!(tf_core::hash::is_lowercase_sha256_hex(&ds.manifest.sha256));

        // 同一 bytes から同一 SHA-256。
        let manifest2 = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let ds2 = AttackDataset::from_stix_bytes(&bundle, manifest2).expect("parse ok");
        assert_eq!(ds.manifest.sha256, ds2.manifest.sha256);
    }

    #[test]
    fn dataset_loads_techniques() {
        let bundle = minimal_bundle();
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let ds = AttackDataset::from_stix_bytes(&bundle, manifest).expect("parse ok");

        assert_eq!(ds.technique_count(), 2);
        assert!(ds.contains_technique("T1059"));
        assert!(ds.contains_technique("T1059.001"));
        assert!(!ds.contains_technique("T9999"));

        let powershell = ds.lookup_technique("T1059.001").unwrap();
        assert_eq!(powershell.name, "PowerShell");
        assert_eq!(powershell.tactic.as_deref(), Some("execution"));
    }

    #[test]
    fn dataset_rejects_non_bundle_json() {
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let not_bundle = r#"{"type": "indicator", "id": "x"}"#.as_bytes();
        let result = AttackDataset::from_stix_bytes(not_bundle, manifest);
        assert!(matches!(result, Err(AttackDatasetError::NotStixBundle(_))));
    }

    #[test]
    fn dataset_rejects_invalid_json() {
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let bad_json = b"not json {";
        let result = AttackDataset::from_stix_bytes(bad_json, manifest);
        assert!(matches!(result, Err(AttackDatasetError::InvalidJson(_))));
    }

    #[test]
    fn dataset_rejects_zero_techniques() {
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        // bundle だが attack-pattern が無い。
        let bundle = r#"{"type": "bundle", "id": "bundle--x", "objects": []}"#.as_bytes();
        let result = AttackDataset::from_stix_bytes(bundle, manifest);
        assert!(matches!(result, Err(AttackDatasetError::NoTechniques)));
    }

    #[test]
    fn dataset_technique_ids_is_sorted() {
        let bundle = minimal_bundle();
        let manifest = AttackDatasetManifest {
            version: "15.1".into(),
            sha256: String::new(),
            source_url: "https://example.com".into(),
            retrieved_at: "2026-08-12T00:00:00Z".into(),
        };
        let ds = AttackDataset::from_stix_bytes(&bundle, manifest).expect("parse ok");

        let ids: Vec<&str> = ds.technique_ids().collect();
        // BTreeMap は byte 昇順。T1059 < T1059.001。
        assert_eq!(ids, vec!["T1059", "T1059.001"]);
    }
}
