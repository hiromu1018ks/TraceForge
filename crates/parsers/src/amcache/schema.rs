//! Amcache.hve の schema family 認識（互換 §4.6・T4-060）。
//!
//! Windows 10 (1607+) 以降の `Amcache.hve` は「Inventory schema」と呼ばれる構造を持ち、
//! `Root` 配下へ `InventoryApplicationFile`・`InventoryApplication`・`InventoryDevicePnp`・
//! `DeviceCensus` 等の subkey が並ぶ。Windows 10 22H2 と Windows 11 24H2 は共にこの
//! Inventory schema family へ属する（細かな subkey の増減はあるが基本構造は同一）。
//!
//! Windows 8 / 8.1（と Windows 10 初期 build の一部）は旧形式で `Root\File`・
//! `Root\Programs` を持つ。本 Parser は v1.0 では Win10 22H2 / Win11 24H2 の Inventory
//! schema のみを Required 対応とし、Win 8/8.1 は Optional（専用 fixture が必要）と扱う
//! （互換 §4.6）。
//!
//! 未知 schema を検出した場合は [`SchemaFamily::Unknown`] へ分類し、呼出側で
//! Warning Issue を出して Event 生成を抑制する（Generic Registry Parser への自動 fallback
//! 禁止・互換 §4.6・§4.7）。

/// Amcache.hve の schema family（互換 §4.6・§5 必須 field「schema family」）。
///
/// Schema 上の lowercase 文字列表現は [`SchemaFamily::as_str`] へよる。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaFamily {
    /// Windows 10 22H2 / Windows 11 24H2（および Windows 10 1607 以降）の Inventory schema。
    /// `InventoryApplicationFile` 等の Inventory 系 subkey を持つ。
    Win10Inventory,
    /// Windows 8 / 8.1（および初期 Windows 10 build）の旧形式。`File`・`Programs` を持つ。
    Win8Legacy,
    /// 認識できない schema family。Unknown 扱いとし、Warning を発する（互換 §4.6）。
    Unknown,
}

impl SchemaFamily {
    /// Schema 上の lowercase 文字列表現（互換 §5 必須 field「schema family」へ使用）。
    pub fn as_str(&self) -> &'static str {
        match self {
            // Win10 22H2 / Win11 24H2 は共に同一の Inventory schema family へ属する。
            SchemaFamily::Win10Inventory => "win10-22h2-win11-24h2-inventory",
            SchemaFamily::Win8Legacy => "win8-8.1-legacy",
            SchemaFamily::Unknown => "unknown",
        }
    }

    /// この schema family が Amcache Parser で「対応済み（Event 生成対象）」か。
    ///
    /// `Unknown` は対応範囲外のため Warning Issue のみとなり、Event 生成は行わない
    /// （互換 §4.6: 未知 schema は Generic Registry parser へ自動 fallback せず Warning）。
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            SchemaFamily::Win10Inventory | SchemaFamily::Win8Legacy
        )
    }
}

/// Inventory schema family を特徴付ける subkey 名（先頭要素）。
///
/// `InventoryApplicationFile` は Windows 10 1607 以降全 build に存在する代表的な key。
/// `InventoryApplication` も同等に特徴的。これらが1つでも存在すれば Inventory family へ
/// 分類する（schema の細部に振り回されないよう、複数の指標を見る）。
const WIN10_INVENTORY_INDICATORS: &[&str] = &[
    "InventoryApplicationFile",
    "InventoryApplication",
    "InventoryApplicationShortcut",
    "InventoryDevicePnp",
    "InventoryDeviceContainer",
    "DeviceCensus",
];

/// Win 8/8.1 旧形式を特徴付ける subkey 名。
const WIN8_LEGACY_INDICATORS: &[&str] = &["File", "Programs"];

/// root key の直下 subkey 名前一覧から schema family を決定する。
///
/// 複数の指標を見て、最も特徴的なものを採用する:
///
/// - Inventory 系 subkey が1つでもあれば [`SchemaFamily::Win10Inventory`]
/// - そうでなく `File` / `Programs` が1つでもあれば [`SchemaFamily::Win8Legacy`]
/// - いずれも無ければ [`SchemaFamily::Unknown`]
///
/// root 直下の subkey 名前を case-insensitive で照合する。実 Windows の key 名は
/// ほぼ全て ASCII であり、大文字・小文字は仕様上 fixed だが、念のため case-insensitive
/// で見る（「file」や「PROGRAMS」等の細工をした不正 hive への耐性）。
pub fn detect_schema_family(root_subkey_names: &[String]) -> SchemaFamily {
    let has = |indicators: &[&str]| -> bool {
        root_subkey_names.iter().any(|n| {
            let n_lower = n.to_ascii_lowercase();
            indicators
                .iter()
                .any(|ind| n_lower == ind.to_ascii_lowercase())
        })
    };

    if has(WIN10_INVENTORY_INDICATORS) {
        SchemaFamily::Win10Inventory
    } else if has(WIN8_LEGACY_INDICATORS) {
        SchemaFamily::Win8Legacy
    } else {
        SchemaFamily::Unknown
    }
}

/// 指定 key 名前が Inventory schema で「file metadata 保存用」として特に重要なものか。
///
/// `InventoryApplicationFile` は実行 file の SHA-1・会社名・製品名・バージョン等を保持する
/// 代表的な leaf key。Amcache Parser ではこの key 配下を特に丁寧に扱う（必須 field として
/// key path と取得 field を Event 属性へ記録する・互換 §5）。
pub fn is_inventory_file_metadata_key(key_name: &str) -> bool {
    matches!(
        key_name.to_ascii_lowercase().as_str(),
        "inventoryapplicationfile" | "inventoryapplication"
    )
}

/// key_path が Inventory schema の file metadata 配下（`InventoryApplicationFile`・
/// `InventoryApplication` のいずれかの直下または更深）かを判定する。
///
/// key_path は `\` 区切り（例: `Root\InventoryApplicationFile\<sha1>`）。
/// 先頭から `InventoryApplicationFile` または `InventoryApplication` の segment が
/// 現れれば true を返す。
pub fn is_file_metadata_path(key_path: &str) -> bool {
    key_path.split('\\').any(is_inventory_file_metadata_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_win10_inventory_from_inventoryapplicationfile() {
        let names = vec!["Root".to_string(), "InventoryApplicationFile".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Win10Inventory);
    }

    #[test]
    fn detect_win10_inventory_from_inventoryapplication() {
        let names = vec!["InventoryApplication".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Win10Inventory);
    }

    #[test]
    fn detect_win10_inventory_from_devicecensus() {
        let names = vec!["DeviceCensus".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Win10Inventory);
    }

    #[test]
    fn detect_win8_legacy_from_file() {
        let names = vec!["File".to_string(), "Programs".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Win8Legacy);
    }

    #[test]
    fn detect_unknown_when_no_indicators() {
        let names = vec!["Random".to_string(), "Stuff".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Unknown);
    }

    #[test]
    fn detect_unknown_when_empty() {
        assert_eq!(detect_schema_family(&[]), SchemaFamily::Unknown);
    }

    #[test]
    fn detection_is_case_insensitive() {
        let names = vec!["inventoryapplicationfile".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Win10Inventory);
        let names2 = vec!["FILE".to_string()];
        assert_eq!(detect_schema_family(&names2), SchemaFamily::Win8Legacy);
    }

    #[test]
    fn inventory_takes_priority_over_legacy() {
        // 両方の指標がある場合は Inventory を優先（新しい OS を信頼）。
        let names = vec!["InventoryApplicationFile".to_string(), "File".to_string()];
        assert_eq!(detect_schema_family(&names), SchemaFamily::Win10Inventory);
    }

    #[test]
    fn schema_family_as_str_is_stable() {
        assert_eq!(
            SchemaFamily::Win10Inventory.as_str(),
            "win10-22h2-win11-24h2-inventory"
        );
        assert_eq!(SchemaFamily::Win8Legacy.as_str(), "win8-8.1-legacy");
        assert_eq!(SchemaFamily::Unknown.as_str(), "unknown");
    }

    #[test]
    fn supported_families() {
        assert!(SchemaFamily::Win10Inventory.is_supported());
        assert!(SchemaFamily::Win8Legacy.is_supported());
        assert!(!SchemaFamily::Unknown.is_supported());
    }

    #[test]
    fn inventory_file_metadata_key_detection() {
        assert!(is_inventory_file_metadata_key("InventoryApplicationFile"));
        assert!(is_inventory_file_metadata_key("InventoryApplication"));
        assert!(!is_inventory_file_metadata_key("DeviceCensus"));
        assert!(!is_inventory_file_metadata_key("Random"));
    }

    #[test]
    fn file_metadata_path_detection() {
        assert!(is_file_metadata_path(
            "Root\\InventoryApplicationFile\\000061e800b0c814"
        ));
        assert!(is_file_metadata_path("Root\\InventoryApplication\\notepad"));
        // 直下でも true。
        assert!(is_file_metadata_path("InventoryApplicationFile"));
        // Inventory 系でなければ false。
        assert!(!is_file_metadata_path("Root\\DeviceCensus"));
        assert!(!is_file_metadata_path("Root\\Random\\Sub"));
    }
}
