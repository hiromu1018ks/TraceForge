//! Sigma field → TraceForge Event field の mapping（互換 §6.3、T5-015）。
//!
//! 互換 §6.3 が定める最低限の field mapping を実装する。複数候補がある場合は
//! 明示順の先頭のみを使用し、全候補を OR で同時評価しない（互換 §6.3）。

/// Sigma field 名から TraceForge Event 上の field path への変換。
///
/// 戻り値は `tf_core::Event` 上の field へのアクセス path:
/// - トップレベル: `hostname`, `user`, `program`, `message`
/// - ネスト: `path.original`, `path.comparison_key`
/// - process: `process.image_path.original`, `process.command_line`, `process.pid`
/// - attributes: `attributes.evtx.event_id`, `attributes.evtx.channel` 等
///
/// 対応表にない Sigma field は `None` を返す。呼出側は `attributes` から
/// Sigma field 名を直接探す fallback を行う。
pub fn map_sigma_field(sigma_field: &str) -> Option<&'static str> {
    match sigma_field {
        // EVTX 共通（互換 §6.3 表）
        "EventID" => Some("attributes.evtx.event_id"),
        "Channel" => Some("attributes.evtx.channel"),
        "Provider_Name" => Some("attributes.evtx.provider"),
        "Computer" => Some("hostname"),

        // Process 関連（互換 §6.3 表: 複数候補は先頭のみ）
        // `Image` / `NewProcessName` → 両方とも process.image_path.original へ mapping
        // それぞれ別名として個別に mapping する（OR 評価ではない）
        "Image" => Some("process.image_path.original"),
        "NewProcessName" => Some("process.image_path.original"),
        "CommandLine" => Some("process.command_line"),
        "ProcessCommandLine" => Some("process.command_line"),
        "ParentImage" => Some("attributes.process.parent_image"),
        "ParentCommandLine" => Some("attributes.process.parent_command_line"),

        // User 関連（互換 §6.3 表）
        // `User` / `SubjectUserName` → `user` へ mapping（明示順の先頭のみ使用）
        "User" => Some("user"),
        "SubjectUserName" => Some("user"),

        // Path 関連
        "TargetFilename" => Some("path.original"),

        _ => None,
    }
}

/// logsource の `definition` に含まれる Event ID 等の追加情報を抽出する。
///
/// Sigma では `logsource.definition` に `%evtx_id%` 等の placeholder を含める
/// ことがあるが、TF-SIGMA-1.0 では definition を情報提供のみとし、評価へは
/// 使用しない。
pub fn extract_definition_info(_definition: &str) -> Vec<(String, String)> {
    // TF-SIGMA-1.0 では definition を評価へ使用しない。
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_mapping() {
        assert_eq!(map_sigma_field("EventID"), Some("attributes.evtx.event_id"));
    }

    #[test]
    fn channel_mapping() {
        assert_eq!(map_sigma_field("Channel"), Some("attributes.evtx.channel"));
    }

    #[test]
    fn provider_mapping() {
        assert_eq!(
            map_sigma_field("Provider_Name"),
            Some("attributes.evtx.provider")
        );
    }

    #[test]
    fn computer_mapping() {
        assert_eq!(map_sigma_field("Computer"), Some("hostname"));
    }

    #[test]
    fn image_mapping() {
        // Image と NewProcessName は両方とも同一 TF field へ mapping
        assert_eq!(
            map_sigma_field("Image"),
            Some("process.image_path.original")
        );
        assert_eq!(
            map_sigma_field("NewProcessName"),
            Some("process.image_path.original")
        );
    }

    #[test]
    fn commandline_mapping() {
        assert_eq!(map_sigma_field("CommandLine"), Some("process.command_line"));
        assert_eq!(
            map_sigma_field("ProcessCommandLine"),
            Some("process.command_line")
        );
    }

    #[test]
    fn user_mapping() {
        assert_eq!(map_sigma_field("User"), Some("user"));
        assert_eq!(map_sigma_field("SubjectUserName"), Some("user"));
    }

    #[test]
    fn targetfilename_mapping() {
        assert_eq!(map_sigma_field("TargetFilename"), Some("path.original"));
    }

    #[test]
    fn unmapped_field_returns_none() {
        assert!(map_sigma_field("UnknownField").is_none());
        assert!(map_sigma_field("CustomEventData").is_none());
    }
}
