//! EVTX event の typed mapping（互換 §4.2、T4-043・T4-044）。
//!
//! 互換 §4.2 は最低限の typed mapping として次の5種を定める:
//!
//! | Event ID | Channel/Provider 条件                       | event type     |
//! |---------:|---------------------------------------------|----------------|
//! |     4624 | Security / Microsoft-Windows-Security-Auditing | `login`         |
//! |     4625 | Security / Microsoft-Windows-Security-Auditing | `login_failure` |
//! |     4688 | Security / Microsoft-Windows-Security-Auditing | `process_start` |
//! |     4689 | Security / Microsoft-Windows-Security-Auditing | `process_stop`  |
//! |     7045 | System  / Service Control Manager            | `service_create` |
//!
//! 「Event ID だけで mapping してはならない。channel・provider・required field を同時に検証する」
//! （互換 §4.2）。本 module は channel・provider の一致と必須 field の存在を検証した上で
//! typed event type を決定する。検証失敗時は汎用 [`EVENT_LOGGED_TYPE`] へ戻す（規範 §7.1）。
//!
//! ## PowerShell Operational / Sysmon Operational（T4-044）
//!
//! これらの channel は汎用 event として channel と raw field を保持する。
//! 本 Phase では typed mapping せず [`EVENT_LOGGED_TYPE`] を生成するが、
//! 必須 field（provider・channel・EventID・computer・event time・raw data）は全て保持する。

use crate::evtx::binxml::EventContent;

/// 汎用 EVTX 観測 event type（規範 §7.1: 観測型）。
pub const EVENT_LOGGED_TYPE: &str = "event_logged";
/// typed mapping 後の event type: 4624 / Security → `login`。
pub const LOGIN_TYPE: &str = "login";
/// typed mapping 後の event type: 4625 / Security → `login_failure`。
pub const LOGIN_FAILURE_TYPE: &str = "login_failure";
/// typed mapping 後の event type: 4688 / Security → `process_start`。
pub const PROCESS_START_TYPE: &str = "process_start";
/// typed mapping 後の event type: 4689 / Security → `process_stop`。
pub const PROCESS_STOP_TYPE: &str = "process_stop";
/// typed mapping 後の event type: 7045 / System + SCM → `service_create`。
pub const SERVICE_CREATE_TYPE: &str = "service_create";

/// 必須 field が typed mapping の要件を満たすか検証する（互換 §4.2）。
///
/// 戻り値は typed event type。検証失敗時は [`EVENT_LOGGED_TYPE`] へ戻す。
pub fn map_event_type(content: &EventContent) -> &'static str {
    let Some(event_id) = content.event_id else {
        return EVENT_LOGGED_TYPE;
    };
    // channel と provider を ASCII 大小比較のために正規化。
    let channel = content.channel.as_deref().unwrap_or("");
    let provider = content.provider_name.as_deref().unwrap_or("");

    // 4624/4625/4688/4689: Security + Microsoft-Windows-Security-Auditing。
    if matches!(event_id, 4624 | 4625 | 4688 | 4689) {
        if !eq_ascii_ci(channel, "Security") {
            return EVENT_LOGGED_TYPE;
        }
        if !eq_ascii_ci(provider, "Microsoft-Windows-Security-Auditing") {
            return EVENT_LOGGED_TYPE;
        }
        // 必須 EventData field の検証。
        if !has_required_security_fields(event_id, content) {
            return EVENT_LOGGED_TYPE;
        }
        return match event_id {
            4624 => LOGIN_TYPE,
            4625 => LOGIN_FAILURE_TYPE,
            4688 => PROCESS_START_TYPE,
            4689 => PROCESS_STOP_TYPE,
            _ => EVENT_LOGGED_TYPE,
        };
    }

    // 7045: System + Service Control Manager。
    if event_id == 7045 {
        if !eq_ascii_ci(channel, "System") {
            return EVENT_LOGGED_TYPE;
        }
        // provider は "Service Control Manager" の他に GUID 形式でも運用される。
        // 安全側へ倒すため、文字列表現の一致だけで判定する。
        if !eq_ascii_ci(provider, "Service Control Manager") {
            return EVENT_LOGGED_TYPE;
        }
        if !has_required_service_create_fields(content) {
            return EVENT_LOGGED_TYPE;
        }
        return SERVICE_CREATE_TYPE;
    }

    EVENT_LOGGED_TYPE
}

/// 4624/4625/4688/4689 の必須 EventData field が揃っているか。
///
/// 互換 §5 EVTX 必須 field（provider・channel・record ID・Event ID・computer・event time・raw data）
/// は record header と System 要素から既に抽出済み。EventData の必須 field は typed mapping
/// 毎に異なる:
/// - 4624/4625: `TargetUserName`（または同等の logon subject）
/// - 4688/4689: `NewProcessName`（4688）/ `ProcessName`（4689）相当の process path
fn has_required_security_fields(event_id: i32, content: &EventContent) -> bool {
    let names: std::collections::BTreeSet<&str> =
        content.event_data.iter().map(|(n, _)| n.as_str()).collect();
    match event_id {
        4624 | 4625 => {
            // SubjectUserName/TargetUserName のいずれかが存在すれば可。
            names.contains("SubjectUserName")
                || names.contains("TargetUserName")
                || names.contains("AuthenticationPackageName")
        }
        4688 => {
            // NewProcessName または同等の process name。
            names.contains("NewProcessName")
                || names.contains("ProcessName")
                || names.contains("Image")
        }
        4689 => {
            names.contains("ProcessName")
                || names.contains("Image")
                || names.contains("NewProcessName")
        }
        _ => false,
    }
}

/// 7045 の必須 EventData field が揃っているか。
fn has_required_service_create_fields(content: &EventContent) -> bool {
    let names: std::collections::BTreeSet<&str> =
        content.event_data.iter().map(|(n, _)| n.as_str()).collect();
    // ServiceType と ImagePath（または ServiceName）のいずれかがあれば可。
    names.contains("ServiceName") || names.contains("ServiceType") || names.contains("ImagePath")
}

/// ASCII 大文字小文字を区別せず文字列比較する。
fn eq_ascii_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evtx::binxml::EventDataValue;

    fn content(
        event_id: Option<i32>,
        channel: Option<&str>,
        provider: Option<&str>,
        event_data: Vec<(&str, EventDataValue)>,
    ) -> EventContent {
        EventContent {
            event_id,
            version: None,
            level: None,
            opcode: None,
            provider_name: provider.map(String::from),
            provider_guid: None,
            channel: channel.map(String::from),
            computer: None,
            event_data: event_data
                .into_iter()
                .map(|(n, v)| (n.to_string(), v))
                .collect(),
            task: None,
            keywords: None,
        }
    }

    #[test]
    fn map_4624_with_valid_context() {
        let c = content(
            Some(4624),
            Some("Security"),
            Some("Microsoft-Windows-Security-Auditing"),
            vec![("TargetUserName", EventDataValue::Str("alice".into()))],
        );
        assert_eq!(map_event_type(&c), LOGIN_TYPE);
    }

    #[test]
    fn map_4625_with_valid_context() {
        let c = content(
            Some(4625),
            Some("Security"),
            Some("Microsoft-Windows-Security-Auditing"),
            vec![("TargetUserName", EventDataValue::Str("bob".into()))],
        );
        assert_eq!(map_event_type(&c), LOGIN_FAILURE_TYPE);
    }

    #[test]
    fn map_4688_with_valid_context() {
        let c = content(
            Some(4688),
            Some("Security"),
            Some("Microsoft-Windows-Security-Auditing"),
            vec![(
                "NewProcessName",
                EventDataValue::Str("C:\\Windows\\System32\\cmd.exe".into()),
            )],
        );
        assert_eq!(map_event_type(&c), PROCESS_START_TYPE);
    }

    #[test]
    fn map_4689_with_valid_context() {
        let c = content(
            Some(4689),
            Some("Security"),
            Some("Microsoft-Windows-Security-Auditing"),
            vec![(
                "ProcessName",
                EventDataValue::Str("C:\\Windows\\System32\\cmd.exe".into()),
            )],
        );
        assert_eq!(map_event_type(&c), PROCESS_STOP_TYPE);
    }

    #[test]
    fn map_7045_with_valid_context() {
        let c = content(
            Some(7045),
            Some("System"),
            Some("Service Control Manager"),
            vec![("ServiceName", EventDataValue::Str("svc1".into()))],
        );
        assert_eq!(map_event_type(&c), SERVICE_CREATE_TYPE);
    }

    #[test]
    fn fallback_when_channel_mismatches() {
        // 4624 だが channel が Security 以外 → 汎用へ。
        let c = content(
            Some(4624),
            Some("Application"),
            Some("Microsoft-Windows-Security-Auditing"),
            vec![("TargetUserName", EventDataValue::Str("alice".into()))],
        );
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn fallback_when_provider_mismatches() {
        let c = content(
            Some(4624),
            Some("Security"),
            Some("SomeOtherProvider"),
            vec![("TargetUserName", EventDataValue::Str("alice".into()))],
        );
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn fallback_when_required_field_missing() {
        let c = content(
            Some(4624),
            Some("Security"),
            Some("Microsoft-Windows-Security-Auditing"),
            vec![],
        );
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn fallback_when_event_id_unknown() {
        let c = content(Some(9999), Some("Security"), Some("X"), vec![]);
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn fallback_when_event_id_none() {
        let c = content(None, Some("Security"), Some("X"), vec![]);
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn case_insensitive_provider_match() {
        // 大文字小文字違い。
        let c = content(
            Some(4624),
            Some("security"),
            Some("microsoft-windows-security-auditing"),
            vec![("TargetUserName", EventDataValue::Str("a".into()))],
        );
        assert_eq!(map_event_type(&c), LOGIN_TYPE);
    }

    #[test]
    fn powershell_operational_falls_back_to_generic() {
        // T4-044: PowerShell Operational は typed mapping しない（汎用保持）。
        let c = content(
            Some(4103),
            Some("Microsoft-Windows-PowerShell/Operational"),
            Some("Microsoft-Windows-PowerShell"),
            vec![],
        );
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }

    #[test]
    fn sysmon_operational_falls_back_to_generic() {
        let c = content(
            Some(1),
            Some("Microsoft-Windows-Sysmon/Operational"),
            Some("Microsoft-Windows-Sysmon"),
            vec![],
        );
        assert_eq!(map_event_type(&c), EVENT_LOGGED_TYPE);
    }
}
