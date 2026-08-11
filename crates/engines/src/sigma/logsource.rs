//! Sigma logsource routing（互換 §6.1、T5-012）。
//!
//! Sigma `logsource` block（`product`・`category`・`service`）から
//! TraceForge Event への routing 条件を構築する。

use serde_json::Value;

use crate::sigma::rule::LogsourceSpec;

/// logsource から決定した routing 条件。
///
/// Sigma Rule はこの条件を満たす Event に対してのみ評価される。
#[derive(Clone, Debug)]
pub struct LogsourceRouting {
    /// `product: windows` でなければならない（互換 §6.1: TF は Windows Evidence 専用）。
    pub is_windows: bool,
    /// EVTX channel 条件（`service: security` → `Security` 等）。
    pub channel: Option<String>,
    /// event_type 条件（`category: process_creation` → `process_start` 等）。
    pub event_type: Option<String>,
    /// routing 判定の根拠（Manifest・Match の logsource_mapping へ記録）。
    pub routing_reason: String,
}

/// logsource block から routing 条件を構築する。
///
/// 互換 §6.1 に基づき Sigma `service`・`category` を TF EVTX channel・event_type へ
/// mapping する。対応表にない service・category は routing 条件へ追加せず、
/// `product: windows` のみを条件とする（過剰な制限を避けるため）。
pub fn build_routing(logsource: &LogsourceSpec) -> LogsourceRouting {
    let is_windows = logsource
        .product
        .as_deref()
        .map(|p| p.eq_ignore_ascii_case("windows"))
        .unwrap_or(false);

    // service → EVTX channel（Sigma 共通 naming convention）
    let channel = logsource.service.as_deref().and_then(service_to_channel);

    // category → event_type（TF typed mapping と整合）
    let event_type = logsource
        .category
        .as_deref()
        .and_then(category_to_event_type);

    let mut reason_parts = Vec::new();
    if let Some(p) = &logsource.product {
        reason_parts.push(format!("product={p}"));
    }
    if let Some(c) = &logsource.category {
        reason_parts.push(format!("category={c}"));
    }
    if let Some(s) = &logsource.service {
        reason_parts.push(format!("service={s}"));
    }
    let routing_reason = reason_parts.join(", ");

    LogsourceRouting {
        is_windows,
        channel,
        event_type,
        routing_reason,
    }
}

/// Sigma `service` を EVTX channel 名へ mapping する。
///
/// Sigma 共通 naming convention に基づく。対応していない service は `None`。
fn service_to_channel(service: &str) -> Option<String> {
    let channel = match service.to_lowercase().as_str() {
        "security" => "Security",
        "system" => "System",
        "application" => "Application",
        "powershell" | "powershell-classic" => "Windows PowerShell",
        "powershell-operational" | "powershell_operational" => {
            "Microsoft-Windows-PowerShell/Operational"
        }
        "sysmon" | "sysmon-operational" => "Microsoft-Windows-Sysmon/Operational",
        "terminalservices-localsessman" | "terminalservices-remotesessionmanager" => {
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
        }
        "windefend" => "Microsoft-Windows-Windows Defender/Operational",
        "wmi" => "Microsoft-Windows-WMI-Activity/Operational",
        "taskscheduler" => "Microsoft-Windows-TaskScheduler/Operational",
        "driver-framework" => "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        "ntfs" => "Microsoft-Windows-Ntfs/Operational",
        "dnsevents" | "dns-server" | "dns-client" => "DNS Client",
        "firewall-asy" | "firewall-as" => {
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        }
        "microsoft-servicebus-client" => "Microsoft-ServiceBus-Client",
        "bitlocker" => "Microsoft-Windows-BitLocker/BitLocker Management",
        "printservice-operational" => "Microsoft-Windows-PrintService/Operational",
        "applocker" => "Microsoft-Windows-AppLocker/EXE and DLL",
        "appxdeployment-server" => "Microsoft-Windows-AppXDeploymentServer/Operational",
        "certificateservicesclient-lifecycle-system" => {
            "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"
        }
        _ => return None,
    };
    Some(channel.to_string())
}

/// Sigma `category` を TF event_type へ mapping する。
///
/// TF の typed mapping（互換 §4.2）と整合するよう、Sigma category を
/// TF event_type 文字列へ変換する。対応していない category は `None`。
fn category_to_event_type(category: &str) -> Option<String> {
    let event_type = match category {
        "process_creation" => "process_start",
        "process_termination" => "process_stop",
        _ => return None,
    };
    Some(event_type.to_string())
}

/// Event が routing 条件を満たすか評価する。
///
/// - `is_windows` は常に true でなければならない（product が windows 以外なら
///   Rule 全体が評価対象外）。
/// - `channel` が指定されていれば、Event の `attributes.evtx.channel` と
///   大文字小文字区別なしで一致する必要がある。
/// - `event_type` が指定されていれば、Event の `event_type` と一致する必要がある。
pub fn matches_event(
    routing: &LogsourceRouting,
    event_attrs: &std::collections::BTreeMap<String, Value>,
    event_type: &str,
) -> bool {
    if !routing.is_windows {
        return false;
    }

    if let Some(required_channel) = &routing.channel {
        let actual = event_attrs.get("evtx.channel").and_then(|v| v.as_str());
        match actual {
            Some(ch) if ch.eq_ignore_ascii_case(required_channel) => {}
            _ => return false,
        }
    }

    if let Some(required_type) = &routing.event_type
        && event_type != required_type
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::rule::LogsourceSpec;

    fn build(
        product: Option<&str>,
        category: Option<&str>,
        service: Option<&str>,
    ) -> LogsourceRouting {
        build_routing(&LogsourceSpec {
            product: product.map(String::from),
            category: category.map(String::from),
            service: service.map(String::from),
            definition: None,
        })
    }

    #[test]
    fn windows_product_accepted() {
        let r = build(Some("windows"), None, None);
        assert!(r.is_windows);
    }

    #[test]
    fn linux_product_rejected() {
        let r = build(Some("linux"), None, None);
        assert!(!r.is_windows);
    }

    #[test]
    fn service_security_maps_to_security_channel() {
        let r = build(Some("windows"), None, Some("security"));
        assert_eq!(r.channel.as_deref(), Some("Security"));
    }

    #[test]
    fn service_sysmon_maps_to_sysmon_channel() {
        let r = build(Some("windows"), None, Some("sysmon"));
        assert_eq!(
            r.channel.as_deref(),
            Some("Microsoft-Windows-Sysmon/Operational")
        );
    }

    #[test]
    fn category_process_creation_maps_to_process_start() {
        let r = build(Some("windows"), Some("process_creation"), None);
        assert_eq!(r.event_type.as_deref(), Some("process_start"));
    }

    #[test]
    fn unknown_service_no_channel_constraint() {
        let r = build(Some("windows"), None, Some("custom_app"));
        assert!(r.channel.is_none(), "unknown service should not constrain");
    }

    #[test]
    fn unknown_category_no_event_type_constraint() {
        let r = build(Some("windows"), Some("custom_category"), None);
        assert!(r.event_type.is_none());
    }
}
