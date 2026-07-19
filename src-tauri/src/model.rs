//! Shared data model. These types serialize to the exact shapes the frontend
//! expects (see `src/types.ts`); struct fields use `camelCase` to match.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceKind {
    Router,
    Computer,
    Mobile,
    SmartHome,
    Microcontroller,
    GamingRig,
    Nas,
    Printer,
    Camera,
    Tv,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AnomalyKind {
    PortScan,
    NewDevice,
    ArpSpoof,
    GatewayImpersonation,
    UnusualOutbound,
    MacFlood,
    UnexpectedService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// Stable identity: MAC when known, otherwise IP.
    pub id: String,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub kind: DeviceKind,
    pub open_ports: Vec<u16>,
    pub is_gateway: bool,
    pub is_local: bool,
    pub online: bool,
    pub first_seen: u64,
    pub last_seen: u64,
    pub rtt_ms: Option<u32>,
    pub threat_score: f32,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anomaly {
    pub id: String,
    pub device_id: String,
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub timestamp: u64,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetInterface {
    pub name: String,
    pub friendly_name: Option<String>,
    pub ipv4: Option<String>,
    pub prefix_len: Option<u8>,
    pub mac: Option<String>,
    pub gateway_ip: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub phase: &'static str,
    pub scanned: u32,
    pub total: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStateEvent {
    pub scanning: bool,
    pub subnet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceOfflineEvent {
    pub id: String,
}

// ---- Event channel names (must match `EVENTS` in src/types.ts) -------------
pub mod events {
    pub const PROGRESS: &str = "scan://progress";
    pub const DEVICE_UPSERT: &str = "device://upsert";
    pub const DEVICE_OFFLINE: &str = "device://offline";
    pub const ANOMALY: &str = "anomaly://detected";
    pub const SCAN_STATE: &str = "scan://state";
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
