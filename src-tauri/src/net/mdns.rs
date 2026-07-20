//! mDNS / DNS-SD (Bonjour) discovery. Many devices advertise their name,
//! model, and services over multicast DNS — an accurate, no-brute-force way to
//! identify Apple gear, Chromecasts, printers, HomeKit accessories, and more.
//!
//! Blocking (drives mdns-sd's daemon); call via `spawn_blocking`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

#[derive(Debug, Default, Clone)]
pub struct MdnsInfo {
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub services: Vec<String>,
}

/// (DNS-SD service type, friendly label).
const SERVICE_TYPES: &[(&str, &str)] = &[
    ("_http._tcp.local.", "HTTP"),
    ("_https._tcp.local.", "HTTPS"),
    ("_ipp._tcp.local.", "Printer"),
    ("_ipps._tcp.local.", "Printer"),
    ("_printer._tcp.local.", "Printer"),
    ("_airplay._tcp.local.", "AirPlay"),
    ("_raop._tcp.local.", "AirPlay"),
    ("_googlecast._tcp.local.", "Chromecast"),
    ("_spotify-connect._tcp.local.", "Spotify"),
    ("_ssh._tcp.local.", "SSH"),
    ("_smb._tcp.local.", "SMB"),
    ("_afpovertcp._tcp.local.", "AFP"),
    ("_hap._tcp.local.", "HomeKit"),
    ("_homekit._tcp.local.", "HomeKit"),
    ("_device-info._tcp.local.", "Device Info"),
    ("_workstation._tcp.local.", "Workstation"),
];

/// Browse common DNS-SD service types for `window`, collecting resolutions.
pub fn discover(window: Duration) -> HashMap<Ipv4Addr, MdnsInfo> {
    let mut result: HashMap<Ipv4Addr, MdnsInfo> = HashMap::new();
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(_) => return result,
    };

    let mut receivers = Vec::new();
    for (service_type, label) in SERVICE_TYPES {
        if let Ok(rx) = daemon.browse(service_type) {
            receivers.push((rx, *label));
        }
    }

    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        let mut any = false;
        for (rx, label) in &receivers {
            while let Ok(event) = rx.try_recv() {
                any = true;
                if let ServiceEvent::ServiceResolved(info) = event {
                    ingest(&mut result, &info, label);
                }
            }
        }
        if !any {
            std::thread::sleep(Duration::from_millis(60));
        }
    }

    let _ = daemon.shutdown();
    result
}

fn ingest(result: &mut HashMap<Ipv4Addr, MdnsInfo>, info: &ServiceInfo, label: &str) {
    let friendly = info
        .get_fullname()
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let host = info
        .get_hostname()
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let model = info
        .get_property_val_str("model")
        .or_else(|| info.get_property_val_str("md"))
        .map(|s| s.to_string());
    let friendly_name = info.get_property_val_str("fn").map(|s| s.to_string());

    for addr in info.get_addresses() {
        let ip = match addr {
            IpAddr::V4(v4) => *v4,
            IpAddr::V6(_) => continue,
        };
        let entry = result.entry(ip).or_default();
        if !entry.services.iter().any(|s| s == label) {
            entry.services.push(label.to_string());
        }
        if entry.hostname.is_none() {
            entry.hostname = friendly_name
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| (!friendly.is_empty()).then(|| friendly.clone()))
                .or_else(|| (!host.is_empty()).then(|| host.clone()));
        }
        if entry.model.is_none() {
            entry.model = model.clone();
        }
    }
}
