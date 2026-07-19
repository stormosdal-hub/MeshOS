//! Reading the operating system's ARP / neighbor cache.
//!
//! After a connect sweep, the kernel has L2-resolved every reachable host on
//! the local segment, so its neighbor table is an unprivileged source of
//! IP → MAC mappings. This is the fallback path that works without raw sockets;
//! the optional `raw-arp` feature can additionally send active ARP requests.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Returns a map of IPv4 → MAC (lowercase, colon-separated) from the OS cache.
pub fn neighbor_table() -> HashMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    {
        linux_proc_arp().unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        arp_command().unwrap_or_default()
    }
}

#[cfg(target_os = "linux")]
fn linux_proc_arp() -> Option<HashMap<Ipv4Addr, String>> {
    // Format of /proc/net/arp:
    // IP address       HW type   Flags  HW address         Mask  Device
    // 192.168.1.1      0x1       0x2    44:38:39:ff:aa:01  *     eth0
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    let mut map = HashMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let ip: Ipv4Addr = match cols[0].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let mac = cols[3].to_ascii_lowercase();
        if is_valid_mac(&mac) {
            map.insert(ip, mac);
        }
    }
    Some(map)
}

/// Parse `arp -a` output on macOS / Windows.
#[cfg(not(target_os = "linux"))]
fn arp_command() -> Option<HashMap<Ipv4Addr, String>> {
    use std::process::Command;
    let out = Command::new("arp").arg("-a").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = HashMap::new();
    for line in text.lines() {
        // Tokens vary by OS, but an IP-in-parens and a MAC-looking token are
        // both present on the matching lines; scan generically.
        let mut ip: Option<Ipv4Addr> = None;
        let mut mac: Option<String> = None;
        for raw in line.split_whitespace() {
            let tok = raw.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none() {
                if let Ok(parsed) = tok.parse::<Ipv4Addr>() {
                    ip = Some(parsed);
                    continue;
                }
            }
            let candidate = normalize_windows_mac(tok);
            if mac.is_none() && is_valid_mac(&candidate) {
                mac = Some(candidate);
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            map.insert(ip, mac);
        }
    }
    Some(map)
}

#[cfg(not(target_os = "linux"))]
fn normalize_windows_mac(tok: &str) -> String {
    // Windows prints MACs as aa-bb-cc-dd-ee-ff; normalize to colons.
    tok.replace('-', ":").to_ascii_lowercase()
}

fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    if parts.iter().all(|p| p == &"00") {
        return false; // incomplete entry
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}
