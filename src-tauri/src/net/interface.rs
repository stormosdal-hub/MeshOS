//! Local interface enumeration and selection (cross-platform via `netdev`).

use crate::model::NetInterface;
use std::net::Ipv4Addr;

/// The interface MeshOS will sweep, resolved to the fields the scanner needs.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub local_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub local_mac: Option<String>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub gateway_mac: Option<String>,
}

/// All non-loopback interfaces, for the UI picker.
pub fn list_interfaces() -> Vec<NetInterface> {
    let default_name = netdev::get_default_interface().ok().map(|i| i.name);
    netdev::get_interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| {
            let v4 = i.ipv4.first();
            NetInterface {
                is_default: default_name.as_deref() == Some(i.name.as_str()),
                name: i.name.clone(),
                friendly_name: i.friendly_name.clone(),
                ipv4: v4.map(|n| n.addr().to_string()),
                prefix_len: v4.map(|n| n.prefix_len()),
                mac: i.mac_addr.map(|m| m.to_string()),
                gateway_ip: i
                    .gateway
                    .as_ref()
                    .and_then(|g| g.ipv4.first())
                    .map(|ip| ip.to_string()),
            }
        })
        .collect()
}

/// Resolve a scan target by interface name, or the OS default route if `None`.
pub fn resolve_target(name: Option<&str>) -> Result<ScanTarget, String> {
    let chosen = match name {
        Some(n) => netdev::get_interfaces()
            .into_iter()
            .find(|i| i.name == n)
            .ok_or_else(|| format!("interface '{n}' not found"))?,
        None => netdev::get_default_interface().map_err(|e| e.to_string())?,
    };

    let v4 = chosen
        .ipv4
        .first()
        .ok_or_else(|| format!("interface '{}' has no IPv4 address", chosen.name))?;

    let gateway_ip = chosen
        .gateway
        .as_ref()
        .and_then(|g| g.ipv4.first())
        .copied();
    let gateway_mac = chosen.gateway.as_ref().map(|g| g.mac_addr.to_string());

    Ok(ScanTarget {
        local_ip: v4.addr(),
        prefix_len: v4.prefix_len(),
        local_mac: chosen.mac_addr.map(|m| m.to_string()),
        gateway_ip,
        gateway_mac,
    })
}

/// Enumerate host IPs in the target's subnet (excluding network & broadcast),
/// capped so an over-wide prefix can't spawn an enormous sweep.
pub fn subnet_hosts(target: &ScanTarget) -> (String, Vec<Ipv4Addr>) {
    let prefix = target.prefix_len.clamp(20, 32); // cap breadth at /20 (4094 hosts)
    let ip_u32 = u32::from(target.local_ip);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    let cidr = format!("{}/{}", Ipv4Addr::from(network), prefix);

    // Bound the sweep so a wide prefix can't spawn an unreasonable number of
    // probes. Typical home /24s (254 hosts) are unaffected.
    const MAX_HOSTS: usize = 1024;

    let mut hosts = Vec::new();
    let (start, end) = if prefix >= 31 {
        (network, broadcast) // point-to-point: both usable
    } else {
        (network + 1, broadcast.saturating_sub(1))
    };
    let mut h = start;
    while h <= end && hosts.len() < MAX_HOSTS {
        hosts.push(Ipv4Addr::from(h));
        h += 1;
    }
    (cidr, hosts)
}
