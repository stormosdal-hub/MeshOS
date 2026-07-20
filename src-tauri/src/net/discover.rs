//! The network sweep: unprivileged TCP-connect liveness + port probe, merged
//! with the OS ARP/neighbor cache and reverse DNS, then classified and scored.
//! Results stream to the frontend as Tauri events.

use crate::ai::classify;
use crate::model::{
    events, now_ms, Device, DeviceKind, DeviceOfflineEvent, ScanProgress, ScanStateEvent,
    ServiceBanner,
};
use crate::net::{arp, fingerprint, interface, mdns, oui, ports, ssdp};
use crate::state::AppState;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_INFLIGHT: usize = 400;
const HOSTNAME_CONCURRENCY: usize = 64;
const RESCAN_INTERVAL: Duration = Duration::from_secs(10);
/// How long mDNS and SSDP listen for announcements each sweep.
const DISCOVERY_WINDOW: Duration = Duration::from_secs(3);

struct HostProbe {
    ip: Ipv4Addr,
    up: bool,
    open_ports: Vec<u16>,
    rtt_ms: Option<u32>,
}

/// A MAC that is present and not the all-zero placeholder.
fn is_real_mac(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex.len() == 12 && hex.chars().any(|c| c != '0')
}

fn emit_progress(app: &AppHandle, phase: &'static str, scanned: u32, total: u32, message: String) {
    let _ = app.emit(
        events::PROGRESS,
        ScanProgress {
            phase,
            scanned,
            total,
            message,
        },
    );
}

/// TCP-connect probe of the given hosts × ports, bounded by a semaphore.
/// A successful connect marks the port open; a refused connect still proves the
/// host is up (reachable at L2/L3) even though that port is closed.
async fn probe_ports(hosts: &[Ipv4Addr], probe: &[u16]) -> HashMap<Ipv4Addr, HostProbe> {
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let mut set: JoinSet<Option<(Ipv4Addr, Option<u16>, u32)>> = JoinSet::new();

    for &ip in hosts {
        for &port in probe {
            let sem = sem.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let start = Instant::now();
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                let result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
                let elapsed = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
                match result {
                    Ok(Ok(_stream)) => Some((ip, Some(port), elapsed)), // port open
                    Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                        Some((ip, None, elapsed)) // host up, port closed
                    }
                    _ => None, // timeout / unreachable / filtered
                }
            });
        }
    }

    let mut map: HashMap<Ipv4Addr, HostProbe> = HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some((ip, port, elapsed))) = joined {
            let entry = map.entry(ip).or_insert(HostProbe {
                ip,
                up: false,
                open_ports: Vec::new(),
                rtt_ms: None,
            });
            entry.up = true;
            if let Some(p) = port {
                entry.open_ports.push(p);
            }
            entry.rtt_ms = Some(match entry.rtt_ms {
                Some(r) => r.min(elapsed),
                None => elapsed,
            });
        }
    }
    map
}

/// Two-phase sweep: a fast liveness pass with a few ports across every host,
/// then the full port set against only the hosts found alive. This keeps a wide
/// port list cheap — dead/absent addresses are never deep-scanned.
async fn sweep(hosts: &[Ipv4Addr]) -> HashMap<Ipv4Addr, HostProbe> {
    let phase1 = probe_ports(hosts, ports::LIVENESS_PORTS).await;
    let live: Vec<Ipv4Addr> = phase1.values().filter(|p| p.up).map(|p| p.ip).collect();

    let mut result = probe_ports(&live, ports::PROBE_PORTS).await;

    // Fold phase-1 findings (liveness + RTT + any open ports) back in.
    for (ip, p1) in phase1 {
        let entry = result.entry(ip).or_insert(HostProbe {
            ip,
            up: p1.up,
            open_ports: Vec::new(),
            rtt_ms: None,
        });
        entry.up = entry.up || p1.up;
        if let Some(r1) = p1.rtt_ms {
            entry.rtt_ms = Some(entry.rtt_ms.map_or(r1, |r| r.min(r1)));
        }
        for p in p1.open_ports {
            if !entry.open_ports.contains(&p) {
                entry.open_ports.push(p);
            }
        }
    }

    for hp in result.values_mut() {
        hp.open_ports.sort_unstable();
        hp.open_ports.dedup();
    }
    result
}

/// Best-effort reverse DNS for the live hosts.
async fn resolve_hostnames(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let sem = Arc::new(Semaphore::new(HOSTNAME_CONCURRENCY));
    let mut set: JoinSet<Option<(Ipv4Addr, String)>> = JoinSet::new();

    for &ip in ips {
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let name = tokio::task::spawn_blocking(move || {
                dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()
            })
            .await
            .ok()
            .flatten()?;
            if name.is_empty() || name == ip.to_string() {
                None
            } else {
                Some((ip, name))
            }
        });
    }

    let mut map = HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some((ip, name))) = joined {
            map.insert(ip, name);
        }
    }
    map
}

/// Fingerprint each live host's open ports concurrently, returning banners.
async fn fingerprint_hosts(
    probes: &HashMap<Ipv4Addr, HostProbe>,
    live: &[Ipv4Addr],
) -> HashMap<Ipv4Addr, Vec<ServiceBanner>> {
    let mut set: JoinSet<(Ipv4Addr, Vec<ServiceBanner>)> = JoinSet::new();
    for &ip in live {
        let ports: Vec<u16> = probes
            .get(&ip)
            .map(|p| p.open_ports.clone())
            .unwrap_or_default();
        if ports.is_empty() {
            continue;
        }
        set.spawn(async move { (ip, fingerprint::fingerprint(ip, &ports).await) });
    }

    let mut out = HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((ip, banners)) = joined {
            if !banners.is_empty() {
                out.insert(ip, banners);
            }
        }
    }
    out
}

/// Perform one full discovery pass and emit results.
pub async fn scan_once(
    app: &AppHandle,
    state: &Arc<AppState>,
    iface_name: Option<String>,
) -> Result<(), String> {
    emit_progress(app, "interfaces", 0, 0, "Resolving interface…".into());
    let target = interface::resolve_target(iface_name.as_deref())?;
    let (cidr, hosts) = interface::subnet_hosts(&target);
    let total = hosts.len() as u32;
    state.set_subnet(Some(cidr.clone()));
    let _ = app.emit(
        events::SCAN_STATE,
        ScanStateEvent {
            scanning: true,
            subnet: Some(cidr.clone()),
        },
    );

    emit_progress(
        app,
        "sweep",
        0,
        total,
        format!("Scanning {cidr} — {total} hosts (ports, mDNS, SSDP)"),
    );
    // Run the port sweep, SSDP, and mDNS concurrently, so the total time is
    // about the slowest of the three rather than their sum.
    let mdns_handle = tokio::task::spawn_blocking(|| mdns::discover(DISCOVERY_WINDOW));
    let (probes, ssdp_map) = tokio::join!(sweep(&hosts), ssdp::discover(DISCOVERY_WINDOW));
    let mdns_map = mdns_handle.await.unwrap_or_default();

    emit_progress(
        app,
        "resolve",
        total,
        total,
        "Reading ARP cache & resolving hostnames…".into(),
    );
    let arp_table = arp::neighbor_table();

    // Live = anything that answered a probe, plus ARP-cache hosts in-subnet,
    // plus this machine and the gateway.
    let host_set: HashSet<Ipv4Addr> = hosts.iter().copied().collect();
    let mut live: HashSet<Ipv4Addr> =
        probes.values().filter(|p| p.up).map(|p| p.ip).collect();
    for ip in arp_table.keys() {
        if host_set.contains(ip) {
            live.insert(*ip);
        }
    }
    live.insert(target.local_ip);
    if let Some(gw) = target.gateway_ip {
        live.insert(gw);
    }
    let live_vec: Vec<Ipv4Addr> = live.into_iter().collect();

    let names = resolve_hostnames(&live_vec).await;
    let banners = fingerprint_hosts(&probes, &live_vec).await;

    emit_progress(
        app,
        "classify",
        total,
        total,
        "Fingerprinting services & classifying…".into(),
    );
    let now = now_ms();
    let mut snapshot: HashMap<String, Device> = HashMap::new();
    {
        let existing = state.devices.lock().unwrap();
        for &ip in &live_vec {
            let is_local = ip == target.local_ip;
            let is_gateway = target.gateway_ip == Some(ip);
            let mac = arp_table.get(&ip).cloned().or_else(|| {
                if is_local {
                    target.local_mac.clone()
                } else if is_gateway {
                    target.gateway_mac.clone().filter(|m| is_real_mac(m))
                } else {
                    None
                }
            });
            let id = mac.clone().unwrap_or_else(|| ip.to_string());
            let vendor = mac.as_deref().and_then(oui::lookup_vendor);

            let mdns_info = mdns_map.get(&ip);
            let ssdp_info = ssdp_map.get(&ip);
            let hostname = names
                .get(&ip)
                .cloned()
                .or_else(|| mdns_info.and_then(|m| m.hostname.clone()));
            let model = mdns_info
                .and_then(|m| m.model.clone())
                .or_else(|| ssdp_info.and_then(|s| s.model.clone()));
            let mut services: Vec<String> = Vec::new();
            for svc in mdns_info
                .map(|m| m.services.as_slice())
                .unwrap_or(&[])
                .iter()
                .chain(ssdp_info.map(|s| s.services.as_slice()).unwrap_or(&[]))
            {
                if !services.contains(svc) {
                    services.push(svc.clone());
                }
            }
            let device_banners = banners.get(&ip).cloned().unwrap_or_default();

            let probe = probes.get(&ip);
            let open_ports = probe.map(|p| p.open_ports.clone()).unwrap_or_default();
            let rtt_ms = if is_local { Some(0) } else { probe.and_then(|p| p.rtt_ms) };

            let (first_seen, prior_threat) = match existing.get(&id) {
                Some(prev) => (prev.first_seen, prev.threat_score * 0.9), // cool down
                None => (now, 0.0),
            };

            let mut device = Device {
                id: id.clone(),
                ip: ip.to_string(),
                mac,
                hostname,
                vendor,
                kind: DeviceKind::Unknown,
                open_ports,
                is_gateway,
                is_local,
                online: true,
                first_seen,
                last_seen: now,
                rtt_ms,
                threat_score: prior_threat,
                labels: Vec::new(),
                model,
                services,
                banners: device_banners,
            };
            classify::classify(&mut device);
            snapshot.insert(id, device);
        }
    }

    // On-device anomaly analysis (mutates threat scores, returns new alerts).
    let observed_gw_mac = target
        .gateway_ip
        .and_then(|gw| arp_table.get(&gw).cloned())
        .or_else(|| target.gateway_mac.clone().filter(|m| is_real_mac(m)));
    let anomalies = {
        let mut engine = state.anomaly_engine.lock().unwrap();
        engine.analyze(&mut snapshot, &arp_table, target.gateway_ip, observed_gw_mac)
    };

    // Diff against the previous snapshot to find devices that dropped off.
    let previous_ids: HashSet<String> =
        state.devices.lock().unwrap().keys().cloned().collect();
    let current_ids: HashSet<String> = snapshot.keys().cloned().collect();

    *state.devices.lock().unwrap() = snapshot.clone();

    for device in snapshot.values() {
        let _ = app.emit(events::DEVICE_UPSERT, device);
    }
    for id in previous_ids.difference(&current_ids) {
        let _ = app.emit(events::DEVICE_OFFLINE, DeviceOfflineEvent { id: id.clone() });
    }
    for anomaly in &anomalies {
        let _ = app.emit(events::ANOMALY, anomaly);
    }

    emit_progress(
        app,
        "done",
        total,
        total,
        format!("{} devices online", current_ids.len()),
    );
    Ok(())
}

/// Continuous scan loop: repeats sweeps until `state.running` is cleared.
pub async fn scan_loop(app: AppHandle, state: Arc<AppState>, iface_name: Option<String>) {
    let _ = app.emit(
        events::SCAN_STATE,
        ScanStateEvent {
            scanning: true,
            subnet: state.subnet(),
        },
    );

    while state.is_running() {
        if let Err(e) = scan_once(&app, &state, iface_name.clone()).await {
            emit_progress(&app, "idle", 0, 0, format!("Scan error: {e}"));
        }
        // Interruptible wait between sweeps.
        let mut waited = Duration::ZERO;
        while state.is_running() && waited < RESCAN_INTERVAL {
            tokio::time::sleep(Duration::from_millis(250)).await;
            waited += Duration::from_millis(250);
        }
    }

    let _ = app.emit(
        events::SCAN_STATE,
        ScanStateEvent {
            scanning: false,
            subnet: state.subnet(),
        },
    );
}

/// Run a single immediate sweep (used by the `rescan` command).
pub async fn scan_now(app: AppHandle, state: Arc<AppState>, iface_name: Option<String>) {
    if let Err(e) = scan_once(&app, &state, iface_name).await {
        emit_progress(&app, "idle", 0, 0, format!("Scan error: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test the two-phase sweep against loopback. Prints what it finds;
    /// if the host runs any TCP service (ssh, a web server…), loopback shows up.
    #[tokio::test]
    async fn sweeps_loopback_without_panicking() {
        let map = sweep(&[Ipv4Addr::LOCALHOST]).await;
        match map.get(&Ipv4Addr::LOCALHOST) {
            Some(hp) => println!(
                "loopback up={} open_ports={:?} rtt={:?}",
                hp.up, hp.open_ports, hp.rtt_ms
            ),
            None => println!("loopback: no listening services detected"),
        }
    }
}
