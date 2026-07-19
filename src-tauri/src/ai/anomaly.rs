//! On-device anomaly detection.
//!
//! Runs entirely locally on each scan snapshot — no telemetry leaves the
//! machine. Detections are derived strictly from data we actually observe
//! (ARP/neighbor cache, open ports, topology), so alerts are explainable:
//!
//!  * `NewDevice`            — a host not present in the established baseline.
//!  * `ArpSpoof`             — the gateway IP now answers from a different MAC.
//!  * `GatewayImpersonation` — a non-gateway host claims the gateway's IP.
//!  * `UnexpectedService`    — a known backdoor/RAT port is listening.
//!  * `MacFlood`             — one MAC bound to many IPs (spoofing/flooding).
//!
//! State is remembered across scans so conditions alert once, not every sweep.

use crate::model::{now_ms, Anomaly, AnomalyKind, Device, Severity};
use crate::net::ports::SUSPICIOUS_PORTS;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

#[derive(Default)]
pub struct AnomalyEngine {
    initialized: bool,
    seen_ids: HashSet<String>,
    baseline_gateway_mac: Option<String>,
    alerted: HashSet<String>,
    counter: u64,
}

impl AnomalyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// True the first time a given signature is seen (dedupes repeat alerts).
    fn first_time(&mut self, signature: &str) -> bool {
        self.alerted.insert(signature.to_string())
    }

    fn make(
        &mut self,
        device_id: &str,
        kind: AnomalyKind,
        severity: Severity,
        title: &str,
        detail: String,
    ) -> Anomaly {
        self.counter += 1;
        Anomaly {
            id: format!("anom-{}-{}", now_ms(), self.counter),
            device_id: device_id.to_string(),
            kind,
            severity,
            title: title.to_string(),
            detail,
            timestamp: now_ms(),
            acknowledged: false,
        }
    }

    fn bump(devices: &mut HashMap<String, Device>, id: &str, delta: f32) {
        if let Some(d) = devices.get_mut(id) {
            d.threat_score = (d.threat_score + delta).clamp(0.0, 100.0);
        }
    }

    /// Analyze one scan snapshot. Mutates `threat_score` on affected devices
    /// and returns any newly-raised anomalies.
    pub fn analyze(
        &mut self,
        devices: &mut HashMap<String, Device>,
        arp: &HashMap<Ipv4Addr, String>,
        gateway_ip: Option<Ipv4Addr>,
        observed_gateway_mac: Option<String>,
    ) -> Vec<Anomaly> {
        let mut out = Vec::new();
        let first_run = !self.initialized;

        // --- ARP spoofing: gateway IP now maps to a different MAC ------------
        if let Some(gw_mac) = observed_gateway_mac.filter(|m| !m.is_empty()) {
            match self.baseline_gateway_mac.clone() {
                None => self.baseline_gateway_mac = Some(gw_mac),
                Some(base) if base != gw_mac => {
                    if self.first_time(&format!("gwmac:{gw_mac}")) {
                        if let Some(id) =
                            devices.values().find(|d| d.is_gateway).map(|d| d.id.clone())
                        {
                            Self::bump(devices, &id, 60.0);
                            let detail = format!(
                                "The gateway ({}) is now answering from MAC {gw_mac} (baseline was {base}). \
                                 This is a classic sign of ARP spoofing / a man-in-the-middle on the LAN.",
                                gateway_ip.map(|i| i.to_string()).unwrap_or_else(|| "?".into()),
                            );
                            out.push(self.make(
                                &id,
                                AnomalyKind::ArpSpoof,
                                Severity::Critical,
                                "Gateway MAC changed",
                                detail,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        // --- Gateway impersonation: a non-gateway host owns the gateway IP ---
        if let Some(gw) = gateway_ip {
            let gw_str = gw.to_string();
            let impostors: Vec<String> = devices
                .values()
                .filter(|d| d.ip == gw_str && !d.is_gateway)
                .map(|d| d.id.clone())
                .collect();
            for id in impostors {
                if self.first_time(&format!("gwimp:{id}")) {
                    Self::bump(devices, &id, 55.0);
                    out.push(self.make(
                        &id,
                        AnomalyKind::GatewayImpersonation,
                        Severity::Critical,
                        "Gateway impersonation",
                        format!("{gw_str} is the gateway address but this host is not the known router."),
                    ));
                }
            }
        }

        // --- MAC flooding: one MAC bound to many distinct IPs ---------------
        let mut mac_ips: HashMap<&String, HashSet<Ipv4Addr>> = HashMap::new();
        for (ip, mac) in arp {
            mac_ips.entry(mac).or_default().insert(*ip);
        }
        for (mac, ips) in &mac_ips {
            if ips.len() >= 5 {
                if let Some(id) = devices.values().find(|d| d.mac.as_ref() == Some(*mac)).map(|d| d.id.clone()) {
                    if self.first_time(&format!("macflood:{mac}")) {
                        Self::bump(devices, &id, 40.0);
                        out.push(self.make(
                            &id,
                            AnomalyKind::MacFlood,
                            Severity::High,
                            "MAC address flooding",
                            format!("MAC {mac} is claiming {} different IP addresses — possible spoofing or a flooding attack.", ips.len()),
                        ));
                    }
                }
            }
        }

        // --- Unexpected service: known backdoor/RAT port listening ----------
        let suspicious: Vec<(String, Vec<u16>)> = devices
            .values()
            .map(|d| {
                let ports: Vec<u16> = d
                    .open_ports
                    .iter()
                    .copied()
                    .filter(|p| SUSPICIOUS_PORTS.contains(p))
                    .collect();
                (d.id.clone(), ports)
            })
            .filter(|(_, p)| !p.is_empty())
            .collect();
        for (id, ports) in suspicious {
            for port in ports {
                if self.first_time(&format!("svc:{id}:{port}")) {
                    Self::bump(devices, &id, 15.0);
                    let ip = devices.get(&id).map(|d| d.ip.clone()).unwrap_or_default();
                    out.push(self.make(
                        &id,
                        AnomalyKind::UnexpectedService,
                        Severity::High,
                        "Suspicious service exposed",
                        format!("{ip} is listening on {port}/tcp, a port commonly used by backdoors and remote-access trojans."),
                    ));
                }
            }
        }

        // --- New device (only after a baseline exists) ----------------------
        if !first_run {
            let new_ids: Vec<String> = devices
                .keys()
                .filter(|id| !self.seen_ids.contains(*id))
                .cloned()
                .collect();
            for id in new_ids {
                if !self.first_time(&format!("new:{id}")) {
                    continue;
                }
                let (severity, ip, vendor_known, kind_unknown) = {
                    let d = &devices[&id];
                    (
                        if d.threat_score >= 30.0 || d.vendor.is_none() {
                            Severity::Medium
                        } else {
                            Severity::Low
                        },
                        d.ip.clone(),
                        d.vendor.is_some(),
                        matches!(d.kind, crate::model::DeviceKind::Unknown),
                    )
                };
                let note = if !vendor_known {
                    " Its MAC has no recognized vendor."
                } else if kind_unknown {
                    " MeshOS could not categorize it."
                } else {
                    ""
                };
                out.push(self.make(
                    &id,
                    AnomalyKind::NewDevice,
                    severity,
                    "New device joined",
                    format!("{ip} appeared on the network and was not part of the established baseline.{note}"),
                ));
            }
        }

        // Update baseline.
        self.seen_ids = devices.keys().cloned().collect();
        self.initialized = true;
        out
    }
}
