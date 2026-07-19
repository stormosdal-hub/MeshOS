//! Device categorization from passive signals: OUI vendor, reverse-DNS
//! hostname, and observed open ports. This is the deterministic classifier;
//! it produces the `kind`, human labels, and a baseline risk contribution.
//!
//! The blueprint calls for a quantized ONNX model here. This module is the
//! feature/label front-end for that: it yields exactly the structured signals
//! (`kind`, `labels`, port/vendor features) an ONNX scorer would consume, so a
//! learned model can be layered on without changing the rest of the pipeline.

use crate::model::{Device, DeviceKind};
use crate::net::oui;
use crate::net::ports::{service_name, SUSPICIOUS_PORTS};

fn push_unique(labels: &mut Vec<String>, label: &str) {
    if !labels.iter().any(|l| l == label) {
        labels.push(label.to_string());
    }
}

/// Classify a device in place: sets `kind`, `labels`, and adds a baseline
/// contribution to `threat_score` for intrinsically risky signals.
pub fn classify(d: &mut Device) {
    let vendor = d.vendor.as_deref().unwrap_or("").to_lowercase();
    let host = d.hostname.as_deref().unwrap_or("").to_lowercase();
    let ports = d.open_ports.clone();
    let has = |p: u16| ports.contains(&p);

    // Service labels from open ports.
    let mut labels: Vec<String> = Vec::new();
    for p in &ports {
        if let Some(name) = service_name(*p) {
            push_unique(&mut labels, name);
        }
    }

    let kind = if d.is_gateway {
        DeviceKind::Router
    } else if host.contains("esp32") || host.contains("esp8266") || host.contains("esp-") {
        DeviceKind::Microcontroller
    } else if vendor.contains("espressif") {
        if has(1883)
            || host.contains("relay")
            || host.contains("switch")
            || host.contains("bulb")
            || host.contains("plug")
        {
            DeviceKind::SmartHome
        } else {
            DeviceKind::Microcontroller
        }
    } else if vendor.contains("raspberry") {
        DeviceKind::Computer
    } else if host.contains("iphone")
        || host.contains("ipad")
        || host.contains("android")
        || host.contains("pixel")
        || host.contains("galaxy")
        || host.contains("phone")
    {
        DeviceKind::Mobile
    } else if host.contains("ps5")
        || host.contains("ps4")
        || host.contains("xbox")
        || host.contains("nintendo")
        || host.contains("steam")
        || host.contains("battlestation")
        || has(27015)
    {
        DeviceKind::GamingRig
    } else if vendor.contains("sony interactive")
        || vendor.contains("nintendo")
        || (vendor.contains("microsoft") && !has(445))
    {
        DeviceKind::GamingRig
    } else if vendor.contains("synology")
        || vendor.contains("qnap")
        || host.contains("nas")
        || has(5001)
    {
        DeviceKind::Nas
    } else if has(9100)
        || has(631)
        || host.contains("printer")
        || vendor.contains("brother")
        || vendor.contains("canon")
        || vendor.contains("epson")
    {
        DeviceKind::Printer
    } else if has(554)
        || host.contains("cam")
        || vendor.contains("axis")
        || vendor.contains("hikvision")
        || vendor.contains("dahua")
        || vendor.contains("reolink")
    {
        DeviceKind::Camera
    } else if host.contains("tv")
        || host.contains("roku")
        || host.contains("chromecast")
        || host.contains("appletv")
        || has(8009)
        || (vendor.contains("samsung") && has(8080))
    {
        DeviceKind::Tv
    } else if vendor.contains("nest")
        || vendor.contains("google")
        || vendor.contains("amazon")
        || vendor.contains("philips")
        || vendor.contains("shelly")
        || vendor.contains("tuya")
        || vendor.contains("kasa")
        || vendor.contains("sonoff")
        || host.contains("thermostat")
        || host.contains("bulb")
        || host.contains("plug")
    {
        DeviceKind::SmartHome
    } else if vendor.contains("apple") {
        DeviceKind::Computer
    } else if vendor.contains("intel")
        || vendor.contains("dell")
        || vendor.contains("lenovo")
        || vendor.contains("asus")
        || vendor.contains("msi")
        || has(3389)
        || has(445)
    {
        DeviceKind::Computer
    } else {
        DeviceKind::Unknown
    };

    // Category labels.
    match kind {
        DeviceKind::Microcontroller => push_unique(&mut labels, "IoT"),
        DeviceKind::SmartHome => push_unique(&mut labels, "IoT"),
        DeviceKind::GamingRig => push_unique(&mut labels, "Gaming"),
        DeviceKind::Camera => push_unique(&mut labels, "Camera"),
        DeviceKind::Nas => push_unique(&mut labels, "Storage"),
        _ => {}
    }

    // Baseline risk contributions.
    let mut base_risk = 0.0f32;
    if ports.iter().any(|p| SUSPICIOUS_PORTS.contains(p)) {
        push_unique(&mut labels, "Suspicious port");
        base_risk += 35.0;
    }
    if kind == DeviceKind::Unknown {
        if d.mac.is_none() {
            base_risk += 8.0;
        } else if let Some(mac) = &d.mac {
            // A randomized MAC on an unknown device with open services is odd
            // (phones use them, but phones rarely expose listening ports).
            if oui::is_locally_administered(mac) && !ports.is_empty() {
                push_unique(&mut labels, "Randomized MAC");
                base_risk += 6.0;
            }
        }
        if d.vendor.is_none() {
            push_unique(&mut labels, "Unknown vendor");
        }
    }

    d.kind = kind;
    d.labels = labels;
    d.threat_score = (d.threat_score + base_risk).clamp(0.0, 100.0);
}
