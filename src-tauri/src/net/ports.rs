//! TCP ports probed during discovery, and their human-readable service names.

/// Ports probed on each host. Chosen to (a) reveal liveness quickly and
/// (b) hint at device category (print, RTSP, MQTT, SMB, gaming, …).
pub const PROBE_PORTS: &[u16] = &[
    22,    // SSH
    53,    // DNS
    80,    // HTTP
    139,   // NetBIOS
    443,   // HTTPS
    445,   // SMB
    554,   // RTSP (cameras)
    631,   // IPP (printers)
    1883,  // MQTT (IoT)
    3389,  // RDP
    5000,  // UPnP / HTTP (NAS, Synology)
    5001,  // Synology HTTPS
    8009,  // Chromecast
    8080,  // HTTP-alt
    8443,  // HTTPS-alt
    9100,  // RAW / JetDirect print
    27015, // Source engine / gaming
    32400, // Plex media server
    62078, // iPhone sync (iOS)
];

/// Ports that strongly suggest something unusual — common backdoor / RAT /
/// exploitation listeners. Presence raises a device's baseline risk.
pub const SUSPICIOUS_PORTS: &[u16] = &[
    1337, 4444, 5555, 6667, 12345, 31337,
];

/// Best-effort IANA-ish service label for a port.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "SSH",
        53 => "DNS",
        80 => "HTTP",
        139 => "NetBIOS",
        443 => "HTTPS",
        445 => "SMB",
        554 => "RTSP",
        631 => "IPP",
        1883 => "MQTT",
        3389 => "RDP",
        5000 => "UPnP",
        5001 => "HTTPS",
        8009 => "Cast",
        8080 => "HTTP",
        8443 => "HTTPS",
        9100 => "Print",
        27015 => "Gaming",
        32400 => "Plex",
        62078 => "iOS-sync",
        _ => return None,
    })
}
