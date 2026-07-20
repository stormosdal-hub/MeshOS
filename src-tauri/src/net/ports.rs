//! TCP ports probed during discovery, and their human-readable service names.

/// Full set of ports probed on a host once it's known to be alive. Chosen to
/// identify device category and running services (web, remote access, DBs,
/// print, media, IoT, gaming), plus a handful of known backdoor/RAT ports so
/// the anomaly engine can actually observe them.
pub const PROBE_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    110,   // POP3
    111,   // RPC
    135,   // MSRPC (Windows)
    139,   // NetBIOS
    143,   // IMAP
    389,   // LDAP
    443,   // HTTPS
    445,   // SMB
    515,   // LPD (printers)
    548,   // AFP (Apple file sharing)
    554,   // RTSP (cameras)
    587,   // SMTP submission
    631,   // IPP (printers)
    993,   // IMAPS
    995,   // POP3S
    1433,  // Microsoft SQL Server
    1883,  // MQTT (IoT)
    3000,  // HTTP (dev servers, Grafana)
    3306,  // MySQL / MariaDB
    3389,  // RDP
    5000,  // UPnP / HTTP (NAS, Synology)
    5001,  // Synology HTTPS
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis
    7000,  // AirPlay / misc
    8009,  // Chromecast
    8080,  // HTTP-alt
    8081,  // HTTP-alt
    8123,  // Home Assistant
    8443,  // HTTPS-alt
    8888,  // HTTP-alt (Jupyter, etc.)
    9000,  // HTTP (PHP-FPM, SonarQube)
    9090,  // HTTP (Prometheus, Cockpit)
    9100,  // RAW / JetDirect print
    9200,  // Elasticsearch
    27017, // MongoDB
    32400, // Plex media server
    49152, // UPnP
    62078, // iPhone sync (iOS)
    // Known backdoor / RAT listeners (see SUSPICIOUS_PORTS):
    1337, 4444, 5555, 6667, 12345, 31337,
];

/// A small subset used for a fast first-pass liveness check across the whole
/// subnet. Full [`PROBE_PORTS`] then run only against hosts found alive here,
/// keeping wide scans quick. Every entry is also in [`PROBE_PORTS`].
pub const LIVENESS_PORTS: &[u16] = &[80, 443, 22, 445, 53, 139, 8080, 3389, 5000, 62078];

/// Ports that strongly suggest something unusual — common backdoor / RAT /
/// exploitation listeners. Presence raises a device's baseline risk.
pub const SUSPICIOUS_PORTS: &[u16] = &[1337, 4444, 5555, 6667, 12345, 31337];

/// Best-effort IANA-ish service label for a port.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        515 => "LPD",
        548 => "AFP",
        554 => "RTSP",
        587 => "SMTP",
        631 => "IPP",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1883 => "MQTT",
        3000 => "HTTP",
        3306 => "MySQL",
        3389 => "RDP",
        5000 => "UPnP",
        5001 => "HTTPS",
        5432 => "PostgreSQL",
        5555 => "ADB",
        5900 => "VNC",
        6379 => "Redis",
        6667 => "IRC",
        7000 => "AirPlay",
        8009 => "Cast",
        8080 => "HTTP",
        8081 => "HTTP",
        8123 => "Home Assistant",
        8443 => "HTTPS",
        8888 => "HTTP",
        9000 => "HTTP",
        9090 => "HTTP",
        9100 => "Print",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        32400 => "Plex",
        49152 => "UPnP",
        62078 => "iOS-sync",
        _ => return None,
    })
}
