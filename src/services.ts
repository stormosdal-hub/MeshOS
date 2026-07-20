// Port → service label, mirroring `service_name()` in
// src-tauri/src/net/ports.rs. Used to annotate open ports in the UI.

export const PORT_SERVICES: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  111: "RPC",
  135: "MSRPC",
  139: "NetBIOS",
  143: "IMAP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  515: "LPD",
  548: "AFP",
  554: "RTSP",
  587: "SMTP",
  631: "IPP",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1883: "MQTT",
  3000: "HTTP",
  3306: "MySQL",
  3389: "RDP",
  5000: "UPnP",
  5001: "HTTPS",
  5432: "PostgreSQL",
  5555: "ADB",
  5900: "VNC",
  6379: "Redis",
  6667: "IRC",
  7000: "AirPlay",
  8009: "Cast",
  8080: "HTTP",
  8081: "HTTP",
  8123: "Home Assistant",
  8443: "HTTPS",
  8888: "HTTP",
  9000: "HTTP",
  9090: "HTTP",
  9100: "Print",
  9200: "Elasticsearch",
  27017: "MongoDB",
  32400: "Plex",
  49152: "UPnP",
  62078: "iOS-sync",
};

/** Known backdoor / RAT ports — highlighted as risky in the UI. */
export const SUSPICIOUS_PORTS = new Set<number>([
  1337, 4444, 5555, 6667, 12345, 31337,
]);

export function serviceName(port: number): string | null {
  return PORT_SERVICES[port] ?? null;
}
