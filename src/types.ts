// Shared data model. These interfaces mirror the Rust structs in
// `src-tauri/src/model.rs`, which serialize with `rename_all = "camelCase"`.

export type DeviceKind =
  | "router"
  | "computer"
  | "mobile"
  | "smartHome"
  | "microcontroller"
  | "gamingRig"
  | "nas"
  | "printer"
  | "camera"
  | "tv"
  | "unknown";

export const DEVICE_KINDS: DeviceKind[] = [
  "router",
  "computer",
  "mobile",
  "smartHome",
  "microcontroller",
  "gamingRig",
  "nas",
  "printer",
  "camera",
  "tv",
  "unknown",
];

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Device {
  /** Stable identity: MAC when known, otherwise IP. */
  id: string;
  ip: string;
  mac: string | null;
  hostname: string | null;
  vendor: string | null;
  kind: DeviceKind;
  openPorts: number[];
  isGateway: boolean;
  /** True for the machine MeshOS is running on. */
  isLocal: boolean;
  online: boolean;
  firstSeen: number; // epoch ms
  lastSeen: number; // epoch ms
  rttMs: number | null;
  /** 0..100 rolling risk score from the on-device analyzer. */
  threatScore: number;
  /** Human-readable classifier tags, e.g. "mDNS", "HTTP", "IoT". */
  labels: string[];
}

export type AnomalyKind =
  | "portScan"
  | "newDevice"
  | "arpSpoof"
  | "gatewayImpersonation"
  | "unusualOutbound"
  | "macFlood"
  | "unexpectedService";

export interface Anomaly {
  id: string;
  deviceId: string;
  kind: AnomalyKind;
  severity: Severity;
  title: string;
  detail: string;
  timestamp: number; // epoch ms
  acknowledged: boolean;
}

export interface NetInterface {
  name: string;
  friendlyName: string | null;
  ipv4: string | null;
  prefixLen: number | null;
  mac: string | null;
  gatewayIp: string | null;
  isDefault: boolean;
}

export type ScanPhase =
  | "idle"
  | "interfaces"
  | "sweep"
  | "resolve"
  | "classify"
  | "done";

export interface ScanProgress {
  phase: ScanPhase;
  scanned: number;
  total: number;
  message: string;
}

// ---- Backend event channel -------------------------------------------------
// The Rust core streams these events to the webview (Tauri's event system acts
// as the "websocket-like channel" described in the blueprint).

export const EVENTS = {
  progress: "scan://progress",
  deviceUpsert: "device://upsert",
  deviceOffline: "device://offline",
  anomaly: "anomaly://detected",
  scanState: "scan://state",
} as const;

export interface ScanStateEvent {
  scanning: boolean;
  subnet: string | null;
}

export interface DeviceOfflineEvent {
  id: string;
}

/** A listening server on the machine running MeshOS (see `net::local` in Rust). */
export interface LocalService {
  address: string;
  port: number;
  protocol: string;
  pid: number | null;
  process: string | null;
  service: string | null;
}
