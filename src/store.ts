import { create } from "zustand";
import type {
  Anomaly,
  Device,
  NetInterface,
  ScanProgress,
} from "./types";

interface MeshState {
  live: boolean;
  devices: Record<string, Device>;
  anomalies: Anomaly[];
  interfaces: NetInterface[];
  selectedInterface: string | null;
  progress: ScanProgress;
  scanning: boolean;
  subnet: string | null;
  selectedId: string | null;

  setLive: (live: boolean) => void;
  upsertDevice: (d: Device) => void;
  removeDevice: (id: string) => void;
  addAnomaly: (a: Anomaly) => void;
  acknowledgeAnomaly: (id: string) => void;
  setInterfaces: (ifaces: NetInterface[]) => void;
  setSelectedInterface: (name: string | null) => void;
  setProgress: (p: ScanProgress) => void;
  setScanState: (scanning: boolean, subnet: string | null) => void;
  select: (id: string | null) => void;
}

const IDLE_PROGRESS: ScanProgress = {
  phase: "idle",
  scanned: 0,
  total: 0,
  message: "Idle",
};

export const useMesh = create<MeshState>((set) => ({
  live: false,
  devices: {},
  anomalies: [],
  interfaces: [],
  selectedInterface: null,
  progress: IDLE_PROGRESS,
  scanning: false,
  subnet: null,
  selectedId: null,

  setLive: (live) => set({ live }),

  upsertDevice: (d) =>
    set((s) => ({ devices: { ...s.devices, [d.id]: d } })),

  removeDevice: (id) =>
    set((s) => {
      const next = { ...s.devices };
      delete next[id];
      const selectedId = s.selectedId === id ? null : s.selectedId;
      return { devices: next, selectedId };
    }),

  addAnomaly: (a) =>
    set((s) => ({ anomalies: [a, ...s.anomalies].slice(0, 200) })),

  acknowledgeAnomaly: (id) =>
    set((s) => ({
      anomalies: s.anomalies.map((a) =>
        a.id === id ? { ...a, acknowledged: true } : a,
      ),
    })),

  setInterfaces: (interfaces) =>
    set((s) => {
      const def = interfaces.find((i) => i.isDefault) ?? interfaces[0];
      return {
        interfaces,
        selectedInterface: s.selectedInterface ?? def?.name ?? null,
      };
    }),

  setSelectedInterface: (selectedInterface) => set({ selectedInterface }),

  setProgress: (progress) => set({ progress }),

  setScanState: (scanning, subnet) => set({ scanning, subnet }),

  select: (selectedId) => set({ selectedId }),
}));

// ---- Derived helpers -------------------------------------------------------

export function deviceList(devices: Record<string, Device>): Device[] {
  return Object.values(devices).sort((a, b) => {
    // Gateway first, then by IP numeric order.
    if (a.isGateway !== b.isGateway) return a.isGateway ? -1 : 1;
    return ipToNumber(a.ip) - ipToNumber(b.ip);
  });
}

export function ipToNumber(ip: string): number {
  const parts = ip.split(".").map((p) => parseInt(p, 10) || 0);
  if (parts.length !== 4) return 0;
  return (
    ((parts[0] << 24) >>> 0) +
    ((parts[1] << 16) >>> 0) +
    ((parts[2] << 8) >>> 0) +
    parts[3]
  );
}

/** Highest unacknowledged severity, mapped to a 0..100 network threat level. */
export function networkThreat(anomalies: Anomaly[]): number {
  const weights: Record<string, number> = {
    info: 5,
    low: 20,
    medium: 45,
    high: 75,
    critical: 100,
  };
  let max = 0;
  for (const a of anomalies) {
    if (a.acknowledged) continue;
    max = Math.max(max, weights[a.severity] ?? 0);
  }
  return max;
}
