import type {
  Anomaly,
  Device,
  DeviceOfflineEvent,
  NetInterface,
  ScanProgress,
  ScanStateEvent,
} from "../types";

/**
 * Abstraction over the systems backend. Two implementations exist:
 *  - `tauri.ts`  — real IPC to the Rust core (used inside the desktop app).
 *  - `mock.ts`   — an in-browser simulation so the UI runs with `npm run dev`
 *                  in a plain browser, with no Rust backend present.
 *
 * The correct one is chosen at runtime by {@link getBackend}.
 */
export interface MeshBackend {
  readonly isLive: boolean;

  listInterfaces(): Promise<NetInterface[]>;
  getDevices(): Promise<Device[]>;
  startScan(interfaceName?: string): Promise<void>;
  stopScan(): Promise<void>;
  rescan(): Promise<void>;
  acknowledgeAnomaly(id: string): Promise<void>;

  onProgress(cb: (p: ScanProgress) => void): Promise<UnlistenFn>;
  onDeviceUpsert(cb: (d: Device) => void): Promise<UnlistenFn>;
  onDeviceOffline(cb: (e: DeviceOfflineEvent) => void): Promise<UnlistenFn>;
  onAnomaly(cb: (a: Anomaly) => void): Promise<UnlistenFn>;
  onScanState(cb: (s: ScanStateEvent) => void): Promise<UnlistenFn>;
}

export type UnlistenFn = () => void;

let backend: MeshBackend | null = null;

/** Returns true when running inside the Tauri webview (vs. a plain browser). */
function runningInTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    ("__TAURI_INTERNALS__" in window || "__TAURI__" in window)
  );
}

/**
 * Lazily resolves the appropriate backend. The mock module is only imported
 * when needed so its simulation code stays out of the production bundle path
 * when the real backend is available.
 */
export async function getBackend(): Promise<MeshBackend> {
  if (backend) return backend;
  if (runningInTauri()) {
    const mod = await import("./tauri");
    backend = mod.createTauriBackend();
  } else {
    const mod = await import("./mock");
    backend = mod.createMockBackend();
  }
  return backend;
}
