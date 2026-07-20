import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  Anomaly,
  Device,
  DeviceOfflineEvent,
  LocalService,
  NetInterface,
  ScanProgress,
  ScanStateEvent,
} from "../types";
import { EVENTS } from "../types";
import type { MeshBackend, UnlistenFn } from "./index";

/**
 * Real backend: forwards commands to the Rust core over Tauri IPC and
 * subscribes to the event stream it emits.
 */
export function createTauriBackend(): MeshBackend {
  async function on<T>(
    event: string,
    cb: (payload: T) => void,
  ): Promise<UnlistenFn> {
    const unlisten = await listen<T>(event, (e) => cb(e.payload));
    return unlisten;
  }

  return {
    isLive: true,

    listInterfaces: () => invoke<NetInterface[]>("list_interfaces"),
    getDevices: () => invoke<Device[]>("get_devices"),
    listLocalServices: () => invoke<LocalService[]>("list_local_services"),
    startScan: (interfaceName?: string) =>
      invoke("start_lan_scan", { interfaceName: interfaceName ?? null }),
    stopScan: () => invoke("stop_lan_scan"),
    rescan: () => invoke("rescan"),
    acknowledgeAnomaly: (id: string) =>
      invoke("acknowledge_anomaly", { id }),

    onProgress: (cb) => on<ScanProgress>(EVENTS.progress, cb),
    onDeviceUpsert: (cb) => on<Device>(EVENTS.deviceUpsert, cb),
    onDeviceOffline: (cb) => on<DeviceOfflineEvent>(EVENTS.deviceOffline, cb),
    onAnomaly: (cb) => on<Anomaly>(EVENTS.anomaly, cb),
    onScanState: (cb) => on<ScanStateEvent>(EVENTS.scanState, cb),
  };
}
