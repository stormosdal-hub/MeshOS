import type {
  Anomaly,
  AnomalyKind,
  Device,
  DeviceKind,
  DeviceOfflineEvent,
  NetInterface,
  ScanProgress,
  ScanStateEvent,
  Severity,
} from "../types";
import type { MeshBackend, UnlistenFn } from "./index";

/**
 * In-browser simulation of the Rust core. Lets the entire UI (3D graph,
 * control panel, live alerts) run and be developed with `npm run dev`, with no
 * native backend present. The desktop build never loads this module.
 *
 * It stages a realistic home LAN discovery and periodically injects anomalies
 * so the security-visualization features are demonstrable end to end.
 */

type Listener<T> = (payload: T) => void;

interface Seed {
  ip: number; // last octet
  mac: string;
  hostname: string | null;
  vendor: string | null;
  kind: DeviceKind;
  openPorts: number[];
  isGateway?: boolean;
  isLocal?: boolean;
  labels: string[];
  baseThreat?: number;
}

const SUBNET = "192.168.1";

const SEEDS: Seed[] = [
  { ip: 1, mac: "44:38:39:ff:aa:01", hostname: "gateway.local", vendor: "Ubiquiti Networks", kind: "router", openPorts: [53, 80, 443], isGateway: true, labels: ["DNS", "HTTP", "Gateway"] },
  { ip: 12, mac: "a4:83:e7:1c:9d:44", hostname: "storm-macbook", vendor: "Apple, Inc.", kind: "computer", openPorts: [22, 5000, 7000], isLocal: true, labels: ["SSH", "mDNS"] },
  { ip: 18, mac: "f0:18:98:23:71:e0", hostname: "iphone-storm", vendor: "Apple, Inc.", kind: "mobile", openPorts: [], labels: ["mDNS"] },
  { ip: 22, mac: "b8:27:eb:44:12:07", hostname: "raspberrypi", vendor: "Raspberry Pi Foundation", kind: "computer", openPorts: [22, 80, 1883], labels: ["SSH", "MQTT"] },
  { ip: 31, mac: "24:6f:28:9a:bb:10", hostname: "esp32-sensor-01", vendor: "Espressif Inc.", kind: "microcontroller", openPorts: [80], labels: ["HTTP", "IoT"] },
  { ip: 32, mac: "24:6f:28:9a:bb:44", hostname: "esp32-relay-02", vendor: "Espressif Inc.", kind: "microcontroller", openPorts: [80, 1883], labels: ["MQTT", "IoT"] },
  { ip: 45, mac: "d8:3a:dd:6b:20:9c", hostname: "ps5-livingroom", vendor: "Sony Interactive", kind: "gamingRig", openPorts: [], labels: ["Gaming"] },
  { ip: 46, mac: "1c:83:41:22:0f:aa", hostname: "battlestation", vendor: "ASUSTek Computer", kind: "gamingRig", openPorts: [3389, 27015], labels: ["RDP", "Gaming"] },
  { ip: 50, mac: "00:11:32:aa:bc:31", hostname: "synology-nas", vendor: "Synology Inc.", kind: "nas", openPorts: [139, 445, 5001], labels: ["SMB", "Storage"] },
  { ip: 60, mac: "30:05:5c:9d:11:02", hostname: "office-printer", vendor: "Hewlett Packard", kind: "printer", openPorts: [631, 9100], labels: ["IPP", "Print"] },
  { ip: 70, mac: "ac:cc:8e:55:2a:9f", hostname: "front-door-cam", vendor: "Axis Communications", kind: "camera", openPorts: [80, 554], labels: ["RTSP", "Camera"] },
  { ip: 80, mac: "50:32:37:aa:11:be", hostname: "living-room-tv", vendor: "Samsung Electronics", kind: "tv", openPorts: [8001, 8080], labels: ["DIAL", "Media"] },
  { ip: 84, mac: "b4:e6:2d:00:71:c3", hostname: null, vendor: "Espressif Inc.", kind: "smartHome", openPorts: [80], labels: ["IoT"] },
  { ip: 92, mac: "68:c6:3a:ee:41:70", hostname: "thermostat", vendor: "Google Nest", kind: "smartHome", openPorts: [443], labels: ["IoT", "Cloud"] },
];

function now(): number {
  return Date.now();
}

function makeDevice(seed: Seed): Device {
  const ip = `${SUBNET}.${seed.ip}`;
  const t = now();
  return {
    id: seed.mac,
    ip,
    mac: seed.mac,
    hostname: seed.hostname,
    vendor: seed.vendor,
    kind: seed.kind,
    openPorts: seed.openPorts,
    isGateway: seed.isGateway ?? false,
    isLocal: seed.isLocal ?? false,
    online: true,
    firstSeen: t,
    lastSeen: t,
    rttMs: seed.isLocal ? 0 : Math.round(2 + Math.random() * 40),
    threatScore: seed.baseThreat ?? 0,
    labels: seed.labels,
  };
}

export function createMockBackend(): MeshBackend {
  const progressCbs: Listener<ScanProgress>[] = [];
  const upsertCbs: Listener<Device>[] = [];
  const offlineCbs: Listener<DeviceOfflineEvent>[] = [];
  const anomalyCbs: Listener<Anomaly>[] = [];
  const stateCbs: Listener<ScanStateEvent>[] = [];

  const devices = new Map<string, Device>();
  let scanning = false;
  let timers: ReturnType<typeof setTimeout>[] = [];
  let anomalyTimer: ReturnType<typeof setInterval> | null = null;

  function emit<T>(cbs: Listener<T>[], payload: T) {
    for (const cb of cbs) cb(payload);
  }

  function subscribe<T>(list: Listener<T>[], cb: Listener<T>): UnlistenFn {
    list.push(cb);
    return () => {
      const i = list.indexOf(cb);
      if (i >= 0) list.splice(i, 1);
    };
  }

  function clearTimers() {
    timers.forEach(clearTimeout);
    timers = [];
    if (anomalyTimer) {
      clearInterval(anomalyTimer);
      anomalyTimer = null;
    }
  }

  function upsert(d: Device) {
    devices.set(d.id, d);
    emit(upsertCbs, d);
  }

  function pushAnomaly(
    device: Device,
    kind: AnomalyKind,
    severity: Severity,
    title: string,
    detail: string,
    scoreDelta: number,
  ) {
    const anomaly: Anomaly = {
      id: `anom-${kind}-${device.id}-${now()}`,
      deviceId: device.id,
      kind,
      severity,
      title,
      detail,
      timestamp: now(),
      acknowledged: false,
    };
    emit(anomalyCbs, anomaly);
    const updated: Device = {
      ...device,
      threatScore: Math.min(100, device.threatScore + scoreDelta),
      lastSeen: now(),
    };
    upsert(updated);
  }

  // Scripted anomaly scenarios triggered on a loop while scanning.
  const scenarios: Array<() => void> = [
    () => {
      const d = devices.get("1c:83:41:22:0f:aa"); // battlestation
      if (d)
        pushAnomaly(
          d,
          "portScan",
          "high",
          "Port scan detected",
          `${d.ip} probed 240+ ports across 12 hosts in 4s — consistent with an internal reconnaissance sweep.`,
          45,
        );
    },
    () => {
      // A previously unseen device joins the network.
      const rogue: Device = {
        id: "de:ad:be:ef:00:99",
        ip: `${SUBNET}.201`,
        mac: "de:ad:be:ef:00:99",
        hostname: null,
        vendor: null,
        kind: "unknown",
        openPorts: [4444],
        isGateway: false,
        isLocal: false,
        online: true,
        firstSeen: now(),
        lastSeen: now(),
        rttMs: 8,
        threatScore: 30,
        labels: ["Unrecognized"],
      };
      upsert(rogue);
      pushAnomaly(
        rogue,
        "newDevice",
        "medium",
        "Unrecognized device joined",
        `${rogue.ip} has no known vendor OUI and is listening on 4444/tcp (common backdoor port).`,
        0,
      );
    },
    () => {
      const cam = devices.get("ac:cc:8e:55:2a:9f");
      if (cam)
        pushAnomaly(
          cam,
          "unusualOutbound",
          "medium",
          "Unusual outbound traffic",
          `${cam.ip} (camera) is streaming 6 Mbps to an unfamiliar external host — cameras normally talk only to the LAN.`,
          25,
        );
    },
    () => {
      const rogue = devices.get("de:ad:be:ef:00:99");
      if (rogue)
        pushAnomaly(
          rogue,
          "gatewayImpersonation",
          "critical",
          "Possible ARP spoofing",
          `${rogue.ip} is broadcasting ARP replies claiming to be the gateway (${SUBNET}.1). Traffic may be intercepted.`,
          40,
        );
    },
  ];

  function startAnomalyLoop() {
    let i = 0;
    anomalyTimer = setInterval(() => {
      if (!scanning) return;
      scenarios[i % scenarios.length]();
      i += 1;
    }, 9000);
  }

  function runDiscovery() {
    emit(stateCbs, { scanning: true, subnet: `${SUBNET}.0/24` });
    emit(progressCbs, {
      phase: "sweep",
      scanned: 0,
      total: 254,
      message: `ARP + ping sweep of ${SUBNET}.0/24`,
    });

    // Stagger device discovery to mimic a live sweep.
    SEEDS.forEach((seed, idx) => {
      const t = setTimeout(() => {
        upsert(makeDevice(seed));
        emit(progressCbs, {
          phase: "sweep",
          scanned: Math.round(((idx + 1) / SEEDS.length) * 254),
          total: 254,
          message: `Discovered ${SUBNET}.${seed.ip}`,
        });
      }, 300 + idx * 260);
      timers.push(t);
    });

    const done = setTimeout(
      () => {
        emit(progressCbs, {
          phase: "done",
          scanned: 254,
          total: 254,
          message: `${SEEDS.length} devices online`,
        });
        startAnomalyLoop();
      },
      300 + SEEDS.length * 260 + 400,
    );
    timers.push(done);
  }

  return {
    isLive: false,

    async listInterfaces(): Promise<NetInterface[]> {
      return [
        {
          name: "en0",
          friendlyName: "Wi-Fi",
          ipv4: `${SUBNET}.12`,
          prefixLen: 24,
          mac: "a4:83:e7:1c:9d:44",
          gatewayIp: `${SUBNET}.1`,
          isDefault: true,
        },
        {
          name: "en5",
          friendlyName: "Ethernet",
          ipv4: null,
          prefixLen: null,
          mac: "a4:83:e7:1c:9d:45",
          gatewayIp: null,
          isDefault: false,
        },
      ];
    },

    async getDevices(): Promise<Device[]> {
      return Array.from(devices.values());
    },

    async startScan(_interfaceName?: string): Promise<void> {
      if (scanning) return;
      scanning = true;
      clearTimers();
      runDiscovery();
    },

    async stopScan(): Promise<void> {
      scanning = false;
      clearTimers();
      emit(stateCbs, { scanning: false, subnet: `${SUBNET}.0/24` });
    },

    async rescan(): Promise<void> {
      clearTimers();
      // Refresh lastSeen on everything already known.
      for (const d of devices.values()) {
        upsert({ ...d, lastSeen: now() });
      }
      if (!scanning) {
        scanning = true;
        runDiscovery();
      }
    },

    async acknowledgeAnomaly(_id: string): Promise<void> {
      // No-op in the mock; the store tracks acknowledgement locally.
    },

    onProgress: async (cb) => subscribe(progressCbs, cb),
    onDeviceUpsert: async (cb) => subscribe(upsertCbs, cb),
    onDeviceOffline: async (cb) => subscribe(offlineCbs, cb),
    onAnomaly: async (cb) => subscribe(anomalyCbs, cb),
    onScanState: async (cb) => subscribe(stateCbs, cb),
  };
}
