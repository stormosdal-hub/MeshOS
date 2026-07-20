import { useEffect, useRef, useState } from "react";
import { getBackend, type MeshBackend, type UnlistenFn } from "./ipc";
import { NetworkScene } from "./scene/NetworkScene";
import { useMesh } from "./store";
import type { LocalService } from "./types";
import { ControlPanel } from "./components/ControlPanel";
import { StatBar } from "./components/StatBar";
import { AlertsFeed } from "./components/AlertsFeed";
import { DeviceInspector } from "./components/DeviceInspector";
import { LocalServices } from "./components/LocalServices";
import { Legend } from "./components/Legend";

/**
 * Actions wired to the live/mock backend and the 3D scene, handed down to the
 * HUD panels so they stay presentational.
 */
export interface Controller {
  start: (iface: string | null) => void;
  stop: () => void;
  rescan: () => void;
  focus: (id: string) => void;
  select: (id: string | null) => void;
  acknowledge: (id: string) => void;
  listLocalServices: () => Promise<LocalService[]>;
}

export default function App() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sceneRef = useRef<NetworkScene | null>(null);
  const backendRef = useRef<MeshBackend | null>(null);
  const [showServers, setShowServers] = useState(false);

  // 1) Build the 3D scene first so it exists before backend events arrive.
  useEffect(() => {
    if (!canvasRef.current) return;
    const scene = new NetworkScene(canvasRef.current, (id) =>
      useMesh.getState().select(id),
    );
    sceneRef.current = scene;
    // Replay anything already in the store.
    for (const d of Object.values(useMesh.getState().devices)) {
      scene.upsertDevice(d);
    }
    return () => {
      scene.dispose();
      sceneRef.current = null;
    };
  }, []);

  // 2) Connect to the backend and stream events into store + scene.
  useEffect(() => {
    let unlisteners: UnlistenFn[] = [];
    let disposed = false;

    (async () => {
      const backend = await getBackend();
      backendRef.current = backend;
      const s = useMesh.getState();
      s.setLive(backend.isLive);

      try {
        s.setInterfaces(await backend.listInterfaces());
        for (const d of await backend.getDevices()) {
          s.upsertDevice(d);
          sceneRef.current?.upsertDevice(d);
        }
      } catch (err) {
        console.error("Backend init failed:", err);
      }

      const subs = await Promise.all([
        backend.onScanState((e) =>
          useMesh.getState().setScanState(e.scanning, e.subnet),
        ),
        backend.onProgress((p) => useMesh.getState().setProgress(p)),
        backend.onDeviceUpsert((d) => {
          useMesh.getState().upsertDevice(d);
          sceneRef.current?.upsertDevice(d);
        }),
        backend.onDeviceOffline((e) => {
          useMesh.getState().removeDevice(e.id);
          sceneRef.current?.removeDevice(e.id);
        }),
        backend.onAnomaly((a) => {
          useMesh.getState().addAnomaly(a);
          sceneRef.current?.flashAnomaly(a.deviceId, a.severity);
        }),
      ]);
      unlisteners = subs;

      if (disposed) {
        unlisteners.forEach((u) => u());
        return;
      }

      // Auto-start the guided demo when there is no native backend.
      if (!backend.isLive) backend.startScan();
    })();

    return () => {
      disposed = true;
      unlisteners.forEach((u) => u());
    };
  }, []);

  // 3) Mirror selection into the scene (outline + could-be-focus).
  const selectedId = useMesh((s) => s.selectedId);
  useEffect(() => {
    sceneRef.current?.setSelected(selectedId);
  }, [selectedId]);

  const controller: Controller = {
    start: (iface) => backendRef.current?.startScan(iface ?? undefined),
    stop: () => backendRef.current?.stopScan(),
    rescan: () => backendRef.current?.rescan(),
    focus: (id) => {
      sceneRef.current?.focus(id);
      useMesh.getState().select(id);
    },
    select: (id) => useMesh.getState().select(id),
    acknowledge: (id) => {
      useMesh.getState().acknowledgeAnomaly(id);
      backendRef.current?.acknowledgeAnomaly(id);
    },
    listLocalServices: () =>
      backendRef.current?.listLocalServices() ?? Promise.resolve([]),
  };

  return (
    <div className="app">
      <canvas ref={canvasRef} className="scene-canvas" />
      <div className="vignette" />

      <div className="hud">
        <header className="hud-top">
          <div className="brand">
            <span className="brand-mark">◈</span>
            <div>
              <div className="brand-name">MeshOS</div>
              <div className="brand-sub">LAN Explorer</div>
            </div>
          </div>
          <StatBar />
        </header>

        <div className="hud-left">
          <ControlPanel
            controller={controller}
            onShowServers={() => setShowServers(true)}
          />
          <Legend />
        </div>

        <div className="hud-right">
          <AlertsFeed controller={controller} />
        </div>

        <DeviceInspector controller={controller} />
      </div>

      <LocalServices
        open={showServers}
        onClose={() => setShowServers(false)}
        controller={controller}
      />
    </div>
  );
}
