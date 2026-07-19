import type { Controller } from "../App";
import { useMesh } from "../store";

export function ControlPanel({ controller }: { controller: Controller }) {
  const interfaces = useMesh((s) => s.interfaces);
  const selectedInterface = useMesh((s) => s.selectedInterface);
  const scanning = useMesh((s) => s.scanning);
  const progress = useMesh((s) => s.progress);
  const live = useMesh((s) => s.live);
  const setSelectedInterface = useMesh((s) => s.setSelectedInterface);

  const pct =
    progress.total > 0
      ? Math.min(100, Math.round((progress.scanned / progress.total) * 100))
      : 0;

  return (
    <section className="panel control-panel">
      <div className="panel-title">
        <span>Scanner</span>
        <span className={`mode-badge ${live ? "live" : "demo"}`}>
          {live ? "LIVE" : "DEMO"}
        </span>
      </div>

      <label className="field">
        <span>Interface</span>
        <select
          value={selectedInterface ?? ""}
          onChange={(e) => setSelectedInterface(e.target.value || null)}
        >
          {interfaces.length === 0 && <option value="">—</option>}
          {interfaces.map((i) => (
            <option key={i.name} value={i.name}>
              {(i.friendlyName ?? i.name) +
                (i.ipv4 ? ` · ${i.ipv4}/${i.prefixLen ?? 24}` : "")}
            </option>
          ))}
        </select>
      </label>

      <div className="button-row">
        {scanning ? (
          <button className="btn btn-stop" onClick={() => controller.stop()}>
            ■ Stop
          </button>
        ) : (
          <button
            className="btn btn-start"
            onClick={() => controller.start(selectedInterface)}
          >
            ▶ Start scan
          </button>
        )}
        <button className="btn btn-ghost" onClick={() => controller.rescan()}>
          ⟳ Rescan
        </button>
      </div>

      <div className="progress">
        <div className="progress-bar">
          <div
            className={`progress-fill ${scanning ? "active" : ""}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="progress-meta">
          <span className="phase">{progress.phase}</span>
          <span className="msg">{progress.message}</span>
        </div>
      </div>
    </section>
  );
}
