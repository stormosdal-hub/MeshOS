import type { Controller } from "../App";
import { SEVERITY_COLORS } from "../scene/deviceVisuals";
import { useMesh } from "../store";

function relTime(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

export function AlertsFeed({ controller }: { controller: Controller }) {
  const anomalies = useMesh((s) => s.anomalies);
  const devices = useMesh((s) => s.devices);
  const unack = anomalies.filter((a) => !a.acknowledged).length;

  return (
    <section className="panel alerts-panel">
      <div className="panel-title">
        <span>Security Alerts</span>
        <span className={`count-pill ${unack > 0 ? "hot" : ""}`}>{unack}</span>
      </div>
      <div className="alerts-list">
        {anomalies.length === 0 && (
          <div className="empty">
            No anomalies detected.
            <br />
            The on-device analyzer is watching traffic.
          </div>
        )}
        {anomalies.map((a) => {
          const dev = devices[a.deviceId];
          const color = SEVERITY_COLORS[a.severity];
          return (
            <div
              key={a.id}
              className={`alert ${a.acknowledged ? "ack" : ""}`}
              onClick={() => controller.focus(a.deviceId)}
            >
              <div className="alert-bar" style={{ background: color }} />
              <div className="alert-body">
                <div className="alert-head">
                  <span className="alert-title">{a.title}</span>
                  <span className="alert-sev" style={{ color }}>
                    {a.severity}
                  </span>
                </div>
                <div className="alert-detail">{a.detail}</div>
                <div className="alert-foot">
                  <span className="alert-dev">
                    {dev ? (dev.hostname ?? dev.ip) : a.deviceId}
                  </span>
                  <span className="alert-time">{relTime(a.timestamp)}</span>
                  {!a.acknowledged && (
                    <button
                      className="ack-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        controller.acknowledge(a.id);
                      }}
                    >
                      Dismiss
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
