import type { Controller } from "../App";
import { KIND_ICONS, KIND_LABELS, kindColor } from "../scene/deviceVisuals";
import { SUSPICIOUS_PORTS, serviceName } from "../services";
import { useMesh } from "../store";

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{v}</dd>
    </>
  );
}

export function DeviceInspector({ controller }: { controller: Controller }) {
  const selectedId = useMesh((s) => s.selectedId);
  const devices = useMesh((s) => s.devices);
  const anomalies = useMesh((s) => s.anomalies);

  if (!selectedId) return null;
  const d = devices[selectedId];
  if (!d) return null;

  const color = kindColor(d.kind);
  const related = anomalies.filter((a) => a.deviceId === d.id);
  const tag =
    (d.isGateway ? " · Gateway" : "") + (d.isLocal ? " · This device" : "");

  return (
    <section className="panel inspector">
      <button className="close-btn" onClick={() => controller.select(null)}>
        ✕
      </button>
      <div className="inspector-head">
        <span className="inspector-icon" style={{ color }}>
          {KIND_ICONS[d.kind]}
        </span>
        <div>
          <div className="inspector-name">{d.hostname ?? d.ip}</div>
          <div className="inspector-kind" style={{ color }}>
            {KIND_LABELS[d.kind]}
            {tag}
          </div>
        </div>
      </div>

      <dl className="kv">
        <Row k="IP" v={d.ip} />
        <Row k="MAC" v={d.mac ?? "unknown"} />
        <Row k="Vendor" v={d.vendor ?? "unknown"} />
        <Row k="RTT" v={d.rttMs != null ? `${d.rttMs} ms` : "—"} />
        <Row k="Status" v={d.online ? "online" : "offline"} />
      </dl>

      <div className="ports-block">
        <div className="ports-title">Open ports &amp; services</div>
        {d.openPorts.length ? (
          <div className="port-chips">
            {d.openPorts.map((p) => {
              const svc = serviceName(p);
              const sus = SUSPICIOUS_PORTS.has(p);
              return (
                <span
                  key={p}
                  className={`port-chip ${sus ? "sus" : ""}`}
                  title={sus ? "Port commonly used by backdoors" : (svc ?? "")}
                >
                  <span className="port-num">{p}</span>
                  {svc && <span className="port-svc">{svc}</span>}
                </span>
              );
            })}
          </div>
        ) : (
          <div className="ports-none">none observed</div>
        )}
      </div>

      <div className="threat-meter">
        <div className="threat-meter-label">
          <span>Threat score</span>
          <span>{Math.round(d.threatScore)}</span>
        </div>
        <div className="threat-meter-bar">
          <div
            className="threat-meter-fill"
            style={{
              width: `${Math.min(100, d.threatScore)}%`,
              background:
                d.threatScore > 60
                  ? "#ef4444"
                  : d.threatScore > 25
                    ? "#fb923c"
                    : "#34d399",
            }}
          />
        </div>
      </div>

      {d.labels.length > 0 && (
        <div className="tags">
          {d.labels.map((l) => (
            <span key={l} className="tag">
              {l}
            </span>
          ))}
        </div>
      )}

      {related.length > 0 && (
        <div className="inspector-alerts">
          <div className="inspector-alerts-title">Related alerts</div>
          {related.map((a) => (
            <div key={a.id} className="inspector-alert">
              • {a.title}
            </div>
          ))}
        </div>
      )}

      <button
        className="btn btn-ghost full"
        onClick={() => controller.focus(d.id)}
      >
        Focus in view
      </button>
    </section>
  );
}
