import { deviceList, networkThreat, useMesh } from "../store";

function threatLabel(v: number): string {
  if (v >= 100) return "CRITICAL";
  if (v >= 75) return "HIGH";
  if (v >= 45) return "ELEVATED";
  if (v >= 20) return "GUARDED";
  return "SECURE";
}

function Stat({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div className={`stat ${highlight ? "stat-alert" : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

export function StatBar() {
  const devices = useMesh((s) => s.devices);
  const anomalies = useMesh((s) => s.anomalies);
  const subnet = useMesh((s) => s.subnet);

  const list = deviceList(devices);
  const online = list.filter((d) => d.online).length;
  const unack = anomalies.filter((a) => !a.acknowledged).length;
  const threat = networkThreat(anomalies);
  const label = threatLabel(threat);

  return (
    <div className="statbar">
      <Stat label="Subnet" value={subnet ?? "—"} />
      <Stat label="Devices" value={String(online)} />
      <Stat label="Alerts" value={String(unack)} highlight={unack > 0} />
      <div className={`threat threat-${label.toLowerCase()}`}>
        <div className="threat-label">Threat level</div>
        <div className="threat-value">{label}</div>
        <div className="threat-gauge">
          <div className="threat-gauge-fill" style={{ width: `${threat}%` }} />
        </div>
      </div>
    </div>
  );
}
