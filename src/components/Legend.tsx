import { KIND_COLORS, KIND_LABELS } from "../scene/deviceVisuals";
import { DEVICE_KINDS } from "../types";

export function Legend() {
  return (
    <section className="panel legend">
      <div className="panel-title">
        <span>Legend</span>
      </div>
      <div className="legend-grid">
        {DEVICE_KINDS.map((k) => (
          <div key={k} className="legend-item">
            <span
              className="legend-dot"
              style={{
                background: KIND_COLORS[k],
                boxShadow: `0 0 8px ${KIND_COLORS[k]}`,
              }}
            />
            <span>{KIND_LABELS[k]}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
