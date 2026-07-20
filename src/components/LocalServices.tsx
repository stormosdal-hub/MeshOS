import { useEffect, useState } from "react";
import type { Controller } from "../App";
import type { LocalService } from "../types";

/**
 * Modal listing the TCP servers currently listening on the machine running
 * MeshOS, with their owning process — the authoritative "what's running on this
 * device" view (in LIVE mode it comes straight from the OS socket table).
 */
export function LocalServices({
  open,
  onClose,
  controller,
}: {
  open: boolean;
  onClose: () => void;
  controller: Controller;
}) {
  const [services, setServices] = useState<LocalService[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoading(true);
    controller
      .listLocalServices()
      .then((s) => {
        if (!cancelled) setServices(s);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open]);

  if (!open) return null;

  const refresh = () => {
    setLoading(true);
    controller
      .listLocalServices()
      .then(setServices)
      .finally(() => setLoading(false));
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <section className="panel servers-modal" onClick={(e) => e.stopPropagation()}>
        <div className="panel-title">
          <span>Listening servers · this device</span>
          <button className="modal-x" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="servers-sub">
          <span>
            {loading
              ? "Reading local sockets…"
              : `${services.length} listening ${services.length === 1 ? "service" : "services"}`}
          </span>
          <button className="ack-btn" onClick={refresh}>
            ⟳ Refresh
          </button>
        </div>

        <div className="servers-table">
          <div className="servers-row servers-head">
            <span>Port</span>
            <span>Service</span>
            <span>Process</span>
            <span>PID</span>
            <span>Address</span>
          </div>
          {!loading && services.length === 0 && (
            <div className="empty">No listening TCP servers found.</div>
          )}
          {services.map((s, i) => (
            <div className="servers-row" key={`${s.address}:${s.port}:${s.pid ?? i}`}>
              <span className="mono">{s.port}</span>
              <span>{s.service ?? "—"}</span>
              <span className="proc">{s.process ?? "—"}</span>
              <span className="mono dim">{s.pid ?? "—"}</span>
              <span className="mono dim">{s.address}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
