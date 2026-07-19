import type { DeviceKind, Severity } from "../types";

// Pure data (no Babylon import) so both the 3D scene and DOM components
// (legend, inspector) can share one source of truth for colors.

export const KIND_COLORS: Record<DeviceKind, string> = {
  router: "#22d3ee",
  computer: "#60a5fa",
  mobile: "#34d399",
  smartHome: "#a78bfa",
  microcontroller: "#fbbf24",
  gamingRig: "#f472b6",
  nas: "#818cf8",
  printer: "#94a3b8",
  camera: "#fb923c",
  tv: "#38bdf8",
  unknown: "#64748b",
};

export const KIND_LABELS: Record<DeviceKind, string> = {
  router: "Router / Gateway",
  computer: "Computer",
  mobile: "Mobile",
  smartHome: "Smart Home",
  microcontroller: "Microcontroller",
  gamingRig: "Gaming Rig",
  nas: "NAS / Storage",
  printer: "Printer",
  camera: "Camera",
  tv: "Smart TV / Media",
  unknown: "Unknown",
};

export const KIND_ICONS: Record<DeviceKind, string> = {
  router: "📡",
  computer: "💻",
  mobile: "📱",
  smartHome: "💡",
  microcontroller: "🔌",
  gamingRig: "🎮",
  nas: "🗄️",
  printer: "🖨️",
  camera: "📷",
  tv: "📺",
  unknown: "❓",
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  info: "#38bdf8",
  low: "#a3e635",
  medium: "#fbbf24",
  high: "#fb923c",
  critical: "#ef4444",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function kindColor(kind: DeviceKind): string {
  return KIND_COLORS[kind] ?? KIND_COLORS.unknown;
}

/** Base sphere diameter per kind — gateways and rigs read as "bigger". */
export function kindSize(kind: DeviceKind, isGateway: boolean): number {
  if (isGateway) return 3.4;
  switch (kind) {
    case "router":
      return 3.0;
    case "nas":
    case "gamingRig":
      return 2.4;
    case "computer":
    case "tv":
      return 2.1;
    case "microcontroller":
    case "smartHome":
      return 1.5;
    default:
      return 1.9;
  }
}
