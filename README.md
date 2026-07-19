# MeshOS — Decentralized LAN Explorer

MeshOS turns your local network into an interactive, gamified **3D physics map**.
It scans your subnet, identifies what's on it (smart-home gear, microcontrollers,
gaming rigs, phones, NAS, cameras…), and runs a small **on-device analyzer** that
visually flags suspicious behavior — a rogue device joining, a backdoor port, ARP
spoofing of the gateway — so anyone can understand their network's security
without reading terminal output.

Everything runs **locally**. No traffic or telemetry ever leaves the machine.

```
┌────────────────────────────────────────────────────────┐
│                   MeshOS App Window                     │
│  ┌──────────────────────────────────────────────────┐  │
│  │               Frontend UI Layer                  │  │
│  │  • 3D Network Graph (Babylon.js)                 │  │
│  │  • React HUD control panel + live alerts         │  │
│  └──────────────────────────────────────────────────┘  │
│                           │                             │
│           Inter-Process Communication (Tauri IPC)       │
│                           ▼                             │
│  ┌──────────────────────────────────────────────────┐  │
│  │               Systems Backend Core (Rust)        │  │
│  │  • Network scanning & telemetry                  │  │
│  │  • On-device classification + anomaly detection  │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

This is the **Tauri** blueprint from the design doc: a Rust systems backend for
raw network access and a Babylon.js/TypeScript frontend for the 3D canvas,
bridged by Tauri IPC. The result is light enough to live in the system tray 24/7
(~tens of MB of RAM, single-digit-MB installer) while still using a web 3D engine
for the rendering.

---

## Tech stack

| Layer          | Choice                                                |
| -------------- | ----------------------------------------------------- |
| Shell          | **Tauri 2** (native OS webview, tiny footprint)       |
| Backend        | **Rust** — async scanning with Tokio                  |
| Frontend       | **React 18 + TypeScript**, built with **Vite**        |
| 3D rendering   | **Babylon.js** (glow layer, particles, force graph)   |
| State          | **Zustand**                                           |
| Interfaces/MAC | `netdev`                                              |
| Reverse DNS    | `dns-lookup`                                          |

---

## Project layout

```
MeshOS-app/
├── index.html                # Vite entry
├── package.json              # Frontend + Tauri CLI
├── scripts/gen-icon.mjs      # Regenerates the app icon
├── src/                      # Frontend (React + Babylon.js)
│   ├── App.tsx               # Wires backend events → store → 3D scene
│   ├── store.ts              # Zustand state
│   ├── types.ts              # Shared model (mirrors Rust)
│   ├── ipc/                  # Backend bridge
│   │   ├── index.ts          # Picks real vs. mock at runtime
│   │   ├── tauri.ts          # Real Tauri IPC
│   │   └── mock.ts           # In-browser simulation (demo mode)
│   ├── scene/                # Babylon.js
│   │   ├── NetworkScene.ts   # Engine, nodes, edges, packets, halos
│   │   ├── forceLayout.ts    # 3D force-directed layout
│   │   └── deviceVisuals.ts  # Colors / sizes / icons
│   └── components/           # HUD panels
└── src-tauri/                # Rust backend
    ├── Cargo.toml
    ├── tauri.conf.json
    └── src/
        ├── main.rs / lib.rs  # Tauri app setup
        ├── commands.rs       # IPC commands
        ├── model.rs          # Serde types + event names
        ├── state.rs          # Shared app state
        ├── net/              # interface, discover, arp, oui, ports
        └── ai/               # classify, anomaly
```

---

## Prerequisites

- **Node.js** ≥ 18 and **npm**
- **Rust** (stable) — https://rustup.rs
- Platform webview / build dependencies for Tauri:
  - **Linux**: `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev build-essential`
  - **macOS**: Xcode Command Line Tools
  - **Windows**: WebView2 (preinstalled on Win 11) + MSVC Build Tools

See the [Tauri prerequisites guide](https://tauri.app/start/prerequisites/) for details.

---

## Running

### 1. Demo mode in a browser (no Rust needed)

The UI ships with an in-browser **mock backend** that simulates a realistic home
LAN and injects staged anomalies, so you can see the whole experience instantly:

```bash
npm install
npm run dev          # open the printed http://localhost:1420
```

A **DEMO** badge appears in the scanner panel when the mock backend is active.

### 2. Full desktop app (real scanning)

```bash
npm install
npm run tauri dev    # builds the Rust backend and opens the native window
```

The scanner panel shows **LIVE**. Pick an interface and press **Start scan**.

> On some systems, reading the ARP cache and probing hosts is more complete when
> the app is run with elevated privileges, but the default path is designed to
> work **unprivileged**.

### 3. Production build

```bash
npm run tauri build  # produces installers under src-tauri/target/release/bundle/
```

---

## How discovery works

MeshOS deliberately uses an **unprivileged** discovery path so it works out of
the box:

1. **Interface & subnet** are resolved via `netdev` (local IP, prefix, gateway).
2. A bounded, concurrent **TCP-connect sweep** probes a curated set of ports on
   every host. A successful connect marks a port open; a *refused* connect still
   proves the host is alive. This also causes the OS to ARP-resolve each live
   host at layer 2.
3. The **OS ARP / neighbor cache** is read (`/proc/net/arp` on Linux, `arp -a`
   elsewhere) to map each live IP → MAC.
4. **Reverse DNS** fills in hostnames; **OUI lookup** maps MAC → vendor.
5. Devices are **classified** and **scored**, then streamed to the UI.

The loop repeats every ~10s, so new devices and anomalies appear over time.

### Optional: active ARP (`raw-arp` feature)

A `raw-arp` Cargo feature is reserved for sending active ARP requests via
`libpnet` for direct MAC discovery on the local segment. It requires elevated
privileges (`CAP_NET_RAW` on Linux) and is **off by default**; the ARP-cache
path above is used instead.

---

## The on-device AI layer

Two stages, both running locally in the Rust core:

**Classification** (`ai/classify.rs`) turns passive signals — OUI vendor,
reverse-DNS hostname, open ports — into a device `kind` (router, microcontroller,
gaming rig, camera, …) plus human labels. This is deliberately the *feature/label
front-end* for a learned model: it produces exactly the structured signals a
quantized **ONNX** scorer (the blueprint's `onnxruntime` / `tch-rs` model) would
consume, so a trained model can be layered in later without touching the pipeline.

**Anomaly detection** (`ai/anomaly.rs`) runs on each scan snapshot and raises
only *explainable* alerts derived from data actually observed:

| Alert                    | Trigger                                             |
| ------------------------ | --------------------------------------------------- |
| **New device**           | A host not in the established baseline appears       |
| **ARP spoof**            | The gateway IP starts answering from a different MAC |
| **Gateway impersonation**| A non-gateway host claims the gateway's IP           |
| **Suspicious service**   | A known backdoor/RAT port (4444, 31337, …) is open   |
| **MAC flooding**         | One MAC bound to many distinct IPs                   |

Each alert pulses a **warning halo** around the offending node in 3D and lands in
the live **Security Alerts** feed with a plain-language explanation.

---

## The 3D scene

- Each device is a **glowing node**, colored by type, sized by role.
- Nodes are laid out by a **3D force-directed simulation** and linked to the
  gateway, forming a living constellation you can orbit, zoom, and click.
- Animated **packet streaks** travel along links and shift color with risk.
- Risky devices emit a pulsing **warning halo**; click any node to inspect it.

---

## Privacy

MeshOS performs **local** discovery only and never transmits anything off the
device. All classification and anomaly analysis happen in-process. It is a
defensive, read-only network-visibility tool for networks you own or are
authorized to inspect.

---

## Regenerating the icon

```bash
node scripts/gen-icon.mjs        # writes app-icon.png
npm run tauri icon app-icon.png  # regenerates src-tauri/icons/*
```
