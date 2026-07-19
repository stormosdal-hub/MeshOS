import {
  ArcRotateCamera,
  Color3,
  Color4,
  DynamicTexture,
  Engine,
  GlowLayer,
  HemisphericLight,
  LinesMesh,
  Mesh,
  MeshBuilder,
  ParticleSystem,
  PointerEventTypes,
  Scene,
  StandardMaterial,
  Texture,
  Vector3,
} from "@babylonjs/core";
import type { Device, Severity } from "../types";
import {
  SEVERITY_COLORS,
  SEVERITY_RANK,
  kindColor,
  kindSize,
} from "./deviceVisuals";
import { LayoutEngine } from "./forceLayout";

interface NodeVisual {
  device: Device;
  mesh: Mesh;
  mat: StandardMaterial;
  halo: Mesh;
  haloMat: StandardMaterial;
  label: Mesh;
  labelTex: DynamicTexture;
  labelText: string;
  baseDiameter: number;
  flashUntil: number;
  flashColor: Color3;
}

interface Packet {
  mesh: Mesh;
  mat: StandardMaterial;
  from: string;
  phase: number;
  speed: number;
}

const SPACE_COLOR = new Color4(0.02, 0.03, 0.06, 1);
const EDGE_COLOR = new Color3(0.13, 0.55, 0.7);
const GRID_COLOR = new Color3(0.1, 0.35, 0.5);

/**
 * Renders the live LAN as a 3D physics constellation: a glowing node per
 * device, springy links to the gateway, animated "packet" traffic, and
 * pulsing warning halos around anomalous devices. All device/anomaly data is
 * pushed in from React; this class owns only the rendering.
 */
export class NetworkScene {
  private engine: Engine;
  private scene: Scene;
  private camera: ArcRotateCamera;
  private layout = new LayoutEngine();

  private nodes = new Map<string, NodeVisual>();
  private edgeLines: LinesMesh | null = null;
  private edgePairs: Array<[string, string]> = [];
  private packets = new Map<string, Packet>();
  private edgesDirty = false;

  private centerId: string | null = null;
  private focusTarget: Vector3 | null = null;
  private selectedId: string | null = null;
  private resizeObserver: ResizeObserver | null = null;

  constructor(
    canvas: HTMLCanvasElement,
    private onSelect: (id: string | null) => void,
  ) {
    this.engine = new Engine(canvas, true, {
      preserveDrawingBuffer: false,
      stencil: true,
    });
    this.scene = new Scene(this.engine);
    this.scene.clearColor = SPACE_COLOR;

    this.camera = new ArcRotateCamera(
      "camera",
      -Math.PI / 2,
      Math.PI / 2.6,
      80,
      Vector3.Zero(),
      this.scene,
    );
    this.camera.attachControl(canvas, true);
    this.camera.wheelPrecision = 2.4;
    this.camera.lowerRadiusLimit = 18;
    this.camera.upperRadiusLimit = 260;
    this.camera.minZ = 0.1;
    this.camera.panningSensibility = 120;

    const light = new HemisphericLight(
      "light",
      new Vector3(0.3, 1, 0.2),
      this.scene,
    );
    light.intensity = 0.55;
    light.groundColor = new Color3(0.05, 0.08, 0.12);

    const glow = new GlowLayer("glow", this.scene);
    glow.intensity = 0.9;

    this.buildGrid();
    this.buildStarfield();
    this.wirePointer();

    this.engine.runRenderLoop(() => {
      this.update();
      this.scene.render();
    });

    this.resizeObserver = new ResizeObserver(() => this.engine.resize());
    this.resizeObserver.observe(canvas);
  }

  // ---- Public API called from React ---------------------------------------

  upsertDevice(device: Device): void {
    const existing = this.nodes.get(device.id);
    if (existing) {
      existing.device = device;
      this.styleNode(existing);
      this.refreshLabel(existing);
    } else {
      this.createNode(device);
    }
    this.recomputeTopology();
  }

  removeDevice(id: string): void {
    const v = this.nodes.get(id);
    if (!v) return;
    v.mesh.dispose();
    v.halo.dispose();
    v.label.dispose();
    v.labelTex.dispose();
    this.nodes.delete(id);
    this.layout.removeNode(id);
    if (this.selectedId === id) this.selectedId = null;
    this.recomputeTopology();
  }

  /** Pulse a device's warning halo in response to an anomaly. */
  flashAnomaly(deviceId: string, severity: Severity): void {
    const v = this.nodes.get(deviceId);
    if (!v) return;
    v.flashUntil = performance.now() + 6000;
    v.flashColor = Color3.FromHexString(SEVERITY_COLORS[severity]);
  }

  setSelected(id: string | null): void {
    this.selectedId = id;
    for (const [nid, v] of this.nodes) {
      v.mesh.renderOutline = nid === id;
    }
  }

  /** Smoothly move the camera focus to a device. */
  focus(id: string): void {
    const pos = this.layout.getPos(id);
    if (pos) this.focusTarget = new Vector3(pos.x, pos.y, pos.z);
  }

  dispose(): void {
    this.resizeObserver?.disconnect();
    this.engine.stopRenderLoop();
    this.scene.dispose();
    this.engine.dispose();
  }

  // ---- Node construction / styling ----------------------------------------

  private createNode(device: Device): void {
    this.layout.addNode(device.id, device.isGateway);

    const diameter = kindSize(device.kind, device.isGateway);
    const mesh = MeshBuilder.CreateSphere(
      `node-${device.id}`,
      { diameter, segments: 20 },
      this.scene,
    );
    mesh.metadata = { id: device.id, kind: "node" };
    mesh.outlineColor = new Color3(0.9, 0.98, 1);
    mesh.outlineWidth = 0.12;

    const mat = new StandardMaterial(`mat-${device.id}`, this.scene);
    mat.specularColor = Color3.Black();
    mesh.material = mat;

    const halo = MeshBuilder.CreateSphere(
      `halo-${device.id}`,
      { diameter: diameter * 2.1, segments: 16 },
      this.scene,
    );
    halo.isPickable = false;
    const haloMat = new StandardMaterial(`halomat-${device.id}`, this.scene);
    haloMat.disableLighting = true;
    haloMat.alpha = 0;
    halo.material = haloMat;

    const labelTex = new DynamicTexture(
      `labeltex-${device.id}`,
      { width: 256, height: 64 },
      this.scene,
      false,
    );
    labelTex.hasAlpha = true;
    const label = MeshBuilder.CreatePlane(
      `label-${device.id}`,
      { width: 9, height: 2.25 },
      this.scene,
    );
    label.billboardMode = Mesh.BILLBOARDMODE_ALL;
    label.isPickable = false;
    const labelMat = new StandardMaterial(`labelmat-${device.id}`, this.scene);
    labelMat.disableLighting = true;
    labelMat.emissiveTexture = labelTex;
    labelMat.opacityTexture = labelTex;
    labelMat.backFaceCulling = false;
    label.material = labelMat;

    const visual: NodeVisual = {
      device,
      mesh,
      mat,
      halo,
      haloMat,
      label,
      labelTex,
      labelText: "",
      baseDiameter: diameter,
      flashUntil: 0,
      flashColor: Color3.FromHexString(SEVERITY_COLORS.medium),
    };
    this.nodes.set(device.id, visual);
    this.styleNode(visual);
    this.refreshLabel(visual);
  }

  private styleNode(v: NodeVisual): void {
    const color = Color3.FromHexString(kindColor(v.device.kind));
    v.mat.emissiveColor = color;
    v.mat.diffuseColor = color.scale(0.2);
    v.haloMat.emissiveColor = color;
  }

  private refreshLabel(v: NodeVisual): void {
    const text = v.device.hostname ?? v.device.ip;
    if (text === v.labelText) return;
    v.labelText = text;
    const ctx = v.labelTex.getContext() as unknown as CanvasRenderingContext2D;
    ctx.clearRect(0, 0, 256, 64);
    ctx.font = "bold 30px Segoe UI, Helvetica, Arial, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = "#dbeafe";
    ctx.fillText(text.slice(0, 22), 128, 34);
    v.labelTex.update();
  }

  // ---- Topology ------------------------------------------------------------

  private pickCenter(): string | null {
    let gateway: string | null = null;
    let local: string | null = null;
    let first: string | null = null;
    for (const [id, v] of this.nodes) {
      first ??= id;
      if (v.device.isGateway) gateway = id;
      if (v.device.isLocal) local = id;
    }
    return gateway ?? local ?? first;
  }

  private recomputeTopology(): void {
    const center = this.pickCenter();
    if (center !== this.centerId) {
      if (this.centerId) this.layout.setPinned(this.centerId, false);
      if (center) this.layout.setPinned(center, true);
      this.centerId = center;
    }
    const edges: Array<[string, string]> = [];
    if (center) {
      for (const id of this.nodes.keys()) {
        if (id !== center) edges.push([id, center]);
      }
    }
    this.edgePairs = edges;
    this.layout.setEdges(edges);
    this.edgesDirty = true;
  }

  private rebuildEdges(): void {
    if (this.edgeLines) {
      this.edgeLines.dispose();
      this.edgeLines = null;
    }
    // Dispose old packets.
    for (const p of this.packets.values()) {
      p.mesh.dispose();
    }
    this.packets.clear();

    if (this.edgePairs.length === 0) return;

    const lines = this.edgePairs.map(([a, b]) => [
      this.posOf(a),
      this.posOf(b),
    ]);
    this.edgeLines = MeshBuilder.CreateLineSystem(
      "edges",
      { lines, updatable: true },
      this.scene,
    );
    this.edgeLines.color = EDGE_COLOR;
    this.edgeLines.alpha = 0.5;
    this.edgeLines.isPickable = false;

    // One traffic packet per edge.
    for (const [a] of this.edgePairs) {
      const mesh = MeshBuilder.CreateSphere(
        `packet-${a}`,
        { diameter: 0.7, segments: 8 },
        this.scene,
      );
      mesh.isPickable = false;
      const mat = new StandardMaterial(`packetmat-${a}`, this.scene);
      mat.disableLighting = true;
      mat.emissiveColor = new Color3(0.4, 1, 0.7);
      mesh.material = mat;
      this.packets.set(a, {
        mesh,
        mat,
        from: a,
        phase: Math.random(),
        speed: 0.004 + Math.random() * 0.01,
      });
    }
  }

  private updateEdges(): void {
    if (!this.edgeLines || this.edgePairs.length === 0) return;
    const lines = this.edgePairs.map(([a, b]) => [
      this.posOf(a),
      this.posOf(b),
    ]);
    this.edgeLines = MeshBuilder.CreateLineSystem("edges", {
      lines,
      instance: this.edgeLines,
    });
  }

  private posOf(id: string): Vector3 {
    const p = this.layout.getPos(id);
    return p ? new Vector3(p.x, p.y, p.z) : Vector3.Zero();
  }

  // ---- Per-frame update ----------------------------------------------------

  private update(): void {
    const dt = this.engine.getDeltaTime();
    const dtScale = Math.min(2.5, Math.max(0.3, dt / 16.6));
    this.layout.step(dtScale);

    const now = performance.now();

    for (const [id, v] of this.nodes) {
      const p = this.layout.getPos(id);
      if (!p) continue;
      v.mesh.position.set(p.x, p.y, p.z);
      v.halo.position.copyFrom(v.mesh.position);
      v.label.position.set(p.x, p.y + v.baseDiameter + 1.6, p.z);

      // Warning halo: visible when the device carries risk or is flashing.
      const flashing = now < v.flashUntil;
      const risk = v.device.threatScore / 100;
      if (flashing || risk > 0.15) {
        const pulse = 0.5 + 0.5 * Math.sin(now * 0.006);
        const strength = flashing ? 0.55 : 0.15 + risk * 0.35;
        v.haloMat.alpha = strength * (0.5 + 0.5 * pulse);
        if (flashing) v.haloMat.emissiveColor = v.flashColor;
        const s = 1 + pulse * 0.18;
        v.halo.scaling.set(s, s, s);
      } else {
        v.haloMat.alpha = 0;
      }
    }

    if (this.edgesDirty) {
      this.rebuildEdges();
      this.edgesDirty = false;
    } else {
      this.updateEdges();
    }

    this.animatePackets(dtScale);

    if (this.focusTarget) {
      Vector3.LerpToRef(
        this.camera.target,
        this.focusTarget,
        0.08,
        this.camera.target,
      );
      if (Vector3.Distance(this.camera.target, this.focusTarget) < 0.3) {
        this.focusTarget = null;
      }
    }
  }

  private animatePackets(dtScale: number): void {
    if (!this.centerId) return;
    const centerPos = this.posOf(this.centerId);
    for (const p of this.packets.values()) {
      const node = this.nodes.get(p.from);
      if (!node) continue;
      p.phase += p.speed * dtScale;
      if (p.phase > 1) p.phase -= 1;
      const from = this.posOf(p.from);
      Vector3.LerpToRef(from, centerPos, p.phase, p.mesh.position);

      // Color traffic by the source device's current risk.
      const risk = node.device.threatScore;
      if (risk > 40) {
        p.mat.emissiveColor.copyFromFloats(1, 0.3, 0.25);
      } else if (risk > 15) {
        p.mat.emissiveColor.copyFromFloats(1, 0.75, 0.3);
      } else {
        p.mat.emissiveColor.copyFromFloats(0.4, 1, 0.7);
      }
    }
  }

  // ---- Scene furniture -----------------------------------------------------

  private buildGrid(): void {
    const lines: Vector3[][] = [];
    const rings = 6;
    const spokes = 24;
    const maxR = 70;
    const y = -22;
    for (let r = 1; r <= rings; r++) {
      const radius = (r / rings) * maxR;
      const circle: Vector3[] = [];
      for (let i = 0; i <= 48; i++) {
        const a = (i / 48) * Math.PI * 2;
        circle.push(new Vector3(Math.cos(a) * radius, y, Math.sin(a) * radius));
      }
      lines.push(circle);
    }
    for (let s = 0; s < spokes; s++) {
      const a = (s / spokes) * Math.PI * 2;
      lines.push([
        new Vector3(0, y, 0),
        new Vector3(Math.cos(a) * maxR, y, Math.sin(a) * maxR),
      ]);
    }
    const grid = MeshBuilder.CreateLineSystem("grid", { lines }, this.scene);
    grid.color = GRID_COLOR;
    grid.alpha = 0.35;
    grid.isPickable = false;
  }

  private buildStarfield(): void {
    const tex = new DynamicTexture(
      "startex",
      { width: 64, height: 64 },
      this.scene,
      false,
    );
    const ctx = tex.getContext() as unknown as CanvasRenderingContext2D;
    const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    grad.addColorStop(0, "rgba(255,255,255,1)");
    grad.addColorStop(0.4, "rgba(180,220,255,0.6)");
    grad.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 64, 64);
    tex.hasAlpha = true;
    tex.update();

    const ps = new ParticleSystem("stars", 500, this.scene);
    ps.particleTexture = tex as unknown as Texture;
    ps.emitter = Vector3.Zero();
    ps.minEmitBox = new Vector3(-180, -120, -180);
    ps.maxEmitBox = new Vector3(180, 120, 180);
    ps.color1 = new Color4(0.7, 0.85, 1, 0.8);
    ps.color2 = new Color4(0.5, 0.7, 1, 0.5);
    ps.colorDead = new Color4(0, 0, 0, 0);
    ps.minSize = 0.3;
    ps.maxSize = 1.1;
    ps.minLifeTime = 30;
    ps.maxLifeTime = 60;
    ps.emitRate = 40;
    ps.blendMode = ParticleSystem.BLENDMODE_ADD;
    ps.gravity = Vector3.Zero();
    ps.minEmitPower = 0.02;
    ps.maxEmitPower = 0.1;
    ps.updateSpeed = 0.01;
    ps.preWarmCycles = 200;
    ps.start();
  }

  private wirePointer(): void {
    this.scene.onPointerObservable.add((info) => {
      if (info.type !== PointerEventTypes.POINTERPICK) return;
      const mesh = info.pickInfo?.pickedMesh;
      const meta = mesh?.metadata as { id?: string; kind?: string } | undefined;
      if (meta?.kind === "node" && meta.id) {
        this.onSelect(meta.id);
      } else {
        this.onSelect(null);
      }
    });
  }
}

// Re-exported so callers can rank/compare severities without another import.
export { SEVERITY_RANK };
