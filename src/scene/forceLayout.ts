// A small dependency-free 3D force-directed layout. The graph is a star of
// devices around the gateway; this spreads them into a stable, gently drifting
// constellation. Positions are plain numbers so the module stays decoupled
// from Babylon (NetworkScene copies them into mesh transforms each frame).

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

interface Node {
  x: number;
  y: number;
  z: number;
  vx: number;
  vy: number;
  vz: number;
  pinned: boolean;
}

const REPULSION = 220; // node-node inverse-square push
const SPRING_K = 0.02; // edge spring stiffness
const SPRING_LEN = 16; // ideal edge length
const CENTER_GRAVITY = 0.008; // pull toward origin
const DAMPING = 0.86;
const MAX_SPEED = 2.2;

export class LayoutEngine {
  private nodes = new Map<string, Node>();
  private edges: Array<[string, string]> = [];

  addNode(id: string, pinned = false): void {
    if (this.nodes.has(id)) return;
    // Seed on a sphere shell so new nodes don't overlap at the origin.
    const r = pinned ? 0 : 10 + Math.random() * 14;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    this.nodes.set(id, {
      x: pinned ? 0 : r * Math.sin(phi) * Math.cos(theta),
      y: pinned ? 0 : r * Math.cos(phi) * 0.6,
      z: pinned ? 0 : r * Math.sin(phi) * Math.sin(theta),
      vx: 0,
      vy: 0,
      vz: 0,
      pinned,
    });
  }

  removeNode(id: string): void {
    this.nodes.delete(id);
    this.edges = this.edges.filter(([a, b]) => a !== id && b !== id);
  }

  has(id: string): boolean {
    return this.nodes.has(id);
  }

  /** Pin/unpin a node at the origin (used for the gateway/center node). */
  setPinned(id: string, pinned: boolean): void {
    const n = this.nodes.get(id);
    if (n) n.pinned = pinned;
  }

  ids(): string[] {
    return Array.from(this.nodes.keys());
  }

  setEdges(edges: Array<[string, string]>): void {
    this.edges = edges.filter(
      ([a, b]) => this.nodes.has(a) && this.nodes.has(b),
    );
  }

  getPos(id: string): Vec3 | null {
    const n = this.nodes.get(id);
    return n ? { x: n.x, y: n.y, z: n.z } : null;
  }

  /** Advance the simulation by one frame. `dtScale` normalizes for framerate. */
  step(dtScale = 1): void {
    const list = Array.from(this.nodes.values());

    // Pairwise repulsion.
    for (let i = 0; i < list.length; i++) {
      const a = list[i];
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let dz = a.z - b.z;
        let d2 = dx * dx + dy * dy + dz * dz;
        if (d2 < 0.01) {
          // Jitter coincident nodes apart.
          dx = Math.random() - 0.5;
          dy = Math.random() - 0.5;
          dz = Math.random() - 0.5;
          d2 = 0.01;
        }
        const d = Math.sqrt(d2);
        const f = REPULSION / d2;
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        const fz = (dz / d) * f;
        a.vx += fx;
        a.vy += fy;
        a.vz += fz;
        b.vx -= fx;
        b.vy -= fy;
        b.vz -= fz;
      }
    }

    // Edge springs.
    for (const [ida, idb] of this.edges) {
      const a = this.nodes.get(ida);
      const b = this.nodes.get(idb);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dz = b.z - a.z;
      const d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 0.001;
      const f = SPRING_K * (d - SPRING_LEN);
      const fx = (dx / d) * f;
      const fy = (dy / d) * f;
      const fz = (dz / d) * f;
      a.vx += fx;
      a.vy += fy;
      a.vz += fz;
      b.vx -= fx;
      b.vy -= fy;
      b.vz -= fz;
    }

    // Centering gravity + integrate.
    for (const n of list) {
      if (n.pinned) {
        n.vx = n.vy = n.vz = 0;
        n.x = n.y = n.z = 0;
        continue;
      }
      n.vx -= n.x * CENTER_GRAVITY;
      n.vy -= n.y * CENTER_GRAVITY;
      n.vz -= n.z * CENTER_GRAVITY;

      n.vx *= DAMPING;
      n.vy *= DAMPING;
      n.vz *= DAMPING;

      const speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy + n.vz * n.vz);
      if (speed > MAX_SPEED) {
        const s = MAX_SPEED / speed;
        n.vx *= s;
        n.vy *= s;
        n.vz *= s;
      }

      n.x += n.vx * dtScale;
      n.y += n.vy * dtScale;
      n.z += n.vz * dtScale;
    }
  }
}
