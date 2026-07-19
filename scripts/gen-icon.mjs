// Generates a 1024x1024 MeshOS source icon (app-icon.png) with no image
// dependencies — a glowing mesh-network motif on deep space. Feed it to
// `npm run tauri icon app-icon.png` to produce every platform size.

import { deflateSync } from "node:zlib";
import { writeFileSync } from "node:fs";

const W = 1024;
const H = 1024;
const CX = W / 2;
const CY = H / 2;

const rgba = Buffer.alloc(W * H * 4);

// Palette
const BG_IN = [11, 18, 32]; // #0b1220
const BG_OUT = [4, 6, 12]; // #04060c
const CYAN = [34, 211, 238]; // #22d3ee
const WHITE = [220, 240, 255];

// Mesh nodes: a hub plus a ring of satellites.
const nodes = [{ x: CX, y: CY, core: 60, glow: 120, color: WHITE }];
const RING = 320;
const SAT = 6;
for (let i = 0; i < SAT; i++) {
  const a = (i / SAT) * Math.PI * 2 - Math.PI / 2;
  nodes.push({
    x: CX + Math.cos(a) * RING,
    y: CY + Math.sin(a) * RING,
    core: 30,
    glow: 70,
    color: CYAN,
  });
}
// Edges from hub to each satellite.
const edges = nodes.slice(1).map((n) => [nodes[0], n]);

function clamp(v) {
  return v < 0 ? 0 : v > 255 ? 255 : v;
}
function lerp(a, b, t) {
  return a + (b - a) * t;
}

function distToSegment(px, py, a, b) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len2 = dx * dx + dy * dy || 1;
  let t = ((px - a.x) * dx + (py - a.y) * dy) / len2;
  t = Math.max(0, Math.min(1, t));
  const cx = a.x + t * dx;
  const cy = a.y + t * dy;
  return Math.hypot(px - cx, py - cy);
}

for (let y = 0; y < H; y++) {
  for (let x = 0; x < W; x++) {
    // Radial background gradient.
    const d = Math.hypot(x - CX, y - CY) / (W / 2);
    let r = lerp(BG_IN[0], BG_OUT[0], Math.min(1, d));
    let g = lerp(BG_IN[1], BG_OUT[1], Math.min(1, d));
    let b = lerp(BG_IN[2], BG_OUT[2], Math.min(1, d));

    // Edge glow.
    for (const [p, q] of edges) {
      const dist = distToSegment(x, y, p, q);
      const gl = Math.exp(-(dist * dist) / (2 * 9 * 9)) * 0.55;
      if (gl > 0.002) {
        r += CYAN[0] * gl;
        g += CYAN[1] * gl;
        b += CYAN[2] * gl;
      }
    }

    // Node cores + glow.
    for (const n of nodes) {
      const dist = Math.hypot(x - n.x, y - n.y);
      if (dist < n.core) {
        const t = 1 - dist / n.core;
        r = lerp(r, n.color[0], t);
        g = lerp(g, n.color[1], t);
        b = lerp(b, n.color[2], t);
      }
      const sigma = n.glow;
      const gl = Math.exp(-(dist * dist) / (2 * sigma * sigma)) * 0.9;
      r += n.color[0] * gl * 0.5;
      g += n.color[1] * gl * 0.5;
      b += n.color[2] * gl * 0.5;
    }

    const i = (y * W + x) * 4;
    rgba[i] = clamp(r);
    rgba[i + 1] = clamp(g);
    rgba[i + 2] = clamp(b);
    rgba[i + 3] = 255;
  }
}

// ---- Minimal PNG encoder ---------------------------------------------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // color type RGBA
ihdr[10] = 0;
ihdr[11] = 0;
ihdr[12] = 0;

// Raw scanlines with filter byte 0 per row.
const raw = Buffer.alloc(H * (W * 4 + 1));
for (let y = 0; y < H; y++) {
  raw[y * (W * 4 + 1)] = 0;
  rgba.copy(raw, y * (W * 4 + 1) + 1, y * W * 4, (y + 1) * W * 4);
}
const idat = deflateSync(raw, { level: 9 });

const png = Buffer.concat([
  sig,
  chunk("IHDR", ihdr),
  chunk("IDAT", idat),
  chunk("IEND", Buffer.alloc(0)),
]);

const out = new URL("../app-icon.png", import.meta.url);
writeFileSync(out, png);
console.log(`Wrote ${out.pathname} (${png.length} bytes)`);
