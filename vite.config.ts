import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed dev-server port and doesn't want Vite to clear the
// terminal (so Rust compiler output stays visible). See tauri.conf.json ->
// build.devUrl / beforeDevCommand.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  // Prevent Vite from obscuring Rust compiler errors.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: {
      // Don't watch the Rust backend; Tauri handles that.
      ignored: ["**/src-tauri/**"],
    },
  },
  // Produce assets Tauri can bundle. Modern webviews support esnext.
  build: {
    target: "esnext",
    minify: "esbuild",
    sourcemap: false,
  },
});
