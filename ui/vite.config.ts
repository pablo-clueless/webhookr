import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * The build lands in `../dist-ui`, which `rust-embed` bakes into the release
 * binary. In debug the Rust server proxies unmatched routes here instead, so
 * HMR works against a live backend.
 *
 * The proxy below covers the other direction: opening the Vite dev server
 * directly on :5173 still reaches the real API and ingress on :4000.
 */
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../dist-ui",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:4000",
        changeOrigin: false,
      },
      "/in": {
        target: "http://127.0.0.1:4000",
        changeOrigin: false,
      },
    },
  },
});
