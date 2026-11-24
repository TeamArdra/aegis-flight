import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { buildInfo } from "./scripts/provenance.mjs";

// The config file's own directory: build-info.json hashes this tree no matter where vite is launched from.
const frontendRoot = fileURLToPath(new URL(".", import.meta.url));

const backendPort = process.env.VITE_BACKEND_PORT || "8000";

// The dev server proxies API + WebSocket to the FastAPI backend,
// so `npm run dev` (on :5173) works against `aegis serve` with no CORS fuss.
export default defineConfig(({ command, mode }) => {
  // A bearer secret must never be baked into a shipped bundle: VITE_* values are public by construction.
  const devToken = process.env.VITE_AEGIS_API_TOKEN || loadEnv(mode, process.cwd(), "VITE_").VITE_AEGIS_API_TOKEN;
  if (command === "build" && devToken) {
    throw new Error(
      "VITE_AEGIS_API_TOKEN is dev-server only and must not be set for a production build " +
        "(it would be embedded in the bundle). Unset it and enter the token in Settings.",
    );
  }
  return {
    plugins: [
      react(),
      // Build only: record which UI source this bundle was built from (served at /build-info.json; verify with scripts/provenance.mjs --check).
      {
        name: "aegis-build-info",
        apply: "build",
        generateBundle() {
          this.emitFile({ type: "asset", fileName: "build-info.json", source: JSON.stringify(buildInfo(frontendRoot), null, 2) + "\n" });
        },
      },
    ],
    server: {
      port: 5173,
      proxy: {
        "/api": { target: `http://localhost:${backendPort}`, changeOrigin: true },
        "/health": { target: `http://localhost:${backendPort}`, changeOrigin: true },
        "/ws": { target: `ws://localhost:${backendPort}`, ws: true },
      },
    },
    build: { outDir: "dist", sourcemap: false },
  };
});
