import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig(({ mode }) => ({
  base: "./",
  plugins: [
    {
      name: "standalone-network-boundary",
      transformIndexHtml() {
        if (loadEnv(mode, ".", "VITE_").VITE_ENABLE_SERVER === "true") return [];
        // The public demo only fetches its own page and offline worker.
        return [{ tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: "connect-src 'self'; object-src 'none'; base-uri 'self'" }, injectTo: "head-prepend" as const }];
      },
    },
    react(),
    viteSingleFile({
      removeViteModuleLoader: true,
    }),
  ],
  build: {
    target: "es2020",
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 8_000,
  },
}));
