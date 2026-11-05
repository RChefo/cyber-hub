/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import { defineConfig, loadEnv } from "vite";
import { normalizeSiteUrl, seo } from "./seo";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const releasesApi = new URL(env.VITE_RELEASES_API_BASE || "https://api.github.com").origin;
  return {
    plugins: [
      react(),
      tailwindcss(),
      seo({
        siteUrl: normalizeSiteUrl(env.VITE_SITE_URL),
        releasesApiOrigin: releasesApi,
        pages: [
          { path: "/", file: "index.html" },
          { path: "/download/", file: "download/index.html" },
          { path: "/download/archive/", file: "download/archive/index.html" },
          { path: "/changelog/", file: "changelog/index.html" },
        ],
      }),
    ],
    resolve: { alias: { "@": resolve(import.meta.dirname, "src") } },
    build: {
      // never inline assets as data: URIs (fonts would then be blocked by font-src 'self')
      assetsInlineLimit: 0,
      rollupOptions: {
        input: {
          home: resolve(import.meta.dirname, "index.html"),
          download: resolve(import.meta.dirname, "download/index.html"),
          archive: resolve(import.meta.dirname, "download/archive/index.html"),
          changelog: resolve(import.meta.dirname, "changelog/index.html"),
        },
      },
    },
    test: {
      environment: "node",
      include: ["src/**/*.test.ts"],
    },
  };
});
