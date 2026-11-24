import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv, type ProxyOptions } from "vite";

export default defineConfig(({ mode }) => {
  // process.env wins over .env files, so `VITE_MOCK=0 npm run dev` disables the mock.
  const env = loadEnv(mode, process.cwd(), "");
  const mock = env.VITE_MOCK === "1";
  const proxy: Record<string, ProxyOptions> | undefined = mock
    ? undefined
    : { "/api": { target: env.HEIMDALL_API ?? "http://127.0.0.1:8080" } };

  return {
    // Relative asset URLs: the bundle works wherever the Go server mounts it.
    base: "./",
    plugins: [react(), tailwindcss()],
    // public/ only holds the MSW service worker; never ship it in a real build.
    publicDir: mock ? "public" : false,
    resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
    server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy },
    preview: { host: "127.0.0.1", port: 4173, strictPort: true, proxy },
    build: {
      outDir: "dist",
      emptyOutDir: true,
      rollupOptions: {
        output: {
          // Long-lived vendor chunks cache well across UI releases.
          manualChunks(id) {
            if (!id.includes("node_modules")) return undefined;
            if (/[\\/](recharts|d3-|victory-vendor|lodash)/.test(id)) return "charts";
            if (/[\\/]@tanstack[\\/]/.test(id)) return "tanstack";
            if (/[\\/](@radix-ui|radix-ui)[\\/]/.test(id)) return "radix";
            if (/[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return "react";
            return "vendor";
          },
        },
      },
    },
  };
});
