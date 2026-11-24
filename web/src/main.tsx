import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import { initTheme } from "./lib/theme";
import "./index.css";

initTheme();

async function main() {
  // Statically false in production builds, so the mock is tree-shaken away.
  if (import.meta.env.VITE_MOCK === "1") {
    const { startMockApi } = await import("./mocks/browser");
    await startMockApi();
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void main();
