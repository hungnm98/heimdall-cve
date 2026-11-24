import { setupWorker } from "msw/browser";
import { db } from "./db";
import { handlers, latency } from "./handlers";

/** Starts the mock API in the browser (dev only, VITE_MOCK=1). */
export async function startMockApi() {
  latency.ms = 180;
  const worker = setupWorker(...handlers);
  await worker.start({
    onUnhandledRequest: "bypass",
    serviceWorker: { url: new URL("mockServiceWorker.js", document.baseURI).pathname },
    quiet: true,
  });
  db.startBackground();
  console.info("[heimdall] mock API enabled (VITE_MOCK=1)");
}
