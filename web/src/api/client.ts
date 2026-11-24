import createClient, { type Middleware } from "openapi-fetch";
import { toApiError } from "./problem";
import type { paths } from "./schema";

/**
 * Resolved against the document, not the origin, so the SPA works when the Go
 * server (or a reverse proxy) mounts it below a path prefix.
 */
export const API_BASE = new URL("api/v1", document.baseURI).href;

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** CSRF guard required by the server on every write (WEBAPP.md §8). */
const csrf: Middleware = {
  onRequest({ request }) {
    if (WRITE_METHODS.has(request.method)) {
      request.headers.set("Content-Type", "application/json");
      request.headers.set("X-Heimdall-Request", "1");
    }
    return request;
  },
};

export const api = createClient<paths>({
  baseUrl: API_BASE,
  // Late-bound so test interceptors that patch globalThis.fetch are honoured.
  fetch: (req) => globalThis.fetch(req),
});
api.use(csrf);

type Result<T> = { data?: T; error?: unknown; response: Response };

/** Unwraps an openapi-fetch result, throwing ApiError on non-2xx. */
export async function unwrap<T>(p: Promise<Result<T>>): Promise<T> {
  const { data, error, response } = await p;
  if (!response.ok) throw toApiError(response.status, response.statusText, error);
  return data as T;
}
