import type { Problem } from "./types";

/** An API failure. Carries the RFC 9457 problem document when the server sent one. */
export class ApiError extends Error {
  readonly status: number;
  readonly title: string;
  readonly detail?: string;
  readonly fields: Record<string, string>;

  constructor(problem: Problem) {
    super(problem.detail || problem.title);
    this.name = "ApiError";
    this.status = problem.status;
    this.title = problem.title;
    this.detail = problem.detail;
    this.fields = problem.fields ?? {};
  }
}

function isProblem(v: unknown): v is Problem {
  return typeof v === "object" && v !== null && typeof (v as Problem).title === "string";
}

/** Builds an ApiError from a failed response body (already parsed by the client, or raw text). */
export function toApiError(status: number, statusText: string, body: unknown): ApiError {
  if (isProblem(body)) return new ApiError({ ...body, status: body.status || status });
  const detail = typeof body === "string" && body.trim() !== "" ? body.trim().slice(0, 300) : undefined;
  return new ApiError({ title: statusText || `HTTP ${status}`, status, detail });
}

/** A human-readable message for any thrown value. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.detail ? `${err.title}: ${err.detail}` : err.title;
  }
  if (err instanceof TypeError) return "Cannot reach the Heimdall server. Check your connection and try again.";
  if (err instanceof Error) return err.message;
  return "Unexpected error";
}

/**
 * Splits a problem's `fields` into those a form knows about and the rest, so that
 * known fields render inline and unknown ones are still shown to the user.
 */
export function splitFieldErrors(
  err: unknown,
  known: readonly string[],
): { fields: Record<string, string>; other: Record<string, string> } {
  const fields: Record<string, string> = {};
  const other: Record<string, string> = {};
  if (!(err instanceof ApiError)) return { fields, other };
  for (const [key, msg] of Object.entries(err.fields)) {
    if (known.includes(key)) fields[key] = msg;
    else other[key] = msg;
  }
  return { fields, other };
}
