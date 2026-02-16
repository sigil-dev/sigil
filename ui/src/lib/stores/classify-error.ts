// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

/** Classified error for user-facing display */
export type ClassifiedError =
  | { kind: "network"; message: string }
  | { kind: "http"; message: string; status: number | undefined }
  | { kind: "client"; message: string }
  | { kind: "unknown"; message: string };

/** Classify a caught error into a user-facing message */
export function classifyError(error: unknown): ClassifiedError {
  if (error instanceof TypeError && /fetch|network/i.test(error.message)) {
    return { kind: "network", message: "Network error — cannot reach gateway" };
  }
  if (error instanceof TypeError) {
    return { kind: "client", message: `Client error: ${error.message}` };
  }
  if (error instanceof Response || (error && typeof error === "object" && "status" in error)) {
    const status = (error as { status?: number }).status;
    return { kind: "http", message: `Gateway error (HTTP ${status ?? "unknown"})`, status };
  }
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return { kind: "client", message: "Request timed out — the gateway took too long to respond" };
  }
  if (error instanceof Error) {
    return { kind: "unknown", message: error.message };
  }
  let message: string;
  if (typeof error === "string") {
    message = error;
  } else if (error && typeof error === "object" && "message" in error) {
    message = String((error as { message: unknown }).message);
  } else {
    message = "An unexpected error occurred";
  }
  return { kind: "unknown", message };
}
