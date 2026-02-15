// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

/** Classified error for user-facing display */
export interface ClassifiedError {
  message: string;
  isNetwork: boolean;
  httpStatus?: number;
}

/** Classify a caught error into a user-facing message */
export function classifyError(error: unknown): ClassifiedError {
  if (error instanceof TypeError && /fetch|network/i.test(error.message)) {
    return { message: "Network error — cannot reach gateway", isNetwork: true };
  }
  if (error instanceof TypeError) {
    return { message: "Unexpected client error", isNetwork: false };
  }
  if (error instanceof Response || (error && typeof error === "object" && "status" in error)) {
    const status = (error as { status?: number }).status;
    return { message: `Gateway error (HTTP ${status ?? "unknown"})`, isNetwork: false, httpStatus: status };
  }
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return { message: "Request timed out — the gateway took too long to respond", isNetwork: false };
  }
  if (error instanceof Error) {
    return { message: error.message, isNetwork: false };
  }
  return { message: "An unexpected error occurred", isNetwork: false };
}
