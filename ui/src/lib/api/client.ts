// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import createClient from "openapi-fetch";
import type { paths } from "./generated/schema";

/**
 * The set of hostnames that are considered loopback (local-only).
 * HTTP (plain) is only safe for these hosts; all non-loopback endpoints
 * MUST use HTTPS to protect credentials and message content in transit.
 */
// Note: URL.hostname preserves brackets for IPv6 addresses, so "[::1]" is correct here.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Validates that the given API base URL is safe to use.
 *
 * Security invariant: plain HTTP is permitted ONLY for loopback addresses
 * (localhost, 127.0.0.1, ::1). Any non-loopback endpoint MUST use HTTPS.
 *
 * @throws {Error} if a non-localhost URL is configured without HTTPS.
 */
export function validateApiUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`API URL is not a valid URL: ${url}`);
  }
  const isHttps = parsed.protocol === "https:";
  const isLoopback = LOOPBACK_HOSTS.has(parsed.hostname);

  if (!isHttps && !isLoopback) {
    throw new Error(
      `API URL must use HTTPS for non-localhost endpoints (got: ${url})`,
    );
  }
}

/**
 * Base URL for the Sigil gateway API.
 *
 * The default uses plain HTTP because it targets localhost only — traffic
 * never leaves the machine. If VITE_API_URL points to a remote host, it
 * MUST use HTTPS; validateApiUrl() enforces this at startup.
 *
 * MUST match: ui/src-tauri/src/main.rs DEFAULT_GATEWAY_PORT
 */
export const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:18789";

// Validate at module load time so mis-configured deployments fail fast.
validateApiUrl(API_BASE);

export const api = createClient<paths>({
  baseUrl: API_BASE,
});
