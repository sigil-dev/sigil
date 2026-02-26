// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { describe, expect, it } from "vitest";
import { validateApiUrl } from "./client";

describe("validateApiUrl", () => {
  // --- localhost variants: HTTP must be allowed ---

  it("allows http://localhost", () => {
    expect(() => validateApiUrl("http://localhost")).not.toThrow();
  });

  it("allows http://localhost with port", () => {
    expect(() => validateApiUrl("http://localhost:18789")).not.toThrow();
  });

  it("allows http://127.0.0.1", () => {
    expect(() => validateApiUrl("http://127.0.0.1")).not.toThrow();
  });

  it("allows http://127.0.0.1 with port", () => {
    expect(() => validateApiUrl("http://127.0.0.1:18789")).not.toThrow();
  });

  it("allows http://[::1] (IPv6 loopback)", () => {
    expect(() => validateApiUrl("http://[::1]")).not.toThrow();
  });

  it("allows http://[::1] with port", () => {
    expect(() => validateApiUrl("http://[::1]:18789")).not.toThrow();
  });

  // --- HTTPS: always allowed regardless of host ---

  it("allows https://localhost", () => {
    expect(() => validateApiUrl("https://localhost")).not.toThrow();
  });

  it("allows https://127.0.0.1", () => {
    expect(() => validateApiUrl("https://127.0.0.1")).not.toThrow();
  });

  it("allows https://example.com", () => {
    expect(() => validateApiUrl("https://example.com")).not.toThrow();
  });

  it("allows https://api.example.com with port", () => {
    expect(() => validateApiUrl("https://api.example.com:8443")).not.toThrow();
  });

  // --- non-localhost HTTP: must be rejected ---

  it("rejects http://example.com", () => {
    expect(() => validateApiUrl("http://example.com")).toThrow(
      "API URL must use HTTPS for non-localhost endpoints",
    );
  });

  it("rejects http://192.168.1.1", () => {
    expect(() => validateApiUrl("http://192.168.1.1")).toThrow(
      "API URL must use HTTPS for non-localhost endpoints",
    );
  });

  it("rejects http://10.0.0.1:18789", () => {
    expect(() => validateApiUrl("http://10.0.0.1:18789")).toThrow(
      "API URL must use HTTPS for non-localhost endpoints",
    );
  });

  it("rejects http://sigil.example.internal", () => {
    expect(() => validateApiUrl("http://sigil.example.internal")).toThrow(
      "API URL must use HTTPS for non-localhost endpoints",
    );
  });

  // --- edge cases ---

  it("rejects a URL that starts with 'localhost' but isn't (e.g. localhostfoo)", () => {
    // 'localhostfoo' is not a loopback host
    expect(() => validateApiUrl("http://localhostfoo")).toThrow(
      "API URL must use HTTPS for non-localhost endpoints",
    );
  });

  it("rejects http://127.0.0.2 (not loopback alias in our allowlist)", () => {
    expect(() => validateApiUrl("http://127.0.0.2")).toThrow(
      "API URL must use HTTPS for non-localhost endpoints",
    );
  });

  // --- non-HTTP/HTTPS schemes on loopback hosts: must be rejected ---

  it("rejects ftp://localhost", () => {
    expect(() => validateApiUrl("ftp://localhost")).toThrow(
      "must use http: or https: scheme",
    );
  });

  it("rejects ws://localhost with port", () => {
    expect(() => validateApiUrl("ws://localhost:18789")).toThrow(
      "must use http: or https: scheme",
    );
  });

  it("rejects file://localhost", () => {
    expect(() => validateApiUrl("file://localhost")).toThrow(
      "must use http: or https: scheme",
    );
  });

  // --- malformed URL inputs: descriptive error instead of raw TypeError ---

  it("throws descriptive error for empty string", () => {
    expect(() => validateApiUrl("")).toThrow("API URL is not a valid URL: ");
  });

  it("throws descriptive error for relative path", () => {
    expect(() => validateApiUrl("/api/v1")).toThrow(
      "API URL is not a valid URL: /api/v1",
    );
  });

  it("throws for bare hostname parsed as non-http scheme", () => {
    expect(() => validateApiUrl("localhost:18789")).toThrow(
      "must use http: or https: scheme",
    );
  });
});
