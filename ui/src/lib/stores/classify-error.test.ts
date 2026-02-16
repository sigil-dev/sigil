// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { describe, expect, it } from "vitest";
import { classifyError } from "./classify-error";

describe("classifyError", () => {
  it("classifies TypeError with 'fetch' in message as network error", () => {
    const error = new TypeError("fetch failed");
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "network",
      message: "Network error — cannot reach gateway",
    });
  });

  it("classifies TypeError with 'network' in message as network error", () => {
    const error = new TypeError("Network request failed");
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "network",
      message: "Network error — cannot reach gateway",
    });
  });

  it("classifies TypeError without 'fetch' or 'network' as client error with details", () => {
    const error = new TypeError("Something else went wrong");
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "client",
      message: "Client error: Something else went wrong",
    });
  });

  it("classifies Response object as gateway error with status", () => {
    const response = new Response(null, { status: 500 });
    const result = classifyError(response);
    expect(result).toEqual({
      kind: "http",
      message: "Gateway error (HTTP 500)",
      status: 500,
    });
  });

  it("classifies object with status field as gateway error", () => {
    const error = { status: 404 };
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "http",
      message: "Gateway error (HTTP 404)",
      status: 404,
    });
  });

  it("classifies object with status field as gateway error with unknown status", () => {
    const error = { status: undefined };
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "http",
      message: "Gateway error (HTTP unknown)",
      status: undefined,
    });
  });

  it("classifies TimeoutError DOMException", () => {
    const error = new DOMException("The operation timed out", "TimeoutError");
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "client",
      message: "Request timed out — the gateway took too long to respond",
    });
  });

  it("classifies generic Error with custom message", () => {
    const error = new Error("Custom error message");
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "unknown",
      message: "Custom error message",
    });
  });

  it("classifies string error by preserving its value", () => {
    const error = "just a string";
    const result = classifyError(error);
    expect(result).toEqual({
      kind: "unknown",
      message: "just a string",
    });
  });

  it("classifies null as unexpected error", () => {
    const result = classifyError(null);
    expect(result).toEqual({
      kind: "unknown",
      message: "An unexpected error occurred",
    });
  });

  it("classifies number as unexpected error", () => {
    const result = classifyError(42);
    expect(result).toEqual({
      kind: "unknown",
      message: "An unexpected error occurred",
    });
  });
});
