// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { describe, expect, it } from "vitest";
import { classifyError } from "./classify-error";

describe("classifyError", () => {
  it("classifies TypeError with 'fetch' in message as network error", () => {
    const error = new TypeError("fetch failed");
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Network error — cannot reach gateway",
      isNetwork: true,
    });
  });

  it("classifies TypeError with 'network' in message as network error", () => {
    const error = new TypeError("Network request failed");
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Network error — cannot reach gateway",
      isNetwork: true,
    });
  });

  it("classifies TypeError without 'fetch' or 'network' as client error with details", () => {
    const error = new TypeError("Something else went wrong");
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Client error: Something else went wrong",
      isNetwork: false,
    });
  });

  it("classifies Response object as gateway error with status", () => {
    const response = new Response(null, { status: 500 });
    const result = classifyError(response);
    expect(result).toEqual({
      message: "Gateway error (HTTP 500)",
      isNetwork: false,
      httpStatus: 500,
    });
  });

  it("classifies object with status field as gateway error", () => {
    const error = { status: 404 };
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Gateway error (HTTP 404)",
      isNetwork: false,
      httpStatus: 404,
    });
  });

  it("classifies object with status field as gateway error with unknown status", () => {
    const error = { status: undefined };
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Gateway error (HTTP unknown)",
      isNetwork: false,
      httpStatus: undefined,
    });
  });

  it("classifies TimeoutError DOMException", () => {
    const error = new DOMException("The operation timed out", "TimeoutError");
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Request timed out — the gateway took too long to respond",
      isNetwork: false,
    });
  });

  it("classifies generic Error with custom message", () => {
    const error = new Error("Custom error message");
    const result = classifyError(error);
    expect(result).toEqual({
      message: "Custom error message",
      isNetwork: false,
    });
  });

  it("classifies string error by preserving its value", () => {
    const error = "just a string";
    const result = classifyError(error);
    expect(result).toEqual({
      message: "just a string",
      isNetwork: false,
    });
  });

  it("classifies null as unexpected error", () => {
    const result = classifyError(null);
    expect(result).toEqual({
      message: "An unexpected error occurred",
      isNetwork: false,
    });
  });

  it("classifies number as unexpected error", () => {
    const result = classifyError(42);
    expect(result).toEqual({
      message: "An unexpected error occurred",
      isNetwork: false,
    });
  });
});
