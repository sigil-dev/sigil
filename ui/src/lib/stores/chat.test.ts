// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { describe, expect, it } from "vitest";
import { parseSSEEventData, parseSSEStream } from "./sse-parser";

describe("parseSSEEventData", () => {
  it("extracts text from JSON-wrapped text_delta events", () => {
    const result = parseSSEEventData("text_delta", "{\"text\":\"Hello\"}");
    expect(result).toEqual({ type: "text_delta", text: "Hello" });
  });

  it("extracts session_id from JSON-wrapped session_id events", () => {
    const result = parseSSEEventData("session_id", "{\"session_id\":\"sess-123\"}");
    expect(result).toEqual({ type: "session_id", sessionId: "sess-123" });
  });

  it("parses tool_call events with name and input", () => {
    const data = "{\"name\":\"web-search\",\"input\":{\"query\":\"test\"}}";
    const result = parseSSEEventData("tool_call", data);
    expect(result).toEqual({
      type: "tool_call",
      name: "web-search",
      input: { query: "test" },
    });
  });

  it("parses tool_result events with name and result", () => {
    const data = "{\"name\":\"web-search\",\"result\":{\"url\":\"https://example.com\"}}";
    const result = parseSSEEventData("tool_result", data);
    expect(result).toEqual({
      type: "tool_result",
      name: "web-search",
      result: { url: "https://example.com" },
    });
  });

  it("returns error event with message", () => {
    const result = parseSSEEventData("error", "Something went wrong");
    expect(result).toEqual({ type: "error", message: "Something went wrong" });
  });

  it("returns done event", () => {
    const result = parseSSEEventData("done", "{}");
    expect(result).toEqual({ type: "done" });
  });

  it("falls back to raw text for non-JSON text_delta data", () => {
    const result = parseSSEEventData("text_delta", "not json");
    expect(result).toEqual({ type: "text_delta", text: "not json" });
  });

  it("returns parse_error for malformed tool_call JSON", () => {
    const result = parseSSEEventData("tool_call", "bad json");
    expect(result.type).toBe("parse_error");
  });
});

describe("parseSSEStream", () => {
  it("dispatches events on blank-line boundaries", () => {
    const raw = "event: text_delta\ndata: {\"text\":\"Hi\"}\n\nevent: done\ndata: {}\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(2);
    expect(events[0]).toEqual({ type: "text_delta", text: "Hi" });
    expect(events[1]).toEqual({ type: "done" });
  });

  it("concatenates multi-line data fields with newlines", () => {
    const raw = "event: text_delta\ndata: line1\ndata: line2\ndata: line3\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    // Multi-line data should be joined with newlines per SSE spec
    expect(events[0].type).toBe("text_delta");
    if (events[0].type === "text_delta") {
      expect(events[0].text).toBe("line1\nline2\nline3");
    }
  });

  it("buffers incomplete events (no trailing blank line)", () => {
    const raw = "event: text_delta\ndata: {\"text\":\"partial\"}";
    const events = parseSSEStream(raw);
    // Without a blank line, the event should still be dispatched for flush
    // but the parser returns only complete events by default
    expect(events).toHaveLength(0);
  });

  it("handles events with no explicit event type as 'message'", () => {
    const raw = "data: {\"text\":\"implicit\"}\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("text_delta");
  });

  it("strips exactly one leading space after 'data:' per SSE spec", () => {
    const raw = "event: text_delta\ndata: value\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("text_delta");
    if (events[0].type === "text_delta") {
      expect(events[0].text).toBe("value");
    }
  });

  it("preserves additional leading spaces after the first one", () => {
    const raw = "event: text_delta\ndata:  value\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("text_delta");
    if (events[0].type === "text_delta") {
      expect(events[0].text).toBe(" value");
    }
  });

  it("handles no leading space after colon", () => {
    const raw = "event: text_delta\ndata:value\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("text_delta");
    if (events[0].type === "text_delta") {
      expect(events[0].text).toBe("value");
    }
  });
});
