// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { describe, expect, it } from "vitest";
import { parseSSEEventData, parseSSEStream } from "./sse-parser";

describe("parseSSEStream robustness", () => {
  it("ignores SSE comment lines starting with colon", () => {
    const raw = ": this is a comment\nevent: text_delta\ndata: {\"text\":\"hi\"}\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({ type: "text_delta", text: "hi" });
  });

  it("handles multiple consecutive blank lines between events", () => {
    const raw = "event: text_delta\ndata: {\"text\":\"a\"}\n\n\n\nevent: text_delta\ndata: {\"text\":\"b\"}\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(2);
  });

  it("handles empty data field", () => {
    const raw = "event: text_delta\ndata:\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    // Empty string is not valid JSON, so should be parse_error
    expect(events[0].type).toBe("parse_error");
  });

  it("handles data field with only a space", () => {
    const raw = "event: text_delta\ndata: \n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    // After stripping the one leading space, data is empty string
    expect(events[0].type).toBe("parse_error");
  });

  it("handles large JSON payload", () => {
    const longText = "x".repeat(100_000);
    const json = JSON.stringify({ text: longText });
    const raw = `event: text_delta\ndata: ${json}\n\n`;
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("text_delta");
    if (events[0].type === "text_delta") {
      expect(events[0].text).toHaveLength(100_000);
    }
  });

  it("handles rapid succession of events", () => {
    const events_raw = Array.from({ length: 50 }, (_, i) => `event: text_delta\ndata: {"text":"chunk${i}"}\n\n`).join(
      "",
    );
    const events = parseSSEStream(events_raw);
    expect(events).toHaveLength(50);
    events.forEach((e, i) => {
      expect(e.type).toBe("text_delta");
      if (e.type === "text_delta") {
        expect(e.text).toBe(`chunk${i}`);
      }
    });
  });

  it("ignores id: and retry: fields per SSE spec", () => {
    const raw = "id: 42\nretry: 3000\nevent: text_delta\ndata: {\"text\":\"ok\"}\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({ type: "text_delta", text: "ok" });
  });

  it("handles interleaved comments between data lines", () => {
    const raw = "event: error\ndata: line1\n: interleaved comment\ndata: line2\n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("error");
    if (events[0].type === "error") {
      expect(events[0].message).toBe("line1\nline2");
    }
  });

  it("handles session_id followed by text_delta stream", () => {
    const raw = [
      "event: session_id\ndata: {\"session_id\":\"sess-abc\"}\n\n",
      "event: text_delta\ndata: {\"text\":\"Hello \"}\n\n",
      "event: text_delta\ndata: {\"text\":\"world\"}\n\n",
      "event: done\ndata: {}\n\n",
    ].join("");
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(4);
    expect(events[0]).toEqual({ type: "session_id", sessionId: "sess-abc" });
    expect(events[1]).toEqual({ type: "text_delta", text: "Hello " });
    expect(events[2]).toEqual({ type: "text_delta", text: "world" });
    expect(events[3]).toEqual({ type: "done" });
  });

  it("handles tool_call followed by tool_result", () => {
    const raw = [
      "event: tool_call\ndata: {\"name\":\"search\",\"input\":{\"q\":\"test\"}}\n\n",
      "event: tool_result\ndata: {\"name\":\"search\",\"result\":{\"url\":\"http://x.com\"}}\n\n",
    ].join("");
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(2);
    expect(events[0]).toEqual({
      type: "tool_call",
      name: "search",
      input: { q: "test" },
    });
    expect(events[1]).toEqual({
      type: "tool_result",
      name: "search",
      result: { url: "http://x.com" },
    });
  });

  it("surfaces error event mid-stream without losing prior events", () => {
    const raw = [
      "event: text_delta\ndata: {\"text\":\"partial\"}\n\n",
      "event: error\ndata: rate limit exceeded\n\n",
    ].join("");
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(2);
    expect(events[0]).toEqual({ type: "text_delta", text: "partial" });
    expect(events[1]).toEqual({ type: "error", message: "rate limit exceeded" });
  });
});

describe("parseSSEStream error recovery", () => {
  it("handles multiple consecutive malformed events", () => {
    const raw = [
      "event: text_delta\ndata: not json 1\n\n",
      "event: text_delta\ndata: not json 2\n\n",
      "event: text_delta\ndata: not json 3\n\n",
    ].join("");
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(3);
    events.forEach((e) => expect(e.type).toBe("parse_error"));
  });

  it("handles event: field with no data: field", () => {
    // Per SSE spec, an event with type but no data lines has no dataLines to dispatch
    const raw = "event: text_delta\n\n";
    const events = parseSSEStream(raw);
    // No data lines means no dispatch (dataLines.length === 0)
    expect(events).toHaveLength(0);
  });

  it("recovers from malformed event and processes subsequent valid events", () => {
    const raw = [
      "event: text_delta\ndata: {\"text\":\"good1\"}\n\n",
      "event: text_delta\ndata: broken\n\n",
      "event: text_delta\ndata: {\"text\":\"good2\"}\n\n",
    ].join("");
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(3);
    expect(events[0]).toEqual({ type: "text_delta", text: "good1" });
    expect(events[1].type).toBe("parse_error");
    expect(events[2]).toEqual({ type: "text_delta", text: "good2" });
  });

  it("handles unknown event types in parseSSEEventData", () => {
    const result = parseSSEEventData("heartbeat", "{}");
    expect(result.type).toBe("parse_error");
    if (result.type === "parse_error") {
      expect(result.error).toContain("Unknown event type");
    }
  });
});

describe("parseSSEEventData edge cases", () => {
  it("handles empty string for session_id", () => {
    const result = parseSSEEventData("session_id", "{\"session_id\":\"\"}");
    expect(result).toEqual({ type: "session_id", sessionId: "" });
  });

  it("handles tool_call with no input field", () => {
    const result = parseSSEEventData("tool_call", "{\"name\":\"ping\"}");
    expect(result).toEqual({ type: "tool_call", name: "ping", input: undefined });
  });

  it("handles tool_result with no result field", () => {
    const result = parseSSEEventData("tool_result", "{\"name\":\"ping\"}");
    expect(result).toEqual({ type: "tool_result", name: "ping", result: undefined });
  });

  it("handles text_delta with unicode text", () => {
    const result = parseSSEEventData("text_delta", "{\"text\":\"Hello 🌍 café\"}");
    expect(result).toEqual({ type: "text_delta", text: "Hello 🌍 café" });
  });

  it("handles text_delta with empty text", () => {
    const result = parseSSEEventData("text_delta", "{\"text\":\"\"}");
    expect(result).toEqual({ type: "text_delta", text: "" });
  });

  it("handles nested JSON in tool_call input", () => {
    const data = "{\"name\":\"query\",\"input\":{\"sql\":\"SELECT * FROM t\",\"params\":[1,2,3]}}";
    const result = parseSSEEventData("tool_call", data);
    expect(result.type).toBe("tool_call");
    if (result.type === "tool_call") {
      expect(result.name).toBe("query");
      expect(result.input).toEqual({ sql: "SELECT * FROM t", params: [1, 2, 3] });
    }
  });
});
