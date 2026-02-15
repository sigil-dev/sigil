// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { describe, it, expect } from "vitest";
import { parseSSEEventData, parseSSEStream } from "./sse-parser";

describe("parseSSEEventData", () => {
  describe("text_delta", () => {
    it("parses valid text_delta event", () => {
      const result = parseSSEEventData("text_delta", '{"text":"hello"}');
      expect(result).toEqual({ type: "text_delta", text: "hello" });
    });

    it("returns parse_error for wrong shape JSON", () => {
      const result = parseSSEEventData("text_delta", '{"foo":1}');
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.eventType).toBe("text_delta");
        expect(result.rawData).toBe('{"foo":1}');
        expect(result.error).toContain("text");
      }
    });

    it("returns parse_error for invalid JSON", () => {
      const result = parseSSEEventData("text_delta", "not json");
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.eventType).toBe("text_delta");
        expect(result.rawData).toBe("not json");
      }
    });

    it("returns parse_error for wrong type (number instead of string)", () => {
      const result = parseSSEEventData("text_delta", '{"text":123}');
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.error).toContain("text");
      }
    });
  });

  describe("session_id", () => {
    it("parses valid session_id event", () => {
      const result = parseSSEEventData("session_id", '{"session_id":"sess-123"}');
      expect(result).toEqual({ type: "session_id", sessionId: "sess-123" });
    });

    it("returns parse_error for wrong shape JSON", () => {
      const result = parseSSEEventData("session_id", '{"foo":"bar"}');
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.eventType).toBe("session_id");
        expect(result.rawData).toBe('{"foo":"bar"}');
        expect(result.error).toContain("session_id");
      }
    });

    it("returns parse_error for invalid JSON", () => {
      const result = parseSSEEventData("session_id", "{invalid}");
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.eventType).toBe("session_id");
      }
    });
  });

  describe("tool_call", () => {
    it("parses valid tool_call with input", () => {
      const result = parseSSEEventData(
        "tool_call",
        '{"name":"search","input":{"query":"test"}}'
      );
      expect(result).toEqual({
        type: "tool_call",
        name: "search",
        input: { query: "test" },
      });
    });

    it("parses valid tool_call without input", () => {
      const result = parseSSEEventData("tool_call", '{"name":"ping"}');
      expect(result).toEqual({
        type: "tool_call",
        name: "ping",
        input: undefined,
      });
    });

    it("returns parse_error for missing name field", () => {
      const result = parseSSEEventData("tool_call", '{"input":{"x":1}}');
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.error).toContain("name");
      }
    });

    it("returns parse_error for wrong type (name as number)", () => {
      const result = parseSSEEventData("tool_call", '{"name":123}');
      expect(result.type).toBe("parse_error");
    });
  });

  describe("tool_result", () => {
    it("parses valid tool_result with result", () => {
      const result = parseSSEEventData(
        "tool_result",
        '{"name":"search","result":["a","b"]}'
      );
      expect(result).toEqual({
        type: "tool_result",
        name: "search",
        result: ["a", "b"],
      });
    });

    it("parses valid tool_result without result", () => {
      const result = parseSSEEventData("tool_result", '{"name":"ping"}');
      expect(result).toEqual({
        type: "tool_result",
        name: "ping",
        result: undefined,
      });
    });

    it("returns parse_error for missing name field", () => {
      const result = parseSSEEventData("tool_result", '{"result":"ok"}');
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.error).toContain("name");
      }
    });
  });

  describe("error and done", () => {
    it("parses error event (plain text, no JSON)", () => {
      const result = parseSSEEventData("error", "Something went wrong");
      expect(result).toEqual({ type: "error", message: "Something went wrong" });
    });

    it("parses done event", () => {
      const result = parseSSEEventData("done", "");
      expect(result).toEqual({ type: "done" });
    });
  });

  describe("unknown event types", () => {
    it("returns parse_error for unknown event type", () => {
      const result = parseSSEEventData("unknown_type", "data");
      expect(result.type).toBe("parse_error");
      if (result.type === "parse_error") {
        expect(result.eventType).toBe("unknown_type");
        expect(result.error).toContain("Unknown event type");
      }
    });
  });
});

describe("parseSSEStream", () => {
  it("parses single text_delta event", () => {
    const raw = 'event: text_delta\ndata: {"text":"hello"}\n\n';
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({ type: "text_delta", text: "hello" });
  });

  it("parses multiple events", () => {
    const raw =
      'event: session_id\ndata: {"session_id":"s1"}\n\n' +
      'event: text_delta\ndata: {"text":"hi"}\n\n' +
      "event: done\ndata: \n\n";
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(3);
    expect(events[0]).toEqual({ type: "session_id", sessionId: "s1" });
    expect(events[1]).toEqual({ type: "text_delta", text: "hi" });
    expect(events[2]).toEqual({ type: "done" });
  });

  it("handles parse errors in stream", () => {
    const raw = 'event: text_delta\ndata: {"wrong":"shape"}\n\n';
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("parse_error");
  });

  it("strips leading space from data values per SSE spec", () => {
    const raw = 'event: text_delta\ndata: {"text":"test"}\n\n';
    const events = parseSSEStream(raw);
    expect(events[0]).toEqual({ type: "text_delta", text: "test" });
  });

  it("joins multiple data lines with newlines", () => {
    const raw = 'event: error\ndata: line1\ndata: line2\n\n';
    const events = parseSSEStream(raw);
    expect(events[0]).toEqual({ type: "error", message: "line1\nline2" });
  });

  it("ignores incomplete events (no trailing blank line)", () => {
    const raw = 'event: text_delta\ndata: {"text":"incomplete"}';
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(0);
  });

  it("ignores comment lines", () => {
    const raw = ': this is a comment\nevent: done\ndata: \n\n';
    const events = parseSSEStream(raw);
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({ type: "done" });
  });
});
