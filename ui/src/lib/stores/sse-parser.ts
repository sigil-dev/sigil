// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

/** Parsed SSE event types returned by the parser. */
export type ParsedSSEEvent =
  | { type: "text_delta"; text: string }
  | { type: "session_id"; sessionId: string }
  | { type: "tool_call"; name: string; input?: unknown }
  | { type: "tool_result"; name: string; result?: unknown }
  | { type: "error"; message: string }
  | { type: "done" }
  | { type: "parse_error"; eventType: string; rawData: string; error: string };

/**
 * Parse the data payload for a single SSE event based on its type.
 * The server emits JSON-wrapped payloads for text_delta and session_id.
 */
export function parseSSEEventData(eventType: string, data: string): ParsedSSEEvent {
  switch (eventType) {
    case "text_delta": {
      try {
        const parsed = JSON.parse(data) as { text: string };
        return { type: "text_delta", text: parsed.text };
      } catch {
        // Fall back to raw text if not JSON (e.g., multi-line data)
        return { type: "text_delta", text: data };
      }
    }
    case "session_id": {
      try {
        const parsed = JSON.parse(data) as { session_id: string };
        return { type: "session_id", sessionId: parsed.session_id };
      } catch (e) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: e instanceof Error ? e.message : "JSON parse failed",
        };
      }
    }
    case "tool_call": {
      try {
        const parsed = JSON.parse(data) as { name: string; input?: unknown };
        return { type: "tool_call", name: parsed.name, input: parsed.input };
      } catch (e) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: e instanceof Error ? e.message : "JSON parse failed",
        };
      }
    }
    case "tool_result": {
      try {
        const parsed = JSON.parse(data) as { name: string; result?: unknown };
        return { type: "tool_result", name: parsed.name, result: parsed.result };
      } catch (e) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: e instanceof Error ? e.message : "JSON parse failed",
        };
      }
    }
    case "error":
      return { type: "error", message: data };
    case "done":
      return { type: "done" };
    default:
      // Unknown event types — treat data as text_delta
      try {
        const parsed = JSON.parse(data) as { text?: string };
        if (parsed.text !== undefined) {
          return { type: "text_delta", text: parsed.text };
        }
      } catch {
        // Not JSON — use raw data as text
      }
      return { type: "text_delta", text: data };
  }
}

/**
 * Parse a raw SSE stream string into typed events.
 * Follows the SSE specification: buffers data lines and dispatches
 * on blank-line boundaries. Multiple data: lines are joined with newlines.
 */
export function parseSSEStream(raw: string): ParsedSSEEvent[] {
  const events: ParsedSSEEvent[] = [];
  let eventType = "";
  const dataLines: string[] = [];

  const lines = raw.split("\n");

  for (const line of lines) {
    if (line === "") {
      // Blank line = dispatch buffered event
      if (dataLines.length > 0) {
        const data = dataLines.join("\n");
        events.push(parseSSEEventData(eventType || "message", data));
        dataLines.length = 0;
        eventType = "";
      }
    } else if (line.startsWith("event:")) {
      eventType = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trimStart());
    }
    // Ignore comments (lines starting with :) and other fields
  }

  // Don't dispatch incomplete events (no trailing blank line)
  return events;
}
