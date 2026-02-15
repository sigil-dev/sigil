// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { logger } from "$lib/logger";
import { z } from "zod";

/** Parsed SSE event types returned by the parser. */
export type ParsedSSEEvent =
  | { type: "text_delta"; text: string }
  | { type: "session_id"; sessionId: string }
  | { type: "tool_call"; name: string; input?: unknown }
  | { type: "tool_result"; name: string; result?: unknown }
  | { type: "error"; message: string }
  | { type: "done" }
  | { type: "parse_error"; eventType: string; rawData: string; error: string };

/** Zod schemas for event payloads */
const TextDeltaPayload = z.object({ text: z.string() });
const SessionIdPayload = z.object({ session_id: z.string() });
const ToolCallPayload = z.object({ name: z.string(), input: z.unknown().optional() });
const ToolResultPayload = z.object({ name: z.string(), result: z.unknown().optional() });

/**
 * Safely parse JSON string and return a result object.
 * On success, returns { success: true, data: unknown }.
 * On failure, returns { success: false, error: string } with the parse error message.
 */
function safeJsonParse(data: string): { success: true; data: unknown } | { success: false; error: string } {
  try {
    return { success: true, data: JSON.parse(data) };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown JSON parse error";
    return { success: false, error: message };
  }
}

/**
 * Parse the data payload for a single SSE event based on its type.
 * The server emits JSON-wrapped payloads for text_delta and session_id.
 * Uses Zod for runtime validation to ensure payload shape correctness.
 */
export function parseSSEEventData(eventType: string, data: string): ParsedSSEEvent {
  switch (eventType) {
    case "text_delta": {
      const parseResult = safeJsonParse(data);
      if (!parseResult.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: parseResult.error,
        };
      }
      const result = TextDeltaPayload.safeParse(parseResult.data);
      if (!result.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: result.error.message,
        };
      }
      return { type: "text_delta", text: result.data.text };
    }
    case "session_id": {
      const parseResult = safeJsonParse(data);
      if (!parseResult.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: parseResult.error,
        };
      }
      const result = SessionIdPayload.safeParse(parseResult.data);
      if (!result.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: result.error.message,
        };
      }
      return { type: "session_id", sessionId: result.data.session_id };
    }
    case "tool_call": {
      const parseResult = safeJsonParse(data);
      if (!parseResult.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: parseResult.error,
        };
      }
      const result = ToolCallPayload.safeParse(parseResult.data);
      if (!result.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: result.error.message,
        };
      }
      return { type: "tool_call", name: result.data.name, input: result.data.input };
    }
    case "tool_result": {
      const parseResult = safeJsonParse(data);
      if (!parseResult.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: parseResult.error,
        };
      }
      const result = ToolResultPayload.safeParse(parseResult.data);
      if (!result.success) {
        return {
          type: "parse_error",
          eventType,
          rawData: data,
          error: result.error.message,
        };
      }
      return { type: "tool_result", name: result.data.name, result: result.data.result };
    }
    case "error":
      return { type: "error", message: data };
    case "done":
      return { type: "done" };
    default:
      logger.warn("Unknown SSE event type", { eventType });
      return {
        type: "parse_error",
        eventType,
        rawData: data,
        error: `Unknown event type: ${eventType}`,
      };
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
      // Per SSE spec: strip at most one leading space if present (U+0020)
      let value = line.slice(5);
      if (value.length > 0 && value.charCodeAt(0) === 0x20) {
        value = value.slice(1);
      }
      dataLines.push(value);
    }
    // Ignore comments (lines starting with :) and other fields
  }

  // Don't dispatch incomplete events (no trailing blank line)
  return events;
}
