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
 * Generic helper to parse JSON and validate against a Zod schema.
 * Returns either the validated data or a parse_error event.
 */
function parseAndValidate<T>(
  data: string,
  schema: z.ZodSchema<T>,
  eventType: string,
): { success: true; data: T } | { success: false; error: ParsedSSEEvent } {
  const parseResult = safeJsonParse(data);
  if (!parseResult.success) {
    return {
      success: false,
      error: {
        type: "parse_error",
        eventType,
        rawData: data,
        error: parseResult.error,
      },
    };
  }

  const result = schema.safeParse(parseResult.data);
  if (!result.success) {
    return {
      success: false,
      error: {
        type: "parse_error",
        eventType,
        rawData: data,
        error: result.error.message,
      },
    };
  }

  return { success: true, data: result.data };
}

/**
 * Parse the data payload for a single SSE event based on its type.
 * The server emits JSON-wrapped payloads for text_delta and session_id.
 * Uses Zod for runtime validation to ensure payload shape correctness.
 */
export function parseSSEEventData(eventType: string, data: string): ParsedSSEEvent {
  switch (eventType) {
    case "text_delta": {
      const result = parseAndValidate(data, TextDeltaPayload, eventType);
      return result.success
        ? { type: "text_delta", text: result.data.text }
        : result.error;
    }
    case "session_id": {
      const result = parseAndValidate(data, SessionIdPayload, eventType);
      return result.success
        ? { type: "session_id", sessionId: result.data.session_id }
        : result.error;
    }
    case "tool_call": {
      const result = parseAndValidate(data, ToolCallPayload, eventType);
      return result.success
        ? { type: "tool_call", name: result.data.name, input: result.data.input }
        : result.error;
    }
    case "tool_result": {
      const result = parseAndValidate(data, ToolResultPayload, eventType);
      return result.success
        ? { type: "tool_result", name: result.data.name, result: result.data.result }
        : result.error;
    }
    case "error": {
      // Server may send JSON payloads like {"error":"...","message":"..."}.
      // Extract the human-readable message field when available.
      const errParse = safeJsonParse(data);
      if (errParse.success && typeof errParse.data === "object" && errParse.data !== null) {
        const obj = errParse.data as Record<string, unknown>;
        if (typeof obj.message === "string") {
          return { type: "error", message: obj.message };
        }
        if (typeof obj.error === "string") {
          return { type: "error", message: obj.error };
        }
      }
      return { type: "error", message: data };
    }
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
