// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { api, API_BASE } from "$lib/api/client";
import { logger } from "$lib/logger";
import { classifyError } from "./classify-error";
import { parseSSEEventData } from "./sse-parser";

/** Maximum SSE stream duration before automatic abort (5 minutes) */
const SSE_STREAM_TIMEOUT_MS = 5 * 60 * 1000;

/** Role of a chat message */
export type MessageRole = "user" | "assistant" | "tool";

/** A tool call embedded in an assistant message */
export interface ToolCall {
  name: string;
  status: "pending" | "running" | "complete" | "error";
  input?: unknown;
  result?: unknown;
}

/** A single chat message */
export interface ChatMessage {
  id: string;
  role: MessageRole;
  content: string;
  timestamp: number;
  toolCalls?: ToolCall[];
  incomplete?: boolean;
}

/** A session summary for the sidebar */
export interface SessionEntry {
  id: string;
  workspaceId: string;
  status: string;
}

/** Workspace with its sessions for sidebar grouping */
export interface WorkspaceGroup {
  id: string;
  description: string;
  sessions: SessionEntry[];
  loadError?: string;
}

let nextMessageId = 0;
function generateMessageId(): string {
  return `msg-${Date.now()}-${nextMessageId++}`;
}

/**
 * Extract error detail from response text, handling both JSON and non-JSON responses.
 */
function extractErrorDetail(text: string, status: number): string {
  try {
    const errJson = JSON.parse(text) as { detail?: string };
    if (errJson.detail !== undefined) return errJson.detail;
  } catch (parseErr) {
    logger.warn("Server returned non-JSON error response", {
      status,
      textPreview: text.substring(0, 200),
      parseError: parseErr instanceof Error ? parseErr.message : String(parseErr),
    });
    if (text.trim().startsWith("<")) {
      return `Server error (HTTP ${status})`;
    }
    return text.substring(0, 500);
  }
  return text;
}

/**
 * Chat store using Svelte 5 runes for reactivity.
 * Manages messages, session state, SSE streaming, and sidebar data.
 */
export class ChatStore {
  sessionId = $state<string | null>(null);
  workspaceId = $state<string | null>(null);
  messages = $state<ChatMessage[]>([]);
  loading = $state(false);
  error = $state<string | null>(null);
  workspaceGroups = $state<WorkspaceGroup[]>([]);
  sidebarLoading = $state(false);
  authToken = $state<string | null>(null);

  private abortController: AbortController | null = null;
  private streamLockFailed = false;

  /** Load workspaces and their sessions for the sidebar */
  async loadSidebar(): Promise<void> {
    this.sidebarLoading = true;
    try {
      const { data: wsData, error: wsErr } = await api.GET("/api/v1/workspaces");
      if (wsErr) {
        this.error = wsErr.detail || "Failed to load workspaces";
        return;
      }
      const workspaces = wsData?.workspaces ?? [];

      const groups = await Promise.all(
        workspaces.map(async (ws) => {
          const { data: sessData, error: sessErr } = await api.GET("/api/v1/workspaces/{id}/sessions", {
            params: { path: { id: ws.id } },
          });

          let sessions: SessionEntry[] = [];
          let loadError: string | undefined;

          if (sessErr) {
            logger.warn("Failed to load sessions for workspace", { workspaceId: ws.id, error: sessErr });
            loadError = sessErr.detail || "Failed to load sessions";
          } else {
            sessions = (sessData?.sessions ?? []).map((s) => ({
              id: s.id,
              workspaceId: s.workspace_id,
              status: s.status,
            }));
          }

          return { id: ws.id, description: ws.description, sessions, loadError };
        }),
      );
      this.workspaceGroups = groups;
    } catch (error) {
      logger.error("Failed to load sidebar", { error });
      const classified = classifyError(error);
      this.error = classified.message;
    } finally {
      this.sidebarLoading = false;
    }
  }

  /** Select an existing session */
  selectSession(workspaceId: string, sessionId: string): void {
    if (!workspaceId || workspaceId.trim() === "") {
      throw new Error("workspaceId cannot be empty");
    }
    this.workspaceId = workspaceId;
    this.sessionId = sessionId;
    this.messages = [];
    this.error = null;
  }

  /** Start a new session in a workspace */
  newSession(workspaceId: string): void {
    if (!workspaceId || workspaceId.trim() === "") {
      throw new Error("workspaceId cannot be empty");
    }
    this.workspaceId = workspaceId;
    this.sessionId = null;
    this.messages = [];
    this.error = null;
  }

  /** Cancel an in-progress streaming response */
  cancel(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
    this.loading = false;
  }

  /**
   * Send a message and stream the response via SSE.
   * Appends user message immediately, then streams assistant response.
   */
  async sendMessage(content: string): Promise<void> {
    if (!content.trim() || this.loading) return;
    if (this.streamLockFailed) {
      this.error = "Stream error — please reload the page to continue";
      return;
    }
    if (!this.workspaceId || this.workspaceId.trim() === "") {
      this.error = "No workspace selected";
      return;
    }

    this.error = null;

    const userMessage: ChatMessage = {
      id: generateMessageId(),
      role: "user",
      content: content.trim(),
      timestamp: Date.now(),
    };
    this.messages = [...this.messages, userMessage];

    const assistantMessage: ChatMessage = {
      id: generateMessageId(),
      role: "assistant",
      content: "",
      timestamp: Date.now(),
    };
    this.messages = [...this.messages, assistantMessage];

    this.loading = true;
    this.abortController = new AbortController();

    try {
      const body: Record<string, unknown> = { content: content.trim() };
      if (this.workspaceId) body.workspace_id = this.workspaceId;
      if (this.sessionId) body.session_id = this.sessionId;

      // Note: Using raw fetch for SSE streaming endpoint instead of typed client.
      // openapi-fetch supports streaming via parseAs: "stream" (v0.9.4+), but raw
      // fetch is simpler for direct SSE event parsing from response.body.
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
      };
      if (this.authToken) {
        headers["Authorization"] = `Bearer ${this.authToken}`;
      }

      const timeoutSignal = AbortSignal.timeout(SSE_STREAM_TIMEOUT_MS);
      const response = await fetch(`${API_BASE}/api/v1/chat/stream`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: AbortSignal.any([this.abortController.signal, timeoutSignal]),
      });

      if (!response.ok) {
        const errText = await response.text();
        const detail = extractErrorDetail(errText, response.status);

        // Handle specific HTTP error codes
        switch (response.status) {
          case 401:
            this.error = "Authentication required — please log in";
            this.authToken = null;
            break;
          case 403:
            this.error = "Access denied — insufficient permissions for this workspace";
            break;
          case 429:
            this.error = "Rate limit exceeded — please wait and try again";
            break;
          case 503:
            this.error = "Gateway unavailable — please try again later";
            break;
          default:
            this.error = `Request failed: ${response.status} — ${detail}`;
        }
        this.removeMessage(assistantMessage.id);
        return;
      }

      if (!response.body) {
        this.error = "No response body";
        this.removeMessage(assistantMessage.id);
        return;
      }

      await this.readSSEStream(response.body, assistantMessage.id);
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === "AbortError") {
        // If we aborted due to parse error, this.error is already set - don't overwrite
        if (this.error) {
          // Empty message cleanup is handled in finally block
          return;
        }
        // User-initiated cancellation - clean up empty message
        const msg = this.messages.find((m) => m.id === assistantMessage.id);
        if (!msg?.content) {
          this.removeMessage(assistantMessage.id);
        }
        return;
      }
      if (err instanceof DOMException && err.name === "TimeoutError") {
        logger.warn("Request timed out");
        this.error = "Request timed out — the gateway took too long to respond";
        const msg = this.messages.find((m) => m.id === assistantMessage.id);
        if (!msg?.content) {
          this.removeMessage(assistantMessage.id);
        }
        return;
      }
      // Separate fetch errors (TypeError for network failure) from SSE stream errors.
      const errorType = err instanceof Error ? err.constructor.name : typeof err;
      if (err instanceof TypeError) {
        logger.error("Fetch network error", { errorType, error: err });
        this.error = "Network error — could not reach the gateway";
      } else {
        logger.error("SSE stream error", { errorType, error: err });
        const classified = classifyError(err);
        this.error = classified.message;
      }
      // Only remove message if no content was streamed yet
      const msg = this.messages.find((m) => m.id === assistantMessage.id);
      if (!msg?.content) {
        this.removeMessage(assistantMessage.id);
      }
    } finally {
      this.loading = false;
      this.abortController = null;
      // Clean up empty assistant message if an error occurred
      if (this.error) {
        const msg = this.messages.find((m) => m.id === assistantMessage.id);
        if (!msg?.content) {
          this.removeMessage(assistantMessage.id);
        }
      }
    }
  }

  /** Parse SSE events from a ReadableStream and update the assistant message.
   *  Follows SSE spec: buffers data lines and dispatches on blank-line boundaries. */
  private async readSSEStream(body: ReadableStream<Uint8Array>, messageId: string): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let eventType = "";
    const dataLines: string[] = [];

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line === "") {
            // Blank line = dispatch buffered event per SSE spec
            if (dataLines.length > 0) {
              const data = dataLines.join("\n");
              this.handleSSEEvent(eventType || "message", data, messageId);
              dataLines.length = 0;
              eventType = "";
            }
          } else if (line.startsWith("event:")) {
            eventType = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            // Per SSE spec: strip at most one leading space after the colon (U+0020)
            let value = line.slice(5);
            if (value.length > 0 && value.charCodeAt(0) === 0x20) {
              value = value.slice(1);
            }
            dataLines.push(value);
          }
        }
      }

      // Flush any remaining buffered event
      if (dataLines.length > 0) {
        const data = dataLines.join("\n");
        this.handleSSEEvent(eventType || "message", data, messageId);
      }
    } finally {
      try {
        reader.releaseLock();
      } catch (err) {
        logger.error("Failed to release SSE reader lock", { error: err });
        // If releaseLock fails, stream is still locked. Try to cancel and retry.
        try {
          await reader.cancel();
          reader.releaseLock();
        } catch (retryErr) {
          logger.error("Failed to cancel and retry reader lock release", { error: retryErr });
          this.streamLockFailed = true;
          this.error = "Stream error — please reload the page to continue";
        }
      }
    }
  }

  /** Handle a single SSE event using the typed parser */
  private handleSSEEvent(eventType: string, data: string, messageId: string): void {
    const event = parseSSEEventData(eventType, data);

    switch (event.type) {
      case "text_delta":
        this.appendToMessage(messageId, event.text);
        break;
      case "session_id":
        this.sessionId = event.sessionId;
        break;
      case "tool_call":
        this.addToolCall(messageId, {
          name: event.name,
          status: "running",
          input: event.input,
        });
        break;
      case "tool_result":
        this.completeToolCall(messageId, event.name, event.result);
        break;
      case "error":
        this.error = event.message;
        break;
      case "done":
        break;
      case "parse_error":
        logger.error("SSE parse error", {
          eventType: event.eventType,
          error: event.error,
          rawData: event.rawData,
        });
        this.error = `Failed to parse ${event.eventType} event`;
        this.markMessageIncomplete(messageId);
        // Abort stream on parse error to prevent further invalid events
        this.abortController?.abort();
        return;
    }
  }

  /** Mark a message as incomplete when the stream ends with an error */
  private markMessageIncomplete(messageId: string): void {
    const msg = this.messages.find((m) => m.id === messageId);
    if (msg && msg.content) {
      this.messages = this.messages.map((m) => m.id === messageId ? { ...m, incomplete: true } : m);
    }
  }

  /** Append text content to a message by ID */
  private appendToMessage(messageId: string, text: string): void {
    this.messages = this.messages.map((m) => m.id === messageId ? { ...m, content: m.content + text } : m);
  }

  /** Add a tool call to a message */
  private addToolCall(messageId: string, toolCall: ToolCall): void {
    this.messages = this.messages.map((m) => {
      if (m.id !== messageId) return m;
      return { ...m, toolCalls: [...(m.toolCalls ?? []), toolCall] };
    });
  }

  /** Complete the most recent running tool call matching the given name */
  private completeToolCall(messageId: string, toolName: string, result?: unknown): void {
    this.messages = this.messages.map((m) => {
      if (m.id !== messageId) return m;
      const toolCalls = [...(m.toolCalls ?? [])];
      // Find the most recent "running" tool call with this name
      for (let i = toolCalls.length - 1; i >= 0; i--) {
        if (toolCalls[i].name === toolName && toolCalls[i].status === "running") {
          toolCalls[i] = { ...toolCalls[i], status: "complete", result };
          break;
        }
      }
      return { ...m, toolCalls };
    });
  }

  /** Remove a message by ID (used when streaming fails) */
  private removeMessage(messageId: string): void {
    this.messages = this.messages.filter((m) => m.id !== messageId);
  }
}

/** Singleton chat store instance */
export const chatStore = new ChatStore();
