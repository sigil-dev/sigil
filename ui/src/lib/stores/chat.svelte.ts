// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { api } from "$lib/api/client";
import { parseSSEEventData } from "./sse-parser";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:18789";

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

  private abortController: AbortController | null = null;

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

      const groups: WorkspaceGroup[] = [];
      for (const ws of workspaces) {
        const { data: sessData, error: sessErr } = await api.GET("/api/v1/workspaces/{id}/sessions", {
          params: { path: { id: ws.id } },
        });

        let sessions: SessionEntry[] = [];
        let loadError: string | undefined;

        if (sessErr) {
          console.warn(`Failed to load sessions for workspace ${ws.id}:`, sessErr);
          loadError = sessErr.detail || "Failed to load sessions";
        } else {
          sessions = (sessData?.sessions ?? []).map((s) => ({
            id: s.id,
            workspaceId: s.workspace_id,
            status: s.status,
          }));
        }

        groups.push({ id: ws.id, description: ws.description, sessions, loadError });
      }
      this.workspaceGroups = groups;
    } catch (error) {
      console.error("Failed to load sidebar:", error);
      this.error = "Failed to load sidebar data";
    } finally {
      this.sidebarLoading = false;
    }
  }

  /** Select an existing session */
  selectSession(workspaceId: string, sessionId: string): void {
    this.workspaceId = workspaceId;
    this.sessionId = sessionId;
    this.messages = [];
    this.error = null;
  }

  /** Start a new session in a workspace */
  newSession(workspaceId: string): void {
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
      // The openapi-fetch client doesn't properly support text/event-stream responses.
      const response = await fetch(`${API_BASE}/api/v1/chat/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify(body),
        signal: this.abortController.signal,
      });

      if (!response.ok) {
        const errText = await response.text();
        this.error = `Request failed: ${response.status} ${errText}`;
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
        return;
      }
      this.error = err instanceof Error ? err.message : "Stream failed";
      // Only remove message if no content was streamed yet
      const msg = this.messages.find((m) => m.id === assistantMessage.id);
      if (!msg?.content) {
        this.removeMessage(assistantMessage.id);
      }
    } finally {
      this.loading = false;
      this.abortController = null;
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
            // Per SSE spec: strip exactly one leading space if present (U+0020)
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
      reader.releaseLock();
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
        console.error(`SSE parse error for ${event.eventType}: ${event.error}`, event.rawData);
        this.error = `Failed to parse ${event.eventType} event`;
        break;
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
