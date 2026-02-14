// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the api module before importing ChatStore
vi.mock("$lib/api/client", () => ({
  api: {
    GET: vi.fn(),
  },
}));

// Mock import.meta.env
vi.stubEnv("VITE_API_URL", "http://localhost:18789");

import { api } from "$lib/api/client";
import { ChatStore } from "./chat.svelte";

// Helper to create a mock ReadableStream from SSE text
function createSSEStream(sseText: string): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(sseText));
      controller.close();
    },
  });
}

// Helper to create a mock fetch Response with SSE body
function mockSSEResponse(sseText: string): Response {
  return new Response(createSSEStream(sseText), {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

describe("ChatStore", () => {
  let store: ChatStore;

  beforeEach(() => {
    store = new ChatStore();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    store.cancel();
  });

  describe("sendMessage", () => {
    it("adds user message and streams assistant response", async () => {
      const sseData = [
        "event: session_id\ndata: {\"session_id\":\"sess-1\"}\n\n",
        "event: text_delta\ndata: {\"text\":\"Hello\"}\n\n",
        "event: text_delta\ndata: {\"text\":\" world\"}\n\n",
        "event: done\ndata: {}\n\n",
      ].join("");

      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockSSEResponse(sseData)));

      store.newSession("ws-1");
      await store.sendMessage("Hi");

      expect(store.messages).toHaveLength(2);
      expect(store.messages[0].role).toBe("user");
      expect(store.messages[0].content).toBe("Hi");
      expect(store.messages[1].role).toBe("assistant");
      expect(store.messages[1].content).toBe("Hello world");
      expect(store.sessionId).toBe("sess-1");
      expect(store.loading).toBe(false);
      expect(store.error).toBeNull();
    });

    it("handles HTTP error with JSON body", async () => {
      const errorResponse = new Response(
        JSON.stringify({ status: 400, detail: "Invalid workspace" }),
        { status: 400 },
      );
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(errorResponse));

      store.newSession("ws-1");
      await store.sendMessage("test");

      expect(store.error).toContain("Invalid workspace");
      // User message should remain, assistant message removed
      expect(store.messages).toHaveLength(1);
      expect(store.messages[0].role).toBe("user");
    });

    it("handles HTTP error with non-JSON body", async () => {
      const errorResponse = new Response("Internal Server Error", { status: 500 });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(errorResponse));

      store.newSession("ws-1");
      await store.sendMessage("test");

      expect(store.error).toContain("500");
      expect(store.error).toContain("Internal Server Error");
    });

    it("ignores empty or whitespace-only messages", async () => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);

      store.newSession("ws-1");
      await store.sendMessage("   ");

      expect(fetchMock).not.toHaveBeenCalled();
      expect(store.messages).toHaveLength(0);
    });

    it("prevents concurrent messages while loading", async () => {
      const fetchMock = vi.fn().mockResolvedValue(
        mockSSEResponse("event: done\ndata: {}\n\n"),
      );
      vi.stubGlobal("fetch", fetchMock);

      store.newSession("ws-1");
      // Start a message (don't await)
      const p1 = store.sendMessage("first");
      // Try to send another while loading
      const p2 = store.sendMessage("second");

      await Promise.all([p1, p2]);

      // Only one fetch call should have been made
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("processes tool_call and tool_result events", async () => {
      const sseData = [
        "event: text_delta\ndata: {\"text\":\"Let me search...\"}\n\n",
        "event: tool_call\ndata: {\"name\":\"web-search\",\"input\":{\"query\":\"test\"}}\n\n",
        "event: tool_result\ndata: {\"name\":\"web-search\",\"result\":{\"url\":\"http://example.com\"}}\n\n",
        "event: text_delta\ndata: {\"text\":\" Found it!\"}\n\n",
        "event: done\ndata: {}\n\n",
      ].join("");

      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockSSEResponse(sseData)));

      store.newSession("ws-1");
      await store.sendMessage("search for test");

      const assistant = store.messages[1];
      expect(assistant.content).toBe("Let me search... Found it!");
      expect(assistant.toolCalls).toHaveLength(1);
      expect(assistant.toolCalls![0].name).toBe("web-search");
      expect(assistant.toolCalls![0].status).toBe("complete");
      expect(assistant.toolCalls![0].result).toEqual({ url: "http://example.com" });
    });

    it("handles error event mid-stream", async () => {
      const sseData = [
        "event: text_delta\ndata: {\"text\":\"partial\"}\n\n",
        "event: error\ndata: rate limit exceeded\n\n",
      ].join("");

      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockSSEResponse(sseData)));

      store.newSession("ws-1");
      await store.sendMessage("test");

      expect(store.error).toBe("rate limit exceeded");
      // Assistant message should be kept since it has content
      expect(store.messages).toHaveLength(2);
      expect(store.messages[1].content).toBe("partial");
    });

    it("handles parse_error events from malformed server data", async () => {
      const sseData = [
        "event: session_id\ndata: not-json\n\n",
        "event: done\ndata: {}\n\n",
      ].join("");

      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockSSEResponse(sseData)));

      store.newSession("ws-1");
      await store.sendMessage("test");

      expect(store.error).toContain("parse");
    });
  });

  describe("cancel", () => {
    it("aborts in-progress streaming", async () => {
      // Create a stream that hangs until aborted
      let abortCallback: (() => void) | null = null as (() => void) | null;
      const stream = new ReadableStream({
        async pull(controller) {
          // Wait for abort signal
          await new Promise<void>((resolve) => {
            abortCallback = () => {
              controller.error(new DOMException("Aborted", "AbortError"));
              resolve();
            };
          });
        },
      });
      const response = new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

      store.newSession("ws-1");
      const sendPromise = store.sendMessage("test");

      // Give it a tick to start
      await new Promise((r) => setTimeout(r, 10));
      expect(store.loading).toBe(true);

      // Abort the stream
      store.cancel();
      if (abortCallback) abortCallback();
      await sendPromise;

      expect(store.loading).toBe(false);
      expect(store.error).toBeNull(); // AbortError is swallowed
    });
  });

  describe("selectSession and newSession", () => {
    it("selectSession sets workspace and session IDs", () => {
      store.selectSession("ws-1", "sess-1");
      expect(store.workspaceId).toBe("ws-1");
      expect(store.sessionId).toBe("sess-1");
      expect(store.messages).toEqual([]);
      expect(store.error).toBeNull();
    });

    it("newSession sets workspace and clears session", () => {
      store.selectSession("ws-1", "sess-1");
      store.newSession("ws-2");
      expect(store.workspaceId).toBe("ws-2");
      expect(store.sessionId).toBeNull();
      expect(store.messages).toEqual([]);
    });
  });

  describe("loadSidebar", () => {
    it("populates workspace groups with sessions", async () => {
      const mockApi = vi.mocked(api.GET);
      mockApi
        .mockResolvedValueOnce({
          data: { workspaces: [{ id: "ws-1", description: "Work" }, { id: "ws-2", description: "Personal" }] },
          error: undefined,
          response: new Response(),
        } as any)
        .mockResolvedValueOnce({
          data: { sessions: [{ id: "s1", workspace_id: "ws-1", status: "active" }] },
          error: undefined,
          response: new Response(),
        } as any)
        .mockResolvedValueOnce({
          data: { sessions: [] },
          error: undefined,
          response: new Response(),
        } as any);

      await store.loadSidebar();

      expect(store.workspaceGroups).toHaveLength(2);
      expect(store.workspaceGroups[0].id).toBe("ws-1");
      expect(store.workspaceGroups[0].sessions).toHaveLength(1);
      expect(store.workspaceGroups[1].id).toBe("ws-2");
      expect(store.workspaceGroups[1].sessions).toHaveLength(0);
      expect(store.sidebarLoading).toBe(false);
    });

    it("sets loadError on per-workspace session fetch failure", async () => {
      const mockApi = vi.mocked(api.GET);
      mockApi
        .mockResolvedValueOnce({
          data: { workspaces: [{ id: "ws-1", description: "Work" }] },
          error: undefined,
          response: new Response(),
        } as any)
        .mockResolvedValueOnce({
          data: undefined,
          error: { detail: "Permission denied" },
          response: new Response(),
        } as any);

      await store.loadSidebar();

      expect(store.workspaceGroups).toHaveLength(1);
      expect(store.workspaceGroups[0].loadError).toBe("Permission denied");
      expect(store.workspaceGroups[0].sessions).toHaveLength(0);
    });

    it("handles workspace list fetch failure", async () => {
      const mockApi = vi.mocked(api.GET);
      mockApi.mockResolvedValueOnce({
        data: undefined,
        error: { detail: "Unauthorized" },
        response: new Response(),
      } as any);

      await store.loadSidebar();

      expect(store.error).toBe("Unauthorized");
      expect(store.workspaceGroups).toHaveLength(0);
    });
  });
});
