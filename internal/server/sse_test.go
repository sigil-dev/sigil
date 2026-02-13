// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStreamHandler sends a fixed sequence of SSE events for testing.
type mockStreamHandler struct {
	events []server.SSEEvent
}

func (m *mockStreamHandler) HandleStream(_ context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	for _, e := range m.events {
		ch <- e
	}
	close(ch)
}

func newTestSSEServer(t *testing.T, events []server.SSEEvent) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)

	srv.RegisterStreamHandler(&mockStreamHandler{events: events})
	return srv
}

func TestSSE_StreamsEvents(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "text_delta", Data: `{"text":" world"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hello", "workspace_id": "homelab", "session_id": "sess-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")

	// Parse SSE events from response.
	scanner := bufio.NewScanner(strings.NewReader(w.Body.String()))
	var parsed []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			parsed = append(parsed, strings.TrimPrefix(line, "data: "))
		}
	}
	assert.Len(t, parsed, 3)
	assert.Contains(t, parsed[0], "Hello")
}

func TestSSE_EventFormat(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hi"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hi", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Each event should have "event:" and "data:" lines.
	output := w.Body.String()
	assert.Contains(t, output, "event: text_delta")
	assert.Contains(t, output, "event: done")
	assert.Contains(t, output, "data: ")
}

func TestSSE_MissingContent(t *testing.T) {
	srv := newTestSSEServer(t, nil)

	body := `{"workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestSSE_NoStreamHandler(t *testing.T) {
	// Server without a stream handler registered.
	srv := newTestServer(t)

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should return error when no handler is configured.
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestSSE_CompoundAcceptHeader(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hi"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hi", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream, application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")
}

func TestSSE_JSONResponse_InvalidEventData(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: "plain text not json"},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Accept: text/event-stream — should get JSON.

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// The response must be valid JSON even when event data is plain text.
	type jsonEvent struct {
		Event string          `json:"event"`
		Data  json.RawMessage `json:"data"`
	}
	var resp struct {
		Events []jsonEvent `json:"events"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err, "response must be valid JSON; got: %s", w.Body.String())
	assert.Len(t, resp.Events, 2)

	// Events should include their type.
	assert.Equal(t, "text_delta", resp.Events[0].Event)
	assert.Equal(t, "done", resp.Events[1].Event)

	// The plain text event should be wrapped as a JSON string.
	assert.Equal(t, `"plain text not json"`, string(resp.Events[0].Data))
	// The valid JSON event should pass through unchanged.
	assert.Equal(t, `{}`, string(resp.Events[1].Data))
}

func TestSSE_JSONResponse(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"response"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Accept: text/event-stream — should get JSON.

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	type jsonEvent struct {
		Event string          `json:"event"`
		Data  json.RawMessage `json:"data"`
	}
	var resp struct {
		Events []jsonEvent `json:"events"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Events, 2)

	// Events must include their type alongside data.
	assert.Equal(t, "text_delta", resp.Events[0].Event)
	assert.Equal(t, "done", resp.Events[1].Event)
}
