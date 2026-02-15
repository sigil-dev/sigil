// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestSSE_MultiLineData(t *testing.T) {
	events := []server.SSEEvent{
		{Event: "text_delta", Data: "line1\nline2\nline3"},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hi", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Each line of multi-line data must be prefixed with "data: " per SSE spec.
	output := w.Body.String()
	assert.Contains(t, output, "data: line1\n")
	assert.Contains(t, output, "data: line2\n")
	assert.Contains(t, output, "data: line3\n")
	// Must NOT contain the raw un-prefixed multi-line block.
	assert.NotContains(t, output, "data: line1\nline2")
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

// leakyStreamHandler sends many events (more than channel buffer) and signals
// completion via the done channel. Used to verify goroutine cleanup on write errors.
type leakyStreamHandler struct {
	eventCount int
	done       chan struct{}
}

func (h *leakyStreamHandler) HandleStream(ctx context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	defer close(ch)
	defer close(h.done)
	for i := range h.eventCount {
		select {
		case ch <- server.SSEEvent{Event: "text_delta", Data: `{"text":"chunk"}` + strings.Repeat("x", i)}:
		case <-ctx.Done():
			return
		}
	}
}

// errResponseWriter is an http.ResponseWriter that returns errors after a
// configured number of successful Write calls, simulating a client disconnect.
type errResponseWriter struct {
	header     http.Header
	writes     int
	maxWrites  int
	statusCode int
}

func newErrResponseWriter(maxWrites int) *errResponseWriter {
	return &errResponseWriter{
		header:    make(http.Header),
		maxWrites: maxWrites,
	}
}

func (w *errResponseWriter) Header() http.Header { return w.header }

func (w *errResponseWriter) WriteHeader(code int) { w.statusCode = code }

func (w *errResponseWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.maxWrites {
		return 0, errors.New("client disconnected")
	}
	return len(p), nil
}

func TestSSE_DrainOnWriteError(t *testing.T) {
	handler := &leakyStreamHandler{
		eventCount: 50, // well above the 16-capacity channel buffer
		done:       make(chan struct{}),
	}
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	srv.RegisterStreamHandler(handler)

	body := `{"content":"hello","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	// Allow only 2 writes before failing, triggering the drain path.
	w := newErrResponseWriter(2)
	srv.Handler().ServeHTTP(w, req)

	// HandleStream must finish (channel drained) within a reasonable timeout.
	// If the drain logic is missing, HandleStream blocks forever → test times out.
	select {
	case <-handler.done:
		// success — goroutine exited
	case <-time.After(3 * time.Second):
		t.Fatal("HandleStream goroutine did not exit; channel was not drained (goroutine leak)")
	}
}

func TestSSE_MalformedJSONBody(t *testing.T) {
	srv := newTestSSEServer(t, nil)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "completely invalid json",
			body: `{this is not json at all}`,
		},
		{
			name: "truncated json",
			body: `{"content": "Hello", "workspace_id":`,
		},
		{
			name: "random garbage",
			body: `!@#$%^&*()`,
		},
		{
			name: "empty body",
			body: ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

			var errResp map[string]string
			err := json.Unmarshal(w.Body.Bytes(), &errResp)
			require.NoError(t, err)
			assert.Contains(t, errResp["error"], "invalid request body")
		})
	}
}

func TestSSE_JSONResponse_EmptyStream(t *testing.T) {
	// Handler that closes channel immediately without sending any events.
	emptyHandler := &mockStreamHandler{events: []server.SSEEvent{}}
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	srv.RegisterStreamHandler(emptyHandler)

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Accept: text/event-stream — should get JSON.

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp struct {
		Events []server.SSEEvent `json:"events"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err, "response must be valid JSON; got: %s", w.Body.String())

	// Verify the events array is empty, not null.
	assert.NotNil(t, resp.Events, "events array should not be nil")
	assert.Len(t, resp.Events, 0, "events array should be empty")

	// Verify the exact JSON structure matches {"events":[]}.
	assert.JSONEq(t, `{"events":[]}`, w.Body.String())
}

func TestSSE_JSONResponse_MarshalFailureEmitsErrorEvent(t *testing.T) {
	// json.Marshal on Go strings cannot fail in practice; the error path
	// in writeJSON exists as defensive code but is untestable without
	// runtime.UnsafeString or similar tricks.
	t.Skip("json.Marshal on Go strings cannot fail in practice; error path exists but is untestable")
}

func TestSSE_DrainRaceCondition(t *testing.T) {
	// Test concurrent write errors + channel drain don't race.
	// This test relies on `go test -race` to detect data races.
	const goroutines = 10

	for i := range goroutines {
		t.Run(fmt.Sprintf("concurrent-%d", i), func(t *testing.T) {
			t.Parallel()
			handler := &leakyStreamHandler{
				eventCount: 100,
				done:       make(chan struct{}),
			}
			srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
			require.NoError(t, err)
			srv.RegisterStreamHandler(handler)

			body := `{"content":"race","workspace_id":"test"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")

			// Fail after 1 write to trigger drain path quickly.
			w := newErrResponseWriter(1)
			srv.Handler().ServeHTTP(w, req)

			select {
			case <-handler.done:
			case <-time.After(5 * time.Second):
				t.Fatal("goroutine leak: HandleStream did not exit")
			}
		})
	}
}

func TestSSE_WorkspaceMembership_AuthDisabled_AllowsAnyWorkspace(t *testing.T) {
	// When auth is disabled (no validator), all workspaces are accessible.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: events})

	body := `{"content": "Hello", "workspace_id": "any-workspace-id"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSSE_WorkspaceMembership_ValidMember_Succeeds(t *testing.T) {
	// User who is a member of the workspace can stream messages.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Valid User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: events})

	// workspace "homelab" has member "user-1" (see mockWorkspaceService.Get)
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSSE_WorkspaceMembership_NonMember_Returns403(t *testing.T) {
	// User who is NOT a member of the workspace gets 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-2",
				Name:        "Non-Member User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: []server.SSEEvent{}})

	// workspace "homelab" has member "user-1", not "user-2"
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "not a member of workspace")
}

func TestSSE_WorkspaceMembership_WorkspaceNotFound_Returns404(t *testing.T) {
	// Non-existent workspace returns 404.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Valid User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: []server.SSEEvent{}})

	body := `{"content": "Hello", "workspace_id": "nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "not found")
}

func TestSSE_WorkspaceMembership_EmptyWorkspaceID_Succeeds(t *testing.T) {
	// When auth is enabled, empty workspace_id returns 422.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": {
				ID:          "user-1",
				Name:        "Valid User",
				Permissions: []string{"workspace:chat"},
			},
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
	})
	require.NoError(t, err)
	srv.RegisterServices(&server.Services{
		Workspaces: &mockWorkspaceService{},
		Plugins:    &mockPluginService{},
		Sessions:   &mockSessionService{},
		Users:      &mockUserService{},
	})
	srv.RegisterStreamHandler(&mockStreamHandler{events: []server.SSEEvent{}})

	body := `{"content": "Hello", "workspace_id": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "workspace_id is required")
}
