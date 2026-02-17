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
		ListenAddr:    "127.0.0.1:0",
		StreamHandler: &mockStreamHandler{events: events},
	})
	require.NoError(t, err)
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

func TestSSE_NonJSONDataIsWrapped(t *testing.T) {
	// Non-JSON data should be wrapped as a JSON string via ensureValidJSON.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: "plain text not json"},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// The plain text should be wrapped as a JSON string in the SSE data field.
	output := w.Body.String()
	assert.Contains(t, output, `"plain text not json"`)
}

func TestSSE_MultiLineDataIsWrapped(t *testing.T) {
	// Multi-line non-JSON data should be wrapped as a JSON string (with escaped newlines).
	events := []server.SSEEvent{
		{Event: "text_delta", Data: "line1\nline2\nline3"},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hi", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Multi-line raw text is wrapped as a JSON string with escaped newlines.
	output := w.Body.String()
	assert.Contains(t, output, `"line1\nline2\nline3"`)
	assert.Contains(t, output, "event: text_delta")
	assert.Contains(t, output, "event: done")
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
	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"hello","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Allow only 2 writes before failing, triggering the drain path.
	w := newErrResponseWriter(2)
	srv.Handler().ServeHTTP(w, req)

	// HandleStream must finish (channel drained) within a reasonable timeout.
	// If the drain logic is missing, HandleStream blocks forever -> test times out.
	select {
	case <-handler.done:
		// success - goroutine exited
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

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestSSE_SkipsEventTypeWithNewline(t *testing.T) {
	// Security test: events with newlines in the event type field should be skipped.
	// This prevents injection of arbitrary SSE fields via newline characters.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"valid1"}`},
		{Event: "text_delta\ninjected: malicious", Data: `{"text":"should be skipped"}`},
		{Event: "text_delta", Data: `{"text":"valid2"}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hello", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")

	// Parse SSE events - the malicious event should be missing.
	output := w.Body.String()
	// Should contain the two valid text_delta events.
	assert.Contains(t, output, "event: text_delta\n")
	// Count occurrences of "event: text_delta" - should be 2, not 3.
	eventCount := strings.Count(output, "event: text_delta")
	assert.Equal(t, 2, eventCount, "should have exactly 2 valid events, malicious one skipped")
	// The malicious data should not appear in output.
	assert.NotContains(t, output, "malicious")
	assert.NotContains(t, output, "injected:")
}

func TestSSE_SkipsEventTypeWithCarriageReturn(t *testing.T) {
	// Security test: events with carriage returns in the event type should be skipped.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"valid"}`},
		{Event: "text_delta\rinjected: malicious", Data: `{"text":"should be skipped"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Hello", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	output := w.Body.String()
	// Should only contain the 2 valid events (text_delta and done), not the malicious one.
	assert.Contains(t, output, "event: text_delta\n")
	assert.Contains(t, output, "event: done\n")
	assert.NotContains(t, output, "malicious")
	assert.NotContains(t, output, "injected:")
}

func TestSSE_WorkspaceMembership_AuthDisabled_AllowsAnyWorkspace(t *testing.T) {
	// When auth is disabled (no validator), all workspaces are accessible.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "done", Data: `{}`},
	}
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: events},
	})
	require.NoError(t, err)

	body := `{"content": "Hello", "workspace_id": "any-workspace-id"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

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
			"user-token": mustNewAuthenticatedUser("user-1", "Valid User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: events},
	})
	require.NoError(t, err)

	// workspace "homelab" has member "user-1" (see mockWorkspaceService.Get)
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSSE_WorkspaceMembership_NonMember_Returns403(t *testing.T) {
	// User who is NOT a member of the workspace gets 403.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-2", "Non-Member User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: []server.SSEEvent{}},
	})
	require.NoError(t, err)

	// workspace "homelab" has member "user-1", not "user-2"
	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSSE_WorkspaceMembership_WorkspaceNotFound_Returns403(t *testing.T) {
	// Non-existent workspace returns 403 to prevent enumeration.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Valid User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: []server.SSEEvent{}},
	})
	require.NoError(t, err)

	body := `{"content": "Hello", "workspace_id": "nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSSE_WorkspaceMembership_EmptyWorkspaceID_Returns422(t *testing.T) {
	// When auth is enabled, empty workspace_id returns 422.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "Valid User", []string{"workspace:chat"}),
		},
	}

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services: server.NewServicesForTest(
			&mockWorkspaceService{},
			&mockPluginService{},
			&mockSessionService{},
			&mockUserService{},
		),
		StreamHandler: &mockStreamHandler{events: []server.SSEEvent{}},
	})
	require.NoError(t, err)

	body := `{"content": "Hello", "workspace_id": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer user-token")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
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
			srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
			require.NoError(t, err)

			body := `{"content":"race","workspace_id":"test"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

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

// rapidStreamHandler sends events as fast as possible without pausing,
// respecting context cancellation. Used to test race conditions during drain.
type rapidStreamHandler struct {
	eventCount int
	started    chan struct{}
	done       chan struct{}
}

func (h *rapidStreamHandler) HandleStream(ctx context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	defer close(ch)
	defer close(h.done)
	close(h.started)

	for i := range h.eventCount {
		select {
		case ch <- server.SSEEvent{
			Event: "text_delta",
			Data:  fmt.Sprintf(`{"text":"chunk-%d"}`, i),
		}:
		case <-ctx.Done():
			return
		}
	}
}

func TestSSE_DrainRaceCondition_CancelDuringRapidWrites(t *testing.T) {
	handler := &rapidStreamHandler{
		eventCount: 200,
		started:    make(chan struct{}),
		done:       make(chan struct{}),
	}

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"test rapid cancellation","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	w := &countingResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		writeTrigger:     3,
		onTrigger:        cancel,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Handler().ServeHTTP(w, req)
	}()

	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start within timeout")
	}

	select {
	case <-handler.done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleStream goroutine did not exit; possible goroutine leak or race in drain logic")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP handler did not finish")
	}

	assert.GreaterOrEqual(t, w.writeCount, 3, "should have written at least 3 times before cancellation")
}

// countingResponseWriter wraps httptest.ResponseRecorder and calls onTrigger
// after writeTrigger Write calls.
type countingResponseWriter struct {
	*httptest.ResponseRecorder
	writeCount   int
	writeTrigger int
	onTrigger    func()
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	w.writeCount++
	if w.writeCount == w.writeTrigger && w.onTrigger != nil {
		w.onTrigger()
	}
	return w.ResponseRecorder.Write(p)
}

func (w *countingResponseWriter) Flush() {
	w.ResponseRecorder.Flush()
}

// concurrentStreamHandler simulates multiple concurrent writers to the event channel.
type concurrentStreamHandler struct {
	goroutines int
	eventsEach int
	started    chan struct{}
	done       chan struct{}
}

func (h *concurrentStreamHandler) HandleStream(ctx context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	defer close(ch)
	defer close(h.done)
	close(h.started)

	writerDone := make(chan struct{}, h.goroutines)
	for i := range h.goroutines {
		go func(id int) {
			defer func() {
				writerDone <- struct{}{}
			}()
			for j := range h.eventsEach {
				select {
				case ch <- server.SSEEvent{
					Event: "text_delta",
					Data:  fmt.Sprintf(`{"text":"goroutine-%d-event-%d"}`, id, j),
				}:
				case <-ctx.Done():
					return
				}
			}
		}(i)
	}

	completedWriters := 0
	for completedWriters < h.goroutines {
		select {
		case <-writerDone:
			completedWriters++
		case <-ctx.Done():
			for completedWriters < h.goroutines {
				<-writerDone
				completedWriters++
			}
			return
		}
	}
}

func TestSSE_ConcurrentWriteAndDrain(t *testing.T) {
	handler := &concurrentStreamHandler{
		goroutines: 10,
		eventsEach: 50,
		started:    make(chan struct{}),
		done:       make(chan struct{}),
	}

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"concurrent race test","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	w := &countingResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		writeTrigger:     10,
		onTrigger:        cancel,
	}

	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		srv.Handler().ServeHTTP(w, req)
	}()

	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start within timeout")
	}

	select {
	case <-handler.done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleStream goroutine did not exit; possible goroutine leak or race condition")
	}

	select {
	case <-httpDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP handler did not finish within timeout")
	}

	assert.GreaterOrEqual(t, w.writeCount, 10, "should have written at least 10 times before cancellation")
}

// aggressiveStreamHandler produces events very rapidly to stress-test race conditions.
type aggressiveStreamHandler struct {
	eventCount int
	done       chan struct{}
}

func (h *aggressiveStreamHandler) HandleStream(ctx context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	defer close(ch)
	defer close(h.done)

	for i := range h.eventCount {
		select {
		case ch <- server.SSEEvent{
			Event: "text_delta",
			Data:  fmt.Sprintf(`{"id":%d}`, i),
		}:
		case <-ctx.Done():
			return
		}
	}
}

func TestSSE_DrainRaceCondition_ComprehensiveStressTest(t *testing.T) {
	const iterations = 20

	for i := range iterations {
		t.Run(fmt.Sprintf("iteration-%d", i), func(t *testing.T) {
			t.Parallel()

			handler := &aggressiveStreamHandler{
				eventCount: 500,
				done:       make(chan struct{}),
			}

			srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
			require.NoError(t, err)

			body := `{"content":"race stress test","workspace_id":"test"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			maxWrites := (i % 3) + 1
			w := newErrResponseWriter(maxWrites)
			srv.Handler().ServeHTTP(w, req)

			select {
			case <-handler.done:
			case <-time.After(5 * time.Second):
				t.Fatal("HandleStream goroutine did not exit; channel not drained (possible race or deadlock)")
			}

			assert.GreaterOrEqual(t, w.writes, 1, "should have written at least once before error")
		})
	}
}

func TestSSE_DrainRaceCondition_MultipleConsumers(t *testing.T) {
	const consumers = 5

	for i := range consumers {
		t.Run(fmt.Sprintf("consumer-%d", i), func(t *testing.T) {
			t.Parallel()

			handler := &aggressiveStreamHandler{
				eventCount: 200,
				done:       make(chan struct{}),
			}

			srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
			require.NoError(t, err)

			body := `{"content":"multi-consumer race","workspace_id":"test"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := newErrResponseWriter(2)
			srv.Handler().ServeHTTP(w, req)

			select {
			case <-handler.done:
			case <-time.After(5 * time.Second):
				t.Fatal("HandleStream did not exit; drain failed")
			}
		})
	}
}

// oscillatingStreamHandler alternates between sending bursts and pausing.
type oscillatingStreamHandler struct {
	burstSize int
	pauses    int
	done      chan struct{}
}

func (h *oscillatingStreamHandler) HandleStream(ctx context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	defer close(ch)
	defer close(h.done)

	for pause := range h.pauses {
		for i := range h.burstSize {
			select {
			case ch <- server.SSEEvent{
				Event: "text_delta",
				Data:  fmt.Sprintf(`{"burst":%d,"event":%d}`, pause, i),
			}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-time.After(1 * time.Millisecond):
		case <-ctx.Done():
			return
		}
	}
}

func TestSSE_DrainRaceCondition_BurstyPattern(t *testing.T) {
	handler := &oscillatingStreamHandler{
		burstSize: 30,
		pauses:    10,
		done:      make(chan struct{}),
	}

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"bursty pattern race test","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := newErrResponseWriter(50)
	srv.Handler().ServeHTTP(w, req)

	select {
	case <-handler.done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleStream did not exit; drain failed with bursty pattern")
	}
}

func TestSSE_DrainOnContextCancellation(t *testing.T) {
	handler := &leakyStreamHandler{
		eventCount: 100,
		done:       make(chan struct{}),
	}

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"test context cancellation","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-handler.done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleStream did not exit after context cancellation; channel not drained")
	}

	select {
	case <-handlerDone:
	case <-time.After(1 * time.Second):
		t.Fatal("HTTP handler did not finish after context cancellation")
	}
}

func TestSSE_OpenAPISpecIncludesSSEEventTypes(t *testing.T) {
	// Verify the OpenAPI spec includes SSE event type documentation.
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	// Should include the SSE event types in the spec.
	assert.Contains(t, body, "text/event-stream", "OpenAPI spec must include SSE content type")
	assert.Contains(t, body, "text_delta", "OpenAPI spec must include text_delta event type")
	assert.Contains(t, body, "tool_call", "OpenAPI spec must include tool_call event type")
	assert.Contains(t, body, "done", "OpenAPI spec must include done event type")
	assert.Contains(t, body, "session_id", "OpenAPI spec must include session_id event type")
}

func TestSSE_HumaInputValidation_EmptyContent(t *testing.T) {
	// Verify huma validates the content field as non-empty via minLength:"1".
	srv := newTestSSEServer(t, nil)

	body := `{"content": "", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestSSE_HumaInputValidation_MissingContentField(t *testing.T) {
	// Verify huma validates the content field as required.
	srv := newTestSSEServer(t, nil)

	body := `{"workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Huma should reject this since content is required (minLength:1 implies required).
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestSSE_HumaErrorFormat(t *testing.T) {
	// Verify error responses use huma's problem+json format.
	srv := newTestServer(t) // no stream handler

	body := `{"content": "Hello", "workspace_id": "homelab"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	// Huma returns problem+json for errors.
	assert.Contains(t, w.Header().Get("Content-Type"), "application/problem+json")

	// Verify the error body is valid JSON.
	var errResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &errResp)
	require.NoError(t, err)
	// Huma error format includes "detail" field.
	assert.Contains(t, errResp, "detail")
}

// ---- Negative Tests for Stream Handling ----

func TestSSE_InvalidJSONMidStream(t *testing.T) {
	// Provider emits valid session_id, text_delta, then invalid JSON,
	// then another valid event, then done. The ensureValidJSON function
	// wraps non-JSON data as a JSON string, so the stream should NOT break.
	events := []server.SSEEvent{
		{Event: "session_id", Data: `{"session_id":"sess-123"}`},
		{Event: "text_delta", Data: `{"text":"Hello"}`},
		{Event: "text_delta", Data: "this is not valid json {{{"},
		{Event: "text_delta", Data: `{"text":"world"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Test", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	output := w.Body.String()
	// All events should be present.
	assert.Contains(t, output, "event: session_id")
	assert.Contains(t, output, "event: text_delta")
	assert.Contains(t, output, "event: done")

	// The invalid JSON should be wrapped as a JSON string.
	assert.Contains(t, output, `"this is not valid json {{{"`)

	// Parse SSE events - should have all 5 events.
	scanner := bufio.NewScanner(strings.NewReader(output))
	eventCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventCount++
		}
	}
	assert.Equal(t, 5, eventCount, "should have all 5 events in output")
}

func TestSSE_UnknownEventTypes(t *testing.T) {
	// Provider emits events with types NOT in sseEventTypeMap.
	// These should be passed through since the event type map is only for
	// OpenAPI schema generation. The isValidEventType check only rejects newlines.
	events := []server.SSEEvent{
		{Event: "text_delta", Data: `{"text":"valid"}`},
		{Event: "heartbeat", Data: `{"timestamp":12345}`},
		{Event: "custom_metric", Data: `{"value":42}`},
		{Event: "text_delta", Data: `{"text":"more"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Test", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	output := w.Body.String()
	// All event types should appear in the output.
	assert.Contains(t, output, "event: text_delta")
	assert.Contains(t, output, "event: heartbeat")
	assert.Contains(t, output, "event: custom_metric")
	assert.Contains(t, output, "event: done")

	// Verify unknown event types have their data intact.
	assert.Contains(t, output, `"timestamp":12345`)
	assert.Contains(t, output, `"value":42`)
}

func TestSSE_EmptyDataField(t *testing.T) {
	// Provider emits an event with empty Data string.
	// ensureValidJSON("") will wrap it as `""` (valid JSON string).
	events := []server.SSEEvent{
		{Event: "text_delta", Data: ""},
		{Event: "text_delta", Data: `{"text":"after empty"}`},
		{Event: "done", Data: `{}`},
	}
	srv := newTestSSEServer(t, events)

	body := `{"content": "Test", "workspace_id": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	output := w.Body.String()
	// Should have all 3 events.
	assert.Contains(t, output, "event: text_delta")
	assert.Contains(t, output, "event: done")

	// The empty data should be wrapped as an empty JSON string: ""
	assert.Contains(t, output, `""`)
	assert.Contains(t, output, `"after empty"`)
}

// blockingStreamHandler sends one event then blocks forever.
type blockingStreamHandler struct {
	started chan struct{}
	done    chan struct{}
}

func (h *blockingStreamHandler) HandleStream(ctx context.Context, _ server.ChatStreamRequest, ch chan<- server.SSEEvent) {
	defer close(ch)
	defer close(h.done)
	close(h.started)

	// Send one event.
	select {
	case ch <- server.SSEEvent{Event: "text_delta", Data: `{"text":"first"}`}:
	case <-ctx.Done():
		return
	}

	// Block forever or until context is cancelled.
	<-ctx.Done()
}

func TestSSE_HangingProviderTimeout(t *testing.T) {
	// Create a blocking handler that hangs forever after sending one event.
	handler := &blockingStreamHandler{
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"test","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Use a context with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
	}()

	// Wait for handler to start.
	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	// Verify the handler goroutine exits when context is cancelled.
	select {
	case <-handler.done:
		// Success - goroutine exited cleanly.
	case <-time.After(3 * time.Second):
		t.Fatal("HandleStream goroutine did not exit after context timeout (goroutine leak)")
	}

	select {
	case <-httpDone:
	case <-time.After(1 * time.Second):
		t.Fatal("HTTP handler did not finish")
	}
}

func TestSSE_ContextCancellationDuringEventRouting(t *testing.T) {
	// Cancel the context right after the first event is sent.
	// Verify the handler exits cleanly and response has at least one event.
	handler := &rapidStreamHandler{
		eventCount: 100,
		started:    make(chan struct{}),
		done:       make(chan struct{}),
	}

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0", StreamHandler: handler})
	require.NoError(t, err)

	body := `{"content":"test cancellation","workspace_id":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	w := &countingResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		writeTrigger:     1, // Cancel after first write.
		onTrigger:        cancel,
	}

	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		srv.Handler().ServeHTTP(w, req)
	}()

	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	// Verify handler exits cleanly.
	select {
	case <-handler.done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleStream did not exit after context cancellation")
	}

	select {
	case <-httpDone:
	case <-time.After(1 * time.Second):
		t.Fatal("HTTP handler did not finish")
	}

	// Verify at least one event was written.
	assert.GreaterOrEqual(t, w.writeCount, 1)
}

func TestSSE_MixedValidAndInvalidDataPayloads(t *testing.T) {
	// Table-driven test with various data payloads: valid JSON, invalid JSON,
	// empty string, large data, unicode, control characters.
	// All should produce valid SSE output via ensureValidJSON.

	largeData := strings.Repeat("x", 10*1024) // 10KB of 'x'
	unicodeData := "Hello 世界 🌍 café"
	controlCharData := "line1\x00\x01\x02line2"

	tests := []struct {
		name string
		data string
	}{
		{"valid json object", `{"text":"valid"}`},
		{"valid json array", `["item1","item2"]`},
		{"invalid json braces", `{this is not json}`},
		{"invalid json truncated", `{"incomplete":`},
		{"empty string", ""},
		{"plain text", "plain text data"},
		{"large data", largeData},
		{"unicode characters", unicodeData},
		{"control characters", controlCharData},
		{"multiline text", "line1\nline2\nline3"},
		{"single quote json-like", `{'key': 'value'}`},
		{"number only", "42"},
		{"boolean only", "true"},
		{"null only", "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := []server.SSEEvent{
				{Event: "text_delta", Data: tt.data},
				{Event: "done", Data: `{}`},
			}
			srv := newTestSSEServer(t, events)

			body := `{"content": "Test", "workspace_id": "test"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/chat/stream", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "test case: %s", tt.name)

			output := w.Body.String()
			// Should contain both events.
			assert.Contains(t, output, "event: text_delta", "test case: %s", tt.name)
			assert.Contains(t, output, "event: done", "test case: %s", tt.name)

			// Parse data lines to verify they are valid JSON.
			scanner := bufio.NewScanner(strings.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "data: ") {
					dataJSON := strings.TrimPrefix(line, "data: ")
					// Each data line should be valid JSON.
					assert.True(t, json.Valid([]byte(dataJSON)),
						"data line should be valid JSON in test case %s: %s", tt.name, dataJSON)
				}
			}
		})
	}
}
