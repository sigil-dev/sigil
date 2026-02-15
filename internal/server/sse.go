// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// SSEEventType defines the allowed event types for server-sent events.
// These correspond to provider.EventType values plus server-specific types.
type SSEEventType string

// SSE event type constants.
const (
	SSEEventTextDelta SSEEventType = "text_delta"
	SSEEventToolCall  SSEEventType = "tool_call"
	SSEEventUsage     SSEEventType = "usage"
	SSEEventDone      SSEEventType = "done"
	SSEEventError     SSEEventType = "error"
	SSEEventSessionID SSEEventType = "session_id"
)

// SSEEvent represents a single server-sent event.
type SSEEvent struct {
	Event SSEEventType `json:"event"`
	Data  string       `json:"data"`
}

// ChatStreamRequest is the request body for the SSE streaming endpoint.
type ChatStreamRequest struct {
	Content     string `json:"content" minLength:"1" doc:"Message content"`
	WorkspaceID string `json:"workspace_id" doc:"Target workspace"`
	SessionID   string `json:"session_id,omitempty" doc:"Optional session to resume"`
}

// StreamHandler processes chat messages and sends SSE events to a channel.
// Implementations must close the channel when done.
type StreamHandler interface {
	HandleStream(ctx context.Context, req ChatStreamRequest, events chan<- SSEEvent)
}

// RegisterStreamHandler sets the handler used by the SSE endpoint.
func (s *Server) RegisterStreamHandler(h StreamHandler) {
	s.streamHandler = h
}

// checkWorkspaceMembership verifies the authenticated user has access to the
// requested workspace. Returns nil when auth is disabled (user is nil).
// When auth is enabled, workspace_id is required and workspace service must be available.
func (s *Server) checkWorkspaceMembership(ctx context.Context, workspaceID string) error {
	user := UserFromContext(ctx)
	if user == nil {
		// Auth disabled — skip membership check.
		return nil
	}
	if workspaceID == "" {
		// Auth enabled but no workspace specified — reject.
		return huma.Error422UnprocessableEntity("workspace_id is required")
	}
	if s.services == nil || s.services.Workspaces == nil {
		// Services not registered — fail closed.
		return huma.Error503ServiceUnavailable("workspace service not available")
	}
	ws, err := s.services.Workspaces.Get(ctx, workspaceID)
	if err != nil {
		if IsNotFound(err) {
			// Return 403 (not 404) to prevent workspace ID enumeration.
			return huma.Error403Forbidden("access denied")
		}
		slog.Error("internal error", "context", fmt.Sprintf("checking workspace %q", workspaceID), "error", err)
		return huma.Error500InternalServerError("internal server error")
	}
	// Check if user is a member of the workspace.
	for _, member := range ws.Members {
		if member == user.ID {
			return nil
		}
	}
	return huma.Error403Forbidden("access denied")
}

func (s *Server) registerSSERoute() {
	s.router.Post("/api/v1/chat/stream", s.handleChatStream)

	// registerSSERoute registers the SSE streaming endpoint outside huma's standard
	// handler registration. The SSE endpoint needs raw http.ResponseWriter access
	// for streaming, which huma's typed handler signature doesn't support. The chi
	// route handles actual requests while the huma OpenAPI entry below provides
	// documentation only. Auth middleware is still applied via the global chi
	// middleware stack registered in New().
	// Register the operation in the OpenAPI spec manually. The SSE streaming
	// handler needs raw http.ResponseWriter access, so it cannot use Huma's
	// standard handler signature. We keep the chi route above for actual
	// request handling and add the spec entry here for documentation.
	minContentLen := 1
	s.api.OpenAPI().AddOperation(&huma.Operation{
		OperationID: "chat-stream",
		Method:      http.MethodPost,
		Path:        "/api/v1/chat/stream",
		Summary:     "Stream a chat response via SSE",
		Description: "Send a message and receive a streaming response. Set Accept: text/event-stream for SSE, otherwise receives a JSON object containing an events array.",
		Tags:        []string{"chat"},
		RequestBody: &huma.RequestBody{
			Required: true,
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: &huma.Schema{
						Type:     "object",
						Required: []string{"content"},
						Properties: map[string]*huma.Schema{
							"content": {
								Type:        "string",
								MinLength:   &minContentLen,
								Description: "Message content",
							},
							"workspace_id": {
								Type:        "string",
								Description: "Target workspace",
							},
							"session_id": {
								Type:        "string",
								Description: "Optional session to resume",
							},
						},
					},
				},
			},
		},
		Responses: map[string]*huma.Response{
			"200": {
				Description: "Streaming response (SSE or JSON depending on Accept header)",
				Content: map[string]*huma.MediaType{
					"text/event-stream": {
						Schema: &huma.Schema{
							Type:        "string",
							Description: "Server-sent event stream",
						},
					},
					"application/json": {
						Schema: &huma.Schema{
							Type: "object",
							Properties: map[string]*huma.Schema{
								"events": {
									Type:        "array",
									Description: "Collected events with type and data",
									Items: &huma.Schema{
										Type: "object",
										Properties: map[string]*huma.Schema{
											"event": {
												Type:        "string",
												Description: "Event type (text_delta, session_id, error, done)",
											},
											"data": {
												Description: "Event payload",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"422": {Description: "Validation error (missing content)"},
			"503": {Description: "Stream handler not configured"},
		},
	})
}

func (s *Server) handleChatStream(w http.ResponseWriter, r *http.Request) {
	// Limit request body to 1MB to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req ChatStreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Type-safe detection of MaxBytesError (Go 1.19+).
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			jsonError(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		// Fallback for older Go versions or wrapped errors.
		if err.Error() == "http: request body too large" {
			jsonError(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		jsonError(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		jsonError(w, `{"error":"content is required"}`, http.StatusUnprocessableEntity)
		return
	}

	// Verify workspace membership before streaming.
	if err := s.checkWorkspaceMembership(r.Context(), req.WorkspaceID); err != nil {
		status := http.StatusForbidden
		if se, ok := err.(huma.StatusError); ok {
			status = se.GetStatus()
		}
		errBody, marshalErr := json.Marshal(map[string]string{"error": err.Error()})
		if marshalErr != nil {
			jsonError(w, `{"error":"internal error"}`, status)
			return
		}
		jsonError(w, string(errBody), status)
		return
	}

	if s.streamHandler == nil {
		jsonError(w, `{"error":"stream handler not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Check if client wants SSE or JSON.
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		s.writeSSE(w, r, req)
		return
	}
	s.writeJSON(w, r, req)
}

// validateEventType checks if an SSE event type contains invalid newline characters.
// Returns true if the event type is valid (no newlines).
func validateEventType(eventType SSEEventType) bool {
	return !strings.ContainsAny(string(eventType), "\r\n")
}

// drainSSEChannel consumes remaining events from ch in a background goroutine
// so that the producer (HandleStream) does not block on a full buffer after
// the consumer has stopped reading. The goroutine exits when ch is closed.
func drainSSEChannel(ch <-chan SSEEvent) {
	go func() {
		for range ch {
		}
	}()
}

// writeSSEField writes a single SSE line and returns true if writing failed.
func writeSSEField(w http.ResponseWriter, format string, args ...any) bool {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		slog.Warn("sse: write error", "error", err)
		return true
	}
	return false
}

func (s *Server) writeSSE(w http.ResponseWriter, r *http.Request, req ChatStreamRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Graceful degradation if response writer does not support Flush.
		flusher = nil
	}

	ch := make(chan SSEEvent, 16)
	go s.streamHandler.HandleStream(r.Context(), req, ch)

	for event := range ch {
		if !validateEventType(event.Event) {
			slog.Warn("sse: skipping event with invalid type containing newlines", "event_type", event.Event)
			continue
		}
		// SSE spec requires each line of a multi-line payload to be
		// prefixed with "data: ". Split on newlines and emit each line.
		if writeSSEField(w, "event: %s\n", event.Event) {
			drainSSEChannel(ch)
			return
		}
		for _, line := range strings.Split(event.Data, "\n") {
			if writeSSEField(w, "data: %s\n", line) {
				drainSSEChannel(ch)
				return
			}
		}
		if writeSSEField(w, "\n") {
			drainSSEChannel(ch)
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// marshalError is the error payload structure for marshal failures.
type marshalError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// jsonEvent pairs an event type with its data payload for JSON responses.
type jsonEvent struct {
	Event SSEEventType    `json:"event"`
	Data  json.RawMessage `json:"data"`
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, req ChatStreamRequest) {
	ch := make(chan SSEEvent, 16)
	go s.streamHandler.HandleStream(r.Context(), req, ch)

	events := make([]jsonEvent, 0)
	for event := range ch {
		if !validateEventType(event.Event) {
			slog.Warn("sse: skipping event with invalid type containing newlines", "event_type", event.Event)
			continue
		}
		raw := []byte(event.Data)
		if !json.Valid(raw) {
			// Wrap non-JSON text as a JSON string so the response stays valid.
			var err error
			raw, err = json.Marshal(event.Data)
			if err != nil {
				slog.Warn("writeJSON: failed to marshal event data, emitting error event", "error", err, "event", event.Event)
				// Emit synthetic error event so client knows events were dropped.
				errPayload, innerErr := json.Marshal(marshalError{
					Error:   "marshal_failure",
					Message: fmt.Sprintf("failed to marshal event data: %s", err.Error()),
				})
				if innerErr != nil {
					slog.Warn("writeJSON: failed to marshal error event payload", "error", innerErr)
					continue
				}
				events = append(events, jsonEvent{Event: "error", Data: json.RawMessage(errPayload)})
				continue
			}
		}
		events = append(events, jsonEvent{Event: event.Event, Data: raw})
	}

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		Events []jsonEvent `json:"events"`
	}{Events: events}

	// Encode to buffer first to detect errors before writing to ResponseWriter.
	// This ensures correct HTTP semantics — either full response or error, not partial.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(resp); err != nil {
		http.Error(w, `{"error":"encoding response"}`, http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		slog.Warn("writeJSON: failed to write response", "error", err)
	}
}

// jsonError writes an HTTP error response with Content-Type: application/json.
func jsonError(w http.ResponseWriter, body string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := fmt.Fprint(w, body); err != nil {
		slog.Debug("jsonError: failed to write error response", "error", err, "code", code)
	}
}
