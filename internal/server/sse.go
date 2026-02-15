// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// SSEEvent represents a single server-sent event.
type SSEEvent struct {
	Event string `json:"event"`
	Data  string `json:"data"`
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

func (s *Server) registerSSERoute() {
	s.router.Post("/api/v1/chat/stream", s.handleChatStream)

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
	var req ChatStreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		jsonError(w, `{"error":"content is required"}`, http.StatusUnprocessableEntity)
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

// drainSSEChannel consumes remaining events from ch so that the goroutine
// writing to ch (HandleStream) does not block on a full buffer.
func drainSSEChannel(ch <-chan SSEEvent) {
	go func() { for range ch {} }()
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
		// SSE spec requires each line of a multi-line payload to be
		// prefixed with "data: ". Split on newlines and emit each line.
		if _, err := fmt.Fprintf(w, "event: %s\n", event.Event); err != nil {
			slog.Warn("sse: write error", "error", err)
			drainSSEChannel(ch)
			return
		}
		for _, line := range strings.Split(event.Data, "\n") {
			if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
				slog.Warn("sse: write error", "error", err)
				drainSSEChannel(ch)
				return
			}
		}
		if _, err := fmt.Fprint(w, "\n"); err != nil {
			slog.Warn("sse: write error", "error", err)
			drainSSEChannel(ch)
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// jsonEvent pairs an event type with its data payload for JSON responses.
type jsonEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, req ChatStreamRequest) {
	ch := make(chan SSEEvent, 16)
	go s.streamHandler.HandleStream(r.Context(), req, ch)

	events := make([]jsonEvent, 0)
	for event := range ch {
		raw := []byte(event.Data)
		if !json.Valid(raw) {
			// Wrap non-JSON text as a JSON string so the response stays valid.
			var err error
			raw, err = json.Marshal(event.Data)
			if err != nil {
				slog.Warn("writeJSON: failed to marshal event data, skipping event", "error", err, "event", event.Event)
				continue
			}
		}
		events = append(events, jsonEvent{Event: event.Event, Data: raw})
	}

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		Events []jsonEvent `json:"events"`
	}{Events: events}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, `{"error":"encoding response"}`, http.StatusInternalServerError)
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
