// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
}

func (s *Server) handleChatStream(w http.ResponseWriter, r *http.Request) {
	var req ChatStreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Content == "" {
		http.Error(w, `{"error":"content is required"}`, http.StatusUnprocessableEntity)
		return
	}

	if s.streamHandler == nil {
		http.Error(w, `{"error":"stream handler not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Check if client wants SSE or JSON.
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		s.writeSSE(w, r, req)
		return
	}
	s.writeJSON(w, r, req)
}

func (s *Server) writeSSE(w http.ResponseWriter, r *http.Request, req ChatStreamRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		// httptest.ResponseRecorder doesn't implement Flusher,
		// but we still write the events for testability.
		flusher = nil
	}

	ch := make(chan SSEEvent, 16)
	go s.streamHandler.HandleStream(r.Context(), req, ch)

	for event := range ch {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, event.Data); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, req ChatStreamRequest) {
	ch := make(chan SSEEvent, 16)
	go s.streamHandler.HandleStream(r.Context(), req, ch)

	var events []json.RawMessage
	for event := range ch {
		events = append(events, json.RawMessage(event.Data))
	}

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		Events []json.RawMessage `json:"events"`
	}{Events: events}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, `{"error":"encoding response"}`, http.StatusInternalServerError)
	}
}
