// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// --- Typed SSE event data for huma OpenAPI schema ---
//
// Each SSE event type has a corresponding Go type wrapping json.RawMessage.
// These types serve two purposes:
//   1. OpenAPI schema generation via sseEventTypeMap
//   2. Type-safe SSE event emission via huma's sse.Sender
//
// Each implements json.Marshaler to pass through raw JSON without re-encoding.

// TextDeltaEventData carries a text_delta SSE event payload.
type TextDeltaEventData json.RawMessage

// MarshalJSON returns the raw JSON bytes.
func (d TextDeltaEventData) MarshalJSON() ([]byte, error) { return json.RawMessage(d), nil }

// ToolCallEventData carries a tool_call SSE event payload.
type ToolCallEventData json.RawMessage

// MarshalJSON returns the raw JSON bytes.
func (d ToolCallEventData) MarshalJSON() ([]byte, error) { return json.RawMessage(d), nil }

// UsageEventData carries a usage SSE event payload.
type UsageEventData json.RawMessage

// MarshalJSON returns the raw JSON bytes.
func (d UsageEventData) MarshalJSON() ([]byte, error) { return json.RawMessage(d), nil }

// DoneEventData carries a done SSE event payload.
type DoneEventData json.RawMessage

// MarshalJSON returns the raw JSON bytes.
func (d DoneEventData) MarshalJSON() ([]byte, error) { return json.RawMessage(d), nil }

// ErrorEventData carries an error SSE event payload.
type ErrorEventData json.RawMessage

// MarshalJSON returns the raw JSON bytes.
func (d ErrorEventData) MarshalJSON() ([]byte, error) { return json.RawMessage(d), nil }

// SessionIDEventData carries a session_id SSE event payload.
type SessionIDEventData json.RawMessage

// MarshalJSON returns the raw JSON bytes.
func (d SessionIDEventData) MarshalJSON() ([]byte, error) { return json.RawMessage(d), nil }

// sseEventTypeMap maps SSE event names to their corresponding Go types.
// Used by buildSSEResponseSchema to generate the OpenAPI oneOf schema,
// and by toTypedEventData to route events to the correct type for sse.Sender.
var sseEventTypeMap = map[string]any{
	string(SSEEventTextDelta): TextDeltaEventData{},
	string(SSEEventToolCall):  ToolCallEventData{},
	string(SSEEventUsage):     UsageEventData{},
	string(SSEEventDone):      DoneEventData{},
	string(SSEEventError):     ErrorEventData{},
	string(SSEEventSessionID): SessionIDEventData{},
}

// chatStreamInput is the huma-compatible input type for the SSE streaming endpoint.
type chatStreamInput struct {
	Body ChatStreamRequest
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
	if s.services == nil || s.services.Workspaces() == nil {
		// Services not registered — fail closed.
		return huma.Error503ServiceUnavailable("workspace service not available")
	}
	ws, err := s.services.Workspaces().Get(ctx, workspaceID)
	if err != nil {
		if IsNotFound(err) {
			// Returns 403 for both not-found and forbidden to prevent workspace ID enumeration.
			return huma.Error403Forbidden("access denied")
		}
		slog.Error("internal error", "context", fmt.Sprintf("checking workspace %q", workspaceID), "error", err)
		return huma.Error500InternalServerError("internal server error")
	}
	// Check if user is a member of the workspace.
	for _, member := range ws.Members {
		if member == user.ID() {
			return nil
		}
	}
	return huma.Error403Forbidden("access denied")
}

// registerSSERoute registers the SSE streaming endpoint using huma.Register
// with a StreamResponse. This integrates with huma's input validation, error
// handling, and OpenAPI spec generation while supporting pre-stream error
// returns (e.g., workspace membership checks, missing handler).
//
// The SSE OpenAPI schema is built from sseEventTypeMap to document all event
// types in the spec using the same pattern as huma's sse.Register.
func (s *Server) registerSSERoute() {
	op := huma.Operation{
		OperationID: "chat-stream",
		Method:      http.MethodPost,
		Path:        "/api/v1/chat/stream",
		Summary:     "Stream a chat response via SSE",
		Description: "Send a message and receive a streaming response as server-sent events.",
		Tags:        []string{"chat"},
		Errors:      []int{http.StatusForbidden, http.StatusUnprocessableEntity, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}

	// Build SSE response schema from the event type map.
	buildSSEResponseSchema(s.api, &op)

	huma.Register(s.api, op, s.handleChatStream)
}

// buildSSEResponseSchema adds the SSE event schema to the operation's 200 response.
func buildSSEResponseSchema(api huma.API, op *huma.Operation) {
	if op.Responses == nil {
		op.Responses = map[string]*huma.Response{}
	}
	if op.Responses["200"] == nil {
		op.Responses["200"] = &huma.Response{}
	}
	if op.Responses["200"].Content == nil {
		op.Responses["200"].Content = map[string]*huma.MediaType{}
	}

	dataSchemas := make([]*huma.Schema, 0, len(sseEventTypeMap))
	for k := range sseEventTypeMap {
		required := []string{"data"}
		if k != "" && k != "message" {
			required = append(required, "event")
		}
		s := &huma.Schema{
			Title: "Event " + k,
			Type:  huma.TypeObject,
			Properties: map[string]*huma.Schema{
				"event": {
					Type:        huma.TypeString,
					Description: "The event name.",
					Extensions: map[string]interface{}{
						"const": k,
					},
				},
				"data": {
					Description: "The event payload (JSON object).",
				},
			},
			Required: required,
		}
		dataSchemas = append(dataSchemas, s)
	}

	// Sort for deterministic output (same as huma's sse package).
	sortSchemasByTitle(dataSchemas)

	schema := &huma.Schema{
		Title:       "Server Sent Events",
		Description: "Each oneOf object in the array represents one possible Server Sent Events (SSE) message.",
		Type:        huma.TypeArray,
		Items: &huma.Schema{
			Extensions: map[string]interface{}{
				"oneOf": dataSchemas,
			},
		},
	}
	op.Responses["200"].Content["text/event-stream"] = &huma.MediaType{
		Schema: schema,
	}
}

// sortSchemasByTitle sorts schemas by Title for deterministic OpenAPI output.
func sortSchemasByTitle(schemas []*huma.Schema) {
	for i := 1; i < len(schemas); i++ {
		for j := i; j > 0 && schemas[j].Title < schemas[j-1].Title; j-- {
			schemas[j], schemas[j-1] = schemas[j-1], schemas[j]
		}
	}
}

func (s *Server) handleChatStream(ctx context.Context, input *chatStreamInput) (*huma.StreamResponse, error) {
	// Pre-stream validation: return HTTP errors before streaming begins.
	if err := s.checkWorkspaceMembership(ctx, input.Body.WorkspaceID); err != nil {
		return nil, err
	}
	if s.streamHandler == nil {
		return nil, huma.Error503ServiceUnavailable("stream handler not configured")
	}

	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			ctx.SetHeader("Content-Type", "text/event-stream")
			ctx.SetHeader("Cache-Control", "no-cache")
			ctx.SetHeader("Connection", "keep-alive")

			bw := ctx.BodyWriter()
			encoder := json.NewEncoder(bw)

			// Get flusher from the body writer.
			var flusher http.Flusher
			if f, ok := bw.(http.Flusher); ok {
				flusher = f
			}

			ch := make(chan SSEEvent, 16)
			go s.streamHandler.HandleStream(ctx.Context(), input.Body, ch)

			for event := range ch {
				if !isValidEventType(event.Event) {
					slog.Warn("sse: skipping event with invalid type containing newlines", "event_type", event.Event)
					continue
				}

				data := ensureValidJSON(event.Data)

				// Write event type.
				if err := writeSSEField(bw, ch, "event: %s\n", event.Event); err != nil {
					return
				}

				// Write data line: "data: " + JSON + "\n" (json.Encode adds \n).
				if err := writeSSEField(bw, ch, "data: "); err != nil {
					return
				}
				if err := encoder.Encode(json.RawMessage(data)); err != nil {
					slog.Warn("sse: encode error", "error", err)
					drainSSEChannel(ch)
					return
				}

				// Empty line terminates the event.
				if err := writeSSEField(bw, ch, "\n"); err != nil {
					return
				}

				if flusher != nil {
					flusher.Flush()
				}
			}
		},
	}, nil
}

// ensureValidJSON wraps data as a JSON string if it is not already valid JSON.
// This prevents sending malformed data that would break the SSE JSON encoding.
func ensureValidJSON(data string) json.RawMessage {
	raw := []byte(data)
	if json.Valid(raw) {
		return raw
	}
	// Wrap non-JSON text as a JSON string.
	wrapped, err := json.Marshal(data)
	if err != nil {
		slog.Warn("sse: failed to marshal event data as string", "error", err)
		return json.RawMessage(`{"error":"marshal failure"}`)
	}
	return wrapped
}

// isValidEventType checks if an SSE event type is valid (no newline characters).
// Returns true if the event type is valid (no newlines).
func isValidEventType(eventType SSEEventType) bool {
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

// writeSSEField writes a formatted SSE field and drains the channel on error.
// Returns the error so the caller can decide whether to continue.
func writeSSEField(w io.Writer, ch <-chan SSEEvent, format string, args ...any) error {
	_, err := fmt.Fprintf(w, format, args...)
	if err != nil {
		slog.Warn("sse: write error", "error", err)
		drainSSEChannel(ch)
		return err
	}
	return nil
}
