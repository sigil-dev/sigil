// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

const trayStatusSSEEvent = "tray_status"

type listNodesOutput struct {
	Body struct {
		Nodes []NodeSummary `json:"nodes"`
	}
}

type nodeIDInput struct {
	ID string `path:"id" maxLength:"253" pattern:"^[a-zA-Z0-9][a-zA-Z0-9._-]*$"`
}

type getNodeOutput struct {
	Body NodeDetail
}

type nodeActionOutput struct {
	Body struct {
		Status NodeActionStatus `json:"status"`
		NodeID string           `json:"node_id"`
	}
}

type agentControlOutput struct {
	Body struct {
		Status AgentState `json:"status"`
	}
}

// userIDFromContext extracts the authenticated user's ID from the context,
// returning an empty string when auth is disabled.
func userIDFromContext(ctx context.Context) string {
	if u := UserFromContext(ctx); u != nil {
		return u.ID()
	}
	return ""
}

func (s *Server) registerNodeRoutes() {
	huma.Register(s.api, huma.Operation{
		OperationID: "list-nodes",
		Method:      http.MethodGet,
		Path:        "/api/v1/nodes",
		Summary:     "List registered nodes",
		Tags:        []string{"nodes"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleListNodes)

	huma.Register(s.api, huma.Operation{
		OperationID: "get-node",
		Method:      http.MethodGet,
		Path:        "/api/v1/nodes/{id}",
		Summary:     "Get node details",
		Tags:        []string{"nodes"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleGetNode)

	huma.Register(s.api, huma.Operation{
		OperationID: "approve-node",
		Method:      http.MethodPost,
		Path:        "/api/v1/nodes/{id}/approve",
		Summary:     "Approve node access",
		Tags:        []string{"nodes"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleApproveNode)

	huma.Register(s.api, huma.Operation{
		OperationID: "revoke-node",
		Method:      http.MethodPost,
		Path:        "/api/v1/nodes/{id}/revoke",
		Summary:     "Revoke node access",
		Tags:        []string{"nodes"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleRevokeNode)

	huma.Register(s.api, huma.Operation{
		OperationID:   "delete-node",
		Method:        http.MethodDelete,
		Path:          "/api/v1/nodes/{id}",
		Summary:       "Delete node registration",
		Tags:          []string{"nodes"},
		DefaultStatus: http.StatusNoContent,
		Errors:        []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleDeleteNode)
}

func (s *Server) registerAgentControlRoutes() {
	huma.Register(s.api, huma.Operation{
		OperationID: "pause-agent",
		Method:      http.MethodPost,
		Path:        "/api/v1/agent/pause",
		Summary:     "Pause the agent loop",
		Tags:        []string{"system"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handlePauseAgent)

	huma.Register(s.api, huma.Operation{
		OperationID: "resume-agent",
		Method:      http.MethodPost,
		Path:        "/api/v1/agent/resume",
		Summary:     "Resume the agent loop",
		Tags:        []string{"system"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleResumeAgent)
}

func (s *Server) registerStatusStreamRoute() {
	op := huma.Operation{
		OperationID: "gateway-status-stream",
		Method:      http.MethodGet,
		Path:        "/api/v1/status/stream",
		Summary:     "Stream gateway status updates via SSE",
		Tags:        []string{"system"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}
	buildStatusSSESchema(&op)
	huma.Register(s.api, op, s.handleStatusStream)
}

// buildStatusSSESchema adds SSE response schema for the status stream endpoint.
func buildStatusSSESchema(op *huma.Operation) {
	content := ensureSSEResponseContent(op)

	content["text/event-stream"] = &huma.MediaType{
		Schema: &huma.Schema{
			Title:       "Server Sent Events",
			Description: "Gateway status updates streamed as SSE with event type 'tray_status'.",
			Type:        huma.TypeArray,
			Items: &huma.Schema{
				Type: huma.TypeObject,
				Properties: map[string]*huma.Schema{
					"event": {
						Type:        huma.TypeString,
						Description: "The event name (always 'tray_status').",
						Extensions:  map[string]interface{}{"const": trayStatusSSEEvent},
					},
					"data": {
						Type:        huma.TypeObject,
						Description: "GatewayStatus snapshot.",
					},
				},
				Required: []string{"event", "data"},
			},
		},
	}
}

// requireAdminService validates admin permissions and returns an error if the
// service container is nil. Callers follow with a specific service nil-check.
func (s *Server) requireAdminService(ctx context.Context, perm, op string) error {
	if err := s.requireAdmin(ctx, perm, op); err != nil {
		return err
	}
	if s.services == nil {
		return huma.Error503ServiceUnavailable("services not available")
	}
	return nil
}

func (s *Server) requireNodeService(ctx context.Context) (NodeService, error) {
	if err := s.requireAdminService(ctx, "admin:nodes", "manage nodes"); err != nil {
		return nil, err
	}
	if s.services.Nodes() == nil {
		return nil, huma.Error503ServiceUnavailable("node service not available")
	}
	return s.services.Nodes(), nil
}

func (s *Server) requireAgentControlService(ctx context.Context) (AgentControlService, error) {
	if err := s.requireAdminService(ctx, "admin:agent", "control agent state"); err != nil {
		return nil, err
	}
	if s.services.AgentControl() == nil {
		return nil, huma.Error503ServiceUnavailable("agent control service not available")
	}
	return s.services.AgentControl(), nil
}

func (s *Server) requireGatewayStatusService(ctx context.Context) (GatewayStatusService, error) {
	if err := s.requireAdminService(ctx, "admin:status", "stream gateway status"); err != nil {
		return nil, err
	}
	if s.services.GatewayStatus() == nil {
		return nil, huma.Error503ServiceUnavailable("gateway status service not available")
	}
	return s.services.GatewayStatus(), nil
}

func (s *Server) handleListNodes(ctx context.Context, _ *struct{}) (*listNodesOutput, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}

	list, err := nodes.List(ctx)
	if err != nil {
		slog.Error("internal error", "context", "listing nodes", "error", err, "user_id", userIDFromContext(ctx))
		return nil, huma.Error500InternalServerError("internal server error")
	}

	out := &listNodesOutput{}
	out.Body.Nodes = list
	return out, nil
}

func (s *Server) handleGetNode(ctx context.Context, input *nodeIDInput) (*getNodeOutput, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}

	node, err := nodes.Get(ctx, input.ID)
	if err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("node %q not found", input.ID),
			fmt.Sprintf("getting node %q", input.ID))
	}
	return &getNodeOutput{Body: *node}, nil
}

// handleNodeAction is a shared helper for approve/revoke operations that
// differ only in the service method called and the status returned.
func (s *Server) handleNodeAction(
	ctx context.Context,
	input *nodeIDInput,
	action func(context.Context, string) error,
	status NodeActionStatus,
	opDesc string,
) (*nodeActionOutput, error) {
	if err := action(ctx, input.ID); err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("node %q not found", input.ID),
			fmt.Sprintf("%s node %q", opDesc, input.ID))
	}
	out := &nodeActionOutput{}
	out.Body.Status = status
	out.Body.NodeID = input.ID
	return out, nil
}

func (s *Server) handleApproveNode(ctx context.Context, input *nodeIDInput) (*nodeActionOutput, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}
	return s.handleNodeAction(ctx, input, nodes.Approve, NodeActionApproved, "approving")
}

func (s *Server) handleRevokeNode(ctx context.Context, input *nodeIDInput) (*nodeActionOutput, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}
	return s.handleNodeAction(ctx, input, nodes.Revoke, NodeActionRevoked, "revoking")
}

func (s *Server) handleDeleteNode(ctx context.Context, input *nodeIDInput) (*struct{}, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}

	if err := nodes.Delete(ctx, input.ID); err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("node %q not found", input.ID),
			fmt.Sprintf("deleting node %q", input.ID))
	}

	return nil, nil
}

func (s *Server) handlePauseAgent(ctx context.Context, _ *struct{}) (*agentControlOutput, error) {
	control, err := s.requireAgentControlService(ctx)
	if err != nil {
		return nil, err
	}

	state, err := control.Pause(ctx)
	if err != nil {
		slog.Error("internal error", "context", "pausing agent", "error", err, "user_id", userIDFromContext(ctx))
		return nil, huma.Error500InternalServerError("internal server error")
	}

	out := &agentControlOutput{}
	out.Body.Status = state
	return out, nil
}

func (s *Server) handleResumeAgent(ctx context.Context, _ *struct{}) (*agentControlOutput, error) {
	control, err := s.requireAgentControlService(ctx)
	if err != nil {
		return nil, err
	}

	state, err := control.Resume(ctx)
	if err != nil {
		slog.Error("internal error", "context", "resuming agent", "error", err, "user_id", userIDFromContext(ctx))
		return nil, huma.Error500InternalServerError("internal server error")
	}

	out := &agentControlOutput{}
	out.Body.Status = state
	return out, nil
}

func (s *Server) handleStatusStream(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	statusSvc, err := s.requireGatewayStatusService(ctx)
	if err != nil {
		return nil, err
	}

	// Subscribe pre-stream so errors return proper HTTP status codes
	// instead of silently failing inside an already-committed 200.
	updates, err := statusSvc.Subscribe(ctx)
	if err != nil {
		slog.Error("internal error", "context", "subscribing gateway status", "error", err, "user_id", userIDFromContext(ctx))
		return nil, huma.Error500InternalServerError("internal server error")
	}

	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			defer drainChannelWithContext(ctx.Context(), updates)
			ctx.SetHeader("Content-Type", "text/event-stream")
			ctx.SetHeader("Cache-Control", "no-store")
			ctx.SetHeader("Connection", "keep-alive")

			bw := ctx.BodyWriter()
			encoder := json.NewEncoder(bw)

			var flusher http.Flusher
			if f, ok := bw.(http.Flusher); ok {
				flusher = f
			}

			for {
				select {
				case <-ctx.Context().Done():
					return
				case update, ok := <-updates:
					if !ok {
						return
					}

					if _, err := fmt.Fprintf(bw, "event: %s\ndata: ", trayStatusSSEEvent); err != nil {
						slog.Warn("status stream: write failed", "error", err)
						return
					}
					if err := encoder.Encode(update); err != nil {
						slog.Warn("status stream: encode failed", "error", err)
						return
					}
					if _, err := fmt.Fprint(bw, "\n"); err != nil {
						slog.Warn("status stream: write separator failed", "error", err)
						return
					}

					if flusher != nil {
						flusher.Flush()
					}
				}
			}
		},
	}, nil
}
