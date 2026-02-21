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
	ID string `path:"id"`
}

type getNodeOutput struct {
	Body NodeDetail
}

type nodeActionOutput struct {
	Body struct {
		Status string `json:"status"`
		NodeID string `json:"node_id"`
	}
}

type agentControlOutput struct {
	Body struct {
		Status AgentState `json:"status"`
	}
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
		OperationID: "delete-node",
		Method:      http.MethodDelete,
		Path:        "/api/v1/nodes/{id}",
		Summary:     "Delete node registration",
		Tags:        []string{"nodes"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable, http.StatusTooManyRequests},
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
	huma.Register(s.api, huma.Operation{
		OperationID: "gateway-status-stream",
		Method:      http.MethodGet,
		Path:        "/api/v1/status/stream",
		Summary:     "Stream gateway status updates via SSE",
		Tags:        []string{"system"},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTooManyRequests},
	}, s.handleStatusStream)
}

func (s *Server) requireNodeService(ctx context.Context) (NodeService, error) {
	if err := s.requireAdmin(ctx, "admin:nodes", "manage nodes"); err != nil {
		return nil, err
	}
	if s.services == nil || s.services.Nodes() == nil {
		return nil, huma.Error503ServiceUnavailable("node service not available")
	}
	return s.services.Nodes(), nil
}

func (s *Server) requireAgentControlService(ctx context.Context) (AgentControlService, error) {
	if err := s.requireAdmin(ctx, "admin:agent", "control agent state"); err != nil {
		return nil, err
	}
	if s.services == nil || s.services.AgentControl() == nil {
		return nil, huma.Error503ServiceUnavailable("agent control service not available")
	}
	return s.services.AgentControl(), nil
}

func (s *Server) requireGatewayStatusService(ctx context.Context) (GatewayStatusService, error) {
	if err := s.requireAdmin(ctx, "admin:status", "stream gateway status"); err != nil {
		return nil, err
	}
	if s.services == nil || s.services.GatewayStatus() == nil {
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
		slog.Error("internal error", "context", "listing nodes", "error", err)
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

func (s *Server) handleApproveNode(ctx context.Context, input *nodeIDInput) (*nodeActionOutput, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}

	if err := nodes.Approve(ctx, input.ID); err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("node %q not found", input.ID),
			fmt.Sprintf("approving node %q", input.ID))
	}

	out := &nodeActionOutput{}
	out.Body.Status = "approved"
	out.Body.NodeID = input.ID
	return out, nil
}

func (s *Server) handleDeleteNode(ctx context.Context, input *nodeIDInput) (*nodeActionOutput, error) {
	nodes, err := s.requireNodeService(ctx)
	if err != nil {
		return nil, err
	}

	if err := nodes.Delete(ctx, input.ID); err != nil {
		return nil, notFoundOr500(err,
			fmt.Sprintf("node %q not found", input.ID),
			fmt.Sprintf("deleting node %q", input.ID))
	}

	out := &nodeActionOutput{}
	out.Body.Status = "deleted"
	out.Body.NodeID = input.ID
	return out, nil
}

func (s *Server) handlePauseAgent(ctx context.Context, _ *struct{}) (*agentControlOutput, error) {
	control, err := s.requireAgentControlService(ctx)
	if err != nil {
		return nil, err
	}

	state, err := control.Pause(ctx)
	if err != nil {
		slog.Error("internal error", "context", "pausing agent", "error", err)
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
		slog.Error("internal error", "context", "resuming agent", "error", err)
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

	updates, err := statusSvc.Subscribe(ctx)
	if err != nil {
		slog.Error("internal error", "context", "subscribing gateway status", "error", err)
		return nil, huma.Error500InternalServerError("internal server error")
	}

	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			ctx.SetHeader("Content-Type", "text/event-stream")
			ctx.SetHeader("Cache-Control", "no-cache")
			ctx.SetHeader("Connection", "keep-alive")

			bw := ctx.BodyWriter()
			encoder := json.NewEncoder(bw)

			var flusher http.Flusher
			if f, ok := bw.(http.Flusher); ok {
				flusher = f
			}

			for update := range updates {
				if _, err := fmt.Fprintf(bw, "event: %s\n", trayStatusSSEEvent); err != nil {
					slog.Warn("status stream: write event failed", "error", err)
					return
				}
				if _, err := fmt.Fprint(bw, "data: "); err != nil {
					slog.Warn("status stream: write data prefix failed", "error", err)
					return
				}
				if err := encoder.Encode(update); err != nil {
					slog.Warn("status stream: encode update failed", "error", err)
					return
				}
				if _, err := fmt.Fprint(bw, "\n"); err != nil {
					slog.Warn("status stream: write event separator failed", "error", err)
					return
				}

				if flusher != nil {
					flusher.Flush()
				}
			}
		},
	}, nil
}
