// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNodeService struct {
	mu    sync.Mutex
	nodes map[string]server.NodeDetail
}

func (m *mockNodeService) List(_ context.Context) ([]server.NodeSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]server.NodeSummary, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, server.NodeSummary{
			ID:       n.ID,
			Online:   n.Online,
			Approved: n.Approved,
		})
	}
	return out, nil
}

func (m *mockNodeService) Get(_ context.Context, id string) (*server.NodeDetail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	n, ok := m.nodes[id]
	if !ok {
		return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "node %q not found", id)
	}
	copyNode := n
	copyNode.Tools = append([]string(nil), n.Tools...)
	return &copyNode, nil
}

func (m *mockNodeService) Approve(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	n, ok := m.nodes[id]
	if !ok {
		return sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "node %q not found", id)
	}
	n.Approved = true
	m.nodes[id] = n
	return nil
}

func (m *mockNodeService) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.nodes[id]; !ok {
		return sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "node %q not found", id)
	}
	delete(m.nodes, id)
	return nil
}

type mockStatusSubscriptionService struct {
	updates []server.GatewayStatus
}

func (m *mockStatusSubscriptionService) Subscribe(_ context.Context) (<-chan server.GatewayStatus, error) {
	ch := make(chan server.GatewayStatus, len(m.updates))
	for _, update := range m.updates {
		ch <- update
	}
	close(ch)
	return ch, nil
}

type mockAgentControlService struct {
	mu     sync.Mutex
	paused bool
}

func (m *mockAgentControlService) Pause(_ context.Context) (server.AgentState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused = true
	return server.AgentStatePaused, nil
}

func (m *mockAgentControlService) Resume(_ context.Context) (server.AgentState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused = false
	return server.AgentStateRunning, nil
}

func (m *mockAgentControlService) Paused() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.paused
}

func newTestServerWithNodeAPIs(
	t *testing.T,
	nodeSvc server.NodeService,
	statusSvc server.GatewayStatusService,
	agentSvc server.AgentControlService,
) *server.Server {
	t.Helper()

	services := server.NewServicesForTest(
		&mockWorkspaceService{},
		&mockPluginService{},
		&mockSessionService{},
		&mockUserService{},
	).
		WithNodeService(nodeSvc).
		WithGatewayStatusService(statusSvc).
		WithAgentControlService(agentSvc)

	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0",
		Services:   services,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})
	return srv
}

func TestNodeRoutes_ListNodes(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{
		nodes: map[string]server.NodeDetail{
			"macbook-pro": {ID: "macbook-pro", Online: true, Approved: true, Tools: []string{"camera"}},
			"iphone-sean": {ID: "iphone-sean", Online: false, Approved: false, Tools: []string{"location"}},
		},
	}, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Nodes []server.NodeSummary `json:"nodes"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Nodes, 2)
}

func TestNodeRoutes_GetNode(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{
		nodes: map[string]server.NodeDetail{
			"macbook-pro": {ID: "macbook-pro", Online: true, Approved: true, Tools: []string{"camera", "screen"}},
		},
	}, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/macbook-pro", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp server.NodeDetail
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "macbook-pro", resp.ID)
	assert.ElementsMatch(t, []string{"camera", "screen"}, resp.Tools)
}

func TestNodeRoutes_ApproveNode(t *testing.T) {
	nodeSvc := &mockNodeService{
		nodes: map[string]server.NodeDetail{
			"macbook-pro": {ID: "macbook-pro", Online: true, Approved: false, Tools: []string{"camera"}},
		},
	}
	srv := newTestServerWithNodeAPIs(t, nodeSvc, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/macbook-pro/approve", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "approved")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/macbook-pro", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp server.NodeDetail
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Approved)
}

func TestNodeRoutes_DeleteNode(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{
		nodes: map[string]server.NodeDetail{
			"iphone-sean": {ID: "iphone-sean", Online: true, Approved: true, Tools: []string{"location"}},
		},
	}, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/iphone-sean", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/iphone-sean", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNodeRoutes_StatusSubscription(t *testing.T) {
	statusSvc := &mockStatusSubscriptionService{
		updates: []server.GatewayStatus{
			{
				Status:         "running",
				AgentState:     server.AgentStatePaused,
				ConnectedNodes: 2,
				ActiveChannels: 1,
			},
		},
	}
	srv := newTestServerWithNodeAPIs(t, nil, statusSvc, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status/stream", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")
	assert.Contains(t, w.Body.String(), "event: tray_status")
	assert.Contains(t, w.Body.String(), `"agent_state":"paused"`)
	assert.Contains(t, w.Body.String(), `"connected_nodes":2`)
}

func TestNodeRoutes_PauseResumeTransitions(t *testing.T) {
	agentSvc := &mockAgentControlService{}
	srv := newTestServerWithNodeAPIs(t, nil, nil, agentSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/pause", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "paused")
	assert.True(t, agentSvc.Paused())

	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent/resume", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "running")
	assert.False(t, agentSvc.Paused())
}

func TestNodeRoutes_OpenAPIIncludesNewTask6Paths(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{nodes: map[string]server.NodeDetail{}}, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "/api/v1/nodes")
	assert.Contains(t, body, "/api/v1/status/stream")
	assert.Contains(t, body, "/api/v1/agent/pause")
	assert.Contains(t, body, "/api/v1/agent/resume")
}
