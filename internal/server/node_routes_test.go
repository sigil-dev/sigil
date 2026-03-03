// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
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

// mockNodeService is a stateful NodeService mock for HTTP handler testing.
// For minimal stubs in internal package tests, see stubNodeService in services_test.go.
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

func (m *mockNodeService) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	n, ok := m.nodes[id]
	if !ok {
		return sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "node %q not found", id)
	}
	n.Approved = false
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

// mockErrorNodeService returns an error from every method, for testing
// the 500 Internal Server Error path via notFoundOr500.
type mockErrorNodeService struct {
	err error
}

func (m *mockErrorNodeService) List(context.Context) ([]server.NodeSummary, error) {
	return nil, m.err
}

func (m *mockErrorNodeService) Get(context.Context, string) (*server.NodeDetail, error) {
	return nil, m.err
}

func (m *mockErrorNodeService) Approve(context.Context, string) error { return m.err }
func (m *mockErrorNodeService) Revoke(context.Context, string) error  { return m.err }
func (m *mockErrorNodeService) Delete(context.Context, string) error  { return m.err }

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

// mockSubscribeErrorService returns an error from Subscribe, for testing
// the pre-stream 500 error path.
type mockSubscribeErrorService struct {
	err error
}

func (m *mockSubscribeErrorService) Subscribe(context.Context) (<-chan server.GatewayStatus, error) {
	return nil, m.err
}

// mockAgentControlService is a stateful AgentControlService mock for HTTP
// handler testing. For minimal stubs in internal package tests, see
// stubAgentControlService in services_test.go.
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

// mockErrorAgentControlService returns an error from every method, for
// testing the 500 Internal Server Error path.
type mockErrorAgentControlService struct {
	err error
}

func (m *mockErrorAgentControlService) Pause(context.Context) (server.AgentState, error) {
	return "", m.err
}

func (m *mockErrorAgentControlService) Resume(context.Context) (server.AgentState, error) {
	return "", m.err
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
			"macbook-pro": {ID: "macbook-pro", Platform: "darwin", Online: true, Approved: true, Tools: []string{"camera"}},
			"iphone-sean": {ID: "iphone-sean", Platform: "ios", Online: false, Approved: false, Tools: []string{"location"}},
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
			"macbook-pro": {ID: "macbook-pro", Platform: "darwin", Online: true, Approved: true, Tools: []string{"camera", "screen"}},
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
			"macbook-pro": {ID: "macbook-pro", Platform: "darwin", Online: true, Approved: false, Tools: []string{"camera"}},
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
			"iphone-sean": {ID: "iphone-sean", Platform: "ios", Online: true, Approved: true, Tools: []string{"location"}},
		},
	}, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/iphone-sean", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String())

	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/iphone-sean", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNodeRoutes_StatusSubscription(t *testing.T) {
	statusSvc := &mockStatusSubscriptionService{
		updates: []server.GatewayStatus{
			{
				Status:         server.GatewayStatusRunning,
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

	req = httptest.NewRequest(http.MethodPost, "/api/v1/agent/resume", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "running")
}

func TestNodeRoutes_RevokeNode(t *testing.T) {
	nodeSvc := &mockNodeService{
		nodes: map[string]server.NodeDetail{
			"macbook-pro": {ID: "macbook-pro", Platform: "darwin", Online: true, Approved: true, Tools: []string{"camera"}},
		},
	}
	srv := newTestServerWithNodeAPIs(t, nodeSvc, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/macbook-pro/revoke", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "revoked")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/nodes/macbook-pro", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp server.NodeDetail
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Approved)
}

// TestNodeRoutes_NotFound consolidates the four separate not-found tests into
// a table-driven test per project convention.
func TestNodeRoutes_NotFound(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{nodes: map[string]server.NodeDetail{}}, nil, nil)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/nodes/no-such-node"},
		{http.MethodPost, "/api/v1/nodes/no-such-node/approve"},
		{http.MethodPost, "/api/v1/nodes/no-such-node/revoke"},
		{http.MethodDelete, "/api/v1/nodes/no-such-node"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

// TestNodeRoutes_NilService_Returns503 consolidates nil-service 503 tests
// into a table-driven test.
func TestNodeRoutes_NilService_Returns503(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, nil, nil, nil)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/nodes"},
		{http.MethodGet, "/api/v1/nodes/test-node"},
		{http.MethodPost, "/api/v1/nodes/test-node/approve"},
		{http.MethodPost, "/api/v1/nodes/test-node/revoke"},
		{http.MethodDelete, "/api/v1/nodes/test-node"},
		{http.MethodGet, "/api/v1/status/stream"},
		{http.MethodPost, "/api/v1/agent/pause"},
		{http.MethodPost, "/api/v1/agent/resume"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}

func TestNodeRoutes_ListNodes_Empty(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{
		nodes: map[string]server.NodeDetail{},
	}, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Nodes []server.NodeSummary `json:"nodes"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Nodes)
}

func TestNodeRoutes_PauseAgent_Idempotent(t *testing.T) {
	agentSvc := &mockAgentControlService{}
	srv := newTestServerWithNodeAPIs(t, nil, nil, agentSvc)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/pause", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, strings.ToLower(w.Body.String()), "paused")
	}
}

func TestNodeRoutes_AuthEnabled_Returns401(t *testing.T) {
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"admin-token": mustNewAuthenticatedUser("admin-1", "Admin", []string{"admin:nodes", "admin:agent", "admin:status"}),
		},
	}
	services := server.NewServicesForTest(
		&mockWorkspaceService{},
		&mockPluginService{},
		&mockSessionService{},
		&mockUserService{},
	).
		WithNodeService(&mockNodeService{nodes: map[string]server.NodeDetail{}}).
		WithAgentControlService(&mockAgentControlService{})

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services:       services,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/nodes"},
		{http.MethodGet, "/api/v1/nodes/test-node"},
		{http.MethodPost, "/api/v1/nodes/test-node/approve"},
		{http.MethodPost, "/api/v1/nodes/test-node/revoke"},
		{http.MethodDelete, "/api/v1/nodes/test-node"},
		{http.MethodPost, "/api/v1/agent/pause"},
		{http.MethodPost, "/api/v1/agent/resume"},
		{http.MethodGet, "/api/v1/status/stream"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestNodeRoutes_AuthEnabled_Returns403(t *testing.T) {
	// When auth is enabled but user lacks admin:nodes/admin:agent/admin:status,
	// all 8 new endpoints must return 403 Forbidden.
	validator := &mockTokenValidator{
		users: map[string]*server.AuthenticatedUser{
			"user-token": mustNewAuthenticatedUser("user-1", "User", []string{"workspace:read"}),
		},
	}
	services := server.NewServicesForTest(
		&mockWorkspaceService{},
		&mockPluginService{},
		&mockSessionService{},
		&mockUserService{},
	).
		WithNodeService(&mockNodeService{nodes: map[string]server.NodeDetail{}}).
		WithAgentControlService(&mockAgentControlService{})

	srv, err := server.New(server.Config{
		ListenAddr:     "127.0.0.1:0",
		TokenValidator: validator,
		Services:       services,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("srv.Close() in cleanup: %v", err)
		}
	})

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/nodes"},
		{http.MethodGet, "/api/v1/nodes/test-node"},
		{http.MethodPost, "/api/v1/nodes/test-node/approve"},
		{http.MethodPost, "/api/v1/nodes/test-node/revoke"},
		{http.MethodDelete, "/api/v1/nodes/test-node"},
		{http.MethodPost, "/api/v1/agent/pause"},
		{http.MethodPost, "/api/v1/agent/resume"},
		{http.MethodGet, "/api/v1/status/stream"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			req.Header.Set("Authorization", "Bearer user-token")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestNodeRoutes_StatusStream_ContextCancellation(t *testing.T) {
	// Use an unbuffered channel so the send blocks until the handler reads,
	// eliminating the race between context cancellation and event consumption.
	ch := make(chan server.GatewayStatus)
	statusSvc := &mockBlockingStatusService{ch: ch}
	srv := newTestServerWithNodeAPIs(t, nil, statusSvc, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()

	// Send one event — the unbuffered send blocks until the handler reads it,
	// guaranteeing the event is consumed before we cancel.
	ch <- server.GatewayStatus{
		Status:         server.GatewayStatusRunning,
		AgentState:     server.AgentStateRunning,
		ConnectedNodes: 1,
		ActiveChannels: 0,
	}

	cancel()
	<-done

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "tray_status")
}

// mockBlockingStatusService returns an open channel that won't be closed by the service.
type mockBlockingStatusService struct {
	ch chan server.GatewayStatus
}

func (m *mockBlockingStatusService) Subscribe(_ context.Context) (<-chan server.GatewayStatus, error) {
	return m.ch, nil
}

func TestNodeRoutes_OpenAPIIncludesNewTask6Paths(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{nodes: map[string]server.NodeDetail{}}, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "/api/v1/nodes")
	assert.Contains(t, body, "/api/v1/nodes/{id}/approve")
	assert.Contains(t, body, "/api/v1/nodes/{id}/revoke")
	assert.Contains(t, body, "/api/v1/status/stream")
	assert.Contains(t, body, "/api/v1/agent/pause")
	assert.Contains(t, body, "/api/v1/agent/resume")
	assert.Contains(t, body, "text/event-stream")
}

// --- New tests for findings .9, .11, .14, .16, .19 ---

func TestNodeRoutes_StatusStream_SubscribeError(t *testing.T) {
	statusSvc := &mockSubscribeErrorService{err: fmt.Errorf("connection refused")}
	srv := newTestServerWithNodeAPIs(t, nil, statusSvc, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status/stream", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestNodeRoutes_InvalidNodeID(t *testing.T) {
	srv := newTestServerWithNodeAPIs(t, &mockNodeService{nodes: map[string]server.NodeDetail{}}, nil, nil)

	tests := []struct {
		name string
		id   string
	}{
		{"starts with dot", ".bad"},
		{"starts with dash", "-bad"},
		{"contains exclamation", "node!name"},
		{"exceeds max length", strings.Repeat("a", 254)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/"+tt.id, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnprocessableEntity, w.Code,
				"expected 422 for invalid node ID %q", tt.id)
		})
	}

	// Minimum valid single-character ID — should reach the handler (404, not 422).
	t.Run("single char valid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/a", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestNodeRoutes_InternalError500(t *testing.T) {
	svc := &mockErrorNodeService{err: fmt.Errorf("db connection lost")}
	srv := newTestServerWithNodeAPIs(t, svc, nil, nil)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/nodes"},
		{http.MethodGet, "/api/v1/nodes/test-node"},
		{http.MethodPost, "/api/v1/nodes/test-node/approve"},
		{http.MethodPost, "/api/v1/nodes/test-node/revoke"},
		{http.MethodDelete, "/api/v1/nodes/test-node"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusInternalServerError, w.Code)
		})
	}
}

func TestNodeRoutes_PauseResume_InternalError(t *testing.T) {
	svc := &mockErrorAgentControlService{err: fmt.Errorf("agent not initialized")}
	srv := newTestServerWithNodeAPIs(t, nil, nil, svc)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"pause error", http.MethodPost, "/api/v1/agent/pause"},
		{"resume error", http.MethodPost, "/api/v1/agent/resume"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusInternalServerError, w.Code)
		})
	}
}

func TestNodeRoutes_StatusStream_WriteError(t *testing.T) {
	statusSvc := &mockStatusSubscriptionService{
		updates: []server.GatewayStatus{
			{Status: server.GatewayStatusRunning, AgentState: server.AgentStateRunning, ConnectedNodes: 1},
			{Status: server.GatewayStatusDegraded, AgentState: server.AgentStatePaused, ConnectedNodes: 0},
		},
	}
	srv := newTestServerWithNodeAPIs(t, nil, statusSvc, nil)

	recorder := httptest.NewRecorder()
	fw := &writeLimitResponseWriter{
		ResponseWriter: recorder,
		failAfter:      10,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status/stream", nil)
	srv.Handler().ServeHTTP(fw, req)

	// The handler should exit cleanly without panic or goroutine leak.
	// No specific status assertion — the write failure occurs inside the
	// stream body after the 200 status is already committed.
}

// writeLimitResponseWriter wraps an http.ResponseWriter and fails Write calls
// after a configurable number of bytes, for testing write-error paths.
type writeLimitResponseWriter struct {
	http.ResponseWriter
	failAfter int
	written   int
}

func (w *writeLimitResponseWriter) Write(p []byte) (n int, err error) {
	if w.written >= w.failAfter {
		return 0, fmt.Errorf("simulated write failure")
	}
	n, err = w.ResponseWriter.Write(p)
	w.written += n
	return n, err
}
