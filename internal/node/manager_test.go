// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"testing"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerRegisterStoresNodeAndMarksOnline(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID: "macbook-pro",
		Tools:  []string{"camera", "screen"},
	})
	require.NoError(t, err)

	nodes := mgr.List()
	require.Len(t, nodes, 1)
	assert.Equal(t, "macbook-pro", nodes[0].ID)
	assert.True(t, nodes[0].Online)
	assert.Equal(t, []string{"camera", "screen"}, nodes[0].Tools)
}

func TestManagerRegisterWithWorkspaceID(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID:      "macbook-pro",
		WorkspaceID: "ws-123",
		Tools:       []string{"camera"},
	})
	require.NoError(t, err)

	nodes := mgr.List()
	require.Len(t, nodes, 1)
	assert.Equal(t, "ws-123", nodes[0].WorkspaceID)
}

func TestManagerPrefixedTools(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID: "phone",
		Tools:  []string{"camera", "location"},
	})
	require.NoError(t, err)

	tools, err := mgr.PrefixedTools("phone")
	require.NoError(t, err)
	assert.Equal(t, []string{"node:phone:camera", "node:phone:location"}, tools)
}

func TestManagerPrefixedToolsUnknownNode(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	_, err := mgr.PrefixedTools("nonexistent")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerEntityNotFound))
}

func TestManagerDisconnectMarksNodeOffline(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID: "tablet",
		Tools:  []string{"camera"},
	})
	require.NoError(t, err)

	mgr.Disconnect("tablet")

	nodes := mgr.List()
	require.Len(t, nodes, 1)
	assert.False(t, nodes[0].Online)
}

func TestManagerListReturnsRegisteredNodes(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
	require.NoError(t, err)
	err = mgr.Register(Registration{NodeID: "phone", Tools: []string{"camera"}})
	require.NoError(t, err)

	nodes := mgr.List()
	require.Len(t, nodes, 2)
	assert.Equal(t, "mac", nodes[0].ID)
	assert.Equal(t, "phone", nodes[1].ID)
}

func TestManagerQueueToolCallQueuesForOfflineNodeWithTTL(t *testing.T) {
	now := time.Date(2026, time.February, 21, 12, 0, 0, 0, time.UTC)
	mgr := NewManager(ManagerConfig{
		QueueTTL: 60 * time.Second,
		Now: func() time.Time {
			return now
		},
	})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
	require.NoError(t, err)
	mgr.Disconnect("mac")

	reqID, err := mgr.QueueToolCall("mac", "screen", `{"format":"png"}`)
	require.NoError(t, err)
	assert.NotEmpty(t, reqID)

	pending, err := mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, reqID, pending[0].ID)
	assert.Equal(t, "mac", pending[0].NodeID)
	assert.Equal(t, "screen", pending[0].Tool)
	assert.Equal(t, `{"format":"png"}`, pending[0].Args)
	assert.Equal(t, now.Add(60*time.Second), pending[0].ExpiresAt)
}

func TestManagerQueueToolCallExpiresAfterTTL(t *testing.T) {
	now := time.Date(2026, time.February, 21, 13, 0, 0, 0, time.UTC)
	mgr := NewManager(ManagerConfig{
		QueueTTL: 2 * time.Second,
		Now: func() time.Time {
			return now
		},
	})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
	require.NoError(t, err)
	mgr.Disconnect("mac")

	_, err = mgr.QueueToolCall("mac", "screen", `{"format":"png"}`)
	require.NoError(t, err)

	pending, err := mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 1)

	now = now.Add(3 * time.Second)
	pending, err = mgr.PendingRequests("mac")
	require.NoError(t, err)
	assert.Empty(t, pending)
}

func TestManagerPendingRequestsUnknownNode(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	_, err := mgr.PendingRequests("nonexistent")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerEntityNotFound))
}

func TestManagerQueueToolCallValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Manager)
		nodeID   string
		tool     string
		wantCode sigilerr.Code
	}{
		{
			name: "unknown node",
			setup: func(_ *Manager) {
			},
			nodeID:   "missing",
			tool:     "screen",
			wantCode: sigilerr.CodeServerEntityNotFound,
		},
		{
			name: "online node cannot queue",
			setup: func(mgr *Manager) {
				require.NoError(t, mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}}))
			},
			nodeID:   "mac",
			tool:     "screen",
			wantCode: sigilerr.CodeServerRequestInvalid,
		},
		{
			name: "tool not registered on node",
			setup: func(mgr *Manager) {
				require.NoError(t, mgr.Register(Registration{NodeID: "mac", Tools: []string{"camera"}}))
				mgr.Disconnect("mac")
			},
			nodeID:   "mac",
			tool:     "screen",
			wantCode: sigilerr.CodeServerRequestInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(ManagerConfig{})
			tt.setup(mgr)

			_, err := mgr.QueueToolCall(tt.nodeID, tt.tool, `{"format":"png"}`)
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode))
		})
	}
}

// stubAuth is a test Authenticator that can be configured to pass or fail.
type stubAuth struct {
	err error
}

func (s *stubAuth) Authenticate(_ Registration) error {
	return s.err
}

func TestManagerRegisterWithAuthValidates(t *testing.T) {
	authErr := sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "auth failed")

	tests := []struct {
		name    string
		authErr error
		wantErr bool
	}{
		{
			name:    "auth passes",
			authErr: nil,
			wantErr: false,
		},
		{
			name:    "auth fails blocks registration",
			authErr: authErr,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(ManagerConfig{
				Auth: &stubAuth{err: tt.authErr},
			})

			err := mgr.Register(Registration{
				NodeID: "phone",
				Tools:  []string{"camera"},
			})

			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerAuthUnauthorized))
				assert.Empty(t, mgr.List())
			} else {
				require.NoError(t, err)
				assert.Len(t, mgr.List(), 1)
			}
		})
	}
}
