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

func TestManagerPrefixedTools(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID: "phone",
		Tools:  []string{"camera", "location"},
	})
	require.NoError(t, err)

	tools := mgr.PrefixedTools("phone")
	assert.Equal(t, []string{"node:phone:camera", "node:phone:location"}, tools)
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

	pending := mgr.PendingRequests("mac")
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
	require.Len(t, mgr.PendingRequests("mac"), 1)

	now = now.Add(3 * time.Second)
	assert.Empty(t, mgr.PendingRequests("mac"))
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
