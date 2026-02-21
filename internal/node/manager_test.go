// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"fmt"
	"strings"
	"sync"
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

	require.NoError(t, mgr.Disconnect("tablet"))

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
	require.NoError(t, mgr.Disconnect("mac"))

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
	require.NoError(t, mgr.Disconnect("mac"))

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
				require.NoError(t, mgr.Disconnect("mac"))
			},
			nodeID:   "mac",
			tool:     "screen",
			wantCode: sigilerr.CodeServerRequestInvalid,
		},
		{
			name: "whitespace-only nodeID",
			setup: func(_ *Manager) {
			},
			nodeID:   "   ",
			tool:     "screen",
			wantCode: sigilerr.CodeServerRequestInvalid,
		},
		{
			name: "whitespace-only tool",
			setup: func(mgr *Manager) {
				require.NoError(t, mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}}))
				require.NoError(t, mgr.Disconnect("mac"))
			},
			nodeID:   "mac",
			tool:     "   ",
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

// stubWorkspaceValidator is a test WorkspaceValidator that can be configured to pass or fail.
type stubWorkspaceValidator struct {
	err    error
	called bool
}

func (s *stubWorkspaceValidator) ValidateWorkspace(_, _ string) error {
	s.called = true
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

func TestManagerRegisterEmptyNodeIDReturnsError(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{NodeID: "   ", Tools: []string{"camera"}})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerRequestInvalid))
	assert.Empty(t, mgr.List())
}

func TestManagerRegisterWorkspaceValidator(t *testing.T) {
	validatorErr := sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "workspace not allowed")

	tests := []struct {
		name         string
		validatorErr error
		wantErr      bool
	}{
		{
			name:         "validator passes",
			validatorErr: nil,
			wantErr:      false,
		},
		{
			name:         "validator returns error blocks registration",
			validatorErr: validatorErr,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(ManagerConfig{
				WorkspaceValidator: &stubWorkspaceValidator{err: tt.validatorErr},
			})

			err := mgr.Register(Registration{
				NodeID:      "phone",
				WorkspaceID: "ws-123",
				Tools:       []string{"camera"},
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

func TestManagerRegisterAuthOrderBeforeWorkspaceValidator(t *testing.T) {
	wsValidator := &stubWorkspaceValidator{}
	mgr := NewManager(ManagerConfig{
		Auth:               &stubAuth{err: sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "unauthorized")},
		WorkspaceValidator: wsValidator,
	})

	err := mgr.Register(Registration{
		NodeID:      "phone",
		WorkspaceID: "ws-123",
		Tools:       []string{"camera"},
	})

	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerAuthUnauthorized))
	assert.False(t, wsValidator.called, "WorkspaceValidator must not be called when Auth fails first")
}

func TestManagerDisconnectUnknownNode(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Disconnect("nonexistent")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerEntityNotFound))

	assert.Empty(t, mgr.List())
}

func TestManagerListCapsDefensiveCopy(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID:       "mac",
		Capabilities: []string{"cap:read"},
		Tools:        []string{"screen"},
	})
	require.NoError(t, err)

	nodes := mgr.List()
	require.Len(t, nodes, 1)

	// Mutate the returned slice in-place; the internal state must not change.
	nodes[0].Capabilities[0] = "MUTATED"

	nodes2 := mgr.List()
	require.Len(t, nodes2, 1)
	assert.Equal(t, "cap:read", nodes2[0].Capabilities[0])
}

func TestManagerQueueToolCallArgsSizeLimit(t *testing.T) {
	tests := []struct {
		name    string
		argsLen int
		wantErr bool
	}{
		{
			name:    "args exactly at 64 KB succeeds",
			argsLen: maxArgsSizeBytes,
			wantErr: false,
		},
		{
			name:    "args at 64 KB plus 1 byte returns error",
			argsLen: maxArgsSizeBytes + 1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(ManagerConfig{})

			err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
			require.NoError(t, err)
			require.NoError(t, mgr.Disconnect("mac"))

			args := strings.Repeat("x", tt.argsLen)

			_, err = mgr.QueueToolCall("mac", "screen", args)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerRequestInvalid))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestManagerQueueToolCallMixedExpiry(t *testing.T) {
	const ttl = 50 * time.Millisecond

	mgr := NewManager(ManagerConfig{
		QueueTTL: ttl,
	})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"tool1"}})
	require.NoError(t, err)
	require.NoError(t, mgr.Disconnect("mac"))

	// Queue first request (will expire after TTL).
	_, err = mgr.QueueToolCall("mac", "tool1", `{}`)
	require.NoError(t, err)

	// Wait for first request to expire.
	time.Sleep(ttl + 10*time.Millisecond)

	// Queue second request (should still be live).
	secondID, err := mgr.QueueToolCall("mac", "tool1", `{}`)
	require.NoError(t, err)

	pending, err := mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, secondID, pending[0].ID)
}

func TestManagerQueueToolCallPendingCap(t *testing.T) {
	now := time.Date(2026, time.February, 21, 14, 0, 0, 0, time.UTC)
	mgr := NewManager(ManagerConfig{
		QueueTTL: 10 * time.Minute,
		Now: func() time.Time {
			return now
		},
	})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
	require.NoError(t, err)
	require.NoError(t, mgr.Disconnect("mac"))

	// Fill the queue to exactly maxPendingPerNode.
	for i := range maxPendingPerNode {
		_, err := mgr.QueueToolCall("mac", "screen", "small")
		require.NoError(t, err, "request %d should succeed", i)
	}

	pending, err := mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, maxPendingPerNode)

	// The 101st request must be rejected.
	_, err = mgr.QueueToolCall("mac", "screen", "small")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerRequestInvalid))
	assert.Contains(t, err.Error(), "pending queue is full")
}

func TestManagerPendingRequestsExactBoundaryExpiry(t *testing.T) {
	const ttl = 30 * time.Second
	start := time.Date(2026, time.February, 21, 15, 0, 0, 0, time.UTC)
	now := start

	mgr := NewManager(ManagerConfig{
		QueueTTL: ttl,
		Now: func() time.Time {
			return now
		},
	})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
	require.NoError(t, err)
	require.NoError(t, mgr.Disconnect("mac"))

	reqID, err := mgr.QueueToolCall("mac", "screen", `{"action":"capture"}`)
	require.NoError(t, err)
	assert.NotEmpty(t, reqID)

	// Advance clock to exactly ExpiresAt (start + TTL).
	// The condition is !req.ExpiresAt.Before(now), i.e. ExpiresAt >= now,
	// so a request whose ExpiresAt equals now must still be kept.
	now = start.Add(ttl)

	pending, err := mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 1, "request at exact ExpiresAt boundary must be kept")
	assert.Equal(t, reqID, pending[0].ID)

	// Advance clock 1 nanosecond past ExpiresAt — request must now be pruned.
	now = start.Add(ttl + time.Nanosecond)

	pending, err = mgr.PendingRequests("mac")
	require.NoError(t, err)
	assert.Empty(t, pending, "request 1ns past ExpiresAt must be pruned")
}

func TestManagerRegisterReregistration(t *testing.T) {
	tests := []struct {
		name        string
		nodeOnline  bool
		wantErr     bool
		wantCode    sigilerr.Code
		wantOnline  bool
	}{
		{
			name:       "offline node can re-register",
			nodeOnline: false,
			wantErr:    false,
			wantOnline: true,
		},
		{
			name:       "online node cannot re-register",
			nodeOnline: true,
			wantErr:    true,
			wantCode:   sigilerr.CodeServerRequestInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(ManagerConfig{})

			// First registration with initial field values
			err := mgr.Register(Registration{
				NodeID:       "mac",
				WorkspaceID:  "ws-old",
				Platform:     "darwin",
				Capabilities: []string{"screen:capture"},
				Tools:        []string{"screen"},
			})
			require.NoError(t, err)

			// Optionally disconnect to make node offline
			if !tt.nodeOnline {
				require.NoError(t, mgr.Disconnect("mac"))
			}

			// Second registration attempt with different field values
			err = mgr.Register(Registration{
				NodeID:       "mac",
				WorkspaceID:  "ws-new",
				Platform:     "linux",
				Capabilities: []string{"screen:capture", "camera:record"},
				Tools:        []string{"screen", "camera"},
			})
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.wantCode))
			} else {
				require.NoError(t, err)
				nodes := mgr.List()
				require.Len(t, nodes, 1)
				assert.Equal(t, tt.wantOnline, nodes[0].Online)
				assert.Equal(t, []string{"screen", "camera"}, nodes[0].Tools)
				assert.Equal(t, "ws-new", nodes[0].WorkspaceID)
				assert.Equal(t, "linux", nodes[0].Platform)
				assert.Equal(t, []string{"screen:capture", "camera:record"}, nodes[0].Capabilities)
			}
		})
	}
}

func TestManagerRegisterNilToolsSlice(t *testing.T) {
	mgr := NewManager(ManagerConfig{})

	err := mgr.Register(Registration{
		NodeID: "phone",
		Tools:  nil,
	})
	require.NoError(t, err)

	nodes := mgr.List()
	require.Len(t, nodes, 1)
	assert.Equal(t, "phone", nodes[0].ID)
	assert.True(t, nodes[0].Online)
	// nil and empty slices are equivalent for ranging; only emptiness matters.
	assert.Empty(t, nodes[0].Tools)

	tools, err := mgr.PrefixedTools("phone")
	require.NoError(t, err)
	assert.NotNil(t, tools)
	assert.Empty(t, tools)
}

func TestManagerPruneDeletesKeyWhenAllExpired(t *testing.T) {
	start := time.Date(2026, time.February, 21, 16, 0, 0, 0, time.UTC)
	now := start
	const ttl = 5 * time.Second

	mgr := NewManager(ManagerConfig{
		QueueTTL: ttl,
		Now: func() time.Time {
			return now
		},
	})

	err := mgr.Register(Registration{NodeID: "mac", Tools: []string{"screen"}})
	require.NoError(t, err)
	require.NoError(t, mgr.Disconnect("mac"))

	// Queue 2 requests at time T.
	req1, err := mgr.QueueToolCall("mac", "screen", `{"a":1}`)
	require.NoError(t, err)
	req2, err := mgr.QueueToolCall("mac", "screen", `{"a":2}`)
	require.NoError(t, err)

	// Both should be visible before expiry.
	pending, err := mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, req1, pending[0].ID)
	assert.Equal(t, req2, pending[1].ID)

	// Advance clock past TTL so both requests expire.
	now = start.Add(ttl + time.Second)

	// Queue a new request at T+6s. This triggers pruneExpiredLocked which
	// should delete the map key for the old (now empty) slice, then append
	// the new request to a fresh slice.
	newID, err := mgr.QueueToolCall("mac", "screen", `{"a":3}`)
	require.NoError(t, err)

	// Only the new request should be pending.
	pending, err = mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, newID, pending[0].ID)

	// Advance clock 1 more second (still within TTL of the new request).
	now = start.Add(ttl + 2*time.Second)

	pending, err = mgr.PendingRequests("mac")
	require.NoError(t, err)
	require.Len(t, pending, 1, "new request must survive; no stale data from pruned slice")
	assert.Equal(t, newID, pending[0].ID)
}

func TestManagerConcurrentAccess(t *testing.T) {
	mgr := NewManager(ManagerConfig{QueueTTL: 10 * time.Minute})

	const goroutines = 10
	const ops = 20

	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			nodeID := fmt.Sprintf("node-%d", i)
			for range ops {
				_ = mgr.Register(Registration{NodeID: nodeID, Tools: []string{"tool"}})
				_ = mgr.List()
				_ = mgr.Disconnect(nodeID)
			}
		}(i)
	}
	wg.Wait()
	// If we reach here without panic or deadlock, concurrent access is safe.
}

func TestManagerConcurrentQueueOperations(t *testing.T) {
	mgr := NewManager(ManagerConfig{QueueTTL: 10 * time.Minute})

	require.NoError(t, mgr.Register(Registration{NodeID: "node", Tools: []string{"tool"}}))
	require.NoError(t, mgr.Disconnect("node"))

	const goroutines = 5
	var wg sync.WaitGroup

	for range goroutines {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = mgr.QueueToolCall("node", "tool", "{}")
		}()
		go func() {
			defer wg.Done()
			_, _ = mgr.PendingRequests("node")
		}()
	}
	wg.Wait()
	// No panic or data race means the mutex coverage is correct.
}
