// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockChannelPlugin implements plugin.ChannelPlugin for testing.
type mockChannelPlugin struct {
	name      string
	sendCount int
	lastSent  plugin.OutboundMessage
}

func (m *mockChannelPlugin) Name() string { return m.name }

func (m *mockChannelPlugin) Send(_ context.Context, msg plugin.OutboundMessage) error {
	m.sendCount++
	m.lastSent = msg
	return nil
}

// --- Mock PairingStore ---

type mockPairingStore struct {
	pairings []*store.Pairing
	err      error
}

func (m *mockPairingStore) Create(context.Context, *store.Pairing) error { return nil }
func (m *mockPairingStore) GetByChannel(context.Context, string, string) (*store.Pairing, error) {
	return nil, nil
}
func (m *mockPairingStore) GetByUser(_ context.Context, userID string) ([]*store.Pairing, error) {
	if m.err != nil {
		return nil, m.err
	}
	var result []*store.Pairing
	for _, p := range m.pairings {
		if p.UserID == userID {
			result = append(result, p)
		}
	}
	return result, nil
}
func (m *mockPairingStore) Delete(context.Context, string) error { return nil }

func TestChannelRouter_RegisterAndRoute(t *testing.T) {
	router := plugin.NewChannelRouter(nil)
	mock := &mockChannelPlugin{name: "telegram"}

	router.Register("telegram", mock)

	ch, err := router.Get("telegram")
	require.NoError(t, err)
	assert.Equal(t, "telegram", ch.Name())
}

func TestChannelRouter_SendMessage(t *testing.T) {
	router := plugin.NewChannelRouter(nil)
	mock := &mockChannelPlugin{name: "telegram"}
	router.Register("telegram", mock)

	msg := plugin.OutboundMessage{
		ChannelType: "telegram",
		ChannelID:   "chat-123",
		Content:     "hello world",
	}

	err := router.Send(context.Background(), msg)
	require.NoError(t, err)
	assert.Equal(t, 1, mock.sendCount)
	assert.Equal(t, "hello world", mock.lastSent.Content)
	assert.Equal(t, "chat-123", mock.lastSent.ChannelID)
}

func TestChannelRouter_UnregisteredChannel(t *testing.T) {
	router := plugin.NewChannelRouter(nil)

	_, err := router.Get("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestPairingModes(t *testing.T) {
	tests := []struct {
		name      string
		mode      plugin.PairingMode
		userID    string
		allowlist []string
		want      bool
	}{
		{
			name:   "open allows anyone",
			mode:   plugin.PairingOpen,
			userID: "anyone",
			want:   true,
		},
		{
			name:   "closed denies everyone",
			mode:   plugin.PairingClosed,
			userID: "anyone",
			want:   false,
		},
		{
			name:      "allowlist allows listed",
			mode:      plugin.PairingAllowlist,
			userID:    "alice",
			allowlist: []string{"alice", "bob"},
			want:      true,
		},
		{
			name:      "allowlist denies unlisted",
			mode:      plugin.PairingAllowlist,
			userID:    "stranger",
			allowlist: []string{"alice", "bob"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.CheckPairing(tt.mode, tt.userID, tt.allowlist)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- AuthorizeInbound tests ---

func TestAuthorizeInbound_OpenMode(t *testing.T) {
	router := plugin.NewChannelRouter(nil)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin: &mockChannelPlugin{name: "telegram"},
		Mode:   plugin.PairingOpen,
	})

	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "any-user", "ws-1")
	assert.NoError(t, err, "open mode should allow any user without pairing")
}

func TestAuthorizeInbound_ClosedMode(t *testing.T) {
	router := plugin.NewChannelRouter(nil)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin: &mockChannelPlugin{name: "telegram"},
		Mode:   plugin.PairingClosed,
	})

	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "any-user", "ws-1")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingDenied))
}

func TestAuthorizeInbound_AllowlistWithPairing(t *testing.T) {
	ps := &mockPairingStore{
		pairings: []*store.Pairing{
			{
				ID:          "p-1",
				UserID:      "alice",
				ChannelType: "telegram",
				ChannelID:   "chat-1",
				WorkspaceID: "ws-1",
				Status:      store.PairingStatusActive,
			},
		},
	}
	router := plugin.NewChannelRouter(ps)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin:    &mockChannelPlugin{name: "telegram"},
		Mode:      plugin.PairingAllowlist,
		Allowlist: []string{"alice", "bob"},
	})

	// Alice is allowlisted and has active pairing for chat-1
	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "alice", "ws-1")
	assert.NoError(t, err)

	// Bob is allowlisted but has no pairing for chat-1
	err = router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "bob", "ws-1")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingRequired))

	// Stranger is not allowlisted
	err = router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "stranger", "ws-1")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingDenied))
}

func TestAuthorizeInbound_PairingScopedToChannelInstance(t *testing.T) {
	// A pairing on chat-1 should NOT authorize access to chat-2.
	ps := &mockPairingStore{
		pairings: []*store.Pairing{
			{
				ID:          "p-1",
				UserID:      "alice",
				ChannelType: "telegram",
				ChannelID:   "chat-1",
				WorkspaceID: "ws-1",
				Status:      store.PairingStatusActive,
			},
		},
	}
	router := plugin.NewChannelRouter(ps)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin:    &mockChannelPlugin{name: "telegram"},
		Mode:      plugin.PairingAllowlist,
		Allowlist: []string{"alice"},
	})

	// Same channel instance: OK
	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "alice", "ws-1")
	assert.NoError(t, err)

	// Different channel instance: denied (no pairing for chat-2)
	err = router.AuthorizeInbound(context.Background(), "telegram", "chat-2", "alice", "ws-1")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingRequired))
}

func TestAuthorizeInbound_PairingBackendFailure(t *testing.T) {
	ps := &mockPairingStore{err: errors.New("database down")}
	router := plugin.NewChannelRouter(ps)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin:    &mockChannelPlugin{name: "telegram"},
		Mode:      plugin.PairingAllowlist,
		Allowlist: []string{"alice"},
	})

	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "alice", "ws-1")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelBackendFailure))
}

func TestAuthorizeInbound_UnregisteredChannel(t *testing.T) {
	router := plugin.NewChannelRouter(nil)

	err := router.AuthorizeInbound(context.Background(), "unknown", "chat-1", "alice", "ws-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestAuthorizeInbound_DefaultRegisterIsOpen(t *testing.T) {
	router := plugin.NewChannelRouter(nil)
	router.Register("telegram", &mockChannelPlugin{name: "telegram"})

	// Default Register should use open mode
	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "any-user", "ws-1")
	assert.NoError(t, err, "default registration should be open mode")
}

func TestAuthorizeInbound_InactivePairingDenied(t *testing.T) {
	ps := &mockPairingStore{
		pairings: []*store.Pairing{
			{
				ID:          "p-1",
				UserID:      "alice",
				ChannelType: "telegram",
				ChannelID:   "chat-1",
				WorkspaceID: "ws-1",
				Status:      store.PairingStatusPending, // not active
			},
		},
	}
	router := plugin.NewChannelRouter(ps)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin:    &mockChannelPlugin{name: "telegram"},
		Mode:      plugin.PairingAllowlist,
		Allowlist: []string{"alice"},
	})

	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "alice", "ws-1")
	require.Error(t, err, "inactive pairing should not authorize")
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingRequired))
}

func TestAuthorizeInbound_CrossChannelTypePairingDenied(t *testing.T) {
	// A pairing on telegram should NOT authorize access on discord.
	ps := &mockPairingStore{
		pairings: []*store.Pairing{
			{
				ID:          "p-1",
				UserID:      "alice",
				ChannelType: "telegram",
				ChannelID:   "chat-1",
				WorkspaceID: "ws-1",
				Status:      store.PairingStatusActive,
			},
		},
	}
	router := plugin.NewChannelRouter(ps)
	router.RegisterWithConfig("discord", plugin.ChannelRegistration{
		Plugin:    &mockChannelPlugin{name: "discord"},
		Mode:      plugin.PairingAllowlist,
		Allowlist: []string{"alice"},
	})

	err := router.AuthorizeInbound(context.Background(), "discord", "server-1", "alice", "ws-1")
	require.Error(t, err, "telegram pairing should not authorize discord access")
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingRequired))
}

func TestAuthorizeInbound_WorkspaceScopedPairingDenied(t *testing.T) {
	// A pairing on ws-1 should NOT authorize access on ws-2.
	ps := &mockPairingStore{
		pairings: []*store.Pairing{
			{
				ID:          "p-1",
				UserID:      "alice",
				ChannelType: "telegram",
				ChannelID:   "chat-1",
				WorkspaceID: "ws-1",
				Status:      store.PairingStatusActive,
			},
		},
	}
	router := plugin.NewChannelRouter(ps)
	router.RegisterWithConfig("telegram", plugin.ChannelRegistration{
		Plugin:    &mockChannelPlugin{name: "telegram"},
		Mode:      plugin.PairingAllowlist,
		Allowlist: []string{"alice"},
	})

	// Same workspace: OK
	err := router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "alice", "ws-1")
	assert.NoError(t, err)

	// Different workspace: denied
	err = router.AuthorizeInbound(context.Background(), "telegram", "chat-1", "alice", "ws-2")
	require.Error(t, err, "ws-1 pairing should not authorize ws-2 access")
	assert.True(t, sigilerr.HasCode(err, plugin.CodeChannelPairingRequired))
}
