// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
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

func TestChannelRouter_RegisterAndRoute(t *testing.T) {
	router := plugin.NewChannelRouter()
	mock := &mockChannelPlugin{name: "telegram"}

	router.Register("telegram", mock)

	ch, err := router.Get("telegram")
	require.NoError(t, err)
	assert.Equal(t, "telegram", ch.Name())
}

func TestChannelRouter_SendMessage(t *testing.T) {
	router := plugin.NewChannelRouter()
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
	router := plugin.NewChannelRouter()

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
