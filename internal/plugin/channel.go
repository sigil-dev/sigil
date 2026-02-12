// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"context"
	"slices"
	"sync"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ChannelPlugin is the interface for channel plugins (messaging platforms).
type ChannelPlugin interface {
	Name() string
	Send(ctx context.Context, msg OutboundMessage) error
}

// OutboundMessage represents a message to send via a channel plugin.
type OutboundMessage struct {
	ChannelType string
	ChannelID   string
	Content     string
	ThreadID    string
	Media       []Media
}

// Media represents an attachment in a message.
type Media struct {
	Type string // "image", "file", "audio", "video"
	URL  string
	Name string
}

// PairingMode determines how new users are paired with a channel.
type PairingMode string

const (
	PairingOpen      PairingMode = "open"
	PairingClosed    PairingMode = "closed"
	PairingAllowlist PairingMode = "allowlist"
)

// ChannelRouter routes outbound messages to the appropriate channel plugin.
type ChannelRouter struct {
	mu       sync.RWMutex
	channels map[string]ChannelPlugin
}

// NewChannelRouter creates a new ChannelRouter.
func NewChannelRouter() *ChannelRouter {
	return &ChannelRouter{
		channels: make(map[string]ChannelPlugin),
	}
}

// Register adds a channel plugin for the given channel type.
func (r *ChannelRouter) Register(channelType string, ch ChannelPlugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[channelType] = ch
}

// Get returns the channel plugin registered for the given type.
func (r *ChannelRouter) Get(channelType string) (ChannelPlugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ch, ok := r.channels[channelType]
	if !ok {
		return nil, sigilerr.Errorf(sigilerr.CodePluginChannelNotFound,
			"channel %q not registered", channelType)
	}
	return ch, nil
}

// Send routes an outbound message to the appropriate channel plugin.
func (r *ChannelRouter) Send(ctx context.Context, msg OutboundMessage) error {
	ch, err := r.Get(msg.ChannelType)
	if err != nil {
		return err
	}
	return ch.Send(ctx, msg)
}

// CheckPairing determines whether a user is allowed to pair with a channel
// based on the pairing mode and allowlist.
func CheckPairing(mode PairingMode, userID string, allowlist []string) bool {
	switch mode {
	case PairingOpen:
		return true
	case PairingClosed:
		return false
	case PairingAllowlist:
		return slices.Contains(allowlist, userID)
	default:
		return false
	}
}
