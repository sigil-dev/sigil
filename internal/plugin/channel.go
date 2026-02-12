// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"context"
	"slices"
	"sync"

	"github.com/sigil-dev/sigil/internal/store"
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

// ChannelRegistration holds a channel plugin along with its pairing configuration.
type ChannelRegistration struct {
	Plugin    ChannelPlugin
	Mode      PairingMode
	Allowlist []string
}

// ChannelRouter routes outbound messages and enforces inbound channel
// authorization based on per-channel pairing mode.
type ChannelRouter struct {
	mu       sync.RWMutex
	channels map[string]*ChannelRegistration
	pairings store.PairingStore
}

// NewChannelRouter creates a new ChannelRouter with the given pairing store
// for authorization checks. If pairings is nil, AuthorizeInbound will skip
// pairing verification for non-open modes.
func NewChannelRouter(pairings store.PairingStore) *ChannelRouter {
	return &ChannelRouter{
		channels: make(map[string]*ChannelRegistration),
		pairings: pairings,
	}
}

// Register adds a channel plugin for the given channel type with default open mode.
func (r *ChannelRouter) Register(channelType string, ch ChannelPlugin) {
	r.RegisterWithConfig(channelType, ChannelRegistration{
		Plugin: ch,
		Mode:   PairingOpen,
	})
}

// RegisterWithConfig adds a channel plugin with explicit pairing configuration.
func (r *ChannelRouter) RegisterWithConfig(channelType string, reg ChannelRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[channelType] = &reg
}

// Get returns the channel plugin registered for the given type.
func (r *ChannelRouter) Get(channelType string) (ChannelPlugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.channels[channelType]
	if !ok {
		return nil, sigilerr.Errorf(sigilerr.CodePluginChannelNotFound,
			"channel %q not registered", channelType)
	}
	return reg.Plugin, nil
}

// Send routes an outbound message to the appropriate channel plugin.
func (r *ChannelRouter) Send(ctx context.Context, msg OutboundMessage) error {
	ch, err := r.Get(msg.ChannelType)
	if err != nil {
		return err
	}
	return ch.Send(ctx, msg)
}

// AuthorizeInbound checks whether a user is authorized to interact via a
// channel based on the channel's pairing mode. For open-mode channels,
// authorization always succeeds (no pairing required). For closed and
// allowlist modes, an active pairing scoped to the specific channel instance
// (channelType + channelID) is required.
func (r *ChannelRouter) AuthorizeInbound(ctx context.Context, channelType, channelID, userID string) error {
	r.mu.RLock()
	reg, ok := r.channels[channelType]
	r.mu.RUnlock()

	if !ok {
		return sigilerr.Errorf(sigilerr.CodePluginChannelNotFound,
			"channel %q not registered", channelType)
	}

	switch reg.Mode {
	case PairingOpen:
		return nil
	case PairingClosed:
		return sigilerr.New(CodeChannelPairingDenied,
			"channel is closed",
			sigilerr.Field("channel_type", channelType),
			sigilerr.Field("channel_id", channelID),
		)
	case PairingAllowlist:
		if !slices.Contains(reg.Allowlist, userID) {
			return sigilerr.New(CodeChannelPairingDenied,
				"user not in channel allowlist",
				sigilerr.Field("channel_type", channelType),
				sigilerr.Field("channel_id", channelID),
				sigilerr.Field("user_id", userID),
			)
		}
	default:
		return sigilerr.New(CodeChannelPairingDenied,
			"unknown pairing mode",
			sigilerr.Field("channel_type", channelType),
			sigilerr.Field("mode", string(reg.Mode)),
		)
	}

	// For non-open modes (allowlist passes above), verify active pairing
	// scoped to the specific channel instance.
	if r.pairings == nil {
		return sigilerr.New(CodeChannelPairingRequired,
			"pairing store not configured",
			sigilerr.Field("channel_type", channelType),
		)
	}

	pairings, err := r.pairings.GetByUser(ctx, userID)
	if err != nil {
		return sigilerr.Wrap(err, CodeChannelBackendFailure,
			"pairing lookup failed",
			sigilerr.Field("channel_type", channelType),
			sigilerr.Field("user_id", userID),
		)
	}

	for _, p := range pairings {
		if p.ChannelType == channelType && p.ChannelID == channelID && p.Status == store.PairingStatusActive {
			return nil
		}
	}

	return sigilerr.New(CodeChannelPairingRequired,
		"no active pairing for channel",
		sigilerr.Field("channel_type", channelType),
		sigilerr.Field("channel_id", channelID),
		sigilerr.Field("user_id", userID),
	)
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

// CodeChannelPairingRequired indicates that no active pairing exists for the channel.
const CodeChannelPairingRequired sigilerr.Code = "channel.pairing.required"

// CodeChannelPairingDenied indicates the channel mode denies the user.
const CodeChannelPairingDenied sigilerr.Code = "channel.pairing.denied"

// CodeChannelBackendFailure indicates an infrastructure error during pairing lookup.
const CodeChannelBackendFailure sigilerr.Code = "channel.backend.failure"
