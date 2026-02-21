// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// TailscaleConfig holds the Phase 6 tailscale baseline settings.
// mTLS is intentionally deferred per D078.
type TailscaleConfig struct {
	Hostname    string
	AuthKey     string
	RequiredTag string
}

func (c TailscaleConfig) Validate() error {
	if strings.TrimSpace(c.Hostname) == "" {
		return sigilerr.New(sigilerr.CodeServerConfigInvalid, "tailscale hostname is required")
	}

	if strings.TrimSpace(c.AuthKey) == "" {
		return sigilerr.New(sigilerr.CodeServerConfigInvalid, "tailscale auth key is required")
	}

	requiredTag := strings.TrimSpace(c.RequiredTag)
	if requiredTag == "" {
		return sigilerr.New(sigilerr.CodeServerConfigInvalid, "tailscale required tag is required")
	}
	if !strings.HasPrefix(requiredTag, "tag:") {
		return sigilerr.New(sigilerr.CodeServerConfigInvalid,
			"tailscale required tag must start with tag:",
			sigilerr.Field("required_tag", requiredTag))
	}

	return nil
}

// TailscaleAuth performs tailnet tag-based checks.
type TailscaleAuth struct {
	requiredTag string
}

func NewTailscaleAuth(cfg TailscaleConfig) (*TailscaleAuth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &TailscaleAuth{requiredTag: strings.TrimSpace(cfg.RequiredTag)}, nil
}

func (a *TailscaleAuth) CheckTag(tags []string) bool {
	if a == nil || a.requiredTag == "" {
		return false
	}

	for _, tag := range tags {
		if strings.TrimSpace(tag) == a.requiredTag {
			return true
		}
	}

	return false
}

// Authenticate implements Authenticator for Tailscale tag-based validation.
func (a *TailscaleAuth) Authenticate(reg Registration) error {
	if !a.CheckTag(reg.TailscaleTags) {
		return sigilerr.New(sigilerr.CodeServerAuthUnauthorized,
			"node does not have required tailscale tag",
			sigilerr.Field("node_id", reg.NodeID),
			sigilerr.Field("required_tag", a.requiredTag))
	}
	return nil
}

// TokenAuth provides Phase 6 token-based node authentication.
type TokenAuth struct {
	tokenHash [32]byte
}

func NewTokenAuth(token string) (*TokenAuth, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "node auth token is required")
	}

	return &TokenAuth{tokenHash: sha256.Sum256([]byte(trimmed))}, nil
}

func (a *TokenAuth) CheckToken(candidate string) error {
	if a == nil {
		return sigilerr.New(sigilerr.CodeServerConfigInvalid, "token auth is not configured")
	}

	candidateHash := sha256.Sum256([]byte(candidate))
	if subtle.ConstantTimeCompare(a.tokenHash[:], candidateHash[:]) == 1 {
		return nil
	}

	slog.Warn("node token authentication failed")
	return sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "invalid node token")
}

// Authenticate implements Authenticator for token-based validation.
func (a *TokenAuth) Authenticate(reg Registration) error {
	return a.CheckToken(reg.AuthToken)
}

// TailscaleListenerConstructor abstracts tsnet listener creation for unit testing.
type TailscaleListenerConstructor func(cfg TailscaleConfig) (net.Listener, error)

func NewTailscaleListener(cfg TailscaleConfig, constructor TailscaleListenerConstructor) (net.Listener, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if constructor == nil {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "tailscale listener constructor is required")
	}

	listener, err := constructor(cfg)
	if err != nil {
		return nil, sigilerr.Wrap(err, sigilerr.CodeServerStartFailure, "creating tailscale listener")
	}
	if listener == nil {
		return nil, sigilerr.New(sigilerr.CodeServerStartFailure,
			"tailscale listener constructor returned nil listener")
	}

	return listener, nil
}

func MTLSAuthDeferredError() error {
	return sigilerr.New(sigilerr.CodeServerNotImplemented,
		"node mTLS authentication is deferred in phase 6")
}
