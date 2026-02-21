// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node_test

import (
	"errors"
	"net"
	"testing"

	"github.com/sigil-dev/sigil/internal/node"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTailscaleConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		cfg      node.TailscaleConfig
		wantCode sigilerr.Code
	}{
		{
			name: "valid config",
			cfg: node.TailscaleConfig{
				Hostname:    "my-agent",
				AuthKey:     "tskey-auth-kzzzz",
				RequiredTag: "tag:agent-node",
			},
		},
		{
			name: "missing hostname",
			cfg: node.TailscaleConfig{
				AuthKey:     "tskey-auth-kzzzz",
				RequiredTag: "tag:agent-node",
			},
			wantCode: sigilerr.CodeServerConfigInvalid,
		},
		{
			name: "missing auth key",
			cfg: node.TailscaleConfig{
				Hostname:    "my-agent",
				RequiredTag: "tag:agent-node",
			},
			wantCode: sigilerr.CodeServerConfigInvalid,
		},
		{
			name: "missing required tag",
			cfg: node.TailscaleConfig{
				Hostname: "my-agent",
				AuthKey:  "tskey-auth-kzzzz",
			},
			wantCode: sigilerr.CodeServerConfigInvalid,
		},
		{
			name: "required tag missing prefix",
			cfg: node.TailscaleConfig{
				Hostname:    "my-agent",
				AuthKey:     "tskey-auth-kzzzz",
				RequiredTag: "agent-node",
			},
			wantCode: sigilerr.CodeServerConfigInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantCode == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode), "expected code %s, got %s", tt.wantCode, sigilerr.CodeOf(err))
		})
	}
}

func TestTailscaleAuthCheckTag(t *testing.T) {
	auth, err := node.NewTailscaleAuth(node.TailscaleConfig{
		Hostname:    "my-agent",
		AuthKey:     "tskey-auth-kzzzz",
		RequiredTag: "tag:agent-node",
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		tags     []string
		wantErr  bool
		wantCode sigilerr.Code
	}{
		{
			name:    "required tag present",
			tags:    []string{"tag:agent-node", "tag:other"},
			wantErr: false,
		},
		{
			name:     "required tag missing",
			tags:     []string{"tag:other"},
			wantErr:  true,
			wantCode: sigilerr.CodeServerAuthUnauthorized,
		},
		{
			name:     "empty tag list",
			tags:     nil,
			wantErr:  true,
			wantCode: sigilerr.CodeServerAuthUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.CheckTag(tt.tags)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, sigilerr.HasCode(err, tt.wantCode))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTokenAuthCheckToken(t *testing.T) {
	auth, err := node.NewTokenAuth("node-secret-token")
	require.NoError(t, err)

	err = auth.CheckToken("node-secret-token")
	require.NoError(t, err)

	err = auth.CheckToken("wrong-token")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerAuthUnauthorized))
}

func TestNewTokenAuthRequiresToken(t *testing.T) {
	auth, err := node.NewTokenAuth("   ")
	require.Error(t, err)
	assert.Nil(t, auth)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid))
}

func TestNewTailscaleListener(t *testing.T) {
	validCfg := node.TailscaleConfig{
		Hostname:    "my-agent",
		AuthKey:     "tskey-auth-kzzzz",
		RequiredTag: "tag:agent-node",
	}

	t.Run("invalid config", func(t *testing.T) {
		called := false
		listener, err := node.NewTailscaleListener(node.TailscaleConfig{}, func(node.TailscaleConfig) (net.Listener, error) {
			called = true
			return nil, nil
		})
		require.Error(t, err)
		assert.Nil(t, listener)
		assert.False(t, called)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid))
	})

	t.Run("missing constructor", func(t *testing.T) {
		listener, err := node.NewTailscaleListener(validCfg, nil)
		require.Error(t, err)
		assert.Nil(t, listener)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid))
	})

	t.Run("constructor failure", func(t *testing.T) {
		listener, err := node.NewTailscaleListener(validCfg, func(node.TailscaleConfig) (net.Listener, error) {
			return nil, errors.New("tsnet failed")
		})
		require.Error(t, err)
		assert.Nil(t, listener)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerStartFailure))
	})

	t.Run("constructor returns nil listener", func(t *testing.T) {
		listener, err := node.NewTailscaleListener(validCfg, func(node.TailscaleConfig) (net.Listener, error) {
			return nil, nil
		})
		require.Error(t, err)
		assert.Nil(t, listener)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerStartFailure))
	})

	t.Run("success", func(t *testing.T) {
		fake := &stubListener{}
		listener, err := node.NewTailscaleListener(validCfg, func(node.TailscaleConfig) (net.Listener, error) {
			return fake, nil
		})
		require.NoError(t, err)
		assert.Equal(t, fake, listener)
	})
}

type stubListener struct{}

func (s *stubListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (s *stubListener) Close() error              { return nil }
func (s *stubListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18789} }

func TestMTLSAuthDeferred(t *testing.T) {
	err := node.MTLSAuthDeferredError()
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerNotImplemented))
	assert.Contains(t, err.Error(), "deferred")
}

func TestTokenAuthRejectsEmptyCandidate(t *testing.T) {
	auth, err := node.NewTokenAuth("node-secret-token")
	require.NoError(t, err)

	err = auth.CheckToken("")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerAuthUnauthorized))
}

func TestTokenAuthTrimsWhitespaceCandidates(t *testing.T) {
	auth, err := node.NewTokenAuth("secret-token")
	require.NoError(t, err)

	// Leading/trailing whitespace should still match
	assert.NoError(t, auth.CheckToken("  secret-token  "))
	assert.NoError(t, auth.CheckToken("secret-token\n"))
	assert.NoError(t, auth.CheckToken("\tsecret-token"))
}

func TestTailscaleAuthAuthenticate(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		wantCode sigilerr.Code
	}{
		{
			name: "valid tags pass",
			tags: []string{"tag:agent-node", "tag:other"},
		},
		{
			name:     "missing required tag fails",
			tags:     []string{"tag:other"},
			wantCode: sigilerr.CodeServerAuthUnauthorized,
		},
		{
			name:     "empty tags fails",
			tags:     nil,
			wantCode: sigilerr.CodeServerAuthUnauthorized,
		},
	}

	auth, err := node.NewTailscaleAuth(node.TailscaleConfig{
		Hostname:    "my-agent",
		AuthKey:     "tskey-auth-kzzzz",
		RequiredTag: "tag:agent-node",
	})
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.Authenticate(node.Registration{
				NodeID:        "phone",
				TailscaleTags: tt.tags,
			})
			if tt.wantCode == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode))
		})
	}
}

func TestTokenAuthAuthenticate(t *testing.T) {
	auth, err := node.NewTokenAuth("node-secret-token")
	require.NoError(t, err)

	t.Run("correct token passes", func(t *testing.T) {
		err := auth.Authenticate(node.Registration{
			NodeID:    "phone",
			AuthToken: "node-secret-token",
		})
		require.NoError(t, err)
	})

	t.Run("wrong token fails", func(t *testing.T) {
		err := auth.Authenticate(node.Registration{
			NodeID:    "phone",
			AuthToken: "wrong-token",
		})
		require.Error(t, err)
		assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerAuthUnauthorized))
	})
}

func TestTailscaleAuthCheckTagNilReceiver(t *testing.T) {
	var auth *node.TailscaleAuth
	err := auth.CheckTag([]string{"tag:agent-node"})
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid))
}

func TestTokenAuthCheckTokenNilReceiver(t *testing.T) {
	var auth *node.TokenAuth
	err := auth.CheckToken("any-token")
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid))
}

func TestNewTailscaleAuthRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		cfg      node.TailscaleConfig
		wantCode sigilerr.Code
	}{
		{
			name: "missing tag prefix creates error",
			cfg: node.TailscaleConfig{
				Hostname:    "my-agent",
				AuthKey:     "tskey-auth-kzzzz",
				RequiredTag: "agent-node", // missing "tag:" prefix
			},
			wantCode: sigilerr.CodeServerConfigInvalid,
		},
		{
			name: "empty required tag creates error",
			cfg: node.TailscaleConfig{
				Hostname: "my-agent",
				AuthKey:  "tskey-auth-kzzzz",
			},
			wantCode: sigilerr.CodeServerConfigInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := node.NewTailscaleAuth(tt.cfg)
			require.Error(t, err)
			assert.Nil(t, auth)
			assert.True(t, sigilerr.HasCode(err, tt.wantCode))
		})
	}
}
