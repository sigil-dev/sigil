// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Minimal stub implementations for the service interfaces.

type stubWorkspaceService struct{}

func (s *stubWorkspaceService) List(context.Context) ([]WorkspaceSummary, error) { return nil, nil }
func (s *stubWorkspaceService) ListForUser(context.Context, string) ([]WorkspaceSummary, error) {
	return nil, nil
}

func (s *stubWorkspaceService) Get(context.Context, string) (*WorkspaceDetail, error) {
	return nil, nil
}

type stubPluginService struct{}

func (s *stubPluginService) List(context.Context) ([]PluginSummary, error)      { return nil, nil }
func (s *stubPluginService) Get(context.Context, string) (*PluginDetail, error) { return nil, nil }
func (s *stubPluginService) Reload(context.Context, string) error               { return nil }

type stubSessionService struct{}

func (s *stubSessionService) List(context.Context, string) ([]SessionSummary, error) {
	return nil, nil
}

func (s *stubSessionService) Get(context.Context, string, string) (*SessionDetail, error) {
	return nil, nil
}

type stubUserService struct{}

func (s *stubUserService) List(context.Context) ([]UserSummary, error) { return nil, nil }

type stubProviderService struct{}

func (s *stubProviderService) GetHealth(context.Context, string) (*ProviderHealthDetail, error) {
	return &ProviderHealthDetail{Provider: "stub", Message: "ok"}, nil
}

func TestNewServices(t *testing.T) {
	ws := &stubWorkspaceService{}
	ps := &stubPluginService{}
	ss := &stubSessionService{}
	us := &stubUserService{}
	prov := &stubProviderService{}

	tests := []struct {
		name          string
		ws            WorkspaceService
		plugins       PluginService
		sessions      SessionService
		users         UserService
		providers     []ProviderService
		wantErr       bool
		errContain    string
		wantProviders ProviderService
	}{
		{
			name:          "all valid no providers",
			ws:            ws,
			plugins:       ps,
			sessions:      ss,
			users:         us,
			wantErr:       false,
			wantProviders: nil,
		},
		{
			name:          "all valid with provider service",
			ws:            ws,
			plugins:       ps,
			sessions:      ss,
			users:         us,
			providers:     []ProviderService{prov},
			wantErr:       false,
			wantProviders: prov,
		},
		{
			name:          "all valid with nil provider service",
			ws:            ws,
			plugins:       ps,
			sessions:      ss,
			users:         us,
			providers:     []ProviderService{nil},
			wantErr:       false,
			wantProviders: nil,
		},
		{
			name:       "nil workspace service",
			ws:         nil,
			plugins:    ps,
			sessions:   ss,
			users:      us,
			wantErr:    true,
			errContain: "workspace service is required",
		},
		{
			name:       "nil plugin service",
			ws:         ws,
			plugins:    nil,
			sessions:   ss,
			users:      us,
			wantErr:    true,
			errContain: "plugin service is required",
		},
		{
			name:       "nil session service",
			ws:         ws,
			plugins:    ps,
			sessions:   nil,
			users:      us,
			wantErr:    true,
			errContain: "session service is required",
		},
		{
			name:       "nil user service",
			ws:         ws,
			plugins:    ps,
			sessions:   ss,
			users:      nil,
			wantErr:    true,
			errContain: "user service is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewServices(tt.ws, tt.plugins, tt.sessions, tt.users, tt.providers...)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, svc)
				assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid),
					"expected error code %s, got: %v", sigilerr.CodeServerConfigInvalid, err)
				assert.Contains(t, err.Error(), tt.errContain)
			} else {
				require.NoError(t, err)
				require.NotNil(t, svc)
				assert.Equal(t, tt.ws, svc.Workspaces())
				assert.Equal(t, tt.plugins, svc.Plugins())
				assert.Equal(t, tt.sessions, svc.Sessions())
				assert.Equal(t, tt.users, svc.Users())
				assert.Equal(t, tt.wantProviders, svc.Providers())
			}
		})
	}
}

func TestNewServices_RejectsMultipleProviders(t *testing.T) {
	ws := &stubWorkspaceService{}
	ps := &stubPluginService{}
	ss := &stubSessionService{}
	us := &stubUserService{}
	prov1 := &stubProviderService{}
	prov2 := &stubProviderService{}

	svc, err := NewServices(ws, ps, ss, us, prov1, prov2)

	require.Error(t, err)
	assert.Nil(t, svc)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeServerConfigInvalid),
		"expected error code %s, got: %v", sigilerr.CodeServerConfigInvalid, err)
	assert.Contains(t, err.Error(), "at most one provider service may be supplied")
}
