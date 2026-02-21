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

type stubNodeService struct{}

func (s *stubNodeService) List(context.Context) ([]NodeSummary, error) { return nil, nil }

func (s *stubNodeService) Get(context.Context, string) (*NodeDetail, error) { return nil, nil }

func (s *stubNodeService) Approve(context.Context, string) error { return nil }

func (s *stubNodeService) Delete(context.Context, string) error { return nil }

type stubGatewayStatusService struct{}

func (s *stubGatewayStatusService) Subscribe(context.Context) (<-chan GatewayStatus, error) {
	ch := make(chan GatewayStatus)
	close(ch)
	return ch, nil
}

type stubAgentControlService struct{}

func (s *stubAgentControlService) Pause(context.Context) (AgentState, error) {
	return AgentStatePaused, nil
}

func (s *stubAgentControlService) Resume(context.Context) (AgentState, error) {
	return AgentStateRunning, nil
}

func TestNewServices(t *testing.T) {
	ws := &stubWorkspaceService{}
	ps := &stubPluginService{}
	ss := &stubSessionService{}
	us := &stubUserService{}

	tests := []struct {
		name       string
		ws         WorkspaceService
		plugins    PluginService
		sessions   SessionService
		users      UserService
		wantErr    bool
		errContain string
	}{
		{
			name:     "all valid",
			ws:       ws,
			plugins:  ps,
			sessions: ss,
			users:    us,
			wantErr:  false,
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
			svc, err := NewServices(tt.ws, tt.plugins, tt.sessions, tt.users)

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
			}
		})
	}
}

func TestServices_WithOptionalNodeAndStatusServices(t *testing.T) {
	ws := &stubWorkspaceService{}
	ps := &stubPluginService{}
	ss := &stubSessionService{}
	us := &stubUserService{}
	ns := &stubNodeService{}
	gss := &stubGatewayStatusService{}
	acs := &stubAgentControlService{}

	svc, err := NewServices(ws, ps, ss, us)
	require.NoError(t, err)

	got := svc.WithNodeService(ns).WithGatewayStatusService(gss).WithAgentControlService(acs)
	assert.Same(t, svc, got)
	assert.Equal(t, ns, svc.Nodes())
	assert.Equal(t, gss, svc.GatewayStatus())
	assert.Equal(t, acs, svc.AgentControl())
}
