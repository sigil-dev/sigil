// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/sigil-dev/sigil/internal/server"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logBuffer is a thread-safe bytes.Buffer for capturing log output.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// stubWorkspaceService is a configurable mock for WorkspaceService.
type stubWorkspaceService struct {
	getFunc func(ctx context.Context, id string) (*server.WorkspaceDetail, error)
}

func (s *stubWorkspaceService) List(_ context.Context) ([]server.WorkspaceSummary, error) {
	return nil, nil
}

func (s *stubWorkspaceService) Get(ctx context.Context, id string) (*server.WorkspaceDetail, error) {
	return s.getFunc(ctx, id)
}

func TestCheckWorkspaceMembership(t *testing.T) {
	tests := []struct {
		name        string
		user        *server.AuthenticatedUser // nil = auth disabled
		workspaceID string
		services    *server.Services // nil = services not registered
		wantErr     bool
		wantStatus  int // expected HTTP status code from huma error
		wantMsg     string
	}{
		{
			name:        "auth disabled (nil user) allows access",
			user:        nil,
			workspaceID: "any-workspace",
			services:    nil,
			wantErr:     false,
		},
		{
			name:        "auth enabled with empty workspace_id returns 422",
			user:        mustNewAuthenticatedUser("user-1", "Sean", nil),
			workspaceID: "",
			services:    nil,
			wantErr:     true,
			wantStatus:  422,
			wantMsg:     "workspace_id is required",
		},
		{
			name:        "nil services returns 503",
			user:        mustNewAuthenticatedUser("user-1", "Sean", nil),
			workspaceID: "ws-1",
			services:    nil,
			wantErr:     true,
			wantStatus:  503,
			wantMsg:     "workspace service not available",
		},
		{
			name:        "nil Workspaces field returns 503",
			user:        mustNewAuthenticatedUser("user-1", "Sean", nil),
			workspaceID: "ws-1",
			services:    &server.Services{Workspaces: nil},
			wantErr:     true,
			wantStatus:  503,
			wantMsg:     "workspace service not available",
		},
		{
			name:        "workspace not found returns 403 to prevent enumeration",
			user:        mustNewAuthenticatedUser("user-1", "Sean", nil),
			workspaceID: "nonexistent",
			services: &server.Services{
				Workspaces: &stubWorkspaceService{
					getFunc: func(_ context.Context, id string) (*server.WorkspaceDetail, error) {
						return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "workspace %q not found", id)
					},
				},
			},
			wantErr:    true,
			wantStatus: 403,
			wantMsg:    "access denied",
		},
		{
			name:        "workspace Get returns internal error returns 500",
			user:        mustNewAuthenticatedUser("user-1", "Sean", nil),
			workspaceID: "ws-broken",
			services: &server.Services{
				Workspaces: &stubWorkspaceService{
					getFunc: func(_ context.Context, _ string) (*server.WorkspaceDetail, error) {
						return nil, fmt.Errorf("database connection lost")
					},
				},
			},
			wantErr:    true,
			wantStatus: 500,
			wantMsg:    "internal server error",
		},
		{
			name:        "user is not a member returns 403",
			user:        mustNewAuthenticatedUser("user-99", "Outsider", nil),
			workspaceID: "ws-1",
			services: &server.Services{
				Workspaces: &stubWorkspaceService{
					getFunc: func(_ context.Context, _ string) (*server.WorkspaceDetail, error) {
						return &server.WorkspaceDetail{
							ID:      "ws-1",
							Members: []string{"user-1", "user-2"},
						}, nil
					},
				},
			},
			wantErr:    true,
			wantStatus: 403,
			wantMsg:    "access denied",
		},
		{
			name:        "user is a member returns nil",
			user:        mustNewAuthenticatedUser("user-1", "Sean", nil),
			workspaceID: "ws-1",
			services: &server.Services{
				Workspaces: &stubWorkspaceService{
					getFunc: func(_ context.Context, _ string) (*server.WorkspaceDetail, error) {
						return &server.WorkspaceDetail{
							ID:      "ws-1",
							Members: []string{"user-1", "user-2"},
						}, nil
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
			require.NoError(t, err)

			if tt.services != nil {
				srv.RegisterServices(tt.services)
			}

			ctx := context.Background()
			if tt.user != nil {
				ctx = server.ContextWithUser(ctx, tt.user)
			}

			err = srv.CheckWorkspaceMembership(ctx, tt.workspaceID)

			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)

			se, ok := err.(huma.StatusError)
			require.True(t, ok, "error should implement huma.StatusError, got: %T", err)
			assert.Equal(t, tt.wantStatus, se.GetStatus())
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

// TestCheckWorkspaceMembership_ErrorObservability tests R18#33: workspace membership error observability.
// When workspace membership check fails with an internal error (not NotFound),
// the error should be logged via slog so operators can diagnose issues.
func TestCheckWorkspaceMembership_ErrorObservability(t *testing.T) {
	// Capture slog output for verification.
	var logBuf logBuffer
	oldLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	srv, err := server.New(server.Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)

	srv.RegisterServices(&server.Services{
		Workspaces: &stubWorkspaceService{
			getFunc: func(_ context.Context, _ string) (*server.WorkspaceDetail, error) {
				return nil, fmt.Errorf("database connection lost")
			},
		},
	})

	user := mustNewAuthenticatedUser("user-1", "Sean", nil)
	ctx := server.ContextWithUser(context.Background(), user)

	err = srv.CheckWorkspaceMembership(ctx, "ws-broken")
	require.Error(t, err)

	// Verify HTTP 500 status.
	se, ok := err.(huma.StatusError)
	require.True(t, ok)
	assert.Equal(t, 500, se.GetStatus())

	// Verify error was logged via slog.
	logs := logBuf.String()
	assert.Contains(t, logs, "internal error", "error log should contain context")
	assert.Contains(t, logs, "ws-broken", "error log should reference the workspace ID")
	assert.Contains(t, logs, "database connection lost", "error log should contain the underlying error message")
}
