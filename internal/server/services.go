// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/health"
	"github.com/sigil-dev/sigil/pkg/plugin"
)

// IsNotFound reports whether err carries the server.entity.not_found code.
// Service implementations should return sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, ...)
// so handlers can distinguish "not found" from internal failures.
func IsNotFound(err error) bool {
	return sigilerr.HasCode(err, sigilerr.CodeServerEntityNotFound)
}

// PluginStatus represents the runtime status of a plugin instance.
// Values correspond to plugin lifecycle states.
type PluginStatus string

const (
	PluginStatusDiscovered PluginStatus = "discovered"
	PluginStatusValidating PluginStatus = "validating"
	PluginStatusLoading    PluginStatus = "loading"
	PluginStatusRunning    PluginStatus = "running"
	PluginStatusDraining   PluginStatus = "draining"
	PluginStatusStopping   PluginStatus = "stopping"
	PluginStatusStopped    PluginStatus = "stopped"
	PluginStatusError      PluginStatus = "error"
)

// Services holds dependencies injected into route handlers.
// Each field is an interface so subsystems can be mocked in tests.
// Use NewServices constructor to ensure all required services are provided.
type Services struct {
	workspaces WorkspaceService
	plugins    PluginService
	sessions   SessionService
	users      UserService
	providers  ProviderService // optional; nil = provider health endpoints unavailable
}

// NewServices creates a Services instance with validation.
// Returns an error if any required service is nil.
// The optional providers variadic parameter sets the provider health service.
func NewServices(ws WorkspaceService, plugins PluginService, sessions SessionService, users UserService, providers ...ProviderService) (*Services, error) {
	if ws == nil {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "workspace service is required")
	}
	if plugins == nil {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "plugin service is required")
	}
	if sessions == nil {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "session service is required")
	}
	if users == nil {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "user service is required")
	}
	if len(providers) > 1 {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "at most one provider service may be supplied")
	}
	s := &Services{
		workspaces: ws,
		plugins:    plugins,
		sessions:   sessions,
		users:      users,
	}
	if len(providers) > 0 && providers[0] != nil {
		s.providers = providers[0]
	}
	return s, nil
}

// Workspaces returns the workspace service.
func (s *Services) Workspaces() WorkspaceService {
	return s.workspaces
}

// Plugins returns the plugin service.
func (s *Services) Plugins() PluginService {
	return s.plugins
}

// Sessions returns the session service.
func (s *Services) Sessions() SessionService {
	return s.sessions
}

// Users returns the user service.
func (s *Services) Users() UserService {
	return s.users
}

// Providers returns the optional provider health service.
// Returns nil when provider health endpoints are not configured.
func (s *Services) Providers() ProviderService {
	return s.providers
}

// WorkspaceService provides workspace operations for REST handlers.
type WorkspaceService interface {
	List(ctx context.Context) ([]WorkspaceSummary, error)
	// ListForUser returns only workspaces the given user is a member of.
	// Avoids the N+1 Get calls that List+filter would require.
	ListForUser(ctx context.Context, userID string) ([]WorkspaceSummary, error)
	Get(ctx context.Context, id string) (*WorkspaceDetail, error)
}

// PluginService provides plugin operations for REST handlers.
type PluginService interface {
	List(ctx context.Context) ([]PluginSummary, error)
	Get(ctx context.Context, name string) (*PluginDetail, error)
	Reload(ctx context.Context, name string) error
}

// SessionService provides session operations for REST handlers.
type SessionService interface {
	List(ctx context.Context, workspaceID string) ([]SessionSummary, error)
	Get(ctx context.Context, workspaceID, sessionID string) (*SessionDetail, error)
}

// UserService provides user operations for REST handlers.
type UserService interface {
	List(ctx context.Context) ([]UserSummary, error)
}

// ProviderService provides provider health operations for REST handlers.
// This is optional — when nil, provider health endpoints are not registered.
type ProviderService interface {
	GetHealth(ctx context.Context, name string) (*ProviderHealthDetail, error)
}

// WorkspaceSummary is the REST representation of a workspace in list results.
type WorkspaceSummary struct {
	ID          string `json:"id" doc:"Workspace identifier"`
	Description string `json:"description" doc:"Workspace description"`
}

// WorkspaceDetail is the full REST representation of a workspace.
type WorkspaceDetail struct {
	ID          string   `json:"id" doc:"Workspace identifier"`
	Description string   `json:"description" doc:"Workspace description"`
	Members     []string `json:"members" doc:"Member user IDs"`
	Model       string   `json:"model,omitempty" doc:"Default model override"`
}

// PluginSummary is the REST representation of a plugin in list results.
type PluginSummary struct {
	Name    string               `json:"name" doc:"Plugin name"`
	Type    plugin.PluginType    `json:"type" doc:"Plugin type (provider, channel, tool, skill)"`
	Version string               `json:"version" doc:"Plugin version"`
	Status  PluginStatus         `json:"status" doc:"Plugin status (running, stopped, error)"`
	Tier    plugin.ExecutionTier `json:"tier" doc:"Execution tier (wasm, process, container)"`
}

// PluginDetail is the full REST representation of a plugin.
type PluginDetail struct {
	Name         string               `json:"name" doc:"Plugin name"`
	Type         plugin.PluginType    `json:"type" doc:"Plugin type"`
	Version      string               `json:"version" doc:"Plugin version"`
	Status       PluginStatus         `json:"status" doc:"Plugin status"`
	Tier         plugin.ExecutionTier `json:"tier" doc:"Execution tier (wasm, process, container)"`
	Capabilities []string             `json:"capabilities" doc:"Granted capabilities"`
}

// SessionSummary is the REST representation of a session in list results.
type SessionSummary struct {
	ID          string `json:"id" doc:"Session identifier"`
	WorkspaceID string `json:"workspace_id" doc:"Workspace identifier"`
	Status      string `json:"status" doc:"Session status (active, archived)"`
}

// SessionDetail is the full REST representation of a session.
type SessionDetail struct {
	ID           string `json:"id" doc:"Session identifier"`
	WorkspaceID  string `json:"workspace_id" doc:"Workspace identifier"`
	Status       string `json:"status" doc:"Session status"`
	MessageCount int    `json:"message_count" doc:"Number of messages"`
}

// UserSummary is the REST representation of a user.
type UserSummary struct {
	ID   string `json:"id" doc:"User identifier"`
	Name string `json:"name" doc:"Display name"`
}

// ProviderHealthDetail is the REST representation of a provider's health metrics.
type ProviderHealthDetail struct {
	Provider         string `json:"provider" doc:"Provider name"`
	Message          string `json:"message" doc:"Human-readable status message"`
	MetricsAvailable bool   `json:"metricsAvailable" doc:"Whether the provider reported health metrics"`
	health.Metrics
}

// NewServicesForTest creates a Services instance for testing.
// It delegates to NewServices to enforce the same validation invariants as production code.
// This is exported for use in server_test package where unexported fields are inaccessible.
// Panics if any required service is nil (same validation as NewServices).
func NewServicesForTest(ws WorkspaceService, plugins PluginService, sessions SessionService, users UserService, providers ...ProviderService) *Services {
	svc, err := NewServices(ws, plugins, sessions, users, providers...)
	if err != nil {
		panic(err) // Test setup should provide all required services
	}
	return svc
}
