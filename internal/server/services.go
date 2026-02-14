// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// IsNotFound reports whether err carries the server.entity.not_found code.
// Service implementations should return sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, ...)
// so handlers can distinguish "not found" from internal failures.
func IsNotFound(err error) bool {
	return sigilerr.HasCode(err, sigilerr.CodeServerEntityNotFound)
}

// Services holds dependencies injected into route handlers.
// Each field is an interface so subsystems can be mocked in tests.
type Services struct {
	Workspaces WorkspaceService
	Plugins    PluginService
	Sessions   SessionService
	Users      UserService
}

// WorkspaceService provides workspace operations for REST handlers.
type WorkspaceService interface {
	List(ctx context.Context) ([]WorkspaceSummary, error)
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
	Name    string `json:"name" doc:"Plugin name"`
	Type    string `json:"type" doc:"Plugin type (provider, channel, tool, skill)"`
	Version string `json:"version" doc:"Plugin version"`
	Status  string `json:"status" doc:"Plugin status (running, stopped, error)"`
}

// PluginDetail is the full REST representation of a plugin.
type PluginDetail struct {
	Name         string   `json:"name" doc:"Plugin name"`
	Type         string   `json:"type" doc:"Plugin type"`
	Version      string   `json:"version" doc:"Plugin version"`
	Status       string   `json:"status" doc:"Plugin status"`
	Tier         string   `json:"tier" doc:"Execution tier (wasm, process, container)"`
	Capabilities []string `json:"capabilities" doc:"Granted capabilities"`
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
