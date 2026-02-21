// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
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
	pairings   PairingService
	nodes      NodeService
	status     GatewayStatusService
	agent      AgentControlService
}

// NewServices creates a Services instance with validation.
// Returns an error if any required service is nil.
func NewServices(ws WorkspaceService, plugins PluginService, sessions SessionService, users UserService) (*Services, error) {
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
	return &Services{
		workspaces: ws,
		plugins:    plugins,
		sessions:   sessions,
		users:      users,
	}, nil
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

// Pairings returns the pairing-code service, if configured.
func (s *Services) Pairings() PairingService {
	return s.pairings
}

// Nodes returns the node service, if configured.
func (s *Services) Nodes() NodeService {
	return s.nodes
}

// GatewayStatus returns the gateway status subscription service, if configured.
func (s *Services) GatewayStatus() GatewayStatusService {
	return s.status
}

// AgentControl returns the agent pause/resume control service, if configured.
func (s *Services) AgentControl() AgentControlService {
	return s.agent
}

// WithNodeService sets the optional node service and returns s.
func (s *Services) WithNodeService(nodes NodeService) *Services {
	s.nodes = nodes
	return s
}

// WithGatewayStatusService sets the optional gateway status service and returns s.
func (s *Services) WithGatewayStatusService(status GatewayStatusService) *Services {
	s.status = status
	return s
}

// WithAgentControlService sets the optional agent control service and returns s.
func (s *Services) WithAgentControlService(agent AgentControlService) *Services {
	s.agent = agent
	return s
}

// WithPairingService sets the optional pairing-code service and returns s.
func (s *Services) WithPairingService(pairings PairingService) *Services {
	s.pairings = pairings
	return s
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

// PairingService provides pairing-code generation and redemption operations.
type PairingService interface {
	CreateCode(ctx context.Context, req CreatePairingCodeRequest) (*PairingCode, error)
	RedeemCode(ctx context.Context, req RedeemPairingCodeRequest) (*PairingRedemption, error)
}

// NodeService provides node CRUD operations for REST handlers.
type NodeService interface {
	List(ctx context.Context) ([]NodeSummary, error)
	Get(ctx context.Context, id string) (*NodeDetail, error)
	Approve(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

// GatewayStatusService provides status streaming updates for tray/status clients.
type GatewayStatusService interface {
	Subscribe(ctx context.Context) (<-chan GatewayStatus, error)
}

// AgentControlService provides pause/resume operations for the agent loop.
type AgentControlService interface {
	Pause(ctx context.Context) (AgentState, error)
	Resume(ctx context.Context) (AgentState, error)
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

// CreatePairingCodeRequest requests creation of a one-time pairing code.
type CreatePairingCodeRequest struct {
	WorkspaceID string
	ChannelType string
	ChannelID   string
	TTLSeconds  int
}

// PairingCode is the generated one-time pairing code payload.
type PairingCode struct {
	Code        string    `json:"code" doc:"One-time pairing code"`
	WorkspaceID string    `json:"workspace_id" doc:"Workspace identifier"`
	ChannelType string    `json:"channel_type" doc:"Channel type"`
	ChannelID   string    `json:"channel_id" doc:"Channel identifier"`
	ExpiresAt   time.Time `json:"expires_at" doc:"Code expiry timestamp"`
}

// RedeemPairingCodeRequest requests redemption of a one-time pairing code.
type RedeemPairingCodeRequest struct {
	Code        string
	UserID      string
	WorkspaceID string
	ChannelType string
	ChannelID   string
}

// PairingRedemption is the result of successful code redemption.
type PairingRedemption struct {
	PairingID string `json:"pairing_id" doc:"Created or existing pairing ID"`
	Status    string `json:"status" doc:"Pairing status"`
}

// NodeSummary is the REST representation of a node in list results.
type NodeSummary struct {
	ID       string `json:"id" doc:"Node identifier"`
	Online   bool   `json:"online" doc:"Whether the node is currently connected"`
	Approved bool   `json:"approved" doc:"Whether the node has been approved for use"`
}

// NodeDetail is the full REST representation of a node.
type NodeDetail struct {
	ID       string   `json:"id" doc:"Node identifier"`
	Online   bool     `json:"online" doc:"Whether the node is currently connected"`
	Approved bool     `json:"approved" doc:"Whether the node has been approved for use"`
	Tools    []string `json:"tools" doc:"Registered tool names exposed by the node"`
}

// AgentState is the paused/running state of the agent loop.
type AgentState string

const (
	AgentStateRunning AgentState = "running"
	AgentStatePaused  AgentState = "paused"
)

// GatewayStatus is the tray-friendly status payload streamed over SSE.
type GatewayStatus struct {
	Status         string     `json:"status" doc:"Gateway status summary"`
	AgentState     AgentState `json:"agent_state" doc:"Current agent state"`
	ConnectedNodes int        `json:"connected_nodes" doc:"Number of connected nodes"`
	ActiveChannels int        `json:"active_channels" doc:"Number of active channels"`
}

// NewServicesForTest creates a Services instance for testing.
// It delegates to NewServices to enforce the same validation invariants as production code.
// This is exported for use in server_test package where unexported fields are inaccessible.
// Panics if any required service is nil (same validation as NewServices).
func NewServicesForTest(ws WorkspaceService, plugins PluginService, sessions SessionService, users UserService) *Services {
	svc, err := NewServices(ws, plugins, sessions, users)
	if err != nil {
		panic(err) // Test setup should provide all required services
	}
	return svc
}
