// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

// Package workspace manages workspace lifecycle, message routing, and
// per-workspace tool allow/deny lists.
package workspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Config maps workspace IDs to their configuration.
type Config map[string]WorkspaceConfig

// WorkspaceConfig defines the settings for a single workspace.
type WorkspaceConfig struct {
	Members  []string // User IDs allowed to access this workspace.
	Tools    ToolConfig
	Bindings []Binding
}

// ToolConfig specifies tool capability allow/deny patterns.
type ToolConfig struct {
	Allow []string // Capability patterns that are permitted.
	Deny  []string // Capability patterns that are blocked (evaluated first).
}

// Binding maps a channel type and ID to a workspace.
type Binding struct {
	Channel   string // Channel type (e.g. "slack", "telegram").
	ChannelID string // Channel-specific identifier.
}

// RouteRequest carries the information needed to route an incoming message
// to the correct workspace.
type RouteRequest struct {
	ChannelType string
	ChannelID   string
	UserID      string
}

// Workspace holds the stores and configuration for a single workspace.
type Workspace struct {
	ID           string
	Config       WorkspaceConfig
	SessionStore store.SessionStore
	MemoryStore  store.MemoryStore
	VectorStore  store.VectorStore

	allowSet security.CapabilitySet
	denySet  security.CapabilitySet
}

// ToolAllowed reports whether the given capability is permitted by this
// workspace's tool configuration. Uses fail-closed semantics: if no allow
// patterns are configured, all tools are denied. Deny patterns are
// evaluated first; then the allow set must explicitly permit the capability.
// Returns an error if any capability pattern is invalid.
func (w *Workspace) ToolAllowed(capability string) (bool, error) {
	denied, err := w.denySet.Contains(capability)
	if err != nil {
		return false, err
	}
	if denied {
		return false, nil
	}
	return w.allowSet.Contains(capability)
}

// Manager creates, caches, and routes to workspaces.
type Manager struct {
	dataDir    string
	storeCfg   *store.StorageConfig
	config     Config
	workspaces map[string]*Workspace
	mu         sync.RWMutex
}

// NewManager creates a Manager that stores workspace data under dataDir.
func NewManager(dataDir string, storeCfg *store.StorageConfig) *Manager {
	return &Manager{
		dataDir:    dataDir,
		storeCfg:   storeCfg,
		config:     Config{},
		workspaces: make(map[string]*Workspace),
	}
}

// SetConfig replaces the workspace configuration. Returns an error if any
// channel binding appears in more than one workspace (non-deterministic routing).
// Existing open workspaces are not affected until they are re-opened.
func (m *Manager) SetConfig(cfg Config) error {
	// Validate binding uniqueness.
	seen := make(map[string]string) // "channel:channelID" → workspaceID
	for wsID, wsCfg := range cfg {
		for _, b := range wsCfg.Bindings {
			key := b.Channel + ":" + b.ChannelID
			if existingWS, ok := seen[key]; ok {
				return sigilerr.Errorf(
					sigilerr.CodeWorkspaceConfigInvalid,
					"duplicate channel binding %s/%s: bound to both %s and %s",
					b.Channel, b.ChannelID, existingWS, wsID,
				)
			}
			seen[key] = wsID
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg

	// Refresh policy on cached workspaces so updated allow/deny sets take
	// effect immediately without requiring a close/reopen cycle.
	for id, ws := range m.workspaces {
		if wsCfg, ok := cfg[id]; ok {
			ws.Config = wsCfg
			ws.allowSet = security.NewCapabilitySet(wsCfg.Tools.Allow...)
			ws.denySet = security.NewCapabilitySet(wsCfg.Tools.Deny...)
		} else {
			// Workspace no longer in config — reset to empty (fail-closed).
			ws.Config = WorkspaceConfig{}
			ws.allowSet = security.NewCapabilitySet()
			ws.denySet = security.NewCapabilitySet()
		}
	}

	return nil
}

// Open returns (and caches) a Workspace for the given ID. The workspace
// directory and backing stores are created on first access.
func (m *Manager) Open(ctx context.Context, workspaceID string) (*Workspace, error) {
	m.mu.RLock()
	if ws, ok := m.workspaces[workspaceID]; ok {
		m.mu.RUnlock()
		return ws, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock.
	if ws, ok := m.workspaces[workspaceID]; ok {
		return ws, nil
	}

	wsDir := filepath.Join(m.dataDir, "workspaces", workspaceID)
	if err := os.MkdirAll(wsDir, 0o750); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeWorkspaceOpenFailure, "creating workspace directory %s: %w", wsDir, err)
	}

	ss, ms, vs, err := store.NewWorkspaceStores(m.storeCfg, wsDir)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeWorkspaceOpenFailure, "opening stores for workspace %s", workspaceID)
	}

	wsCfg := m.config[workspaceID]
	ws := &Workspace{
		ID:           workspaceID,
		Config:       wsCfg,
		SessionStore: ss,
		MemoryStore:  ms,
		VectorStore:  vs,
		allowSet:     security.NewCapabilitySet(wsCfg.Tools.Allow...),
		denySet:      security.NewCapabilitySet(wsCfg.Tools.Deny...),
	}

	m.workspaces[workspaceID] = ws
	return ws, nil
}

// Route finds the workspace for an incoming message based on channel bindings,
// checks membership, and returns the opened workspace. Unbound channels fall
// back to a user-scoped personal workspace ("personal:<userID>").
func (m *Manager) Route(ctx context.Context, req RouteRequest) (*Workspace, error) {
	m.mu.RLock()
	wsID := m.findBinding(req.ChannelType, req.ChannelID)
	m.mu.RUnlock()

	if wsID == "" {
		// User-scoped personal workspace — each user gets their own isolated
		// fallback workspace. Membership is implied (it's the user's own space).
		return m.Open(ctx, "personal:"+req.UserID)
	}

	// Check membership.
	m.mu.RLock()
	wsCfg, ok := m.config[wsID]
	m.mu.RUnlock()
	if ok && !isMember(wsCfg.Members, req.UserID) {
		return nil, sigilerr.New(
			sigilerr.CodeWorkspaceMembershipDenied,
			fmt.Sprintf("not a member of workspace %s", wsID),
			sigilerr.FieldWorkspaceID(wsID),
			sigilerr.FieldUserID(req.UserID),
		)
	}

	return m.Open(ctx, wsID)
}

// Close closes all open workspace stores.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for id, ws := range m.workspaces {
		if ws.SessionStore != nil {
			if closer, ok := ws.SessionStore.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, sigilerr.Errorf(sigilerr.CodeWorkspaceCloseFailure, "closing session store for %s: %w", id, err))
				}
			}
		}
		if ws.MemoryStore != nil {
			if err := ws.MemoryStore.Close(); err != nil {
				errs = append(errs, sigilerr.Errorf(sigilerr.CodeWorkspaceCloseFailure, "closing memory store for %s: %w", id, err))
			}
		}
		if ws.VectorStore != nil {
			if err := ws.VectorStore.Close(); err != nil {
				errs = append(errs, sigilerr.Errorf(sigilerr.CodeWorkspaceCloseFailure, "closing vector store for %s: %w", id, err))
			}
		}
		delete(m.workspaces, id)
	}

	if len(errs) > 0 {
		return sigilerr.Errorf(sigilerr.CodeWorkspaceCloseFailure, "closing workspaces: %w", sigilerr.Join(errs...))
	}
	return nil
}

// findBinding returns the workspace ID whose binding matches the given channel,
// or empty string if none match. Caller must hold at least m.mu.RLock.
func (m *Manager) findBinding(channelType, channelID string) string {
	for wsID, wsCfg := range m.config {
		for _, b := range wsCfg.Bindings {
			if b.Channel == channelType && b.ChannelID == channelID {
				return wsID
			}
		}
	}
	return ""
}

// isMember checks whether userID is in the members slice.
func isMember(members []string, userID string) bool {
	for _, m := range members {
		if m == userID {
			return true
		}
	}
	return false
}
