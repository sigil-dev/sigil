// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/server"
	"github.com/sigil-dev/sigil/internal/store"
	_ "github.com/sigil-dev/sigil/internal/store/sqlite" // register sqlite backend
	"github.com/sigil-dev/sigil/internal/workspace"
)

// Gateway holds all wired subsystems and manages their lifecycle.
type Gateway struct {
	Server           *server.Server
	GatewayStore     store.GatewayStore
	PluginManager    *plugin.Manager
	ProviderRegistry *provider.Registry
	WorkspaceManager *workspace.Manager
	Enforcer         *security.Enforcer
}

// WireGateway creates all subsystems and wires them together.
// The dataDir is the root directory for all persistent state.
func WireGateway(cfg *config.Config, dataDir string) (*Gateway, error) {
	storeCfg := &store.StorageConfig{Backend: cfg.Storage.Backend}

	// Ensure the data directory exists.
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}

	// 1. Gateway store (users, pairings, audit log).
	gs, err := store.NewGatewayStore(storeCfg, dataDir)
	if err != nil {
		return nil, fmt.Errorf("creating gateway store: %w", err)
	}

	// 2. Security enforcer.
	enforcer := security.NewEnforcer(gs.AuditLog())

	// 3. Plugin manager.
	pluginMgr := plugin.NewManager(filepath.Join(dataDir, "plugins"), enforcer)

	// 4. Provider registry.
	provReg := provider.NewRegistry()

	// 5. Workspace manager.
	wsMgr := workspace.NewManager(filepath.Join(dataDir, "workspaces"), storeCfg)

	// Configure workspaces from config.
	if cfg.Workspaces != nil {
		wsCfg := make(workspace.Config)
		for id, wc := range cfg.Workspaces {
			wsCfg[id] = workspace.WorkspaceConfig{
				Members:  wc.Members,
				Bindings: convertBindings(wc.Bindings),
			}
		}
		if err := wsMgr.SetConfig(wsCfg); err != nil {
			_ = gs.Close()
			return nil, fmt.Errorf("setting workspace config: %w", err)
		}
	}

	// 6. HTTP server.
	srv, err := server.New(server.Config{
		ListenAddr:  cfg.Networking.Listen,
		CORSOrigins: nil, // use defaults
	})
	if err != nil {
		_ = gs.Close()
		return nil, fmt.Errorf("creating server: %w", err)
	}

	// Wire service adapters for REST endpoints.
	srv.RegisterServices(&server.Services{
		Workspaces: &workspaceServiceAdapter{cfg: cfg},
		Plugins:    &pluginServiceAdapter{mgr: pluginMgr},
		Sessions:   &sessionServiceAdapter{wsMgr: wsMgr},
		Users:      &userServiceAdapter{store: gs.Users()},
	})

	return &Gateway{
		Server:           srv,
		GatewayStore:     gs,
		PluginManager:    pluginMgr,
		ProviderRegistry: provReg,
		WorkspaceManager: wsMgr,
		Enforcer:         enforcer,
	}, nil
}

// Start runs the HTTP server and blocks until the context is cancelled.
func (gw *Gateway) Start(ctx context.Context) error {
	return gw.Server.Start(ctx)
}

// Close releases all resources held by the gateway.
func (gw *Gateway) Close() error {
	var firstErr error
	if gw.WorkspaceManager != nil {
		if err := gw.WorkspaceManager.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if gw.GatewayStore != nil {
		if err := gw.GatewayStore.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func convertBindings(bindings []config.BindingConfig) []workspace.Binding {
	out := make([]workspace.Binding, len(bindings))
	for i, b := range bindings {
		out[i] = workspace.Binding{
			Channel:   b.Channel,
			ChannelID: b.ChannelID,
		}
	}
	return out
}

// --- Service adapters ---

// workspaceServiceAdapter bridges config workspaces to the server's WorkspaceService.
type workspaceServiceAdapter struct {
	cfg *config.Config
}

func (a *workspaceServiceAdapter) List(_ context.Context) ([]server.WorkspaceSummary, error) {
	if a.cfg.Workspaces == nil {
		return nil, nil
	}
	out := make([]server.WorkspaceSummary, 0, len(a.cfg.Workspaces))
	for id, ws := range a.cfg.Workspaces {
		out = append(out, server.WorkspaceSummary{
			ID:          id,
			Description: ws.Description,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (a *workspaceServiceAdapter) Get(_ context.Context, id string) (*server.WorkspaceDetail, error) {
	if a.cfg.Workspaces == nil {
		return nil, fmt.Errorf("workspace %q not found", id)
	}
	ws, ok := a.cfg.Workspaces[id]
	if !ok {
		return nil, fmt.Errorf("workspace %q not found", id)
	}
	return &server.WorkspaceDetail{
		ID:          id,
		Description: ws.Description,
		Members:     ws.Members,
	}, nil
}

// pluginServiceAdapter bridges plugin.Manager to the server's PluginService.
type pluginServiceAdapter struct {
	mgr *plugin.Manager
}

func (a *pluginServiceAdapter) List(_ context.Context) ([]server.PluginSummary, error) {
	instances := a.mgr.List()
	out := make([]server.PluginSummary, len(instances))
	for i, inst := range instances {
		out[i] = server.PluginSummary{
			Name:   inst.Name(),
			Status: inst.State().String(),
		}
	}
	return out, nil
}

func (a *pluginServiceAdapter) Get(_ context.Context, name string) (*server.PluginDetail, error) {
	inst, err := a.mgr.Get(name)
	if err != nil {
		return nil, err
	}
	return &server.PluginDetail{
		Name:   inst.Name(),
		Status: inst.State().String(),
	}, nil
}

func (a *pluginServiceAdapter) Reload(_ context.Context, _ string) error {
	return fmt.Errorf("plugin reload not yet implemented")
}

// sessionServiceAdapter bridges workspace sessions to the server's SessionService.
type sessionServiceAdapter struct {
	wsMgr *workspace.Manager
}

func (a *sessionServiceAdapter) List(_ context.Context, _ string) ([]server.SessionSummary, error) {
	return nil, nil // Sessions require an open workspace; deferred to agent loop integration.
}

func (a *sessionServiceAdapter) Get(_ context.Context, _, _ string) (*server.SessionDetail, error) {
	return nil, fmt.Errorf("session lookup requires workspace context")
}

// userServiceAdapter bridges GatewayStore users to the server's UserService.
type userServiceAdapter struct {
	store store.UserStore
}

func (a *userServiceAdapter) List(ctx context.Context) ([]server.UserSummary, error) {
	users, err := a.store.List(ctx, store.ListOpts{Limit: 100})
	if err != nil {
		return nil, err
	}
	out := make([]server.UserSummary, len(users))
	for i, u := range users {
		out[i] = server.UserSummary{
			ID:   u.ID,
			Name: u.Name,
		}
	}
	return out, nil
}
