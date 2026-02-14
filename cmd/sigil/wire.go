// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/plugin"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/internal/provider"
	anthropicprov "github.com/sigil-dev/sigil/internal/provider/anthropic"
	googleprov "github.com/sigil-dev/sigil/internal/provider/google"
	openaiprov "github.com/sigil-dev/sigil/internal/provider/openai"
	openrouterprov "github.com/sigil-dev/sigil/internal/provider/openrouter"
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
func WireGateway(ctx context.Context, cfg *config.Config, dataDir string) (*Gateway, error) {
	storeCfg := &store.StorageConfig{Backend: cfg.Storage.Backend}

	// Ensure the data directory exists.
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "creating data directory: %w", err)
	}

	// 1. Gateway store (users, pairings, audit log).
	gs, err := store.NewGatewayStore(storeCfg, dataDir)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "creating gateway store: %w", err)
	}

	// 2. Security enforcer.
	enforcer := security.NewEnforcer(gs.AuditLog())

	// 3. Plugin manager — discover plugins in the plugins directory.
	pluginMgr := plugin.NewManager(filepath.Join(dataDir, "plugins"), enforcer)

	manifests, err := pluginMgr.Discover(ctx)
	if err != nil {
		slog.Warn("plugin discovery error", "error", err)
	} else if len(manifests) > 0 {
		slog.Info("discovered plugins", "count", len(manifests))
	}

	// 4. Provider registry — register built-in providers from config.
	provReg := provider.NewRegistry()

	registerBuiltinProviders(cfg, provReg)

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
			return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "setting workspace config: %w", err)
		}
	}

	// 6. HTTP server.
	srv, err := server.New(server.Config{
		ListenAddr:  cfg.Networking.Listen,
		CORSOrigins: nil, // use defaults
	})
	if err != nil {
		_ = gs.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "creating server: %w", err)
	}

	// Wire service adapters for REST endpoints.
	srv.RegisterServices(&server.Services{
		Workspaces: &workspaceServiceAdapter{cfg: cfg},
		Plugins:    &pluginServiceAdapter{mgr: pluginMgr},
		Sessions:   &sessionServiceAdapter{wsMgr: wsMgr},
		Users:      &userServiceAdapter{store: gs.Users()},
	})

	// Register stub stream handler so chat endpoints return a helpful
	// message instead of 503. Will be replaced by real agent loop.
	srv.RegisterStreamHandler(&stubStreamHandler{})

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

// providerFactory builds a provider.Provider from a ProviderConfig.
type providerFactory func(config.ProviderConfig) (provider.Provider, error)

// builtinProviderFactories maps provider names to their constructors.
// Declared as a variable so tests can inject failing factories.
var builtinProviderFactories = map[string]providerFactory{
	"anthropic": func(pc config.ProviderConfig) (provider.Provider, error) {
		return anthropicprov.New(anthropicprov.Config{APIKey: pc.APIKey, BaseURL: pc.Endpoint})
	},
	"google": func(pc config.ProviderConfig) (provider.Provider, error) {
		return googleprov.New(googleprov.Config{APIKey: pc.APIKey})
	},
	"openai": func(pc config.ProviderConfig) (provider.Provider, error) {
		return openaiprov.New(openaiprov.Config{APIKey: pc.APIKey, BaseURL: pc.Endpoint})
	},
	"openrouter": func(pc config.ProviderConfig) (provider.Provider, error) {
		return openrouterprov.New(openrouterprov.Config{APIKey: pc.APIKey, BaseURL: pc.Endpoint})
	},
}

// registerBuiltinProviders iterates configured providers and registers
// matching built-in implementations. Unknown names or empty API keys are
// logged and skipped — neither is fatal at startup.
func registerBuiltinProviders(cfg *config.Config, reg *provider.Registry) {
	for name, pc := range cfg.Providers {
		if pc.APIKey == "" {
			slog.Warn("skipping provider with empty API key", "provider", name)
			continue
		}
		factory, ok := builtinProviderFactories[name]
		if !ok {
			slog.Warn("unknown provider in config, skipping", "provider", name)
			continue
		}
		p, err := factory(pc)
		if err != nil {
			slog.Warn("failed to create provider", "provider", name, "error", err)
			continue
		}
		reg.Register(name, p)
		slog.Info("registered provider", "provider", name)
	}
}

// --- Service adapters ---

// workspaceServiceAdapter bridges config workspaces to the server's WorkspaceService.
type workspaceServiceAdapter struct {
	cfg *config.Config
}

func (a *workspaceServiceAdapter) List(_ context.Context) ([]server.WorkspaceSummary, error) {
	if a.cfg.Workspaces == nil {
		return []server.WorkspaceSummary{}, nil
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
		return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "workspace %q not found", id)
	}
	ws, ok := a.cfg.Workspaces[id]
	if !ok {
		return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "workspace %q not found", id)
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
			Name:    inst.Name(),
			Type:    inst.Type(),
			Version: inst.Version(),
			Status:  inst.State().String(),
		}
	}
	return out, nil
}

func (a *pluginServiceAdapter) Get(_ context.Context, name string) (*server.PluginDetail, error) {
	inst, err := a.mgr.Get(name)
	if err != nil {
		if sigilerr.HasCode(err, sigilerr.CodePluginNotFound) {
			return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "plugin %q not found", name)
		}
		return nil, err
	}
	caps := inst.Capabilities()
	if caps == nil {
		caps = []string{}
	}
	return &server.PluginDetail{
		Name:         inst.Name(),
		Type:         inst.Type(),
		Version:      inst.Version(),
		Status:       inst.State().String(),
		Tier:         inst.Tier(),
		Capabilities: caps,
	}, nil
}

func (a *pluginServiceAdapter) Reload(_ context.Context, _ string) error {
	return sigilerr.New(sigilerr.CodeServerNotImplemented, "plugin reload not yet implemented")
}

// sessionServiceAdapter bridges workspace sessions to the server's SessionService.
type sessionServiceAdapter struct {
	wsMgr *workspace.Manager
}

func (a *sessionServiceAdapter) List(_ context.Context, _ string) ([]server.SessionSummary, error) {
	return []server.SessionSummary{}, nil // Sessions require an open workspace; deferred to agent loop integration.
}

func (a *sessionServiceAdapter) Get(_ context.Context, _, sessionID string) (*server.SessionDetail, error) {
	return nil, sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, "session %q not found", sessionID)
}

// userServiceAdapter bridges GatewayStore users to the server's UserService.
type userServiceAdapter struct {
	store store.UserStore
}

// stubStreamHandler returns a placeholder message until a real agent loop is wired.
type stubStreamHandler struct{}

func (h *stubStreamHandler) HandleStream(_ context.Context, _ server.ChatStreamRequest, events chan<- server.SSEEvent) {
	events <- server.SSEEvent{
		Event: "text_delta",
		Data:  `{"text":"Agent not yet configured. Please set up a provider and workspace."}`,
	}
	events <- server.SSEEvent{
		Event: "done",
		Data:  `{}`,
	}
	close(events)
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
