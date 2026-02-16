// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/sigil-dev/sigil/internal/plugin"
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
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	pluginpkg "github.com/sigil-dev/sigil/pkg/plugin"
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

	// 4. Provider registry — register built-in providers and wire routing.
	provReg := provider.NewRegistry()

	registerBuiltinProviders(cfg, provReg)

	// Wire default model and failover chain from config so the agent loop
	// can route requests without "no default provider configured" errors.
	if cfg.Models.Default != "" {
		if err := provReg.SetDefault(cfg.Models.Default); err != nil {
			_ = gs.Close()
			return nil, sigilerr.Wrapf(err, sigilerr.CodeCLISetupFailure, "setting default provider: %s", cfg.Models.Default)
		}
	}
	if len(cfg.Models.Failover) > 0 {
		if err := provReg.SetFailover(cfg.Models.Failover); err != nil {
			_ = gs.Close()
			return nil, sigilerr.Wrapf(err, sigilerr.CodeCLISetupFailure, "setting failover chain")
		}
	}

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
	var tokenValidator server.TokenValidator
	if len(cfg.Auth.Tokens) > 0 {
		var tvErr error
		tokenValidator, tvErr = newConfigTokenValidator(cfg.Auth.Tokens)
		if tvErr != nil {
			_ = gs.Close()
			return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "configuring auth tokens: %w", tvErr)
		}
	} else {
		slog.Warn("authentication disabled: no API tokens configured — all endpoints are unauthenticated")
	}

	// Wire service adapters for REST endpoints.
	services, err := server.NewServices(
		&workspaceServiceAdapter{cfg: cfg},
		&pluginServiceAdapter{mgr: pluginMgr},
		&sessionServiceAdapter{wsMgr: wsMgr},
		&userServiceAdapter{store: gs.Users()},
	)
	if err != nil {
		_ = gs.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "creating services: %w", err)
	}

	srv, err := server.New(server.Config{
		ListenAddr:     cfg.Networking.Listen,
		CORSOrigins:    cfg.Networking.CORSOrigins,
		TokenValidator: tokenValidator,
		BehindProxy:    cfg.Networking.Mode == "tailscale", // Only trust proxy headers when behind tailscale
		TrustedProxies: cfg.Networking.TrustedProxies,
		EnableHSTS:     cfg.Networking.EnableHSTS,
		RateLimit: server.RateLimitConfig{
			RequestsPerSecond: cfg.Networking.RateLimitRPS,
			Burst:             cfg.Networking.RateLimitBurst,
		},
		// Stub stream handler so chat endpoints return a helpful message instead of 503.
		// Will be replaced by real agent loop.
		StreamHandler: &stubStreamHandler{},
		Services:      services,
	})
	if err != nil {
		_ = gs.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "creating server: %w", err)
	}

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
	type closer interface{ Close() error }
	closers := []closer{gw.Server, gw.ProviderRegistry, gw.WorkspaceManager, gw.GatewayStore}

	var errs []error
	for _, c := range closers {
		if c != nil {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
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

func (a *workspaceServiceAdapter) ListForUser(_ context.Context, userID string) ([]server.WorkspaceSummary, error) {
	if a.cfg.Workspaces == nil {
		return []server.WorkspaceSummary{}, nil
	}
	out := make([]server.WorkspaceSummary, 0, len(a.cfg.Workspaces))
	for id, ws := range a.cfg.Workspaces {
		for _, member := range ws.Members {
			if member == userID {
				out = append(out, server.WorkspaceSummary{
					ID:          id,
					Description: ws.Description,
				})
				break
			}
		}
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
			Type:    pluginpkg.PluginType(inst.Type()),
			Version: inst.Version(),
			Status:  server.PluginStatus(inst.State().String()),
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
		Type:         pluginpkg.PluginType(inst.Type()),
		Version:      inst.Version(),
		Status:       server.PluginStatus(inst.State().String()),
		Tier:         pluginpkg.ExecutionTier(inst.Tier()),
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

// configTokenValidator validates bearer tokens against pre-computed SHA256
// hashes of static config entries. Hashing at init time avoids per-request
// rehashing and keeps raw tokens out of long-lived memory.
type configTokenValidator struct {
	tokens map[[32]byte]*server.AuthenticatedUser
}

func newConfigTokenValidator(tokens []config.TokenConfig) (*configTokenValidator, error) {
	m := make(map[[32]byte]*server.AuthenticatedUser, len(tokens))
	for _, tc := range tokens {
		user, err := server.NewAuthenticatedUser(tc.UserID, tc.Name, tc.Permissions)
		if err != nil {
			slog.Warn("skipping token with invalid user config", "error", err, "user_id", tc.UserID)
			continue
		}
		hash := sha256.Sum256([]byte(tc.Token))
		m[hash] = user
	}
	if len(tokens) > 0 && len(m) == 0 {
		return nil, sigilerr.New(sigilerr.CodeCLISetupFailure,
			"all configured auth tokens failed validation — gateway would be unusable")
	}
	return &configTokenValidator{tokens: m}, nil
}

func (v *configTokenValidator) ValidateToken(_ context.Context, token string) (*server.AuthenticatedUser, error) {
	candidateHash := sha256.Sum256([]byte(token))
	// Iterate through ALL tokens to prevent timing attacks that leak token count/position.
	// Even after finding a match, we continue iterating to ensure constant-time behavior
	// regardless of which token matches or where it appears in the iteration order.
	var matched *server.AuthenticatedUser

	for hash, user := range v.tokens {
		// subtle.ConstantTimeCompare ensures the hash comparison takes the same time
		// whether hashes match or not, preventing timing attacks on the hash value itself.
		if subtle.ConstantTimeCompare(hash[:], candidateHash[:]) == 1 {
			matched = user
			// CRITICAL: Do NOT return here. Continue iterating through remaining tokens
			// to prevent timing attacks that could reveal token position/count by measuring
			// how many iterations were performed.
		}
	}

	if matched != nil {
		return matched, nil
	}
	slog.Debug("token validation failed: no configured token matched")
	return nil, sigilerr.New(sigilerr.CodeServerAuthUnauthorized, "invalid token")
}
