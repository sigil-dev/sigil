# Phase 4: Platform Integration

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire together workspaces, channels, and providers — the three systems that make Sigil actually useful. After this phase, a message can flow from a channel plugin through workspace routing to the agent loop to an LLM provider and back.

**Architecture:** Workspace manager owns routing (message → identity → workspace → session). Channel system manages streaming connections to platform plugins. Provider system abstracts LLM access with failover and budgets. Built-in providers compile into the binary for zero-config common cases.

**Tech Stack:** Go interfaces, gRPC streaming, anthropic-sdk-go, openai-go, Google genai SDK, testify

**Design Docs:**

- [Section 5: Workspace System](../design/05-workspace-system.md) — routing, scoping, membership
- [Section 4: Channel System](../design/04-channel-system.md) — channel plugins, pairing, identity
- [Section 7: Provider System](../design/07-provider-system.md) — provider interface, routing, failover, budgets

**Depends on:** Phase 1 (stores), Phase 2 (enforcer, plugin host), Phase 3 (agent loop, sessions)

---

## Task 1: Workspace Manager

**Files:**

- Create: `internal/workspace/manager.go`
- Create: `internal/workspace/manager_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package workspace_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/workspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_OpenWorkspace(t *testing.T) {
	mgr := newTestManager(t)

	ws, err := mgr.Open(context.Background(), "homelab")
	require.NoError(t, err)
	assert.Equal(t, "homelab", ws.ID)
	assert.NotNil(t, ws.SessionStore)
	assert.NotNil(t, ws.MemoryStore)
}

func TestManager_RouteMessage(t *testing.T) {
	mgr := newTestManager(t)

	// Configure workspace bindings
	mgr.SetConfig(workspace.Config{
		Workspaces: map[string]workspace.WorkspaceConfig{
			"homelab": {
				Members:  []string{"sean"},
				Tools:    workspace.ToolConfig{Allow: []string{"exec.sandboxed", "k8s.*"}},
				Bindings: []workspace.Binding{{Channel: "telegram", ChannelID: "-100123"}},
			},
			"family": {
				Members:  []string{"sean", "wife"},
				Tools:    workspace.ToolConfig{Allow: []string{"calendar.*"}},
				Bindings: []workspace.Binding{{Channel: "telegram", ChannelID: "-100789"}},
			},
		},
	})

	ctx := context.Background()

	// Route to homelab by channel binding
	ws, err := mgr.Route(ctx, workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "-100123",
		UserID:      "sean",
	})
	require.NoError(t, err)
	assert.Equal(t, "homelab", ws.ID)

	// Route to family
	ws, err = mgr.Route(ctx, workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "-100789",
		UserID:      "sean",
	})
	require.NoError(t, err)
	assert.Equal(t, "family", ws.ID)

	// Unbound channel routes to "personal"
	ws, err = mgr.Route(ctx, workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "-999999",
		UserID:      "sean",
	})
	require.NoError(t, err)
	assert.Equal(t, "personal", ws.ID)
}

func TestManager_MembershipCheck(t *testing.T) {
	mgr := newTestManager(t)
	mgr.SetConfig(workspace.Config{
		Workspaces: map[string]workspace.WorkspaceConfig{
			"homelab": {Members: []string{"sean"}},
		},
	})

	ctx := context.Background()

	// Non-member should be denied
	_, err := mgr.Route(ctx, workspace.RouteRequest{
		ChannelType: "telegram",
		ChannelID:   "-100123",
		UserID:      "stranger",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a member")
}

func TestManager_ToolAllowlist(t *testing.T) {
	mgr := newTestManager(t)
	mgr.SetConfig(workspace.Config{
		Workspaces: map[string]workspace.WorkspaceConfig{
			"family": {
				Members: []string{"sean"},
				Tools: workspace.ToolConfig{
					Allow: []string{"calendar.*", "shopping.*"},
					Deny:  []string{"exec.*", "filesystem.*"},
				},
			},
		},
	})

	ws, err := mgr.Open(context.Background(), "family")
	require.NoError(t, err)

	assert.True(t, ws.ToolAllowed("calendar.create"))
	assert.True(t, ws.ToolAllowed("shopping.add"))
	assert.False(t, ws.ToolAllowed("exec.run"))
	assert.False(t, ws.ToolAllowed("filesystem.write"))
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/workspace/manager.go`:

- `Manager` struct with data dir, storage config, workspace configs, store factory
- `Open(ctx, workspaceID string) (*Workspace, error)` — creates workspace stores via factory, caches open workspaces
- `Route(ctx, RouteRequest) (*Workspace, error)` — matches channel binding → workspace, checks membership, falls back to "personal"
- `Workspace` struct: ID, config, stores (SessionStore, MemoryStore, VectorStore), tool allow/deny sets
- `ToolAllowed(capability string) bool` — checks against workspace allow/deny lists using security.MatchCapability

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/workspace/
git commit -m "feat(workspace): add workspace manager with routing and tool allowlists"
```

---

## Task 2: Identity Resolution

**Files:**

- Create: `internal/identity/resolver.go`
- Create: `internal/identity/resolver_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package identity_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_ResolvePlatformUser(t *testing.T) {
	userStore := newMockUserStore()
	pairingStore := newMockPairingStore()

	resolver := identity.NewResolver(userStore, pairingStore)

	// Create a user with multiple identities
	setupTestUser(userStore, "usr-1", "Alice", []store.UserIdentity{
		{Channel: "telegram", PlatformID: "alice"},
		{Channel: "whatsapp", PlatformID: "+15551234567"},
	})

	ctx := context.Background()

	// Resolve from Telegram
	user, err := resolver.Resolve(ctx, "telegram", "alice")
	require.NoError(t, err)
	assert.Equal(t, "usr-1", user.ID)
	assert.Equal(t, "Alice", user.Name)

	// Same user from WhatsApp
	user, err = resolver.Resolve(ctx, "whatsapp", "+15551234567")
	require.NoError(t, err)
	assert.Equal(t, "usr-1", user.ID)
}

func TestResolver_UnknownUser(t *testing.T) {
	resolver := identity.NewResolver(newMockUserStore(), newMockPairingStore())

	ctx := context.Background()
	_, err := resolver.Resolve(ctx, "telegram", "unknown_user")
	assert.Error(t, err)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/identity/resolver.go`:

- `Resolver` struct with UserStore and PairingStore
- `Resolve(ctx, channelType, platformUserID string) (*store.User, error)` — looks up user by external ID

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): add identity resolver for multi-platform user lookup"
```

---

## Task 3: Channel System

**Files:**

- Create: `internal/plugin/channel.go`
- Create: `internal/plugin/channel_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChannelRouter_RegisterAndRoute(t *testing.T) {
	router := plugin.NewChannelRouter()

	// Register a mock channel
	mockChannel := &mockChannelPlugin{name: "telegram"}
	router.Register("telegram", mockChannel)

	ch, err := router.Get("telegram")
	require.NoError(t, err)
	assert.Equal(t, "telegram", ch.Name())
}

func TestChannelRouter_SendMessage(t *testing.T) {
	router := plugin.NewChannelRouter()
	mock := &mockChannelPlugin{name: "telegram"}
	router.Register("telegram", mock)

	ctx := context.Background()
	err := router.Send(ctx, plugin.OutboundMessage{
		ChannelType: "telegram",
		ChannelID:   "-100123",
		Content:     "Hello from agent",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, mock.sendCount)
	assert.Equal(t, "Hello from agent", mock.lastSent.Content)
}

func TestChannelRouter_UnregisteredChannel(t *testing.T) {
	router := plugin.NewChannelRouter()

	_, err := router.Get("nonexistent")
	assert.Error(t, err)
}

func TestPairingModes(t *testing.T) {
	tests := []struct {
		name     string
		mode     plugin.PairingMode
		userID   string
		allowed  []string
		expected bool
	}{
		{"open allows anyone", plugin.PairingOpen, "stranger", nil, true},
		{"closed denies everyone", plugin.PairingClosed, "anyone", nil, false},
		{"allowlist allows listed", plugin.PairingAllowlist, "alice", []string{"alice", "bob"}, true},
		{"allowlist denies unlisted", plugin.PairingAllowlist, "stranger", []string{"alice", "bob"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.CheckPairing(tt.mode, tt.userID, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/channel.go`:

- `ChannelRouter` struct: map of channel type → channel plugin interface
- `Register(channelType string, ch ChannelPlugin)`
- `Get(channelType string) (ChannelPlugin, error)`
- `Send(ctx, OutboundMessage) error` — routes to correct channel plugin
- `PairingMode` enum: `open`, `closed`, `allowlist`, `pair_on_request`, `pair_with_code`
- `CheckPairing(mode, userID string, allowlist []string) bool`
- `OutboundMessage` struct: ChannelType, ChannelID, Content, ThreadID, Media

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/channel.go internal/plugin/channel_test.go
git commit -m "feat(plugin): add channel router and pairing modes"
```

---

## Task 4: Provider Registry and Routing

**Files:**

- Create: `internal/provider/registry.go`
- Create: `internal/provider/registry_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := provider.NewRegistry()

	mock := &mockProvider{name: "anthropic", available: true}
	reg.Register("anthropic", mock)

	p, err := reg.Get("anthropic")
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
}

func TestRegistry_RouteDefault(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockProvider{name: "anthropic", available: true})
	reg.Register("openai", &mockProvider{name: "openai", available: true})

	reg.SetDefault("anthropic/claude-sonnet-4-5")

	p, model, err := reg.Route(context.Background(), provider.RouteRequest{})
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
	assert.Equal(t, "claude-sonnet-4-5", model)
}

func TestRegistry_RouteWorkspaceOverride(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockProvider{name: "anthropic", available: true})
	reg.Register("openai", &mockProvider{name: "openai", available: true})

	reg.SetDefault("anthropic/claude-sonnet-4-5")
	reg.SetOverride("homelab", "openai/gpt-4.1")

	p, model, err := reg.Route(context.Background(), provider.RouteRequest{WorkspaceID: "homelab"})
	require.NoError(t, err)
	assert.Equal(t, "openai", p.Name())
	assert.Equal(t, "gpt-4.1", model)
}

func TestRegistry_Failover(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockProvider{name: "anthropic", available: false}) // down
	reg.Register("openai", &mockProvider{name: "openai", available: true})

	reg.SetDefault("anthropic/claude-sonnet-4-5")
	reg.SetFailover([]string{"anthropic/claude-sonnet-4-5", "openai/gpt-4.1"})

	p, model, err := reg.Route(context.Background(), provider.RouteRequest{})
	require.NoError(t, err)
	assert.Equal(t, "openai", p.Name())
	assert.Equal(t, "gpt-4.1", model)
}

func TestRegistry_AllProvidersDown(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockProvider{name: "anthropic", available: false})
	reg.Register("openai", &mockProvider{name: "openai", available: false})

	reg.SetDefault("anthropic/claude-sonnet-4-5")
	reg.SetFailover([]string{"anthropic/claude-sonnet-4-5", "openai/gpt-4.1"})

	_, _, err := reg.Route(context.Background(), provider.RouteRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all providers")
}

func TestRegistry_BudgetEnforcement(t *testing.T) {
	reg := provider.NewRegistry()
	reg.Register("anthropic", &mockProvider{name: "anthropic", available: true})
	reg.SetDefault("anthropic/claude-sonnet-4-5")

	budget := &provider.Budget{
		MaxSessionTokens: 100,
		UsedSessionTokens: 100, // already at limit
	}

	_, _, err := reg.Route(context.Background(), provider.RouteRequest{Budget: budget})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "budget")
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/provider/registry.go`:

- `Registry` struct: providers map, default model, workspace overrides, failover chain
- `Register(name string, p Provider)`
- `Route(ctx, RouteRequest) (Provider, model string, error)`:
  1. Check workspace override → use if set
  2. Use default model
  3. Check budget → deny if exceeded
  4. Try provider → if available, return
  5. Walk failover chain → return first available
  6. All exhausted → error
- `Budget` struct: MaxSessionTokens, MaxPerHourUSD, MaxPerDayUSD, used counters

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/provider/registry.go internal/provider/registry_test.go
git commit -m "feat(provider): add provider registry with routing, failover, and budgets"
```

---

## Task 5: Provider Interface

**Files:**

- Create: `internal/provider/provider.go`
- Create: `internal/provider/provider_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/stretchr/testify/assert"
)

func TestProviderInterfaceExists(t *testing.T) {
	var _ provider.Provider = nil
}

func TestChatRequestFields(t *testing.T) {
	req := provider.ChatRequest{
		Model: "claude-sonnet-4-5",
		Messages: []provider.Message{
			{Role: "user", Content: "Hello"},
		},
		SystemPrompt: "You are a helpful assistant",
		MaxTokens:    1024,
		Stream:       true,
	}
	assert.Equal(t, "claude-sonnet-4-5", req.Model)
	assert.True(t, req.Stream)
}

func TestChatEventTypes(t *testing.T) {
	// TextDelta event
	event := provider.ChatEvent{Type: provider.EventTextDelta, Text: "Hello"}
	assert.Equal(t, provider.EventTextDelta, event.Type)

	// ToolCall event
	event = provider.ChatEvent{Type: provider.EventToolCall, ToolCall: &provider.ToolCall{Name: "exec"}}
	assert.Equal(t, "exec", event.ToolCall.Name)

	// Done event
	event = provider.ChatEvent{Type: provider.EventDone}
	assert.Equal(t, provider.EventDone, event.Type)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/provider/provider.go`:

- `Provider` interface:
  - `Name() string`
  - `Available(ctx) bool`
  - `ListModels(ctx) ([]ModelInfo, error)`
  - `Chat(ctx, ChatRequest) (<-chan ChatEvent, error)` — returns channel for streaming
- `ChatRequest`, `ChatEvent`, `Message`, `ToolCall`, `ModelInfo` structs
- Event type enum: `EventTextDelta`, `EventToolCall`, `EventUsage`, `EventDone`, `EventError`

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/provider/provider.go internal/provider/provider_test.go
git commit -m "feat(provider): add provider interface with streaming chat events"
```

---

## Task 6: Built-in Anthropic Provider

**Files:**

- Create: `internal/provider/anthropic/anthropic.go`
- Create: `internal/provider/anthropic/anthropic_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package anthropic_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/provider/anthropic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicProvider_ImplementsInterface(t *testing.T) {
	var _ provider.Provider = (*anthropic.Provider)(nil)
}

func TestAnthropicProvider_Name(t *testing.T) {
	p, err := anthropic.New(anthropic.Config{APIKey: "test-key"})
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
}

func TestAnthropicProvider_ListModels(t *testing.T) {
	p, err := anthropic.New(anthropic.Config{APIKey: "test-key"})
	require.NoError(t, err)

	models, err := p.ListModels(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, models)

	// Should include known Anthropic models
	var names []string
	for _, m := range models {
		names = append(names, m.ID)
	}
	assert.Contains(t, names, "claude-opus-4-6")
	assert.Contains(t, names, "claude-sonnet-4-5")
}

func TestAnthropicProvider_MissingAPIKey(t *testing.T) {
	_, err := anthropic.New(anthropic.Config{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

// Integration test — requires real API key
func TestAnthropicProvider_Chat_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	// This test requires ANTHROPIC_API_KEY env var
	// Run with: task test -- -run TestAnthropicProvider_Chat_Integration
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set")
	}

	p, err := anthropic.New(anthropic.Config{APIKey: apiKey})
	require.NoError(t, err)

	ctx := context.Background()
	events, err := p.Chat(ctx, provider.ChatRequest{
		Model: "claude-haiku-4-5",
		Messages: []provider.Message{
			{Role: "user", Content: "Say hello in exactly 3 words"},
		},
		MaxTokens: 20,
		Stream:    true,
	})
	require.NoError(t, err)

	var text string
	for event := range events {
		if event.Type == provider.EventTextDelta {
			text += event.Text
		}
	}
	assert.NotEmpty(t, text)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/provider/anthropic/anthropic.go`:

- `Provider` struct with anthropic-sdk-go client
- `New(Config) (*Provider, error)` — validates API key, creates client
- `Name() string` → "anthropic"
- `Available(ctx) bool` — ping API
- `ListModels(ctx)` — returns known Anthropic models (hardcoded list with capabilities)
- `Chat(ctx, ChatRequest) (<-chan ChatEvent, error)` — streams via anthropic-sdk-go, converts events to `provider.ChatEvent`

**Step 4: Run test — expect PASS (unit tests; integration test needs API key)**

**Step 5: Commit**

```bash
git add internal/provider/anthropic/
git commit -m "feat(provider): add built-in Anthropic provider"
```

---

## Task 7: Built-in OpenAI and Google Providers

**Files:**

- Create: `internal/provider/openai/openai.go`
- Create: `internal/provider/openai/openai_test.go`
- Create: `internal/provider/google/google.go`
- Create: `internal/provider/google/google_test.go`

Follow the same pattern as the Anthropic provider:

1. Write unit tests (interface satisfaction, Name(), ListModels(), missing API key)
2. Write integration test (skip unless API key set)
3. Implement using respective SDK (openai-go, Google genai SDK)
4. Verify unit tests pass
5. Commit each separately

**OpenAI commit:**

```bash
git add internal/provider/openai/
git commit -m "feat(provider): add built-in OpenAI provider"
```

**Google commit:**

```bash
git add internal/provider/google/
git commit -m "feat(provider): add built-in Google provider"
```

---

## Gate 4 Checklist

After completing all 7 tasks, verify:

- [ ] `task test` — all tests pass (including Phase 1–3 tests)
- [ ] `task lint` — zero lint errors
- [ ] Workspace manager routes messages to correct workspace by channel binding
- [ ] Unbound channels route to "personal" workspace
- [ ] Membership checks deny non-members
- [ ] Tool allowlists are enforced per workspace
- [ ] Identity resolver maps platform users to canonical IDs across channels
- [ ] Channel router registers and routes to channel plugins
- [ ] Pairing modes work (open, closed, allowlist)
- [ ] Provider registry routes to correct provider with workspace overrides
- [ ] Failover chain works when primary provider is down
- [ ] Budget enforcement denies requests exceeding limits
- [ ] Anthropic provider sends/receives streaming chat (integration test with API key)
- [ ] OpenAI and Google providers implement the provider interface

Only proceed to Phase 5 after all checks pass.
