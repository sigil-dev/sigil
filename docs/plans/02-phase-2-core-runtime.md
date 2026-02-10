# Phase 2: Core Runtime

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the security enforcer, plugin host, and execution tiers that form the trusted runtime layer.

**Architecture:** The enforcer is the gateway's security kernel — every plugin operation passes through it. The plugin host manages lifecycle (discover → validate → load → register → drain → stop). Two execution tiers: process (go-plugin + OS sandbox) and Wasm (Wazero). Container tier is deferred to Phase 6.

**Tech Stack:** hashicorp/go-plugin, tetratelabs/wazero, testify, gopkg.in/yaml.v3

**Design Docs:**

- [Section 2: Plugin System](../design/02-plugin-system.md) — manifests, tiers, lifecycle, gRPC contracts
- [Section 3: Security Model](../design/03-security-model.md) — capability enforcement, ABAC, isolation

**Depends on:** Phase 1 (proto definitions, plugin SDK types)

---

## Task 1: Capability Model and Glob Matching

**Files:**

- Create: `internal/security/capability.go`
- Create: `internal/security/capability_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/security"
	"github.com/stretchr/testify/assert"
)

func TestMatchCapability(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		cap     string
		want    bool
	}{
		{"exact match", "sessions.read", "sessions.read", true},
		{"no match", "sessions.read", "sessions.write", false},
		{"wildcard all", "*", "anything.here", true},
		{"wildcard suffix", "sessions.*", "sessions.read", true},
		{"wildcard suffix no match", "sessions.*", "messages.send", false},
		{"wildcard middle", "messages.send.*", "messages.send.telegram", true},
		{"path scoped", "filesystem.read./data/*", "filesystem.read./data/plugins/foo", true},
		{"path scoped no match", "filesystem.read./data/*", "filesystem.read./etc/shadow", false},
		{"self scope", "config.read.self", "config.read.self", true},
		{"self scope no match", "config.read.self", "config.read.other", false},
		{"double wildcard", "exec.*", "exec.run.sandboxed", true},
		{"empty pattern", "", "sessions.read", false},
		{"empty capability", "sessions.read", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := security.MatchCapability(tt.pattern, tt.cap)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCapabilitySet_Contains(t *testing.T) {
	set := security.NewCapabilitySet("sessions.read", "sessions.write", "messages.send.*")

	assert.True(t, set.Contains("sessions.read"))
	assert.True(t, set.Contains("messages.send.telegram"))
	assert.False(t, set.Contains("exec.run"))
	assert.False(t, set.Contains("config.write.global"))
}

func TestCapabilitySet_Intersect(t *testing.T) {
	a := security.NewCapabilitySet("sessions.*", "messages.send.*", "exec.run")
	b := security.NewCapabilitySet("sessions.read", "messages.*")

	// Intersection: capabilities allowed by both
	result := a.AllowedBy(b, "sessions.read")
	assert.True(t, result) // sessions.* allows it, sessions.read allows it

	result = a.AllowedBy(b, "exec.run")
	assert.False(t, result) // a allows, b does not
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/security/capability.go`:

- `MatchCapability(pattern, cap string) bool` — glob matching on dot-separated segments. `*` matches one or more segments.
- `CapabilitySet` type wrapping `[]string` with methods:
  - `Contains(cap string) bool` — any pattern in the set matches
  - `AllowedBy(other CapabilitySet, cap string) bool` — both sets must contain the capability

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/security/
git commit -m "feat(security): add capability model with glob matching"
```

---

## Task 2: Security Enforcer

**Files:**

- Create: `internal/security/enforcer.go`
- Create: `internal/security/enforcer_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/security"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuditStore captures audit entries for testing.
type mockAuditStore struct {
	entries []*store.AuditEntry
}

func (m *mockAuditStore) Append(_ context.Context, entry *store.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditStore) Query(_ context.Context, _ store.AuditFilter) ([]*store.AuditEntry, error) {
	return m.entries, nil
}

func TestEnforcer_AllowMatchingCapability(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	// Register a plugin with capabilities
	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read", "messages.send.*",
	), security.NewCapabilitySet( // deny
		"exec.*",
	))

	ctx := context.Background()

	// Should allow: plugin has sessions.read, workspace allows *, user allows *
	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:            "telegram",
		Capability:        "sessions.read",
		WorkspaceID:       "ws-1",
		WorkspaceAllow:    security.NewCapabilitySet("*"),
		UserPermissions:   security.NewCapabilitySet("*"),
	})
	assert.NoError(t, err)
}

func TestEnforcer_DenyMissingCapability(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("telegram", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	ctx := context.Background()

	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "telegram",
		Capability:      "exec.run",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestEnforcer_DenyExplicitlyDenied(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("malicious", security.NewCapabilitySet(
		"exec.*", // plugin claims exec
	), security.NewCapabilitySet(
		"exec.*", // but manifest denies exec
	))

	ctx := context.Background()

	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "malicious",
		Capability:      "exec.run",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("exec.*"),
		UserPermissions: security.NewCapabilitySet("exec.*"),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestEnforcer_DenyByWorkspaceScope(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("exec-tool", security.NewCapabilitySet(
		"exec.run.sandboxed",
	), security.NewCapabilitySet())

	ctx := context.Background()

	// Workspace only allows calendar tools (user allows all)
	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "exec-tool",
		Capability:      "exec.run.sandboxed",
		WorkspaceID:     "family",
		WorkspaceAllow:  security.NewCapabilitySet("calendar.*", "shopping.*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	assert.Error(t, err)
}

func TestEnforcer_DenyByUserPermissions(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("exec-tool", security.NewCapabilitySet(
		"exec.run.sandboxed",
	), security.NewCapabilitySet())

	ctx := context.Background()

	// Plugin allows, workspace allows, but user (member role) does not
	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "exec-tool",
		Capability:      "exec.run.sandboxed",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("sessions.*", "messages.*"),
	})
	assert.Error(t, err)
}

func TestEnforcer_AllowThreeWayIntersection(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("test-plugin", security.NewCapabilitySet(
		"sessions.read", "sessions.write", "exec.run",
	), security.NewCapabilitySet())

	ctx := context.Background()

	// User with restricted permissions — only sessions.read passes all three checks
	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("sessions.*", "messages.*"),
		UserPermissions: security.NewCapabilitySet("sessions.read", "messages.send.*"),
	})
	assert.NoError(t, err)

	// exec.run fails: user doesn't have it
	err = enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "exec.run",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("sessions.read"),
	})
	assert.Error(t, err)

	// sessions.write fails: user doesn't have it
	err = enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "sessions.write",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("sessions.read"),
	})
	assert.Error(t, err)
}

func TestEnforcer_UserWithNoPermissions(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("test-plugin", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	ctx := context.Background()

	// User with empty permission set — nothing passes
	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet(),
	})
	assert.Error(t, err)
}

func TestEnforcer_AuditLogging(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	enforcer.RegisterPlugin("test-plugin", security.NewCapabilitySet(
		"sessions.read",
	), security.NewCapabilitySet())

	ctx := context.Background()

	_ = enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "test-plugin",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})

	require.Len(t, audit.entries, 1)
	assert.Equal(t, "capability_check", audit.entries[0].Action)
	assert.Equal(t, "test-plugin", audit.entries[0].Plugin)
	assert.Equal(t, "allowed", audit.entries[0].Result)
}

func TestEnforcer_UnregisteredPlugin(t *testing.T) {
	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)

	ctx := context.Background()

	err := enforcer.Check(ctx, security.CheckRequest{
		Plugin:          "unknown",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	assert.Error(t, err)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/security/enforcer.go`:

- `Enforcer` struct holds registered plugins (map of plugin name → allow set + deny set)
- `RegisterPlugin(name string, allow, deny CapabilitySet)`
- `UnregisterPlugin(name string)`
- `Check(ctx, CheckRequest) error` — three-way intersection:
  1. Plugin allow set must contain the capability
  2. Plugin deny set must NOT contain the capability
  3. Workspace allow set must contain the capability
  4. User permissions set must contain the capability
- `CheckRequest` includes `UserPermissions CapabilitySet` field
- Every check (allow or deny) gets audit-logged

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/security/enforcer.go internal/security/enforcer_test.go
git commit -m "feat(security): add capability enforcer with ABAC and audit logging"
```

---

## Task 3: Plugin Manifest Parsing and Validation

**Context:** This task defines the **runtime's internal representation** of plugin manifests, which is distinct from the public SDK types in `pkg/plugin/types.go` (Phase 1 Task 14). The internal types use simplified forms optimized for runtime enforcement (e.g., `Capabilities []string` instead of `[]Capability` struct with Pattern/Description fields). A conversion function between the two representations should be added when the plugin loading pipeline is implemented.

**Files:**

- Create: `internal/plugin/manifest.go`
- Create: `internal/plugin/manifest_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseManifest_Valid(t *testing.T) {
	yaml := `
name: telegram-channel
version: 1.2.0
type: channel
engine: ">= 1.0.0"
license: MIT
capabilities:
  - sessions.read
  - sessions.write
  - messages.send
deny_capabilities:
  - exec.*
execution:
  tier: process
  sandbox:
    network:
      allow:
        - api.telegram.org:443
lifecycle:
  hot_reload: true
  graceful_shutdown_timeout: 30s
`
	m, err := plugin.ParseManifest([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "telegram-channel", m.Name)
	assert.Equal(t, "1.2.0", m.Version)
	assert.Equal(t, plugin.TypeChannel, m.Type)
	assert.Equal(t, plugin.TierProcess, m.Execution.Tier)
	assert.Contains(t, m.Capabilities, "sessions.read")
	assert.Contains(t, m.DenyCapabilities, "exec.*")
	assert.True(t, m.Lifecycle.HotReload)
}

func TestParseManifest_InvalidType(t *testing.T) {
	yaml := `
name: bad-plugin
version: 1.0.0
type: invalid
`
	_, err := plugin.ParseManifest([]byte(yaml))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestParseManifest_MissingName(t *testing.T) {
	yaml := `
version: 1.0.0
type: tool
`
	_, err := plugin.ParseManifest([]byte(yaml))
	assert.Error(t, err)
}

func TestParseManifest_InvalidTier(t *testing.T) {
	yaml := `
name: bad-tier
version: 1.0.0
type: tool
execution:
  tier: quantum
`
	_, err := plugin.ParseManifest([]byte(yaml))
	assert.Error(t, err)
}

func TestValidateManifest_ConflictingCapabilities(t *testing.T) {
	m := &plugin.Manifest{
		Name:    "conflict",
		Version: "1.0.0",
		Type:    plugin.TypeTool,
		Capabilities:     []string{"exec.run"},
		DenyCapabilities: []string{"exec.*"},
		Execution: plugin.ExecutionConfig{Tier: plugin.TierProcess},
	}

	errs := m.Validate()
	assert.NotEmpty(t, errs)
}

// NOTE: These are internal runtime types (plugin.TypeChannel, plugin.TierProcess),
// distinct from the public SDK types in pkg/plugin (plugin.PluginTypeChannel, plugin.ExecutionTierProcess).
// The internal types use simplified string constants for efficient runtime matching.

func TestPluginTypeValues(t *testing.T) {
	assert.Equal(t, plugin.PluginType("provider"), plugin.TypeProvider)
	assert.Equal(t, plugin.PluginType("channel"), plugin.TypeChannel)
	assert.Equal(t, plugin.PluginType("tool"), plugin.TypeTool)
	assert.Equal(t, plugin.PluginType("skill"), plugin.TypeSkill)
}

func TestExecutionTierValues(t *testing.T) {
	assert.Equal(t, plugin.ExecutionTier("wasm"), plugin.TierWasm)
	assert.Equal(t, plugin.ExecutionTier("process"), plugin.TierProcess)
	assert.Equal(t, plugin.ExecutionTier("container"), plugin.TierContainer)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/manifest.go`:

- `PluginType` enum: `provider`, `channel`, `tool`, `skill` (internal runtime constants)
- `ExecutionTier` enum: `wasm`, `process`, `container` (internal runtime constants)
- `Manifest` struct matching `plugin.yaml` schema from Section 2
  - Uses simplified types: `Capabilities []string`, `DenyCapabilities []string` (not the `[]Capability` struct from `pkg/plugin`)
  - This is the **runtime's parsed representation**, optimized for enforcement checks
- `ParseManifest(data []byte) (*Manifest, error)` — YAML parsing + validation
- `Validate() []error` — check required fields, valid type/tier, no conflicting caps

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/manifest.go internal/plugin/manifest_test.go
git commit -m "feat(plugin): add manifest parsing and validation"
```

---

## Task 4: Plugin Lifecycle State Machine

**Files:**

- Create: `internal/plugin/lifecycle.go`
- Create: `internal/plugin/lifecycle_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/stretchr/testify/assert"
)

func TestLifecycleState_Transitions(t *testing.T) {
	tests := []struct {
		name    string
		from    plugin.PluginState
		to      plugin.PluginState
		allowed bool
	}{
		{"discovered to validating", plugin.StateDiscovered, plugin.StateValidating, true},
		{"validating to loading", plugin.StateValidating, plugin.StateLoading, true},
		{"loading to running", plugin.StateLoading, plugin.StateRunning, true},
		{"running to draining", plugin.StateRunning, plugin.StateDraining, true},
		{"draining to stopping", plugin.StateDraining, plugin.StateStopping, true},
		{"stopping to stopped", plugin.StateStopping, plugin.StateStopped, true},
		{"validating to error", plugin.StateValidating, plugin.StateError, true},
		{"loading to error", plugin.StateLoading, plugin.StateError, true},
		{"running to error", plugin.StateRunning, plugin.StateError, true},
		// Invalid transitions
		{"discovered to running", plugin.StateDiscovered, plugin.StateRunning, false},
		{"stopped to running", plugin.StateStopped, plugin.StateRunning, false},
		{"running to discovered", plugin.StateRunning, plugin.StateDiscovered, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, plugin.ValidTransition(tt.from, tt.to))
		})
	}
}

func TestPluginInstance_StateTransition(t *testing.T) {
	inst := plugin.NewInstance("telegram", plugin.StateDiscovered)

	assert.Equal(t, plugin.StateDiscovered, inst.State())

	err := inst.TransitionTo(plugin.StateValidating)
	assert.NoError(t, err)
	assert.Equal(t, plugin.StateValidating, inst.State())

	err = inst.TransitionTo(plugin.StateRunning) // invalid: skip loading
	assert.Error(t, err)
	assert.Equal(t, plugin.StateValidating, inst.State()) // state unchanged
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/lifecycle.go`:

- `PluginState` enum: `discovered`, `validating`, `loading`, `running`, `draining`, `stopping`, `stopped`, `error`
- `ValidTransition(from, to PluginState) bool` — adjacency check
- `PluginInstance` struct with state, name, mutex
- `TransitionTo(state PluginState) error` — validates transition, updates state

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/lifecycle.go internal/plugin/lifecycle_test.go
git commit -m "feat(plugin): add lifecycle state machine with valid transitions"
```

---

## Task 5: Plugin Manager

**Files:**

- Create: `internal/plugin/manager.go`
- Create: `internal/plugin/manager_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_DiscoverPlugins(t *testing.T) {
	dir := t.TempDir()

	// Create a plugin directory with a valid manifest
	pluginDir := filepath.Join(dir, "test-tool")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))

	manifest := `
name: test-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 1)
	assert.Equal(t, "test-tool", plugins[0].Name)
}

func TestManager_DiscoverSkipsInvalidManifest(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "bad-plugin")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte("invalid: [yaml"), 0644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	plugins, err := mgr.Discover(context.Background())
	require.NoError(t, err)
	assert.Len(t, plugins, 0) // invalid manifests are skipped, not fatal
}

func TestManager_RegisterCapabilities(t *testing.T) {
	dir := t.TempDir()

	pluginDir := filepath.Join(dir, "test-tool")
	require.NoError(t, os.MkdirAll(pluginDir, 0755))
	manifest := `
name: test-tool
version: 1.0.0
type: tool
execution:
  tier: process
capabilities:
  - sessions.read
  - exec.run.sandboxed
deny_capabilities:
  - config.write.global
`
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0644))

	audit := &mockAuditStore{}
	enforcer := security.NewEnforcer(audit)
	mgr := plugin.NewManager(dir, enforcer)

	_, err := mgr.Discover(context.Background())
	require.NoError(t, err)

	// Verify enforcer was populated
	err = enforcer.Check(context.Background(), security.CheckRequest{
		Plugin:          "test-tool",
		Capability:      "sessions.read",
		WorkspaceID:     "ws-1",
		WorkspaceAllow:  security.NewCapabilitySet("*"),
		UserPermissions: security.NewCapabilitySet("*"),
	})
	assert.NoError(t, err)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/manager.go`:

- `Manager` struct with plugins dir, enforcer reference, registered plugins map
- `Discover(ctx) ([]*Manifest, error)` — scan dir for subdirectories containing `plugin.yaml`, parse, validate, register capabilities with enforcer
- `Get(name string) (*PluginInstance, error)`
- `List() []*PluginInstance`

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/manager.go internal/plugin/manager_test.go
git commit -m "feat(plugin): add plugin manager with discovery and capability registration"
```

---

## Task 6: go-plugin Host (Process Tier)

**Files:**

- Create: `internal/plugin/goplugin/host.go`
- Create: `internal/plugin/goplugin/host_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package goplugin_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin/goplugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHost_HandshakeConfig(t *testing.T) {
	config := goplugin.HandshakeConfig()
	assert.NotEmpty(t, config.ProtocolVersion)
	assert.NotEmpty(t, config.MagicCookieKey)
	assert.NotEmpty(t, config.MagicCookieValue)
}

func TestHost_PluginMap(t *testing.T) {
	pm := goplugin.PluginMap()
	require.NotNil(t, pm)

	// Should have entries for each plugin type
	_, ok := pm["lifecycle"]
	assert.True(t, ok)
	_, ok = pm["channel"]
	assert.True(t, ok)
	_, ok = pm["tool"]
	assert.True(t, ok)
	_, ok = pm["provider"]
	assert.True(t, ok)
}

func TestHost_NewClient(t *testing.T) {
	// This tests the client configuration, not an actual plugin process.
	// Integration tests with real plugins are in Phase 4.
	config := goplugin.ClientConfig("/nonexistent/binary", nil)
	assert.NotNil(t, config)
	assert.Equal(t, "/nonexistent/binary", config.Cmd.Path)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/goplugin/host.go`:

- `HandshakeConfig()` — returns `plugin.HandshakeConfig` with Sigil-specific magic cookie
- `PluginMap()` — returns map of plugin type → `plugin.Plugin` implementations (gRPC plugins wrapping the proto services)
- `ClientConfig(binary string, sandbox []string)` — creates `plugin.ClientConfig` with optional sandbox command wrapper
- gRPC plugin wrappers for: `PluginLifecycle`, `Channel`, `Tool`, `Provider` (client-side stubs that call the gRPC services)

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/goplugin/
git commit -m "feat(plugin): add go-plugin host with gRPC service stubs"
```

---

## Task 7: Process-Tier Sandbox Configuration

**Context:** This task references sandbox configuration types from the internal manifest representation (`plugin.FilesystemSandbox`, `plugin.NetworkSandbox`). These correspond to the public SDK types `FilesystemConfig` and `NetworkConfig` defined in `pkg/plugin/types.go` (Phase 1 Task 14). The internal types may use slightly different naming for runtime clarity.

**Files:**

- Create: `internal/plugin/sandbox/sandbox.go`
- Create: `internal/plugin/sandbox/sandbox_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sandbox_test

import (
	"runtime"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/plugin/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSandboxArgs_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	// NOTE: Using internal types (plugin.FilesystemSandbox, plugin.NetworkSandbox)
	// These correspond to pkg/plugin.FilesystemConfig and pkg/plugin.NetworkConfig
	// from the public SDK, but may have different naming in the runtime representation.
	manifest := &plugin.Manifest{
		Name: "test-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{
				Filesystem: plugin.FilesystemSandbox{
					WriteAllow: []string{"/data/plugins/self/*"},
					ReadDeny:   []string{"/etc/shadow", "~/.ssh/*"},
				},
				Network: plugin.NetworkSandbox{
					Allow: []string{"api.telegram.org:443"},
					Proxy: true,
				},
			},
		},
	}

	args, err := sandbox.GenerateArgs(manifest, "/usr/bin/plugin-binary")
	require.NoError(t, err)
	assert.Contains(t, args[0], "bwrap")
	assert.Contains(t, args, "--ro-bind")
}

func TestGenerateSandboxArgs_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	manifest := &plugin.Manifest{
		Name: "test-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierProcess,
			Sandbox: plugin.SandboxConfig{
				Filesystem: plugin.FilesystemSandbox{
					WriteAllow: []string{"/data/plugins/self/*"},
				},
				Network: plugin.NetworkSandbox{
					Allow: []string{"api.telegram.org:443"},
				},
			},
		},
	}

	args, err := sandbox.GenerateArgs(manifest, "/usr/bin/plugin-binary")
	require.NoError(t, err)
	assert.Contains(t, args[0], "sandbox-exec")
}

func TestGenerateSandboxArgs_NoSandboxForWasm(t *testing.T) {
	manifest := &plugin.Manifest{
		Name: "wasm-plugin",
		Execution: plugin.ExecutionConfig{
			Tier: plugin.TierWasm,
		},
	}

	args, err := sandbox.GenerateArgs(manifest, "/path/to/binary")
	require.NoError(t, err)
	assert.Nil(t, args) // Wasm doesn't need OS-level sandbox
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/sandbox/sandbox.go`:

- `GenerateArgs(manifest, binaryPath) ([]string, error)` — returns command args to wrap the plugin binary in a sandbox
- Linux: generates `bwrap` arguments (read-only bind mounts, filesystem allow/deny, network namespace if proxy)
- macOS: generates `sandbox-exec` arguments with dynamically generated Seatbelt profile
- Returns nil for non-process tiers

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/sandbox/
git commit -m "feat(plugin): add OS-level sandbox config generation (bwrap/sandbox-exec)"
```

---

## Task 8: Wasm Host (Wazero)

**Files:**

- Create: `internal/plugin/wasm/host.go`
- Create: `internal/plugin/wasm/host_test.go`
- Create: `internal/plugin/wasm/testdata/echo.wasm` (test fixture — minimal Wasm module)

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package wasm_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin/wasm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWasmHost_Create(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer host.Close()
	assert.NotNil(t, host)
}

func TestWasmHost_LoadModule(t *testing.T) {
	host, err := wasm.NewHost()
	require.NoError(t, err)
	defer host.Close()

	ctx := context.Background()

	// Load a minimal test Wasm module
	// For the initial test, we test with an empty/minimal module
	// Real plugin Wasm modules will be tested in integration
	_, err = host.LoadModule(ctx, "test-module", minimalWasm())
	require.NoError(t, err)
}

func TestWasmHost_FuelMeteringEnforced(t *testing.T) {
	host, err := wasm.NewHost(wasm.WithFuelLimit(1000))
	require.NoError(t, err)
	defer host.Close()

	// Fuel metering is configured
	assert.Equal(t, uint64(1000), host.FuelLimit())
}

// minimalWasm returns a valid minimal Wasm module binary.
func minimalWasm() []byte {
	// Minimal valid Wasm module: magic number + version + empty sections
	return []byte{
		0x00, 0x61, 0x73, 0x6d, // magic: \0asm
		0x01, 0x00, 0x00, 0x00, // version: 1
	}
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/wasm/host.go`:

- `Host` struct wrapping `wazero.Runtime`
- `NewHost(opts ...Option) (*Host, error)` — creates Wazero runtime with optional fuel metering
- `LoadModule(ctx, name string, wasmBytes []byte) (*Module, error)` — compiles and instantiates
- `Close() error` — cleans up runtime
- `WithFuelLimit(n uint64) Option` — sets fuel metering limit

Wazero provides memory sandboxing and no network/filesystem access by default — ideal for the Wasm tier.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/wasm/
git commit -m "feat(plugin): add Wazero Wasm host with fuel metering"
```

---

## Gate 2 Checklist

After completing all 8 tasks, verify:

- [ ] `task test` — all tests pass (including Phase 1 tests)
- [ ] `task lint` — zero lint errors
- [ ] Capability matching handles all glob patterns correctly
- [ ] Enforcer performs three-way intersection (plugin ∩ workspace ∩ user ∩ !deny)
- [ ] User permissions dimension enforced (including empty permission set)
- [ ] All enforcer decisions are audit-logged
- [ ] Plugin manifests parse from YAML and validate
- [ ] Lifecycle state machine allows only valid transitions
- [ ] Plugin manager discovers, validates, and registers plugins
- [ ] go-plugin host creates proper client configurations
- [ ] Sandbox generates platform-appropriate args from manifest
- [ ] Wasm host creates, loads, and closes modules

Only proceed to Phase 3 after all checks pass.
