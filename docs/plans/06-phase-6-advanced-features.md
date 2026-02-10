# Phase 6: Advanced Features

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add the advanced subsystems: node management (remote plugin hosts), container execution tier, Tailscale networking integration, and full memory compaction lifecycle.

**Architecture:** Nodes are remote instances of the plugin host that connect back to the gateway via gRPC streaming. Container tier uses containerd/OCI for full isolation. Tailscale provides zero-config NAT traversal via tsnet. Memory compaction uses LLM calls to generate summaries and extract facts from old messages.

**Tech Stack:** gRPC bidirectional streaming, tailscale.com/tsnet, containerd (OCI), testify

**Design Docs:**

- [Section 6: Node System](../design/06-node-system.md) — nodes, trust tiers, Tailscale
- [Section 2: Plugin System](../design/02-plugin-system.md) — container tier
- [Section 8: Agent Core](../design/08-agent-core.md) — compaction lifecycle

**Depends on:** Phase 1–5 (all core systems). Phase 6 and Phase 7 can run in parallel.

---

## Task 1: Node Registration Protocol

**Files:**

- Create: `internal/node/manager.go`
- Create: `internal/node/manager_test.go`
- Create: `api/proto/sigil/v1/node.proto`

**Step 1: Write node proto**

```protobuf
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

syntax = "proto3";

package sigil.v1;

option go_package = "github.com/sigil-dev/sigil/internal/gen/proto/sigil/v1;sigilv1";

import "common/v1/types.proto";

service NodeService {
  // Bidirectional stream for node ↔ gateway communication.
  rpc Connect(stream NodeMessage) returns (stream GatewayMessage);
}

message NodeMessage {
  oneof msg {
    NodeRegister register = 1;
    ToolResult tool_result = 2;
    NodeStatus status = 3;
  }
}

message GatewayMessage {
  oneof msg {
    RegisterAck register_ack = 1;
    ToolExecuteRequest tool_execute = 2;
  }
}

message NodeRegister {
  string node_id = 1;
  string platform = 2;      // "darwin", "linux", "ios"
  repeated string tools = 3; // available tool names
  map<string, string> capabilities = 4;
}

message RegisterAck {
  bool accepted = 1;
  string error = 2;
}

message ToolResult {
  string request_id = 1;
  string output = 2;
  string error = 3;
}

message ToolExecuteRequest {
  string request_id = 1;
  string tool_name = 2;
  string arguments = 3;
  int32 timeout_seconds = 4;
}

message NodeStatus {
  string node_id = 1;
  bool online = 2;
  repeated string available_tools = 3;
}
```

**Step 2: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeManager_RegisterNode(t *testing.T) {
	mgr := node.NewManager(node.ManagerConfig{})

	err := mgr.Register(node.Registration{
		NodeID:   "macbook-pro",
		Platform: "darwin",
		Tools:    []string{"camera-tool", "screen-capture"},
	})
	require.NoError(t, err)

	n, err := mgr.Get("macbook-pro")
	require.NoError(t, err)
	assert.Equal(t, "macbook-pro", n.ID)
	assert.True(t, n.Online)
	assert.Contains(t, n.Tools, "camera-tool")
}

func TestNodeManager_ToolPrefixing(t *testing.T) {
	mgr := node.NewManager(node.ManagerConfig{})

	err := mgr.Register(node.Registration{
		NodeID: "macbook-pro",
		Tools:  []string{"camera", "screen"},
	})
	require.NoError(t, err)

	tools := mgr.PrefixedTools("macbook-pro")
	assert.Contains(t, tools, "node:macbook-pro:camera")
	assert.Contains(t, tools, "node:macbook-pro:screen")
}

func TestNodeManager_Disconnect(t *testing.T) {
	mgr := node.NewManager(node.ManagerConfig{})

	mgr.Register(node.Registration{NodeID: "phone", Tools: []string{"camera"}})
	mgr.Disconnect("phone")

	n, err := mgr.Get("phone")
	require.NoError(t, err)
	assert.False(t, n.Online)
}

func TestNodeManager_ListNodes(t *testing.T) {
	mgr := node.NewManager(node.ManagerConfig{})

	mgr.Register(node.Registration{NodeID: "mac", Tools: []string{"screen"}})
	mgr.Register(node.Registration{NodeID: "phone", Tools: []string{"camera"}})

	nodes := mgr.List()
	assert.Len(t, nodes, 2)
}

func TestNodeManager_QueueToolCall(t *testing.T) {
	mgr := node.NewManager(node.ManagerConfig{QueueTTL: 60 * time.Second})

	mgr.Register(node.Registration{NodeID: "mac", Tools: []string{"screen"}})
	mgr.Disconnect("mac") // offline

	// Queue a tool call for offline node
	reqID, err := mgr.QueueToolCall("mac", "screen", `{"format": "png"}`)
	require.NoError(t, err)
	assert.NotEmpty(t, reqID)

	// Pending requests exist
	pending := mgr.PendingRequests("mac")
	assert.Len(t, pending, 1)
}
```

**Step 3: Run test — expect FAIL**

**Step 4: Implement**

`internal/node/manager.go`:

- `Manager` struct with registered nodes map, pending request queues
- `Register(Registration) error` — records node, marks online
- `Disconnect(nodeID string)` — marks offline, tools become unavailable
- `PrefixedTools(nodeID string) []string` — returns `node:<id>:<tool>` formatted names
- `QueueToolCall(nodeID, tool, args string) (requestID string, error)` — queues for offline nodes with TTL
- `PendingRequests(nodeID string) []PendingRequest`

**Step 5: Run test — expect PASS**

**Step 6: Commit**

```bash
git add api/proto/sigil/v1/node.proto internal/gen/proto/sigil/v1/ internal/node/
git commit -m "feat(node): add node manager with registration, prefixing, and offline queuing"
```

---

## Task 2: Tailscale Integration

**Files:**

- Create: `internal/node/tailscale.go`
- Create: `internal/node/tailscale_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTailscaleConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     node.TailscaleConfig
		wantErr bool
	}{
		{"valid", node.TailscaleConfig{Hostname: "my-agent", AuthKey: "tskey-xxx", RequiredTag: "tag:agent-node"}, false},
		{"missing hostname", node.TailscaleConfig{AuthKey: "tskey-xxx"}, true},
		{"missing auth key", node.TailscaleConfig{Hostname: "my-agent"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTailscaleAuth_TagCheck(t *testing.T) {
	auth := node.NewTailscaleAuth(node.TailscaleConfig{
		RequiredTag: "tag:agent-node",
	})

	// Node with correct tag — allowed
	assert.True(t, auth.CheckTag([]string{"tag:agent-node", "tag:server"}))

	// Node without tag — denied
	assert.False(t, auth.CheckTag([]string{"tag:server"}))

	// Empty tags — denied
	assert.False(t, auth.CheckTag(nil))
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/node/tailscale.go`:

- `TailscaleConfig` struct: Hostname, AuthKey, RequiredTag
- `Validate() error`
- `TailscaleAuth` — tag-based authentication checker
- `NewTailscaleListener(cfg TailscaleConfig) (net.Listener, error)` — creates tsnet.Server listener (integration test only, unit tests mock the interface)

The actual tsnet integration (creating a Tailscale node) is behind a build tag or interface so unit tests don't need Tailscale.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/node/tailscale.go internal/node/tailscale_test.go
git commit -m "feat(node): add Tailscale config validation and tag-based auth"
```

---

## Task 3: Container Execution Tier

**Files:**

- Create: `internal/plugin/container/runtime.go`
- Create: `internal/plugin/container/runtime_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package container_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/plugin"
	"github.com/sigil-dev/sigil/internal/plugin/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerConfig_FromManifest(t *testing.T) {
	manifest := &plugin.Manifest{
		Name: "python-tool",
		Execution: plugin.ExecutionConfig{
			Tier:        plugin.TierContainer,
			Image:       "ghcr.io/org/python-tool:latest",
			Network:     "restricted",
			MemoryLimit: "256Mi",
		},
	}

	cfg, err := container.ConfigFromManifest(manifest)
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io/org/python-tool:latest", cfg.Image)
	assert.Equal(t, "restricted", cfg.NetworkMode)
	assert.Equal(t, int64(256*1024*1024), cfg.MemoryLimitBytes)
}

func TestContainerConfig_ParseMemoryLimit(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"256Mi", 256 * 1024 * 1024},
		{"1Gi", 1024 * 1024 * 1024},
		{"512Mi", 512 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := container.ParseMemoryLimit(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainerConfig_ValidateImage(t *testing.T) {
	tests := []struct {
		image   string
		wantErr bool
	}{
		{"ghcr.io/org/tool:latest", false},
		{"docker.io/library/python:3.12", false},
		{"", true},
		{"../relative/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			err := container.ValidateImage(tt.image)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNetworkMode_Values(t *testing.T) {
	assert.Equal(t, container.NetworkMode("none"), container.NetworkNone)
	assert.Equal(t, container.NetworkMode("restricted"), container.NetworkRestricted)
	assert.Equal(t, container.NetworkMode("host"), container.NetworkHost)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/plugin/container/runtime.go`:

- `ContainerConfig` struct: Image, NetworkMode, MemoryLimitBytes, gRPC port
- `ConfigFromManifest(manifest) (*ContainerConfig, error)` — extracts container-specific settings
- `ParseMemoryLimit(s string) (int64, error)` — parses `256Mi`, `1Gi` etc.
- `ValidateImage(image string) error` — basic validation
- `NetworkMode` enum: `none`, `restricted`, `host`
- `Runtime` interface with `Start(ctx, config) (ContainerInstance, error)` and `Stop(ctx, id) error`
- Actual containerd integration is behind an interface — unit tests use mocks

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/plugin/container/
git commit -m "feat(plugin): add container tier config, memory parsing, and image validation"
```

---

## Task 4: Full Memory Compaction Lifecycle

**Files:**

- Modify: `internal/agent/compaction.go`
- Create: `internal/agent/compaction_integration_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompaction_FullLifecycle(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	ss := newMockSessionStore()
	mockProvider := newMockSummarizationProvider()

	compactor := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:          ms,
		VectorStore:          vs,
		SessionStore:         ss,
		SummarizationProvider: mockProvider,
		BatchSize:            5, // small batch for testing
		WindowSize:           3,
	})

	ctx := context.Background()

	// Add messages beyond batch size
	for i := 0; i < 7; i++ {
		err := ms.Messages().Append(ctx, "ws-1", &store.Message{
			ID: fmt.Sprintf("msg-%d", i),
			Content: fmt.Sprintf("Message number %d about testing", i),
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
		require.NoError(t, err)
	}

	// Run compaction
	result, err := compactor.Compact(ctx, "ws-1")
	require.NoError(t, err)

	// Should have generated a summary
	assert.Equal(t, 1, result.SummariesCreated)

	// Summary should exist in SummaryStore
	summaries, err := ms.Summaries().GetLatest(ctx, "ws-1", 1)
	require.NoError(t, err)
	assert.Len(t, summaries, 1)
	assert.NotEmpty(t, summaries[0].Content)

	// Excess messages should be trimmed from Tier 1
	count, err := ms.Messages().Count(ctx, "ws-1")
	require.NoError(t, err)
	assert.LessOrEqual(t, count, int64(5)) // kept within batch size after compaction
}

func TestCompaction_FactExtraction(t *testing.T) {
	ms := newMockMemoryStore()
	vs := newMockVectorStore()
	ss := newMockSessionStore()
	mockProvider := newMockFactExtractionProvider()

	compactor := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:          ms,
		VectorStore:          vs,
		SessionStore:         ss,
		SummarizationProvider: mockProvider,
		BatchSize:            5,
		WindowSize:           3,
		ExtractFacts:         true,
	})

	ctx := context.Background()

	// Add messages that contain extractable facts
	ms.Messages().Append(ctx, "ws-1", &store.Message{
		ID: "msg-1", Content: "Alice is a software engineer at Acme Corp",
		CreatedAt: time.Now(),
	})

	result, err := compactor.Compact(ctx, "ws-1")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, result.FactsExtracted, 1)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

Extend `internal/agent/compaction.go`:

- `Compact(ctx, workspaceID string) (*CompactionResult, error)`:
  1. Count messages in Tier 1
  2. If count >= batchSize: get oldest batch
  3. Call summarization provider to generate summary
  4. Store summary in SummaryStore (Tier 2)
  5. If ExtractFacts enabled: call provider to extract entities/facts, store in KnowledgeStore (Tier 3)
  6. Generate embeddings for summary, store in VectorStore (Tier 4)
  7. Trim processed messages from Tier 1
- `CompactionResult`: SummariesCreated, FactsExtracted, MessagesProcessed, MessagesTrimmed

The summarization provider is an interface so tests can mock LLM calls.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/agent/compaction.go internal/agent/compaction_integration_test.go
git commit -m "feat(agent): add full memory compaction lifecycle (summarize, extract facts, trim)"
```

---

## Task 5: Node-Workspace Integration

**Files:**

- Create: `internal/node/workspace.go`
- Create: `internal/node/workspace_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package node_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/node"
	"github.com/stretchr/testify/assert"
)

func TestNodeWorkspaceBinding(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.Bind("homelab", []string{"macbook-pro", "homelab-server"})
	binder.Bind("family", []string{"iphone-sean", "iphone-wife"})

	// Check binding
	assert.True(t, binder.IsAllowed("homelab", "macbook-pro"))
	assert.True(t, binder.IsAllowed("homelab", "homelab-server"))
	assert.False(t, binder.IsAllowed("homelab", "iphone-sean"))
	assert.False(t, binder.IsAllowed("family", "macbook-pro"))
}

func TestNodeWorkspaceBinding_GlobPattern(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.Bind("family", []string{"iphone-*"})

	assert.True(t, binder.IsAllowed("family", "iphone-sean"))
	assert.True(t, binder.IsAllowed("family", "iphone-wife"))
	assert.False(t, binder.IsAllowed("family", "macbook-pro"))
}

func TestNodeWorkspaceBinding_ToolFiltering(t *testing.T) {
	binder := node.NewWorkspaceBinder()

	binder.BindWithTools("family", "iphone-*", []string{"camera", "location"})

	tools := binder.AllowedTools("family", "iphone-sean")
	assert.Contains(t, tools, "node:iphone-sean:camera")
	assert.Contains(t, tools, "node:iphone-sean:location")
	assert.NotContains(t, tools, "node:iphone-sean:filesystem")
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/node/workspace.go`:

- `WorkspaceBinder` struct
- `Bind(workspaceID string, nodePatterns []string)`
- `BindWithTools(workspaceID, nodePattern string, tools []string)`
- `IsAllowed(workspaceID, nodeID string) bool` — glob match
- `AllowedTools(workspaceID, nodeID string) []string` — returns prefixed tool names for allowed tools

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/node/workspace.go internal/node/workspace_test.go
git commit -m "feat(node): add workspace binding with glob patterns and tool filtering"
```

---

## Task 6: Node REST API Endpoints

**Files:**

- Modify: `internal/server/routes.go` — add node endpoints
- Create: `internal/server/node_routes_test.go`

**Step 1: Write failing tests**

```go
func TestRoutes_ListNodes(t *testing.T) {
	srv := newTestServerWithNodes(t)

	req := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_GetNode(t *testing.T) {
	srv := newTestServerWithNodes(t)

	req := httptest.NewRequest("GET", "/api/v1/nodes/macbook-pro", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "macbook-pro")
}

func TestRoutes_ApproveNode(t *testing.T) {
	srv := newTestServerWithNodes(t)

	req := httptest.NewRequest("POST", "/api/v1/nodes/macbook-pro/approve", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement** — add endpoints: `GET /api/v1/nodes`, `GET /api/v1/nodes/{id}`, `POST /api/v1/nodes/{id}/approve`, `DELETE /api/v1/nodes/{id}`

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat(server): add node management REST endpoints"
```

---

## Gate 6 Checklist

After completing all 6 tasks, verify:

- [ ] `task test` — all tests pass (including Phase 1–5 tests)
- [ ] `task lint` — zero lint errors
- [ ] Node proto compiles via `buf generate`
- [ ] Nodes register with gateway and expose prefixed tools
- [ ] Node disconnect marks tools as unavailable
- [ ] Offline tool calls are queued with TTL
- [ ] Tailscale config validates correctly
- [ ] Tag-based auth checks work
- [ ] Container tier config parses memory limits and validates images
- [ ] Full compaction lifecycle works: summarize → extract facts → store embeddings → trim
- [ ] Node-workspace binding with glob patterns works
- [ ] Node REST endpoints respond correctly

Phase 6 and Phase 7 are independent — proceed to Phase 7 if ready, or work on both in parallel.
