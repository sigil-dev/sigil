# Phase 5: Server & API

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expose the gateway as an HTTP server with REST+SSE endpoints, generate an OpenAPI 3.1 spec from Go types, and build the CLI that launches and manages everything.

**Architecture:** huma framework on chi router generates OpenAPI spec from Go struct types. SSE endpoint streams agent responses. CLI uses Cobra subcommands with Viper config resolution (flags > env > file > defaults). The CLI `start` command wires everything together and starts the server.

**Tech Stack:** huma, chi, cobra, viper, SSE (standard HTTP), testify

**Design Docs:**

- [Section 1: Core Architecture](../design/01-core-architecture.md) — protocol stack (REST+SSE+OpenAPI)
- [Section 9: UI and CLI](../design/09-ui-and-cli.md) — CLI commands, SvelteKit API contract

**Depends on:** Phase 1–4 (all subsystems this server exposes)

---

## Task 1: HTTP Server Setup (huma + chi)

**Files:**

- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Starts(t *testing.T) {
	srv, err := server.New(server.Config{
		ListenAddr: "127.0.0.1:0", // random port
	})
	require.NoError(t, err)
	assert.NotNil(t, srv)
}

func TestServer_HealthEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestServer_OpenAPISpec(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/openapi.json", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, w.Body.String(), "openapi")
}

func TestServer_CORSHeaders(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("OPTIONS", "/api/v1/workspaces", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/server/server.go`:

- `Server` struct wrapping chi.Router and huma.API
- `New(Config) (*Server, error)` — creates chi router, configures huma, registers `/health` and `/openapi.json`
- `Handler() http.Handler` — returns the chi router for testing
- `Start(ctx context.Context) error` — starts HTTP server with graceful shutdown
- CORS middleware for SvelteKit dev server (localhost:5173)

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat(server): add HTTP server with huma+chi, health endpoint, OpenAPI spec"
```

---

## Task 2: REST API Endpoints

**Files:**

- Create: `internal/server/routes.go`
- Create: `internal/server/routes_test.go`

**Step 1: Write failing tests**

Cover the core REST endpoints:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigil-dev/sigil/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutes_ListWorkspaces(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest("GET", "/api/v1/workspaces", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Workspaces []struct {
			ID string `json:"id"`
		} `json:"workspaces"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Workspaces)
}

func TestRoutes_GetWorkspace(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest("GET", "/api/v1/workspaces/homelab", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "homelab")
}

func TestRoutes_ListSessions(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest("GET", "/api/v1/workspaces/homelab/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_ListPlugins(t *testing.T) {
	srv := newTestServerWithData(t)

	req := httptest.NewRequest("GET", "/api/v1/plugins", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_SendMessage(t *testing.T) {
	srv := newTestServerWithData(t)

	body := `{"content": "Hello, agent!", "workspace_id": "homelab"}`
	req := httptest.NewRequest("POST", "/api/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoutes_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/server/routes.go`:

Register huma operations for:

- `GET /api/v1/workspaces` — list workspaces
- `GET /api/v1/workspaces/{id}` — get workspace details
- `GET /api/v1/workspaces/{id}/sessions` — list sessions in workspace
- `GET /api/v1/workspaces/{id}/sessions/{sessionId}` — get session
- `POST /api/v1/chat` — send message to agent
- `GET /api/v1/plugins` — list plugins
- `GET /api/v1/plugins/{name}` — get plugin details
- `POST /api/v1/plugins/{name}/reload` — reload plugin
- `GET /api/v1/users` — list users
- `GET /api/v1/status` — gateway status

Each endpoint handler calls into the appropriate subsystem (workspace manager, session manager, plugin manager, etc.).

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/server/routes.go internal/server/routes_test.go
git commit -m "feat(server): add REST API endpoints for workspaces, sessions, plugins, chat"
```

---

## Task 3: SSE Streaming Endpoint

**Files:**

- Create: `internal/server/sse.go`
- Create: `internal/server/sse_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSE_StreamsEvents(t *testing.T) {
	srv := newTestServerWithMockAgent(t)

	req := httptest.NewRequest("POST", "/api/v1/chat/stream", strings.NewReader(
		`{"content": "Hello", "workspace_id": "homelab", "session_id": "sess-1"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")

	// Parse SSE events
	scanner := bufio.NewScanner(strings.NewReader(w.Body.String()))
	var events []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			events = append(events, strings.TrimPrefix(line, "data: "))
		}
	}
	assert.NotEmpty(t, events)
}

func TestSSE_ContentTypeNegotiation(t *testing.T) {
	srv := newTestServerWithMockAgent(t)

	// Without Accept: text/event-stream, should return JSON
	req := httptest.NewRequest("POST", "/api/v1/chat/stream", strings.NewReader(
		`{"content": "Hello", "workspace_id": "homelab"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should still work but return complete response (not streamed)
	assert.Equal(t, http.StatusOK, w.Code)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`internal/server/sse.go`:

- `POST /api/v1/chat/stream` endpoint
- If `Accept: text/event-stream`, stream SSE events as the agent processes
- Events: `text_delta` (incremental text), `tool_call` (tool invocation), `tool_result`, `usage`, `done`, `error`
- Each event is JSON-encoded and sent as `data: {...}\n\n`
- Uses `http.Flusher` for streaming
- Graceful shutdown: context cancellation closes the stream

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add internal/server/sse.go internal/server/sse_test.go
git commit -m "feat(server): add SSE streaming endpoint for real-time agent responses"
```

---

## Task 4: OpenAPI Spec Generation

**Files:**

- Modify: `cmd/openapi-gen/main.go`
- Create: `cmd/openapi-gen/main_test.go`

**Step 1: Write failing test**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAPIGen_ProducesValidSpec(t *testing.T) {
	// Run the generator
	spec, err := generateSpec()
	require.NoError(t, err)
	assert.Contains(t, string(spec), "openapi")
	assert.Contains(t, string(spec), "3.1")
	assert.Contains(t, string(spec), "/api/v1/workspaces")
	assert.Contains(t, string(spec), "/api/v1/chat")
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`cmd/openapi-gen/main.go`:

- Creates a huma API instance with all routes registered (reuses `internal/server` route registration)
- Exports the OpenAPI spec to `api/openapi/spec.json` (JSON is the canonical format)
- Run via `task generate` or directly

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add cmd/openapi-gen/ api/openapi/
git commit -m "feat(api): add OpenAPI 3.1 spec generator from Go types"
```

---

## Task 5: CLI Framework (Cobra + Viper)

**Files:**

- Create: `cmd/sigil/main.go`
- Create: `cmd/sigil/root.go`
- Create: `cmd/sigil/start.go`
- Create: `cmd/sigil/status.go`
- Create: `cmd/sigil/version.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main_test

import (
	"bytes"
	"testing"

	cmd "github.com/sigil-dev/sigil/cmd/sigil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand_Help(t *testing.T) {
	root := cmd.NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"--help"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "sigil")
	assert.Contains(t, buf.String(), "start")
	assert.Contains(t, buf.String(), "status")
	assert.Contains(t, buf.String(), "version")
}

func TestVersionCommand(t *testing.T) {
	root := cmd.NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"version"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "sigil")
}

func TestStartCommand_RequiresConfig(t *testing.T) {
	root := cmd.NewRootCmd()
	root.SetArgs([]string{"start", "--config", "/nonexistent/path.yaml"})

	err := root.Execute()
	assert.Error(t, err)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

- `cmd/sigil/main.go` — entry point calling root command
- `cmd/sigil/root.go` — root Cobra command with global flags (--config, --data-dir, --verbose)
- `cmd/sigil/start.go` — loads config, creates all subsystems, starts HTTP server
- `cmd/sigil/status.go` — calls `/health` endpoint, displays status
- `cmd/sigil/version.go` — prints version info

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add cmd/sigil/
git commit -m "feat(cli): add Cobra CLI with start, status, and version commands"
```

---

## Task 6: CLI Management Commands

**Files:**

- Create: `cmd/sigil/workspace.go`
- Create: `cmd/sigil/plugin.go`
- Create: `cmd/sigil/session.go`
- Create: `cmd/sigil/chat.go`
- Create: `cmd/sigil/doctor.go`

**Step 1: Write failing tests**

Test each subcommand group exists and shows help:

```go
func TestWorkspaceCommand_Help(t *testing.T) {
	root := cmd.NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"workspace", "--help"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "list")
	assert.Contains(t, buf.String(), "create")
}

func TestPluginCommand_Help(t *testing.T) {
	root := cmd.NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"plugin", "--help"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "list")
	assert.Contains(t, buf.String(), "install")
}

func TestChatCommand_Exists(t *testing.T) {
	root := cmd.NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"chat", "--help"})
	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "workspace")
}

func TestDoctorCommand_Exists(t *testing.T) {
	root := cmd.NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor", "--help"})
	err := root.Execute()
	require.NoError(t, err)
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

Each file adds subcommands matching Section 9 CLI spec:

- `workspace` — list, create, delete, show
- `plugin` — list, install, remove, reload, inspect, logs
- `session` — list, show, archive, export
- `chat` — interactive CLI chat (--workspace, --model, --session flags)
- `doctor` — check binary health, provider API keys, channel connections, disk space

Commands that need a running gateway connect to it via HTTP client.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add cmd/sigil/
git commit -m "feat(cli): add workspace, plugin, session, chat, and doctor commands"
```

---

## Task 7: Gateway Wiring (Start Command)

**Files:**

- Modify: `cmd/sigil/start.go`
- Create: `cmd/sigil/wire.go`
- Create: `cmd/sigil/wire_test.go`

**Step 1: Write failing tests**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main_test

import (
	"context"
	"testing"
	"time"

	cmd "github.com/sigil-dev/sigil/cmd/sigil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWireGateway(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir) // minimal valid config

	gw, err := cmd.WireGateway(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gw.Server)
	assert.NotNil(t, gw.WorkspaceManager)
	assert.NotNil(t, gw.PluginManager)
	assert.NotNil(t, gw.ProviderRegistry)
	assert.NotNil(t, gw.Enforcer)
}

func TestGateway_GracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	gw, err := cmd.WireGateway(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start and immediately cancel — should shut down cleanly
	err = gw.Start(ctx)
	assert.NoError(t, err) // context cancellation is clean shutdown
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement**

`cmd/sigil/wire.go`:

- `WireGateway(cfg *config.Config) (*Gateway, error)` — dependency injection:
  1. Create GatewayStore
  2. Create Enforcer
  3. Create PluginManager → discover plugins → register capabilities
  4. Create ProviderRegistry → register built-in providers → register plugin providers
  5. Create WorkspaceManager
  6. Create AgentLoop
  7. Create HTTP Server → register routes → register SSE
  8. Return `Gateway` struct with all components
- `Gateway.Start(ctx) error` — starts server, plugin health checks, config watcher
- `Gateway.Shutdown(ctx) error` — graceful shutdown of all components

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add cmd/sigil/wire.go cmd/sigil/wire_test.go cmd/sigil/start.go
git commit -m "feat(cli): add gateway wiring and graceful shutdown"
```

---

## Gate 5 Checklist

After completing all 7 tasks, verify:

- [ ] `task test` — all tests pass (including Phase 1–4 tests)
- [ ] `task lint` — zero lint errors
- [ ] HTTP server starts and serves `/health` and `/openapi.json`
- [ ] REST endpoints respond for workspaces, sessions, plugins, chat
- [ ] SSE endpoint streams events for chat messages
- [ ] OpenAPI spec generates correctly from Go types
- [ ] `sigil start` launches the gateway (with graceful shutdown)
- [ ] `sigil status` reports health
- [ ] `sigil version` prints version info
- [ ] `sigil workspace list` shows configured workspaces
- [ ] `sigil doctor` runs diagnostics
- [ ] Gateway wiring creates all subsystems correctly

Only proceed to Phase 6 after all checks pass.
