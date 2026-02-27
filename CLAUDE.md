# Sigil Development Guide

Instructions for Claude Code working on the Sigil codebase.

## Session Completion Protocol (CRITICAL)

**When ending ANY work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

### Mandatory Workflow

1. **File issues for remaining work** - Create beads issues for anything needing follow-up
2. **Run quality gates** (if code changed) - `task test`, `task lint`
3. **Update issue status** - `bd close <id>` for completed work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:

   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```

5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**

- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

## Issue Tracking (beads)

This project uses **bd** (beads) for issue tracking.

| Command                               | Purpose              |
| ------------------------------------- | -------------------- |
| `bd ready`                            | Find available work  |
| `bd show <id>`                        | View issue details   |
| `bd update <id> --status in_progress` | Claim work           |
| `bd close <id>`                       | Complete work        |
| `bd dolt push`                        | Push beads to remote |

## Project Overview

Sigil is a secure, lightweight Go gateway connecting messaging platforms to AI agents via a HashiCorp-style plugin architecture. Inspired by [OpenClaw](https://github.com/openclaw/openclaw).

- Go core with security-first agent loop
- HashiCorp go-plugin (gRPC) for plugin isolation
- Three execution tiers: Wasm (Wazero) → Process (go-plugin + sandbox) → Container (OCI)
- Capability-gated ABAC for all plugin operations
- SQLite per workspace (mattn/go-sqlite3 + sqlite-vec)
- REST+SSE API with OpenAPI 3.1 (huma on chi)
- SvelteKit web UI + Tauri desktop app
- Optional Tailscale integration (tsnet)

**Architecture Reference**: [docs/design/00-overview.md](docs/design/00-overview.md)

---

## Commands

### Task Commands (Required)

**MUST use `task` for all build, test, lint, and format operations.** Do NOT run `go build`, `go test`, `golangci-lint`, etc. directly.

```bash
task dev       # Run in development mode
task build     # Build binary (CGO_ENABLED=1)
task test      # Run all tests
task lint      # Run all linters
task fmt       # Format all files
task proto     # Generate Go code from protobuf
task deps      # Download and tidy dependencies
```

| Requirement                            | Description                                    |
| -------------------------------------- | ---------------------------------------------- |
| **MUST** use `task`                    | Never run Go/lint/fmt commands directly        |
| **MUST** run `task test`               | Before claiming any implementation is complete |
| **MUST** run `task lint`               | Before committing changes                      |
| **MUST NOT** disable lint/format rules | Without explicit user confirmation             |

### CGo Requirement

Sigil requires `CGO_ENABLED=1` for sqlite3 and sqlite-vec. All build commands in Taskfile handle this. Do NOT set `CGO_ENABLED=0`.

### Python: Use uv, Not pip

Any Python operations (docs site, tooling, scripts) MUST use `uv` instead of `pip`:

```bash
uv sync          # Install from pyproject.toml (preferred)
uv pip install   # If you must install ad-hoc
uv run           # Run Python commands in the project venv
```

**MUST NOT** use `pip install`, `pip3 install`, or `python -m pip`.

### Git: Protected Branch

`main` is a protected branch. Direct pushes to main are not allowed.

| Requirement                        | Description                                          |
| ---------------------------------- | ---------------------------------------------------- |
| **MUST** create feature branch     | All work happens on feature branches                 |
| **MUST** submit PR for review      | All changes to main require a pull request           |
| **MUST NOT** push directly to main | Create a branch and PR instead                       |
| **MUST NOT** use `--no-verify`     | Fix the underlying issue, don't skip hooks           |
| **MUST NOT** force push            | Use `--force-with-lease` only with user confirmation |

---

## Claude Code Configuration

This repo includes in-repo Claude Code hooks and commands in `.claude/`:

### Hooks (automatic enforcement)

| Hook                         | Enforces                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------ |
| `enforce-dev-practices.sh`   | `task` over raw go/lint commands, uv over pip, no CGO_ENABLED=0, no --no-verify, no push to main |
| `protect-generated-files.sh` | No edits to `*.pb.go`, `internal/gen/`, or `go.sum`                                              |

### Commands (slash commands)

| Command                 | Purpose                                         |
| ----------------------- | ----------------------------------------------- |
| `/sigil-test`           | Run tests and analyze failures                  |
| `/sigil-lint-fix`       | Iterative lint → format → fix → verify cycle    |
| `/sigil-new-plugin`     | Scaffold a new plugin (manifest + code + tests) |
| `/sigil-design-review`  | Check implementation against design docs        |
| `/sigil-security-check` | Audit code for security model compliance        |

---

## Development Principles

### Test-Driven Development

- Tests MUST be written before implementation
- Tests MUST pass before any task is complete
- Use table-driven tests for comprehensive coverage
- Mock external dependencies (database, network, plugins)

### Spec-Driven Development

- Work MUST NOT start without a spec/design/plan
- Design docs live in `docs/design/`
- Implementation plans live in `docs/plans/`
- Decisions live in `docs/decisions/`

### Design Documents vs Decisions

| Action                       | Where                                              |
| ---------------------------- | -------------------------------------------------- |
| **MUST NOT** modify          | `docs/design/` files (treated as immutable specs)  |
| **MUST** document deviations | `docs/decisions/decision-log.md` (next D0XX entry) |

### RFC2119 Keywords

| Keyword      | Meaning                                    |
| ------------ | ------------------------------------------ |
| **MUST**     | Absolute requirement                       |
| **MUST NOT** | Absolute prohibition                       |
| **SHOULD**   | Recommended, may ignore with justification |
| **MAY**      | Optional                                   |

---

## Code Conventions

### Go Idioms

- Accept interfaces, return structs
- Errors are values — handle them explicitly
- Use context for cancellation and timeouts
- Prefer composition over inheritance

### Error Handling (D056)

All production code **MUST** use `pkg/errors` (`sigilerr`) for error creation — **not** `fmt.Errorf` or `errors.New`:

```go
// Create with code + context
return sigilerr.Errorf(sigilerr.CodePluginRuntimeStartFailure, "loading plugin %s: %w", name, err)

// Classify errors by code, not sentinels
if sigilerr.HasCode(err, sigilerr.CodeServerEntityNotFound) { ... }

// Add structured fields for observability
return sigilerr.New(sigilerr.CodeProviderUpstreamFailure, "provider timeout",
    sigilerr.ProviderField("anthropic"))
```

| Requirement                                   | Description                                                 |
| --------------------------------------------- | ----------------------------------------------------------- |
| **MUST** use `sigilerr.Errorf/New/Wrap/Wrapf` | Not `fmt.Errorf` or `errors.New` in production code         |
| **MUST** use `sigilerr.HasCode`               | Not `errors.Is` with sentinel vars for error classification |
| **MUST** assign error codes                   | Every error site needs a code from `pkg/errors/errors.go`   |
| **SHOULD** add new codes                      | When no existing code fits the error site                   |
| **MAY** use `fmt.Errorf` in tests             | For mock errors not participating in error classification   |
| **MUST NOT** use sentinel vars                | Use `IsXxx()` helpers with `sigilerr.HasCode` instead       |

### Logging

- Use structured logging (slog)
- Log at appropriate levels (debug, info, warn, error)
- Include relevant context: plugin name, workspace ID, session ID

### Naming

- Use clear, descriptive names
- Avoid abbreviations except well-known ones (ID, URL, HTTP)
- Package names are lowercase, single words when possible

### License Headers

All source files MUST include SPDX license headers. Lefthook pre-commit hook adds them automatically.

**Go files:**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors
```

**Shell/Proto/YAML:** Same pattern with appropriate comment syntax.

| Requirement                         | Description                           |
| ----------------------------------- | ------------------------------------- |
| **MUST** include SPDX header        | All `.go`, `.sh`, `.proto` files      |
| **MUST NOT** add to generated files | Skip `*.pb.go` files                  |
| **Auto-added on commit**            | Lefthook pre-commit hook handles this |

**Directories checked:** `api/`, `cmd/`, `internal/`, `pkg/`, `plugins/`, `scripts/`

```bash
task license:check   # Verify all files have headers
task license:add     # Add missing headers
```

---

## Testing

### Test Files

- Tests live next to implementation: `foo.go` → `foo_test.go`
- Integration tests in `*_integration_test.go` with `//go:build integration`
- Use table-driven tests

### Table-Driven Tests

```go
func TestCapabilityMatch(t *testing.T) {
    tests := []struct {
        name    string
        pattern string
        cap     string
        want    bool
    }{
        {"exact match", "channel:send", "channel:send", true},
        {"glob match", "channel:*", "channel:send", true},
        {"no match", "channel:send", "tool:exec", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := matchCapability(tt.pattern, tt.cap)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

### Assertions

Use testify:

```go
assert.Equal(t, expected, got)
require.NoError(t, err)
assert.Contains(t, slice, element)
```

---

## Directory Structure

```text
api/                     # Protocol definitions
  proto/                 # Protobuf service definitions
    common/v1/           # Shared types
    plugin/v1/           # Plugin gRPC contracts
    sigil/v1/            # Gateway API types
  openapi/               # Generated OpenAPI specs
cmd/
  sigil/                 # Main binary entry point
  openapi-gen/           # OpenAPI spec generator
docs/
  design/                # Architecture design (12 sections, 00-11)
  decisions/             # Decision log, pre-release checklist
  plans/                 # Implementation plans
internal/
  agent/                 # Agent loop, session management
  config/                # Viper configuration
  gen/                   # Generated code (proto)
  identity/              # User identity and auth
  store/                 # Storage interfaces + factory + backends
    sqlite/              # SQLite implementations (default)
  memory/                # Tiered memory (FTS5, summaries, sqlite-vec)
  node/                  # Remote node management
  plugin/                # Plugin host
    goplugin/            # HashiCorp go-plugin integration
    sandbox/             # OS-level sandboxing (bwrap, sandbox-exec)
    wasm/                # Wazero Wasm runtime
  provider/              # LLM provider implementations
    anthropic/           # Built-in Anthropic provider
    google/              # Built-in Google provider
    openai/              # Built-in OpenAI provider
    openrouter/          # Built-in OpenRouter provider
  security/              # Capability enforcement, ABAC
  server/                # HTTP server (huma + chi)
  workspace/             # Workspace scoping
pkg/
  errors/                # Structured error codes (sigilerr)
  health/                # Shared health metrics types
  plugin/                # Public plugin SDK types
  types/                 # Shared value types (Origin, ScannerMode)
plugins/                 # First-party plugins
skills/                  # Built-in skills
scripts/                 # Build and utility scripts
site/                    # Documentation site (zensical)
ui/                      # SvelteKit web UI
```

### Dual Message Stores

There are TWO separate SQLite message stores with independent schemas:

| Store          | Table             | Purpose                                                    | Location                           |
| -------------- | ----------------- | ---------------------------------------------------------- | ---------------------------------- |
| `SessionStore` | `messages`        | Active session history (`AppendMessage`/`GetActiveWindow`) | `internal/store/sqlite/session.go` |
| `MessageStore` | `memory_messages` | FTS5 search + memory retrieval                             | `internal/store/sqlite/message.go` |

**MUST** update BOTH when adding/removing columns from message schema.

### Summary Store Two-Phase Commit

Summaries use a two-phase commit pattern: stored as `status='pending'`, promoted to `'committed'` via `SummaryStore.Confirm()` after all post-operations (embedding, vector store, message deletion) succeed. `GetByRange`/`GetLatest` filter `WHERE status = 'committed'` so incomplete compactions are invisible.

### Transactional Fact Persistence

`KnowledgeStore.PutFacts()` wraps all fact inserts in a single SQLite transaction for all-or-nothing semantics. The `storeFacts` method separates sanitization (first pass) from persistence (single `PutFacts` call) so no partial writes occur on validation failure.

### Shared Health Package

`pkg/health` defines `health.Metrics` — the canonical health snapshot struct used by both `internal/provider` and `internal/server`. The `internal/provider` package re-exports it via type alias: `type HealthMetrics = health.Metrics`. Do NOT add health-related fields to `server.ProviderHealthDetail` directly — embed `health.Metrics` instead.

---

## Security Principles

Security is Sigil's primary differentiator. All code MUST follow these principles:

| Principle              | Description                                                          |
| ---------------------- | -------------------------------------------------------------------- |
| Default deny           | Plugins have zero capabilities unless explicitly granted in manifest |
| Capability enforcement | Every plugin operation checked against manifest capabilities         |
| Agent loop integrity   | LLM outputs are validated before tool dispatch (7-step pipeline)     |
| Plugin isolation       | Execution tier determines sandbox boundary                           |
| No trust escalation    | A plugin cannot grant capabilities it doesn't have                   |

When implementing any plugin-facing API:

1. **MUST** check capabilities before executing
2. **MUST** validate all inputs from plugins (they are untrusted)
3. **MUST** audit security-relevant operations
4. **MUST NOT** pass raw LLM output to shell or system calls

---

## Plugin System

Four plugin types, all via gRPC (go-plugin):

| Type     | Purpose              | Example                            |
| -------- | -------------------- | ---------------------------------- |
| Provider | LLM integration      | Anthropic, OpenAI, Ollama          |
| Channel  | Messaging platform   | Telegram, WhatsApp, Discord        |
| Tool     | Agent capabilities   | File access, web search, code exec |
| Skill    | Structured workflows | Summarize, translate, analyze      |

Three execution tiers:

| Tier                | Isolation                             | Use Case                           |
| ------------------- | ------------------------------------- | ---------------------------------- |
| Wasm (Wazero)       | Memory-safe, no syscalls              | Lightweight pure-compute tools     |
| Process (go-plugin) | OS-level sandbox (bwrap/sandbox-exec) | Most plugins                       |
| Container (OCI)     | Full container isolation              | Untrusted or network-heavy plugins |

---

## Conventions Specific to Sigil

### Config

- Viper for configuration with YAML format
- Environment variable override: `SIGIL_<SECTION>_<KEY>`
- Example config: `sigil.yaml.example`

### Protobuf

- Definitions in `api/proto/`
- Generated Go code in `internal/gen/proto/`
- Use `buf` for generation: `task proto`
- **MUST NOT** edit generated `*.pb.go` files

### Commits

- Conventional commits enforced by Cocogitto (lefthook commit-msg hook)
- Format: `type(scope): description`
- Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert

---

## Key Design Docs

| Doc                | Path                                       | Covers                       |
| ------------------ | ------------------------------------------ | ---------------------------- |
| Overview           | `docs/design/00-overview.md`               | Goals, non-goals, prior art  |
| Core Architecture  | `docs/design/01-core-architecture.md`      | Layers, trust boundaries     |
| Plugin System      | `docs/design/02-plugin-system.md`          | Manifests, tiers, lifecycle  |
| Security Model     | `docs/design/03-security-model.md`         | ABAC, agent integrity        |
| Channel System     | `docs/design/04-channel-system.md`         | Channel plugins, pairing     |
| Workspaces         | `docs/design/05-workspace-system.md`       | Scoped contexts              |
| Nodes              | `docs/design/06-node-system.md`            | Remote devices, Tailscale    |
| Providers          | `docs/design/07-provider-system.md`        | LLM routing, budgets         |
| Agent Core         | `docs/design/08-agent-core.md`             | Agent loop, memory, skills   |
| UI & CLI           | `docs/design/09-ui-and-cli.md`             | SvelteKit, Tauri, Cobra      |
| Build              | `docs/design/10-build-and-distribution.md` | Toolchain, CI/CD             |
| Storage Interfaces | `docs/design/11-storage-interfaces.md`     | Store abstractions, backends |
| Decisions          | `docs/decisions/decision-log.md`           | All architectural decisions  |

<!-- BEGIN BEADS INTEGRATION -->

## Issue Tracking with bd (beads)

**IMPORTANT**: This project uses **bd (beads)** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other tracking methods.

The beads system-reminder hook injects full CLI reference into every session. Key commands:

| Command                                                                | Purpose              |
| ---------------------------------------------------------------------- | -------------------- |
| `bd ready`                                                             | Find unblocked work  |
| `bd show <id>`                                                         | View issue details   |
| `bd update <id> --status in_progress`                                  | Claim work           |
| `bd close <id>`                                                        | Complete work        |
| `bd create --title="..." --description="..." --type=task --priority=2` | New issue            |
| `bd dolt push`                                                         | Push beads to remote |

**Rules:** Use `bd` for ALL tracking. No markdown TODOs. Link discovered work with `--deps discovered-from:<id>`.

<!-- END BEADS INTEGRATION -->
