# Sigil — AI Agent Coding Guide

Instructions for AI coding assistants (Cursor, Copilot, Windsurf, Claude Code, etc.) working on Sigil.

## What Is Sigil?

A secure Go gateway connecting messaging platforms to AI agents via HashiCorp-style plugin isolation. Inspired by [OpenClaw](https://github.com/openclaw/openclaw).

**Key properties:** Go core, gRPC plugin system, capability-gated ABAC, SQLite per workspace, REST+SSE API, SvelteKit UI.

## Before You Start

1. Read the relevant design doc in `docs/design/` for the area you're working on
2. Check `docs/decisions/decision-log.md` for architectural decisions that may constrain your approach
3. Use `task` (Taskfile.dev) for all build/test/lint operations — never run Go commands directly

## Build Commands

```bash
task dev       # Run development mode
task build     # Build binary (requires CGO_ENABLED=1)
task test      # Run all tests
task lint      # Run all linters (golangci-lint, rumdl, yamlfmt)
task fmt       # Format all files (gofumpt, yamlfmt, dprint)
task proto     # Generate code from protobuf definitions
```

## Rules

### Must

- Use `task` for all build/test/lint/format operations
- Write tests before implementation (TDD)
- Run `task test` and `task lint` before claiming work is done
- Include SPDX license headers on all source files (`task license:add`)
- Use conventional commits: `type(scope): description`
- Follow existing code patterns and conventions
- Check capabilities before any plugin-facing operation
- Validate all plugin inputs (plugins are untrusted)
- Keep CGO_ENABLED=1 (required for sqlite3, sqlite-vec)

### Must Not

- Edit generated files (`*.pb.go`, `internal/gen/`)
- Disable linter rules without explicit approval
- Pass raw LLM output to shell or system calls
- Set CGO_ENABLED=0
- Skip tests or security checks for convenience

### Should

- Use table-driven tests
- Use structured logging (slog) with context
- Accept interfaces, return structs
- Prefer composition over inheritance
- Use context for cancellation and timeouts

## Project Structure

```
cmd/sigil/           → Main binary
api/proto/           → Protobuf definitions (buf generate)
api/openapi/         → Generated OpenAPI specs
internal/agent/      → Agent loop, sessions
internal/config/     → Viper configuration
internal/memory/     → Tiered memory (FTS5, summaries, sqlite-vec)
internal/plugin/     → Plugin host (goplugin/, sandbox/, wasm/)
internal/provider/   → LLM providers (anthropic/, google/, openai/)
internal/security/   → Capability enforcement, ABAC
internal/server/     → HTTP server (huma + chi)
internal/workspace/  → Workspace scoping
pkg/plugin/          → Public plugin SDK
plugins/             → First-party plugins
skills/              → Built-in skills
ui/                  → SvelteKit web UI
site/                → Documentation site (zensical)
docs/design/         → Architecture (11 sections)
docs/decisions/      → Decision log
docs/plans/          → Implementation plans
```

## Security Is the Primary Concern

Sigil's differentiator is its security model. Every plugin operation is capability-checked. The agent loop validates LLM outputs before dispatching to tools. Plugins run in sandboxed execution tiers (Wasm → Process with bwrap/sandbox-exec → Container).

When writing any code that touches plugins, the agent loop, or tool dispatch: assume all external input is hostile.

## Design Documents

Architecture is documented in `docs/design/00-overview.md` through `10-build-and-distribution.md`. Read the relevant section before modifying that area. Architectural decisions with rationale are in `docs/decisions/decision-log.md`.

## Toolchain

| Tool | Purpose |
|---|---|
| Taskfile.dev | Build orchestration |
| buf | Protobuf codegen |
| golangci-lint | Go linting |
| gofumpt | Go formatting |
| rumdl | Markdown linting |
| yamlfmt | YAML formatting |
| dprint | Multi-language formatting |
| lefthook | Git hooks |
| cocogitto | Conventional commit validation |
| GoReleaser | Release builds |
| release-please | Versioning and changelog |
| cosign | Binary signing |
