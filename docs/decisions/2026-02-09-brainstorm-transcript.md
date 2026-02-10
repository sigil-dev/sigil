# Brainstorm Transcript: Go-OpenClaw Architecture

**Date:** 2026-02-09
**Participants:** Sean (human), Claude Opus 4.6 (AI)
**Duration:** ~1 session
**Outcome:** Architecture design document (10 sections) + decision log (23 decisions)

---

## Context

Sean wants to fork [OpenClaw](https://github.com/openclaw/openclaw) -- a popular (180k stars) TypeScript personal AI assistant/gateway -- and rewrite the core in Go with a HashiCorp plugin system modeled after his [holomush](https://github.com/holomush/holomush) project.

## Research Phase

Two parallel research tasks were launched:

1. **HoloMUSH plugin architecture exploration** -- Revealed a clean dual-tier plugin system (Lua in-process + binary go-plugin), event-driven design, capability-based ABAC, protobuf contracts, and a public SDK.

2. **OpenClaw research** -- Revealed a TypeScript gateway-centric architecture with ~40k lines of code, connecting WhatsApp/Telegram/Discord/Slack/Signal/etc. to an embedded AI agent runtime. Key weaknesses identified: no plugin isolation, restart-to-reconfigure, flat trust model, Docker-only sandboxing.

## Discussion Flow

### 1. Primary Motivation

**Q:** What's the primary motivation for the rewrite?
**A:** All of the above (performance, plugin ecosystem, architectural control) plus:
- Security is paramount, especially around agentic corruption/hijacking
- Lightweight, easy to install
- Viper-based CLI, Taskfile.dev builds
- Best/highest quality dependencies

### 2. Channel Integration Strategy

**Q:** Go-native channels, channel plugins, or hybrid?
**A:** Channel plugins -- all channels are plugins via go-plugin.

Additional notes:
- OpenClaw's restart-to-reconfigure approach is terrible; we need hot-reload
- Take advantage of sandbox/containerized support for plugin execution

### 3. Agent Runtime Approach

**Q:** Agent-as-core, agent-as-plugin, or thin agent core + plugin tools?

Research into OpenClaw's current approach was conducted. Found:
- Agent loop deeply embedded in gateway
- Multi-layered tool policies but all in-process
- No plugin isolation (JS modules loaded via jiti)
- Hybrid hot-reload (config changes hot-reload, plugin changes require restart)
- Security is defense-in-depth but within a flat trust model

**A:** Thin agent core + plugin tools -- own the agent loop in Go for security, tools are the extensibility point.

### 4. LLM Provider Integration

**Q:** How to invoke LLMs?
**A:** Provider interface in Go core + built-in first-party providers. Study but don't delegate to agent SDKs (Claude Agent SDK, etc.) -- they'd cede control of the security-critical loop.

### 5. UI Technology

**A:** SvelteKit web UI + Tauri desktop app. Not headless-only.

### 6. UI-Gateway Protocol

**Q:** ConnectRPC between SvelteKit and Go server?
**A:** After discussing trade-offs (proto toolchain in frontend vs SvelteKit-idiomatic fetch), decided on REST+SSE for UI, gRPC for plugins. OpenAPI codegen for type safety.

### 7. Plugin Sandboxing

**Q:** Why not use bubblewrap/sandbox-exec like Anthropic's sandbox-runtime?
**A:** Yes -- adopt the srt approach for process-tier plugins. macOS gets sandbox-exec, Linux gets bubblewrap. Closes the network isolation gap without requiring containers. Implement as a Go library integrated with go-plugin.

### 8. Tailscale Integration

**Q:** Is there native Tailscale we can leverage?
**A:** Yes -- tsnet embeds a Tailscale node in the Go binary. Provides NAT traversal, auto TLS, MagicDNS, ACL enforcement. Opt-in via config.

**Q:** Should we require a tag for auto-auth?
**A:** Yes -- `tag:agent-node` required for nodes to auto-pair. Three-layer auth: Tailscale ACL + tag check + workspace binding.

### 9. Conversation Memory

**Q:** Can we optimize memory/chat history access?
**A:** Tiered memory model. Active window (last N messages) in context, older messages searchable via FTS5/sqlite-vec tools. Agent decides when to retrieve -- no automatic RAG injection.

### 10. Workspace Scoping

**Q:** Do we need topic scoping? (homelab group vs holomush group vs family group)
**A:** Workspaces -- scoped contexts with own sessions, tools, skills, members, channel bindings. Provides blast radius containment.

### 11. Skills Format

**A:** Follow agentskills.io open spec. Extensions in metadata namespace for spec compatibility.

### 12. Build Toolchain

**A:**
- CGo required (sqlite3, sqlite-vec)
- GoReleaser + release-please for releases
- Cocogitto for conventional commit validation
- Lefthook for git hooks
- Cosign + Syft for signing and SBOM
- Zensical for doc site
- rumdl replaces markdownlint (Rust binary, no Node.js dep)

Holomush patterns ported: goreleaser config (with CGo), lefthook config, cog.toml, Taskfile structure.

## Key Architectural Insights

1. **OpenClaw's biggest weakness is its flat trust model.** Plugins run in-process with full access. No capability gating. The fork's primary differentiator is security-first design.

2. **"Nodes are just remote plugin hosts"** reuses the entire plugin infrastructure (capability enforcement, audit logging, workspace scoping) without building a separate node protocol.

3. **The agent loop is where corruption happens.** Owning it in compiled Go with strict checks at every step (input scan, tool authorization, result scanning, output filtering) is the strongest security posture.

4. **SQLite-per-workspace** keeps everything self-contained. No external databases. Workspaces can be backed up, moved, or deleted independently.

5. **Process-tier sandboxing via bwrap/sandbox-exec** means most users never need Docker installed. The container tier becomes a niche concern for heavy/untrusted plugins.

### 13. Project Name

Three candidates evaluated: Talon, Sigil, Loom.

- **Talon** rejected: Talon Voice (voice coding tool) dominates the namespace, plus multiple other conflicts.
- **Loom** rejected: Atlassian's Loom video product is a household name.
- **Sigil** selected: Cleanest namespace, security connotation, `sigil-dev` org available on GitHub.

## Open Questions (for future sessions)
- ~~GitHub organization~~ -> `sigil-dev`
- ~~License choice~~ -> Apache 2.0
- V1 scope -- which channels and tools to ship first
- Plugin SDK for non-Go languages (TypeScript, Python) -- API design
- Authentication for the web UI itself
- Multi-gateway federation (future)
- Mobile app story (future)
