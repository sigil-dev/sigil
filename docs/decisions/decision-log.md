# Decision Log

Architectural decisions made during the 2026-02-09 brainstorming session.

## Format

Each decision records: the question, options considered, choice made, and rationale.

---

## D001: Core Language

**Question:** What language to rewrite the OpenClaw core in?

**Decision:** Go

**Rationale:** User preference. Go excels at gateway-pattern workloads (concurrent connections, low memory per goroutine). Enables single-binary distribution. Aligns with holomush experience and HashiCorp go-plugin.

---

## D002: Plugin Architecture

**Question:** How to structure the plugin system?

**Decision:** HashiCorp go-plugin with three execution tiers (Wasm, process, container)

**Options considered:**
- In-process plugins (like OpenClaw's TypeScript modules) -- rejected: no isolation
- go-plugin only (like holomush) -- too limited for untrusted plugins
- Container-only -- too heavy for simple tools

**Rationale:** Three tiers provide right-sized isolation. Wasm for lightweight, process for most plugins, container for untrusted/heavy plugins. go-plugin is proven in holomush.

---

## D003: Channel Integration Strategy

**Question:** How to integrate messaging platforms (Telegram, WhatsApp, etc.)?

**Options considered:**
- Go-native channels (Go libraries for each platform)
- Channel plugins (channels are plugins via go-plugin)
- Hybrid (core channels in Go, niche channels as plugins)

**Decision:** Channel plugins -- all channels are plugins

**Rationale:** Dogfoods the plugin system. Lets us use the best library per platform regardless of language (Node.js Baileys for WhatsApp, Go telebot for Telegram). Keeps core minimal.

---

## D004: Agent Runtime Approach

**Question:** Where does the AI agent loop live?

**Options considered:**
- Agent-as-core (embedded in gateway)
- Agent-as-plugin (agent runtime is a plugin)
- Thin agent core + plugin tools

**Decision:** Thin agent core + plugin tools

**Rationale:** The agent loop is where corruption happens. Owning it in compiled Go with strict capability checks is the strongest security posture. Tools are the extensibility point, not the loop itself.

---

## D005: LLM Provider Integration

**Question:** How to invoke LLMs from multiple providers?

**Options considered:**
- Direct provider SDKs in core
- Unified proxy (LiteLLM/OpenRouter)
- Provider-as-plugin interface
- Delegate to agent SDKs (Claude Agent SDK, etc.)

**Decision:** Provider interface in Go core + built-in first-party providers + plugin providers for exotic cases

**Rationale:** Built-in Anthropic/OpenAI/Google covers 90% of users with zero config. Plugin interface allows extending to anything. Delegating to external agent SDKs would cede control of the security-critical agent loop.

---

## D006: UI Technology

**Question:** What to build the web UI with?

**Decision:** SvelteKit web UI + Tauri v2 desktop wrapper

**Rationale:** SvelteKit for the web interface, Tauri bundles it as a native desktop app with the gateway binary as a sidecar. One UI codebase, two deployment targets.

---

## D007: UI-Gateway Protocol

**Question:** How should the SvelteKit UI communicate with the Go gateway?

**Options considered:**
- WebSocket (custom protocol)
- ConnectRPC (typed RPC, proto-based)
- REST + SSE (standard HTTP)
- REST + SSE + OpenAPI codegen

**Decision:** REST + SSE with OpenAPI spec generation

**Rationale:** ConnectRPC adds proto/buf complexity to the frontend build. SvelteKit's fetch-based data loading is naturally REST-friendly. OpenAPI spec generated from Go types (via huma) gives typed TypeScript clients without proto toolchain in the UI. gRPC stays internal (go-plugin).

---

## D008: Hot Reconfiguration

**Question:** How to avoid OpenClaw's restart-to-reconfigure problem?

**Decision:** Viper config watching + Plugin Manager hot-reload lifecycle

**Rationale:** Viper supports file watching natively. Plugin Manager drains in-flight requests, stops old instance, starts new, re-validates capabilities, routes traffic. No gateway restart. Active conversations queue during swap window.

---

## D009: Plugin Sandboxing (Process Tier)

**Question:** How to isolate process-tier plugins (go-plugin subprocess)?

**Options considered:**
- No isolation (like OpenClaw)
- Docker containers for everything
- OS-level sandboxing (bubblewrap/sandbox-exec)

**Decision:** OS-level sandboxing inspired by Anthropic's `sandbox-runtime` (srt)

**Rationale:** Lightweight, no container runtime dependency. macOS uses built-in sandbox-exec, Linux uses bubblewrap. Closes the network isolation gap in the process tier. Most users never need Docker installed.

---

## D010: Conversation Memory

**Question:** How to handle long conversation history efficiently?

**Decision:** Tiered memory model with agent-controlled retrieval

**Tiers:**
1. Active window (last N messages in LLM context)
2. Recent messages (SQLite FTS5, searchable)
3. Auto-generated summaries
4. Extracted knowledge/facts
5. Semantic search (sqlite-vec embeddings)

**Rationale:** Agent decides when to look up old context via memory tools rather than automatic RAG injection. Keeps context lean for simple exchanges, gives unlimited history access when needed. All embedded in SQLite -- no external databases.

---

## D011: Workspace Scoping

**Question:** How to scope conversations by topic/group?

**Decision:** Workspaces -- scoped contexts with own sessions, tools, skills, members, and channel bindings

**Rationale:** User has multiple use cases (homelab, holomush dev, family) that need different tools, skills, and access control. Workspaces provide blast radius containment -- corruption in one workspace cannot reach another's tools.

---

## D012: Node Networking

**Question:** How should remote nodes connect to the gateway?

**Decision:** Standard TCP/TLS (default) with optional Tailscale integration via tsnet

**Rationale:** Tailscale provides NAT traversal, auto TLS, MagicDNS, and ACL-governed connectivity. Tag-based auto-auth (`tag:agent-node`) eliminates manual token management. Opt-in keeps the project accessible to users without Tailscale.

---

## D013: Tailscale Tag-Based Auth

**Question:** Should nodes auto-authenticate via Tailscale?

**Decision:** Yes, with a required tag (`tag:agent-node`)

**Three-layer auth:**
1. Tailscale ACL -- can this device reach the gateway?
2. Tag check -- does it have `tag:agent-node`?
3. Workspace binding -- which workspaces can it access?

---

## D014: Skills Spec

**Question:** What format for agent skills?

**Decision:** agentskills.io open format with gateway-specific extensions in `metadata.*`

**Rationale:** agentskills.io is the emerging standard adopted by Claude Code, Cursor, Gemini CLI, and others. Our skills work everywhere; community skills work in our gateway. Extensions live in metadata to avoid spec conflicts.

---

## D015: CGo

**Question:** Pure Go or CGo?

**Decision:** CGo required

**Rationale:** SQLite3 and sqlite-vec require CGo. Accepted trade-off: complicates cross-compilation (use goreleaser-cross in CI) but enables embedded database without external dependencies.

---

## D016: Build System

**Decision:** Taskfile.dev

**Rationale:** User preference. Proven in holomush. YAML-based, simple, cross-platform.

---

## D017: Release Pipeline

**Decision:** GoReleaser + release-please + Cosign + Syft

**Rationale:** Proven in holomush. GoReleaser handles cross-compilation and Docker. Release-please handles versioning and changelog. Cosign provides keyless signing via GitHub OIDC. Syft generates dual-format SBOMs.

---

## D018: Conventional Commits

**Decision:** Cocogitto for commit message validation only

**Rationale:** Proven in holomush. Cocogitto validates conventional commit format. Release-please handles the actual versioning based on commit types. Clean separation of concerns.

---

## D019: Git Hooks

**Decision:** Lefthook

**Rationale:** Proven in holomush. Parallel pre-commit hooks, commit-msg validation via cog. Stage-fixed mode auto-adds formatting changes.

---

## D020: Markdown Linting

**Question:** Which markdown linter?

**Options considered:**
- markdownlint-cli2 (Node.js)
- dprint markdown plugin
- rumdl (Rust)

**Decision:** rumdl

**Rationale:** Rust binary, no Node.js dependency. Aligns with lightweight goal -- keeps Node.js scoped to SvelteKit UI development only.

---

## D021: Documentation Site

**Decision:** Zensical (Python, uv-managed)

**Rationale:** Proven in holomush. Simple TOML config, audience-based doc organization, auto-navigation from directory structure.

---

## D022: Database

**Decision:** SQLite (mattn/go-sqlite3) per workspace

**Rationale:** Embedded, zero-config, self-contained per workspace. FTS5 for text search, sqlite-vec for embeddings. No PostgreSQL/Redis required for core functionality. mattn/go-sqlite3 since CGo is already required.

---

## D024: License

**Decision:** Apache License 2.0

**Rationale:** Same license as holomush. Permissive, patent grant, compatible with most other open-source licenses. Standard for infrastructure Go projects (Kubernetes, Terraform, etc.).

---

## D025: Project Name

**Question:** What to name the project?

**Options considered:**
- Talon -- spiritual successor to "claw". Rejected: Talon Voice (voice coding tool) dominates the namespace. Multiple other conflicts (mailgun/talon, optiv/Talon).
- Loom -- weaves things together. Rejected: Atlassian's Loom video product is a household name in dev tools.
- Sigil -- protective mark, seal of authority.

**Decision:** Sigil

**GitHub org:** `sigil-dev`
**Repo:** `sigil-dev/sigil`
**CLI binary:** `sigil`
**Go module:** `github.com/sigil-dev/sigil`

**Rationale:** Cleanest namespace. Only notable conflict is Sigil-Ebook (EPUB editor, completely different domain). Strong security connotation aligns with the project's primary differentiator. Short, memorable, good CLI ergonomics.

---

## D023: HTTP Framework

**Decision:** huma (on chi router)

**Rationale:** Generates OpenAPI 3.1 spec from Go struct types. Request validation against spec at runtime. Works with any Go router. One source of truth for API types.

---

## D026: OpenClaw Attribution

**Decision:** Acknowledge OpenClaw as inspiration with NOTICE file and design doc references

**Rationale:** Sigil is inspired by OpenClaw's concepts but is an independent Go reimplementation, not a code fork. Apache 2.0 NOTICE file provides proper attribution. Design overview acknowledges OpenClaw's community. We respect OpenClaw's work and want to play nice with their ecosystem — complementary projects, not competitors.

**Pre-release gate:** See [pre-release-checklist.md](pre-release-checklist.md) — ALL items MUST be completed before any public release.

---

## D027: Storage Interface Architecture

**Question:** Should storage be hardcoded to SQLite or abstracted behind interfaces?

**Options considered:**

- SQLite-everything (original design) — simple, one technology, one backup strategy
- Interface-based with factory pattern — backends swappable via config
- Registry pattern (like database/sql) — extensible but heavier than needed

**Decision:** Interface-based storage with config-driven factory. Four top-level interfaces grouped by concern:

1. `SessionStore` — sessions and active message windows (per workspace)
2. `MemoryStore` — tiered memory with composable sub-interfaces (per workspace)
3. `VectorStore` — embedding storage and similarity search (per workspace)
4. `GatewayStore` — users, pairings, audit log (global)

Factory reads `storage.*` config, creates the right backend. Callers import only `internal/store`.

**Rationale:** The tiered memory model has natural upgrade paths — LanceDB for vectors (Tier 4), graph databases for knowledge (Tier 3). Defining interfaces now lets initial implementation use SQLite everywhere while keeping the door open for purpose-built backends. The factory pattern is sufficient for a known set of backends; registry pattern can be added later if needed.

**Design doc:** [docs/design/11-storage-interfaces.md](../design/11-storage-interfaces.md)

---

## D028: KnowledgeStore Graph Semantics

**Question:** How should the KnowledgeStore interface support both relational and graph backends?

**Decision:** KnowledgeStore is a composable sub-interface of MemoryStore, independently swappable via `storage.memory.knowledge.backend` config. The interface uses graph-friendly semantics (entities, relationships, facts, traversal) that map to both models:

- **SQLite backend:** RDF triple model (subject-predicate-object) in a single `triples` table with SPO/POS/OSP indexes. Traversal via recursive CTEs.
- **Graph backend (LadybugDB):** Native property graph with Cypher queries. Direct mapping from interface methods to graph operations.

**Rationale:** RDF triples are the simplest correct way to represent graph data in a relational database. Three covering indexes enable efficient lookups in any direction. The entity/relationship/fact API maps naturally to both property graphs and triple stores without leaking backend-specific semantics.

---

## D029: Future Backend Candidates

**Question:** Which alternative storage backends should the interface architecture support?

**Decision:** Two candidates identified, neither adopted yet:

| Backend | Replaces | Language | Go SDK Status (early 2026) | License |
|---------|----------|----------|---------------------------|---------|
| LanceDB | VectorStore (sqlite-vec) | Rust | v0.1.2 (pre-1.0, not production-ready) | Apache 2.0 |
| LadybugDB | KnowledgeStore (SQLite RDF) | C++ (fork of KuzuDB) | Moderate maturity, active development | MIT |

**Rationale:** Both are embedded (no server), both are Apache 2.0/MIT compatible, both add CGo dependencies (already required). However:

- LanceDB Go SDK hasn't reached 1.0; sqlite-vec is more mature today
- LadybugDB is a community fork after Kùzu Inc. abandoned KuzuDB (Oct 2025); fork stability uncertain

The interface-first approach means we can adopt either when their Go SDKs stabilize without changing any caller code. Monitor progress and add implementations when ready.

---

## D030: Expand Go UserIdentity to Match Proto

**Question:** Proto `UserIdentity` has 4 fields (`user_id`, `platform`, `platform_user_id`, `display_name`) while the Go store type has 2 (`Channel`, `PlatformID`). Should the Go type be kept minimal or expanded?

**Decision:** Expand Go `UserIdentity` to match proto with all 4 fields: `UserID`, `Platform` (renamed from `Channel`), `PlatformID`, `DisplayName`.

**Rationale:** The store type is the internal representation that maps to the proto wire format. Keeping them aligned avoids lossy conversions and simplifies the mapping layer. The additional fields (`UserID` for Sigil's internal identity, `DisplayName` for human-readable context) are needed for proper user management.

**Ref:** PR #5 review finding 12, bead `sigil-fuw.25`

---

## D031: Add Manifest.Validate() as Security Boundary

**Question:** Should the plugin Manifest type have a `Validate()` method?

**Decision:** Yes. Add `Validate()` to `pkg/plugin/types.go` `Manifest` to enforce security invariants at the SDK level.

**Rationale:** The Manifest is the security boundary for capability grants (design doc §3). Default deny means every capability must be explicitly declared and well-formed. Validation catches malformed manifests before they enter the system: empty names, invalid semver versions, unknown plugin types, malformed capability glob patterns, and invalid execution tiers.

**Ref:** PR #5 review suggestion 1, bead `sigil-fuw.26`

---

## D032: Store Package Owns Canonical MessageRole Type

**Question:** Both `internal/store/types.go` and `internal/provider/provider.go` define an identical `MessageRole` type. Which package should own the canonical definition?

**Decision:** `internal/store` owns `MessageRole`. The `provider` package imports from `store`.

**Rationale:** The store package is more foundational — messages are persisted with roles, and all consumers (providers, agents, API layer) read from the store. Having providers import from store follows the dependency direction (higher-level imports lower-level). The proto definitions remain the source of truth for wire format.

**Ref:** PR #5 review suggestion 3, bead `sigil-fuw.29`

---

## D033: Config Validates at Load Time (Fail-Fast)

**Question:** Should configuration be validated at load time or lazily when values are used?

**Decision:** Fail-fast. `config.Load()` calls `Validate()` and returns an error for invalid configurations.

**Rationale:** Late validation produces confusing errors deep in startup or at runtime. Fail-fast at load time gives clear, actionable error messages before any side effects. This is consistent with the security-first design — invalid configuration should never reach the runtime.

**Ref:** PR #5 review suggestion 5, bead `sigil-fuw.31`
