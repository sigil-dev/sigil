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

| Backend   | Replaces                    | Language             | Go SDK Status (early 2026)             | License    |
| --------- | --------------------------- | -------------------- | -------------------------------------- | ---------- |
| LanceDB   | VectorStore (sqlite-vec)    | Rust                 | v0.1.2 (pre-1.0, not production-ready) | Apache 2.0 |
| LadybugDB | KnowledgeStore (SQLite RDF) | C++ (fork of KuzuDB) | Moderate maturity, active development  | MIT        |

**Rationale:** Both are embedded (no server), both are Apache 2.0/MIT compatible, both add CGo dependencies (already required). However:

- LanceDB Go SDK hasn't reached 1.0; sqlite-vec is more mature today
- LadybugDB is a community fork after Kùzu Inc. abandoned KuzuDB (Oct 2025); fork stability uncertain

The interface-first approach means we can adopt either when their Go SDKs stabilize without changing any caller code. Monitor progress and add implementations when ready.

---

## D030: Expand Go UserIdentity to Match Proto

**Question:** Proto `UserIdentity` has 4 fields (`user_id`, `platform`, `platform_user_id`, `display_name`) while the Go store type has 2 (`Channel`, `PlatformID`). Should the Go type be kept minimal or expanded?

**Decision:** Expand Go `UserIdentity` to match proto with all 4 fields: `UserID`, `Platform` (renamed from `Channel`), `PlatformUserID` (renamed from `PlatformID` to match proto `platform_user_id`), `DisplayName`.

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

---

## D034: Standardize Structured Errors on pkg/errors + samber/oops

**Question:** How should Sigil represent and classify runtime errors across packages and API boundaries?

**Decision:** Use `pkg/errors` as the stable public error API, implemented on top of `samber/oops`, and replace production `fmt.Errorf` call sites with typed error codes.

**Rationale:** A shared, code-first taxonomy improves observability and client behavior consistency while preserving wrapped causes for `errors.Is` checks. `pkg/errors` provides machine-readable codes (for example `store.entity.get.not_found`), structured fields, classification helpers, and HTTP-status mapping. This establishes a stable contract for internal services and plugin-facing surfaces while keeping contextual debugging data in the wrapped error chain.

**Ref:** bead `sigil-fuw.37`

---

## D035: Wasm Execution Bounding — Context Timeout over Fuel Metering

**Question:** How should the Wasm execution tier bound plugin execution? The spec called for instruction-level fuel metering, but Wazero doesn't support it natively.

**Options considered:**

- Wasmtime-go (CGO, native fuel metering) — rejected: no precompiled arm64/darwin binaries, adds CI build complexity
- Wasmer-go (CGO) — rejected: unmaintained since 2021, incomplete arm64/darwin support
- Wasm bytecode injection (go-wasm-metering) — rejected: abandoned project (2019), instruction-level billing unnecessary for gateway plugins
- Keep Wazero + context-based timeout — chosen

**Decision:** Keep Wazero. Use `context.WithTimeout` + `WithCloseOnContextDone(true)` instead of fuel metering. Replace `WithFuelLimit`/`FuelLimit` with `WithExecTimeout`/`ExecTimeout`.

**Rationale:** Sigil already requires CGO for sqlite3/sqlite-vec, but the CGO Wasm runtimes have significant build-chain problems. More importantly, Sigil plugins aren't smart contracts — the security goal is bounding runaway execution, not deterministic per-instruction billing. Context timeout is idiomatic Go, zero new dependencies, and Wazero supports it natively. Wazero's pure-Go nature remains valuable for cross-platform builds even though CGO is already required for other dependencies.

**Ref:** bead `sigil-anm.10`, design `docs/plans/2026-02-11-wasm-timeout-design.md`

---

## D036: Provider Failover — First-Event Only, Not Mid-Stream

**Question:** Should provider failover retry on mid-stream failures, or only on initial connection/first-event failures?

**Options considered:**

- Full mid-stream retry (buffer all events, replay conversation to fallback) — deferred: requires buffering entire stream, resending all messages to new provider, handling partial-output ambiguity (user may have already seen partial text). Significant complexity.
- First-event-only retry (current) — chosen: catches auth errors, rate limits, and provider-down scenarios which are the most common failure modes. Clean and predictable.
- No retry (fail immediately) — rejected: too brittle for multi-provider deployments.

**Decision:** Failover retries on first-event failures only. Mid-stream failures surface to the caller as errors. Full mid-stream retry deferred as future work.

**Rationale:** Most provider failures manifest immediately (auth, rate limit, 503). Mid-stream failures (network drop, timeout) are rare and would require fundamentally different architecture — buffering all events, managing partial output state, and replaying the full conversation. The complexity cost doesn't justify the edge case coverage at this stage.

**Ref:** PR #12 review finding 4, bead `sigil-dxw`

---

## D037: User-Scoped Personal Workspace Fallback

**Question:** Should unbound channels route to a shared `"personal"` workspace or a user-scoped `"personal:<userID>"` workspace?

**Options considered:**

- Shared `"personal"` workspace (original spec) — all users share the same fallback workspace. Simple but leaks context between users and provides no isolation.
- User-scoped `"personal:<userID>"` (chosen) — each user gets their own isolated fallback workspace with implied membership.

**Decision:** Unbound channels route to `personal:<userID>`. Design docs and plan updated to match.

**Rationale:** A shared personal workspace is a security and privacy concern — users would see each other's conversation history and tool outputs. User-scoped workspaces provide proper isolation with minimal additional complexity. Membership is implied since the workspace belongs to the user.

**Ref:** PR #12 review round 5 finding 4, bead `sigil-0cs`

## D038: Tool Capability Dot Namespace

**Question:** Should runtime tool capability checks use colon (`tool:name`) or dot (`tool.name`) as the namespace separator?

**Options considered:**

- Colon-separated `tool:<name>` — used in initial implementation, but colons are rejected by manifest `capPatternRe` validation (`^[a-zA-Z0-9.*_\-/]+$`), breaking least-privilege enforcement for non-wildcard grants.
- Dot-separated `tool.<name>` (chosen) — consistent with existing `MatchCapability` dot-segment matching and the design docs' capability namespace convention.

**Decision:** Runtime tool capability checks use `tool.<name>`. Manifest validation, `MatchCapability`, and the enforcer all operate on dot-segmented namespaces consistently.

**Rationale:** The colon separator was an implementation artifact that conflicted with the validation regex. Aligning on dot namespaces means `tool.search`, `tool.*`, and `tool.web_search` all pass manifest validation and match correctly at runtime without requiring wildcard grants.

**Ref:** PR #12 review round 6 finding 1

## D039: Identity Resolver User-Scoped Pairing Verification

**Superseded by D042.** Pairing was fully removed from the identity resolver.

**Original decision:** Resolver used `GetByUser(user.ID)` and filtered for matching `channelType` + active status. This was superseded in round 7 when pairing enforcement moved entirely to `ChannelRouter.AuthorizeInbound()`, making the resolver a pure identity lookup.

**Ref:** PR #12 review round 6 finding 2, superseded by round 7 finding 1

## D040: Tool Loop Iteration Limit Returns Error

**Question:** Should the tool loop return success or an error when it exhausts its iteration limit with tool calls still pending?

**Decision:** The tool loop now returns `CodeAgentLoopFailure` when `maxToolLoopIterations` is reached with unresolved tool calls, instead of silently returning success.

**Rationale:** Returning success with incomplete orchestration is misleading and diverges from the design intent ("continue until done or limit hit"). An explicit error lets callers distinguish between clean completion and truncated execution.

**Ref:** PR #12 review round 6 finding 3, `docs/design/08-agent-core.md` §Multi-Turn Tool Orchestration

## D041: Temperature Zero via Pointer Type

**Question:** How should providers handle `temperature=0` (deterministic) when the Go zero value for `float32` is also `0`?

**Decision:** `ChatOptions.Temperature` is now `*float32`. A nil pointer means "not set" (use provider default); a non-nil pointer sends the exact value, including `0`.

**Rationale:** The previous `> 0` guard silently dropped `temperature=0`, making deterministic output impossible. The pointer type is the standard Go idiom for optional numeric fields and matches the pattern used by the Anthropic, OpenAI, and Google SDKs themselves.

**Ref:** PR #12 review round 6 finding 4

## D042: Channel-Level Pairing Enforcement (Moved from Identity Resolver)

**Question:** Should pairing verification live in the identity resolver or the channel router?

**Options considered:**

- Keep pairing in identity resolver, pass channel mode — simple but muddies identity/authorization boundary. Every identity lookup requires pairing state, even for open channels.
- Move to channel router (chosen) — channel router knows the pairing mode per-channel and can skip pairing for open channels. Resolver becomes a pure identity lookup. Pairing is scoped to specific channel instances (channelType + channelID), not just channel type.

**Decision:** Pairing enforcement moved from `identity.Resolver` to `plugin.ChannelRouter.AuthorizeInbound()`. The resolver now performs only user identity lookup. The channel router applies mode-aware authorization: open channels skip pairing entirely, closed channels deny all, allowlist channels check membership + active pairing for the specific channel instance.

**Rationale:** Identity resolution (who is this user?) and channel authorization (can this user interact here?) are separate concerns. Mixing them caused three bugs: (1) open-mode channels couldn't allow unpaired users, (2) a pairing on one channel of a type (e.g., Telegram bot A) could satisfy checks for a different channel of the same type (bot B), (3) the resolver required `PairingStore` even when the channel mode made pairing irrelevant.

**Ref:** PR #12 review round 7 finding 1

## D043: Pre-Stream Chat Failure Health Reporting via HealthReporter Interface

**Question:** How should the agent loop mark providers unhealthy when `Chat()` returns an error before creating a stream?

**Options considered:**

- Add `RecordFailure()` to the `Provider` interface — breaks the interface for all implementors including plugin providers.
- Optional `HealthReporter` interface (chosen) — providers that embed `HealthTracker` implement the interface. The agent loop type-asserts and calls `RecordFailure()`. Non-implementing providers (e.g., future plugin providers) degrade gracefully.
- Per-attempt exclusion set in `Route()` — more explicit but requires `Router` interface changes and duplicates the circuit-breaker logic already in `HealthTracker`.

**Decision:** Added `provider.HealthReporter` interface (`RecordFailure()`, `RecordSuccess()`). All 4 built-in providers implement it. On pre-stream `Chat()` errors, `callLLM` calls `RecordFailure()` via type assertion. The existing `HealthTracker` cooldown (30s) acts as a circuit breaker with automatic half-open recovery.

**Rationale:** In-stream errors already triggered `RecordFailure()` (via the streaming goroutine), but pre-stream errors bypassed it because the goroutine never started. This caused failover retries to keep selecting the same broken primary provider. The optional interface pattern preserves backward compatibility while closing the health tracking gap.

**Ref:** PR #12 review round 7 finding 2

## D044: Tool Definitions Sent to Providers

**Question:** How should the agent loop provide tool schemas (names, parameters) to LLM providers for function-calling?

**Decision:** `ToolRegistry` extended with `GetToolDefinitions() []provider.ToolDefinition`. Each `Register()` call now accepts a `provider.ToolDefinition` alongside the plugin name. The agent loop populates `ChatRequest.Tools` from the registry before calling the provider.

**Rationale:** Without tool definitions in the `ChatRequest`, providers had no tool schemas to present to the LLM, so the model could never generate tool calls. The registry is the natural home for this data since it already maps tool names to plugins.

**Ref:** PR #12 review round 8 finding 1

## D045: Workspace-Scoped Pairing Authorization

**Question:** Should `AuthorizeInbound` check workspace scope when verifying pairings?

**Decision:** `AuthorizeInbound` now requires a `workspaceID` parameter and checks that the pairing matches the specific workspace in addition to channel type, channel ID, and active status.

**Rationale:** Without workspace scoping, a pairing on workspace A could authorize access to workspace B through the same channel, violating workspace isolation boundaries.

**Ref:** PR #12 review round 8 finding 2

## D046: Config Schema — Workspace Bindings and Tool Deny Rules

**Question:** Should the config schema include `bindings` and `deny` fields that the design docs and example config reference?

**Decision:** Added `Bindings []BindingConfig` to `WorkspaceConfig` and `Deny []string` to `ToolsConfig`. These fields were already described in the design docs and example config but missing from the Go structs, causing silent ignore on parse.

**Rationale:** The schema should match what users can configure. Missing struct fields meant valid YAML was silently dropped by Viper unmarshalling.

**Ref:** PR #12 review round 8 finding 3

## D047: Per-Attempt Provider Exclusion in RouteWithBudget

**Question:** How should failover avoid re-selecting a provider that already failed in the current turn?

**Decision:** `RouteWithBudget` accepts an `exclude []string` parameter. The agent loop tracks provider names across retry attempts and passes them to the router, which skips excluded providers in both primary and failover selection.

**Rationale:** The `HealthReporter` circuit breaker operates on a 30s cooldown window — too coarse for within-turn retries. A provider that fails on attempt 1 stays "available" to the health check and gets re-selected on attempt 2. The exclusion list ensures deterministic failover progression without requiring all providers to implement `HealthReporter`.

**Ref:** PR #12 review round 8 finding 4

---

## D048: Config File Auto-Discovery

**Question:** Should the CLI require `--config` to load a config file, or auto-discover from standard locations?

**Options considered:**

- Explicit only (`--config` required) — original implementation. Simple but diverges from the design doc's "standard precedence" (flag > env > file > defaults) which implies automatic file discovery.
- Auto-discovery with standard paths (chosen) — search `.`, `$HOME/.config/sigil/`, `/etc/sigil/` for `sigil.yaml`. Missing file is silently ignored.
- Auto-discovery with XDG_CONFIG_HOME — more correct on Linux but adds complexity for a single search path.

**Decision:** Auto-discover `sigil.yaml` from `.`, `$HOME/.config/sigil/`, `/etc/sigil/` when `--config` is not explicitly provided. Missing file is silently ignored — defaults and environment variables still apply. Explicit `--config` takes full priority.

**Rationale:** The design doc (§9 CLI, Viper Config Resolution) specifies "Config file (`sigil.yaml`)" as tier 3 in the precedence chain, implying automatic loading. Requiring `--config` for every invocation would break the expected ergonomics of `sigil start` with a config file in the current directory. The three search paths follow common Go CLI conventions (Viper, Cobra ecosystem).

**Ref:** PR #13 review round 4, `docs/design/09-ui-and-cli.md`

---

## D049: Auth Middleware — Stub Now, Full ABAC Deferred

**Question:** REST endpoints lack authentication and ABAC enforcement. Should the security model be implemented in the Phase 5 CLI PR, or deferred?

**Options considered:**

- Full ABAC in Phase 5 — rejected: scope creep; the security model depends on identity resolution, workspace membership, and capability enforcement which are separate subsystems.
- No auth at all — rejected: leaves no extension point for future auth integration and doesn't acknowledge the gap.
- Pass-through stub middleware (chosen) — wires `authMiddleware` into the chi stack now, logs requests at debug level, passes everything through. Full implementation tracked separately.

**Decision:** Add a pass-through `authMiddleware` stub wired into the chi middleware stack. Full token validation and ABAC capability checks deferred to the security phase (tracked in `sigil-9s6`).

**Rationale:** The middleware stub establishes the extension point in the correct position in the middleware chain (after CORS, before route handlers). When real auth is implemented, it replaces the stub body without changing the server wiring. The default binding to `127.0.0.1` provides the baseline security boundary until proper auth is added.

**Ref:** PR #13 review round 4, `sigil-9s6`, `docs/design/03-security-model.md`

---

## D050: ErrNotFound Sentinel for REST Error Differentiation

> **Superseded by D054.** The sentinel pattern described below was replaced with `sigilerr.CodeServerEntityNotFound` + `server.IsNotFound()` in PR #13 round 6. See D054 for current approach.

**Question:** How should REST GET handlers distinguish "entity not found" (404) from internal errors (500)?

**Options considered:**

- String matching on error messages — fragile, breaks when error messages change.
- Custom error types with interface assertion — more complex than needed for a single distinction.
- Sentinel error with `errors.Is()` (chosen) — idiomatic Go, simple, extensible.

**Decision:** ~~All service implementations wrap not-found errors with `server.ErrNotFound` sentinel. GET handlers use `errors.Is(err, ErrNotFound)` to return 404; all other errors return 500.~~ Superseded — see D054.

**Rationale:** Mapping all service errors to 404 (the original behavior) masks internal failures — a database connection error would appear as "not found" to the client, making debugging impossible. This rationale still applies; only the mechanism changed.

**Ref:** PR #13 review round 4

## D051: Phase 5 CLI Scope — List-Only Subcommands, CRUD Deferred

**Question:** Phase 5 plan specifies full CRUD subcommands (workspace create/delete/show, plugin install/remove/reload/inspect/logs, session show/archive/export) and full doctor diagnostics, but the implementation provides only `list` subcommands and stubs. Should the plan be updated or the commands implemented?

**Decision:** Keep the plan as-is (plans are not retroactively edited). The implementation correctly follows the design doc scope (design/09-ui-and-cli.md) which explicitly limits Phase 5 to: `start`, `status`, `version`, `workspace list`, `plugin list`, `session list`, `chat` (stub), `doctor` (stub). Full CRUD and doctor diagnostics are deferred to Phase 6 (Advanced Features), tracked in `sigil-n6m`.

**Rationale:** The design doc is the authoritative scope definition. The plan document described the full target state; the design doc subsequently narrowed Phase 5 scope. Changing plans retroactively obscures the original intent. Documenting the deferral here maintains traceability.

**Ref:** PR #13 review round 5

## D052: Status Command Calls /api/v1/status, Not /health

**Question:** Phase 5 plan says `sigil status` calls `/health`, but the implementation calls `/api/v1/status`. Which endpoint should the CLI use?

**Decision:** Keep `/api/v1/status`. The plan is not retroactively edited; this deviation is documented here.

**Rationale:** `/health` is a minimal liveness probe (returns 200 OK with no payload) intended for load balancers and orchestrators. `/api/v1/status` is the designated gateway status endpoint for CLI and operator use. In Phase 5 it returns `{"status": "ok"}` as a stub; future phases will enrich the response with version, uptime, and component health per the design doc. The endpoint choice is correct even though the response is not yet enriched — the CLI is wired to the right path for when richer data is added.

**Ref:** PR #13 review round 5

## D053: Doctor Command — Stub in Phase 5, Full Diagnostics Deferred

**Question:** The design doc's "Doctor Command" section describes full diagnostics (binary health, plugin processes, provider API keys, channel connections, node connectivity, disk space, Tailscale status), but Phase 5 implements only a stub. Should the design doc clarify this phasing?

**Decision:** The design doc describes the complete target state, not per-phase scope. Phase 5 delivers `doctor` as a registered command with placeholder output. Full diagnostic checks are deferred to Phase 6 alongside the remaining CLI commands, tracked in `sigil-n6m`. The design doc is not modified; this decision documents the phased rollout.

**Rationale:** Design docs describe what the system will eventually do. Phase scoping is handled in plan docs and decision log entries. Adding phase annotations to every design doc section would create maintenance burden and clutter the architectural narrative.

**Ref:** PR #13 review round 5

## D054: Replace Error Sentinels with sigilerr Structured Error Codes

**Question:** D050 introduced `server.ErrNotFound` as a sentinel checked via `errors.Is()`. The rest of the codebase uses `sigilerr` structured error codes with `sigilerr.HasCode()`. Should the server layer follow the same pattern?

**Decision:** Replace `server.ErrNotFound` sentinel with `sigilerr.CodeServerEntityNotFound`. Route handlers use `server.IsNotFound(err)` (which calls `sigilerr.HasCode`) instead of `errors.Is(err, ErrNotFound)`. Service adapters return `sigilerr.Errorf(sigilerr.CodeServerEntityNotFound, ...)`. The plugin adapter translates `CodePluginNotFound` → `CodeServerEntityNotFound` at the boundary.

**Rationale:** Using two error classification mechanisms (sentinels + error codes) in the same codebase creates translation gaps at boundaries. The plugin manager returned `CodePluginNotFound` but the server expected a sentinel, so adapters had to bridge them manually — and the initial implementation missed this, causing 404s to surface as 500s. A single mechanism (`sigilerr.HasCode`) eliminates this class of bug. Supersedes D050.

**Ref:** PR #13 review round 6

## D055: Session List Returns Empty Array in Phase 5

**Question:** `sessionServiceAdapter.List` returns an empty array and nil error. Should it return a "not implemented" error instead, or is the empty array acceptable?

**Decision:** Return empty array. This is semantically correct — there are zero sessions because the agent loop is not yet wired. The adapter comment documents the deferral. An empty list is not misleading; it accurately reflects the system state in Phase 5.

**Rationale:** Returning an error would break the API contract (`GET /api/v1/workspaces/{id}/sessions` should return a list, possibly empty). Clients consuming the API would need special "not implemented" error handling that adds no value and would be removed when sessions are wired in a later phase. The in-code comment in `wire.go` plus this decision provide sufficient documentation.

**Ref:** PR #13 review round 7

## D056: Mandate sigilerr Structured Errors for All Production Code

**Question:** The codebase has ~67 remaining `fmt.Errorf`/`errors.New` sites in production code alongside ~284 `sigilerr` sites. Should we mandate structured errors everywhere?

**Decision:** Yes. All production Go code (excluding generated code in `internal/gen/`) MUST use `sigilerr` for error creation. Specifically:

- **MUST** use `sigilerr.Errorf`, `sigilerr.New`, `sigilerr.Wrap`, or `sigilerr.Wrapf` instead of `fmt.Errorf` or `errors.New`.
- **MUST** use `sigilerr.HasCode` for error classification instead of `errors.Is` with sentinels.
- **MUST** assign an appropriate error code from `pkg/errors` for every error site.
- **SHOULD** add new error codes to `pkg/errors/errors.go` when no existing code fits.
- **MAY** use `fmt.Errorf` in test files for creating mock/stub errors that don't participate in error classification.
- Existing sentinel vars (e.g., `store.ErrNotFound`, `store.ErrConflict`) will be replaced with `IsXxx()` helpers using `sigilerr.HasCode`, following the pattern established in D054.

**Rationale:** Mixed error patterns create translation gaps at subsystem boundaries (demonstrated by the 404→500 bug in PR #13). Structured errors provide machine-readable codes, structured context (via `sigilerr.Field`), and consistent classification. The `samber/oops` foundation already supports all needed patterns. A single error mechanism across the codebase eliminates an entire class of boundary bugs and enables future error reporting/observability.

**Migration tracked in:** sigil-c99

**Ref:** PR #13 review round 7

## D057: Startup Graceful Degradation — Non-Fatal Plugin Discovery and Provider Registration

**Question:** Should the gateway fail to start if plugin discovery errors occur or if a configured provider cannot be created?

**Options considered:**

- Fail-fast on any error — rejected: prevents the gateway from starting when a single provider has a bad API key or the plugins directory is missing. Too brittle for operator experience.
- Silent ignore — rejected: operators would have no visibility into misconfiguration.
- Warn and continue (chosen) — log warnings for each failure, continue startup with whatever succeeded.

**Decision:** Plugin discovery errors and provider registration failures (empty API keys, unknown provider names, constructor errors) are logged as warnings and skipped. Neither is fatal. The gateway starts with whatever plugins and providers succeed.

**Rationale:** The gateway should be resilient to partial misconfiguration. An operator who configures three providers but has one typo should still get the other two working. The structured slog warnings provide clear diagnostics without blocking the entire startup. This is consistent with D033 (config validation fails fast) — config _structure_ is validated strictly at load time, but _runtime initialization_ of optional subsystems degrades gracefully.

**Ref:** PR #14, `cmd/sigil/wire.go`

## D058: Provider Factory Map for Constructor Testability

**Question:** How should provider construction be structured to allow testing the creation failure path?

**Options considered:**

- Direct switch/case (original) — clean but the error path is unreachable in tests because all current constructors only fail on empty API keys, which are pre-filtered.
- Accept constructor functions as parameters — more functional but changes the call signature at every call site.
- Package-level factory map (chosen) — `builtinProviderFactories` maps provider names to constructors. Tests can temporarily replace entries to inject failures.

**Decision:** Extract the switch/case into a `var builtinProviderFactories map[string]providerFactory`. The `registerBuiltinProviders` function looks up constructors from this map. Tests override entries to inject failing factories via `t.Cleanup` restoration.

**Rationale:** The provider creation error path (`wire.go:180-183`) is a defensive guard — all current constructors succeed with non-empty API keys. But future providers may have richer validation. The factory map makes this path testable without changing the public API or over-engineering the function signature. The pattern is local to `cmd/sigil` and doesn't leak into the provider packages.

**Ref:** PR #14 review, `cmd/sigil/wire.go`, `cmd/sigil/wire_test.go`

---

## D059: Auth Middleware — Bearer Token Validation (Supersedes D049)

> **Supersedes D049.** The pass-through stub described in D049 has been replaced with full bearer token validation.

**Question:** D049 deferred auth to a security phase, but `sigil-9s6` tracked implementing bearer token validation. Should this be done in the Phase 5 PR or remain a stub?

**Options considered:**

- Keep stub, defer to dedicated security PR — rejected: the `TokenValidator` interface and middleware are clean, self-contained, and already have comprehensive tests. Deferring adds unnecessary delay.
- Full ABAC with capability checks — rejected: still too early. Identity resolution, workspace membership, and capability enforcement remain separate subsystems.
- Bearer token validation with dev-mode bypass (chosen) — implements `TokenValidator` interface with config-backed static tokens. Public paths (`/health`, `/openapi.*`) bypass auth. When no tokens are configured, auth is disabled (dev mode).

**Decision:** Replace the D049 pass-through stub with bearer token validation via a `TokenValidator` interface. The middleware validates `Authorization: Bearer <token>` headers, returns 401 for missing/invalid tokens and 403 for forbidden access. User context is injected via `UserFromContext`. Dev mode (nil validator) preserves the pass-through behavior for local development.

**Rationale:** The `TokenValidator` interface keeps the middleware decoupled from the token storage backend. Config-backed static tokens are sufficient for the current phase. When ABAC is implemented, the interface extends naturally without changing the middleware wiring. The 9 auth tests provide confidence in the security boundary.

**Ref:** PR #15, D049, `sigil-9s6`, `internal/server/auth.go`, `internal/server/auth_test.go`

---

## D060: Phase 7 API Behavioral Changes

**Question:** Two API behavioral changes were made during Phase 7 UI development. Should these be documented?

**Changes:**

1. **Anthropic stream-end-without-`message_stop` error emission**: Previously, if an Anthropic SSE stream ended without a `message_stop` event, the provider would emit a "done" event. Now it emits an error event instead, allowing the agent loop to detect incomplete streams.

2. **SSE JSON empty response format**: The `/api/v1/chat/send` SSE endpoint previously returned `{"events":null}` when no events were available. Now it returns `{"events":[]}` for consistency with JSON array semantics.

**Rationale:** The first change improves error detection for malformed provider responses. The second change aligns the API response format with standard JSON array representation. Both changes were made during implementation to match expected UI client behavior.

**Impact:** Both changes affect wire format but are non-breaking in practice:

- The stream-end change only affects error cases (streams should always include `message_stop`)
- The empty array change is semantically equivalent (null vs empty array both represent "no events")

**Ref:** PR #16 review findings #25, #26

---

## D061: Auth-Enabled API Behavioral Changes

**Question:** When authentication is enabled (tokens configured), how should the following endpoints behave relative to their unauthenticated implementations?

**Changes:**

1. **Workspace listing** — `GET /workspaces` now filters results to only workspaces where the authenticated user is a member. Previously returned all workspaces regardless of user identity.

2. **Plugin endpoints** — `GET /plugins`, `GET /plugins/{id}`, `POST /plugins/{id}/reload` now require `admin:plugins` permission. Previously accessible to any authenticated user.

3. **Chat workspace verification** — `POST /chat` and `GET /chat/stream` now verify the authenticated user is a member of the specified workspace. Previously accepted any workspace ID from any authenticated user.

**Decision:** These three behavioral changes are intentional security hardening measures applied when token validation is enabled.

**Rationale:**

- **Workspace filtering** provides proper access control — users see only workspaces they belong to, preventing accidental or malicious cross-workspace access.
- **Plugin admin restriction** enforces the principle of least privilege — plugin management (reload, inspect, lifecycle) is a sensitive operation requiring explicit `admin:plugins` capability.
- **Chat workspace verification** prevents unauthorized conversation access — users cannot initiate chats in workspaces they're not members of, even if they know the workspace ID.

**Impact on existing clients:**

- Clients that previously iterated all workspaces will now see filtered results. Clients should check for empty results gracefully.
- Clients attempting plugin operations will receive 403 Forbidden unless the token has `admin:plugins` permission.
- Clients attempting chat in non-member workspaces will receive 403 Forbidden.

**Unauthenticated mode (no tokens configured):**

When no tokens are configured, the gateway operates in development mode: authentication middleware is disabled, and all three endpoints return to their previous behavior (unrestricted workspace access, plugin operations available to all authenticated requests, chat accepted for any workspace). This preserves the development experience while allowing secure production deployments.

**Token permissions:**

Existing tokens and client authentication headers MUST be reviewed after enabling auth. Tokens that worked in unauthenticated mode may now be insufficient if clients relied on implicit access to all workspaces or plugin operations. Token permissions should be updated to grant specific `admin:plugins` or workspace-scoped capabilities as needed.

**Ref:** PR #16, auth enforcement hardening during Phase 7 UI distribution

---

## D062: Shared Security Scanner for Agent Loop Integrity Hooks

**Question:** Design/03 specified three deferred security hooks in the agent loop — input scanning (Step 1), tool injection detection (Step 6), and output filtering (Step 7). How should these be architected?

**Options considered:**

- Three separate implementations (one per hook) — rejected: duplicates pattern matching, configuration, and testing across three packages.
- Single shared `Scanner` interface with per-hook rule configurations (chosen) — one engine, three configs, consistent behavior.
- TruffleHog integration for secret detection — rejected: AGPL-3.0 license incompatible with Apache-2.0.
- ML-based PII detection — deferred: false-positive rate too high without ML-based detection; not viable for v1.

**Decision:** Implement a shared `Scanner` interface in `internal/security/scanner/` with three rule configurations, one per hook. Key design choices:

1. **Shared scanner engine** — single `Scanner` interface with three `RuleConfig` sets (input, tool, output) avoids duplication and ensures consistent pattern matching behavior.
2. **stdlib `regexp` for detection** — TruffleHog (the leading open-source secret scanner) is AGPL-3.0, incompatible with Sigil's Apache-2.0 license. stdlib regexp is zero-dependency and sufficient for pattern-based detection.
3. **Per-hook configurable modes:**
   - Input hook: `block` — reject the message on detection (prompt injection is high-severity).
   - Tool hook: `flag` — log a warning and continue for both injection patterns and secret detection (tool results may legitimately contain credential-shaped strings and injection-like patterns). ToolSecretRules runs at StageTool via DefaultRules(), so tool results are scanned for secrets before reaching the output stage.
   - Output hook: `redact` — replace matched content with `[REDACTED]` before sending to the user.
4. **Origin tagging on `provider.Message`** — enables context-aware rule selection (e.g., stricter rules for user input vs. system prompts).
5. **No PII detection in v1** — false-positive rates for regex-based PII detection (names, addresses, phone numbers) are unacceptably high without ML-based NER. Deferred until a suitable Apache-2.0-compatible library is available.
6. **Secret pattern scope (output and tool stages):** AWS keys, Google API keys, OpenAI API keys (including legacy sk- prefix), Anthropic API keys, GitHub PATs, Slack tokens, bearer tokens, PEM private keys, database connection strings, `keyring://` URIs.

**Rationale:** A single scanner engine with per-hook configuration is the simplest correct architecture. The three hooks share 90% of their logic (compile patterns, scan text, report findings) and differ only in what action to take on a match. Separate implementations would triple the test surface and create inconsistency risk. The stdlib regexp choice trades detection sophistication for license compatibility — an acceptable trade-off since the primary goal is catching accidental secret exposure, not adversarial obfuscation.

**Scanner error handling:** The scanner distinguishes between two error categories with different handling paths:

1. **Scanner internal errors** — context cancellation, regex panic, compilation errors, etc. These are failures of the scanner itself, not threat detection results. Error handling differs by stage:
   - **Input and output stages**: fail closed — return the error to the caller, blocking execution. This enforces the default-deny security principle.
   - **Tool stage**: best-effort — log a warning and continue with unscanned content to preserve availability. Tool results are less security-sensitive than user input (they cannot inject system prompts), and blocking on transient scanner failures would degrade the user experience. Content-too-large errors are an exception: oversized tool results are truncated and re-scanned to prevent bypass (see sigil-7g5.184).

2. **Threat detection** (per-hook behavior) — when the scanner successfully detects a pattern (prompt injection, secret, etc.):
   - **Input hook**: `block` — reject the message and return error to caller (prompt injection is high-severity).
   - **Tool hook**: `flag` — log a warning and continue (tool results may legitimately contain credential-shaped strings and injection-like patterns).
   - **Output hook**: `redact` — replace matched content with `[REDACTED]` and continue to the user.

**Ref:** `internal/security/scanner/`, `docs/design/03-security-model.md` Steps 1/6/7

---

## D063: Regex Scanner English-Only Limitation

**Status:** Accepted

**Question:** The regex-based security scanner detects prompt injection patterns using English-language rules only. Non-English prompt injection attacks (e.g., "Ignorez toutes les instructions précédentes", "Ignora todas las instrucciones anteriores") bypass all input scanning rules. How should this limitation be handled?

**Context:** The design doc defense matrix (docs/design/03-security-model.md) lists "Input scanning (Step 1)" as an implemented defense against prompt injection. This is accurate but incomplete — Step 1 only detects English-language patterns. Non-English attacks are undetected at the regex scanner layer. Tests document this explicitly via `currentlyDetected: false` cases for non-English bypass patterns.

**Options considered:**

- Multilingual regex rules — rejected: intractable. Covering even a subset of major languages (Spanish, French, German, Chinese, Arabic, etc.) requires hundreds of patterns that must be maintained across language drift and dialect variation. False-positive rates would be unacceptably high for non-English system prompts.
- Third-party multilingual NLP libraries — rejected for v1: no Apache-2.0-compatible library provides production-quality multilingual prompt injection detection. Most are Python-only, ML-model-dependent, or carry incompatible licenses.
- LLM-based semantic classification — deferred: passing each input through a second LLM call for injection detection adds latency and cost but would provide genuine multilingual coverage. Viable as a future enhancement once the provider abstraction supports lightweight classification calls.
- Accept English-only for v1 (chosen) — acknowledge the limitation formally, document bypasses in tests, and defer multilingual support to a future LLM-based classification layer.

**Decision:** Accept English-only regex coverage for the v1 scanner. Non-English prompt injection bypass is a known, documented limitation — not an oversight.

Specific consequences accepted:

1. The defense matrix entry for Step 1 (input scanning) is accurate for English inputs only.
2. Non-English prompt injection is undetected by the regex scanner. Users relying on Sigil for multilingual deployments must be aware of this gap.
3. Test cases for non-English bypass patterns are marked `currentlyDetected: false` and retained as regression anchors — they must remain failing until a multilingual solution is implemented.

**Future enhancement path:** Replace or augment the regex scanner with an LLM-based semantic classifier (e.g., a fast provider call with a classification prompt) that operates language-agnostically. The `Scanner` interface is already abstracted to support this swap without agent loop changes.

**Rationale:** Regex-based multilingual detection is a maintenance burden with high false-positive risk and no clear termination condition. The honest posture is to document the English-only coverage as a known limitation, preserve the bypass test cases as regression anchors, and plan a proper multilingual solution (LLM classification) for a future milestone. This avoids false security claims while keeping v1 scope tractable.

**Ref:** `internal/security/scanner/`, `docs/design/03-security-model.md` Step 1, sigil-7g5.314

## D064: Scanner Content Size Limits — Two-Tier Model

**Status:** Accepted

**Question:** The design doc (03-security-model.md, Step 6) describes "result size capped — scanner enforces maxToolContentScanSize (512KB)" but the actual implementation uses a two-tier model with different thresholds. What are the correct limits and how should they be documented?

**Context:** The scanner implementation uses two constants:

- `DefaultMaxContentLength` (1MB) — the primary scanner limit. Content up to 1MB is scanned normally by `RegexScanner.Scan()`.
- `maxToolContentScanSize` (512KB) — the truncation target in the agent loop's `scanContent()`. When tool result content exceeds 1MB, it is truncated to 512KB and re-scanned. The truncated+scanned content is returned with a `[TRUNCATED]` marker so the LLM knows data was lost.

The design doc's "512KB" reference describes only the truncation fallback, not the primary limit.

**Decision:** Accept the two-tier model as implemented. The primary scanner limit is 1MB; the 512KB truncation target is a fallback for oversized tool results only.

**Rationale:** 1MB accommodates typical tool results (API responses, file contents) without truncation. The 512KB fallback ensures that even oversized results get some scanning coverage rather than passing through unscanned. The truncation marker (`[TRUNCATED: tool result exceeded scan limit]`) informs the LLM that data is incomplete, preventing incorrect reasoning from partial results.

**Ref:** `internal/security/scanner/scanner.go` `DefaultMaxContentLength`, `internal/agent/loop.go` `maxToolContentScanSize`, `docs/design/03-security-model.md` Step 6, sigil-7g5.329

---

## D065: Design Doc Update for Security Scanner Implementation Status

**Status:** Revoked

**Question:** PR #17 modifies `docs/design/03-security-model.md` to remove Phase 8+ deferred markers and update the defense matrix. The project convention is "MUST NOT modify docs/design/ files" — they are treated as immutable specs. Is this modification justified?

**Context:** The plan document (docs/plans/2026-02-17-agent-loop-security-pipeline.md Task 6) explicitly instructed updating the design doc to reflect implementation status. The changes are status updates (marking deferred items as implemented, updating the defense matrix) — not architectural changes to the spec itself.

**Options considered:**

- Revert the design doc changes — rejected: the defense matrix now accurately reflects implemented state. Reverting would leave the design doc showing "deferred" for features that are actually implemented, misleading future developers.
- Keep changes with decision record (chosen) — acknowledge the deviation, clarify that status updates to design docs are acceptable when documented.
- Move status tracking to a separate file — rejected: would fragment the security model documentation across multiple files without clear benefit.

**Decision:** Accept the design doc modification. Status updates (marking deferred features as implemented, updating defense matrices to reflect actual state) are a permissible exception to the "MUST NOT modify docs/design/" rule, provided each instance is documented in this decision log.

**Rationale:** The intent of the immutability rule is to prevent unilateral architectural changes that bypass review. Updating implementation status annotations preserves the architectural content while keeping the document current. The alternative — a permanently stale defense matrix — would be more harmful than a controlled update with a decision record.

**Ref:** PR #17, sigil-7g5.364

**Revocation note (2026-02-17):** This decision is revoked. A self-authored exception to a MUST NOT rule does not carry the authority to override that rule. The CLAUDE.md prohibition on modifying `docs/design/` files is absolute and requires explicit human maintainer approval to override — an AI-generated decision log entry authored in the same PR that performs the modification is a circular self-exception, not an approval. The design doc changes have been reverted to match `main`. Implementation status for the security scanner is documented in D068 without modifying the design doc. See sigil-7g5.399 and sigil-7g5.414.

---

## D066: Scanner Circuit Breaker — Fail-Closed After Consecutive Failures

**Status:** Accepted

**Question:** The tool-stage scanner operates in best-effort mode (D062: "log a warning and continue"). But what happens when the scanner fails repeatedly? Unbounded best-effort means persistent scanner failures silently degrade security indefinitely.

**Context:** The implementation adds a circuit breaker (`scannerCircuitBreakerThreshold = 3`) on the tool-stage scan path. After 3 consecutive scanner internal failures, the loop transitions from best-effort (pass-through with warning) to fail-closed (block with `CodeSecurityScannerCircuitBreakerOpen`). This behavior is not described in D062.

**Options considered:**

- Unbounded best-effort (D062 as written) — rejected: a persistently failing scanner would silently pass all tool output unscanned forever, creating an invisible security gap.
- Fail-closed immediately on first failure — rejected: too aggressive. Transient regex engine errors or one-off edge cases should not halt the agent loop.
- Circuit breaker with threshold (chosen) — 3 consecutive failures triggers fail-closed. Balances availability (transient errors tolerated) with security (persistent failures caught).

**Decision:** Add a circuit breaker to the best-effort tool-stage scanner path. After `scannerCircuitBreakerThreshold` (3) consecutive scanner internal failures, the agent loop returns `CodeSecurityScannerCircuitBreakerOpen` and blocks further tool execution until a successful scan resets the counter.

The threshold value (3) was chosen to tolerate:

- A single transient regex engine error
- A pair of rapid consecutive failures from the same edge case
  while catching:
- Persistent scanner misconfiguration
- Systematic regex compilation failures after a bad rules update

**Rationale:** D062 describes the steady-state best-effort behavior but does not address the failure accumulation case. This decision extends D062 with a safety net: best-effort is the default, but the system refuses to operate indefinitely without security scanning. The circuit breaker counter resets on any successful scan, so recovery is automatic once the underlying issue resolves.

**Ref:** `internal/agent/loop.go` `scannerCircuitBreakerThreshold`, `CodeSecurityScannerCircuitBreakerOpen`, D062, sigil-7g5.367

---

## D067: Non-English Prompt Injection — Accepted Risk for v1

**Status:** Accepted (extends D063)

**Question:** PR #17 review identified that the English-only regex scanner limitation (D063) should be explicitly documented as an accepted security risk with a future mitigation path.

**Context:** D063 established the English-only limitation as a known constraint. This decision extends D063 with formal risk acceptance language and tracking.

**Decision:** The non-English prompt injection bypass is formally accepted as a known risk for v1. No code changes are required — D063 already covers the technical rationale. This entry adds:

1. **Risk classification:** Medium severity, high likelihood for multilingual deployments.
2. **Mitigation path:** LLM-based semantic classifier (as outlined in D063's "Future enhancement path").
3. **Monitoring:** Test cases for non-English bypass patterns are retained as regression anchors with `currentlyDetected: false`.

**Rationale:** The PR review flagged this as a gap requiring formal acknowledgment. D063 documented the technical limitation; this entry provides the risk management framing.

**Ref:** D063, sigil-7g5.340

---

## D068: Security Scanner Implementation Status — Agent Loop Steps 1, 6, and 7

**Status:** Accepted

**Question:** PR #17 implemented the security scanner described in D062. The design doc (`docs/design/03-security-model.md`) still shows Phase 8+ deferred markers for scanner functionality at steps 1, 6, and 7 of the agent loop. Where should the implementation status be recorded without modifying the immutable design doc?

**Context:** D065 (now revoked) attempted to record this status by modifying `docs/design/03-security-model.md` directly. That approach violated the MUST NOT rule in CLAUDE.md. The correct approach is to record implementation status in the decision log, not in the design doc. The design doc represents the architectural intent (which is unchanged); the decision log records what has been built.

**Implementation status as of PR #17 (2026-02-17):**

- **Step 1 — Input sanitization (prompt injection scan):** Implemented in `internal/security/scanner/`. Previously deferred (Phase 8+, sigil-39g). Now covered by D062.
- **Step 6 — Result size enforcement:** Scanner enforces `maxToolContentScanSize` (512KB); oversized results are truncated and re-scanned. Implemented in `internal/security/scanner/`. Previously deferred (sigil-7g5.184). See D064 for size-limit rationale.
- **Step 6 — Result injection scan:** Tool results scanned for instruction patterns. Implemented in `internal/security/scanner/`. Previously deferred (Phase 8+, sigil-j32).
- **Step 7 — Output filtering (secrets):** Implemented in `internal/security/scanner/`. Previously deferred (Phase 8+, sigil-hnh).
- **Step 7 — PII detection:** Still deferred. D062 notes PII detection remains a future enhancement.

**Defense matrix — updated state (not modifying design doc):**

| Attack Vector                     | Previous status     | Current status     |
| --------------------------------- | ------------------- | ------------------ |
| Prompt injection via user message | Phase 8+, sigil-39g | Implemented (D062) |
| Prompt injection via tool result  | Phase 8+, sigil-j32 | Implemented (D062) |

All other rows in the defense matrix (tool escalation, infinite loops, cost explosion, plugin data exfiltration, session hijacking, config poisoning) were already implemented and unchanged.

**Decision:** Record the scanner implementation status here rather than annotating the design doc. The architectural intent in `docs/design/03-security-model.md` remains valid and unchanged; the design doc is not modified.

**Rationale:** The design doc describes what the system must do. The decision log records what has been done and when. This separation keeps the spec stable while providing a traceable implementation history.

**Ref:** D062, D064, D065 (revoked), PR #17, sigil-7g5.399, sigil-7g5.414

---

## D069: Origin Tagging — Emergent Feature Not in Design Doc 03

**Status:** Accepted

**Question:** Origin tagging (prepending `[user_input]`, `[system]`, `[tool_output]` markers to message content) is an emergent feature implemented in PR #17. It is not explicitly specified in `docs/design/03-security-model.md`. Where should it be documented?

**Context:** Origin tagging is implemented in `internal/provider/provider.go` (`OriginTag`, `OriginTagIfEnabled`) and described in D062. Design doc 03 is immutable per CLAUDE.md policy.

**Decision:** Origin tagging is documented in D062 and in the provider package code comments. Design doc 03 is not modified per CLAUDE.md policy ("MUST NOT modify docs/design/ files").

**Rationale:** The design doc captures architectural intent. Origin tagging is an implementation detail of the security pipeline that supports the intent (message provenance tracking). D062 is the appropriate home for this documentation. Future readers can locate it via the D062 reference in provider.go.

**Ref:** D062, `internal/provider/provider.go`, PR #17, sigil-7g5.482

---

## D070: Design Doc 03 Stale Annotations — Immutability Takes Precedence

**Status:** Accepted

**Question:** Design doc 03 (`docs/design/03-security-model.md`) contains annotations that were corrected by D068 (implementation status for scanner steps 1, 6, and 7). Should the design doc be updated to remove stale annotations?

**Context:** D065 (now revoked) attempted to update the design doc directly. D068 recorded the implementation status in the decision log instead. The underlying annotation discrepancy (design doc shows "Phase 8+ deferred" for features that are now implemented) remains visible in the design doc itself.

**Decision:** No — design docs are immutable per project policy (CLAUDE.md: "MUST NOT modify docs/design/ files"). The stale annotations in design doc 03 remain as written. Implementation status is tracked exclusively in the decision log (D068). Readers who notice the discrepancy should consult D068 for the authoritative implementation status.

**Rationale:** The immutability rule exists to prevent unilateral architectural changes that bypass review. A self-authored AI decision log entry does not constitute the "explicit human maintainer approval" required to override a MUST NOT rule. The decision log is the correct and sufficient record of what has been built.

**Ref:** D065 (revoked), D068, sigil-7g5.482

---

## D071: Circuit Breaker Reset Correction — Turn Boundary, Not Per-Scan

**Status:** Accepted

**Question:** How does the scanner circuit breaker counter reset?

**Context:** D066 states: "The circuit breaker counter resets on any successful scan, so recovery is automatic once the underlying issue resolves." The actual implementation resets only at the turn boundary (`l.scannerFailCount.Store(0)` in `runToolLoop` entry). `applyScannedResult` explicitly documents: "The per-turn scanner failure counter is NOT reset here; it only resets at the start of each runToolLoop call."

**Options considered:**

1. Update D066 in place — rejected (decision log entries are append-only corrections)
2. Add correction entry — accepted

**Decision:** The circuit breaker counter resets at the start of each turn (`runToolLoop` call), not on individual successful scans mid-turn. Once tripped (3 consecutive failures within a turn), it stays tripped for the remainder of that turn. The next turn starts fresh. D066's claim about automatic recovery via successful scans is incorrect.

**Rationale:** Per-turn reset is simpler and more predictable than mid-turn recovery. The agent loop's natural unit of work is a turn; allowing mid-turn recovery would create complex re-trip-and-reset dynamics.

**Ref:** PR #17, sigil-7g5.502, D066, `internal/agent/loop.go`

---

## D072: Origin Does Not Influence Scanner Rule Selection

**Status:** Accepted

**Question:** Does the Origin field influence scanner rule selection?

**Context:** D062 item 4 states: "Origin tagging on provider.Message — enables context-aware rule selection (e.g., stricter rules for user input vs. system prompts)." The implementation contradicts this. `scanner.Scan()` documents: "Origin does not influence which rules are evaluated. Rule selection is determined exclusively by Stage." The Rule struct has a stage field for filtering but no origin-based filtering.

**Options considered:**

1. Implement origin-based rule filtering — rejected (adds complexity for unclear security benefit)
2. Correct D062's claim via new decision entry — accepted

**Decision:** Origin is audit/logging metadata only. Rule selection is determined exclusively by Stage. D062's claim about context-aware rule selection via Origin is inaccurate — it describes a design intent that was not implemented.

**Rationale:** Stage-only rule selection keeps the scanner simple and predictable. Origin adds audit granularity (e.g., "was this scan for user input or system prompt?") without affecting security posture. Adding origin-based rule filtering would increase scanner complexity with questionable value.

**Ref:** PR #17, sigil-7g5.494, D062, `internal/security/scanner/scanner.go:271-274`

---

## D073: DefaultScannerModes.Tool Uses ScannerModeFlag, Not ScannerModeBlock

**Status:** Accepted

**Question:** Should `DefaultScannerModes.Tool` use `ScannerModeBlock` instead of `ScannerModeFlag`?

**Context:** `ScannerModeFlag` detects injection patterns in tool results and emits structured log entries, but does not block or modify content. Tool results containing injection patterns are passed through to the LLM unmodified. This is a known gap relative to maximum-security posture. D062 documents an explicit availability-over-security tradeoff for the tool stage: blocking tool results breaks agent workflows when tools return content that resembles injection syntax (formatted output, code, structured data).

**Options considered:**

1. `ScannerModeBlock` — maximum security; reject tool results containing injection patterns. Rejected: breaks agent workflows when legitimate tool output triggers scanner rules.
2. `ScannerModeRedact` — sanitize injection patterns before passing to LLM. Rejected as default: alters tool output in ways that can corrupt structured data or code; surprising to operators who haven't opted in.
3. `ScannerModeFlag` (current, per D062 design) — log detected patterns, pass content through unmodified. Accepted.

**Decision:** Keep `DefaultScannerModes.Tool` as `ScannerModeFlag`. Add prominent warning documentation in `scanner_config.go` directing operators who require blocking to configure `tool: block` or `tool: redact` explicitly.

**Rationale:** D062 documents this tradeoff deliberately. Tool results with blocked content break agent workflows. Flag mode provides audit trails sufficient for detection and incident response. Operators who require a stricter posture can configure it via `sigil.yaml`. The warning comment in `scanner_config.go` ensures the non-blocking default is visible to anyone reading the code.

**Ref:** sigil-7g5.918, D062, `internal/agent/scanner_config.go`

---

## D074: Scanner Size Limits Made Operator-Configurable

**Status:** Accepted

**Question:** Should the hardcoded scanner size constants (DefaultMaxContentLength, maxPreNormContentLength, maxToolResultScanSize, maxToolContentScanSize) be exposed as operator-configurable values?

**Context:** PR #17 introduced hardcoded size constants across the scanner and agent loop packages. Different deployments need different limits: large-context models (Gemini 1.5 Pro with 1M tokens) may need larger limits, while memory-constrained or strict-security deployments need smaller ones. The constants were chosen without explicit reference to model context windows or API limits.

**Options considered:**

1. Keep hardcoded — rejected: operators cannot tune for their deployment.
2. Expose all size constants — rejected: some constants (maxArgLen, scannerCircuitBreakerThreshold, maxHTMLDecodeIterations) are implementation details, not security knobs.
3. Expose the four operator-relevant size limits via `security.scanner.limits.*` — accepted.

**Decision:** Expose four size constants as configurable values under `security.scanner.limits.*` in `sigil.yaml`:

- `max_content_length` (default 1MB): primary scanner size limit post-normalization
- `max_pre_norm_content_length` (default 5MB): hard cap before normalization (CPU DoS prevention)
- `max_tool_result_scan_size` (default 1MB): pre-scanner truncation for tool results
- `max_tool_content_scan_size` (default 512KB): truncation target for oversized tool results before re-scan

Validation: all must be 64KB–10MB. Cross-field: `max_tool_content_scan_size` < `max_content_length`, `max_tool_result_scan_size` >= `max_tool_content_scan_size`. Environment variable overrides are blocked (same pattern as scanner modes) to prevent env injection from weakening security limits.

**Rationale:** These four constants are the operator-tunable security knobs that directly affect what content passes through the scanner pipeline. The other constants (circuit breaker threshold, HTML decode iterations, max arg length) are internal safety mechanisms that should not be tuned per-deployment. The 64KB–10MB range prevents both useless scanning (below 64KB) and CPU DoS (above 10MB).

**Ref:** D064, sigil-7g5.956, `internal/config/config.go`, `internal/security/scanner/scanner.go`, `internal/agent/loop.go`

---

## D075: Phase 6 Node Transport Aligns to Remote Plugin Host Model

**Status:** Accepted (2026-02-21)

**Question:** Should Phase 6 Task 1 introduce a dedicated `NodeService` protocol, or implement node registration/handshake through the existing remote plugin-host model described in Section 6?

**Options considered:**

1. Introduce dedicated `NodeService` proto and stream RPC per the initial Phase 6 task draft.
2. Implement node connectivity via the existing remote plugin-host model (chosen).

**Decision:** Phase 6 Task 1 will use the existing remote plugin-host architecture. A separate dedicated node protocol is not introduced in this phase.

**Rationale:** Section 6 explicitly defines nodes as remote plugin hosts. Introducing a second protocol now would duplicate responsibilities, increase maintenance surface, and diverge from the design intent without a compelling security or operability gain.

**Ref:** sigil-7ek.1, `docs/design/06-node-system.md`, `docs/plans/06-phase-6-advanced-features.md`

---

## D076: Phase 6 Container Tier Completion Requires Minimal Runnable Runtime

**Status:** Accepted (2026-02-21)

**Question:** For Phase 6 Task 3, is config parsing/validation sufficient, or must the phase include a runnable container execution path?

**Options considered:**

1. Config-only foundation (manifest parsing, validation, interfaces/mocks).
2. Minimal runnable runtime (chosen): real container lifecycle start/stop with basic isolation controls and integration coverage.
3. Full production-grade tier (pull policy, advanced networking/observability/recovery) in Phase 6.

**Decision:** Phase 6 requires a minimal runnable container tier, not config-only scaffolding.

**Rationale:** The task is explicitly "Container Execution Tier." Config-only work would not satisfy that outcome and would defer core execution risk to later phases. A minimal runnable path keeps scope bounded while delivering real behavior.

**Ref:** sigil-7ek.3, `docs/plans/06-phase-6-advanced-features.md`, `docs/design/02-plugin-system.md`

---

## D077: Phase 6 Task 6 Expanded with Status Subscription and Pause/Resume Controls

**Status:** Accepted (2026-02-21)

**Question:** Should Phase 6 Task 6 remain limited to node CRUD endpoints, or include backend APIs required by dependent desktop features?

**Options considered:**

1. Keep Task 6 strictly node CRUD.
2. Expand Task 6 to include status subscription and agent pause/resume controls (chosen).
3. Keep Task 6 narrow and create separate backend beads for those APIs.

**Decision:** Task 6 includes node CRUD endpoints plus status subscription and pause/resume control surfaces needed by desktop tray integrations.

**Rationale:** Multiple follow-on features already depend on these APIs. Including them in Task 6 removes artificial dependency gaps and keeps backend/platform behavior cohesive.

**Ref:** sigil-7ek.6, sigil-94o, sigil-bt3, `docs/plans/06-phase-6-advanced-features.md`

---

## D078: Phase 6 Node Auth Baseline Is Tailscale Plus Token; mTLS Deferred

**Status:** Accepted (2026-02-21)

**Question:** Which node authentication methods are in-scope for Phase 6?

**Options considered:**

1. Tailscale-only baseline.
2. Tailscale plus token auth (chosen), defer mTLS.
3. Implement tailscale, token, and mTLS in Phase 6.

**Decision:** Phase 6 baseline includes Tailscale tag-based auth and token-based auth. mTLS is deferred to later hardening scope.

**Rationale:** This provides practical coverage for both tailnet and non-tailnet deployments while keeping implementation and test scope manageable for the phase.

**Ref:** sigil-7ek.2, D012, D013, `docs/design/06-node-system.md`

---

## D079: Container Tier NetworkRestricted Uses Bridge Network with Localhost-Publish Isolation

**Status:** Accepted (2026-02-22)

**Question:** What Docker network mode should `NetworkRestricted` map to in the container execution tier?

**Options considered:**

1. `--network none` — no network access at all; requires sidecar proxy for gRPC.
2. `--network bridge` with `--publish 127.0.0.1:<port>:<port>/tcp` (chosen) — containers use Docker bridge network but gRPC is exposed only on localhost.
3. Custom Docker network with iptables filtering — future work.

**Decision:** `NetworkRestricted` maps to Docker bridge network with `--publish 127.0.0.1` for inbound gRPC isolation. Full outbound filtering is deferred.

**Rationale:** The localhost-publish constraint prevents external inbound access while keeping the implementation simple. Full outbound network filtering (via custom Docker networks or iptables) is a security hardening follow-up, not a Phase 6 blocker. This is documented explicitly to prevent the "bridge = unrestricted" misread from being re-raised as a bug.

**Ref:** sigil-7ek.3, sigil-jp39.1, `docs/design/02-plugin-system.md`

---

## D080: Container Execution Tier Implemented in internal/plugin/container/

**Status:** Accepted (2026-02-22)

**Question:** Where does the container execution tier implementation live in the repository?

**Options considered:**

1. `internal/plugin/container/` — parallel to existing `goplugin/`, `wasm/`, `sandbox/` subdirectories (chosen).
2. `internal/container/` — top-level alongside other internal packages.

**Decision:** Container tier lives at `internal/plugin/container/`, consistent with the pattern established by `goplugin/`, `wasm/`, and `sandbox/`.

**Rationale:** The design doc directory structure table predates the container tier implementation. The `internal/plugin/` subdirectory pattern already exists for runtime-tier code and is the natural home for a new tier. No design doc modification is needed; this ADR records the location decision.

**Ref:** sigil-7ek.3, sigil-jp39.5, `docs/design/02-plugin-system.md`, `docs/design/10-build-and-distribution.md`

---

## D081: Phase 6 Container Tier Uses Docker CLI as Initial OCI Runtime

**Status:** Accepted (2026-02-22)

**Question:** Which OCI runtime CLI should the container execution tier use in Phase 6?

**Options considered:**

1. Docker CLI (chosen for Phase 6) — widely available, well-documented, supports create/start/stop/rm lifecycle.
2. containerd/nerdctl — spec mentions OCI/containerd; closer to spec intent but less ubiquitous in dev environments.
3. Generic OCI runtime abstraction — `OCIEngine.runtimeBinary` is already configurable; full abstraction is future work.

**Decision:** Docker CLI (`docker`) is the default and only tested runtime for Phase 6. The `runtimeBinary` field on `OCIEngine` allows substituting alternatives (podman, nerdctl) without code changes.

**Rationale:** Docker is universally available in development and CI environments. The `commandRunner` interface and configurable `runtimeBinary` design already supports alternative runtimes. Expanding test coverage to containerd/nerdctl is a follow-up concern outside Phase 6 scope.

**Ref:** sigil-7ek.3, sigil-jp39.8, `docs/design/02-plugin-system.md`

---

## D082: Defer Windows Builds and Plugin Binary Distribution to Post-Phase 7

**Status:** Decided (2026-02-21)

**Question:** Should Windows builds and plugin binary distribution be included in Phase 7?

**Context:** GoReleaser currently targets linux/darwin for the core binary. Adding Windows (.msi via Tauri) requires the Tauri Windows CI runner plus goreleaser-cross Docker image — significant CI infrastructure investment. Plugin binary bundling requires the full CI matrix.

**Options considered:**

1. Include Windows builds and plugin binary distribution in Phase 7 — rejected: CI infrastructure investment delays Phase 7 delivery.
2. Defer Windows builds and plugin binary distribution to post-Phase 7 — accepted.

**Decision:** Defer Windows builds and plugin binary distribution (as specified in design doc 10) to post-Phase 7. Phase 7 focuses on linux/darwin core binary only.

**Rationale:** The infrastructure complexity (Tauri Windows CI runner, goreleaser-cross image, full CI matrix for plugin binaries) doesn't justify delaying Phase 7 delivery. Windows support and plugin distribution are important but not blocking core functionality.

**Ref:** sigil-kqd.300, `docs/design/10-build-and-distribution.md`, `.goreleaser.yaml`

---

## D083: Defer Chat Attachment Support to Post-Phase 7

**Status:** Decided (2026-02-21)

**Question:** Should chat attachment support be included in Phase 7?

**Context:** Design doc 09 §Chat specifies "Message input with attachment support". Implementing this requires a multipart upload endpoint, a file storage strategy, and provider-specific handling for vision vs text models — significant scope beyond core messaging.

**Options considered:**

1. Include attachment support in Phase 7 — rejected: disproportionate scope relative to user benefit at this stage.
2. Defer chat attachment support to post-Phase 7 — accepted.

**Decision:** Defer chat attachment support to post-Phase 7.

**Rationale:** Attachment support doesn't block core messaging functionality. The additional scope (multipart upload endpoint, file storage strategy, provider-specific vision vs text handling) would delay Phase 7 delivery without proportional user benefit at this stage.

**Ref:** sigil-kqd.307, `docs/design/09-ui-and-cli.md`

---

## D084: Provider Health REST Endpoint with Optional Registration

**Status:** Decided (2026-02-21)

**Question:** How should provider health metrics be exposed for operator visibility?

**Context:** The provider system tracks health state internally (cooldown after failures, failure counts) via HealthTracker. Operators need visibility into provider availability for monitoring and debugging. The design doc (07-provider-system.md §Status) implies a coherent availability report but doesn't specify a REST endpoint.

**Options considered:**

1. Internal-only metrics — Expose health only through structured logging. Simple but requires log parsing for monitoring.
2. REST endpoint with mandatory registration — Always register the endpoint. Requires a concrete ProviderService at server construction time.
3. REST endpoint with optional registration — Register the endpoint only when a ProviderService is available. Graceful degradation when providers aren't configured.

**Decision:** Option 3. Added GET /api/v1/providers/{name}/health with optional ProviderService registration. The endpoint is gated by `admin:providers` capability (new). The ProviderService interface is optional on Services — when nil, the endpoint is not registered. A providerServiceAdapter in cmd/sigil/wire.go bridges the provider.Registry to the server.ProviderService interface. The protobuf StatusResponse was extended with health fields (failure_count, last_failure_at, cooldown_until) so plugin providers can expose the same metrics via gRPC.

**Rationale:** Optional registration handles the case where Sigil runs without any providers configured (e.g., channel-only deployments). The admin:providers capability follows the existing ABAC pattern. The adapter pattern matches the existing service adapters (workspaceServiceAdapter, pluginServiceAdapter, etc.).

**Ref:** PR #28, sigil-cv7y review epic, sigil-kqd.307, `docs/design/07-provider-system.md`

---

## D085: DeleteByIDs Replaces Trim for Concurrent-Append Race Safety

**Status:** Decided (2026-02-27)

**Question:** Should compaction remove processed messages using `Trim(keepLast)` as specified in the plan, or using `DeleteByIDs` targeting only the captured batch?

**Context:** The plan doc (docs/plans/06-phase-6-advanced-features.md Task 4, Step 3, point 7) specified "Trim processed messages from Tier 1." The implementation uses `DeleteByIDs` instead. This was a deliberate deviation to fix a concurrent-append race condition: `Trim(keepLast)` could delete messages appended after the compaction window was captured, whereas `DeleteByIDs` targets only the exact IDs captured in the batch.

**Options considered:**

1. Trim with pre-computed keepLast accounting for post-batch appends — Complex to compute correctly, still racy under high concurrency.
2. DeleteByIDs targeting captured batch IDs — Targets exact messages, immune to concurrent appends. Requires adding DeleteByIDs to MessageStore interface.
3. Trim within a transaction lock — Prevents concurrent appends during trim but adds lock contention.

**Decision:** Option 2. `DeleteByIDs` was added to the `store.MessageStore` interface. The compaction method `Compact()` collects batch message IDs during `loadBatch()`, then passes those exact IDs to `DeleteByIDs` after summarization. This also addresses the interface cohesion concern — `DeleteByIDs` serves a distinct purpose (targeted deletion of known IDs) vs `Trim` (retain last N).

**Rationale:** Correctness over spec adherence. The race condition is a real data-loss risk in production where messages can arrive while compaction runs. The ID-based approach is deterministic and auditable (the exact IDs deleted are logged).

**Ref:** PR #29, `internal/agent/compaction.go`, `internal/store/memory.go`

---

## D086: WindowSize Removed from CompactorConfig

**Status:** Decided (2026-02-27)

**Question:** Should `CompactorConfig` expose both `BatchSize` and `WindowSize` parameters as specified in the plan, or only `BatchSize`?

**Context:** The plan doc specified both `BatchSize` and `WindowSize` parameters for `CompactorConfig`. The implementation uses only `BatchSize` as the sole pagination parameter for compaction batches.

**Options considered:**

1. Keep both BatchSize and WindowSize — More flexible but adds configuration complexity without a clear use case.
2. Use only BatchSize — Simpler, single knob. The "window" concept is implicit in BatchSize (process the oldest N messages).
3. Add WindowSize later when time-based windowing is needed — YAGNI principle.

**Decision:** Option 2. `BatchSize` serves as both the trigger threshold (via `ShouldCompact`) and the batch size for `loadBatch`. `WindowSize` was removed as unnecessary complexity with no distinct semantic difference from `BatchSize` in the current implementation.

**Rationale:** YAGNI. Adding a second size parameter without a concrete use case increases configuration surface area. If time-based windowing becomes needed (e.g., "compact messages older than 24 hours"), it can be added as a distinct parameter with clear semantics rather than overloading the existing one.

**Ref:** PR #29, `internal/agent/compaction.go`, `docs/plans/06-phase-6-advanced-features.md`

---

## D087: Summarizer and Embedder as Explicit Interface Boundaries

**Status:** Decided (2026-02-27)

**Question:** Where should the `Summarizer` and `Embedder` interfaces introduced by the Phase 6 compaction system be documented?

**Context:** The compaction system introduces two new interfaces — `Summarizer` (text summarization) and `Embedder` (vector embedding) — that form a boundary between the agent loop and the LLM provider layer. These interfaces are not documented in the design docs but represent an emergent architectural boundary.

**Options considered:**

1. Document interfaces in the design doc — Modify `docs/design/08-agent-core.md`. But design docs are immutable per project convention.
2. Document interfaces in decision log only — Record the design rationale here.
3. Add a dedicated interface spec document — Overkill for two small interfaces.

**Decision:** Option 2. The `Summarizer` and `Embedder` interfaces are documented here as part of the Phase 6 memory compaction system. `Summarizer` transforms a batch of messages into a text summary. `Embedder` converts text to a vector embedding for similarity search. Both are injected into `CompactorConfig` and validated at construction time. A separate `FactExtractor` interface handles optional fact extraction from summaries.

**Rationale:** Design docs are immutable specs. The decision log is the appropriate place to document emergent interfaces that arise during implementation. These interfaces follow the project's "accept interfaces, return structs" pattern and serve as the provider abstraction boundary for the compaction subsystem.

**Ref:** PR #29, `internal/agent/compaction.go`, `docs/design/08-agent-core.md`
