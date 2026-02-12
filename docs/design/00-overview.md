# Architecture Design: Sigil

**Status:** Draft
**Date:** 2026-02-09
**Authors:** Sean (human), Claude Opus 4.6 (AI)

## Document Index

This design is split into logical sections for readability:

| Section | File                                                         | Description                                          |
| ------- | ------------------------------------------------------------ | ---------------------------------------------------- |
| 0       | [00-overview.md](00-overview.md)                             | This file — project goals, non-goals, constraints    |
| 1       | [01-core-architecture.md](01-core-architecture.md)           | Gateway layers, trust boundaries, component layout   |
| 2       | [02-plugin-system.md](02-plugin-system.md)                   | Manifests, execution tiers, lifecycle, hot-reload    |
| 3       | [03-security-model.md](03-security-model.md)                 | Capability enforcement, agent integrity, isolation   |
| 4       | [04-channel-system.md](04-channel-system.md)                 | Channel plugins, auth/pairing, multi-channel routing |
| 5       | [05-workspace-system.md](05-workspace-system.md)             | Scoped conversations, tools, skills, multi-member    |
| 6       | [06-node-system.md](06-node-system.md)                       | Remote devices, Tailscale integration                |
| 7       | [07-provider-system.md](07-provider-system.md)               | LLM integration, routing, failover, budgets          |
| 8       | [08-agent-core.md](08-agent-core.md)                         | Agent loop, sessions, skills, memory                 |
| 9       | [09-ui-and-cli.md](09-ui-and-cli.md)                         | SvelteKit UI, Tauri desktop, Cobra CLI               |
| 10      | [10-build-and-distribution.md](10-build-and-distribution.md) | Taskfile, GoReleaser, CI/CD, toolchain               |
| 11      | [11-storage-interfaces.md](11-storage-interfaces.md)         | Storage interface architecture, backend abstraction  |

Supporting documents:

| Document           | File                                                                                                 | Description                                |
| ------------------ | ---------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Decision Log       | [../decisions/decision-log.md](../decisions/decision-log.md)                                         | All architectural decisions with rationale |
| Session Transcript | [../decisions/2026-02-09-brainstorm-transcript.md](../decisions/2026-02-09-brainstorm-transcript.md) | Raw brainstorming session notes            |

---

## Project Summary

**Name:** Sigil

**GitHub:** `sigil-dev/sigil`
**CLI:** `sigil`
**Go module:** `github.com/sigil-dev/sigil`

**One-liner:** A secure, lightweight Go gateway that connects messaging platforms to AI agents via a HashiCorp-style plugin architecture.

**Origin:** Inspired by [OpenClaw](https://github.com/openclaw/openclaw) (TypeScript), an open-source personal AI assistant gateway. Sigil reimagines OpenClaw's concepts in Go with a fundamentally different architecture centered on security, plugin isolation, and multi-language extensibility. We gratefully acknowledge OpenClaw and its community for pioneering the personal AI gateway space.

---

## Goals

| Goal                      | Measure of Success                                                                                                                  |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Security-first            | Capability-gated plugin system, sandboxed execution tiers, agent loop integrity checks. No plugin can escalate beyond its manifest. |
| Lightweight               | Single Go binary + plugin binaries. No Node.js/Python runtime required for core. `curl install` or `brew install`.                  |
| Multi-provider AI         | Swap between Anthropic, OpenAI, Google, local models via config. Agent loop is provider-agnostic.                                   |
| Multi-channel             | Talk to your agent on Telegram, WhatsApp, Discord, Slack, Signal, etc. Channels are plugins.                                        |
| Multi-language plugins    | Write plugins in Go, TypeScript, Python, Rust — anything that speaks gRPC or compiles to Wasm.                                      |
| Hot-reconfigurable        | Add/remove channels, swap providers, load/unload plugins without restarting the gateway.                                            |
| SvelteKit Web UI          | Admin dashboard, chat interface, plugin management, config editing via browser.                                                     |
| Tauri desktop app         | Optional native wrapper around SvelteKit UI for desktop experience with bundled gateway sidecar.                                    |
| agentskills.io compatible | Skills follow the open agentskills.io spec for cross-agent portability.                                                             |
| OpenClaw feature parity   | User-facing capabilities match or exceed OpenClaw.                                                                                  |

## Non-Goals

| Non-Goal                                 | Rationale                                                                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Mobile native apps (iOS/Android)         | Desktop covered by Tauri; mobile is future scope                                                              |
| Building our own LLM                     | We integrate with providers, not compete with them                                                            |
| Backward compat with OpenClaw TS plugins | Clean break enables better architecture                                                                       |
| Pure Go (no CGo)                         | SQLite3 + sqlite-vec require CGo; future backends (LanceDB, LadybugDB) add Rust/C++ FFI; accept the trade-off |

## Key Constraints

| Constraint         | Detail                                                    |
| ------------------ | --------------------------------------------------------- |
| Security paramount | Agent corruption/hijacking prevention is the top priority |
| CLI                | Cobra + Viper                                             |
| Build              | Taskfile.dev                                              |
| Release            | GoReleaser + release-please                               |
| Commits            | Conventional commits via Cocogitto                        |
| Signing            | Cosign keyless signing + SBOM (Syft)                      |
| Git hooks          | Lefthook                                                  |
| Docs site          | Zensical                                                  |
| Markdown lint      | rumdl                                                     |
| CGo required       | For sqlite3, sqlite-vec                                   |
| Skills spec        | agentskills.io open format                                |

## Prior Art

| Project                      | What We Take                                                                                                            | What We Improve                                                                           |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| OpenClaw                     | Feature set, channel coverage, skill concept                                                                            | Security model, plugin isolation, hot-reload, Go performance                              |
| HoloMUSH (holomush/holomush) | HashiCorp go-plugin pattern, capability ABAC, event-driven plugins, toolchain (GoReleaser, lefthook, cocogitto, cosign) | Broader plugin types (channels, providers, tools, skills), multi-language SDKs, Wasm tier |
| Anthropic sandbox-runtime    | OS-level sandboxing (bwrap + sandbox-exec)                                                                              | Integrated into plugin host, manifest-driven sandbox config                               |
