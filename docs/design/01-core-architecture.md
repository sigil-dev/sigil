# Section 1: Core Architecture

## Five-Layer Design

The system has five layers, from clients at the top to plugins at the bottom:

```
+-------------------------------------------------------------+
|  Clients                                                     |
|  +-- SvelteKit Web UI (REST+SSE via OpenAPI)                |
|  +-- Tauri Desktop App (wraps SvelteKit + sidecar)          |
|  +-- CLI (Cobra+Viper, direct binary)                       |
+--------------------------+----------------------------------+
                           |
+--------------------------v----------------------------------+
|  Gateway (Go binary)                                         |
|  +--------------+ +--------------+ +--------------------+   |
|  | HTTP/SSE     | | Plugin       | | Config Manager     |   |
|  | Server       | | Manager      | | (Viper + watch)    |   |
|  | (huma)       | | (lifecycle)  | |                    |   |
|  +------+-------+ +------+-------+ +--------------------+   |
|         |                |                                   |
|  +------v----------------v-------------------------------+   |
|  |  Agent Core                                           |   |
|  |  +-- Conversation Router (session -> workspace)       |   |
|  |  +-- Agent Loop (prompt, call LLM, dispatch tool)     |   |
|  |  +-- Security Enforcer (capability ABAC)              |   |
|  |  +-- Session Store (state, history, compaction)       |   |
|  +----------------------------+--------------------------+   |
|                               |                              |
|  +----------------------------v--------------------------+   |
|  |  Plugin Host (go-plugin + Wasm + OCI)                 |   |
|  |  +-- Provider plugins   (Anthropic, OpenAI, ...)      |   |
|  |  +-- Channel plugins    (Telegram, WhatsApp, ...)     |   |
|  |  +-- Tool plugins       (exec, browse, search...)     |   |
|  |  +-- Skill plugins      (domain-specific agents)      |   |
|  +-------------------------------------------------------+   |
+--------------------------------------------------------------+
```

## Key Principles

- **Gateway is the trust boundary.** Everything outside it (plugins, UI, CLI) is untrusted by default. Every request is authenticated, every plugin call is capability-checked.
- **Plugins are the extensibility surface.** Channels, tools, providers, and skills are all plugins. The core only does routing, orchestration, and enforcement.
- **Config drives behavior.** Viper watches config files, triggers hot-reload events. Plugin Manager subscribes to these events to load/unload/reconfigure without restart.
- **Sessions are first-class.** Each conversation gets isolated state, history, and capability scope. Cross-session data sharing requires explicit grants.

## Protocol Stack

```
SvelteKit UI                    Go Gateway                    Plugins
(fetch + SSE + typed client) -> (REST/SSE + OpenAPI spec) -> (gRPC via go-plugin)
  generated from OpenAPI          generated from Go types      generated from proto
```

- **UI <-> Gateway:** REST + SSE. Go types define the API via huma, OpenAPI 3.1 spec generated at build time, TypeScript client generated from spec via `openapi-typescript` + `openapi-fetch`.
- **Gateway <-> Plugins:** gRPC via HashiCorp go-plugin (process tier), native calls (Wasm tier), gRPC over container network (container tier).

## Proto Definitions

```
api/proto/
+-- gateway/v1/gateway.proto    (UI <-> Gateway — also generates OpenAPI)
+-- plugin/v1/plugin.proto      (Gateway <-> Plugin lifecycle + tools)
+-- plugin/v1/channel.proto     (Channel plugin service)
+-- plugin/v1/provider.proto    (Provider plugin service)
+-- common/v1/types.proto       (shared types: Event, Message, etc.)
```

## Networking Modes

| Mode | Transport | Node Auth | Setup |
|------|-----------|-----------|-------|
| `local` | Standard TCP/TLS | Token or mTLS (manual) | User manages certs/tokens |
| `tailscale` | WireGuard via tsnet | Tailscale identity (automatic) | Install Tailscale, done |

When `tailscale` mode is enabled, the gateway binary becomes a Tailscale node via `tsnet`. Provides: auto TLS, NAT traversal, MagicDNS, ACL-governed connectivity.
