# Section 2: Plugin System

## Plugin Types

Four plugin categories, all using the same manifest and lifecycle system:

| Type         | Purpose                   | Examples                                 |
| ------------ | ------------------------- | ---------------------------------------- |
| **Provider** | LLM API integration       | Anthropic, OpenAI, Google, Ollama        |
| **Channel**  | Messaging platform bridge | Telegram, WhatsApp, Discord, Slack       |
| **Tool**     | Agent capabilities        | exec, browse, search, file-ops, calendar |
| **Skill**    | Domain-specific behaviors | "booking assistant", "code reviewer"     |

## Plugin Manifest (`plugin.yaml`)

```yaml
name: telegram-channel
version: 1.2.0
type: channel # provider | channel | tool | skill
engine: ">= 1.0.0" # core version constraint
license: MIT

# What this plugin needs from the gateway
capabilities:
  - sessions.read
  - sessions.write
  - messages.send
  - messages.receive
  - config.read.self # read own plugin config only
  - kv.* # plugin-scoped key-value store

# What this plugin must NOT have (defense in depth)
deny_capabilities:
  - exec.*
  - filesystem.*
  - config.write.global

# Execution tier (determines isolation level)
execution:
  tier: process # wasm | process | container
  sandbox:
    filesystem:
      write_allow:
        - /data/plugins/self/*
      read_deny:
        - /etc/shadow
        - ~/.ssh/*
    network:
      allow:
        - api.telegram.org:443
      proxy: true
  # container-only options:
  image: ghcr.io/org/telegram-channel:latest
  network: restricted # none | restricted | host
  memory_limit: 256Mi

# Plugin-specific config schema (validated by gateway)
config_schema:
  type: object
  properties:
    bot_token:
      type: string
      secret: true # encrypted at rest, never logged
    allowed_chat_ids:
      type: array
      items: { type: integer }

# Dependencies on other plugins
dependencies:
  session-store: ">= 1.0.0"

# Hot-reload behavior
lifecycle:
  hot_reload: true
  graceful_shutdown_timeout: 30s

# Future: storage declarations
storage:
  kv: true
  volumes:
    - name: model-cache
      mount: /data/cache
      size_limit: 10Gi
      persist: true
  memory:
    collections:
      - name: conversation-summaries
        embedding_model: default
        max_entries: 10000
```

## Execution Tiers

```text
         Isolation ------------------------------------------->
         Overhead  ------------------------------------------->

  +------------+    +--------------------+    +------------------+
  |   Wasm     |    |     Process        |    |   Container      |
  | (Wazero)   |    | (go-plugin +       |    | (OCI/containerd) |
  |            |    |  srt-style sandbox)|    |                  |
  +------------+    +--------------------+    +------------------+
  | ~1ms start |    | ~10ms start        |    | ~500ms start     |
  | No net     |    | Net: proxy-only    |    | Full isolation   |
  | No FS      |    | FS: write-allow    |    | Own filesystem   |
  | Memory     |    | Seccomp filtered   |    | Network policy   |
  |  sandbox   |    | Capability gated   |    | Own runtime env  |
  +------------+    +--------------------+    +------------------+
  | Filters,   |    | Most plugins       |    | Plugins needing  |
  | transforms,|    | (Go, Rust, any     |    | own runtime      |
  | simple     |    |  compiled binary)  |    | (Python+deps,    |
  | tools      |    |                    |    |  Node+deps)      |
  +------------+    +--------------------+    +------------------+
```

### Process-Tier Sandboxing

Inspired by Anthropic's `sandbox-runtime` (srt):

- **macOS:** `sandbox-exec` with dynamic Seatbelt profiles (built-in, no deps)
- **Linux:** Bubblewrap (`bwrap`) + network namespaces + seccomp filters

Filesystem: allow-only for writes, deny-only for reads. Network: allow-only, routed through gateway proxy for audit. The gateway generates Seatbelt profiles or bwrap arguments from the plugin manifest at launch time.

### Tier Selection Rules

- Manifest declares preferred tier
- Gateway can **upgrade** tier (process -> container) based on trust policy, never downgrade
- First install of a community plugin defaults to `container` regardless of manifest

## Plugin Lifecycle (Hot-Reload)

```text
Config change or CLI/UI trigger
  |
  v
+-- Discover (scan plugins directory)
+-- Validate manifest (capabilities, schema, version)
+-- Deny if invalid capabilities
+-- Load (start plugin in declared tier)
+-- Register capabilities with enforcer
+-- Plugin is Running
  |
Hot reload trigger:
  |
  v
+-- Drain in-flight requests to old instance (with timeout)
+-- Stop old instance (graceful shutdown signal)
+-- Start new instance
+-- Re-validate capability manifest
+-- Route traffic to new instance
+-- Old instance terminates after drain completes
```

No gateway restart required. Active conversations continue -- messages queue during the swap window.

## gRPC Service Contracts

```protobuf
// All plugins implement this base
service PluginLifecycle {
  rpc Init(InitRequest) returns (InitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc Shutdown(ShutdownRequest) returns (ShutdownResponse);
}

// Channel plugins additionally implement:
service Channel {
  rpc Start(StartRequest) returns (stream InboundMessage);
  rpc Send(SendRequest) returns (SendResponse);
  rpc UpdatePresence(PresenceRequest) returns (PresenceResponse);
  rpc GetIdentity(GetIdentityRequest) returns (UserIdentity);
}

// Tool plugins:
service Tool {
  rpc Describe(DescribeRequest) returns (ToolSchema);
  rpc Execute(ExecuteRequest) returns (stream ExecuteChunk);
}

// Provider plugins:
service Provider {
  rpc ListModels(ListModelsRequest) returns (ListModelsResponse);
  rpc Chat(ChatRequest) returns (stream ChatChunk);
  rpc Status(StatusRequest) returns (StatusResponse);
}
```

The `Channel.Start` RPC returning a stream is key -- the channel plugin connects to its platform and streams inbound messages to the gateway continuously. The gateway does not need to know anything about Telegram's API -- it just reads typed `InboundMessage` objects off the stream.
