# Section 9: UI and CLI

## CLI (Cobra + Viper)

Single binary, subcommand structure:

```text
sigil
+-- start                            # start the gateway (foreground)
|   +-- --config <path>
|   +-- --data-dir <path>
|   +-- --tailscale
|
+-- status                           # health + connected channels/nodes
|
+-- workspace
|   +-- list / create / delete / show
|
+-- channel
|   +-- list / add / remove / status
|
+-- plugin
|   +-- list / install / remove / reload / inspect / logs
|
+-- skill
|   +-- list / install / copy / link / remove / edit / show
|
+-- node
|   +-- list / approve / revoke / status
|
+-- user
|   +-- list / add / pair / unpair
|
+-- session
|   +-- list / show / archive / export
|
+-- chat                             # CLI chat interface (direct to agent)
|   +-- --workspace <ws>
|   +-- --model <model>
|   +-- --session <id>
|
+-- config
|   +-- show / validate / edit
|
+-- doctor                           # diagnostics
|   +-- check / benchmark
|
+-- version
```

### Viper Config Resolution (standard precedence)

1. CLI flags (highest)
2. Environment variables (`GATEWAY_*`)
3. Config file (`gateway.yaml`)
4. Defaults (lowest)

### Doctor Command

Verifies: binary health, plugin processes, provider API key validity, channel connections, node connectivity, disk space, Tailscale status. Provides actionable messages: "Anthropic API key expired. Run `sigil config edit` to update."

## SvelteKit Web UI

Talks to the gateway via REST+SSE (OpenAPI-typed). Four main areas:

### Chat

- Session sidebar (grouped by workspace)
- Conversation view with streaming responses
- Tool call visualization (name, status, expandable results)
- Message input with attachment support

### Workspaces

- Workspace overview: members, model, channels, nodes, tools, skills, budget
- Skill management: install, copy/link between workspaces, edit
- Tool allowlist configuration
- Channel and node bindings

### Plugins

- Installed plugins with status indicators (running, stopped, error)
- Execution tier badge (wasm, process, container)
- Resource usage (memory, CPU)
- Per-plugin actions: logs, reload, remove, inspect manifest
- Install new plugins from file/URL/registry

### Settings

- Provider configuration (API keys, endpoints)
- Global settings (networking mode, default model, budgets)
- User management and pairing
- Audit log viewer

## Tauri Desktop App

Wraps the SvelteKit UI + bundles the gateway binary as a sidecar:

```text
app (Tauri v2)
+-- SvelteKit UI (webview)
+-- Gateway binary (sidecar, auto-launched)
+-- System tray icon
|   +-- Status indicator (running, channels, nodes)
|   +-- Quick actions: Open UI, Pause Agent, Restart
|   +-- Quit
+-- Auto-update (Tauri updater)
```

### First-Run Experience

1. Launch app
2. Onboarding wizard: "Add your first provider" -> paste API key
3. "Add a channel" -> Telegram bot token setup
4. "Send your first message" -> test from UI chat
5. Done
