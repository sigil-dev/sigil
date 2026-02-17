# Reference

Technical reference documentation for Sigil CLI, configuration, and APIs.

## CLI Reference

Complete command-line interface documentation.

### Global Flags

Flags available to all commands.

```bash
--config, -c string   Path to config file
--data-dir string     Path to data directory
--verbose, -v         Enable verbose output
```

### `sigil start`

Start the Sigil gateway server.

```bash
sigil start [flags]
```

**Flags:**

- `--listen string` - Override listen address, host:port (default: "127.0.0.1:18789")

### `sigil status`

Show Sigil server status and configuration.

```bash
sigil status [flags]
```

### `sigil version`

Display Sigil version information.

```bash
sigil version
```

### `sigil workspace`

Manage workspaces.

```bash
sigil workspace [command]
```

**Subcommands:**

- `create <name>` - Create a new workspace
- `list` - List all workspaces
- `delete <name>` - Delete a workspace
- `switch <name>` - Switch active workspace

### `sigil plugin`

Manage plugins.

```bash
sigil plugin [command]
```

**Subcommands:**

- `list` - List installed plugins
- `install <path>` - Install a plugin
- `remove <name>` - Remove a plugin
- `info <name>` - Show plugin information

### `sigil channel`

Manage communication channels.

```bash
sigil channel [command]
```

**Subcommands:**

- `list` - List configured channels
- `add <type> <name>` - Add a new channel
- `remove <name>` - Remove a channel
- `test <name>` - Test channel connectivity

### `sigil doctor`

Run diagnostics and health checks.

```bash
sigil doctor [flags]
```

**Checks:**

- Configuration validity
- Plugin compatibility
- Database connectivity
- Provider API access

## Configuration Reference

Complete configuration file specification.

### File Format

Configuration files use YAML format.

**Default locations:**

- Linux: `~/.config/sigil/config.yaml`
- macOS: `~/Library/Application Support/sigil/config.yaml`
- Windows: `%APPDATA%\sigil\config.yaml`

### Server Configuration

```yaml
networking:
  mode: local        # local or tailscale
  listen: "127.0.0.1:18789"
```

### Storage Configuration

```yaml
storage:
  backend: sqlite
```

### Authentication Configuration

```yaml
auth:
  tokens:
    - token: "your-bearer-token"
      user_id: "user-1"
      name: "Admin"
      permissions: ["admin"]
```

### Provider Configuration

```yaml
providers:
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    endpoint: ""
```

### Channel Configuration

```yaml
channels:
  - name: telegram
    type: telegram
    config:
      bot_token_env: TELEGRAM_BOT_TOKEN
      allowed_users: []
```

### Plugin Configuration

```yaml
plugins:
  search_paths:
    - ~/.sigil/plugins
    - /usr/local/lib/sigil/plugins
  auto_discover: true
```

### Memory Configuration

```yaml
memory:
  active_window: 20
  compaction:
    strategy: summarize
    summary_model: anthropic/claude-haiku-4-5
    batch_size: 50
```

### Environment Variables

Override configuration with environment variables:

```bash
SIGIL_NETWORKING_LISTEN=127.0.0.1:9000
SIGIL_STORAGE_BACKEND=sqlite
```

## API Reference

REST API and SSE endpoints.

### Authentication

API authentication and authorization.

**Bearer Token:**

```text
Authorization: Bearer <token>
```

### REST Endpoints

#### GET /health

Server health and status.

**Response:**

```json
{
  "status": "running",
  "version": "0.1.0",
  "uptime_seconds": 3600
}
```

#### GET /api/v1/workspaces

List workspaces.

**Response:**

```json
{
  "workspaces": [
    { "id": "default", "name": "Default Workspace" }
  ]
}
```

#### POST /api/v1/workspaces

Create a workspace.

**Request:**

```json
{
  "name": "My Workspace",
  "description": "Personal workspace"
}
```

#### GET /api/v1/sessions

List agent sessions.

#### POST /api/v1/sessions

Create a new agent session.

#### GET /api/v1/sessions/:id/messages

Get session messages.

#### POST /api/v1/sessions/:id/messages

Send a message to the agent.

### SSE Endpoints

Server-Sent Events for real-time updates.

#### GET /api/v1/sessions/:id/stream

Stream agent responses in real-time.

**Event types:**

- `message.start` - Agent response started
- `message.chunk` - Response content chunk
- `message.complete` - Response complete
- `tool.call` - Tool invocation
- `tool.result` - Tool result

### OpenAPI Specification

Full OpenAPI 3.1 specification available at `/api/v1/openapi.json`.

## Protocol Reference

gRPC protocol definitions for plugin development.

### Common Types

Shared protobuf types across all plugins.

### Plugin Protocol

Base plugin service contract.

### Provider Protocol

LLM provider service contract.

### Channel Protocol

Messaging channel service contract.

### Tool Protocol

Tool execution service contract.

### Skill Protocol

Skill workflow service contract.

## Error Codes

Standard error codes and their meanings.

### Client Errors (4xx)

- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded

### Server Errors (5xx)

- `500 Internal Server Error` - Unexpected server error
- `502 Bad Gateway` - Plugin communication failure
- `503 Service Unavailable` - Server overloaded or starting up
- `504 Gateway Timeout` - Plugin execution timeout
