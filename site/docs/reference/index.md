# Reference

Technical reference documentation for Sigil CLI, configuration, and APIs.

## CLI Reference

Complete command-line interface documentation.

### Global Flags

Flags available to all commands.

```bash
--config string      Config file path (default: ~/.sigil/config.yaml)
--log-level string   Log level: debug, info, warn, error (default: info)
--workspace string   Workspace to operate on (default: "default")
```

### `sigil start`

Start the Sigil gateway server.

```bash
sigil start [flags]
```

**Flags:**

- `--host string` - Host to bind to (default: "localhost")
- `--port int` - Port to listen on (default: 8080)
- `--dev` - Enable development mode

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
server:
  host: localhost
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
  cors:
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]
```

### Database Configuration

```yaml
database:
  type: sqlite
  path: ~/.sigil/data
  sqlite:
    journal_mode: WAL
    synchronous: NORMAL
```

### Security Configuration

```yaml
security:
  sandbox:
    default_tier: process
    enable_wasm: true
    enable_container: false
  capabilities:
    default_deny: true
    audit_log: true
```

### Provider Configuration

```yaml
providers:
  - name: anthropic
    type: anthropic
    config:
      api_key_env: ANTHROPIC_API_KEY
      default_model: claude-opus-4.6
      budget:
        daily_limit_usd: 10.0
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
  max_context_messages: 100
  summarization:
    enabled: true
    threshold: 50
    model: claude-opus-4.6
  vector:
    enabled: true
    dimensions: 1024
```

### Environment Variables

Override configuration with environment variables:

```bash
SIGIL_SERVER_PORT=9000
SIGIL_DATABASE_PATH=/var/lib/sigil
SIGIL_LOG_LEVEL=debug
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

#### GET /api/v1/status

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
