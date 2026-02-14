# Security

Understand Sigil's security model and capability-based access control.

## Security Principles

Core security principles guiding Sigil's design.

### Default Deny

Plugins have zero capabilities unless explicitly granted in the manifest.

### Capability Enforcement

Every plugin operation is checked against manifest capabilities.

### Agent Loop Integrity

LLM outputs are validated through 7-step checks before tool dispatch.

### Plugin Isolation

Execution tier determines the sandbox boundary and isolation strength.

### No Trust Escalation

A plugin cannot grant capabilities it doesn't have.

## Security Model

Detailed overview of Sigil's security architecture.

### Trust Boundaries

Separation between agent core, plugins, and external services.

### Threat Model

Assumptions about adversaries and attack vectors.

### Defense in Depth

Multiple layers of security controls.

## Capability System

Attribute-Based Access Control (ABAC) for plugin permissions.

### Capability Patterns

Hierarchical glob patterns for capability matching.

```
channel:send          # Exact match
channel:*             # All channel operations
tool:file:read:/*     # All file reads
```

### Capability Grants

How capabilities are declared and granted.

### Capability Inheritance

How child capabilities inherit from parent scopes.

### Runtime Checks

When and how capabilities are enforced during execution.

## Capability Reference

Complete list of available capabilities and their meanings.

### Channel Capabilities

- `channel:send` - Send messages to channels
- `channel:receive` - Receive messages from channels
- `channel:list` - List available channels
- `channel:manage` - Create or delete channels

### Tool Capabilities

- `tool:exec` - Execute arbitrary tools
- `tool:file:read` - Read files from disk
- `tool:file:write` - Write files to disk
- `tool:network:http` - Make HTTP requests
- `tool:network:websocket` - Open WebSocket connections

### Provider Capabilities

- `provider:llm:call` - Invoke LLM APIs
- `provider:llm:stream` - Stream LLM responses
- `provider:embedding` - Generate embeddings

### Storage Capabilities

- `storage:workspace:read` - Read workspace data
- `storage:workspace:write` - Write workspace data
- `storage:memory:read` - Read agent memory
- `storage:memory:write` - Write agent memory

### System Capabilities

- `system:config:read` - Read Sigil configuration
- `system:plugin:list` - List installed plugins
- `system:node:connect` - Connect to remote nodes

## Isolation Tiers

Execution environments and their security guarantees.

### Wasm Tier

Lightweight, memory-safe plugins with no syscall access.

**Use case:** Pure-compute tools, data transformation, safe parsing.

**Guarantees:**
- No network access
- No file system access
- No process spawning
- Memory safety enforced by Wazero

### Process Tier

OS-level sandboxing with bwrap (Linux) or sandbox-exec (macOS).

**Use case:** Most plugins, including channels and providers.

**Guarantees:**
- Restricted syscalls
- Limited file system access
- No privilege escalation
- Resource limits (CPU, memory)

### Container Tier

Full OCI container isolation for untrusted plugins.

**Use case:** Untrusted plugins, network-heavy tools, complex dependencies.

**Guarantees:**
- Network isolation
- Full file system isolation
- Resource quotas
- No host access

## Agent Loop Security

How Sigil validates LLM outputs before execution.

### 7-Step Validation

1. Parse LLM output to extract tool calls
2. Validate tool call structure (JSON schema)
3. Check tool existence in registry
4. Verify plugin capabilities for tool
5. Sanitize tool inputs
6. Check rate limits and budgets
7. Dispatch to sandboxed plugin

### Input Sanitization

How Sigil sanitizes tool inputs from LLM outputs.

### Output Validation

How tool outputs are validated before returning to the agent loop.

## Audit Logging

Tracking security-relevant operations.

### Audit Events

What events are logged for security auditing.

### Log Format

Structured logging format for audit events.

### Retention Policies

How long audit logs are retained.

## Secure Configuration

Best practices for configuring Sigil securely.

### API Key Management

Securely store and rotate provider API keys.

### TLS Configuration

Enable TLS for REST API and node-to-node communication.

### Access Control

Restrict access to Sigil API and admin endpoints.

### Network Policies

Configure firewall rules and network segmentation.

## Security Hardening

Additional steps to harden your Sigil deployment.

### Minimal Capabilities

Grant only the capabilities plugins need.

### Regular Updates

Keep Sigil and plugins up to date with security patches.

### Security Scanning

Scan plugins for vulnerabilities before installation.

### Incident Response

Prepare for and respond to security incidents.
