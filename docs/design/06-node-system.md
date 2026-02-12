# Section 6: Node System

Nodes are remote devices that connect to the gateway and expose device capabilities as tools.

## Design: Nodes as Remote Plugin Hosts

Rather than building a separate node protocol, nodes are remote instances of the plugin host that connect back to the gateway:

```text
Gateway                          Node (macOS laptop)
  |                               +-- Node Agent (Go binary)
  |<------- gRPC (TLS) ----------|    +-- camera-tool
  |                               |    +-- screen-tool
  | "node:mac is online,          |    +-- voice-tool
  |  has camera, voice, screen"   |    +-- applescript-tool
  |                               |    +-- filesystem-tool
  |
  |<------- gRPC (TLS) ----------+-- Node (iPhone)
  |                               |   +-- Node Agent (Swift)
  | "node:phone is online,        |   +-- camera-tool
  |  has camera, location"        |   +-- location-tool
```

A node is just a plugin host running on a different machine. It registers its available tools with the gateway, and the gateway routes tool calls to it. The agent does not know or care that `camera-tool` is running on your phone.

## Node Agent Configuration

```yaml
# node.yaml on the device
gateway: "my-agent:18789"         # or IP address in local mode
node_id: "macbook-pro"
auth:
  method: tailscale               # or: token, mtls
  # method: token
  # token: "${NODE_TOKEN}"

plugins:
  - camera-tool
  - screen-capture
  - voice-tts
  - voice-stt
  - applescript-exec
  - filesystem-read

capabilities:
  deny:
    - filesystem.write.*          # read-only from gateway's perspective
```

## Connection and Trust

```text
Node Agent starts
  +-- Connects to gateway (gRPC stream, TLS)
  +-- Authenticates (token, mTLS, or Tailscale identity)
  +-- Sends NodeRegister: { node_id, platform, capabilities, available_tools[] }
  +-- Gateway validates:
  |   +-- Is this node_id known/approved?
  |   +-- Do declared capabilities match node policy?
  |   +-- Register tools with "node:<node_id>" prefix
  +-- Bidirectional stream established:
      Gateway -> Node: ToolExecute requests
      Node -> Gateway: ToolResult responses, status updates
```

### Trust Model

| Node Type | Auth | Trust Level |
|-----------|------|-------------|
| Owner device (macOS/iOS) | mTLS or Tailscale identity | High -- full tool access per node config |
| Shared device | Token + approval | Medium -- workspace-scoped tools only |
| Ephemeral (CI runner, cloud VM) | One-time token with TTL | Low -- specific tools, auto-expires |

## Tailscale Integration (Opt-In)

When tailscale networking is enabled:

```yaml
# gateway.yaml
networking:
  mode: tailscale
  tailscale:
    hostname: "my-agent"
    auth_key: "${TS_AUTHKEY}"
    node_auth:
      required_tag: "tag:agent-node"
```

### What Tailscale Provides

| Feature | Benefit |
|---------|---------|
| `tsnet` embedded node | Gateway is on your tailnet. No port forwarding. |
| Auto TLS (HTTPS) | Tailscale provisions Let's Encrypt certs. Zero config. |
| NAT traversal | Nodes behind NAT/CGNAT connect without relay servers. |
| Tailscale ACLs | "Only my devices can reach the gateway." Network-layer enforcement. |
| MagicDNS | Nodes find gateway by name, not IP. |
| Funnel (optional) | Expose gateway to internet for webhooks without reverse proxy. |

### Tag-Based Auto-Auth

Three-layer auth for nodes over Tailscale:

| Layer | What | Who Controls |
|-------|------|-------------|
| 1. Tailscale ACL | "Can this device reach the gateway port?" | Tailnet admin |
| 2. Tag check | "Does this node have `tag:agent-node`?" | Gateway config |
| 3. Workspace binding | "Which workspaces can this node access?" | Gateway config |

Recommended Tailscale ACL:

```jsonc
{
  "tagOwners": {
    "tag:agent-gateway": ["autogroup:admin"],
    "tag:agent-node":    ["autogroup:admin"]
  },
  "acls": [
    { "action": "accept",
      "src": ["tag:agent-node"],
      "dst": ["tag:agent-gateway:18789"] }
  ]
}
```

## Workspace Integration

Nodes bind to workspaces:

```yaml
workspaces:
  homelab:
    nodes:
      allow: [macbook-pro, homelab-server]
    tools:
      allow: [node:macbook-pro:screen-capture, exec.sandboxed, k8s.*]

  family:
    nodes:
      allow: [iphone-sean, iphone-wife]
    tools:
      allow: [node:iphone-*:camera, node:iphone-*:location, calendar.*]
```

## Offline / Reconnection

- Gateway marks node tools as "unavailable" when node disconnects
- Agent sees: "camera-tool: currently offline (node: iphone)"
- Pending tool calls queued with configurable TTL (default 60s)
- Node reconnects: re-authenticates, drains queued requests, tools become available
