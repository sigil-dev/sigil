# Section 5: Workspace System

A workspace is a scoped context with its own sessions, tools, skills, and access control.

## Concept

```
Gateway
  +-- Workspace: "homelab"
  |   +-- Members: sean
  |   +-- Model: claude-opus-4-6
  |   +-- Channels: telegram:homelab-group
  |   +-- Nodes: macbook-pro, homelab-server
  |   +-- Tools: exec, k8s, terraform
  |   +-- Skills: infra-ops, k8s-patterns
  |   +-- Budget: $12.40 / $50.00 today
  |
  +-- Workspace: "holomush"
  |   +-- Members: sean
  |   +-- Tools: exec, github, go
  |   +-- Skills: code-review, go-patterns
  |
  +-- Workspace: "family"
  |   +-- Members: sean, wife
  |   +-- Tools: calendar, shopping, recipes
  |   +-- Skills: meal-planning, household
  |
  +-- Workspace: "personal"  (default for DMs)
      +-- Members: sean
```

## Routing Logic

```
Message arrives from Telegram group "homelab"
  -> Channel plugin: InboundMessage { chat_id: -100123, sender: @sean }
  -> Gateway router:
    1. Resolve sender identity -> usr_sean
    2. Match chat_id to workspace binding -> workspace:homelab
    3. Check membership -> sean IN homelab.members
    4. Route to homelab workspace session
    5. Agent sees homelab's tools + skills + history
```

## Key Properties

| Property | Detail |
|----------|--------|
| **Scoped tools** | Each workspace has its own tool allowlist. Homelab gets k8s/terraform, family gets calendar/shopping. |
| **Scoped sessions** | Conversation history stays within the workspace. |
| **Scoped skills** | Workspace-specific system prompt extensions. |
| **Multi-member** | Workspaces can have multiple users with shared context. |
| **Multi-binding** | A workspace can bind to multiple channels. |
| **Channel binding** | A channel (group/DM) maps to exactly one workspace. Unbound channels route to "personal". |

## Configuration

```yaml
workspaces:
  homelab:
    description: "Home infrastructure and lab projects"
    members: [sean]
    tools:
      allow: [exec.sandboxed, k8s.*, terraform.*]
    skills: [infra-ops, monitoring]
    bindings:
      - channel: telegram
        chat_id: -100123456
      - channel: discord
        guild_id: "987654"
        channel_id: "111222"

  family:
    description: "Shared family assistant"
    members: [sean, wife]
    tools:
      allow: [calendar.*, shopping.*, recipes.*]
      deny: [exec.*, filesystem.*]
    skills: [meal-planning, household]
    bindings:
      - channel: telegram
        chat_id: -100789012
```

## Security: Blast Radius Containment

If the agent is corrupted in one workspace (via prompt injection in a group chat), it can only access that workspace's tools and sessions. Homelab infra tools are not reachable from the family group.

Capability scoping integrates with the enforcer:

```
plugin.caps INTERSECT workspace.tools.allow INTERSECT user.role -> ALLOW/DENY
```
