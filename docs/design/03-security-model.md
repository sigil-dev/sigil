# Section 3: Security Model

Security is the core differentiator. Three layers: capability enforcement, agent integrity, and plugin isolation.

## Layer 1: Capability Enforcement (ABAC)

Every plugin call passes through the Enforcer before reaching the gateway's internal services:

```text
Plugin --gRPC--> Gateway Host Functions
                      |
                 +----v-----+
                 | Enforcer  |
                 |           |
                 | manifest  |--> DENY (logged + alerted)
                 | caps AND  |
                 | requested |--> ALLOW (audited)
                 | action    |
                 +-----------+
```

### Capability Model (glob-based)

```text
sessions.read                    # read any session
sessions.read.self               # read only sessions this plugin handles
sessions.write.self              # write only own sessions
messages.send.<channel>          # send via specific channel
messages.send.*                  # send via any channel
exec.run                         # execute commands (high privilege)
exec.run.sandboxed               # execute in sandbox only
config.read.self                 # read own plugin config
config.read.*                    # read all config (admin only)
filesystem.read./data/*          # path-scoped filesystem access
filesystem.write./data/plugins/self/*  # write only to own directory
kv.*                             # full KV access (plugin-scoped automatically)
tool.<name>                      # dispatch a specific tool (D038)
tool.*                           # dispatch any tool
provider.chat                    # invoke LLM (skill plugins need this)
storage.volumes.*                # (future) volume management
storage.memory.*                 # (future) memory collections
```

### Enforcement Rules

- Capabilities are **additive** -- a plugin starts with nothing and MUST declare what it needs
- `deny_capabilities` in manifest are enforced even if a config override tries to grant them
- Gateway can further **restrict** via policy config, never expand beyond manifest
- All checks are **fail-closed** -- unknown capability = denied
- All decisions are **audit-logged** with plugin name, action, result, timestamp

## Layer 2: Agent Integrity

The agent loop itself has security checks at every step:

### Step-by-Step Security Enforcement

1. **Receive message from channel**
   - Input sanitization (prompt injection scan) — implemented in `internal/security/scanner/` (D062)
   - Origin tagging (LLM sees `[user_input]` vs `[system]` markers)

2. **Construct prompt**
   - System prompt is immutable (not in history, not modifiable by plugins)
   - User message tagged with origin metadata

3. **Call LLM provider**
   - Provider is capability-gated
   - Token/cost budget enforced per-session

4. **Parse tool calls from response**
   - Tool MUST exist in session's allowed set
   - Tool args validated against JSON Schema
   - Capability check: does the session grant this tool's required capabilities?
   - Rate limiting per-tool, per-session

5. **Execute tool (dispatched to plugin)**
   - Enforcer checks plugin capabilities
   - Timeout enforced (configurable per-tool)

6. **Tool result returned**
   - Result size capped — *deferred: not yet enforced by scanner; tracked as future work*
   - Result scanned for injection patterns — implemented in `internal/security/scanner/` (D062)
   - Result tagged as `tool_output` (not user input)

7. **Format response**
   - Output filtering (secrets) — implemented in `internal/security/scanner/` (D062); PII detection deferred (D062)
   - Response sent back through channel

### Defense Matrix

| Attack Vector                     | Defense                                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| Prompt injection via user message | Input scanning (implemented, D062) + origin tagging                                               |
| Prompt injection via tool result  | Tool outputs tagged as `tool_output` role, scanned for instruction patterns (implemented, D062)    |
| Tool escalation                   | Session-scoped tool allowlist + capability check before dispatch                                  |
| Infinite tool loops               | Per-session tool call budget (max N calls per turn, max M turns per session)                      |
| Cost explosion                    | Token budget per-session, per-hour, per-day enforced at provider level                            |
| Plugin data exfiltration          | Plugins cannot read other plugins' KV/config. Network policy for container tier.                  |
| Session hijacking                 | Sessions bound to channel+user identity. Cross-session access requires explicit grant.            |
| Config poisoning                  | Config changes validated against schema, audit-logged, require admin capability                   |

## Layer 3: Plugin Isolation

Isolation depends on execution tier, but all tiers get baseline controls:

| Control                | Wasm                 | Process            | Container            |
| ---------------------- | -------------------- | ------------------ | -------------------- |
| Memory isolation       | Yes (Wazero sandbox) | Yes (OS process)   | Yes (cgroup)         |
| Filesystem isolation   | Yes (no FS access)   | Yes (srt sandbox)  | Yes (overlay FS)     |
| Network isolation      | Yes (no network)     | Yes (proxy-only)   | Yes (network policy) |
| Resource limits        | Yes (fuel metering)  | Partial (OOM kill) | Yes (cgroup limits)  |
| Capability enforcement | Yes                  | Yes                | Yes                  |
| Audit logging          | Yes                  | Yes                | Yes                  |
| Secret injection       | Via host function    | Via gRPC init      | Via mounted secrets  |

### Process Tier Sandboxing Detail

Inspired by Anthropic's `sandbox-runtime`:

- **macOS:** `sandbox-exec` with dynamically generated Seatbelt profiles
- **Linux:** Bubblewrap + network namespaces + seccomp filters

Sandbox configuration is derived from the plugin manifest's `execution.sandbox` section. The gateway generates the platform-appropriate sandbox config at plugin launch time.

## Workspace-Level Capability Scoping

Capabilities are further scoped by workspace:

```text
Enforcer input:
  1. Plugin declares:     capabilities: [exec.run.sandboxed]
  2. Workspace allows:    tools.allow: [exec.sandboxed]
  3. User role:           user.role = member

  Result: plugin.caps INTERSECT workspace.tools.allow INTERSECT user.permissions
          -> ALLOW or DENY
```

Three inputs MUST all agree for a capability to be granted.
