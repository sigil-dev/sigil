# Section 8: Agent Core

The agent core is the heart of the system -- Go code that orchestrates conversations between users, LLMs, and tools. It is not a plugin; it is the trusted kernel.

## Agent Loop (per conversation turn)

1. **RECEIVE**
   - InboundMessage from channel plugin
   - Resolve user identity -> workspace -> session
   - Input sanitization (injection scan)
   - Enqueue in session lane (serialized per-session)

2. **PREPARE**
   - Load session state (active window + compaction summary)
   - Resolve workspace: tools, skills, model, budget
   - Assemble system prompt: base personality + workspace skills + tool descriptions + memory context + channel capability hints
   - Build message array (system + active window + new user message)

3. **CALL LLM**
   - Select provider (workspace override -> default)
   - Check budget (deny if exceeded)
   - `provider.Chat(messages, tools, options)`
   - Stream response events

4. **PROCESS RESPONSE (streaming loop)**
   - TextDelta -> buffer + stream to channel
   - ToolCall -> validate, capability check, dispatch, scan result, continue
   - Usage -> update budget counters
   - Done -> finalize response

5. **RESPOND**
   - Output filtering (PII, secrets)
   - Adapt format to channel capabilities
   - Send via channel plugin
   - Update session state (append to active window, trigger compaction if needed)

6. **AUDIT**
   - Log: user, workspace, model, tools used, tokens consumed, duration, cost estimate

## Session Management

```go
type Session struct {
    ID              string
    WorkspaceID     string
    UserID          string
    ActiveMessages  []Message       // last N messages (in LLM context)
    Summary         string          // rolling summary of older messages
    LastCompaction  time.Time
    ModelOverride   string
    ToolBudget      ToolBudget
    TokenBudget     TokenBudget
    Status          SessionStatus   // active | paused | archived
    CreatedAt       time.Time
    UpdatedAt       time.Time
}
```

### Storage: Interface-Based (see [Section 11](11-storage-interfaces.md))

All storage is accessed through interfaces, enabling backend swaps via configuration. Initial implementations use SQLite.

| Interface | Scope | Default Backend |
|-----------|-------|-----------------|
| `SessionStore` | Per workspace | SQLite |
| `MemoryStore` | Per workspace | SQLite (FTS5 + RDF triples) |
| `VectorStore` | Per workspace | sqlite-vec |
| `GatewayStore` | Global | SQLite |

`MemoryStore` composes three sub-interfaces: `MessageStore` (Tier 1), `SummaryStore` (Tier 2), and `KnowledgeStore` (Tier 3). The `KnowledgeStore` sub-interface is independently swappable — enabling graph database backends for entity/relationship storage.

```
data/
+-- gateway.db                 # GatewayStore (users, pairings, audit)
+-- workspaces/
|   +-- homelab/
|   |   +-- sessions.db        # SessionStore
|   |   +-- memory.db          # MessageStore + SummaryStore (FTS5)
|   |   +-- knowledge.db       # KnowledgeStore (RDF triples)
|   |   +-- vectors.db         # VectorStore (sqlite-vec)
|   |   +-- plugins/           # plugin-scoped KV data
|   +-- family/
|   |   +-- sessions.db
|   |   +-- memory.db
|   |   +-- knowledge.db
|   |   +-- vectors.db
|   |   +-- plugins/
|   +-- personal/
|       +-- ...
```

## Session Lanes (Concurrency Control)

One conversation at a time per session. Prevents race conditions where two parallel LLM calls produce conflicting tool actions.

```
User sends 3 messages quickly:
  msg1 -> +
  msg2 -> +-- Session lane (FIFO queue)
  msg3 -> +
           |
           v
  Process msg1 (full agent loop)
  Then msg2, then msg3
```

Lanes are per-session, not global. Different workspaces/users run concurrently.

## Tiered Conversation Memory

Instead of stuffing entire history into context, older messages are summarized and indexed:

### Tiers

| Tier | Interface | Default Backend | Content | Access |
|------|-----------|-----------------|---------|--------|
| Active Window | `SessionStore` | SQLite | Last N messages (configurable, default 20) | Automatic |
| Tier 1: Recent | `MessageStore` | SQLite FTS5 | Full message text, last ~1000 messages | `memory_search(query)` tool |
| Tier 2: Summaries | `SummaryStore` | SQLite | LLM-generated summaries per ~50 messages | `memory_summary(date_range)` tool |
| Tier 3: Knowledge | `KnowledgeStore` | SQLite (RDF triples) | Entities, relationships, facts | `memory_recall(topic)` tool |
| Tier 4: Embeddings | `VectorStore` | sqlite-vec | Semantic search across all history | `memory_semantic(query, k)` tool |

### Configuration

```yaml
sessions:
  memory:
    active_window: 20
    compaction:
      strategy: summarize
      summary_model: "openai/gpt-4.1-mini"
      batch_size: 50
    recent_store:
      max_messages: 1000
    summaries:
      enabled: true
      extract_facts: true
    knowledge:
      enabled: true
      scope: workspace
    embeddings:
      enabled: true
      model: "openai/text-embedding-3-small"

# Storage backend selection (see Section 11)
storage:
  backend: sqlite             # default for all stores
  memory:
    knowledge:
      backend: sqlite         # future: ladybugdb
  vector:
    backend: sqlite_vec       # future: lancedb
```

### Compaction Lifecycle

Messages 1-20 are in the active window (`SessionStore.GetActiveWindow()`). When message 21 arrives, message 1 rolls out to Tier 1 (`MessageStore.Append()`) and Tier 4 (`VectorStore.Store()`). When 50 messages accumulate in Tier 1, a compaction trigger summarizes them, extracts facts to Tier 3 (`KnowledgeStore.PutFact()`), and stores the summary in Tier 2 (`SummaryStore.Store()`).

The agent decides when to use memory tools. This keeps context lean for simple exchanges while giving access to unlimited history when needed. No automatic RAG injection burning tokens on every turn.

Memory is workspace-scoped: the agent in "homelab" cannot recall conversations from "family". Store interfaces enforce this via the `workspaceID` parameter on all queries.

## Skills (agentskills.io Format)

Skills are markdown files that inject domain knowledge into the system prompt:

```
workspaces/
+-- homelab/
|   +-- skills/
|       +-- infra-ops/
|       |   +-- SKILL.md
|       |   +-- references/
|       |   +-- scripts/
|       +-- k8s-patterns/
|           +-- SKILL.md
```

### SKILL.md Format (agentskills.io spec)

```yaml
---
name: infra-ops
description: Infrastructure operations expertise for Kubernetes and Terraform...
license: MIT
compatibility: Requires kubectl, terraform CLI
allowed-tools: Bash(kubectl:*) Bash(terraform:*)
metadata:
  author: sean
  version: "1.0"
  gateway:trigger: auto          # auto | manual | keyword
  gateway:keywords: server deploy kubernetes terraform
  gateway:workspace: homelab
---

You are an infrastructure operations expert...
```

Our extensions live in `metadata.*` to stay spec-compliant. Any agentskills.io skill works in our gateway; our skills work in Claude Code, Cursor, etc.

### Trigger Modes

| Mode | Behavior |
|------|----------|
| `auto` | Always injected into system prompt for this workspace |
| `manual` | Only when user says "use skill: infra-ops" |
| `keyword` | Injected when user message matches keywords |

### Skill Management

```bash
sigil skill list [--workspace <ws>]
sigil skill install <url|path> --workspace <ws>
sigil skill copy <name> --from <ws> --to <ws>
sigil skill link <name> --from <ws> --to <ws>    # shared, edits propagate
sigil skill remove <name> --workspace <ws>
sigil skill search "kubernetes"                    # search registry (future)
```

## Multi-Turn Tool Orchestration

The agent loop supports multi-step tool chains within a single turn. Each tool call goes through the full security check. The loop continues until the LLM produces a text response or hits the per-turn tool call limit (configurable, default 20).
