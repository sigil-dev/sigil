# Section 11: Storage Interface Architecture

## Motivation

Sigil's initial design uses SQLite for all storage (sessions, memory tiers, embeddings, gateway state). This works well for v1, but the tiered memory model has natural upgrade paths:

- **Tier 4 (Embeddings):** sqlite-vec → LanceDB (purpose-built columnar vector store)
- **Tier 3 (Knowledge):** SQLite rows → LadybugDB/KuzuDB (embedded graph database)

Rather than hardcode SQLite, we define storage interfaces that all components program against. Initial implementations are SQLite. Backends are swappable via configuration without changing callers.

## Design Decisions

- **Grouped by concern:** Four top-level interfaces, not one per tier (see D027)
- **Composition for Knowledge:** MemoryStore embeds a KnowledgeStore sub-interface that can be independently swapped (see D028)
- **Factory pattern:** Config-driven factory creates the right backend; callers never import backend packages
- **RDF triples for SQLite knowledge:** The SQLite KnowledgeStore uses an RDF triple model (subject-predicate-object) that maps cleanly to both relational and graph backends (see D028)

## Top-Level Interfaces

Four store interfaces, scoped by lifecycle:

| Interface | Scope | Purpose |
|-----------|-------|---------|
| `SessionStore` | Per workspace | Sessions and active message windows |
| `MemoryStore` | Per workspace | Tiered memory (messages, summaries, knowledge) |
| `VectorStore` | Per workspace | Embedding storage and similarity search |
| `GatewayStore` | Global | Users, pairings, audit log |

### SessionStore

Manages conversation sessions and the active message window (messages currently in LLM context).

```go
type SessionStore interface {
    CreateSession(ctx context.Context, session *Session) error
    GetSession(ctx context.Context, id string) (*Session, error)
    UpdateSession(ctx context.Context, session *Session) error
    ListSessions(ctx context.Context, workspaceID string, opts ListOpts) ([]*Session, error)
    DeleteSession(ctx context.Context, id string) error

    // Active message window (last N messages in LLM context)
    AppendMessage(ctx context.Context, sessionID string, msg *Message) error
    GetActiveWindow(ctx context.Context, sessionID string, limit int) ([]*Message, error)
}
```

### MemoryStore

Groups the three non-vector memory subsystems. Sub-interfaces are independently swappable via config.

```go
type MemoryStore interface {
    Messages() MessageStore      // Tier 1: recent searchable messages
    Summaries() SummaryStore     // Tier 2: compaction summaries
    Knowledge() KnowledgeStore   // Tier 3: entities, facts, relationships
    Close() error
}
```

### VectorStore

Manages embedding storage and semantic similarity search. Tier 4 of the memory model.

```go
type VectorStore interface {
    Store(ctx context.Context, id string, embedding []float32, metadata map[string]any) error
    Search(ctx context.Context, query []float32, k int, filters map[string]any) ([]VectorResult, error)
    Delete(ctx context.Context, ids []string) error
    Close() error
}
```

### GatewayStore

Manages global (non-workspace) state.

```go
type GatewayStore interface {
    Users() UserStore
    Pairings() PairingStore
    AuditLog() AuditStore
    Close() error
}
```

## Memory Sub-Interfaces

### MessageStore (Tier 1)

Recent searchable messages. Backed by FTS5 in SQLite.

```go
type MessageStore interface {
    Append(ctx context.Context, workspaceID string, msg *Message) error
    Search(ctx context.Context, workspaceID string, query string, opts SearchOpts) ([]*Message, error)
    GetRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*Message, error)
    Count(ctx context.Context, workspaceID string) (int64, error)
    Trim(ctx context.Context, workspaceID string, keepLast int) (int64, error)
    Close() error
}
```

### SummaryStore (Tier 2)

LLM-generated compaction summaries.

```go
type SummaryStore interface {
    Store(ctx context.Context, workspaceID string, summary *Summary) error
    GetByRange(ctx context.Context, workspaceID string, from, to time.Time) ([]*Summary, error)
    GetLatest(ctx context.Context, workspaceID string, n int) ([]*Summary, error)
    Close() error
}
```

### KnowledgeStore (Tier 3)

Entities, facts, and relationships. Designed with graph semantics so it maps naturally to both RDF triples (SQLite) and property graphs (LadybugDB).

```go
type KnowledgeStore interface {
    // Entities (nodes in graph terms)
    PutEntity(ctx context.Context, workspaceID string, entity *Entity) error
    GetEntity(ctx context.Context, workspaceID string, id string) (*Entity, error)
    FindEntities(ctx context.Context, workspaceID string, query EntityQuery) ([]*Entity, error)

    // Relationships (edges in graph terms)
    PutRelationship(ctx context.Context, rel *Relationship) error
    GetRelationships(ctx context.Context, entityID string, opts RelOpts) ([]*Relationship, error)

    // Facts (attributed statements about entities)
    PutFact(ctx context.Context, workspaceID string, fact *Fact) error
    FindFacts(ctx context.Context, workspaceID string, query FactQuery) ([]*Fact, error)

    // Graph traversal — multi-hop relationship queries
    Traverse(ctx context.Context, startID string, depth int, filter TraversalFilter) (*Graph, error)

    Close() error
}
```

### Gateway Sub-Interfaces

```go
type UserStore interface {
    Create(ctx context.Context, user *User) error
    Get(ctx context.Context, id string) (*User, error)
    GetByExternalID(ctx context.Context, provider, externalID string) (*User, error)
    Update(ctx context.Context, user *User) error
    List(ctx context.Context, opts ListOpts) ([]*User, error)
    Delete(ctx context.Context, id string) error
}

type PairingStore interface {
    Create(ctx context.Context, pairing *Pairing) error
    GetByChannel(ctx context.Context, channelType, channelID string) (*Pairing, error)
    GetByUser(ctx context.Context, userID string) ([]*Pairing, error)
    Delete(ctx context.Context, id string) error
}

type AuditStore interface {
    Append(ctx context.Context, entry *AuditEntry) error
    Query(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
}
```

## SQLite Knowledge Implementation: RDF Triples

The SQLite backend for KnowledgeStore uses an RDF triple model (subject-predicate-object). This maps cleanly to both relational storage and graph semantics.

### Schema

```sql
CREATE TABLE triples (
    subject   TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object    TEXT NOT NULL,
    workspace TEXT NOT NULL,
    metadata  TEXT,  -- JSON for extra properties
    created   TEXT NOT NULL,
    UNIQUE(workspace, subject, predicate, object)
);
CREATE INDEX idx_spo ON triples(workspace, subject, predicate, object);
CREATE INDEX idx_pos ON triples(workspace, predicate, object, subject);
CREATE INDEX idx_osp ON triples(workspace, object, subject, predicate);
```

### Mapping

| KnowledgeStore Method | Triple Pattern |
|---|---|
| `PutEntity(entity)` | `(entity.ID, "type", entity.Type)` + property triples |
| `PutRelationship(rel)` | `(rel.FromID, rel.Type, rel.ToID)` |
| `PutFact(fact)` | `(fact.EntityID, fact.Predicate, fact.Value)` |
| `FindEntities(query)` | `SELECT subject FROM triples WHERE predicate = 'type' AND ...` |
| `Traverse(startID, depth)` | Recursive CTE over triples |

When swapping to LadybugDB, the same interface methods map to Cypher: `CREATE (n:Entity)`, `MATCH (a)-[r]->(b)`, `MATCH path = (a)-[*1..N]->(b)`.

## Configuration

```yaml
storage:
  # Default backend for all stores
  backend: sqlite

  # Per-workspace stores
  session:
    backend: sqlite
  memory:
    backend: sqlite
    knowledge:
      backend: sqlite       # future: ladybugdb
  vector:
    backend: sqlite_vec     # future: lancedb

  # Global store
  gateway:
    backend: sqlite
```

Per-store `backend` overrides the top-level default. The `knowledge` key nests under `memory` because KnowledgeStore is a sub-interface of MemoryStore.

## Factory

```go
// NewWorkspaceStores creates all stores for a workspace.
// Reads storage config to select backends, returns interfaces.
func NewWorkspaceStores(cfg *config.Storage, workspacePath string) (
    SessionStore, MemoryStore, VectorStore, error,
)

// NewGatewayStore creates the global gateway store.
func NewGatewayStore(cfg *config.Storage, dataPath string) (GatewayStore, error)
```

The factory lives in `internal/store/factory.go`. It reads config, imports the backend packages, and returns interface types. Callers import only `internal/store` — never a backend package directly.

## Package Layout

```
internal/
  store/
    store.go                  # SessionStore, MemoryStore, VectorStore, GatewayStore
    memory.go                 # MessageStore, SummaryStore, KnowledgeStore
    gateway.go                # UserStore, PairingStore, AuditStore
    types.go                  # Entity, Relationship, Fact, VectorResult, etc.
    factory.go                # NewWorkspaceStores(), NewGatewayStore()
    sqlite/                   # SQLite implementations
      session.go
      memory.go               # MessageStore + SummaryStore (FTS5)
      knowledge.go            # KnowledgeStore via RDF triples
      vector.go               # VectorStore via sqlite-vec
      gateway.go
    lancedb/                  # Future: LanceDB VectorStore
    ladybugdb/                # Future: LadybugDB KnowledgeStore
```

## Workspace Directory Layout

```
data/
  gateway.db                  # GatewayStore (users, pairings, audit)
  workspaces/
    homelab/
      sessions.db             # SessionStore
      memory.db               # MessageStore + SummaryStore (SQLite FTS5)
      knowledge.db            # KnowledgeStore (SQLite RDF triples)
      vectors.db              # VectorStore (sqlite-vec)
      plugins/                # Plugin-scoped KV (unchanged)
    family/
      sessions.db
      memory.db
      knowledge.db
      vectors.db
      plugins/
```

When a backend changes, only its file changes:

| Backend Swap | File Change |
|---|---|
| Knowledge: sqlite → ladybugdb | `knowledge.db` → `knowledge.kuzu` |
| Vector: sqlite_vec → lancedb | `vectors.db` → `vectors/` (directory) |

## Integration Points

### Agent Core

The agent loop (`internal/agent/`) consumes store interfaces during PREPARE and RESPOND steps:

- **PREPARE:** `SessionStore.GetActiveWindow()` loads context; memory tools call `MemoryStore` sub-interfaces
- **RESPOND:** `SessionStore.AppendMessage()` updates active window; compaction calls `MessageStore.Trim()` + `SummaryStore.Store()`

Memory tools exposed to the LLM become thin wrappers:

| Tool | Store Method |
|---|---|
| `memory_search(query)` | `MemoryStore.Messages().Search()` |
| `memory_summary(range)` | `MemoryStore.Summaries().GetByRange()` |
| `memory_recall(topic)` | `MemoryStore.Knowledge().FindFacts()` |
| `memory_semantic(query, k)` | `VectorStore.Search()` |

### Workspace Manager

`internal/workspace/` creates stores when a workspace activates:

```go
func (wm *Manager) Open(workspaceID string) (*Workspace, error) {
    path := filepath.Join(wm.dataDir, "workspaces", workspaceID)
    sess, mem, vec, err := store.NewWorkspaceStores(wm.cfg.Storage, path)
    // ... wire into workspace
}
```

## Future Backend Candidates

| Backend | Replaces | Status (early 2026) | Waiting For |
|---|---|---|---|
| LanceDB | VectorStore (sqlite-vec) | Go SDK v0.1.2, pre-1.0 | Stable Go SDK |
| LadybugDB | KnowledgeStore (SQLite RDF) | Go bindings moderate maturity | 1.0 release, fork stability |

The interface architecture means we can adopt these when ready without changing any caller code. Monitor Go SDK maturity and add implementations when they stabilize.
