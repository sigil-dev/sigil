# CGO Elimination Design

**Date:** 2026-02-21
**Status:** Draft
**Branch:** worktree-zig-eval

## Problem

Sigil currently requires `CGO_ENABLED=1` due to two dependencies in `internal/store/sqlite/`:

| Dependency                                     | Purpose                             | Files                                                 |
| ---------------------------------------------- | ----------------------------------- | ----------------------------------------------------- |
| `github.com/mattn/go-sqlite3`                  | SQLite driver                       | gateway, knowledge, message, session, summary, vector |
| `github.com/asg017/sqlite-vec-go-bindings/cgo` | Vector KNN via `vec0` virtual table | vector only                                           |

This forces the use of the `goreleaser-cross` Docker image (with pre-installed C cross-compilers) for all cross-platform builds. Without CGO, builds become `go build` across all targets with no additional toolchain.

## Goal

Eliminate CGO from the main Sigil binary entirely (`CGO_ENABLED=0`), preserving all existing functionality including vector storage and semantic search.

## Chosen Approach: `modernc.org/sqlite` + `chromem-go`

### SQLite Driver (5 files)

Replace `mattn/go-sqlite3` with `modernc.org/sqlite` — a pure-Go transpilation of the SQLite C source via ccgo. It is functionally equivalent (same SQLite version, same SQL dialect, FTS5, WAL mode, foreign keys, all URI parameters), registers as driver name `"sqlite"`, and is production-tested.

**Changes required per file:**

- Remove `_ "github.com/mattn/go-sqlite3"` import
- Add `_ "modernc.org/sqlite"` import
- Change `sql.Open("sqlite3", ...)` → `sql.Open("sqlite", ...)`

### Vector Store

Replace the `vec0`-based `VectorStore` with a new implementation backed by `chromem-go` (`github.com/philippgille/chromem-go`) — a pure-Go embedded vector database with cosine similarity, metadata filtering, and zero third-party dependencies.

**Architecture:**

- Use chromem-go in **in-memory mode** (`chromem.NewDB()`) — not persistent mode
- Implement an **atomic export wrapper**: on every write, export the full DB to a temp file then `os.Rename()` to the final path (POSIX rename is atomic)
- On startup, import from the snapshot file if it exists
- One chromem-go collection per workspace (collection name = workspace ID)

**Why in-memory + atomic export over chromem-go's built-in persistent mode:**
chromem-go's persistent mode writes gob files directly without atomic rename, making it vulnerable to corruption on crash. Our wrapper provides WAL-equivalent durability: the snapshot is always a complete consistent state.

**Durability properties:**

- A crash mid-export leaves the old snapshot intact (rename is not called until write succeeds)
- A crash mid-operation in memory loses only in-flight writes (same semantics as SQLite crash without WAL)
- Ultimate fallback: vectors are derived from message content in SQLite → full reindex is always possible

### Vector Schema Change

Current schema uses a `vec0` virtual table (sqlite-vec extension):

```sql
CREATE VIRTUAL TABLE vectors USING vec0(id TEXT PRIMARY KEY, embedding float[1536])
CREATE TABLE vector_metadata (id TEXT PRIMARY KEY, metadata TEXT)
```

New schema: vectors stored as gob-encoded chromem-go snapshot file alongside the SQLite databases.

**Migration:** No data migration needed. Current vector entries are placeholder `[]float32{0}` embeddings — no real semantic data exists yet. The `vectors.db` file can be deleted on upgrade.

### Metadata Filtering

The current `Search` implementation returns an error for any non-empty `filters` map:

```go
// current
if len(filters) > 0 {
    return nil, sigilerr.Errorf(..., "vector search filters not yet implemented")
}
```

chromem-go has first-class metadata filtering. This migration is an opportunity to implement filtering (workspace_id at minimum) rather than carry the error forward.

## File Layout (per workspace)

```text
<workspace-path>/
  sessions.db          # SessionStore (modernc)
  memory.db            # MessageStore + SummaryStore (modernc)
  knowledge.db         # KnowledgeStore (modernc)
  vectors.chromem      # chromem-go atomic snapshot (replaces vectors.db)
  vectors.chromem.tmp  # written then renamed; never persists
```

## Dependency Changes

```text
go.mod removes:
  github.com/mattn/go-sqlite3
  github.com/asg017/sqlite-vec-go-bindings

go.mod adds:
  modernc.org/sqlite
  github.com/philippgille/chromem-go
```

## Build Impact

- `CGO_ENABLED=1` flag removed from all Taskfile build commands
- `goreleaser-cross` Docker image no longer needed for CI cross-compilation
- Plugin binaries already use `CGO_ENABLED=0` — no change
- `go build ./...` works on any machine with Go installed, no C toolchain

## Affected Files

| File                                 | Change                                     |
| ------------------------------------ | ------------------------------------------ |
| `internal/store/sqlite/gateway.go`   | Driver import swap                         |
| `internal/store/sqlite/knowledge.go` | Driver import swap                         |
| `internal/store/sqlite/message.go`   | Driver import swap                         |
| `internal/store/sqlite/session.go`   | Driver import swap                         |
| `internal/store/sqlite/summary.go`   | Driver import swap                         |
| `internal/store/sqlite/vector.go`    | Full rewrite (chromem-go)                  |
| `internal/store/sqlite/register.go`  | `NewVectorStore` call updated              |
| `Taskfile.yaml`                      | Remove `CGO_ENABLED=1` from build commands |
| `go.mod` / `go.sum`                  | Dependency swap                            |

## Testing

Existing `vector_test.go` tests cover Store/Search/Delete/Upsert behaviours and must pass without modification (they test the interface, not the implementation). The driver swap for the other 5 stores should be transparent to all existing tests.

## Decision Log

This design will be recorded as a decision in `docs/decisions/decision-log.md` since it deviates from the design doc's stated `mattn/go-sqlite3` dependency.

## Open Questions

None — all concerns resolved during brainstorming:

- Cross-store atomicity: pre-existing (separate .db files already)
- Durability: mitigated by atomic export wrapper + regenerability
- Data migration: trivial (placeholder embeddings only)
