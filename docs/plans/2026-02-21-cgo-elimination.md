# CGO Elimination Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace all CGO dependencies in the Sigil binary with pure-Go equivalents so `CGO_ENABLED=0` works everywhere.

**Architecture:** Swap `mattn/go-sqlite3` → `modernc.org/sqlite` (pure-Go transpiled SQLite, driver name `"sqlite"`) in 5 store files. Replace the `sqlite-vec`-backed `VectorStore` with a new chromem-go implementation using in-memory mode + atomic snapshot persistence.

**Tech Stack:** `modernc.org/sqlite`, `github.com/philippgille/chromem-go`, standard `os.Rename` for atomic writes.

**Design doc:** `docs/plans/2026-02-21-cgo-elimination-design.md`

---

## Task 1: Add new dependencies, remove old ones

**Files:**

- Modify: `go.mod`

**Step 1: Add modernc and chromem-go**

```bash
cd /Volumes/Code/github.com/sigil-dev/sigil/.claude/worktrees/zig-eval
go get modernc.org/sqlite
go get github.com/philippgille/chromem-go
```

Expected: both added to `go.mod` / `go.sum`.

**Step 2: Remove old CGO deps**

```bash
go mod edit -droprequire=github.com/mattn/go-sqlite3
go mod edit -droprequire=github.com/asg017/sqlite-vec-go-bindings
go mod tidy
```

Expected: both removed from `go.mod`. `go.sum` updated.

**Step 3: Verify module graph is clean**

```bash
go mod verify
```

Expected: `all modules verified`

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "build(deps): swap mattn/go-sqlite3+sqlite-vec for modernc+chromem-go"
```

---

## Task 2: Swap SQLite driver in `gateway.go`

**Files:**

- Modify: `internal/store/sqlite/gateway.go`

**Context:** This file has one CGO import (`_ "github.com/mattn/go-sqlite3"`) and one `sql.Open("sqlite3", ...)` call at line ~37. The only change is the driver name in the import and open call.

**Step 1: Replace the import**

In `gateway.go`, find:

```go
_ "github.com/mattn/go-sqlite3"
```

Replace with:

```go
_ "modernc.org/sqlite"
```

**Step 2: Replace the driver name in sql.Open**

Find (around line 37):

```go
db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
```

Replace with:

```go
db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
```

**Step 3: Build to verify**

```bash
CGO_ENABLED=0 go build ./internal/store/sqlite/
```

Expected: compiles cleanly.

**Step 4: Run gateway tests**

```bash
task test 2>&1 | grep -E "gateway|FAIL|ok" | head -20
```

Expected: `ok` for the sqlite package, no FAIL lines.

---

## Task 3: Swap SQLite driver in `knowledge.go`, `message.go`, `session.go`, `summary.go`

**Files:**

- Modify: `internal/store/sqlite/knowledge.go`
- Modify: `internal/store/sqlite/message.go`
- Modify: `internal/store/sqlite/session.go`
- Modify: `internal/store/sqlite/summary.go`

Apply the same two-line change to each file as in Task 2:

**Step 1: For each file, replace the import**

Find:

```go
_ "github.com/mattn/go-sqlite3"
```

Replace with:

```go
_ "modernc.org/sqlite"
```

**Step 2: For each file, replace the driver name**

Find:

```go
sql.Open("sqlite3", ...
```

Replace with:

```go
sql.Open("sqlite", ...
```

All four files use the same `"sqlite3"` driver name string. After changes, all four use `"sqlite"`.

**Step 3: Build to verify**

```bash
CGO_ENABLED=0 go build ./internal/store/sqlite/
```

Expected: compiles cleanly.

**Step 4: Run all sqlite store tests**

```bash
task test 2>&1 | grep -E "store/sqlite|FAIL|ok" | head -30
```

Expected: all pass. The `register_test.go` tests (`TestNewWorkspaceStores_Success`, `TestNewWorkspaceStores_PartialFailureCleanup`, `TestNewGatewayStore_Success`) should all pass.

**Step 5: Commit**

```bash
git add internal/store/sqlite/gateway.go internal/store/sqlite/knowledge.go \
         internal/store/sqlite/message.go internal/store/sqlite/session.go \
         internal/store/sqlite/summary.go
git commit -m "refactor(store): swap mattn/go-sqlite3 driver for modernc.org/sqlite"
```

---

## Task 4: Rewrite `vector.go` with chromem-go

**Files:**

- Modify: `internal/store/sqlite/vector.go`

**Context:** The current implementation uses a `vec0` virtual table (sqlite-vec extension) and `sqlite_vec.SerializeFloat32` for binary encoding. We replace the entire file with a chromem-go-backed implementation. Key design decisions:

- Use `chromem.NewDB()` (in-memory), NOT `NewPersistentDB` (direct file writes are not crash-safe)
- Persist via `db.Export()` → write to `<path>.tmp` → `os.Rename` (atomic on POSIX)
- One chromem-go collection per workspace; collection name is the workspace path hash (or fixed `"vectors"` since one store = one workspace)
- Implement metadata filtering using chromem-go's `Where` parameter (fixes the current `"not yet implemented"` error)

**Step 1: Write the failing tests** (the existing tests serve this purpose — verify they currently fail with new deps)

```bash
CGO_ENABLED=0 go test ./internal/store/sqlite/ -run TestVectorStore -v 2>&1 | head -30
```

Expected: FAIL or compile error (sqlite-vec import no longer exists).

**Step 2: Replace `vector.go` entirely**

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	chromem "github.com/philippgille/chromem-go"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const (
	vectorsCollection = "vectors"
	snapshotExt       = ".chromem"
	snapshotTmpExt    = ".chromem.tmp"
)

// Compile-time interface check.
var _ store.VectorStore = (*VectorStore)(nil)

// VectorStore implements store.VectorStore using chromem-go for pure-Go
// vector storage and cosine similarity search. Data is kept in memory and
// atomically snapshotted to disk on every write so that the on-disk file is
// always a complete, consistent state (crash during export leaves the previous
// snapshot intact; os.Rename is atomic on POSIX).
type VectorStore struct {
	mu         sync.Mutex
	db         *chromem.DB
	collection *chromem.Collection
	snapPath   string // e.g. /workspace/vectors.chromem
	tmpPath    string // e.g. /workspace/vectors.chromem.tmp
}

// NewVectorStore creates a VectorStore backed by a chromem-go in-memory DB.
// If a snapshot file exists at dbPath it is imported on startup.
// dbPath should end in ".chromem" (the caller in register.go passes
// filepath.Join(workspacePath, "vectors.chromem")).
func NewVectorStore(dbPath string, _ int) (*VectorStore, error) {
	db := chromem.NewDB()

	// Import existing snapshot if present.
	if data, err := os.ReadFile(dbPath); err == nil {
		if importErr := db.Import(bytes.NewReader(data), false, ""); importErr != nil {
			// Snapshot corrupted — start fresh. Vectors are re-derivable from messages.
			db = chromem.NewDB()
		}
	}

	col, err := db.GetOrCreateCollection(vectorsCollection, nil, nil)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "creating chromem collection: %w", err)
	}

	vs := &VectorStore{
		db:         db,
		collection: col,
		snapPath:   dbPath,
		tmpPath:    dbPath[:len(dbPath)-len(filepath.Ext(dbPath))] + snapshotTmpExt,
	}
	return vs, nil
}

// persist atomically exports the in-memory DB to disk.
// Called after every mutating operation.
func (v *VectorStore) persist() error {
	var buf bytes.Buffer
	if err := v.db.Export(&buf, false, ""); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "exporting vector snapshot: %w", err)
	}
	if err := os.WriteFile(v.tmpPath, buf.Bytes(), 0o600); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "writing vector snapshot tmp: %w", err)
	}
	if err := os.Rename(v.tmpPath, v.snapPath); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "renaming vector snapshot: %w", err)
	}
	return nil
}

// Store inserts or replaces a vector and its metadata.
func (v *VectorStore) Store(ctx context.Context, id string, embedding []float32, metadata map[string]any) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Build string metadata map for chromem-go.
	strMeta := make(map[string]string, len(metadata))
	for k, val := range metadata {
		switch s := val.(type) {
		case string:
			strMeta[k] = s
		default:
			b, err := json.Marshal(val)
			if err != nil {
				return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling metadata key %s: %w", k, err)
			}
			strMeta[k] = string(b)
		}
	}

	doc := chromem.Document{
		ID:        id,
		Embedding: embedding,
		Metadata:  strMeta,
		Content:   strMeta["content"], // surface content for optional FTS
	}

	if err := v.collection.AddDocument(ctx, doc); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "storing vector %s: %w", id, err)
	}

	return v.persist()
}

// Search performs a k-nearest-neighbor cosine similarity search.
// Score represents distance (lower = more similar); 0.0 = exact match.
// Filters match on string metadata values (exact match).
func (v *VectorStore) Search(ctx context.Context, query []float32, k int, filters map[string]any) ([]store.VectorResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Build chromem-go Where filters.
	var where map[string]string
	if len(filters) > 0 {
		where = make(map[string]string, len(filters))
		for k, val := range filters {
			switch s := val.(type) {
			case string:
				where[k] = s
			default:
				b, _ := json.Marshal(val)
				where[k] = string(b)
			}
		}
	}

	results, err := v.collection.QueryEmbedding(ctx, query, k, where, nil)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "searching vectors: %w", err)
	}

	out := make([]store.VectorResult, 0, len(results))
	for _, r := range results {
		// chromem-go returns similarity (1 = exact); convert to distance (0 = exact).
		meta := make(map[string]any, len(r.Metadata))
		for k, v := range r.Metadata {
			meta[k] = v
		}
		out = append(out, store.VectorResult{
			ID:       r.ID,
			Score:    float64(1 - r.Similarity),
			Metadata: meta,
		})
	}
	return out, nil
}

// Delete removes vectors by ID.
func (v *VectorStore) Delete(ctx context.Context, ids []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, id := range ids {
		if err := v.collection.Delete(ctx, nil, nil, id); err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "deleting vector %s: %w", id, err)
		}
	}

	if len(ids) > 0 {
		return v.persist()
	}
	return nil
}

// Close is a no-op; chromem-go has no resources to release.
// The final in-memory state is already persisted after every write.
func (v *VectorStore) Close() error {
	return nil
}
```

**Step 3: Update `register.go` to pass the new snapshot path**

In `register.go`, find the `NewVectorStore` call:

```go
vs, err := NewVectorStore(filepath.Join(workspacePath, "vectors.db"), vectorDims)
```

Replace with:

```go
vs, err := NewVectorStore(filepath.Join(workspacePath, "vectors.chromem"), vectorDims)
```

**Step 4: Run vector tests to verify they pass**

```bash
CGO_ENABLED=0 go test ./internal/store/sqlite/ -run TestVectorStore -v
```

Expected: all 4 vector tests pass (`TestVectorStore_StoreAndSearch`, `TestVectorStore_Delete`, `TestVectorStore_StoreUpsert`, and any others).

**Step 5: Run full sqlite package tests**

```bash
CGO_ENABLED=0 go test ./internal/store/sqlite/ -v 2>&1 | tail -20
```

Expected: all pass, no FAIL.

**Step 6: Commit**

```bash
git add internal/store/sqlite/vector.go internal/store/sqlite/register.go
git commit -m "refactor(store): replace sqlite-vec VectorStore with chromem-go pure-Go implementation"
```

---

## Task 5: Remove `CGO_ENABLED=1` from Taskfile and verify CGO-free build

**Files:**

- Modify: `Taskfile.yaml`

**Step 1: Remove CGO flags from cross-compilation tasks**

In `Taskfile.yaml`, find and update the `build:linux` task:

```yaml
build:linux:
  desc: Build for Linux
  cmds:
    - GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build ...
    - GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build ...
```

Remove `CGO_ENABLED=1` from each line:

```yaml
build:linux:
  desc: Build for Linux
  cmds:
    - GOOS=linux GOARCH=amd64 go build ...
    - GOOS=linux GOARCH=arm64 go build ...
```

Repeat for `build:darwin`:

```yaml
build:darwin:
  desc: Build for macOS
  cmds:
    - GOOS=darwin GOARCH=amd64 go build ...
    - GOOS=darwin GOARCH=arm64 go build ...
```

**Step 2: Verify CGO-free build of the full binary**

```bash
CGO_ENABLED=0 go build ./cmd/sigil/
```

Expected: binary produced with no errors.

**Step 3: Verify cross-compile works without C toolchain (Linux target from macOS)**

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/sigil-linux-arm64 ./cmd/sigil/
```

Expected: binary produced. This previously required `goreleaser-cross` Docker image.

**Step 4: Run the full test suite one final time**

```bash
task test
```

Expected: all tests pass.

**Step 5: Run linter**

```bash
task lint
```

Expected: no errors. If golangci-lint flags unused `CGO_ENABLED` env vars in comments, update the comments.

**Step 6: Commit**

```bash
git add Taskfile.yaml
git commit -m "build: remove CGO_ENABLED=1 from cross-compilation tasks"
```

---

## Task 6: Record decision and update design doc reference

**Files:**

- Modify: `docs/decisions/decision-log.md`

**Step 1: Add decision entry D079**

Append to `docs/decisions/decision-log.md`:

```markdown
## D079: Replace CGO SQLite Dependencies with Pure-Go Equivalents

**Status:** Accepted
**Question:** How do we eliminate CGO from the Sigil binary to simplify cross-compilation?
**Context:** `mattn/go-sqlite3` and `asg017/sqlite-vec-go-bindings` require CGO, forcing use of `goreleaser-cross` Docker image with pre-installed C cross-compilers. This complicates CI and local cross-builds.
**Options considered:**

- Use `zig cc` as a CGO C cross-compiler (keeps CGO, simplifies toolchain)
- Pure-Go alternatives: `modernc.org/sqlite` + pure-Go cosine similarity
- Pure-Go alternatives: `modernc.org/sqlite` + `chromem-go` embedded vector DB
  **Decision:** Option 3 — `modernc.org/sqlite` for SQLite driver, `chromem-go` for vector storage.
  **Rationale:** modernc is a production-grade pure-Go transpilation of SQLite with equivalent feature coverage. chromem-go eliminates sqlite-vec CGO dependency and as a bonus enables vector metadata filtering (previously unimplemented). Vectors are re-derivable from messages so chromem-go's durability trade-offs are acceptable. Atomic snapshot persistence (in-memory + os.Rename) mitigates chromem-go's lack of WAL.
  **Ref:** worktree-zig-eval, `docs/plans/2026-02-21-cgo-elimination-design.md`, `docs/plans/2026-02-21-cgo-elimination.md`
```

**Step 2: Commit**

```bash
git add docs/decisions/decision-log.md
git commit -m "docs(decisions): record D079 CGO elimination via modernc + chromem-go"
```

---

## Task 7: Final verification

**Step 1: Confirm no CGO imports remain in production code**

```bash
grep -r 'import "C"' --include="*.go" ./internal/ ./cmd/ ./pkg/ | grep -v "_test.go"
```

Expected: no output.

**Step 2: Confirm no mattn/sqlite-vec references remain**

```bash
grep -r "mattn/go-sqlite3\|sqlite-vec-go-bindings" --include="*.go" ./internal/ ./cmd/ ./pkg/
```

Expected: no output.

**Step 3: Confirm modernc and chromem-go are the only sqlite/vector deps**

```bash
go list -m all | grep -E "sqlite|chromem"
```

Expected: `modernc.org/sqlite` and `github.com/philippgille/chromem-go` present; `mattn` and `asg017` absent.

**Step 4: Full test suite + lint**

```bash
task test && task lint
```

Expected: all pass.

**Step 5: Push branch**

```bash
git push -u origin worktree-zig-eval
```
