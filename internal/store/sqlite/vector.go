// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	chromem "github.com/philippgille/chromem-go"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const (
	vectorsCollection = "vectors"
	snapshotTmpExt    = ".tmp"
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
func NewVectorStore(dbPath string, _ int) (*VectorStore, error) {
	db := chromem.NewDB()

	// Import existing snapshot if present.
	if _, err := os.Stat(dbPath); err == nil {
		if importErr := db.ImportFromFile(dbPath, ""); importErr != nil {
			// Snapshot corrupted — start fresh. Vectors are re-derivable from messages.
			db = chromem.NewDB()
		}
	}

	col, err := db.GetOrCreateCollection(vectorsCollection, nil, nil)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "creating chromem collection: %w", err)
	}

	ext := filepath.Ext(dbPath)
	var tmpPath string
	if ext != "" {
		tmpPath = dbPath[:len(dbPath)-len(ext)] + snapshotTmpExt
	} else {
		tmpPath = dbPath + snapshotTmpExt
	}

	vs := &VectorStore{
		db:         db,
		collection: col,
		snapPath:   dbPath,
		tmpPath:    tmpPath,
	}
	return vs, nil
}

// persist atomically exports the in-memory DB to disk.
// Called after every mutating operation.
func (v *VectorStore) persist() error {
	if err := v.db.ExportToFile(v.tmpPath, false, ""); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "exporting vector snapshot: %w", err)
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

	// chromem-go requires nResults <= collection size; cap to avoid errors.
	count := v.collection.Count()
	if count == 0 {
		return nil, nil
	}
	if k > count {
		k = count
	}

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
			// Attempt to unmarshal JSON-encoded non-string values back to their
			// original types (numbers, bools, objects, arrays). Plain strings
			// stored as-is are not valid bare JSON and fall through to string.
			var parsed any
			if json.Unmarshal([]byte(v), &parsed) == nil {
				meta[k] = parsed
			} else {
				meta[k] = v
			}
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

	var errs []error
	for _, id := range ids {
		if err := v.collection.Delete(ctx, nil, nil, id); err != nil {
			errs = append(errs, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "deleting vector %s: %w", id, err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
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
