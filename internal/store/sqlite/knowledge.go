// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Compile-time interface check.
var _ store.KnowledgeStore = (*KnowledgeStore)(nil)

// KnowledgeStore implements store.KnowledgeStore backed by SQLite,
// storing entities, relationships, and facts as RDF-style triples
// in a single unified table.
type KnowledgeStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewKnowledgeStore opens (or creates) a SQLite database at dbPath and
// initialises the single RDF triples table with SPO/POS/OSP indexes.
func NewKnowledgeStore(dbPath string) (*KnowledgeStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "opening sqlite db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "pinging sqlite db: %w", err)
	}

	if err := migrateKnowledge(db); err != nil {
		_ = db.Close()
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "migrating knowledge tables: %w", err)
	}

	return &KnowledgeStore{db: db, logger: slog.Default()}, nil
}

func migrateKnowledge(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS triples (
	subject   TEXT NOT NULL,
	predicate TEXT NOT NULL,
	object    TEXT NOT NULL,
	workspace TEXT NOT NULL,
	metadata  TEXT,
	created   TEXT NOT NULL,
	UNIQUE(workspace, subject, predicate, object)
);

CREATE INDEX IF NOT EXISTS idx_spo ON triples(workspace, subject, predicate, object);
CREATE INDEX IF NOT EXISTS idx_pos ON triples(workspace, predicate, object, subject);
CREATE INDEX IF NOT EXISTS idx_osp ON triples(workspace, object, subject, predicate);
`
	_, err := db.Exec(ddl)
	return err
}

// Close closes the underlying database connection.
func (k *KnowledgeStore) Close() error {
	return k.db.Close()
}

// upsertTriple inserts or updates a single triple.
func (k *KnowledgeStore) upsertTriple(ctx context.Context, tx *sql.Tx, workspace, subject, predicate, object, metadata, created string) error {
	const q = `INSERT INTO triples (subject, predicate, object, workspace, metadata, created)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(workspace, subject, predicate, object) DO UPDATE SET
	metadata = excluded.metadata,
	created = excluded.created`

	_, err := tx.ExecContext(ctx, q, subject, predicate, object, workspace, metadata, created)
	return err
}

// entityMetadata encodes entity-level metadata (workspace_id, created_at, updated_at)
// into JSON for storage in the metadata column of the "type" triple.
type entityMetadata struct {
	WorkspaceID string `json:"workspace_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// PutEntity upserts an entity into the knowledge graph as a set of triples:
//   - (entity.ID, "type", entity.Type) with entity metadata in the metadata column
//   - (entity.ID, "name", entity.Name)
//   - (entity.ID, "prop:<key>", jsonValue) for each property
func (k *KnowledgeStore) PutEntity(ctx context.Context, workspaceID string, entity *store.Entity) error {
	tx, err := k.db.BeginTx(ctx, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	created := formatTime(entity.CreatedAt)

	em := entityMetadata{
		WorkspaceID: workspaceID,
		CreatedAt:   formatTime(entity.CreatedAt),
		UpdatedAt:   formatTime(entity.UpdatedAt),
	}
	metaJSON, err := json.Marshal(em)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling entity metadata: %w", err)
	}

	// Type triple carries entity-level metadata.
	if err := k.upsertTriple(ctx, tx, workspaceID, entity.ID, "type", entity.Type, string(metaJSON), created); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "putting entity type triple: %w", err)
	}

	// Name triple.
	if err := k.upsertTriple(ctx, tx, workspaceID, entity.ID, "name", entity.Name, "", created); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "putting entity name triple: %w", err)
	}

	// Property triples.
	for key, val := range entity.Properties {
		valJSON, err := json.Marshal(val)
		if err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling property %s: %w", key, err)
		}
		if err := k.upsertTriple(ctx, tx, workspaceID, entity.ID, "prop:"+key, string(valJSON), "", created); err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "putting entity property triple %s: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "committing entity %s: %w", entity.ID, err)
	}
	return nil
}

// GetEntity retrieves an entity by reconstructing it from its triples.
func (k *KnowledgeStore) GetEntity(ctx context.Context, workspaceID string, id string) (*store.Entity, error) {
	const q = `SELECT predicate, object, metadata FROM triples
WHERE workspace = ? AND subject = ? AND (predicate = 'type' OR predicate = 'name' OR predicate LIKE 'prop:%')`

	rows, err := k.db.QueryContext(ctx, q, workspaceID, id)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting entity %s: %w", id, err)
	}
	defer func() { _ = rows.Close() }()

	ent := &store.Entity{
		ID:          id,
		WorkspaceID: workspaceID,
		Properties:  make(map[string]any),
	}
	found := false

	for rows.Next() {
		var predicate, object string
		var metadataStr sql.NullString

		if err := rows.Scan(&predicate, &object, &metadataStr); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning entity triple: %w", err)
		}
		found = true

		switch {
		case predicate == "type":
			ent.Type = object
			if metadataStr.Valid && metadataStr.String != "" {
				var em entityMetadata
				if err := json.Unmarshal([]byte(metadataStr.String), &em); err != nil {
					slog.Warn("failed to unmarshal entity metadata",
						slog.String("entity_id", id),
						slog.String("workspace", workspaceID),
						slog.String("error", err.Error()),
					)
				} else {
					var parseErr error
					ent.CreatedAt, parseErr = ParseTime(em.CreatedAt)
					if parseErr != nil {
						return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing entity %s created_at: %w", id, parseErr)
					}
					ent.UpdatedAt, parseErr = ParseTime(em.UpdatedAt)
					if parseErr != nil {
						return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing entity %s updated_at: %w", id, parseErr)
					}
				}
			}
		case predicate == "name":
			ent.Name = object
		case strings.HasPrefix(predicate, "prop:"):
			key := strings.TrimPrefix(predicate, "prop:")
			var val any
			if err := json.Unmarshal([]byte(object), &val); err != nil {
				val = object
			}
			ent.Properties[key] = val
		}
	}
	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating entity triples: %w", err)
	}

	if !found {
		return nil, sigilerr.New(sigilerr.CodeStoreEntityNotFound, "entity "+id+" in workspace "+workspaceID+" not found")
	}

	if len(ent.Properties) == 0 {
		ent.Properties = nil
	}

	return ent, nil
}

// FindEntities searches for entities by workspace with optional type and name prefix filters.
func (k *KnowledgeStore) FindEntities(ctx context.Context, workspaceID string, query store.EntityQuery) ([]*store.Entity, error) {
	// Find matching entity IDs by querying type/name triples.
	var (
		qb   strings.Builder
		args []any
	)

	qb.WriteString(`SELECT DISTINCT subject FROM triples WHERE workspace = ?`)
	args = append(args, workspaceID)

	if query.Type != "" {
		qb.WriteString(` AND subject IN (SELECT subject FROM triples WHERE workspace = ? AND predicate = 'type' AND object = ?)`)
		args = append(args, workspaceID, query.Type)
	} else {
		qb.WriteString(` AND predicate = 'type'`)
	}

	if query.NamePrefix != "" {
		qb.WriteString(` AND subject IN (SELECT subject FROM triples WHERE workspace = ? AND predicate = 'name' AND object LIKE ?)`)
		args = append(args, workspaceID, query.NamePrefix+"%")
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	qb.WriteString(` LIMIT ?`)
	args = append(args, limit)

	rows, err := k.db.QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "finding entity IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning entity ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating entity IDs: %w", err)
	}

	// Reconstruct each entity from its triples.
	entities := make([]*store.Entity, 0, len(ids))
	for _, id := range ids {
		ent, err := k.GetEntity(ctx, workspaceID, id)
		if err != nil {
			return nil, err
		}
		entities = append(entities, ent)
	}

	return entities, nil
}

// relTripleMetadata stores relationship ID and user metadata in the triple's metadata column.
type relTripleMetadata struct {
	RelID    string         `json:"rel_id"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// PutRelationship inserts a relationship as a triple: (fromID, relType, toID).
// The relationship ID and metadata are stored in the triple's metadata JSON column.
// Since the interface doesn't include workspaceID, we look up the workspace from
// the source entity's triples.
func (k *KnowledgeStore) PutRelationship(ctx context.Context, rel *store.Relationship) error {
	// Look up workspace from the source entity's type triple.
	workspace, err := k.lookupWorkspace(ctx, rel.FromID)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "looking up workspace for relationship: %w", err)
	}

	rm := relTripleMetadata{
		RelID:    rel.ID,
		Metadata: rel.Metadata,
	}
	metaJSON, err := json.Marshal(rm)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling relationship metadata: %w", err)
	}

	const q = `INSERT INTO triples (subject, predicate, object, workspace, metadata, created)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(workspace, subject, predicate, object) DO UPDATE SET
	metadata = excluded.metadata,
	created = excluded.created`

	_, err = k.db.ExecContext(ctx, q,
		rel.FromID,
		rel.Type,
		rel.ToID,
		workspace,
		string(metaJSON),
		formatTime(time.Now()),
	)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "putting relationship %s: %w", rel.ID, err)
	}
	return nil
}

// lookupWorkspace finds the workspace for an entity by querying its type triple.
func (k *KnowledgeStore) lookupWorkspace(ctx context.Context, entityID string) (string, error) {
	const q = `SELECT workspace FROM triples WHERE subject = ? AND predicate = 'type' LIMIT 1`
	var ws string
	err := k.db.QueryRowContext(ctx, q, entityID).Scan(&ws)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sigilerr.Errorf(sigilerr.CodeStoreEntityNotFound, "entity %s: %w", entityID, sql.ErrNoRows)
		}
		return "", sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "looking up workspace for entity %s: %w", entityID, err)
	}
	return ws, nil
}

// GetRelationships returns relationships for an entity filtered by direction.
// Relationship triples are identified by having rel_id in their metadata JSON.
func (k *KnowledgeStore) GetRelationships(ctx context.Context, entityID string, opts store.RelOpts) ([]*store.Relationship, error) {
	// Look up workspace for scoping.
	workspace, err := k.lookupWorkspace(ctx, entityID)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "looking up workspace for relationships: %w", err)
	}

	var (
		qb   strings.Builder
		args []any
	)

	qb.WriteString(`SELECT subject, predicate, object, metadata FROM triples WHERE workspace = ?`)
	args = append(args, workspace)
	qb.WriteString(` AND predicate NOT IN ('type', 'name') AND predicate NOT LIKE 'prop:%'`)
	// Only include relationship triples (those with rel_id in metadata).
	qb.WriteString(` AND json_extract(metadata, '$.rel_id') IS NOT NULL`)

	switch opts.Direction {
	case "incoming":
		qb.WriteString(` AND object = ?`)
		args = append(args, entityID)
	case "outgoing":
		qb.WriteString(` AND subject = ?`)
		args = append(args, entityID)
	default: // "both" or empty
		qb.WriteString(` AND (subject = ? OR object = ?)`)
		args = append(args, entityID, entityID)
	}

	if opts.Type != "" {
		qb.WriteString(` AND predicate = ?`)
		args = append(args, opts.Type)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	qb.WriteString(` LIMIT ?`)
	args = append(args, limit)

	rows, err := k.db.QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting relationships for %s: %w", entityID, err)
	}
	defer func() { _ = rows.Close() }()

	var rels []*store.Relationship
	for rows.Next() {
		var subject, predicate, object string
		var metaStr sql.NullString

		if err := rows.Scan(&subject, &predicate, &object, &metaStr); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning relationship triple: %w", err)
		}

		rel := &store.Relationship{
			FromID: subject,
			ToID:   object,
			Type:   predicate,
		}

		if metaStr.Valid && metaStr.String != "" {
			var rm relTripleMetadata
			if err := json.Unmarshal([]byte(metaStr.String), &rm); err != nil {
				slog.Warn("skipping relationship with corrupt metadata",
					slog.String("from_id", subject),
					slog.String("to_id", object),
					slog.String("error", err.Error()),
				)
				continue
			}
			rel.ID = rm.RelID
			rel.Metadata = rm.Metadata
		}

		rels = append(rels, rel)
	}
	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating relationships: %w", err)
	}

	return rels, nil
}

// factTripleMetadata stores fact-specific fields in the triple's metadata column.
type factTripleMetadata struct {
	FactID     string  `json:"fact_id"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source,omitempty"`
}

// PutFact inserts a fact as a triple: (entityID, predicate, value).
// Fact-specific fields (ID, confidence, source) are stored in the metadata column.
func (k *KnowledgeStore) PutFact(ctx context.Context, workspaceID string, fact *store.Fact) error {
	fm := factTripleMetadata{
		FactID:     fact.ID,
		Confidence: fact.Confidence,
		Source:     fact.Source,
	}
	metaJSON, err := json.Marshal(fm)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling fact metadata: %w", err)
	}

	const q = `INSERT INTO triples (subject, predicate, object, workspace, metadata, created)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(workspace, subject, predicate, object) DO UPDATE SET
	metadata = excluded.metadata,
	created = excluded.created`

	_, err = k.db.ExecContext(ctx, q,
		fact.EntityID,
		fact.Predicate,
		fact.Value,
		workspaceID,
		string(metaJSON),
		formatTime(fact.CreatedAt),
	)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "putting fact %s: %w", fact.ID, err)
	}
	return nil
}

// PutFacts inserts multiple facts atomically using a database transaction.
// If any insert fails, all prior inserts in the batch are rolled back.
func (k *KnowledgeStore) PutFacts(ctx context.Context, workspaceID string, facts []*store.Fact) error {
	if len(facts) == 0 {
		return nil
	}
	tx, err := k.db.BeginTx(ctx, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "beginning fact transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
			k.logger.ErrorContext(ctx, "PutFacts rollback failed",
				"workspace_id", workspaceID,
				"fact_count", len(facts),
				"error", rbErr,
			)
		}
	}()

	const q = `INSERT INTO triples (subject, predicate, object, workspace, metadata, created)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(workspace, subject, predicate, object) DO UPDATE SET
	metadata = excluded.metadata,
	created = excluded.created`

	for _, fact := range facts {
		fm := factTripleMetadata{
			FactID:     fact.ID,
			Confidence: fact.Confidence,
			Source:     fact.Source,
		}
		metaJSON, err := json.Marshal(fm)
		if err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "marshalling fact metadata: %w", err)
		}
		if _, err := tx.ExecContext(ctx, q,
			fact.EntityID, fact.Predicate, fact.Value,
			workspaceID, string(metaJSON), formatTime(fact.CreatedAt),
		); err != nil {
			return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "putting fact %s: %w", fact.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "committing fact transaction: %w", err)
	}
	return nil
}

// DeleteFactsBySource removes all facts (triples) in a workspace whose metadata
// source field matches the given value. Used to roll back facts when compaction
// fails after storeFacts has already committed.
func (k *KnowledgeStore) DeleteFactsBySource(ctx context.Context, workspaceID string, source string) error {
	const q = `DELETE FROM triples WHERE workspace = ? AND json_extract(metadata, '$.source') = ?`
	if _, err := k.db.ExecContext(ctx, q, workspaceID, source); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "deleting facts by source %q: %w", source, err)
	}
	return nil
}

// DeleteFactsByIDs removes specific facts (triples) in a workspace by their IDs.
// An empty ids slice is a no-op. Used for precise rollback during compaction cleanup,
// targeting only the facts written in the current pass.
func (k *KnowledgeStore) DeleteFactsByIDs(ctx context.Context, workspaceID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	q := `DELETE FROM triples WHERE workspace = ? AND json_extract(metadata, '$.fact_id') IN (` + placeholders + `)`
	args := make([]any, 0, 1+len(ids))
	args = append(args, workspaceID)
	for _, id := range ids {
		args = append(args, id)
	}
	if _, err := k.db.ExecContext(ctx, q, args...); err != nil {
		return sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "deleting facts by IDs: %w", err)
	}
	return nil
}

// FindFacts searches for facts by workspace with optional entity and predicate filters.
// Facts are triples where the predicate is not a reserved entity predicate (type, name, prop:*).
func (k *KnowledgeStore) FindFacts(ctx context.Context, workspaceID string, query store.FactQuery) ([]*store.Fact, error) {
	var (
		qb   strings.Builder
		args []any
	)

	qb.WriteString(`SELECT subject, predicate, object, workspace, metadata, created FROM triples WHERE workspace = ?`)
	args = append(args, workspaceID)

	// Exclude entity-definition triples. Only include fact triples (those with fact_id in metadata).
	qb.WriteString(` AND predicate NOT IN ('type', 'name') AND predicate NOT LIKE 'prop:%'`)
	qb.WriteString(` AND json_extract(metadata, '$.fact_id') IS NOT NULL`)

	if query.EntityID != "" {
		qb.WriteString(` AND subject = ?`)
		args = append(args, query.EntityID)
	}
	if query.Predicate != "" {
		qb.WriteString(` AND predicate = ?`)
		args = append(args, query.Predicate)
	}

	qb.WriteString(` ORDER BY created DESC`)

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	qb.WriteString(` LIMIT ?`)
	args = append(args, limit)

	rows, err := k.db.QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "finding facts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var facts []*store.Fact
	for rows.Next() {
		var subject, predicate, object, workspace, created string
		var metaStr sql.NullString

		if err := rows.Scan(&subject, &predicate, &object, &workspace, &metaStr, &created); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning fact triple: %w", err)
		}

		createdAt, err := ParseTime(created)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "parsing fact created_at: %w", err)
		}

		f := &store.Fact{
			WorkspaceID: workspace,
			EntityID:    subject,
			Predicate:   predicate,
			Value:       object,
			CreatedAt:   createdAt,
		}

		if metaStr.Valid && metaStr.String != "" {
			var fm factTripleMetadata
			if err := json.Unmarshal([]byte(metaStr.String), &fm); err != nil {
				slog.Warn("skipping fact with corrupt metadata",
					slog.String("entity_id", subject),
					slog.String("predicate", predicate),
					slog.String("error", err.Error()),
				)
				continue
			}
			f.ID = fm.FactID
			f.Confidence = fm.Confidence
			f.Source = fm.Source
		}

		facts = append(facts, f)
	}
	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating facts: %w", err)
	}

	return facts, nil
}

// Traverse performs a graph traversal from startID up to the given depth
// using a recursive CTE over the triples table, returning all reachable
// entities and the relationships connecting them.
func (k *KnowledgeStore) Traverse(ctx context.Context, startID string, depth int, filter store.TraversalFilter) (*store.Graph, error) {
	if depth <= 0 {
		depth = 1
	}

	// Respect filter.MaxDepth if set (and non-zero).
	// MaxDepth=0 means no limit (backward compatible).
	if filter.MaxDepth > 0 && filter.MaxDepth < depth {
		depth = filter.MaxDepth
	}

	// Look up workspace for scoping.
	workspace, err := k.lookupWorkspace(ctx, startID)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "looking up workspace for traversal: %w", err)
	}

	// Use recursive CTE to find all reachable nodes.
	var (
		qb   strings.Builder
		args []any
	)

	qb.WriteString(`WITH RECURSIVE reachable(node, depth) AS (
	SELECT ?, 0
	UNION
	SELECT CASE WHEN t.subject = r.node THEN t.object ELSE t.subject END, r.depth + 1
	FROM reachable r
	JOIN triples t ON (t.subject = r.node OR t.object = r.node)
		AND t.workspace = ?
		AND t.predicate NOT IN ('type', 'name')
		AND t.predicate NOT LIKE 'prop:%'
	WHERE r.depth < ?`)
	args = append(args, startID, workspace, depth)

	// Optionally filter relationship types.
	if len(filter.RelationshipTypes) > 0 {
		placeholders := strings.Repeat("?,", len(filter.RelationshipTypes))
		placeholders = placeholders[:len(placeholders)-1]
		qb.WriteString(` AND t.predicate IN (`)
		qb.WriteString(placeholders)
		qb.WriteString(`)`)
		for _, rt := range filter.RelationshipTypes {
			args = append(args, rt)
		}
	}

	qb.WriteString(`)
SELECT DISTINCT node FROM reachable`)

	rows, err := k.db.QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "traversing from %s: %w", startID, err)
	}
	defer func() { _ = rows.Close() }()

	nodeSet := make(map[string]bool)
	for rows.Next() {
		var node string
		if err := rows.Scan(&node); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning traversal node: %w", err)
		}
		nodeSet[node] = true
	}
	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating traversal nodes: %w", err)
	}

	// Collect entities for all reachable nodes.
	entities := make([]*store.Entity, 0, len(nodeSet))
	for id := range nodeSet {
		ent, err := k.GetEntity(ctx, workspace, id)
		if err != nil {
			// Only skip if entity not found; propagate DB errors
			if sigilerr.IsNotFound(err) {
				continue // Node might not be a full entity
			}
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "getting entity %s during traversal: %w", id, err)
		}
		entities = append(entities, ent)
	}

	// Collect relationships between reachable nodes.
	rels, err := k.getRelsBetweenNodes(ctx, workspace, nodeSet)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "collecting traversal relationships: %w", err)
	}

	return &store.Graph{
		Entities:      entities,
		Relationships: rels,
	}, nil
}

// getRelsBetweenNodes returns all relationship triples where both subject and
// object are in the given node set.
func (k *KnowledgeStore) getRelsBetweenNodes(ctx context.Context, workspace string, nodes map[string]bool) ([]*store.Relationship, error) {
	if len(nodes) == 0 {
		return nil, nil
	}

	ids := make([]any, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}

	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]

	q := `SELECT subject, predicate, object, metadata FROM triples
WHERE workspace = ?
	AND predicate NOT IN ('type', 'name')
	AND predicate NOT LIKE 'prop:%'
	AND json_extract(metadata, '$.rel_id') IS NOT NULL
	AND subject IN (` + placeholders + `)
	AND object IN (` + placeholders + `)`

	args := make([]any, 0, 1+len(ids)*2)
	args = append(args, workspace)
	args = append(args, ids...)
	args = append(args, ids...)

	rows, err := k.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var rels []*store.Relationship
	seen := make(map[string]bool)
	for rows.Next() {
		var subject, predicate, object string
		var metaStr sql.NullString

		if err := rows.Scan(&subject, &predicate, &object, &metaStr); err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "scanning relationship triple: %w", err)
		}

		rel := &store.Relationship{
			FromID: subject,
			ToID:   object,
			Type:   predicate,
		}

		if metaStr.Valid && metaStr.String != "" {
			var rm relTripleMetadata
			if err := json.Unmarshal([]byte(metaStr.String), &rm); err != nil {
				slog.Warn("skipping relationship with corrupt metadata",
					slog.String("from_id", subject),
					slog.String("to_id", object),
					slog.String("error", err.Error()),
				)
				continue
			}
			rel.ID = rm.RelID
			rel.Metadata = rm.Metadata
		}

		// Deduplicate by relationship ID.
		if rel.ID != "" && seen[rel.ID] {
			continue
		}
		if rel.ID != "" {
			seen[rel.ID] = true
		}

		rels = append(rels, rel)
	}
	if err := rows.Err(); err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeStoreDatabaseFailure, "iterating relationship triples: %w", err)
	}

	return rels, nil
}
