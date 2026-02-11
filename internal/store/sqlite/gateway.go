// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	"github.com/sigil-dev/sigil/internal/store"
)

// Compile-time interface checks.
var (
	_ store.GatewayStore = (*GatewayStore)(nil)
	_ store.UserStore    = (*userStore)(nil)
	_ store.PairingStore = (*pairingStore)(nil)
	_ store.AuditStore   = (*auditStore)(nil)
)

// GatewayStore implements store.GatewayStore backed by a single SQLite database.
type GatewayStore struct {
	db       *sql.DB
	users    *userStore
	pairings *pairingStore
	audit    *auditStore
}

// NewGatewayStore opens (or creates) a SQLite database at dbPath and
// initialises the users, user_identities, pairings, and audit_log tables.
func NewGatewayStore(dbPath string) (*GatewayStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening gateway db: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging gateway db: %w", err)
	}

	if err := migrateGateway(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating gateway db: %w", err)
	}

	return &GatewayStore{
		db:       db,
		users:    &userStore{db: db},
		pairings: &pairingStore{db: db},
		audit:    &auditStore{db: db},
	}, nil
}

func migrateGateway(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS users (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	role       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_identities (
	user_id          TEXT NOT NULL,
	platform         TEXT NOT NULL,
	platform_user_id TEXT NOT NULL,
	display_name     TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (user_id, platform, platform_user_id),
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_identities_lookup
	ON user_identities(platform, platform_user_id);

CREATE TABLE IF NOT EXISTS pairings (
	id           TEXT PRIMARY KEY,
	user_id      TEXT NOT NULL,
	channel_type TEXT NOT NULL,
	channel_id   TEXT NOT NULL,
	workspace_id TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT 'pending',
	created_at   TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pairings_channel
	ON pairings(channel_type, channel_id);
CREATE INDEX IF NOT EXISTS idx_pairings_user
	ON pairings(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
	id           TEXT PRIMARY KEY,
	timestamp    TEXT NOT NULL,
	action       TEXT NOT NULL DEFAULT '',
	actor        TEXT NOT NULL DEFAULT '',
	plugin       TEXT NOT NULL DEFAULT '',
	workspace_id TEXT NOT NULL DEFAULT '',
	session_id   TEXT NOT NULL DEFAULT '',
	details      TEXT NOT NULL DEFAULT '{}',
	result       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action    ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor     ON audit_log(actor);
`
	_, err := db.Exec(ddl)
	return err
}

// Users returns the UserStore sub-store.
func (g *GatewayStore) Users() store.UserStore { return g.users }

// Pairings returns the PairingStore sub-store.
func (g *GatewayStore) Pairings() store.PairingStore { return g.pairings }

// AuditLog returns the AuditStore sub-store.
func (g *GatewayStore) AuditLog() store.AuditStore { return g.audit }

// Close closes the underlying database connection.
func (g *GatewayStore) Close() error { return g.db.Close() }

// ---------- userStore ----------

type userStore struct {
	db *sql.DB
}

func (s *userStore) Create(ctx context.Context, user *store.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning tx for user %s: %w", user.ID, err)
	}
	defer tx.Rollback() //nolint:errcheck

	const insertUser = `INSERT INTO users (id, name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`
	_, err = tx.ExecContext(ctx, insertUser,
		user.ID, user.Name, user.Role,
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("inserting user %s: %w", user.ID, err)
	}

	if err := insertIdentities(ctx, tx, user.ID, user.Identities); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *userStore) Get(ctx context.Context, id string) (*store.User, error) {
	const q = `SELECT id, name, role, created_at, updated_at FROM users WHERE id = ?`

	var u store.User
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, q, id).Scan(&u.ID, &u.Name, &u.Role, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user %s: %w", id, store.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("getting user %s: %w", id, err)
	}
	u.CreatedAt, err = ParseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing user %s created_at: %w", id, err)
	}
	u.UpdatedAt, err = ParseTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing user %s updated_at: %w", id, err)
	}

	ids, err := loadIdentities(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	u.Identities = ids

	return &u, nil
}

func (s *userStore) GetByExternalID(ctx context.Context, provider, externalID string) (*store.User, error) {
	const q = `SELECT u.id, u.name, u.role, u.created_at, u.updated_at
FROM users u
JOIN user_identities ui ON u.id = ui.user_id
WHERE ui.platform = ? AND ui.platform_user_id = ?`

	var u store.User
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, q, provider, externalID).Scan(
		&u.ID, &u.Name, &u.Role, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user with external id %s/%s: %w", provider, externalID, store.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("getting user by external id %s/%s: %w", provider, externalID, err)
	}
	u.CreatedAt, err = ParseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing user %s created_at: %w", u.ID, err)
	}
	u.UpdatedAt, err = ParseTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing user %s updated_at: %w", u.ID, err)
	}

	ids, err := loadIdentities(ctx, s.db, u.ID)
	if err != nil {
		return nil, err
	}
	u.Identities = ids

	return &u, nil
}

func (s *userStore) Update(ctx context.Context, user *store.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning tx for user update %s: %w", user.ID, err)
	}
	defer tx.Rollback() //nolint:errcheck

	const q = `UPDATE users SET name = ?, role = ?, updated_at = ? WHERE id = ?`
	result, err := tx.ExecContext(ctx, q, user.Name, user.Role, formatTime(user.UpdatedAt), user.ID)
	if err != nil {
		return fmt.Errorf("updating user %s: %w", user.ID, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows for user %s: %w", user.ID, err)
	}
	if rows == 0 {
		return fmt.Errorf("user %s: %w", user.ID, store.ErrNotFound)
	}

	// Replace identities: delete old, insert new.
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id = ?`, user.ID); err != nil {
		return fmt.Errorf("clearing identities for user %s: %w", user.ID, err)
	}
	if err := insertIdentities(ctx, tx, user.ID, user.Identities); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *userStore) List(ctx context.Context, opts store.ListOpts) ([]*store.User, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	const q = `SELECT id, name, role, created_at, updated_at FROM users ORDER BY created_at ASC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close() //nolint:errcheck // error on read-path close is not actionable

	var users []*store.User
	for rows.Next() {
		var u store.User
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.Name, &u.Role, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning user row: %w", err)
		}
		var err error
		u.CreatedAt, err = ParseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("parsing user %s created_at: %w", u.ID, err)
		}
		u.UpdatedAt, err = ParseTime(updatedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing user %s updated_at: %w", u.ID, err)
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating user rows: %w", err)
	}

	// Load identities for each user.
	for _, u := range users {
		ids, err := loadIdentities(ctx, s.db, u.ID)
		if err != nil {
			return nil, err
		}
		u.Identities = ids
	}

	return users, nil
}

func (s *userStore) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting user %s: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows for user %s: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("user %s: %w", id, store.ErrNotFound)
	}
	return nil
}

// ---------- identity helpers ----------

// execer abstracts *sql.DB and *sql.Tx for identity inserts.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertIdentities(ctx context.Context, ex execer, userID string, ids []store.UserIdentity) error {
	const q = `INSERT INTO user_identities (user_id, platform, platform_user_id, display_name) VALUES (?, ?, ?, ?)`
	for _, id := range ids {
		if _, err := ex.ExecContext(ctx, q, userID, id.Platform, id.PlatformUserID, id.DisplayName); err != nil {
			return fmt.Errorf("inserting identity %s/%s for user %s: %w", id.Platform, id.PlatformUserID, userID, err)
		}
	}
	return nil
}

func loadIdentities(ctx context.Context, db *sql.DB, userID string) ([]store.UserIdentity, error) {
	const q = `SELECT user_id, platform, platform_user_id, display_name FROM user_identities WHERE user_id = ? ORDER BY platform, platform_user_id`
	rows, err := db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("loading identities for user %s: %w", userID, err)
	}
	defer rows.Close() //nolint:errcheck // error on read-path close is not actionable

	var ids []store.UserIdentity
	for rows.Next() {
		var id store.UserIdentity
		if err := rows.Scan(&id.UserID, &id.Platform, &id.PlatformUserID, &id.DisplayName); err != nil {
			return nil, fmt.Errorf("scanning identity row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating identities: %w", err)
	}
	return ids, nil
}

// ---------- pairingStore ----------

type pairingStore struct {
	db *sql.DB
}

func (s *pairingStore) Create(ctx context.Context, pairing *store.Pairing) error {
	const q = `INSERT INTO pairings (id, user_id, channel_type, channel_id, workspace_id, status, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, q,
		pairing.ID, pairing.UserID, pairing.ChannelType, pairing.ChannelID,
		pairing.WorkspaceID, string(pairing.Status), formatTime(pairing.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("creating pairing %s: %w", pairing.ID, err)
	}
	return nil
}

func (s *pairingStore) GetByChannel(ctx context.Context, channelType, channelID string) (*store.Pairing, error) {
	const q = `SELECT id, user_id, channel_type, channel_id, workspace_id, status, created_at
FROM pairings WHERE channel_type = ? AND channel_id = ?`

	var p store.Pairing
	var createdAt string
	err := s.db.QueryRowContext(ctx, q, channelType, channelID).Scan(
		&p.ID, &p.UserID, &p.ChannelType, &p.ChannelID,
		&p.WorkspaceID, &p.Status, &createdAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("pairing for channel %s/%s: %w", channelType, channelID, store.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("getting pairing for channel %s/%s: %w", channelType, channelID, err)
	}
	p.CreatedAt, err = ParseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing pairing %s created_at: %w", p.ID, err)
	}
	return &p, nil
}

func (s *pairingStore) GetByUser(ctx context.Context, userID string) ([]*store.Pairing, error) {
	const q = `SELECT id, user_id, channel_type, channel_id, workspace_id, status, created_at
FROM pairings WHERE user_id = ? ORDER BY created_at ASC`

	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("listing pairings for user %s: %w", userID, err)
	}
	defer rows.Close() //nolint:errcheck // error on read-path close is not actionable

	var pairings []*store.Pairing
	for rows.Next() {
		var p store.Pairing
		var createdAt string
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.ChannelType, &p.ChannelID,
			&p.WorkspaceID, &p.Status, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("scanning pairing row: %w", err)
		}
		var err error
		p.CreatedAt, err = ParseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("parsing pairing %s created_at: %w", p.ID, err)
		}
		pairings = append(pairings, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating pairings: %w", err)
	}
	return pairings, nil
}

func (s *pairingStore) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM pairings WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting pairing %s: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows for pairing %s: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("pairing %s: %w", id, store.ErrNotFound)
	}
	return nil
}

// ---------- auditStore ----------

type auditStore struct {
	db *sql.DB
}

func (s *auditStore) Append(ctx context.Context, entry *store.AuditEntry) error {
	details := "{}"
	if entry.Details != nil {
		b, err := json.Marshal(entry.Details)
		if err != nil {
			return fmt.Errorf("marshalling audit details: %w", err)
		}
		details = string(b)
	}

	const q = `INSERT INTO audit_log (id, timestamp, action, actor, plugin, workspace_id, session_id, details, result)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, q,
		entry.ID, formatTime(entry.Timestamp), entry.Action, entry.Actor,
		entry.Plugin, entry.WorkspaceID, entry.SessionID, details, entry.Result,
	)
	if err != nil {
		return fmt.Errorf("appending audit entry %s: %w", entry.ID, err)
	}
	return nil
}

func (s *auditStore) Query(ctx context.Context, filter store.AuditFilter) ([]*store.AuditEntry, error) {
	var qb strings.Builder
	qb.WriteString(`SELECT id, timestamp, action, actor, plugin, workspace_id, session_id, details, result FROM audit_log`)

	var conditions []string
	var args []any

	if filter.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.Actor != "" {
		conditions = append(conditions, "actor = ?")
		args = append(args, filter.Actor)
	}
	if filter.Plugin != "" {
		conditions = append(conditions, "plugin = ?")
		args = append(args, filter.Plugin)
	}
	if filter.WorkspaceID != "" {
		conditions = append(conditions, "workspace_id = ?")
		args = append(args, filter.WorkspaceID)
	}
	if !filter.From.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, formatTime(filter.From))
	}
	if !filter.To.IsZero() {
		conditions = append(conditions, "timestamp < ?")
		args = append(args, formatTime(filter.To))
	}

	if len(conditions) > 0 {
		qb.WriteString(" WHERE ")
		qb.WriteString(strings.Join(conditions, " AND "))
	}

	qb.WriteString(" ORDER BY timestamp ASC")

	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}
	qb.WriteString(" LIMIT ? OFFSET ?")
	args = append(args, limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close() //nolint:errcheck // error on read-path close is not actionable

	var entries []*store.AuditEntry
	for rows.Next() {
		var e store.AuditEntry
		var ts, detailsJSON string
		if err := rows.Scan(
			&e.ID, &ts, &e.Action, &e.Actor, &e.Plugin,
			&e.WorkspaceID, &e.SessionID, &detailsJSON, &e.Result,
		); err != nil {
			return nil, fmt.Errorf("scanning audit row: %w", err)
		}
		var err error
		e.Timestamp, err = ParseTime(ts)
		if err != nil {
			return nil, fmt.Errorf("parsing audit entry %s timestamp: %w", e.ID, err)
		}
		if detailsJSON != "" && detailsJSON != "{}" {
			if err := json.Unmarshal([]byte(detailsJSON), &e.Details); err != nil {
				return nil, fmt.Errorf("unmarshalling audit details: %w", err)
			}
		}
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit entries: %w", err)
	}
	return entries, nil
}
