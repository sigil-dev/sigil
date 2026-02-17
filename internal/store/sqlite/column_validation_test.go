// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openTestDB creates an in-memory (or temp-file) SQLite database for unit tests
// that need to exercise addColumnIfMissing against a real schema.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "sigil-coltest-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	db, err := sql.Open("sqlite3", filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`)
	require.NoError(t, err)
	return db
}

func TestAddColumnIfMissing_Validation(t *testing.T) {
	tests := []struct {
		name        string
		table       string
		column      string
		columnDef   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid simple type",
			table:     "t",
			column:    "col1",
			columnDef: "TEXT",
			wantErr:   false,
		},
		{
			name:      "valid composite def with keywords",
			table:     "t",
			column:    "col2",
			columnDef: "TEXT NOT NULL",
			wantErr:   false,
		},
		{
			name:      "valid def with quoted default",
			table:     "t",
			column:    "col3",
			columnDef: "TEXT NOT NULL DEFAULT '{}'",
			wantErr:   false,
		},
		{
			name:        "unsafe table name with semicolon",
			table:       "t;DROP TABLE t--",
			column:      "col",
			columnDef:   "TEXT",
			wantErr:     true,
			errContains: "unsafe table name",
		},
		{
			name:        "unsafe column name with injection",
			table:       "t",
			column:      "col--drop",
			columnDef:   "TEXT",
			wantErr:     true,
			errContains: "unsafe column name",
		},
		{
			name:        "unsafe token in middle of columnDef",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT NOT; NULL",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "unsafe token with SQL comment injection",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT --comment",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "unsafe token with semicolon in columnDef",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT; DROP TABLE t",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "unsafe quoted default with embedded quote",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT DEFAULT 'x''y'",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "empty columnDef",
			table:       "t",
			column:      "col",
			columnDef:   "",
			wantErr:     true,
			errContains: "empty column definition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			err := addColumnIfMissing(db, tt.table, tt.column, tt.columnDef)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
