// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
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

	db, err := sql.Open("sqlite", filepath.Join(dir, "test.db"))
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
		// Regression tests for safeDefTokenRe character-class range bug
		// (sigil-7g5.652): ' -' created an unintended range U+0020..U+002D,
		// which admitted SQL metacharacters like !, $, (.
		{
			name:      "valid quoted default with hyphen",
			table:     "t",
			column:    "col_hyph",
			columnDef: "TEXT NOT NULL DEFAULT 'foo-bar'",
			wantErr:   false,
		},
		{
			name:        "quoted default with space rejected by tokenizer",
			table:       "t",
			column:      "col_sp",
			columnDef:   "TEXT NOT NULL DEFAULT 'foo bar'",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "reject exclamation in quoted default",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT DEFAULT 'bad!'",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "reject dollar in quoted default",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT DEFAULT '$var'",
			wantErr:     true,
			errContains: "unsafe token",
		},
		{
			name:        "reject paren in quoted default",
			table:       "t",
			column:      "col",
			columnDef:   "TEXT DEFAULT '(inject)'",
			wantErr:     true,
			errContains: "unsafe token",
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

// TestAddColumnIfMissing_Idempotency verifies that calling addColumnIfMissing
// twice with the same column name is a no-op: the second call must not return
// an error and must not corrupt the schema (no duplicate columns).
func TestAddColumnIfMissing_Idempotency(t *testing.T) {
	db := openTestDB(t)

	// First call: column does not exist yet — should add it.
	err := addColumnIfMissing(db, "t", "extra", "TEXT")
	require.NoError(t, err, "first addColumnIfMissing should succeed")

	// Second call: column already exists — must be a no-op, not an error.
	err = addColumnIfMissing(db, "t", "extra", "TEXT")
	require.NoError(t, err, "second addColumnIfMissing (duplicate) must be a no-op")

	// Confirm the schema has exactly the expected columns and no duplicates.
	rows, err := db.Query("PRAGMA table_info(t)")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var cols []string
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		require.NoError(t, rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk))
		cols = append(cols, name)
	}
	require.NoError(t, rows.Err())

	assert.Equal(t, []string{"id", "extra"}, cols, "schema must contain exactly the original column plus the added one, with no duplicates")
}

// TestSafeDefTokenRe_CharacterClassRange verifies that safeDefTokenRe treats
// hyphen as a literal character rather than creating a range from space
// (U+0020) to hyphen (U+002D). Regression test for sigil-7g5.652.
func TestSafeDefTokenRe_CharacterClassRange(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Characters that SHOULD match.
		{"plain identifier", "TEXT", true},
		{"quoted braces", "'{}'", true},
		{"quoted hyphen", "'foo-bar'", true},
		{"quoted with space", "'foo bar'", true},
		{"quoted with dot", "'1.0'", true},
		{"quoted with comma", "'a,b'", true},
		{"quoted with brackets", "'[0]'", true},

		// Characters between space and hyphen (U+0021..U+002C) that MUST be
		// rejected now that the range bug is fixed.
		{"reject exclamation", "'bad!'", false},
		{"reject double quote", "'say\"hi'", false},
		{"reject hash", "'#tag'", false},
		{"reject dollar", "'$var'", false},
		{"reject percent", "'100%'", false},
		{"reject ampersand", "'a&b'", false},
		{"reject open paren", "'f('", false},
		{"reject close paren", "'f)'", false},
		{"reject asterisk", "'a*b'", false},
		{"reject plus", "'a+b'", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeDefTokenRe.MatchString(tt.input)
			assert.Equal(t, tt.want, got, "safeDefTokenRe.MatchString(%q)", tt.input)
		})
	}
}
