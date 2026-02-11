// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store_test

import (
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
)

func TestSessionStatusValues(t *testing.T) {
	assert.Equal(t, store.SessionStatus("active"), store.SessionStatusActive)
	assert.Equal(t, store.SessionStatus("paused"), store.SessionStatusPaused)
	assert.Equal(t, store.SessionStatus("archived"), store.SessionStatusArchived)
}

func TestMessageRoleValues(t *testing.T) {
	assert.Equal(t, store.MessageRole("user"), store.MessageRoleUser)
	assert.Equal(t, store.MessageRole("assistant"), store.MessageRoleAssistant)
	assert.Equal(t, store.MessageRole("system"), store.MessageRoleSystem)
	assert.Equal(t, store.MessageRole("tool"), store.MessageRoleTool)
}

func TestListOptsDefaults(t *testing.T) {
	opts := store.ListOpts{}
	assert.Equal(t, 0, opts.Limit)
	assert.Equal(t, 0, opts.Offset)
}

func TestSearchOptsFields(t *testing.T) {
	opts := store.SearchOpts{
		Limit:  10,
		Offset: 0,
	}
	assert.Equal(t, 10, opts.Limit)
}

func TestVectorResultFields(t *testing.T) {
	result := store.VectorResult{
		ID:       "vec-1",
		Score:    0.95,
		Metadata: map[string]any{"source": "test"},
	}
	assert.Equal(t, "vec-1", result.ID)
	assert.InDelta(t, 0.95, result.Score, 0.001)
}

func TestEntityFields(t *testing.T) {
	entity := store.Entity{
		ID:          "ent-1",
		WorkspaceID: "ws-1",
		Type:        "person",
		Name:        "Alice",
		Properties:  map[string]any{"role": "engineer"},
		CreatedAt:   time.Now(),
	}
	assert.Equal(t, "person", entity.Type)
}
