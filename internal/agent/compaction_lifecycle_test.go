// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/sigil-dev/sigil/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompaction_Compact_NoOpBelowThreshold(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "unused",
		facts:     []*store.Fact{{ID: "fact-unused"}},
		embedding: []float32{0.1, 0.2},
	}

	appendMessages(t, mem.messages, "ws-1", 4)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.SummariesCreated)
	assert.Equal(t, 0, result.FactsExtracted)
	assert.Equal(t, 0, result.MessagesProcessed)
	assert.Equal(t, 0, result.MessagesTrimmed)
	assert.Equal(t, 0, p.summarizeCalls)
	assert.Equal(t, 0, p.extractCalls)
	assert.Equal(t, 0, p.embedCalls)
	assert.Len(t, mem.summaries.summaries, 0)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_FullLifecycle_ExtractFactsEnabled(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary: "Summary: discussion about deployment and ownership",
		facts: []*store.Fact{
			{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95},
			{ID: "fact-2", EntityID: "project", Predicate: "status", Value: "active", Confidence: 0.90},
		},
		embedding: []float32{0.4, 0.3, 0.2},
	}

	appendMessages(t, mem.messages, "ws-1", 7)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.SummariesCreated)
	assert.Equal(t, 2, result.FactsExtracted)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, 5, result.MessagesTrimmed)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Equal(t, 1, p.extractCalls)
	assert.Equal(t, 1, p.embedCalls)

	require.Len(t, mem.summaries.summaries, 1)
	summary := mem.summaries.summaries[0]
	assert.Equal(t, "Summary: discussion about deployment and ownership", summary.Content)
	assert.Len(t, summary.MessageIDs, 5)
	assert.Equal(t, "msg-0", summary.MessageIDs[0])
	assert.Equal(t, "msg-4", summary.MessageIDs[4])

	require.Len(t, mem.knowledge.facts, 2)
	assert.Equal(t, "ws-1", mem.knowledge.facts[0].WorkspaceID)
	assert.Equal(t, "ws-1", mem.knowledge.facts[1].WorkspaceID)

	// Verify identity fields are overridden by compaction — not taken from the provider.
	// The summary ID follows the pattern "sum-<ts>-<hex>", so fact IDs must be
	// "<sumID>-fact-<index>" which matches "sum-<digits>-<hex>-fact-<index>".
	factIDPattern := regexp.MustCompile(`^sum-\d+-[0-9a-f]+-fact-\d+$`)
	for i, fact := range mem.knowledge.facts {
		assert.Regexp(t, factIDPattern, fact.ID,
			"fact[%d].ID must follow sum-<ts>-<hex>-fact-<index> pattern, got %q", i, fact.ID)
		assert.NotEqual(t, fmt.Sprintf("fact-%d", i+1), fact.ID,
			"fact[%d].ID must not be the provider-supplied value", i)
		assert.Equal(t, "compaction", fact.Source,
			"fact[%d].Source must be overridden to 'compaction'", i)
		assert.False(t, fact.CreatedAt.IsZero(),
			"fact[%d].CreatedAt must be non-zero", i)
		assert.WithinDuration(t, time.Now(), fact.CreatedAt, 10*time.Second,
			"fact[%d].CreatedAt must be set to approximately now", i)
	}

	count, err := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "oldest compacted batch should be trimmed")

	require.Len(t, vec.vectors, 1)
	for _, v := range vec.vectors {
		assert.Equal(t, []float32{0.4, 0.3, 0.2}, v.embedding)
		assert.Equal(t, "ws-1", v.metadata["workspace_id"])
		assert.Equal(t, "summary", v.metadata["kind"])
	}

	// Verify two-phase commit: summary stored as pending, then confirmed to committed.
	require.Len(t, mem.summaries.summaries, 1)
	assert.Equal(t, store.SummaryStatusCommitted, mem.summaries.summaries[0].Status,
		"Compact() must promote summary to committed after Confirm")
	assert.True(t, mem.summaries.confirmCalled, "Confirm must be called after successful compaction")
}

func TestCompaction_Compact_FullLifecycle_ExtractFactsDisabled(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "Summary without fact extraction",
		facts:     []*store.Fact{{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95}},
		embedding: []float32{0.8, 0.1},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,

	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 1, result.SummariesCreated)
	assert.Equal(t, 0, result.FactsExtracted)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, 5, result.MessagesTrimmed)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Equal(t, 0, p.extractCalls, "fact extraction should be skipped when disabled")
	assert.Equal(t, 1, p.embedCalls)
	assert.Len(t, mem.knowledge.facts, 0)
}

func TestCompaction_Compact_SummarizeProviderFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summarizeErr: fmt.Errorf("summarize failed"),
		embedding:    []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Len(t, mem.summaries.summaries, 0)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_SummaryStoreFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	mem.summaries.storeErr = fmt.Errorf("summary store failed")
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, p.summarizeCalls)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
}

func TestCompaction_Compact_FactExtractionProviderFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:    "summary",
		extractErr: fmt.Errorf("extract facts failed"),
		embedding:  []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, 1, p.extractCalls)
	assert.Len(t, mem.summaries.summaries, 1, "summary is stored before extraction stage")
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
	assert.Len(t, mem.summaries.deletedIDs, 1, "Delete must be called once to clean up pending summary")
}

func TestCompaction_Compact_KnowledgeStoreFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	mem.knowledge.putFactErr = fmt.Errorf("knowledge store failed")
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary: "summary",
		facts: []*store.Fact{
			{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95},
		},
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Len(t, mem.summaries.summaries, 1)
	assert.Len(t, mem.knowledge.facts, 0)
	assert.Len(t, vec.vectors, 0)
	assert.Len(t, mem.summaries.deletedIDs, 1, "Delete must be called once to clean up pending summary")
}

func TestCompaction_Compact_EmbeddingProviderFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:  "summary",
		embedErr: fmt.Errorf("embed failed"),
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,

	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Len(t, mem.summaries.summaries, 1)
	assert.Len(t, vec.vectors, 0)
	assert.Len(t, mem.summaries.deletedIDs, 1, "Delete must be called once to clean up pending summary")
}

func TestCompaction_Compact_VectorStoreFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	vec.storeErr = fmt.Errorf("vector store failed")

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,

	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)

	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(5), count, "messages should not trim when vector storage fails")
	assert.Len(t, mem.summaries.deletedIDs, 1, "Delete must be called once to clean up pending summary")
}

func TestCompaction_Compact_VectorDeleteFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	vec.deleteErr = fmt.Errorf("vector delete failed")

	p := &mockCompactionProvider{
		summary: "summary",
		facts: []*store.Fact{
			{ID: "fact-1", EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.95},
		},
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:   mem,
		VectorStore:   vec,

		Summarizer:    p,
		Embedder:      p,
		BatchSize:     5,
		FactExtractor: p,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)

	// Summary and facts were committed before Delete was called.
	assert.Len(t, mem.summaries.summaries, 1, "summary should be stored before Delete is called")
	assert.Len(t, mem.knowledge.facts, 1, "facts should be stored before Delete is called")

	// The summary embedding was stored before Delete was called; it should be present.
	// The message placeholder vectors (from RollMessage) are not in this test setup,
	// but Delete was not called so no vectors were removed.
	assert.Len(t, vec.vectors, 1, "summary embedding should be stored; Delete did not run so no removal occurred")

	// Messages were not trimmed (DeleteByIDs was not reached).
	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(5), count, "messages should not be trimmed when vector Delete fails")
	assert.Len(t, mem.summaries.deletedIDs, 1, "Delete must be called once to clean up pending summary")
}

func TestCompaction_Compact_DeleteCleanupFailure(t *testing.T) {
	// When the deferred Delete() call to clean up the pending summary itself fails,
	// the primary error from the failing step must still be returned — the cleanup
	// error must not be swallowed or replace the original error.
	mem := newLifecycleMemoryStore()
	mem.summaries.deleteErr = fmt.Errorf("delete cleanup failed")
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:  "summary",
		embedErr: fmt.Errorf("embed failed"),
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore: mem,
		VectorStore: vec,

		Summarizer: p,
		Embedder:   p,
		BatchSize:  5,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "embed failed", "primary error must be returned even when cleanup Delete fails")
	assert.Len(t, mem.summaries.deletedIDs, 1, "Delete must be called once to attempt cleanup")
}

func TestCompaction_Compact_DeleteByIDsFailure(t *testing.T) {
	// In the new order, Confirm runs before DeleteByIDs. Confirm succeeds here,
	// so the summary is committed (confirmed=true) and the defer does NOT clean
	// it up. Messages still exist because DeleteByIDs failed — duplicate but
	// recoverable (summary committed, messages not yet trimmed).
	mem := newLifecycleMemoryStore()
	mem.messages.deleteErr = fmt.Errorf("delete failed")
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore: mem,
		VectorStore: vec,

		Summarizer: p,
		Embedder:   p,
		BatchSize:  5,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	// DeleteByIDs failed after Confirm — partial commit with recovery data.
	require.NotNil(t, result)
	assert.True(t, result.PartialCommit)
	assert.Equal(t, mem.summaries.summaries[0].ID, result.SummaryID, "SummaryID must match the committed summary")
	assert.ElementsMatch(t, []string{"msg-0", "msg-1", "msg-2", "msg-3", "msg-4"}, result.MessageIDs, "MessageIDs must contain the exact batch message IDs")
	// Summary is committed (Confirm succeeded before DeleteByIDs was reached).
	assert.Len(t, mem.summaries.summaries, 1)
	assert.Len(t, vec.vectors, 1)
}

func TestCompaction_Compact_ConfirmFailure(t *testing.T) {
	// Confirm is now called before DeleteByIDs. If Confirm fails, no messages
	// have been deleted yet — the failure is fully reversible. The pending
	// summary is cleaned up by the defer block (confirmed remains false).
	mem := newLifecycleMemoryStore()
	mem.summaries.confirmErr = fmt.Errorf("confirm failed")
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore: mem,
		VectorStore: vec,

		Summarizer: p,
		Embedder:   p,
		BatchSize:  5,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)

	// Summary was stored (as pending) before Confirm was called, but the
	// pending record remains (SummaryStore.Delete tracks the ID, not removal from slice).
	assert.Len(t, mem.summaries.summaries, 1, "summary should be stored before Confirm is called")

	// Defer cleanup called SummaryStore.Delete to remove the orphaned pending summary.
	assert.Len(t, mem.summaries.deletedIDs, 1, "defer should delete orphaned pending summary")

	// Defer cleanup called VectorStore.Delete — embedding removed from store.
	assert.Len(t, vec.vectors, 0, "defer should remove orphaned vector embedding")

	// Messages were NOT deleted — Confirm failed before DeleteByIDs was reached.
	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(5), count, "messages are preserved when Confirm fails — no data loss")
}

func TestCompaction_Compact_OrphanVectorRetryQueue(t *testing.T) {
	// Scenario:
	// 1. First Compact(): summary embedding is stored (embeddingStored=true), then
	//    Confirm fails so the defer runs with confirmed=false. The defer calls
	//    VectorStore.Delete which fails on call #2 (the defer cleanup), so the
	//    summary ID is queued in pendingOrphans.
	// 2. PendingOrphanCount() == 1 after the failed Compact.
	// 3. Second Compact(): drainOrphans() runs first, retries the delete which now
	//    succeeds (deleteErrOnCall=2 means only call #2 fails). The orphan is cleared.
	// 4. PendingOrphanCount() == 0 after the successful drain.

	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()
	// Fail VectorStore.Delete only on call #2: the defer cleanup in Compact 1.
	// Call #1 is the per-batch-IDs delete (succeeds), call #2 is the defer cleanup
	// of the summary embedding (fails → orphan queued), call #3 is drainOrphans
	// in the second Compact (succeeds).
	vec.deleteErr = fmt.Errorf("vector delete transient failure")
	vec.deleteErrOnCall = 2

	mem.summaries.confirmErr = fmt.Errorf("confirm failed")

	p := &mockCompactionProvider{
		summary:   "summary for orphan test",
		embedding: []float32{0.5, 0.6},
	}

	// First compaction: 5 messages → triggers Compact.
	appendMessages(t, mem.messages, "ws-orphan", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore: mem,
		VectorStore: vec,
		Summarizer:  p,
		Embedder:    p,
		BatchSize:   5,
	})
	require.NoError(t, newErr)

	// First Compact: Confirm fails → defer runs → VectorStore.Delete fails → orphan queued.
	result, err := c.Compact(context.Background(), "ws-orphan")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "confirming compaction summary")

	// The vector ID should be in the orphan queue.
	assert.Equal(t, 1, c.PendingOrphanCount(), "failed defer Delete must add ID to pendingOrphans")

	// Verify the summary embedding is still in the vector store (delete failed).
	assert.Len(t, vec.vectors, 1, "summary embedding should remain after failed delete")

	// Remove the Confirm error so the second Compact can succeed.
	mem.summaries.confirmErr = nil
	// Also need fresh messages to exceed the batch threshold again.
	appendMessages(t, mem.messages, "ws-orphan", 5, 5)

	// Second Compact: drainOrphans() runs first (retry succeeds), then full compaction.
	result2, err2 := c.Compact(context.Background(), "ws-orphan")
	require.NoError(t, err2)
	require.NotNil(t, result2)

	// Orphan queue drained successfully.
	assert.Equal(t, 0, c.PendingOrphanCount(), "orphan must be drained after successful retry")

	// The orphaned vector from the first Compact was deleted during drainOrphans.
	// The second Compact then stored a new summary embedding and deleted message vectors.
	// At the end, only the new summary embedding should remain.
	assert.Len(t, vec.vectors, 1, "only the second summary embedding should remain after drain and compaction")

	// Verify Delete was called at least twice: once in the first defer (failed) and
	// once via drainOrphans (succeeded), plus the per-message delete in the second Compact.
	assert.GreaterOrEqual(t, vec.deleteCalls, 2, "Delete must be called at least twice across both Compact calls")
}

func TestCompaction_Compact_PreservesMessageAppendedDuringCompaction(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
		summarizeHook: func() error {
			return mem.messages.Append(context.Background(), "ws-1", &store.Message{
				ID:        "msg-appended",
				Role:      store.MessageRoleUser,
				Content:   "appended while compacting",
				CreatedAt: time.Now().UTC(),
			})
		},
	}

	appendMessages(t, mem.messages, "ws-1", 5)

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,

	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, 5, result.MessagesTrimmed)

	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(1), count, "newly appended message must be preserved")

	messages, rangeErr := mem.messages.GetRange(
		context.Background(),
		"ws-1",
		time.Time{},
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	)
	require.NoError(t, rangeErr)
	require.Len(t, messages, 1)
	assert.Equal(t, "msg-appended", messages[0].ID)
}

func TestCompaction_Compact_PreservesMessageAppendedAfterCountBeforeDelete(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)
	mem.messages.appendBeforeDelete = func() error {
		return mem.messages.Append(context.Background(), "ws-1", &store.Message{
			ID:        "msg-appended-after-count",
			Role:      store.MessageRoleUser,
			Content:   "appended after count before delete",
			CreatedAt: time.Now().UTC(),
		})
	}

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:           mem,
		VectorStore:           vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:             5,

	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 5, result.MessagesProcessed)
	assert.Equal(t, 5, result.MessagesTrimmed)

	count, countErr := mem.messages.Count(context.Background(), "ws-1")
	require.NoError(t, countErr)
	assert.Equal(t, int64(1), count, "message appended after count must be preserved")

	messages, rangeErr := mem.messages.GetRange(
		context.Background(),
		"ws-1",
		time.Time{},
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	)
	require.NoError(t, rangeErr)
	require.Len(t, messages, 1)
	assert.Equal(t, "msg-appended-after-count", messages[0].ID)
}

type lifecycleMemoryStore struct {
	messages  *lifecycleMessageStore
	summaries *lifecycleSummaryStore
	knowledge *lifecycleKnowledgeStore
}

func newLifecycleMemoryStore() *lifecycleMemoryStore {
	return &lifecycleMemoryStore{
		messages:  &lifecycleMessageStore{},
		summaries: &lifecycleSummaryStore{},
		knowledge: &lifecycleKnowledgeStore{},
	}
}

func (m *lifecycleMemoryStore) Messages() store.MessageStore    { return m.messages }
func (m *lifecycleMemoryStore) Summaries() store.SummaryStore   { return m.summaries }
func (m *lifecycleMemoryStore) Knowledge() store.KnowledgeStore { return m.knowledge }
func (m *lifecycleMemoryStore) Close() error                    { return nil }

type lifecycleMessageStore struct {
	msgs               []*store.Message
	countErr           error
	getRangeErr        error
	getOldestErr       error
	deleteErr          error
	appendBeforeDelete func() error
}

func (m *lifecycleMessageStore) Append(_ context.Context, _ string, msg *store.Message) error {
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *lifecycleMessageStore) Search(_ context.Context, _ string, _ string, _ store.SearchOpts) ([]*store.Message, error) {
	return nil, nil
}

func (m *lifecycleMessageStore) GetRange(_ context.Context, _ string, from, to time.Time, limit ...int) ([]*store.Message, error) {
	if m.getRangeErr != nil {
		return nil, m.getRangeErr
	}
	var inRange []*store.Message
	for _, msg := range m.msgs {
		if (msg.CreatedAt.Equal(from) || msg.CreatedAt.After(from)) && msg.CreatedAt.Before(to) {
			inRange = append(inRange, msg)
		}
	}
	sort.Slice(inRange, func(i, j int) bool {
		return inRange[i].CreatedAt.Before(inRange[j].CreatedAt)
	})
	n := 0
	if len(limit) > 0 {
		n = limit[0]
	}
	if n > 0 && n < len(inRange) {
		inRange = inRange[:n]
	}
	return inRange, nil
}

func (m *lifecycleMessageStore) GetOldest(_ context.Context, _ string, n int) ([]*store.Message, error) {
	if m.getOldestErr != nil {
		return nil, m.getOldestErr
	}
	sorted := make([]*store.Message, len(m.msgs))
	copy(sorted, m.msgs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	if n <= 0 {
		return []*store.Message{}, nil
	}
	if n < len(sorted) {
		sorted = sorted[:n]
	}
	return sorted, nil
}

func (m *lifecycleMessageStore) Count(_ context.Context, _ string) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.msgs)), nil
}

func (m *lifecycleMessageStore) Trim(_ context.Context, _ string, keepLast int) (int64, error) {
	if keepLast < 0 {
		keepLast = 0
	}

	sort.Slice(m.msgs, func(i, j int) bool {
		return m.msgs[i].CreatedAt.Before(m.msgs[j].CreatedAt)
	})

	if keepLast >= len(m.msgs) {
		return 0, nil
	}

	toTrim := len(m.msgs) - keepLast
	m.msgs = append([]*store.Message(nil), m.msgs[toTrim:]...)
	return int64(toTrim), nil
}

func (m *lifecycleMessageStore) DeleteByIDs(_ context.Context, _ string, ids []string) (int64, error) {
	if m.deleteErr != nil {
		return 0, m.deleteErr
	}
	if m.appendBeforeDelete != nil {
		if err := m.appendBeforeDelete(); err != nil {
			return 0, err
		}
		m.appendBeforeDelete = nil
	}

	if len(ids) == 0 {
		return 0, nil
	}

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idSet[id] = struct{}{}
	}

	var kept []*store.Message
	var deleted int64
	for _, msg := range m.msgs {
		if _, ok := idSet[msg.ID]; ok {
			deleted++
			continue
		}
		kept = append(kept, msg)
	}
	m.msgs = kept
	return deleted, nil
}

func (m *lifecycleMessageStore) Close() error { return nil }

type lifecycleSummaryStore struct {
	summaries     []*store.Summary
	storeErr      error
	confirmErr    error
	deleteErr     error
	deletedIDs    []string
	confirmCalled bool
}

func (s *lifecycleSummaryStore) Store(_ context.Context, _ string, summary *store.Summary) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.summaries = append(s.summaries, summary)
	return nil
}

func (s *lifecycleSummaryStore) GetByRange(_ context.Context, _ string, from, to time.Time) ([]*store.Summary, error) {
	var out []*store.Summary
	for _, summary := range s.summaries {
		if summary.Status != store.SummaryStatusCommitted {
			continue
		}
		if !summary.FromTime.Before(from) && !summary.ToTime.After(to) {
			out = append(out, summary)
		}
	}
	return out, nil
}

func (s *lifecycleSummaryStore) GetLatest(_ context.Context, _ string, n int) ([]*store.Summary, error) {
	if n <= 0 || len(s.summaries) == 0 {
		return nil, nil
	}

	var committed []*store.Summary
	for _, summary := range s.summaries {
		if summary.Status == store.SummaryStatusCommitted {
			committed = append(committed, summary)
		}
	}
	if len(committed) == 0 {
		return nil, nil
	}

	sorted := append([]*store.Summary(nil), committed...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
	})
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n], nil
}

func (s *lifecycleSummaryStore) Confirm(_ context.Context, _ string, summaryID string) error {
	s.confirmCalled = true
	if s.confirmErr != nil {
		return s.confirmErr
	}
	for _, summary := range s.summaries {
		if summary.ID == summaryID {
			summary.Status = store.SummaryStatusCommitted
			break
		}
	}
	return nil
}

func (s *lifecycleSummaryStore) Delete(_ context.Context, _ string, id string) error {
	s.deletedIDs = append(s.deletedIDs, id)
	return s.deleteErr
}

func (s *lifecycleSummaryStore) Close() error { return nil }

type lifecycleKnowledgeStore struct {
	facts      []*store.Fact
	putFactErr error
}

func (k *lifecycleKnowledgeStore) PutEntity(_ context.Context, _ string, _ *store.Entity) error { return nil }
func (k *lifecycleKnowledgeStore) GetEntity(_ context.Context, _ string, _ string) (*store.Entity, error) {
	return nil, nil
}
func (k *lifecycleKnowledgeStore) FindEntities(_ context.Context, _ string, _ store.EntityQuery) ([]*store.Entity, error) {
	return nil, nil
}
func (k *lifecycleKnowledgeStore) PutRelationship(_ context.Context, _ *store.Relationship) error { return nil }
func (k *lifecycleKnowledgeStore) GetRelationships(_ context.Context, _ string, _ store.RelOpts) ([]*store.Relationship, error) {
	return nil, nil
}

func (k *lifecycleKnowledgeStore) PutFact(_ context.Context, _ string, fact *store.Fact) error {
	if k.putFactErr != nil {
		return k.putFactErr
	}
	k.facts = append(k.facts, fact)
	return nil
}

func (k *lifecycleKnowledgeStore) PutFacts(_ context.Context, _ string, facts []*store.Fact) error {
	if k.putFactErr != nil {
		return k.putFactErr
	}
	k.facts = append(k.facts, facts...)
	return nil
}

func (k *lifecycleKnowledgeStore) FindFacts(_ context.Context, _ string, _ store.FactQuery) ([]*store.Fact, error) {
	return k.facts, nil
}

func (k *lifecycleKnowledgeStore) Traverse(_ context.Context, _ string, _ int, _ store.TraversalFilter) (*store.Graph, error) {
	return nil, nil
}

func (k *lifecycleKnowledgeStore) Close() error { return nil }

type lifecycleVector struct {
	embedding []float32
	metadata  map[string]any
}

type lifecycleVectorStore struct {
	vectors         map[string]lifecycleVector
	storeErr        error
	searchErr       error
	deleteErr       error
	deleteErrOnCall int // if > 0, return deleteErr only on this specific call number (1-indexed)
	deleteCalls     int // total number of Delete calls made
}

func newLifecycleVectorStore() *lifecycleVectorStore {
	return &lifecycleVectorStore{
		vectors: make(map[string]lifecycleVector),
	}
}

func (v *lifecycleVectorStore) Store(_ context.Context, id string, embedding []float32, metadata map[string]any) error {
	if v.storeErr != nil {
		return v.storeErr
	}
	v.vectors[id] = lifecycleVector{embedding: embedding, metadata: metadata}
	return nil
}

func (v *lifecycleVectorStore) Search(_ context.Context, _ []float32, _ int, _ map[string]any) ([]store.VectorResult, error) {
	if v.searchErr != nil {
		return nil, v.searchErr
	}
	return nil, nil
}

func (v *lifecycleVectorStore) Delete(_ context.Context, ids []string) error {
	v.deleteCalls++
	if v.deleteErr != nil {
		// If deleteErrOnCall is set, fail only on that specific call number.
		// If deleteErrOnCall is zero, fail on every call.
		if v.deleteErrOnCall == 0 || v.deleteCalls == v.deleteErrOnCall {
			return v.deleteErr
		}
	}
	for _, id := range ids {
		delete(v.vectors, id)
	}
	return nil
}

func (v *lifecycleVectorStore) Close() error { return nil }

type mockCompactionProvider struct {
	summary string
	facts   []*store.Fact

	embedding []float32

	summarizeErr error
	extractErr   error
	embedErr     error

	summarizeHook func() error

	summarizeCalls int
	extractCalls   int
	embedCalls     int
}

func (m *mockCompactionProvider) Summarize(_ context.Context, _ []*store.Message) (string, error) {
	m.summarizeCalls++
	if m.summarizeHook != nil {
		if err := m.summarizeHook(); err != nil {
			return "", err
		}
	}
	if m.summarizeErr != nil {
		return "", m.summarizeErr
	}
	return m.summary, nil
}

func (m *mockCompactionProvider) ExtractFacts(_ context.Context, _ string, _ []*store.Message) ([]*store.Fact, error) {
	m.extractCalls++
	if m.extractErr != nil {
		return nil, m.extractErr
	}
	return m.facts, nil
}

func (m *mockCompactionProvider) Embed(_ context.Context, _ string) ([]float32, error) {
	m.embedCalls++
	if m.embedErr != nil {
		return nil, m.embedErr
	}
	return m.embedding, nil
}

func TestCompaction_storeFacts_Sanitization(t *testing.T) {
	tests := []struct {
		name          string
		inputFacts    []*store.Fact
		wantFactCount int
		checkFacts    func(t *testing.T, facts []*store.Fact)
	}{
		{
			name: "101 facts capped to 100",
			inputFacts: func() []*store.Fact {
				facts := make([]*store.Fact, 101)
				for i := range facts {
					facts[i] = &store.Fact{
						EntityID:   fmt.Sprintf("entity-%d", i),
						Predicate:  "role",
						Value:      "engineer",
						Confidence: 0.9,
					}
				}
				return facts
			}(),
			wantFactCount: 100,
		},
		{
			name: "nil entry mid-slice is skipped",
			inputFacts: []*store.Fact{
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.9},
				nil,
				{EntityID: "bob", Predicate: "role", Value: "manager", Confidence: 0.8},
			},
			wantFactCount: 2,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				entityIDs := make([]string, 0, len(facts))
				for _, f := range facts {
					entityIDs = append(entityIDs, f.EntityID)
				}
				assert.Contains(t, entityIDs, "alice")
				assert.Contains(t, entityIDs, "bob")
			},
		},
		{
			name: "empty EntityID is skipped",
			inputFacts: []*store.Fact{
				{EntityID: "", Predicate: "role", Value: "engineer", Confidence: 0.9},
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 0.9},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				assert.Equal(t, "alice", facts[0].EntityID)
			},
		},
		{
			name: "EntityID longer than 4096 chars is truncated",
			inputFacts: []*store.Fact{
				{
					EntityID:   strings.Repeat("x", 5000),
					Predicate:  "role",
					Value:      "engineer",
					Confidence: 0.9,
				},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				assert.Equal(t, 4096, len(facts[0].EntityID))
			},
		},
		{
			name: "Confidence NaN stored as 0.0",
			inputFacts: []*store.Fact{
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: math.NaN()},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				assert.Equal(t, 0.0, facts[0].Confidence)
			},
		},
		{
			name: "Confidence -0.5 stored as 0.0",
			inputFacts: []*store.Fact{
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: -0.5},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				assert.Equal(t, 0.0, facts[0].Confidence)
			},
		},
		{
			name: "Confidence 1.5 stored as 1.0",
			inputFacts: []*store.Fact{
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: 1.5},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				assert.Equal(t, 1.0, facts[0].Confidence)
			},
		},
		{
			name: "all facts have empty EntityID — zero stored",
			inputFacts: []*store.Fact{
				{EntityID: "", Predicate: "role", Value: "engineer", Confidence: 0.9},
				{EntityID: "", Predicate: "team", Value: "platform", Confidence: 0.8},
			},
			wantFactCount: 0,
		},
		{
			name: "all nil facts — zero stored",
			inputFacts: []*store.Fact{nil, nil, nil},
			wantFactCount: 0,
		},
		{
			name: "Confidence +Inf stored as 0.0",
			inputFacts: []*store.Fact{
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: math.Inf(1)},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				// +Inf matches IsInf branch, clamped to 0 before the >1 check.
				assert.Equal(t, 0.0, facts[0].Confidence)
			},
		},
		{
			name: "Confidence -Inf stored as 0.0",
			inputFacts: []*store.Fact{
				{EntityID: "alice", Predicate: "role", Value: "engineer", Confidence: math.Inf(-1)},
			},
			wantFactCount: 1,
			checkFacts: func(t *testing.T, facts []*store.Fact) {
				t.Helper()
				require.Len(t, facts, 1)
				assert.Equal(t, 0.0, facts[0].Confidence)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := newLifecycleMemoryStore()
			vec := newLifecycleVectorStore()
		
			p := &mockCompactionProvider{
				summary:   "test summary",
				facts:     tt.inputFacts,
				embedding: []float32{0.1},
			}

			// Need enough messages to exceed BatchSize and trigger Compact.
			appendMessages(t, mem.messages, "ws-san", 5)

			c, newErr := agent.NewCompactor(agent.CompactorConfig{
				MemoryStore:   mem,
				VectorStore:   vec,
		
				Summarizer:    p,
				Embedder:      p,
				BatchSize:     5,
				FactExtractor: p,
			})
			require.NoError(t, newErr)

			result, err := c.Compact(context.Background(), "ws-san")
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.wantFactCount, result.FactsExtracted)
			assert.Len(t, mem.knowledge.facts, tt.wantFactCount)

			if tt.checkFacts != nil {
				tt.checkFacts(t, mem.knowledge.facts)
			}
		})
	}
}

func TestCompaction_Compact_EmptyWorkspaceID(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:  mem,
		VectorStore:  vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:    5,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "workspaceID must not be empty")
}

func TestCompaction_Compact_CountFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	mem.messages.countErr = fmt.Errorf("count failed")
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:  mem,
		VectorStore:  vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:    5,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "counting messages")
}

func TestCompaction_Compact_LoadBatchFailure(t *testing.T) {
	mem := newLifecycleMemoryStore()
	vec := newLifecycleVectorStore()

	p := &mockCompactionProvider{
		summary:   "summary",
		embedding: []float32{1.0},
	}

	appendMessages(t, mem.messages, "ws-1", 5)
	mem.messages.getOldestErr = fmt.Errorf("get oldest failed")

	c, newErr := agent.NewCompactor(agent.CompactorConfig{
		MemoryStore:  mem,
		VectorStore:  vec,

		Summarizer:   p,
		Embedder:     p,
		BatchSize:    5,
	})
	require.NoError(t, newErr)

	result, err := c.Compact(context.Background(), "ws-1")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "loading compaction batch")
}

func appendMessages(t *testing.T, ms *lifecycleMessageStore, workspaceID string, n int, startIndex ...int) {
	t.Helper()

	start := 0
	if len(startIndex) > 0 {
		start = startIndex[0]
	}

	now := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	for i := range n {
		idx := start + i
		err := ms.Append(context.Background(), workspaceID, &store.Message{
			ID:        fmt.Sprintf("msg-%d", idx),
			Role:      store.MessageRoleUser,
			Content:   fmt.Sprintf("message %d", idx),
			CreatedAt: now.Add(time.Duration(idx) * time.Minute),
		})
		require.NoError(t, err)
	}
}
