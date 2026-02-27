// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Sentinel time bounds for querying all messages regardless of timestamp.
var (
	timeMin = time.Time{}
	timeMax = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// ShouldCompact returns true when count >= batchSize, indicating
// that enough messages have accumulated to trigger a compaction pass.
func ShouldCompact(count int64, batchSize int) bool {
	return count >= int64(batchSize)
}

// Summarizer performs summarization and fact extraction for the
// compaction lifecycle.
type Summarizer interface {
	Summarize(ctx context.Context, messages []*store.Message) (string, error)
	ExtractFacts(ctx context.Context, summary string, messages []*store.Message) ([]*store.Fact, error)
}

// Embedder generates vector embeddings from text.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// CompactorConfig holds the dependencies and tuning parameters for a Compactor.
type CompactorConfig struct {
	MemoryStore  store.MemoryStore
	VectorStore  store.VectorStore
	SessionStore store.SessionStore
	Summarizer   Summarizer
	Embedder     Embedder
	BatchSize    int
	ExtractFacts bool
}

// Compactor manages the memory compaction lifecycle: rolling messages into
// long-term storage and (in Phase 6) summarising and extracting facts.
type Compactor struct {
	cfg CompactorConfig
}

// CompactionResult reports the work completed by one Compact pass.
type CompactionResult struct {
	SummariesCreated  int
	FactsExtracted    int
	MessagesProcessed int
	MessagesTrimmed   int64
}

// NewCompactor creates a Compactor with the given configuration.
// Returns an error if required dependencies are nil or BatchSize is not positive.
func NewCompactor(cfg CompactorConfig) (*Compactor, error) {
	if cfg.MemoryStore == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "CompactorConfig.MemoryStore must not be nil")
	}
	if cfg.VectorStore == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "CompactorConfig.VectorStore must not be nil")
	}
	if cfg.BatchSize <= 0 {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "CompactorConfig.BatchSize must be positive")
	}
	return &Compactor{cfg: cfg}, nil
}

// RollMessage appends a message to Tier 1 (message store) and stores a
// placeholder embedding in Tier 4 (vector store). Full compaction
// (summarise + extract facts) is deferred to Phase 6.
func (c *Compactor) RollMessage(ctx context.Context, workspaceID, sessionID string, msg *store.Message) error {
	if err := c.cfg.MemoryStore.Messages().Append(ctx, workspaceID, msg); err != nil {
		return err
	}

	return c.cfg.VectorStore.Store(ctx, msg.ID, []float32{0}, map[string]any{
		"workspace_id": workspaceID,
		"session_id":   sessionID,
		"content":      msg.Content,
	})
}

// Compact executes one full memory compaction pass for a workspace:
// summarize oldest Tier-1 messages, optionally extract facts, store summary
// embedding, then delete the compacted messages from Tier 1.
func (c *Compactor) Compact(ctx context.Context, workspaceID string) (*CompactionResult, error) {
	if workspaceID == "" {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "workspaceID must not be empty")
	}
	if c.cfg.Summarizer == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Summarizer is required for compaction")
	}
	if c.cfg.Embedder == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "Embedder is required for compaction")
	}

	count, err := c.cfg.MemoryStore.Messages().Count(ctx, workspaceID)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "counting messages for workspace %s", workspaceID)
	}

	result := &CompactionResult{}
	if !ShouldCompact(count, c.cfg.BatchSize) {
		return result, nil
	}

	batch, batchIDs, err := c.loadBatch(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return result, nil
	}

	summaryText, err := c.cfg.Summarizer.Summarize(ctx, batch)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "summarizing compaction batch for workspace %s", workspaceID)
	}

	now := time.Now().UTC()
	summary := &store.Summary{
		ID:          generateSummaryID(now),
		WorkspaceID: workspaceID,
		FromTime:    batch[0].CreatedAt,
		ToTime:      batch[len(batch)-1].CreatedAt,
		Content:     summaryText,
		MessageIDs:  batchIDs,
		CreatedAt:   now,
	}
	if err := c.cfg.MemoryStore.Summaries().Store(ctx, workspaceID, summary); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing compaction summary for workspace %s", workspaceID)
	}

	result.SummariesCreated = 1
	result.MessagesProcessed = len(batch)

	if c.cfg.ExtractFacts {
		n, err := c.storeFacts(ctx, workspaceID, summary.ID, summaryText, batch, now)
		if err != nil {
			return nil, err
		}
		result.FactsExtracted = n
	}

	embedding, err := c.cfg.Embedder.Embed(ctx, summaryText)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "embedding compaction summary for workspace %s", workspaceID)
	}

	if err := c.cfg.VectorStore.Store(ctx, summary.ID, embedding, map[string]any{
		"workspace_id": workspaceID,
		"kind":         "summary",
		"from_time":    summary.FromTime.UTC().Format(time.RFC3339Nano),
		"to_time":      summary.ToTime.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing summary embedding for workspace %s", workspaceID)
	}

	// Clean up per-message placeholder vectors from RollMessage.
	if err := c.cfg.VectorStore.Delete(ctx, batchIDs); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "deleting compacted message vectors for workspace %s", workspaceID)
	}

	trimmed, err := c.cfg.MemoryStore.Messages().DeleteByIDs(ctx, workspaceID, batchIDs)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "deleting compacted messages for workspace %s", workspaceID)
	}
	result.MessagesTrimmed = trimmed

	return result, nil
}

// loadBatch fetches all messages, sorts by time, and returns the oldest BatchSize entries.
func (c *Compactor) loadBatch(ctx context.Context, workspaceID string) ([]*store.Message, []string, error) {
	allMessages, err := c.cfg.MemoryStore.Messages().GetRange(ctx, workspaceID, timeMin, timeMax)
	if err != nil {
		return nil, nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "loading compaction batch for workspace %s", workspaceID)
	}
	if len(allMessages) == 0 {
		return nil, nil, nil
	}

	sort.Slice(allMessages, func(i, j int) bool {
		if allMessages[i].CreatedAt.Equal(allMessages[j].CreatedAt) {
			return allMessages[i].ID < allMessages[j].ID
		}
		return allMessages[i].CreatedAt.Before(allMessages[j].CreatedAt)
	})

	batchSize := c.cfg.BatchSize
	if batchSize > len(allMessages) {
		batchSize = len(allMessages)
	}
	batch := allMessages[:batchSize]
	return batch, messageIDs(batch), nil
}

// storeFacts extracts facts from the summarized batch and persists them.
// IDs and WorkspaceIDs are always overwritten — provider output is untrusted.
func (c *Compactor) storeFacts(ctx context.Context, workspaceID, summaryID, summaryText string, batch []*store.Message, now time.Time) (int, error) {
	facts, err := c.cfg.Summarizer.ExtractFacts(ctx, summaryText, batch)
	if err != nil {
		return 0, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "extracting facts for workspace %s", workspaceID)
	}

	count := 0
	for i, fact := range facts {
		if fact == nil {
			continue
		}
		// Always override — do not trust provider-returned values.
		fact.ID = fmt.Sprintf("%s-fact-%d", summaryID, i)
		fact.WorkspaceID = workspaceID
		if fact.CreatedAt.IsZero() {
			fact.CreatedAt = now
		}

		if err := c.cfg.MemoryStore.Knowledge().PutFact(ctx, workspaceID, fact); err != nil {
			return 0, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing extracted fact %s for workspace %s", fact.ID, workspaceID)
		}
		count++
	}
	return count, nil
}

// generateSummaryID creates a unique summary ID using timestamp and random bytes.
func generateSummaryID(t time.Time) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("sum-%d-%s", t.UnixNano(), hex.EncodeToString(b))
}

func messageIDs(messages []*store.Message) []string {
	ids := make([]string, 0, len(messages))
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		ids = append(ids, msg.ID)
	}
	return ids
}
