// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ShouldCompact returns true when count >= batchSize, indicating
// that enough messages have accumulated to trigger a compaction pass.
func ShouldCompact(count int64, batchSize int) bool {
	return count >= int64(batchSize)
}

// CompactionProvider performs summarization, fact extraction, and embedding
// generation used by the compaction lifecycle.
type CompactionProvider interface {
	Summarize(ctx context.Context, messages []*store.Message) (string, error)
	ExtractFacts(ctx context.Context, summary string, messages []*store.Message) ([]*store.Fact, error)
	Embed(ctx context.Context, text string) ([]float32, error)
}

// CompactorConfig holds the dependencies and tuning parameters for a Compactor.
type CompactorConfig struct {
	MemoryStore           store.MemoryStore
	VectorStore           store.VectorStore
	SessionStore          store.SessionStore
	SummarizationProvider CompactionProvider
	BatchSize             int
	WindowSize            int
	ExtractFacts          bool
}

// Compactor manages the memory compaction lifecycle: rolling messages into
// long-term storage and (in Phase 6) summarising and extracting facts.
type Compactor struct {
	cfg CompactorConfig
}

// CompactionResult reports the work completed by one Compact pass.
type CompactionResult struct {
	SummariesCreated int
	FactsExtracted   int
	MessagesProcessed int
	MessagesTrimmed  int64
}

// NewCompactor creates a Compactor with the given configuration.
func NewCompactor(cfg CompactorConfig) *Compactor {
	return &Compactor{cfg: cfg}
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
// embedding, then trim processed messages from Tier 1.
func (c *Compactor) Compact(ctx context.Context, workspaceID string) (*CompactionResult, error) {
	if c.cfg.MemoryStore == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "MemoryStore is required")
	}
	if c.cfg.VectorStore == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "VectorStore is required")
	}
	if c.cfg.BatchSize <= 0 {
		return nil, sigilerr.Errorf(sigilerr.CodeAgentLoopInvalidInput, "BatchSize must be greater than zero: %d", c.cfg.BatchSize)
	}

	count, err := c.cfg.MemoryStore.Messages().Count(ctx, workspaceID)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "counting messages for workspace %s", workspaceID)
	}

	result := &CompactionResult{}
	if !ShouldCompact(count, c.cfg.BatchSize) {
		return result, nil
	}
	if c.cfg.SummarizationProvider == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "SummarizationProvider is required when compaction threshold is met")
	}

	allMessages, err := c.cfg.MemoryStore.Messages().GetRange(
		ctx,
		workspaceID,
		time.Time{},
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "loading compaction batch for workspace %s", workspaceID)
	}
	if len(allMessages) == 0 {
		return result, nil
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

	summaryText, err := c.cfg.SummarizationProvider.Summarize(ctx, batch)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "summarizing compaction batch for workspace %s", workspaceID)
	}

	now := time.Now().UTC()
	summary := &store.Summary{
		ID:          fmt.Sprintf("sum-%d", now.UnixNano()),
		WorkspaceID: workspaceID,
		FromTime:    batch[0].CreatedAt,
		ToTime:      batch[len(batch)-1].CreatedAt,
		Content:     summaryText,
		MessageIDs:  messageIDs(batch),
		CreatedAt:   now,
	}
	if err := c.cfg.MemoryStore.Summaries().Store(ctx, workspaceID, summary); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing compaction summary for workspace %s", workspaceID)
	}

	result.SummariesCreated = 1
	result.MessagesProcessed = len(batch)

	if c.cfg.ExtractFacts {
		facts, err := c.cfg.SummarizationProvider.ExtractFacts(ctx, summaryText, batch)
		if err != nil {
			return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "extracting facts for workspace %s", workspaceID)
		}

		for i, fact := range facts {
			if fact == nil {
				continue
			}
			if fact.ID == "" {
				fact.ID = fmt.Sprintf("%s-fact-%d", summary.ID, i)
			}
			if fact.WorkspaceID == "" {
				fact.WorkspaceID = workspaceID
			}
			if fact.CreatedAt.IsZero() {
				fact.CreatedAt = now
			}

			if err := c.cfg.MemoryStore.Knowledge().PutFact(ctx, workspaceID, fact); err != nil {
				return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing extracted fact %s for workspace %s", fact.ID, workspaceID)
			}
			result.FactsExtracted++
		}
	}

	embedding, err := c.cfg.SummarizationProvider.Embed(ctx, summaryText)
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

	currentCount, err := c.cfg.MemoryStore.Messages().Count(ctx, workspaceID)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "counting messages before trim for workspace %s", workspaceID)
	}

	keepLast := int(currentCount) - len(batch)
	if keepLast < 0 {
		keepLast = 0
	}

	trimmed, err := c.cfg.MemoryStore.Messages().Trim(ctx, workspaceID, keepLast)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "trimming compacted messages for workspace %s", workspaceID)
	}
	result.MessagesTrimmed = trimmed

	return result, nil
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
