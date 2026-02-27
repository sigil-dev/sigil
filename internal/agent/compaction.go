// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ShouldCompact returns true when count >= batchSize, indicating
// that enough messages have accumulated to trigger a compaction pass.
func ShouldCompact(count int64, batchSize int) bool {
	return count >= int64(batchSize)
}

// Summarizer produces text summaries from messages during compaction.
type Summarizer interface {
	Summarize(ctx context.Context, messages []*store.Message) (string, error)
}

// FactExtractor extracts structured facts from a summary and its source messages.
type FactExtractor interface {
	ExtractFacts(ctx context.Context, summary string, messages []*store.Message) ([]*store.Fact, error)
}

// Embedder generates vector embeddings from text.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// CompactorConfig holds the dependencies and tuning parameters for a Compactor.
type CompactorConfig struct {
	MemoryStore   store.MemoryStore
	VectorStore   store.VectorStore
	Summarizer    Summarizer
	Embedder      Embedder
	FactExtractor FactExtractor
	BatchSize     int
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
	MessagesTrimmed   int
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
	if cfg.Summarizer == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "CompactorConfig.Summarizer must not be nil")
	}
	if cfg.Embedder == nil {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "CompactorConfig.Embedder must not be nil")
	}
	return &Compactor{cfg: cfg}, nil
}

// RollMessage appends a message to Tier 1 (message store) and stores a
// placeholder embedding in Tier 4 (vector store). Full compaction
// (summarise + extract facts) is deferred to Phase 6.
func (c *Compactor) RollMessage(ctx context.Context, workspaceID, sessionID string, msg *store.Message) error {
	if err := c.cfg.MemoryStore.Messages().Append(ctx, workspaceID, msg); err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "rolling message for workspace %s session %s", workspaceID, sessionID)
	}

	if err := c.cfg.VectorStore.Store(ctx, msg.ID, []float32{0}, map[string]any{
		"workspace_id": workspaceID,
		"session_id":   sessionID,
		"content":      msg.Content,
	}); err != nil {
		return sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing placeholder vector for message %s workspace %s session %s", msg.ID, workspaceID, sessionID)
	}
	return nil
}

// Compact executes one full memory compaction pass for a workspace:
// summarize oldest Tier-1 messages, optionally extract facts, store summary
// embedding, then delete the compacted messages from Tier 1.
func (c *Compactor) Compact(ctx context.Context, workspaceID string) (*CompactionResult, error) {
	if workspaceID == "" {
		return nil, sigilerr.New(sigilerr.CodeAgentLoopInvalidInput, "workspaceID must not be empty")
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
	sumID, err := generateSummaryID(now)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "generating summary ID for workspace %s", workspaceID)
	}
	summary := &store.Summary{
		ID:          sumID,
		WorkspaceID: workspaceID,
		FromTime:    batch[0].CreatedAt,
		ToTime:      batch[len(batch)-1].CreatedAt,
		Content:     summaryText,
		MessageIDs:  batchIDs,
		CreatedAt:   now,
		Status:      "pending",
	}
	if err := c.cfg.MemoryStore.Summaries().Store(ctx, workspaceID, summary); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing compaction summary for workspace %s", workspaceID)
	}

	// Clean up the pending summary and any stored embedding if any subsequent step fails.
	confirmed := false
	embeddingStored := false
	defer func() {
		if !confirmed {
			if embeddingStored {
				if vecErr := c.cfg.VectorStore.Delete(ctx, []string{summary.ID}); vecErr != nil {
					slog.WarnContext(ctx, "compaction: failed to clean up summary vector embedding",
						"workspace_id", workspaceID,
						"summary_id", summary.ID,
						"error", vecErr,
					)
				}
			}
			if delErr := c.cfg.MemoryStore.Summaries().Delete(ctx, workspaceID, summary.ID); delErr != nil {
				slog.WarnContext(ctx, "compaction: failed to clean up pending summary",
					"workspace_id", workspaceID,
					"summary_id", summary.ID,
					"error", delErr,
				)
			}
		}
	}()

	result.SummariesCreated = 1
	result.MessagesProcessed = len(batch)

	if c.cfg.FactExtractor != nil {
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
	embeddingStored = true

	// Clean up per-message placeholder vectors from RollMessage.
	if err := c.cfg.VectorStore.Delete(ctx, batchIDs); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "deleting compacted message vectors for workspace %s", workspaceID)
	}

	// Promote summary from pending to committed before deleting messages.
	// If Confirm fails here, no messages have been deleted yet — fully reversible.
	// If DeleteByIDs fails after Confirm, messages still exist and summary is committed
	// (duplicate, recoverable), which is preferable to permanent data loss.
	if err := c.cfg.MemoryStore.Summaries().Confirm(ctx, workspaceID, summary.ID); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "confirming compaction summary for workspace %s", workspaceID)
	}
	confirmed = true

	trimmed, err := c.cfg.MemoryStore.Messages().DeleteByIDs(ctx, workspaceID, batchIDs)
	if err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "deleting compacted messages for workspace %s", workspaceID)
	}
	result.MessagesTrimmed = int(trimmed)

	return result, nil
}

// loadBatch fetches the oldest BatchSize messages from the memory store.
func (c *Compactor) loadBatch(ctx context.Context, workspaceID string) ([]*store.Message, []string, error) {
	batch, err := c.cfg.MemoryStore.Messages().GetOldest(ctx, workspaceID, c.cfg.BatchSize)
	if err != nil {
		return nil, nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "loading compaction batch for workspace %s", workspaceID)
	}
	if len(batch) == 0 {
		return nil, nil, nil
	}
	return batch, messageIDs(batch), nil
}

// maxFactsPerCompaction caps the number of facts that can be extracted from a
// single compaction batch, preventing LLM output from exhausting memory/storage.
const maxFactsPerCompaction = 100

// maxFactFieldLen caps the length of untrusted text fields on extracted facts.
const maxFactFieldLen = 4096

// storeFacts extracts facts from the summarized batch and persists them atomically.
// All provider-supplied fields are validated and sanitized — LLM output is untrusted.
// Facts are persisted via PutFacts for all-or-nothing semantics: if any write fails,
// no facts from this batch are committed to the store.
func (c *Compactor) storeFacts(ctx context.Context, workspaceID, summaryID, summaryText string, batch []*store.Message, now time.Time) (int, error) {
	facts, err := c.cfg.FactExtractor.ExtractFacts(ctx, summaryText, batch)
	if err != nil {
		return 0, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "extracting facts for workspace %s", workspaceID)
	}

	if len(facts) > maxFactsPerCompaction {
		facts = facts[:maxFactsPerCompaction]
	}

	// First pass: sanitize all facts and collect valid ones.
	sanitized := make([]*store.Fact, 0, len(facts))
	for i, fact := range facts {
		if fact == nil {
			continue
		}
		// Always override identity and scoping — do not trust provider-returned values.
		fact.ID = fmt.Sprintf("%s-fact-%d", summaryID, i)
		fact.WorkspaceID = workspaceID
		fact.CreatedAt = now
		fact.Source = "compaction"

		// Validate and truncate untrusted text fields.
		if fact.EntityID == "" {
			slog.WarnContext(ctx, "compaction: skipping fact with empty entity ID",
				"workspace_id", workspaceID,
				"summary_id", summaryID,
				"index", i,
			)
			continue
		}
		fact.EntityID = truncateField(fact.EntityID, maxFactFieldLen)
		fact.Predicate = truncateField(fact.Predicate, maxFactFieldLen)
		fact.Value = truncateField(fact.Value, maxFactFieldLen)

		// Clamp confidence to valid range.
		if math.IsNaN(fact.Confidence) || math.IsInf(fact.Confidence, 0) || fact.Confidence < 0 {
			fact.Confidence = 0
		} else if fact.Confidence > 1 {
			fact.Confidence = 1
		}

		sanitized = append(sanitized, fact)
	}

	// Second pass: persist all sanitized facts atomically.
	if err := c.cfg.MemoryStore.Knowledge().PutFacts(ctx, workspaceID, sanitized); err != nil {
		return 0, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing extracted facts for workspace %s", workspaceID)
	}
	return len(sanitized), nil
}

func truncateField(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len()+utf8.RuneLen(r) > maxLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// generateSummaryID creates a unique summary ID using timestamp and random bytes.
func generateSummaryID(t time.Time) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "generating summary ID: crypto/rand unavailable")
	}
	return fmt.Sprintf("sum-%d-%s", t.UnixNano(), hex.EncodeToString(b)), nil
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
