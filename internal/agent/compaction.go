// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sigil-dev/sigil/internal/store"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// maxPendingOrphans caps the number of orphaned vector IDs retained in memory.
// Under persistent VectorStore failure, new orphans are dropped with a warning
// once this limit is reached. The dropped IDs are lost (in-process only, not
// durable), but the next successful compaction will naturally re-orphan and
// retry them.
const maxPendingOrphans = 1000

// maxPendingFacts caps the number of orphaned fact IDs retained in memory.
// Matches the maxPendingOrphans cap for consistency.
const maxPendingFacts = 1000

// maxPendingSummaryOrphans caps the number of orphaned summary IDs retained in memory.
// Matches the maxPendingOrphans cap for consistency.
const maxPendingSummaryOrphans = 1000

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
	// Logger is the structured logger the Compactor will use for all internal
	// log output. When nil, slog.Default() is used. Setting an explicit logger
	// avoids mutating the process-global default and makes log capture in tests
	// safe for parallel execution.
	Logger *slog.Logger
}

// pendingFactEntry groups fact IDs with their workspace for deferred retry.
type pendingFactEntry struct {
	workspaceID string
	factIDs     []string
}

// pendingSummaryEntry groups a summary ID with its workspace for deferred retry.
type pendingSummaryEntry struct {
	workspaceID string
	summaryID   string
}

// Compactor manages the memory compaction lifecycle: rolling messages into
// long-term storage and (in Phase 6) summarising and extracting facts.
type Compactor struct {
	cfg CompactorConfig
	// log is the structured logger for all internal log output. Always
	// non-nil after NewCompactor; defaults to slog.Default() when not
	// supplied via CompactorConfig.Logger.
	log *slog.Logger

	// mu guards pendingOrphans, pendingFacts, and pendingSummaryOrphans for concurrent access.
	mu sync.Mutex
	// pendingOrphans tracks vector embedding IDs that failed cleanup in a
	// previous Compact defer block. Retried at the start of the next Compact call.
	// In-process only (not durable across restarts).
	pendingOrphans []string
	// pendingFacts tracks fact IDs that failed rollback deletion in a previous
	// Compact defer block. Retried at the start of the next Compact call.
	// In-process only (not durable across restarts).
	pendingFacts []pendingFactEntry
	// pendingSummaryOrphans tracks summary IDs that failed deletion in a previous
	// Compact defer block. Retried at the start of the next Compact call.
	// In-process only (not durable across restarts).
	pendingSummaryOrphans []pendingSummaryEntry
}

// InjectOrphans adds orphan IDs for testing. Not for production use.
func (c *Compactor) InjectOrphans(ids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingOrphans = append(c.pendingOrphans, ids...)
}

// PendingOrphanCount returns the number of orphaned vector IDs awaiting cleanup.
func (c *Compactor) PendingOrphanCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pendingOrphans)
}

// drainOrphans attempts to delete any previously orphaned vector embeddings.
// Successful deletes are removed; failures are re-queued for the next pass.
// A fresh background context with bounded timeout is used for VectorStore.Delete
// calls to avoid inheriting a cancelled or deadline-exceeded caller context.
func (c *Compactor) drainOrphans(ctx context.Context, workspaceID string) {
	c.mu.Lock()
	orphans := c.pendingOrphans
	c.pendingOrphans = nil
	c.mu.Unlock()

	if len(orphans) == 0 {
		return
	}

	var remaining []string
	for _, id := range orphans {
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := c.cfg.VectorStore.Delete(deleteCtx, []string{id})
		cancel()
		if err != nil {
			// Note: workspace_id reflects the current compaction context, not
			// necessarily the workspace where the orphaned embedding originated.
			c.log.ErrorContext(ctx, "compaction: orphan vector cleanup retry failed",
				"workspace_id", workspaceID,
				"embedding_id", id,
				"error", err,
			)
			remaining = append(remaining, id)
		} else {
			// Note: workspace_id reflects the current compaction context, not
			// necessarily the workspace where the orphaned embedding originated.
			c.log.InfoContext(ctx, "compaction: cleaned up orphaned vector embedding",
				"workspace_id", workspaceID,
				"embedding_id", id,
			)
		}
	}

	if len(remaining) > 0 {
		c.mu.Lock()
		c.appendOrphansLocked(ctx, workspaceID, remaining)
		c.mu.Unlock()
	}
}

// InjectPendingSummaries adds a pending summary entry for testing. Not for production use.
func (c *Compactor) InjectPendingSummaries(workspaceID, summaryID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingSummaryOrphans = append(c.pendingSummaryOrphans, pendingSummaryEntry{
		workspaceID: workspaceID,
		summaryID:   summaryID,
	})
}

// PendingSummaryOrphanCount returns the number of orphaned summary IDs awaiting cleanup.
func (c *Compactor) PendingSummaryOrphanCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pendingSummaryOrphans)
}

// drainPendingSummaries attempts to delete any previously orphaned pending summaries.
// Successful deletes are removed; failures are re-queued for the next pass.
// A fresh background context with bounded timeout is used for Summaries().Delete
// calls to avoid inheriting a cancelled or deadline-exceeded caller context.
func (c *Compactor) drainPendingSummaries(ctx context.Context) {
	c.mu.Lock()
	entries := c.pendingSummaryOrphans
	c.pendingSummaryOrphans = nil
	c.mu.Unlock()

	if len(entries) == 0 {
		return
	}

	var remaining []pendingSummaryEntry
	for _, entry := range entries {
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := c.cfg.MemoryStore.Summaries().Delete(deleteCtx, entry.workspaceID, entry.summaryID)
		cancel()
		if err != nil {
			c.log.ErrorContext(ctx, "compaction: pending summary cleanup retry failed",
				"workspace_id", entry.workspaceID,
				"summary_id", entry.summaryID,
				"error", err,
			)
			remaining = append(remaining, entry)
		} else {
			c.log.InfoContext(ctx, "compaction: cleaned up orphaned pending summary",
				"workspace_id", entry.workspaceID,
				"summary_id", entry.summaryID,
			)
		}
	}

	if len(remaining) > 0 {
		c.mu.Lock()
		c.appendPendingSummaryOrphansLocked(ctx, remaining)
		c.mu.Unlock()
	}
}

// appendPendingSummaryOrphansLocked appends pending summary entries, dropping excess
// entries if the cap would be exceeded. Caller must hold c.mu.
func (c *Compactor) appendPendingSummaryOrphansLocked(ctx context.Context, entries []pendingSummaryEntry) {
	space := maxPendingSummaryOrphans - len(c.pendingSummaryOrphans)
	for _, entry := range entries {
		if space <= 0 {
			c.log.WarnContext(ctx, "compaction: pendingSummaryOrphans cap reached, dropping summary ID",
				"workspace_id", entry.workspaceID,
				"summary_id", entry.summaryID,
				"cap", maxPendingSummaryOrphans,
			)
			continue
		}
		c.pendingSummaryOrphans = append(c.pendingSummaryOrphans, entry)
		space--
	}
}

// InjectPendingFacts adds pending fact entries for testing. Not for production use.
func (c *Compactor) InjectPendingFacts(workspaceID string, factIDs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingFacts = append(c.pendingFacts, pendingFactEntry{
		workspaceID: workspaceID,
		factIDs:     factIDs,
	})
}

// PendingFactCount returns the total number of orphaned fact IDs awaiting cleanup.
func (c *Compactor) PendingFactCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.pendingFacts {
		n += len(e.factIDs)
	}
	return n
}

// drainPendingFacts attempts to delete any previously orphaned facts.
// Successful deletes are removed; failures are re-queued for the next pass.
// A fresh background context with bounded timeout is used for DeleteFactsByIDs
// calls to avoid inheriting a cancelled or deadline-exceeded caller context.
func (c *Compactor) drainPendingFacts(ctx context.Context) {
	c.mu.Lock()
	entries := c.pendingFacts
	c.pendingFacts = nil
	c.mu.Unlock()

	if len(entries) == 0 {
		return
	}

	var remaining []pendingFactEntry
	for _, entry := range entries {
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := c.cfg.MemoryStore.Knowledge().DeleteFactsByIDs(deleteCtx, entry.workspaceID, entry.factIDs)
		cancel()
		if err != nil {
			c.log.ErrorContext(ctx, "compaction: pending fact cleanup retry failed",
				"workspace_id", entry.workspaceID,
				"fact_ids", entry.factIDs,
				"error", err,
			)
			remaining = append(remaining, entry)
		} else {
			c.log.InfoContext(ctx, "compaction: cleaned up orphaned facts",
				"workspace_id", entry.workspaceID,
				"fact_count", len(entry.factIDs),
			)
		}
	}

	if len(remaining) > 0 {
		c.mu.Lock()
		c.appendPendingFactsLocked(ctx, remaining)
		c.mu.Unlock()
	}
}

// appendPendingFactsLocked appends pending fact entries, dropping excess
// entries if the cap would be exceeded. Caller must hold c.mu.
func (c *Compactor) appendPendingFactsLocked(ctx context.Context, entries []pendingFactEntry) {
	currentCount := 0
	for _, e := range c.pendingFacts {
		currentCount += len(e.factIDs)
	}

	for _, entry := range entries {
		space := maxPendingFacts - currentCount
		if space <= 0 {
			c.log.WarnContext(ctx, "compaction: pendingFacts cap reached, dropping fact IDs",
				"workspace_id", entry.workspaceID,
				"dropped", len(entry.factIDs),
				"cap", maxPendingFacts,
			)
			continue
		}
		if len(entry.factIDs) <= space {
			c.pendingFacts = append(c.pendingFacts, entry)
			currentCount += len(entry.factIDs)
		} else {
			c.pendingFacts = append(c.pendingFacts, pendingFactEntry{
				workspaceID: entry.workspaceID,
				factIDs:     entry.factIDs[:space],
			})
			dropped := len(entry.factIDs) - space
			currentCount += space
			c.log.WarnContext(ctx, "compaction: pendingFacts cap reached, dropping fact IDs",
				"workspace_id", entry.workspaceID,
				"dropped", dropped,
				"cap", maxPendingFacts,
			)
		}
	}
}

// appendOrphansLocked appends orphan IDs to pendingOrphans, dropping excess
// entries if the cap would be exceeded. Caller must hold c.mu.
func (c *Compactor) appendOrphansLocked(ctx context.Context, workspaceID string, ids []string) {
	space := maxPendingOrphans - len(c.pendingOrphans)
	if space >= len(ids) {
		c.pendingOrphans = append(c.pendingOrphans, ids...)
		return
	}
	if space > 0 {
		c.pendingOrphans = append(c.pendingOrphans, ids[:space]...)
	}
	dropped := len(ids) - space
	c.log.WarnContext(ctx, "compaction: pendingOrphans cap reached, dropping orphan IDs",
		"workspace_id", workspaceID,
		"dropped", dropped,
		"cap", maxPendingOrphans,
	)
}

// CompactionResult reports the work completed by one Compact pass.
type CompactionResult struct {
	SummariesCreated  int
	FactsExtracted    int
	MessagesProcessed int
	MessagesTrimmed   int
}

// PartialCommitError is returned by Compact when the summary was committed
// but the source messages were not deleted. Callers should use errors.As to
// extract recovery data and retry the deletion or schedule reconciliation.
type PartialCommitError struct {
	// Cause is the underlying DeleteByIDs error.
	Cause error
	// SummaryID is the committed summary's ID.
	SummaryID string
	// MessageIDs lists the source message IDs that should have been deleted.
	MessageIDs []string
	coded      error // sigilerr-wrapped for HasCode() classification
}

// NewPartialCommitError creates a PartialCommitError with sigilerr coding
// so it participates in sigilerr.HasCode classification (D056).
func NewPartialCommitError(cause error, summaryID string, messageIDs []string) *PartialCommitError {
	return &PartialCommitError{
		Cause:      cause,
		SummaryID:  summaryID,
		MessageIDs: messageIDs,
		coded: sigilerr.Wrapf(cause, sigilerr.CodeAgentLoopPartialCommit,
			"partial commit: summary %s committed but %d messages not deleted",
			summaryID, len(messageIDs)),
	}
}

func (e *PartialCommitError) Error() string {
	return e.coded.Error()
}

func (e *PartialCommitError) Unwrap() error {
	return e.coded
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
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Compactor{cfg: cfg, log: log}, nil
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

	// Best-effort cleanup of any orphaned pending summaries from prior failures.
	c.drainPendingSummaries(ctx)
	// Best-effort cleanup of any orphaned vector embeddings from prior failures.
	c.drainOrphans(ctx, workspaceID)
	// Best-effort cleanup of any orphaned facts from prior rollback failures.
	c.drainPendingFacts(ctx)

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
		Status:      store.SummaryStatusPending,
	}
	if err := c.cfg.MemoryStore.Summaries().Store(ctx, workspaceID, summary); err != nil {
		return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing compaction summary for workspace %s", workspaceID)
	}

	// Clean up the pending summary, stored embedding, and committed facts
	// if any subsequent step fails.
	confirmed := false
	embeddingStored := false
	var storedFactIDs []string
	defer func() {
		if !confirmed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if embeddingStored {
				if vecErr := c.cfg.VectorStore.Delete(cleanupCtx, []string{summary.ID}); vecErr != nil {
					c.log.ErrorContext(cleanupCtx, "compaction: failed to clean up summary vector embedding, queuing for retry",
						"workspace_id", workspaceID,
						"embedding_id", summary.ID,
						"error", vecErr,
					)
					c.mu.Lock()
					c.appendOrphansLocked(cleanupCtx, workspaceID, []string{summary.ID})
					c.mu.Unlock()
				}
			}
			if len(storedFactIDs) > 0 {
				if factErr := c.cfg.MemoryStore.Knowledge().DeleteFactsByIDs(cleanupCtx, workspaceID, storedFactIDs); factErr != nil {
					c.log.ErrorContext(cleanupCtx, "compaction: failed to roll back committed facts, queuing for retry",
						"workspace_id", workspaceID,
						"summary_id", summary.ID,
						"fact_ids", storedFactIDs,
						"error", factErr,
					)
					c.mu.Lock()
					c.appendPendingFactsLocked(cleanupCtx, []pendingFactEntry{{
						workspaceID: workspaceID,
						factIDs:     storedFactIDs,
					}})
					c.mu.Unlock()
				}
			}
			if delErr := c.cfg.MemoryStore.Summaries().Delete(cleanupCtx, workspaceID, summary.ID); delErr != nil {
				c.log.ErrorContext(cleanupCtx, "compaction: failed to clean up pending summary, queuing for retry",
					"workspace_id", workspaceID,
					"summary_id", summary.ID,
					"error", delErr,
				)
				c.mu.Lock()
				c.appendPendingSummaryOrphansLocked(cleanupCtx, []pendingSummaryEntry{{
					workspaceID: workspaceID,
					summaryID:   summary.ID,
				}})
				c.mu.Unlock()
			}
		}
	}()

	result.SummariesCreated = 1
	result.MessagesProcessed = len(batch)

	if c.cfg.FactExtractor != nil {
		n, factIDs, err := c.storeFacts(ctx, workspaceID, summary.ID, summaryText, batch, now)
		if err != nil {
			return nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "compacting workspace %s: storing facts", workspaceID)
		}
		storedFactIDs = factIDs
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
		c.mu.Lock()
		c.appendOrphansLocked(ctx, workspaceID, batchIDs)
		c.mu.Unlock()
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
		// Summary is committed but messages were not deleted — partial commit.
		// Return a PartialCommitError so callers can extract recovery data via errors.As.
		return result, NewPartialCommitError(err, summary.ID, batchIDs)
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
// Returns the count of stored facts, the IDs of the stored facts (for targeted rollback),
// and any error.
func (c *Compactor) storeFacts(ctx context.Context, workspaceID, summaryID, summaryText string, batch []*store.Message, now time.Time) (int, []string, error) {
	facts, err := c.cfg.FactExtractor.ExtractFacts(ctx, summaryText, batch)
	if err != nil {
		return 0, nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "extracting facts for workspace %s", workspaceID)
	}

	if len(facts) > maxFactsPerCompaction {
		c.log.WarnContext(ctx, "compaction: fact count exceeds cap, truncating",
			"workspace_id", workspaceID,
			"summary_id", summaryID,
			"extracted", len(facts),
			"cap", maxFactsPerCompaction,
		)
		facts = facts[:maxFactsPerCompaction]
	}

	// First pass: sanitize all facts and collect valid ones.
	sanitized := make([]*store.Fact, 0, len(facts))
	for i, fact := range facts {
		if fact == nil {
			continue
		}

		// Validate untrusted text fields before building the sanitized fact.
		if fact.EntityID == "" {
			c.log.WarnContext(ctx, "compaction: skipping fact with empty entity ID",
				"workspace_id", workspaceID,
				"summary_id", summaryID,
				"index", i,
			)
			continue
		}

		// Clamp confidence to valid range.
		clampedConfidence := fact.Confidence
		if math.IsNaN(clampedConfidence) || math.IsInf(clampedConfidence, 0) || clampedConfidence < 0 {
			clampedConfidence = 0
		} else if clampedConfidence > 1 {
			clampedConfidence = 1
		}

		// Build a new struct with sanitized values — do not mutate FactExtractor-owned objects.
		// Always override identity and scoping — do not trust provider-returned values.
		sanitized = append(sanitized, &store.Fact{
			ID:          factID(summaryID, fact.EntityID, fact.Predicate, fact.Value),
			WorkspaceID: workspaceID,
			CreatedAt:   now,
			Source:      "compaction",
			EntityID:    truncateField(fact.EntityID, maxFactFieldLen),
			Predicate:   truncateField(fact.Predicate, maxFactFieldLen),
			Value:       truncateField(fact.Value, maxFactFieldLen),
			Confidence:  clampedConfidence,
		})
	}

	if len(facts) > 0 && len(sanitized) == 0 {
		c.log.WarnContext(ctx, "compaction: all extracted facts discarded by sanitization",
			"workspace_id", workspaceID,
			"summary_id", summaryID,
			"raw_count", len(facts),
		)
	}

	// Second pass: persist all sanitized facts atomically.
	if err := c.cfg.MemoryStore.Knowledge().PutFacts(ctx, workspaceID, sanitized); err != nil {
		return 0, nil, sigilerr.Wrapf(err, sigilerr.CodeAgentLoopFailure, "storing extracted facts for workspace %s", workspaceID)
	}

	ids := make([]string, len(sanitized))
	for i, f := range sanitized {
		ids[i] = f.ID
	}
	return len(sanitized), ids, nil
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

// factID derives a content-addressable fact identifier from the summary and
// fact content. The hash removes any implication of extraction ordering.
func factID(summaryID, entityID, predicate, value string) string {
	h := sha256.New()
	h.Write([]byte(summaryID))
	h.Write([]byte{0})
	h.Write([]byte(entityID))
	h.Write([]byte{0})
	h.Write([]byte(predicate))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return fmt.Sprintf("%s-fact-%s", summaryID, hex.EncodeToString(h.Sum(nil))[:12])
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
