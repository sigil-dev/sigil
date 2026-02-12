// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"

	"github.com/sigil-dev/sigil/pkg/errors"
)

// workItem represents a unit of work submitted to a Lane.
type workItem struct {
	fn     func(context.Context) error
	ctx    context.Context
	result chan<- error
}

// Lane serialises work for a single session. Tasks submitted via Submit are
// executed one at a time in FIFO order by a background goroutine.
type Lane struct {
	sessionID string
	queue     chan workItem
	done      chan struct{}
	closing   chan struct{} // Closed immediately when Close() is called

	once sync.Once
}

// NewLane creates a Lane for the given session and starts its background
// processing goroutine. Call Close when the lane is no longer needed.
func NewLane(sessionID string) *Lane {
	l := &Lane{
		sessionID: sessionID,
		queue:     make(chan workItem, 256),
		done:      make(chan struct{}),
		closing:   make(chan struct{}),
	}
	go l.run()
	return l
}

// run processes work items sequentially until the lane is closed.
func (l *Lane) run() {
	defer close(l.done)
	for {
		select {
		case w := <-l.queue:
			l.executeWork(w)
		case <-l.closing:
			// Drain any remaining queued items before exiting.
			for {
				select {
				case w := <-l.queue:
					l.executeWork(w)
				default:
					return
				}
			}
		}
	}
}

// executeWork runs a work item with panic recovery.
func (l *Lane) executeWork(w workItem) {
	// Skip execution if the submitter's context is already cancelled.
	if err := w.ctx.Err(); err != nil {
		w.result <- err
		return
	}

	// Execute the work function with panic recovery.
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				slog.Error("lane worker panic recovered",
					"session_id", l.sessionID,
					"panic", r,
					"stack", string(stack))
				err = errors.Errorf(errors.CodeAgentLoopFailure,
					"worker panic: %v", r)
			}
		}()
		err = w.fn(w.ctx)
	}()

	w.result <- err
}

// Submit enqueues fn for execution on this lane and blocks until it completes.
// If ctx is cancelled before the work item can be enqueued or before execution
// begins, ctx.Err() is returned without executing fn.
// Returns an error if the lane has been closed.
func (l *Lane) Submit(ctx context.Context, fn func(context.Context) error) error {
	// Fast path: bail immediately if context is already done.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Check if lane is closing before attempting to submit.
	// This non-blocking check prevents send-to-closed-channel panics.
	select {
	case <-l.closing:
		return errors.New(errors.CodeAgentSessionInactive,
			"lane is closed")
	default:
	}

	result := make(chan error, 1)
	w := workItem{
		fn:     fn,
		ctx:    ctx,
		result: result,
	}

	// Submit work or bail on context/close.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.closing:
		return errors.New(errors.CodeAgentSessionInactive,
			"lane is closed")
	case l.queue <- w:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.closing:
		return errors.New(errors.CodeAgentSessionInactive,
			"lane closed while waiting for result")
	case err := <-result:
		return err
	}
}

// Close shuts down the lane's background goroutine and waits for it to finish
// processing any already-enqueued work. Close is idempotent and safe for
// concurrent calls.
func (l *Lane) Close() {
	l.once.Do(func() {
		close(l.closing) // Signal Submit to stop accepting new work; worker drains remaining items
		<-l.done         // Wait for worker to finish processing
	})
}

// LanePool manages a set of Lanes keyed by session ID. It creates lanes on
// first access and is safe for concurrent use.
type LanePool struct {
	mu    sync.Mutex
	lanes map[string]*Lane
}

// NewLanePool returns an empty LanePool.
func NewLanePool() *LanePool {
	return &LanePool{
		lanes: make(map[string]*Lane),
	}
}

// Get returns the Lane for the given session, creating one if it does not
// already exist.
func (p *LanePool) Get(sessionID string) *Lane {
	p.mu.Lock()
	defer p.mu.Unlock()

	if l, ok := p.lanes[sessionID]; ok {
		return l
	}

	l := NewLane(sessionID)
	p.lanes[sessionID] = l
	return l
}

// Close shuts down all lanes managed by the pool.
func (p *LanePool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, l := range p.lanes {
		l.Close()
	}
	p.lanes = make(map[string]*Lane)
}
