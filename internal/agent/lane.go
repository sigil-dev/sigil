// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent

import (
	"context"
	"sync"
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
}

// NewLane creates a Lane for the given session and starts its background
// processing goroutine. Call Close when the lane is no longer needed.
func NewLane(sessionID string) *Lane {
	l := &Lane{
		sessionID: sessionID,
		queue:     make(chan workItem, 256),
		done:      make(chan struct{}),
	}
	go l.run()
	return l
}

// run processes work items sequentially until the queue channel is closed.
func (l *Lane) run() {
	defer close(l.done)
	for w := range l.queue {
		// Skip execution if the submitter's context is already cancelled.
		if err := w.ctx.Err(); err != nil {
			w.result <- err
			continue
		}
		w.result <- w.fn(w.ctx)
	}
}

// Submit enqueues fn for execution on this lane and blocks until it completes.
// If ctx is cancelled before the work item can be enqueued or before execution
// begins, ctx.Err() is returned without executing fn.
func (l *Lane) Submit(ctx context.Context, fn func(context.Context) error) error {
	// Fast path: bail immediately if context is already done.
	if err := ctx.Err(); err != nil {
		return err
	}

	result := make(chan error, 1)
	w := workItem{
		fn:     fn,
		ctx:    ctx,
		result: result,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case l.queue <- w:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		return err
	}
}

// Close shuts down the lane's background goroutine and waits for it to finish
// processing any already-enqueued work.
func (l *Lane) Close() {
	close(l.queue)
	<-l.done
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
