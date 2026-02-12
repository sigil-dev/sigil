// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package agent_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigil-dev/sigil/internal/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLane_SerializesMessages(t *testing.T) {
	lane := agent.NewLane("session-1")
	defer lane.Close()

	var mu sync.Mutex
	var order []int

	// Submit 3 tasks sequentially (not concurrently) to ensure FIFO submission order.
	// Since the test is about FIFO *execution* order matching submission order,
	// we don't need concurrent submission - just verify that the lane executes
	// tasks in the order they were submitted.
	var wg sync.WaitGroup
	for i := range 3 {
		i := i
		wg.Add(1)
		// Submit synchronously to guarantee submission order 0, 1, 2.
		err := lane.Submit(context.Background(), func(_ context.Context) error {
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			wg.Done()
			return nil
		})
		require.NoError(t, err)
	}

	wg.Wait()

	assert.Equal(t, []int{0, 1, 2}, order, "tasks must execute in FIFO submission order")
}

func TestLane_ConcurrentSessions(t *testing.T) {
	pool := agent.NewLanePool()
	defer pool.Close()

	sessionIDs := []string{"sess-a", "sess-b", "sess-c"}

	var peak atomic.Int32
	var running atomic.Int32

	// Use a started channel to ensure all workers are ready before measuring concurrency.
	started := make(chan struct{})
	var startedCount atomic.Int32

	var workWg sync.WaitGroup
	for _, sid := range sessionIDs {
		lane := pool.Get(sid)
		workWg.Add(1)
		go func() {
			defer workWg.Done()
			err := lane.Submit(context.Background(), func(_ context.Context) error {
				// Signal that this worker has started.
				if startedCount.Add(1) == int32(len(sessionIDs)) {
					close(started)
				}

				// Wait for all workers to start before measuring concurrency.
				<-started

				cur := running.Add(1)
				// Track peak concurrency.
				for {
					old := peak.Load()
					if cur <= old || peak.CompareAndSwap(old, cur) {
						break
					}
				}

				// Keep worker alive long enough for concurrent execution to be measured.
				// Use a small sleep here since we need actual concurrent execution to
				// demonstrate that different lanes run in parallel.
				time.Sleep(10 * time.Millisecond)
				running.Add(-1)
				return nil
			})
			assert.NoError(t, err)
		}()
	}

	// Wait for all work to complete.
	workWg.Wait()

	assert.GreaterOrEqual(t, peak.Load(), int32(2),
		"at least 2 lanes should have run concurrently")
}

func TestLane_ContextCancellation(t *testing.T) {
	lane := agent.NewLane("session-cancel")
	defer lane.Close()

	// Submit a long-running task to occupy the lane.
	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := lane.Submit(context.Background(), func(_ context.Context) error {
			close(started)
			time.Sleep(1 * time.Second)
			return nil
		})
		assert.NoError(t, err)
	}()

	// Wait until the first task is running.
	<-started

	// Submit a second task with an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := lane.Submit(ctx, func(_ context.Context) error {
		t.Fatal("should not execute")
		return nil
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	wg.Wait()
}

func TestLane_CloseIdempotent(t *testing.T) {
	lane := agent.NewLane("session-idempotent")

	// Close the lane multiple times concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lane.Close()
		}()
	}

	wg.Wait()

	// Verify we can close again without panic.
	lane.Close()
}

func TestLane_SubmitAfterClose(t *testing.T) {
	lane := agent.NewLane("session-closed")
	lane.Close()

	// Submit should return an error, not panic.
	err := lane.Submit(context.Background(), func(_ context.Context) error {
		t.Fatal("should not execute")
		return nil
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "lane is closed")
}

func TestLane_ConcurrentSubmitAndClose(t *testing.T) {
	// Run this test multiple times to increase chance of catching race.
	for i := 0; i < 10; i++ {
		lane := agent.NewLane("session-race")

		var wg sync.WaitGroup
		submitted := atomic.Int32{}
		succeeded := atomic.Int32{}
		failed := atomic.Int32{}

		// Start multiple goroutines submitting work.
		for j := 0; j < 20; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				submitted.Add(1)
				err := lane.Submit(context.Background(), func(_ context.Context) error {
					time.Sleep(1 * time.Millisecond)
					return nil
				})
				if err != nil {
					failed.Add(1)
				} else {
					succeeded.Add(1)
				}
			}()
		}

		// Close the lane concurrently with submissions.
		time.Sleep(5 * time.Millisecond)
		wg.Add(1)
		go func() {
			defer wg.Done()
			lane.Close()
		}()

		wg.Wait()

		// Verify that submitted = succeeded + failed (no panics or lost work).
		assert.Equal(t, submitted.Load(), succeeded.Load()+failed.Load(),
			"iteration %d: all submitted work should be accounted for", i)
	}
}

func TestLane_SubmitDoesNotHangWhenCloseRaces(t *testing.T) {
	// Verify that Submit returns an error (not hangs forever) when Close()
	// fires after the work item is enqueued but before the worker processes it.
	for i := 0; i < 50; i++ {
		lane := agent.NewLane("session-race-hang")

		// Block the worker so our next Submit sits in the queue.
		blocked := make(chan struct{})
		go func() {
			_ = lane.Submit(context.Background(), func(_ context.Context) error {
				<-blocked
				return nil
			})
		}()

		// Give the blocking task time to be picked up by the worker.
		time.Sleep(1 * time.Millisecond)

		// Submit a second task — it will sit in the queue.
		done := make(chan error, 1)
		go func() {
			done <- lane.Submit(context.Background(), func(_ context.Context) error {
				return nil
			})
		}()

		// Give the second submit time to enqueue.
		time.Sleep(1 * time.Millisecond)

		// Close the lane while the second task is queued but unprocessed.
		// Unblock the first task so the worker can drain and exit.
		close(blocked)
		lane.Close()

		// The second Submit must return within a reasonable time, not hang.
		select {
		case err := <-done:
			// Either nil (worker drained it) or an error (lane closed) — both ok.
			_ = err
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: Submit hung after Close", i)
		}
	}
}

func TestLane_WorkerPanicRecovery(t *testing.T) {
	lane := agent.NewLane("session-panic")
	defer lane.Close()

	// Submit a task that panics.
	err := lane.Submit(context.Background(), func(_ context.Context) error {
		panic("intentional panic for testing")
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "worker panic")
	assert.Contains(t, err.Error(), "intentional panic")

	// Verify the lane is still functional after panic recovery.
	err = lane.Submit(context.Background(), func(_ context.Context) error {
		return nil
	})
	assert.NoError(t, err, "lane should still accept work after panic recovery")
}
