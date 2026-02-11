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

	// Submit 3 tasks concurrently with staggered submission so FIFO order is
	// deterministic: task 0 is submitted first, then 1, then 2.
	var wg sync.WaitGroup
	for i := range 3 {
		i := i
		// Stagger submissions so the channel receives them in order.
		time.Sleep(5 * time.Millisecond)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := lane.Submit(context.Background(), func(_ context.Context) error {
				time.Sleep(10 * time.Millisecond)
				mu.Lock()
				order = append(order, i)
				mu.Unlock()
				return nil
			})
			assert.NoError(t, err)
		}()
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

	var wg sync.WaitGroup
	for _, sid := range sessionIDs {
		lane := pool.Get(sid)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := lane.Submit(context.Background(), func(_ context.Context) error {
				cur := running.Add(1)
				// Track peak concurrency.
				for {
					old := peak.Load()
					if cur <= old || peak.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				running.Add(-1)
				return nil
			})
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

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
