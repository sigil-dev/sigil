// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestValidateEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType SSEEventType
		want      bool
	}{
		{
			name:      "valid plain event type",
			eventType: "text_delta",
			want:      true,
		},
		{
			name:      "valid event type with dots",
			eventType: "tool.call.result",
			want:      true,
		},
		{
			name:      "newline rejected",
			eventType: "text_delta\ninjected: data",
			want:      false,
		},
		{
			name:      "carriage return rejected",
			eventType: "text_delta\rinjected: data",
			want:      false,
		},
		{
			name:      "crlf rejected",
			eventType: "text_delta\r\ninjected: data",
			want:      false,
		},
		{
			name:      "empty string is valid",
			eventType: "",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEventType(tt.eventType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDrainChannel_ClosedBuffered(t *testing.T) {
	defer goleak.VerifyNone(t)

	ch := make(chan int, 3)
	ch <- 1
	ch <- 2
	ch <- 3
	close(ch)

	drainChannel(ch)
}

func TestDrainChannel_ProducerAfterConsumerStops(t *testing.T) {
	defer goleak.VerifyNone(t)

	ch := make(chan int, 1)

	drainChannel(ch)

	// Producer can still send without deadlocking — the key invariant
	// drainChannel exists to protect.
	done := make(chan struct{})
	go func() {
		ch <- 42
		close(ch)
		close(done)
	}()

	select {
	case <-done:
		// Success — no deadlock.
	case <-time.After(time.Second):
		t.Fatal("deadlock: producer blocked after consumer stopped")
	}
}

func TestDrainChannelWithContext_ContextCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)

	ch := make(chan int) // never closed
	ctx, cancel := context.WithCancel(context.Background())

	drainChannelWithContext(ctx, ch)
	cancel()
}

func TestDrainChannelWithContext_ProducerAfterCancel(t *testing.T) {
	defer goleak.VerifyNone(t)

	ch := make(chan int, 1) // buffered so producer doesn't block permanently
	ctx, cancel := context.WithCancel(context.Background())

	drainChannelWithContext(ctx, ch)
	cancel()

	// After context cancellation, the drain goroutine exits. A producer
	// attempting to send should not block permanently if the channel is
	// buffered. This verifies the expectation that callers are responsible
	// for using buffered channels or closing the channel when the drain
	// goroutine may exit via context cancellation.
	select {
	case ch <- 42:
		// Buffered channel accepted the value — expected.
	case <-time.After(100 * time.Millisecond):
		t.Fatal("producer blocked: buffered channel should accept at least one value after drain exits")
	}
}
