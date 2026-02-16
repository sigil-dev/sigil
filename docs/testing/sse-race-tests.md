# SSE Race Condition Tests

This document describes the comprehensive race condition tests for SSE (Server-Sent Events) streaming in Sigil.

## Background

SSE streaming involves three concurrent actors:

1. **Producer goroutine** - `HandleStream()` sends events to a buffered channel
2. **Consumer goroutine** - `writeSSE()` reads events from the channel and writes to HTTP response
3. **Drain goroutine** - Spawned by `drainSSEChannel()` when a write error occurs to prevent producer blocking

The drain logic is critical: when the HTTP client disconnects mid-stream, the consumer stops reading but the producer may still be sending events. Without proper draining, the producer would block forever on the buffered channel, causing a goroutine leak.

## Test Coverage

### Existing Tests (Pre-PR)

These tests were already in place:

- **TestSSE_DrainOnWriteError** - Basic drain test with write errors
- **TestSSE_DrainRaceCondition** - 10 parallel goroutines testing concurrent drain
- **TestSSE_DrainOnContextCancellation** - Tests context cancellation during streaming
- **TestSSE_ConcurrentWriteAndDrain** - 10 concurrent writers with cancellation
- **TestSSE_ConcurrentWriteAndDrain_JSON** - Same test for JSON response path

### New Tests (This PR)

Three new comprehensive race tests specifically target edge cases in the drain logic:

#### 1. TestSSE_DrainRaceCondition_ComprehensiveStressTest

**Purpose**: Most aggressive race test for the drain path.

**Strategy**:

- Runs 20 parallel iterations with varying write failure points
- Uses `aggressiveStreamHandler` that produces 500 events in a tight loop (no throttling)
- Fails HTTP writes after 1-3 events (varies per iteration) to trigger drain early
- Producer is still rapidly sending events when drain starts

**Why it matters**:

- Maximizes contention on the channel during concurrent writes + drain
- Tests the worst-case scenario: drain starts immediately while producer is at full speed
- 20 iterations increase probability of catching timing-dependent races

**Run with**: `go test -race -run TestSSE_DrainRaceCondition_ComprehensiveStressTest ./internal/server/`

#### 2. TestSSE_DrainRaceCondition_MultipleConsumers

**Purpose**: Tests concurrent drain operations from multiple independent streams.

**Strategy**:

- 5 parallel consumers, each with their own handler and channel
- All consumers produce 200 events rapidly
- All consumers fail writes quickly and trigger drain path simultaneously
- Tests if drain implementation has any shared state issues

**Why it matters**:

- Real-world scenario: multiple SSE streams active at once
- Verifies drain goroutines don't interfere with each other
- Tests for races in any shared resources (logging, metrics, etc.)

**Run with**: `go test -race -run TestSSE_DrainRaceCondition_MultipleConsumers ./internal/server/`

#### 3. TestSSE_DrainRaceCondition_BurstyPattern

**Purpose**: Tests drain with realistic bursty traffic patterns.

**Strategy**:

- Uses `oscillatingStreamHandler` that alternates between bursts and pauses
- Sends 30 events per burst, then 1ms pause, repeated 10 times
- Simulates real LLM streaming (chunks followed by processing pauses)
- Fails writes after 50 events (mid-burst)

**Why it matters**:

- Bursty patterns create timing windows where channel transitions between full/empty states
- Tests drain behavior during different channel occupancy levels
- More realistic than purely uniform or purely random patterns

**Run with**: `go test -race -run TestSSE_DrainRaceCondition_BurstyPattern ./internal/server/`

## Running the Tests

### Individual test

```bash
go test -race -run TestSSE_DrainRaceCondition_ComprehensiveStressTest ./internal/server/ -v
```

### All SSE tests with race detector

```bash
task test -- -race -run TestSSE ./internal/server/
```

### Full test suite with race detector

```bash
task test -- -race ./internal/server/
```

## Expected Behavior

All tests should pass with **no race conditions detected** when run with `-race` flag.

If a race is detected, Go's race detector will print:

```text
WARNING: DATA RACE
Read at ...
Previous write at ...
...
```

## Implementation Details

The drain logic is in `internal/server/sse.go`:

```go
// drainSSEChannel consumes remaining events from ch in a background goroutine
// so that the producer (HandleStream) does not block on a full buffer after
// the consumer has stopped reading. The goroutine exits when ch is closed.
func drainSSEChannel(ch <-chan SSEEvent) {
	go func() {
		for range ch {
		}
	}()
}
```

Called from `writeSSE()` on write errors:

```go
if writeSSEField(w, "event: %s\n", event.Event) {
	drainSSEChannel(ch)
	return
}
```

The producer must cooperate by:

1. Respecting context cancellation
2. Closing the channel when done
3. Using select to avoid blocking on send

## Test Helpers

### aggressiveStreamHandler

Produces events as fast as possible with minimal overhead. Used in stress tests.

```go
type aggressiveStreamHandler struct {
	eventCount int
	done       chan struct{}
}
```

### oscillatingStreamHandler

Produces events in bursts with pauses between. Used in bursty pattern tests.

```go
type oscillatingStreamHandler struct {
	burstSize int
	pauses    int
	done      chan struct{}
}
```

### errResponseWriter

Simulates client disconnect by returning errors after N writes.

```go
type errResponseWriter struct {
	header     http.Header
	writes     int
	maxWrites  int
	statusCode int
}
```

## Success Criteria

- ✅ All tests pass with `-race` flag
- ✅ No data races detected
- ✅ All producer goroutines finish within timeout (no goroutine leaks)
- ✅ Write counts match expected values
- ✅ No panics or deadlocks

## Related Files

- `/Volumes/Code/github.com/sigil-dev/sigil/internal/server/sse.go` - SSE implementation
- `/Volumes/Code/github.com/sigil-dev/sigil/internal/server/sse_test.go` - SSE tests
- `/Volumes/Code/github.com/sigil-dev/sigil/internal/server/sse_internal_test.go` - Internal unit tests

## References

- PR #16 Review Round 22 - Comprehensive code review identifying test gap
- Issue: "Fix test gap: SSE drain race condition" (rated 9/10)
