# Agent Loop Security Pipeline Design

**Issue**: sigil-6wo.1
**Date**: 2026-02-17
**Status**: Approved

## Goal

Implement the three deferred security hooks in the agent loop (design/03 §Agent Integrity steps 1, 6, 7) plus origin tagging, using a shared scanner engine.

## Architecture

### Shared Scanner Package (`internal/security/scanner/`)

A single `Scanner` interface with a regex-based rule engine. Three rule configurations share the engine:

```go
type Scanner interface {
    Scan(ctx context.Context, content string, opts ScanContext) (*ScanResult, error)
}

type ScanContext struct {
    Stage    Stage    // StageInput | StageTool | StageOutput
    Origin   Origin   // OriginUser | OriginTool | OriginSystem
    Metadata map[string]string
}

type ScanResult struct {
    Threat  bool
    Matches []Match // pattern name, location, severity
}
```

Implementation uses Go stdlib `regexp` (compiled at init). TruffleHog was considered but rejected due to AGPL-3.0 license incompatibility with Apache-2.0.

### Rule Categories

| Category | Patterns | Default Mode |
|----------|----------|-------------|
| Input | Prompt injection: instruction override, role confusion, delimiter abuse | block |
| Tool | Instruction injection in tool results: system prompt leaks, role impersonation | flag |
| Output | Secrets: AWS keys, Google API keys, OpenAI API keys (incl. legacy), Anthropic API keys, GitHub PATs, Slack tokens, bearer tokens, PEM keys, DB connection strings, keyring:// URIs | redact |

PII detection (SSNs, emails, phones) excluded from v1 due to false-positive risk.

### Detection Modes

- **block**: Reject the message, return error to caller
- **flag**: Log warning with match details, tag message, continue processing
- **redact**: Replace matched content with `[REDACTED]`

### Origin Tagging

New `Origin` field on `provider.Message`:

```go
type Origin string

const (
    OriginUser   Origin = "user_input"
    OriginSystem Origin = "system"
    OriginTool   Origin = "tool_output"
)
```

Set at message construction time in `loop.go`. Scanner uses origin for context-aware rule selection.

### Configuration

```yaml
security:
  scanner:
    input:  block
    tool:   flag
    output: redact
```

New `ScannerConfig` struct in config package with Viper mapstructure binding.

### Integration Points (loop.go)

1. **Line ~313** (Step 1): Input scanning + origin tagging before message persistence
2. **Line ~631** (Step 6): Tool result injection scanning after tool execution
3. **Line ~673** (Step 7): Output filtering in `respond()` before persisting assistant message

### Error Codes

New codes in `pkg/errors/errors.go`:
- `security.scanner.input_blocked` — input rejected by scanner
- `security.scanner.failure` — scanner internal error

### Testing Strategy

- Table-driven tests for scanner patterns (each regex, each mode)
- Integration tests for each hook point in loop.go (mock scanner)
- Config tests for mode parsing and defaults

## Decisions

- **stdlib regexp over trufflehog**: AGPL-3.0 incompatible with Apache-2.0
- **Shared engine, separate rules**: Avoids code duplication, consistent scanning behavior
- **No PII in v1**: False-positive rate too high without ML-based detection
- **Flag as tool default**: Blocking tool results risks breaking agent loop; flagging preserves observability without disruption
