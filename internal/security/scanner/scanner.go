// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	"context"
	"html"
	"regexp"
	"slices"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/sigil-dev/sigil/pkg/types"
	"golang.org/x/text/unicode/norm"
)

// Severity indicates how critical a detection is.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Valid reports whether the severity is a known severity level.
func (s Severity) Valid() bool {
	switch s {
	case SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// ScanContext provides context for the scan.
type ScanContext struct {
	Stage types.ScanStage
	// Origin is recorded in scan results for audit and logging purposes; it does
	// not affect which rules are evaluated. Rule filtering uses only Stage.
	Origin types.Origin
	// Metadata holds caller-supplied key-value pairs for audit/logging context.
	// Use NewScanContext for safe construction (deep-copies the map). When
	// constructing ScanContext directly, the caller retains ownership of the map
	// and must not mutate it after passing it to Scan.
	Metadata map[string]string
}

// NewScanContext creates a ScanContext with a deep-copied Metadata map so
// callers cannot mutate the map after construction.
func NewScanContext(stage types.ScanStage, origin types.Origin, metadata map[string]string) ScanContext {
	var copied map[string]string
	if metadata != nil {
		copied = make(map[string]string, len(metadata))
		for k, v := range metadata {
			copied[k] = v
		}
	}
	return ScanContext{
		Stage:    stage,
		Origin:   origin,
		Metadata: copied,
	}
}

// ScanResult holds the outcome of a scan.
type ScanResult struct {
	Threat bool
	// Matches must not be mutated after Scan returns. The slice offsets reference
	// Content (the normalized form); sorting, filtering, or appending to Matches
	// may invalidate the offset invariant used by ApplyMode for redaction.
	Matches []Match
	// Content holds the normalized content after Scan processing (NFKC +
	// zero-width character stripping). Match.Location()/Length() are byte offsets
	// into this string. Callers MUST use this for redaction to avoid offset
	// misalignment when the original content contained Unicode evasion chars.
	Content string
}

// Match describes a single pattern match.
// location and length are unexported to enforce the invariant that both are >= 0.
// Use NewMatch for all construction; use Location() and Length() accessors for reads.
// Invariant: location >= 0 and length >= 0, guaranteed by NewMatch.
type Match struct {
	Rule     string
	location int // byte offset into ScanResult.Content
	length   int // byte length of the matched region
	Severity Severity
}

// Location returns the byte offset of the match into ScanResult.Content.
func (m Match) Location() int { return m.location }

// Length returns the byte length of the matched region.
func (m Match) Length() int { return m.length }

// NewMatch creates a Match with validated invariants.
// location and length must be >= 0.
func NewMatch(rule string, location, length int, severity Severity) (Match, error) {
	if location < 0 || length < 0 {
		return Match{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
			"invalid match: location=%d, length=%d must be >= 0", location, length)
	}
	return Match{
		Rule:     rule,
		location: location,
		length:   length,
		Severity: severity,
	}, nil
}

// Scanner scans content for threats.
type Scanner interface {
	Scan(ctx context.Context, content string, opts ScanContext) (ScanResult, error)
}

// Rule defines a detection pattern.
// All fields are unexported to enforce construction via NewRule, which validates invariants.
// Use the accessor methods Stage(), Name(), Pattern(), and Severity() for reads.
type Rule struct {
	// stage is the pipeline phase this rule applies to; the scanner only evaluates rules whose stage matches ScanContext.Stage.
	stage    types.ScanStage
	name     string
	pattern  *regexp.Regexp
	severity Severity
}

// Stage returns the pipeline stage this rule applies to.
func (r Rule) Stage() types.ScanStage { return r.stage }

// Name returns the rule's identifier name.
func (r Rule) Name() string { return r.name }

// Pattern returns the compiled regex pattern for this rule.
func (r Rule) Pattern() *regexp.Regexp { return r.pattern }

// Severity returns the severity level of this rule.
func (r Rule) Severity() Severity { return r.severity }

// NewRule creates a Rule with validated fields.
func NewRule(name string, pattern *regexp.Regexp, stage types.ScanStage, severity Severity) (Rule, error) {
	if name == "" {
		return Rule{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule name must not be empty")
	}
	if pattern == nil {
		return Rule{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %s has nil pattern", name)
	}
	if !stage.Valid() {
		return Rule{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %s has invalid stage %q", name, stage)
	}
	if !severity.Valid() {
		return Rule{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %s has invalid severity %q", name, severity)
	}
	return Rule{
		name:     name,
		pattern:  pattern,
		stage:    stage,
		severity: severity,
	}, nil
}

// DefaultMaxContentLength is the default maximum content size accepted by RegexScanner (1MB).
const DefaultMaxContentLength = 1 << 20 // 1MB

// RegexScanner implements Scanner using compiled regexes.
type RegexScanner struct {
	rules            []Rule
	maxContentLength int
}

// ScannerOption configures a RegexScanner.
type ScannerOption func(*RegexScanner)

// WithMaxContentLength sets the maximum content length the scanner will accept.
// Values <= 0 cause NewRegexScanner to return an error.
func WithMaxContentLength(n int) ScannerOption {
	return func(s *RegexScanner) { s.maxContentLength = n }
}

// NewRegexScanner creates a scanner with the given rules and optional configuration.
func NewRegexScanner(rules []Rule, opts ...ScannerOption) (*RegexScanner, error) {
	copied := make([]Rule, len(rules))
	for i, r := range rules {
		// Deep-copy via re-compilation ensures the scanner's rules are not aliased
		// with the caller's slice. regexp.Regexp is safe for concurrent use (stdlib
		// guarantee), so the copy is for ownership isolation, not thread safety.
		c, err := NewRule(r.name, regexp.MustCompile(r.pattern.String()), r.stage, r.severity)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %d: %w", i, err)
		}
		copied[i] = c
	}
	s := &RegexScanner{rules: copied, maxContentLength: DefaultMaxContentLength}
	for _, opt := range opts {
		opt(s)
	}
	if s.maxContentLength <= 0 {
		return nil, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
			"maxContentLength must be > 0, got %d", s.maxContentLength)
	}
	return s, nil
}

// invisibleCharReplacer strips zero-width and other invisible Unicode characters
// to reduce evasion via Unicode homoglyphs. Allocated once at package init.
var invisibleCharReplacer = strings.NewReplacer(
	"\x00", "", // ASCII null byte (not collapsed by NFKC; used to fragment injection phrases)
	"\u200b", "", // zero-width space
	"\u200c", "", // zero-width non-joiner
	"\u200d", "", // zero-width joiner
	"\ufeff", "", // zero-width no-break space / BOM
	"\u00ad", "", // soft hyphen
	"\u034f", "", // combining grapheme joiner
	"\u061c", "", // Arabic letter mark
	"\u180e", "", // Mongolian vowel separator
	"\u2060", "", // word joiner
	"\u2061", "", // invisible function application
	"\u2062", "", // invisible times
	"\u2063", "", // invisible separator
	"\u2064", "", // invisible plus
	"\u206a", "", // inhibit symmetric swapping
	"\u206b", "", // activate symmetric swapping
	"\u206c", "", // inhibit Arabic form shaping
	"\u206d", "", // activate Arabic form shaping
	"\u206e", "", // national digit shapes
	"\u206f", "", // nominal digit shapes
	"\ufff9", "", // interlinear annotation anchor
	"\ufffa", "", // interlinear annotation separator
	"\ufffb", "", // interlinear annotation terminator
)

// Normalize applies HTML entity decoding, zero-width character stripping, and
// NFKC normalization to reduce evasion via Unicode homoglyphs and HTML encoding.
// Exported so other packages (e.g., the agent loop) can apply the same
// normalization pipeline.
func Normalize(s string) string {
	// 1. Decode HTML entities iteratively so that double/triple-encoded
	// payloads (e.g. &amp;lt;|system|&amp;gt;) are fully decoded.
	for prev := ""; prev != s; {
		prev = s
		s = html.UnescapeString(s)
	}
	// 2. Strip zero-width and invisible Unicode characters.
	s = invisibleCharReplacer.Replace(s)
	// 3. NFKC normalization collapses compatibility equivalents.
	return norm.NFKC.String(s)
}

// Scan checks content against rules matching the given stage.
// The context.Context parameter is intentionally discarded: Go RE2 guarantees
// linear-time matching, so mid-scan cancellation is unnecessary for typical
// content sizes. The interface accepts context for future Scanner implementations.
//
// opts.Origin is validated and stored in the returned ScanResult for audit and
// logging purposes only; it does not influence which rules are evaluated. Rule
// selection is determined exclusively by opts.Stage.
func (s *RegexScanner) Scan(_ context.Context, content string, opts ScanContext) (ScanResult, error) {
	if !opts.Stage.Valid() {
		return ScanResult{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "invalid scan stage: %q", opts.Stage)
	}
	// opts.Origin is validated here to catch misconfigured callers early.
	// It is metadata for audit/logging and does not affect rule evaluation.
	if !opts.Origin.Valid() {
		return ScanResult{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "invalid scan origin: %q", opts.Origin)
	}

	// Metadata was already deep-copied by NewScanContext; no additional copy needed.
	// Callers constructing ScanContext directly accept ownership of the map.

	content = Normalize(content)

	if len(content) > s.maxContentLength {
		return ScanResult{
				Content: content,
			}, sigilerr.New(sigilerr.CodeSecurityScannerContentTooLarge,
				"content exceeds maximum length",
				sigilerr.Field("length", len(content)),
				sigilerr.Field("max_length", s.maxContentLength),
				sigilerr.Field("stage", string(opts.Stage)),
			)
	}

	result := ScanResult{Content: content}

	for _, rule := range s.rules {
		if rule.stage != opts.Stage {
			continue
		}
		locs := rule.pattern.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			m, err := NewMatch(rule.name, loc[0], loc[1]-loc[0], rule.severity)
			if err != nil {
				return ScanResult{}, err
			}
			result.Threat = true
			result.Matches = append(result.Matches, m)
		}
	}

	return result, nil
}

// DefaultRules returns the built-in rule set for all three stages.
// Returns an error if the embedded secrets-patterns-db cannot be loaded.
func DefaultRules() ([]Rule, error) {
	input, err := InputRules()
	if err != nil {
		return nil, err
	}
	output, err := OutputRules()
	if err != nil {
		return nil, err
	}
	toolSecrets, err := ToolSecretRules()
	if err != nil {
		return nil, err
	}
	return slices.Concat(input, ToolRules(), toolSecrets, output), nil
}

// mustNewRule creates a Rule via NewRule, panicking on error.
// For use only with compile-time-constant patterns that are known valid.
func mustNewRule(name string, pattern *regexp.Regexp, stage types.ScanStage, severity Severity) Rule {
	r, err := NewRule(name, pattern, stage, severity)
	if err != nil {
		panic("scanner: invalid built-in rule: " + err.Error())
	}
	return r
}

// InputRules returns rules for StageInput: prompt injection, instruction override,
// and secret detection patterns. Secrets in user input are blocked (default mode)
// before reaching the LLM, preventing accidental credential forwarding.
//
// Including secretRules at StageInput is a defense-in-depth measure. The primary
// secret scan is at StageOutput (to prevent the LLM from leaking credentials in
// its responses), but scanning user input as well prevents:
//   - Accidental credential forwarding: users pasting API keys into chat messages.
//   - Prompt-injection-with-credential-theft: an adversary including a secret in
//     their message to have it echoed back by the LLM in a logged session.
//
// Callers that only want prompt-injection rules without secret detection can
// construct rules manually. This function returns the full input-stage rule set.
func InputRules() ([]Rule, error) {
	injection := []Rule{
		// Allow up to 3 optional words between the verb and the target noun phrase.
		mustNewRule("instruction_override",
			regexp.MustCompile(`(?i)(ignore|disregard|override|forget|do\s+not\s+follow)(\s+\w+){0,3}\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`),
			types.ScanStageInput, SeverityHigh),
		mustNewRule("role_confusion",
			regexp.MustCompile(`(?i)you\s+are\s+now\s+\w+[,.]?\s*(do|ignore|forget|disregard)`),
			types.ScanStageInput, SeverityHigh),
		mustNewRule("delimiter_abuse",
			regexp.MustCompile("(?i)```system\\b"),
			types.ScanStageInput, SeverityMedium),
		// new_task_injection: 'new task' and 'from now on' require attack-intent
		// keywords in proximity to avoid false positives on benign messages like
		// "I have a new task for you" or "From now on, use bullet points".
		mustNewRule("new_task_injection",
			regexp.MustCompile(`(?i)((?:new\s+task|from\s+now\s+on)\s*[,:;.!]?\s*(?:ignore|disregard|forget|override|bypass|do\s+not\s+follow|stop\s+following)|pretend\s+(?:the\s+)?(?:above|previous)\s+(?:rules?|instructions?|guidelines?)\s+(?:do\s+not|don'?t)\s+exist)`),
			types.ScanStageInput, SeverityMedium),
		mustNewRule("system_block_injection",
			regexp.MustCompile(`(?i)(?:<\|?system\|?>|\[system\]|<<SYS>>)`),
			types.ScanStageInput, SeverityHigh),
	}
	secrets, err := secretRules(types.ScanStageInput)
	if err != nil {
		return nil, err
	}
	return slices.Concat(injection, secrets), nil
}

// ToolRules returns rules for StageTool: tool call injection and system command patterns.
// These are static patterns that do not depend on the secrets DB.
func ToolRules() []Rule {
	return []Rule{
		mustNewRule("system_prompt_leak",
			regexp.MustCompile(`(?im)^SYSTEM:\s`),
			types.ScanStageTool, SeverityHigh),
		mustNewRule("role_impersonation_open",
			regexp.MustCompile(`(?i)\[INST\]`),
			types.ScanStageTool, SeverityHigh),
		mustNewRule("role_impersonation_close",
			regexp.MustCompile(`(?i)\[/INST\]`),
			types.ScanStageTool, SeverityHigh),
	}
}

// secretRules returns the combined secrets-patterns-db + Sigil-specific secret
// detection patterns for the given stage. Sigil-specific rules override DB
// rules with the same name (better precision or coverage).
func secretRules(stage types.ScanStage) ([]Rule, error) {
	sigil := sigilSpecificRules(stage)
	sigilNames := make(map[string]struct{}, len(sigil))
	for _, r := range sigil {
		sigilNames[r.name] = struct{}{}
	}

	db, err := loadDBRules(stage)
	if err != nil {
		return nil, err
	}

	// Filter DB rules that collide with Sigil-specific names.
	filtered := make([]Rule, 0, len(db))
	for _, r := range db {
		if _, ok := sigilNames[r.name]; !ok {
			filtered = append(filtered, r)
		}
	}

	return append(filtered, sigil...), nil
}

// OutputRules returns rules for StageOutput: secret/credential detection patterns.
func OutputRules() ([]Rule, error) { return secretRules(types.ScanStageOutput) }

// ToolSecretRules returns rules for StageTool: secret/credential detection patterns.
func ToolSecretRules() ([]Rule, error) { return secretRules(types.ScanStageTool) }

// ParseMode parses a case-insensitive string into a types.ScannerMode.
func ParseMode(s string) (types.ScannerMode, error) {
	return types.ParseScannerMode(s)
}

// ApplyMode applies the detection mode to the scan result.
// For block: returns an error with a stage-specific error code if threat detected.
// For flag: returns the normalized content from ScanResult unchanged. Note that
// ScanResult.Content is the NFKC-normalized form produced by Scan; it may differ
// from the original input if Unicode normalization was applied. Callers are
// responsible for logging or recording the threat details from ScanResult.Matches.
// For redact: replaces matched regions with [REDACTED] using ScanResult.Content offsets.
func ApplyMode(mode types.ScannerMode, stage types.ScanStage, result ScanResult) (string, error) {
	if !result.Threat {
		return result.Content, nil
	}

	switch mode {
	case types.ScannerModeBlock:
		firstRule := "unknown"
		if len(result.Matches) > 0 {
			firstRule = result.Matches[0].Rule
		}
		code := sigilerr.CodeSecurityScannerInputBlocked
		switch stage {
		case types.ScanStageTool:
			code = sigilerr.CodeSecurityScannerToolBlocked
		case types.ScanStageOutput:
			code = sigilerr.CodeSecurityScannerOutputBlocked
		}
		return "", sigilerr.New(code,
			"content blocked by security scanner",
			sigilerr.Field("matches", len(result.Matches)),
			sigilerr.Field("first_rule", firstRule),
			sigilerr.Field("stage", string(stage)),
		)
	case types.ScannerModeFlag:
		return result.Content, nil
	case types.ScannerModeRedact:
		// Always use the normalized content from the scan result for redaction.
		// Match offsets are computed against the normalized string; applying
		// them to the original un-normalized content causes incorrect redaction
		// when zero-width or NFKC-affected characters shift byte positions.
		return redact(result.Content, result.Matches), nil
	default:
		return "", sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "unknown scanner mode %q", mode)
	}
}

// redact replaces matched regions in content with [REDACTED].
// Handles overlapping matches by merging ranges before substitution.
func redact(content string, matches []Match) string {
	if len(matches) == 0 {
		return content
	}

	// Sort by location ascending.
	sorted := make([]Match, len(matches))
	copy(sorted, matches)

	// Skip invalid matches (defensive against non-regex Scanner implementations).
	sorted = slices.DeleteFunc(sorted, func(m Match) bool {
		return m.location < 0 || m.length < 0
	})
	if len(sorted) == 0 {
		return content
	}

	slices.SortFunc(sorted, func(a, b Match) int { return a.location - b.location })

	// Merge overlapping ranges.
	type span struct{ start, end int }
	spans := []span{{sorted[0].location, sorted[0].location + sorted[0].length}}
	for _, m := range sorted[1:] {
		last := &spans[len(spans)-1]
		end := m.location + m.length
		if m.location <= last.end {
			if end > last.end {
				last.end = end
			}
		} else {
			spans = append(spans, span{m.location, end})
		}
	}

	// Build result with forward scan.
	var b strings.Builder
	b.Grow(len(content))
	pos := 0
	for _, s := range spans {
		start := max(min(s.start, len(content)), pos)
		end := min(s.end, len(content))
		b.WriteString(content[pos:start])
		if start < end {
			b.WriteString("[REDACTED]")
		}
		pos = end
	}
	b.WriteString(content[pos:])
	return b.String()
}
