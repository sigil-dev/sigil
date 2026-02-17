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

// Stage identifies where in the pipeline scanning occurs.
// Aliased from pkg/types for backward compatibility.
type Stage = types.ScanStage

const (
	StageInput  Stage = types.ScanStageInput
	StageTool   Stage = types.ScanStageTool
	StageOutput Stage = types.ScanStageOutput
)

// Origin indicates the source of content (user input, system, or tool output).
// Aliased from pkg/types for backward compatibility.
type Origin = types.Origin

const (
	OriginUser   = types.OriginUserInput
	OriginSystem = types.OriginSystem
	OriginTool   = types.OriginToolOutput
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
	Stage    Stage
	Origin   Origin
	Metadata map[string]string
}

// NewScanContext creates a ScanContext with a deep-copied Metadata map so
// callers cannot mutate the map after construction.
func NewScanContext(stage Stage, origin Origin, metadata map[string]string) ScanContext {
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
	Threat  bool
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
type Rule struct {
	// Stage is the pipeline phase this rule applies to; the scanner only evaluates rules whose Stage matches ScanContext.Stage.
	Stage    Stage
	Name     string
	Pattern  *regexp.Regexp
	Severity Severity
}

// NewRule creates a Rule with validated fields.
func NewRule(name string, pattern *regexp.Regexp, stage Stage, severity Severity) (Rule, error) {
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
		Name:     name,
		Pattern:  pattern,
		Stage:    stage,
		Severity: severity,
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
		// Validate rules in the same loop that copies them.
		if r.Pattern == nil {
			return nil, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %d (%s) has nil pattern", i, r.Name)
		}
		if !r.Stage.Valid() {
			return nil, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %d (%s) has invalid stage %q", i, r.Name, r.Stage)
		}
		if r.Name == "" {
			return nil, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %d has empty name", i)
		}
		if !r.Severity.Valid() {
			return nil, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "rule %d (%s) has invalid severity %q", i, r.Name, r.Severity)
		}
		// Deep-copy the rule.
		copied[i] = Rule{
			Stage:    r.Stage,
			Name:     r.Name,
			Pattern:  regexp.MustCompile(r.Pattern.String()),
			Severity: r.Severity,
		}
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
	// 1. Decode HTML entities so that encoded payloads get normalized.
	s = html.UnescapeString(s)
	// 2. Strip zero-width and invisible Unicode characters.
	s = invisibleCharReplacer.Replace(s)
	// 3. NFKC normalization collapses compatibility equivalents.
	return norm.NFKC.String(s)
}

// Scan checks content against rules matching the given stage.
// The context.Context parameter is intentionally discarded: Go RE2 guarantees
// linear-time matching, so mid-scan cancellation is unnecessary for typical
// content sizes. The interface accepts context for future Scanner implementations.
func (s *RegexScanner) Scan(_ context.Context, content string, opts ScanContext) (ScanResult, error) {
	if !opts.Stage.Valid() {
		return ScanResult{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "invalid scan stage: %q", opts.Stage)
	}
	if !opts.Origin.Valid() {
		return ScanResult{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "invalid scan origin: %q", opts.Origin)
	}

	// Defensive copy: prevent caller mutation of shared metadata.
	if opts.Metadata != nil {
		copied := make(map[string]string, len(opts.Metadata))
		for k, v := range opts.Metadata {
			copied[k] = v
		}
		opts.Metadata = copied
	}

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
		if rule.Stage != opts.Stage {
			continue
		}
		locs := rule.Pattern.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			m, err := NewMatch(rule.Name, loc[0], loc[1]-loc[0], rule.Severity)
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
// Stage ordering does not affect behavior; the scanner filters rules by Stage during Scan().
func DefaultRules() []Rule {
	return slices.Concat(InputRules(), ToolRules(), ToolSecretRules(), OutputRules())
}

// InputRules returns rules for StageInput: prompt injection, instruction override,
// and secret detection patterns. Secrets in user input are blocked (default mode)
// before reaching the LLM, preventing accidental credential forwarding.
func InputRules() []Rule {
	injection := []Rule{
		{
			// Allow up to 3 optional words between the verb and the target noun phrase.
			// This catches "Please disregard your previous instructions" and similar
			// constructions while keeping the regex anchored to known keywords.
			Name:     "instruction_override",
			Pattern:  regexp.MustCompile(`(?i)(ignore|disregard|override|forget|do\s+not\s+follow)(\s+\w+){0,3}\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`),
			Stage:    StageInput,
			Severity: SeverityHigh,
		},
		{
			Name:     "role_confusion",
			Pattern:  regexp.MustCompile(`(?i)you\s+are\s+now\s+\w+[,.]?\s*(do|ignore|forget|disregard)`),
			Stage:    StageInput,
			Severity: SeverityHigh,
		},
		{
			Name:     "delimiter_abuse",
			Pattern:  regexp.MustCompile("(?i)```system\\b"),
			Stage:    StageInput,
			Severity: SeverityMedium,
		},
		{
			// NOTE: This pattern uses nested alternatives; safe due to Go RE2 linear-time guarantee.
			Name:     "new_task_injection",
			Pattern:  regexp.MustCompile(`(?i)(new\s+task|from\s+now\s+on|pretend\s+(?:the\s+)?(?:above|previous)\s+(?:rules?|instructions?)\s+(?:do\s+not|don'?t)\s+exist)`),
			Stage:    StageInput,
			Severity: SeverityMedium,
		},
		{
			Name:     "system_block_injection",
			Pattern:  regexp.MustCompile(`(?i)(?:<\|?system\|?>|\[system\]|<<SYS>>)`),
			Stage:    StageInput,
			Severity: SeverityHigh,
		},
	}
	return slices.Concat(injection, secretRules(StageInput))
}

// ToolRules returns rules for StageTool: tool call injection and system command patterns.
func ToolRules() []Rule {
	return []Rule{
		{
			Name:     "system_prompt_leak",
			Pattern:  regexp.MustCompile(`(?im)^SYSTEM:\s`),
			Stage:    StageTool,
			Severity: SeverityHigh,
		},
		{
			Name:     "role_impersonation_open",
			Pattern:  regexp.MustCompile(`(?i)\[INST\]`),
			Stage:    StageTool,
			Severity: SeverityHigh,
		},
		{
			Name:     "role_impersonation_close",
			Pattern:  regexp.MustCompile(`(?i)\[/INST\]`),
			Stage:    StageTool,
			Severity: SeverityHigh,
		},
	}
}

// secretRules returns secret/credential detection patterns for the given stage.
func secretRules(stage Stage) []Rule {
	return []Rule{
		{
			Name:     "aws_access_key",
			Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "openai_api_key",
			Pattern:  regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		// openai_legacy_key: matches sk-[40+ chars]. Intentionally broad —
		// overlaps with anthropic_api_key and openai_api_key patterns.
		// Redundant matches are safe: redaction merge handles overlapping spans.
		// Go's RE2 engine lacks lookaheads, so exclusion requires post-match
		// filtering. Accepted as defense-in-depth for v1.
		{
			Name:     "openai_legacy_key",
			Pattern:  regexp.MustCompile(`sk-[A-Za-z0-9]{40,}`),
			Stage:    stage,
			Severity: SeverityMedium,
		},
		{
			Name:     "github_pat",
			Pattern:  regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "github_fine_grained_pat",
			Pattern:  regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "slack_token",
			Pattern:  regexp.MustCompile(`xox[bpas]-[A-Za-z0-9-]{10,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "anthropic_api_key",
			Pattern:  regexp.MustCompile(`sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "google_api_key",
			Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "bearer_token",
			Pattern:  regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "pem_private_key",
			Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name: "database_connection_string",
			// Matches: protocol://[user[:password]@]host[:port][/path]
			// Supports:
			// - URL-encoded passwords (e.g., p%40ssw0rd for p@ssw0rd, p%3Aword for p:word)
			// - IPv6 hosts in brackets (e.g., [::1], [fe80::1])
			// - Standard hostnames and IPv4 addresses
			Pattern:  regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb|redis|jdbc:[a-z]+)://[^\s:@]+:(?:[^@\s%]|%[0-9A-Fa-f]{2})+@(?:\[[0-9A-Fa-f:]+\]|[^\s/:]+)(?:[:/][^\s]*)?`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "mssql_connection_string",
			Pattern:  regexp.MustCompile(`(?i)(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^;]+`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "keyring_uri",
			Pattern:  regexp.MustCompile(`keyring://[^\s]+`),
			Stage:    stage,
			Severity: SeverityMedium,
		},
		{
			Name:     "stripe_api_key",
			Pattern:  regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "stripe_restricted_key",
			Pattern:  regexp.MustCompile(`rk_live_[A-Za-z0-9]{24,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "npm_token",
			Pattern:  regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "azure_connection_string",
			Pattern:  regexp.MustCompile(`(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "sendgrid_api_key",
			Pattern:  regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "digitalocean_pat",
			Pattern:  regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "vault_token",
			Pattern:  regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name:     "twilio_api_key",
			Pattern:  regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
	}
}

// OutputRules returns rules for StageOutput: secret/credential detection patterns.
func OutputRules() []Rule { return secretRules(StageOutput) }

// ToolSecretRules returns rules for StageTool: secret/credential detection patterns.
func ToolSecretRules() []Rule { return secretRules(StageTool) }

// Mode is the scanner detection mode. Aliased from pkg/types for backward compatibility.
type Mode = types.ScannerMode

const (
	ModeBlock  = types.ScannerModeBlock
	ModeFlag   = types.ScannerModeFlag
	ModeRedact = types.ScannerModeRedact
)

// ParseMode parses a case-insensitive string into a Mode.
func ParseMode(s string) (Mode, error) {
	return types.ParseScannerMode(s)
}

// ApplyMode applies the detection mode to the scan result.
// For block: returns an error with a stage-specific error code if threat detected.
// For flag: returns the content unchanged. Callers are responsible for
// logging or recording the threat details from ScanResult.Matches.
// For redact: replaces matched regions with [REDACTED] using ScanResult.Content offsets.
func ApplyMode(mode Mode, stage Stage, result ScanResult) (string, error) {
	if !result.Threat {
		return result.Content, nil
	}

	switch mode {
	case ModeBlock:
		firstRule := "unknown"
		if len(result.Matches) > 0 {
			firstRule = result.Matches[0].Rule
		}
		code := sigilerr.CodeSecurityScannerInputBlocked
		switch stage {
		case StageTool:
			code = sigilerr.CodeSecurityScannerToolBlocked
		case StageOutput:
			code = sigilerr.CodeSecurityScannerOutputBlocked
		}
		return "", sigilerr.New(code,
			"content blocked by security scanner",
			sigilerr.Field("matches", len(result.Matches)),
			sigilerr.Field("first_rule", firstRule),
			sigilerr.Field("stage", string(stage)),
		)
	case ModeFlag:
		return result.Content, nil
	case ModeRedact:
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
