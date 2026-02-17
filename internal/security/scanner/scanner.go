// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	"context"
	"regexp"
	"slices"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"golang.org/x/text/unicode/norm"
)

// Stage identifies where in the pipeline scanning occurs.
type Stage string

const (
	StageInput  Stage = "input"
	StageTool   Stage = "tool"
	StageOutput Stage = "output"
)

// Valid reports whether the stage is a known pipeline stage.
func (s Stage) Valid() bool {
	switch s {
	case StageInput, StageTool, StageOutput:
		return true
	default:
		return false
	}
}

// Origin indicates the source of content, used for context-aware logging and future rule selection.
type Origin string

const (
	OriginUser   Origin = "user_input"
	OriginSystem Origin = "system"
	OriginTool   Origin = "tool_output"
)

// Valid reports whether the origin is a known content origin.
func (o Origin) Valid() bool {
	switch o {
	case OriginUser, OriginSystem, OriginTool:
		return true
	default:
		return false
	}
}

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

// ScanResult holds the outcome of a scan.
type ScanResult struct {
	Threat  bool
	Matches []Match
	// Content holds the normalized content after Scan processing (NFKC +
	// zero-width character stripping). Match.Location/Length are byte offsets
	// into this string. Callers MUST use this for redaction to avoid offset
	// misalignment when the original content contained Unicode evasion chars.
	Content string
}

// Match describes a single pattern match.
// Location and Length are byte offsets into ScanResult.Content.
// Invariant: Location >= 0 and Length >= 0. RegexScanner guarantees
// this; other Scanner implementations must uphold it.
type Match struct {
	Rule     string
	Location int // byte offset into ScanResult.Content
	Length   int // byte length of the matched region
	Severity Severity
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

// DefaultMaxContentLength is the default maximum content size accepted by RegexScanner (1MB).
const DefaultMaxContentLength = 1 << 20 // 1MB

// RegexScanner implements Scanner using compiled regexes.
type RegexScanner struct {
	rules            []Rule
	maxContentLength int
}

// NewRegexScanner creates a scanner with the given rules.
func NewRegexScanner(rules []Rule) (*RegexScanner, error) {
	for i, r := range rules {
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
	}
	return &RegexScanner{rules: rules, maxContentLength: DefaultMaxContentLength}, nil
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

// normalize applies NFKC normalization and strips zero-width characters
// to reduce evasion via Unicode homoglyphs.
func normalize(s string) string {
	s = invisibleCharReplacer.Replace(s)
	// NFKC normalization collapses compatibility equivalents.
	return norm.NFKC.String(s)
}

// Scan checks content against rules matching the given stage.
func (s *RegexScanner) Scan(_ context.Context, content string, opts ScanContext) (ScanResult, error) {
	if !opts.Stage.Valid() {
		return ScanResult{}, sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure, "invalid scan stage %q", opts.Stage)
	}

	content = normalize(content)

	if len(content) > s.maxContentLength {
		return ScanResult{Threat: true, Content: content, Matches: []Match{{
			Rule:     "content_too_large",
			Location: 0,
			Length:   len(content),
			Severity: SeverityHigh,
		}}}, nil
	}

	result := ScanResult{Content: content}

	for _, rule := range s.rules {
		if rule.Stage != opts.Stage {
			continue
		}
		locs := rule.Pattern.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			result.Threat = true
			result.Matches = append(result.Matches, Match{
				Rule:     rule.Name,
				Location: loc[0],
				Length:   loc[1] - loc[0],
				Severity: rule.Severity,
			})
		}
	}

	return result, nil
}

// DefaultRules returns the built-in rule set for all three stages.
func DefaultRules() []Rule {
	return slices.Concat(InputRules(), ToolRules(), ToolSecretRules(), OutputRules())
}

// InputRules returns prompt injection detection patterns.
func InputRules() []Rule {
	return []Rule{
		{
			Name:     "instruction_override",
			Pattern:  regexp.MustCompile(`(?i)(ignore|disregard|override|forget|do\s+not\s+follow)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`),
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
}

// ToolRules returns tool result injection detection patterns.
func ToolRules() []Rule {
	return []Rule{
		{
			Name:     "system_prompt_leak",
			Pattern:  regexp.MustCompile(`(?im)^SYSTEM:\s`),
			Stage:    StageTool,
			Severity: SeverityHigh,
		},
		{
			Name:     "role_impersonation",
			Pattern:  regexp.MustCompile(`(?is)\[INST\].{0,1000}?\[/INST\]`),
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
			Pattern:  regexp.MustCompile(`xox[bpas]-[A-Za-z0-9-]+`),
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
			Name:     "database_connection_string",
			Pattern:  regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis|jdbc:[a-z]+)://[^\s]+:[^\s]+@[^\s]+`),
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
	}
}

// OutputRules returns secret/credential detection patterns for the output stage.
func OutputRules() []Rule { return secretRules(StageOutput) }

// ToolSecretRules returns secret/credential detection patterns for the tool stage.
func ToolSecretRules() []Rule { return secretRules(StageTool) }

// Mode defines how the scanner result is handled.
type Mode string

const (
	ModeBlock  Mode = "block"
	ModeFlag   Mode = "flag"
	ModeRedact Mode = "redact"
)

// Valid reports whether the mode is a known scanner mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeBlock, ModeFlag, ModeRedact:
		return true
	default:
		return false
	}
}

// ParseMode parses a mode string (case-insensitive).
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "block":
		return ModeBlock, nil
	case "flag":
		return ModeFlag, nil
	case "redact":
		return ModeRedact, nil
	default:
		return "", sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue, "invalid scanner mode: %q", s)
	}
}

// ApplyMode applies the detection mode to the scan result.
// For block: returns error if threat detected.
// For flag: returns the content argument as-is (threat already logged by caller).
//
//	Note: callers typically pass ScanResult.Content (normalized), not the original input.
//
// For redact: replaces matched regions with [REDACTED] using ScanResult.Content offsets.
func ApplyMode(mode Mode, content string, result ScanResult) (string, error) {
	if !result.Threat {
		return content, nil
	}

	switch mode {
	case ModeBlock:
		firstRule := "unknown"
		if len(result.Matches) > 0 {
			firstRule = result.Matches[0].Rule
		}
		return "", sigilerr.New(sigilerr.CodeSecurityScannerInputBlocked,
			"content blocked by security scanner",
			sigilerr.Field("matches", len(result.Matches)),
			sigilerr.Field("first_rule", firstRule),
		)
	case ModeFlag:
		return content, nil
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
		return m.Location < 0 || m.Length < 0
	})
	if len(sorted) == 0 {
		return content
	}

	slices.SortFunc(sorted, func(a, b Match) int { return a.Location - b.Location })

	// Merge overlapping ranges.
	type span struct{ start, end int }
	spans := []span{{sorted[0].Location, sorted[0].Location + sorted[0].Length}}
	for _, m := range sorted[1:] {
		last := &spans[len(spans)-1]
		end := m.Location + m.Length
		if m.Location <= last.end {
			if end > last.end {
				last.end = end
			}
		} else {
			spans = append(spans, span{m.Location, end})
		}
	}

	// Build result with forward scan.
	var b strings.Builder
	b.Grow(len(content))
	pos := 0
	for _, s := range spans {
		start := s.start
		end := s.end
		if end > len(content) {
			end = len(content)
		}
		b.WriteString(content[pos:start])
		b.WriteString("[REDACTED]")
		pos = end
	}
	b.WriteString(content[pos:])
	return b.String()
}
