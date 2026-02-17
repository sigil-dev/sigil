// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	"context"
	"regexp"
	"sort"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Stage identifies where in the pipeline scanning occurs.
type Stage string

const (
	StageInput  Stage = "input"
	StageTool   Stage = "tool"
	StageOutput Stage = "output"
)

// Origin indicates the source of the content being scanned.
type Origin string

const (
	OriginUser   Origin = "user_input"
	OriginSystem Origin = "system"
	OriginTool   Origin = "tool_output"
)

// Severity indicates how critical a detection is.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

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
}

// Match describes a single pattern match.
type Match struct {
	Rule     string
	Location int // byte offset
	Length   int
	Severity Severity
}

// Scanner scans content for threats.
type Scanner interface {
	Scan(ctx context.Context, content string, opts ScanContext) (*ScanResult, error)
}

// Rule defines a detection pattern.
type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Stage    Stage
	Severity Severity
}

// RegexScanner implements Scanner using compiled regexes.
type RegexScanner struct {
	rules []Rule
}

// NewRegexScanner creates a scanner with the given rules.
func NewRegexScanner(rules []Rule) *RegexScanner {
	return &RegexScanner{rules: rules}
}

// Scan checks content against rules matching the given stage.
func (s *RegexScanner) Scan(_ context.Context, content string, opts ScanContext) (*ScanResult, error) {
	result := &ScanResult{}

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
	rules := make([]Rule, 0, len(InputRules())+len(ToolRules())+len(OutputRules()))
	rules = append(rules, InputRules()...)
	rules = append(rules, ToolRules()...)
	rules = append(rules, OutputRules()...)
	return rules
}

// InputRules returns prompt injection detection patterns.
func InputRules() []Rule {
	return []Rule{
		{
			Name:     "instruction_override",
			Pattern:  regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`),
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
	}
}

// ToolRules returns tool result injection detection patterns.
func ToolRules() []Rule {
	return []Rule{
		{
			Name:     "system_prompt_leak",
			Pattern:  regexp.MustCompile(`(?i)^SYSTEM:\s`),
			Stage:    StageTool,
			Severity: SeverityHigh,
		},
		{
			Name:     "role_impersonation",
			Pattern:  regexp.MustCompile(`(?i)\[INST\].*\[/INST\]`),
			Stage:    StageTool,
			Severity: SeverityHigh,
		},
	}
}

// OutputRules returns secret/credential detection patterns.
func OutputRules() []Rule {
	return []Rule{
		{
			Name:     "aws_access_key",
			Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "openai_api_key",
			Pattern:  regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "anthropic_api_key",
			Pattern:  regexp.MustCompile(`sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "google_api_key",
			Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "bearer_token",
			Pattern:  regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "pem_private_key",
			Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "database_connection_string",
			Pattern:  regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@[^\s]+`),
			Stage:    StageOutput,
			Severity: SeverityHigh,
		},
		{
			Name:     "keyring_uri",
			Pattern:  regexp.MustCompile(`keyring://[^\s]+`),
			Stage:    StageOutput,
			Severity: SeverityMedium,
		},
	}
}

// Mode defines how the scanner result is handled.
type Mode string

const (
	ModeBlock  Mode = "block"
	ModeFlag   Mode = "flag"
	ModeRedact Mode = "redact"
)

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
// For flag: returns content unchanged (caller should log).
// For redact: replaces matched regions with [REDACTED].
func ApplyMode(mode Mode, content string, result *ScanResult) (string, error) {
	if !result.Threat {
		return content, nil
	}

	switch mode {
	case ModeBlock:
		return "", sigilerr.New(sigilerr.CodeSecurityScannerInputBlocked,
			"content blocked by security scanner",
			sigilerr.Field("matches", len(result.Matches)),
			sigilerr.Field("first_rule", result.Matches[0].Rule),
		)
	case ModeFlag:
		return content, nil
	case ModeRedact:
		return redact(content, result.Matches), nil
	default:
		return content, nil
	}
}

// redact replaces matched regions in content with [REDACTED].
// Processes matches in reverse order to preserve byte offsets.
func redact(content string, matches []Match) string {
	sorted := make([]Match, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Location > sorted[j].Location
	})

	result := content
	for _, m := range sorted {
		end := m.Location + m.Length
		if end > len(result) {
			end = len(result)
		}
		result = result[:m.Location] + "[REDACTED]" + result[end:]
	}
	return result
}
