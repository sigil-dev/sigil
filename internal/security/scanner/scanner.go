// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	"context"
	"regexp"
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
