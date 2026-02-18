// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	"regexp"

	"github.com/sigil-dev/sigil/pkg/types"
)

// sigilRuleSpec holds the compile-time-constant data for a Sigil-specific rule.
// Stage is stamped at call time by sigilSpecificRules; patterns are shared across stages.
type sigilRuleSpec struct {
	name     string
	pattern  *regexp.Regexp
	severity Severity
}

// sigilPatterns holds the compiled patterns for Sigil-specific rules.
// regexp.MustCompile panics on invalid patterns, so initialization is safe at
// package level (pattern validity is enforced by tests).
var sigilPatterns = []sigilRuleSpec{
	{
		name:     "bearer_token",
		pattern:  regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`),
		severity: SeverityHigh,
	},
	{
		// database_connection_string: matches protocol://[user[:password]@]host[:port][/path]
		// Supports URL-encoded passwords, IPv6 hosts in brackets.
		name:     "database_connection_string",
		pattern:  regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb|redis|jdbc:[a-z]+)://[^\s:@]+:(?:[^@\s%]|%[0-9A-Fa-f]{2})+@(?:\[[0-9A-Fa-f:]+\]|[^\s/:]+)(?:[:/][^\s]*)?`),
		severity: SeverityHigh,
	},
	{
		name:     "mssql_connection_string",
		pattern:  regexp.MustCompile(`(?i)(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^;]+`),
		severity: SeverityHigh,
	},
	{
		name:     "keyring_uri",
		pattern:  regexp.MustCompile(`keyring://[^\s]+`),
		severity: SeverityMedium,
	},
	{
		name:     "anthropic_api_key",
		pattern:  regexp.MustCompile(`sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}`),
		severity: SeverityHigh,
	},
	{
		name:     "openai_api_key",
		pattern:  regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`),
		severity: SeverityHigh,
	},
	{
		// openai_legacy_key: matches sk-[40+ chars]. Intentionally broad —
		// defense-in-depth at SeverityMedium.
		name:     "openai_legacy_key",
		pattern:  regexp.MustCompile(`sk-[A-Za-z0-9]{40,}`),
		severity: SeverityMedium,
	},
	{
		// DB's google_api_key regex only allows lowercase; real keys have uppercase.
		name:     "google_api_key",
		pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		severity: SeverityHigh,
	},
	{
		name:     "npm_token",
		pattern:  regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		severity: SeverityHigh,
	},
	{
		name:     "azure_connection_string",
		pattern:  regexp.MustCompile(`(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}`),
		severity: SeverityHigh,
	},
	{
		name:     "vault_token",
		pattern:  regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`),
		severity: SeverityHigh,
	},
	{
		// GitHub fine-grained PAT not in DB (DB only covers ghp_/ghu_/ghs_/gho_).
		name:     "github_fine_grained_pat",
		pattern:  regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
		severity: SeverityHigh,
	},
	{
		// DB pattern requires "digitalocean" context; this matches the prefix directly.
		name:     "digitalocean_pat",
		pattern:  regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		severity: SeverityHigh,
	},
}

// sigilSpecificRules returns secret detection patterns that are either
// not present in secrets-patterns-db or have better precision than the DB
// equivalents. These are maintained by the Sigil project.
//
// Patterns are shared across stages (see sigilPatterns). Each call stamps
// the requested stage onto freshly constructed Rule values.
func sigilSpecificRules(stage types.ScanStage) []Rule {
	rules := make([]Rule, len(sigilPatterns))
	for i, s := range sigilPatterns {
		rules[i] = mustNewRule(s.name, s.pattern, stage, s.severity)
	}
	return rules
}
