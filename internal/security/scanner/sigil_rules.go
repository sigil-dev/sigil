// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	"regexp"
	"sync"

	"github.com/sigil-dev/sigil/pkg/types"
)

// sigilRuleSpec holds the compile-time-constant data for a Sigil-specific rule.
// Patterns are compiled once via sigilPatternsOnce; stage is stamped at call time.
type sigilRuleSpec struct {
	name     string
	pattern  *regexp.Regexp
	severity Severity
}

var (
	sigilPatternsOnce  sync.Once
	sigilPatternsCache []sigilRuleSpec
)

// sigilPatterns returns the cached compiled patterns for Sigil-specific rules.
// Patterns are compiled exactly once on first call.
func sigilPatterns() []sigilRuleSpec {
	sigilPatternsOnce.Do(func() {
		sigilPatternsCache = []sigilRuleSpec{
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
	})
	return sigilPatternsCache
}

// sigilSpecificRules returns secret detection patterns that are either
// not present in secrets-patterns-db or have better precision than the DB
// equivalents. These are maintained by the Sigil project.
//
// Patterns are compiled once (via sigilPatternsOnce) and reused across stages.
// Each call stamps the requested stage onto freshly constructed Rule values.
func sigilSpecificRules(stage types.ScanStage) []Rule {
	specs := sigilPatterns()
	rules := make([]Rule, len(specs))
	for i, s := range specs {
		rules[i] = mustNewRule(s.name, s.pattern, stage, s.severity)
	}
	return rules
}
