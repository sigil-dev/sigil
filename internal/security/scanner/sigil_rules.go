// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import "regexp"

// sigilSpecificRules returns secret detection patterns that are either
// not present in secrets-patterns-db or have better precision than the DB
// equivalents. These are maintained by the Sigil project.
func sigilSpecificRules(stage Stage) []Rule {
	return []Rule{
		{
			Name:     "bearer_token",
			Pattern:  regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			Name: "database_connection_string",
			// Matches: protocol://[user[:password]@]host[:port][/path]
			// Supports URL-encoded passwords, IPv6 hosts in brackets.
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
			Name:     "anthropic_api_key",
			Pattern:  regexp.MustCompile(`sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}`),
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
			// openai_legacy_key: matches sk-[40+ chars]. Intentionally broad —
			// defense-in-depth at SeverityMedium.
			Name:     "openai_legacy_key",
			Pattern:  regexp.MustCompile(`sk-[A-Za-z0-9]{40,}`),
			Stage:    stage,
			Severity: SeverityMedium,
		},
		{
			// DB's google_api_key regex only allows lowercase; real keys have uppercase.
			Name:     "google_api_key",
			Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
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
			Name:     "vault_token",
			Pattern:  regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			// GitHub fine-grained PAT not in DB (DB only covers ghp_/ghu_/ghs_/gho_).
			Name:     "github_fine_grained_pat",
			Pattern:  regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
		{
			// DB pattern requires "digitalocean" context; this matches the prefix directly.
			Name:     "digitalocean_pat",
			Pattern:  regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
			Stage:    stage,
			Severity: SeverityHigh,
		},
	}
}
