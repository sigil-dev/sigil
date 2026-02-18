// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import "regexp"

// sigilSpecificRules returns secret detection patterns that are either
// not present in secrets-patterns-db or have better precision than the DB
// equivalents. These are maintained by the Sigil project.
func sigilSpecificRules(stage Stage) []Rule {
	return []Rule{
		mustNewRule("bearer_token",
			regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`),
			stage, SeverityHigh),
		// database_connection_string: matches protocol://[user[:password]@]host[:port][/path]
		// Supports URL-encoded passwords, IPv6 hosts in brackets.
		mustNewRule("database_connection_string",
			regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb|redis|jdbc:[a-z]+)://[^\s:@]+:(?:[^@\s%]|%[0-9A-Fa-f]{2})+@(?:\[[0-9A-Fa-f:]+\]|[^\s/:]+)(?:[:/][^\s]*)?`),
			stage, SeverityHigh),
		mustNewRule("mssql_connection_string",
			regexp.MustCompile(`(?i)(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^;]+`),
			stage, SeverityHigh),
		mustNewRule("keyring_uri",
			regexp.MustCompile(`keyring://[^\s]+`),
			stage, SeverityMedium),
		mustNewRule("anthropic_api_key",
			regexp.MustCompile(`sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}`),
			stage, SeverityHigh),
		mustNewRule("openai_api_key",
			regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`),
			stage, SeverityHigh),
		// openai_legacy_key: matches sk-[40+ chars]. Intentionally broad —
		// defense-in-depth at SeverityMedium.
		mustNewRule("openai_legacy_key",
			regexp.MustCompile(`sk-[A-Za-z0-9]{40,}`),
			stage, SeverityMedium),
		// DB's google_api_key regex only allows lowercase; real keys have uppercase.
		mustNewRule("google_api_key",
			regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
			stage, SeverityHigh),
		mustNewRule("npm_token",
			regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
			stage, SeverityHigh),
		mustNewRule("azure_connection_string",
			regexp.MustCompile(`(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}`),
			stage, SeverityHigh),
		mustNewRule("vault_token",
			regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`),
			stage, SeverityHigh),
		// GitHub fine-grained PAT not in DB (DB only covers ghp_/ghu_/ghs_/gho_).
		mustNewRule("github_fine_grained_pat",
			regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
			stage, SeverityHigh),
		// DB pattern requires "digitalocean" context; this matches the prefix directly.
		mustNewRule("digitalocean_pat",
			regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
			stage, SeverityHigh),
	}
}
