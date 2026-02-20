// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/sigil-dev/sigil/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretsDB_HighConfidenceCount verifies the expected number of DB patterns load.
func TestSecretsDB_HighConfidenceCount(t *testing.T) {
	rules := mustOutputRules(t)

	// Count rules that are NOT Sigil-specific (i.e., from the DB).
	sigilNames := map[string]struct{}{
		"bearer_token":               {},
		"database_connection_string": {},
		"mssql_connection_string":    {},
		"keyring_uri":                {},
		"anthropic_api_key":          {},
		"openai_api_key":             {},
		"openai_legacy_key":          {},
		"npm_token":                  {},
		"azure_connection_string":    {},
		"vault_token":                {},
	}
	dbCount := 0
	for _, r := range rules {
		if _, ok := sigilNames[r.Name()]; !ok {
			dbCount++
		}
	}

	// The vendored rules-stable.yml contains 883 high-confidence patterns.
	// Some may be deduplicated by name, so assert >= 850 as a safety margin.
	assert.GreaterOrEqual(t, dbCount, 850,
		"expected at least 850 DB patterns, got %d (total rules: %d)", dbCount, len(rules))
}

// TestSecretsDB_AllPatternsCompile verifies every loaded rule has a non-nil compiled regex.
func TestSecretsDB_AllPatternsCompile(t *testing.T) {
	rules := mustOutputRules(t)
	for _, r := range rules {
		assert.NotNil(t, r.Pattern(), "rule %q has nil pattern", r.Name())
	}
}

// TestSecretsDB_NoDuplicateNames verifies no two rules share the same name.
func TestSecretsDB_NoDuplicateNames(t *testing.T) {
	rules := mustOutputRules(t)
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if _, dup := seen[r.Name()]; dup {
			t.Errorf("duplicate rule name: %q", r.Name())
		}
		seen[r.Name()] = struct{}{}
	}
}

// TestToSnakeCase verifies the name conversion function via round-trip through loaded rules.
func TestToSnakeCase(t *testing.T) {
	// toSnakeCase is unexported, so we test it indirectly by checking
	// known DB pattern names that we know the original names of.
	rules := mustOutputRules(t)
	ruleNames := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		ruleNames[r.Name()] = struct{}{}
	}

	has := func(name string) bool { _, ok := ruleNames[name]; return ok }

	// "AWS API Key" -> "aws_api_key"
	assert.True(t, has("aws_api_key"), "expected aws_api_key from DB")
	// google_api_key: Sigil-specific override (DB version is lowercase-only)
	assert.True(t, has("google_api_key"), "expected google_api_key")
	// "SendGrid API Key" -> "sendgrid_api_key"
	assert.True(t, has("sendgrid_api_key"), "expected sendgrid_api_key from DB")
	// "Twilio API Key" -> "twilio_api_key"
	assert.True(t, has("twilio_api_key"), "expected twilio_api_key from DB")
	// "Github Personal Access Token" -> "github_personal_access_token"
	assert.True(t, has("github_personal_access_token"),
		"expected github_personal_access_token from DB")
}

// TestSecretRules_DeduplicationLogic verifies the three invariants of the secretRules()
// deduplication logic via OutputRules() as the public entry point:
//
//  1. DB-only rule: a rule present in the DB but not overridden by Sigil is
//     included unchanged.
//  2. Sigil-only rule: a Sigil-specific rule with no DB counterpart is included.
//  3. Collision: when DB and Sigil share a rule name, the Sigil version wins
//     (its pattern differs from the DB version and takes precedence).
func TestSecretRules_DeduplicationLogic(t *testing.T) {
	rules := mustOutputRules(t)

	// Build an index of name → pattern string for O(1) lookup.
	byName := make(map[string]string, len(rules))
	for _, r := range rules {
		byName[r.Name()] = r.Pattern().String()
	}

	tests := []struct {
		name        string
		ruleName    string
		wantPresent bool
		// wantPattern is the expected pattern string. Empty means "any non-empty pattern".
		wantPattern string
		description string
	}{
		{
			// Case 1: DB-only rule.
			// "aws_api_key" appears in secrets-patterns-db as a high-confidence rule and
			// has no Sigil override in sigil_rules.go. It should be present as-is from the DB.
			name:        "DB-only rule is included",
			ruleName:    "aws_api_key",
			wantPresent: true,
			wantPattern: "",
			description: "aws_api_key is a DB-only rule with no Sigil override; must be included",
		},
		{
			// Case 1 (second example): Another DB-only rule to confirm the general property.
			// "sendgrid_api_key" appears in the DB and has no Sigil override.
			name:        "DB-only rule sendgrid is included",
			ruleName:    "sendgrid_api_key",
			wantPresent: true,
			wantPattern: "",
			description: "sendgrid_api_key is a DB-only rule with no Sigil override; must be included",
		},
		{
			// Case 2: Sigil-only rule.
			// "github_fine_grained_pat" is defined in sigil_rules.go and is NOT present
			// in secrets-patterns-db (DB only covers ghp_/ghu_/ghs_/gho_ prefixes).
			// It must appear in the merged output from OutputRules().
			name:        "Sigil-only rule is included",
			ruleName:    "github_fine_grained_pat",
			wantPresent: true,
			wantPattern: `github_pat_[A-Za-z0-9_]{22,}`,
			description: "github_fine_grained_pat is Sigil-only; must be present in merged output",
		},
		{
			// Case 2 (second example): Another Sigil-only rule.
			// "digitalocean_pat" is defined in sigil_rules.go with prefix "dop_v1_";
			// DB uses context-keyword matching, not a prefix approach.
			name:        "Sigil-only rule digitalocean is included",
			ruleName:    "digitalocean_pat",
			wantPresent: true,
			wantPattern: `dop_v1_[a-f0-9]{64}`,
			description: "digitalocean_pat is Sigil-only; must be present in merged output",
		},
		{
			// Case 3: Collision — Sigil wins.
			// "google_api_key" exists in both the DB and sigil_rules.go. The DB version
			// only matches lowercase hex after "AIza", while the Sigil version allows
			// uppercase (AIza[0-9A-Za-z_-]{35}). The Sigil pattern must take precedence.
			name:        "collision: Sigil pattern wins over DB pattern",
			ruleName:    "google_api_key",
			wantPresent: true,
			wantPattern: `AIza[0-9A-Za-z_-]{35}`,
			description: "google_api_key collision: Sigil pattern (case-insensitive range) must win over DB pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, present := byName[tt.ruleName]
			assert.Equal(t, tt.wantPresent, present,
				"%s: rule %q presence mismatch", tt.description, tt.ruleName)
			if present && tt.wantPattern != "" {
				assert.Equal(t, tt.wantPattern, pattern,
					"%s: rule %q has pattern %q; want %q", tt.description, tt.ruleName, pattern, tt.wantPattern)
			}
			if present {
				assert.NotEmpty(t, pattern,
					"%s: rule %q has empty pattern string", tt.description, tt.ruleName)
			}
		})
	}
}

// TestSecretsDB_SpotCheckDetection verifies known secrets are detected by DB patterns.
func TestSecretsDB_SpotCheckDetection(t *testing.T) {
	s, err := scanner.NewRegexScanner(mustOutputRules(t))
	require.NoError(t, err)

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "AWS access key",
			content: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:    "GitHub classic PAT",
			content: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		},
		{
			name:    "Slack bot token",
			content: "xoxb-FAKE0TOKEN-abcdefghijklmnop",
		},
		{
			name:    "Google API key",
			content: "AIzaSyA0123456789abcdefghijklmnopqrstuvw",
		},
		{
			name:    "Stripe live key",
			content: "sk_live_00FAKE00TEST00FAKE00TEST00",
		},
		{
			name:    "PEM private key header",
			content: "-----BEGIN RSA PRIVATE KEY-----",
		},
		{
			name:    "SendGrid API key",
			content: "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",
		},
		{
			name:    "Twilio API key",
			content: "SK00000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Scan(context.Background(), tt.content, scanner.ScanContext{
				Stage:  types.ScanStageOutput,
				Origin: types.OriginSystem,
			})
			require.NoError(t, err)
			assert.True(t, result.Threat, "expected threat for: %q", tt.content)
		})
	}
}
