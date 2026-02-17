// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner_test

import (
	"context"
	"testing"

	"github.com/sigil-dev/sigil/internal/security/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretsDB_HighConfidenceCount verifies the expected number of DB patterns load.
func TestSecretsDB_HighConfidenceCount(t *testing.T) {
	rules := mustOutputRules(t)

	// Count rules that are NOT Sigil-specific (i.e., from the DB).
	sigilNames := map[string]bool{
		"bearer_token":              true,
		"database_connection_string": true,
		"mssql_connection_string":   true,
		"keyring_uri":               true,
		"anthropic_api_key":         true,
		"openai_api_key":            true,
		"openai_legacy_key":         true,
		"npm_token":                 true,
		"azure_connection_string":   true,
		"vault_token":               true,
	}
	dbCount := 0
	for _, r := range rules {
		if !sigilNames[r.Name] {
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
		assert.NotNil(t, r.Pattern, "rule %q has nil pattern", r.Name)
	}
}

// TestSecretsDB_NoDuplicateNames verifies no two rules share the same name.
func TestSecretsDB_NoDuplicateNames(t *testing.T) {
	rules := mustOutputRules(t)
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.Name] {
			t.Errorf("duplicate rule name: %q", r.Name)
		}
		seen[r.Name] = true
	}
}

// TestToSnakeCase verifies the name conversion function via round-trip through loaded rules.
func TestToSnakeCase(t *testing.T) {
	// toSnakeCase is unexported, so we test it indirectly by checking
	// known DB pattern names that we know the original names of.
	rules := mustOutputRules(t)
	ruleNames := make(map[string]bool, len(rules))
	for _, r := range rules {
		ruleNames[r.Name] = true
	}

	// "AWS API Key" -> "aws_api_key"
	assert.True(t, ruleNames["aws_api_key"], "expected aws_api_key from DB")
	// google_api_key: Sigil-specific override (DB version is lowercase-only)
	assert.True(t, ruleNames["google_api_key"], "expected google_api_key")
	// "SendGrid API Key" -> "sendgrid_api_key"
	assert.True(t, ruleNames["sendgrid_api_key"], "expected sendgrid_api_key from DB")
	// "Twilio API Key" -> "twilio_api_key"
	assert.True(t, ruleNames["twilio_api_key"], "expected twilio_api_key from DB")
	// "Github Personal Access Token" -> "github_personal_access_token"
	assert.True(t, ruleNames["github_personal_access_token"],
		"expected github_personal_access_token from DB")
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
				Stage:  scanner.StageOutput,
				Origin: scanner.OriginSystem,
			})
			require.NoError(t, err)
			assert.True(t, result.Threat, "expected threat for: %q", tt.content)
		})
	}
}
