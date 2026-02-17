// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package scanner

import (
	_ "embed"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"unicode"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"gopkg.in/yaml.v3"
)

//go:embed db/rules-stable.yml
var rulesStableYAML []byte

// dbFile is the top-level structure of rules-stable.yml.
type dbFile struct {
	Patterns []dbEntry `yaml:"patterns"`
}

// dbEntry is a single pattern entry in the YAML.
type dbEntry struct {
	Pattern dbPattern `yaml:"pattern"`
}

// dbPattern holds the name, regex, and confidence level.
type dbPattern struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
}

var (
	dbOnce  sync.Once
	dbRules []Rule
	dbErr   error
)

// loadDBRules parses the embedded YAML and returns compiled high-confidence
// rules for the given stage. Uses sync.Once to parse only once.
func loadDBRules(stage Stage) ([]Rule, error) {
	dbOnce.Do(func() {
		var f dbFile
		if err := yaml.Unmarshal(rulesStableYAML, &f); err != nil {
			dbErr = sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
				"parsing secrets-patterns-db YAML: %w", err)
			return
		}

		seen := make(map[string]bool, len(f.Patterns))
		for _, entry := range f.Patterns {
			p := entry.Pattern
			if p.Confidence != "high" {
				continue
			}

			name := toSnakeCase(p.Name)

			// Deduplicate: first occurrence wins.
			if seen[name] {
				slog.Warn("duplicate DB rule name, skipping",
					"name", name, "original", p.Name)
				continue
			}
			seen[name] = true

			re, err := regexp.Compile(p.Regex)
			if err != nil {
				slog.Warn("skipping uncompilable DB pattern",
					"name", name, "regex", p.Regex, "error", err)
				continue
			}

			dbRules = append(dbRules, Rule{
				Name:     name,
				Pattern:  re,
				Severity: SeverityHigh,
				// Stage is set to a placeholder; callers stamp the correct stage.
			})
		}

		if len(dbRules) == 0 {
			dbErr = sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
				"zero high-confidence patterns loaded from secrets-patterns-db")
		}
	})

	if dbErr != nil {
		return nil, dbErr
	}

	// Stamp the requested stage onto each rule (rules are shared via dbOnce,
	// so we must copy to avoid mutating the cached slice).
	out := make([]Rule, len(dbRules))
	for i, r := range dbRules {
		r.Stage = stage
		out[i] = r
	}
	return out, nil
}

// toSnakeCase converts a display name like "AWS API Key" to "aws_api_key".
func toSnakeCase(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	prevWasUnderscore := false
	for _, r := range name {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			prevWasUnderscore = false
		default:
			// Collapse consecutive non-alnum chars into one underscore.
			if !prevWasUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				prevWasUnderscore = true
			}
		}
	}
	s := b.String()
	return strings.TrimRight(s, "_")
}
