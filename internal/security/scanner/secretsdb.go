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
	"github.com/sigil-dev/sigil/pkg/types"
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

// dbCacheEntry holds validated intermediate rule data (name + compiled regex)
// without a stage, so the same cache can serve any stage via loadDBRules.
type dbCacheEntry struct {
	name    string
	pattern *regexp.Regexp
}

var (
	dbOnce    sync.Once
	dbEntries []dbCacheEntry
	dbErr     error
)

// loadDBRules parses the embedded YAML and returns compiled high-confidence
// rules for the given stage. Uses sync.Once to parse only once.
//
// False-positive filtering strategy: only patterns whose Confidence field
// equals "high" are loaded. Medium- and low-confidence patterns are excluded
// because they produce too many false positives in general-purpose text
// (common English words, short hex strings, etc.). Sigil-specific rules in
// sigilSpecificRules() override DB rules with the same name to provide better
// precision where the DB regex is known to be overly broad.
func loadDBRules(stage types.ScanStage) ([]Rule, error) {
	dbOnce.Do(func() {
		var f dbFile
		if err := yaml.Unmarshal(rulesStableYAML, &f); err != nil {
			dbErr = sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
				"parsing secrets-patterns-db YAML: %w", err)
			return
		}

		seen := make(map[string]bool, len(f.Patterns))
		var failedNames []string
		var duplicateCount int
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
				duplicateCount++
				continue
			}
			seen[name] = true

			re, err := regexp.Compile(p.Regex)
			if err != nil {
				slog.Error("high-confidence DB pattern failed to compile",
					"name", name, "regex", p.Regex, "error", err)
				failedNames = append(failedNames, name)
				continue
			}

			dbEntries = append(dbEntries, dbCacheEntry{name: name, pattern: re})
		}

		// Fail-closed: any compile failure in a high-confidence pattern means
		// the scanner cannot guarantee full coverage and must refuse to start.
		if len(failedNames) > 0 {
			dbErr = sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
				"scanner startup aborted: %d high-confidence pattern(s) failed to compile: %v",
				len(failedNames), failedNames)
			return
		}

		if len(dbEntries) == 0 {
			dbErr = sigilerr.Errorf(sigilerr.CodeSecurityScannerFailure,
				"zero high-confidence patterns loaded from secrets-patterns-db (%d duplicates skipped)",
				duplicateCount)
		}
	})

	if dbErr != nil {
		return nil, dbErr
	}

	// Construct proper Rules with the requested stage.
	// We must stamp the stage — Rules are immutable once created via NewRule.
	out := make([]Rule, 0, len(dbEntries))
	for _, e := range dbEntries {
		r, err := NewRule(e.name, e.pattern, stage, SeverityHigh)
		if err != nil {
			return nil, sigilerr.Wrapf(err, sigilerr.CodeSecurityScannerFailure,
				"creating rule %q for stage %s", e.name, stage)
		}
		out = append(out, r)
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
