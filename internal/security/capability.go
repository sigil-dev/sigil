// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

// Package security implements the capability-based access control model.
// Capability patterns use dot-separated segments with glob support.
// Only the "*" glob is supported (no "?", "[...]" or other glob metacharacters).
package security

import (
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// CapabilitySet is a set of capability patterns.
type CapabilitySet struct {
	patterns []string
}

// NewCapabilitySet constructs a CapabilitySet from the provided patterns.
func NewCapabilitySet(patterns ...string) CapabilitySet {
	copied := append([]string(nil), patterns...)
	return CapabilitySet{patterns: copied}
}

const maxSegments = 32

// MatchCapability reports whether cap matches pattern.
// Pattern matching is dot-segment aware:
//   - A segment exactly "*" matches one or more capability segments.
//   - "*" inside a non-"*" segment is an in-segment wildcard and matches
//     zero or more characters in that same segment.
//
// Malformed dotted strings (leading/trailing dot or consecutive dots) are rejected.
// Returns an error if either pattern or cap exceeds 32 dot-separated segments.
func MatchCapability(pattern, cap string) (bool, error) {
	if pattern == "" || cap == "" {
		return false, nil
	}
	if !isValidDottedString(pattern) || !isValidDottedString(cap) {
		return false, nil
	}

	patternSegments := strings.Split(pattern, ".")
	capSegments := strings.Split(cap, ".")

	if len(patternSegments) > maxSegments {
		return false, sigilerr.Errorf(sigilerr.CodeSecurityCapabilityInvalid, "pattern exceeds maximum %d segments: got %d", maxSegments, len(patternSegments))
	}
	if len(capSegments) > maxSegments {
		return false, sigilerr.Errorf(sigilerr.CodeSecurityCapabilityInvalid, "capability exceeds maximum %d segments: got %d", maxSegments, len(capSegments))
	}

	memo := make(map[[2]int]bool)
	seen := make(map[[2]int]bool)

	var match func(pi, ci int) bool
	match = func(pi, ci int) bool {
		key := [2]int{pi, ci}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true

		if pi == len(patternSegments) {
			memo[key] = ci == len(capSegments)
			return memo[key]
		}
		if ci == len(capSegments) {
			memo[key] = false
			return false
		}

		segment := patternSegments[pi]
		if segment == "*" {
			for next := ci + 1; next <= len(capSegments); next++ {
				if match(pi+1, next) {
					memo[key] = true
					return true
				}
			}
			memo[key] = false
			return false
		}

		if !matchSegment(segment, capSegments[ci]) {
			memo[key] = false
			return false
		}

		memo[key] = match(pi+1, ci+1)
		return memo[key]
	}

	return match(0, 0), nil
}

// Contains reports whether any capability pattern in the set matches cap.
// If MatchCapability returns an error, that pattern is skipped.
// Callers MUST validate patterns at load time (e.g. via manifest.Validate)
// to ensure errors here indicate programming bugs, not untrusted input.
func (s CapabilitySet) Contains(cap string) bool {
	for _, pattern := range s.patterns {
		match, err := MatchCapability(pattern, cap)
		if err == nil && match {
			return true
		}
	}
	return false
}

// AllowedBy reports whether cap is allowed by both sets.
func (s CapabilitySet) AllowedBy(other CapabilitySet, cap string) bool {
	return s.Contains(cap) && other.Contains(cap)
}

func matchSegment(patternSegment, capSegment string) bool {
	if patternSegment == capSegment {
		return true
	}
	if !strings.Contains(patternSegment, "*") {
		return false
	}
	return matchInSegmentGlob(patternSegment, capSegment)
}

func isValidDottedString(s string) bool {
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	return !strings.Contains(s, "..")
}

// matchInSegmentGlob matches pattern and text where '*' matches zero or more characters.
func matchInSegmentGlob(pattern, text string) bool {
	pi, ti := 0, 0
	star := -1
	match := 0

	for ti < len(text) {
		if pi < len(pattern) && pattern[pi] == text[ti] {
			pi++
			ti++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			match = ti
			pi++
			continue
		}
		if star != -1 {
			pi = star + 1
			match++
			ti = match
			continue
		}
		return false
	}

	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
