// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security

import (
	"strings"
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

// MatchCapability reports whether cap matches pattern.
// Pattern matching is dot-segment aware:
//   - A segment exactly "*" matches one or more capability segments.
//   - "*" inside a non-"*" segment is an in-segment wildcard and matches
//     zero or more characters in that same segment.
//
// Malformed dotted strings (leading/trailing dot or consecutive dots) are rejected.
func MatchCapability(pattern, cap string) bool {
	if pattern == "" || cap == "" {
		return false
	}
	if !isValidDottedString(pattern) || !isValidDottedString(cap) {
		return false
	}

	patternSegments := strings.Split(pattern, ".")
	capSegments := strings.Split(cap, ".")

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

	return match(0, 0)
}

// Contains reports whether any capability pattern in the set matches cap.
func (s CapabilitySet) Contains(cap string) bool {
	for _, pattern := range s.patterns {
		if MatchCapability(pattern, cap) {
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
