// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package security_test

import (
	"testing"

	"github.com/sigil-dev/sigil/internal/security"
)

func TestMatchCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		cap     string
		want    bool
	}{
		{name: "exact match", pattern: "sessions.read", cap: "sessions.read", want: true},
		{name: "exact no match", pattern: "sessions.read", cap: "sessions.write", want: false},
		{name: "wildcard single segment", pattern: "sessions.*", cap: "sessions.read", want: true},
		{name: "wildcard multiple segments", pattern: "exec.*", cap: "exec.run.sandboxed", want: true},
		{name: "wildcard requires one or more segments", pattern: "sessions.*", cap: "sessions", want: false},
		{name: "single wildcard matches multi segment capability", pattern: "*", cap: "a.b", want: true},
		{name: "single wildcard does not match empty capability", pattern: "*", cap: "", want: false},
		{name: "two wildcards match two segments", pattern: "*.*", cap: "a.b", want: true},
		{name: "two wildcards match three segments via first wildcard consumption", pattern: "*.*", cap: "a.b.c", want: true},
		{name: "two wildcards do not match single segment", pattern: "*.*", cap: "a", want: false},
		{name: "middle wildcard backtracks positive", pattern: "a.*.c", cap: "a.b.d.c", want: true},
		{name: "middle wildcard positive single segment", pattern: "a.*.c", cap: "a.b.c", want: true},
		{name: "middle wildcard negative suffix mismatch", pattern: "a.*.c", cap: "a.b.d", want: false},
		{name: "middle wildcard negative missing middle segment", pattern: "a.*.c", cap: "a.c", want: false},
		{name: "path scoped", pattern: "filesystem.read./data/*", cap: "filesystem.read./data/plugins/foo", want: true},
		{name: "path scoped no match", pattern: "filesystem.read./data/*", cap: "filesystem.read./etc/shadow", want: false},
		{name: "self scope", pattern: "config.read.self", cap: "config.read.self", want: true},
		{name: "self scope no match", pattern: "config.read.self", cap: "config.read.other", want: false},
		// In-segment "*" is a character glob in the same segment and matches zero or more chars.
		{name: "in-segment wildcard zero chars", pattern: "messages.send.foo*bar", cap: "messages.send.foobar", want: true},
		{name: "in-segment wildcard one or more chars", pattern: "messages.send.foo*bar", cap: "messages.send.foo123bar", want: true},
		{name: "in-segment wildcard no match", pattern: "messages.send.foo*bar", cap: "messages.send.foo123baz", want: false},
		{name: "multiple in-segment wildcards", pattern: "messages.send.f*o*b*r", cap: "messages.send.foooooobar", want: true},
		{name: "double wildcard chars in segment", pattern: "messages.send.foo**bar", cap: "messages.send.fooXYZbar", want: true},
		{name: "empty pattern", pattern: "", cap: "sessions.read", want: false},
		{name: "empty capability", pattern: "sessions.read", cap: "", want: false},
		{name: "invalid pattern consecutive dots", pattern: "a..b", cap: "a.x.b", want: false},
		{name: "invalid pattern leading dot", pattern: ".a.b", cap: "a.b", want: false},
		{name: "invalid pattern trailing dot", pattern: "a.b.", cap: "a.b", want: false},
		{name: "invalid capability consecutive dots", pattern: "a.*.b", cap: "a..b", want: false},
		{name: "invalid capability leading dot", pattern: "a.b", cap: ".a.b", want: false},
		{name: "invalid capability trailing dot", pattern: "a.b", cap: "a.b.", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := security.MatchCapability(tt.pattern, tt.cap); got != tt.want {
				t.Fatalf("MatchCapability(%q, %q) = %v, want %v", tt.pattern, tt.cap, got, tt.want)
			}
		})
	}
}

func TestCapabilitySetContains(t *testing.T) {
	t.Parallel()

	set := security.NewCapabilitySet("sessions.read", "sessions.write", "messages.send.*")

	tests := []struct {
		name string
		cap  string
		want bool
	}{
		{name: "exact capability", cap: "sessions.read", want: true},
		{name: "wildcard capability", cap: "messages.send.telegram", want: true},
		{name: "missing capability", cap: "exec.run", want: false},
		{name: "empty set", cap: "sessions.read", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			target := set
			if tt.name == "empty set" {
				target = security.NewCapabilitySet()
			}

			if got := target.Contains(tt.cap); got != tt.want {
				t.Fatalf("Contains(%q) = %v, want %v", tt.cap, got, tt.want)
			}
		})
	}
}

func TestCapabilitySetAllowedBy(t *testing.T) {
	t.Parallel()

	a := security.NewCapabilitySet("sessions.*", "messages.send.*", "exec.run")
	b := security.NewCapabilitySet("sessions.read", "messages.*")
	empty := security.NewCapabilitySet()

	tests := []struct {
		name  string
		left  security.CapabilitySet
		right security.CapabilitySet
		cap   string
		want  bool
	}{
		{name: "allowed by both", left: a, right: b, cap: "sessions.read", want: true},
		{name: "missing from right", left: a, right: b, cap: "exec.run", want: false},
		{name: "missing from left", left: b, right: a, cap: "exec.run", want: false},
		{name: "empty left", left: empty, right: b, cap: "sessions.read", want: false},
		{name: "empty right", left: a, right: empty, cap: "sessions.read", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.left.AllowedBy(tt.right, tt.cap); got != tt.want {
				t.Fatalf("AllowedBy(..., %q) = %v, want %v", tt.cap, got, tt.want)
			}
		})
	}
}
