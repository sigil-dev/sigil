// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package types

import (
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ScannerMode defines how the security scanner handles detected threats.
type ScannerMode string

const (
	ScannerModeBlock  ScannerMode = "block"
	ScannerModeFlag   ScannerMode = "flag"
	ScannerModeRedact ScannerMode = "redact"
)

// Valid reports whether m is a recognized scanner mode.
func (m ScannerMode) Valid() bool {
	switch m {
	case ScannerModeBlock, ScannerModeFlag, ScannerModeRedact:
		return true
	default:
		return false
	}
}

// ParseScannerMode parses a case-insensitive string into a ScannerMode.
func ParseScannerMode(s string) (ScannerMode, error) {
	m := ScannerMode(strings.ToLower(s))
	if !m.Valid() {
		return "", sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"invalid scanner mode: %q", s)
	}
	return m, nil
}

