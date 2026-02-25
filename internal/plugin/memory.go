// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"regexp"
	"strconv"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

var memoryLimitPattern = regexp.MustCompile(`^([1-9][0-9]*)(Ki|Mi|Gi)?$`)

// ParseMemoryLimit parses memory limits like "256Mi", "1Gi", or raw bytes "4096".
func ParseMemoryLimit(limit string) (int64, error) {
	match := memoryLimitPattern.FindStringSubmatch(strings.TrimSpace(limit))
	if len(match) != 3 {
		return 0, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"memory_limit must match <positive-int>[Ki|Mi|Gi], got %q", limit)
	}

	base, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return 0, sigilerr.Wrapf(err, sigilerr.CodeConfigValidateInvalidValue,
			"parsing memory_limit %q", limit)
	}

	factor := int64(1)
	switch match[2] {
	case "Ki":
		factor = 1024
	case "Mi":
		factor = 1024 * 1024
	case "Gi":
		factor = 1024 * 1024 * 1024
	}

	value := base * factor
	if value/factor != base {
		return 0, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"memory_limit %q overflows int64", limit)
	}
	if value <= 0 {
		return 0, sigilerr.Errorf(sigilerr.CodeConfigValidateInvalidValue,
			"memory_limit must be > 0, got %q", limit)
	}

	return value, nil
}
