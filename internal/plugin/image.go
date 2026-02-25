// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package plugin

import (
	"regexp"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// validOCIImagePattern matches valid OCI image references.
var validOCIImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./:_@-]*$`)

// ValidateImageRef validates an OCI image reference string.
// It checks for empty values, path-like prefixes, whitespace, and invalid characters.
func ValidateImageRef(image string) error {
	clean := strings.TrimSpace(image)
	if clean == "" {
		return sigilerr.New(sigilerr.CodePluginManifestValidateInvalid, "execution.image must not be empty")
	}
	if strings.Contains(clean, "..") {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q must not contain '..'", image)
	}
	if strings.ContainsAny(clean, " \t\r\n") {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q must not contain whitespace", image)
	}
	if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, ".") {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q must be an OCI image reference", image)
	}
	if !validOCIImagePattern.MatchString(clean) {
		return sigilerr.Errorf(sigilerr.CodePluginManifestValidateInvalid,
			"execution.image %q contains invalid characters", image)
	}
	return nil
}
