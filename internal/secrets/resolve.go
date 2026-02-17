// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package secrets

import (
	"log/slog"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/viper"
)

const keyringScheme = "keyring://"

// IsKeyringURI reports whether value uses the keyring:// URI scheme.
func IsKeyringURI(value string) bool {
	return strings.HasPrefix(value, keyringScheme)
}

// ParseKeyringURI extracts service and key from a keyring://service/key URI.
// Returns an error if the URI is malformed.
func ParseKeyringURI(uri string) (service, key string, err error) {
	if !IsKeyringURI(uri) {
		return "", "", sigilerr.Errorf(sigilerr.CodeSecretInvalidInput, "not a keyring URI: %q", uri)
	}

	path := strings.TrimPrefix(uri, keyringScheme)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", sigilerr.Errorf(sigilerr.CodeSecretInvalidInput,
			"invalid keyring URI %q: expected keyring://service/key", uri)
	}

	return parts[0], parts[1], nil
}

// ResolveKeyringURI resolves a single keyring:// URI to its secret value.
// Returns the original value unchanged if it is not a keyring URI.
func ResolveKeyringURI(store Store, value string) (string, error) {
	if !IsKeyringURI(value) {
		return value, nil
	}

	service, key, err := ParseKeyringURI(value)
	if err != nil {
		return "", err
	}

	secret, err := store.Retrieve(service, key)
	if err != nil {
		return "", sigilerr.Wrapf(err, sigilerr.CodeSecretResolveFailure,
			"resolving keyring URI %q", value)
	}

	return secret, nil
}

// ResolveViperSecrets walks all keys in a Viper instance and resolves any
// string values that use the keyring:// URI scheme. This is a post-load
// resolution step, not a Viper decoder hook.
//
// Resolution failures are logged as warnings and the original URI value is
// kept in place, allowing the application to surface the error later when
// the config value is actually used.
func ResolveViperSecrets(v *viper.Viper, store Store) {
	for _, key := range v.AllKeys() {
		val := v.GetString(key)
		if !IsKeyringURI(val) {
			continue
		}

		resolved, err := ResolveKeyringURI(store, val)
		if err != nil {
			slog.Warn("failed to resolve keyring URI, keeping original value",
				"config_key", key,
				"error", err,
			)
			continue
		}

		v.Set(key, resolved)
	}
}
