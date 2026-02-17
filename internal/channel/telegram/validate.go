// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package telegram

import (
	"context"
	"io"
	"net/http"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ValidateToken calls Telegram's getMe endpoint to verify the bot token.
func ValidateToken(ctx context.Context, client *http.Client, token string) error {
	url := "https://api.telegram.org/bot" + token + "/getMe"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "building Telegram validation request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "validating Telegram token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenInvalid, "invalid Telegram bot token (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "Telegram validation failed (HTTP %d)", resp.StatusCode)
	}

	return nil
}

// ValidateTokenWithURL is a testable version that uses the given URL directly
// instead of constructing the Telegram API URL from the token.
func ValidateTokenWithURL(ctx context.Context, client *http.Client, token, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "building Telegram request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "Telegram request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenInvalid, "invalid Telegram bot token (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return sigilerr.Errorf(sigilerr.CodeChannelTokenCheckFailed, "Telegram validation failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}
