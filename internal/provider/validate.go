// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package provider

import (
	"context"
	"io"
	"net/http"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// ProviderName identifies a supported LLM provider for key validation.
type ProviderName string

const (
	ProviderAnthropic  ProviderName = "anthropic"
	ProviderOpenAI     ProviderName = "openai"
	ProviderGoogle     ProviderName = "google"
	ProviderOpenRouter ProviderName = "openrouter"
)

// ValidateKey makes a lightweight HTTP call to the provider's models endpoint
// to confirm the API key is valid.
func ValidateKey(ctx context.Context, client *http.Client, provider ProviderName, key string) error {
	var (
		url     string
		headers map[string]string
	)

	switch provider {
	case ProviderAnthropic:
		url = "https://api.anthropic.com/v1/models"
		headers = map[string]string{
			"x-api-key":         key,
			"anthropic-version": "2023-06-01",
		}
	case ProviderOpenAI:
		url = "https://api.openai.com/v1/models"
		headers = map[string]string{
			"Authorization": "Bearer " + key,
		}
	case ProviderGoogle:
		// Google's Generative Language API authenticates via query parameter.
		// This is Google's standard approach — there is no header-based alternative.
		// Note: the key will appear in HTTP proxy/CDN access logs.
		url = "https://generativelanguage.googleapis.com/v1/models?key=" + key
	case ProviderOpenRouter:
		url = "https://openrouter.ai/api/v1/models"
		headers = map[string]string{
			"Authorization": "Bearer " + key,
		}
	default:
		return sigilerr.Errorf(sigilerr.CodeProviderKeyInvalid, "unknown provider: %s", provider)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "building validation request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "validating %s key: %w", provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyInvalid, "invalid %s API key (HTTP %d)", provider, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "%s validation failed (HTTP %d)", provider, resp.StatusCode)
	}

	return nil
}

// ValidateKeyWithURL is a testable version of ValidateKey that accepts an
// explicit URL. When url is non-empty it overrides the provider default.
func ValidateKeyWithURL(ctx context.Context, client *http.Client, provider ProviderName, key, url string, headers map[string]string) error {
	if provider == "" || provider == "unknown" {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyInvalid, "unknown provider: %s", provider)
	}

	if url == "" {
		return ValidateKey(ctx, client, provider, key)
	}

	if headers == nil {
		headers = make(map[string]string)
	}
	switch provider {
	case ProviderAnthropic:
		headers["x-api-key"] = key
		headers["anthropic-version"] = "2023-06-01"
	case ProviderOpenAI, ProviderOpenRouter:
		headers["Authorization"] = "Bearer " + key
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "building request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyInvalid, "invalid %s API key (HTTP %d)", provider, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return sigilerr.Errorf(sigilerr.CodeProviderKeyCheckFailed, "validation failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}
