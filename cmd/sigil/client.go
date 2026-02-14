// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// defaultHTTPClient is the package-level HTTP client used by gateway commands.
// Overridden in tests via httptest.
var defaultHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

// gatewayClient provides HTTP access to a running Sigil gateway.
type gatewayClient struct {
	baseURL string
	http    *http.Client
}

// newGatewayClient creates a client targeting the given host:port address.
func newGatewayClient(addr string) *gatewayClient {
	return &gatewayClient{
		baseURL: "http://" + addr,
		http:    defaultHTTPClient,
	}
}

// getJSON performs a GET request and decodes the JSON response into dest.
// Returns an error with CodeCLIGatewayNotRunning on connection refused.
func (c *gatewayClient) getJSON(path string, dest interface{}) error {
	resp, err := c.http.Get(c.baseURL + path)
	if err != nil {
		if isDialError(err) {
			return sigilerr.New(sigilerr.CodeCLIGatewayNotRunning, "gateway is not running (connection refused)")
		}
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "gateway returned status %d: %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLIResponseInvalid, "invalid response: %w", err)
	}
	return nil
}

// isDialError returns true if err is a net dial error (connection refused, etc.).
func isDialError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial"
	}
	return false
}
