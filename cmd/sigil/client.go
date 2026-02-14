// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
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

// chatStreamEvent is a single SSE event parsed from the chat/stream response.
type chatStreamEvent struct {
	Event string
	Data  string
}

// postSSE sends a POST request and streams SSE events via the returned channel.
// The channel is closed when the stream ends. The caller must drain the channel.
// Returns an error with CodeCLIGatewayNotRunning on connection refused.
func (c *gatewayClient) postSSE(path string, body interface{}) (<-chan chatStreamEvent, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "marshaling request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	// Use a client without timeout for streaming.
	streamClient := &http.Client{Transport: c.http.Transport}
	resp, err := streamClient.Do(req)
	if err != nil {
		if isDialError(err) {
			return nil, sigilerr.New(sigilerr.CodeCLIGatewayNotRunning, "gateway is not running (connection refused)")
		}
		return nil, sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		respBody, _ := io.ReadAll(resp.Body)
		return nil, sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "gateway returned status %d: %s", resp.StatusCode, string(respBody))
	}

	ch := make(chan chatStreamEvent, 16)
	go func() {
		defer func() { _ = resp.Body.Close() }()
		defer close(ch)
		parseSSEStream(resp.Body, ch)
	}()

	return ch, nil
}

// parseSSEStream reads an SSE stream and sends parsed events to ch.
func parseSSEStream(r io.Reader, ch chan<- chatStreamEvent) {
	scanner := bufio.NewScanner(r)
	var currentEvent string
	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line = end of event.
			if currentEvent != "" || len(dataLines) > 0 {
				ch <- chatStreamEvent{
					Event: currentEvent,
					Data:  strings.Join(dataLines, "\n"),
				}
				currentEvent = ""
				dataLines = nil
			}
			continue
		}

		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
	}

	// Flush any trailing event without final blank line.
	if currentEvent != "" || len(dataLines) > 0 {
		ch <- chatStreamEvent{
			Event: currentEvent,
			Data:  strings.Join(dataLines, "\n"),
		}
	}
}

// isDialError returns true if err is a net dial error (connection refused, etc.).
func isDialError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial"
	}
	return false
}
