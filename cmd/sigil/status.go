// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show gateway status",
		Long:  "Check the running gateway's health endpoint and display status information.",
		RunE:  runStatus,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address to check")

	return cmd
}

// statusClient is the HTTP client used for health checks. Overridden in tests.
var statusClient = &http.Client{
	Timeout: 5 * time.Second,
}

func runStatus(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	resp, err := statusClient.Get("http://" + addr + "/health")
	if err != nil {
		if isConnRefused(err) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(out, "Gateway at %s returned status %d\n", addr, resp.StatusCode)
		return nil
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		_, _ = fmt.Fprintf(out, "Gateway at %s is reachable but returned invalid response\n", addr)
		return nil
	}

	_, _ = fmt.Fprintf(out, "Gateway at %s: %s\n", addr, body.Status)
	return nil
}

func isConnRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial"
	}
	return false
}
