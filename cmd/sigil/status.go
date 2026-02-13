// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show gateway status",
		Long:  "Check the running gateway's status endpoint and display status information.",
		RunE:  runStatus,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address to check")

	return cmd
}

func runStatus(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	gw := newGatewayClient(addr)
	var body struct {
		Status string `json:"status"`
	}
	if err := gw.getJSON("/api/v1/status", &body); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeCLIGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		_, _ = fmt.Fprintf(out, "Gateway at %s: %s\n", addr, err)
		return nil
	}

	_, _ = fmt.Fprintf(out, "Gateway at %s: %s\n", addr, body.Status)
	return nil
}
