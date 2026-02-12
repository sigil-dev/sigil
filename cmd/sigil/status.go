// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"

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

func runStatus(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("address")

	// TODO: HTTP call to /health endpoint once server is implemented (Task 1/7).
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Checking status at %s...\n", addr); err != nil {
		return err
	}
	_, err := fmt.Fprintln(cmd.OutOrStdout(), "Gateway is not running (connection refused)")
	return err
}
