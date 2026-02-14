// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"text/tabwriter"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage plugins",
		Long:  "List installed plugins. Additional commands (install, remove, reload, inspect, logs) will be added in Phase 6.",
	}

	cmd.AddCommand(
		newPluginListCmd(),
	)

	return cmd
}

func newPluginListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed plugins",
		RunE:  runPluginList,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address")

	return cmd
}

func runPluginList(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	gw := newGatewayClient(addr)
	var body struct {
		Plugins []struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Version string `json:"version"`
			Status  string `json:"status"`
		} `json:"plugins"`
	}
	if err := gw.getJSON("/api/v1/plugins", &body); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeCLIGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "listing plugins: %w", err)
	}

	if len(body.Plugins) == 0 {
		_, _ = fmt.Fprintln(out, "No plugins found")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tTYPE\tVERSION\tSTATUS")
	for _, p := range body.Plugins {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.Type, p.Version, p.Status)
	}
	return tw.Flush()
}
