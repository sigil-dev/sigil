// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"text/tabwriter"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
)

func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage workspaces",
		Long:  "List workspaces. Additional commands (create, delete, show) will be added in Phase 6.",
	}

	cmd.AddCommand(
		newWorkspaceListCmd(),
	)

	return cmd
}

func newWorkspaceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		RunE:  runWorkspaceList,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address")

	return cmd
}

func runWorkspaceList(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	gw := newGatewayClient(addr)
	var body struct {
		Workspaces []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"workspaces"`
	}
	if err := gw.getJSON("/api/v1/workspaces", &body); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeCLIGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "listing workspaces: %w", err)
	}

	if len(body.Workspaces) == 0 {
		_, _ = fmt.Fprintln(out, "No workspaces found")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tDESCRIPTION")
	for _, ws := range body.Workspaces {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", ws.ID, ws.Description)
	}
	return tw.Flush()
}

