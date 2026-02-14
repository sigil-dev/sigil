// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"text/tabwriter"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage sessions",
		Long:  "List agent sessions. Additional commands (show, archive, export) will be added in Phase 6.",
	}

	cmd.PersistentFlags().StringP("workspace", "w", "", "filter by workspace")

	cmd.AddCommand(
		newSessionListCmd(),
	)

	return cmd
}

func newSessionListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE:  runSessionList,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address")

	return cmd
}

func runSessionList(cmd *cobra.Command, _ []string) error {
	workspace, _ := cmd.Flags().GetString("workspace")
	if workspace == "" {
		return sigilerr.New(sigilerr.CodeCLIInputInvalid, "--workspace flag is required")
	}

	addr, _ := cmd.Flags().GetString("address")
	out := cmd.OutOrStdout()

	gw := newGatewayClient(addr)
	var body struct {
		Sessions []struct {
			ID          string `json:"id"`
			WorkspaceID string `json:"workspace_id"`
			Status      string `json:"status"`
		} `json:"sessions"`
	}
	if err := gw.getJSON("/api/v1/workspaces/"+workspace+"/sessions", &body); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeCLIGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return sigilerr.Errorf(sigilerr.CodeCLIRequestFailure, "listing sessions: %w", err)
	}

	if len(body.Sessions) == 0 {
		_, _ = fmt.Fprintln(out, "No sessions found")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tWORKSPACE\tSTATUS")
	for _, s := range body.Sessions {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", s.ID, s.WorkspaceID, s.Status)
	}
	return tw.Flush()
}
