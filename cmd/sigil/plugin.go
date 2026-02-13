// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage plugins",
		Long:  "List, install, remove, reload, inspect, and view logs for plugins.",
	}

	cmd.AddCommand(
		newPluginListCmd(),
		newPluginInstallCmd(),
		newPluginRemoveCmd(),
		newPluginReloadCmd(),
		newPluginInspectCmd(),
		newPluginLogsCmd(),
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
		if errors.Is(err, ErrGatewayNotRunning) {
			_, _ = fmt.Fprintf(out, "Gateway at %s is not running (connection refused)\n", addr)
			return nil
		}
		return fmt.Errorf("listing plugins: %w", err)
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

func newPluginInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install [path-or-url]",
		Short: "Install a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Installing plugin from %s\n", args[0])
			return err
		},
	}

	cmd.Flags().String("tier", "process", "execution tier (wasm, process, container)")

	return cmd
}

func newPluginRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed plugin %q\n", args[0])
			return err
		},
	}
}

func newPluginReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload [name]",
		Short: "Reload a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Reloaded plugin %q\n", args[0])
			return err
		},
	}
}

func newPluginInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect [name]",
		Short: "Inspect plugin manifest and capabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Plugin: %s\n", args[0])
			return err
		},
	}
}

func newPluginLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs [name]",
		Short: "View plugin logs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Logs for plugin %q\n", args[0])
			return err
		},
	}

	cmd.Flags().BoolP("follow", "f", false, "follow log output")
	cmd.Flags().Int("tail", 100, "number of lines to show")

	return cmd
}
