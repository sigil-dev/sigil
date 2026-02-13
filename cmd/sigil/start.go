// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sigil-dev/sigil/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the sigil gateway",
		Long:  "Load configuration, initialize all subsystems, and start the HTTP server.",
		RunE:  runStart,
	}

	cmd.Flags().String("listen", "", "override listen address (host:port)")
	_ = viper.BindPFlag("networking.listen", cmd.Flags().Lookup("listen"))

	return cmd
}

func runStart(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Apply any flag/env overrides that Viper resolved.
	if listen := viper.GetString("networking.listen"); listen != "" {
		cfg.Networking.Listen = listen
	}

	if viper.GetBool("verbose") {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	dataDir := viper.GetString("data_dir")
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".sigil")
	}

	gw, err := WireGateway(cfg, dataDir)
	if err != nil {
		return fmt.Errorf("wiring gateway: %w", err)
	}
	defer func() { _ = gw.Close() }()

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Sigil listening on %s\n", cfg.Networking.Listen)
	if err != nil {
		return err
	}

	return gw.Start(cmd.Context())
}
