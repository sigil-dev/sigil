// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sigil-dev/sigil/internal/config"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
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

	return cmd
}

func runStart(cmd *cobra.Command, _ []string) error {
	v := viper.GetViper()

	if err := viper.BindPFlag("networking.listen", cmd.Flags().Lookup("listen")); err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "binding listen flag: %w", err)
	}

	cfg, err := config.FromViper(v)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "loading config: %w", err)
	}

	if v.GetBool("verbose") {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	// Warn if config file has overly permissive permissions (tokens may be exposed).
	config.WarnInsecurePermissions(v.ConfigFileUsed())

	dataDir := v.GetString("data_dir")
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "getting user home directory: %w", err)
		}
		dataDir = filepath.Join(home, ".sigil")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	gw, err := WireGateway(ctx, cfg, dataDir)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "wiring gateway: %w", err)
	}
	defer func() {
		if err := gw.Close(); err != nil {
			slog.Error("gateway shutdown error", "error", err)
		}
	}()

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Sigil listening on %s\n", cfg.Networking.Listen)
	if err != nil {
		return err
	}

	return gw.Start(ctx)
}
