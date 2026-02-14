// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"github.com/sigil-dev/sigil/internal/config"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewRootCmd creates the root sigil command with all subcommands registered.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sigil",
		Short: "Sigil — secure AI agent gateway",
		Long:  "Sigil is a secure, lightweight gateway connecting messaging platforms to AI agents.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return initViper(cmd)
		},
	}

	// Global flags — these map to viper keys via initViper.
	root.PersistentFlags().StringP("config", "c", "", "path to config file")
	root.PersistentFlags().String("data-dir", "", "path to data directory")
	root.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")

	// Register subcommands
	root.AddCommand(
		newStartCmd(),
		newStatusCmd(),
		newVersionCmd(),
		newWorkspaceCmd(),
		newPluginCmd(),
		newSessionCmd(),
		newChatCmd(),
		newDoctorCmd(),
	)

	return root
}

// initViper sets up the global Viper with defaults, env bindings, flag
// bindings, and optional config file so the standard precedence
// (flag > env > file > defaults) is handled uniformly.
func initViper(cmd *cobra.Command) error {
	v := viper.GetViper()

	config.SetDefaults(v)
	config.SetupEnv(v)

	if cfgFile, _ := cmd.Flags().GetString("config"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "reading config file: %w", err)
		}
	} else {
		// Auto-discover sigil.yaml from standard locations.
		v.SetConfigName("sigil")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.config/sigil")
		v.AddConfigPath("/etc/sigil")
		// Ignore "config file not found" — defaults and env vars still apply.
		_ = v.ReadInConfig()
	}

	// Bind persistent flags to viper keys.
	_ = v.BindPFlag("data_dir", cmd.Root().PersistentFlags().Lookup("data-dir"))
	_ = v.BindPFlag("verbose", cmd.Root().PersistentFlags().Lookup("verbose"))

	return nil
}
