// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"errors"

	"github.com/sigil-dev/sigil/internal/config"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewRootCmd creates the root sigil command with all subcommands registered.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sigil",
		Short:         "Sigil — secure AI agent gateway",
		Long:          "Sigil is a secure, lightweight gateway connecting messaging platforms to AI agents.",
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
		newInitCmd(),
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
		// Note: SetConfigType is intentionally omitted. When set, Viper
		// falls back to trying the bare config name without extension,
		// which collides with the ./sigil binary in the project root.
		v.SetConfigName("sigil")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.config/sigil")
		v.AddConfigPath("/etc/sigil")
		// No config file is fine — defaults and env vars still apply.
		// Parse or permission errors must surface.
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "reading config: %w", err)
			}
			// No config found anywhere — bootstrap a default to ~/.config/sigil/.
			if path := config.BootstrapConfig(); path != "" {
				v.SetConfigFile(path)
				if err := v.ReadInConfig(); err != nil {
					return sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "reading bootstrapped config: %w", err)
				}
			}
		}
	}

	// Bind persistent flags to viper keys.
	if err := v.BindPFlag("data_dir", cmd.Root().PersistentFlags().Lookup("data-dir")); err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "binding data-dir flag: %w", err)
	}
	if err := v.BindPFlag("verbose", cmd.Root().PersistentFlags().Lookup("verbose")); err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "binding verbose flag: %w", err)
	}

	return nil
}
