// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run diagnostics",
		Long:  "Check binary health, provider API keys, channel connections, disk space, and other system requirements.",
		RunE:  runDoctor,
	}

	cmd.Flags().String("address", "127.0.0.1:18789", "gateway address to check")

	return cmd
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	w := cmd.OutOrStdout()
	addr, _ := cmd.Flags().GetString("address")
	dataDir := resolveDataDir()

	checks := []struct {
		name string
		fn   func() string
	}{
		{"Binary", checkBinary},
		{"Platform", checkPlatform},
		{"Gateway", func() string { return checkGateway(addr) }},
		{"Config", checkConfig},
		{"Plugins", func() string { return checkPlugins(dataDir) }},
		{"Disk Space", func() string { return checkDiskSpace(dataDir) }},
	}

	for _, c := range checks {
		if _, err := fmt.Fprintf(w, "%-20s %s\n", c.name+":", c.fn()); err != nil {
			return err
		}
	}

	return nil
}

// resolveDataDir returns the data directory from viper or the default.
func resolveDataDir() string {
	dataDir := viper.GetString("data_dir")
	if dataDir != "" {
		return dataDir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sigil")
}

func checkBinary() string {
	return fmt.Sprintf("sigil %s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

func checkPlatform() string {
	return fmt.Sprintf("%s/%s, Go %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func checkGateway(addr string) string {
	gw := newGatewayClient(addr)
	var body struct {
		Status string `json:"status"`
	}
	if err := gw.getJSON("/api/v1/status", &body); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeCLIGatewayNotRunning) {
			return fmt.Sprintf("not running at %s (run 'sigil start')", addr)
		}
		return fmt.Sprintf("error: %s", err)
	}
	return fmt.Sprintf("%s at %s", body.Status, addr)
}

func checkConfig() string {
	cfgFile := viper.ConfigFileUsed()
	if cfgFile != "" {
		return fmt.Sprintf("loaded from %s", cfgFile)
	}
	return "using defaults (no config file found)"
}

func checkPlugins(dataDir string) string {
	pluginsDir := filepath.Join(dataDir, "plugins")
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Sprintf("no plugins directory at %s", pluginsDir)
		}
		return fmt.Sprintf("error reading plugins: %s", err)
	}

	count := 0
	for _, e := range entries {
		if !e.IsDir() && e.Name()[0] != '.' {
			count++
		}
	}

	if count == 0 {
		return "no plugins installed"
	}
	return fmt.Sprintf("%d plugin(s) found in %s", count, pluginsDir)
}

func checkDiskSpace(dataDir string) string {
	path := dataDir
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Fall back to home directory if data dir doesn't exist yet.
		path, _ = os.UserHomeDir()
	}

	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return fmt.Sprintf("unable to check: %s", err)
	}

	availBytes := stat.Bavail * uint64(stat.Bsize)
	return formatBytes(availBytes) + " available"
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(b uint64) string {
	const (
		gb = 1024 * 1024 * 1024
		mb = 1024 * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}
