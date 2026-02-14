// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctor_RunsAllChecks(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor"})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	// Must contain the check names from all implemented checks.
	assert.Contains(t, output, "Binary:")
	assert.Contains(t, output, "Platform:")
	assert.Contains(t, output, "Gateway:")
	assert.Contains(t, output, "Config:")
	assert.Contains(t, output, "Disk Space:")
}

func TestDoctor_GatewayRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	defer func() { defaultHTTPClient = old }()

	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor", "--address", addr})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Gateway:")
	assert.Contains(t, output, "ok")
}

func TestDoctor_GatewayNotRunning(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor", "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Gateway:")
	assert.Contains(t, output, "not running")
}

func TestDoctor_PluginsDir(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, "plugins")
	require.NoError(t, os.MkdirAll(pluginsDir, 0o755))

	// Create a fake plugin file.
	require.NoError(t, os.WriteFile(filepath.Join(pluginsDir, "test-plugin"), []byte("x"), 0o755))

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor", "--data-dir", dir, "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Plugins:")
	assert.Contains(t, output, "1 plugin")
}

func TestDoctor_PluginsDirMissing(t *testing.T) {
	dir := t.TempDir()

	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor", "--data-dir", dir, "--address", "127.0.0.1:1"})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Plugins:")
	assert.Contains(t, output, "no plugins directory")
}

func TestDoctor_DiskSpace(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor"})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Disk Space:")
	// Should show available space in some unit (GB, MB, etc.).
	assert.Regexp(t, `\d+(\.\d+)?\s*(GB|MB|TB)`, output)
}

func TestDoctor_ConfigCheck(t *testing.T) {
	root := NewRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"doctor"})

	err := root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Config:")
}
