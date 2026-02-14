// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChat_StreamsTextDelta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chat/stream" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		// Verify request body.
		var req struct {
			Content     string `json:"content"`
			WorkspaceID string `json:"workspace_id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "hello world", req.Content)
		assert.Equal(t, "default", req.WorkspaceID)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = fmt.Fprint(w, "event: text_delta\ndata: {\"text\":\"Hello\"}\n\n")
		_, _ = fmt.Fprint(w, "event: text_delta\ndata: {\"text\":\" world\"}\n\n")
		_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
	}))
	defer srv.Close()

	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	defer func() { defaultHTTPClient = old }()

	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"chat", "--address", addr, "hello", "world"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "Hello world", stdout.String())
}

func TestChat_ConnectionFailure(t *testing.T) {
	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"chat", "--address", "127.0.0.1:1", "hello"})

	err := root.Execute()
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeCLIGatewayNotRunning),
		"expected CodeCLIGatewayNotRunning, got %s", sigilerr.CodeOf(err))
}

func TestChat_ErrorEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: text_delta\ndata: {\"text\":\"partial\"}\n\n")
		_, _ = fmt.Fprint(w, "event: error\ndata: {\"message\":\"provider timeout\"}\n\n")
		_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
	}))
	defer srv.Close()

	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	defer func() { defaultHTTPClient = old }()

	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"chat", "--address", addr, "hello"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "partial", stdout.String())
	assert.Contains(t, stderr.String(), "provider timeout")
}

func TestChat_NoArgs_InteractiveStub(t *testing.T) {
	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetArgs([]string{"chat"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "Interactive chat")
	assert.Contains(t, stdout.String(), "default")
}

func TestChat_CustomWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			WorkspaceID string `json:"workspace_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "myws", req.WorkspaceID)

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: text_delta\ndata: {\"text\":\"ok\"}\n\n")
		_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
	}))
	defer srv.Close()

	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	defer func() { defaultHTTPClient = old }()

	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetArgs([]string{"chat", "--address", addr, "--workspace", "myws", "hi"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "ok", stdout.String())
}

func TestChat_ModelAndSessionFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content     string `json:"content"`
			WorkspaceID string `json:"workspace_id"`
			SessionID   string `json:"session_id"`
			Model       string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "sess-123", req.SessionID)
		assert.Equal(t, "claude-4", req.Model)

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: text_delta\ndata: {\"text\":\"reply\"}\n\n")
		_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
	}))
	defer srv.Close()

	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	defer func() { defaultHTTPClient = old }()

	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetArgs([]string{"chat", "--address", addr, "--model", "claude-4", "--session", "sess-123", "test"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Equal(t, "reply", stdout.String())
}

func TestChat_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	old := defaultHTTPClient
	defaultHTTPClient = srv.Client()
	defer func() { defaultHTTPClient = old }()

	addr := srv.URL[len("http://"):]

	root := NewRootCmd()
	stdout := new(bytes.Buffer)
	root.SetOut(stdout)
	root.SetArgs([]string{"chat", "--address", addr, "hello"})

	err := root.Execute()
	require.Error(t, err)
	assert.True(t, sigilerr.HasCode(err, sigilerr.CodeCLIRequestFailure),
		"expected CodeCLIRequestFailure, got %s", sigilerr.CodeOf(err))
}
