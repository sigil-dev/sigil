#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
#
# Claude Code PreToolUse hook for Bash commands.
# Enforces Sigil development practices by rejecting commands that bypass
# the project's Taskfile-based workflow.

set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

# --- Rule: Enforce `task` for build/test/lint/fmt ---
# Direct go build/test/vet, golangci-lint, gofumpt, yamlfmt, dprint, rumdl
# should all go through Taskfile.
if echo "$COMMAND" | grep -qE '^\s*(go\s+(build|test|vet|run)\s|golangci-lint\s|gofumpt\s|yamlfmt\s|dprint\s|rumdl\s)'; then
  # Allow "go run" only for non-main packages (tooling installs etc.)
  if echo "$COMMAND" | grep -qE '^\s*go\s+run\s' && ! echo "$COMMAND" | grep -qE './cmd/sigil'; then
    : # allow go run for tooling
  else
    jq -n '{
      "decision": "block",
      "reason": "Use `task` commands instead of running Go/lint tools directly. Examples: `task build`, `task test`, `task lint`, `task fmt`. See Taskfile.yaml for all available tasks."
    }'
    exit 0
  fi
fi

# --- Rule: Prevent CGO_ENABLED=0 ---
if echo "$COMMAND" | grep -qE 'CGO_ENABLED=0'; then
  jq -n '{
    "decision": "block",
    "reason": "CGO_ENABLED=0 is not allowed. Sigil requires CGo for sqlite3 and sqlite-vec. All task build commands set CGO_ENABLED=1."
  }'
  exit 0
fi

# --- Rule: Prevent --no-verify on git commits ---
if echo "$COMMAND" | grep -qE 'git\s+(commit|push).*--no-verify'; then
  jq -n '{
    "decision": "block",
    "reason": "Do not skip git hooks (--no-verify). Lefthook pre-commit hooks enforce license headers, linting, and formatting. Fix the underlying issue instead."
  }'
  exit 0
fi

# --- Rule: Prevent direct push to main ---
if echo "$COMMAND" | grep -qE 'git\s+push\s+(origin\s+)?main(\s|$)'; then
  jq -n '{
    "decision": "block",
    "reason": "main is a protected branch. Create a feature branch and submit a PR instead. Example: git checkout -b feat/my-feature"
  }'
  exit 0
fi

# --- Rule: Prevent force push (but allow --force-with-lease) ---
# Strip --force-with-lease (and variants like --force-with-lease=ref) first,
# then check for bare --force / -f. This prevents bypass via both flags together.
STRIPPED_FORCE_CMD=$(echo "$COMMAND" | sed 's/--force-with-lease[^ ]*//')
if echo "$STRIPPED_FORCE_CMD" | grep -qE 'git\s+push\s.*(-f\b|--force\b)'; then
  jq -n '{
    "decision": "block",
    "reason": "Force push is not allowed. It can destroy remote history. If you need to update a PR branch, use `git push --force-with-lease` after confirming with the user."
  }'
  exit 0
fi

# --- Rule: Enforce uv over pip ---
if echo "$COMMAND" | grep -qE '^\s*pip[3]?\s+install|^\s*python[3]?\s+-m\s+pip'; then
  jq -n '{
    "decision": "block",
    "reason": "Use `uv` instead of pip for Python package management. Examples: `uv pip install <pkg>`, `uv sync`, `uv run <cmd>`. The docs site (site/) uses uv."
  }'
  exit 0
fi

# --- Rule: Prevent pip in any context ---
if echo "$COMMAND" | grep -qE '\bpip[3]?\s+install\b'; then
  jq -n '{
    "decision": "block",
    "reason": "Use `uv` instead of pip. Example: `uv pip install <package>` or add to pyproject.toml and run `uv sync`."
  }'
  exit 0
fi

# No rules matched — allow
exit 0
