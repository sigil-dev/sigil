#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
#
# Claude Code PreToolUse hook for Edit/Write tools.
# Prevents modification of generated files.

set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

# --- Rule: Protect generated protobuf files ---
if echo "$FILE_PATH" | grep -qE '\.pb\.go$'; then
  jq -n '{
    "decision": "block",
    "reason": "This is a generated protobuf file (*.pb.go). Edit the .proto source in api/proto/ and run `task proto` to regenerate."
  }'
  exit 0
fi

# --- Rule: Protect internal/gen directory ---
if echo "$FILE_PATH" | grep -qE '/internal/gen/'; then
  jq -n '{
    "decision": "block",
    "reason": "Files in internal/gen/ are auto-generated. Edit the source definitions and run the appropriate generate command (e.g., `task proto`)."
  }'
  exit 0
fi

# --- Rule: Protect go.sum ---
if echo "$FILE_PATH" | grep -qE '/go\.sum$'; then
  jq -n '{
    "decision": "block",
    "reason": "Do not edit go.sum directly. Run `task deps` (go mod tidy) to update it."
  }'
  exit 0
fi

# No rules matched — allow
exit 0
