#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
#
# Claude Code SessionStart hook.
# Runs bd prime to restore context from beads issue tracking.
# Writes a timestamp marker for session-end summary scoping.

set -euo pipefail

MARKER_DIR=".beads/.session"

# Only run if beads is initialized and we're in a git repo
if [[ ! -d ".beads" ]] || ! git rev-parse --git-dir > /dev/null 2>&1; then
  exit 0
fi

if ! command -v bd >/dev/null 2>&1; then
  exit 0
fi

# Parse hook input for session_id
hook_input=$(cat)
session_id=$(echo "$hook_input" | jq -r '.session_id // "unknown"' 2>/dev/null || echo "unknown")
short_hash=$(echo -n "$session_id" | shasum -a 256 | cut -c1-8)

# Write session start marker (timestamp + HEAD ref)
mkdir -p "$MARKER_DIR"
cat > "${MARKER_DIR}/${short_hash}" <<EOF
start_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
start_head=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
branch=$(git branch --show-current 2>/dev/null || echo "unknown")
EOF

# Restore context (surfaces in-progress beads and snapshot beads)
bd prime 2>&1 || true

exit 0
