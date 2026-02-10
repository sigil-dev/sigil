#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
#
# Claude Code SessionStart hook.
# Runs bd prime to restore context from beads issue tracking.

set -euo pipefail

# Only run if beads is initialized and we're in a git repo
if [[ -d ".beads" ]] && git rev-parse --git-dir > /dev/null 2>&1; then
  echo "📿 Restoring session context with beads..." >&2
  if command -v bd >/dev/null 2>&1; then
    bd prime 2>&1 || true
  fi
fi

exit 0
