#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
#
# Claude Code PreCompact hook.
# Creates/updates a "session state" bead before context compaction,
# serving as a message-in-a-bottle for the post-compaction Claude.
# Labeled with session-memory-snapshot + session short hash for grouping.
# Cleaned up by session-end.sh on session close.

set -euo pipefail

LABEL="session-memory-snapshot"

# Only run if beads is initialized and bd is available
if [[ ! -d ".beads" ]] || ! command -v bd >/dev/null 2>&1; then
  exit 0
fi

# Parse hook input from stdin
hook_input=$(cat)
trigger=$(echo "$hook_input" | jq -r '.trigger // "auto"' 2>/dev/null || echo "auto")
session_id=$(echo "$hook_input" | jq -r '.session_id // "unknown"' 2>/dev/null || echo "unknown")
short_hash=$(echo -n "$session_id" | shasum -a 256 | cut -c1-8)
session_label="sess:${short_hash}"

# Capture current git state
branch=$(git branch --show-current 2>/dev/null || echo "unknown")
git_status=$(git status --short 2>/dev/null || echo "")
git_diff_stat=$(git diff --stat 2>/dev/null || echo "")
staged_diff_stat=$(git diff --cached --stat 2>/dev/null || echo "")

# Build state snapshot
state="## Session State (${trigger} compaction)\n"
state+="**Session:** ${short_hash}\n"
state+="**Branch:** ${branch}\n"
state+="**Timestamp:** $(date -u '+%Y-%m-%dT%H:%M:%SZ')\n"

if [[ -n "$git_status" ]]; then
  state+="\n### Working Tree\n\`\`\`\n${git_status}\n\`\`\`\n"
fi

if [[ -n "$staged_diff_stat" ]]; then
  state+="\n### Staged Changes\n\`\`\`\n${staged_diff_stat}\n\`\`\`\n"
fi

if [[ -n "$git_diff_stat" ]]; then
  state+="\n### Unstaged Changes\n\`\`\`\n${git_diff_stat}\n\`\`\`\n"
fi

# Check for in-progress beads
in_progress=$(bd list --status=in_progress --json 2>/dev/null || echo "[]")
active_count=$(echo "$in_progress" | jq 'length' 2>/dev/null || echo "0")

if [[ "$active_count" -gt 0 ]]; then
  # Update each active bead with current state
  active_ids=()
  while IFS= read -r id; do
    active_ids+=("$id")
    bd update "$id" --notes "$(printf '%b' "$state")" 2>/dev/null || true
  done < <(echo "$in_progress" | jq -r '.[].id' 2>/dev/null)

  echo "Pre-compaction state saved to active bead(s): ${active_ids[*]}"
  echo "After compaction, run: bd show ${active_ids[0]}"
  echo "Active work was on branch: ${branch}"
else
  # No active beads — create a session snapshot bead
  snapshot_id=$(bd create \
    --title="Session ${short_hash} state snapshot" \
    --description="$(printf '%b' "$state")" \
    --type=task \
    --priority=3 \
    --json 2>/dev/null | jq -r '.id // empty' 2>/dev/null || echo "")

  if [[ -n "$snapshot_id" ]]; then
    bd label add "$snapshot_id" "$LABEL" 2>/dev/null || true
    bd label add "$snapshot_id" "$session_label" 2>/dev/null || true
    echo "Session snapshot bead created: ${snapshot_id} [${LABEL}, ${session_label}]"
    echo "After compaction, run: bd show ${snapshot_id}"
    echo "Work was on branch: ${branch}"
  fi
fi

exit 0
