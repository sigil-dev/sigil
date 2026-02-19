#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sigil Contributors
#
# Claude Code SessionEnd hook.
# 1. Creates a persistent session-summary bead with mechanical session facts
# 2. Deletes transient session-memory-snapshot beads

set -euo pipefail

SNAPSHOT_LABEL="session-memory-snapshot"
SUMMARY_LABEL="session-summary"
MARKER_DIR=".beads/.session"

# Only run if beads is initialized and bd is available
if [[ ! -d ".beads" ]] || ! command -v bd >/dev/null 2>&1; then
  exit 0
fi

# Parse hook input
hook_input=$(cat)
session_id=$(echo "$hook_input" | jq -r '.session_id // "unknown"' 2>/dev/null || echo "unknown")
short_hash=$(echo -n "$session_id" | shasum -a 256 | cut -c1-8)
session_label="sess:${short_hash}"
marker_file="${MARKER_DIR}/${short_hash}"

# Read session start marker
start_time=""
start_head=""
branch=""
if [[ -f "$marker_file" ]]; then
  # shellcheck source=/dev/null
  source "$marker_file"
fi
branch="${branch:-$(git branch --show-current 2>/dev/null || echo "unknown")}"
end_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# --- Build session summary ---
summary="## Session Summary\n"
summary+="**Session:** ${short_hash}\n"
summary+="**Branch:** ${branch}\n"
summary+="**Started:** ${start_time:-unknown}\n"
summary+="**Ended:** ${end_time}\n"

# Commits made during session
if [[ -n "$start_head" && "$start_head" != "unknown" ]]; then
  current_head=$(git rev-parse HEAD 2>/dev/null || echo "")
  if [[ "$start_head" != "$current_head" && -n "$current_head" ]]; then
    commits=$(git log --oneline "${start_head}..HEAD" 2>/dev/null || echo "")
    if [[ -n "$commits" ]]; then
      summary+="\n### Commits\n\`\`\`\n${commits}\n\`\`\`\n"
    fi
  fi
fi

# Files changed (working tree)
git_status=$(git status --short 2>/dev/null || echo "")
if [[ -n "$git_status" ]]; then
  summary+="\n### Uncommitted Changes\n\`\`\`\n${git_status}\n\`\`\`\n"
fi

# Beads activity — issues that are currently in_progress
in_progress=$(bd list --status=in_progress --json 2>/dev/null || echo "[]")
active_count=$(echo "$in_progress" | jq 'length' 2>/dev/null || echo "0")
if [[ "$active_count" -gt 0 ]]; then
  active_list=$(echo "$in_progress" | jq -r '.[] | "- \(.id): \(.title)"' 2>/dev/null || echo "")
  summary+="\n### Active Beads (in_progress)\n${active_list}\n"
fi

# Only create summary if there's something to report
has_content=false
if [[ -n "$git_status" ]] || [[ "$active_count" -gt 0 ]]; then
  has_content=true
fi
if [[ -n "$start_head" && "$start_head" != "unknown" ]]; then
  current_head=$(git rev-parse HEAD 2>/dev/null || echo "")
  if [[ "$start_head" != "$current_head" ]]; then
    has_content=true
  fi
fi

if [[ "$has_content" == "true" ]]; then
  summary_id=$(bd create \
    --title="Session ${short_hash} summary" \
    --description="$(echo -e "$summary")" \
    --type=task \
    --priority=4 \
    --json 2>/dev/null | jq -r '.id // empty' 2>/dev/null || echo "")

  if [[ -n "$summary_id" ]]; then
    bd label add "$summary_id" "$SUMMARY_LABEL" 2>/dev/null || true
    bd label add "$summary_id" "$session_label" 2>/dev/null || true
    bd close "$summary_id" --reason "Session ended" 2>/dev/null || true
  fi
fi

# --- Delete snapshot beads from this session ---
snapshot_ids=$(bd list --json 2>/dev/null \
  | jq -r --arg label "$session_label" '
    [.[] | select(.labels? and (.labels | index($label)))] | .[].id
  ' 2>/dev/null || echo "")

if [[ -n "$snapshot_ids" ]]; then
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    bd delete "$id" 2>/dev/null || true
  done <<< "$snapshot_ids"
fi

# Sweep orphaned snapshots from crashed sessions
orphan_ids=$(bd list --json 2>/dev/null \
  | jq -r --arg label "$SNAPSHOT_LABEL" '
    [.[] | select(.labels? and (.labels | index($label)))] | .[].id
  ' 2>/dev/null || echo "")

if [[ -n "$orphan_ids" ]]; then
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    bd delete "$id" 2>/dev/null || true
  done <<< "$orphan_ids"
fi

# Clean up marker file
rm -f "$marker_file"

exit 0
