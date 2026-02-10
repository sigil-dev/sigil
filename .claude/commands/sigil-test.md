---
description: Run Sigil tests and analyze any failures
allowed-tools: Bash(task *), Read, Grep, Glob
---

# Run Tests

Run the Sigil test suite and analyze results.

1. Run `task test`
2. If any tests fail:
   - Read the failing test file to understand what's being tested
   - Read the implementation file to identify the bug
   - Explain the failure and suggest a fix
3. If all tests pass, report the summary

$ARGUMENTS
