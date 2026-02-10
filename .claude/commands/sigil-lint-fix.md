---
description: Run linters, fix issues, and verify
allowed-tools: Bash(task *), Read, Edit, Grep, Glob
---

# Lint and Fix

Run the full lint and format cycle:

1. Run `task lint` — capture all warnings and errors
2. Run `task fmt` — auto-fix formatting issues
3. For remaining lint errors that `fmt` didn't fix:
   - Read the offending file
   - Apply the minimal fix
   - Do NOT add lint-ignore directives without explaining why
4. Run `task lint` again to verify everything passes
5. Report what was fixed

$ARGUMENTS
