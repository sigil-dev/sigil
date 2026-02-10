---
description: Check implementation alignment with Sigil design documents
allowed-tools: Read, Grep, Glob
---

# Design Review

Compare current implementation against the relevant design document.

1. Identify which design doc(s) in `docs/design/` are relevant to $ARGUMENTS (or the current work area)
2. Read the design document(s)
3. Read the corresponding implementation code
4. Report:
   - **Aligned**: implementation matches design
   - **Diverged**: implementation differs from design (explain how)
   - **Missing**: design elements not yet implemented
   - **Undocumented**: implementation details not in any design doc
5. Check `docs/decisions/decision-log.md` for any decisions that affect this area

$ARGUMENTS
