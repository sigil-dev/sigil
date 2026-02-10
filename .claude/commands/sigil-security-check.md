---
description: Audit code for Sigil security principles compliance
allowed-tools: Read, Grep, Glob
---

# Security Audit

Audit the specified file or package against Sigil's security model (`docs/design/03-security-model.md`).

Check for:

1. **Capability enforcement**: Does plugin-facing code check capabilities before executing?
2. **Input validation**: Are all plugin/external inputs validated?
3. **No trust escalation**: Can a plugin grant capabilities it doesn't have?
4. **Agent loop integrity**: Is LLM output validated before tool dispatch?
5. **No raw shell execution**: Is there any path from LLM output to shell/system calls without sanitization?
6. **Audit trail**: Are security-relevant operations logged?
7. **Sandbox boundaries**: Does the code respect execution tier isolation?

For each finding, rate severity: CRITICAL / HIGH / MEDIUM / LOW

Reference: `docs/design/03-security-model.md` for the full security model.

$ARGUMENTS
