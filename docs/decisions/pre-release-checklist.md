# Pre-Release Checklist: OpenClaw Attribution & Community

**Status:** MUST complete ALL items before any public release (alpha, beta, RC, or stable)
**Decision:** D026
**Date:** 2026-02-09

## Attribution (in repo)

- [ ] **NOTICE file** — present and accurate (Apache 2.0 standard attribution)
- [ ] **README "Inspired by" section** — prominent, near the top, links to OpenClaw repo with warm language (e.g., "If you want a battle-tested TypeScript implementation today, check out [OpenClaw](https://github.com/openclaw/openclaw)")
- [ ] **No "fork" language anywhere** — Sigil is an independent reimplementation, not a fork. Audit all docs for "fork of" and replace with "inspired by"
- [ ] **No OpenClaw branding** — no use of "OpenClaw" in project name, CLI, logos, or marketing
- [ ] **Design docs credit specific ideas** — Prior Art table in 00-overview.md accurately reflects what was inspired by OpenClaw vs. original work

## Community outreach (before public announcement)

- [ ] **Introduce project to OpenClaw maintainers** — open a GitHub Discussion (or Issue if no Discussions) on openclaw/openclaw introducing Sigil, thanking them for the inspiration, and offering to collaborate on interop (e.g., shared skill format)
- [ ] **Do NOT position as replacement** — all messaging frames Sigil as "different approach, different trade-offs" not "OpenClaw but better"
- [ ] **Credit specific ideas in announcements** — any blog post, HN post, or social announcement must acknowledge OpenClaw as inspiration (e.g., "OpenClaw pioneered the personal AI gateway concept; Sigil takes that idea in a Go-native direction")

## Ongoing

- [ ] **Upstream contributions** — if Sigil discovers bugs, patterns, or improvements applicable to OpenClaw, consider contributing back or sharing findings
- [ ] **Link maintenance** — keep OpenClaw links in NOTICE and README current if their repo moves
