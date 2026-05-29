# kube-rbac-proxy — Claude Code Project Guide

## Maintenance Workflow

This project has an agentic maintenance workflow. On session start, set up the cron:

```
CronCreate with cron "23 8 * * 1-5" and prompt "Run /maintain to check kube-rbac-proxy for new issues, PRs, CVEs, and release status."
```

Note: CronCreate jobs auto-expire after 3 days. Re-establish at each new session.

### Available Skills

- `/maintain` — Orchestrator: triage + release + downstream (cron entry point)
- `/triage-issues` — Classify open issues (CVE/bug/feature), run govulncheck
- `/triage-prs` — Evaluate contributor PRs, comment with feedback
- `/release-upstream` — Full release process (phases: init → deps → version → commit_and_pr → awaiting_merge → post_merge)
- `/release-downstream` — OpenShift downstream merge after upstream release
- `/retrospective` — Record an incident or lesson learned in the knowledge base (PDCA Act phase)

### State & Knowledge Base

- Persistent state: `.claude/state/maintain.json`
- Knowledge base: `.claude/state/knowledge-base.md` — living document of lessons learned
- Release process reference: `agent-how-to-release.md`

### PDCA Cycle (Plan-Do-Check-Act)

All skills follow the PDCA continuous improvement cycle:
1. **Plan**: Read knowledge-base.md for relevant lessons before acting
2. **Do**: Execute the step
3. **Check**: Verify the outcome matches expectations
4. **Act**: If something unexpected happens, invoke `/retrospective` to record it

The knowledge base grows over time as incidents are recorded. Skills consult it before each phase to avoid repeating mistakes. Skills do NOT self-modify — they flag issues for the user. Only update skills when the user explicitly requests it.

## Project Conventions

### Release Safety (CRITICAL)
- **NEVER push to origin or create release branches/tags without a human-approved, merged PR**
- High priority CVEs mean faster preparation, NOT skipping review
- `ibihim` has push rights to the upstream `brancz/kube-rbac-proxy` — exercise extreme caution

### Release Process
- Push release PR branches to `ibihim` fork, NEVER directly to `origin`
- Release branches use full version: `release-X.Y.Z` (not `release-X.Y`)
- Tags come from VERSION file directly (already has "v" prefix — never prepend another "v")
- Two separate commits: first deps (`go.mod` + `go.sum`), then release changes
- GPG signing: use `git commit -s -S` and `git tag -s`

### OSS Sensitivity
- Do NOT commit `.claude/` directory or any AI tooling artifacts to this repo
- `.claude/` is in the global gitignore to prevent accidental commits
- Co-contributor and community are not receptive to AI tooling
