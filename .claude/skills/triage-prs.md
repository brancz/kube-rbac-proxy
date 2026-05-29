---
name: triage-prs
description: Evaluate open contributor PRs — check quality, comment with feedback or encouragement, update state
---

# Triage PRs for kube-rbac-proxy

You are evaluating open contributor PRs on `brancz/kube-rbac-proxy`. Your job is to assess quality, provide helpful feedback, and motivate good contributors.

## PDCA Cycle

Before starting, read `.claude/state/knowledge-base.md` — check for any entries tagged with `triage-prs` context. If previous PR evaluations had issues (e.g., CI checks unreachable, diff too large), the KB will have prevention steps.

After each action (diff read, CI check, comment post), verify the outcome. If anything unexpected happens, invoke `/retrospective` to record it. Do NOT modify this skill directly — flag for the user.

## Steps

### 1. Load State

Read `.claude/state/maintain.json`. Note which PR numbers are already tracked in `prs` and check if there are any `ultra_high` priority issues (for urgency context).

### 2. Fetch Open PRs

```bash
gh pr list --repo brancz/kube-rbac-proxy --state open --json number,title,body,author,files,reviews,createdAt,headRefName --limit 50
```

**Check**: Verify the command returned valid JSON. If API failed, invoke `/retrospective` and stop.

### 3. Filter PRs

Skip:
- PRs already tracked in state
- PRs authored by maintainers (brancz, ibihim)
- Release PRs (branch names starting with `rc-`)
- Bot PRs (dependabot, renovate)

### 4. Evaluate Each New Contributor PR

For each contributor PR:

#### Quality Check
1. **Files changed**: Read the PR diff to understand what's being changed
   ```bash
   gh pr diff <number> --repo brancz/kube-rbac-proxy
   ```
   **Check**: If diff is empty or the command failed, note this. Large diffs (>1000 lines) may need special handling — note but don't skip.

2. **CI status**: Check if CI is passing
   ```bash
   gh pr checks <number> --repo brancz/kube-rbac-proxy
   ```
   **Check**: If CI checks are pending or unavailable, note this in the evaluation rather than assuming pass/fail.

3. **Assess quality** against these criteria:
   - Does the PR include tests (files matching `*_test.go`)?
   - Is CI passing?
   - If it bumps dependencies in `go.mod`, did it also bump Go version in `.github/workflows/build.yml` if needed?
   - Does the commit message follow conventions?
   - Is the scope reasonable (not too large, focused)?

#### Response Based on Quality

**Good PR** (CI passes, tests included, follows conventions):
- Comment with genuine encouragement: "Great contribution! The approach looks solid. Thanks for taking the time to submit this."
- Set `quality: "good"`, `status: "reviewed"`
- **Check**: Verify comment posted.

**Needs work + no urgent CVE** (medium priority or no CVEs):
- Comment with specific, actionable feedback about what's missing. Be kind and constructive.
- Examples: "This looks like a good start! A few things that would help get this merged: [specific items]"
- Common missing items:
  - Go version bump in `.github/workflows/build.yml`
  - Missing test coverage
  - CHANGELOG.md entry
  - License headers on new files
- Set `quality: "needs_work"`, `status: "commented"`
- **Check**: Verify comment posted and is constructive (re-read it before posting).

**Needs work + ultra_high priority CVE active**:
- Comment thanking them for the contribution
- Explain: "Thank you for this contribution! Due to an urgent security fix we need to address, we're preparing our own release PR. Your work is still valued and we'd love to revisit it after the release. We'll keep this PR open."
- Set `quality: "needs_work"`, `status: "commented"`
- NOTE: We still prepare our own release PR through the normal process with review gate. We do NOT skip review.
- **Check**: Verify comment posted. Ensure tone is appreciative, not dismissive.

### 5. Save State

Write the updated state back to `.claude/state/maintain.json`.

**Check**: Re-read state to verify correctness.

### 6. Report Summary

Print a summary:
- Number of new PRs evaluated
- Good PRs (with PR numbers)
- PRs needing work (with PR numbers and what's missing)
- Any KB entries consulted
- Any incidents recorded via `/retrospective`
