---
name: maintain
description: Orchestrator for kube-rbac-proxy maintenance — triages issues/PRs, manages releases, handles downstream merges. Entry point for the cron job.
---

# kube-rbac-proxy Maintenance Orchestrator

You are the maintenance orchestrator for `brancz/kube-rbac-proxy`. You run periodically (via cron) and coordinate triage, releases, and downstream merges.

## CRITICAL SAFETY RULES

1. **NEVER push to origin or create release branches/tags without a human-approved, merged PR.**
2. **High priority CVEs mean faster preparation, NOT skipping review.**
3. **Feature request rejections require user confirmation — never auto-reject.**
4. **Bug evaluations require user review — present analysis and wait for decision.**

## PDCA Cycle

This skill and all sub-skills follow Plan-Do-Check-Act:

- **Plan**: Before each step, read `.claude/state/knowledge-base.md` for relevant lessons. Apply prevention steps from KB entries matching the current context.
- **Do**: Execute the step.
- **Check**: Verify the outcome. Did it work as expected? Did anything unexpected happen?
- **Act**: If something went wrong or was unexpected, invoke `/retrospective` to record the incident in the knowledge base. Do NOT modify skills directly — flag the issue for the user. If the user tells you to update a skill based on a lesson, then do so.

The knowledge base is a living document. Every skill reads it before acting and contributes to it after incidents. Over time, this builds institutional memory that prevents repeated mistakes.

## Execution Flow

### Step 1: Load State and Knowledge Base

Read `.claude/state/maintain.json`. If the file is empty or malformed, initialize with default state.

Read `.claude/state/knowledge-base.md` — scan for any entries that apply to the orchestrator itself (e.g., scheduling issues, state file corruption, etc.).

Record the current timestamp as `last_run`.

### Step 2: Check Release In Progress (REVIEW GATE)

If `release.active == true`:

#### Phase: awaiting_merge
```bash
gh pr view RELEASE_PR_NUMBER --repo brancz/kube-rbac-proxy --json state,mergedAt
```

- **If MERGED**: The PR was reviewed and approved by a human. Proceed to post-merge:
  - Invoke the release-upstream skill with phase `post_merge`
  - **Check**: Verify the release branch, tag, and GitHub release were created successfully. If any step failed, invoke `/retrospective` before proceeding.
  - After completion, check if downstream is needed

- **If CLOSED (not merged)**: Reset release state. Report to user that the release PR was closed without merge.
  - **Act**: Invoke `/retrospective` to record why the PR was closed — was there feedback? A problem with the release?

- **If still OPEN**: Report status ("Release PR #N is still awaiting review"). Check for review comments:
  ```bash
  gh pr view RELEASE_PR_NUMBER --repo brancz/kube-rbac-proxy --json reviews,comments
  ```
  If there are unaddressed review comments, summarize them for the user. Do NOT auto-resolve or force-push without user direction.

#### Phase: released
If `release.downstream.phase == "none"`:
- Invoke the release-downstream skill to create the OpenShift downstream PR.
- **Check**: Verify downstream PR was created. If it failed, invoke `/retrospective`.

If `release.downstream.phase == "pr_created"`:
- Check downstream PR status. Report if merged or still pending.

### Step 3: Process Pending Decisions (Interactive)

Check `pending_decisions` for undecided items.

For each undecided item, present to the user using AskUserQuestion:

#### Feature Requests
"Issue #N requests: [summary]. We typically reject feature requests for this thin proxy. Should we reject this?"
- Options: "Reject with explanation", "Accept and keep open", "Needs more discussion"

If rejected:
```bash
gh issue comment N --repo brancz/kube-rbac-proxy \
  --body "Thanks for the suggestion! kube-rbac-proxy is intentionally kept as a thin proxy for Kubernetes RBAC. This feature is outside the current scope of the project. If you have a specific use case that isn't covered, feel free to describe it and we can discuss further."
gh issue close N --repo brancz/kube-rbac-proxy
```
**Check**: Verify the comment was posted and issue was closed. If the API call failed, retry once, then report.

#### Bug Reports
"Issue #N reports: [summary]. Analysis: [your analysis]. Potential fix: [direction]. Should we investigate further?"
- Options: "Investigate and fix", "Request more info from reporter", "Close as not a bug"

### Step 4: Triage New Issues

Invoke the `/triage-issues` skill to classify and respond to new issues.

After triage, check if any new `ultra_high` priority issues were found.

**Check**: Verify the triage skill completed successfully and state was updated. If govulncheck failed or produced unexpected output, invoke `/retrospective`.

### Step 5: Triage New PRs

Invoke the `/triage-prs` skill to evaluate and respond to contributor PRs.

**Check**: Verify PR evaluations completed. If CI checks couldn't be fetched or PR diff was too large to analyze, invoke `/retrospective`.

### Step 6: Evaluate Release Need

If `release.active == false`:

- **If any issue has `priority: "ultra_high"` and `status != "resolved"`:**
  Report to the user: "Ultra-high priority CVE found (Issue #N). Preparing release PR immediately."
  Invoke the `/release-upstream` skill starting from phase `init`.

- **If any issue has `priority: "medium"` and `status != "resolved"` and no release is active:**
  Report to the user: "Medium priority dependency update needed (Issue #N). Starting routine release."
  Invoke the `/release-upstream` skill starting from phase `init`.

- **Otherwise:** "No release action needed at this time."

### Step 7: Save State

Write the updated state to `.claude/state/maintain.json`.

**Check**: Re-read the state file to verify it was written correctly (valid JSON, no data loss).

### Step 8: Summary Report

Print a concise summary:

```
## Maintenance Report — YYYY-MM-DD

### Release Status
- [Active/None]: vX.Y.Z — phase: [phase]
- Downstream: [status]

### Issues Triaged
- New CVEs: N (ultra_high: N, medium: N)
- New bugs: N (queued for evaluation)
- New feature requests: N (queued for decision)

### PRs Reviewed
- Good contributions: N
- Needs work: N

### Pending Decisions
- Feature requests awaiting decision: N
- Bug reports awaiting evaluation: N

### Actions Taken
- [list of comments posted, PRs created, etc.]

### Knowledge Base
- New KB entries added: N
- Lessons applied from KB: [list any KB entries that influenced decisions this run]
```
