---
name: triage-issues
description: Triage open GitHub issues — classify as CVE/bug/feature, run govulncheck for CVEs, comment on issues, update state
---

# Triage Issues for kube-rbac-proxy

You are triaging open issues on `brancz/kube-rbac-proxy`. Your job is to classify each issue, assess priority, and ensure the reporter knows we're aware.

## PDCA Cycle

Before starting, read `.claude/state/knowledge-base.md` — especially the **Triage** section (KB-011 and any incident log entries tagged with `triage-issues`). Apply any prevention steps before proceeding.

After each action (govulncheck run, issue comment, classification), verify the outcome:
- Did govulncheck run successfully? Was the output parseable?
- Did the GitHub comment post correctly?
- Was the classification reasonable given the issue content?

If anything unexpected happens, invoke `/retrospective` to record it. Do NOT modify this skill directly — flag the issue for the user.

## Steps

### 1. Load State

Read `.claude/state/maintain.json`. Note which issue numbers are already tracked in `issues`.

### 2. Fetch Open Issues

```bash
gh issue list --repo brancz/kube-rbac-proxy --state open --json number,title,body,labels,createdAt,comments --limit 50
```

**Check**: Verify the command succeeded and returned valid JSON. If the API returned an error (rate limit, auth issue), invoke `/retrospective` and stop.

### 3. Classify Each NEW Issue

Skip issues already present in state. For each new issue:

#### CVE Detection
If the issue body or title contains any of: "CVE", "vulnerability", "security", "trivy", "grype", "snyk", "scanner", "govulncheck":

1. Extract CVE IDs using pattern `CVE-\d{4}-\d{4,}` from the issue body
2. Run govulncheck to check reachability:
   ```bash
   govulncheck ./... 2>&1
   ```
   If govulncheck is not installed, install it first:
   ```bash
   go install golang.org/x/vuln/cmd/govulncheck@latest
   ```
3. **Check**: Verify govulncheck completed (exit code 0 or 3). If it crashed or timed out, record in `/retrospective` — classify conservatively as `medium` until we can re-run.
4. For each CVE mentioned:
   - If govulncheck reports it as **reachable** in our code: `priority: "ultra_high"`, `govulncheck_reachable: true`
   - If NOT reachable (scanner-only finding): `priority: "medium"`, `govulncheck_reachable: false`
5. Comment on the issue with findings:
   - **If reachable**: "Thanks for reporting this. We've confirmed via `govulncheck` that this vulnerability is reachable in our code. We're prioritizing a release to address it."
   - **If not reachable**: "Thanks for reporting this. We've checked with `govulncheck` and this CVE is not reachable in our code paths. It's a scanner-reported finding. We'll address it in our next routine dependency update."
6. **Check**: Verify the comment was posted by fetching the issue comments. If posting failed, retry once.
7. Add to state: `type: "cve"`, with priority, cve_ids, govulncheck_reachable, `status: "commented"`

#### Bug Detection
If the issue body or title contains: "bug", "error", "panic", "crash", "nil pointer", "doesn't work", "broken", "regression":

1. Analyze the bug report for reasonableness — does it describe a real scenario? Is there enough info to reproduce?
2. Add to `pending_decisions` with:
   - `type: "bug_evaluation"`
   - `summary`: brief description of the bug
   - `proposed_action`: "evaluate" with your analysis and potential fix direction
   - `decided: false`
3. Add to state issues: `type: "bug"`, `priority: "low"`, `status: "new"`
4. Comment on the issue: "Thanks for reporting this. We're looking into it."
5. **Check**: Verify comment posted.

#### Feature Request Detection
If the issue body or title contains: "feature", "request", "proposal", "add support", "would be nice", "enhancement":

1. Add to `pending_decisions` with:
   - `type: "feature_request_rejection"`
   - `summary`: brief description of what's requested
   - `proposed_action`: "reject" (kube-rbac-proxy is a thin proxy, we usually reject feature requests)
   - `decided: false`
2. Add to state issues: `type: "feature"`, `priority: "low"`, `status: "new"`
3. Do NOT comment yet — wait for the maintainer to decide

#### Unclassified
If none of the above match:
1. Add to state issues: `type: "unknown"`, `priority: "low"`, `status: "new"`
2. Comment: "Thanks for opening this issue. We'll take a look."

### 4. Save State

Write the updated state back to `.claude/state/maintain.json`.

**Check**: Re-read state to verify it was written correctly.

### 5. Report Summary

Print a summary of what was found:
- Number of new issues triaged
- Any CVEs found (with priority)
- Any bugs queued for evaluation
- Any feature requests queued for decision
- Any KB entries that were consulted or should be updated
- Any incidents recorded via `/retrospective`
