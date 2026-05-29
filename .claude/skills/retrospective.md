---
name: retrospective
description: Record an incident or lesson learned in the knowledge base. Use after something unexpected happens during maintenance, release, or triage.
---

# Retrospective — Record a Lesson Learned

You are recording an incident or lesson learned for the kube-rbac-proxy maintenance workflow. This follows the PDCA (Plan-Do-Check-Act) cycle — specifically the "Act" phase where we improve the process.

## When to Use

Invoke this skill when:
- A release step failed unexpectedly
- CI rejected a PR for a reason the skill didn't anticipate
- A reviewer requested changes the skill should have known about
- A command produced unexpected output
- A workaround was needed that isn't documented
- The agent made a mistake that should be prevented in the future

## Steps

### 1. Gather Context

Ask the user (or analyze the current conversation) for:
- **What happened?** — The observable behavior
- **What was expected?** — What should have happened
- **What skill/phase was active?** — e.g., release-upstream/deps, triage-issues, release-downstream
- **What was the fix?** — How was it resolved

### 2. Determine Root Cause

Analyze why the issue occurred. Common categories:
- **Environment**: Tool version mismatch, missing dependency, network issue
- **Process**: Step missing from the skill, wrong order of operations
- **Assumption**: The skill assumed something that wasn't true (e.g., file format, version scheme)
- **External**: Upstream change, CI config change, API behavior change
- **Human**: The agent misinterpreted instructions or context

### 3. Determine Next KB ID

Read `.claude/state/knowledge-base.md` and find the highest `KB-NNN` entry number. The new entry will be `KB-(N+1)`.

### 4. Write the Entry

Append the new entry to the `## Incident Log` section at the bottom of `.claude/state/knowledge-base.md`:

```markdown
### KB-NNN: [Short descriptive title]
- **Date**: YYYY-MM-DD
- **Context**: [skill-name / phase]
- **What happened**: [Clear description of the incident]
- **Root cause**: [Why it happened — be specific]
- **Fix applied**: [What was done to resolve it]
- **Prevention**: [What to check/do to prevent recurrence — actionable steps]
- **Check command**: [Optional — a concrete command to verify the issue is absent before proceeding]
```

### 5. Consider Skill Updates

After recording the entry, evaluate whether the relevant skill should be updated to:
- Add a pre-flight check for this condition
- Add a verification step after the relevant action
- Modify the instructions to avoid the mistake

If a skill update is warranted, suggest the specific change to the user. Do NOT modify skills without approval.

### 6. Report

Summarize:
- Entry ID and title
- Which skill/phase it applies to
- Whether a skill update is recommended
