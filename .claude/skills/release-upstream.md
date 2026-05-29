---
name: release-upstream
description: Execute the upstream kube-rbac-proxy release process with phase-based resumption. Follows agent-how-to-release.md exactly.
---

# Upstream Release for kube-rbac-proxy

You are performing a release of `brancz/kube-rbac-proxy`. This skill follows the process documented in `/workspace/agent-how-to-release.md` exactly.

## CRITICAL SAFETY RULES

1. **NEVER push to `origin` without a human-approved, merged PR.** The `ibihim` account has push rights to the upstream repo. Any push to origin triggers the publish job.
2. **Push release PR branches to the `ibihim` fork ONLY.**
3. **The `awaiting_merge` → `post_merge` transition requires a MERGED PR** (human reviewed and approved). Never auto-merge.
4. **High priority does NOT mean skip review.** It means prepare faster.

## PDCA Cycle

Every phase follows Plan-Do-Check-Act:

- **Plan**: Before each phase, read `.claude/state/knowledge-base.md` and review entries matching the current phase context (e.g., "release-upstream / deps phase"). Apply prevention steps and run check commands from relevant KB entries BEFORE proceeding.
- **Do**: Execute the phase steps.
- **Check**: After each phase, verify the results. Run the check commands. Compare actual vs expected outcomes.
- **Act**: If something unexpected happens:
  1. Attempt to fix it
  2. Invoke `/retrospective` to record the incident in the knowledge base
  3. Only proceed to the next phase if the fix was successful
  4. Do NOT modify this skill directly — flag for the user

## Steps

### 0. Load State and Determine Phase

Read `.claude/state/maintain.json`. Check `release.phase` to determine where to resume.

Read `.claude/state/knowledge-base.md` for lessons relevant to the current phase. Pay special attention to:
- **init**: KB-002 (untracked Go files)
- **deps**: KB-001 (k8s minor bump), KB-002 (go mod tidy failures)
- **version**: KB-003 (worktree .md files), KB-004 (version string exclusions)
- **commit_and_pr**: KB-005 (pushing to origin), KB-006 (double v prefix)
- **post_merge**: KB-007 (git pull conflicts), KB-008 (release branch naming), KB-006 (double v)

If invoked with a specific phase argument, use that. Otherwise, start from the current phase in state.

### Phase: init

**Plan**: Check KB for init-phase entries. Run KB-002 prevention step.

1. **Check working directory is clean:**
   ```bash
   git status --short | grep "^??"
   ```
   **KB-002 check**: Look specifically for untracked `.go` files:
   ```bash
   git status --short | grep "^??" | grep "\.go$"
   ```
   If untracked Go files exist (with missing imports), remove them or warn. WIP Go files with bad imports will break `go mod tidy`.

2. **Determine current version:**
   ```bash
   cat VERSION
   ```

3. **Determine release type:**
   - If the trigger is a CVE fix or dependency bump only → **patch release** (increment patch version)
   - If k8s.io dependencies need a minor version bump → **minor release** (increment minor version)
   - Read the trigger issue from state to understand context

4. **Calculate new version:**
   - Current: read from VERSION (e.g., `v0.21.0`)
   - Patch: `v0.21.0` → `v0.21.1`
   - Minor: `v0.21.0` → `v0.22.0`

5. **Update state:**
   ```json
   {
     "release": {
       "active": true,
       "version": "vX.Y.Z",
       "type": "patch|minor",
       "phase": "init"
     }
   }
   ```

6. **Check**: Verify state was written. Verify VERSION file is readable. Proceed to `deps` phase.

### Phase: deps

**Plan**: Check KB-001 (k8s minor bump on patch releases). Record current k8s version BEFORE updating.

1. **Record pre-update k8s version** (for KB-001 check later):
   ```bash
   grep "k8s.io/api " go.mod
   ```

2. **Update dependencies:**
   ```bash
   make update-go-deps
   ```

3. **KB-001 Check — For PATCH releases, constrain k8s to current minor:**
   ```bash
   grep "k8s.io/api " go.mod
   ```
   Compare with pre-update version. If `make update-go-deps` bumped k8s to a new minor (e.g., v0.34.x → v0.35.x), downgrade:
   ```bash
   # Find latest patch of current minor
   go list -m -versions k8s.io/api | tr ' ' '\n' | grep "v0.CURRENT_MINOR" | tail -1
   ```
   Then sed all k8s.io packages back to the current minor's latest patch and run `go mod tidy`.

4. **If CVE requires Go version bump:**
   ```bash
   # Check latest stable Go
   curl -s https://go.dev/dl/?mode=json | jq -r '.[0].version'
   ```
   Update both:
   - `.github/workflows/build.yml`: `go-version: X.Y.Z`
   - `go.mod`: `go X.Y.Z` (may revert on `go mod tidy` — that's OK)

5. **Verify build and tests:**
   ```bash
   make build
   make test-unit
   ```
   **Check**: Both must pass. If either fails:
   - Check if it's related to a known KB issue
   - Attempt to fix
   - If fix works, invoke `/retrospective` to record what happened and how it was fixed
   - If fix fails, stop and report. Do NOT proceed with a broken build.

6. **Update state:** `phase: "deps_updated"`

### Phase: version

**Plan**: Check KB-003 (worktree .md files) and KB-004 (version string exclusions).

1. **Update VERSION file:**
   ```bash
   echo "vX.Y.Z" > VERSION
   ```

2. **KB-004 Check — Update version references with proper exclusions:**
   ```bash
   OLD_VERSION=$(git log --oneline -1 VERSION | awk '{print $NF}')  # or read from state
   NEW_VERSION="vX.Y.Z"
   rg "$OLD_VERSION" --files-with-matches \
       | rg -v go.sum \
       | rg -v RELEASE.md \
       | rg -v CHANGELOG.md \
       | rg -v ".claude/" \
       | rg -v agent-how-to-release.md \
       | xargs -I {} sed -i "s|$OLD_VERSION|$NEW_VERSION|g" {}
   ```

3. **Update CHANGELOG.md** — add new section at top (after `# Changelog`):
   ```markdown
   ## X.Y.Z / YYYY-MM-DD

   - [ENHANCEMENT] Bump dependencies
   ```
   Include any specific CVE fix notes if applicable.

4. **Update RELEASE.md** — add new row to table (at top of table body):
   ```markdown
   | vX.Y.Z         | YYYY-MM-DD                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
   ```

5. **KB-003 Check — Regenerate docs with worktree protection:**
   ```bash
   # Move worktrees aside if they exist (they contain .md files that break embedmd)
   if [ -d .claude/worktrees ]; then
     mv .claude/worktrees /tmp/claude-worktrees-backup
   fi

   make generate

   if [ -d /tmp/claude-worktrees-backup ]; then
     mv /tmp/claude-worktrees-backup .claude/worktrees
   fi
   ```
   **Check**: If `make generate` failed even after moving worktrees, invoke `/retrospective` — there may be a new source of stale .md files.

6. **Verify only expected files changed:**
   ```bash
   git diff --stat
   ```
   **Check**: Should show VERSION, CHANGELOG.md, RELEASE.md, `examples/*/deployment.yaml`, `examples/*/README.md`. Plus `go.mod`, `go.sum` if deps were updated. Plus `.github/workflows/build.yml` if Go version was bumped. If unexpected files appear, investigate before proceeding. Invoke `/retrospective` if something new shows up.

7. **Update state:** `phase: "version_bumped"`

### Phase: commit_and_pr

**Plan**: Check KB-005 (pushing to origin) — triple-check we push to ibihim, not origin.

1. **Create two separate commits:**

   Commit 1 — Dependencies only:
   ```bash
   git add go.mod go.sum
   git commit -s -S -m 'go*: update dependencies'
   ```

   Commit 2 — Release changes:
   ```bash
   git add VERSION CHANGELOG.md RELEASE.md examples/ .github/workflows/build.yml
   git commit -s -S -m '*: cut vX.Y.Z release'
   ```

   **Check**: `git log --oneline -2` — verify two separate commits exist with correct messages.

2. **KB-005 Check — Create branch and push to ibihim fork (NOT origin!):**
   ```bash
   git checkout -b rc-X.Y.Z
   ```
   **SAFETY CHECK before push**: Verify the remote is ibihim, not origin:
   ```bash
   git remote get-url ibihim
   ```
   Then push:
   ```bash
   git push -u ibihim rc-X.Y.Z
   ```

3. **Create cross-fork PR:**
   ```bash
   gh pr create --repo brancz/kube-rbac-proxy \
     --head ibihim:rc-X.Y.Z \
     --base master \
     --reviewer stlaz \
     --title "*: cut vX.Y.Z release" \
     --body "## Summary
   - Bump dependencies
   - Update version references

   ## Checklist
   - [x] VERSION updated
   - [x] CHANGELOG.md updated
   - [x] RELEASE.md updated
   - [x] Example files updated
   - [ ] Tests pass

   Closes #TRIGGER_ISSUE_NUMBER"
   ```
   **Check**: Parse the PR URL from output. Verify PR was created successfully.

4. **Record PR details in state:**
   ```json
   {
     "release": {
       "phase": "awaiting_merge",
       "pr_number": <number>,
       "pr_url": "<url>",
       "branch": "rc-X.Y.Z"
     }
   }
   ```

5. **STOP HERE.** The next cron tick will check if the PR has been merged.

### Phase: post_merge

**GATE CHECK — This phase ONLY runs if the PR was merged by a human reviewer.**

**Plan**: Check KB-006 (double v prefix), KB-007 (git pull conflicts), KB-008 (release branch naming).

1. **Verify PR is actually merged:**
   ```bash
   gh pr view <PR_NUMBER> --repo brancz/kube-rbac-proxy --json state
   ```
   If state is NOT `MERGED`, do nothing. Exit immediately.

2. **KB-007 — Update local master (fetch+reset, NOT pull):**
   ```bash
   git checkout master
   git fetch origin
   git reset --hard origin/master
   ```
   **Check**: `git log --oneline -1` should match the latest commit on origin/master.

3. **KB-008 — Create release branch (full version!):**
   ```bash
   git checkout -b release-X.Y.Z
   git push origin release-X.Y.Z
   ```
   **Check**: `git branch -r | grep "release-X.Y.Z"` — verify branch exists on origin.

4. **KB-006 — Create and push tag (no double v!):**
   ```bash
   tag="$(< VERSION)"
   echo "Tag will be: ${tag}"  # Verify — should be vX.Y.Z, not vvX.Y.Z
   ```
   **Check**: Verify tag starts with exactly one "v". Then proceed:
   ```bash
   git tag -s "${tag}" -m "${tag}"
   git push origin "${tag}"
   ```
   **Check**: `git tag -l "${tag}"` — verify tag exists.

5. **Create GitHub release:**
   ```bash
   tag="$(< VERSION)"
   gh release create "${tag}" \
     --repo brancz/kube-rbac-proxy \
     --title "${tag}" \
     --notes "## Changelog

   - [ENHANCEMENT] Bump dependencies

   See [CHANGELOG.md](https://github.com/brancz/kube-rbac-proxy/blob/${tag}/CHANGELOG.md) for details."
   ```
   **Check**: Verify release was created: `gh release view "${tag}" --repo brancz/kube-rbac-proxy --json tagName`.

6. **Comment on trigger issue (if any):**
   ```bash
   gh issue comment <TRIGGER_ISSUE> --repo brancz/kube-rbac-proxy \
     --body "This has been addressed in release ${tag}. The updated version is available on [quay.io](https://quay.io/repository/brancz/kube-rbac-proxy)."
   ```

7. **Update state:**
   ```json
   {
     "release": {
       "phase": "released"
     }
   }
   ```

8. **Report completion** — note that downstream merge should be triggered next. List any KB entries that were consulted and any incidents recorded via `/retrospective`.
