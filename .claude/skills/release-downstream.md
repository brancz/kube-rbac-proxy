---
name: release-downstream
description: Merge upstream kube-rbac-proxy release into openshift/kube-rbac-proxy downstream. Handles vendoring, Go version adjustment, and PR creation.
---

# Downstream Release (OpenShift) for kube-rbac-proxy

You are merging an upstream kube-rbac-proxy release into `openshift/kube-rbac-proxy`. This follows Part 2 of `/workspace/agent-how-to-release.md`.

## SAFETY RULES

1. This skill only runs AFTER a successful upstream release (state `release.phase == "released"`).
2. The downstream PR also requires human review before merge.
3. Push to `ibihim` fork, create PR to `openshift/kube-rbac-proxy`.

## PDCA Cycle

Before starting, read `.claude/state/knowledge-base.md` — especially KB-009 (Go version mismatch) and KB-010 (YAML test manifests). These are the most common downstream issues.

After each step, verify the outcome. The downstream merge is particularly prone to unexpected issues because we're crossing repo boundaries (upstream → downstream with different CI, dependencies, and conventions).

If anything unexpected happens, invoke `/retrospective` to record it. Do NOT modify this skill directly — flag for the user.

## Steps

### 1. Load State and Verify Prerequisites

Read `.claude/state/maintain.json`.
- Verify `release.phase == "released"`
- Get the released version from `release.version`

Read `.claude/state/knowledge-base.md` for downstream-specific lessons.

### 2. Verify Remotes

```bash
git remote -v | grep -E "(origin|openshift|ibihim)"
```

Expected:
- `origin` → brancz/kube-rbac-proxy (upstream)
- `openshift` → openshift/kube-rbac-proxy (downstream)
- `ibihim` → your fork

If `openshift` remote is missing:
```bash
git remote add openshift https://github.com/openshift/kube-rbac-proxy.git
```

**Check**: Verify all three remotes exist after setup.

### 3. Fetch and Create Merge Branch

```bash
git fetch origin
git fetch openshift

git checkout -b merge-vX.Y.Z-downstream openshift/master
```

**Check**: Verify we're on the correct branch: `git branch --show-current` should show `merge-vX.Y.Z-downstream`.

### 4. Merge Upstream Tag

```bash
git merge vX.Y.Z --no-edit
```

If merge conflicts occur:
- `go.mod` — generally take upstream (`--theirs`)
- `examples/*/deployment.yaml` — take upstream
- Other conflicts — take upstream unless downstream has specific requirements

```bash
git checkout --theirs <conflicted-file>
git add <conflicted-file>
git commit --no-edit
```

**Check**: Verify merge completed: `git log --oneline -3` should show the merge commit. If merge failed entirely, invoke `/retrospective` with details of which files conflicted.

### 5. Check and Adjust Go Version for CI

**KB-009 and KB-012 apply here — this is a known pitfall at BOTH major/minor AND patch level.**

```bash
cat .ci-operator.yaml
```

Look for: `tag: rhel-9-release-golang-X.YY-openshift-4.ZZ`

**Important (KB-012):** The CI tag `golang-1.25` does NOT guarantee the latest 1.25.x patch. CI sets `GOTOOLCHAIN=local`, so even a one-patch difference (e.g., go.mod says 1.25.8 but CI has 1.25.7) causes a hard failure. When in doubt, check the previous successful CI build for the exact Go version, or downgrade to the previous known-good patch version.

If CI uses a different Go version than what's in go.mod:

```bash
# For major/minor mismatch (e.g., CI has 1.24, go.mod says 1.25):
sed -i 's/^go 1.25.*/go 1.24.11/' go.mod
go mod tidy

# For patch mismatch (e.g., CI has 1.25.7, go.mod says 1.25.8):
sed -i 's/^go 1.25.8/go 1.25.7/' go.mod
# No go mod tidy needed for Go directive-only change
```

**Check**: Verify `head -3 go.mod` shows the correct Go version matching CI. If there's a mismatch we didn't anticipate, invoke `/retrospective`.

### 6. Vendor Dependencies

OpenShift requires vendoring:

```bash
rm -rf vendor
go mod vendor
```

**Check**: Verify vendor directory was created: `ls vendor/ | head -5`. If vendoring failed, it's usually a go.mod issue — check the error and invoke `/retrospective`.

### 7. Check for YAML-based Tests

**KB-010 applies here — this is a known pitfall.**

Look for YAML manifests used in e2e tests:

```bash
find test/ -name "*.yaml" -not -path "*/kind-config/*" 2>/dev/null
```

If downstream tests reference YAML manifests that were removed upstream, they need to be refactored to use programmatic setup:

```go
// Use kubetest.NewBasicKubeRBACProxyTestConfig() instead of YAML manifests
```

If refactoring is complex, flag this for the user rather than attempting it automatically. Invoke `/retrospective` to document the specific test files and what needs to change.

### 8. Build and Test

```bash
make build
make test-unit
```

**Check**: Both must pass. If tests fail:
1. Check if it's a Go version issue (step 5)
2. Check if it's a missing vendor dependency (step 6)
3. Check if it's a test refactoring issue (step 7)
4. Invoke `/retrospective` with the specific failure details

### 9. Commit Changes

```bash
# Vendor changes
git add vendor
git commit -s -S -m 'vendor: bump'

# If Go version was adjusted
git add go.mod go.sum
git commit -s -S -m 'go.mod: adjust Go version for CI'

# If tests were refactored
git add test/
git commit -s -S -m 'e2e: refactor to use programmatic setup'
```

**Check**: `git log --oneline -5` — verify commits are clean and in the right order.

### 10. Push and Create PR

```bash
git push -u ibihim merge-vX.Y.Z-downstream

gh pr create --repo openshift/kube-rbac-proxy \
  --base master \
  --head ibihim:merge-vX.Y.Z-downstream \
  --title "Merge upstream vX.Y.Z" \
  --body "## Summary
Merge upstream kube-rbac-proxy vX.Y.Z into OpenShift downstream.

### Upstream changes
- Bump dependencies
- See upstream CHANGELOG for details

### Downstream changes
- Adjust Go version to match CI (if needed)
- Regenerate vendor directory

### Verification
- [ ] CI passes
- [ ] Build succeeds
- [ ] Unit tests pass"
```

**Check**: Verify PR was created by parsing the output URL. If push or PR creation failed, invoke `/retrospective`.

### 11. Update State

```json
{
  "release": {
    "downstream": {
      "active": true,
      "pr_number": <number>,
      "phase": "pr_created"
    }
  }
}
```

Write updated state to `.claude/state/maintain.json`.

**Check**: Re-read state to verify correctness.

### 12. Report

Print summary:
- Downstream PR created with URL
- Any conflicts that were resolved
- Any Go version adjustments made
- Any test refactoring needed (flagged for user if complex)
- KB entries consulted (list which ones influenced decisions)
- Any incidents recorded via `/retrospective`
