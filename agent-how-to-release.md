# How To Release (Agent Guide)

This guide is for AI agents performing releases of kube-rbac-proxy. It documents the process, decision points, common pitfalls, and recovery procedures.

---

## Pre-Flight Checks

### 1. Clean Working Directory

**Critical**: Untracked Go files with missing imports will break `go mod tidy`.

```bash
# Check for untracked files
git status --short | grep "^??"

# If WIP Go files exist, remove or stash them
rm -f path/to/wip.go
# OR
git stash push --include-untracked -m "WIP: stash for release"
```

⚠️ **Warning**: Stashing can cause merge conflicts later. Prefer removing WIP files if not needed.

### 2. Understand Current State

```bash
# Current version
cat VERSION

# Latest release branches
git fetch origin
git branch -r | grep "origin/release-" | sort -V | tail -5

# Commits since last release
git log --oneline origin/release-$(cat VERSION | sed 's/v//')..master
```

### 3. Check for Security Issues

```bash
# Look for CVE or security issues
gh issue list --search "CVE" --state open
```

If CVEs exist in Go stdlib, note the fixed Go version for later.

---

## Phase 1: Determine Release Type

### Patch Release (v0.20.1 → v0.20.2)
- Bug fixes, dependency updates, security patches
- **Keep k8s.io packages on same minor version** (e.g., stay on v0.34.x)
- Only bump patch versions of dependencies

### Minor Release (v0.20.x → v0.21.0)
- New features, significant changes
- **k8s.io minor version bump** (e.g., v0.34.x → v0.35.x) — this alone warrants a minor release since kube-rbac-proxy is a thin wrapper around k8s authn/authz libraries, so a k8s minor bump changes effective behavior toward Kubernetes

---

## Phase 2: Update Dependencies

### 2.1 For Patch Releases (Constrained Update)

First, find the latest patch version of current k8s minor:

```bash
# Check current k8s version
grep "k8s.io/api" go.mod

# Find latest patch (if currently on v0.34.x)
go list -m -versions k8s.io/api | tr ' ' '\n' | grep "v0.34" | tail -1
```

Update dependencies but constrain k8s:

```bash
make update-go-deps
```

If k8s jumped to a new minor, downgrade:

```bash
# Replace v0.35.0 with v0.34.3 (latest patch of current minor)
sed -i 's|k8s.io/api v0.35.0|k8s.io/api v0.34.3|' go.mod
sed -i 's|k8s.io/apimachinery v0.35.0|k8s.io/apimachinery v0.34.3|' go.mod
sed -i 's|k8s.io/apiserver v0.35.0|k8s.io/apiserver v0.34.3|' go.mod
sed -i 's|k8s.io/client-go v0.35.0|k8s.io/client-go v0.34.3|' go.mod
sed -i 's|k8s.io/component-base v0.35.0|k8s.io/component-base v0.34.3|' go.mod
sed -i 's|k8s.io/kms v0.35.0|k8s.io/kms v0.34.3|' go.mod

go mod tidy
```

### 2.2 For Minor Releases (Full Update)

```bash
make update-go-deps
```

### 2.3 Update Go Version (If CVE Fix Needed)

Check latest Go version:
```bash
# Latest stable
curl -s https://go.dev/dl/?mode=json | jq -r '.[0].version'
```

Update both locations:
```bash
# CI workflow
sed -i 's/go-version: .*/go-version: 1.25.5/' .github/workflows/build.yml

# go.mod (may revert on go mod tidy - that's okay)
sed -i 's/^go .*/go 1.25.5/' go.mod
go mod tidy
```

### 2.4 Verify

```bash
make build
make test-unit
```

---

## Phase 3: Update Version Files

### 3.1 Determine New Version

```bash
OLD_VERSION=$(cat VERSION)
NEW_VERSION="v0.20.2"  # Set appropriately
```

### 3.2 Update VERSION

```bash
echo "$NEW_VERSION" > VERSION
```

### 3.3 Update All Version References

```bash
# Update examples and READMEs (exclude RELEASE.md - has history)
rg "$OLD_VERSION" --files-with-matches \
    | rg -v go.sum \
    | rg -v RELEASE.md \
    | xargs -I {} sed -i "s|$OLD_VERSION|$NEW_VERSION|g" {}
```

### 3.4 Update CHANGELOG.md

Add at top (after `# Changelog`):

```markdown
## X.Y.Z / YYYY-MM-DD

- [ENHANCEMENT] Bump dependencies
```

### 3.5 Update RELEASE.md

Add new row to table (at top of table body):

```markdown
| vX.Y.Z         | YYYY-MM-DD                       | Name (GitHub: @handle)   |
```

---

## Phase 4: Regenerate Docs

**Critical**: The example READMEs embed snippets from `deployment.yaml` via `embedmd`. After updating deployment.yaml image tags, you **must** regenerate or CI will fail on `make generate && git diff --exit-code`.

```bash
make generate
```

⚠️ **Warning**: `make generate` runs `find ./ -name "*.md"` recursively. If `.claude/worktrees/` or other directories contain stale `.md` files with `embedmd` directives, the command will fail. Temporarily move them aside:

```bash
mv .claude/worktrees /tmp/claude-worktrees-backup
make generate
mv /tmp/claude-worktrees-backup .claude/worktrees
```

Verify no unexpected changes:
```bash
git diff --stat
# Should only show examples/*/README.md updates
```

---

## Phase 5: Create Commits

**Important**: Keep dependency update separate from release changes.

```bash
# Commit 1: Dependencies only (if deps were updated in this release)
git add go.mod go.sum
git commit -s -S -m 'go*: update dependencies'

# Commit 2: Release changes (includes generated READMEs)
git add VERSION CHANGELOG.md RELEASE.md examples/ .github/workflows/build.yml
git commit -s -S -m '*: cut vX.Y.Z release'
```

---

## Phase 6: Create PR

**Important**: Push to the `ibihim` fork, not `origin`. Pushing to `origin` (brancz/kube-rbac-proxy) triggers the `publish` job which pushes a dev-tagged container image to Quay — unnecessary noise for a release PR branch.

```bash
# Create branch
git checkout -b rc-X.Y.Z
git push -u ibihim rc-X.Y.Z

# Create PR (cross-fork: ibihim -> brancz)
gh pr create --repo brancz/kube-rbac-proxy \
  --head ibihim:rc-X.Y.Z \
  --base master \
  --title "*: cut vX.Y.Z release" \
  --body "## Summary
- Bump dependencies (k8s vA.B.C, Go X.Y.Z)
- Update version references

## Checklist
- [x] VERSION updated
- [x] CHANGELOG.md updated
- [x] RELEASE.md updated
- [x] Example files updated
- [ ] Tests pass

Closes #XXX"
```

---

## Phase 7: Handle Review Feedback

### Common Feedback: "Stay on k8s minor version"

```bash
# Downgrade k8s packages
sed -i 's|k8s.io/api v0.35.0|k8s.io/api v0.34.3|' go.mod
# ... (repeat for all k8s.io packages)

go mod tidy
make build
make test-unit

# Recommit properly
git reset --soft HEAD~2
git reset HEAD  # Unstage all

git add go.mod go.sum
git commit -s -S -m 'go*: update dependencies'

git add VERSION CHANGELOG.md RELEASE.md examples/ .github/workflows/build.yml
git commit -s -S -m '*: cut vX.Y.Z release'

# Force push (to fork, not origin)
git push --force-with-lease ibihim rc-X.Y.Z
```

---

## Phase 8: Post-Merge Release

After PR is merged:

```bash
# 1. Update local master
#    Your local master likely has the old release commit that conflicts
#    with the squash-merged PR. Abort any rebase and hard-reset.
git checkout master
git fetch origin
git reset --hard origin/master
```

⚠️ **Warning**: `git pull` will often fail here with rebase conflicts because your local master has the pre-merge release commit while origin/master has the squash-merged version. Always use `fetch` + `reset --hard` instead.

```bash
# 2. Create release branch (use FULL version: release-X.Y.Z, not release-X.Y)
git checkout -b release-X.Y.Z
git push origin release-X.Y.Z
```

⚠️ **Warning**: RELEASE.md documents the convention as `release-<major>.<minor>` but the actual project convention uses the full version `release-X.Y.Z`.

```bash
# 3. Create and push tag
#    IMPORTANT: VERSION file already contains the "v" prefix (e.g., "v0.21.0").
#    Do NOT prepend another "v" or you'll get "vv0.21.0".
tag="$(< VERSION)"
git tag -s "${tag}" -m "${tag}"
git push origin "${tag}"

# 4. Create GitHub release
gh release create "${tag}" \
  --repo brancz/kube-rbac-proxy \
  --title "${tag}" \
  --notes "## Changelog

- [ENHANCEMENT] Bump dependencies

See [CHANGELOG.md](https://github.com/brancz/kube-rbac-proxy/blob/${tag}/CHANGELOG.md) for details."
```

---

## Decision Tree

```
Start Release
│
├─ Check for WIP/untracked Go files
│  └─ If exist → Remove or stash (prefer remove)
│
├─ Check for CVE issues
│  └─ If CVE in Go stdlib → Note fixed version
│
├─ Determine release type
│  ├─ Patch → Constrain k8s to current minor
│  └─ Minor → k8s minor bump OR new features
│
├─ Update dependencies
│  └─ If k8s jumped minor on patch release → Downgrade
│
├─ Update Go version (if CVE fix needed)
│  └─ Update both CI workflow AND go.mod
│
├─ Run `make generate` to update READMEs
│  └─ If worktrees/stale .md files cause errors → move them aside temporarily
│
├─ Create commits (2 separate commits)
│  ├─ go.mod + go.sum
│  └─ VERSION + CHANGELOG + RELEASE + examples (incl. READMEs) + workflow
│
├─ Create PR (push to ibihim fork, NOT origin)
│  └─ If feedback requires changes → Amend and force push to ibihim
│
└─ After merge
   ├─ Reset local master (fetch + reset --hard, NOT pull)
   ├─ Create release branch (release-X.Y.Z, full version)
   ├─ Create and push tag (tag="$(< VERSION)", no extra "v")
   └─ Create GitHub release (gh release create)
```

---

## Common Pitfalls

| Problem | Cause | Solution |
|---------|-------|----------|
| `go mod tidy` fails with "no matching versions" | Untracked Go file imports non-existent packages | Remove the WIP file |
| Merge conflicts on stash pop | Stashed go.mod/go.sum outdated | `git checkout --ours go.mod go.sum` |
| All files in one commit | Soft reset stages everything | `git reset HEAD` to unstage, then add selectively |
| Reviewer asks for k8s downgrade | Bumped k8s minor on patch release | Downgrade with sed, recommit, force push |
| Tag already exists | Re-running release | Delete tag locally and remote, recreate |
| CI fails on `generate` with README diff | Didn't run `make generate` after updating deployment.yaml image tags | Run `make generate` before committing — `embedmd` regenerates READMEs from deployment.yaml snippets |
| `make generate` fails on stale worktree `.md` | `find ./ -name "*.md"` picks up `.claude/worktrees/` files | Move worktrees aside temporarily |
| Pushing to `origin` triggers Quay publish | `publish` job runs on any push to `origin` | Push to `ibihim` fork instead; use `--head ibihim:rc-X.Y.Z` for cross-fork PR |
| Tag created as `vv0.21.0` (double v) | VERSION file already contains `v` prefix, and command used `v$(< VERSION)` | Use `tag="$(< VERSION)"` — never prepend `v` |
| Rebase conflicts on `git pull` after merge | Local master has pre-merge commit, origin has squash-merged version | Use `git fetch origin && git reset --hard origin/master` instead of `git pull` |

---

## Files Modified in Typical Release

| File | Change |
|------|--------|
| `go.mod` | Dependency versions |
| `go.sum` | Checksums |
| `VERSION` | New version |
| `CHANGELOG.md` | New section |
| `RELEASE.md` | New table row |
| `.github/workflows/build.yml` | Go version (if CVE fix) |
| `examples/*/deployment.yaml` | Image tags |
| `examples/*/README.md` | Version references |

---

## Verification Checklist

Before PR:
- [ ] `make build` passes
- [ ] `make test-unit` passes
- [ ] k8s.io packages on correct minor version
- [ ] Go version updated (if CVE fix needed)
- [ ] VERSION file correct
- [ ] CHANGELOG.md has new section
- [ ] RELEASE.md has new row
- [ ] Example files have new image tag

After merge:
- [ ] Release branch pushed
- [ ] Tag pushed
- [ ] GitHub release created
- [ ] Container image available on quay.io

---

# Part 2: Downstream Merge (OpenShift)

After upstream release, merge to `openshift/kube-rbac-proxy`.

---

## Prerequisites

### Remote Setup

```bash
# Verify remotes
git remote -v | grep -E "(origin|openshift|ibihim)"

# Should have:
# origin    -> brancz/kube-rbac-proxy (upstream)
# openshift -> openshift/kube-rbac-proxy (downstream)
# ibihim    -> your fork of kube-rbac-proxy
```

---

## Phase 1: Create Merge Branch

```bash
# Fetch latest from both repos
git fetch origin
git fetch openshift

# Create branch from openshift/master
git checkout -b merge-vX.Y.Z-downstream openshift/master
```

---

## Phase 2: Merge Upstream Tag

```bash
git merge vX.Y.Z --no-edit
```

### Handle Merge Conflicts

Common conflicts:
- `go.mod` - Go version mismatch
- `examples/*/deployment.yaml` - image tags

For conflicts, generally take upstream (`--theirs`) unless downstream has specific requirements.

```bash
git checkout --theirs <conflicted-file>
git add <conflicted-file>
git commit --no-edit
```

---

## Phase 3: Adjust Go Version for CI

**Critical**: Check `.ci-operator.yaml` for required Go version:

```bash
cat .ci-operator.yaml
# Look for: tag: rhel-9-release-golang-X.YY-openshift-4.ZZ
```

If CI uses `golang-1.24`, you must use Go 1.24.x (not 1.25.x):

```bash
# Check current go.mod version
head -3 go.mod

# If it shows 1.25.x but CI needs 1.24.x:
sed -i 's/^go 1.25.*/go 1.24.11/' go.mod
go mod tidy
```

---

## Phase 4: Vendor Dependencies

OpenShift requires vendoring:

```bash
rm -rf vendor
go mod vendor
```

---

## Phase 5: Refactor Downstream-Only Tests

If downstream has tests using YAML manifests, refactor to programmatic setup:

### Pattern: Use `kubetest.NewBasicKubeRBACProxyTestConfig()`

```go
// Old (YAML-based):
Given: kubetest.Actions(
    kubetest.CreatedManifests(client, "path/to/manifests/*.yaml"),
),

// New (programmatic):
Given: kubetest.Actions(
    kubetest.NewBasicKubeRBACProxyTestConfig().
        AddSAClusterRoleBinding("kube-rbac-proxy", testtemplates.GetKRPAuthDelegatorRole()).
        Launch(client),
),
```

### Custom Namespace Support

For tests needing non-default namespace, create local helper:

```go
// In test file (keeps kubetest unmodified for back-merge)
func runScenarioInNamespace(t *testing.T, namespace string, s kubetest.Scenario) bool {
    ctx := &kubetest.ScenarioContext{Namespace: namespace}
    defer func() { /* cleanup */ }()
    return t.Run(s.Name, func(t *testing.T) { /* run scenario */ })
}
```

---

## Phase 6: Verify and Commit

```bash
# Build and test
make build
make test-unit

# Commit vendor changes
git add vendor
git commit -s -S -m 'vendor: bump'

# If tests were refactored:
git add test/
git commit -s -S -m 'e2e: refactor to use programmatic setup'
```

---

## Phase 7: Push and Create PR

```bash
# Push to your fork
git push -u <your-fork> merge-vX.Y.Z-downstream

# Create PR to openshift/kube-rbac-proxy
gh pr create --repo openshift/kube-rbac-proxy \
  --base master \
  --head <your-username>:merge-vX.Y.Z-downstream \
  --title "Merge upstream vX.Y.Z" \
  --body "## Summary
Merge upstream kube-rbac-proxy vX.Y.Z into OpenShift downstream.

### Upstream changes
- Bump dependencies (k8s vA.B.C)
- [other changes from upstream CHANGELOG]

### Downstream changes
- Adjust Go version to 1.24.x (matching CI)
- Regenerate vendor directory
- [any test refactoring]"
```

---

## Downstream Decision Tree

```
Start Downstream Merge
│
├─ Fetch openshift remote
│
├─ Create merge branch from openshift/master
│
├─ Merge upstream tag
│  └─ If conflicts → resolve (usually take upstream)
│
├─ Check .ci-operator.yaml for Go version
│  └─ If mismatch → adjust go.mod to match CI
│
├─ Vendor dependencies
│  └─ rm -rf vendor && go mod vendor
│
├─ Check for YAML-based tests
│  └─ If exist → refactor to programmatic setup
│
├─ Build and test
│
└─ Push and create PR
```

---

## Downstream Pitfalls

| Problem | Cause | Solution |
|---------|-------|----------|
| CI fails with Go version error | go.mod has newer Go than CI supports | Check `.ci-operator.yaml`, downgrade go.mod |
| Tests fail finding YAML files | Upstream removed YAML manifests | Refactor to programmatic setup |
| Vendor directory huge diff | Normal for dependency bumps | Expected, just commit it |
| Merge conflicts in go.mod | Downstream had different deps | Usually take upstream (`--theirs`) |

---

## Downstream Verification Checklist

- [ ] Go version in go.mod matches CI (check `.ci-operator.yaml`)
- [ ] `make build` passes
- [ ] `make test-unit` passes
- [ ] Vendor directory regenerated
- [ ] No YAML manifests in test/e2e/* (use programmatic setup)
- [ ] PR created to openshift/kube-rbac-proxy
