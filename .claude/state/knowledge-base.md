# Knowledge Base — kube-rbac-proxy Maintenance

This is a living document of lessons learned during maintenance operations.
Skills MUST read relevant sections before acting. After incidents, use `/retrospective` to add new entries.

---

## Release — Dependencies Phase

### KB-001: `make update-go-deps` can bump k8s minor on patch releases
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / deps phase
- **What happened**: `make update-go-deps` bumped k8s.io packages from v0.34.x to v0.35.0 during what should have been a patch release.
- **Root cause**: `update-go-deps` pulls latest versions unconditionally. It doesn't know about our patch vs. minor release distinction.
- **Prevention**: After `make update-go-deps`, always compare the k8s.io/api version in go.mod against the pre-update version. If the minor version changed during a patch release, downgrade all k8s.io packages to the latest patch of the original minor.
- **Check command**: `grep "k8s.io/api" go.mod` before and after.

### KB-002: `go mod tidy` fails when untracked Go files have bad imports
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / deps phase
- **What happened**: `go mod tidy` failed with "no matching versions for module" errors.
- **Root cause**: An untracked WIP `.go` file imported a non-existent package. `go mod tidy` tries to resolve all imports in the module, including untracked files.
- **Prevention**: Before running `go mod tidy` or `make update-go-deps`, check for untracked Go files: `git status --short | grep "^??" | grep "\.go$"`. Remove or stash them.

---

## Release — Version Phase

### KB-003: `make generate` fails on stale worktree .md files
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / version phase
- **What happened**: `make generate` failed because `embedmd` found `.md` files in `.claude/worktrees/` with broken `embedmd` directives.
- **Root cause**: `make generate` runs `find ./ -name "*.md"` recursively, which picks up everything including Claude's worktree directories.
- **Prevention**: Before `make generate`, move `.claude/worktrees` aside: `mv .claude/worktrees /tmp/claude-worktrees-backup`. Restore after.
- **Check command**: `find ./ -name "*.md" -path ".claude/*"` — if any results, move them first.

### KB-004: Version references in rg/sed must exclude certain files
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / version phase
- **What happened**: Sed replaced version strings in go.sum, RELEASE.md history, and CHANGELOG.md history, creating spurious changes.
- **Root cause**: The `rg | xargs sed` pipeline didn't exclude files that contain old version strings intentionally.
- **Prevention**: Always exclude: `go.sum`, `RELEASE.md`, `CHANGELOG.md`, `.claude/`, `agent-how-to-release.md` from version string replacement.

---

## Release — Commit & PR Phase

### KB-005: Pushing to origin triggers Quay publish job
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / commit_and_pr phase
- **What happened**: Push to `origin` (brancz/kube-rbac-proxy) triggered the CI `publish` job, which pushed a dev-tagged container image to Quay.io.
- **Root cause**: The `publish` workflow runs on any push to `origin`, not just tags.
- **Prevention**: ALWAYS push release PR branches to the `ibihim` fork. Use `git push -u ibihim <branch>`, never `git push origin <branch>`. The PR uses `--head ibihim:<branch>` for cross-fork.

### KB-006: Tag created as `vv0.21.0` (double v prefix)
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / post_merge phase
- **What happened**: The tag was created as `vv0.21.0` instead of `v0.21.0`.
- **Root cause**: The VERSION file already contains the "v" prefix (e.g., `v0.21.0`). The command used `v$(< VERSION)` which prepended another "v".
- **Prevention**: Always use `tag="$(< VERSION)"` — never prepend "v". Check: `cat VERSION` to verify it starts with "v".

---

## Release — Post-Merge Phase

### KB-007: `git pull` fails after PR merge with rebase conflicts
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / post_merge phase
- **What happened**: `git pull` on master failed with rebase conflicts after the release PR was squash-merged.
- **Root cause**: Local master has the pre-merge release commits while origin/master has the squash-merged version. Git tries to rebase and conflicts.
- **Prevention**: NEVER use `git pull` after a PR merge. Always use `git fetch origin && git reset --hard origin/master`.

### KB-008: Release branch naming convention
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-upstream / post_merge phase
- **What happened**: Release branch was created as `release-0.21` but convention requires full version.
- **Root cause**: RELEASE.md documents the convention as `release-<major>.<minor>` but the actual project convention uses full version.
- **Prevention**: Always use `release-X.Y.Z` (full version). Check existing branches: `git branch -r | grep "origin/release-" | tail -5`.

---

## Downstream — OpenShift Merge

### KB-009: Go version mismatch with CI operator
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-downstream
- **What happened**: CI failed because go.mod specified Go 1.25.x but the CI operator image only had Go 1.24.x.
- **Root cause**: OpenShift CI uses pinned Go versions in `.ci-operator.yaml`. Upstream Go version bumps can exceed what's available downstream.
- **Prevention**: Always check `.ci-operator.yaml` for the Go version tag (e.g., `rhel-9-release-golang-1.24-openshift-4.19`). If go.mod has a newer version, downgrade: `sed -i 's/^go 1.25.*/go 1.24.11/' go.mod && go mod tidy`.
- **See also**: KB-012 — this applies to **patch** versions too, not just major/minor mismatches. CI sets `GOTOOLCHAIN=local` so even a 1.25.7 vs 1.25.8 difference causes a hard failure.

### KB-010: Downstream tests use removed YAML manifests
- **Date**: Seeded from agent-how-to-release.md
- **Context**: release-downstream
- **What happened**: E2E tests failed because they referenced YAML manifest files that were removed in the upstream merge.
- **Root cause**: Downstream tests used `kubetest.CreatedManifests()` to load YAML files, but upstream moved to programmatic setup.
- **Prevention**: After merge, check for YAML references in test files: `grep -r "CreatedManifests\|\.yaml" test/e2e/ | grep -v kind-config`. Refactor to use `kubetest.NewBasicKubeRBACProxyTestConfig()`.

---

## Triage

### KB-011: Scanner CVEs vs. real vulnerabilities
- **Date**: Seeded from workflow design
- **Context**: triage-issues
- **What happened**: Scanner tools (Trivy, Grype, Snyk) report CVEs in transitive dependencies that are not reachable from our code.
- **Root cause**: Scanners check dependency versions, not code reachability. A CVE in a library we depend on doesn't mean our code is affected.
- **Prevention**: Always run `govulncheck ./...` to determine reachability. Only classify as `ultra_high` if govulncheck confirms the vulnerability is reachable. Scanner-only findings are `medium` priority.

---

## Incident Log

<!-- New incidents go here. Use /retrospective to add entries. -->
<!-- Format:
### KB-NNN: [Short title]
- **Date**: YYYY-MM-DD
- **Context**: [skill / phase]
- **What happened**: [description of the incident]
- **Root cause**: [why it happened]
- **Fix applied**: [what was done to resolve it]
- **Prevention**: [what to check/do to prevent recurrence]
- **Check command**: [optional — command to verify the issue is absent]
-->

### KB-012: Go patch version mismatch in downstream CI (not just major/minor)
- **Date**: 2026-03-16
- **Context**: release-downstream / Go version adjustment (step 5)
- **What happened**: All 6 CI checks on openshift/kube-rbac-proxy PR #133 failed. Error: `go: go.mod requires go >= 1.25.8 (running go 1.25.7; GOTOOLCHAIN=local)`. The upstream release bumped go.mod to 1.25.8 for CVE fixes, but the downstream CI image (`rhel-9-release-golang-1.25-openshift-4.22`) only had Go 1.25.7.
- **Root cause**: KB-009 only anticipated major/minor version mismatches (e.g., 1.25 vs 1.24). But the CI image can also lag behind on **patch** versions within the same minor. OpenShift CI sets `GOTOOLCHAIN=local` which prevents auto-downloading a newer toolchain, causing a hard failure even for a one-patch difference.
- **Fix applied**: Downgraded `go 1.25.8` to `go 1.25.7` in go.mod to match CI. No `go mod tidy` or re-vendor needed since only the Go directive changed (no dependency resolution impact).
- **Prevention**: In release-downstream step 5, compare the **full** Go version (including patch) from go.mod against what CI provides, not just the major.minor. The CI image tag `golang-1.25` does NOT guarantee the latest 1.25.x — check the actual Go version available. When in doubt, downgrade to match.
- **Check command**: `head -3 go.mod` and compare against `.ci-operator.yaml` tag. If the tag is `golang-1.25`, check OpenShift CI release notes or the previous successful build to determine the exact Go patch version available.
