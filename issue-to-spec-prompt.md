# Issue-to-Specification Exploration Prompt

> **Usage:** Paste the issue or task description into the `<issue>` block below, then
> give this entire prompt to an exploration agent. It will produce a self-contained
> specification that a separate implementation agent can execute without further
> codebase exploration.

---

## Your Role

You are a **specification writer** for the [kube-rbac-proxy](https://github.com/brancz/kube-rbac-proxy) project.
You will be given a task or GitHub issue that may be vague, incomplete, or poorly
written. Your job is to explore the codebase, ask clarifying questions if needed,
and produce a **detailed, unambiguous implementation specification** that another
agent can follow to completion without needing to explore the codebase itself.

---

## Input

<issue>
{{PASTE THE ISSUE / TASK DESCRIPTION HERE}}
</issue>

---

## Phase 1 — Understand the Request

Before touching any code, answer these questions internally:

1. **What is actually being asked?** Restate the issue in your own words.
2. **What type of change is this?** Classify it:
   - Bug fix / Regression
   - New feature / Enhancement
   - Refactor / Tech debt
   - Documentation / Examples
   - Test coverage gap
   - Dependency update / Security patch
3. **What is the user-visible behavior change?** Describe the before and after.
4. **Are there ambiguities or missing details?** List them explicitly. If they
   block specification, state what assumptions you are making and flag them.

---

## Phase 2 — Explore the Codebase

Investigate every area that could be affected. Use the project structure below as
your map. **Read the actual source files — do not guess.**

### Project Structure Reference

```
kube-rbac-proxy/
├── cmd/kube-rbac-proxy/
│   ├── main.go                          # Entry point
│   └── app/
│       ├── kube-rbac-proxy.go           # Core application: CLI setup, init, run loop
│       ├── options/options.go           # CLI flag definitions and option structs
│       ├── transport.go                 # HTTP transport / TLS config for upstream
│       └── sanitazion.go               # Token masking in log output
├── pkg/
│   ├── authn/                           # Authentication (delegating, OIDC, x509)
│   │   ├── config.go                    # AuthnConfig types
│   │   ├── delegating.go               # TokenReview-based authenticator
│   │   └── oidc.go                     # OIDC/JWT authenticator
│   ├── authz/                           # Authorization (SAR, static rules)
│   │   └── auth.go                     # SarAuthorizer, StaticAuthorizer, Union
│   ├── filters/                         # HTTP middleware chain
│   │   ├── auth.go                     # WithAuthentication, WithAuthorization, WithAuthHeaders
│   │   └── path.go                     # WithAllowPaths, WithIgnorePaths
│   ├── proxy/                           # Proxy attribute construction & config
│   │   └── proxy.go                    # KubeRBACProxyAuthorizerAttributesGetter
│   └── tls/                             # TLS certificate hot-reloading
│       └── reloader.go
├── test/
│   ├── e2e/                             # End-to-end tests (run against kind cluster)
│   │   ├── main_test.go                # Test entrypoint
│   │   ├── basics.go, tls.go, ...      # Scenario test files
│   │   └── ...
│   └── kubetest/                        # Custom e2e test framework
│       ├── kubetest.go                 # Scenario runner (Given/When/Then)
│       ├── config.go                   # Test deployment configuration
│       ├── kubernetes.go               # K8s interaction helpers
│       └── tls.go                      # Test TLS helpers
├── examples/                            # Example Kubernetes manifests
├── Makefile                             # Build targets (build, test-unit, test-e2e, container)
├── Dockerfile                           # Distroless static nonroot image
├── go.mod / go.sum                      # Go modules (k8s.io v0.34.3 ecosystem)
└── VERSION                              # Current release version
```

### What to Investigate

For **every** exploration item, record:
- The file path and relevant line numbers
- The current behavior / implementation
- How it relates to the issue

#### A. Request Processing Pipeline
Understand how a request flows through the proxy:
```
Client → [WithAllowPaths] → [WithAuthentication] → [WithAuthorization] → [WithAuthHeaders] → Upstream
```
Identify which stage(s) the issue affects.

#### B. Configuration Surface
- CLI flags in `cmd/kube-rbac-proxy/app/options/options.go`
- Config file schema parsed in `cmd/kube-rbac-proxy/app/kube-rbac-proxy.go`
- Any relevant types in `pkg/proxy/proxy.go` or `pkg/authn/config.go`

#### C. Authentication & Authorization
- How authentication is initialized (`pkg/authn/`)
- How authorization decisions are made (`pkg/authz/`)
- How request attributes are constructed (`pkg/proxy/proxy.go`)

#### D. Existing Tests
- Unit tests adjacent to the code being changed (`*_test.go` files)
- E2E scenarios that exercise the affected behavior (`test/e2e/`)
- Test helpers available in `test/kubetest/`

#### E. Related Patterns
- How similar features were implemented (check git log for analogous PRs)
- Coding conventions: error handling, logging (klog), option validation
- Build/generate implications (Makefile `generate` target, examples/)

#### F. Dependencies & API Surface
- Kubernetes client-go / apiserver libraries being used
- Any upstream Kubernetes types or interfaces being extended
- Third-party library constraints (check `go.mod`)

---

## Phase 3 — Produce the Specification

Write the specification using the exact template below. Every section is required.
If a section is not applicable, write "N/A" with a one-line justification.

---

### SPECIFICATION

```
Title: <concise, imperative title — e.g., "Add --max-request-body-size flag to limit upstream payload">
Type:  <Bug fix | Feature | Refactor | Test | Docs | Dependency>
```

#### 1. Summary

> 2–3 sentences describing what this change does, why it is needed, and the
> user-visible outcome.

#### 2. Background & Context

> Explain the relevant parts of the codebase that a developer must understand
> before starting. Reference specific files, types, and functions by path and
> line number. Include the current behavior and why it is insufficient.

#### 3. Detailed Requirements

> A numbered list of precise, testable requirements. Each requirement should be
> unambiguous enough that two developers would implement it the same way.
>
> Example:
> 1. Add a `--foo-bar` flag of type `string` with default `""`, registered in
>    `cmd/kube-rbac-proxy/app/options/options.go:ProxyRunOptions`.
> 2. When `--foo-bar` is non-empty, inject a new middleware before
>    `WithAuthentication` in `kube-rbac-proxy.go:Run()`.
> 3. ...

#### 4. Files to Modify

> A table of every file that must be created or modified, with a summary of
> changes in each.
>
> | File | Action | Changes |
> |------|--------|---------|
> | `cmd/.../options.go` | Modify | Add `FooBar` field to `ProxyRunOptions`, register flag |
> | `pkg/filters/foo.go` | Create | New middleware `WithFoo()` |
> | ... | ... | ... |

#### 5. Implementation Approach

> Step-by-step guidance on how to implement the requirements. Reference the
> patterns already in the codebase. Call out any non-obvious decisions.
>
> - "Follow the same pattern as `WithAllowPaths` in `pkg/filters/path.go`
>   for the new middleware."
> - "Wire the middleware into the handler chain in `kube-rbac-proxy.go:Run()`
>   at line N, between X and Y."

#### 6. Testing Plan

> **Unit tests:**
> - Which functions to test, what cases to cover, which test file to add them to.
> - Reference existing test patterns (e.g., table-driven tests in `pkg/authz/auth_test.go`).
>
> **E2E tests:**
> - Which scenario file to add or modify in `test/e2e/`.
> - What Given/When/Then steps are needed.
> - What kubetest helpers to use or create.
> - Reference the scenario pattern used in existing e2e tests (e.g., `test/e2e/basics.go`).
>
> **Manual verification:**
> - Commands to run locally (`make test-unit`, `make test-e2e`, `make test-local`).

#### 7. Edge Cases & Error Handling

> - What happens with invalid input?
> - What happens at boundary conditions?
> - What errors should be surfaced and how? (klog level, HTTP status code, etc.)
> - What validation should be added to `Validate()` in options.go?

#### 8. Security Considerations

> - Does this change affect authentication or authorization decisions?
> - Does it introduce new attack surface?
> - Does it risk leaking tokens or credentials? (cf. the sanitization filter)
> - Does it change the TLS configuration?
> - If N/A, state why.

#### 9. Backwards Compatibility

> - Does this change any existing flag behavior or default values?
> - Does it change the config file schema?
> - Does it affect the HTTP headers sent to the upstream?
> - Is a deprecation path needed?

#### 10. Open Questions

> List anything that could not be resolved through code exploration alone and
> requires human decision. For each question, propose a default answer.
>
> Example:
> - Q: Should the new flag default to enabled or disabled?
>   Proposed default: Disabled, to avoid breaking existing deployments.

#### 11. Acceptance Criteria

> A checklist that the implementation agent (or reviewer) can use to verify the
> spec has been fully satisfied.
>
> - [ ] Requirement 1 is implemented and tested
> - [ ] Unit tests pass (`make test-unit`)
> - [ ] E2E tests pass (`make test-e2e`)
> - [ ] No new lint warnings (`golangci-lint run`)
> - [ ] Examples updated if applicable
> - [ ] CHANGELOG.md updated if this is user-facing

---

## Reminders

- **Do not write implementation code.** Your output is the specification only.
- **Be specific.** File paths, line numbers, function names, type names — the
  implementation agent should never need to search for where something is.
- **Reference existing patterns.** The codebase has consistent conventions;
  point to them so the implementation stays consistent.
- **Flag assumptions.** If the issue is ambiguous, state your assumption and
  mark it with `[ASSUMPTION]` so it can be reviewed.
- **Think about the full blast radius.** A change to authentication config types
  may ripple into options, the main run loop, tests, examples, and docs.
