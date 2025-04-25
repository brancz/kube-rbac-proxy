# Releases

This page describes the release process and the respective release shepherd.
Release shepherds are chosen on a voluntary basis.

## Release schedule

| release series | date of release (year-month-day) | release shepherd                        |
|----------------|----------------------------------|-----------------------------------------|
| v0.20.0        | TBD                              | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.19.1        | 2025-04-23                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.19.0        | 2025-02-14                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.18.2        | 2024-11-29                       | Anya Kramar (GitHub: @kramaranya)       |
| v0.18.1        | 2024-08-30                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.18.0        | 2024-06-05                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.17.1        | 2024-05-07                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.17.0        | 2024-04-18                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.16.0        | 2024-02-08                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.15.0        | 2023-10-20                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.14.4        | 2023-10-16                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.14.3        | 2023-09-07                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.14.2        | 2023-06-05                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.14.1        | 2023-04-06                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.14.0        | 2022-12-15                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.13.1        | 2022-10-04                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.13.0        | 2022-06-29                       | Krzysztof Ostrowski (GitHub: @ibihim)   |
| v0.12.0        | 2022-04-08                       | Sergiusz Urbaniak (GitHub: @s-urbaniak) |
| v0.11.0        | 2021-08-02                       | Sergiusz Urbaniak (GitHub: @s-urbaniak) |
| v0.10.0        | 2021-05-07                       | Sergiusz Urbaniak (GitHub: @s-urbaniak) |
| v0.9.0         | 2021-04-27                       | Sergiusz Urbaniak (GitHub: @s-urbaniak) |
| v0.8.0         | 2020-11-03                       | Paweł Krupa (GitHub: @paulfantom)       |
| v0.7.0         | 2020-09-15                       | Paweł Krupa (GitHub: @paulfantom)       |
| v0.6.0         | 2020-06-11                       | Frederic Branczyk (GitHub: @brancz)     |
| v0.5.0         | 2020-02-17                       | Frederic Branczyk (GitHub: @brancz)     |
| v0.4.1         | 2019-01-23                       | Frederic Branczyk (GitHub: @brancz)     |
| v0.4.0         | 2018-10-24                       | Frederic Branczyk (GitHub: @brancz)     |
| v0.3.1         | 2018-06-20                       | Frederic Branczyk (GitHub: @brancz)     |

## How to cut a new release

> This guide is strongly based on the [Prometheus release instructions](https://github.com/prometheus/prometheus/blob/main/RELEASE.md).

We maintain a separate branch for each minor release, named release-<major>.<minor>, e.g. release-1.1, release-2.0.

### Branch management and versioning strategy

We use [Semantic Versioning](https://semver.org/).

We maintain a separate branch for each minor release, named `release-<major>.<minor>`, e.g. `release-1.1`, `release-2.0`.

Note that branch protection kicks in automatically for any branches whose name starts with `release-`. Never use names starting with `release-` for branches that are not release branches.

The usual flow is to merge new features and changes into the master branch and
to merge bug fixes into the latest release branch. Bug fixes are then merged
into main from the latest release branch. The main branch should always contain
all commits from the latest release branch. As long as main hasn't deviated from
the release branch, new commits can also go to main, followed by merging main
back into the release branch.

If a bug fix got accidentally merged into main after non-bug-fix changes in
main, the bug-fix commits have to be cherry-picked into the release branch,
which then have to be merged back into main. Try to avoid that situation.

### 1. Updating dependencies

Before publishing a new release, consider updating the dependencies. Then create
a pull request against the main branch.

Note that after a dependency update, you should look out for any weirdness that
might have happened. Such weirdnesses include but are not limited to: flaky
tests, differences in resource usage, panic.

In case of doubt or issues that can't be solved in a reasonable amount of time,
you can skip the dependency update or only update select dependencies. In such a
case, you have to create an issue or pull request in the GitHub project for
later follow-up.

#### Updating Go dependencies

```
make update-go-deps
git add go.mod go.sum
git commit -m "Update dependencies"
```

### 2. Prepare your release

At the start of a new major or minor release cycle create the corresponding
release branch based on the main branch. For example if we're releasing `2.17.0`
and the previous stable release is `2.16.0` we need to create a `release-2.17`
branch. Note that all releases are handled in protected release branches, see
the above `Branch management and versioning` section.

Bump the version in the `VERSION`, update `CHANGELOG.md`, and modify version references in the example deployment manifests.
Do this in a proper PR pointing to the release branch as this gives others the opportunity to
chime in on the release in general and on the addition to the changelog in
particular.

Note that `CHANGELOG.md` should only document changes relevant to users of
kube-rbac-proxy, including external API changes, performance improvements, and
new features. Do not document changes of internal interfaces, code refactorings
and clean-ups, changes to the build process, etc. People interested in these are
asked to refer to the git history.

Entries in the `CHANGELOG.md` are meant to be in this order:

* `[CHANGE]`
* `[FEATURE]`
* `[ENHANCEMENT]`
* `[BUGFIX]`

Submit a PR against the master branch titled "*: cut vx.y.z release ".

### 3. Draft the new release

Tag the new release via the following commands:

```bash
$ tag="v$(< VERSION)"
$ git tag -s "${tag}" -m "${tag}"
$ git push origin "${tag}"
```

Optionally, you can use this handy `.gitconfig` alias.

```ini
[alias]
  tag-release = "!f() { tag=v${1:-$(cat VERSION)} ; git tag -s ${tag} -m ${tag} && git push origin ${tag}; }; f"
```

Then release with `git tag-release`.

Signing a tag with a GPG key is appreciated, but in case you can't add a GPG key
to your Github account using the following
[procedure](https://help.github.com/articles/generating-a-gpg-key/), you can
replace the `-s` flag by `-a` flag of the `git tag` command to only annotate the
tag without signing.

Once a tag is created, the release process through GitHub Actions will be
triggered for this tag.

Finally, wait for the build step for the tag to finish. The point here is to
wait for tarballs to be uploaded to the Github release and the container images
to be pushed to Quay.io.

### 4. Wrapping up

If the release has happened in the latest release branch, merge the changes into
main.
