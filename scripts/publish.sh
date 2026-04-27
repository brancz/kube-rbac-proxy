#!/usr/bin/env bash
# exit immediately when a command fails
set -e
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail
# error on unset variables
set -u
# for debugging
set -x

REGISTRY_PATH="${REGISTRY_PATH:-quay.io/brancz/kube-rbac-proxy}"
CPU_ARCHS="amd64 arm64 arm ppc64le s390x"
TAG_COMMIT=$(git rev-list --abbrev-commit --tags --max-count=1)
COMMIT=$(git rev-parse --short HEAD)
TAG=$(git describe --abbrev=0 --tags ${TAG_COMMIT})
VERSION="${TAG}"
PULL_TAGS=${PULL_TAGS:-""}

if [[ -n "$PULL_TAGS" ]]; then
  # github actions, by default, fetches using `--no-tags`.
  # we need tags though to create a release version string.
  git fetch --tags --force
fi

# if the current commit, does not correspond to a tag, create a verbose version string.
if [ "${TAG_COMMIT}" != "${COMMIT}" ]; then
  echo "current head commit does not match any 'v*' tag"
  exit 1
fi

# build and push arch specific images
for arch in ${CPU_ARCHS}; do
  VERSION="${VERSION}" DOCKER_REPO="${REGISTRY_PATH}" GOARCH="${arch}" make container
  docker push "${REGISTRY_PATH}:${VERSION}-${arch}"
done

# Create manifest to join all images under one virtual tag
MANIFEST="docker manifest create -a ${REGISTRY_PATH}:${VERSION}"
for arch in ${CPU_ARCHS}; do
  MANIFEST="${MANIFEST} ${REGISTRY_PATH}:${VERSION}-${arch}"
done
eval "${MANIFEST}"

# Annotate to set which image is build for which CPU architecture
for arch in ${CPU_ARCHS}; do
  docker manifest annotate --arch "${arch}" "${REGISTRY_PATH}:${VERSION}" "${REGISTRY_PATH}:${VERSION}-${arch}"
done
docker manifest push "${REGISTRY_PATH}:${VERSION}"
