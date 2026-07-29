#!/usr/bin/env bash
#
# ansible-test requires the collection to live at
# <root>/ansible_collections/<namespace>/<name>/ regardless of where the
# repository is checked out. This script materialises that layout and prints
# the resulting collection path on stdout.
#
# Usage:
#   COLLECTION_PATH=$(./scripts/setup-collection-tree.sh)
#   cd "$COLLECTION_PATH"
#   ansible-test sanity --venv
#
# We copy rather than symlink: ansible-test resolves paths in ways that make a
# symlinked collection root behave inconsistently across ansible-core versions.

set -euo pipefail

NAMESPACE="james_crowley"
NAME="intel_amt"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The build root is derived from the repository location, not a fixed path.
# Two *different* checkouts of this repo staged on one host (parallel CI jobs, or
# several worktrees) would otherwise share one directory and clobber each other
# mid-run, which surfaces as sanity failures naming files that do not exist in
# the branch under test -- a genuinely baffling symptom. Override with
# COLLECTION_BUILD_ROOT when a specific location is needed.
#
# Note precisely what that keying does and does not protect. It is keyed on the
# repository PATH, so it separates different checkouts and does nothing at all
# for two processes staging from the SAME checkout -- which is the common case
# when several agents or terminals work one clone concurrently. That case is
# handled by the in-use guard below rather than by the path, because a stable
# path is deliberate: callers cd into it and re-run tests across invocations.
if [ -n "${COLLECTION_BUILD_ROOT:-}" ]; then
    BUILD_ROOT="${COLLECTION_BUILD_ROOT}"
else
    REPO_TAG="$(printf '%s' "${REPO_ROOT}" | cksum | cut -d' ' -f1)"
    BUILD_ROOT="${TMPDIR:-/tmp}/ansible-collection-build-${REPO_TAG}"
fi
COLLECTION_PATH="${BUILD_ROOT}/ansible_collections/${NAMESPACE}/${NAME}"

# A marker identifying a directory this script created. `rm -rf "${BUILD_ROOT}"`
# runs on caller-supplied input, and the old `-n` test rejected only the empty
# string -- so COLLECTION_BUILD_ROOT=$HOME deleted a home directory wholesale.
# Refusing to delete anything that is not demonstrably ours is cheap insurance
# against a one-character mistake in an export.
MARKER="${BUILD_ROOT}/.amt-collection-build-root"
OWNER_PID_FILE="${BUILD_ROOT}/.amt-collection-build-root.pid"

if [ -e "${BUILD_ROOT}" ]; then
    if [ ! -f "${MARKER}" ]; then
        echo "Refusing to delete ${BUILD_ROOT}: it exists but was not created by" >&2
        echo "this script (no ${MARKER##*/} marker). Point COLLECTION_BUILD_ROOT at a" >&2
        echo "path this script owns, or remove that directory yourself if you are sure." >&2
        exit 1
    fi

    # Concurrency guard. Two runs staging the same checkout at once means the
    # second `rm -rf` lands while the first is mid-test, and the failure it
    # produces names files from the wrong tree. Fail loudly with the remedy
    # instead: this is recoverable in one command, and silently destroying
    # another run's tree costs far more than an error message here.
    if [ -f "${OWNER_PID_FILE}" ]; then
        OWNER_PID="$(cat "${OWNER_PID_FILE}" 2>/dev/null || true)"
        if [ -n "${OWNER_PID}" ] && [ "${OWNER_PID}" != "$$" ] && kill -0 "${OWNER_PID}" 2>/dev/null; then
            echo "Refusing to stage into ${BUILD_ROOT}: process ${OWNER_PID} is still" >&2
            echo "using it, and staging would delete the tree underneath it." >&2
            echo >&2
            echo "Set a unique build root for this run, e.g.:" >&2
            echo "  export COLLECTION_BUILD_ROOT=\${TMPDIR:-/tmp}/amt-build-\$\$" >&2
            exit 1
        fi
    fi

    rm -rf "${BUILD_ROOT}"
fi

mkdir -p "$(dirname "${COLLECTION_PATH}")"
mkdir -p "${BUILD_ROOT}"
: > "${MARKER}"
printf '%s\n' "$$" > "${OWNER_PID_FILE}"

if command -v rsync >/dev/null 2>&1; then
    rsync -a \
        --exclude '.git/' \
        --exclude 'tests/output/' \
        --exclude '__pycache__/' \
        --exclude '*.pyc' \
        --exclude '.venv/' \
        "${REPO_ROOT}/" "${COLLECTION_PATH}/"
else
    mkdir -p "${COLLECTION_PATH}"
    tar -C "${REPO_ROOT}" \
        --exclude='./.git' \
        --exclude='./tests/output' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='./.venv' \
        -cf - . | tar -C "${COLLECTION_PATH}" -xf -
fi

echo "${COLLECTION_PATH}"
