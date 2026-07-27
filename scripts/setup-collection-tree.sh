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
BUILD_ROOT="${COLLECTION_BUILD_ROOT:-${TMPDIR:-/tmp}/ansible-collection-build}"
COLLECTION_PATH="${BUILD_ROOT}/ansible_collections/${NAMESPACE}/${NAME}"

rm -rf "${BUILD_ROOT}"
mkdir -p "$(dirname "${COLLECTION_PATH}")"

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
