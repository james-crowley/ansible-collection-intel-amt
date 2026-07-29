#!/usr/bin/env bash
# Fail if .circleci/config.yml contains a double angle bracket that is not a
# CircleCI parameter tag.
#
# Why this exists: CircleCI's preprocessor treats a double angle bracket as the
# start of a parameter tag, anywhere in the file, including inside a shell
# `command:` block and inside comments. A bash here-string therefore produces
# "Unclosed tag", which is a CONFIG error -- the affected workflow fails to
# launch entirely.
#
# `circleci config validate` does NOT catch this. It reported the config valid on
# the commit that introduced exactly this bug, and the breakage only surfaced the
# next time the hardware workflow was actually triggered. Since that workflow is
# only reachable via a pipeline parameter, the gap between "merged" and "found
# out" was several releases.
set -euo pipefail

config="${1:-.circleci/config.yml}"
total=$(grep -oE '<<' "${config}" | wc -l | tr -d ' ')
tags=$(grep -oE '<< *(pipeline\.)?parameters\.' "${config}" | wc -l | tr -d ' ')

if [ "${total}" -ne "${tags}" ]; then
    echo "ERROR: ${config} contains $((total - tags)) double-angle-bracket sequence(s)" >&2
    echo "that are not CircleCI parameter tags. CircleCI will fail to parse the" >&2
    echo "config with \"Unclosed tag\" and the workflow will not launch." >&2
    echo >&2
    echo "Offending lines:" >&2
    grep -nE '<<' "${config}" | grep -vE '<< *(pipeline\.)?parameters\.' >&2
    echo >&2
    echo "Rewrite without the sequence -- including in comments. For splitting a" >&2
    echo "string in bash, set IFS around a bare 'for' instead of a here-string." >&2
    exit 1
fi

echo "OK: ${config} has ${tags} parameter tag(s) and no stray double angle brackets."
