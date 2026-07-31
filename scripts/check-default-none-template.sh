#!/usr/bin/env bash
# Fail if a tracked YAML file contains a quoted scalar Jinja template whose
# entire value is one expression ending in `| default(none)` / `| default(None)`.
#
# Why this exists: on ansible-core <= 2.18 (2.17 is this collection's declared
# floor) a quoted scalar template that is *only* `{{ ... }}` is rendered by
# Jinja's finalize step to text, and Ansible's convert_data step only evaluates
# that text back into a native value it recognises -- dicts, lists, True/False.
# A bare None is not among them, so it comes back as the EMPTY STRING, not
# `null`/`None`. On ansible-core >= 2.19 the templating engine preserves the
# native object instead, so the same line renders `None`. Measured, not
# inferred: `"{{ undefined | default(none) }}"` is `""` (str, `is none` ->
# false) on 2.17.14, and `null` (NoneType, `is none` -> true) on 2.19.11 and
# 2.21.2.
#
# That divergence has now cost three separate incidents: issue #80 (an
# integration target asserted `is none` on a value built this way, and only
# failed on the declared floor -- CI pins 2.19), the 0.6.0 qualification
# summary (a `| default(none)` printed a convincing "null" for a class that
# had in fact been read, masking a wrong-key bug), and issue #87 (production
# role defaults built this way arrive as `""` on 2.17, which fails an `int`
# argspec outright for an unset port and silently passes an `is not none`
# connection guard for an unset password/TLS fingerprint). This is the guard
# so a fourth occurrence is caught here instead of by whoever next runs the
# floor.
#
# The fix in each case is the same: never let a bare `default(none)` be the
# WHOLE value of a quoted scalar. Build the value inside a larger expression
# (a dict/list literal, `to_json`, etc.) so only the finished text crosses the
# template boundary -- see the comment on `nested_observation` in
# tests/integration/targets/amt_baremetal_install_role/files/nested_play.yml
# for a worked example -- or use `default(omit)` when the variable is optional
# and the intent is "let the callee's own default apply" (omit is a marker
# string, not None, so it survives the boundary intact on every core; but see
# the allowlist below for why that fix is out of scope for some existing
# lines).
#
# What this script deliberately does NOT do: understand what happens to a
# value after it is assigned. `| default(none)` in a quoted scalar is only a
# defect if something downstream cares whether the result is `None` or `""`
# (an `is none` test, an `int`/typed argspec, a security guard written as
# `is not none`). A required role variable with no other viable default can
# legitimately keep this exact shape forever, PROVIDED the downstream check is
# `is truthy` (which treats "" and None alike) rather than `is none`/
# `is not none`. Telling those two cases apart needs the downstream file, which
# this script does not read -- so precise exceptions are handled by the
# allowlist/opt-out below rather than by trying to make the pattern itself
# smarter.
#
# Two ways to except a line, most-specific first:
#
#   1. An inline marker comment on the SAME line as the match:
#        foo: "{{ bar | default(none) }}"  # default-none-reviewed: <reason>
#      Use this for any new, reviewed case in a file you are free to edit.
#
#   2. The ALLOWLIST below, keyed by "path:line". This exists ONLY because this
#      script was written under a constraint that forbade editing the three
#      files it would otherwise need to annotate inline (see the entries for
#      why). Prefer the inline marker for anything new; add to this list only
#      when the same constraint applies again.
set -euo pipefail

# path:line entries that are known, reviewed instances of the pattern this
# script flags, and are not fixed inline because the file could not be edited
# when this check was added.
#
# roles/amt_baremetal_install/defaults/main.yml:27/30/35 (host, password,
# tls_fingerprint) are required connection values with no viable alternative
# to `default(None)`: `default(omit)` would trade a clear role-level refusal
# in tasks/validate.yml for a less clear module-level one (see issue #87), and
# dropping the default outright would break the amt_host-inventory-variable
# fallback these three exist for. The empty-string-vs-None hazard this script
# exists to catch is real here too, but it is neutralised downstream by using
# `is truthy` (host already does; #87 makes password and tls_fingerprint match
# it) rather than `is none`/`is not none` -- "" is falsy exactly like None, so
# the check does not care which one it got.
#
# roles/amt_baremetal_install/defaults/main.yml:28/34/89 (port, ca_path,
# media_port) are the ACTUAL, currently-unfixed defect issue #87 tracks: these
# are optional/tunable values where None is supposed to mean "let the module
# apply its own default", and port/media_port feed a typed `int` argspec that
# cannot convert "". These three entries are deliberately temporary. #87's own
# fix replaces `default(None)` with `default(omit)` on these lines, at which
# point they stop matching this script's pattern at all and these entries
# become inert. Remove them when #87 lands rather than leaving dead weight.
ALLOWLIST='
roles/amt_baremetal_install/defaults/main.yml:27
roles/amt_baremetal_install/defaults/main.yml:28
roles/amt_baremetal_install/defaults/main.yml:30
roles/amt_baremetal_install/defaults/main.yml:34
roles/amt_baremetal_install/defaults/main.yml:35
roles/amt_baremetal_install/defaults/main.yml:89
'

OPT_OUT_MARKER='# *default-none-reviewed:'

# A quoted scalar (single or double) whose entire content is one `{{ ... }}`
# expression ending in `default(none)`/`default(None)`. `[^{}]*` between the
# opening `{{` and the `|` is what excludes the fixed pattern: a `default(none)`
# used as a value *inside* a larger dict/list literal (e.g.
# `{{ {'k': v | default(none)} }}`) contains a brace before it and does not
# match, because that whole expression -- not the bare filter result -- is what
# crosses the template boundary.
DQ_PATTERN='"\{\{[^{}]*\|[[:space:]]*default\([[:space:]]*[Nn]one[[:space:]]*\)[[:space:]]*\}\}"'
Q="'"
SQ_PATTERN="${Q}\\{\\{[^{}]*\\|[[:space:]]*default\\([[:space:]]*[Nn]one[[:space:]]*\\)[[:space:]]*\\}\\}${Q}"

files=()
if [ "$#" -gt 0 ]; then
    files=("$@")
else
    # Tracked YAML only. Prose in docs/markdown/CHANGELOG.rst that merely
    # *describes* this pattern (this script's own header, issue write-ups,
    # changelog fragments) is not an executable template and would otherwise
    # be a steady source of exactly the false positives the task requires
    # avoiding.
    while IFS= read -r f; do
        files+=("${f}")
    done < <(git ls-files '*.yml' '*.yaml')
fi

raw_matches="$(grep -nE -e "${DQ_PATTERN}" -e "${SQ_PATTERN}" "${files[@]}" 2>/dev/null || true)"

flagged=()
allowlisted_count=0
opted_out_count=0
while IFS= read -r hit; do
    [ -z "${hit}" ] && continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    key="${file}:${line}"

    if printf '%s\n' "${hit}" | grep -qE "${OPT_OUT_MARKER}"; then
        opted_out_count=$((opted_out_count + 1))
        continue
    fi
    if printf '%s\n' "${ALLOWLIST}" | grep -qxF "${key}"; then
        allowlisted_count=$((allowlisted_count + 1))
        continue
    fi
    flagged+=("${hit}")
done <<< "${raw_matches}"

if [ "${#flagged[@]}" -gt 0 ]; then
    echo "ERROR: found ${#flagged[@]} quoted scalar template(s) of the form" >&2
    echo "\"{{ ... | default(none) }}\" (or default(None)) -- see this script's" >&2
    echo "header for why that exact shape is dangerous:" >&2
    echo >&2
    echo "On ansible-core <= 2.18 (this collection's floor is 2.17) that renders" >&2
    echo "as the EMPTY STRING, not None/null -- Jinja finalizes a bare None to" >&2
    echo "text and Ansible's convert_data does not evaluate a bare 'None' back." >&2
    echo "On ansible-core >= 2.19 the same line renders None/null. Measured:" >&2
    echo "  2.17.14 -> \"\" (str), \`is none\` is false" >&2
    echo "  2.19.11 / 2.21.2 -> null (NoneType), \`is none\` is true" >&2
    echo >&2
    echo "This has already caused issue #80 (a test asserted \`is none\` and only" >&2
    echo "failed on the floor), the 0.6.0 qualification-summary bug (a printed" >&2
    echo "\"null\" masked a wrong-key defect), and issue #87 (a role default" >&2
    echo "fails an int argspec, and a security guard silently passes)." >&2
    echo >&2
    echo "Fix: build the value inside a larger expression -- a dict/list" >&2
    echo "literal or to_json -- so only the finished text crosses the template" >&2
    echo "boundary, or use default(omit) if the variable is optional and the" >&2
    echo "intent is \"let the callee's own default apply\". If this is a" >&2
    echo "reviewed exception (a required value with no viable alternative," >&2
    echo "checked downstream with \`is truthy\` rather than \`is none\`), add" >&2
    echo "a trailing '# default-none-reviewed: <reason>' comment on the line." >&2
    echo >&2
    echo "Offending lines:" >&2
    printf '%s\n' "${flagged[@]}" >&2
    exit 1
fi

echo "OK: no quoted-scalar default(none)/default(None) template found (${allowlisted_count} allowlisted, ${opted_out_count} inline-opted-out)."
