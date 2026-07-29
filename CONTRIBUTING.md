<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Contributing

Practical instructions for working on this collection, plus the traps that have
actually cost real time. If something here disagrees with `docs/testing.md`, that
file is the more detailed reference on the testing tiers themselves — this document
is about the day-to-day mechanics of making a change.

## Before you start: stage the collection tree

`ansible-test` insists the collection live at
`<root>/ansible_collections/james_crowley/intel_amt/`, regardless of where you
actually checked the repository out. `scripts/setup-collection-tree.sh` materialises
that layout and prints the resulting path:

```bash
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH"
```

Two things about this that will cost you time if you miss them:

1. **It copies, not symlinks.** `ansible-test` resolves paths in ways that make a
   symlinked collection root behave inconsistently across `ansible-core` versions, so
   this script does a real `rsync`/`tar` copy instead. The direct consequence: **the
   staged tree goes stale the moment you edit a source file again.** Re-run the script
   after every edit, or every subsequent `ansible-test`/`pytest` invocation is testing
   a snapshot that no longer matches your working tree — a genuinely confusing failure
   mode, because the error messages reference line numbers and content that look
   right until you check the timestamp.
2. **Set `COLLECTION_BUILD_ROOT` when more than one checkout might stage
   concurrently** (parallel CI jobs, several worktrees, more than one agent or
   contributor building on the same host at once). Left unset, the script derives a
   build root from a checksum of the repository's own path
   (`${TMPDIR:-/tmp}/ansible-collection-build-<hash>`) — which means two *different*
   checkouts at the *same* path (e.g. two worktrees created the same way, or two CI
   jobs on the same executor image) can collide on the same build root and clobber
   each other mid-run. The symptom is exactly as confusing as the stale-tree problem
   above: sanity or unit-test failures naming files that are not present in the branch
   you are actually looking at. Set `COLLECTION_BUILD_ROOT` to something
   checkout-specific (a path under the checkout itself, or one salted with a job/PID)
   whenever there is any chance of concurrent staging:

   ```bash
   export COLLECTION_BUILD_ROOT=/tmp/my-build-root
   COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
   ```

## Install the tooling

Everything below assumes `ansible-core` plus the pinned linters and release
tooling are on your `PATH`. There is one file for that, and CI's `lint` job
installs from the same file, so the ruff that judges your PR is the ruff you ran:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install "ansible-core~=2.17.0" -r requirements.txt -r requirements-dev.txt
```

`requirements-dev.txt` pins exact versions on purpose — `ruff` in particular
changes which findings it reports between patch releases (0.15.5 reports three
`S603` findings in the unit tests that 0.16.0 does not), so an unpinned install
makes a lint result depend on the day it ran. Bump the pins in their own PR and
fix whatever the new version finds there.

`ansible-core~=2.17.0` above is the collection's declared floor; anything in
`>= 2.17` works locally. Use the floor if you want your local run to match the
oldest series CI tests.

## Local verification sequence

Run this before opening a PR — it is the same sequence CI runs, minus the
version/Python matrix:

```bash
# From the repository root:
export COLLECTION_BUILD_ROOT=/tmp/my-build-root   # see above
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH"

ansible-test sanity --venv --python 3.12
ansible-test units  --venv --python 3.12
ansible-test integration --venv --python 3.12   # against local mock servers only

# Back at the repository root:
cd -
yamllint -c .yamllint .
ruff check plugins tests
ruff format --check plugins tests

# ansible-lint resolves `james_crowley.intel_amt.*` FQCNs by looking in the
# collections path, and unlike ansible-test it does not stage the tree itself.
# Without this symlink every module reference in tests/hardware/*.yml fails
# syntax-check[unknown-module], a rule that cannot be silenced with a `# noqa`.
# CI does exactly this in the lint job.
mkdir -p ~/.ansible/collections/ansible_collections/james_crowley
ln -sfn "$(pwd)" ~/.ansible/collections/ansible_collections/james_crowley/intel_amt
ansible-lint --offline

ansible-galaxy collection build --output-path /tmp/dbuild --force
```

`3.12`, not `3.13`: CI runs sanity and the mock integration suite on 3.12, and
`docs/testing.md` and the README use 3.12 throughout. `ansible-test` will happily
run on 3.13 — the units matrix covers it — but if you are reproducing a CI
failure, match the version CI used.

### Running `pytest` directly, for a fast inner loop

`ansible-test units` builds a fresh virtualenv every invocation, which is the
right thing for CI and far too slow when you are iterating on one test. You can
run `pytest` yourself, but **not from the repository root** — every test imports
its subject as `ansible_collections.james_crowley.intel_amt.plugins.…`, which
only resolves if the collection is sitting inside an `ansible_collections/`
directory that is itself on `sys.path`. From the root you get:

```
ModuleNotFoundError: No module named 'ansible_collections'
```

That is not a missing dependency and installing something will not fix it. It
needs the staged tree, run from inside it, with `PYTHONPATH` pointing at the tree
*root* (the directory containing `ansible_collections/`, i.e. two levels above
the collection):

```bash
export COLLECTION_BUILD_ROOT=/tmp/my-build-root
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH"
PYTHONPATH="${COLLECTION_BUILD_ROOT}" pytest tests/unit -q      # 559 passed
```

`pytest tests/unit/plugins/modules/test_amt_boot.py -k some_name` narrows it from
there. Two reminders that follow from the staging being a **copy**: re-run
`setup-collection-tree.sh` after every source edit, and remember you are editing
files in the repository while running files in `/tmp` — a "my fix had no effect"
moment here is almost always a stale tree.

`ansible-test sanity` is currently 24/24 exit 0 — it must stay exit 0. If your change
adds a sanity finding, fix it or get an explicit, justified entry in
`tests/sanity/ignore-*.txt`; do not silence it by restructuring code around the
checker without understanding what it was catching.

`ansible-test --venv`, not `--docker`: the CircleCI Docker executor cannot bind-mount
the working directory into a `setup_remote_docker` container, which is what
`ansible-test --docker` requires. See `docs/testing.md` if you need `--docker`
specifically to reproduce upstream Ansible's own sanity containers — that needs a
`machine` executor, not the default Docker one.

## Practical traps

These are not theoretical — each one produced a real, confusing failure at some point
during this collection's development.

### `ansible-core >= 2.17` only, and there is no dual-compatible sanity boilerplate

The sanity-test boilerplate requirement changed **incompatibly** at `ansible-core`
2.17. Every module and `module_utils` file needs:

```python
from __future__ import annotations
```

at the top (after the license header, before any other import). The older
`from __future__ import absolute_import, division, print_function` plus a
module-level `__metaclass__ = type` pair — which is what pre-2.17 sanity wants — is
now **rejected** by 2.17+'s sanity checks. There is no single form that passes sanity
on both an old and a new `ansible-core`. This is why the collection's floor is
`ansible-core >= 2.17`, full stop — supporting anything older would require picking
one boilerplate form and failing sanity on the other side of the line.

### Any doc string containing a colon-space must be a block scalar

If a `DOCUMENTATION`/`RETURN`/doc-fragment YAML string contains a literal `: ` (colon
followed by a space) — for example `C(delegate_to: localhost)` — it **must** be
written as a YAML block scalar (`>-` or `|-`), never a plain scalar. In a plain
scalar, YAML reads the embedded colon-space as a mapping key/value separator and the
`yamllint` sanity test fails. See `plugins/doc_fragments/connection.py`'s `notes`
section for the canonical example and its own comment explaining why.

### `ansible-core >= 2.21` needs `_ANSIBLE_PROFILE = "legacy"` in unit tests

Unit tests that drive `AnsibleModule` directly by setting
`basic._ANSIBLE_ARGS` (see the `_set_module_args()` helper duplicated across
`tests/unit/plugins/modules/test_*.py`) must also set:

```python
basic._ANSIBLE_PROFILE = "legacy"
```

`ansible-core >= 2.21` requires this explicit args-decoding profile alongside
`_ANSIBLE_ARGS`; older cores simply ignore the attribute, so setting it
unconditionally is harmless across the whole supported range. Forgetting it only
breaks on the newest `ansible-core` in the test matrix, which makes it easy to miss
locally if you are not pinned to that version.

### Never add an inline `# noqa` for a rule `pyproject.toml` already ignores per-file

`ruff`'s `RUF100` (unused `noqa` directive) is enabled, so a `# noqa: X` whose finding
was already suppressed at config level is itself an error. Check
`[tool.ruff.lint.per-file-ignores]` before reaching for an inline comment. The two that
have actually bitten:

- **`E402` in `plugins/modules/*.py`.** Ansible's module convention requires the
  `DOCUMENTATION`/`EXAMPLES`/`RETURN` string literals at the top of the file, before any
  import — `ansible-doc` and the sanity toolchain both depend on that ordering — so
  `E402` is ignored for those files project-wide.
- **`S603` (subprocess-without-shell-check) anywhere under `tests/**`.** Several tests
  spawn a helper process with a fully-controlled literal argv. Note this one is
  version-sensitive: `ruff` 0.15.5 reports `S603` in the unit tests and 0.16.0 does not,
  which is part of why `requirements-dev.txt` pins `ruff` exactly.

Whichever direction you hit it from, the fix is the same: one suppression, at one level,
not both.

### Bare `_` as a variable name is rejected by `ansible-test`'s `pylint` sanity config

Use a named-but-unused convention instead, e.g. `_unused_tag`, `_unused_attempt` — see
`plugins/module_utils/tls.py`'s `_parse_der_certificate()` for an example
(`_unused_tag, certificate_content, _unused_end = _der_read_tlv(...)`) and its comment
explaining why bare `_` was avoided there specifically.

## Conventional commits and changelog fragments

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, …). Keep commits atomic —
one logical change per commit, with a real body explaining *why*, not just *what*.

**Every user-facing change needs a changelog fragment** in `changelogs/fragments/`,
following the `antsibull-changelog` format configured in `changelogs/config.yaml`.
Name it after your change (`changelogs/fragments/<something-descriptive>.yml`) — the
filename is not load-bearing, only the contents are. This document deliberately does
not point you at a specific existing fragment as an example: `changelogs/config.yaml`
sets `keep_fragments: false`, so `antsibull-changelog release` **deletes** every
fragment once it has folded it into `CHANGELOG.md`/`CHANGELOG.rst`. Any filename named
here would be a dead link after the next release. Look in `changelogs/fragments/` for
whatever is currently unreleased, or at a released entry in `CHANGELOG.md`. The shape:

```yaml
---
bugfixes:
  - "amt_info - report the AMT firmware version from ``CIM_SoftwareIdentity`` ... (https://github.com/james-crowley/ansible-collection-intel-amt/issues/18)."
```

Valid top-level sections (from `changelogs/config.yaml`): `major_changes`,
`minor_changes`, `breaking_changes`, `deprecated_features`, `removed_features`,
`security_fixes`, `bugfixes`, `known_issues`. Use Ansible doc markup (`` C() ``,
`` O() ``, `` V() ``, `` M() ``) inside fragment entries, exactly as in module
`DOCUMENTATION`/`RETURN` strings, and link back to the issue or PR the change
addresses. Purely internal changes (test-only refactors, CI tweaks with no
user-visible effect) do not need a fragment, but if in doubt, add one — a missing
fragment is a silent gap in the release notes, and an unnecessary one costs nothing.

## Hardware tests: two gates, deliberately

Hardware-in-the-loop tests power-cycle and reimage real machines, so they are gated
twice — see `docs/testing.md` for the full qualification-order procedure once you are
actually running them:

1. **Pipeline parameter.** The `hardware` CircleCI workflow only exists when the
   pipeline is explicitly triggered with `run-hardware-tests=true`. An ordinary push
   cannot reach it at all.
2. **Manual approval.** Even then, a human must approve the `hardware-approval` job in
   the CircleCI UI before anything touches a machine.

Do not try to shortcut either gate to "just test something quickly" — the entire
point is that a mistake here power-cycles hardware and can leave a machine in a boot
state that needs physical or KVM recovery (see `docs/testing.md`, "If a machine ends
up in a bad boot state").

## Scope reminders

- `tests/hardware/inventory.yml` is gitignored and must never contain real hostnames,
  credentials, or certificate fingerprints in a commit — see `.gitignore` and commit
  only an `.example` file if you add new hardware-test scaffolding.
- Never commit real boot media (`*.iso`, `*.img` are gitignored except under test
  fixture directories).
- If you touch `docs/protocol-notes.md`, treat the byte layouts and field mappings
  there as normative — "improving" them without a firmware/reference source to back
  the change is exactly the kind of unverified drift the
  [Capability matrix](docs/capability-matrix.md) exists to call out.
