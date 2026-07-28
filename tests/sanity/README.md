<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Sanity test ignores

One `ignore-<ansible-core-version>.txt` per version we sanity-test against.
Entries must be a single line with an optional *trailing* comment; a standalone
comment line fails the `ignores` sanity test itself.

Keep this list short. Every entry is a rule we have chosen not to enforce, so
each needs a reason that survives review.

## `pep8:E704` on `plugins/module_utils/redirection.py` (2.17, 2.18)

`E704` is "multiple statements on one line (def)". It fires on the `Protocol`
method stubs in `redirection.py`, written as:

```python
def recv(self, bufsize: int) -> bytes: ...
```

This is suppressed rather than reformatted because the two tools we run disagree
irreconcilably:

- `ruff format` **collapses** a `...` body onto one line, matching Black's stable
  style for dummy implementations. Expanding the stubs by hand is undone by the
  next format run — verified: the expansion was silently reverted, and the
  following CI run failed on the same four lines.
- `ansible-test sanity --test pep8` on **2.17 and 2.18** rejects exactly that
  form.

ansible-core **2.19 no longer reports E704 at all**, which suggests upstream also
treats the rule as obsolete for this construct. So the ignore is scoped to the
two versions that still flag it, and will disappear when the support floor moves
past them.

Note it is deliberately *not* in an `ignore-2.19.txt`: an ignore for a rule that
does not fire is itself reported by the `ignores` sanity test as unnecessary.

## Why this was caught late

Local verification only ever ran sanity against ansible-core 2.19, while CI runs
2.17, 2.18 and 2.19. Sanity behaviour genuinely differs between them — this
entry exists because of one such difference. When changing anything a sanity test
inspects, run at least the oldest supported version locally too:

```bash
python3 -m venv /tmp/v217 && /tmp/v217/bin/pip install "ansible-core~=2.17.0"
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH" && /tmp/v217/bin/ansible-test sanity --venv
```
