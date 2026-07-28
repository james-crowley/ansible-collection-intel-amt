<!--
Thanks for contributing. The checklist below is short on purpose — every item is
something that has actually caught a real bug in this collection, not
box-ticking.
-->

## What this changes

<!-- And why. If it fixes an issue, "Closes #N". -->

## How it was verified

<!--
Paste the actual results rather than asserting they pass. "Tests pass" is not
reviewable; the counts and exit codes are.
-->

```
pytest tests/unit -q        ->
ansible-test sanity --venv  ->
ansible-test integration    ->
```

## Checklist

- [ ] `ansible-test sanity --venv` exits 0. **Run it against the oldest supported
      ansible-core, not just the newest** — sanity behaviour differs between them,
      and a pep8 rule that only 2.17/2.18 enforce has slipped through before.
- [ ] `ansible-test integration --venv` exits 0. This tier is what catches a
      missed consumer of a changed return value.
- [ ] `ruff check` / `ruff format --check` / `yamllint` / `ansible-lint --offline`
      are clean.
- [ ] A changelog fragment is added under `changelogs/fragments/`.
- [ ] Nothing in a message, receipt, fact, or state file can contain a credential.
      If you added an error path, confirm it goes through `errors.py`'s redaction.
- [ ] If you changed a module's return shape, every consumer is updated:
      `roles/`, `tests/integration/targets/`, `tests/hardware/`, `docs/`, `README.md`.
- [ ] Documentation says only what is actually true. If something is unverified
      against real firmware, it is described that way — see
      `docs/capability-matrix.md`.

## If this touches the wire protocol

- [ ] `docs/protocol-notes.md` is updated, and cites evidence (a firmware
      response, a fixture, or a reference implementation) rather than inference.
- [ ] You have considered whether a mock server *could* catch a regression here.
      Several real bugs were invisible to the mocks because a conformant parser
      accepts what firmware rejects — if that applies, say so and note it for
      hardware qualification.

## If this is destructive

Power, boot, and media changes can strand a machine.

- [ ] Check mode makes no mutation, and there is a test asserting it.
- [ ] An uncertain outcome is reported as `indeterminate` rather than retried.
