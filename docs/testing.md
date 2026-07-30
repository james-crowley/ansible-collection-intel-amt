<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Testing

Three tiers, in increasing cost and risk:

| Tier | Needs | Runs where | Risk |
|---|---|---|---|
| Sanity + unit | nothing | every push | none |
| Mock integration | local fixture servers | every push | none |
| Hardware-in-the-loop | real AMT machines | self-hosted runner, opt-in | **power-cycles hardware** |

## The collection path requirement

`ansible-test` insists the collection live at
`<root>/ansible_collections/<namespace>/<name>/`, regardless of where the
repository is checked out. `scripts/setup-collection-tree.sh` materialises that
layout and prints the path:

```bash
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH"
```

It **copies** rather than symlinks, because `ansible-test` resolves paths in ways
that make a symlinked collection root behave inconsistently across ansible-core
versions. Consequence worth remembering: **re-run the script after every edit**,
or you will be testing a stale copy.

## Sanity and unit tests

```bash
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH"
ansible-test sanity --venv --python 3.12
ansible-test units  --venv --python 3.12
```

### What the CI matrix actually covers

It is **not** the full cross product of three ansible-core versions and four
Pythons. Writing it down because "2.17/2.18/2.19 × 3.10-3.13" is the obvious
shorthand and it would overstate coverage by half:

| Job | Python | ansible-core | Cells |
|---|---|---|---|
| `sanity` | 3.12 only | 2.17, 2.18, 2.19, 2.20, 2.21 | **5** |
| `units` | 3.10, 3.11, 3.12, 3.13 | 2.17, 2.19, 2.21 | **8** after excludes |
| `sanity-devel` | 3.13 | `devel` branch | **1**, weekly only — see below |

`sanity` covers **every currently-supported upstream core** (2.19, 2.20, 2.21) plus
the two EOL ones this collection still declares. That second part is an obligation
rather than a courtesy: the collection requirements state that if a collection
supports EOL core releases it MUST run sanity against all of them, so `requires_ansible:
'>=2.17.0'` is what puts 2.17 and 2.18 in this table. Raising the floor would delete
cells rather than add them — worth knowing, because the intuition runs the other way.

Every `units` exclude is forced by an upstream support range, not chosen:

| Excluded | Because |
|---|---|
| 3.13 × 2.17 | 3.13 controller support arrived in 2.18 |
| 3.10 × 2.19 | 2.19 requires Python 3.11+ |
| 3.10, 3.11 × 2.21 | 2.21 requires Python 3.12+ |

**ansible-core 2.18 and 2.20 have no unit-test cell.** Both are covered by `sanity`,
and 2.18 additionally by the hardware jobs, which pin `ansible-core~=2.18.18` in the
lab virtualenv (see "Runner Python version" below) — so 2.18 is the version the
hardware tier actually executes on, while the unit tier brackets it from either side.
That is a deliberate cost/coverage trade: a full cross-product would be twenty cells,
and the versions chosen for `units` are the floor, the middle and the newest, which is
where a Python-version incompatibility actually shows up.

### The `devel` canary

`sanity-devel` runs `ansible-test sanity` against ansible-core's `devel` branch. It is
**advisory and weekly, not part of the PR path**, which is deliberate on both counts.

The collection requirements mandate testing against `devel` or `milestone` "in every PR
or on a scheduled basis of at least once per week", and the weekly option is the right
one here: `devel` breaks for reasons that are upstream's business, and a red PR check
nobody can act on teaches people to ignore red checks. It runs on the newest
interpreter available so that a controller-Python floor rising upstream surfaces as a
real failure rather than an install error.

The value is **lead time**. New sanity requirements land in `devel` first — the
boilerplate change that set this collection's 2.17 floor is exactly that kind of event
— so this is how such a change is found before it becomes a release blocker.

It is triggered by the `run-devel-canary` pipeline parameter, which the weekly schedule
sets. A failure there is a signal to investigate, never a reason to block a merge.

### Why `--venv` and not `--docker`

`ansible-test --docker` needs to bind-mount the collection source tree into its
test container. On a CircleCI Docker executor that is impossible: steps run
inside a container, and `setup_remote_docker` provides a *separate* VM with its
own filesystem, so the working directory does not exist on the Docker host and
the bind mount cannot resolve. `--venv` sidesteps the problem entirely and is
faster to start, which matters across a version matrix.

If you specifically need `--docker` (to reproduce upstream Ansible's own sanity
containers), use a `machine` executor instead — a real VM with a local Docker
daemon — not `setup_remote_docker`.

### Running a subset while iterating

```bash
# One sanity test
ansible-test sanity --venv --python 3.12 --test validate-modules

# One unit test file, fast loop with a plain venv
python3 -m venv /tmp/amtvenv && /tmp/amtvenv/bin/pip -q install pytest requests
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
BUILD_ROOT="$(dirname "$(dirname "$(dirname "$COLLECTION_PATH")")")"
cd "$COLLECTION_PATH"
PYTHONPATH="$BUILD_ROOT" /tmp/amtvenv/bin/python -m pytest tests/unit -q
```

`PYTHONPATH` must point at the directory *containing* `ansible_collections/`, so
that `from ansible_collections.james_crowley.intel_amt...` imports resolve.

## Mock integration tests

There is no AMT hardware in CI, so correctness comes from deterministic local
fixture servers that speak both protocol planes:

- a **mock WS-Man server** — HTTP Digest challenge/response, TLS with a generated
  self-signed certificate so both CA and fingerprint-pinning paths are exercised,
  canned responses per resource URI, and fault injection for AMT error codes,
  malformed SOAP, HTTP 401, and timeouts both before and after the request body
  is transmitted;
- a **mock IDE-R server** — the binary redirection and IDE-R protocols: start
  session, auth-type query, digest challenge, `OPEN_SESSION` reply with a
  configurable `readbfr`, SCSI command issuance, and a write path that verifies
  bytes actually land in the backing image.

```bash
ansible-test integration --venv --python 3.12
```

**The `integration-mock` CI job pins ansible-core 2.19.** Run the integration suite
against 2.19 as well as whatever you have installed: on 2.19 the controller attaches
an `exception` key to every failed task result, while on 2.17 it appears only at
`-vvv`, so a target asserting on that key passes on one line and fails on the other.
Prefer asserting on `error_class` — a real crash on 2.19 emits no `error_class` at all.


These must pass with no network access and no hardware. The timeout-classification
and multi-frame-write paths in particular can only be tested this way — they are
invisible to unit tests of pure functions and impractical to trigger on demand
against real firmware.

## Scheduled drift detection

A weekly CircleCI schedule (`weekly-drift-detection`, Mondays 11:00 UTC) runs the
standard `test` workflow against `main`. It exists because some breakage arrives
without anyone pushing: a new `ansible-core` point release, a PyPI dependency
change, or a rebuilt `cimg/python` image. A repository with no scheduled run only
learns about those on the next unrelated commit.

It is safe by construction: `run-hardware-tests` defaults to `false`, so a
scheduled pipeline can only ever run the `test` workflow and never reaches lab
hardware.

Scheduled triggers are **not** expressible in `.circleci/config.yml` — they live in
project settings, so they are easy to forget when reasoning about coverage from the
repository alone. Inspect with:

```bash
circleci api "/api/v2/project/gh/james-crowley/ansible-collection-intel-amt/schedule"
```

## Hardware-in-the-loop tests

These power-cycle and reimage real machines. Nothing here runs by accident:

- the `run-hardware-tests` pipeline parameter, false by default;
- a manual approval before the read-only stages;
- **a separate manual approval before each mutating stage** (power, media,
  writable, PXE), so every escalation is confirmed independently;
- the `amt-lab-runner` context, restricted by project ID;
- `branches: only: main`;
- and for stage 7, a `pxe-prereqs-confirmed` parameter attesting that DHCP/boot
  services exist, since no technical check can establish that.

### Gate 1: pipeline parameter

The `hardware` workflow only exists when the pipeline is triggered with
`run-hardware-tests=true`. An ordinary push cannot reach it:

```bash
curl -X POST "https://circleci.com/api/v2/project/<project-slug>/pipeline" \
  -u "${CIRCLE_TOKEN}:" \
  -H 'Content-Type: application/json' \
  -d '{"parameters": {"run-hardware-tests": true}}'
```

### Gate 2: manual approval

Even then, a human must approve `hardware-approval` in the CircleCI UI before any
job touches a machine.

### Runner setup

Hardware jobs target a self-hosted machine runner inside the lab network, so no
inbound ports need opening — the agent polls outward.

```bash
circleci runner resource-class create crowley/amt-runner "Intel AMT hardware runner" --generate-token
# then install the machine runner 3 agent on the lab host with that token
#
# The agent must be able to create its working directory. A read-only root
# filesystem, or a work volume the runner UID cannot write, makes every job die
# in ~100ms with no steps executed and no error surfaced -- see issue #26.
```

The job declares:

```yaml
machine: true
resource_class: crowley/amt-runner
```

### Runner Python version

**What the hardware jobs run now.** The lab runner host has Python 3.12
installed alongside its system Python 3.10, and the hardware jobs pin
`ansible-core~=2.18.18` in a workspace virtualenv built from **Python 3.12
explicitly**. 2.18.18 is the first release that fixes GHSA-w8p5-mx5w-cpqj
[HIGH] (argument injection in `ansible-galaxy role install`); the 2.17 line is
EOL and has no fix, so staying on it was not an option. 3.12 rather than the
newest available Python for two reasons: ansible-core 2.18's supported
controller range ends at 3.13, and 3.12 is the newest version that can still run
ansible-core 2.17 — the collection's `requires_ansible` floor — so the same
interpreter can reproduce a floor run by hand on that host.

The system `python3` is still 3.10 and stays that way, so
`install-lab-ansible-venv` never uses it. The command probes for `python3.12`,
falls back to `python3.11`/`python3.13`, and **fails immediately** — naming what
it looked for and what it found — if none exists, rather than letting pip
produce a confusing resolution error. It echoes the interpreter it chose, so
every job log records which one actually ran. `python3.14` is deliberately not a
candidate: ansible-core 2.18 does not support it.

**What the recorded qualifications ran on.** The Tier 3 evidence in
`docs/capability-matrix.md` comes from three runs across two environments, and no
record is retroactively edited — each states the environment its own run used:

- **Machine 1 (AMT 16.1.30), 2026-07-28** — all eight stages, on Python 3.10 with
  ansible-core 2.17.
- **Machine 2 (AMT 19.0.5), 2026-07-29** — all eight stages, on Python 3.12.13,
  ansible-core 2.18.18, the configuration described above. This was the first
  hardware run to reach the lab at all under it: a `.circleci/config.yml` parse
  error meant every hardware trigger since v0.1.0 errored before any job started,
  so nothing had exercised the 3.12/2.18 path until this run.
- **Machine 1 again, 2026-07-29** — the read-only stages only (1, 3, 8), via
  `hardware-tests`, limited with `hardware-limit=amt-lab-01`, on the same
  ansible-core 2.18.18 lab virtualenv `install-lab-ansible-venv` builds for every
  hardware job. Nothing was mutated, and none of the stage 4-7 approvals were
  requested. Its purpose was narrow: read machine 1 with v0.2.0's fact code, which
  its 2026-07-28 evidence predated. Machine 1's mutating result therefore still
  rests on the 2026-07-28 run, in the environment recorded for it above.

Machine 2's run **clears GHSA-w8p5-mx5w-cpqj [HIGH] for the lab runner**: the 2.17
line it previously used is EOL and permanently affected, and the runner is now
demonstrably executing on 2.18.18, the first release carrying the fix.

The collection still supports a 3.10 controller for consumers
(`requires_ansible: '>=2.17.0'` is unchanged, and the unit matrix still covers
3.10). Two 3.11-only APIs (`enum.StrEnum`, `datetime.UTC`) reached `main` before
that was noticed, because the unit matrix once started at 3.11; the matrix is
what guards 3.10 now, not the lab runner.

### Inventory and credentials

`tests/hardware/inventory.yml` is **gitignored**. Real hostnames, AMT
credentials, and certificate fingerprints must come from the runner's
environment, never the repository. Commit only an `.example` file.

### Qualification order

**Eight numbered stages.** Run them in order and never in parallel; each is a gate
on the next. Stage 2 is the odd one out: it has **no playbook of its own**, because
it is a human cross-check performed on the output of stage 1's playbook
(`qualify_readonly.yml`). That is why CI runs seven playbooks across eight stages.

1. Read-only `amt_info` against each target.
2. Compare the reported facts against an independent power probe and reviewed
   BIOS inventory — this is what catches an inventory/reality mismatch before it
   becomes a reset of the wrong machine. **No playbook**: `qualify_readonly.yml`
   prints the firmware-reported UUID, and a human reviews it and records
   `amt_expected_uuid` so every later run cross-checks it automatically. That
   automatic comparison is live for machine 2 as of 2026-07-29 and matched. Note
   what it can and cannot do: recorded from a value this collection observed, it
   catches **drift** in the inventory-to-endpoint binding, not independent machine
   identity — the human step 2 asks for is what supplies that, and the booted OS's
   own `dmidecode -s system-uuid` is the independent source if you want one.
3. Check-mode power and boot plans. No mutation.
4. Attended power on/off.
5. IDE-R attach with a small test ISO; confirm boot handoff.
6. Writable-image test: confirm the device accepts writes and the bytes land.
7. One-time firmware PXE, only after DHCP/boot-service and NIC prerequisites are
   separately proven.
8. Idempotent re-probe.

**Qualify one machine through all eight stages first.** A second machine proves
repeatability. Never cut both over to a new stage at once — if a firmware quirk
bricks a boot configuration, you want a known-good machine to compare against.

### If a machine ends up in a bad boot state

One-shot boot is single-use, so a plain power cycle usually clears it. If the
machine is stuck, the recovery path is out-of-band and manual: attach a KVM
console (MeshCentral is useful here), enter MEBx, and reset the boot
configuration. Keep that path available before running step 5 for the first time
on any new machine.

## What CI does not prove

Being explicit, because the gap matters:

- ~~No test here proves real firmware accepts our `AMT_BootSettingData` `Put`.~~
  **Now proven on both lab generations.** Stages 5 and 7 armed a one-shot boot
  against AMT 16.1.30 and, on 2026-07-29, against AMT 19.0.5 — which exercises the
  full `Put` including the field delete-list in
  [`protocol-notes.md`](protocol-notes.md) §2.5. Retained here because the
  reasoning still holds for every *other* firmware generation, and because the
  same call did reject an empty `<Source/>` — so this firmware demonstrably
  enforces its schema, which is what makes the passing result meaningful.
- Mock servers implement the protocol *as we understand it*. A shared
  misunderstanding between implementation and mock passes both.
- Real firmware differs across AMT generations and SKUs. Anything version
  dependent is unverified until step 1 runs on that generation.
- **Nothing in the hardware tier covers `amt_event_log` or `amt_log_clear`.** Five
  of the collection's seven modules are hardware-qualified; those two are not, on
  any generation. The eight stages predate both modules and none was extended to
  reach them, so their `AMT_MessageLog` iteration, record decode and `ClearLog`
  invocation rest entirely on the unit and mock tiers plus a captured firmware
  fixture. See Tier 4 in [`capability-matrix.md`](capability-matrix.md).

This collection is protocol-complete, test-covered, and **hardware-qualified on two
machines for five of its seven modules** — precisely: **all eight stages against AMT
16.1.30 (`amt-lab-01`, 2026-07-28) and all eight against AMT 19.0.5 (`amt-lab-02`,
2026-07-29)**, each run limited to the machine it qualified (`hardware-limit`), so
neither touched the other.
A read-only re-run against machine 1 on 2026-07-29 then read that machine with
v0.2.0's fact code, which closed the last coverage difference between the two:
`amt_info`'s network and system-state facts are now confirmed populated on both
generations rather than on 19.0.5 alone. Qualification found six defects the first
two tiers could not have found, which is the concrete argument for this tier existing
rather than a theoretical one.

What it still does not cover is listed as Tier 4 in
[`capability-matrix.md`](capability-matrix.md): a non-zero IDE-R write, whether a
PXE exchange actually occurred, AMT's internal one-shot role bit, the sleep and
hibernate power actions, whether either endpoint answers WS-Man at all while
powered off (both report `wake_on_lan_capable: true`, but no stage powers a machine
off, confirms it, and then tries to reach it), and any firmware generation other than
those two.
