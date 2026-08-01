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
`docs/capability-matrix.md` comes from four runs across two environments, and no
record is retroactively edited — each states the environment its own run used.
That document cites each run by workflow and job; this list is about interpreters:

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
- **Both machines, 2026-07-30** — the read-only stages only (1, 1b, 3, 8), with no
  `hardware-limit` set, on the same ansible-core 2.18.18 lab virtualenv. Nothing was
  mutated and none of the stage 4-7 approvals were requested. Its purpose was to read
  both machines with the 0.5.0 hardware-inventory code, which every earlier run
  predated, and it is the sole evidence for the inventory rows in Tier 3.
- **Machine 1, stages 9-12, 2026-07-31** — the first real-firmware run of any of the
  four newest qualification stages, all four against `amt-lab-01` only, all four
  passed. CircleCI **pipeline 208**, workflow `282b6692-94a2-481b-aacf-32c2cb1b2dfe`;
  jobs `hardware-tests` (2568, stage 9), `hardware-log-clear` (2574, stage 10),
  `hardware-sleep-hibernate` (2576, stage 11), `hardware-wake-from-off` (2578, stage
  12). Machine 2 was not touched by this run. This is also the first run whose
  published evidence carries a per-file SHA-256 digest manifest
  (`hardware-evidence/SHA256SUMS`) -- see `docs/capability-matrix.md`'s Tier 3 audit-
  limits subsection for what that does and does not let a reader check for this run
  versus the four before it.
- **Both machines, stage 9 only — the run that found issue #105.** Stage 9 was re-run
  against `amt-lab-01` after its stage-10 clear had emptied the log, and against
  `amt-lab-02`. **Machine 1 failed its accounting assertion** — `records_read: 223`
  against `total_records: 18`, because firmware pads its `GetRecords` response with a
  zero-filled entry per record slot the clear had freed and `amt_event_log` was counting
  them. Machine 2 passed cleanly, 110 records. Machine 1's reading is CircleCI job
  **2976**, evidence file `hardware-evidence/amt-lab-01-qualify_event_log.json`; machine
  2's clean read is on record for **pipeline 226**. No workflow UUID and no pipeline
  number is recorded for job 2976, and none is inferred from ordering. This is the only
  run listed here that did not end green, and the defect it found is the seventh in
  `docs/capability-matrix.md`'s hardware-defect table.
- **Machine 2, stages 10-12.** The last gap among the newest four stages: `amt-lab-02`
  had never run `amt_log_clear`, sleep/hibernate, or wake-from-off. All three now have,
  and all three passed, with the same outcomes machine 1 recorded: `amt_log_clear`
  archived and cleared 110 records, with an independent re-read confirming empty;
  sleep-light/sleep-deep/hibernate were all `firmware_refused`; wake-from-off answered
  WS-Man 3/3 and accepted a wake request. CircleCI pipeline **244**, workflow
  `b7865873-40b2-43b5-825f-be5ebba704fc`; jobs `hardware-tests` (**3158**, the read-only
  stage 9/1/3/8 floor this run's approvals gate on), `hardware-log-clear` (**3168**,
  stage 10), `hardware-sleep-hibernate` (**3170**, stage 11), `hardware-wake-from-off`
  (**3172**, stage 12). `SHA256SUMS` is present in jobs 3168, 3170 and 3172's
  artifacts, and job 3170's was downloaded and verified directly (`shasum -a 256 -c
  SHA256SUMS` reported `amt-lab-02-qualify_sleep_hibernate.json: OK`) -- checked
  against the published bytes, not merely confirmed present. One refinement: the
  independent re-read taken immediately after this run's clear showed `empty_slots: 0`,
  unlike machine 1's later read (after partial refill), which showed 205 -- see
  `docs/capability-matrix.md`'s stage 9/10 subsection for what that does and does not
  establish about timing versus firmware generation.

None of the first four runs above cover stages 9-12 at all -- "all eight" in each of
those bullets means all eight that existed on that date, not all twelve that exist
now. The fifth run covers stages 9-12, but only on machine 1; the sixth adds stage 9
on machine 2; the seventh adds stages 10-12 on machine 2, closing the last per-stage
machine gap among stages 9-12. See "Qualification order" below.

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

**Twelve numbered stages across eleven playbooks.** Run them in order and never in
parallel; each is a gate on the next. Stage 2 is the odd one out: it has **no
playbook of its own**, because it is a human cross-check performed on the output of
stage 1's playbook (`qualify_readonly.yml`).

1. Read-only `amt_info` against each target. Since 0.5.0 the same playbook also runs
   **stage 1b**, a second read-only `amt_info` call with
   `gather_subset: [config, hardware]` for the inventory subsets, with its own
   evidence file. It is numbered `1b` rather than a new top-level number because it
   is read-only and gates nothing, so it does not need one of its own.
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
9. Read-only `amt_event_log`: follows the `GetRecords` iteration to completion and
   checks that every record returned decodes cleanly under the 21-byte layout this
   collection assumes, with a specific check against the wrong-byte-order failure
   mode for the little-endian timestamp. Shares stage 1/3/8's approval gate rather
   than earning its own, because a read is not a mutation.
10. `amt_log_clear` — **irreversible**. Reads and archives the log to disk, confirms
    the archive is actually there, only then clears, then independently re-reads to
    confirm empty. Own approval gate. **Read
    [`PREFLIGHT.md`](../tests/hardware/PREFLIGHT.md) before approving.**
11. Sleep-light, sleep-deep, hibernate. Every attempt is classified
    `confirmed_transition` / `os_did_not_transition` / `firmware_refused`, since
    whether the target OS supports or enables a given ACPI state is outside AMT's
    control; only a failure to restore back to `on` is fatal. Own approval gate. See
    [`PREFLIGHT.md`](../tests/hardware/PREFLIGHT.md).
12. Wake-while-powered-off: power off, then attempt to reach and wake the endpoint
    over WS-Man while it reports off. The last stage in the chain, own approval
    gate. **There is no channel available in CI that independently confirms the
    host is genuinely, physically off** — see
    [`PREFLIGHT.md`](../tests/hardware/PREFLIGHT.md) for exactly what a run of this
    stage does and does not establish.

**Stages 9-12 have each run against real hardware on machine 1** (pipeline 208,
2026-07-31) — see "What the recorded qualifications ran on" above. All four passed:
stage 9 read the log to completion with zero decode errors; stage 10 archived, cleared
and independently confirmed empty; stage 11 found firmware refused all three
sleep/hibernate actions; stage 12 found AMT answering WS-Man and accepting a wake
request while self-reporting off. **Stage 9 has since also run against machine 2, and
been re-run against machine 1 on the log stage 10 had cleared — where it failed and
found a real defect** (issue #105, `amt_event_log` counting firmware's zero-filled empty
record slots as records). **Stages 10, 11 and 12 have since also run against machine 2**
(pipeline 244, workflow `b7865873-40b2-43b5-825f-be5ebba704fc`, jobs
`hardware-log-clear` 3168, `hardware-sleep-hibernate` 3170, `hardware-wake-from-off`
3172), with the same outcomes on each: the log clear reproduced, both sleep/hibernate
refusals reproduced, and wake-from-off reproduced. Every one of stages 9-12 has now
run on both machines — see
`docs/capability-matrix.md` Tier 4 for what is still left open (the padding-on-refill
question for 19.0.5, and wake-from-off's independent-confirmation step, which no CI run
on either machine can supply).

**A failing qualification stage is the tier working.** Stage 9's failure is the reason
issue #105 exists, and no unit or mock test in this repository could have produced it —
the mock derived both the `GetRecords` record array and the container's own
`CurrentNumberOfRecords` from one list, so they could not disagree there. Do not read
"stage 9 failed" as a hardware-tier problem to be tidied away; it is the return on
having the tier.

**Qualify one machine through all twelve stages first.** A second machine proves
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
  misunderstanding between implementation and mock passes both. **Issue #105 is the
  second recorded instance of exactly that** — after the `wake_on_lan_capable`
  inversion — and the sharper of the two, because the agreement was structural rather
  than a matter of understanding: the mock built the `GetRecords` record array and the
  container's `CurrentNumberOfRecords` from the same list, so no configuration of it
  could make the two disagree, and the bug lived entirely in the case where they do.
- Real firmware differs across AMT generations and SKUs. Anything version
  dependent is unverified until step 1 runs on that generation.
- **`amt_event_log` and `amt_log_clear` have now run against real hardware on both
  machines.** Stage 9 (read-only) and stage 10 (irreversible) first ran against
  `amt-lab-01`, AMT 16.1.30, on 2026-07-31 (pipeline 208) and both passed: stage 9's
  `AMT_MessageLog` iteration read all 205 records to completion with zero decode
  errors, confirming the 21-byte layout against records a real ME actually wrote;
  stage 10 archived those records, invoked `ClearLog`, and independently re-read the
  log to confirm empty rather than trusting `ClearLog`'s own return value. **Stage 9
  has since passed on `amt-lab-02` (AMT 19.0.5, 110 records, pipeline 226) as well, and
  stage 10 has since passed there too** (pipeline 244, workflow
  `b7865873-40b2-43b5-825f-be5ebba704fc`, job `hardware-log-clear` 3168, same
  archive-clear-reread sequence on its own 110 records), so both modules now rest on
  two generations. What no green run on
  either machine settles is the **empty-slot padding's relationship to firmware
  generation versus timing**: machine 1's 205 padding entries were read on a log that
  had partly refilled after its clear, while machine 2's immediate post-clear re-read
  showed `empty_slots: 0` — consistent with padding correlating with refill timing
  rather than with the clear alone, but that is an observation from two data points,
  not a firmware rule, and whether 19.0.5 pads a refilled log the way 16.1.30 does
  remains unmeasured. See Tier 3 in [`capability-matrix.md`](capability-matrix.md) for
  the full result and Tier 4 for what remains open.
- **A post-clear read does *not* serve deleted records, and that was tested rather than
  assumed.** The over-count in issue #105 was first read as firmware serving records
  `ClearLog` had deleted, which would have made every post-clear `amt_event_log` read
  untrustworthy and the stage-10 confirmation re-read meaningless. **Zero** of the 205
  records the clear archived appear in the read that followed it; the extra entries were
  all-zero padding for freed slots. `amt_log_clear` therefore carries no "post-clear
  reads are unreliable" warning, because that claim is disproven, not merely
  unsubstantiated. See [`capability-matrix.md`](capability-matrix.md), "The hypothesis
  that `GetRecords` serves records `ClearLog` deleted — tested and refuted".
- **Stage 11 found that real firmware refuses `amt_power`'s sleep and hibernate
  actions outright — on both machines.** The 2026-07-31 run issued `sleep-light`,
  `sleep-deep` and `hibernate` against `amt-lab-01` for the first time any hardware
  stage had issued any of them, and firmware answered `outcome: firmware_refused` /
  `error_class: remote_operation` for all three, before any request reached the
  platform. The machine was left `on` and healthy. The same stage ran again against
  `amt-lab-02` (pipeline 244, workflow `b7865873-40b2-43b5-825f-be5ebba704fc`, job
  `hardware-sleep-hibernate` 3170), with the identical refusal on all three and the
  same healthy `on` outcome. This is the most
  consequential update: the finding reproduces across **two firmware generations
  three majors apart**, which materially strengthens it — though it remains
  repeatability, not a general claim about AMT's sleep/hibernate support everywhere.
  See [`docs/amt_power.md`](amt_power.md) and Tier 3 of
  [`capability-matrix.md`](capability-matrix.md).
- **Stage 12 found AMT answering WS-Man, and accepting a wake request, while
  reporting itself powered off — on both machines.** First against `amt-lab-01`
  (2026-07-31): 3 reachability probes while AMT self-reported off, 0 failures, a wake
  request accepted, and the machine restored to `on`. Then against `amt-lab-02`
  (pipeline 244, workflow `b7865873-40b2-43b5-825f-be5ebba704fc`, job
  `hardware-wake-from-off` 3172), identically. `operator_attestation`
  is `null` on both runs, as it will be on every unattended CI run on either machine
  — nothing reachable from CI independently confirms genuine physical power-off, and
  two machines agreeing does not close that gap. See Tier 4 in
  [`capability-matrix.md`](capability-matrix.md) for exactly what remains open.

This collection is protocol-complete, test-covered, and **hardware-qualified on two
machines for all seven of its modules** — precisely: **all eight (of the stages that
existed at the time) against AMT 16.1.30 (`amt-lab-01`, 2026-07-28) and all eight
against AMT 19.0.5 (`amt-lab-02`, 2026-07-29)**, each run limited to the machine it
qualified (`hardware-limit`), so neither touched the other, **plus stages 9-12 against
`amt-lab-01` (2026-07-31, pipeline 208) and again against `amt-lab-02`** (stage 9 in
pipeline 226; stages 10-12 in pipeline 244, workflow
`b7865873-40b2-43b5-825f-be5ebba704fc`). A
read-only re-run against machine 1 on 2026-07-29 then read that machine with v0.2.0's
fact code, which closed the last coverage difference between the two for the original
eight stages: `amt_info`'s network and system-state facts are now confirmed populated
on both generations rather than on 19.0.5 alone. Qualification found seven defects the
first two tiers could not have found, which is the concrete argument for this tier
existing rather than a theoretical one.

What it still does not cover is listed as Tier 4 in
[`capability-matrix.md`](capability-matrix.md): a non-zero IDE-R write, whether a
PXE exchange actually occurred, AMT's internal one-shot role bit, whether a target OS
genuinely enters S1/S3/S4/S5 (moot on both machines while firmware itself refuses the
request), independent confirmation of genuine physical power-off during wake-from-off
(both machines answer WS-Man and accept a wake request while self-reporting off, but
neither reading is independent of AMT's own report), whether AMT 19.0.5 pads freed
event-log slots the way 16.1.30 does on a refilled log, and any firmware generation
other than those two.
