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

These must pass with no network access and no hardware. The timeout-classification
and multi-frame-write paths in particular can only be tested this way — they are
invisible to unit tests of pure functions and impractical to trigger on demand
against real firmware.

## Hardware-in-the-loop tests

These power-cycle and reimage real machines. They are gated twice.

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
circleci namespace create james-crowley --org-id <org-id>
circleci runner resource-class create james-crowley/amt-lab "Intel AMT hardware runner" --generate-token
# then install the machine runner 3 agent on the lab host with that token
```

The job declares:

```yaml
machine: true
resource_class: james-crowley/amt-lab
```

### Inventory and credentials

`tests/hardware/inventory.yml` is **gitignored**. Real hostnames, AMT
credentials, and certificate fingerprints must come from the runner's
environment, never the repository. Commit only an `.example` file.

### Qualification order

Run these in order and never in parallel. Each step is a gate on the next.

1. Read-only `amt_info` against each target.
2. Compare the reported facts against an independent power probe and reviewed
   BIOS inventory — this is what catches an inventory/reality mismatch before it
   becomes a reset of the wrong machine.
3. Check-mode power and boot plans. No mutation.
4. Attended power on/off.
5. IDE-R attach with a small test ISO; confirm boot handoff.
6. Writable-image test: confirm the device accepts writes and the bytes land.
7. One-time firmware PXE, only after DHCP/boot-service and NIC prerequisites are
   separately proven.
8. Idempotent re-probe.

**Qualify one machine first.** A second machine proves repeatability. Never cut
both over at once — if a firmware quirk bricks a boot configuration, you want a
known-good machine to compare against.

### If a machine ends up in a bad boot state

One-shot boot is single-use, so a plain power cycle usually clears it. If the
machine is stuck, the recovery path is out-of-band and manual: attach a KVM
console (MeshCentral is useful here), enter MEBx, and reset the boot
configuration. Keep that path available before running step 5 for the first time
on any new machine.

## What CI does not prove

Being explicit, because the gap matters:

- No test here proves real firmware accepts our `AMT_BootSettingData` `Put`. The
  field delete-list in [`protocol-notes.md`](protocol-notes.md) §2.5 exists
  because firmware rejects echoed read-only fields, and the mock server cannot
  independently confirm we got that list right.
- Mock servers implement the protocol *as we understand it*. A shared
  misunderstanding between implementation and mock passes both.
- Real firmware differs across AMT generations and SKUs. Anything version
  dependent is unverified until step 1 runs on that generation.

Until hardware qualification has run, treat this collection as protocol-complete
and test-covered but **hardware-unverified**.
