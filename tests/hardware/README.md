<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Hardware-in-the-loop qualification

These playbooks power-cycle, attach boot media to, and can reimage **real**
Intel AMT machines. Nothing here runs against a mock server. See
[`docs/testing.md`](../../docs/testing.md) for how this fits into the
collection's three testing tiers.

## Gating

Every hardware job sits behind at least two independent gates, neither of
which fires on an ordinary push:

1. **Pipeline parameter.** The `hardware` CircleCI workflow only exists when
   the pipeline is triggered with `run-hardware-tests=true`
   (`.circleci/config.yml`). A normal push cannot reach it.
2. **Manual approval.** Even then, a human must approve a `type: approval`
   job in the CircleCI UI before the corresponding hardware job runs.

`hardware-tests` runs on a self-hosted machine runner inside the lab network
(`resource_class: crowley/amt-runner`), behind `hardware-approval`, and
invokes the three **non-mutating** stages below:

```yaml
- run:
    name: "Stage 1: read-only AMT qualification"
    command: ansible-playbook tests/hardware/qualify_readonly.yml -i tests/hardware/inventory.yml -v
- run:
    name: "Stage 3: check-mode power and boot plans (no mutation)"
    command: ansible-playbook tests/hardware/qualify_checkmode.yml -i tests/hardware/inventory.yml --check -v
- run:
    name: "Stage 8: idempotent re-probe"
    command: ansible-playbook tests/hardware/qualify_idempotent_reprobe.yml -i tests/hardware/inventory.yml -v
```

Stages 4-7 -- the mutating ones -- are wired into CI too, as four separate
jobs (`hardware-power`, `hardware-media`, `hardware-writable`, `hardware-pxe`),
each **escalating past the last and each behind its own separate approval
job** (`hardware-power-approval`, `hardware-media-approval`,
`hardware-writable-approval`, `hardware-pxe-approval`). One approval does not
cover all four: a human confirms every escalation independently, from
"power-cycle" through "arm a native PXE boot," rather than one click
green-lighting everything. Each of these jobs runs the corresponding
playbook with `-e amt_qualify_attended=false`, which skips the playbook's own
interactive `ansible.builtin.pause` prompts -- those block on stdin, which the
CircleCI machine executor cannot supply, so the approval job itself is CI's
human checkpoint. **The approver is expected to already have the KVM/console
open before clicking approve**, exactly as an attended manual run asks a human
to do by hand. Stage 7's job additionally reads the `pxe-prereqs-confirmed`
pipeline parameter (default `false`) into `amt_pxe_prereqs_confirmed`, so that
attestation has to be set deliberately on the pipeline trigger, not assumed.

Stages 5 and 6 need small local media files that must never be committed
(`.gitignore` blocks `*.iso`/`*.img`); their jobs run
[`make-test-media.sh`](make-test-media.sh) first to provision a small
genuinely-bootable ISO (iPXE's own `ipxe.iso`) and a zero-filled writable
image, entirely inside the workspace. Run it yourself for a manual run too:

```bash
./tests/hardware/make-test-media.sh
# prints AMT_TEST_ISO_PATH= / AMT_TEST_IMAGE_PATH= for tests/hardware/render-inventory.sh
# to pick up, or pass them directly with -e amt_test_iso_path=... / -e amt_test_image_path=...
```

None of this weakens what stages 4-7 running unattended in CI can actually
prove -- see each job's own comment in `.circleci/config.yml` and each
playbook's own header comment for the exact, honest scope of what a green run
does and does not establish. In particular: stage 6 (`hardware-writable`)
will always observe `bytes_written=0` when run unattended, because nothing is
booted on the target to issue a write -- that is documented as a legitimate
outcome, not a failure. Stage 7 (`hardware-pxe`) cannot verify netboot itself
succeeds, since that depends on DHCP/boot-service infrastructure this
collection has no way to observe.

## Inventory and credentials

`tests/hardware/inventory.yml` is **gitignored** (see the repository
`.gitignore`). Commit only [`inventory.yml.example`](inventory.yml.example),
which uses obviously fake hostnames (`.invalid` TLD) and addresses
(`203.0.113.0/24`, the RFC 5737 documentation range).

Real hostnames, AMT credentials, and TLS fingerprints come from the
self-hosted runner's environment (`AMT_USERNAME`, `AMT_PASSWORD`,
`AMT_TLS_FINGERPRINT`, looked up via `lookup('ansible.builtin.env', ...)` in
the example inventory) -- never from a file in this repository.

Evidence this stage produces is written to `tests/hardware/output/`, which is
also gitignored; the CircleCI job stores it as build artifacts instead
(`store_artifacts: path: tests/hardware/output`).

## The staged plan, and why it never runs in parallel

There are **eight numbered stages** and **seven playbooks**: stage 2 has no
playbook of its own, because it is a human cross-check performed on stage 1's
output rather than anything Ansible can assert unaided. Each stage is a gate on
the next. They run in this order, and **never in parallel** -- a failure at stage
N must stop everything after it, not race ahead on the assumption stage N was
cosmetic:

| Stage | Playbook | Mutates? | What it catches |
|---|---|---|---|
| 1 | `qualify_readonly.yml` | No | Endpoint unreachable, firmware read failures |
| 2 | *(none -- human review of stage 1's output)* | No | **Inventory/reality mismatch** -- firmware-reported UUID vs. reviewed `amt_expected_uuid` |
| 3 | `qualify_checkmode.yml` (`--check`) | No | Module check-mode paths that unit/mock tests cannot fully exercise against real firmware quirks |
| 4 | `qualify_power.yml` | Yes | Real `RequestPowerStateChange` behaviour, attended |
| 5 | `qualify_media_attach.yml` | Yes | IDE-R attach and boot hand-off against real firmware |
| 6 | `qualify_writable_image.yml` | Yes | The device is accepted, attached, and presented writable; a non-zero `bytes_written` (needs something booted on the target to write) is cross-checked against the on-disk checksum. `bytes_written=0` is expected without that and is **not** a failure -- see the playbook header |
| 7 | `qualify_pxe.yml` | Yes | One-time PXE arms and reads back armed; the reset is issued and the endpoint recovers; `AMT_BootSettingData` is not left drifted by the reset. Does **not** verify netboot itself succeeds (depends on DHCP/boot-service infrastructure) or read back AMT's internal one-shot role bit -- see the playbook header |
| 8 | `qualify_idempotent_reprobe.yml` | No | No session or state was left quietly drifting after everything above |

**Stage 2 is the one that matters most and is easiest to skip.** It is not
testing AMT or this collection -- it is testing whether `inventory.yml` and
the physical machine in front of you still agree with each other. Inventory
drifts: a machine gets re-racked, a DHCP lease changes, someone repurposes a
lab box. `qualify_readonly.yml` records the firmware-reported UUID on first
run and, once a human has reviewed it and filled in `amt_expected_uuid`,
cross-checks it on every subsequent run. Skipping this is how you reset the
wrong machine.

Stage 3 gates on `ansible_check_mode` itself (see the assertion in
`qualify_checkmode.yml`) precisely so that forgetting `--check` on the
command line turns into an immediate, loud failure instead of a real power
action landing where a preview was expected.

Stages 4 through 7 are progressively more disruptive and are marked
"attended" in their own file headers: a human should be watching the machine
(console or KVM) while each one runs, not just watching the Ansible output.
For a manual run this means answering the `ansible.builtin.pause` prompts;
in CI it means the approver watching the console before approving that
stage's job (see Gating above -- `amt_qualify_attended=false` skips the
prompts themselves in CI, but the human checkpoint they exist for is still
there, just moved to the approval). Stage 7 additionally requires
`-e amt_pxe_prereqs_confirmed=true` (or, in CI, the `pxe-prereqs-confirmed`
pipeline parameter set `true`), because nothing in this collection can verify
a PXE/DHCP boot service actually exists on the target's network -- that has
to be proven independently first, or stage 7 just strands the machine at a
PXE ROM prompt.

## Qualify one machine first

Qualify exactly one machine through all eight stages before running any
stage against a second. A second machine then proves **repeatability** --
that the first machine's success was not a fluke of that specific firmware
build or lab-network quirk. Never cut both machines over to a new stage at
once: if a firmware quirk bricks a boot configuration, you want a known-good
machine to compare against while recovering the other.

### Where the lab actually stands

As of 2026-07-28, and stated precisely because the difference matters:

| Machine | Firmware | Stages completed |
|---|---|---|
| `amt-lab-01` | AMT 16.1.30 | **All eight** (1, 2, 3, 4, 5, 6, 7, 8) |
| `amt-lab-02` | AMT 19.0.5 | **Only 1, 2, 3 and 8** -- the non-mutating ones |

Machine 2's run reached `hardware-power-approval` and stopped there; that
approval was never given, so stages 4 through 7 never ran against it. Nothing
about power control, IDE-R media, the writable-image path or native PXE has
been reproduced on any machine other than `amt-lab-01`. Read-only facts,
check-mode plans and the idempotent re-probe have -- on a machine of a
different firmware generation, which is worth more than a second machine of
the same one.

Real hostnames, addresses and fingerprints are deliberately absent from this
repository; `amt-lab-01`/`amt-lab-02` are the neutral names
[`render-inventory.sh`](render-inventory.sh) emits.

## If a machine ends up in a bad boot state

One-shot boot is single-use, so a plain power cycle usually clears it. If the
machine is stuck:

1. **KVM console.** [MeshCentral](https://github.com/Ylianst/MeshCentral) (or
   any AMT-aware KVM tool) can show you what the machine is actually doing,
   which is the first thing to check -- a "stuck" machine is often just
   sitting at a BIOS/PXE prompt waiting for input.
2. **MEBx.** Enter the Intel Management Engine BIOS Extension (usually
   `Ctrl+P` at boot) and reset the boot configuration from there if AMT's own
   `AMT_BootSettingData` state looks wrong or the machine will not leave a
   forced boot source.
3. As an absolute last resort, a full AMT unprovision/reprovision cycle
   clears everything, including the admin credential -- treat that as
   destroying the endpoint's identity, not a qualification step.

**Set this path up and confirm it actually works before running stage 5 for
the first time on any new machine.** Discovering you cannot reach the KVM
console *after* a boot configuration has gone wrong is the failure mode this
note exists to prevent.

## What this does not prove

Same caveat as [`docs/testing.md`](../../docs/testing.md): qualifying one or
two lab machines does not prove every AMT generation or SKU behaves
identically. Anything version-dependent is unverified until a stage has
actually run against that specific firmware.
