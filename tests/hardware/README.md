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

Two independent gates, neither of which fires on an ordinary push:

1. **Pipeline parameter.** The `hardware` CircleCI workflow only exists when
   the pipeline is triggered with `run-hardware-tests=true`
   (`.circleci/config.yml`). A normal push cannot reach it.
2. **Manual approval.** Even then, a human must approve the
   `hardware-approval` job in the CircleCI UI before `hardware-tests` runs.

`hardware-tests` itself runs on a self-hosted machine runner inside the lab
network (`resource_class: james-crowley/amt-lab`), and currently invokes only
two of the eight stages below:

```yaml
- run:
    name: Read-only AMT qualification
    command: ansible-playbook tests/hardware/qualify_readonly.yml -i tests/hardware/inventory.yml -v
- run:
    name: Check-mode power and boot plans
    command: ansible-playbook tests/hardware/qualify_checkmode.yml -i tests/hardware/inventory.yml --check -v
```

Stages 4-8 are **not** wired into CI. They power-cycle and attach media to
real machines, and this repository's position is that those stay
human-attended, run explicitly from a terminal on (or with access to) the lab
network, not from an unattended pipeline job.

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

Each stage is a gate on the next. They run in this order, and **never in
parallel** -- a failure at stage N must stop everything after it, not race
ahead on the assumption stage N was cosmetic:

| Stage | Playbook | Mutates? | What it catches |
|---|---|---|---|
| 1 | `qualify_readonly.yml` | No | Endpoint unreachable, firmware read failures |
| 2 | `qualify_readonly.yml` (same file) | No | **Inventory/reality mismatch** -- firmware-reported UUID vs. reviewed `amt_expected_uuid` |
| 3 | `qualify_checkmode.yml` (`--check`) | No | Module check-mode paths that unit/mock tests cannot fully exercise against real firmware quirks |
| 4 | `qualify_power.yml` | Yes | Real `RequestPowerStateChange` behaviour, attended |
| 5 | `qualify_media_attach.yml` | Yes | IDE-R attach and boot hand-off against real firmware |
| 6 | `qualify_writable_image.yml` | Yes | The writable floppy/USB-R path actually lands bytes on disk |
| 7 | `qualify_pxe.yml` | Yes | Native one-time PXE boot, only once DHCP/boot-service prerequisites are proven separately |
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
Stage 7 additionally requires `-e amt_pxe_prereqs_confirmed=true`, because
nothing in this collection can verify a PXE/DHCP boot service actually exists
on the target's network -- that has to be proven independently first, or
stage 7 just strands the machine at a PXE ROM prompt.

## Qualify one machine first

Qualify exactly one machine through all eight stages before running any
stage against a second. A second machine then proves **repeatability** --
that the first machine's success was not a fluke of that specific firmware
build or lab-network quirk. Never cut both machines over to a new stage at
once: if a firmware quirk bricks a boot configuration, you want a known-good
machine to compare against while recovering the other.

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
