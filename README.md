<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Ansible Collection: `james_crowley.intel_amt`

<!-- Badges must stay on ONE line. GitHub renders the soft line break between two
     badge links as a <br>, which stacks them vertically instead of forming a row.
     The Galaxy badge reads the v3 published-collection index, not the v2 API:
     v2 no longer returns JSON for this path, so shields.io rendered "resource
     not found" against it. Verified against a published collection before use.

     The CircleCI badge reports live status again. That works only while
     CircleCI's "Free and Open Source" project flag is ON, which makes build logs
     and artifacts publicly readable. It was briefly off because the hardware
     qualification jobs store evidence artifacts carrying lab machine
     identifiers; those platform GUIDs are now held as values in the
     `amt-lab-runner` context, and CircleCI masks context values wherever they
     appear in log output, so they are censored rather than kept private by
     hiding the whole build. If the OSS flag is ever turned off again this badge
     will 404 for anonymous visitors and must go back to a static one -- a
     status-scoped `circle-token` is not an option, because GitHub push
     protection correctly classifies it as a secret. -->
[![Galaxy](https://img.shields.io/badge/dynamic/json?label=galaxy&query=%24.highest_version.version&url=https%3A%2F%2Fgalaxy.ansible.com%2Fapi%2Fv3%2Fplugin%2Fansible%2Fcontent%2Fpublished%2Fcollections%2Findex%2Fjames_crowley%2Fintel_amt%2F&color=blue)](https://galaxy.ansible.com/ui/repo/published/james_crowley/intel_amt/) [![CircleCI](https://dl.circleci.com/status-badge/img/gh/james-crowley/ansible-collection-intel-amt/tree/main.svg?style=shield)](https://dl.circleci.com/status-badge/redirect/gh/james-crowley/ansible-collection-intel-amt/tree/main) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE) [![ansible-core](https://img.shields.io/badge/ansible--core-%3E%3D2.17-blue.svg)](https://docs.ansible.com/) [![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/) [![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange.svg)](#project-status)

Out-of-band management of **Intel AMT / vPro** machines from Ansible — power
control, one-time boot selection, redirection state, and **native IDE-R virtual
media** so you can boot a machine from an ISO you hold locally and install an
operating system onto bare metal, repeatably, with no agent and no OS on the
target.

The motivating use case is turning a pile of mini PCs into a hypervisor cluster:
attach the installer ISO, attach a writable image carrying an unattended-install
answer file, arm a one-shot boot, reset, and let it install. Then hand off to
ordinary Ansible roles once the OS is up.

## Why this exists

Intel AMT is genuinely two protocols wearing one trench coat:

| Plane | Transport | Port (plain / TLS) | Nature |
|---|---|---|---|
| WS-Man management | HTTP(S) + SOAP + Digest | 16992 / 16993 | Stateless request/response |
| Redirection (SOL, IDE-R) | Raw TCP(+TLS), binary framing | 16994 / 16995 | Stateful, long-lived, bidirectional |

Existing Ansible options cover only the first. Serving boot media requires a real
IDE-R client that acts as a SCSI target for the remote BIOS — which is why most
automation shells out to MeshCmd (Node.js) for that step. This collection
implements the redirection plane natively in Python, so the whole workflow is one
toolchain with typed arguments, check mode, and classified errors.

See [`docs/protocol-notes.md`](docs/protocol-notes.md) for the full wire-format
reference this implementation is built against.

## Project status

**Pre-release, and now hardware-qualified on two machines.** All five modules and
the bare-metal install role have been exercised end to end against real Intel AMT
firmware, on a self-hosted CircleCI runner inside the lab network, through all
**eight** qualification stages: read-only facts, an identity cross-check,
check-mode plans, attended power on/off, IDE-R media attach and boot, a writable
image, native one-time PXE, and an idempotent re-probe. (Stage 2 is the
cross-check and has no playbook of its own, which is why eight stages run as
seven playbooks.)

All eight stages have now completed on **`amt-lab-01`, AMT 16.1.30** (2026-07-28)
and on **`amt-lab-02`, AMT 19.0.5** (2026-07-29) — so power control, IDE-R media,
the writable-image path and native PXE are verified on two machines across two
firmware generations. Coverage is not identical: `amt_info`'s network and
system-state facts came back populated on 19.0.5 and have **never been read on
16.1.30**, because machine 1 has not been re-run since v0.2.0 added them.

That qualification found six real defects that the unit and mock-integration
tiers could not have found, including one that made IDE-R and BIOS boot
impossible against real firmware. See [`docs/capability-matrix.md`](docs/capability-matrix.md)
for exactly what is verified, on which machine, what is only mock-tested, and what
remains unproven — the distinction matters and is kept current.

Still pre-1.0: a genuinely non-zero IDE-R **write** has not been observed, because
that needs an operating system on the target that writes.

## Requirements

- **Controller**: Python 3.10+ with `requests`. Install with
  `pip install -r requirements.txt`. The floor is 3.10 because ansible-core 2.17
  — this collection's own floor — still supports a 3.10 controller, and the lab
  hardware runner is one; CI's unit matrix covers 3.10, 3.11, 3.12 and 3.13.
- **ansible-core >= 2.17.** The floor is deliberate: the sanity-test boilerplate
  requirement changed incompatibly at 2.17, and no single module form is
  sanity-clean on both 2.16 and 2.17+.
- **Target**: nothing. No agent, no SSH, no Python. AMT is firmware.
- An AMT endpoint that is **provisioned and has a known admin credential**. This
  collection manages AMT; it does not provision it from the factory state.

### These modules run on the controller

An AMT endpoint cannot execute a Python payload, so every task must be delegated:

```yaml
- name: Read AMT capabilities
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
```

> **`delegate_to: localhost` does not protect you from fan-out.** Delegation
> changes *where* the module runs, not *how many times*. A play over ten hosts
> will still issue ten resets. Pair power and boot tasks with `serial: 1` and an
> explicit single-target selection.

## Installation

```bash
ansible-galaxy collection install james_crowley.intel_amt
pip install -r requirements.txt
```

To track `main` instead of a published release:

```bash
ansible-galaxy collection install git+https://github.com/james-crowley/ansible-collection-intel-amt.git
```

## Modules

| Module | Purpose | Mutates? |
|---|---|---|
| `amt_info` | Capability and state discovery; canonical fact schema | No |
| `amt_power` | Convergent `on`/`off`, imperative `reset`/`reboot`/`cycle` | Yes |
| `amt_boot` | One-time boot device selection, no permanent boot-order change | Yes |
| `amt_redirection` | Inspect, and optionally configure, SOL/IDE-R service state | Optional |
| `amt_media` | Attach boot media over IDE-R (bootable ISO + writable image) | Yes |

All five accept the same connection options, documented once in the
`connection` doc fragment. Set them centrally with `module_defaults`:

```yaml
module_defaults:
  group/james_crowley.intel_amt.intel_amt:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
```

## Transport and trust

TLS is the default, on port 16993, with a real trust decision required. Two
mutually exclusive modes:

- **`ca_path`** — chain and hostname verification.
- **`tls_fingerprint`** — exact SHA-256 leaf pinning. In practice this is the
  mode you want: AMT certificates are typically self-signed and served on a bare
  IP address, where chain and hostname verification cannot succeed.

> **`amt_media` is the exception**, because the redirection plane is a raw TLS
> socket with no CA-chain path. It supports pinning only: `tls_fingerprint` is
> **required** when `use_tls: true`, and `ca_path` is **rejected** rather than
> silently ignored. TLS without a pin would be encrypted but unauthenticated,
> which would let an on-path attacker serve its own boot media.

### The plaintext escape hatch, and why it exists

Some AMT machines **cannot do TLS at all.** AMT provisioned in Small Business
Mode has no TLS PKI menu in MEBx and never opens port 16993 — this is
architectural, not a misconfiguration, and it is confirmed on real hardware
(Intel AMT 10.0.56). A TLS-only collection would be unusable on those machines.

So plaintext is reachable, but never implicitly:

```yaml
use_tls: false
allow_insecure_transport: true   # required; omitting it is a hard failure
```

The collection will **never** probe 16993 and silently fall back to 16992. If you
use plaintext, credentials cross the network recoverable by an on-path attacker —
put AMT on an isolated management VLAN.

## Virtual media: what is and is not writable

This is the part most easily overstated, so plainly:

| Slot | Device | Sector size | Writable? |
|---|---|---|---|
| CD/DVD | `0xB0` | 2048 | **No — read-only by design** |
| Floppy / USB-R | `0xA0` | 512 | **Yes, opt-in** |

The CD slot advertises the CD-ROM profile, which is what makes a BIOS willing to
boot it. Making it writable would mean emulating a burner, and BIOSes generally
will not boot such a device.

Both slots can be attached in the same session, and that combination is the
useful one: **boot the read-only ISO while presenting a writable image.**
Unattended installers look for an answer file on removable media and often want
to write results back. For Proxmox VE, `proxmox-auto-install-assistant` reads
`answer.toml` from removable media — so the writable image carries the answer
file and can collect post-install artifacts.

## Example: unattended bare-metal install

```yaml
- name: Install a hypervisor onto a bare-metal machine
  hosts: "{{ target }}"
  serial: 1                     # never fan out a reset
  gather_facts: false
  connection: local
  vars:
    amt_confirm_destructive: false   # override at runtime, deliberately
  module_defaults:
    group/james_crowley.intel_amt.intel_amt:
      host: "{{ amt_host }}"
      username: "{{ amt_username }}"
      password: "{{ amt_password }}"
      tls_fingerprint: "{{ amt_tls_fingerprint }}"

  tasks:
    - name: Confirm this run may reset the machine
      ansible.builtin.assert:
        that: amt_confirm_destructive | bool
        fail_msg: >-
          Refusing to continue. This play power-cycles hardware and destroys the
          existing installation. Re-run with -e amt_confirm_destructive=true.

    - name: Verify the endpoint can do what we are about to ask
      james_crowley.intel_amt.amt_info:
      register: amt

    - name: Require IDE-R support before touching anything
      ansible.builtin.assert:
        that:
          - amt.amt.capabilities.storage_redirection
          - amt.amt.reachable

    - name: Attach the installer ISO plus a writable answer-file image
      james_crowley.intel_amt.amt_media:
        cdrom: "{{ installer_iso }}"
        floppy: "{{ answer_image }}"
        floppy_writable: true
        start_mode: on_reboot
        state: attached
      register: media
      no_log: true

    - name: Arm a one-shot boot from the redirected CD
      james_crowley.intel_amt.amt_boot:
        device: ider_cdrom
        mode: once
        action_token: "{{ media.session_id }}"
      no_log: true

    - name: Reset into the installer
      james_crowley.intel_amt.amt_power:
        state: reset
      no_log: true

    - name: Wait for the installed OS to come up
      ansible.builtin.wait_for:
        host: "{{ provisioned_host }}"
        port: 22
        timeout: 3600
        delay: 120

    - name: Detach the media
      james_crowley.intel_amt.amt_media:
        state: detached
        session_id: "{{ media.session_id }}"
      no_log: true
```

Nothing above is lab-specific. Point the variables at any AMT machine.

## Idempotence and check mode

| Action | Read before write | `changed` | Check mode |
|---|---|---|---|
| `amt_info` | yes | always `false` | full read |
| `amt_power` `on`/`off` | yes | desired differs | reports plan |
| `amt_power` `reset`/`reboot`/`cycle` | yes | `true` when issued | reports plan |
| `amt_boot` `mode=once` | yes | new action token arms one reset | reports plan |
| `amt_redirection` inspect | yes | always `false` | full read |
| `amt_redirection` mutate | yes | effective config differs | reports plan |

Two rules the whole design depends on:

- **An uncertain mutation is never retried automatically.** A timeout *after* a
  request was transmitted returns `indeterminate`, so the caller re-probes
  instead of re-issuing a reset that may already have happened.
- **One-shot boot is never silently re-armed.** Re-arming takes a new explicit
  action token.

## Error handling

Every failure carries a stable `error_class`, so you can branch on it:

`connection`, `tls_validation`, `authentication`, `unsupported_capability`,
`invalid_state`, `timeout`, `protocol`, `remote_operation`, `identity_mismatch`.

Messages and diagnostics are redacted — passwords, `Authorization` headers,
digest responses, and cookies are stripped, and excerpts are length-bounded.
Field and tag names survive so failures stay diagnosable.

## Testing

```bash
# Unit tests and sanity, as CI runs them
COLLECTION_PATH="$(./scripts/setup-collection-tree.sh)"
cd "$COLLECTION_PATH"
ansible-test sanity --venv --python 3.12
ansible-test units  --venv --python 3.12
ansible-test integration --venv --python 3.12   # against local mock servers
```

CI uses `--venv` rather than `--docker` deliberately: the CircleCI Docker
executor cannot bind-mount the working directory into a remote-docker container,
which is what `ansible-test --docker` requires.

Hardware tests are opt-in, run serially on a self-hosted runner, and require a
manual approval. See [`docs/testing.md`](docs/testing.md).

## Security notes

- `password` is `no_log` in every argument spec; examples also set task-level
  `no_log: true` as defence in depth.
- Credentials are never written to receipts, facts, or state files, and are never
  passed via argv or environment to a helper process.
- Writable IDE-R hands a remote BIOS raw block access to a local file. It is
  opt-in per image, symlinks and paths outside an allowed directory are refused,
  and the ISO is never opened read-write.
- AMT is a pre-OS management engine. Treat its credentials as equivalent to
  physical access to the machine.

## License and attribution

GPL-3.0-or-later. See [LICENSE](LICENSE).

Protocol knowledge was reimplemented from **MeshCentral** (Apache-2.0, Intel
Corporation) and informed by **`parmstro/intel_amt`** (GPL-3.0-or-later),
including its hardware-verified finding about AMT 10.x TLS availability.
Full attribution with per-file provenance is in [NOTICE](NOTICE).

## Contributing

Issues and PRs welcome. Conventional commits; every change needs a changelog
fragment in `changelogs/fragments/`; CI must be green.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the local verification sequence and
the practical traps this project has actually hit,
[`SECURITY.md`](SECURITY.md) for why this collection warrants unusual care with
credentials, and [`docs/maintainer-setup.md`](docs/maintainer-setup.md) for the
one-time account/secret steps a maintainer needs.

## Further reading

- [`docs/amt_info.md`](docs/amt_info.md), [`docs/amt_power.md`](docs/amt_power.md),
  [`docs/amt_boot.md`](docs/amt_boot.md), [`docs/amt_redirection.md`](docs/amt_redirection.md),
  [`docs/amt_media.md`](docs/amt_media.md) — per-module reference: options, return
  values, examples, errors, and limitations.
- [`docs/capability-matrix.md`](docs/capability-matrix.md) — exactly what is verified
  against real firmware evidence, what is only mock-tested, and what open risks are
  tracked and why.
