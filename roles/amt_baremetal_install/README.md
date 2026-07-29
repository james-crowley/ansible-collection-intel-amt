<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Role: `james_crowley.intel_amt.amt_baremetal_install`

Drives one complete unattended bare-metal OS install over Intel AMT, end to
end, against exactly one target:

```
validate -> probe -> attach media -> arm one-time boot -> reset -> observe -> wait for hand-off -> detach
```

This role wraps the five modules in this collection (`amt_info`, `amt_power`,
`amt_boot`, `amt_redirection`, `amt_media`) with the safety scaffolding a
real, physically disruptive operation needs: a fan-out guard, an explicit
destructive-action confirmation, preflight capability checks, resumability
across interrupted runs, and a guaranteed detach even on failure.

**Generic by design.** Nothing in this role names a lab, a hostname, an IP
range, or a specific piece of hardware. Every input is a variable with a
sensible default. It works unchanged against any AMT endpoint.

## What this role does *not* decide for you

- Which OS or installer to use, or how its answer file is built. This role
  only gets bytes onto the machine's boot device and confirms hand-off; it
  has no opinion about what those bytes are.
- Whether a PXE boot service actually exists on the target's network. For
  `amt_baremetal_install_boot_provider: pxe`, this role verifies the *firmware* supports
  one-time PXE boot (`amt_info`'s `capabilities.boot_once_pxe`); it cannot
  verify a DHCP/TFTP/HTTP boot server is listening. See
  `tests/hardware/README.md` stage 7.
- Physical/KVM recovery if a machine ends up in a bad boot state. See
  `tests/hardware/README.md`'s manual recovery section, and keep that path
  reachable *before* running this role against new hardware for the first
  time.

## The single most important variable

```yaml
amt_baremetal_install_confirm_destructive: false   # default -- this role does nothing destructive until you flip it
```

This role power-cycles and can reimage the target. It refuses to proceed past
validation unless `amt_baremetal_install_confirm_destructive` is explicitly `true`, and the
failure message names the variable. Set it at the point of use
(`-e amt_baremetal_install_confirm_destructive=true`), not in a checked-in defaults file.

## Fan-out guard

`delegate_to: localhost` changes *where* a task runs, not *how many times*. A
play over ten hosts still issues ten resets, `serial: 1` or not. This role
asserts, at runtime, that:

- `ansible_play_hosts_all | length == 1` -- the play's full host roster
  (not just the current serial batch) is exactly one host, and
- `ansible_play_batch | length == 1` -- confirming `serial: 1` is actually set.

Both must hold, independently. Point this role at exactly one host per play.

## Boot providers

| `amt_baremetal_install_boot_provider` | What happens | Preflight capability required |
|---|---|---|
| `ider_cdrom` (default) | Attaches media over IDE-R, arms `device: ider_cdrom` | `capabilities.storage_redirection` |
| `pxe` | Skips the media phase, arms `device: pxe` | `capabilities.boot_once_pxe` |

Native PXE and IDE-R boot are mutually exclusive at the firmware level --
selecting one boot source overrides the other's redirection (see
`amt_boot`'s `DOCUMENTATION` and `docs/protocol-notes.md` s2.5). This role
requires exactly one explicit value and fails on anything else rather than
guessing or trying to combine them.

## Resumability

A separate `ansible-playbook` invocation has no memory of a prior run. This
role gives it one: a small JSON file per target
(`{{ amt_baremetal_install_state_dir }}/<amt_baremetal_install_host>.json`, default
`~/.ansible/intel_amt/baremetal-install/`) tracking whether media is
attached, whether one-time boot is armed, whether a reset was issued, and
whether that reset was *confirmed* (the postcondition probe actually
observed the endpoint powered back on).

What this protects against: a run that armed one-time boot and/or issued a
reset, then got interrupted -- Ctrl-C, controller crash, network partition --
before the outcome was confirmed. Two rules follow directly from this
collection's own contract (`amt_boot` is never silently re-armed; `amt_power`
never retries a mutation itself):

- If the state file shows `boot_armed: true` and `reset_confirmed: false`,
  the role refuses to continue on its own. It fails with a message pointing
  at the manual recovery path in `tests/hardware/README.md`, and requires
  `-e amt_baremetal_install_force_resume=true` before it will touch that target again.
- Once `amt_baremetal_install_force_resume=true` is given, the role clears the armed/reset
  flags and proceeds with a **brand-new** `action_token` -- never the
  previous one -- and re-confirms (rather than re-starts) any media session
  that was already attached, since `amt_media` treats re-attaching a live
  `session_id` as idempotent.
- If a prior run's `reset_confirmed` was `true` (it finished cleanly), the
  next run starts from a clean slate rather than carrying stale state
  forward.

A reset call that itself fails or times out is treated conservatively: this
role cannot tell a timeout-after-the-request-was-sent apart from one before
it was sent, so it records `reset_issued: true` either way and stops, exactly
mirroring `amt_power`'s own `indeterminate` signal
(`plugins/module_utils/errors.py`).

**Failure mode this does not cover:** if the *controller* itself is
different between runs (a different laptop, a fresh CI container with no
persisted `amt_baremetal_install_state_dir`), the state file will not be there and this role
has no way to know a previous, different controller left a target armed.
Point `amt_baremetal_install_state_dir` at durable, shared storage if resumability needs to
survive a change of controller.

## Always detach

Media attach/detach is wrapped in `block`/`rescue`/`always` at the top level
(`tasks/main.yml`): whatever fails -- probe, attach, arm, reset, observe, or
wait-for-hand-off -- the `always` section still runs and detaches media. A
failed install must never leave a background media daemon holding the
target's boot device open.

## The CD/DVD slot is read-only. Always.

`amt_baremetal_install_iso_path` attaches to the CD/DVD slot, which is read-only by firmware
design -- there is no writable option for it anywhere in this role or in
`amt_media`. Only `amt_baremetal_install_answer_image_path` (the floppy/USB-R slot) can ever be
opened writable, via `amt_baremetal_install_answer_image_writable`.

## Worked example: Proxmox VE

Proxmox VE's automated installer
(`proxmox-auto-install-assistant`) reads its unattended-install answer file,
`answer.toml`, from removable media. That maps directly onto this
collection's two-slot model: the installer ISO goes on the read-only CD/DVD
slot, and the answer file goes on the writable floppy/USB-R slot, both
attached in the same IDE-R session.

Nothing below is Proxmox-specific in the role itself -- only in how the two
image paths are built, which is entirely the caller's concern.

```yaml
- name: Install Proxmox VE onto a bare-metal machine
  hosts: "{{ target }}"       # exactly one host -- see the fan-out guard above
  serial: 1
  gather_facts: false
  connection: local

  vars:
    amt_baremetal_install_confirm_destructive: false   # override at the point of use, deliberately
    amt_baremetal_install_host: "{{ amt_management_address }}"
    amt_baremetal_install_username: "{{ amt_admin_username }}"
    amt_baremetal_install_password: "{{ vaulted_amt_password }}"
    amt_baremetal_install_tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"

    amt_baremetal_install_boot_provider: ider_cdrom
    amt_baremetal_install_iso_path: "{{ proxmox_installer_iso }}"          # built with proxmox-auto-install-assistant prepare-iso
    amt_baremetal_install_answer_image_path: "{{ proxmox_answer_carrier_img }}"   # carries answer.toml
    amt_baremetal_install_answer_image_writable: true

    amt_baremetal_install_wait_for_handoff: true
    amt_baremetal_install_handoff_host: "{{ provisioned_host_address }}"
    amt_baremetal_install_handoff_port: 22
    amt_baremetal_install_handoff_timeout: 3600     # Proxmox's own installer can run a long time unattended
    amt_baremetal_install_handoff_delay: 120

  roles:
    - james_crowley.intel_amt.amt_baremetal_install
```

Building `proxmox_installer_iso` and `proxmox_answer_carrier_img` (running
`proxmox-auto-install-assistant prepare-iso` and writing/formatting the
answer-carrier image) is outside this role's scope -- it starts from
already-built image paths, exactly like `amt_media` does.

## Variables

### Connection (mirrors the `connection` doc fragment)

**Every connection variable falls back to the conventional `amt_*` inventory
variable of the same name**, which is what this collection's README, the `docs/`
examples, and `tests/hardware/inventory.yml.example` all use. A conventional
inventory therefore drives this role with no per-variable mapping, and an explicit
`amt_baremetal_install_*` value still wins. The defaults below are quoted exactly
as `defaults/main.yml` sets them.

| Variable | Default | Notes |
|---|---|---|
| `amt_baremetal_install_host` | `{{ amt_host \| default(None) }}` | The AMT management address. **It does not fall back to `inventory_hostname`.** It used to, and that was removed as a bug: the inventory hostname is the *operating system's* name, whereas AMT answers on a separate management address, so the old default silently pointed at the wrong endpoint or an unresolvable name. With no `amt_host` it stays unset and `tasks/validate.yml` fails loudly — which is the correct outcome for a role that power-cycles hardware |
| `amt_baremetal_install_port` | `{{ amt_port \| default(None) }}` | WS-Man port; the module picks `16993`/`16992` when unset |
| `amt_baremetal_install_username` | `{{ amt_username \| default('admin') }}` | |
| `amt_baremetal_install_password` | `{{ amt_password \| default(None) }}` (required) | Always vaulted. No default beyond the fallback, on purpose: a missing required value must fail loudly in `tasks/validate.yml`, not coerce silently |
| `amt_baremetal_install_use_tls` | `{{ amt_use_tls \| default(true) }}` | |
| `amt_baremetal_install_allow_insecure_transport` | `{{ amt_allow_insecure_transport \| default(false) }}` | Required alongside `amt_baremetal_install_use_tls: false` |
| `amt_baremetal_install_validate_certs` | `{{ amt_validate_certs \| default(true) }}` | |
| `amt_baremetal_install_ca_path` | `{{ amt_ca_path \| default(None) }}` | Mutually exclusive with `amt_baremetal_install_tls_fingerprint` |
| `amt_baremetal_install_tls_fingerprint` | `{{ amt_tls_fingerprint \| default(None) }}` | Required when `amt_baremetal_install_use_tls: true`. Same rationale as the password: no default beyond the fallback |
| `amt_baremetal_install_timeout` / `amt_baremetal_install_connect_timeout` | `{{ amt_timeout \| default(30) }}` / `{{ amt_connect_timeout \| default(10) }}` | |

### Lifecycle

| Variable | Default | Notes |
|---|---|---|
| `amt_baremetal_install_confirm_destructive` | `false` | **Required `true` to do anything destructive** |
| `amt_baremetal_install_boot_provider` | `ider_cdrom` | `ider_cdrom` or `pxe`, mutually exclusive |
| `amt_baremetal_install_iso_path` | `null` | Read-only CD/DVD slot |
| `amt_baremetal_install_answer_image_path` | `null` | Writable floppy/USB-R slot |
| `amt_baremetal_install_answer_image_writable` | `true` | Ignored (forced `false`) when `amt_baremetal_install_answer_image_path` is unset |
| `amt_baremetal_install_media_start_mode` | `on_reboot` | Passed to `amt_media` |
| `amt_baremetal_install_media_allowed_directory` | `null` | Restricts `amt_baremetal_install_iso_path`/`amt_baremetal_install_answer_image_path` |
| `amt_baremetal_install_media_runtime_dir` | `~/.ansible/intel_amt/media-sessions` | Must match across attach/detach |
| `amt_baremetal_install_media_attach_timeout` / `amt_baremetal_install_media_detach_timeout` | `10` / `15` | |
| `amt_baremetal_install_wait_for_handoff` | `true` | Set `false` to skip the final wait |
| `amt_baremetal_install_handoff_host` / `amt_baremetal_install_handoff_port` | `{{ amt_baremetal_install_host }}` / `22` | What to wait for after reset |
| `amt_baremetal_install_handoff_timeout` / `amt_baremetal_install_handoff_delay` | `3600` / `120` | |
| `amt_baremetal_install_observe_retries` / `amt_baremetal_install_observe_delay` | `5` / `10` | Bounded postcondition power probe |
| `amt_baremetal_install_state_dir` | `~/.ansible/intel_amt/baremetal-install` | Resumability state; needs durable, per-controller-shared storage |
| `amt_baremetal_install_force_resume` | `false` | Human-only override past an uncertain prior boot/reset |

## Idempotence

- Re-running this role against a target with `reset_confirmed: true` in its
  state file starts a brand-new install attempt from a clean slate --
  exactly as if no state file existed. This role does not protect you from
  intentionally reinstalling an already-installed machine; that is what
  `amt_baremetal_install_confirm_destructive` is for.
- Re-running against a target with an unconfirmed prior boot/reset fails
  closed, by design. See "Resumability" above.
- `amt_media` attach is idempotent against a live `session_id`; `amt_boot` is
  not idempotent against prior state by contract (every successful arm
  reports `changed: true`) -- which is exactly why this role never arms it
  more than once per confirmed attempt.

## Verification status

**Both boot providers have now driven real firmware.** Hardware qualification
stages 5 and 7 invoke this role directly via `ansible.builtin.include_role`
(`tests/hardware/qualify_media_attach.yml` and `tests/hardware/qualify_pxe.yml`),
and both passed against the lab's AMT 16.1.30 machine:

| Stage | Playbook | Provider | What the role did on real hardware |
|---|---|---|---|
| 5 | `qualify_media_attach.yml` | `ider_cdrom` | validate -> probe -> enable IDE-R -> attach a real bootable ISO over IDE-R -> arm one-time boot -> reset -> observe -> detach |
| 7 | `qualify_pxe.yml` | `pxe` | validate -> probe -> arm native one-time PXE -> reset -> observe, with `AMT_BootSettingData` re-read afterwards and asserted undrifted |

So the `ider_cdrom` path's orchestration of `amt_redirection` and `amt_media`
together -- the thing no mock tier covers, because the mock IDE-R server needs an
active per-test handshake-driving script rather than passively answering
connections (see `tests/integration/mock_servers/run_ider_mock.py`'s docstring) --
is verified, not inferred.

Below that, `--syntax-check` passes for the role and for every playbook under
`tests/hardware/`, and the role was also driven ad hoc (not as a committed
automated test) against a live instance of this collection's mock WS-Man server
(`tests/integration/mock_servers/wsman_server.py`) with
`amt_baremetal_install_boot_provider: pxe`, both under `--check` and for real, over
plaintext. That run exercised the fan-out guard (refused a two-host play), the
destructive-confirmation gate, a full validate -> probe -> arm -> reset -> observe
-> detach pass with `reset_confirmed: true` written to a real state file, the
resumability guard refusing a hand-crafted "interrupted, unconfirmed" state file
without `amt_baremetal_install_force_resume`, and that flag then letting it proceed
with a fresh `action_token`.

**What is still unverified against real hardware**, stated specifically:

- **A second machine.** Stages 5 and 7 have only ever run against
  `amt-lab-01` (AMT 16.1.30). The lab's second machine never got past the
  read-only stages, so nothing in this role is confirmed on a second endpoint or a
  second firmware generation -- see [`docs/capability-matrix.md`](../../docs/capability-matrix.md).
- **The hand-off wait.** Both hardware stages set
  `amt_baremetal_install_wait_for_handoff: false`, so the `wait_for` phase and its
  timeout behaviour have never run against a machine that actually installs an OS.
- **`amt_baremetal_install_answer_image_path`.** Stage 6 proves `amt_media` presents
  a writable image to real firmware, but it calls the module directly; this role has
  never attached an answer-file image on hardware.
- **The resumability guard on hardware.** It is covered only by the ad hoc mock run
  above, with a hand-crafted state file.
- **A real unattended install completing.** No stage boots an installer through to
  a provisioned OS; stage 5 confirms boot hand-off over KVM and stops there.
