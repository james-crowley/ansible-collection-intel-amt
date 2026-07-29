<!--
Copyright (c) 2026 Jim Crowley
GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# `amt_media`

Attach or detach IDE-R virtual media (bootable ISO and/or writable image).

## Purpose

Attaches a bootable ISO (CD/DVD slot) and/or a raw writable image (floppy/USB-R slot)
to an Intel AMT endpoint over IDE-R, or detaches a previously attached session.

**The CD/DVD slot is read-only by design.** Only the floppy/USB-R slot can be opened
writable, via `floppy_writable`. "Writable media" in this collection always means: a
bootable read-only ISO on `cdrom` **plus** a writable image on `floppy`, attached in
the *same* session — never a writable optical device. This is exactly what unattended
installers such as Proxmox VE's `proxmox-auto-install-assistant` need, since it reads
`answer.toml` from removable media (see `docs/protocol-notes.md` §5.1).

**This module does not enable the redirection service** at the WS-Man layer — pair it
with `amt_redirection` (`state: ider`) beforehand — **and does not arm the boot
selection** — pair it with `amt_boot` (`device: ider_floppy` or `device: ider_cdrom`).
`amt_redirection` does not move media; only `amt_media` does.

**Unlike every other module in this collection, `amt_media` does not use `requests` or
speak WS-Man at all.** It speaks the IDE-R/redirection protocol directly over
`socket`/`ssl`. Its `port` option therefore defaults to `16995`/`16994` (the
redirection ports), not `16993`/`16992`.

### Session lifecycle

An IDE-R session is long-lived — the endpoint stays booted from attached media for as
long as an install takes, which can be an hour or more — while a module invocation
must return in seconds. `state=attached` forks a **detached background process**
(double-fork, never `exec`/`subprocess` — see `plugins/module_utils/media_session.py`)
that owns the connection, writes a small JSON state file under `runtime_dir` keyed by
`session_id`, and returns once that process reports `attached` or an early failure
(bounded by `attach_timeout`). `state=detached` looks that process up by its recorded
pid, signals it (`SIGTERM`) to stop, and waits (bounded by `detach_timeout`) for it to
exit.

A stale state file (recorded pid no longer running — most often because the endpoint
or controller was rebooted without a clean detach) is always recoverable: a subsequent
`state=attached` for the same `session_id` discards it and starts fresh; a subsequent
`state=detached` just cleans it up and reports `changed: false`.

## Options

| Option | Type | Default | Required | Choices |
|---|---|---|---|---|
| `state` | `str` | — | yes | `attached`, `detached` |
| `cdrom` | `path` | — | no | — |
| `floppy` | `path` | — | no | — |
| `floppy_writable` | `bool` | `false` | no | — |
| `start_mode` | `str` | `on_reboot` | no | `on_reboot`, `graceful`, `immediate` |
| `session_id` | `str` | (generated if omitted) | no† | — |
| `allowed_directory` | `path` | — | no | — |
| `runtime_dir` | `path` | `~/.ansible/intel_amt/media-sessions` | no | — |
| `attach_timeout` | `int` | `10` | no | — |
| `detach_timeout` | `int` | `15` | no | — |
| `host` | `str` | — | yes | — |
| `port` | `int` | (16995 if `use_tls` else 16994 — **redirection ports, not WS-Man**) | no | — |
| `username` | `str` | `admin` | no | — |
| `password` | `str` (`no_log`) | — | yes | — |
| `use_tls` | `bool` | `true` | no | — |
| `allow_insecure_transport` | `bool` | `false` | no | — |
| `validate_certs` | `bool` | `true` | no | — (accepted for parity; **has no effect**, see below) |
| `ca_path` | `path` | — | no | — (**rejected**, see below) |
| `timeout` | `int` | `30` | no | — (accepted for parity; **not used**, see below) |
| `connect_timeout` | `int` | `10` | no | — |

† `session_id` is `required_if` `state == "detached"` (enforced via the module's
`required_if`, not the argument spec's own `required` flag — `ansible-doc` reports
`required: False` for this option, but omitting it with `state=detached` still fails,
just via a different Ansible mechanism).

Verified against `_argument_spec()` in `plugins/modules/amt_media.py`, its
`required_if`, and the rendered `ansible-doc` output.

### Trust-mode divergence from the other four modules

The redirection plane implements **exactly one trust mode**: exact SHA-256 leaf
pinning via `tls_fingerprint`, which this module *requires* whenever `use_tls=true`
(`enforce_redirection_trust_policy()`). Unlike the WS-Man modules:

- `validate_certs` is accepted for parity with the shared connection options but has
  **no effect** — there is no chain-validation behaviour for it to turn on or off.
- `ca_path` is **rejected outright**: passing it fails with `error_class: tls_validation`
  before any connection is attempted. The redirection plane is a raw TLS socket with no
  CA-chain trust path, so silently ignoring `ca_path` would leave an operator believing
  the session is chain-validated when nothing is checking.
- `timeout` is accepted for parity but **not used** — an IDE-R session has no
  individual request/response cycle to bound the way a WS-Man operation does. Use
  `attach_timeout`/`detach_timeout` instead.

This trust-policy enforcement only runs for `state=attached` — `state=detached` opens
no connection at all (it only signals a recorded pid), so gating it on a trust
decision would make a live session unstoppable by the very configuration change meant
to let an operator shut it down.

## Return values

`amt_media` nests its `intel-amt-operation/v1` receipt under an `operation` key, the
same shape every module in this collection returns it under (see
[Capability matrix](capability-matrix.md) — this was previously inconsistent across
modules, and is exactly what caused issue #21's `media.operation.session_id` bug before
issue #22 normalised it: `session_id` has always been, and remains, a top-level field,
never nested under `operation`).

| Field | Type | Returned | Description |
|---|---|---|---|
| `changed` | `bool` | always | Attach: `true` only if a new background process was actually forked (or, in check mode, would be) — `false` if an already-live session for `session_id` was found and confirmed. Detach: `true` only if a live process was actually signalled — `false` if nothing was live. |
| `session_id` | `str` | always | The session id in effect — generated for `state=attached` when not supplied. **Capture this** if you will need to detach later. |
| `session_state` | `str` | always | Last state the background process reported: `starting`, `connecting`, `attached`, `detached`, `error`. `unknown` if `state=detached` found no state file. |
| `pid` | `int` | when available | Background process id, or `null`. |
| `bytes_read` | `int` | always | Total bytes read across all attached devices. |
| `bytes_written` | `int` | always | Total bytes written across all attached devices. Always `0` for a read-only session. |
| `devices` | `dict` | always | Keyed by `cdrom`/`floppy`. Each entry: `path`, `writable`, `size`, `bytes_read`, `bytes_written`. `writable` is always `false` for `cdrom`. |
| `error` | `str` | when `session_state` is `error` | The background process's own error message. |
| `operation.schema` | `str` | always | Always `intel-amt-operation/v1`. |
| `operation.action` | `str` | always | `amt_media.attach` or `amt_media.detach`. |
| `operation.endpoint` | `str` | always | The redirection `host:port`. |
| `operation.changed` | `bool` | always | Mirrors the top-level `changed`. |
| `operation.previous` | `dict` or `null` | always | The session state as read before this call, or `null` when none existed. |
| `operation.desired` | `str` | always | `attached` or `detached`, whichever this call requested. |
| `operation.observed` | `dict` | always | The session state as read (or, in check mode, assumed) after this call. |
| `operation.tls_peer_fingerprint` | `str` or `null` | always | SHA-256 fingerprint of the TLS leaf certificate observed, or `null` over plaintext or before any connection was made. This used to also be duplicated at the top level (spread from the receipt); it now lives only under `operation`. |
| `operation.error_class` | `str` or `null` | always | `null` on success; a stable machine-readable failure class on failure. |

Additional fields not in the module's `RETURN` docstring but present in the actual
result dict (see `_attach()`/`_detach()` in `amt_media.py`): `recovered_stale_session`
(`bool`, when a stale state file was discarded) and `exited_cleanly` (`bool`, on
detach, whether the process exited within `detach_timeout`). Both are module-specific
and stay at the top level, same as `session_id`. `error_class` also appears at the
**top level** of a failed module's result (what `fail_json`/rescue blocks read),
independent of `operation.error_class`, which is always `null` on the successful-exit
path documented above.

## Examples

```yaml
- name: Attach a bootable installer ISO alongside a writable answer-file image
  james_crowley.intel_amt.amt_media:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    cdrom: /srv/images/proxmox-auto.iso
    floppy: /srv/images/answer-carrier.img
    floppy_writable: true
    start_mode: on_reboot
    state: attached
  delegate_to: localhost
  no_log: true
  register: media
```

```yaml
- name: Detach once the install has finished
  james_crowley.intel_amt.amt_media:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    session_id: "{{ media.session_id }}"
    state: detached
  delegate_to: localhost
  no_log: true
```

## Idempotence and check mode

`state=attached` is idempotent against an already-live session for the same
`session_id`: calling it again confirms the existing session (`changed: false`)
rather than starting a second one — IDE-R is a single-session protocol and firmware
only has one connection to give. `state=detached` against a `session_id` with nothing
live reports `changed: false`.

`check_mode` support is `full`. For `state=attached`: options are validated and, for
each configured image, `ider.MediaImage` is opened and immediately closed to confirm
the path/size/symlink/`allowed_directory` checks would pass, but the background
process is never forked and the endpoint is never contacted. For `state=detached`:
reports whether a live session would be stopped, but never signals it. `diff_mode`
support is `none` — use `session_state` and `devices` instead of `--diff`.

## Errors this module can raise

| `error_class` | Meaning here |
|---|---|
| `invalid_state` | Neither `cdrom` nor `floppy` given for `state=attached`; or `floppy_writable=true` without `floppy`. Caught before any connection attempt. |
| `tls_validation` | `ca_path` passed (always rejected); or `use_tls=true` without `tls_fingerprint`; or a peer-fingerprint mismatch during the handshake. |
| `unsupported_capability` | The controller has no `os.fork()` (i.e. it is Windows) — the background-session mechanism requires a POSIX controller. |
| `connection` | TCP failure connecting to the redirection port. |
| `authentication` | Redirection-plane digest authentication rejected, or firmware does not offer the required auth type (4). |
| `protocol` | Malformed redirection/IDE-R framing, an out-of-sequence frame (session torn down, no resync), or an invalid image (surfaced by `media_session.validate_media_specs` wrapping a `ValueError`/`OSError` from `ider.MediaImage`). |
| `timeout` | Connect or attach/detach timeout elapsed. |

A daemon failure that occurs *after* attach begins is reported through
`session_state=error` and the top-level `error`/`error_class` fields, not by
`fail_json` directly from the attach call path in every case — check `session_state`
as well as whether the task itself failed.

## Limitations

- **Requires a POSIX controller** (`os.fork()`). Not available when the Ansible
  controller itself runs on Windows.
- **The CD/DVD slot cannot be made writable.** There is no option, present or future,
  that changes this — see `ider.MediaImage`'s hard `ValueError` if `device_code` is
  `DEVICE_CDROM` and `writable=True` is somehow requested internally.
- **The backing file for a writable image is never extended.** A remote host that
  writes past the declared image size is refused (bounds-checked both at the SCSI
  layer and again in `MediaImage.write()`), not silently truncated or grown.
- **`runtime_dir` must be identical** across the `state=attached` call and the later
  `state=detached` call for the same session — the state file is the only channel
  between the two, since they run in unrelated Ansible module processes.
- **No cross-host session sharing.** State files live under a per-user directory on
  whatever host the module runs on (normally the controller, via `delegate_to:
  localhost`); running attach and detach from different controllers/users will not
  find each other's sessions.
- **`attach_timeout` is an early-confirmation bound, not an attach deadline.** A slow
  but eventually-successful attach that exceeds it is not reported as a failure —
  `session_state` may still read `starting`; poll again with a repeated
  `state=attached` call for the same `session_id`.
- **Hardware-qualified against AMT 16.1.30 and AMT 19.0.5**, and this module carries
  the most protocol surface of the five (the entire IDE-R/SCSI emulation in
  `plugins/module_utils/ider.py`). In stage 5 the native Python IDE-R engine served
  a real bootable ISO to real firmware; in stage 6 the floppy/USB-R slot was
  presented **writable** (MODE_SENSE write-protect bit `0x00`, not `0x80`) and the
  session stayed healthy. Both stages have now run on both lab machines, so this is
  no longer a single-machine result. **A non-zero `bytes_written` has still never
  been observed** — both machines reported `bytes_written = 0`, which is the
  expected unattended outcome (nothing on the target issues a SCSI write), and the
  agreement across two endpoints is evidence that the zero is a property of the
  unattended setup rather than of one endpoint. See the
  [Capability matrix](capability-matrix.md), including the reset-during-write gap
  noted there.
