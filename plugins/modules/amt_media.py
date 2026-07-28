#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_media
short_description: Attach or detach IDE-R virtual media (bootable ISO and/or writable image)
description:
  - >-
    Attaches a bootable ISO (CD/DVD slot) and/or a raw writable image (floppy/USB-R slot) to an
    Intel AMT endpoint over IDE-R, or detaches a previously attached session.
  - >-
    An IDE-R session is a long-lived process: the endpoint stays booted from the attached media
    for as long as an installer needs, which can be an hour or more, while a single module
    invocation must return in seconds. This module never pretends a synchronous call can hold that
    session open. O(state=attached) forks a detached background process that owns the connection,
    writes a small JSON state file keyed by O(session_id) under O(runtime_dir), and returns once
    that process has reported either V(attached) or an early failure (bounded by O(attach_timeout)).
    O(state=detached) looks that process up by the pid recorded in the state file, asks it to stop,
    and waits (bounded by O(detach_timeout)) for it to actually exit. See RV(session_state) and
    RV(pid) for what to poll afterwards, and the C(RETURN) documentation below for the full
    lifecycle contract.
  - >-
    A stale state file -- the recorded pid is no longer running, most often because the endpoint
    or the controller was rebooted without a clean detach -- is always recoverable. A subsequent
    O(state=attached) call for the same O(session_id) detects this, discards the stale file, and
    starts a fresh session rather than refusing to proceed; a subsequent O(state=detached) call
    simply cleans the file up and reports C(changed=false), since nothing live was actually there
    to stop.
  - >-
    The CD/DVD slot (O(cdrom)) is read-only by firmware design and is never described as writable
    anywhere in this module's options or return values. Only the floppy/USB-R slot (O(floppy)) can
    be opened writable, via O(floppy_writable). The useful combination -- and the one shown in
    C(EXAMPLES) -- is a bootable read-only ISO on O(cdrom) alongside a writable answer-file image on
    O(floppy), attached in the same session: this is exactly what unattended installers such as
    Proxmox VE's C(proxmox-auto-install-assistant) need, since it reads C(answer.toml) from
    removable media.
  - >-
    This module does not itself enable the redirection service at the WS-Man layer -- pair it with
    M(james_crowley.intel_amt.amt_redirection) (C(state=ider)) beforehand, and with
    M(james_crowley.intel_amt.amt_boot) (C(device=ider_floppy) or C(device=ider_cdrom)) to make the
    next reset actually boot from the attached media.
  - >-
    Unlike the other modules in this collection, this module does not use the C(requests) library
    at all: it speaks the IDE-R/redirection protocol directly over C(socket)/C(ssl), never WS-Man.
    O(port) therefore defaults to the redirection ports (V(16995)/V(16994)), not the WS-Man
    management ports the shared connection options otherwise document.
version_added: 0.1.0
author:
  - Jim Crowley (@james-crowley)
options:
  port:
    description:
      - >-
        TCP port of the IDE-R/redirection plane -- not the WS-Man management port. When not set,
        defaults to V(16995) if O(use_tls=true) and V(16994) otherwise.
    type: int
  use_tls:
    description:
      - >-
        Whether to use TLS for the redirection connection. Left at the default of V(true), the
        module connects to port 16995 and pins the peer leaf certificate before any protocol byte
        is sent.
      - >-
        O(tls_fingerprint) is B(required) when this is V(true). TLS without a pin would be
        encrypted but unauthenticated, letting an on-path attacker terminate the session and serve
        its own boot media, so it is refused rather than silently allowed.
      - >-
        Setting this to V(false) is only honoured when O(allow_insecure_transport=true) is also
        set, exactly as for the WS-Man modules in this collection.
    type: bool
    default: true
  allow_insecure_transport:
    description:
      - Explicit acknowledgement required to run the redirection session over unencrypted TCP.
      - >-
        As with the WS-Man modules, some AMT provisioning modes never open the TLS redirection
        port (16995), making plaintext (16994) the only option. Never selected implicitly.
    type: bool
    default: false
  validate_certs:
    description:
      - >-
        Accepted for parity with the shared connection options, but has no effect on this module.
        The redirection plane implements exactly one trust mode, exact SHA-256 leaf pinning via
        O(tls_fingerprint), which this module B(requires) whenever O(use_tls=true). There is
        therefore no chain-validation behaviour for this option to turn on or off.
    type: bool
    default: true
  ca_path:
    description:
      - >-
        B(Rejected) by this module. The redirection plane is a raw TLS socket with no CA-chain
        trust path, so this option cannot be honoured, and silently ignoring it would leave an
        operator believing the media session is chain-validated when nothing is checking. Passing
        it fails with RV(ignore:error_class) V(tls_validation). Use O(tls_fingerprint) instead.
    type: path
  timeout:
    description:
      - >-
        Accepted for parity with the shared connection options, but not used by this module: an
        IDE-R session has no individual request/response cycle to bound the way a WS-Man operation
        does. Use O(attach_timeout) and O(detach_timeout) instead.
    type: int
    default: 30
  cdrom:
    description:
      - >-
        Path to a bootable ISO image to attach on the CD/DVD slot. Always read-only -- there is no
        writable option for this slot, by firmware design; see the module description.
    type: path
  floppy:
    description:
      - Path to a raw image to attach on the floppy/USB-R slot.
      - >-
        At least one of O(cdrom) or O(floppy) is required for O(state=attached). Attaching both in
        the same call is supported and is the common unattended-install pattern.
    type: path
  floppy_writable:
    description:
      - >-
        Whether the floppy/USB-R image is opened read-write. Requires O(floppy) to be set; setting
        this without O(floppy) is a usage error, reported before any connection is attempted.
      - >-
        The backing file is never extended, however much a remote host writes -- see the
        C(bytes_written) entry under RV(devices) and docs/protocol-notes.md s5 for the
        bounds-checking this relies on.
    type: bool
    default: false
  start_mode:
    description:
      - >-
        When the IDE-R redirection actually engages, mirroring the C(DisableEnableFeatures) values
        in docs/protocol-notes.md s4.1. V(on_reboot) is almost always what an unattended-install
        playbook wants, paired with M(james_crowley.intel_amt.amt_boot) and
        M(james_crowley.intel_amt.amt_power) to actually trigger the reset.
    type: str
    default: on_reboot
    choices: [on_reboot, graceful, immediate]
  state:
    description:
      - >-
        V(attached) starts (or, if O(session_id) already names a live session, confirms) a
        background IDE-R session serving the configured media. V(detached) stops a previously
        attached session.
    type: str
    required: true
    choices: [attached, detached]
  session_id:
    description:
      - >-
        Identifies the background session across separate module invocations. Required for
        O(state=detached), so a caller can only ever stop a session it can name. Optional for
        O(state=attached) -- when omitted, a fresh id is generated and returned in RV(session_id);
        callers that need to detach later must capture and reuse that value (V(register) the task
        and pass C({{ result.session_id }})).
      - >-
        Calling O(state=attached) again with an O(session_id) that already names a live session is
        idempotent: C(changed=false), and no second background process is started.
    type: str
  allowed_directory:
    description:
      - >-
        When set, every image path (O(cdrom) and O(floppy)) must resolve inside this directory.
        Refuses a symlinked leaf path unconditionally, regardless of this setting -- see
        docs/protocol-notes.md s5.3.
    type: path
  runtime_dir:
    description:
      - >-
        Directory holding one JSON state/receipt file per O(session_id) (plus its background
        process's log file). Must be the same path across the O(state=attached) call and the later
        O(state=detached) call for the same session -- the state file is the only channel between
        them, since the two calls run in unrelated Ansible module processes.
      - Created (mode C(0700)) if it does not already exist.
    type: path
    default: ~/.ansible/intel_amt/media-sessions
  attach_timeout:
    description:
      - >-
        Bounded number of seconds O(state=attached) waits for the background process to report
        V(attached) or an early failure before returning. A slow-but-eventually-successful attach
        that exceeds this is not a failure -- RV(session_state) may still show V(starting); poll the
        state again with a repeated O(state=attached) call for the same O(session_id).
    type: int
    default: 10
  detach_timeout:
    description:
      - >-
        Bounded number of seconds O(state=detached) waits for the background process to actually
        exit after being asked to stop, before returning anyway. Exceeding this is reported as a
        warning, not a failure -- the process was asked to stop and may simply be slow.
    type: int
    default: 15
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
attributes:
  check_mode:
    description: >-
      Supported. Validates options and, for O(state=attached), opens (and immediately closes) every
      configured image to confirm the path/size/symlink/allowed_directory checks would pass, but
      never forks the background process or contacts the endpoint. For O(state=detached), reports
      whether a live session would be stopped, but never signals it.
    support: full
  diff_mode:
    description: Not supported. Use RV(session_state) and RV(devices) instead of C(--diff).
    support: none
"""

EXAMPLES = r"""
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

- name: Arm one-time IDE-R boot and reset into the attached media
  james_crowley.intel_amt.amt_boot:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    device: ider_cdrom
    action_token: "{{ lookup('ansible.builtin.password', '/dev/null length=32') }}"
  delegate_to: localhost
  no_log: true

- name: Poll the same session id later in the play
  james_crowley.intel_amt.amt_media:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    cdrom: /srv/images/proxmox-auto.iso
    floppy: /srv/images/answer-carrier.img
    floppy_writable: true
    session_id: "{{ media.session_id }}"
    state: attached
  delegate_to: localhost
  no_log: true
  register: media_status

- name: Detach once the install has finished
  james_crowley.intel_amt.amt_media:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    session_id: "{{ media.session_id }}"
    state: detached
  delegate_to: localhost
  no_log: true
"""

RETURN = r"""
changed:
  description: >-
    For O(state=attached): V(true) only when a new background process was actually forked (or, in
    check mode, would be). V(false) when an already-live session for O(session_id) was found and
    confirmed instead. For O(state=detached): V(true) only when a live process was actually asked
    to stop (or, in check mode, would be); V(false) when there was nothing live to stop.
  type: bool
  returned: always
session_id:
  description: The session id in effect -- generated for O(state=attached) when not supplied.
  type: str
  returned: always
session_state:
  description:
    - >-
      The last state the background process reported: V(starting) (forked, not yet connected),
      V(connecting), V(attached), V(detached), or V(error). V(unknown) if O(state=detached) found no
      state file at all.
    - >-
      A caller that needs the session to survive across many subsequent tasks should re-run this
      module with O(state=attached) and the same O(session_id) periodically and check this field,
      rather than assuming the first V(attached) result still holds an hour later.
  type: str
  returned: always
pid:
  description: Process id of the background session, when one is recorded. V(null) if none is.
  type: int
  returned: when available
bytes_read:
  description: Total bytes read from attached media across all devices (sum of RV(devices) entries).
  type: int
  returned: always
bytes_written:
  description: Total bytes written to attached media across all devices. Always V(0) for a read-only session.
  type: int
  returned: always
devices:
  description: Per-slot detail, keyed by V(cdrom)/V(floppy), for whichever slots are attached.
  type: dict
  returned: always
  contains:
    path:
      description: Resolved path of the backing image.
      type: str
    writable:
      description: Whether this slot was opened read-write. Always V(false) for V(cdrom).
      type: bool
    size:
      description: Backing file size in bytes.
      type: int
    bytes_read:
      description: Bytes read from this device so far.
      type: int
    bytes_written:
      description: Bytes written to this device so far. Always V(0) for V(cdrom).
      type: int
error:
  description: The background process's own error message, when RV(session_state) is V(error).
  type: str
  returned: when session_state is error
operation:
  description: >-
    The C(intel-amt-operation/v1) receipt for this action, in the same nested shape every module
    in this collection returns it under.
  type: dict
  returned: always
  contains:
    schema:
      description: Always V(intel-amt-operation/v1).
      type: str
    action:
      description: One of V(amt_media.attach) or V(amt_media.detach).
      type: str
    endpoint:
      description: The redirection C(host:port) this session connects (or connected) to.
      type: str
    changed:
      description: Mirrors the top-level RV(changed).
      type: bool
    previous:
      description: The session state as read before this call, or V(null) when none existed.
      type: dict
    desired:
      description: V(attached) or V(detached), whichever this call requested.
      type: str
    observed:
      description: The session state as read (or, in check mode, assumed) after this call.
      type: dict
    tls_peer_fingerprint:
      description: >-
        SHA-256 fingerprint of the TLS leaf certificate observed during this session, or V(null)
        over plaintext or before a connection was ever established.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import ider, media_session
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError, ErrorClass, InvalidStateError, TlsValidationError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.redirection import (
    REDIRECTION_PORT_PLAIN,
    REDIRECTION_PORT_TLS,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.tls import (
    enforce_transport_policy,
    normalize_fingerprint,
)

#: docs/protocol-notes.md s4.1 DisableEnableFeatures start-mode payloads.
_START_MODE_TO_VALUE = {
    "on_reboot": ider.START_MODE_ON_REBOOT,
    "graceful": ider.START_MODE_GRACEFUL,
    "immediate": ider.START_MODE_IMMEDIATE,
}


def _argument_spec() -> dict:
    return {
        "host": {"type": "str", "required": True},
        "port": {"type": "int"},
        "username": {"type": "str", "default": "admin"},
        "password": {"type": "str", "required": True, "no_log": True},
        "use_tls": {"type": "bool", "default": True},
        "allow_insecure_transport": {"type": "bool", "default": False},
        "validate_certs": {"type": "bool", "default": True},
        "ca_path": {"type": "path"},
        "tls_fingerprint": {"type": "str"},
        "timeout": {"type": "int", "default": 30},
        "connect_timeout": {"type": "int", "default": 10},
        "cdrom": {"type": "path"},
        "floppy": {"type": "path"},
        "floppy_writable": {"type": "bool", "default": False},
        "start_mode": {"type": "str", "default": "on_reboot", "choices": list(_START_MODE_TO_VALUE)},
        "state": {"type": "str", "required": True, "choices": ["attached", "detached"]},
        "session_id": {"type": "str"},
        "allowed_directory": {"type": "path"},
        "runtime_dir": {"type": "path", "default": media_session.DEFAULT_RUNTIME_DIR},
        "attach_timeout": {"type": "int", "default": 10},
        "detach_timeout": {"type": "int", "default": 15},
    }


def resolve_redirection_port(*, port: int | None, use_tls: bool) -> int:
    if port is not None:
        return port
    return REDIRECTION_PORT_TLS if use_tls else REDIRECTION_PORT_PLAIN


def build_media_specs(params: dict) -> tuple[media_session.MediaSpec, ...]:
    """Validate the cdrom/floppy/floppy_writable combination and build the device specs.

    Runs before any connection is attempted (and in check mode) -- this is a usage-error
    surface, not a firmware/protocol one: no O(cdrom)/O(floppy) at all, or O(floppy_writable)
    without O(floppy), are caller mistakes that must never reach the background process.
    """
    cdrom = params.get("cdrom")
    floppy = params.get("floppy")
    floppy_writable = params["floppy_writable"]

    if not cdrom and not floppy:
        raise InvalidStateError(
            "amt_media state=attached requires at least one of cdrom or floppy to be set",
            operation="amt_media.build_media_specs",
        )
    if floppy_writable and not floppy:
        raise InvalidStateError(
            "floppy_writable=true requires floppy to be set; there is nothing to open writable",
            operation="amt_media.build_media_specs",
        )

    specs: list[media_session.MediaSpec] = []
    if cdrom:
        # writable is unconditionally False here, never sourced from an option -- the CD/DVD
        # slot has no writable option to smuggle through in the first place. See ider.MediaImage,
        # which enforces the same rule again independently on device_code.
        specs.append(media_session.MediaSpec(path=cdrom, device_code=ider.DEVICE_CDROM, writable=False))
    if floppy:
        specs.append(media_session.MediaSpec(path=floppy, device_code=ider.DEVICE_FLOPPY, writable=floppy_writable))
    return tuple(specs)


def enforce_redirection_trust_policy(params: dict) -> None:
    """Fail closed on a trust configuration this plane cannot honour.

    The redirection plane implements exactly one trust mode: SHA-256 leaf
    pinning. It has no CA-chain path, because there is no HTTP layer here to
    hang one off -- it is a raw TLS socket carrying a proprietary framing.

    Accepting ``ca_path`` and silently ignoring it would be the worst outcome:
    an operator who sets it reasonably believes the media session is
    chain-validated when nothing is checking. Documenting "has no effect" is
    not enough, because documentation does not stop a misconfiguration from
    shipping.

    Likewise, TLS with no pin is encrypted but *unauthenticated* -- an on-path
    attacker can terminate it. That is materially worse than the plaintext path,
    which at least announces itself, and it contradicts this collection's rule
    that a trust decision is always explicit.
    """
    if params.get("ca_path"):
        raise TlsValidationError(
            "ca_path is not supported by amt_media. The IDE-R redirection plane is a raw TLS "
            "socket with no CA-chain trust path; its only trust mode is exact SHA-256 leaf "
            "pinning. Set tls_fingerprint instead.",
            endpoint=f"{params.get('host')}:{params.get('port')}",
        )

    if params.get("use_tls") and not params.get("tls_fingerprint"):
        raise TlsValidationError(
            "amt_media requires tls_fingerprint when use_tls is true. Without a pin the "
            "redirection session would be encrypted but unauthenticated, so an on-path "
            "attacker could terminate it and serve its own boot media. Supply the reviewed "
            "SHA-256 leaf fingerprint, or set use_tls=false with allow_insecure_transport=true "
            "for an endpoint that cannot do TLS at all.",
            endpoint=f"{params.get('host')}:{params.get('port')}",
        )


def build_session_config(params: dict, *, session_id: str, port: int, specs: tuple[media_session.MediaSpec, ...]) -> media_session.SessionConfig:
    fingerprint = normalize_fingerprint(params["tls_fingerprint"]) if params.get("tls_fingerprint") else None
    return media_session.SessionConfig(
        session_id=session_id,
        host=params["host"],
        port=port,
        use_tls=params["use_tls"],
        tls_pin_sha256=fingerprint,
        connect_timeout=float(params["connect_timeout"]),
        start_mode=_START_MODE_TO_VALUE[params["start_mode"]],
        allowed_directory=params.get("allowed_directory"),
        runtime_dir=params["runtime_dir"],
        devices=specs,
    )


def _finalize(receipt: OperationReceipt, *, session_id: str, fields: dict, **extra) -> dict:
    """Assemble the module result: module-specific keys at the top level, the receipt nested.

    ``fields`` (from :func:`_status_fields`) carries ``tls_peer_fingerprint`` purely so callers
    of this helper can hand it straight to ``OperationReceipt`` -- it is deliberately not
    re-exposed at the top level here, since it already lives in ``operation.tls_peer_fingerprint``
    and this collection does not duplicate receipt fields outside the receipt (see issue #22).
    """
    return {
        "changed": receipt.changed,
        "session_id": session_id,
        "session_state": fields["session_state"],
        "pid": fields["pid"],
        "bytes_read": fields["bytes_read"],
        "bytes_written": fields["bytes_written"],
        "devices": fields["devices"],
        "error": fields["error"],
        "operation": receipt.to_dict(),
        **extra,
    }


def _status_fields(state: dict | None) -> dict:
    bytes_read, bytes_written = media_session.aggregate_bytes(state)
    return {
        "session_state": (state or {}).get("state", "unknown"),
        "pid": (state or {}).get("pid"),
        "bytes_read": bytes_read,
        "bytes_written": bytes_written,
        "devices": (state or {}).get("devices", {}),
        "error": (state or {}).get("error"),
        "tls_peer_fingerprint": (state or {}).get("tls_peer_fingerprint"),
    }


def _error_class_of(state: dict | None) -> str:
    """The error_class to fail with for a state whose ``state`` key is V(error).

    Falls back to the generic class only if the daemon somehow recorded an error with
    no classification at all -- every ``AmtError`` the daemon can raise carries its own
    real ``error_class`` (see ``media_session._run_daemon``), so a caller sees
    C(authentication) for a wrong password rather than a one-size-fits-all value.
    """
    return (state or {}).get("error_class") or ErrorClass.PROTOCOL


def _attach(module: AnsibleModule, params: dict, *, endpoint: str, port: int) -> dict:
    session_id = params.get("session_id") or media_session.generate_session_id()
    runtime_dir = params["runtime_dir"]

    existing = media_session.read_state(runtime_dir, session_id)
    if existing is not None and media_session.is_pid_alive(existing.get("pid")) and existing.get("state") not in media_session.TERMINAL_STATES:
        # Idempotent: a live session already answers to this id. Never start a second one --
        # IDE-R is a single-session protocol, and firmware only has one connection to give.
        fields = _status_fields(existing)
        receipt = OperationReceipt(
            action="amt_media.attach",
            endpoint=endpoint,
            changed=False,
            previous=existing,
            desired=None,
            observed=existing,
            tls_peer_fingerprint=fields["tls_peer_fingerprint"],
        )
        return _finalize(receipt, session_id=session_id, fields=fields)

    recovered_stale = existing is not None
    if recovered_stale:
        media_session.remove_state(runtime_dir, session_id)

    specs = build_media_specs(params)
    media_session.validate_media_specs(specs, allowed_directory=params.get("allowed_directory"))

    if module.check_mode:
        fields = {
            "session_state": "starting",
            "pid": None,
            "bytes_read": 0,
            "bytes_written": 0,
            "devices": {},
            "error": None,
            "tls_peer_fingerprint": None,
        }
        receipt = OperationReceipt(action="amt_media.attach", endpoint=endpoint, changed=True, previous=existing, desired="attached", observed=None)
        return _finalize(receipt, session_id=session_id, fields=fields, recovered_stale_session=recovered_stale)

    config = build_session_config(params, session_id=session_id, port=port, specs=specs)
    media_session.spawn_session(config, username=params["username"], password=params["password"])

    observed = media_session.wait_for_state(
        runtime_dir,
        session_id,
        until=lambda s: s.get("state") in (media_session.STATE_ATTACHED, media_session.STATE_ERROR, media_session.STATE_DETACHED),
        timeout=float(params["attach_timeout"]),
    )
    fields = _status_fields(observed)

    if fields["session_state"] == media_session.STATE_ERROR:
        module.fail_json(
            msg=f"amt_media attach failed: {fields['error']}",
            error_class=_error_class_of(observed),
            session_id=session_id,
            **fields,
        )

    receipt = OperationReceipt(
        action="amt_media.attach",
        endpoint=endpoint,
        changed=True,
        previous=existing,
        desired="attached",
        observed=observed,
        tls_peer_fingerprint=fields["tls_peer_fingerprint"],
    )
    return _finalize(receipt, session_id=session_id, fields=fields, recovered_stale_session=recovered_stale)


def _detach(module: AnsibleModule, params: dict, *, endpoint: str) -> dict:
    session_id = params["session_id"]
    runtime_dir = params["runtime_dir"]

    existing = media_session.read_state(runtime_dir, session_id)
    if existing is None:
        fields = _status_fields(None)
        receipt = OperationReceipt(action="amt_media.detach", endpoint=endpoint, changed=False, previous=None, desired="detached", observed=None)
        return _finalize(receipt, session_id=session_id, fields=fields)

    pid = existing.get("pid")
    live = media_session.is_pid_alive(pid)

    if module.check_mode:
        fields = _status_fields(existing)
        receipt = OperationReceipt(action="amt_media.detach", endpoint=endpoint, changed=live, previous=existing, desired="detached", observed=existing)
        return _finalize(receipt, session_id=session_id, fields=fields)

    if not live:
        # Stale: nothing live to stop. Clean the file up so the id is usable again, but this was
        # not a mutation of any running thing.
        media_session.remove_state(runtime_dir, session_id)
        fields = _status_fields(existing)
        receipt = OperationReceipt(action="amt_media.detach", endpoint=endpoint, changed=False, previous=existing, desired="detached", observed=existing)
        return _finalize(receipt, session_id=session_id, fields=fields, recovered_stale_session=True)

    media_session.request_stop(pid)
    exited = media_session.wait_for_exit(pid, timeout=float(params["detach_timeout"]))
    final_state = media_session.read_state(runtime_dir, session_id) or existing
    media_session.remove_state(runtime_dir, session_id)

    if not exited:
        module.warn(
            f"amt_media session {session_id} (pid {pid}) did not exit within detach_timeout="
            f"{params['detach_timeout']}s after being signalled; it may still be shutting down."
        )

    fields = _status_fields(final_state)
    receipt = OperationReceipt(
        action="amt_media.detach",
        endpoint=endpoint,
        changed=True,
        previous=existing,
        desired="detached",
        observed=final_state,
        tls_peer_fingerprint=fields["tls_peer_fingerprint"],
    )
    return _finalize(receipt, session_id=session_id, fields=fields, exited_cleanly=exited)


def main() -> None:
    module = AnsibleModule(
        argument_spec=_argument_spec(),
        required_if=[("state", "detached", ["session_id"])],
        supports_check_mode=True,
    )
    params = module.params

    try:
        port = resolve_redirection_port(port=params["port"], use_tls=params["use_tls"])
        endpoint = f"{params['host']}:{port}"

        if params["state"] == "attached":
            # Transport and trust policy are only meaningful when we are about to
            # open a redirection session. Detach opens no connection at all: it
            # reads the state file and signals the recorded pid. Gating it on a
            # trust decision would make a session unstoppable by the very
            # configuration change that should let an operator shut it down --
            # and would leave an orphaned daemon holding media open.
            enforce_transport_policy(use_tls=params["use_tls"], allow_insecure_transport=params["allow_insecure_transport"])
            enforce_redirection_trust_policy(params)
            result = _attach(module, params, endpoint=endpoint, port=port)
        else:
            result = _detach(module, params, endpoint=endpoint)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return

    module.exit_json(**result)


if __name__ == "__main__":
    main()
