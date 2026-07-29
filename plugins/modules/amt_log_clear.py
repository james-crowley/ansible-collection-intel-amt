#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_log_clear
short_description: Clear the Intel AMT event log
description:
  - >-
    Clears the Intel AMT event log over WS-Man, via C(AMT_MessageLog.ClearLog).
  - >-
    B(This is irreversible.) The records are gone; there is no undo and no
    firmware-side archive. It cannot strand the management path -- clearing a log
    does not affect reachability -- so the risk here is B(destroyed forensic
    evidence), not lost access. The event log is the only record of why an
    unattended install failed, so clearing it before reading it discards the one
    artefact that explains the failure. Read with
    M(james_crowley.intel_amt.amt_event_log) first.
  - >-
    Because of that, the module refuses to do anything unless O(confirm_destructive=true)
    is set explicitly, mirroring C(amt_baremetal_install_confirm_destructive) in the
    C(amt_baremetal_install) role. A bare invocation never clears.
  - >-
    Convergent on an already-empty log: if C(CurrentNumberOfRecords) reads V(0)
    beforehand, nothing is sent and C(changed) is V(false). There is nothing to
    destroy, and reporting a change for a no-op would be wrong. If firmware does
    not report the count at all, the clear is attempted rather than assumed
    unnecessary.
  - >-
    B(Neither this module nor M(james_crowley.intel_amt.amt_event_log) has been
    exercised against real firmware.) No hardware qualification stage covers them.
    The wire protocol is per the sources recorded in C(docs/protocol-notes.md) §2.8.
version_added: 0.3.0
author:
  - Jim Crowley (@james-crowley)
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
options:
  confirm_destructive:
    description:
      - >-
        Must be set to V(true) or the module refuses to run, before it opens a
        connection or reads anything. Clearing the event log destroys the only
        record of why an unattended install failed.
      - >-
        The refusal applies in check mode too. C(--check) is for previewing a
        correctly-configured play, not for discovering that the confirmation is
        missing only once the play runs for real. To preview safely, set
        O(confirm_destructive=true) B(and) run with C(--check) -- that reads the
        record count and reports what would be cleared, sending nothing.
      - >-
        Set it at the point of use (for example C(-e amt_confirm_clear=true) fed
        into this option), not in a checked-in defaults file, so the confirmation
        stays a deliberate act.
    type: bool
    default: false
seealso:
  - module: james_crowley.intel_amt.amt_event_log
attributes:
  check_mode:
    description: >-
      Fully supported, and it really reads: C(CurrentNumberOfRecords) is fetched and
      reported so the preview says how many records would be destroyed. Nothing is sent.
    support: full
    details:
      - >-
        Fully supported, and it really reads. C(CurrentNumberOfRecords) is fetched so the
        preview reports how many records B(would) be destroyed, and C(ClearLog) is never
        invoked. A check-mode run that reported C(changed) without reading anything would
        make check mode useless for exactly the decision it is needed for.
  diff_mode:
    description: >-
      Not supported. Use the returned RV(records_before)/RV(records_after) fields instead
      of C(--diff).
    support: none
    details:
      - >-
        Not supported. Use the returned RV(records_before)/RV(records_after) fields
        instead of C(--diff).
"""

EXAMPLES = r"""
- name: Preview what clearing the event log would destroy, without clearing it
  james_crowley.intel_amt.amt_log_clear:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    confirm_destructive: true
  delegate_to: localhost
  no_log: true
  check_mode: true
  register: clear_preview

- name: Report how many records the clear would destroy
  ansible.builtin.debug:
    msg: "Clearing would discard {{ clear_preview.records_before }} event log records."

# Read the log before destroying it: after ClearLog there is nothing left to diagnose
# an install failure with.
- name: Archive the event log before clearing it
  james_crowley.intel_amt.amt_event_log:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: archived_log

- name: Save the archived records to the controller
  ansible.builtin.copy:
    content: "{{ archived_log.records | to_nice_json }}"
    dest: "{{ evidence_dir }}/amt-event-log.json"
    mode: "0600"
  delegate_to: localhost

- name: Clear the event log for real
  james_crowley.intel_amt.amt_log_clear:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    confirm_destructive: "{{ amt_confirm_clear | default(false) }}"
  delegate_to: localhost
  no_log: true
  register: cleared

- name: Assert the log really is empty afterwards
  ansible.builtin.assert:
    that:
      - cleared.records_after == 0
    fail_msg: >-
      ClearLog was accepted but the log still reports {{ cleared.records_after }} records.
"""

RETURN = r"""
records_before:
  description: >-
    C(AMT_MessageLog.CurrentNumberOfRecords) read B(before) anything was sent -- how many
    records were about to be destroyed. V(null) if firmware did not report it.
  type: int
  returned: always
records_after:
  description: >-
    C(CurrentNumberOfRecords) re-read B(after) C(ClearLog) returned. Expected V(0). This
    is observed, not assumed: C(ReturnValue == 0) means AMT accepted the request, not that
    the log is empty. V(null) in check mode, and when no clear was sent.
  type: int
  returned: always
cleared:
  description: >-
    V(true) only when C(ClearLog) was actually invoked and accepted. V(false) in check
    mode, and when the log was already empty.
  type: bool
  returned: always
return_value:
  description: >-
    The AMT C(ReturnValue) from C(ClearLog). Only present when a request was sent --
    V(0) always, since a non-zero value raises a C(remote_operation) failure instead of
    being returned here.
  type: int
  returned: when a request was sent
log:
  description: >-
    The C(AMT_MessageLog) container properties as read before the clear -- capacity,
    record size, overwrite policy, capabilities. C(capabilities) containing V(6)
    (C(ClearLogSupported)) is firmware stating this method is implemented.
  type: dict
  returned: always
operation:
  description: >-
    The C(intel-amt-operation/v1) receipt for this action, in the same nested shape every
    module in this collection returns it under.
  type: dict
  returned: always
  contains:
    schema:
      description: Always V(intel-amt-operation/v1).
      type: str
    action:
      description: Always V(amt_log_clear.clear).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Mirrors the top-level C(changed) value Ansible always returns.
      type: bool
    previous:
      description: The record count before the clear, as C(current_number_of_records).
      type: dict
    desired:
      description: Always C(current_number_of_records) V(0) -- the state a clear targets.
      type: dict
    observed:
      description: >-
        The record count re-read after the clear, as C(current_number_of_records).
        V(null) when nothing was sent.
      type: dict
    tls_peer_fingerprint:
      description: SHA-256 fingerprint of the TLS leaf certificate observed, or V(null) over plaintext.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

import dataclasses

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import message_log
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError, InvalidStateError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import HAS_REQUESTS, REQUESTS_IMPORT_ERROR, WsmanClient

#: The message the confirmation gate refuses with. A constant so the unit test
#: asserting the refusal cannot drift from the text an operator actually sees.
CONFIRMATION_REQUIRED_MSG = (
    "Refusing to clear the Intel AMT event log: confirm_destructive is not true. "
    "Clearing is irreversible and destroys the only record of why an unattended install failed -- "
    "read it with amt_event_log first. Re-run with confirm_destructive=true only after confirming "
    "this is the intended target. This refusal also applies in check mode, deliberately."
)


def _connection_argument_spec() -> dict[str, dict]:
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
    }


def argument_spec() -> dict[str, dict]:
    spec = _connection_argument_spec()
    spec["confirm_destructive"] = {"type": "bool", "default": False}
    return spec


def build_wsman_client(params: dict) -> WsmanClient:
    """Construct a :class:`WsmanClient` from the module's connection parameters."""
    return WsmanClient.from_connection_options(
        host=params["host"],
        port=params["port"],
        username=params["username"],
        password=params["password"],
        use_tls=params["use_tls"],
        allow_insecure_transport=params["allow_insecure_transport"],
        validate_certs=params["validate_certs"],
        ca_path=params["ca_path"],
        tls_fingerprint=params["tls_fingerprint"],
        timeout=params["timeout"],
        connect_timeout=params["connect_timeout"],
    )


def plan(records_before: int | None) -> bool:
    """Decide whether a clear is worth sending, given the record count read first.

    ``0`` means the log is already empty: there is nothing to destroy, so nothing
    is sent and ``changed`` is ``False``. ``None`` means firmware did not report
    the count -- which is emphatically **not** the same as reporting zero, and
    must not be treated as "already clean", so the clear is attempted.
    """
    return records_before is None or records_before > 0


def _count_dict(count: int | None) -> dict[str, int | None] | None:
    return None if count is None else {"current_number_of_records": count}


def main() -> None:
    module = AnsibleModule(argument_spec=argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    try:
        wsman = build_wsman_client(module.params)

        # The gate is checked before the first WS-Man request, so an unconfirmed
        # invocation touches the endpoint not at all -- it does not even
        # authenticate. Classified `invalid_state` because that is the closest of
        # the nine stable error classes: the operation is not legal as invoked.
        # It is a *client-side* refusal, not a firmware state report, and
        # docs/amt_log_clear.md says so where an operator branching on the class
        # will see it.
        if not module.params["confirm_destructive"]:
            raise InvalidStateError(
                CONFIRMATION_REQUIRED_MSG,
                endpoint=wsman.endpoint,
                operation="amt_log_clear.clear",
            )

        properties = message_log.get_log_properties(wsman)
        records_before = properties.current_number_of_records
        should_clear = plan(records_before)

        records_after: int | None = None
        return_value: int | None = None
        cleared = False

        if should_clear and not module.check_mode:
            # A non-zero ReturnValue propagates out of clear_log() as
            # RemoteOperationError. It is never demoted to a warning: an operator
            # told "cleared" about a log that was not cleared will go looking for
            # evidence that is still there, or stop looking for evidence that is not.
            return_value = message_log.clear_log(wsman)
            cleared = True
            # Observed, not assumed. ReturnValue == 0 means AMT accepted the
            # request; only a re-read says what the log now holds.
            records_after = message_log.get_log_properties(wsman).current_number_of_records

        peer_cert = wsman.last_peer_certificate
        receipt = OperationReceipt(
            action="amt_log_clear.clear",
            endpoint=wsman.endpoint,
            changed=should_clear,
            previous=_count_dict(records_before),
            desired={"current_number_of_records": 0},
            observed=_count_dict(records_after),
            tls_peer_fingerprint=peer_cert.sha256_fingerprint if peer_cert else None,
        )
    except AmtError as err:
        module.fail_json(**err.to_result())
        return

    module.exit_json(
        changed=should_clear,
        records_before=records_before,
        records_after=records_after,
        cleared=cleared,
        return_value=return_value,
        log=dataclasses.asdict(properties),
        operation=receipt.to_dict(),
    )


if __name__ == "__main__":
    main()
