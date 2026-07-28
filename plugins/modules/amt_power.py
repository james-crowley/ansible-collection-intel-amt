#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_power
short_description: Control and query Intel AMT power state
description:
  - Reads and changes the power state of an Intel AMT managed endpoint over WS-Man,
    via C(CIM_AssociatedPowerManagementService) and
    C(CIM_PowerManagementService.RequestPowerStateChange).
  - >-
    O(state=on) and O(state=off) are convergent: the current state is read first,
    and nothing is sent if the endpoint is already in the requested state.
    O(state=reboot), O(state=reset), and O(state=cycle) are imperative and always
    issue a request when not in check mode.
  - >-
    A successful request only means AMT accepted it (C(ReturnValue == 0)), not that
    the transition finished. This module polls a bounded number of times afterwards
    and reports what it actually observed; it never retries a request itself.
version_added: 0.1.0
author:
  - Jim Crowley (@james-crowley)
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
options:
  state:
    description:
      - >-
        Desired power action. V(on) and V(off) are convergent (nothing is sent if
        already in that state). V(reboot) and V(reset) both issue AMT's master-bus-reset
        request (code 10) -- AMT has no separate graceful-reboot primitive, so these are
        two names for the same action. V(cycle) issues a power-off-then-on request.
        V(query) only reads the current state and never mutates anything.
    type: str
    choices: ['on', 'off', 'reboot', 'reset', 'cycle', query]
    default: query
seealso:
  - module: james_crowley.intel_amt.amt_info
attributes:
  check_mode:
    description: >-
      The planned transition is computed and returned exactly as it would be in
      normal mode, but C(RequestPowerStateChange) is never sent.
    support: full
    details:
      - >-
        In check mode, the planned transition is computed and returned exactly as it
        would be in normal mode, but C(RequestPowerStateChange) is never sent.
  diff_mode:
    description: >-
      Not supported. Use the returned RV(previous_state)/RV(desired_state) fields
      instead of C(--diff).
    support: none
    details:
      - >-
        Not implemented. Use the returned RV(previous_state)/RV(desired_state) fields
        instead of C(--diff).
"""

EXAMPLES = r"""
- name: Ensure the endpoint is powered on
  james_crowley.intel_amt.amt_power:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    state: "on"
  delegate_to: localhost
  no_log: true
  register: power

- name: Query current power state without changing anything
  james_crowley.intel_amt.amt_power:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    state: query
  delegate_to: localhost
  no_log: true
  register: power_query

- name: Master-bus-reset into a freshly attached installer image
  james_crowley.intel_amt.amt_power:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    state: reset
  delegate_to: localhost
  no_log: true
"""

RETURN = r"""
state:
  description: The requested O(state), echoed back.
  type: str
  returned: always
previous_state:
  description: Power state observed before any action was taken.
  type: dict
  returned: always
  contains:
    normalized:
      description: One of V(on), V(off), V(sleep), V(hibernate), V(unknown).
      type: str
    raw:
      description: The raw CIM power-state integer as reported by firmware.
      type: int
desired_state:
  description: The normalized power state this action targets. Absent for O(state=query).
  type: str
  returned: when a transition was requested or planned
return_value:
  description: >-
    The AMT C(ReturnValue) from C(RequestPowerStateChange). Only present when a
    request was actually sent -- V(0) always, since a non-zero value raises a
    C(remote_operation) failure instead of being returned here.
  type: int
  returned: when a request was sent
probes:
  description: >-
    Bounded postcondition probe results taken after a request was sent, each with
    the same shape as RV(previous_state). Empty when no request was sent, or when
    every probe attempt itself failed.
  type: list
  elements: dict
  returned: when a request was sent
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
      description: V(amt_power.<state>), e.g. V(amt_power.on).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Mirrors the top-level C(changed) value Ansible always returns.
      type: bool
    previous:
      description: Same shape as RV(previous_state).
      type: dict
    desired:
      description: Same value as RV(desired_state).
      type: str
    observed:
      description: The last postcondition probe taken, same shape as RV(previous_state), or V(null).
      type: dict
    tls_peer_fingerprint:
      description: >-
        SHA-256 fingerprint of the TLS leaf certificate observed during this operation, or V(null)
        over plaintext.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.client import AmtClient, PowerAction
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import HAS_REQUESTS, REQUESTS_IMPORT_ERROR, WsmanClient

#: The convergent states: read-first, no-op if already there.
_CONVERGENT_STATES = ("on", "off")

#: Map a module `state` to the client-level action it issues. `query` has no
#: entry -- it never reaches request_power_state at all.
_STATE_TO_ACTION = {
    "on": PowerAction.ON,
    "off": PowerAction.OFF,
    "reboot": PowerAction.REBOOT,
    "reset": PowerAction.RESET,
    "cycle": PowerAction.CYCLE,
}

#: The normalized end state each action is expected to converge on -- kept
#: alongside the action map for the convergence check and the check-mode
#: preview, both of which need it without sending anything.
_ACTION_EXPECTED_STATE = {
    PowerAction.ON: "on",
    PowerAction.OFF: "off",
    PowerAction.REBOOT: "on",
    PowerAction.RESET: "on",
    PowerAction.CYCLE: "on",
}


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
    spec["state"] = {
        "type": "str",
        "choices": ["on", "off", "reboot", "reset", "cycle", "query"],
        "default": "query",
    }
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


def plan(state: str, previous_normalized: str) -> tuple[bool, str | None]:
    """Decide whether a request is needed, and what it would target.

    Returns ``(changed, desired_normalized)``. ``query`` never changes anything;
    V(on)/V(off) are convergent and only change when the observed state differs;
    V(reboot)/V(reset)/V(cycle) are imperative and always report ``changed=True``
    once a request would be issued -- this function does not know about check
    mode, which is the caller's concern.
    """
    if state == "query":
        return False, None
    action = _STATE_TO_ACTION[state]
    desired = _ACTION_EXPECTED_STATE[action]
    if state in _CONVERGENT_STATES:
        return previous_normalized != desired, desired
    return True, desired


def result_from_receipt(state: str, receipt: OperationReceipt) -> dict:
    return {
        "changed": receipt.changed,
        "state": state,
        "previous_state": _state_dict(receipt.previous),
        "desired_state": receipt.desired,
        "return_value": receipt.extra.get("return_value"),
        "probes": receipt.extra.get("probes", []),
        "operation": receipt.to_dict(),
    }


def _state_dict(power_state) -> dict | None:
    if power_state is None:
        return None
    return {"normalized": power_state.normalized, "raw": power_state.raw}


def main() -> None:
    module = AnsibleModule(argument_spec=argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests", reason=REQUESTS_IMPORT_ERROR))

    state = module.params["state"]

    try:
        wsman = build_wsman_client(module.params)
        client = AmtClient(wsman)
        previous = client.get_power_state()
        changed, desired = plan(state, previous.normalized)

        if not changed or module.check_mode:
            receipt = OperationReceipt(
                action=f"amt_power.{state}",
                endpoint=wsman.endpoint,
                changed=changed,
                previous=previous,
                desired=desired,
            )
            module.exit_json(**result_from_receipt(state, receipt))
            return

        action = _STATE_TO_ACTION[state]
        receipt = client.request_power_state(action)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return

    module.exit_json(**result_from_receipt(state, receipt))


if __name__ == "__main__":
    main()
