#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_redirection
short_description: Report and optionally toggle Intel AMT redirection-service enablement
description:
  - >-
    Reads (and, if O(state) is given, mutates) whether the Intel AMT redirection service -- IDE-R
    and/or Serial-over-LAN -- is enabled at the WS-Man management layer, plus whether the
    redirection ports are actually reachable over TCP.
  - >-
    Three separate signals are always reported and never collapsed into one boolean: whether the
    firmware advertises support for IDER/SOL at all (C(AMT_BootCapabilities)), whether the
    redirection service is currently enabled (C(AMT_RedirectionService.EnabledState)), and whether
    a bare TCP connect to ports 16994/16995 actually succeeds. A machine can be supported and
    enabled yet unreachable behind a firewall, or reachable on the port while the service itself
    is disabled -- collapsing these would hide exactly the distinction an operator needs.
  - >-
    This module does not attach or stream any media, and it does not itself open a redirection
    session -- it only reports and toggles the WS-Man-level enablement flag. Attaching and
    streaming IDE-R media is M(james_crowley.intel_amt.amt_media)'s job, not this module's.
  - Without O(state), this module is read-only and always reports C(changed=false).
version_added: 0.1.0
author:
  - Jim Crowley (@james-crowley)
options:
  state:
    description:
      - >-
        When set, requests this redirection-service state via C(AMT_RedirectionService.RequestStateChange):
        V(disabled) turns both IDE-R and SOL off, V(ider) enables IDE-R only, V(sol) enables SOL
        only, and V(all) enables both.
      - >-
        When absent (the default), the module only reads and reports current state; C(changed) is
        always V(false) in that case.
      - >-
        Requesting V(ider), V(sol), or V(all) when the firmware does not advertise the
        corresponding capability fails with C(error_class=unsupported_capability) before any
        mutation is attempted.
    type: str
    choices: [disabled, ider, sol, all]
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
attributes:
  check_mode:
    description: >-
      Supported. With O(state) set, reports the state that would be requested and whether it
      differs from the current state, without invoking C(RequestStateChange).
    support: full
  diff_mode:
    description: Returns the previous and (with O(state) set) intended enabled-state in the operation receipt.
    support: full
"""

EXAMPLES = r"""
- name: Report redirection-service support, enablement, and reachability
  james_crowley.intel_amt.amt_redirection:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt_redirection_status

- name: Enable IDE-R ahead of a virtual-media attach
  james_crowley.intel_amt.amt_redirection:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    state: ider
  delegate_to: localhost
  no_log: true

- name: Turn redirection off entirely once a job is done
  james_crowley.intel_amt.amt_redirection:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    state: disabled
  delegate_to: localhost
  no_log: true
"""

RETURN = r"""
changed:
  description: >-
    V(true) only when O(state) was given, differed from the observed state, and (outside check
    mode) C(RequestStateChange) was invoked. Always V(false) when O(state) is absent.
  type: bool
  returned: always
supported:
  description: >-
    What C(AMT_BootCapabilities) advertises. Contains C(ider) and C(sol) booleans. This is a
    separate signal from C(enabled) and C(transport_reachable) and must not be read as implying
    either of them.
  type: dict
  returned: always
enabled:
  description: >-
    The current (or, on a successful mutation, resulting) C(AMT_RedirectionService) state:
    C(enabled_state) (the raw CIM integer), C(listener_enabled), C(ider_enabled), and C(sol_enabled).
  type: dict
  returned: always
transport_reachable:
  description: >-
    Whether a bare TCP connect to each redirection port succeeded, keyed by port number (V(16994)
    and V(16995)). This does not attempt any redirection-protocol handshake -- see
    M(james_crowley.intel_amt.amt_media) for that.
  type: dict
  returned: always
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
      description: Always V(amt_redirection).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Mirrors the top-level RV(changed).
      type: bool
    previous:
      description: The C(AMT_RedirectionService) state name observed before any action, or V(null).
      type: str
    desired:
      description: The O(state) requested, or V(null) when O(state) is absent.
      type: str
    observed:
      description: Same shape as the top-level RV(enabled).
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

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import redirection_service
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.tls import resolve_port
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    HAS_REQUESTS,
    REQUESTS_IMPORT_ERROR,
    WsmanClient,
)


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
        "state": {"type": "str", "choices": ["disabled", "ider", "sol", "all"]},
    }


def _status_dicts(status: redirection_service.RedirectionStatus) -> tuple[dict, dict, dict]:
    supported = {"ider": status.capabilities.ider_supported, "sol": status.capabilities.sol_supported}
    enabled = {
        "enabled_state": status.state.enabled_state,
        "listener_enabled": status.state.listener_enabled,
        "ider_enabled": status.state.ider_enabled,
        "sol_enabled": status.state.sol_enabled,
    }
    transport_reachable = dict(status.transport_reachable)
    return supported, enabled, transport_reachable


def main() -> None:
    module = AnsibleModule(argument_spec=_argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    params = module.params
    endpoint = f"{params['host']}:{resolve_port(port=params['port'], use_tls=params['use_tls'])}"
    desired_state_name = params["state"]

    client = WsmanClient.from_connection_options(
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

    try:
        status = redirection_service.get_status(client, params["host"])
        previous_state_name = redirection_service.ENABLED_STATE_TO_STATE_NAME.get(status.state.enabled_state)
        changed = desired_state_name is not None and desired_state_name != previous_state_name

        if changed:
            # Discovery before mutation, same principle as amt_boot: fail unsupported_capability
            # before RequestStateChange is ever invoked.
            redirection_service.validate_state_change(status.capabilities, desired_state_name)
            if not module.check_mode:
                redirection_service.request_state_change(client, desired_state_name)
                status = redirection_service.get_status(client, params["host"])
    except AmtError as err:
        module.fail_json(**err.to_result())
        return
    finally:
        client.close()

    supported, enabled, transport_reachable = _status_dicts(status)

    receipt = OperationReceipt(
        action="amt_redirection",
        endpoint=endpoint,
        changed=changed,
        previous=previous_state_name,
        desired=desired_state_name,
        observed=enabled,
        tls_peer_fingerprint=(client.last_peer_certificate.sha256_fingerprint if client.last_peer_certificate else None),
    )
    module.exit_json(
        changed=changed,
        supported=supported,
        enabled=enabled,
        transport_reachable=transport_reachable,
        operation=receipt.to_dict(),
    )


if __name__ == "__main__":
    main()
