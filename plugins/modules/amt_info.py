#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_info
short_description: Gather Intel AMT capability and state facts
description:
  - Reads firmware-observed facts and capabilities from an Intel AMT management
    endpoint over WS-Man -- provisioning state, current power state, and which
    boot/redirection capabilities the firmware actually implements.
  - Capabilities are discovered from live firmware responses, never assumed from
    an AMT generation or SKU. A firmware that omits an optional WS-Man class
    degrades the corresponding capability to V(false)/unknown rather than
    failing the whole read.
  - This module never mutates anything and always reports C(changed=false).
version_added: 0.1.0
author:
  - Jim Crowley (@james-crowley)
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
seealso:
  - module: james_crowley.intel_amt.amt_power
attributes:
  check_mode:
    description: A full read runs identically in check mode, since this module never mutates firmware state.
    support: full
    details:
      - >-
        A full read runs in check mode identically to normal mode: this module
        never mutates firmware state, so there is nothing check mode changes.
  diff_mode:
    description: Not supported. There is no prior/after state to diff for a read-only module.
    support: none
    details:
      - There is no prior/after state to diff for a read-only module.
"""

EXAMPLES = r"""
- name: Read AMT capabilities and state
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: amt

- name: Require IDE-R support before attempting a media-backed install
  ansible.builtin.assert:
    that:
      - amt.amt.reachable
      - amt.amt.capabilities.storage_redirection
"""

RETURN = r"""
amt:
  description: Firmware-observed facts and capabilities.
  returned: success
  type: dict
  contains:
    reachable:
      description: Whether the WS-Man management plane answered this read at all.
      type: bool
      returned: always
      sample: true
    version:
      description: AMT firmware/version string, when the firmware reports one.
      type: str
      returned: when available
      sample: "11.8.50"
    uuid:
      description: >-
        The endpoint's system UUID, read from C(CIM_ComputerSystemPackage.PlatformGUID) and
        rendered in the canonical dashed form an operator sees in MEBx or BIOS. The firmware
        returns 32 undashed hex characters holding an SMBIOS Type 1 UUID, whose first three
        fields are little-endian, so those fields are byte-reversed on the way out. Any value
        that is not exactly 32 bare hex characters is reported verbatim rather than reformatted.
      type: str
      returned: when available
    control_mode:
      description: Provisioning/control mode reported by C(AMT_SetupAndConfigurationService).
      type: str
      returned: when available
    provisioning_state:
      description: Provisioning state reported by C(AMT_SetupAndConfigurationService).
      type: str
      returned: when available
    hostname:
      description: >-
        Hostname the firmware itself reports (C(AMT_GeneralSettings.HostName)).
        This is firmware-observed evidence, not a value taken from inventory.
      type: str
      returned: when available
    power_state:
      description: Current power state, normalized from the CIM power-state table.
      type: dict
      returned: when available
      contains:
        normalized:
          description: One of V(on), V(off), V(sleep), V(hibernate), V(unknown).
          type: str
        raw:
          description: The raw CIM power-state integer as reported by firmware.
          type: int
    capabilities:
      description: Capability flags discovered from live firmware responses.
      type: dict
      contains:
        power:
          description: Whether the endpoint's power state could be read at all.
          type: bool
        boot_once_pxe:
          description: Whether C(AMT_BootCapabilities) reports one-time forced PXE boot support.
          type: bool
        sol:
          description: Whether C(AMT_BootCapabilities) reports Serial-over-LAN support.
          type: bool
        storage_redirection:
          description: Whether C(AMT_BootCapabilities) reports IDE-R (storage redirection) support.
          type: bool
    redirection_status:
      description: >-
        Current C(AMT_RedirectionService) enablement, distinct from what the
        firmware merely supports (RV(amt.capabilities)).
      type: dict
      returned: when available
      contains:
        enabled_state:
          description: The raw C(EnabledState) value reported by firmware.
          type: int
        listener_enabled:
          description: Whether the redirection listener itself is enabled.
          type: bool
        ider_enabled:
          description: Whether IDE-R is currently enabled (not merely supported).
          type: bool
        sol_enabled:
          description: Whether Serial-over-LAN is currently enabled (not merely supported).
          type: bool
operation:
  description: >-
    The non-secret C(intel-amt-operation/v1) receipt for this read, in the same nested shape
    every other module in this collection returns it under. RV(operation.previous) and
    RV(operation.desired) are always V(null): a read has no prior state and no intended change to
    report. See RV(amt) for what was actually observed -- it is not duplicated under
    RV(operation.observed).
  type: dict
  returned: always
  contains:
    schema:
      description: Always V(intel-amt-operation/v1).
      type: str
    action:
      description: Always V(get_facts).
      type: str
    endpoint:
      description: The C(host:port) this read was performed against.
      type: str
    changed:
      description: Always V(false).
      type: bool
    previous:
      description: Always V(null) -- a read-only module has no prior state to report.
      type: str
    desired:
      description: Always V(null) -- a read-only module has no intended state to report.
      type: str
    observed:
      description: Always V(null). See RV(amt) instead, which carries the actual observed facts.
      type: str
    tls_peer_fingerprint:
      description: >-
        SHA-256 fingerprint of the TLS leaf certificate observed during this read, or V(null) over
        plaintext.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

import dataclasses

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.client import AmtClient
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import HAS_REQUESTS, REQUESTS_IMPORT_ERROR, WsmanClient


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


def facts_to_result(client: AmtClient) -> dict:
    """Gather facts via ``client`` and shape them into this module's C(amt) return key."""
    facts = client.get_facts()

    power_state = None
    if facts.power_state is not None:
        power_state = dataclasses.asdict(facts.power_state)

    redirection_status = None
    if facts.redirection is not None:
        redirection_status = dataclasses.asdict(facts.redirection)

    return {
        "reachable": True,
        "version": facts.version,
        "uuid": facts.uuid,
        "control_mode": facts.control_mode,
        "provisioning_state": facts.provisioning_state,
        "hostname": facts.reported_hostname,
        "power_state": power_state,
        "capabilities": dataclasses.asdict(facts.capabilities),
        "redirection_status": redirection_status,
    }


def main() -> None:
    module = AnsibleModule(argument_spec=_connection_argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    try:
        wsman = build_wsman_client(module.params)
        client = AmtClient(wsman)
        amt = facts_to_result(client)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return

    peer_cert = wsman.last_peer_certificate
    receipt = OperationReceipt(
        action="get_facts",
        endpoint=wsman.endpoint,
        changed=False,
        tls_peer_fingerprint=peer_cert.sha256_fingerprint if peer_cert else None,
    )
    module.exit_json(changed=False, amt=amt, operation=receipt.to_dict())


if __name__ == "__main__":
    main()
