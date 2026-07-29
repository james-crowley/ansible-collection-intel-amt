#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_boot
short_description: Arm a one-time boot device selection on an Intel AMT endpoint
description:
  - >-
    Arms exactly one upcoming reset to boot from a specific device, using the five-step
    C(AMT_BootSettingData) / C(CIM_BootConfigSetting) / C(CIM_BootService) sequence documented in
    this collection's protocol notes. The selection is a one-shot C(IsNextSingleUse) role and is
    consumed by the next reset the endpoint experiences, however that reset happens.
  - >-
    This module never issues a power action itself. Pair it with M(james_crowley.intel_amt.amt_power)
    (or an external reset) to actually apply the boot selection once it is armed.
  - >-
    This is the highest-consequence operation in this collection: a machine left with a wrong boot
    configuration typically needs physical or KVM recovery. The module refuses to arm anything
    without an explicit O(action_token), enumerates the endpoint's boot capabilities and sources
    before touching anything, and never re-arms automatically -- a retry after an uncertain result
    requires a fresh O(action_token) from the caller.
version_added: 0.1.0
author:
  - Jim Crowley (@james-crowley)
options:
  device:
    description:
      - >-
        Boot device to select for exactly one upcoming reset. V(pxe), V(hdd), and V(cd) each name a
        specific C(CIM_BootSourceSetting) instance (for example V(pxe) selects the instance titled
        C(Intel(r) AMT: Force PXE Boot)).
      - >-
        V(ider_floppy) and V(ider_cdrom) redirect the boot through IDE-R instead: no boot source is
        named, and C(UseIDER)/C(IDERBootDevice) in C(AMT_BootSettingData) do the redirecting. Because
        naming a native boot source in the same operation would override IDE-R redirection, native
        PXE/HDD/CD selection and IDE-R selection are mutually exclusive by construction -- pick one
        O(device) value, never both.
      - V(bios) requests one entry into BIOS/MEBx setup on the next boot rather than selecting a boot source.
    type: str
    required: true
    choices: [pxe, hdd, cd, bios, ider_floppy, ider_cdrom]
  mode:
    description:
      - >-
        Always V(once): every boot selection this module can make is a single-use arm consumed by
        exactly the next reset. There is no persistent boot-order mode.
    type: str
    default: once
    choices: [once]
  action_token:
    description:
      - >-
        Caller-supplied one-time token that must be present and non-empty to arm the boot
        selection, in check mode and in normal mode alike.
      - >-
        This module never arms a boot selection implicitly, and never re-arms one automatically
        after an uncertain reset or a later re-probe of endpoint state. A caller that wants to try
        again after any such uncertainty must generate and supply a new token; reusing the same
        token across separate attempts is a caller decision this module does not second-guess, but
        it never invents or reuses a token on the caller's behalf.
    type: str
    required: true
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
attributes:
  check_mode:
    description: >-
      Supported. Performs discovery and reads C(AMT_BootSettingData) but issues none of the four
      mutating WS-Man calls, so the endpoint's boot configuration is left exactly as found.
    support: full
  diff_mode:
    description: Returns the previous and intended C(AMT_BootSettingData) properties in the operation receipt.
    support: full
"""

EXAMPLES = r"""
# Arming a boot selection is a mutation with a physical consequence, so it is
# usually worth doing one machine at a time. Put `serial: 1` on the enclosing
# PLAY to get that -- `serial` is a play keyword and is rejected outright if
# written on a task ("conflicting action statements"). Do not reach for
# `delegate_to: localhost` instead: it moves execution to the controller but
# does nothing to inventory fan-out, so the task below still runs once per host
# in the batch, in parallel, unless the play limits the batch size.
- name: Arm a one-time PXE boot for an unattended install
  james_crowley.intel_amt.amt_boot:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    device: pxe
    action_token: "{{ lookup('ansible.builtin.password', '/dev/null length=32') }}"
  delegate_to: localhost
  no_log: true

- name: Arm IDE-R floppy redirection for a writable answer-file image
  james_crowley.intel_amt.amt_boot:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    device: ider_floppy
    action_token: "{{ boot_action_token }}"
  delegate_to: localhost
  no_log: true

- name: Preview the plan without arming anything
  james_crowley.intel_amt.amt_boot:
    host: 10.0.0.5
    username: admin
    password: "{{ vaulted_amt_password }}"
    tls_fingerprint: "{{ vaulted_amt_tls_fingerprint }}"
    device: hdd
    action_token: preview-only-not-applied
  delegate_to: localhost
  no_log: true
  check_mode: true
"""

RETURN = r"""
changed:
  description: >-
    Whether the boot selection was (or, in check mode, would be) armed. Always V(true) on success,
    since arming is not idempotent against prior state -- every successful call re-clears and
    re-sets the boot order.
  type: bool
  returned: always
device:
  description: The O(device) value that was armed.
  type: str
  returned: always
boot_config_selector:
  description: The C(CIM_BootConfigSetting) selector used for steps 2, 4, and 5.
  type: dict
  returned: always
boot_source_selector:
  description: >-
    The C(CIM_BootSourceSetting) selector named in step 5, or V(null) for O(device) values that
    pass a null Source (V(bios), V(ider_floppy), V(ider_cdrom)).
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
      description: Always V(amt_boot).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Mirrors the top-level RV(changed).
      type: bool
    previous:
      description: The C(AMT_BootSettingData) properties as read before any mutation.
      type: dict
    desired:
      description: The C(AMT_BootSettingData) properties this module attempted (or, in check mode, would attempt) to Put.
      type: dict
    observed:
      description: >-
        The C(AMT_BootSettingData) properties read back after the sequence completed. Equal to
        C(previous) in check mode, since nothing was mutated.
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

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import boot
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
        "device": {"type": "str", "required": True, "choices": list(boot.BOOT_TARGETS)},
        "mode": {"type": "str", "default": "once", "choices": ["once"]},
        "action_token": {"type": "str", "required": True, "no_log": False},
    }


def main() -> None:
    module = AnsibleModule(argument_spec=_argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    params = module.params
    endpoint = f"{params['host']}:{resolve_port(port=params['port'], use_tls=params['use_tls'])}"

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
        result = boot.arm_one_time_boot(
            client,
            params["device"],
            action_token=params["action_token"],
            check_mode=module.check_mode,
        )
    except AmtError as err:
        module.fail_json(**err.to_result())
        return
    finally:
        client.close()

    receipt = OperationReceipt(
        action="amt_boot",
        endpoint=endpoint,
        changed=True,
        previous=result.previous,
        desired=result.put_properties,
        observed=result.observed,
        tls_peer_fingerprint=(client.last_peer_certificate.sha256_fingerprint if client.last_peer_certificate else None),
    )
    module.exit_json(
        changed=True,
        device=result.plan.target,
        boot_config_selector=result.boot_config_selector,
        boot_source_selector=result.boot_source_selector,
        operation=receipt.to_dict(),
    )


if __name__ == "__main__":
    main()
