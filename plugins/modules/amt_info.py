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
  - >-
    Round-trip cost. One invocation performs ten WS-Man HTTP requests: eight
    C(Get) operations plus an C(Enumerate)/C(Pull) pair for
    C(CIM_SoftwareIdentity). Three of the C(Get)s are new in this release --
    C(AMT_EthernetPortSettings) instance 0, C(CIM_ComputerSystem) with selector
    C(Name=ManagedSystem), and C(CIM_BIOSElement). The C(CIM_ComputerSystem)
    read had previously been removed precisely to save a round trip, when it
    existed only to source a C(UUID) property that class does not define; it is
    back because it does define the three state fields under
    RV(amt.system_state). C(CIM_BIOSElement) may cost one further
    C(Enumerate)/C(Pull) pair, but only on firmware where the bare C(Get)
    faults.
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

- name: Warn when this endpoint will not answer WS-Man while powered off
  ansible.builtin.debug:
    msg: >-
      LinkPolicy {{ amt.amt.network.link_policy }} carries no Sx value (14 = Sx AC, 224 =
      Sx DC), so the link is maintained only while the host is running and a later
      amt_power state=on will fail looking like a network fault rather than the
      configuration issue it is.
  when:
    - amt.amt.network is not none
    - amt.amt.network.wake_on_lan_capable is false

- name: Cross-check both identity anchors before doing anything destructive
  ansible.builtin.assert:
    that:
      - amt.amt.uuid == amt_expected_uuid
      - amt.amt.network.mac_address == (amt_expected_mac | lower)
    fail_msg: Endpoint evidence disagrees with the reviewed inventory binding; refusing to proceed.
  when: amt_expected_uuid is defined and amt_expected_mac is defined
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
    domain_name:
      description: >-
        Domain name the firmware reports (C(AMT_GeneralSettings.DomainName)).
        Firmware-observed, not an inventory value, and read from the same
        instance as RV(amt.hostname) at no extra WS-Man round trip.
      type: str
      returned: when available
      sample: amt.example.invalid
    idle_wake_timeout:
      description: >-
        C(AMT_GeneralSettings.IdleWakeTimeout), in minutes -- how long AMT stays
        awake in a low-power state before returning to sleep.
      type: int
      returned: when available
      sample: 1
    ping_response_enabled:
      description: >-
        C(AMT_GeneralSettings.PingResponseEnabled) -- whether AMT answers ICMP
        echo. This is the ping-response toggle; RV(amt.network.ip_sync_enabled)
        is not, despite what some other tooling implies.
      type: bool
      returned: when available
    rmcp_ping_response_enabled:
      description: C(AMT_GeneralSettings.RmcpPingResponseEnabled) -- whether AMT answers RMCP ping.
      type: bool
      returned: when available
    network_interface_enabled:
      description: C(AMT_GeneralSettings.NetworkInterfaceEnabled) -- whether AMT's own network interface is enabled.
      type: bool
      returned: when available
    ddns_update_enabled:
      description: C(AMT_GeneralSettings.DDNSUpdateEnabled) -- whether AMT registers itself in DNS via dynamic update.
      type: bool
      returned: when available
    bios_version:
      description: >-
        Host BIOS version from C(CIM_BIOSElement.Version) -- the platform's BIOS, not
        the AMT firmware version (that is RV(amt.version)). This is the least
        well-evidenced field this module returns; see the module documentation and
        C(docs/capability-matrix.md). V(null) whenever the class or property is absent.
      type: str
      returned: when available
      sample: EXAMPLE10H.86A.0000.2026.0101.0000
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
    network:
      description: >-
        C(AMT_EthernetPortSettings) instance 0 -- the wired port AMT itself answers
        on -- read with an explicit C(Get) selector
        (C(InstanceID="Intel(r) AMT Ethernet Port Settings 0")). V(null) when the
        class or that instance is absent. Instance 0 only. Higher indices exist on
        multi-NIC parts and are deliberately not looked for.
      type: dict
      returned: when available
      contains:
        mac_address:
          description: >-
            C(MACAddress), normalized to colon-separated lowercase. A second
            independent identity anchor alongside RV(amt.uuid), and the value a
            PXE reservation is keyed on. Real firmware has been observed
            returning this dash-separated, so it is normalized on ingest;
            RV(amt.network.mac_address_raw) keeps the original.
          type: str
          sample: "00:00:5e:00:53:01"
        mac_address_raw:
          description: C(MACAddress) exactly as the firmware reported it, separators and case included.
          type: str
          sample: 00-00-5e-00-53-01
        ip_address:
          description: C(IPAddress) -- AMT's IPv4 address.
          type: str
          sample: 192.0.2.10
        subnet_mask:
          description: C(SubnetMask).
          type: str
          sample: 255.255.255.0
        default_gateway:
          description: C(DefaultGateway).
          type: str
          sample: 192.0.2.1
        primary_dns:
          description: C(PrimaryDNS).
          type: str
          sample: 192.0.2.2
        secondary_dns:
          description: C(SecondaryDNS).
          type: str
          sample: 192.0.2.3
        dhcp_enabled:
          description: C(DHCPEnabled) -- whether AMT obtains its address by DHCP.
          type: bool
        link_is_up:
          description: C(LinkIsUp) -- whether the port reports link at the time of the read.
          type: bool
        ip_sync_enabled:
          description: >-
            C(IpSyncEnabled) -- whether AMT shares the host operating system's IP
            address rather than holding its own. This is B(not) a ping-response
            toggle; RV(amt.ping_response_enabled) is that.
          type: bool
        link_policy:
          description: >-
            Raw C(LinkPolicy) values -- which host power states and power sources
            AMT keeps the network link up in. V(1) = available on S0 AC, V(14) =
            available on Sx AC, V(16) = available on S0 DC, V(224) = available on
            Sx DC. S0 is "host powered on", Sx is any other ACPI state (sleep,
            hibernate, off); AC/DC is the power source. There is no
            "always on" value. V(null) when the property is absent, V([]) when it
            is present but empty.
          type: list
          elements: int
          sample: [1, 14]
        link_policy_names:
          description: >-
            RV(amt.network.link_policy) decoded, element-wise, into
            V(s0_ac)/V(sx_ac)/V(s0_dc)/V(sx_dc). Only those four values are defined
            by Intel; anything else renders as V(unknown(<raw>)) rather than being
            dropped. B(Changed in 0.3.1) -- V(14) now correctly decodes to V(sx_ac)
            and V(16) to V(s0_dc), and V(always_on) is gone.
          type: list
          elements: str
          sample: ["s0_ac", "sx_ac"]
        wake_on_lan_capable:
          description: >-
            Derived: whether C(LinkPolicy) contains an B(Sx) value -- V(14) (Sx AC)
            or V(224) (Sx DC) -- meaning AMT maintains the network link while the
            host is asleep, hibernating or off. An endpoint with only S0 values
            (V(1), V(16)) does not answer WS-Man in those states, so C(amt_power)
            with C(state=on) fails there in a way that looks like a network fault
            rather than a configuration one. V(null) when C(LinkPolicy) was not
            reported at all -- unknown is not the same finding as V(false).
            B(Changed in 0.3.1) -- 0.2.0 and 0.3.0 keyed this off V(16), which is
            in fact "S0 DC", and so returned the inverse answer on mains-powered
            hardware. The name is kept for compatibility even though it reads only
            C(LinkPolicy) and not AMT's wake settings.
          type: bool
    system_state:
      description: >-
        C(CIM_ComputerSystem) state, read with selector C(Name=ManagedSystem).
        V(null) when the class is absent. This read costs one WS-Man round trip
        that a previous release removed; it is back for these fields and B(not)
        for a UUID, which this class does not carry (RV(amt.uuid) comes from
        C(CIM_ComputerSystemPackage.PlatformGUID)).
      type: dict
      returned: when available
      contains:
        element_name:
          description: C(ElementName) -- the system's own label. Read instead of C(Name), which is just the selector value.
          type: str
          sample: ManagedSystem
        enabled_state:
          description: Raw DMTF C(EnabledState) integer.
          type: int
          sample: 2
        enabled_state_text:
          description: >-
            C(EnabledState) decoded per DMTF -- V(unknown) (0), V(other) (1),
            V(enabled) (2), V(disabled) (3), V(shutting_down) (4),
            V(not_applicable) (5), V(enabled_but_offline) (6), V(in_test) (7),
            V(deferred) (8), V(quiesce) (9), V(starting) (10). A value outside the
            table renders as V(unknown(<raw>)).
          type: str
          sample: enabled
        requested_state:
          description: >-
            Raw DMTF C(RequestedState) integer. Reported raw and undecoded on
            purpose - no value table for it is claimed here. AMT 10 has been
            observed reporting V(12), which DMTF defines as "Not Applicable".
          type: int
          sample: 12
        operational_status:
          description: >-
            Raw DMTF C(OperationalStatus) values. Always a list: CIM types this
            property as an array, and firmware reporting a single value is simply
            an array of one.
          type: list
          elements: int
          sample: [2]
        operational_status_text:
          description: >-
            C(OperationalStatus) decoded element-wise per DMTF -- V(unknown) (0),
            V(other) (1), V(ok) (2), V(degraded) (3), V(stressed) (4),
            V(predictive_failure) (5), V(error) (6), V(non_recoverable_error) (7),
            V(starting) (8), V(stopping) (9), V(stopped) (10), V(in_service) (11),
            V(no_contact) (12), V(lost_communication) (13), V(aborted) (14),
            V(dormant) (15), V(supporting_entity_in_error) (16), V(completed) (17),
            V(power_mode) (18), V(relocating) (19).
          type: list
          elements: str
          sample: ["ok"]
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

    # Additive only. Every key that existed before keeps its name, position and
    # shape -- roles/amt_baremetal_install, the integration targets and
    # tests/hardware all read `amt.capabilities.*`, `amt.reachable` and
    # `amt.power_state.*` and must not have to change.
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
        "domain_name": facts.reported_domain_name,
        "idle_wake_timeout": facts.idle_wake_timeout,
        "ping_response_enabled": facts.ping_response_enabled,
        "rmcp_ping_response_enabled": facts.rmcp_ping_response_enabled,
        "network_interface_enabled": facts.network_interface_enabled,
        "ddns_update_enabled": facts.ddns_update_enabled,
        "network": dataclasses.asdict(facts.network) if facts.network is not None else None,
        "system_state": dataclasses.asdict(facts.system_state) if facts.system_state is not None else None,
        "bios_version": facts.bios_version,
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
