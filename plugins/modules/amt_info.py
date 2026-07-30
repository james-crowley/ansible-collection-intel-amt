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
    Hardware/asset inventory (system serial number, model, manufacturer,
    baseboard, processors, DIMMs and disks) is available through O(gather_subset)
    and is B(opt-in). Because AMT runs beneath the host operating system, these
    are readable while the machine is B(powered off) -- which is frequently the
    only way to get them. Where an agent is running, use M(ansible.builtin.setup)
    instead; where one is not, AMT is the only source of truth.
  - >-
    Round-trip cost. The default O(gather_subset=config) performs ten WS-Man HTTP
    requests: eight C(Get) operations plus an C(Enumerate)/C(Pull) pair for
    C(CIM_SoftwareIdentity). C(CIM_BIOSElement) may cost one further
    C(Enumerate)/C(Pull) pair, but only on firmware where the bare C(Get)
    faults. Each hardware subset adds its own cost on top, listed under
    O(gather_subset). C(gather_subset=all) costs B(20) requests.
version_added: 0.1.0
author:
  - Jim Crowley (@james-crowley)
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
options:
  gather_subset:
    description:
      - Which fact subsets to gather, using the same C(!)-negation vocabulary as
        M(ansible.builtin.setup)'s O(ansible.builtin.setup#module:gather_subset).
      - >-
        V(config) is everything this module returned before version 0.5.0 --
        provisioning state, power state, capabilities, network and system state.
        It is the default, and it B(cannot be excluded): C(!config) and C(!min)
        are both inert, exactly as C(!min) is inert in M(ansible.builtin.setup).
        That is deliberate, and it is what makes this option unable to break an
        existing caller -- no value of O(gather_subset) can remove a key this
        module returned before 0.5.0.
      - >-
        V(system) reads C(CIM_Chassis) and C(CIM_Card) -- the system serial
        number, model and manufacturer, plus the baseboard's own serial. B(Two)
        C(Get) requests, or up to six on firmware where those C(Get)s fault and
        the C(Enumerate) fallback runs.
      - >-
        V(processor) reads C(CIM_Processor) and C(CIM_Chip). Both, always:
        C(CIM_Processor) carries clocks, socket and stepping but identifies the
        part only by a C(Family) integer this module does not decode, while
        C(CIM_Chip.Version) carries the human-readable processor name. B(Four)
        requests (two C(Enumerate)/C(Pull) pairs).
      - V(memory) reads C(CIM_PhysicalMemory), one instance per DIMM. B(Two) requests.
      - V(storage) reads C(CIM_MediaAccessDevice), one instance per disk. B(Two) requests.
      - V(hardware) is an alias for V(system) + V(processor) + V(memory) + V(storage). B(Ten) requests.
      - V(all) is V(config) + V(hardware). B(Twenty) requests.
      - V(min) is V(config).
      - >-
        Resolution order matches M(ansible.builtin.setup) exactly. Exclusions are
        applied B(last), so V(all) with C(!memory) resolves in favour of the
        exclusion. If the list contains B(no) positive entry -- for example
        C([!memory]) alone -- every subset is gathered and then the exclusions
        applied, so C([!memory]) means "everything except memory" and costs
        B(more) than the default, not less. That is the C(setup) contract and is
        reproduced rather than second-guessed; pass V(config) explicitly if the
        default cost is what you want.
      - >-
        B(This differs from) M(ansible.builtin.setup) B(in exactly one way): the
        default. C(setup) defaults to gathering everything; this module defaults
        to V(config) only. Gathering everything here means ten extra WS-Man round
        trips against firmware, and no existing caller should start paying for
        inventory they did not ask for.
    type: list
    elements: str
    default:
      - config
    choices:
      - all
      - '!all'
      - min
      - '!min'
      - config
      - '!config'
      - hardware
      - '!hardware'
      - system
      - '!system'
      - processor
      - '!processor'
      - memory
      - '!memory'
      - storage
      - '!storage'
    version_added: 0.5.0
seealso:
  - module: james_crowley.intel_amt.amt_power
  - module: ansible.builtin.setup
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

# Asset inventory. The point of reading it over AMT is that none of this needs
# the machine to be powered on, or to have an agent installed.
- name: Read the asset inventory of a powered-off machine
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    gather_subset:
      - hardware
  delegate_to: localhost
  no_log: true
  register: inventory

- name: Record the chassis serial number against this host
  ansible.builtin.debug:
    msg: >-
      {{ inventory.amt.hardware.chassis.manufacturer }}
      {{ inventory.amt.hardware.chassis.model }},
      chassis serial {{ inventory.amt.hardware.chassis.serial_number }},
      board serial {{ inventory.amt.hardware.baseboard.serial_number }}
  when: inventory.amt.hardware.chassis is not none

# Only what a CMDB row needs, at four WS-Man requests rather than twenty.
- name: Gather just the identity plates and the disks
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    gather_subset:
      - system
      - storage
  delegate_to: localhost
  no_log: true
  register: cmdb_row

- name: Everything except the per-DIMM detail
  james_crowley.intel_amt.amt_info:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    gather_subset:
      - all
      - '!memory'
  delegate_to: localhost
  no_log: true
  register: no_dimms

- name: Report installed memory per DIMM slot
  ansible.builtin.debug:
    msg: >-
      {{ item.bank_label }}: {{ (item.capacity_bytes / 1073741824) | round(1) }} GiB
      {{ item.memory_type_text }} at {{ item.configured_clock_speed_mhz }} MHz
  loop: "{{ inventory.amt.hardware.memory | default([], true) }}"
  loop_control:
    label: "{{ item.bank_label }}"

- name: Fail the play if any disk reports itself write-protected
  ansible.builtin.assert:
    that:
      - "'read_only' not in (item.security_text | default(''))"
    fail_msg: "{{ item.device_id }} reports Security {{ item.security }} ({{ item.security_text }})"
  loop: "{{ inventory.amt.hardware.storage | default([], true) }}"
  loop_control:
    label: "{{ item.device_id }}"
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
    hardware:
      description:
        - >-
          Hardware/asset inventory. V(null) unless a hardware O(gather_subset)
          was requested -- which is not the default, so an existing caller sees
          V(null) here and pays no extra WS-Man round trip.
        - >-
          Each key is present B(only) if its subset was requested. So
          C('memory' in amt.hardware) answers "did I ask for it", while
          C(amt.hardware.memory is none) answers "does this firmware implement
          the class". Those are different questions and this shape keeps them
          apart. A list-valued key that is V([]) is a third, distinct answer:
          firmware returned B(zero) instances, which is a real reading of a
          diskless or single-DIMM machine and not a gap.
        - >-
          B(Every enumerated property is reported as both a raw integer and a
          decoded name), following RV(amt.power_state) and
          RV(amt.system_state.enabled_state). A value outside the table this
          collection holds renders as V(unknown(<raw>)) -- never a bare
          V(unknown), because several of these tables define V(0) as
          C(unknown) and the two findings must not print identically.
        - >-
          B(Three properties are reported raw and undecoded on purpose), because
          no value table for them could be sourced from
          C(go-wsman-messages) or the DMTF schema:
          RV(amt.hardware.processors[].family),
          RV(amt.hardware.memory[].form_factor), and C(requested_state) on both
          processors and storage. Shipping a raw integer is honest; a guessed
          label is what this collection spent 0.3.1 undoing. See
          C(docs/amt_info.md) for the full accounting.
      type: dict
      returned: when a hardware gather_subset was requested
      contains:
        chassis:
          description:
            - >-
              C(CIM_Chassis) -- the enclosure, and where the B(system serial
              number) lives. Present when O(gather_subset) includes V(system);
              V(null) when the firmware does not implement the class.
            - >-
              There is B(no asset-tag property) on this class. C(Tag) is
              reported as RV(amt.hardware.chassis.tag), but on the only recorded
              real-firmware response it holds the literal string
              C(CIM_Chassis) -- the class name -- so it is deliberately not
              named C(asset_tag).
          type: dict
          contains:
            serial_number:
              description: C(SerialNumber) -- the system serial, readable with the machine powered off.
              type: str
            model:
              description: C(Model).
              type: str
            manufacturer:
              description: C(Manufacturer).
              type: str
            version:
              description: C(Version) -- the chassis part revision, not a software version.
              type: str
            tag:
              description: C(Tag), the DMTF key property. Not an asset tag -- see above.
              type: str
            element_name:
              description: C(ElementName).
              type: str
            chassis_package_type:
              description: Raw C(ChassisPackageType) integer -- the chassis form factor.
              type: int
            chassis_package_type_text:
              description: >-
                C(ChassisPackageType) decoded, e.g. V(desktop) (3), V(mini_tower) (6),
                V(notebook) (10), V(all_in_one) (13), V(mini_pc) (35). Thirty-seven
                values are defined; anything else renders V(unknown(<raw>)).
              type: str
            package_type:
              description: >-
                Raw C(PackageType) integer. A B(different) enumeration from
                RV(amt.hardware.chassis.chassis_package_type), which this class carries
                at the same time.
              type: int
            package_type_text:
              description: C(PackageType) decoded, e.g. V(chassis_frame) (3), V(module_card) (9).
              type: str
            operational_status:
              description: Raw DMTF C(OperationalStatus) values. Always a list.
              type: list
              elements: int
            operational_status_text:
              description: C(OperationalStatus) decoded element-wise, as RV(amt.system_state.operational_status_text) is.
              type: list
              elements: str
        baseboard:
          description: >-
            C(CIM_Card) -- the motherboard and its own serial number, which is
            distinct from the chassis serial: recording only one cannot tell a
            board swap from a re-rack. Present when O(gather_subset) includes
            V(system). Same C(Tag) caveat as RV(amt.hardware.chassis).
          type: dict
          contains:
            serial_number:
              description: C(SerialNumber) -- the baseboard serial.
              type: str
            model:
              description: C(Model).
              type: str
            manufacturer:
              description: C(Manufacturer).
              type: str
            version:
              description: C(Version).
              type: str
            tag:
              description: C(Tag). Not an asset tag.
              type: str
            element_name:
              description: C(ElementName).
              type: str
            can_be_frued:
              description: C(CanBeFRUed) -- whether this is a field-replaceable unit.
              type: bool
            package_type:
              description: Raw C(PackageType) integer.
              type: int
            package_type_text:
              description: C(PackageType) decoded.
              type: str
            operational_status:
              description: Raw DMTF C(OperationalStatus) values.
              type: list
              elements: int
            operational_status_text:
              description: C(OperationalStatus) decoded element-wise.
              type: list
              elements: str
        processors:
          description:
            - >-
              C(CIM_Processor), one entry per physical package -- B(not) per
              core. Present when O(gather_subset) includes V(processor).
            - >-
              B(This class carries no core or thread count), on any firmware:
              AMT's implementation does not expose one, so this module reports
              none. Nothing here is a substitute for it.
          type: list
          elements: dict
          contains:
            device_id:
              description: C(DeviceID), e.g. V(CPU 0). What distinguishes one package from another.
              type: str
            element_name:
              description: C(ElementName).
              type: str
            role:
              description: C(Role) -- a free-form string, e.g. V(Central).
              type: str
            family:
              description: >-
                Raw C(Family) integer, B(undecoded). C(go-wsman-messages) defines no
                value map for this property and the DMTF C(Family) ValueMap runs to
                several hundred entries, so nothing could be sourced. Use
                RV(amt.hardware.chips[].version) for the processor's actual name.
              type: int
            other_family_description:
              description: C(OtherFamilyDescription) -- set only when C(Family) is V(1) (Other).
              type: str
            max_clock_speed_mhz:
              description: C(MaxClockSpeed), in MHz per the class definition.
              type: int
            current_clock_speed_mhz:
              description: C(CurrentClockSpeed), in MHz.
              type: int
            external_bus_clock_speed_mhz:
              description: C(ExternalBusClockSpeed) -- front-side bus, in MHz.
              type: int
            stepping:
              description: >-
                C(Stepping) -- a B(free-form string) per the class definition, not an
                integer. Firmware may report V(13) or V(B0) and both are valid.
              type: str
            cpu_status:
              description: Raw C(CPUStatus) integer.
              type: int
            cpu_status_text:
              description: >-
                C(CPUStatus) decoded -- V(unknown) (0), V(cpu_enabled) (1),
                V(cpu_disabled_by_user) (2), V(cpu_disabled_by_bios) (3),
                V(cpu_is_idle) (4), V(other) (5).
              type: str
            upgrade_method:
              description: Raw C(UpgradeMethod) integer -- the CPU socket.
              type: int
            upgrade_method_text:
              description: >-
                C(UpgradeMethod) decoded -- 85 defined values, which is what says
                whether a processor is socketed or soldered. Note V(0) is V(other)
                and V(1) is V(unknown), the opposite way round from most tables here.
              type: str
            health_state:
              description: Raw C(HealthState) integer.
              type: int
            health_state_text:
              description: >-
                C(HealthState) decoded -- V(unknown) (0), V(ok) (5),
                V(degraded_warning) (10), V(minor_failure) (15), V(major_failure) (20),
                V(critical_failure) (25), V(non_recoverable_error) (30). Sparse by
                design; values in between are genuinely undefined.
              type: str
            enabled_state:
              description: Raw DMTF C(EnabledState) integer.
              type: int
            enabled_state_text:
              description: >-
                C(EnabledState) decoded per DMTF, using the same full 0-10 table as
                RV(amt.system_state.enabled_state_text).
              type: str
            requested_state:
              description: >-
                Raw C(RequestedState) integer, reported B(undecoded) -- matching how
                this module already reports RV(amt.system_state.requested_state).
              type: int
            operational_status:
              description: Raw DMTF C(OperationalStatus) values.
              type: list
              elements: int
            operational_status_text:
              description: C(OperationalStatus) decoded element-wise.
              type: list
              elements: str
        chips:
          description:
            - >-
              C(CIM_Chip). Present when O(gather_subset) includes V(processor),
              and read for one reason: RV(amt.hardware.chips[].version) is the
              B(human-readable processor name), which C(CIM_Processor) cannot
              supply.
            - >-
              C(CIM_PhysicalMemory) is a subclass of C(CIM_Chip), so firmware may
              legitimately return memory chips here alongside processor chips.
              Instances are reported B(unfiltered) -- filtering would mean
              asserting which C(ElementName) values firmware uses, which no
              available evidence establishes. Use
              RV(amt.hardware.chips[].element_name) to tell them apart.
          type: list
          elements: dict
          contains:
            version:
              description: >-
                C(Version) -- the processor's marketing name, e.g. an
                V(Intel(R) Core(TM) ...) string. The field this class is read for.
              type: str
            tag:
              description: C(Tag), e.g. V(CPU 0).
              type: str
            element_name:
              description: >-
                C(ElementName) -- what distinguishes a processor chip from a memory
                chip in this list.
              type: str
            manufacturer:
              description: C(Manufacturer).
              type: str
            can_be_frued:
              description: C(CanBeFRUed).
              type: bool
            operational_status:
              description: Raw DMTF C(OperationalStatus) values.
              type: list
              elements: int
            operational_status_text:
              description: C(OperationalStatus) decoded element-wise.
              type: list
              elements: str
        memory:
          description:
            - >-
              C(CIM_PhysicalMemory), one entry per DIMM, in the order firmware
              returned them. Present when O(gather_subset) includes V(memory).
              V([]) is a legitimate reading, not a gap.
            - >-
              B(Read the speed fields carefully.) C(IsSpeedInMhz) selects which
              property actually holds the speed, and the two are in B(different
              units): when it is V(true) the speed is
              RV(amt.hardware.memory[].max_memory_speed_mhz) in MHz, and when it
              is V(false) it is RV(amt.hardware.memory[].speed_ns) in
              nanoseconds. Real firmware has been recorded reporting C(Speed) as
              V(0) with C(IsSpeedInMhz) V(true), so anything reading C(Speed)
              naively would report every DIMM as zero. No single derived speed
              field is offered, because there is no honest value for it in the
              V(false) branch.
          type: list
          elements: dict
          contains:
            bank_label:
              description: C(BankLabel) -- the physically labelled slot, e.g. V(BANK 0).
              type: str
            capacity_bytes:
              description: C(Capacity), in B(bytes) per the class definition.
              type: int
            memory_type:
              description: Raw C(MemoryType) integer.
              type: int
            memory_type_text:
              description: >-
                C(MemoryType) decoded -- 37 defined values including V(ddr3) (24),
                V(ddr4) (26), V(ddr5) (34), V(lpddr5) (35).
              type: str
            form_factor:
              description: >-
                Raw C(FormFactor) integer, B(undecoded). C(go-wsman-messages) defines
                no map for it, and the two published tables that might apply B(disagree
                about the value real firmware reports): V(13) is C(SODIMM) under the
                SMBIOS type-17 enumeration but C(SRIMM) under the DMTF
                C(CIM_PhysicalMemory.FormFactor) ValueMap. Nothing available settles
                which, so no name is claimed.
              type: int
            speed_ns:
              description: >-
                C(Speed), in B(nanoseconds). Meaningful only when
                RV(amt.hardware.memory[].is_speed_in_mhz) is V(false).
              type: int
            max_memory_speed_mhz:
              description: >-
                C(MaxMemorySpeed), in B(MHz). The DIMM's rated speed, and the
                speed field to read when RV(amt.hardware.memory[].is_speed_in_mhz)
                is V(true).
              type: int
            configured_clock_speed_mhz:
              description: >-
                C(ConfiguredMemoryClockSpeed), in MHz -- what the DIMM is actually
                clocked at, which may be below its rated speed.
              type: int
            is_speed_in_mhz:
              description: C(IsSpeedInMhz) -- which of the two speed properties is the real one.
              type: bool
            manufacturer:
              description: >-
                C(Manufacturer). Firmware has been recorded reporting a JEDEC
                manufacturer B(ID) here rather than a name; it is passed through
                verbatim, because no JEDEC ID table could be sourced.
              type: str
            part_number:
              description: C(PartNumber) -- the module part number.
              type: str
            serial_number:
              description: C(SerialNumber) -- this DIMM's own serial.
              type: str
            tag:
              description: C(Tag), the DMTF key property.
              type: str
            element_name:
              description: C(ElementName).
              type: str
            operational_status:
              description: Raw DMTF C(OperationalStatus) values.
              type: list
              elements: int
            operational_status_text:
              description: C(OperationalStatus) decoded element-wise.
              type: list
              elements: str
        storage:
          description:
            - >-
              C(CIM_MediaAccessDevice), one entry per disk. Present when
              O(gather_subset) includes V(storage).
            - >-
              B(This class carries no model, vendor or serial number), and its
              C(ElementName) is a constant string on every instance. What
              distinguishes one disk from another is
              RV(amt.hardware.storage[].device_id) and
              RV(amt.hardware.storage[].max_media_size_kb). A disk model number
              is not obtainable from AMT through this class, and this module does
              not pretend otherwise.
          type: list
          elements: dict
          contains:
            device_id:
              description: C(DeviceID), e.g. V(MEDIA DEV 0). The only per-instance identifier here.
              type: str
            element_name:
              description: C(ElementName) -- a constant string, identifying nothing.
              type: str
            max_media_size_kb:
              description: >-
                C(MaxMediaSize), in B(KBytes) per the class definition and
                deliberately B(not) converted: nothing establishes whether firmware
                means 1000 or 1024 bytes, and a C(_bytes) field would bake that guess
                in at a 2.4%% error.
              type: int
            capabilities:
              description: Raw C(Capabilities) values. A CIM array, so always a list.
              type: list
              elements: int
            capabilities_text:
              description: >-
                C(Capabilities) decoded element-wise -- 13 defined values including
                V(random_access) (3), V(supports_writing) (4),
                V(supports_removable_media) (7).
              type: list
              elements: str
            security:
              description: Raw C(Security) integer.
              type: int
            security_text:
              description: >-
                C(Security) decoded. B(Note the order): V(other) is V(1) and
                V(unknown) is V(2), the reverse of most tables here, then V(none) (3),
                V(read_only) (4), V(locked_out) (5), V(boot_bypass) (6),
                V(boot_bypass_and_read_only) (7). There is no value V(0).
              type: str
            enabled_state:
              description: Raw DMTF C(EnabledState) integer.
              type: int
            enabled_state_text:
              description: C(EnabledState) decoded per DMTF, same table as elsewhere in this module.
              type: str
            enabled_default:
              description: >-
                Raw C(EnabledDefault) integer -- the configured startup state, distinct
                from the live C(EnabledState).
              type: int
            enabled_default_text:
              description: >-
                C(EnabledDefault) decoded -- V(enabled) (2), V(disabled) (3),
                V(not_applicable) (5), V(enabled_but_offline) (6), V(no_default) (7),
                V(quiesce) (9). Sparse: 0, 1, 4 and 8 are undefined and render
                V(unknown(<raw>)).
              type: str
            requested_state:
              description: Raw C(RequestedState) integer, reported B(undecoded).
              type: int
            operational_status:
              description: Raw DMTF C(OperationalStatus) values.
              type: list
              elements: int
            operational_status_text:
              description: C(OperationalStatus) decoded element-wise.
              type: list
              elements: str
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
    gather_subset:
      description: >-
        The O(gather_subset) actually resolved for this read, sorted. Worth
        checking when C(!)-negation is in play: C([!memory]) resolves to
        everything but memory, which is more than the default, and this is where
        that is visible.
      type: list
      elements: str
      version_added: 0.5.0
      sample: ["config", "memory", "processor", "storage", "system"]
    wsman_requests_estimated:
      description: >-
        Best-case WS-Man HTTP request count for the resolved subsets. B(Best
        case) is load-bearing -- a C(CIM_BIOSElement) or V(system) C(Get) that
        faults costs one further C(Enumerate)/C(Pull) pair on top, and an
        enumeration returning more than 64 instances costs an extra C(Pull) each.
      type: int
      version_added: 0.5.0
      sample: 10
"""

import dataclasses

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.client import AmtClient
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.hardware import (
    GATHER_SUBSET_CHOICES,
    SUBSET_CONFIG,
    resolve_gather_subset,
    round_trip_estimate,
)
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
        # Validated by `choices` rather than in module code, so a typo is refused
        # before a single byte goes on the wire and `ansible-doc` lists the whole
        # vocabulary. Same treatment as `state` on amt_power/amt_boot. The default
        # is deliberately NOT `all` -- see the option documentation: gathering
        # everything costs ten extra WS-Man round trips, and no existing caller
        # should start paying for inventory they never asked for.
        "gather_subset": {
            "type": "list",
            "elements": "str",
            "default": [SUBSET_CONFIG],
            "choices": list(GATHER_SUBSET_CHOICES),
        },
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


def facts_to_result(client: AmtClient, subsets: frozenset[str] | None = None) -> dict:
    """Gather facts via ``client`` and shape them into this module's C(amt) return key.

    ``subsets`` is a resolved subset set from
    ``hardware.resolve_gather_subset()``. ``None`` means the default -- exactly
    the pre-0.5.0 fact set, at exactly the pre-0.5.0 round-trip cost.
    """
    facts = client.get_facts(subsets)

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
        # HardwareFacts.to_dict(), not dataclasses.asdict(): the rendered dict
        # omits keys for subsets that were not requested, which is what keeps
        # "I did not ask" distinguishable from "firmware has no such class".
        # asdict() would flatten both to null and lose that.
        "hardware": facts.hardware.to_dict() if facts.hardware is not None else None,
    }


def main() -> None:
    module = AnsibleModule(argument_spec=_connection_argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    # Resolved before the client is built, so a subset spec is interpreted with
    # no connection open. `choices` has already refused anything unrecognised.
    subsets = resolve_gather_subset(module.params["gather_subset"])

    try:
        wsman = build_wsman_client(module.params)
        client = AmtClient(wsman)
        amt = facts_to_result(client, subsets)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return

    peer_cert = wsman.last_peer_certificate
    receipt = OperationReceipt(
        action="get_facts",
        endpoint=wsman.endpoint,
        changed=False,
        tls_peer_fingerprint=peer_cert.sha256_fingerprint if peer_cert else None,
        # What this read actually resolved to and what it cost. Belongs on the
        # receipt rather than under `amt`, which is documented as
        # firmware-observed evidence -- a request count is neither observed nor
        # firmware's.
        extra={
            "gather_subset": sorted(subsets),
            "wsman_requests_estimated": round_trip_estimate(subsets),
        },
    )
    module.exit_json(changed=False, amt=amt, operation=receipt.to_dict())


if __name__ == "__main__":
    main()
