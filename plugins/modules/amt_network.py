#!/usr/bin/python
# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: amt_network
short_description: Configure Intel AMT network settings (IPv4 addressing, DHCP, ping response, link policy)
description:
  - >-
    Declaratively sets the Intel AMT management interface's network configuration over WS-Man:
    C(AMT_EthernetPortSettings) instance 0 for IPv4 addressing, DHCP mode and C(LinkPolicy), and
    C(AMT_GeneralSettings) for hostname, domain name and the two ping-response toggles. Every option
    defaults to "leave this alone", so a task states only what it intends to converge.
  - >-
    This is the write counterpart to M(james_crowley.intel_amt.amt_info), which already reports every
    one of these values. The reading side is unchanged and remains the way to inspect state; this
    module never reports facts it did not write.
  - >-
    B(The central hazard: this module reconfigures the interface its own request arrived on.)
    C(AMT_EthernetPortSettings) instance 0 is by definition the wired port AMT answers WS-Man on
    (see C(docs/protocol-notes.md) s2.7 and s2.10), so changing its address, mask, gateway or DHCP
    mode can invalidate this connection before the write can be confirmed. Everything below follows
    from that.
  - >-
    B(Addressing changes are refused unless explicitly acknowledged.) A change to O(ip_address),
    O(subnet_mask), O(default_gateway) or O(dhcp_enabled) fails with RV(ignore:error_class)
    V(invalid_state) unless O(allow_self_disconnect=true). This is the same stance
    M(james_crowley.intel_amt.amt_media) takes on C(ca_path) -- refuse an option that cannot be
    honoured safely rather than accept it and quietly not deliver what the operator believes they
    asked for. O(primary_dns) and O(secondary_dns) are deliberately B(not) gated: those configure
    the endpoint's own outbound name resolution and cannot affect how a controller reaches it.
  - >-
    B(A write is confirmed by a re-read, or it is not reported as a success.) A C(Put) answering
    HTTP 200 means firmware accepted the body, not that the property took. This module re-reads
    every class it wrote and compares. If the confirming read cannot be obtained -- which is the
    B(expected) outcome of a forced address change -- the task fails carrying
    RV(ignore:indeterminate) V(true), which in this collection means B(re-probe, do not retry):
    the endpoint answers at its new address, not the one this task connected to. If the confirming
    read succeeds but reports the old value, firmware accepted the body and declined the property,
    and the task fails with RV(ignore:error_class) V(unsupported_capability).
  - >-
    B(This module deliberately does not re-probe at the new address itself.) That was considered
    and rejected: the module cannot know a DHCP-assigned address, and a fresh connection to a
    different address is a new trust decision -- this collection requires a per-machine TLS
    fingerprint, and inventing a second connection whose pin nobody reviewed would trade an honest
    C(indeterminate) for a confident guess. The caller re-probes with a second task naming the
    address it now expects.
  - >-
    B(O(link_policy) is the one option that can strand an endpoint without disconnecting you now.)
    A policy carrying neither Sx value keeps the network link up only while the host is in S0, so
    the endpoint stops answering WS-Man once it sleeps or powers off -- at which point
    M(james_crowley.intel_amt.amt_power) with C(state=on) can no longer reach it to bring it back.
    Removing the last Sx value therefore requires O(allow_wake_capability_loss=true). The four
    values are re-derived from C(go-wsman-messages) v2.48.3's own request struct rather than reused
    from this collection's read table -- a wrong C(LinkPolicy) table shipped here for two releases
    (0.2.0/0.3.0) and inverted C(wake_on_lan_capable); see C(docs/protocol-notes.md) s2.10 for the
    derivation and the conclusion that the read and write tables agree.
  - >-
    There is no hardware qualification stage for this module, on purpose. A bad write can leave a
    machine needing a physical MEBx visit, so the pre-flight brief in
    C(tests/hardware/PREFLIGHT.md) exists for a human to decide from, and no stage is wired up.
    Mock coverage drives the real client end to end against the fixture WS-Man server.
version_added: 0.8.0
author:
  - Jim Crowley (@james-crowley)
options:
  dhcp_enabled:
    description:
      - >-
        Whether the AMT interface acquires its IPv4 configuration by DHCP. V(true) switches to DHCP;
        V(false) switches to a static configuration, which requires that O(ip_address) and
        O(subnet_mask) either be supplied here or already be set on the endpoint.
      - >-
        When the resulting mode is DHCP, the static addressing properties are B(removed) from the
        C(Put) body rather than echoed back -- firmware documents C(IPAddress) as settable "in
        static mode only", and MeshCmd deletes the same five properties before its own DHCP switch.
        Sending a full static configuration alongside C(DHCPEnabled=true) asks firmware to
        reconcile a contradiction.
      - Changing this requires O(allow_self_disconnect=true), because a DHCP lease can land anywhere.
    type: bool
  ip_address:
    description:
      - Static IPv4 address for the AMT interface, as a dotted quad. Only meaningful when the resulting mode is static.
      - >-
        Validated strictly before anything is written: four decimal octets, no leading zeros
        (V(192.0.2.010) is octal to some resolvers and decimal to others). A value this module
        cannot parse is refused rather than handed to firmware.
      - Changing this requires O(allow_self_disconnect=true).
    type: str
  subnet_mask:
    description:
      - Static IPv4 netmask, as a dotted quad.
      - >-
        Must be B(contiguous). V(255.255.0.255) parses as an address and is not a mask; an endpoint
        whose mask has a hole in it is reachable from an arbitrary-looking subset of the network,
        which is the hardest possible failure to diagnose remotely.
      - >-
        Changing this requires O(allow_self_disconnect=true) -- a narrowed mask removes the endpoint from a
        controller's path as completely as a moved address does.
    type: str
  default_gateway:
    description:
      - Static IPv4 default gateway, as a dotted quad.
      - >-
        A gateway that is not on the same subnet as the resulting address/mask produces a B(warning),
        not a failure. It is legal in point-to-point and proxy-ARP setups and this collection has no
        evidence about how AMT firmware treats it -- but it is also exactly what a transposed octet
        looks like.
      - Changing this requires O(allow_self_disconnect=true).
    type: str
  primary_dns:
    description:
      - Primary DNS server the B(endpoint) uses for its own outbound name resolution, as a dotted quad.
      - >-
        Deliberately B(not) gated behind O(allow_self_disconnect): this cannot affect how a
        controller reaches the endpoint, which is whatever O(host) names. Gating a change that
        cannot disconnect anyone is how a safety gate comes to be set routinely.
    type: str
  secondary_dns:
    description:
      - Secondary DNS server for the endpoint's own outbound resolution, as a dotted quad. Not gated, for the same reason as O(primary_dns).
    type: str
  link_policy:
    description:
      - >-
        The complete set of C(AMT_EthernetPortSettings.LinkPolicy) values to write. This is a
        replacement, not a merge: whatever is listed becomes the policy, and the resulting list is
        sorted so the same set written in a different order is still idempotent (firmware types this
        property as an unordered array).
      - >-
        The enum crosses two axes -- ACPI state (V(s0) versus any V(sx)) and power source (V(ac)
        versus V(dc)) -- and there is B(no) "always on" value. V(s0_ac) is 1, V(sx_ac) is 14,
        V(s0_dc) is 16, V(sx_dc) is 224.
      - >-
        A policy carrying neither V(sx_ac) nor V(sx_dc) keeps the link up only while the host is in
        S0, so the endpoint answers nothing once it sleeps or powers off. Removing the last Sx value
        from a policy that had one requires O(allow_wake_capability_loss=true), because it cannot be
        undone remotely.
    type: list
    elements: str
    choices: [s0_ac, sx_ac, s0_dc, sx_dc]
  ping_response_enabled:
    description:
      - Whether AMT answers ICMP echo requests (C(AMT_GeneralSettings.PingResponseEnabled)).
      - >-
        B(This) is the ping toggle. It is not C(AMT_EthernetPortSettings.IpSyncEnabled), which means
        "AMT shares the host OS's IP address" and which C(parmstro)'s collection writes from an
        option of this name -- a conflation this collection does not reproduce (see
        C(docs/protocol-notes.md) s2.7).
    type: bool
  rmcp_ping_response_enabled:
    description: Whether AMT answers RMCP ping echo requests (C(AMT_GeneralSettings.RmcpPingResponseEnabled)).
    type: bool
  hostname:
    description:
      - >-
        The hostname AMT reports for itself (C(AMT_GeneralSettings.HostName)). This is the
        firmware's own hostname, not the host OS's, and it is what
        M(james_crowley.intel_amt.amt_info) returns as RV(ignore:amt.reported_hostname).
    type: str
  domain_name:
    description: The domain name AMT reports for itself (C(AMT_GeneralSettings.DomainName)).
    type: str
  allow_self_disconnect:
    description:
      - >-
        Explicit acknowledgement that a change to this connection's own addressing may end the
        connection before the write can be confirmed. Required for any change to O(dhcp_enabled),
        O(ip_address), O(subnet_mask) or O(default_gateway); ignored otherwise.
      - >-
        Setting it does not make the write safe, and it does not make the module claim success it
        cannot see. It permits the attempt. The likely successful outcome is a task failure carrying
        RV(ignore:error_class) V(connection) and RV(ignore:indeterminate) V(true) -- meaning the
        endpoint stopped answering at the old address, which is what a working address change looks
        like from here.
      - Never selected implicitly, exactly like O(allow_insecure_transport).
    type: bool
    default: false
  allow_wake_capability_loss:
    description:
      - >-
        Explicit acknowledgement that the requested O(link_policy) removes the last Sx value and so
        will stop the endpoint answering WS-Man while the host is asleep or powered off. Required
        only for that specific transition; ignored otherwise.
      - >-
        Kept separate from O(allow_self_disconnect) because the consequences differ in kind and an
        operator may well permit one and not the other: O(allow_self_disconnect) risks losing this
        connection B(now), and this risks losing every connection B(from the next time the host
        leaves S0), which no remote action can then repair.
    type: bool
    default: false
extends_documentation_fragment:
  - james_crowley.intel_amt.connection
seealso:
  - module: james_crowley.intel_amt.amt_info
  - module: james_crowley.intel_amt.amt_power
attributes:
  check_mode:
    description: >-
      Supported. Reads both classes, computes the plan, applies every refusal (including the
      O(allow_self_disconnect) and O(allow_wake_capability_loss) gates), and returns the exact
      C(Put) bodies a real run would send -- but issues no C(Put). A dry run that skipped the safety
      refusals would be worse than no dry run, since it would report a dangerous write as fine.
    support: full
  diff_mode:
    description: Returns the previous and intended properties of both classes in the operation receipt, plus a per-property RV(changes) list.
    support: full
"""

EXAMPLES = r"""
# Nothing here is gated, so no acknowledgement is needed: none of these three
# properties can affect how this task reaches the endpoint.
- name: Ensure the endpoint answers neither ICMP nor RMCP ping, and knows its own name
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    ping_response_enabled: false
    rmcp_ping_response_enabled: false
    hostname: amt-lab-01
    domain_name: lab.example.invalid
  delegate_to: localhost
  no_log: true

- name: Preview pinning the endpoint to a static address without touching it
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    dhcp_enabled: false
    ip_address: 192.0.2.10
    subnet_mask: 255.255.255.0
    default_gateway: 192.0.2.1
    allow_self_disconnect: true
  delegate_to: localhost
  no_log: true
  check_mode: true
  register: plan

# An addressing change is a one-machine-at-a-time operation. Put `serial: 1` on
# the enclosing PLAY to get that -- `serial` is a play keyword and a task
# carrying it fails with "conflicting action statements". Do not reach for
# `delegate_to: localhost` instead: it moves execution to the controller and does
# nothing about inventory fan-out, so the task below still runs once per host in
# the batch, in parallel, unless the play limits the batch size.
- name: Move the endpoint to a static address, expecting to lose this connection
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    dhcp_enabled: false
    ip_address: 192.0.2.10
    subnet_mask: 255.255.255.0
    default_gateway: 192.0.2.1
    allow_self_disconnect: true
  delegate_to: localhost
  no_log: true
  register: moved
  # An indeterminate failure here is the expected shape of a successful address
  # change: the endpoint stopped answering at the old address. Tolerate exactly
  # that, and nothing else.
  failed_when:
    - moved.failed | default(false)
    - not (moved.indeterminate | default(false))

- name: Re-probe at the address we now expect, rather than retrying the write
  james_crowley.intel_amt.amt_info:
    host: 192.0.2.10
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
  delegate_to: localhost
  no_log: true
  register: reprobe
  until: reprobe is succeeded
  retries: 10
  delay: 6

- name: Keep the link up while the host is off, on mains and on battery
  james_crowley.intel_amt.amt_network:
    host: "{{ amt_host }}"
    username: "{{ amt_username }}"
    password: "{{ amt_password }}"
    tls_fingerprint: "{{ amt_tls_fingerprint }}"
    link_policy: [s0_ac, sx_ac, sx_dc]
  delegate_to: localhost
  no_log: true
"""

RETURN = r"""
changed:
  description: >-
    Whether any property was (or, in check mode, would be) written. V(false) when every requested
    value already matched what firmware reported -- the comparison is made on the wire
    representation, so a bool read back as the string V("false") does not count as drift.
  type: bool
  returned: always
changes:
  description: >-
    One entry per property this call moves, in a stable order. Empty when already converged. This is
    the same list in check mode and in a real run.
  type: list
  elements: dict
  returned: always
  contains:
    resource_class:
      description: V(AMT_EthernetPortSettings) or V(AMT_GeneralSettings).
      type: str
    property:
      description: The CIM/AMT property name, e.g. V(DHCPEnabled).
      type: str
    previous:
      description: >-
        The value firmware reported before the write. For V(LinkPolicy) this is a dict with
        C(values) (the raw integers) and C(names) (their decoded names, with an unrecognised value
        rendered V(unknown(<raw>))).
      type: raw
    desired:
      description: The value this call requested, in the same shape as C(previous).
      type: raw
written_classes:
  description: The classes actually written, in the order written. Empty in check mode and when already converged.
  type: list
  elements: str
  returned: always
indeterminate:
  description: >-
    V(true) when a C(Put) was issued and no confirming read could be obtained, so the write may or
    may not have taken effect. When V(true) the task also B(fails) -- this module never reports
    success for a write it could not observe. Re-probe the endpoint at the address you now expect;
    do not retry the write.
  type: bool
  returned: always
addressing_change:
  description: Whether the plan touches this connection's own addressing (C(DHCPEnabled), C(IPAddress), C(SubnetMask), C(DefaultGateway)).
  type: bool
  returned: always
wake_capability_loss:
  description: Whether the plan would leave C(LinkPolicy) with no Sx value, so the endpoint stops answering once the host leaves S0.
  type: bool
  returned: always
connected_through_managed_address:
  description: >-
    Whether O(host) equals the C(IPAddress) firmware reports for the interface being configured.
    V(null) when O(host) is not an IPv4 literal, which is a third state and not a synonym for
    V(false): a hostname cannot be compared against a firmware-reported address without resolving
    it, and this module does not resolve names -- doing so would introduce a second opinion about
    where the connection went. Reported as evidence; the O(allow_self_disconnect) gate does not
    depend on it.
  type: bool
  returned: always
network:
  description: >-
    The endpoint's C(AMT_EthernetPortSettings) instance 0 as decoded after the write, in exactly the
    field shape M(james_crowley.intel_amt.amt_info) returns under RV(ignore:amt.network). The value
    read B(before) the write in check mode, when already converged, and when only
    C(AMT_GeneralSettings) was written.
  type: dict
  returned: always
general:
  description: >-
    The writable C(AMT_GeneralSettings) fields (plus read-only C(network_interface_enabled)) as decoded
    after the write, on the same terms as RV(network).
  type: dict
  returned: always
operation:
  description: >-
    The C(intel-amt-operation/v1) receipt for this action, in the same nested shape every module in
    this collection returns it under.
  type: dict
  returned: always
  contains:
    schema:
      description: Always V(intel-amt-operation/v1).
      type: str
    action:
      description: Always V(amt_network).
      type: str
    endpoint:
      description: The C(host:port) this operation was performed against.
      type: str
    changed:
      description: Mirrors the top-level RV(changed).
      type: bool
    previous:
      description: The C(AMT_EthernetPortSettings) and C(AMT_GeneralSettings) instances as read before any mutation, keyed by class name.
      type: dict
    desired:
      description: >-
        The C(Put) bodies this module issued, or in check mode would issue, keyed by class name. A
        class with nothing to write is V(null). These are the exact bodies, not a summary -- so a
        check-mode run shows the read-only fields that were stripped and the static addressing
        fields dropped for a DHCP switch.
      type: dict
    observed:
      description: >-
        The instances re-read after the write, keyed by class name. V(null) for a class whose confirming
        read could not be obtained, and in check mode.
      type: dict
    tls_peer_fingerprint:
      description: SHA-256 fingerprint of the TLS leaf certificate observed during this operation, or V(null) over plaintext.
      type: str
    error_class:
      description: A stable machine-readable failure class. V(null) on success.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import network
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AmtError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.tls import resolve_port
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    HAS_REQUESTS,
    REQUESTS_IMPORT_ERROR,
    WsmanClient,
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
    """The module's full argument spec.

    Every setting option is typed with **no default**, so "not mentioned" is
    ``None`` and means *leave this alone*. Deliberately not ``default: false`` on
    the booleans: a default would make every call assert a value for
    ``dhcp_enabled``, turning a task that only wanted to set the hostname into an
    addressing change -- the exact class of accident this module's gates exist to
    prevent.
    """
    spec = _connection_argument_spec()
    spec.update(
        {
            "dhcp_enabled": {"type": "bool"},
            "ip_address": {"type": "str"},
            "subnet_mask": {"type": "str"},
            "default_gateway": {"type": "str"},
            "primary_dns": {"type": "str"},
            "secondary_dns": {"type": "str"},
            "link_policy": {"type": "list", "elements": "str", "choices": sorted(network.LINK_POLICY_WRITE_VALUES)},
            "ping_response_enabled": {"type": "bool"},
            "rmcp_ping_response_enabled": {"type": "bool"},
            "hostname": {"type": "str"},
            "domain_name": {"type": "str"},
            "allow_self_disconnect": {"type": "bool", "default": False},
            "allow_wake_capability_loss": {"type": "bool", "default": False},
        }
    )
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


def build_result(result: network.NetworkApplyResult, *, endpoint: str, tls_peer_fingerprint: str | None) -> dict:
    """Assemble the module result: module-specific keys at the top level, the receipt nested.

    ``network``/``general`` report the *observed* instance where one was obtained
    and fall back to the instance read before the write otherwise. That fallback
    covers check mode, an already-converged run, and a class that was not
    written at all -- three cases where the pre-write reading is genuinely the
    current state, not a stale guess. It deliberately does **not** cover the
    indeterminate case: that path fails before reaching here, so this function
    never presents a pre-write reading as though it described a written endpoint.
    """
    plan = result.plan
    return {
        "changed": plan.changed,
        "changes": [change.to_dict() for change in plan.changes],
        "written_classes": list(result.written_classes),
        "indeterminate": result.indeterminate,
        "addressing_change": plan.addressing_change,
        "wake_capability_loss": plan.wake_capability_loss,
        "connected_through_managed_address": plan.connected_through_managed_address,
        "network": network.decode_ethernet(result.ethernet_observed or plan.ethernet_previous),
        "general": network.decode_general(result.general_observed or plan.general_previous),
        "operation": OperationReceipt(
            action="amt_network",
            endpoint=endpoint,
            changed=plan.changed,
            previous={
                "AMT_EthernetPortSettings": plan.ethernet_previous,
                "AMT_GeneralSettings": plan.general_previous,
            },
            desired={
                "AMT_EthernetPortSettings": plan.ethernet_put,
                "AMT_GeneralSettings": plan.general_put,
            },
            observed={
                "AMT_EthernetPortSettings": result.ethernet_observed,
                "AMT_GeneralSettings": result.general_observed,
            },
            tls_peer_fingerprint=tls_peer_fingerprint,
        ).to_dict(),
    }


def main() -> None:
    module = AnsibleModule(argument_spec=argument_spec(), supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    params = module.params
    endpoint = f"{params['host']}:{resolve_port(port=params['port'], use_tls=params['use_tls'])}"

    client = None
    try:
        client = build_wsman_client(params)
        ethernet_instance, general_instance = network.read_network_state(client)
        plan = network.plan_network_change(
            ethernet_instance=ethernet_instance,
            general_instance=general_instance,
            options=params,
            host=params["host"],
            allow_self_disconnect=params["allow_self_disconnect"],
            allow_wake_capability_loss=params["allow_wake_capability_loss"],
        )
        for warning in plan.warnings:
            module.warn(warning)
        result = network.apply_network_change(client, plan, check_mode=module.check_mode)
    except AmtError as err:
        module.fail_json(**err.to_result())
        return
    finally:
        if client is not None:
            client.close()

    # The two unsuccessful outcomes of a write that firmware answered. Both are
    # failures and neither is a partial success: this module does not have a
    # "changed, but we are not sure" result shape, because a caller acting on one
    # would be acting on nothing.
    if result.indeterminate:
        module.fail_json(**network.indeterminate_error(result, endpoint=endpoint).to_result(), written_classes=list(result.written_classes))
    if result.unapplied:
        module.fail_json(**network.unapplied_error(result, endpoint=endpoint).to_result(), written_classes=list(result.written_classes))

    module.exit_json(
        **build_result(
            result,
            endpoint=endpoint,
            tls_peer_fingerprint=(client.last_peer_certificate.sha256_fingerprint if client.last_peer_certificate else None),
        )
    )


if __name__ == "__main__":
    main()
