# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""The write path for AMT network configuration: ``AMT_EthernetPortSettings`` + ``AMT_GeneralSettings``.

``amt_info`` already *reads* both classes (``plugins/module_utils/client.py``,
``models.EthernetSettings``). This module owns the other direction, and it is
deliberately its own file for the same reason ``boot.py`` is: it is a mutation
whose failure mode is *losing the endpoint*, not losing a fact.

Four rules run through it, each enforced structurally rather than by convention.

1. **The interface being configured is the interface you arrived on.**
   ``AMT_EthernetPortSettings`` instance 0 is, by definition, the wired port AMT
   answers WS-Man on (docs/protocol-notes.md s2.7). So any change to its
   addressing is a change to the path carrying the request -- the module is
   sawing the branch it is sitting on. :func:`plan_network_change` therefore
   **refuses** an addressing change unless the caller passes an explicit
   acknowledgement, exactly the way ``amt_media`` refuses ``ca_path`` rather
   than accepting it and quietly not honouring it
   (``plugins/modules/amt_media.py``, ``enforce_redirection_trust_policy``).

2. **A write is confirmed by a re-read, or it is reported as unconfirmed.**
   ``Put`` answering HTTP 200 means firmware accepted the body, not that the
   property took. :func:`apply_network_change` re-reads both classes afterwards
   and compares. If the re-read cannot be obtained at all -- which is the
   *expected* outcome of a forced address change -- the result carries
   ``indeterminate=True`` and the module fails rather than claiming a success
   nothing observed. That vocabulary is not invented here: it is
   ``errors.AmtError(indeterminate=...)``, and it means one specific thing
   throughout this collection -- *re-probe, do not retry*.

3. **Never echo back a property firmware does not accept on Put.** The
   read-only field lists below are derived from the vendor request structs, not
   from what a Get happens to return. Same failure this collection already has
   machinery for in ``boot.DELETE_BEFORE_PUT_FIELDS``.

4. **Validate the addressing before writing it, not after.** A syntactically
   wrong address, a non-contiguous mask, or a static configuration with no
   address at all are all caller mistakes that strand the endpoint if they reach
   firmware. They are refused with ``invalid_state`` before the first ``Put``.

Sources
-------

Everything in this module that is a value, a field list, or a wire shape comes
from one of:

* ``device-management-toolkit/go-wsman-messages`` v2.48.3 --
  ``pkg/wsman/amt/ethernetport/{types,decoder,settings}.go``,
  ``pkg/wsman/amt/general/types.go``, and the recorded firmware responses under
  ``pkg/wsman/wsmantesting/responses/amt/{ethernetport,general}/``. This is the
  authoritative source.
* MeshCentral (``agents/meshcmd.js`` ``performAmtNetConfig1``, ``amtmanager.js``)
  as corroborating prior art for the read-modify-write shape.

See docs/protocol-notes.md s2.10 for the full write-up with citations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    InvalidStateError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    LINK_POLICY_S0_AC,
    LINK_POLICY_S0_DC,
    LINK_POLICY_SX_AC,
    LINK_POLICY_SX_DC,
    EthernetSettings,
    optional_bool,
    optional_int,
    optional_str,
    truthy,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import WsmanClient

#: ``AMT_EthernetPortSettings`` instance 0 -- the wired port AMT itself answers on.
#:
#: Public and shared: ``client.py`` imports it for the read path rather than
#: keeping its own copy. A selector string that exists in two places can drift
#: against itself, and this collection already has a value-table-in-two-places
#: incident on this exact class (``docs/capability-matrix.md``, ``LinkPolicy``).
#:
#: A ``Get`` **and** a ``Put`` both require this exact selector: ``Enumerate`` is
#: HTTP 400 on ``AMT_``-prefixed classes on AMT 10 (docs/protocol-notes.md s2.7),
#: and go-wsman-messages' ``ethernetport.Settings.Put()`` overrides the generic
#: selector-less Put precisely to add it (``pkg/wsman/amt/ethernetport/settings.go``:
#: "each instance must be addressed by an InstanceID selector, which the generic
#: Put does not provide").
ETHERNET_PORT_0_SELECTOR: dict[str, str] = {"InstanceID": "Intel(r) AMT Ethernet Port Settings 0"}

#: ``AMT_GeneralSettings`` is a **singleton and is addressed with no selector at
#: all**, unlike its sibling above. Not an oversight in either direction:
#: go-wsman-messages' ``general`` package does *not* override the generic
#: ``WSManService.Put()``, and that generic Put calls
#: ``Base.Put(request, useHeaderSelector=false, nil)`` which emits no
#: ``<w:SelectorSet>`` (``internal/message/base.go``). MeshCentral agrees --
#: ``amtstack.Put('AMT_GeneralSettings', body, ...)`` in both ``amtmanager.js``
#: and ``agents/meshcmd.js`` passes no selectors. And it matches this
#: collection's own hardware-verified read, which is selector-less
#: (``client.py``'s ``_get_optional("AMT_GeneralSettings")``, populated on AMT
#: 16.1.30 and 19.0.5).
#:
#: Kept as an explicit ``None`` rather than an absent argument so the asymmetry
#: with the ethernet port is visible at both call sites instead of being an
#: accident of which keyword someone remembered to pass.
GENERAL_SETTINGS_SELECTOR: dict[str, str] | None = None

#: ``AMT_EthernetPortSettings.LinkPolicy`` values for the **write** direction.
#:
#: **Re-derived from the vendor source rather than reused from**
#: ``models._LINK_POLICY_TABLE`` **on trust**, because a wrong ``LinkPolicy``
#: table already shipped in 0.2.0 and 0.3.0 here and inverted
#: ``wake_on_lan_capable`` (docs/protocol-notes.md s2.7, ``capability-matrix.md``),
#: and a wrong table on the *write* side does not merely misreport -- it can make
#: an endpoint unreachable while powered off.
#:
#: The derivation: ``pkg/wsman/amt/ethernetport/types.go`` declares
#: ``SettingsRequest.LinkPolicy`` as ``[]LinkPolicy`` -- the **same Go type** as
#: ``SettingsResponse.LinkPolicy``, carrying the same schema annotation
#: ``ValueMap={1, 14, 16, 224}`` /
#: ``Values={available on S0 AC, available on Sx AC, available on S0 DC, available on Sx DC}``,
#: and ``decoder.go`` defines exactly four constants for it: ``LinkPolicyS0AC = 1``,
#: ``LinkPolicySxAC = 14``, ``LinkPolicyS0DC = 16``, ``LinkPolicySxDC = 224``.
#: There is no separate write-side enum. **The read table and the write table
#: therefore agree**, and this dict is the same four pairs stated in the
#: write direction (name -> value) with the read-side constants imported from
#: ``models`` so the two cannot drift apart numerically even though they were
#: derived independently.
#:
#: Wire shape is settled by the recorded firmware response
#: ``responses/amt/ethernetport/put.xml``: three consecutive ``<g:LinkPolicy>``
#: elements with no wrapper. ``wsman.WsmanClient._append_params`` emits a list as
#: repeated elements, so that shape comes out of the existing transport for free.
LINK_POLICY_WRITE_VALUES: dict[str, int] = {
    "s0_ac": LINK_POLICY_S0_AC,  # 1   -- host powered on, mains
    "sx_ac": LINK_POLICY_SX_AC,  # 14  -- host asleep/hibernating/off, mains
    "s0_dc": LINK_POLICY_S0_DC,  # 16  -- host powered on, battery
    "sx_dc": LINK_POLICY_SX_DC,  # 224 -- host asleep/hibernating/off, battery
}

#: The two write-side values that keep the link up while the host is **not** in
#: S0. Losing both is what makes an endpoint unreachable once it sleeps or powers
#: off -- see :func:`plan_network_change`'s wake-capability guard.
LINK_POLICY_SX_WRITE_VALUES: tuple[int, ...] = (LINK_POLICY_SX_AC, LINK_POLICY_SX_DC)

#: ``AMT_EthernetPortSettings`` properties that must be **deleted** from a
#: read-modify-write body before ``Put``.
#:
#: Derived by diffing the vendor's two structs in
#: ``pkg/wsman/amt/ethernetport/types.go``: these four appear on
#: ``SettingsResponse`` (what a Get returns) and are **absent from**
#: ``SettingsRequest`` (what a Put may carry). Three of them say why in their own
#: doc comments -- ``MACAddress``: "This property can only be read and can't be
#: changed"; ``LinkControl``: "This property is read-only";
#: ``WLANLinkProtectionLevel``: "Read only property"; ``SharedDynamicIP``: "This
#: property is read only."
#:
#: MeshCmd's ``performAmtNetConfig1`` deletes a **superset** of these
#: (additionally ``SharedMAC``, ``SharedStaticIp``, ``LinkIsUp``, ``LinkPolicy``,
#: ``IpSyncEnabled``) before its Put. That is prior art for "more deletion is
#: tolerated", not evidence that those five are read-only -- the vendor request
#: struct lists all five as settable, and ``LinkPolicy`` in particular is a
#: property this module exists to be able to write. So this list stays at the
#: four the vendor schema actually marks read-only, and the ones MeshCmd drops
#: for its own convenience are carried through unchanged.
ETHERNET_READ_ONLY_FIELDS: tuple[str, ...] = (
    "MACAddress",
    "LinkControl",
    "SharedDynamicIP",
    "WLANLinkProtectionLevel",
)

#: ``AMT_EthernetPortSettings`` static-addressing properties, which must **not**
#: be sent when ``DHCPEnabled`` is true.
#:
#: MeshCmd is the source and is explicit about it: ``performAmtNetConfig1`` does
#: ``if (x['DHCPEnabled'] == true) { delete x['IPAddress']; delete
#: x['DefaultGateway']; delete x['PrimaryDNS']; delete x['SecondaryDNS']; delete
#: x['SubnetMask']; }`` immediately before the Put. The vendor class definition
#: corroborates the reasoning on ``IPAddress``: "Get operation - reports the
#: acquired IP address (whether in static or DHCP mode). Put operation - sets the
#: IP address (**in static mode only**)".
#:
#: This matters for a plain read-modify-write: a Get on a static endpoint returns
#: all five populated, so switching to DHCP by flipping one boolean would
#: otherwise echo a full static configuration back alongside ``DHCPEnabled=true``
#: and ask firmware to reconcile a contradiction.
ETHERNET_STATIC_ADDRESS_FIELDS: tuple[str, ...] = (
    "IPAddress",
    "SubnetMask",
    "DefaultGateway",
    "PrimaryDNS",
    "SecondaryDNS",
)

#: ``AMT_GeneralSettings`` properties present on the Get response and **absent
#: from** ``GeneralSettingsRequest`` in ``pkg/wsman/amt/general/types.go``, i.e.
#: read-only. Their own doc comments confirm all four: ``NetworkInterfaceEnabled``
#: "This is a read-only property"; ``DigestRealm`` "This is a read-only
#: property"; ``PrivacyLevel`` "This is a read-only property"; ``PowerSource``
#: "This is a read-only property".
#:
#: MeshCentral does **not** strip these -- both ``amtmanager.js`` and
#: ``agents/meshcmd.js`` Put the whole Get body back including ``DigestRealm``,
#: apparently successfully. So firmware tolerating them is prior art. Stripping
#: is still the choice here, on the same reasoning ``boot.DELETE_BEFORE_PUT_FIELDS``
#: encodes: the cost of sending a read-only property is a rejected Put on some
#: firmware generation, and the cost of omitting one is nothing, because none of
#: the four is documented as required for the Put.
GENERAL_READ_ONLY_FIELDS: tuple[str, ...] = (
    "NetworkInterfaceEnabled",
    "DigestRealm",
    "PrivacyLevel",
    "PowerSource",
)

#: ``AMT_GeneralSettings`` properties the vendor class definition marks
#: **required for the Put command** -- verbatim from
#: ``pkg/wsman/amt/general/types.go``: "'PingResponseEnabled' is a required field
#: for the Put command", "'WsmanOnlyMode' is a required field for the Put
#: command".
#:
#: This module always read-modify-writes, so both arrive from the Get and are
#: simply never dropped. The tuple exists so :func:`build_general_put_properties`
#: can *assert* they survived rather than leaving it to be true by accident --
#: which is exactly what a future edit to ``GENERAL_READ_ONLY_FIELDS`` could
#: break silently.
GENERAL_REQUIRED_FOR_PUT: tuple[str, ...] = ("PingResponseEnabled", "WsmanOnlyMode")

#: ``AMT_EthernetPortSettings.DHCPEnabled`` is likewise annotated "'DHCPEnabled'
#: is a required field for the Put command" in the vendor class definition. Same
#: treatment, same reason.
ETHERNET_REQUIRED_FOR_PUT: tuple[str, ...] = ("DHCPEnabled",)

#: Module option name -> ``AMT_EthernetPortSettings`` property name. Kept as a
#: data table rather than branching code so the option surface can be audited
#: against the vendor request struct at a glance.
ETHERNET_OPTION_TO_PROPERTY: dict[str, str] = {
    "dhcp_enabled": "DHCPEnabled",
    "ip_address": "IPAddress",
    "subnet_mask": "SubnetMask",
    "default_gateway": "DefaultGateway",
    "primary_dns": "PrimaryDNS",
    "secondary_dns": "SecondaryDNS",
    "link_policy": "LinkPolicy",
}

#: Module option name -> ``AMT_GeneralSettings`` property name.
GENERAL_OPTION_TO_PROPERTY: dict[str, str] = {
    "ping_response_enabled": "PingResponseEnabled",
    "rmcp_ping_response_enabled": "RmcpPingResponseEnabled",
    "hostname": "HostName",
    "domain_name": "DomainName",
}

#: The options whose application changes **the addressing of the interface this
#: connection arrived on**, and therefore may end the connection mid-write.
#:
#: ``primary_dns``/``secondary_dns`` are deliberately **not** here, and the
#: distinction is not cosmetic: those two configure the *endpoint's own outbound*
#: name resolution. They have no effect on how a controller reaches the endpoint,
#: which is whatever ``host`` says. Sweeping them in would demand the
#: acknowledgement flag for a change that cannot possibly disconnect anyone,
#: which is how a safety gate gets routinely bypassed.
#:
#: ``subnet_mask`` and ``default_gateway`` *are* here even though neither changes
#: the address: a narrowed mask or a wrong gateway takes the endpoint off the
#: controller's path just as completely as a moved address does, for any
#: controller that is not on the same link.
SELF_DISCONNECTING_OPTIONS: tuple[str, ...] = (
    "dhcp_enabled",
    "ip_address",
    "subnet_mask",
    "default_gateway",
)


def _parse_ipv4(value: str) -> tuple[int, int, int, int] | None:
    """Parse a strict dotted-quad IPv4 literal, or return ``None``.

    Deliberately stricter than :func:`ipaddress.IPv4Address`, which accepts
    forms an operator never means here. Rejects leading zeros (``192.0.2.010``
    is octal in some resolvers and decimal in others), anything that is not
    exactly four parts, and any non-digit character. The value is about to be
    written into firmware on the interface carrying this request, so "probably
    fine" is not good enough.
    """
    parts = value.split(".")
    if len(parts) != 4:
        return None
    octets: list[int] = []
    for part in parts:
        if not part or not part.isdigit():
            return None
        if len(part) > 1 and part[0] == "0":
            return None
        number = int(part)
        if number > 255:
            return None
        octets.append(number)
    return (octets[0], octets[1], octets[2], octets[3])


def is_ipv4(value: str | None) -> bool:
    """Whether ``value`` is a strict dotted-quad IPv4 literal."""
    return bool(value) and _parse_ipv4(value) is not None  # type: ignore[arg-type]


def _to_int(octets: tuple[int, int, int, int]) -> int:
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


def is_contiguous_netmask(value: str) -> bool:
    """Whether ``value`` is a dotted-quad mask with a single run of leading ones.

    ``255.255.0.255`` parses as an IPv4 literal and is not a mask. Firmware is
    not obliged to reject it, and an endpoint whose mask has a hole in it is
    reachable from an arbitrary-looking subset of the network -- the worst shape
    of failure to diagnose remotely.

    ``0.0.0.0`` and ``255.255.255.255`` are both accepted as contiguous: they are
    degenerate but well-defined, and refusing them here would be this module
    inventing a rule rather than checking one.
    """
    octets = _parse_ipv4(value)
    if octets is None:
        return False
    as_int = _to_int(octets)
    # A contiguous mask is 2^32 - 2^(32-prefix). Inverting it gives a value whose
    # binary form is all-ones-then-nothing, and (x & (x + 1)) == 0 tests exactly
    # that for the inverse.
    inverse = (~as_int) & 0xFFFFFFFF
    return (inverse & (inverse + 1)) == 0


def same_subnet(address: str, other: str, netmask: str) -> bool:
    """Whether two IPv4 addresses share a subnet under ``netmask``.

    Returns ``False`` if any of the three is not parseable rather than raising:
    every caller here has already validated them, and this is used to build a
    *warning*, which must never be the thing that fails a run.
    """
    left, right, mask = _parse_ipv4(address), _parse_ipv4(other), _parse_ipv4(netmask)
    if left is None or right is None or mask is None:
        return False
    mask_int = _to_int(mask)
    return (_to_int(left) & mask_int) == (_to_int(right) & mask_int)


def decode_link_policy_option(names: list[str]) -> list[int]:
    """Turn the module's ``link_policy`` name list into the integers firmware takes.

    Order-preserving and duplicate-collapsing, then sorted, so two callers who
    wrote the same set in a different order produce the same Put body and the
    same idempotence verdict. Firmware's ``LinkPolicy`` is a *set* -- the vendor
    schema types it as an unordered array of enum values -- so imposing a stable
    order here invents no meaning, whereas leaving it caller-ordered would make
    ``changed`` depend on YAML ordering.

    Raises :class:`ValueError` for a name outside :data:`LINK_POLICY_WRITE_VALUES`.
    A programming error, not a firmware capability question, so it is not one of
    the :mod:`errors` classes -- the module's ``choices`` list makes it
    unreachable from a playbook.
    """
    unknown = sorted(set(names) - set(LINK_POLICY_WRITE_VALUES))
    if unknown:
        raise ValueError(f"unknown link_policy name(s) {unknown}; expected a subset of {sorted(LINK_POLICY_WRITE_VALUES)}")
    return sorted({LINK_POLICY_WRITE_VALUES[name] for name in names})


def link_policy_names(values: list[int]) -> list[str]:
    """Name each raw ``LinkPolicy`` integer, keeping an unrecognised one visible.

    Mirrors ``models._decode``'s contract exactly, including that a value outside
    the four-member enum renders ``unknown(<raw>)`` rather than a bare
    ``unknown`` -- 0 is not a defined member here, but "the firmware reported
    something we cannot name" and "the firmware reported the defined value that
    happens to mean unknown" must never render identically. See
    docs/protocol-notes.md s2.7.
    """
    by_value = {value: name for name, value in LINK_POLICY_WRITE_VALUES.items()}
    return [by_value.get(value, f"unknown({value})") for value in values]


@dataclass(frozen=True, slots=True)
class PropertyChange:
    """One property this plan would move, with both readings kept.

    ``raw_previous``/``raw_desired`` are the values as they cross the wire (the
    strings and lists a ``Put`` body carries). ``previous``/``desired`` are the
    human-facing renderings -- for ``LinkPolicy`` that is the decoded name list
    alongside the integers, per this collection's rule that every decoded enum
    reports its raw integer next to its name.
    """

    resource_class: str
    property_name: str
    previous: Any
    desired: Any
    raw_previous: Any = None
    raw_desired: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_class": self.resource_class,
            "property": self.property_name,
            "previous": self.previous,
            "desired": self.desired,
        }


@dataclass(frozen=True, slots=True)
class NetworkPlan:
    """Everything decided before any mutation is issued.

    Built entirely from reads, so it is identical in check mode and normal mode
    -- which is the property that makes ``--check`` worth anything here. Holding
    the finished Put bodies (rather than the option values) means check mode
    reports the exact bytes normal mode would send, not a paraphrase of them.
    """

    changes: tuple[PropertyChange, ...]
    ethernet_previous: dict[str, Any]
    general_previous: dict[str, Any]
    ethernet_put: dict[str, Any] | None
    general_put: dict[str, Any] | None
    #: Advisory findings that do not block the write. Reported through
    #: ``AnsibleModule.warn`` by the module, never raised: each is a
    #: configuration a competent operator may genuinely intend.
    warnings: tuple[str, ...] = ()
    #: Whether ``host`` matches the address firmware reports for the interface
    #: being configured. ``None`` when ``host`` is not an IPv4 literal, and that
    #: third state is load-bearing -- see :func:`plan_network_change`.
    connected_through_managed_address: bool | None = None
    #: Whether the plan touches this connection's own addressing at all.
    addressing_change: bool = False
    #: Whether the plan would leave ``LinkPolicy`` with no Sx value.
    wake_capability_loss: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "changes": [change.to_dict() for change in self.changes],
            "addressing_change": self.addressing_change,
            "wake_capability_loss": self.wake_capability_loss,
            "connected_through_managed_address": self.connected_through_managed_address,
        }


@dataclass(frozen=True, slots=True)
class NetworkApplyResult:
    """What :func:`apply_network_change` actually did and actually observed."""

    plan: NetworkPlan
    #: The classes written, in the order written. Empty in check mode and when
    #: the plan was already converged.
    written_classes: tuple[str, ...] = ()
    #: Re-read instances, or ``None`` for a class whose confirming read could not
    #: be obtained.
    ethernet_observed: dict[str, Any] | None = None
    general_observed: dict[str, Any] | None = None
    #: True when a Put was issued and no confirming read could be obtained. The
    #: module turns this into a failure carrying ``indeterminate: true``.
    indeterminate: bool = False
    #: The classified error the confirming read failed with, when it did.
    confirmation_error: AmtError | None = None
    #: Properties that were written, re-read successfully, and came back with a
    #: value other than the one requested.
    unapplied: tuple[PropertyChange, ...] = field(default_factory=tuple)


def _normalize_bool_for_wire(value: Any) -> str:
    """Render a bool the way firmware's own responses do: lowercase ``true``/``false``.

    Not ``str(bool)``: that yields ``True``/``False``, which is not what the
    ``xsd:boolean`` lexical space accepts and not what any recorded firmware
    response uses. ``wsman._coerce_param_text`` already does this for real
    ``bool`` objects; this exists so a comparison between "what we intend to
    send" and "what the Get returned as text" is made on one representation.
    """
    return "true" if truthy(value) else "false"


def _comparable(value: Any) -> Any:
    """Reduce a wire value to something two readings can be compared on.

    Firmware returns element text, so every scalar arrives as ``str``; the plan
    holds Python types. Without this, ``DHCPEnabled: False`` and
    ``DHCPEnabled: "false"`` compare unequal and the module reports a change on
    every run forever -- the classic non-idempotent-module bug.
    """
    if isinstance(value, bool):
        return _normalize_bool_for_wire(value)
    if isinstance(value, list):
        return [_comparable(item) for item in value]
    if value is None:
        return None
    return str(value).strip()


def build_ethernet_put_properties(read_instance: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    """Read-modify-write body for ``AMT_EthernetPortSettings``.

    Order matters and is not stylistic:

    1. Start from the whole read instance. This is a ``Put``, which replaces the
       instance -- a partial body would ask firmware to default everything it did
       not mention.
    2. Delete :data:`ETHERNET_READ_ONLY_FIELDS`.
    3. Apply the desired properties.
    4. **Then** drop :data:`ETHERNET_STATIC_ADDRESS_FIELDS` if the *resulting*
       ``DHCPEnabled`` is true. Step 4 must come after step 3, not before: the
       decision depends on the value being written, not the one that was read.
       Getting this backwards is how you send ``DHCPEnabled=true`` alongside a
       full static configuration.

    Raises :class:`InvalidStateError` if a property the vendor marks required for
    the Put would be absent from the body. That cannot happen through this
    module's own option surface -- the value comes from the Get -- which is
    exactly why it is asserted rather than assumed.
    """
    body: dict[str, Any] = dict(read_instance)

    for field_name in ETHERNET_READ_ONLY_FIELDS:
        body.pop(field_name, None)

    body.update(desired)

    if truthy(body.get("DHCPEnabled")):
        for field_name in ETHERNET_STATIC_ADDRESS_FIELDS:
            body.pop(field_name, None)

    missing = [name for name in ETHERNET_REQUIRED_FOR_PUT if name not in body]
    if missing:
        raise InvalidStateError(
            f"refusing to Put AMT_EthernetPortSettings without {missing}, which the class definition marks required for the Put command "
            "(go-wsman-messages pkg/wsman/amt/ethernetport/types.go). The value should have come from the preceding Get; that it did not "
            "means firmware did not report it, and writing the instance without it could reset the interface's addressing mode.",
            operation="build_ethernet_put_properties",
        )
    return body


def build_general_put_properties(read_instance: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    """Read-modify-write body for ``AMT_GeneralSettings``.

    Same shape as :func:`build_ethernet_put_properties` minus the DHCP
    interaction, which has no analogue here. The required-field assertion is the
    important part: ``PingResponseEnabled`` and ``WsmanOnlyMode`` are both
    documented as required for this Put, and ``WsmanOnlyMode`` is one this module
    never sets -- it only ever passes it through. A future edit that added it to
    :data:`GENERAL_READ_ONLY_FIELDS` would silently start sending a body firmware
    can reject; this turns that into an immediate, named failure.
    """
    body: dict[str, Any] = dict(read_instance)

    for field_name in GENERAL_READ_ONLY_FIELDS:
        body.pop(field_name, None)

    body.update(desired)

    missing = [name for name in GENERAL_REQUIRED_FOR_PUT if name not in body]
    if missing:
        raise InvalidStateError(
            f"refusing to Put AMT_GeneralSettings without {missing}, which the class definition marks required for the Put command "
            "(go-wsman-messages pkg/wsman/amt/general/types.go). Both values should have come from the preceding Get.",
            operation="build_general_put_properties",
        )
    return body


def _desired_ethernet(options: dict[str, Any]) -> dict[str, Any]:
    """The ``AMT_EthernetPortSettings`` properties the caller asked for, wire-shaped."""
    desired: dict[str, Any] = {}
    for option_name, property_name in ETHERNET_OPTION_TO_PROPERTY.items():
        value = options.get(option_name)
        if value is None:
            continue
        if option_name == "link_policy":
            if not value:
                # An empty list is not "no change" and it is not a valid policy. It
                # would also be *unwritable*: an array property with no values emits
                # no elements at all (wsman._append_params), so the Put body would
                # simply omit LinkPolicy and firmware would be asked nothing. Refuse
                # it rather than let a caller reach a shape whose meaning is
                # unestablished on both sides.
                raise InvalidStateError(
                    "link_policy was supplied as an empty list. Omit the option entirely to leave the policy alone; a policy with no "
                    f"values is not one of the four the enum defines ({sorted(LINK_POLICY_WRITE_VALUES)}) and would be written as an "
                    "absent property rather than as an empty one.",
                    operation="plan_network_change",
                )
            desired[property_name] = decode_link_policy_option(list(value))
        elif isinstance(value, bool):
            desired[property_name] = value
        else:
            desired[property_name] = str(value)
    return desired


def _desired_general(options: dict[str, Any]) -> dict[str, Any]:
    """The ``AMT_GeneralSettings`` properties the caller asked for, wire-shaped."""
    desired: dict[str, Any] = {}
    for option_name, property_name in GENERAL_OPTION_TO_PROPERTY.items():
        value = options.get(option_name)
        if value is None:
            continue
        desired[property_name] = value if isinstance(value, bool) else str(value)
    return desired


def _validate_addressing(options: dict[str, Any], resulting: dict[str, Any]) -> None:
    """Refuse a syntactically or structurally impossible addressing configuration.

    Runs before the first ``Put``, so a caller mistake costs a task failure
    rather than an endpoint. ``resulting`` is the post-merge view of
    ``AMT_EthernetPortSettings``, because most of these questions are about what
    the interface will *end up* configured as, not about which option was
    supplied on this call.
    """
    for option_name in ("ip_address", "subnet_mask", "default_gateway", "primary_dns", "secondary_dns"):
        value = options.get(option_name)
        if value is None:
            continue
        if not is_ipv4(str(value)):
            raise InvalidStateError(
                f"{option_name}={value!r} is not a dotted-quad IPv4 address. This module writes IPv4 addressing to the interface that "
                "carries its own connection, so an address it cannot parse is refused rather than handed to firmware. Leading zeros are "
                "rejected too: '010' is octal to some resolvers and decimal to others.",
                operation="validate_addressing",
            )

    subnet_mask = options.get("subnet_mask")
    if subnet_mask is not None and not is_contiguous_netmask(str(subnet_mask)):
        raise InvalidStateError(
            f"subnet_mask={subnet_mask!r} is not a contiguous netmask. A mask with a hole in it (for example 255.255.0.255) parses as an "
            "IPv4 address but makes the endpoint reachable from an arbitrary-looking subset of the network, which is the hardest possible "
            "failure to diagnose remotely.",
            operation="validate_addressing",
        )

    if truthy(resulting.get("DHCPEnabled")):
        # Nothing further to require: firmware supplies the addressing, and
        # build_ethernet_put_properties has already dropped the static fields.
        return

    for property_name, option_name in (("IPAddress", "ip_address"), ("SubnetMask", "subnet_mask")):
        if not optional_str(resulting.get(property_name)):
            raise InvalidStateError(
                f"a static configuration (dhcp_enabled=false) needs {property_name}, and neither the endpoint's current value nor a "
                f"supplied {option_name} provides one. Writing a static interface with no address would leave the endpoint unreachable "
                "until someone visits MEBx, so this is refused before any Put is issued.",
                operation="validate_addressing",
            )


def _gateway_warnings(resulting: dict[str, Any]) -> tuple[str, ...]:
    """Advisory checks on the resulting static configuration.

    Deliberately warnings and not refusals. An off-link default gateway is
    unusual on an AMT management NIC and is worth saying out loud, but it is a
    real configuration in point-to-point and proxy-ARP setups, and this module
    has no evidence about what AMT firmware does with one. Refusing it would be
    inventing a rule; staying silent would waste the one cheap chance to catch a
    transposed octet before it strands the endpoint.
    """
    if truthy(resulting.get("DHCPEnabled")):
        return ()
    address = optional_str(resulting.get("IPAddress"))
    netmask = optional_str(resulting.get("SubnetMask"))
    gateway = optional_str(resulting.get("DefaultGateway"))
    if not (address and netmask and gateway):
        return ()
    # 0.0.0.0 is how firmware reports "no gateway configured", not an off-link one.
    if gateway == "0.0.0.0":  # noqa: S104 -- a sentinel being recognised, not an address being bound
        return ()
    if not same_subnet(address, gateway, netmask):
        return (
            f"default_gateway {gateway} is not on the same subnet as {address}/{netmask}. That is legal in point-to-point and proxy-ARP "
            "setups and this module has no evidence about how AMT firmware treats it, so it is reported rather than refused -- but it is "
            "also exactly what a transposed octet looks like. Check it before relying on this endpoint being routable.",
        )
    return ()


def plan_network_change(
    *,
    ethernet_instance: dict[str, Any],
    general_instance: dict[str, Any],
    options: dict[str, Any],
    host: str,
    allow_self_disconnect: bool = False,
    allow_wake_capability_loss: bool = False,
) -> NetworkPlan:
    """Decide everything, refuse everything refusable, and issue nothing.

    Pure: no client, no I/O, no check-mode parameter. Check mode and normal mode
    call this identically, which is the only way ``--check`` can honestly claim
    to report what a real run would do. Every guard below therefore also fires in
    check mode -- a dry run that silently skipped the self-disconnect refusal
    would be worse than no dry run, because it would tell an operator the write
    is safe.

    Raises :class:`InvalidStateError` for a caller mistake or an unacknowledged
    hazard, and :class:`UnsupportedCapabilityError` when the interface being
    configured is not present at all.
    """
    if not ethernet_instance:
        raise UnsupportedCapabilityError(
            f"AMT_EthernetPortSettings {ETHERNET_PORT_0_SELECTOR['InstanceID']!r} did not answer a Get, so there is no interface to "
            "configure. amt_info reports this as network: null. This module will not fall back to another instance index: instance 0 is "
            "the wired port AMT answers on (docs/protocol-notes.md s2.7), and writing addressing to a different port than the one the "
            "caller believes they are configuring is worse than refusing.",
            operation="plan_network_change",
        )

    desired_ethernet = _desired_ethernet(options)
    desired_general = _desired_general(options)

    if not desired_ethernet and not desired_general:
        raise InvalidStateError(
            "amt_network was called with no setting to apply. At least one of "
            f"{sorted([*ETHERNET_OPTION_TO_PROPERTY, *GENERAL_OPTION_TO_PROPERTY])} must be set. A call that changes nothing would "
            "report changed=false and look like successful convergence, which is indistinguishable from a mistyped option name.",
            operation="plan_network_change",
        )

    if desired_general and not general_instance:
        raise UnsupportedCapabilityError(
            f"AMT_GeneralSettings did not answer a Get, so {sorted(desired_general)} cannot be written. Nothing is Put to "
            "AMT_EthernetPortSettings either: a call that asked for both classes and silently configured only one would leave the "
            "endpoint in a state the caller did not describe.",
            operation="plan_network_change",
        )

    # The resulting view is needed by the validators before the bodies are built,
    # because "is the end state static, and does it have an address" is a
    # question about the merge, not about either side of it.
    resulting_ethernet = {**ethernet_instance, **desired_ethernet}
    _validate_addressing(options, resulting_ethernet)

    changes: list[PropertyChange] = []
    for property_name, desired_value in sorted(desired_ethernet.items()):
        previous_value = ethernet_instance.get(property_name)
        if _comparable(previous_value) == _comparable(desired_value):
            continue
        if property_name == "LinkPolicy":
            previous_values = [
                number for item in (previous_value if isinstance(previous_value, list) else [previous_value]) if (number := optional_int(item)) is not None
            ]
            changes.append(
                PropertyChange(
                    resource_class="AMT_EthernetPortSettings",
                    property_name=property_name,
                    previous={"values": previous_values, "names": link_policy_names(previous_values)},
                    desired={"values": list(desired_value), "names": link_policy_names(list(desired_value))},
                    raw_previous=previous_value,
                    raw_desired=desired_value,
                )
            )
            continue
        changes.append(
            PropertyChange(
                resource_class="AMT_EthernetPortSettings",
                property_name=property_name,
                previous=optional_bool(previous_value) if isinstance(desired_value, bool) else optional_str(previous_value),
                desired=desired_value,
                raw_previous=previous_value,
                raw_desired=desired_value,
            )
        )

    for property_name, desired_value in sorted(desired_general.items()):
        previous_value = general_instance.get(property_name)
        if _comparable(previous_value) == _comparable(desired_value):
            continue
        changes.append(
            PropertyChange(
                resource_class="AMT_GeneralSettings",
                property_name=property_name,
                previous=optional_bool(previous_value) if isinstance(desired_value, bool) else optional_str(previous_value),
                desired=desired_value,
                raw_previous=previous_value,
                raw_desired=desired_value,
            )
        )

    changed_properties = {(change.resource_class, change.property_name) for change in changes}
    addressing_change = any(
        ("AMT_EthernetPortSettings", ETHERNET_OPTION_TO_PROPERTY[option_name]) in changed_properties for option_name in SELF_DISCONNECTING_OPTIONS
    )

    reported_address = optional_str(ethernet_instance.get("IPAddress"))
    connected_through_managed_address: bool | None = None
    if is_ipv4(host) and reported_address is not None:
        connected_through_managed_address = host == reported_address

    if addressing_change and not allow_self_disconnect:
        addressing_properties = sorted(
            ETHERNET_OPTION_TO_PROPERTY[option_name]
            for option_name in SELF_DISCONNECTING_OPTIONS
            if ("AMT_EthernetPortSettings", ETHERNET_OPTION_TO_PROPERTY[option_name]) in changed_properties
        )
        raise InvalidStateError(
            "refusing to change the addressing of the interface this connection arrived on without allow_self_disconnect=true. "
            "AMT_EthernetPortSettings instance 0 is the wired port AMT answers WS-Man on, so a change to "
            f"{addressing_properties} can invalidate this very connection before the write can be confirmed -- and this module will not "
            f"report a success it could not observe. host={host!r}, firmware reports IPAddress={reported_address!r} "
            f"(connected_through_managed_address={connected_through_managed_address}). Set allow_self_disconnect=true to proceed, and "
            "expect either a confirmed change or a failure carrying indeterminate=true telling you to re-probe at the new address.",
            operation="plan_network_change",
        )

    wake_capability_loss = False
    if ("AMT_EthernetPortSettings", "LinkPolicy") in changed_properties:
        previous_policy = [number for item in (ethernet_instance.get("LinkPolicy") or []) if (number := optional_int(item)) is not None]
        desired_policy = list(desired_ethernet["LinkPolicy"])
        had_sx = any(value in LINK_POLICY_SX_WRITE_VALUES for value in previous_policy)
        keeps_sx = any(value in LINK_POLICY_SX_WRITE_VALUES for value in desired_policy)
        wake_capability_loss = had_sx and not keeps_sx
        if wake_capability_loss and not allow_wake_capability_loss:
            raise InvalidStateError(
                "refusing to remove the last Sx value from LinkPolicy without allow_wake_capability_loss=true. The endpoint currently "
                f"reports {previous_policy} ({link_policy_names(previous_policy)}) and the requested policy is "
                f"{desired_policy} ({link_policy_names(desired_policy)}), which carries neither {LINK_POLICY_SX_AC} (Sx AC) nor "
                f"{LINK_POLICY_SX_DC} (Sx DC). Without an Sx value the network link is maintained only while the host is in S0, so the "
                "endpoint stops answering WS-Man entirely once it sleeps or powers down -- and amt_power state=on can then no longer "
                "reach it to bring it back. This is a change you can make and cannot undo remotely.",
                operation="plan_network_change",
            )

    ethernet_put = (
        build_ethernet_put_properties(ethernet_instance, desired_ethernet)
        if any(change.resource_class == "AMT_EthernetPortSettings" for change in changes)
        else None
    )
    general_put = (
        build_general_put_properties(general_instance, desired_general) if any(change.resource_class == "AMT_GeneralSettings" for change in changes) else None
    )

    return NetworkPlan(
        changes=tuple(changes),
        ethernet_previous=dict(ethernet_instance),
        general_previous=dict(general_instance),
        ethernet_put=ethernet_put,
        general_put=general_put,
        warnings=_gateway_warnings(resulting_ethernet),
        connected_through_managed_address=connected_through_managed_address,
        addressing_change=addressing_change,
        wake_capability_loss=wake_capability_loss,
    )


def read_network_state(client: WsmanClient) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read both classes, tolerating neither failure.

    Unlike ``client.AmtClient.get_facts``, which degrades a missing class to
    ``None`` because a fact is worth less than the read, a *mutation* must not
    proceed on a class it could not read: the Put body is the read instance with
    edits applied, so an unreadable class means there is nothing to edit. A
    firmware that genuinely lacks the class surfaces through
    :func:`plan_network_change`'s ``unsupported_capability`` refusal, which says
    so in those words, rather than through an empty Put.

    ``AMT_EthernetPortSettings`` is read with its exact selector and
    ``AMT_GeneralSettings`` with none -- see :data:`ETHERNET_PORT_0_SELECTOR` and
    :data:`GENERAL_SETTINGS_SELECTOR` for why that asymmetry is the vendor's and
    not this module's.
    """
    ethernet = client.get("AMT_EthernetPortSettings", selectors=ETHERNET_PORT_0_SELECTOR)
    general = client.get("AMT_GeneralSettings", selectors=GENERAL_SETTINGS_SELECTOR)
    return ethernet, general


def decode_ethernet(instance: dict[str, Any] | None) -> dict[str, Any] | None:
    """Render an ``AMT_EthernetPortSettings`` instance through the existing reader.

    Reuses :class:`models.EthernetSettings` rather than re-deriving the same
    fields: the decode table, the MAC normalization and the
    ``wake_on_lan_capable`` derivation all already exist and are the ones
    ``amt_info`` publishes, so a caller can compare this module's output against
    ``amt_info``'s field for field.
    """
    if not instance:
        return None
    settings = EthernetSettings.from_instance(instance)
    return {
        "mac_address": settings.mac_address,
        "ip_address": settings.ip_address,
        "subnet_mask": settings.subnet_mask,
        "default_gateway": settings.default_gateway,
        "primary_dns": settings.primary_dns,
        "secondary_dns": settings.secondary_dns,
        "dhcp_enabled": settings.dhcp_enabled,
        "link_is_up": settings.link_is_up,
        "ip_sync_enabled": settings.ip_sync_enabled,
        "link_policy": settings.link_policy,
        "link_policy_names": settings.link_policy_names,
        "wake_on_lan_capable": settings.wake_on_lan_capable,
    }


def decode_general(instance: dict[str, Any] | None) -> dict[str, Any] | None:
    """The ``AMT_GeneralSettings`` fields this module can write, plus the two it reads.

    ``network_interface_enabled`` is read-only (:data:`GENERAL_READ_ONLY_FIELDS`)
    and is reported anyway: it is the property that explains an endpoint whose
    addressing is perfect and which still answers nothing.
    """
    if not instance:
        return None
    return {
        "hostname": optional_str(instance.get("HostName")),
        "domain_name": optional_str(instance.get("DomainName")),
        "ping_response_enabled": optional_bool(instance.get("PingResponseEnabled")),
        "rmcp_ping_response_enabled": optional_bool(instance.get("RmcpPingResponseEnabled")),
        "network_interface_enabled": optional_bool(instance.get("NetworkInterfaceEnabled")),
    }


def _unapplied_changes(plan: NetworkPlan, ethernet_observed: dict[str, Any] | None, general_observed: dict[str, Any] | None) -> tuple[PropertyChange, ...]:
    """Which planned changes the confirming read shows did not take.

    Only checked for a class whose re-read succeeded: a class with no
    observation contributes nothing here, because "we could not look" and "we
    looked and it had not changed" are different findings and only the second one
    is firmware refusing a write. The first is :attr:`NetworkApplyResult.indeterminate`.
    """
    observed_by_class = {
        "AMT_EthernetPortSettings": ethernet_observed,
        "AMT_GeneralSettings": general_observed,
    }
    unapplied: list[PropertyChange] = []
    for change in plan.changes:
        observed = observed_by_class.get(change.resource_class)
        if observed is None:
            continue
        if _comparable(observed.get(change.property_name)) != _comparable(change.raw_desired):
            unapplied.append(
                PropertyChange(
                    resource_class=change.resource_class,
                    property_name=change.property_name,
                    previous=change.previous,
                    desired=change.desired,
                    raw_previous=observed.get(change.property_name),
                    raw_desired=change.raw_desired,
                )
            )
    return tuple(unapplied)


def apply_network_change(client: WsmanClient, plan: NetworkPlan, *, check_mode: bool = False) -> NetworkApplyResult:
    """Issue the plan's Puts, then confirm by re-reading. Never retries anything.

    Ordering: ``AMT_GeneralSettings`` **first**, ``AMT_EthernetPortSettings``
    second, and that is deliberate. The ethernet Put is the one that can end the
    connection; running it last means every non-addressing change in the same
    call has already been written and confirmed by the time the risky one is
    issued. The reverse order would make a self-disconnecting address change also
    lose the hostname change the caller asked for in the same task, with no way
    to tell which of the two happened.

    Confirmation is a fresh ``Get`` of each written class. Three outcomes, each
    reported differently because a caller acts on them differently:

    * both re-reads succeed and agree with the plan -- a confirmed change.
    * a re-read succeeds and *disagrees* -- firmware accepted the body and did
      not apply the property. Reported in ``unapplied``; the module fails with
      ``unsupported_capability``, following the rule issue #69 established for
      ``amt_media``: unsupported_capability for a definite refusal, timeout for
      no verdict.
    * a re-read cannot be obtained at all -- ``indeterminate=True``, carrying the
      original error so its classification survives. This is the expected shape
      of a forced address change, and it is a failure rather than a success
      precisely because nothing confirmed it.

    ``AmtError`` from a ``Put`` is deliberately **not** caught: a rejected body
    (SOAP fault, HTTP 400) or a timeout raised by the transport already carries
    the right classification, and ``wsman.WsmanClient._execute`` already sets
    ``indeterminate=True`` on a post-transmission read timeout. Re-wrapping it
    here would only blur it.
    """
    if check_mode or not plan.changed:
        return NetworkApplyResult(plan=plan, ethernet_observed=None, general_observed=None)

    written: list[str] = []
    if plan.general_put is not None:
        client.put("AMT_GeneralSettings", plan.general_put, selectors=GENERAL_SETTINGS_SELECTOR)
        written.append("AMT_GeneralSettings")
    if plan.ethernet_put is not None:
        client.put("AMT_EthernetPortSettings", plan.ethernet_put, selectors=ETHERNET_PORT_0_SELECTOR)
        written.append("AMT_EthernetPortSettings")

    ethernet_observed: dict[str, Any] | None = None
    general_observed: dict[str, Any] | None = None
    confirmation_error: AmtError | None = None
    try:
        if "AMT_GeneralSettings" in written:
            general_observed = client.get("AMT_GeneralSettings", selectors=GENERAL_SETTINGS_SELECTOR)
        if "AMT_EthernetPortSettings" in written:
            ethernet_observed = client.get("AMT_EthernetPortSettings", selectors=ETHERNET_PORT_0_SELECTOR)
    except AmtError as err:
        # The write is already on the wire. A failed confirming read says nothing
        # about whether it took, which is the entire content of `indeterminate`.
        confirmation_error = err

    return NetworkApplyResult(
        plan=plan,
        written_classes=tuple(written),
        ethernet_observed=ethernet_observed,
        general_observed=general_observed,
        indeterminate=confirmation_error is not None,
        confirmation_error=confirmation_error,
        unapplied=_unapplied_changes(plan, ethernet_observed, general_observed),
    )


def indeterminate_error(result: NetworkApplyResult, *, endpoint: str) -> AmtError:
    """Re-raise the confirming read's failure with ``indeterminate=True`` attached.

    Constructed as the **same exception type** the confirming read raised, so a
    connection failure stays ``error_class=connection`` and a timeout stays
    ``timeout``. Coercing everything to ``TimeoutError_`` would be the easy shape
    and would misclassify the most likely case: a forced address change ends with
    the endpoint refusing connections at the old address, which is
    ``connection``, not ``timeout``.

    ``indeterminate`` is not decoration. It has one meaning in this collection
    (``errors.AmtError.to_result``, ``errors.TimeoutError_``): the mutation may
    have taken effect, so **re-probe, do not retry**. Retrying an addressing Put
    against an endpoint that already moved would be a write to nothing at best.
    """
    original = result.confirmation_error
    if original is None:
        raise ValueError("indeterminate_error() called on a result whose confirming read succeeded; there is nothing indeterminate to report")
    written = ", ".join(result.written_classes) or "nothing"
    return type(original)(
        f"amt_network issued a Put to {written} and then could not confirm it: {original.message} "
        "The write may or may not have taken effect, so this is reported as indeterminate rather than as either success or a clean "
        "failure. This is the expected outcome of an allow_self_disconnect=true addressing change -- the endpoint answers at its new "
        "address, not the one this task connected to. Re-probe with amt_info against the address you now expect, and do not retry this "
        "task against the old one.",
        endpoint=endpoint,
        operation="amt_network.confirm",
        indeterminate=True,
    )


def unapplied_error(result: NetworkApplyResult, *, endpoint: str) -> AmtError:
    """The failure for a Put firmware accepted and did not honour.

    ``unsupported_capability``, not ``remote_operation``: nothing returned a
    non-zero ``ReturnValue`` -- a ``Put`` has no ``ReturnValue`` at all -- and
    the request was well-formed enough for firmware to answer 200. What actually
    happened is that this firmware does not let that property be written, which
    is what ``unsupported_capability`` means (``errors.UnsupportedCapabilityError``).
    This follows the classification rule issue #69 set for ``amt_media``: a
    definite refusal is ``unsupported_capability``; only an absent verdict is
    ``timeout``.

    Not ``indeterminate``: this is settled. The confirming read succeeded and
    reported the old value, so there is nothing in flight to re-probe.
    """
    detail = "; ".join(f"{change.property_name} requested {change.desired!r}, firmware still reports {change.raw_previous!r}" for change in result.unapplied)
    return UnsupportedCapabilityError(
        f"amt_network's Put was accepted but {len(result.unapplied)} propert{'y' if len(result.unapplied) == 1 else 'ies'} did not take: {detail}. "
        "Firmware answered the Put with HTTP 200 and then reported the previous value on a fresh Get, which means this firmware does not "
        "permit that property to be written rather than that the request was malformed. Nothing is retried: a second identical Put would "
        "be refused identically.",
        endpoint=endpoint,
        operation="amt_network.confirm",
    )
