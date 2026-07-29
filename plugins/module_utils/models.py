# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Typed result objects and the operation receipt for Intel AMT modules.

Two design rules run through this module:

1. **Observed evidence and caller-supplied identity are different types.**
   :class:`AmtFacts` holds only what the firmware itself reported. A hostname
   or MAC address from inventory is a *claim*, not evidence, and is modelled
   as a separate :class:`CallerSuppliedIdentity` so the two can never be
   merged into one blob that a later identity check might mistake for all
   being firmware-observed.
2. **The receipt never carries credentials.** None of these dataclasses has a
   field shaped like a secret, and :meth:`OperationReceipt.to_dict` also
   runs every string value through :func:`errors.redact` as a defence-in-depth
   backstop, in case a caller ever stuffs something unexpected into
   ``previous``/``desired``/``observed``.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import redact

#: docs/protocol-notes.md s2.4 -- CIM_AssociatedPowerManagementService.PowerState.
#:
#: Names are the DMTF CIM ValueMap for this property, which MeshCmd's own
#: ``DMTFPowerStates`` table (``agents/meshcmd.js``) reproduces identically --
#: 5 = Power Cycle (Off-Soft), 6 = Off-Hard, 8 = Off-Soft, 9 = Power Cycle
#: (Off-Hard). Do not "correct" these against go-wsman-messages'
#: ``pkg/wsman/cim/power/decoder.go``: that file names 5 ``PowerCycleOffHard``,
#: 6 ``PowerCycleOffSoft``, 8 ``PowerOffHard`` and 9 ``PowerOffSoft``, i.e. it
#: transposes the soft/hard qualifier within each pair relative to DMTF. It is
#: also a list of *action* codes to send to ``RequestPowerStateChange`` rather
#: than the observed-state ValueMap, and it carries its own
#: ``TODO: This list of contants needs to be scrubbed`` with most entries marked
#: ``?``. DMTF plus MeshCmd agreeing is the stronger evidence, so the names here
#: follow them.
#:
#: The normalizations, not the names, are what behaviour depends on, and 5 and 9
#: are the weak spot: both are *power cycles* under the DMTF reading, so both end
#: powered on, yet this table normalizes 5 to ``on`` and 9 to ``off``. That
#: asymmetry is inherited, not reasoned, and it is left alone deliberately --
#: changing it is a behaviour change and nothing has measured it. In practice
#: neither value should ever be observed here: 5, 9, 10 and 11 are transitional
#: or action-only codes, and firmware reports a settled state. If a real endpoint
#: is ever seen returning 5 or 9 from
#: ``CIM_AssociatedPowerManagementService.PowerState``, that observation -- not a
#: table -- is what should decide how it normalizes.
_POWER_STATE_TABLE: dict[int, str] = {
    2: "on",  # On
    3: "sleep",  # Sleep - Light
    4: "sleep",  # Sleep - Deep
    5: "on",  # Power Cycle (Off-Soft) -- a cycle, so it ends powered on
    6: "off",  # Off - Hard
    7: "hibernate",  # Hibernate
    8: "off",  # Off - Soft
    9: "off",  # Power Cycle (Off-Hard) -- see the note above on 5 vs 9
    13: "off",  # Off - Hard Graceful
}

#: DMTF ``CIM_EnabledLogicalElement.EnabledState``, per docs/protocol-notes.md s2.7.
#: The full standard table, including ``4`` (shutting down) -- a partial table
#: would report a real transitional state as "unknown".
_ENABLED_STATE_TABLE: dict[int, str] = {
    0: "unknown",
    1: "other",
    2: "enabled",
    3: "disabled",
    4: "shutting_down",
    5: "not_applicable",
    6: "enabled_but_offline",
    7: "in_test",
    8: "deferred",
    9: "quiesce",
    10: "starting",
}

#: DMTF ``CIM_ManagedSystemElement.OperationalStatus``, per docs/protocol-notes.md
#: s2.7. Typed by CIM as an *array*, so it is decoded element-wise.
_OPERATIONAL_STATUS_TABLE: dict[int, str] = {
    0: "unknown",
    1: "other",
    2: "ok",
    3: "degraded",
    4: "stressed",
    5: "predictive_failure",
    6: "error",
    7: "non_recoverable_error",
    8: "starting",
    9: "stopping",
    10: "stopped",
    11: "in_service",
    12: "no_contact",
    13: "lost_communication",
    14: "aborted",
    15: "dormant",
    16: "supporting_entity_in_error",
    17: "completed",
    18: "power_mode",
    19: "relocating",
}

#: ``AMT_EthernetPortSettings.LinkPolicy`` values, from the vendor reference
#: implementation: ``device-management-toolkit/go-wsman-messages``
#: ``pkg/wsman/amt/ethernetport`` (``decoder.go`` named constants, ``types.go``
#: ``ValueMap={1, 14, 16, 224}`` / ``Values={available on S0 AC, available on Sx
#: AC, available on S0 DC, available on Sx DC}``). See docs/protocol-notes.md
#: s2.7.
#:
#: ``Sx`` is any non-S0 ACPI state -- sleep, hibernate, soft-off. ``AC``/``DC``
#: is the power source. The enum therefore crosses two axes, and there is **no**
#: "always on" value: the table this replaced invented one at ``16``, which is
#: really S0 DC. That inversion is what ``_LINK_POLICY_SX_VALUES`` below fixes.
LINK_POLICY_S0_AC = 1
LINK_POLICY_SX_AC = 14
LINK_POLICY_S0_DC = 16
LINK_POLICY_SX_DC = 224

#: The two values that mean "the link is maintained while the host is *not* in
#: S0" -- i.e. while it is asleep, hibernating or off. Presence of either is what
#: makes an endpoint answerable (and so wakeable) over WS-Man in that state; the
#: pair differ only in whether the machine is on mains or battery.
_LINK_POLICY_SX_VALUES = (LINK_POLICY_SX_AC, LINK_POLICY_SX_DC)

#: Only the four values Intel's enum actually defines. Deliberately no more:
#: this table previously carried ``2: sx_ac`` and ``15: sx_dc`` transcribed from
#: ``parmstro``'s constants file, neither of which is in the vendor enum, and
#: naming them lent invented meanings the same authority as real ones. A value
#: outside this table now decodes to ``unknown(<raw>)`` -- passed through and
#: visibly unnamed, which is what go-wsman-messages itself does (its decoder
#: returns "Value not found in map").
_LINK_POLICY_TABLE: dict[int, str] = {
    LINK_POLICY_S0_AC: "s0_ac",  # available on S0 AC -- powered on, mains
    LINK_POLICY_SX_AC: "sx_ac",  # available on Sx AC -- asleep/off, mains
    LINK_POLICY_S0_DC: "s0_dc",  # available on S0 DC -- powered on, battery
    LINK_POLICY_SX_DC: "sx_dc",  # available on Sx DC -- asleep/off, battery
}


def truthy(value: Any) -> bool:
    """Interpret a WS-Man boolean property, which arrives as element text (a string)."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("true", "1", "yes")


def optional_bool(value: Any) -> bool | None:
    """Like :func:`truthy`, but keeps "the firmware did not report this" distinct from ``False``.

    A property a firmware generation simply does not implement must not read as
    "the feature is switched off" -- an operator acting on that difference would
    be acting on an invention.
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return truthy(value)


def optional_int(value: Any) -> int | None:
    """Coerce WS-Man element text to ``int``, or ``None`` if it is absent/not a number."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def optional_str(value: Any) -> str | None:
    """Coerce WS-Man element text to a non-empty ``str``, or ``None``."""
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _decode(table: dict[int, str], value: int) -> str:
    """Name a DMTF enumeration value, keeping an unrecognised one visible as ``unknown(<raw>)``."""
    return table.get(value, f"unknown({value})")


def _normalize_mac(value: str) -> str:
    """Render a MAC address colon-separated and lowercase, whatever separator firmware used.

    Real AMT 10.0.56 returns ``MACAddress`` **dash**-separated and lowercase
    (observed on the hardware ``parmstro`` dumped; the value itself is that lab's
    and is deliberately not reproduced here), while ``parmstro``'s own documented
    RETURN sample claims colons. Both shapes are
    therefore in circulation for the same property, and a MAC is about to be
    used as an identity anchor and as a PXE reservation key -- comparisons that
    a stray separator silently breaks. So normalize on ingest and keep the raw
    reading alongside it.

    Anything that is not six hex octets (or twelve bare hex characters) is
    returned stripped but otherwise unchanged: an unexpected shape is better
    surfaced verbatim than mangled into a confident lie about an identity.
    Never raises.
    """
    text = value.strip()
    compact = text.replace("-", "").replace(":", "").replace(".", "")
    if len(compact) != 12:
        return text
    try:
        int(compact, 16)
    except ValueError:
        return text
    lowered = compact.lower()
    return ":".join(lowered[i : i + 2] for i in range(0, 12, 2))


def _link_policy_values(value: Any) -> list[int] | None:
    """Flatten ``AMT_EthernetPortSettings.LinkPolicy`` into a list of ints.

    The wire shape is not settled by the evidence available. AMT's schema types
    ``LinkPolicy`` as a ``uint32`` array, which WS-Man renders as a repeated
    plain element (``<LinkPolicy>16</LinkPolicy>`` x N, parsed here into a list
    of strings). ``parmstro``'s module code instead looks for ``<PolicyValue>``
    children inside a ``LinkPolicy`` wrapper, and their hardware notes only
    record the decoded result (``[1, 14, 16]``), never the XML -- so neither
    shape can be ruled out. Both are accepted rather than betting on one, since
    the cost of being wrong is a silently empty policy list and a
    ``wake_on_lan_capable`` that reads ``false`` on a machine that is in fact
    wakeable.

    Returns ``None`` when the property is absent entirely (unknown), and ``[]``
    when it is present but carries no values (genuinely no policies).
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return []

    candidates: list[Any] = value if isinstance(value, list) else [value]
    values: list[int] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            nested = candidate.get("PolicyValue")
            nested_list = nested if isinstance(nested, list) else [nested]
            values.extend(number for item in nested_list if (number := optional_int(item)) is not None)
            continue
        number = optional_int(candidate)
        if number is not None:
            values.append(number)
    return values


@dataclass(frozen=True, slots=True)
class PowerState:
    """A CIM power state, normalized to on/off/sleep/hibernate/unknown.

    ``raw`` is always kept, even for the ``unknown`` case: a value the table
    does not recognise is still useful diagnostic information, and discarding
    it would turn a forward-compatibility gap into a silent data loss.
    """

    normalized: str
    raw: int

    @classmethod
    def from_cim_value(cls, value: int | str) -> PowerState:
        try:
            raw = int(value)
        except (TypeError, ValueError):
            # A value AMT could not plausibly have sent (non-numeric). Still
            # surfaced as "unknown" rather than raising: facts-gathering
            # should degrade, not abort, on one unexpected field.
            return cls(normalized="unknown", raw=-1)
        return cls(normalized=_POWER_STATE_TABLE.get(raw, "unknown"), raw=raw)


@dataclass(frozen=True, slots=True)
class CallerSuppliedIdentity:
    """Identity the caller/inventory asserts about the endpoint -- not observed evidence.

    Kept as its own type, never a field on :class:`AmtFacts`, so a hostname
    or MAC pulled from inventory can never be confused for something the
    firmware itself reported. An identity-mismatch check (see
    ``errors.IdentityMismatchError``) exists precisely to compare one of
    these against the corresponding field in :class:`AmtFacts`; collapsing
    them into one object would remove the thing being compared.
    """

    hostname: str | None = None
    mac_address: str | None = None


@dataclass(frozen=True, slots=True)
class AmtCapabilities:
    """Firmware-discovered capability flags for ``amt_info``.

    Every field here is derived from an actual WS-Man response (mainly
    ``AMT_BootCapabilities``), never assumed from AMT generation or SKU. A
    firmware that omits the backing class entirely degrades every flag here
    to ``False`` rather than failing the whole facts read -- see
    :meth:`client.AmtClient.get_facts`.
    """

    power: bool = False
    boot_once_pxe: bool = False
    sol: bool = False
    storage_redirection: bool = False


@dataclass(frozen=True, slots=True)
class EthernetSettings:
    """``AMT_EthernetPortSettings`` instance 0, per docs/protocol-notes.md s2.7.

    Every field is optional: this whole class is read through the
    optional-degradation path, and a firmware generation that omits an
    individual property must yield ``None`` for it rather than a fabricated
    default.

    Two fields carry more meaning than their names suggest:

    * ``mac_address`` is normalized (colon-separated, lowercase) while
      ``mac_address_raw`` preserves exactly what firmware said. The MAC is a
      **second independent identity anchor** alongside the platform GUID, and
      it is what a PXE reservation is keyed on, so the normalized form exists
      to make comparisons work and the raw form exists so the evidence is not
      lost.
    * ``ip_sync_enabled`` is ``IpSyncEnabled``, which means *AMT shares the
      host OS's IP address*. It is **not** a ping-response toggle;
      ``AMT_GeneralSettings.PingResponseEnabled`` is that. ``parmstro``'s
      ``amt_network_settings`` conflates the two (it writes ``IpSyncEnabled``
      from a ``ping_response_enabled`` option), which is one of the reasons
      this collection derives protocol facts from their research notes rather
      than adopting their modules.
    * ``wake_on_lan_capable`` means precisely *``LinkPolicy`` includes an Sx
      value, so the network link is maintained while the host is not in S0*. The
      name is imperfect -- AMT's own wake plumbing (``IdleWakeTimeout``, the MEBx
      ``Intel ME ON in Host Sleep States`` setting) is adjacent but distinct, and
      this field reads only ``LinkPolicy``. It is kept anyway: it shipped in
      0.2.0 and 0.3.0, removing a return key is a breaking change, and one
      correct field under an approximate name beats two fields whose only
      difference a caller has to look up. The precise meaning is stated here, in
      ``docs/amt_info.md`` and in the module's RETURN block.
    """

    mac_address: str | None = None
    mac_address_raw: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    default_gateway: str | None = None
    primary_dns: str | None = None
    secondary_dns: str | None = None
    dhcp_enabled: bool | None = None
    link_is_up: bool | None = None
    ip_sync_enabled: bool | None = None
    link_policy: list[int] | None = None
    link_policy_names: list[str] | None = None
    wake_on_lan_capable: bool | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> EthernetSettings:
        """Build from a parsed ``Get AMT_EthernetPortSettings`` response instance."""
        raw_mac = optional_str(instance.get("MACAddress"))
        policies = _link_policy_values(instance.get("LinkPolicy"))
        return cls(
            mac_address=_normalize_mac(raw_mac) if raw_mac else None,
            mac_address_raw=raw_mac,
            ip_address=optional_str(instance.get("IPAddress")),
            subnet_mask=optional_str(instance.get("SubnetMask")),
            default_gateway=optional_str(instance.get("DefaultGateway")),
            primary_dns=optional_str(instance.get("PrimaryDNS")),
            secondary_dns=optional_str(instance.get("SecondaryDNS")),
            dhcp_enabled=optional_bool(instance.get("DHCPEnabled")),
            link_is_up=optional_bool(instance.get("LinkIsUp")),
            ip_sync_enabled=optional_bool(instance.get("IpSyncEnabled")),
            link_policy=policies,
            link_policy_names=[_decode(_LINK_POLICY_TABLE, value) for value in policies] if policies is not None else None,
            # True when *either* Sx value is present -- Sx AC (14) or Sx DC
            # (224). Both mean the link survives the host leaving S0; they
            # differ only in power source, and an endpoint that maintains the
            # link on battery but not mains (or vice versa) is still an endpoint
            # this field must report as reachable-while-off.
            #
            # None, not False, when the property is absent: "this firmware did
            # not tell us" and "this link will not stay up while powered off"
            # are different diagnoses, and only the second one explains why
            # `amt_power state=on` cannot reach the endpoint.
            wake_on_lan_capable=(any(value in _LINK_POLICY_SX_VALUES for value in policies)) if policies is not None else None,
        )


@dataclass(frozen=True, slots=True)
class SystemState:
    """``CIM_ComputerSystem`` (selector ``Name=ManagedSystem``) state, per docs/protocol-notes.md s2.7.

    ``operational_status`` is a **list**: CIM types
    ``CIM_ManagedSystemElement.OperationalStatus`` as ``uint16[]``, and firmware
    that reports a single value is just an array of length one. Collapsing it to
    a scalar would silently drop every status after the first, which is exactly
    the set that says *why* a system is degraded.

    Raw values are kept alongside every decoded name, on the same reasoning as
    :class:`PowerState`: a value outside the DMTF table this collection knows is
    still evidence and must not be discarded.
    """

    element_name: str | None = None
    enabled_state: int | None = None
    enabled_state_text: str | None = None
    requested_state: int | None = None
    operational_status: list[int] | None = None
    operational_status_text: list[str] | None = None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> SystemState:
        """Build from a parsed ``Get CIM_ComputerSystem`` response instance."""
        enabled_state = optional_int(instance.get("EnabledState"))
        raw_status = instance.get("OperationalStatus")
        statuses: list[int] | None = None
        if raw_status is not None:
            candidates = raw_status if isinstance(raw_status, list) else [raw_status]
            statuses = [number for item in candidates if (number := optional_int(item)) is not None]
        return cls(
            # ElementName, not Name. Name is the WS-Man selector key
            # ("ManagedSystem") and carries no information a caller did not
            # already supply in order to address the instance.
            element_name=optional_str(instance.get("ElementName")),
            enabled_state=enabled_state,
            # A value outside the DMTF table renders as unknown(<raw>) rather
            # than a bare "unknown", which the table already uses for the
            # defined value 0. The two are different findings and must not
            # render identically.
            enabled_state_text=_decode(_ENABLED_STATE_TABLE, enabled_state) if enabled_state is not None else None,
            requested_state=optional_int(instance.get("RequestedState")),
            operational_status=statuses,
            operational_status_text=[_decode(_OPERATIONAL_STATUS_TABLE, value) for value in statuses] if statuses is not None else None,
        )


@dataclass(frozen=True, slots=True)
class AmtFacts:
    """Firmware-observed evidence only. Every field here came from a WS-Man response.

    Do not add a field for *caller-supplied* data (hostname, MAC, inventory
    labels, ...) to this class -- see :class:`CallerSuppliedIdentity`.
    ``reported_hostname`` is deliberately named to avoid that trap while still
    surfacing it: it is what ``AMT_GeneralSettings`` itself reports, i.e.
    firmware-observed evidence, not an inventory claim, so it belongs here.
    """

    version: str | None = None
    uuid: str | None = None
    control_mode: str | None = None
    provisioning_state: str | None = None
    power_state: PowerState | None = None
    reported_hostname: str | None = None
    capabilities: AmtCapabilities = field(default_factory=AmtCapabilities)
    redirection: RedirectionState | None = None
    #: The rest of the AMT_GeneralSettings instance already read for
    #: reported_hostname -- surfaced at no extra WS-Man round trip.
    reported_domain_name: str | None = None
    idle_wake_timeout: int | None = None
    ping_response_enabled: bool | None = None
    rmcp_ping_response_enabled: bool | None = None
    network_interface_enabled: bool | None = None
    ddns_update_enabled: bool | None = None
    #: AMT_EthernetPortSettings instance 0 (see EthernetSettings).
    network: EthernetSettings | None = None
    #: CIM_ComputerSystem enabled/requested/operational state (see SystemState).
    system_state: SystemState | None = None
    #: CIM_BIOSElement.Version -- host BIOS, not AMT firmware. `version` is the
    #: AMT one; these two are routinely confused, so they are named apart.
    bios_version: str | None = None


@dataclass(frozen=True, slots=True)
class BootConfiguration:
    """``AMT_BootSettingData`` fields set by the boot-configuration sequence.

    Field set and defaults match docs/protocol-notes.md s2.5 step 3 exactly.
    ``secure_erase``/``platform_erase`` are ``None`` when the field is absent
    from the read instance -- newer firmware may not expose them at all, and
    the boot-configuration Put logic treats "absent" and "present but False"
    differently (only the latter is included in the mutated Put body).
    """

    configuration_data_reset: bool = False
    bios_pause: bool = False
    enforce_secure_boot: bool = False
    bios_setup: bool = False
    boot_media_index: int = 0
    firmware_verbosity: int = 0
    forced_progress_events: bool = False
    ider_boot_device: int = 0
    lock_keyboard: bool = False
    lock_power_button: bool = False
    lock_reset_button: bool = False
    lock_sleep_button: bool = False
    reflash_bios: bool = False
    use_ider: bool = False
    use_sol: bool = False
    use_safe_mode: bool = False
    user_password_bypass: bool = False
    secure_erase: bool | None = None
    platform_erase: bool | None = None


@dataclass(frozen=True, slots=True)
class RedirectionState:
    """``AMT_RedirectionService`` state, per docs/protocol-notes.md s2.6.

    ``enabled_state`` is kept as the raw CIM value alongside the two derived
    booleans, so a value this collection does not yet special-case is still
    visible rather than collapsed to "both false".
    """

    enabled_state: int
    listener_enabled: bool
    ider_enabled: bool
    sol_enabled: bool

    @classmethod
    def from_enabled_state(cls, enabled_state: int | str, listener_enabled: bool) -> RedirectionState:
        try:
            state = int(enabled_state)
        except (TypeError, ValueError):
            state = -1
        return cls(
            enabled_state=state,
            listener_enabled=listener_enabled,
            ider_enabled=state in (32769, 32771),
            sol_enabled=state in (32770, 32771),
        )


#: The receipt schema identifier. Part of the public contract: callers key
#: off this string to know how to interpret the rest of the document.
RECEIPT_SCHEMA = "intel-amt-operation/v1"


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    """The ``intel-amt-operation/v1`` receipt returned by every mutating module.

    ``previous``/``desired``/``observed`` accept any of the typed dataclasses
    above, plain dicts, or ``None`` -- :meth:`to_dict` normalizes whichever
    was given into plain JSON-safe structures.
    """

    action: str
    endpoint: str
    changed: bool
    previous: Any = None
    desired: Any = None
    observed: Any = None
    tls_peer_fingerprint: str | None = None
    error_class: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Render to exactly the ``intel-amt-operation/v1`` schema.

        Every string value is passed through :func:`errors.redact` as a
        last-resort backstop -- the structural guarantee is that none of
        these dataclasses have a credential-shaped field, but this catches
        the case where a caller passes through data it should not have.
        """
        document: dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "action": self.action,
            "endpoint": self.endpoint,
            "changed": self.changed,
            "previous": _to_serializable(self.previous),
            "desired": _to_serializable(self.desired),
            "observed": _to_serializable(self.observed),
            "tls_peer_fingerprint": self.tls_peer_fingerprint,
            "error_class": self.error_class,
        }
        if self.extra:
            document.update({k: _to_serializable(v) for k, v in self.extra.items()})
        return _redact_strings(document)


def _to_serializable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _redact_strings(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_strings(item) for item in value]
    return value
