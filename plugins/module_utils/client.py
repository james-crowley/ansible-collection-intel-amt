# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""The typed AMT management API that ``amt_info`` and ``amt_power`` adapt to.

:class:`AmtClient` is the seam between "Ansible module shaped" requests
(gather facts, read power state, request a power transition) and the raw
WS-Man operations in :mod:`wsman`. It is intentionally scoped to facts and
power only -- boot configuration and redirection-service mutation are owned
by sibling client methods added alongside ``amt_boot``/``amt_redirection``,
not by this module.

Two design rules carried over from :mod:`models` and :mod:`wsman`:

1. **Facts-gathering degrades, it does not abort.** Real AMT firmware varies
   in which optional WS-Man classes it implements. A ``Get`` against a class
   the firmware does not support comes back as a SOAP Fault (``ProtocolError``)
   or an explicit ``UnsupportedCapabilityError``; either is treated as "this
   capability is unknown/False", not as a reason to fail the whole read.
2. **A mutation is requested, never confirmed, by ``ReturnValue == 0``.**
   :meth:`AmtClient.request_power_state` polls afterwards and reports what it
   actually observed. A timeout raised *after* the request was transmitted
   (``TimeoutError_`` with ``indeterminate=True``) is allowed to propagate
   unmodified -- it must reach the caller so they re-probe rather than retry.
"""

from __future__ import annotations

import dataclasses
import time
from enum import Enum
from typing import TYPE_CHECKING, Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    ProtocolError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.hardware import (
    FACT_GROUP_BY_CLASS,
    MINIMAL_SUBSET,
    READ_OUTCOME_ABSENT,
    READ_OUTCOME_EMPTY,
    READ_OUTCOME_READ,
    SUBSET_MEMORY,
    SUBSET_PROCESSOR,
    SUBSET_STORAGE,
    SUBSET_SYSTEM,
    BaseboardInfo,
    ChassisInfo,
    ChipInfo,
    ClassRead,
    HardwareFacts,
    MemoryInfo,
    ProcessorInfo,
    StorageInfo,
    property_shapes,
    requested_fact_groups,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    AmtCapabilities,
    AmtFacts,
    EthernetSettings,
    OperationReceipt,
    PowerState,
    RedirectionState,
    SystemState,
    optional_bool,
    optional_int,
    optional_str,
    truthy,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.network import (
    ETHERNET_PORT_0_SELECTOR,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    EndpointReference,
    WsmanClient,
)

if TYPE_CHECKING:
    from collections.abc import Callable

#: Errors that mean "this optional class/property is not implemented by this
#: firmware" rather than "the operation failed". Only these are swallowed
#: while gathering facts; connection/auth/timeout/TLS failures are real
#: failures and must propagate.
_DEGRADABLE_ERRORS: tuple[type[AmtError], ...] = (ProtocolError, UnsupportedCapabilityError)

#: The ``CIM_ComputerSystem`` selector RequestPowerStateChange's
#: ``ManagedElement`` must name, per docs/protocol-notes.md s2.4. The same
#: selector addresses the instance for the state read in :meth:`get_facts`.
_MANAGED_SYSTEM_SELECTOR = {"Name": "ManagedSystem"}

#: ``AMT_EthernetPortSettings`` instance 0 -- the wired port AMT itself uses.
#: Instance 0 only: multi-NIC parts expose higher indices, this collection does
#: not assume they exist, and a missing instance degrades rather than failing.
#: A ``Get`` with this exact selector is mandatory -- ``Enumerate`` on
#: ``AMT_``-prefixed classes is HTTP 400 on AMT 10 (docs/protocol-notes.md s2.7).
#:
#: Imported from :mod:`network` rather than declared here, so the read path and
#: the write path address the same instance by construction. It was a private
#: copy in this file until ``amt_network`` needed the same string: two copies of
#: a selector can drift, and this collection already has a
#: table-in-two-places incident on this exact class (``docs/capability-matrix.md``,
#: ``LinkPolicy``).
_ETHERNET_PORT_0_SELECTOR = ETHERNET_PORT_0_SELECTOR


class PowerAction(str, Enum):
    """A requestable AMT power transition.

    Values match the ``state`` argument ``amt_power`` documents. ``RESET``
    and ``REBOOT`` are distinct members but issue the identical underlying
    AMT action (master bus reset, code 10) -- AMT has no separate "graceful
    reboot" primitive, so both are offered as friendlier/more technical names
    for the same request.
    """

    ON = "on"
    OFF = "off"
    CYCLE = "cycle"
    RESET = "reset"
    REBOOT = "reboot"
    SLEEP_LIGHT = "sleep-light"
    SLEEP_DEEP = "sleep-deep"
    HIBERNATE = "hibernate"

    def __str__(self) -> str:
        """Return the bare value, e.g. ``"on"`` rather than ``"PowerAction.ON"``.

        This restores the behaviour of :class:`enum.StrEnum`, which this class
        replaced in order to support Python 3.10 (StrEnum is 3.11+, and
        ansible-core 2.17 -- this collection's floor -- runs on 3.10).

        Without this, a plain ``(str, Enum)`` renders as ``PowerAction.ON`` under
        ``str()`` and f-string interpolation, so any message or receipt field
        built that way would silently change shape. Keeping the shim
        behaviourally identical is the whole point of it being a shim.
        """
        return self.value


#: docs/protocol-notes.md s2.4 -- CIM_PowerManagementService.RequestPowerStateChange
#: action codes, as used by MeshCmd and verified against firmware.
_POWER_ACTION_CODES: dict[PowerAction, int] = {
    PowerAction.ON: 2,
    PowerAction.SLEEP_LIGHT: 3,
    PowerAction.SLEEP_DEEP: 4,
    PowerAction.CYCLE: 5,
    PowerAction.HIBERNATE: 7,
    PowerAction.OFF: 8,
    PowerAction.RESET: 10,
    PowerAction.REBOOT: 10,
}

#: The normalized :class:`PowerState` a successful request is expected to
#: converge on. Action codes are *requests*, not CIM power-state values, so
#: this is a separate table rather than a reuse of ``PowerState``'s.
_ACTION_EXPECTED_STATE: dict[PowerAction, str] = {
    PowerAction.ON: "on",
    PowerAction.SLEEP_LIGHT: "sleep",
    PowerAction.SLEEP_DEEP: "sleep",
    PowerAction.CYCLE: "on",
    PowerAction.HIBERNATE: "hibernate",
    PowerAction.OFF: "off",
    PowerAction.RESET: "on",
    PowerAction.REBOOT: "on",
}


def _canonical_uuid(value: str) -> str:
    """Render a platform GUID in the canonical dashed form an operator sees.

    ``CIM_ComputerSystemPackage.PlatformGUID`` comes back as 32 undashed hex
    characters, and the SMBIOS Type 1 UUID stores its **first three fields
    little-endian**. Both facts matter, because the whole purpose of this value is
    to be compared against the UUID a human reads in MEBx or BIOS.

    Getting the byte order wrong is not a cosmetic problem: it produces something
    that still looks like a UUID, so the identity cross-check would fail against a
    correctly-recorded expectation and be quietly useless. On real AMT 16.1.30
    firmware the two readings are::

        naive big-endian     DDCCBBAA-FFEE-F011-8899-001122334455   version F
        SMBIOS little-endian AABBCCDD-EEFF-11F0-8899-001122334455   version 1

    A valid UUID version is 1-8, so the naive reading is demonstrably wrong while
    remaining plausible. The unit tests assert the version nibble for exactly this
    reason -- it is the cheap invariant that distinguishes the two.

    Anything that is not 32 bare hex characters is returned unchanged: firmware
    that already reports a dashed UUID must not be converted twice, and an
    unexpected shape is better surfaced verbatim than mangled into a confident
    lie. Never raises -- this is a fact, and facts degrade rather than failing the
    whole read.
    """
    compact = value.replace("-", "")
    if len(compact) != 32:
        return value
    try:
        raw = bytes.fromhex(compact)
    except ValueError:
        return value
    if "-" in value:
        # Already canonical (or at least already dashed): assume the firmware did
        # the field ordering and leave it alone.
        return value.upper()
    return (f"{raw[0:4][::-1].hex()}-{raw[4:6][::-1].hex()}-{raw[6:8][::-1].hex()}-{raw[8:10].hex()}-{raw[10:16].hex()}").upper()


class AmtClient:
    """Facts and power control for one Intel AMT endpoint.

    Wraps an already-constructed :class:`WsmanClient` -- callers (modules)
    own connection setup via ``WsmanClient.from_connection_options()``; this
    class owns only the mapping from AMT's CIM/AMT classes to typed results.
    Accepting the transport as a constructor argument, rather than building
    one internally, is what lets unit tests exercise this class without ever
    touching a socket.
    """

    def __init__(
        self,
        wsman: WsmanClient,
        *,
        poll_count: int = 5,
        poll_delay: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._wsman = wsman
        #: Bounded postcondition-probe parameters for request_power_state.
        #: Injectable so tests can set poll_count=0 or a no-op `sleep` and
        #: never actually wait -- see docs/protocol-notes.md s2.4: ReturnValue
        #: == 0 means accepted, not complete, so a caller must poll to see
        #: what actually happened, but that polling must stay bounded.
        self._poll_count = poll_count
        self._poll_delay = poll_delay
        self._sleep = sleep

    # -- Facts ----------------------------------------------------------------

    def get_facts(self, subsets: frozenset[str] | None = None) -> AmtFacts:
        """Gather firmware-observed facts and capabilities.

        ``subsets`` is a **resolved** subset set from
        ``hardware.resolve_gather_subset()``. It defaults to
        ``hardware.MINIMAL_SUBSET`` -- i.e. exactly the pre-0.5.0 fact set and
        exactly the pre-0.5.0 round-trip count -- so an existing caller that has
        never heard of ``gather_subset`` pays nothing for the inventory feature.
        ``config`` is un-excludable by construction (see ``MINIMAL_SUBSET``), so
        everything below the hardware section always runs.

        Each source class is read independently and tolerated if absent, per
        the module docstring: a firmware that does not implement e.g.
        ``AMT_BootCapabilities`` yields ``capabilities`` with every flag
        ``False`` rather than failing the whole read. A genuine transport
        failure (connection/auth/TLS/timeout) is not tolerated here and
        propagates to the caller unchanged. That rule extends unchanged to the
        hardware classes: each of the six degrades to ``None`` on its own,
        independently, so a firmware missing ``CIM_MediaAccessDevice`` still
        reports its DIMMs.

        **Round-trip cost.** Eight WS-Man operations, ten HTTP requests
        (``Enumerate CIM_SoftwareIdentity`` costs an Enumerate plus one Pull):

        ===================================================  =====  =========
        Operation                                            Verb   Since
        ===================================================  =====  =========
        ``AMT_GeneralSettings``                              Get    0.1.0
        ``AMT_SetupAndConfigurationService``                 Get    0.1.0
        ``CIM_AssociatedPowerManagementService``             Get    0.1.0
        ``AMT_BootCapabilities``                             Get    0.1.0
        ``AMT_RedirectionService``                           Get    0.1.0
        ``CIM_SoftwareIdentity``                             Enum   0.1.0
        ``CIM_ComputerSystemPackage``                        Get    0.1.0
        ``AMT_EthernetPortSettings`` (instance 0)            Get    **new**
        ``CIM_ComputerSystem`` (``Name=ManagedSystem``)      Get    **new**
        ``CIM_BIOSElement``                                  Get    **new**
        ===================================================  =====  =========

        Those ten are the ``config`` subset and are **always** performed. Each
        hardware subset adds its own, and only when asked for:

        =================  ===========================================  =====  =====
        Subset             Classes                                      Verb   Cost
        =================  ===========================================  =====  =====
        ``system``         ``CIM_Chassis``, ``CIM_Card``                 Get    2
        ``processor``      ``CIM_Processor``, ``CIM_Chip``               Enum   4
        ``memory``         ``CIM_PhysicalMemory``                        Enum   2
        ``storage``        ``CIM_MediaAccessDevice``                     Enum   2
        =================  ===========================================  =====  =====

        So ``gather_subset: ['all']`` costs **20** requests against the default's
        10. ``system``'s two ``Get``s fall back to ``Enumerate`` when they fault,
        so that subset can reach 6 on firmware that refuses ``Get`` for both.

        The ``CIM_ComputerSystem`` read is deliberately *reintroduced*: it was
        removed in 0.1.0 because it existed only to source a ``UUID`` property
        that class does not have. It is back to source ``EnabledState`` /
        ``RequestedState`` / ``OperationalStatus`` / ``ElementName``, which it
        does have. The UUID still comes from
        ``CIM_ComputerSystemPackage.PlatformGUID`` and must not be read here.
        """
        general = self._get_optional("AMT_GeneralSettings")
        setup = self._get_optional("AMT_SetupAndConfigurationService")
        power_assoc = self._get_optional("CIM_AssociatedPowerManagementService")
        boot_caps = self._get_optional("AMT_BootCapabilities")
        redirection = self._get_optional("AMT_RedirectionService")

        power_state = None
        if power_assoc and power_assoc.get("PowerState") is not None:
            power_state = PowerState.from_cim_value(power_assoc["PowerState"])

        capabilities = AmtCapabilities(
            power=power_state is not None,
            boot_once_pxe=truthy(boot_caps.get("ForcePXEBoot")) if boot_caps else False,
            sol=truthy(boot_caps.get("SOL")) if boot_caps else False,
            storage_redirection=truthy(boot_caps.get("IDER")) if boot_caps else False,
        )

        redirection_state = None
        if redirection is not None:
            redirection_state = RedirectionState.from_enabled_state(
                redirection.get("EnabledState", -1),
                listener_enabled=truthy(redirection.get("ListenerEnabled")),
            )

        version = self._get_amt_version()
        general_settings = general or {}

        return AmtFacts(
            version=version,
            uuid=self._get_system_uuid(),
            control_mode=(setup or {}).get("ProvisioningMode"),
            provisioning_state=(setup or {}).get("ProvisioningState"),
            power_state=power_state,
            reported_hostname=general_settings.get("HostName"),
            capabilities=capabilities,
            redirection=redirection_state,
            reported_domain_name=optional_str(general_settings.get("DomainName")),
            idle_wake_timeout=optional_int(general_settings.get("IdleWakeTimeout")),
            ping_response_enabled=optional_bool(general_settings.get("PingResponseEnabled")),
            rmcp_ping_response_enabled=optional_bool(general_settings.get("RmcpPingResponseEnabled")),
            network_interface_enabled=optional_bool(general_settings.get("NetworkInterfaceEnabled")),
            ddns_update_enabled=optional_bool(general_settings.get("DDNSUpdateEnabled")),
            network=self._get_ethernet_settings(),
            system_state=self._get_system_state(),
            bios_version=self._get_bios_version(),
            hardware=self._get_hardware_facts(subsets if subsets is not None else MINIMAL_SUBSET),
        )

    # -- Hardware / asset inventory ---------------------------------------------

    def _get_hardware_facts(self, subsets: frozenset[str]) -> HardwareFacts | None:
        """Read the requested inventory classes, degrading each one independently.

        Returns ``None`` when no hardware subset was requested at all, which is
        the default: no request is issued, and ``amt.hardware`` is ``null``. That
        is a third state distinct from both "requested and absent" and "requested
        and empty", and :class:`hardware.HardwareFacts` documents all three.

        ``CIM_`` classes only, so ``docs/protocol-notes.md`` s2.7's
        ``Enumerate``-is-HTTP-400 finding does not apply -- that section states
        outright that it does not affect ``CIM_``-prefixed classes, and the vendor
        fixture set ships ``enumerate.xml`` + ``pull.xml`` for every multi-instance
        class read here. So ``Enumerate`` is the right verb for the multi-instance
        ones and needs no ``Get`` fallback.

        **Every read also records a** :class:`hardware.ClassRead` **in**
        :attr:`last_hardware_reads`. The fact values are unchanged by this -- a
        class that cannot be read still degrades to ``None``. What changes is that
        the *reason* is no longer invisible. Before this existed, a ``null`` fact
        group was indistinguishable between "this firmware has no such class", "we
        asked with the wrong verb or selector" and "it answered and the reader did
        not recognise the shape" -- and the first hardware run against real
        firmware needed precisely that distinction. It reported four of the six
        groups as ``null`` when firmware had in fact returned all six, and nothing
        in the module's output could contradict the claim.

        The two single-instance classes additionally carry a per-property **shape
        census** (``ClassRead.property_shapes``). ``ClassRead`` alone diagnoses a
        whole class; it says nothing about one ``null`` *field* on a class that
        answered perfectly well, which is what issue #84 is. See
        ``hardware.property_shapes()``.
        """
        reads: dict[str, ClassRead] = {}
        groups = requested_fact_groups(subsets)
        if not groups:
            return None

        chassis = baseboard = None
        processors = chips = memory = storage = None

        if SUBSET_SYSTEM in subsets:
            # Get with an Enumerate fallback, following CIM_BIOSElement's
            # precedent in this file: neither class has a singleton selector, and
            # the vendor fixture set evidences *both* verbs for both classes
            # (chassis/{get,enumerate,pull}.xml, card/{get,enumerate,pull}.xml).
            # MeshCentral fetches both with Get -- its BatchEnum '*' prefix means
            # "Get instead of Enumerate, to reduce round trips" -- so Get is the
            # cheap path and Enumerate the insurance. Both reference
            # implementations send a bare Get with NO SelectorSet, which is worth
            # recording because "wrong selector" was a live hypothesis for the
            # first hardware run's apparent nulls: go-wsman-messages' shared
            # base.WSManService.Get() calls getBySelector(nil) and emits no
            # <w:SelectorSet> element at all (v2.48.3, internal/message/base.go),
            # and MeshCentral's obj.Get/ExecGet have no selectors parameter to
            # pass one with. Real firmware settles it -- AMT 16.1.30 and 19.0.5
            # both answer this bare Get with a populated instance.
            chassis_instance, reads["CIM_Chassis"] = self._read_single("CIM_Chassis")
            chassis = ChassisInfo.from_instance(chassis_instance) if chassis_instance else None
            card_instance, reads["CIM_Card"] = self._read_single("CIM_Card")
            baseboard = BaseboardInfo.from_instance(card_instance) if card_instance else None

        if SUBSET_PROCESSOR in subsets:
            processors, reads["CIM_Processor"] = self._read_many(ProcessorInfo, "CIM_Processor")
            chips, reads["CIM_Chip"] = self._read_many(ChipInfo, "CIM_Chip")

        if SUBSET_MEMORY in subsets:
            memory, reads["CIM_PhysicalMemory"] = self._read_many(MemoryInfo, "CIM_PhysicalMemory")

        if SUBSET_STORAGE in subsets:
            storage, reads["CIM_MediaAccessDevice"] = self._read_many(StorageInfo, "CIM_MediaAccessDevice")

        # The reads travel with the facts they describe rather than being cached
        # on the client. A client attribute would be a second source of truth for
        # the same thing, and a receipt built from it could outlive the facts it
        # claims to describe.
        return HardwareFacts(
            chassis=chassis,
            baseboard=baseboard,
            processors=processors,
            chips=chips,
            memory=memory,
            storage=storage,
            requested=groups,
            reads=reads,
        )

    def _read_single(self, resource_class: str) -> tuple[dict[str, Any] | None, ClassRead]:
        """``Get`` one instance, falling back to the first ``Enumerate`` result.

        Generalises what :meth:`_get_bios_version` does inline. Returns ``None``
        when neither verb yields an instance -- a firmware that does not
        implement the class degrades one fact group rather than failing the read
        -- paired with the :class:`hardware.ClassRead` recording which of the
        three outcomes that was and how.

        ``verb`` on the returned record names the verb that actually produced the
        reported result, so a value of ``"Enumerate"`` is also the signal that the
        bare ``Get`` was refused and this subset cost two round trips more than
        ``hardware.round_trip_estimate()`` predicted.

        A successful read also carries a per-property **shape census** of the
        instance (``hardware.property_shapes()``). It is taken here, from the
        parsed instance, because here is the last point at which it can be: the
        very next thing that happens to this dict is a ``from_instance``, whose
        ``optional_str`` calls collapse "element absent", "element present and
        empty", "element carried children" and "element repeated" onto one
        indistinguishable ``None``. Issue #84 turns on precisely that distinction
        for ``CIM_Card.SerialNumber``, and no amount of reading the module's output
        afterwards can recover it.
        """
        fact_group = FACT_GROUP_BY_CLASS[resource_class]
        instance, _get_error_class = self._get_with_error_class(resource_class)
        if instance:
            shapes, dropped = property_shapes(resource_class, instance)
            return instance, ClassRead(
                fact_group=fact_group,
                outcome=READ_OUTCOME_READ,
                verb="Get",
                instances=1,
                property_shapes=shapes,
                property_names_dropped=dropped,
            )

        instances, enumerate_error_class = self._enumerate_with_error_class(resource_class)
        if enumerate_error_class is not None:
            # Both verbs were refused. The Enumerate's error class is the one
            # reported: Enumerate is the fallback, so its refusal is what actually
            # settled the outcome. No census: there is no instance to census, which
            # is a different reading from a census of all-absent properties.
            return None, ClassRead(fact_group=fact_group, outcome=READ_OUTCOME_ABSENT, verb="Enumerate", error_class=enumerate_error_class)

        candidates = [item for item in instances or () if isinstance(item, dict) and item]
        if candidates:
            # Censuses the instance actually reported, which is candidates[0] -- the
            # same one BaseboardInfo/ChassisInfo will be built from. A census of a
            # different instance than the facts came from would be worse than none.
            shapes, dropped = property_shapes(resource_class, candidates[0])
            return candidates[0], ClassRead(
                fact_group=fact_group,
                outcome=READ_OUTCOME_READ,
                verb="Enumerate",
                instances=len(candidates),
                property_shapes=shapes,
                property_names_dropped=dropped,
            )
        return None, ClassRead(fact_group=fact_group, outcome=READ_OUTCOME_EMPTY, verb="Enumerate", instances=0)

    def _read_many(self, factory: Any, resource_class: str) -> tuple[list[Any] | None, ClassRead]:
        """``Enumerate`` a multi-instance class into a list of typed records.

        Three outcomes, all of which a caller acts on differently, and each of
        which the returned :class:`hardware.ClassRead` names explicitly rather
        than leaving to be inferred from the fact value:

        * ``None`` / ``absent`` -- the class faulted or is not implemented here.
        * ``[]`` / ``empty`` -- the class answered with **zero** instances. A real
          answer: a machine can genuinely have no ``CIM_MediaAccessDevice``.
          Collapsing this to ``None`` would report a diskless machine as a
          firmware gap.
        * a populated list / ``read`` -- one record per instance, in the order
          firmware returned them. Order is preserved rather than sorted:
          firmware's order is the only ordering that carries any meaning (DIMM
          slot sequence), and re-sorting would invent a bookkeeping it does not
          promise.
        """
        fact_group = FACT_GROUP_BY_CLASS[resource_class]
        instances, error_class = self._enumerate_with_error_class(resource_class)
        if error_class is not None:
            return None, ClassRead(fact_group=fact_group, outcome=READ_OUTCOME_ABSENT, verb="Enumerate", error_class=error_class)

        records = [factory.from_instance(instance) for instance in instances or () if isinstance(instance, dict)]
        return records, ClassRead(
            fact_group=fact_group,
            outcome=READ_OUTCOME_READ if records else READ_OUTCOME_EMPTY,
            verb="Enumerate",
            instances=len(records),
        )

    def _get_with_error_class(self, resource_class: str, *, selectors: dict[str, str] | None = None) -> tuple[dict[str, Any] | None, str | None]:
        """``Get``, returning ``(instance, error_class)`` rather than discarding the reason.

        :meth:`_get_optional` throws away *which* degradable error occurred, which
        is fine for a capability flag but is the entire diagnostic when the
        question is why an inventory group came back ``null``. Identical
        tolerance and identical caught exceptions -- only the reason survives.
        """
        try:
            return self._wsman.get(resource_class, selectors=selectors), None
        except _DEGRADABLE_ERRORS as err:
            return None, err.error_class

    def _enumerate_with_error_class(self, resource_class: str) -> tuple[list[dict[str, Any]] | None, str | None]:
        """``Enumerate``, returning ``(instances, error_class)``.

        ``error_class`` is ``None`` on success **including when firmware returns
        zero instances**: an empty enumeration is an answer, not a refusal, and
        the two must not collapse into each other here -- that distinction is the
        whole reason ``[]`` and ``None`` are different fact values.
        """
        try:
            return self._wsman.enumerate(resource_class), None
        except _DEGRADABLE_ERRORS as err:
            return None, err.error_class

    def _get_optional(self, resource_class: str, *, selectors: dict[str, str] | None = None) -> dict[str, Any] | None:
        """``Get`` a class that a firmware may legitimately not implement.

        Returns ``None`` on the degradable errors (protocol/unsupported --
        i.e. "this class does not exist here"), letting the caller degrade
        the derived capability rather than aborting. Anything else (a real
        connection/auth/TLS/timeout failure) is not this method's to hide and
        is left to propagate.

        ``selectors`` addresses one specific instance. It is not optional
        stylistic detail for ``AMT_``-prefixed classes: on AMT 10,
        ``Enumerate`` returns HTTP 400 for ``AMT_EthernetPortSettings``,
        ``AMT_GeneralSettings``, ``AMT_BootCapabilities``,
        ``AMT_BootSettingData`` and ``AMT_TLSSettingData``, while a ``Get``
        with an exact selector works -- see docs/protocol-notes.md s2.7.
        """
        try:
            return self._wsman.get(resource_class, selectors=selectors)
        except _DEGRADABLE_ERRORS:
            return None

    def _get_ethernet_settings(self) -> EthernetSettings | None:
        """Read ``AMT_EthernetPortSettings`` instance 0: MAC, IPv4, DHCP, link state, link policy.

        Instance 0 is the wired port AMT itself answers on. Higher indices exist
        on multi-NIC parts; this deliberately does not look for them, and an
        endpoint that has no instance 0 (or no such class) yields ``None``
        rather than failing the read.

        Read with an explicit ``Get`` selector, never ``Enumerate`` -- see
        :meth:`_get_optional`.
        """
        instance = self._get_optional("AMT_EthernetPortSettings", selectors=_ETHERNET_PORT_0_SELECTOR)
        if not instance:
            return None
        return EthernetSettings.from_instance(instance)

    def _get_system_state(self) -> SystemState | None:
        """Read ``CIM_ComputerSystem``'s enabled/requested/operational state.

        This class was **removed** from facts gathering in 0.1.0 and is
        reintroduced here on purpose, so the reasoning is worth stating rather
        than leaving to archaeology. It was removed because it was only ever
        read to source a ``UUID`` property that ``CIM_ComputerSystem`` does not
        define, making it a wasted round trip that returned nothing usable. It
        is back because ``EnabledState``, ``RequestedState``,
        ``OperationalStatus`` and ``ElementName`` *are* defined on it and are
        genuinely useful state. The UUID still comes from
        ``CIM_ComputerSystemPackage.PlatformGUID`` (see
        :meth:`_get_system_uuid`) -- do not reintroduce that defect alongside
        the round trip.
        """
        instance = self._get_optional("CIM_ComputerSystem", selectors=_MANAGED_SYSTEM_SELECTOR)
        if not instance:
            return None
        return SystemState.from_instance(instance)

    def _get_bios_version(self) -> str | None:
        """Read the host BIOS version from ``CIM_BIOSElement.Version``.

        This is the **weakest-evidenced** of the facts gathered here.
        ``parmstro``'s notes claim the class works on AMT 10.0.56 but never
        record a dumped value, and their implementation swallows any failure to
        ``None``, so their "it works" proves nothing either way. It is therefore
        read strictly through the optional-degradation path: a fault yields
        ``None`` and the module still succeeds.

        ``CIM_BIOSElement`` has no obvious singleton selector, so a bare ``Get``
        is tried first and ``Enumerate`` is used as a fallback -- a class with no
        selector may require enumeration, and AMT's WS-Man implementation is
        selective about which verb it accepts per class (docs/protocol-notes.md
        s2.7). Note this is the *host BIOS* version, not the AMT firmware
        version, which comes from ``CIM_SoftwareIdentity``.
        """
        instance = self._get_optional("CIM_BIOSElement")
        version = optional_str((instance or {}).get("Version"))
        if version is not None:
            return version

        try:
            instances = self._wsman.enumerate("CIM_BIOSElement")
        except _DEGRADABLE_ERRORS:
            return None
        for candidate in instances or ():
            if not isinstance(candidate, dict):
                continue
            version = optional_str(candidate.get("Version"))
            if version is not None:
                return version
        return None

    def _get_amt_version(self) -> str | None:
        """Read the AMT firmware version from ``CIM_SoftwareIdentity``.

        Neither ``AMT_GeneralSettings`` nor ``AMT_SetupAndConfigurationService``
        carries a version property at all -- verified against the class
        definitions in ``device-management-toolkit/go-wsman-messages``.
        ``AMT_GeneralSettings`` exposes ``HostName``, ``DomainName``,
        ``DigestRealm`` and similar; ``AMT_SetupAndConfigurationService``
        exposes ``ProvisioningMode`` and ``ProvisioningState``. An earlier
        implementation read ``Version`` and ``VersionsSupported`` from those two
        classes, so the reported version was always ``None``.

        The firmware version lives in ``CIM_SoftwareIdentity``, which enumerates
        several components. The AMT one is the instance whose ``InstanceID`` is
        ``AMT``, and its version is in ``VersionString``. This is how MeshCmd
        does it (``agents/meshcmd.js``, which selects the ``AMT`` instance and
        reads ``VersionString``).
        """
        try:
            instances = self._wsman.enumerate("CIM_SoftwareIdentity")
        except _DEGRADABLE_ERRORS:
            return None

        for instance in instances or ():
            if not isinstance(instance, dict):
                continue
            # Match exactly rather than by substring: the enumeration also
            # carries entries such as "AMTApps" and "BIOS", and a substring
            # match would report whichever happened to come back first.
            if str(instance.get("InstanceID", "")).strip() == "AMT":
                version = instance.get("VersionString")
                return str(version) if version is not None else None
        return None

    def _get_system_uuid(self) -> str | None:
        """Read the platform's system UUID, for binding an endpoint to an identity.

        Read from ``CIM_ComputerSystemPackage.PlatformGUID``. An earlier
        implementation read ``UUID`` from ``CIM_ComputerSystem``, which has no such
        property -- verified against the class definitions in
        ``device-management-toolkit/go-wsman-messages`` -- so it returned ``None``
        on every endpoint. That was not a firmware quirk; it silently disabled the
        identity cross-check that exists to stop a reset landing on the wrong
        machine.

        ``AMT_SetupAndConfigurationService.GetUuid()`` is the other real source and
        is deliberately NOT used here. It returns the value base64-encoded, and the
        SMBIOS Type 1 UUID carries its first three fields little-endian, so a naive
        decode yields a plausible-looking GUID that does not match what an operator
        reads in MEBx. A cross-check that compares against a wrong-but-convincing
        value is worse than no cross-check, because it fails on a correctly
        recorded expectation. If PlatformGUID turns out to be absent on some
        firmware, add GetUuid then -- and verify it against the UUID physically
        visible on the machine, not merely against itself.

        Returns ``None`` when the class or property is absent, consistent with the
        rest of facts gathering: a missing optional class degrades one fact rather
        than failing the whole read.
        """
        package = self._get_optional("CIM_ComputerSystemPackage")
        if not package:
            return None
        value = package.get("PlatformGUID")
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return _canonical_uuid(text)

    # -- Power ------------------------------------------------------------------

    def get_power_state(self) -> PowerState:
        """Read the endpoint's current power state.

        Unlike :meth:`get_facts`, failures here are not tolerated: a caller
        asking for power state wants to know it, or wants to know why it
        could not be read, not a silent "unknown".
        """
        instance = self._wsman.get("CIM_AssociatedPowerManagementService")
        return PowerState.from_cim_value(instance.get("PowerState", -1))

    def request_power_state(self, action: PowerAction) -> OperationReceipt:
        """Request a power transition and report the bounded postcondition probe.

        ``ReturnValue == 0`` from ``RequestPowerStateChange`` means AMT
        accepted the request, not that the transition finished (see
        docs/protocol-notes.md s2.4), so this polls
        ``CIM_AssociatedPowerManagementService`` a bounded number of times
        afterwards and reports what it actually observed.

        Deliberately does not catch ``RemoteOperationError`` (non-zero
        ``ReturnValue``) or ``TimeoutError_`` raised by the ``invoke`` call
        itself -- both must reach the caller unmodified: a non-zero
        ``ReturnValue`` is a real rejection, and a timeout *after* the
        request was transmitted must surface as ``indeterminate`` so the
        caller re-probes instead of this method retrying a possibly-applied
        mutation on its own initiative.
        """
        previous = self.get_power_state()
        code = _POWER_ACTION_CODES[action]
        managed_element = EndpointReference("CIM_ComputerSystem", _MANAGED_SYSTEM_SELECTOR)

        _output, return_value = self._wsman.invoke(
            "CIM_PowerManagementService",
            "RequestPowerStateChange",
            {"PowerState": code, "ManagedElement": managed_element},
        )

        expected = _ACTION_EXPECTED_STATE[action]
        probes: list[PowerState] = []
        observed: PowerState | None = None
        for _unused_attempt in range(max(0, self._poll_count)):
            self._sleep(self._poll_delay)
            try:
                observed = self.get_power_state()
            except AmtError:
                # The mutation itself already succeeded (ReturnValue == 0
                # above); a failed postcondition probe is diagnostic-only and
                # must not turn a successful request into a reported failure.
                continue
            probes.append(observed)
            if observed.normalized == expected:
                break

        peer_cert = self._wsman.last_peer_certificate
        return OperationReceipt(
            action=f"amt_power.{action.value}",
            endpoint=self._wsman.endpoint,
            changed=True,
            previous=previous,
            desired=expected,
            observed=observed,
            tls_peer_fingerprint=peer_cert.sha256_fingerprint if peer_cert else None,
            extra={
                "return_value": return_value,
                "probes": [dataclasses.asdict(probe) for probe in probes],
            },
        )
