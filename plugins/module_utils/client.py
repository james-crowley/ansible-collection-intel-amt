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
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    AmtCapabilities,
    AmtFacts,
    OperationReceipt,
    PowerState,
    RedirectionState,
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
#: ``ManagedElement`` must name, per docs/protocol-notes.md s2.4.
_MANAGED_SYSTEM_SELECTOR = {"Name": "ManagedSystem"}


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


def _truthy(value: Any) -> bool:
    """Interpret a WS-Man boolean property, which arrives as element text (a string)."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("true", "1", "yes")


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

        naive big-endian     LAMBDA_PLATFORM_GUID_BE   version F
        SMBIOS little-endian LAMBDA_PLATFORM_GUID   version 1

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

    def get_facts(self) -> AmtFacts:
        """Gather firmware-observed facts and capabilities.

        Each source class is read independently and tolerated if absent, per
        the module docstring: a firmware that does not implement e.g.
        ``AMT_BootCapabilities`` yields ``capabilities`` with every flag
        ``False`` rather than failing the whole read. A genuine transport
        failure (connection/auth/TLS/timeout) is not tolerated here and
        propagates to the caller unchanged.
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
            boot_once_pxe=_truthy(boot_caps.get("ForcePXEBoot")) if boot_caps else False,
            sol=_truthy(boot_caps.get("SOL")) if boot_caps else False,
            storage_redirection=_truthy(boot_caps.get("IDER")) if boot_caps else False,
        )

        redirection_state = None
        if redirection is not None:
            redirection_state = RedirectionState.from_enabled_state(
                redirection.get("EnabledState", -1),
                listener_enabled=_truthy(redirection.get("ListenerEnabled")),
            )

        version = self._get_amt_version()

        return AmtFacts(
            version=version,
            uuid=self._get_system_uuid(),
            control_mode=(setup or {}).get("ProvisioningMode"),
            provisioning_state=(setup or {}).get("ProvisioningState"),
            power_state=power_state,
            reported_hostname=(general or {}).get("HostName"),
            capabilities=capabilities,
            redirection=redirection_state,
        )

    def _get_optional(self, resource_class: str) -> dict[str, Any] | None:
        """``Get`` a class that a firmware may legitimately not implement.

        Returns ``None`` on the degradable errors (protocol/unsupported --
        i.e. "this class does not exist here"), letting the caller degrade
        the derived capability rather than aborting. Anything else (a real
        connection/auth/TLS/timeout failure) is not this method's to hide and
        is left to propagate.
        """
        try:
            return self._wsman.get(resource_class)
        except _DEGRADABLE_ERRORS:
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
