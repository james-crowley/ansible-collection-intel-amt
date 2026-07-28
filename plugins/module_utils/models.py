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
_POWER_STATE_TABLE: dict[int, str] = {
    2: "on",  # On
    3: "sleep",  # Sleep - Light
    4: "sleep",  # Sleep - Deep
    5: "on",  # Power Cycle (soft) -- ends powered on
    6: "off",  # Off - Hard
    7: "hibernate",  # Hibernate
    8: "off",  # Off - Soft
    9: "off",  # Power Cycle (off-hard) -- ends powered off
    13: "off",  # Off - Hard Graceful
}


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
class AmtFacts:
    """Firmware-observed evidence only. Every field here came from a WS-Man response.

    Do not add a field for caller-supplied data (hostname, MAC, inventory
    labels, ...) to this class -- see :class:`CallerSuppliedIdentity`.
    """

    version: str | None = None
    uuid: str | None = None
    control_mode: str | None = None
    provisioning_state: str | None = None
    power_state: PowerState | None = None


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
