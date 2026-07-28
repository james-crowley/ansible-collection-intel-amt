# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""The WS-Man management view of the Intel AMT redirection service: supported / enabled / reachable.

Per docs/protocol-notes.md s2.6, three questions about redirection have three different, and
sometimes disagreeing, answers:

- **supported** -- does the firmware implement IDE-R / SOL at all? From ``AMT_BootCapabilities``.
- **enabled** -- is the redirection service turned on in the management-plane configuration?
  From ``AMT_RedirectionService.EnabledState`` / ``ListenerEnabled``.
- **transport_reachable** -- does a bare TCP connect to 16994/16995 actually succeed?

This module reports all three separately, always, and never collapses them into one boolean --
a machine can be "supported and enabled" yet unreachable behind a firewall, or "reachable" on the
port while the service itself is disabled at the WS-Man layer.

This is emphatically **not** the stateful, binary redirection session (SOL/IDE-R framing per
protocol-notes s3-s5); that lives in ``plugins/module_utils/redirection.py``, owned separately.
Everything here is a WS-Man Get/Enumerate/Invoke plus, for the reachability signal, a
connect-and-close TCP probe -- never a byte of the redirection protocol itself.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import UnsupportedCapabilityError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import RedirectionState
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import WsmanClient

# docs/protocol-notes.md s2.6 -- AMT_RedirectionService.EnabledState.
ENABLED_STATE_DISABLED = 32768
ENABLED_STATE_IDER_ONLY = 32769
ENABLED_STATE_SOL_ONLY = 32770
ENABLED_STATE_BOTH = 32771

#: The four states an amt_redirection `state=` mutation can request.
STATE_NAME_TO_ENABLED_STATE: dict[str, int] = {
    "disabled": ENABLED_STATE_DISABLED,
    "ider": ENABLED_STATE_IDER_ONLY,
    "sol": ENABLED_STATE_SOL_ONLY,
    "all": ENABLED_STATE_BOTH,
}
ENABLED_STATE_TO_STATE_NAME: dict[int, str] = {value: name for name, value in STATE_NAME_TO_ENABLED_STATE.items()}

#: Redirection-plane ports (plain / TLS), per docs/protocol-notes.md s1. Independent of the
#: WS-Man management port -- probing these is *not* affected by a caller's `port=` option.
DEFAULT_REDIRECTION_PORTS: tuple[int, ...] = (16994, 16995)

#: The reachability probe's socket factory. Injectable so unit tests exercise this module without
#: ever opening a real socket -- see tests/unit/plugins/module_utils/test_redirection_service.py.
ConnectFn = Callable[[tuple[str, int], float], Any]


def _truthy(value: Any) -> bool:
    """Interpret a WS-Man response value (often the string ``"true"``/``"false"``) as a bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1")
    return bool(value)


@dataclass(frozen=True, slots=True)
class RedirectionCapabilities:
    """What the firmware advertises it supports, from ``AMT_BootCapabilities``.

    Field names (``IDER``, ``SOL``) follow Intel's published AMT_BootCapabilities schema; unlike
    the five-step boot sequence, docs/protocol-notes.md s2.6 does not itself name the specific
    capability fields, so this mapping has not been independently re-verified against real
    firmware output. Flagged for hardware verification -- see the PR description.
    """

    ider_supported: bool
    sol_supported: bool


@dataclass(frozen=True, slots=True)
class RedirectionStatus:
    """The three signals from docs/protocol-notes.md s2.6, kept as three separate fields.

    ``transport_reachable`` maps each probed port to whether the connect succeeded, rather than
    being a single bool, because 16994 vs 16995 reachability can legitimately differ (e.g. TLS
    disabled entirely, per protocol-notes s1.1).
    """

    capabilities: RedirectionCapabilities
    state: RedirectionState
    transport_reachable: dict[int, bool]


def get_capabilities(client: WsmanClient) -> RedirectionCapabilities:
    """Enumerate AMT_BootCapabilities and report IDER/SOL support.

    Raises :class:`UnsupportedCapabilityError` if firmware does not expose exactly one
    AMT_BootCapabilities instance -- an ambiguous or absent instance means "supported" cannot be
    answered at all, so this fails closed rather than guessing.
    """
    instances = client.enumerate("AMT_BootCapabilities")
    if len(instances) != 1:
        raise UnsupportedCapabilityError(
            f"expected exactly one AMT_BootCapabilities instance, found {len(instances)}",
            operation="discover_redirection_capabilities",
        )
    capabilities = instances[0]
    return RedirectionCapabilities(
        ider_supported=_truthy(capabilities.get("IDER")),
        sol_supported=_truthy(capabilities.get("SOL")),
    )


def get_state(client: WsmanClient) -> RedirectionState:
    """Get AMT_RedirectionService and normalize EnabledState/ListenerEnabled."""
    instance = client.get("AMT_RedirectionService")
    return RedirectionState.from_enabled_state(
        instance.get("EnabledState", -1),
        _truthy(instance.get("ListenerEnabled")),
    )


def probe_transport_reachable(
    host: str,
    ports: tuple[int, ...] = DEFAULT_REDIRECTION_PORTS,
    *,
    timeout: float = 2.0,
    connect: ConnectFn = socket.create_connection,
) -> dict[int, bool]:
    """Attempt a bare TCP connect-and-close to each redirection port.

    ``connect`` defaults to :func:`socket.create_connection` but is always injectable -- unit
    tests must never open a real socket, per this module's own design brief. A fake that raises
    ``OSError`` for a closed port and returns anything with a no-op ``close()`` for an open one is
    sufficient to exercise both branches.
    """
    reachable: dict[int, bool] = {}
    for port in ports:
        try:
            connection = connect((host, port), timeout)
        except OSError:
            reachable[port] = False
        else:
            reachable[port] = True
            close = getattr(connection, "close", None)
            if callable(close):
                close()
    return reachable


def get_status(
    client: WsmanClient,
    host: str,
    *,
    ports: tuple[int, ...] = DEFAULT_REDIRECTION_PORTS,
    timeout: float = 2.0,
    connect: ConnectFn = socket.create_connection,
) -> RedirectionStatus:
    """Gather all three signals -- supported, enabled, transport_reachable -- in one call."""
    return RedirectionStatus(
        capabilities=get_capabilities(client),
        state=get_state(client),
        transport_reachable=probe_transport_reachable(host, ports, timeout=timeout, connect=connect),
    )


def validate_state_change(capabilities: RedirectionCapabilities, state_name: str) -> None:
    """Fail unsupported_capability before mutating towards a state the firmware cannot honour.

    ``state_name="disabled"`` requires nothing (disabling never needs a capability check).
    ``"ider"``/``"sol"``/``"all"`` require the corresponding capability bit(s) to be set.
    """
    if state_name not in STATE_NAME_TO_ENABLED_STATE:
        raise ValueError(f"unknown redirection state {state_name!r}; expected one of {sorted(STATE_NAME_TO_ENABLED_STATE)}")
    if state_name in ("ider", "all") and not capabilities.ider_supported:
        raise UnsupportedCapabilityError(
            f"firmware does not advertise IDER support in AMT_BootCapabilities; cannot request state={state_name!r}",
            operation="validate_redirection_state_change",
        )
    if state_name in ("sol", "all") and not capabilities.sol_supported:
        raise UnsupportedCapabilityError(
            f"firmware does not advertise SOL support in AMT_BootCapabilities; cannot request state={state_name!r}",
            operation="validate_redirection_state_change",
        )


def request_state_change(client: WsmanClient, state_name: str) -> None:
    """Invoke AMT_RedirectionService.RequestStateChange for one of STATE_NAME_TO_ENABLED_STATE.

    Callers should run :func:`validate_state_change` first -- this function does not repeat that
    check, so that a caller which has already validated does not pay for a second lookup.
    """
    if state_name not in STATE_NAME_TO_ENABLED_STATE:
        raise ValueError(f"unknown redirection state {state_name!r}; expected one of {sorted(STATE_NAME_TO_ENABLED_STATE)}")
    requested_state = STATE_NAME_TO_ENABLED_STATE[state_name]
    client.invoke("AMT_RedirectionService", "RequestStateChange", {"RequestedState": requested_state})
