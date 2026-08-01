# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deterministic mock WS-Man endpoint for integration testing.

There is no Intel AMT hardware in CI (see ``docs/testing.md``), so this server
stands in for firmware's WS-Management plane (``docs/protocol-notes.md`` §2).
It is deliberately standard-library only: ``http.server`` for the HTTP/TLS
listener, ``xml.etree.ElementTree`` for SOAP, ``hashlib``/``hmac`` for HTTP
Digest. Test-side HTTP clients (``requests``) are fine; the *server* itself
must not gain a runtime dependency the collection does not already have.

External dependency: TLS mode shells out to the ``openssl`` CLI to generate a
throw-away self-signed certificate at start-up. Pure-stdlib certificate
generation is not practical (the ``ssl`` module can consume certs but not
mint them), and adding the ``cryptography`` package as a dependency here
would leak into ``tests/integration/requirements.txt`` for a capability we
only need transiently. ``openssl`` is assumed present on the CI image
(it is, on ``cimg/python``) and on any reasonable developer machine.

Design notes for reviewers:

* Every fault-injection knob lives on ``WsmanMockServer.faults`` (a
  :class:`FaultConfig`) and ``WsmanMockServer.state`` (an :class:`AmtState`),
  both mutable for the lifetime of the running server, so a test can arm a
  fault, make one request, then disarm it and keep using the same server.
* ``timeout_before_read`` / ``timeout_after_read`` and ``force_status`` are
  one-shot: they fire once then reset themselves, matching how a test uses
  them ("the next request should see X"). Per-resource faults
  (``return_value_for``, ``soap_fault_for``, ``malformed_xml_for``,
  ``http_status_for``) are persistent sets/dicts a test adds to and removes
  from explicitly, because they are usually armed for the duration of one
  assertion block rather than "the next call".
* State mutations happen under a single lock because ``ThreadingHTTPServer``
  dispatches concurrent requests onto separate threads and the whole point of
  the boot-settings/power-state fixtures is that they are observable
  cross-request state, not per-request scratch data.

Provenance convention
---------------------

A mock that accepts what firmware rejects is worse than no mock, and a mock
whose response bodies are this project's own guesses is worse still, because a
later reader cites them as evidence. Every response-producing handler here
therefore carries **exactly one** of these three markers in its docstring or a
comment immediately above it:

``FIRMWARE-DERIVED``
    The field set and values are copied from a recorded real-firmware response.
    The citation is mandatory and names the fixture path, e.g.
    ``go-wsman-messages``'s
    ``pkg/wsman/wsmantesting/responses/amt/messagelog/get.xml``. These may be
    cited as evidence of what firmware sends.

``NAMES-ONLY``
    The property *names* are attested -- by a class definition (that library's
    ``types.go``) or a hardware property dump -- but the *values* served here are
    this mock's own choice. The names may be cited; the values may not.

``INVENTED``
    Neither the field set nor the values are attested anywhere. Nothing may cite
    these as evidence of firmware behaviour. Present only because some client
    path needs *a* response, and marked so it is never mistaken for the other
    two.

``_get_message_log`` is the model for a FIRMWARE-DERIVED entry; ``_get_computer_system``
is the model for an INVENTED one.

One narrow, explicit carve-out on NAMES-ONLY, added for the hardware-inventory
handlers
------------------------------------------------------------------------------

A NAMES-ONLY handler may carry across a *non-identifying enumeration or numeric*
value from the cited fixture, **provided the individual value is cited where it is
served**. The reason is specific: this mock's job includes exercising the client's
DMTF value-table decoding, and a table fed from this project's own idea of what
firmware sends is precisely how the ``LinkPolicy`` inversion survived two releases
(``docs/capability-matrix.md``). Serving ``MemoryType`` 26 because a real firmware
response says 26 is evidence; serving it because 26 looked like a sensible number
is not.

What may **never** be carried across is identifying data. The
``go-wsman-messages`` fixtures for these classes contain what appear to be real
serial numbers, model numbers, part numbers and a BIOS revision from an actual
machine. Every one of those is substituted here with an obviously-fake value, and
each handler says so. So for these handlers: the field set and the cited
enumeration values may be relied on; every identity-shaped string may not.

Rejections
----------

Faults this mock injects on request are one thing; rejections it applies
*unconditionally* because real firmware does are another, and the second kind is
what keeps the client honest. They are deliberately few and each cites its
evidence, because inventing a rejection firmware does not perform is the same
error class as inventing a property value. Where it is genuinely unknown whether
firmware rejects something, this mock stays permissive and says so in a comment
rather than guessing.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------
# WS-Man / SOAP constants (docs/protocol-notes.md §2.2-2.3)
# --------------------------------------------------------------------------

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_A = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
NS_W = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

ACTION_GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
ACTION_GET_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
ACTION_PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
ACTION_PUT_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse"
ACTION_DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
ACTION_DELETE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_ENUMERATE_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
ACTION_PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
ACTION_PULL_RESPONSE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse"
ACTION_FAULT = "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault"

CIM_BASE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2"
AMT_BASE = "http://intel.com/wbem/wscim/1/amt-schema/1"
IPS_BASE = "http://intel.com/wbem/wscim/1/ips-schema/1"
#: The DMTF "common" namespace a CIM datetime/interval value's inner element sits
#: in (docs/protocol-notes.md §2.10). Not a resource base -- it never appears in a
#: ResourceURI, only inside an instance body.
NS_CIM_COMMON = "http://schemas.dmtf.org/wbem/wscim/1/common"

CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE = f"{CIM_BASE}/CIM_AssociatedPowerManagementService"
CIM_POWER_MANAGEMENT_SERVICE = f"{CIM_BASE}/CIM_PowerManagementService"
CIM_BOOT_CONFIG_SETTING = f"{CIM_BASE}/CIM_BootConfigSetting"
CIM_BOOT_SERVICE = f"{CIM_BASE}/CIM_BootService"
CIM_BOOT_SOURCE_SETTING = f"{CIM_BASE}/CIM_BootSourceSetting"
CIM_COMPUTER_SYSTEM = f"{CIM_BASE}/CIM_ComputerSystem"
CIM_BIOS_ELEMENT = f"{CIM_BASE}/CIM_BIOSElement"
# Hardware/asset inventory (docs/protocol-notes.md 2.9). All CIM_-prefixed, so
# 2.7's "Enumerate is HTTP 400 on AMT_ classes" finding does not reach them --
# that section says so explicitly.
CIM_CHASSIS = f"{CIM_BASE}/CIM_Chassis"
CIM_CARD = f"{CIM_BASE}/CIM_Card"
CIM_PROCESSOR = f"{CIM_BASE}/CIM_Processor"
CIM_CHIP = f"{CIM_BASE}/CIM_Chip"
CIM_PHYSICAL_MEMORY = f"{CIM_BASE}/CIM_PhysicalMemory"
CIM_MEDIA_ACCESS_DEVICE = f"{CIM_BASE}/CIM_MediaAccessDevice"
AMT_ETHERNET_PORT_SETTINGS = f"{AMT_BASE}/AMT_EthernetPortSettings"
AMT_BOOT_SETTING_DATA = f"{AMT_BASE}/AMT_BootSettingData"
AMT_BOOT_CAPABILITIES = f"{AMT_BASE}/AMT_BootCapabilities"
AMT_REDIRECTION_SERVICE = f"{AMT_BASE}/AMT_RedirectionService"
AMT_GENERAL_SETTINGS = f"{AMT_BASE}/AMT_GeneralSettings"
AMT_SETUP_AND_CONFIGURATION_SERVICE = f"{AMT_BASE}/AMT_SetupAndConfigurationService"
AMT_MESSAGE_LOG = f"{AMT_BASE}/AMT_MessageLog"
# Alarm clock (docs/protocol-notes.md §2.10). The service owns AddAlarm; the
# occurrence class is Enumerate-and-Delete only -- there is no Put on it in any
# source, which is why this mock does not serve one.
AMT_ALARM_CLOCK_SERVICE = f"{AMT_BASE}/AMT_AlarmClockService"
AMT_TIME_SYNCHRONIZATION_SERVICE = f"{AMT_BASE}/AMT_TimeSynchronizationService"
IPS_ALARM_CLOCK_OCCURRENCE = f"{IPS_BASE}/IPS_AlarmClockOccurrence"

#: Fields firmware reports on Get but rejects if echoed back on Put
#: (docs/protocol-notes.md §2.5). This is the single most important fault this
#: mock implements: it is the only way to test that a client actually applies
#: the delete-list rather than doing a naive read-modify-write.
READONLY_BOOT_FIELDS = frozenset(
    {
        "WinREBootEnabled",
        "UEFILocalPBABootEnabled",
        "UEFIHTTPSBootEnabled",
        "SecureBootControlEnabled",
        "BootguardStatus",
        "OptionsCleared",
        "BIOSLastStatus",
        "UefiBootParametersArray",
    }
)

BOOT_SOURCE_NAMES = (
    "Intel(r) AMT: Force PXE Boot",
    "Intel(r) AMT: Force Hard-drive Boot",
    "Intel(r) AMT: Force CD/DVD Boot",
    "Intel(r) AMT: Force Diagnostic Boot",
    "Intel(r) AMT: Force USB Boot",
)

#: ``CIM_BootSourceSetting.ElementName`` -- the **same** value on every instance.
#: Verbatim from the real firmware response fixture
#: ``go-wsman-messages``' ``pkg/wsman/wsmantesting/responses/cim/boot/sourcesetting/pull.xml``,
#: where all three returned instances share it and differ only in ``InstanceID``.
BOOT_SOURCE_ELEMENT_NAME = "Intel(r) AMT: Boot Source"

#: ``FailThroughSupported`` = 2 = ``NotSupported``
#: (``pkg/wsman/cim/boot/decoder.go``: 0 Unknown, 1 IsSupported, 2 NotSupported). This is
#: the value the fixture reports on all three instances.
FAIL_THROUGH_SUPPORTED_NOT_SUPPORTED = 2

#: ``InstanceID`` -> ``StructuredBootString``.
#:
#: The format is ``"<OrgID>:<identifier>:<index>"`` with ``OrgID`` = ``CIM`` and
#: ``<identifier>`` drawn from the DMTF set ``Floppy``, ``Hard-Disk``, ``CD/DVD``,
#: ``Network``, ``PCMCIA``, ``USB`` -- documented on ``StructuredBootString`` in
#: ``pkg/wsman/cim/boot/types.go``. The first three entries are **verbatim from the
#: fixture** ``responses/cim/boot/sourcesetting/pull.xml``.
#:
#: ``Force USB Boot`` uses the DMTF ``USB`` identifier, which is a *names-only*
#: construction: the identifier is documented but no fixture shows AMT emitting a USB boot
#: source. ``Force Diagnostic Boot`` is deliberately **absent** -- the DMTF identifier set
#: has no diagnostic member, so there is nothing to derive and guessing one would be
#: exactly the invention this file exists to avoid. An instance with no
#: ``StructuredBootString`` is a legitimate shape: the property is ``omitempty`` in the
#: class definition.
BOOT_SOURCE_STRUCTURED_STRINGS: dict[str, str] = {
    "Intel(r) AMT: Force PXE Boot": "CIM:Network:1",
    "Intel(r) AMT: Force Hard-drive Boot": "CIM:Hard-Disk:1",
    "Intel(r) AMT: Force CD/DVD Boot": "CIM:CD/DVD:1",
    "Intel(r) AMT: Force USB Boot": "CIM:USB:1",
}

#: The exact HTTP 400 reason real AMT 16.1.30 returns for a request whose body does
#: not validate against the resource's XML schema, recorded in
#: docs/protocol-notes.md §2.5 from a hardware observation:
#:
#:   HTTP 400 -- "The supplied SOAP violates the corresponding XML schema definition."
#:
#: Only the status code and this message string are established. The *body shape*
#: firmware wraps it in is not, so this is served as ``text/plain`` exactly like the
#: mock's pre-existing "malformed SOAP request" 400 rather than inventing a SOAP
#: fault envelope for it. The collection's client classifies any non-2xx that is not
#: 401 as ``protocol`` and carries the body through as diagnostic, so the message
#: reaches the operator either way.
SCHEMA_VIOLATION_MESSAGE = "The supplied SOAP violates the corresponding XML schema definition."

#: ``ReturnValue`` for "Invalid Parameter" on every method this mock serves that has a
#: published ValueMap: ``CIM_BootConfigSetting``/``CIM_BootService`` (go-wsman-messages
#: ``pkg/wsman/cim/boot/decoder.go``), ``CIM_PowerManagementService``
#: (``pkg/wsman/cim/power/decoder.go``) and ``AMT_RedirectionService``
#: (``pkg/wsman/amt/redirection/decoder.go``) all define ``5 = InvalidParameter``.
#:
#: This mock previously answered ``2`` for every malformed-parameter case. In all three
#: of those maps ``2`` is *Unknown/Unspecified Error* -- a different condition, and one a
#: client could reasonably treat as retryable where an invalid parameter never is.
#: ``AMT_MessageLog``'s methods keep their own values (see ``GET_RECORDS_NO_RECORDS``);
#: they have a different ValueMap and were already verified against it.
RETURN_VALUE_INVALID_PARAMETER = 5

#: ``AvailableRequestedPowerStates`` exactly as the real firmware response fixture
#: ``go-wsman-messages`` ships at
#: ``pkg/wsman/wsmantesting/responses/cim/associatedpower/managementservice/get.xml``
#: reports them, in that fixture's order (which is *not* sorted -- the values are a set,
#: and reordering them would be inventing a bookkeeping firmware does not promise).
AVAILABLE_REQUESTED_POWER_STATES = (10, 8, 5, 11, 4, 7, 14, 12)

#: RequestPowerStateChange action code -> resulting CIM_AssociatedPowerManagementService.PowerState
#: (docs/protocol-notes.md §2.4). Codes 5 (power cycle) and 10 (reset) both end powered-on.
#:
#: Aligned with ``AVAILABLE_REQUESTED_POWER_STATES`` above, with two deliberate
#: exceptions that are **kept permissive on purpose**:
#:
#: * ``2`` (On) and ``3`` (Sleep - Light) are absent from that fixture's list, but the
#:   list is explicitly *state-dependent*: the class definition says the advertised
#:   values "are a function of the current power state of the system", and the fixture
#:   was captured at ``PowerState = 2`` -- so "On" is missing from it precisely because
#:   the machine was already on. Rejecting ``2`` would therefore make ``amt_power``'s
#:   power-on path impossible against this mock while asserting something the evidence
#:   does not support. ``3`` is left alongside it for the same reason: this collection
#:   sends it for ``sleep_light`` and nothing establishes that firmware refuses it when
#:   the machine is on.
#: * ``11`` (Diagnostic Interrupt / NMI) is advertised by the fixture and now accepted,
#:   but it maps to **no** power-state change: an NMI interrupts the running OS, it does
#:   not transition the machine. What ``PowerState`` firmware reports afterwards is not
#:   established, so this mock leaves the value untouched rather than inventing one.
#:
#: Codes ``12`` (Off - Soft Graceful) and ``14`` (Master Bus Reset Graceful) are the
#: graceful counterparts of ``8`` and ``10`` and land in the same end states. This
#: collection's client does not currently send ``11``, ``12`` or ``14`` at all
#: (``plugins/module_utils/client.py``'s ``_POWER_ACTION_CODES``); they are served
#: because the mock now advertises them, and a mock that advertises a value it then
#: refuses is a worse fixture than one that never mentioned it.
POWER_ACTION_TO_STATE: dict[int, int | None] = {
    2: 2,
    3: 3,
    4: 4,
    5: 2,
    7: 7,
    8: 8,
    10: 2,
    11: None,  # Diagnostic Interrupt (NMI): accepted, no state transition.
    12: 8,
    14: 2,
}

#: The one ``AMT_EthernetPortSettings`` instance this mock serves
#: (docs/protocol-notes.md §2.7). Real firmware requires an exact selector for
#: this class -- ``Enumerate`` is HTTP 400 on AMT 10 -- and a wrong or absent
#: instance index must fault rather than quietly returning instance 0's data,
#: which is the whole point of the mock checking the selector at all.
ETHERNET_PORT_0_INSTANCE_ID = "Intel(r) AMT Ethernet Port Settings 0"

#: The selector values that address the single instance this mock serves, per
#: resource URI. A ``Get`` carrying a ``SelectorSet`` that disagrees with these
#: faults, rather than being answered with instance 0's data anyway -- a client
#: that asks for a nonexistent instance must find out.
SELECTOR_MATCH_FOR_GET: dict[str, dict[str, str]] = {
    AMT_ETHERNET_PORT_SETTINGS: {"InstanceID": ETHERNET_PORT_0_INSTANCE_ID},
    CIM_COMPUTER_SYSTEM: {"Name": "ManagedSystem"},
}

#: Resources where a ``Get`` with **no** selector faults. Only
#: ``AMT_EthernetPortSettings`` is listed: it is an indexed class (instance 0, 1,
#: ...), and AMT 10 requires the exact selector for it -- ``Enumerate`` is HTTP
#: 400 (docs/protocol-notes.md §2.7). ``CIM_ComputerSystem`` is deliberately not
#: listed: a bare ``Get`` against it is reported to work on real AMT 10, so
#: requiring the selector here would assert firmware behaviour nothing has
#: observed.
SELECTOR_REQUIRED_FOR_GET = frozenset({AMT_ETHERNET_PORT_SETTINGS})

#: Method output parameters that real firmware emits **before** ``ReturnValue``.
#:
#: Every other method this mock serves returns ``ReturnValue`` and nothing else, so
#: the ordering never mattered before. It matters for ``AMT_MessageLog``: the real
#: firmware response fixtures
#: (``go-wsman-messages``' ``pkg/wsman/wsmantesting/responses/amt/messagelog/``)
#: put ``IterationIdentifier``, ``NoMoreRecords`` and every ``RecordArray`` element
#: *ahead* of ``ReturnValue`` in both ``GetRecords_OUTPUT`` and
#: ``PositionToFirstRecord_OUTPUT``. Serving our own convenient ordering instead
#: would be the mock asserting a shape no firmware produces -- which is the exact
#: class of bug this file's ``_boot_capabilities_items`` docstring records.
#: ``AMT_AlarmClockService.AddAlarm`` and
#: ``AMT_TimeSynchronizationService.GetLowAccuracyTimeSynch`` are in this set for
#: the same reason and on the same kind of evidence: ``responses/amt/alarmclock/
#: addalarm.xml`` puts ``AlarmClock`` before ``ReturnValue``, and
#: ``responses/amt/timesynchronization/getlowaccuracytimesynch.xml`` puts ``Ta0``
#: before it.
EXTRA_BEFORE_RETURN_VALUE = frozenset(
    {
        (AMT_MESSAGE_LOG, "GetRecords"),
        (AMT_MESSAGE_LOG, "PositionToFirstRecord"),
        (AMT_ALARM_CLOCK_SERVICE, "AddAlarm"),
        (AMT_TIME_SYNCHRONIZATION_SERVICE, "GetLowAccuracyTimeSynch"),
    }
)

#: The event-log records a freshly-started mock serves, newest first (which is how
#: AMT stores them -- go-wsman-messages' ``messagelog`` package comment: "In most
#: implementations, log entries are stored backwards, i.e. the newest record is the
#: first record").
#:
#: The first two are the **real firmware records** from
#: ``responses/amt/messagelog/getrecords.xml``, used verbatim: they are the
#: strongest available evidence of what a record looks like on the wire, and they
#: contain no identifying data at all -- an event log record has no room for a
#: hostname, address, MAC, GUID or fingerprint. The remaining four are constructed
#: here from the documented sensor-type/entity/severity tables so the integration
#: target can assert on the event classes this collection exists to surface
#: (watchdog expiry, no bootable media, a firmware boot error, boot failure).
#: Every constructed timestamp is an obviously-synthetic 2023 value.
DEFAULT_MESSAGE_LOG_RECORDS: tuple[str, ...] = (
    # Real firmware: sensor type 6, severity 16 (critical), entity 38 (Intel(r) ME).
    # Decodes to "Authentication failed 10 times. The system may be under attack."
    "Y8iYZf8GbwVoEP8mYaoKAAAAAAAA",
    # Constructed: sensor type 18, EventData[0]=0xAA, EventData[7]=8 -> watchdog Expired.
    "AAcBZf8SbwBoEP8mAKoBAgMEBQYI",
    # Constructed: sensor type 30 -> "No bootable media".
    "AQcBZf8ebwBoEP8iAAAAAAAAAAAA",
    # Constructed: sensor type 15, offset 0, EventData[1]=8 -> "Removable boot media not found."
    "AgcBZf8PbwBoEP8iAAAIAAAAAAAA",
    # Constructed: sensor type 35, severity 32 (non-recoverable) -> "System boot failure".
    "AwcBZf8jbwBoIP8iAAAAAAAAAAAA",
    # Real firmware: sensor type 15, offset 2, entity 34 (BIOS), severity 1 (monitor).
    # Decodes to "PCI resource configuration".
    "IgYBZf8PbwJoAf8iAEAHAAAAAAAA",
)

#: One **empty record slot**: 21 zero bytes, base64-encoded, exactly as real firmware
#: pads a ``GetRecords`` response.
#:
#: Derived, not measured: this is ``b64encode(bytes(21))``, the same primitive
#: ``message_log._EMPTY_SLOT_HEX`` is built from. Separately *confirmed* to match what
#: real firmware sent -- ``amt-lab-01`` (AMT 16.1.30, CircleCI job 2976) answered one
#: ``GetRecords`` call with 223 ``RecordArray`` elements while ``CurrentNumberOfRecords``
#: reported 18 and ``NoMoreRecords`` was already set. The 223 hold 18 real records
#: followed by *this exact string* repeated 205 times -- one per record slot a
#: ``ClearLog`` earlier the same day had freed. See ``message_log.is_empty_record_slot``.
EMPTY_MESSAGE_LOG_SLOT = b64encode(bytes(21)).decode("ascii")

#: How many records this mock returns from one ``GetRecords`` call, regardless of
#: the client's ``MaxReadRecords``. Deliberately smaller than
#: ``DEFAULT_MESSAGE_LOG_RECORDS`` so that following the iteration to completion is
#: exercised over a real socket rather than only where a unit test hands back a
#: pre-paged list. Real firmware is likewise entitled to return fewer records than
#: asked for -- that is what ``NoMoreRecords`` is for.
MESSAGE_LOG_BATCH_SIZE = 2

#: ``AMT_MessageLog.GetRecords`` ReturnValue for "No record exists in log", and
#: ``PositionToFirstRecord``'s for "No record exists". The two methods use
#: *different* values for the same condition (3 and 2 respectively), per the
#: ValueMap annotations in go-wsman-messages' ``types.go``. Serving one value for
#: both would let a client that conflated them pass here and fail on firmware.
GET_RECORDS_NO_RECORDS = 3
POSITION_TO_FIRST_RECORD_NO_RECORDS = 2


class _UnknownResource(Exception):
    """Raised internally when no handler exists for a (ResourceURI, Action) pair."""


class _HttpFault(Exception):
    """Reject a request at the HTTP layer, the way firmware does, instead of answering.

    A SOAP fault is a valid response to a request firmware *understood*; an HTTP 400 is
    what firmware sends when the request never got that far because its body did not
    validate. Those are different things and the collection's client classifies them by
    different code paths, so the mock must be able to produce both. Raised from anywhere
    inside :meth:`WsmanMockServer.dispatch` and turned into a response by the handler.
    """

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _schema_violation() -> _HttpFault:
    """The HTTP 400 real AMT 16.1.30 returns for a schema-invalid body (§2.5)."""
    return _HttpFault(400, SCHEMA_VIOLATION_MESSAGE)


def _default_boot_setting_data() -> dict[str, object]:
    """The instance a freshly-started mock reports for ``AMT_BootSettingData``.

    Includes the read-only fields real firmware reports on Get (see
    ``READONLY_BOOT_FIELDS``) so that a client under test must actively strip
    them, exactly as it would have to against real hardware.
    """
    return {
        "InstanceID": "Intel(r) AMT: Boot Configuration 0",
        "ElementName": "Intel(r) AMT Boot Configuration Data",
        "ConfigurationDataReset": False,
        "BIOSPause": False,
        "BIOSSetup": False,
        "BootMediaIndex": 0,
        "EnforceSecureBoot": False,
        "FirmwareVerbosity": 0,
        "ForcedProgressEvents": False,
        "IDERBootDevice": 0,
        "LockKeyboard": False,
        "LockPowerButton": False,
        "LockResetButton": False,
        "LockSleepButton": False,
        "ReflashBIOS": False,
        "UseIDER": False,
        "UseSOL": False,
        "UseSafeMode": False,
        "UserPasswordBypass": False,
        "SecureErase": False,
        "PlatformErase": False,
        # Read-only on real firmware -- must be deleted before Put.
        "WinREBootEnabled": False,
        "UEFILocalPBABootEnabled": False,
        "UEFIHTTPSBootEnabled": False,
        "SecureBootControlEnabled": False,
        "BootguardStatus": 0,
        "OptionsCleared": True,
        "BIOSLastStatus": [0, 0],
        "UefiBootParametersArray": [],
        "UefiBootNumberOfParams": 0,
    }


@dataclass
class AmtState:
    """Mutable firmware-like state. A `Put` or method call here is what makes
    a later `Get` observe the change -- the whole reason this is a stateful
    mock rather than a table of canned strings."""

    power_state: int = 2  # CIM PowerState: 2 = On
    redirection_enabled_state: int = 32768  # disabled
    redirection_listener_enabled: bool = False
    boot_config_role: int = 0
    boot_order_source: str | None = None
    #: How many ``CIM_BootSourceSetting`` instances to serve. Below
    #: ``len(BOOT_SOURCE_NAMES)`` the tail targets become undiscoverable; above it,
    #: index-suffixed near-misses of the known names appear. See
    #: :func:`_boot_source_items` for what each direction proves about the client.
    boot_source_count: int = 5
    digest_realm: str = "Digest:A4000000000000000000000000000000"
    boot_setting_data: dict[str, object] = field(default_factory=_default_boot_setting_data)
    #: AMT_EthernetPortSettings instance 0 (docs/protocol-notes.md §2.7). The MAC
    #: is deliberately **dash**-separated and from the RFC 7042 documentation
    #: range: real AMT 10 firmware was observed returning dashes, so a client that
    #: only handles colons must fail here rather than in production.
    ethernet_mac_address: str = "00-00-5E-00-53-01"
    ethernet_link_policy: list[int] = field(default_factory=lambda: [1, 14, 16])
    #: Set False to make the instance-0 Get fault, standing in for firmware that
    #: does not implement the class (or a machine with no such port).
    ethernet_port_present: bool = True
    #: CIM_ComputerSystem. OperationalStatus is a CIM array, so it is a list here.
    enabled_state: int = 2  # DMTF: enabled
    requested_state: int = 12  # DMTF: not applicable -- what AMT 10 reports
    operational_status: list[int] = field(default_factory=lambda: [2])  # DMTF: OK
    #: CIM_BIOSElement.Version. Obviously-fake, shaped like a real Intel BIOS ID.
    bios_version: str = "EXAMPLE10H.86A.0000.2026.0101.0000"
    #: AMT_MessageLog records, newest first, base64 as firmware sends them. Mutable:
    #: ClearLog empties this list and a later Get observes CurrentNumberOfRecords 0,
    #: which is what makes the clear module's before/after receipt testable end to end.
    message_log_records: list[str] = field(default_factory=lambda: list(DEFAULT_MESSAGE_LOG_RECORDS))
    #: How many zero-filled **empty record slots** GetRecords pads its response with,
    #: after the real records. See EMPTY_MESSAGE_LOG_SLOT for the firmware measurement
    #: this reproduces. Deliberately NOT counted in CurrentNumberOfRecords: the whole
    #: point of the state is that the container counter and the returned array
    #: disagree, and a mock that kept them consistent is exactly why nothing here
    #: caught issue #105.
    message_log_empty_slots: int = 0
    #: Set False to make both Get and Enumerate of AMT_MessageLog fault, standing in
    #: for firmware that does not implement the event log at all.
    message_log_present: bool = True

    # -- Hardware / asset inventory (docs/protocol-notes.md 2.9) ---------------
    #
    # Serials are obviously fake and deliberately *different* from each other: a
    # chassis serial reported where a board serial belongs is a real bug class,
    # and identical placeholders would let it pass. Neither is a real machine's --
    # the vendor fixtures these handlers derive from do carry what look like real
    # ones, and none of those is reproduced anywhere in this repository.
    chassis_serial_number: str = "MOCKCHASSIS0001"
    #: ``None`` omits the ``SerialNumber`` element from the ``CIM_Card`` response
    #: entirely; ``""`` emits it empty. Both exist because both are firmware
    #: behaviours a client must be able to tell apart, and it cannot tell them apart
    #: from the parsed facts: ``models.optional_str`` renders both as ``null``, which
    #: is what left issue #84 -- board serial null on both lab machines while the
    #: chassis serial populates -- unresolvable for three releases.
    #:
    #: ``_value_to_xml`` already implements the distinction (``None`` renders
    #: nothing, ``""`` renders an empty element), so serving it needs no new
    #: rendering path -- only the ability to ask for it. Which of the two a firmware
    #: does is a property of that firmware, so it is a start-up flag on
    #: ``run_wsman_mock.py`` rather than something a running server can be switched
    #: between.
    baseboard_serial_number: str | None = "MOCKBOARD0001"
    #: CIM_Chassis.ChassisPackageType. Defaults to the real fixture's 0, which is
    #: the *defined* value "Unknown" -- distinct from a value outside the table.
    #: Mutable so a test can serve a defined non-zero value and an undefined one.
    chassis_package_type: int = 0
    #: How many instances each multi-instance class returns. Zero is a legitimate
    #: reading, not a fault: a diskless machine really has no
    #: CIM_MediaAccessDevice, and a client must report that as an empty list
    #: rather than as a firmware gap.
    processor_count: int = 1
    memory_dimm_count: int = 2
    storage_device_count: int = 2
    #: Set any of these False to make both Get and Enumerate of that class fault,
    #: standing in for firmware that does not implement it. Each degrades one fact
    #: group independently -- a machine with no CIM_MediaAccessDevice must still
    #: report its DIMMs. See HARDWARE_PRESENCE_ATTR.
    chassis_present: bool = True
    card_present: bool = True
    processor_present: bool = True
    chip_present: bool = True
    physical_memory_present: bool = True
    media_access_present: bool = True

    # -- Alarm clock (docs/protocol-notes.md 2.10) -----------------------------
    #
    #: Configured alarms, keyed by ``InstanceID``. **Real, mutable, cross-request
    #: state**, which is the whole reason the idempotence property is observable
    #: here rather than merely asserted about a mocked object: ``AddAlarm`` inserts,
    #: ``Delete`` removes, and a later ``Enumerate`` sees exactly what the previous
    #: call did. A canned list could not tell a second run that reported
    #: ``changed=false`` because convergence worked from one that reported it
    #: because nothing was ever written.
    #:
    #: Each value is the parsed template: ``InstanceID``, ``ElementName``,
    #: ``StartTime`` (the ``<Datetime>`` text verbatim), ``Interval`` (the ISO-8601
    #: duration text verbatim) and ``DeleteOnCompletion``. Stored as the strings
    #: firmware would echo, not as parsed times -- a mock that normalised them
    #: could not reproduce a firmware that echoes back something other than what it
    #: was sent, which is the documented way idempotence could fail here.
    alarm_occurrences: dict[str, dict[str, object]] = field(default_factory=dict)
    #: How many occurrences ``AddAlarm`` will accept before refusing. Default 5,
    #: which is the limit go-wsman-messages documents ("The method would fail if 5
    #: instances or more of IPS_AlarmClockOccurrence already exist in the system").
    #: Mutable so a test can prove the client's own pre-check and this refusal agree
    #: about where the boundary is, and can move it to reach the boundary cheaply.
    alarm_occurrence_limit: int = 5
    #: Set False to make both Get and Enumerate of the two alarm classes fault,
    #: standing in for firmware with no alarm clock at all.
    alarm_clock_present: bool = True
    #: ``GetLowAccuracyTimeSynch``'s ``Ta0`` -- firmware's RTC, in Unix epoch
    #: seconds. Settable so a test can serve a clock that disagrees with the
    #: controller's by a known amount, which is the only way to show the past-date
    #: check really consults *firmware's* clock rather than the controller's.
    #: ``None`` omits ``Ta0`` from the response entirely, which is a shape no source
    #: describes and which the client must treat as "firmware would not say".
    #:
    #: Defaults to the host's current time, deliberately, rather than to a frozen
    #: constant: a mock whose clock is stuck in 2024 would refuse every alarm a test
    #: wrote with a near-future time, and the failure would look like a bug in the
    #: past-date check instead of in the fixture. A test that needs determinism sets
    #: it explicitly.
    time_sync_ta0: int | None = field(default_factory=lambda: int(time.time()))
    #: ``AMT_TimeSynchronizationService.TimeSource`` / ``LocalTimeSyncEnabled``.
    #: Defaults are the vendor fixture's (``0`` and ``0``).
    time_sync_time_source: int = 0
    time_sync_local_enabled: int = 0
    #: Set False to make both verbs of ``AMT_TimeSynchronizationService`` fault.
    #: Distinct from ``alarm_clock_present``: a firmware can hold alarms while
    #: refusing to report its clock, and the client degrades differently for each.
    time_sync_present: bool = True


@dataclass
class FaultConfig:
    """Every fault-injection knob the mock understands. All mutable in place
    on a running server -- see the module docstring for the one-shot vs.
    persistent distinction."""

    #: Toggle for the read-only-field Put rejection. Default on: this is what
    #: real firmware does, and turning it off is the exception, not the rule.
    reject_boot_readonly_fields: bool = True

    #: Opt-in: answer **HTTP 400** to ``Enumerate`` on every ``AMT_``-prefixed resource,
    #: standing in for AMT 10-era firmware.
    #:
    #: docs/protocol-notes.md §2.7 records this as hardware-verified on AMT 10.0.56 for
    #: ``AMT_EthernetPortSettings``, ``AMT_GeneralSettings``, ``AMT_BootCapabilities``,
    #: ``AMT_BootSettingData`` and ``AMT_TLSSettingData``: that firmware offers selective
    #: instance access only, so ``Get`` with an exact selector works and ``Enumerate``
    #: does not.
    #:
    #: **Deliberately default-off, and deliberately not unconditional.** The same section
    #: records that this collection's ``Enumerate`` call sites *do* work on AMT 16.1.30 and
    #: 19.0.5, both hardware-verified. Making the mock reject ``Enumerate`` always would
    #: assert something false about modern firmware and break correct code; making it
    #: unreachable would leave the AMT 10 behaviour untestable. An opt-in knob is the only
    #: honest option: the mock can be *either* generation, and a test says which.
    #:
    #: ``AMT_MessageLog`` is exempt. §2.7's finding lists five classes and that is not one
    #: of them, and unusually for an ``AMT_`` class its ``Enumerate`` *is* directly
    #: evidenced -- ``responses/amt/messagelog/`` ships ``enumerate.xml`` and ``pull.xml``
    #: alongside ``get.xml`` (see ``_message_log_items``). Sweeping it in would be
    #: extending a hardware finding past what it covers.
    enumerate_faults_for_amt_classes: bool = False

    #: Fault a bare ``Get`` of ``CIM_Chassis`` and ``CIM_Card``, leaving only the
    #: ``Enumerate`` path -- the same knob as ``bios_element_get_faults`` below and
    #: for the same reason. The vendor fixture set evidences *both* verbs for both
    #: classes (``get.xml`` and ``enumerate.xml``+``pull.xml``), so which one a
    #: given firmware accepts is not settled, and the client's fallback has to be
    #: exercised over a real socket rather than only where a unit test mocks the
    #: transport away. Distinct from ``chassis_present``/``card_present``, which
    #: model the class being absent from *both* verbs.
    hardware_get_faults: bool = False

    #: Fault a bare ``Get CIM_BIOSElement``, leaving only the ``Enumerate`` path.
    #: This exists because ``CIM_BIOSElement`` has no obvious singleton selector,
    #: so which verb real firmware accepts for it is genuinely unsettled -- see
    #: docs/capability-matrix.md. A client must survive either answer, and this
    #: knob is how the ``Enumerate`` fallback gets exercised on the wire rather
    #: than only where a unit test mocks it away.
    bios_element_get_faults: bool = False

    #: One-shot: hang before ever reading the request body.
    timeout_before_read: bool = False
    #: One-shot: read the full body, then hang before writing any response.
    timeout_after_read: bool = False
    #: Set by the handler after a timeout fault fires, so a test can assert
    #: which of the two actually happened.
    last_timeout_body_was_read: bool | None = None

    #: One-shot: short-circuit the very next request to this HTTP status,
    #: bypassing auth and dispatch entirely.
    force_status: int | None = None

    #: Persistent, keyed by (resource_uri, action): force this AMT ReturnValue
    #: on a method call instead of running its normal side effect.
    return_value_for: dict[tuple[str, str], int] = field(default_factory=dict)
    #: Persistent: respond with a SOAP s:Fault instead of the normal body.
    soap_fault_for: set[tuple[str, str]] = field(default_factory=set)
    #: Persistent: respond 200 with deliberately truncated/invalid XML.
    malformed_xml_for: set[tuple[str, str]] = field(default_factory=set)
    #: Persistent: respond with an arbitrary HTTP status (e.g. 401, 500) for a
    #: specific (resource_uri, action) once authenticated and parsed.
    http_status_for: dict[tuple[str, str], int] = field(default_factory=dict)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _tag_namespace(tag: str) -> str | None:
    return tag[1 : tag.index("}")] if tag.startswith("{") else None


def _param(elem: ET.Element | None, local_name: str) -> ET.Element | None:
    """Find one method/enumeration parameter: a **direct child** in the **wrapper's own
    namespace**.

    This used to be a ``.iter()`` walk matching on local name at any depth in any
    namespace, which is exactly the "mock accepts what firmware rejects" defect this
    file exists to prevent: a parameter placed in the wrong namespace, or nested one
    level too deep inside some other element, sailed through the mock and then failed
    schema validation on real firmware.

    Both constraints come from the same place. A WS-Man method's input parameters are
    declared as the children of a ``<Method_INPUT>`` element in a sequence, in the
    resource's own target namespace -- which is why every implementation emits them that
    way: MeshCentral's ``amt-wsman.js``, go-wsman-messages'
    ``pkg/wsman/cim/boot/service.go`` (``<h:SetBootConfigRole_INPUT xmlns:h="...CIM_BootService">``
    with ``<h:BootConfigSetting>`` / ``<h:Role>`` children), and this collection's own
    ``plugins/module_utils/wsman.py`` ``_append_params``. Deriving the expected namespace
    from ``elem``'s own tag rather than taking it as an argument is what makes this work
    unchanged for ``Pull``, whose ``EnumerationContext`` child sits in the enumeration
    namespace rather than a resource URI.

    Elements *inside* a parameter -- an endpoint reference's ``Address`` and
    ``ReferenceParameters`` -- are in the addressing namespace, not the wrapper's, and
    are read by :func:`_endpoint_reference_instance_id` instead.
    """
    if elem is None:
        return None
    namespace = _tag_namespace(elem.tag)
    want = f"{{{namespace}}}{local_name}" if namespace else local_name
    for child in elem:
        if child.tag == want:
            return child
    return None


def _param_text(elem: ET.Element | None, local_name: str) -> str | None:
    """Text of the parameter :func:`_param` finds, or ``None`` if it is absent."""
    found = _param(elem, local_name)
    return found.text if found is not None else None


def _param_in(elem: ET.Element | None, namespace: str, local_name: str) -> ET.Element | None:
    """Like :func:`_param`, but with the child's namespace given rather than derived.

    Needed for an **embedded instance**, where the wrapper and its children are in
    deliberately *different* namespaces. ``AddAlarm``'s ``<AlarmTemplate>`` sits in
    the ``AMT_AlarmClockService`` namespace while every property inside it is in the
    ``IPS_AlarmClockOccurrence`` one, and ``StartTime``/``Interval``'s inner value
    elements are in the DMTF common namespace -- three namespaces in one body. See
    docs/protocol-notes.md §2.10 for the shape and the two sources it comes from.

    :func:`_param`'s derive-the-namespace-from-the-wrapper rule is correct for a flat
    parameter list and structurally cannot express that, which is the only reason this
    exists. The namespace is still **checked exactly**, never ignored: an element
    placed in the wrong one is not found, which is the same strictness for the same
    reason :func:`_param`'s own docstring gives.
    """
    if elem is None:
        return None
    want = f"{{{namespace}}}{local_name}"
    for child in elem:
        if child.tag == want:
            return child
    return None


def _param_text_in(elem: ET.Element | None, namespace: str, local_name: str) -> str | None:
    """Text of the element :func:`_param_in` finds, stripped, or ``None`` if absent/empty."""
    found = _param_in(elem, namespace, local_name)
    if found is None:
        return None
    text = (found.text or "").strip()
    return text or None


def _endpoint_reference_instance_id(param: ET.Element) -> str | None:
    """Read ``ReferenceParameters/SelectorSet/Selector[@Name="InstanceID"]`` from an EPR.

    Depth- and namespace-aware for the same reason :func:`_param` is. The nesting and
    namespaces asserted here are the exact ones docs/protocol-notes.md §2.5 records for
    the ``ChangeBootOrder`` ``Source`` body, and the ones go-wsman-messages emits
    verbatim in ``pkg/wsman/cim/boot/configsetting.go``: ``ReferenceParameters`` in the
    addressing namespace, containing ``SelectorSet`` and ``Selector`` in the WS-Man
    namespace.

    Returns ``None`` when the EPR is well-formed but names no ``InstanceID`` selector --
    that is a semantic question for the caller, not a schema violation.
    """
    reference_parameters = param.find(f"{{{NS_A}}}ReferenceParameters")
    if reference_parameters is None:
        return None
    selector_set = reference_parameters.find(f"{{{NS_W}}}SelectorSet")
    if selector_set is None:
        return None
    for selector in selector_set.findall(f"{{{NS_W}}}Selector"):
        if selector.attrib.get("Name") == "InstanceID":
            return selector.text
    return None


def _require_endpoint_reference(param: ET.Element) -> None:
    """Reject an endpoint-reference parameter that is present but carries no children.

    **This is the single highest-value rejection in this file.** ``ChangeBootOrder``'s
    ``Source`` is typed as an endpoint reference, so the schema requires ``Address`` and
    ``ReferenceParameters`` children; an empty ``<Source/>`` is schema-invalid and real
    AMT 16.1.30 answers the whole request with HTTP 400 and
    :data:`SCHEMA_VIOLATION_MESSAGE` (docs/protocol-notes.md §2.5, hardware-observed).
    An *absent* element is valid, because these parameters are optional
    (``minOccurs=0``) -- so "pass a null Source" means send no element at all.

    That defect made IDE-R and BIOS boot entirely impossible against real hardware, and
    until this check existed the mock reported ``ReturnValue 0`` for it, so mock and
    client could agree while both were wrong. Corroborated independently by the vendor
    reference implementation: go-wsman-messages'
    ``pkg/wsman/cim/boot/configsetting.go`` emits a *completely empty*
    ``<h:ChangeBootOrder_INPUT>`` when clearing the boot order and never an empty
    ``<h:Source/>``.

    Applied to every EPR-typed parameter this mock accepts, not only ``Source``: they are
    the same type, validated by the same firmware schema validator, so generalising the
    observed rejection is not the same as inventing new ones.
    """
    if len(param) == 0:
        raise _schema_violation()
    if param.find(f"{{{NS_A}}}Address") is None or param.find(f"{{{NS_A}}}ReferenceParameters") is None:
        raise _schema_violation()


def _optional_endpoint_reference(elem: ET.Element | None, local_name: str) -> ET.Element | None:
    """Return an EPR parameter if present, validating its shape; ``None`` if absent."""
    param = _param(elem, local_name)
    if param is None:
        return None
    _require_endpoint_reference(param)
    return param


def _value_to_xml(tag: str, value: object) -> str:
    """Render one AMT/CIM property as XML, matching the shapes firmware uses.

    Booleans render lowercase; array properties render as repeated elements
    (or nothing, if empty, which is how firmware represents an absent array);
    everything else renders as escaped text.
    """
    if isinstance(value, bool):
        return f"<r:{tag}>{'true' if value else 'false'}</r:{tag}>"
    if isinstance(value, (list, tuple)):
        return "".join(f"<r:{tag}>{escape(str(v))}</r:{tag}>" for v in value)
    if value is None:
        return ""
    return f"<r:{tag}>{escape(str(value))}</r:{tag}>"


def _fields_to_instance_xml(resource_uri: str, fields: dict[str, object]) -> str:
    """Render one instance, properties in **alphabetical order**.

    Every real firmware response fixture in ``go-wsman-messages``'
    ``pkg/wsman/wsmantesting/responses/`` orders an instance's properties strictly
    alphabetically -- ``amt/setupandconfiguration/get.xml``,
    ``cim/associatedpower/managementservice/get.xml``,
    ``cim/boot/sourcesetting/pull.xml`` and ``amt/messagelog/get.xml`` all do. This mock
    previously emitted Python dict-insertion order, which matched for only two of its ten
    handlers by luck.

    Sorting here rather than by hand-reordering each handler's literal is deliberate: it
    fixes every handler at once, cannot drift as fields are added, and keeps each
    handler's dict grouped the way a *reader* wants (identity fields first) while the
    *wire* gets the order firmware uses. Array properties are unaffected -- sorting is by
    property name, and :func:`_value_to_xml` emits a list's repeated elements
    contiguously, so ``AvailableRequestedPowerStates`` / ``OperationalStatus`` /
    ``LinkPolicy`` keep their own order, which is the only ordering that carries meaning.

    Worth stating plainly so nobody over-reads this change: this collection's parser is
    **not** order-sensitive for distinct property names. ``plugins/module_utils/wsman.py``
    ``_element_to_value()`` accumulates children into a dict keyed by local name, so
    sibling order across different names cannot affect it. This is fidelity insurance
    against a *future* parser that does care, not a bug fix -- which is why it is one
    ``sorted()`` and not ten edits.

    Method ``_OUTPUT`` element order is a separate question, handled by
    ``EXTRA_BEFORE_RETURN_VALUE``, because there the fixtures are *not* alphabetical.
    """
    class_name = resource_uri.rsplit("/", 1)[-1]
    inner = "".join(_value_to_xml(k, fields[k]) for k in sorted(fields))
    return f'<r:{class_name} xmlns:r="{resource_uri}">{inner}</r:{class_name}>'


def _envelope(action: str, relates_to: str | None, body: str, *, resource_uri: str | None = None) -> str:
    new_id = f"uuid:{uuid.uuid4()}"
    resource_hdr = f"<w:ResourceURI>{escape(resource_uri)}</w:ResourceURI>" if resource_uri else ""
    relates_hdr = f"<a:RelatesTo>{escape(relates_to)}</a:RelatesTo>" if relates_to else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{NS_S}" xmlns:a="{NS_A}" xmlns:w="{NS_W}">'
        "<s:Header>"
        f'<a:Action s:mustUnderstand="true">{escape(action)}</a:Action>'
        f"<a:To>{NS_A}/role/anonymous</a:To>"
        f"{resource_hdr}"
        f"<a:MessageID>{new_id}</a:MessageID>"
        f"{relates_hdr}"
        "</s:Header>"
        f"<s:Body>{body}</s:Body>"
        "</s:Envelope>"
    )


def _fault_body(subcode: str, reason: str) -> str:
    return (
        "<s:Fault>"
        "<s:Code><s:Value>s:Receiver</s:Value>"
        f"<s:Subcode><s:Value>w:{escape(subcode)}</s:Value></s:Subcode></s:Code>"
        f'<s:Reason><s:Text xml:lang="en-US">{escape(reason)}</s:Text></s:Reason>'
        "</s:Fault>"
    )


# --------------------------------------------------------------------------
# Resource GET handlers
# --------------------------------------------------------------------------


def _get_power(state: AmtState) -> dict[str, object]:
    """``CIM_AssociatedPowerManagementService`` -- **FIRMWARE-DERIVED** field set.

    Both properties come from the real firmware response fixture
    ``go-wsman-messages`` ships at
    ``pkg/wsman/wsmantesting/responses/cim/associatedpower/managementservice/get.xml``,
    with ``PowerState`` made live so a ``RequestPowerStateChange`` is observable here.

    ``ElementName`` was **removed**: it is not on that fixture and not in the class
    definition (``pkg/wsman/cim/associatedpower/types.go`` declares
    ``AvailableRequestedPowerStates``, ``PowerState``, ``OtherPowerState``,
    ``RequestedPowerState``, ``OtherRequestedPowerState``, ``PowerOnTime``,
    ``TransitioningToPowerState``, ``ServiceProvided``, ``UserOfService`` -- and no
    ``ElementName``). Serving it invited a future reader to conclude firmware sends it.
    Nothing in this collection read it: ``plugins/module_utils/client.py`` reads only
    ``PowerState`` from this class.

    ``ServiceProvided`` / ``UserOfService`` are on the fixture but not served: they are
    nested endpoint references rather than scalar properties, nothing here reads them, and
    ``_value_to_xml`` has no way to render them. Their absence is a gap in this mock, not
    a claim about firmware.
    """
    return {
        "AvailableRequestedPowerStates": list(AVAILABLE_REQUESTED_POWER_STATES),
        "PowerState": state.power_state,
    }


def _get_boot_capabilities(_state: AmtState) -> dict[str, object]:
    """``AMT_BootCapabilities`` -- **NAMES-ONLY**.

    Every property name is on the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/amt/boot/capabilities/get.xml`` (the same fixture
    docs/protocol-notes.md §2.5's capability table is verified against). The *values* are
    this mock's own choice: the mock advertises a permissive machine so the integration
    targets can arm every boot target, where the fixture's machine happens to have
    ``ForceDiagnosticBoot`` and the button locks off. Do not cite these values as
    firmware behaviour -- only the names.

    ``BIOSSecureBoot``, ``ConfigurationDataReset``, ``InstanceID``, ``VerbosityQuiet`` and
    ``VerbosityVerbose`` are on that fixture and were missing here. A client applying
    §2.5's "treat a missing field as not supported" rule cannot be exercised against
    fields the mock never sends, so an incomplete name set quietly narrows what the mock
    can catch.
    """
    return {
        "InstanceID": "Intel(r) AMT:BootCapabilities 0",
        "ElementName": "Intel(r) AMT: Boot Capabilities",
        "IDER": True,
        "SOL": True,
        "BIOSReflash": False,
        "BIOSSecureBoot": True,
        "BIOSSetup": True,
        "BIOSPause": True,
        "ConfigurationDataReset": False,
        "ForcePXEBoot": True,
        "ForceHardDriveBoot": True,
        "ForceHardDriveSafeModeBoot": False,
        "ForceDiagnosticBoot": True,
        "ForceCDorDVDBoot": True,
        "VerbosityQuiet": False,
        "VerbosityScreenBlank": True,
        "VerbosityVerbose": False,
        "PowerButtonLock": True,
        "ResetButtonLock": True,
        "KeyboardLock": True,
        "SleepButtonLock": True,
        "UserPasswordBypass": True,
        "ForcedProgressEvents": True,
        "SecureErase": False,
    }


def _get_redirection(state: AmtState) -> dict[str, object]:
    """``AMT_RedirectionService`` -- **FIRMWARE-DERIVED** field set.

    Every property is on the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/amt/redirectionservice/get.xml``, with
    ``EnabledState`` / ``ListenerEnabled`` made live so a ``RequestStateChange`` is
    observable. The four key properties (``CreationClassName``, ``Name``,
    ``SystemCreationClassName``, ``SystemName``) are copied verbatim from it and were
    missing here; ``SystemName = "Intel(r) AMT"`` in particular is what identifies the
    scoping system on every AMT service class.
    """
    return {
        "CreationClassName": "AMT_RedirectionService",
        "ElementName": "Intel(r) AMT Redirection Service",
        "EnabledState": state.redirection_enabled_state,
        "ListenerEnabled": state.redirection_listener_enabled,
        "Name": "Intel(r) AMT Redirection Service",
        "SystemCreationClassName": "CIM_ComputerSystem",
        "SystemName": "Intel(r) AMT",
    }


def _get_general_settings(state: AmtState) -> dict[str, object]:
    return {
        "ElementName": "Intel(r) AMT General Settings",
        "InstanceID": "Intel(r) AMT: General Settings",
        "NetworkInterfaceEnabled": True,
        "DigestRealm": state.digest_realm,
        "HostName": "mock-amt-host",
        "DomainName": "example.invalid",
        "PingResponseEnabled": True,
        "SharedFQDN": True,
        "AMTNetworkEnabled": 1,
        "RmcpPingResponseEnabled": True,
        "PreferredAddressFamily": 0,
        # Hardware-dumped on AMT 10.0.56 alongside the fields above
        # (docs/protocol-notes.md §2.7). PowerSource/PrivacyLevel are also on the
        # real instance but are deliberately not served here: this collection does
        # not surface them, because nothing documents what their integers mean.
        "IdleWakeTimeout": 1,
        "DDNSUpdateEnabled": False,
    }


def _get_ethernet_port_settings(state: AmtState) -> dict[str, object]:
    """``AMT_EthernetPortSettings`` instance 0 -- **NAMES-ONLY** (docs/protocol-notes.md §2.7).

    Names come from the AMT 10.0.56 hardware property dump §2.7 cites and are corroborated
    by ``pkg/wsman/wsmantesting/responses/amt/ethernetport/get.xml``. Every value is
    synthetic and from a documentation range (RFC 5737 ``192.0.2.0/24``, RFC 7042
    documentation MAC) -- never a real address.

    ``LinkPolicy`` is emitted as a **repeated plain element**. That is no longer merely
    the schema-implied shape: the fixture above settles it, carrying two consecutive
    ``<g:LinkPolicy>`` elements with no wrapper. ``parmstro``'s module code expects
    ``<PolicyValue>`` children inside a wrapper instead, and their hardware notes record
    only the decoded result (``[1, 14, 16]``) -- so that shape now has *no* supporting
    evidence and the repeated-element shape has direct fixture evidence. This mock serves
    the evidenced one. ``plugins/module_utils/models.py``'s ``_link_policy_values()``
    tolerates both, which is harmless leniency in a parser, not a second candidate shape.

    The same fixture independently corroborates §2.7's dash-separated MAC observation:
    it reports ``MACAddress`` as ``c8-d9-d2-7a-1e-33``. (Note that fixture's addresses are
    *real-looking* and are not reused here -- see ``AmtState.ethernet_mac_address``.)
    """
    return {
        "ElementName": "Intel(r) AMT Ethernet Port Settings",
        "InstanceID": ETHERNET_PORT_0_INSTANCE_ID,
        "MACAddress": state.ethernet_mac_address,
        "IPAddress": "192.0.2.10",
        "SubnetMask": "255.255.255.0",
        "DefaultGateway": "192.0.2.1",
        "PrimaryDNS": "192.0.2.2",
        "SecondaryDNS": "192.0.2.3",
        "DHCPEnabled": False,
        "LinkIsUp": True,
        "IpSyncEnabled": False,
        "SharedMAC": True,
        "LinkPolicy": list(state.ethernet_link_policy),
    }


def _get_bios_element(state: AmtState) -> dict[str, object]:
    """``CIM_BIOSElement`` -- **NAMES-ONLY**.

    All five names are on the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/cim/bios/element/get.xml``. The values are
    obviously-synthetic on purpose: a BIOS version string is machine-identifying, so this
    serves an ``EXAMPLE``-prefixed one shaped like a real Intel BIOS ID and an
    ``example.invalid`` manufacturer.
    """
    return {
        "ElementName": "Intel(r) AMT: BIOS Element",
        "Name": "MockBIOS",
        "Manufacturer": "Mock Systems (example.invalid)",
        "Version": state.bios_version,
        "PrimaryBIOS": True,
    }


def _get_setup_and_configuration_service(_state: AmtState) -> dict[str, object]:
    """``AMT_SetupAndConfigurationService`` -- **NAMES-ONLY**.

    Every name is on the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/amt/setupandconfiguration/get.xml`` and in the
    class definition ``pkg/wsman/amt/setupandconfiguration/types.go``. Values are this
    mock's own: ``ProvisioningServerOTP`` is emptied rather than carrying the fixture's
    base64 blob, since an OTP is a credential shape and this mock never serves one.

    ``InstanceID`` was **removed**: this class has no such property. It is keyed by
    ``Name`` / ``CreationClassName`` / ``SystemName`` / ``SystemCreationClassName``, all
    four of which the fixture carries and are now served in its place. Nothing in this
    collection read ``InstanceID`` from here -- ``plugins/module_utils/client.py`` reads
    ``ProvisioningMode`` and ``ProvisioningState`` only -- so serving it was pure
    misinformation waiting to be cited.

    ``EnabledState`` and ``RequestedState`` are on the fixture too and are served, because
    a client that reads state off the wrong class should find the right one populated.
    """
    return {
        "CreationClassName": "AMT_SetupAndConfigurationService",
        "ElementName": "Intel(r) AMT Setup and Configuration Service",
        "EnabledState": 5,
        "Name": "Intel(r) AMT Setup and Configuration Service",
        "RequestedState": 12,
        "SystemCreationClassName": "CIM_ComputerSystem",
        "SystemName": "Intel(r) AMT",
        "ProvisioningState": 2,
        "ZeroTouchConfigurationEnabled": False,
        "ProvisioningMode": 1,
        "ProvisioningServerOTP": "",
        "PasswordModel": 0,
        "DhcpDNSSuffix": "",
    }


def _get_computer_system(state: AmtState) -> dict[str, object]:
    """``CIM_ComputerSystem`` -- **INVENTED**. Do not cite this body as evidence.

    There is **no** ``CIM_ComputerSystem`` response fixture in
    ``go-wsman-messages``' ``pkg/wsman/wsmantesting/responses/`` -- the class appears
    there only inside *endpoint references* (as a ``ResourceURI`` plus a ``SelectorSet``),
    never as a returned instance body. So while the class exists and this collection
    reads it (``plugins/module_utils/client.py``'s ``get_facts()``, for
    ``EnabledState`` / ``RequestedState`` / ``OperationalStatus`` / ``ElementName``), the
    field set and every value below are this project's construction.

    The one traceable part is the **selector**, not the body: the power fixture
    ``cim/associatedpower/managementservice/get.xml`` addresses this class with
    ``Selector Name="Name"`` = ``ManagedSystem``, which is where
    ``SELECTOR_MATCH_FOR_GET``'s entry and ``client.py``'s
    ``_MANAGED_SYSTEM_SELECTOR`` both come from. ``Name`` here therefore *is* evidenced;
    ``ElementName``, ``Caption``, and the specific state values are not.

    Marked explicitly because ``tests/integration/targets/amt_info`` asserts
    ``system_state.element_name == 'ManagedSystem'`` against it, and a later reader could
    easily mistake a passing assertion for firmware corroboration. It is not. It only
    proves the client reads what this file writes.
    """
    return {
        "ElementName": "ManagedSystem",
        # Evidenced: the power fixture's EPR selects this class by Name=ManagedSystem.
        "Name": "ManagedSystem",
        "Caption": "Computer System",
        "EnabledState": state.enabled_state,
        "RequestedState": state.requested_state,
        # A CIM array (uint16[]), so a repeated element even when there is one
        # value. A client that reads only the first would pass here and then drop
        # every status after the first on a degraded machine.
        "OperationalStatus": list(state.operational_status),
    }


def _get_message_log(state: AmtState) -> dict[str, object]:
    """``AMT_MessageLog`` -- the log container, not its records.

    Field set, order and values are copied from the real firmware response fixture
    ``go-wsman-messages`` ships at
    ``pkg/wsman/wsmantesting/responses/amt/messagelog/get.xml``, with the two
    record counters made live so they track ``state.message_log_records``:

    * ``MaxRecordSize`` is ``21`` there, independently corroborating the 21-byte
      record struct this collection decodes.
    * ``Capabilities`` is ``[5, 6, 8, 7]`` there, and ``6`` is
      ``ClearLogSupported`` -- firmware stating that ``ClearLog`` is implemented.
    * ``MaxNumberOfRecords`` is ``390`` there, which is where this collection's
      ``MAX_READ_RECORDS`` and default ``max_records`` come from.

    ``CurrentNumberOfRecords`` counts ``state.message_log_records`` and **nothing
    else** -- specifically not ``state.message_log_empty_slots``, which
    ``GetRecords`` does serve. That asymmetry is the point, not an oversight: it is
    what real firmware does (``amt-lab-01`` reported 18 while returning 223 entries)
    and reproducing it is the only way this mock can produce the state that issue
    #105's defect needed.

    Deliberately served for a ``Get`` carrying **no** ``SelectorSet``, because that
    is what the fixture is a response to, and because the instance has no
    ``InstanceID`` property from which a selector could be built. This class is
    therefore absent from ``SELECTOR_MATCH_FOR_GET``.
    """
    return {
        "Capabilities": [5, 6, 8, 7],
        "CharacterSet": 10,
        "CreationClassName": "AMT_MessageLog",
        "CurrentNumberOfRecords": len(state.message_log_records),
        "ElementName": "Intel(r) AMT:MessageLog 1",
        "EnabledDefault": 2,
        "EnabledState": 2,
        "HealthState": 5,
        "IsFrozen": False,
        "LastChange": 0,
        "LogState": 4,
        "MaxLogSize": 0,
        "MaxNumberOfRecords": 390,
        "MaxRecordSize": 21,
        "Name": "Intel(r) AMT:MessageLog 1",
        "OperationalStatus": [2],
        "OverwritePolicy": 2,
        "PercentageNearFull": 100,
        "RequestedState": 12,
        "SizeOfHeader": 0,
        "SizeOfRecordHeader": 0,
        "Status": "OK",
    }


def _get_chassis(state: AmtState) -> dict[str, object]:
    """``CIM_Chassis`` -- **NAMES-ONLY**, with cited enum values.

    Field set is exactly the ten properties on the real firmware response fixture
    ``go-wsman-messages`` ships at
    ``pkg/wsman/wsmantesting/responses/cim/chassis/get.xml``, cross-checked
    against ``pkg/wsman/cim/chassis/types.go``. No property is added and none is
    omitted.

    **Enumeration values carried across from that fixture, and citable as such:**

    * ``ChassisPackageType`` = ``0`` -- the fixture's value. ``0`` is a *defined*
      value (``Unknown``) in ``chassis/decoder.go``, which makes it the single
      most useful value to serve here: a client that renders defined-0 as a bare
      ``unknown`` instead of the value it holds, or that confuses "table says
      unknown" with "value not in table", fails against this.
    * ``PackageType`` = ``3`` -- also the fixture's value, and a *different*
      enumeration (``ChassisFrame``) on the same instance. Serving both at once,
      with different values, is what catches a client that decodes one with the
      other's table. The fixture is the reason they differ here rather than a
      choice of this mock's.
    * ``OperationalStatus`` = ``0`` -- the fixture's value, and a CIM array, so
      emitted as a repeated element.

    **Substituted, and NOT citable:** ``SerialNumber``, ``Model``,
    ``Manufacturer`` and ``Version``. The fixture's are what look like a real
    machine's (``JRQN0243007J``, ``NUC9V7QNX``, ``K47174-402``); this repository
    holds no such data, so obviously-fake stand-ins are served.

    ``Tag`` is served as the literal ``CIM_Chassis`` because **that is what the
    fixture reports** -- the class name, not an asset tag. It is kept verbatim
    precisely because it is the evidence that this class carries no asset tag,
    which is a claim ``docs/amt_info.md`` makes and an integration assertion
    checks.
    """
    return {
        "ChassisPackageType": state.chassis_package_type,
        "CreationClassName": "CIM_Chassis",
        "ElementName": "Managed System Chassis",
        "Manufacturer": "Mock Systems (example.invalid)",
        "Model": "MOCK-CHASSIS-0000",
        "OperationalStatus": [0],
        "PackageType": 3,
        "SerialNumber": state.chassis_serial_number,
        # Verbatim from the fixture: firmware really does put the class name here.
        "Tag": "CIM_Chassis",
        "Version": "MOCK-000-000",
    }


def _get_card(state: AmtState) -> dict[str, object]:
    """``CIM_Card`` -- **NAMES-ONLY**, with cited enum values.

    Field set is exactly the ten properties on the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/cim/card/get.xml``, cross-checked against
    ``pkg/wsman/cim/card/types.go``.

    **Carried across and citable:** ``PackageType`` = ``9`` (``ModuleCard``) and
    ``OperationalStatus`` = ``0``, both the fixture's. ``9`` is deliberately
    *different* from the chassis handler's ``3`` above -- both come from their
    respective fixtures, and serving two different values through one shared
    table is how a client that hard-codes either gets caught.
    ``CanBeFRUed`` = ``true``, also the fixture's.

    **Substituted:** serial, model, manufacturer and version, for the same reason
    as ``_get_chassis``. The board serial served here is deliberately *different*
    from the chassis serial, as it is on the real fixtures -- a client that
    reported one for the other would otherwise pass.

    ``Tag`` is again the class name, verbatim from the fixture.

    ``SerialNumber`` is the one field here whose *absence* is configurable, and it
    is the only field in this mock for which that is true. Both lab machines return
    this class populated with manufacturer, model and version and **no serial**
    (issue #84), while the vendor fixture carries one -- so the fixture establishes
    that the property exists and establishes nothing about whether a given firmware
    fills it in. ``state.baseboard_serial_number`` of ``None`` omits the element and
    ``""`` emits it empty, which are two different firmware behaviours that produce
    the same ``null`` fact. See :class:`AmtState`.
    """
    return {
        "CanBeFRUed": True,
        "CreationClassName": "CIM_Card",
        "ElementName": "Managed System Base Board",
        "Manufacturer": "Mock Systems (example.invalid)",
        "Model": "MOCK-BOARD-0000",
        "OperationalStatus": [0],
        "PackageType": 9,
        "SerialNumber": state.baseboard_serial_number,
        "Tag": "CIM_Card",
        "Version": "MOCK-000-001",
    }


def _get_alarm_clock_service(_state: AmtState) -> dict[str, object]:
    """``AMT_AlarmClockService`` -- **FIRMWARE-DERIVED**, field set and values both.

    Every value is verbatim from the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/amt/alarmclock/get.xml``, which contains no
    identifying data at all -- the five properties are the class name, the scoping
    system's class and name, and a constant Intel product string.

    **``NextAMTAlarmTime`` and ``AMTAlarmClockInterval`` are deliberately absent.**
    go-wsman-messages' ``AlarmClockService`` struct declares both, and the captured
    response from real firmware omits both -- even on a system that could have had
    an alarm set. Serving them because a Go struct mentions them would be this mock
    asserting a shape no firmware has been observed to produce, and it would hide
    the exact thing the client has to cope with: a service instance that says
    nothing about the alarms it holds, which is why convergence reads the
    occurrence list instead. ``plugins/module_utils/alarm.py``'s ``get_service``
    docstring records the same finding from the other side.
    """
    return {
        "CreationClassName": "AMT_AlarmClockService",
        "ElementName": "Intel(r) AMT Alarm Clock Service",
        "Name": "Intel(r) AMT Alarm Clock Service",
        "SystemCreationClassName": "CIM_ComputerSystem",
        "SystemName": "ManagedSystem",
    }


def _get_time_synchronization_service(state: AmtState) -> dict[str, object]:
    """``AMT_TimeSynchronizationService`` -- **FIRMWARE-DERIVED**, field set and values.

    Verbatim from ``pkg/wsman/wsmantesting/responses/amt/timesynchronization/get.xml``,
    which likewise carries nothing identifying. ``TimeSource`` and
    ``LocalTimeSyncEnabled`` come from :class:`AmtState` so a test can serve a
    defined non-default value and an undefined one, but their **defaults are that
    fixture's** (``0`` and ``0``) rather than values picked here.

    ``TimeSource`` 0 is the value that matters for the alarm clock and is why this
    class is served at all: go-wsman-messages names it ``TimeSourceBiosRTC`` and
    documents the property as "Determines if RTC was set to UTC by any
    configuration SW", so a machine reporting 0 is one whose clock is whatever the
    platform RTC holds -- not necessarily UTC. See docs/protocol-notes.md §2.10.
    """
    return {
        "CreationClassName": "AMT_TimeSynchronizationService",
        "ElementName": "Intel(r) AMT Time Synchronization Service",
        "EnabledState": 5,
        "LocalTimeSyncEnabled": state.time_sync_local_enabled,
        "Name": "Intel(r) AMT Time Synchronization Service",
        "RequestedState": 12,
        "SystemCreationClassName": "CIM_ComputerSystem",
        "SystemName": "Intel(r) AMT",
        "TimeSource": state.time_sync_time_source,
    }


GET_HANDLERS: dict[str, Callable[[AmtState], dict[str, object]]] = {
    CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE: _get_power,
    AMT_ALARM_CLOCK_SERVICE: _get_alarm_clock_service,
    AMT_TIME_SYNCHRONIZATION_SERVICE: _get_time_synchronization_service,
    AMT_MESSAGE_LOG: _get_message_log,
    AMT_BOOT_SETTING_DATA: lambda state: dict(state.boot_setting_data),
    AMT_BOOT_CAPABILITIES: _get_boot_capabilities,
    AMT_REDIRECTION_SERVICE: _get_redirection,
    AMT_GENERAL_SETTINGS: _get_general_settings,
    AMT_SETUP_AND_CONFIGURATION_SERVICE: _get_setup_and_configuration_service,
    CIM_COMPUTER_SYSTEM: _get_computer_system,
    AMT_ETHERNET_PORT_SETTINGS: _get_ethernet_port_settings,
    CIM_BIOS_ELEMENT: _get_bios_element,
    # Both hardware singletons answer Get, which is how MeshCentral fetches them
    # (`*CIM_Chassis`/`*CIM_Card` in amtmanager.js's BatchEnum -- the `*` prefix
    # means "Get instead of Enumerate, to reduce round trips"). Both also answer
    # Enumerate, via ENUMERATE_HANDLERS: the fixture set ships get.xml AND
    # enumerate.xml+pull.xml for each, so both verbs are directly evidenced and a
    # client is entitled to use either.
    CIM_CHASSIS: _get_chassis,
    CIM_CARD: _get_card,
}


# --------------------------------------------------------------------------
# Method (CIM/AMT Method_INPUT) handlers -- return (ReturnValue, extra body xml)
# --------------------------------------------------------------------------


def _method_request_power_state_change(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    """``CIM_PowerManagementService.RequestPowerStateChange`` (docs/protocol-notes.md §2.4).

    ``PowerState`` is required: it is the entire content of the request, and firmware
    cannot transition to a state it was not told. Absent or non-numeric is
    ``InvalidParameter``, not success. ``ManagedElement`` is an EPR-typed parameter (this
    collection sends the ``CIM_ComputerSystem`` ``Name=ManagedSystem`` reference) and is
    shape-checked when present -- an empty ``<ManagedElement/>`` is the same schema
    violation as an empty ``<Source/>``.

    ``ManagedElement`` being *absent* is left permissive: it is optional in the same
    ``minOccurs=0`` sense as ``Source`` and nothing establishes that firmware refuses a
    request that omits it, given there is one managed system.
    """
    _optional_endpoint_reference(body_elem, "ManagedElement")

    requested = _param_text(body_elem, "PowerState")
    if requested is None:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    try:
        code = int(requested)
    except ValueError:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    if code not in POWER_ACTION_TO_STATE:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    new_state = POWER_ACTION_TO_STATE[code]
    if new_state is not None:
        state.power_state = new_state
    return 0, ""


def _method_change_boot_order(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    """``CIM_BootConfigSetting.ChangeBootOrder`` (docs/protocol-notes.md §2.5 steps 2 and 5).

    Two distinct requests, and firmware treats them very differently:

    * **No ``Source`` element at all** -- clear the boot order. Valid, ``ReturnValue 0``.
      This is step 2, and step 5 for the IDE-R and BIOS-setup targets.
    * **An empty ``<Source/>``** -- **HTTP 400**, schema violation. See
      :func:`_require_endpoint_reference` for the evidence; this is the regression the
      capability matrix credits hardware qualification with finding and that this mock
      previously answered with ``ReturnValue 0``.

    A well-formed ``Source`` that names no ``InstanceID`` selector is *not* rejected: the
    EPR satisfies the schema, so any complaint would be semantic, and what firmware
    returns for it is not established. It records ``None``, same as a cleared order, and
    is called out here rather than guessed at.
    """
    source = _optional_endpoint_reference(body_elem, "Source")
    state.boot_order_source = _endpoint_reference_instance_id(source) if source is not None else None
    return 0, ""


def _method_set_boot_config_role(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    """``CIM_BootService.SetBootConfigRole`` (docs/protocol-notes.md §2.5 step 4).

    ``Role`` is required. This mock used to answer ``ReturnValue 0`` when it was absent
    entirely, which is impossible on any reading: firmware cannot assign a role it was
    not given, so the only question is *how* it refuses, not whether. It refuses here with
    ``InvalidParameter`` rather than an HTTP 400, deliberately: §2.5 records these method
    parameters as ``minOccurs=0`` in the WS-CIM binding, so a missing element is a
    semantic rejection rather than a schema violation. Both reference implementations
    always send it (go-wsman-messages' ``pkg/wsman/cim/boot/service.go``, MeshCmd).

    ``BootConfigSetting`` is EPR-typed and shape-checked when present. Absent is left
    permissive for the same reason as ``ManagedElement`` above -- there is exactly one
    ``CIM_BootConfigSetting`` instance, and no evidence says firmware insists on being
    handed a reference to it.
    """
    _optional_endpoint_reference(body_elem, "BootConfigSetting")

    role_text = _param_text(body_elem, "Role")
    if role_text is None:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    try:
        state.boot_config_role = int(role_text)
    except ValueError:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    return 0, ""


def _method_request_redirection_state_change(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    """``AMT_RedirectionService.RequestStateChange`` (docs/protocol-notes.md §2.6).

    ``RequestedState`` is required and must be one of the four documented values;
    anything else is ``InvalidParameter``.
    """
    requested = _param_text(body_elem, "RequestedState")
    if requested is None:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    try:
        value = int(requested)
    except ValueError:
        return RETURN_VALUE_INVALID_PARAMETER, ""
    if value not in (32768, 32769, 32770, 32771):
        return RETURN_VALUE_INVALID_PARAMETER, ""
    state.redirection_enabled_state = value
    state.redirection_listener_enabled = value != 32768
    return 0, ""


def _message_log_served_records(state: AmtState) -> list[str]:
    """What ``GetRecords`` actually puts on the wire: the real records, then the padding.

    Padding goes **after** the real records because that is where firmware put it --
    on ``amt-lab-01`` the 205 zero slots were contiguous and strictly trailing, all
    18 real records first (CircleCI job 2976). No source describes this padding at
    all, so no other placement is served here: a mock that interleaved slots would be
    asserting a firmware behaviour nobody has observed. The interleaved case is
    covered where it can be constructed honestly rather than served as firmware --
    against a fake transport in
    ``tests/unit/plugins/module_utils/test_message_log.py``.

    Note what this does *not* touch: ``_get_message_log``'s
    ``CurrentNumberOfRecords`` still counts ``state.message_log_records`` only. The
    disagreement between that counter and the length of this list is the entire state
    under test.
    """
    if state.message_log_empty_slots <= 0:
        return list(state.message_log_records)
    return list(state.message_log_records) + [EMPTY_MESSAGE_LOG_SLOT] * state.message_log_empty_slots


def _method_position_to_first_record(state: AmtState, _body_elem: ET.Element | None) -> tuple[int, str]:
    """``AMT_MessageLog.PositionToFirstRecord`` -- establish an iteration.

    Takes no input parameters (MeshCentral's ``AMT_MessageLog_PositionToFirstRecord``
    passes none, and the fixture request body is an empty
    ``PositionToFirstRecord_INPUT``). Returns ``IterationIdentifier`` 1 -- the
    position of the first record, per go-wsman-messages' ``GetRecords`` doc comment
    ("a numeric value (starting at 1) which is the position of the first record") --
    and the fixture's own ``IterationIdentifier`` is likewise ``1``.

    An empty log answers ``ReturnValue`` 2 ("No record exists"), **not** 3: that is
    ``GetRecords``' value for the same condition. A client that only handles one of
    the two must fail here rather than in production.

    Keyed on ``_message_log_served_records`` rather than on ``message_log_records``,
    so this method and ``GetRecords`` can never contradict each other: a
    ``PositionToFirstRecord`` answering "no record exists" while ``GetRecords`` would
    hand back padding is an internally inconsistent endpoint no firmware could be.
    """
    if not _message_log_served_records(state):
        return POSITION_TO_FIRST_RECORD_NO_RECORDS, "<r:IterationIdentifier>1</r:IterationIdentifier>"
    return 0, "<r:IterationIdentifier>1</r:IterationIdentifier>"


def _method_get_records(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    """``AMT_MessageLog.GetRecords`` -- one batch of base64 records.

    Input is ``IterationIdentifier`` (1-based position of the first record to
    return) and ``MaxReadRecords``. Output is ``IterationIdentifier`` (where to
    continue from), ``NoMoreRecords``, a repeated ``RecordArray``, and
    ``ReturnValue`` -- in that order, per ``EXTRA_BEFORE_RETURN_VALUE``.

    This mock caps a batch at ``MESSAGE_LOG_BATCH_SIZE`` regardless of what the
    client asked for, so following the iteration across several round trips is
    actually exercised. Firmware may legitimately return fewer records than
    requested; that is precisely why ``NoMoreRecords`` exists and why a client must
    not infer completion from a short batch.

    The next ``IterationIdentifier`` is ``identifier + len(batch)``, which is the
    only arithmetic consistent with a 1-based position. Note the real fixture
    returns ``3`` after serving 3 records from position 1, which does not fit that
    rule -- so firmware's exact bookkeeping is *not* established, and a client must
    treat the returned identifier as opaque and feed it back verbatim, which is
    what MeshCentral does and what this collection does. This mock deliberately
    does not reproduce the fixture's unexplained value, because doing so would bake
    an arithmetic no client should rely on into the only place it could be relied on.

    What is served is ``_message_log_served_records`` -- the real records **plus**
    however many zero-filled empty slots ``state.message_log_empty_slots`` asks for.
    Every position here, including ``NoMoreRecords``, is computed against that list
    and not against ``message_log_records``, because on real firmware the padding is
    genuinely part of the array ``GetRecords`` returns while being absent from
    ``CurrentNumberOfRecords``.
    """
    served = _message_log_served_records(state)
    if not served:
        return GET_RECORDS_NO_RECORDS, "<r:IterationIdentifier>1</r:IterationIdentifier><r:NoMoreRecords>true</r:NoMoreRecords>"

    identifier = 1
    raw_identifier = _param_text(body_elem, "IterationIdentifier")
    if raw_identifier is not None:
        try:
            identifier = int(raw_identifier)
        except ValueError:
            return 2, ""  # "Invalid record pointed"
    max_read = MESSAGE_LOG_BATCH_SIZE
    raw_max = _param_text(body_elem, "MaxReadRecords")
    if raw_max is not None:
        try:
            max_read = max(1, min(MESSAGE_LOG_BATCH_SIZE, int(raw_max)))
        except ValueError:
            return 2, ""

    start = identifier - 1
    if start < 0 or start >= len(served):
        return 2, ""  # "Invalid record pointed"

    batch = served[start : start + max_read]
    next_identifier = identifier + len(batch)
    no_more = next_identifier > len(served)
    records_xml = "".join(f"<r:RecordArray>{escape(record)}</r:RecordArray>" for record in batch)
    extra = f"<r:IterationIdentifier>{next_identifier}</r:IterationIdentifier><r:NoMoreRecords>{'true' if no_more else 'false'}</r:NoMoreRecords>{records_xml}"
    return 0, extra


def _method_clear_log(state: AmtState, _body_elem: ET.Element | None) -> tuple[int, str]:
    """``AMT_MessageLog.ClearLog`` -- irreversibly empty the log.

    Takes no input parameters: MeshCentral's ``AMT_MessageLog_ClearLog`` passes an
    empty parameter object. The mutation is real, so a later
    ``Get AMT_MessageLog`` observes ``CurrentNumberOfRecords`` 0 in the same running
    server -- which is what lets the integration target assert the before/after
    receipt rather than trusting ``ReturnValue`` alone.
    """
    state.message_log_records.clear()
    return 0, ""


#: The ``ReturnValue`` this mock uses when ``AddAlarm`` is refused.
#:
#: **INVENTED, and the only invented value in the alarm-clock handlers.** No source
#: names any ``AddAlarm`` return code except ``0: Success`` -- go-wsman-messages'
#: ``pkg/wsman/amt/alarmclock/decoder.go`` defines exactly one entry in
#: ``returnValueToString``, and no captured response shows a failure. So a mock that
#: must refuse *something* has to pick a number, and this one is chosen to be
#: obviously not a DMTF code. It is served only for the two refusals real firmware is
#: documented or reported to make (the occurrence limit, and a duplicate key); the
#: client under test never decodes it, only reports it raw, which is exactly what it
#: would have to do against firmware.
ADD_ALARM_REFUSED_RETURN_VALUE = 2054


def _method_add_alarm(state: AmtState, body_elem: ET.Element | None) -> tuple[int, str]:
    """``AMT_AlarmClockService.AddAlarm`` -- create one ``IPS_AlarmClockOccurrence``.

    Parses the embedded ``AlarmTemplate`` the same way firmware must: by local
    element name, across three namespaces (the template in the
    ``AMT_AlarmClockService`` namespace, its properties in the
    ``IPS_AlarmClockOccurrence`` one, and ``Datetime``/``Interval`` in the DMTF
    common one). See docs/protocol-notes.md §2.10 for the wire shape and the two
    sources it is transcribed from.

    Two refusals, both with evidence:

    * **The occurrence limit.** go-wsman-messages' ``service.go`` states on this very
      method: "The method would fail if 5 instances or more of
      ``IPS_AlarmClockOccurrence`` already exist in the system."
    * **A duplicate ``InstanceID``.** ``InstanceID`` is the instance key, so a second
      instance under the same key cannot exist. What firmware *returns* for the
      attempt is unknown; that it cannot succeed is not. This is what forces a client
      changing an existing alarm to delete first -- and the reason
      ``plugins/module_utils/alarm.py``'s replace path is delete-then-add rather than
      add-over-the-top.

    Deliberately **not** refused here: a past-dated ``StartTime``. MeshCentral's
    meshcmd prints "Verify the alarm is for a future time" on failure, which is a
    hint rather than a specification, and no fixture or class definition says what
    firmware does. Inventing that rejection would make this mock the source of a
    behaviour claim nothing supports -- and would make the client's own past-date
    refusal untestable, since the mock would refuse first. The client refuses
    past-dated alarms itself, before sending, and that is where the check is tested.

    The success output carries ``AlarmClock`` (an endpoint reference to the created
    instance) before ``ReturnValue``, matching
    ``responses/amt/alarmclock/addalarm.xml``. See ``EXTRA_BEFORE_RETURN_VALUE``.
    """
    template = _param(body_elem, "AlarmTemplate")
    if template is None:
        # An AddAlarm with no template is schema-invalid, and real AMT answers HTTP
        # 400 to a schema-invalid body rather than a SOAP fault (§2.5).
        raise _schema_violation()

    # Every property is read at its exact namespace, never by local name alone -- see
    # _param_in. A client that put InstanceID in the AMT_AlarmClockService namespace
    # instead of the IPS_AlarmClockOccurrence one fails here, which is what firmware's
    # schema validation would do.
    instance_id = _param_text_in(template, IPS_ALARM_CLOCK_OCCURRENCE, "InstanceID")
    if not instance_id:
        raise _schema_violation()
    start_time = _param_text_in(_param_in(template, IPS_ALARM_CLOCK_OCCURRENCE, "StartTime"), NS_CIM_COMMON, "Datetime")
    if not start_time:
        raise _schema_violation()

    if instance_id in state.alarm_occurrences:
        return ADD_ALARM_REFUSED_RETURN_VALUE, ""
    if len(state.alarm_occurrences) >= state.alarm_occurrence_limit:
        return ADD_ALARM_REFUSED_RETURN_VALUE, ""

    element_name = _param_text_in(template, IPS_ALARM_CLOCK_OCCURRENCE, "ElementName")
    # An absent Interval is legitimate rather than a schema violation: MeshCentral's
    # amt.js omits the element entirely for a one-shot alarm. Stored as None, which is
    # then how the Enumerate reports it back -- so a client must cope with the property
    # being missing, not merely with it being P0DT0H0M.
    interval = _param_text_in(_param_in(template, IPS_ALARM_CLOCK_OCCURRENCE, "Interval"), NS_CIM_COMMON, "Interval")
    delete_on_completion = (_param_text_in(template, IPS_ALARM_CLOCK_OCCURRENCE, "DeleteOnCompletion") or "").lower() in ("true", "1")

    state.alarm_occurrences[instance_id] = {
        "InstanceID": instance_id,
        "ElementName": element_name or instance_id,
        "StartTime": start_time,
        "Interval": interval,
        "DeleteOnCompletion": delete_on_completion,
    }
    # The reference address in the vendor's captured response is the literal string
    # "default", which is what firmware really sent -- not a URL. Reproduced verbatim
    # rather than tidied into something that looks more like an EPR.
    extra = (
        "<r:AlarmClock>"
        "<r:Address>default</r:Address>"
        "<r:ReferenceParameters>"
        f"<w:ResourceURI>{escape(IPS_ALARM_CLOCK_OCCURRENCE)}</w:ResourceURI>"
        f'<w:SelectorSet><w:Selector Name="InstanceID">{escape(instance_id)}</w:Selector></w:SelectorSet>'
        "</r:ReferenceParameters>"
        "</r:AlarmClock>"
    )
    return 0, extra


def _method_get_low_accuracy_time_synch(state: AmtState, _body_elem: ET.Element | None) -> tuple[int, str]:
    """``AMT_TimeSynchronizationService.GetLowAccuracyTimeSynch`` -- read firmware's RTC.

    Returns ``Ta0``, Unix epoch seconds. The vendor's captured response
    (``responses/amt/timesynchronization/getlowaccuracytimesynch.xml``) reports
    ``1704586865``, which reads as 2024-01-07T00:21:05Z -- the same epoch and units
    as the ``AMT_MessageLog`` record timestamps, which is what lets this collection
    reuse that decoder's basis.

    ``Ta0`` precedes ``ReturnValue`` in that fixture, so this method is in
    ``EXTRA_BEFORE_RETURN_VALUE``. ``state.time_sync_ta0 is None`` omits ``Ta0``
    entirely while still returning ``ReturnValue`` 0 -- a shape no source describes,
    served so the client's "firmware would not say" branch is reachable over a real
    socket rather than only where a unit test fakes the transport.
    """
    if state.time_sync_ta0 is None:
        return 0, ""
    return 0, f"<r:Ta0>{state.time_sync_ta0}</r:Ta0>"


METHOD_HANDLERS: dict[tuple[str, str], Callable[[AmtState, ET.Element | None], tuple[int, str]]] = {
    (CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange"): _method_request_power_state_change,
    (AMT_ALARM_CLOCK_SERVICE, "AddAlarm"): _method_add_alarm,
    (AMT_TIME_SYNCHRONIZATION_SERVICE, "GetLowAccuracyTimeSynch"): _method_get_low_accuracy_time_synch,
    (CIM_BOOT_CONFIG_SETTING, "ChangeBootOrder"): _method_change_boot_order,
    (CIM_BOOT_SERVICE, "SetBootConfigRole"): _method_set_boot_config_role,
    (AMT_REDIRECTION_SERVICE, "RequestStateChange"): _method_request_redirection_state_change,
    (AMT_MESSAGE_LOG, "PositionToFirstRecord"): _method_position_to_first_record,
    (AMT_MESSAGE_LOG, "GetRecords"): _method_get_records,
    (AMT_MESSAGE_LOG, "ClearLog"): _method_clear_log,
}


# --------------------------------------------------------------------------
# Enumerate/Pull item generators
# --------------------------------------------------------------------------


def _boot_source_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_BootSourceSetting`` -- **FIRMWARE-DERIVED** field set.

    Matched to the real firmware response fixture
    ``pkg/wsman/wsmantesting/responses/cim/boot/sourcesetting/pull.xml``, which returns
    three instances each carrying exactly ``ElementName``, ``FailThroughSupported``,
    ``InstanceID``, ``StructuredBootString`` -- alphabetically, as
    ``_fields_to_instance_xml`` now emits.

    Three corrections, all client-visible:

    * ``BootSourceIndex`` was **removed**. The property does not exist on this class:
      ``pkg/wsman/cim/boot/types.go``'s ``BootSourceSetting`` declares ``ElementName``,
      ``InstanceID``, ``StructuredBootString``, ``BIOSBootString``, ``BootString`` and
      ``FailThroughSupported``, and no index property of any name. Nothing in this
      collection read it -- ``plugins/module_utils/boot.py``'s ``discover_and_validate()``
      matches on ``InstanceID`` alone -- so it was inventing a property firmware does not
      send.
    * ``StructuredBootString`` was equal to the instance label, which is the wrong shape
      entirely. Firmware sends ``"<OrgID>:<identifier>:<index>"`` per that class
      definition, with DMTF identifiers ``Floppy``, ``Hard-Disk``, ``CD/DVD``, ``Network``,
      ``PCMCIA``, ``USB`` and ``OrgID`` = ``CIM``. The fixture confirms three of them
      verbatim: ``CIM:Hard-Disk:1``, ``CIM:Network:1``, ``CIM:CD/DVD:1``. See
      :data:`BOOT_SOURCE_STRUCTURED_STRINGS`.
    * ``ElementName`` was the instance label. Firmware sends the *same* ``ElementName``
      for all three instances -- ``"Intel(r) AMT: Boot Source"`` -- and distinguishes them
      by ``InstanceID`` only. A client keying off ``ElementName`` to tell boot sources
      apart would have passed here and then matched every instance on real firmware.

    ``state.boot_source_count`` sizes the served set in both directions, and each direction is
    a distinct client-visible verdict in ``plugins/module_utils/boot.py``'s
    ``discover_and_validate()`` (protocol-notes.md §2.5: "confirm exactly one instance matches
    the requested target ... Fail with unsupported_capability if absent or ambiguous"):

    * **Below** ``len(BOOT_SOURCE_NAMES)`` the tail names are simply not served, which is how a
      test reaches the "absent" verdict -- firmware whose boot list is shorter than the set of
      targets the module offers.
    * **Above** it, extra instances are synthesised, repeating the names with an ``" (<idx>)"``
      suffix. Note precisely what that does and does not produce: the suffix keeps every
      ``InstanceID`` **distinct**, so it cannot make discovery ambiguous for a client that
      matches on equality -- the wording here previously claimed it could, and was wrong. What
      it does produce is a near-miss neighbour for each known name, which a client matching on
      prefix or substring rather than equality would count twice.

    Synthesised instances carry no ``StructuredBootString``, because there is no firmware shape
    to copy for an instance firmware would never emit.
    """
    count = state.boot_source_count
    names = [BOOT_SOURCE_NAMES[i % len(BOOT_SOURCE_NAMES)] for i in range(count)]
    items = []
    for idx, name in enumerate(names):
        label = name if idx < len(BOOT_SOURCE_NAMES) else f"{name} ({idx})"
        fields: dict[str, object] = {
            "ElementName": BOOT_SOURCE_ELEMENT_NAME,
            "FailThroughSupported": FAIL_THROUGH_SUPPORTED_NOT_SUPPORTED,
            "InstanceID": label,
        }
        structured = BOOT_SOURCE_STRUCTURED_STRINGS.get(label)
        if structured is not None:
            fields["StructuredBootString"] = structured
        items.append(_fields_to_instance_xml(CIM_BOOT_SOURCE_SETTING, fields))
    return items


def _boot_capabilities_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``AMT_BootCapabilities``, sharing ``_get_boot_capabilities``'s
    fields with the ``Get`` form (``GET_HANDLERS``) so both verbs report identically.

    AMT_BootCapabilities has no natural instance key, so real WS-Man implementations
    (and this collection's own client code -- ``plugins/module_utils/boot.py``'s
    ``discover_and_validate()`` and ``plugins/module_utils/redirection_service.py``'s
    ``get_capabilities()``) reach it via Enumerate+Pull, not Get with a SelectorSet.
    ``plugins/module_utils/client.py``'s facts-gathering path (``amt_info``) happens to
    use ``Get`` instead, which is why a ``GET_HANDLERS`` entry exists too -- this mock
    must answer both verbs the same way, or a client written against one of them starts
    failing the moment it is exercised against a real WS-Man endpoint's actual required
    verb. Found via the ``amt_boot``/``amt_redirection`` integration targets: unit tests
    mocking ``WsmanClient.enumerate()`` directly never exercised this mock server's own
    ``Enumerate`` dispatch table for this resource, so the gap went unnoticed until a
    real Enumerate request actually hit this server.
    """
    return [_fields_to_instance_xml(AMT_BOOT_CAPABILITIES, _get_boot_capabilities(state))]


def _bios_element_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_BIOSElement``, sharing ``_get_bios_element``'s fields.

    Both verbs are served for the same reason ``AMT_BootCapabilities`` is (see
    ``_boot_capabilities_items``): this class has no obvious singleton selector,
    so whether real firmware answers a bare ``Get``, an ``Enumerate``, or both is
    not established by any evidence this collection has. ``AmtClient`` tries
    ``Get`` and falls back to ``Enumerate``, and the ``bios_element_get_faults``
    knob exists so the fallback is exercised against a real server rather than
    only where a unit test mocks the client's own transport.
    """
    return [_fields_to_instance_xml(CIM_BIOS_ELEMENT, _get_bios_element(state))]


def _message_log_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``AMT_MessageLog``, sharing ``_get_message_log``'s fields.

    Both verbs are served because real firmware answers both: the fixture set at
    ``responses/amt/messagelog/`` contains ``get.xml`` *and* ``enumerate.xml`` +
    ``pull.xml``, all returning the same instance. That makes ``AMT_MessageLog``
    unusual among ``AMT_``-prefixed classes, where ``Enumerate`` is HTTP 400 on
    AMT 10 (``docs/protocol-notes.md`` §2.7).

    ``plugins/module_utils/message_log.py``'s ``get_log_properties()`` tries ``Get``
    then falls back to ``Enumerate``, and it needs both paths to be real here for
    the same reason ``_boot_capabilities_items`` exists: a client written against
    one verb starts failing the moment it meets firmware that only serves the other,
    and a unit test that mocks the transport never notices.
    """
    return [_fields_to_instance_xml(AMT_MESSAGE_LOG, _get_message_log(state))]


def _chassis_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_Chassis``, sharing ``_get_chassis``'s fields.

    Both verbs are served because the fixture set directly evidences both:
    ``responses/cim/chassis/`` ships ``get.xml``, ``enumerate.xml`` and
    ``pull.xml``. ``AmtClient`` tries ``Get`` and falls back to ``Enumerate``
    (following ``CIM_BIOSElement``'s precedent), and the
    ``chassis_get_faults`` knob exists so the fallback is exercised over a real
    socket rather than only where a unit test mocks the transport away -- the
    exact gap that let a Get-only mock hide an Enumerate-only class once before.
    """
    return [_fields_to_instance_xml(CIM_CHASSIS, _get_chassis(state))]


def _card_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_Card``, sharing ``_get_card``'s fields.

    Same reasoning as ``_chassis_items``: ``responses/cim/card/`` ships
    ``get.xml``, ``enumerate.xml`` and ``pull.xml``, so both verbs are evidenced
    and both must answer identically here.

    Note ``responses/cim/physical/package/pull.xml`` -- the ``Enumerate`` of
    ``CIM_PhysicalPackage`` -- returns a ``CIM_Card`` instance, because
    ``CIM_Card`` and ``CIM_Chassis`` are both subclasses of it. That is why this
    mock serves no ``CIM_PhysicalPackage`` handler at all: it would return these
    same two instances under a third resource URI, adding a round trip and no
    information. Stated here rather than left as an unexplained absence.
    """
    return [_fields_to_instance_xml(CIM_CARD, _get_card(state))]


def _processor_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_Processor`` -- **NAMES-ONLY**, with cited enum values.

    Field set is exactly the eighteen properties on the real firmware response
    fixtures ``pkg/wsman/wsmantesting/responses/cim/physical/processor/get.xml``
    and ``.../pull.xml`` (identical sets), cross-checked against
    ``pkg/wsman/cim/processor/types.go``.

    **There is no core count or thread count**, on the fixtures or in the class
    definition, so none is served. Adding one would be inventing a property AMT
    does not implement -- the same defect as the ``BootSourceIndex`` this file
    removed from ``_boot_source_items``.

    **Enumeration and numeric values carried across from the fixture, citable:**

    * ``Family`` = ``198``. Served precisely *because* this collection does not
      decode it: the integration target asserts it comes through raw, and 198 is
      what real firmware actually reported.
    * ``UpgradeMethod`` = ``52`` -- ``SocketBGA1515`` in
      ``processor/decoder.go``, a soldered part, consistent with the NUC the rest
      of that fixture set describes.
    * ``CPUStatus`` = ``1`` (``CPUEnabled``), ``HealthState`` = ``0``
      (``Unknown``, a defined value), ``EnabledState`` = ``2`` (``Enabled``),
      ``RequestedState`` = ``12``, ``OperationalStatus`` = ``0``.
      ``EnabledState`` 2 matters: ``go-wsman-messages``' own ``processor``
      ``enabledStateMap`` omits 0, 1 and 2, so its decoder answers "Value not
      found in map" for this very fixture. This collection decodes it with the
      full DMTF table instead, and serving the fixture's 2 is what proves that.
    * ``MaxClockSpeed`` ``8300``, ``CurrentClockSpeed`` ``2400``,
      ``ExternalBusClockSpeed`` ``100``, ``Stepping`` ``13``, ``Role``
      ``Central`` -- all the fixture's. ``Stepping`` is a *string* property per
      the class definition even though it looks numeric, and is served as one.
    * ``OtherFamilyDescription`` empty, as on the fixture -- which is correct,
      since it is only populated when ``Family`` is 1.

    Nothing here is identity-shaped, so nothing needed substituting; ``DeviceID``
    is ``CPU 0``, a slot label, not a serial. ``state.processor_count`` lets a
    test ask for a multi-socket machine, with ``DeviceID`` indexed the way the
    fixture's single instance is.
    """
    items = []
    for index in range(state.processor_count):
        items.append(
            _fields_to_instance_xml(
                CIM_PROCESSOR,
                {
                    "CPUStatus": 1,
                    "CreationClassName": "CIM_Processor",
                    "CurrentClockSpeed": 2400,
                    "DeviceID": f"CPU {index}",
                    "ElementName": "Managed System CPU",
                    "EnabledState": 2,
                    "ExternalBusClockSpeed": 100,
                    "Family": 198,
                    "HealthState": 0,
                    "MaxClockSpeed": 8300,
                    "OperationalStatus": [0],
                    "OtherFamilyDescription": "",
                    "RequestedState": 12,
                    "Role": "Central",
                    "Stepping": "13",
                    "SystemCreationClassName": "CIM_ComputerSystem",
                    "SystemName": "ManagedSystem",
                    "UpgradeMethod": 52,
                },
            )
        )
    return items


def _chip_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_Chip`` -- **NAMES-ONLY**.

    Field set is exactly the seven properties on the real firmware response
    fixtures ``pkg/wsman/wsmantesting/responses/cim/chip/{get,pull}.xml``,
    cross-checked against ``pkg/wsman/cim/chip/types.go``.

    **Carried across and citable:** ``CanBeFRUed`` ``true``,
    ``OperationalStatus`` ``0``, ``ElementName`` ``Managed System Processor
    Chip`` and ``Tag`` ``CPU 0``. ``ElementName`` in particular is the field a
    caller uses to tell a processor chip from a memory chip, since
    ``CIM_PhysicalMemory`` is a subclass of this class -- so its exact value is
    worth serving verbatim.

    **Substituted:** ``Version``. On the fixture it is
    ``Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz`` -- a real processor model from a
    real machine. An obviously-fake stand-in is served in the same *shape*,
    because the shape is the point: this is the field that carries the
    human-readable processor name, which ``CIM_Processor`` cannot supply, and it
    is the whole reason this class is read.

    Only processor chips are served, matching the fixture, which returns exactly
    one item despite the same machine having two DIMMs. That is *not* a claim that
    firmware never returns memory chips here -- one fixture cannot establish that
    -- which is why the client reports these instances unfiltered.
    """
    items = []
    for index in range(state.processor_count):
        items.append(
            _fields_to_instance_xml(
                CIM_CHIP,
                {
                    "CanBeFRUed": True,
                    "CreationClassName": "CIM_Chip",
                    "ElementName": "Managed System Processor Chip",
                    "Manufacturer": "Mock Systems (example.invalid)",
                    "OperationalStatus": [0],
                    "Tag": f"CPU {index}",
                    "Version": "Mock(R) Example(TM) CPU E0000 @ 2.40GHz",
                },
            )
        )
    return items


def _physical_memory_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_PhysicalMemory`` -- **NAMES-ONLY**, cited enums.

    Field set is exactly the fifteen properties on the real firmware response
    fixture ``pkg/wsman/wsmantesting/responses/cim/physical/memory/pull.xml``
    (which returns two instances, ``BANK 0`` and ``BANK 2``), cross-checked
    against ``pkg/wsman/cim/physical/types.go``.

    **Enumeration and numeric values carried across, citable:**

    * ``MemoryType`` = ``26``. That is ``DDR4`` in ``physical/decoder.go``, and
      the fixture's part number is a DDR4 SODIMM -- so this single value
      cross-checks the table against firmware rather than only against itself.
    * ``FormFactor`` = ``13``. Served precisely *because* this collection refuses
      to decode it: 13 is ``SODIMM`` under SMBIOS type 17 and ``SRIMM`` under the
      DMTF ``CIM_PhysicalMemory.FormFactor`` ValueMap, the fixture's part really
      is a SODIMM, and no vendor map exists to settle it. The integration target
      asserts it arrives raw with no name attached.
    * ``Capacity`` = ``17179869184`` -- 16 GiB exactly, which corroborates the
      class definition's claim that the unit is bytes.
    * ``Speed`` = ``0`` with ``IsSpeedInMhz`` = ``true`` and ``MaxMemorySpeed`` =
      ``2400``. **This combination is the single most valuable thing in this
      handler.** It is what real firmware reported, and it means a client that
      reads ``Speed`` as "the speed" reports every DIMM on this machine as zero.
      Serving a tidier combination would let exactly that bug pass.
    * ``ConfiguredMemoryClockSpeed`` = ``2400``, and ``OperationalStatus`` = ``0``.

    **Substituted:** ``PartNumber``, ``SerialNumber``, ``Manufacturer`` and
    ``Tag``. The fixture's are a real Crucial part number, real module serials and
    a real JEDEC vendor ID. Note the fixture's ``Tag`` values are
    ``9876543210`` and ``9876543210 (#1)`` -- the ``(#N)`` suffix shape is
    preserved here because it is how firmware disambiguates DIMMs whose ``Tag``
    would otherwise collide, and a client keying on ``Tag`` needs to meet that.

    ``state.memory_dimm_count`` drives how many instances are returned, so the
    zero-, one- and several-DIMM cases are all reachable over a real socket.
    ``BankLabel`` follows the fixture's even-numbered pattern (``BANK 0``,
    ``BANK 2``, ...).
    """
    items = []
    for index in range(state.memory_dimm_count):
        fields: dict[str, object] = {
            "BankLabel": f"BANK {index * 2}",
            "Capacity": 17179869184,
            "ConfiguredMemoryClockSpeed": 2400,
            "CreationClassName": "CIM_PhysicalMemory",
            "ElementName": "Managed System Memory Chip",
            "FormFactor": 13,
            "IsSpeedInMhz": True,
            "Manufacturer": "0000",
            "MaxMemorySpeed": 2400,
            "MemoryType": 26,
            "OperationalStatus": [0],
            "PartNumber": "MOCKDIMM16G0000.M00XX",
            "SerialNumber": f"A000000{index}",
            # Speed 0 alongside IsSpeedInMhz true, exactly as the fixture reports
            # it. See the docstring -- this is deliberate, not an oversight.
            "Speed": 0,
            "Tag": "9000000000" if index == 0 else f"9000000000 (#{index})",
        }
        items.append(_fields_to_instance_xml(CIM_PHYSICAL_MEMORY, fields))
    return items


def _media_access_device_items(state: AmtState) -> list[str]:
    """``Enumerate`` form of ``CIM_MediaAccessDevice`` -- **NAMES-ONLY**, cited enums.

    Field set is exactly the twelve properties on the real firmware response
    fixture ``pkg/wsman/wsmantesting/responses/cim/mediaaccess/pull.xml`` (two
    devices), cross-checked against ``pkg/wsman/cim/mediaaccess/types.go``.

    **No model, vendor or serial number is served, because the class has none.**
    That is not an omission in this mock: those properties do not exist on the
    class definition or on the fixture. ``ElementName`` is the constant string
    ``Managed System Media Access Device`` on **both** fixture devices, and it is
    served identically on every instance here for that reason -- a client trying
    to tell disks apart by ``ElementName`` must fail, because it would fail on
    firmware.

    **Enumeration and numeric values carried across, citable:**

    * ``Capabilities`` = ``4`` -- ``SupportsWriting`` in
      ``mediaaccess/decoder.go``. A CIM *indexed array*, so emitted as a repeated
      element even at length one.
    * ``Security`` = ``2``. In this class's enumeration ``2`` is ``Unknown`` and
      ``1`` is ``Other`` -- the reverse of most CIM tables. Serving the fixture's
      2 is what catches a client that transposed them, which would otherwise
      report every disk here as "other" and look entirely plausible doing it.
    * ``EnabledDefault`` = ``2`` (``Enabled``), ``EnabledState`` = ``0``
      (``Unknown`` -- a *defined* value, not a gap), ``RequestedState`` = ``12``,
      ``OperationalStatus`` = ``0``.
    * ``MaxMediaSize`` -- the fixture's two devices report ``960197124`` and
      ``500107862`` **KBytes**. Those exact figures are served: they read as a
      960 GB and a 500 GB device only under KB = 1000, which is what makes the
      unit ambiguity real rather than theoretical, and the client deliberately
      does not convert them.

    ``state.storage_device_count`` selects how many of those two are returned, so
    the zero-, one- and two-disk cases are all reachable.
    """
    sizes = (960197124, 500107862)
    items = []
    for index in range(state.storage_device_count):
        items.append(
            _fields_to_instance_xml(
                CIM_MEDIA_ACCESS_DEVICE,
                {
                    "Capabilities": [4],
                    "CreationClassName": "CIM_MediaAccessDevice",
                    "DeviceID": f"MEDIA DEV {index}",
                    "ElementName": "Managed System Media Access Device",
                    "EnabledDefault": 2,
                    "EnabledState": 0,
                    "MaxMediaSize": sizes[index % len(sizes)],
                    "OperationalStatus": [0],
                    "RequestedState": 12,
                    "Security": 2,
                    "SystemCreationClassName": "CIM_ComputerSystem",
                    "SystemName": "ManagedSystem",
                },
            )
        )
    return items


def _alarm_occurrence_items(state: AmtState) -> list[str]:
    """``IPS_AlarmClockOccurrence`` -- one item per configured alarm.

    **FIRMWARE-DERIVED field set; values are whatever ``AddAlarm`` was sent.** The
    five properties are exactly those on ``responses/ips/alarmclock/get.xml`` and
    ``pull.xml``, and on go-wsman-messages' ``AlarmClockOccurrence`` struct.

    Two things about that fixture are worth stating, because they are why this
    handler is hand-rolled instead of going through ``_fields_to_instance_xml``:

    * It is a **hand-written placeholder, not a firmware capture**. Its
      ``StartTime`` is the literal string ``testdatetime`` and its ``InstanceID``
      is ``testalarm``. So it establishes the *field set* and nothing about value
      shapes -- unlike the hardware-inventory fixtures, which are real responses.
    * It sends ``StartTime`` and ``Interval`` **flat** (``<g:StartTime>text</
      g:StartTime>``), while go-wsman's parser for the same class expects the
      nested ``<StartTime><Datetime>`` form the write path uses. The two disagree.

    This mock serves the **nested** shape, because that is the shape the write path
    is documented and tested to send, and a class that accepted one shape and
    reported the other would be a claim nothing supports. The client parses both
    (``alarm.decode_start_time``), so the flat shape is covered by unit tests
    against a fake transport, where it can be labelled constructed rather than
    served here as if firmware did it.

    Empty when no alarm is configured -- a legitimate reading, not a fault, exactly
    like a diskless machine's ``CIM_MediaAccessDevice``.
    """
    items: list[str] = []
    for occurrence in state.alarm_occurrences.values():
        interval = occurrence.get("Interval")
        interval_xml = (
            f'<r:Interval><p:Interval xmlns:p="{NS_CIM_COMMON}">{escape(str(interval))}</p:Interval></r:Interval>' if interval is not None else ""
        )
        items.append(
            f'<r:IPS_AlarmClockOccurrence xmlns:r="{IPS_ALARM_CLOCK_OCCURRENCE}">'
            f"<r:DeleteOnCompletion>{'true' if occurrence.get('DeleteOnCompletion') else 'false'}</r:DeleteOnCompletion>"
            f"<r:ElementName>{escape(str(occurrence.get('ElementName') or ''))}</r:ElementName>"
            f"<r:InstanceID>{escape(str(occurrence.get('InstanceID') or ''))}</r:InstanceID>"
            f"{interval_xml}"
            f'<r:StartTime><p:Datetime xmlns:p="{NS_CIM_COMMON}">{escape(str(occurrence.get("StartTime") or ""))}</p:Datetime></r:StartTime>'
            "</r:IPS_AlarmClockOccurrence>"
        )
    return items


def _alarm_clock_service_items(state: AmtState) -> list[str]:
    """``AMT_AlarmClockService`` via ``Enumerate`` -- the same singleton ``Get`` serves.

    Exists because the vendor ships ``enumerate.xml`` + ``pull.xml`` for this class
    alongside ``get.xml``, so both verbs are evidenced, and because §2.7's
    "``Enumerate`` is HTTP 400 on ``AMT_`` classes" finding is *not* exempted for it
    -- a client on AMT 10-era firmware would have to use ``Get``, which is what this
    collection does. Serving both keeps the mock able to be either generation.
    """
    return [_fields_to_instance_xml(AMT_ALARM_CLOCK_SERVICE, _get_alarm_clock_service(state))]


def _time_synchronization_items(state: AmtState) -> list[str]:
    """``AMT_TimeSynchronizationService`` via ``Enumerate``. Same reasoning as above."""
    return [_fields_to_instance_xml(AMT_TIME_SYNCHRONIZATION_SERVICE, _get_time_synchronization_service(state))]


ENUMERATE_HANDLERS: dict[str, Callable[[AmtState], list[str]]] = {
    CIM_BOOT_SOURCE_SETTING: _boot_source_items,
    IPS_ALARM_CLOCK_OCCURRENCE: _alarm_occurrence_items,
    AMT_ALARM_CLOCK_SERVICE: _alarm_clock_service_items,
    AMT_TIME_SYNCHRONIZATION_SERVICE: _time_synchronization_items,
    AMT_BOOT_CAPABILITIES: _boot_capabilities_items,
    CIM_BIOS_ELEMENT: _bios_element_items,
    AMT_MESSAGE_LOG: _message_log_items,
    CIM_CHASSIS: _chassis_items,
    CIM_CARD: _card_items,
    CIM_PROCESSOR: _processor_items,
    CIM_CHIP: _chip_items,
    CIM_PHYSICAL_MEMORY: _physical_memory_items,
    CIM_MEDIA_ACCESS_DEVICE: _media_access_device_items,
}

#: Hardware inventory classes a test can make **absent**, standing in for
#: firmware that does not implement them, mapped to the :class:`AmtState`
#: attribute that must be true for the class to exist.
#:
#: Applied to ``Get`` *and* ``Enumerate`` alike: a class that is absent must be
#: absent for both verbs, or the ``Get``-then-``Enumerate`` fallback would still
#: find an answer for firmware that has no such class at all -- the opposite of
#: the scenario being modelled. That mistake was already made once here and is
#: recorded in ``_handle_enumerate``'s comment about ``AMT_MessageLog``.
HARDWARE_PRESENCE_ATTR: dict[str, str] = {
    CIM_CHASSIS: "chassis_present",
    CIM_CARD: "card_present",
    CIM_PROCESSOR: "processor_present",
    CIM_CHIP: "chip_present",
    CIM_PHYSICAL_MEMORY: "physical_memory_present",
    CIM_MEDIA_ACCESS_DEVICE: "media_access_present",
}

#: The alarm-clock classes a test can make absent, same contract as
#: :data:`HARDWARE_PRESENCE_ATTR` and enforced by the same helper.
#:
#: Two flags, not one, because they degrade the client differently and a single flag
#: could not tell the two apart: firmware with no alarm classes makes ``amt_alarm``
#: fail ``unsupported_capability``, while firmware that holds alarms but will not
#: report its clock makes it fall back to comparing the requested time against the
#: *controller's* clock -- which the module says out loud in its refusal message. A
#: combined flag would leave that second, quieter path unreachable.
ALARM_PRESENCE_ATTR: dict[str, str] = {
    AMT_ALARM_CLOCK_SERVICE: "alarm_clock_present",
    IPS_ALARM_CLOCK_OCCURRENCE: "alarm_clock_present",
    AMT_TIME_SYNCHRONIZATION_SERVICE: "time_sync_present",
}

#: Every class whose presence is switchable, hardware inventory and alarm clock
#: alike. One dict so :meth:`WsmanMockServer._absence_fault` cannot cover one group
#: and miss the other, and so ``Get`` and ``Enumerate`` cannot drift apart on which
#: classes exist. The two sources are kept separate above because their docstrings
#: are about different things.
CLASS_PRESENCE_ATTR: dict[str, str] = {**HARDWARE_PRESENCE_ATTR, **ALARM_PRESENCE_ATTR}


def generate_self_signed_tls_context(host: str) -> tuple[ssl.SSLContext, str, tempfile.TemporaryDirectory]:
    """Generate a throw-away self-signed cert/key via the ``openssl`` CLI.

    Returns the loaded server-side TLS context, the leaf certificate's
    SHA-256 fingerprint (hex), and the TemporaryDirectory holding the files
    (kept alive so the paths stay valid; caller is responsible for
    ``cleanup()`` when the server stops).
    """
    openssl_bin = shutil.which("openssl")
    if openssl_bin is None:
        raise RuntimeError(
            "openssl CLI not found in PATH. TLS mode for the mock WS-Man server shells out to "
            "openssl to generate a throw-away self-signed certificate (see wsman_server.py module "
            "docstring); install it or use use_tls=False."
        )
    tmpdir = tempfile.TemporaryDirectory(prefix="amt-mock-wsman-tls-")
    key_path = os.path.join(tmpdir.name, "key.pem")
    cert_path = os.path.join(tmpdir.name, "cert.pem")
    # Fixed argv, no shell, no untrusted input. This call used to carry an inline
    # suppression for ruff's S603; it must not, because pyproject.toml now ignores
    # S603 for tests/** and RUF100 then fails the redundant inline directive
    # instead. Same trap CONTRIBUTING.md describes for E402 in plugins/modules/.
    subprocess.run(
        [
            openssl_bin,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "2",
            "-nodes",
            "-subj",
            f"/CN={host}",
        ],
        check=True,
        capture_output=True,
    )
    with open(cert_path, encoding="ascii") as fh:
        pem = fh.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    fingerprint = hashlib.sha256(der).hexdigest()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx, fingerprint, tmpdir


class DigestAuth:
    """Real HTTP Digest (RFC 2617) challenge/verify, ``qop=auth`` only.

    This is not a rubber stamp: :meth:`verify` recomputes the expected
    response from the username/realm/password plus the request method and
    actual request-target, and compares against what the client sent. A
    client with a wrong password, or one that just replays a previous
    response, will fail.
    """

    def __init__(self, realm: str, credentials: dict[str, str]) -> None:
        self.realm = realm
        self.credentials = dict(credentials)
        self._nonces: set[str] = set()
        self._lock = threading.Lock()

    def challenge(self) -> str:
        import secrets

        nonce = secrets.token_hex(16)
        opaque = secrets.token_hex(8)
        with self._lock:
            self._nonces.add(nonce)
        return f'Digest realm="{self.realm}", qop="auth", nonce="{nonce}", opaque="{opaque}", algorithm=MD5'

    def verify(self, header: str | None, method: str, uri: str) -> bool:
        if not header or not header.lower().startswith("digest "):
            return False
        params = _parse_digest_header(header[len("Digest ") :])
        username = params.get("username")
        if username is None:
            return False
        password = self.credentials.get(username)
        if password is None:
            return False
        nonce = params.get("nonce")
        if not nonce:
            return False
        with self._lock:
            if nonce not in self._nonces:
                return False
        response = params.get("response")
        if not response:
            return False
        qop = params.get("qop", "auth")
        nc = params.get("nc", "")
        cnonce = params.get("cnonce", "")
        ha1 = _md5(f"{username}:{self.realm}:{password}")
        ha2 = _md5(f"{method}:{uri}")
        if qop:
            expected = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        else:
            expected = _md5(f"{ha1}:{nonce}:{ha2}")
        return hmac.compare_digest(expected, response)


def _md5(data: str) -> str:
    # MD5 is mandated by RFC 2617 digest auth, not a security choice we get to
    # make -- see plugins/module_utils/redirection.py for the identical note
    # on the redirection-plane digest.
    return hashlib.md5(data.encode("utf-8"), usedforsecurity=False).hexdigest()


_DIGEST_FIELD_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')


def _parse_digest_header(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _DIGEST_FIELD_RE.finditer(value):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = val
    return result


class _MockThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """A handful of test scenarios legitimately disconnect mid-request: a
    fingerprint-only TLS probe that never sends an HTTP request, or a client
    that gives up after one of our own timeout faults fires. Those are
    expected, not bugs, so silence the default traceback-to-stderr for them
    and let anything else through."""

    def handle_error(self, request: object, client_address: object) -> None:
        exc_type = sys.exc_info()[0]
        if exc_type is not None and issubclass(exc_type, (ConnectionError, TimeoutError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


class _WsmanHandler(http.server.BaseHTTPRequestHandler):
    server_version = "MockAMT-WSMAN/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass  # Silence: tests assert behaviour, not console noise.

    def do_POST(self) -> None:
        mock: WsmanMockServer = self.server.mock  # type: ignore[attr-defined]
        faults = mock.faults

        if faults.force_status is not None:
            status = faults.force_status
            faults.force_status = None
            self._send_plain(status, b"injected fault")
            return

        if faults.timeout_before_read:
            faults.timeout_before_read = False
            faults.last_timeout_body_was_read = False
            self._hang(mock)
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_body = self.rfile.read(length) if length else b""

        if faults.timeout_after_read:
            faults.timeout_after_read = False
            faults.last_timeout_body_was_read = True
            self._hang(mock)
            return

        if not mock.digest.verify(self.headers.get("Authorization"), "POST", self.path):
            self._send_401(mock)
            return

        try:
            root = ET.fromstring(raw_body)  # noqa: S314 -- fixed local test fixture input, not untrusted
        except ET.ParseError:
            self._send_plain(400, b"malformed SOAP request")
            return

        action, resource_uri, relates_to, body_elem, selectors = _parse_envelope(root)
        key = (resource_uri, action)

        if key in faults.malformed_xml_for:
            self._send_raw(200, b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><truncated')
            return
        if key in faults.soap_fault_for:
            body = _fault_body("InjectedFault", "Fault injected by test fixture")
            self._send_raw(500, _envelope(ACTION_FAULT, relates_to, body).encode("utf-8"))
            return
        if key in faults.http_status_for:
            self._send_plain(faults.http_status_for[key], b"injected fault")
            return

        return_override = faults.return_value_for.get(key)
        try:
            status, response_xml = mock.dispatch(action, resource_uri, relates_to, body_elem, return_override, selectors)
        except _HttpFault as fault:
            # Firmware rejected the request before it produced a SOAP body at all --
            # see _HttpFault. Served as text/plain like the pre-existing malformed-SOAP
            # 400 above, because no evidence establishes the body shape AMT wraps these in.
            self._send_plain(fault.status, fault.message.encode("utf-8"))
            return
        self._send_raw(status, response_xml.encode("utf-8"))

    def _hang(self, mock: WsmanMockServer) -> None:
        # Block long enough for the client's own (short) timeout to fire, then
        # let this handler thread unwind naturally -- never write a response.
        threading.Event().wait(mock.timeout_hang_seconds)
        self.close_connection = True

    def _send_401(self, mock: WsmanMockServer) -> None:
        body = b"Unauthorized"
        self.send_response(401)
        self.send_header("WWW-Authenticate", mock.digest.challenge())
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_plain(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _parse_selector_set(header: ET.Element | None) -> dict[str, str]:
    """Read the request's ``<w:SelectorSet>`` into a name->value mapping.

    Only the header's own SelectorSet, never one nested inside a method body's
    endpoint reference: those name a *parameter*, not the instance the request
    itself addresses, and conflating the two would make e.g. ``ChangeBootOrder``
    look like a Get against ``CIM_BootSourceSetting``.
    """
    if header is None:
        return {}
    selector_set = header.find(f"{{{NS_W}}}SelectorSet")
    if selector_set is None:
        return {}
    selectors: dict[str, str] = {}
    for selector in selector_set.findall(f"{{{NS_W}}}Selector"):
        name = selector.attrib.get("Name")
        if name:
            selectors[name] = (selector.text or "").strip()
    return selectors


def _parse_envelope(root: ET.Element) -> tuple[str, str, str, ET.Element | None, dict[str, str]]:
    header = root.find(f"{{{NS_S}}}Header")
    body = root.find(f"{{{NS_S}}}Body")
    action = (header.findtext(f"{{{NS_A}}}Action", default="") if header is not None else "").strip()
    resource_uri = (header.findtext(f"{{{NS_W}}}ResourceURI", default="") if header is not None else "").strip()
    message_id = (header.findtext(f"{{{NS_A}}}MessageID", default="") if header is not None else "").strip()
    body_elem = next(iter(body), None) if body is not None else None
    return action, resource_uri, message_id, body_elem, _parse_selector_set(header)


class WsmanMockServer:
    """Threaded mock WS-Man endpoint. Use as a context manager::

        with WsmanMockServer(password="test-password-not-real") as server:
            requests.post(server.base_url, auth=HTTPDigestAuth(...), data=..., verify=server.ca_bundle)

    Binds to an ephemeral port on 127.0.0.1 only. TLS mode generates a
    throw-away self-signed certificate per instance and exposes its SHA-256
    fingerprint via :attr:`cert_fingerprint` for fingerprint-pinning tests.

    ``page_size`` is how many instances one ``Pull`` returns (:meth:`_handle_pull`).
    The default of 2 already splits any enumeration of three or more instances across
    pages, so paging is exercised without a test asking for it; the values worth
    passing explicitly are the boundaries -- ``1`` (a page per instance, the maximum
    number of continuations) and anything above the instance count (one page, no
    continuation at all, which is what real AMT does for a small class). Both are
    covered against the real client in ``tests/unit/mock_servers/test_wsman_server.py``.
    """

    def __init__(
        self,
        *,
        username: str = "admin",
        password: str = "test-password-not-real",  # noqa: S107 -- obviously-fake fixture default, not a real credential
        realm: str = "Digest:mock-amt-fixture",
        use_tls: bool = False,
        host: str = "127.0.0.1",
        page_size: int = 2,
        timeout_hang_seconds: float = 1.0,
    ) -> None:
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.host = host
        self.page_size = page_size
        self.timeout_hang_seconds = timeout_hang_seconds

        self.state = AmtState()
        self.faults = FaultConfig()
        self.digest = DigestAuth(realm, {username: password})

        self._contexts: dict[str, list[str]] = {}
        self._lock = threading.Lock()
        self._httpd: _MockThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._tls_tmpdir: tempfile.TemporaryDirectory | None = None

        self.cert_fingerprint: str | None = None
        self.port: int | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> WsmanMockServer:
        httpd = _MockThreadingHTTPServer((self.host, 0), _WsmanHandler)
        httpd.daemon_threads = True
        httpd.mock = self  # type: ignore[attr-defined]

        if self.use_tls:
            ctx, fingerprint, tmpdir = generate_self_signed_tls_context(self.host)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            self.cert_fingerprint = fingerprint
            self._tls_tmpdir = tmpdir

        self._httpd = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(target=httpd.serve_forever, name="wsman-mock", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout_hang_seconds + 5)
        if self._tls_tmpdir is not None:
            self._tls_tmpdir.cleanup()
            self._tls_tmpdir = None
        self._httpd = None
        self._thread = None

    def __enter__(self) -> WsmanMockServer:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://{self.host}:{self.port}/wsman"

    # -- dispatch ------------------------------------------------------------

    def dispatch(
        self,
        action: str,
        resource_uri: str,
        relates_to: str,
        body_elem: ET.Element | None,
        return_override: int | None,
        selectors: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        with self._lock:
            try:
                if action == ACTION_GET:
                    return self._handle_get(resource_uri, relates_to, selectors or {})
                if action == ACTION_PUT:
                    return self._handle_put(resource_uri, relates_to, body_elem)
                if action == ACTION_DELETE:
                    return self._handle_delete(resource_uri, relates_to, selectors or {})
                if action == ACTION_ENUMERATE:
                    return self._handle_enumerate(resource_uri, relates_to)
                if action == ACTION_PULL:
                    return self._handle_pull(resource_uri, relates_to, body_elem)
                if resource_uri and action.startswith(resource_uri + "/"):
                    method_name = action[len(resource_uri) + 1 :]
                    return self._handle_method(resource_uri, method_name, relates_to, body_elem, return_override)
            except _UnknownResource:
                pass
            # An unlisted resource answers **HTTP 500 + a SOAP fault**, and that is
            # deliberately *not* changed to a 400.
            #
            # WS-Management binds SOAP faults to HTTP 500; a 400 is for a request whose
            # body did not validate (see _HttpFault). "I understood the request and there
            # is no such resource" is the former, so 500 + wsman:InvalidResourceURI is the
            # WS-Man-correct shape and the 400 §2.7 records is specific to the
            # Enumerate-verb case, which is now modelled separately above.
            #
            # These are also **not** two different classification paths in this
            # collection's client, contrary to what one might assume:
            # ``plugins/module_utils/wsman.py`` ``_handle_response()`` tests
            # ``response.status_code == 401`` and then ``not response.ok``, so *every*
            # non-2xx -- 400 and 500 alike -- becomes the same ``ProtocolError`` with the
            # body carried through as ``diagnostic``. The SOAP-fault parser
            # (``_raise_for_fault``) only ever runs on a 2xx body, so the fault element
            # served here is never actually parsed as a fault. Nothing is lost (the reason
            # text reaches the operator via ``diagnostic``), and both statuses land on the
            # ``protocol`` error class, which is the right class for both.
            body = _fault_body("UnsupportedCapability", f"No handler for action={action!r} resourceURI={resource_uri!r}")
            return 500, _envelope(ACTION_FAULT, relates_to, body)

    def _absence_fault(self, resource_uri: str, relates_to: str) -> tuple[int, str] | None:
        """A SOAP fault for a class a test has switched off, else ``None``.

        One helper rather than an ``if`` block per class per verb, so ``Get``,
        ``Enumerate`` and ``Delete`` cannot drift apart on which classes exist --
        see :data:`CLASS_PRESENCE_ATTR`. Covers the hardware-inventory classes and
        the alarm-clock ones alike; it was called ``_hardware_absence_fault`` when
        the hardware group was the only switchable one.
        """
        attribute = CLASS_PRESENCE_ATTR.get(resource_uri)
        if attribute is None or getattr(self.state, attribute):
            return None
        class_name = resource_uri.rsplit("/", 1)[-1]
        body = _fault_body("InvalidResourceURI", f"{class_name} is not implemented on this firmware")
        return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)

    def _handle_get(self, resource_uri: str, relates_to: str, selectors: dict[str, str]) -> tuple[int, str]:
        handler = GET_HANDLERS.get(resource_uri)
        if handler is None:
            raise _UnknownResource

        expected = SELECTOR_MATCH_FOR_GET.get(resource_uri)
        if expected is not None:
            if not selectors and resource_uri in SELECTOR_REQUIRED_FOR_GET:
                body = _fault_body(
                    "InvalidSelectors",
                    f"{resource_uri.rsplit('/', 1)[-1]} requires a SelectorSet naming one instance",
                )
                return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
            mismatched = {name: value for name, value in selectors.items() if expected.get(name) != value}
            if mismatched:
                body = _fault_body("InvalidSelectors", f"No instance matches selector(s) {sorted(mismatched)}")
                return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)

        if resource_uri == AMT_ETHERNET_PORT_SETTINGS and not self.state.ethernet_port_present:
            body = _fault_body("InvalidResourceURI", "AMT_EthernetPortSettings is not implemented on this firmware")
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        if resource_uri == CIM_BIOS_ELEMENT and self.faults.bios_element_get_faults:
            body = _fault_body("UnsupportedCapability", "CIM_BIOSElement does not answer a bare Get on this firmware")
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        if resource_uri == AMT_MESSAGE_LOG and not self.state.message_log_present:
            body = _fault_body("InvalidResourceURI", "AMT_MessageLog is not implemented on this firmware")
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        absent = self._absence_fault(resource_uri, relates_to)
        if absent is not None:
            return absent
        if resource_uri in (CIM_CHASSIS, CIM_CARD) and self.faults.hardware_get_faults:
            body = _fault_body(
                "UnsupportedCapability",
                f"{resource_uri.rsplit('/', 1)[-1]} does not answer a bare Get on this firmware",
            )
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)

        fields = handler(self.state)
        body = _fields_to_instance_xml(resource_uri, fields)
        return 200, _envelope(ACTION_GET_RESPONSE, relates_to, body, resource_uri=resource_uri)

    def _handle_put(self, resource_uri: str, relates_to: str, body_elem: ET.Element | None) -> tuple[int, str]:
        if resource_uri != AMT_BOOT_SETTING_DATA:
            raise _UnknownResource
        incoming = {_local_name(child.tag): (child.text or "") for child in (body_elem or [])}
        if self.faults.reject_boot_readonly_fields:
            offending = sorted(READONLY_BOOT_FIELDS & incoming.keys())
            if offending:
                body = _fault_body(
                    "InvalidParameter",
                    "Put rejected: read-only field(s) present: " + ", ".join(offending),
                )
                return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        self.state.boot_setting_data.update(incoming)
        body = _fields_to_instance_xml(resource_uri, self.state.boot_setting_data)
        return 200, _envelope(ACTION_PUT_RESPONSE, relates_to, body, resource_uri=resource_uri)

    def _handle_delete(self, resource_uri: str, relates_to: str, selectors: dict[str, str]) -> tuple[int, str]:
        """WS-Transfer ``Delete``. Only ``IPS_AlarmClockOccurrence`` is deletable.

        Deliberately narrow: it is the only class in this collection any code path
        deletes, and the only one either prior-art source deletes. A mock that
        answered ``Delete`` for everything would let a client delete something
        firmware would refuse.

        The instance is named entirely by the ``InstanceID`` selector, which is what
        both go-wsman-messages (``message.Selector{Name: "InstanceID", ...}``) and
        MeshCentral's meshcmd (``stack.Delete('IPS_AlarmClockOccurrence',
        { InstanceID: ... })``) send. ``ElementName`` is **not** accepted as a
        selector, because neither source sends it as one -- a client that keyed on
        the friendly name must fail here rather than in production.

        A ``Delete`` for a name that does not exist faults. That is not invented: the
        instance is addressed by its key, and WS-Transfer has no "delete if present".
        It is also what makes the client's read-then-decide ordering load-bearing
        rather than decorative -- a module that deleted optimistically would fail on
        an already-absent alarm, which is precisely the ``state=absent`` idempotence
        case.

        The response body is **empty**, matching the vendor's captured
        ``responses/ips/alarmclock/delete.xml`` (``<a:Body></a:Body>``).
        """
        if resource_uri != IPS_ALARM_CLOCK_OCCURRENCE:
            raise _UnknownResource
        absent = self._absence_fault(resource_uri, relates_to)
        if absent is not None:
            return absent
        instance_id = selectors.get("InstanceID")
        if not instance_id:
            body = _fault_body("InvalidSelectors", "IPS_AlarmClockOccurrence requires an InstanceID selector naming one instance")
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        if instance_id not in self.state.alarm_occurrences:
            body = _fault_body("InvalidSelectors", f"No IPS_AlarmClockOccurrence instance with InstanceID {instance_id!r}")
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        del self.state.alarm_occurrences[instance_id]
        return 200, _envelope(ACTION_DELETE_RESPONSE, relates_to, "", resource_uri=resource_uri)

    def _handle_enumerate(self, resource_uri: str, relates_to: str) -> tuple[int, str]:
        # AMT 10-era firmware, when a test asks for it. See
        # FaultConfig.enumerate_faults_for_amt_classes for why this is opt-in and why
        # AMT_MessageLog is exempt. Checked before the handler lookup so it applies to
        # every AMT_ class, including ones this mock does not otherwise serve for
        # Enumerate -- on that firmware the verb fails for the whole prefix, not just for
        # the classes this fixture happens to implement.
        if self.faults.enumerate_faults_for_amt_classes and resource_uri.startswith(AMT_BASE + "/") and resource_uri != AMT_MESSAGE_LOG:
            raise _HttpFault(400, "Enumerate is not supported for this resource; use Get with a SelectorSet")

        handler = ENUMERATE_HANDLERS.get(resource_uri)
        if handler is None:
            raise _UnknownResource
        # Absent classes must be absent for *both* verbs. Faulting only the Get
        # would leave the Enumerate fallback answering for firmware that has no
        # such class at all, which is the opposite of the scenario being modelled.
        if resource_uri == AMT_MESSAGE_LOG and not self.state.message_log_present:
            body = _fault_body("InvalidResourceURI", "AMT_MessageLog is not implemented on this firmware")
            return 500, _envelope(ACTION_FAULT, relates_to, body, resource_uri=resource_uri)
        # Same reasoning as the AMT_MessageLog line above, generalised: an absent
        # class must be absent for both verbs, or the client's Get-then-Enumerate
        # fallback still finds an answer on firmware that has no such class.
        absent = self._absence_fault(resource_uri, relates_to)
        if absent is not None:
            return absent
        items = handler(self.state)
        ctx = uuid.uuid4().hex
        self._contexts[ctx] = list(items)
        body = f'<wsen:EnumerateResponse xmlns:wsen="{NS_WSEN}"><wsen:EnumerationContext>{ctx}</wsen:EnumerationContext></wsen:EnumerateResponse>'
        return 200, _envelope(ACTION_ENUMERATE_RESPONSE, relates_to, body)

    def _handle_pull(self, _resource_uri: str, relates_to: str, body_elem: ET.Element | None) -> tuple[int, str]:
        ctx = _param_text(body_elem, "EnumerationContext")
        if ctx is None or ctx not in self._contexts:
            body = _fault_body("InvalidEnumerationContext", "Unknown or expired enumeration context")
            return 500, _envelope(ACTION_FAULT, relates_to, body)
        remaining = self._contexts[ctx]
        page, remaining[:] = remaining[: self.page_size], remaining[self.page_size :]
        items_xml = "".join(page)
        if remaining:
            body = (
                f'<wsen:PullResponse xmlns:wsen="{NS_WSEN}">'
                f"<wsen:Items>{items_xml}</wsen:Items>"
                f"<wsen:EnumerationContext>{ctx}</wsen:EnumerationContext>"
                "</wsen:PullResponse>"
            )
        else:
            del self._contexts[ctx]
            body = f'<wsen:PullResponse xmlns:wsen="{NS_WSEN}"><wsen:Items>{items_xml}</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse>'
        return 200, _envelope(ACTION_PULL_RESPONSE, relates_to, body)

    def _handle_method(
        self,
        resource_uri: str,
        method_name: str,
        relates_to: str,
        body_elem: ET.Element | None,
        return_override: int | None,
    ) -> tuple[int, str]:
        handler = METHOD_HANDLERS.get((resource_uri, method_name))
        if handler is None:
            raise _UnknownResource
        # A class a test has switched off must be absent for its *methods* too, not
        # only for Get and Enumerate. Otherwise firmware with no alarm clock would
        # still accept AddAlarm, and the "no such class" scenario would be
        # self-contradictory -- the same mistake, one verb further along, that
        # _handle_enumerate's AMT_MessageLog comment records.
        absent = self._absence_fault(resource_uri, relates_to)
        if absent is not None:
            return absent
        if return_override is not None:
            return_value, extra = return_override, ""
        else:
            return_value, extra = handler(self.state, body_elem)
        return_xml = f"<r:ReturnValue>{return_value}</r:ReturnValue>"
        # Element order follows real firmware per resource/method -- see
        # EXTRA_BEFORE_RETURN_VALUE.
        inner = f"{extra}{return_xml}" if (resource_uri, method_name) in EXTRA_BEFORE_RETURN_VALUE else f"{return_xml}{extra}"
        out = f'<r:{method_name}_OUTPUT xmlns:r="{resource_uri}">{inner}</r:{method_name}_OUTPUT>'
        return 200, _envelope(f"{resource_uri}/{method_name}Response", relates_to, out, resource_uri=resource_uri)
