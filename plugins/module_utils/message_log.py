# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""``AMT_MessageLog`` -- the Intel AMT event log: read, decode, and clear.

This is the class that records *why* an unattended bare-metal install failed:
boot failures, watchdog expiry, and power events the host operating system
never saw, because it was not running when they happened. Nothing else in this
collection can reach them.

Every protocol fact below is sourced, and the sources are named per-fact in
``docs/protocol-notes.md`` §2.8. The short version:

* ``AMT_MessageLog`` carries the log *container* properties
  (``CurrentNumberOfRecords``, ``MaxNumberOfRecords``, ``MaxRecordSize``, ...)
  and the ``PositionToFirstRecord`` / ``GetRecords`` / ``ClearLog`` methods.
* ``GetRecords`` returns ``RecordArray``, an array of **base64-encoded 21-byte
  binary records**, plus a ``NoMoreRecords`` flag and an
  ``IterationIdentifier`` to feed the next call.
* Each record is a fixed 21-byte struct: a little-endian ``UINT32`` timestamp
  followed by nine ``UINT8`` fields and eight ``UINT8`` event-data bytes.

Two rules run through this module, and both exist because of specific defects
in the prior art (``parmstro/intel_amt``'s ``amt_event_log``, which queries the
``CIM_RecordLog`` container for ``RecordData`` elements that never exist and so
always reports success with zero records):

1. **The raw bytes are always returned.** Every decoded record carries
   ``raw_base64`` and ``raw_hex`` alongside the decoded fields. The decode is
   derived from two independent sources rather than from firmware this
   collection has ever talked to, so if it is wrong on some generation, the raw
   bytes are the only thing that lets someone diagnose that. This is not
   negotiable and must not be "optimised" away.
2. **A field with no source is not invented.** ``EventType``,
   ``EventOffset``, ``EventSourceType``, ``DeviceAddress`` and ``SensorNumber``
   are reported as raw integers and nothing else, because no value table for
   them is established by any source available here. Only ``EventSeverity`` and
   ``Entity`` get named, and only from the tables both sources agree on.
"""

from __future__ import annotations

import base64
import binascii
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    ProtocolError,
    RemoteOperationError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import optional_int, optional_str, truthy

if TYPE_CHECKING:
    from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import WsmanClient

#: The resource class. Both the container properties and all three methods live
#: on this one class -- **not** on ``CIM_RecordLog``, which is what the prior art
#: queries and is why it returns nothing.
MESSAGE_LOG_CLASS = "AMT_MessageLog"

#: Fixed record size in bytes. Established twice over: the ``EVENT_DATA`` struct
#: documented in go-wsman-messages' ``pkg/wsman/amt/messagelog/log.go`` package
#: comment (4 + 9x1 + 8), and ``MaxRecordSize == 21`` in the real-firmware
#: response fixture ``wsmantesting/responses/amt/messagelog/get.xml``.
RECORD_SIZE = 21

#: Length of the trailing ``EventData`` array, in bytes (offsets 13..20).
EVENT_DATA_SIZE = 8

#: Records to request per ``GetRecords`` call. go-wsman-messages caps its own
#: ``MaxReadRecords`` at 390 with the comment "Intel AMT can return 400 records
#: in a single GetRecords call, but we limit it to 390", and MeshCentral's
#: ``GetMessageLog`` passes exactly 390. The real-firmware fixture also reports
#: ``MaxNumberOfRecords == 390``, i.e. 390 is the whole log on that generation.
MAX_READ_RECORDS = 390

#: Default ceiling on the total number of records a single read will pull.
#: One full log on the firmware generation the fixtures came from, so the
#: default is not a truncating one there, while still bounding a play against a
#: generation with a larger log.
DEFAULT_MAX_RECORDS = 390

#: ``GetRecords`` ``ReturnValue``, from the ``ValueMap``/``Values`` annotation on
#: ``GetRecordsResponse.ReturnValue`` in go-wsman-messages' ``types.go``.
GET_RECORDS_RETURN_VALUES: dict[int, str] = {
    0: "completed_with_no_error",
    1: "not_supported",
    2: "invalid_record_pointed",
    3: "no_record_exists_in_log",
}

#: ``PositionToFirstRecord`` ``ReturnValue``, same source. Note ``2`` means "no
#: record exists" here, whereas for ``GetRecords`` that meaning is ``3``: the two
#: methods do **not** share a return-value table, and treating them as if they
#: did would read an empty log as a protocol error.
POSITION_TO_FIRST_RECORD_RETURN_VALUES: dict[int, str] = {
    0: "completed_with_no_error",
    1: "not_supported",
    2: "no_record_exists",
}

#: ``EventSeverity``. Both sources carry this table identically
#: (go-wsman-messages ``decoder.go`` ``EventSeverity``). The values are sparse
#: and non-contiguous (0, 1, 2, 4, 8, 16, 32), so they are a lookup, **not** an
#: ordered ladder: ``ok`` (4) is numerically greater than ``information`` (2)
#: without being "worse". Nothing here compares them with ``<``.
EVENT_SEVERITY_TABLE: dict[int, str] = {
    0: "unspecified",
    1: "monitor",
    2: "information",
    4: "ok",
    8: "non_critical",
    16: "critical",
    32: "non_recoverable",
}

#: The severity names an operator can filter on. Derived from
#: :data:`EVENT_SEVERITY_TABLE` so the two can never drift apart.
SEVERITY_CHOICES: tuple[str, ...] = tuple(EVENT_SEVERITY_TABLE[key] for key in sorted(EVENT_SEVERITY_TABLE))

#: ``Entity`` -- the IPMI-style system entity that raised the event. From
#: go-wsman-messages ``decoder.go`` ``SystemEntityTypes``; MeshCentral's
#: ``_SystemEntityTypes`` is the same list in the same order. Note 35 and 38 are
#: **both** "Intel(r) ME" in both sources; that is not a transcription slip.
SYSTEM_ENTITY_TABLE: dict[int, str] = {
    0: "Unspecified",
    1: "Other",
    2: "Unknown",
    3: "Processor",
    4: "Disk",
    5: "Peripheral",
    6: "System management module",
    7: "System board",
    8: "Memory module",
    9: "Processor module",
    10: "Power supply",
    11: "Add in card",
    12: "Front panel board",
    13: "Back panel board",
    14: "Power system board",
    15: "Drive backplane",
    16: "System internal expansion board",
    17: "Other system board",
    18: "Processor board",
    19: "Power unit",
    20: "Power module",
    21: "Power management board",
    22: "Chassis back panel board",
    23: "System chassis",
    24: "Sub chassis",
    25: "Other chassis board",
    26: "Disk drive bay",
    27: "Peripheral bay",
    28: "Device bay",
    29: "Fan cooling",
    30: "Cooling unit",
    31: "Cable interconnect",
    32: "Memory device",
    33: "System management software",
    34: "BIOS",
    35: "Intel(r) ME",
    36: "System bus",
    37: "Group",
    38: "Intel(r) ME",
    39: "External environment",
    40: "Battery",
    41: "Processing blade",
    42: "Connectivity switch",
    43: "Processor/memory module",
    44: "I/O module",
    45: "Processor I/O module",
    46: "Management controller firmware",
    47: "IPMI channel",
    48: "PCI bus",
    49: "PCI express bus",
    50: "SCSI bus",
    51: "SATA/SAS bus",
    52: "Processor front side bus",
}

#: ``EventSensorType == 15`` with ``EventOffset == 0``: ``EventData[1]`` indexes
#: this table. Identical in both sources (go-wsman-messages
#: ``SystemFirmwareError``, MeshCentral ``_SystemFirmwareError``).
SYSTEM_FIRMWARE_ERROR_TABLE: dict[int, str] = {
    0: "Unspecified.",
    1: "No system memory is physically installed in the system.",
    2: "No usable system memory, all installed memory has experienced an unrecoverable failure.",
    3: "Unrecoverable hard-disk/ATAPI/IDE device failure.",
    4: "Unrecoverable system-board failure.",
    5: "Unrecoverable diskette subsystem failure.",
    6: "Unrecoverable hard-disk controller failure.",
    7: "Unrecoverable PS/2 or USB keyboard failure.",
    8: "Removable boot media not found.",
    9: "Unrecoverable video controller failure.",
    10: "No video device detected.",
    11: "Firmware (BIOS) ROM corruption detected.",
    12: "CPU voltage mismatch (processors that share same supply have mismatched voltage requirements)",
    13: "CPU speed matching failure",
}

#: ``EventSensorType == 15`` with a non-zero ``EventOffset``: ``EventData[1]``
#: indexes this table. Identical in both sources. Index 21 really is the string
#: ``"reserved"`` in both, and is kept rather than tidied away -- a firmware that
#: emits it is saying something, and inventing a nicer name for it would be
#: inventing.
SYSTEM_FIRMWARE_PROGRESS_TABLE: dict[int, str] = {
    0: "Unspecified.",
    1: "Memory initialization.",
    2: "Starting hard-disk initialization and test",
    3: "Secondary processor(s) initialization",
    4: "User authentication",
    5: "User-initiated system setup",
    6: "USB resource configuration",
    7: "PCI resource configuration",
    8: "Option ROM initialization",
    9: "Video initialization",
    10: "Cache initialization",
    11: "SM Bus initialization",
    12: "Keyboard controller initialization",
    13: "Embedded controller/management controller initialization",
    14: "Docking station attachment",
    15: "Enabling docking station",
    16: "Docking station ejection",
    17: "Disabling docking station",
    18: "Calling operating system wake-up vector",
    19: "Starting operating system boot process",
    20: "Baseboard or motherboard initialization",
    21: "reserved",
    22: "Floppy initialization",
    23: "Keyboard test",
    24: "Pointing device test",
    25: "Primary processor initialization",
}

#: ``EventSensorType == 18`` (agent watchdog): ``EventData[7]`` indexes this.
#: Identical in both sources. Sparse and bit-like (1, 2, 4, 8, 16).
WATCHDOG_STATE_TABLE: dict[int, str] = {
    1: "Not Started",
    2: "Stopped",
    4: "Running",
    8: "Expired",
    16: "Suspended",
}

#: ``EventData[0]`` sentinel meaning "the rest of this record's event data is not
#: valid" for ``EventSensorType == 15``. Both sources check for it (0xEB).
_FIRMWARE_DATA_INVALID = 0xEB

#: ``EventData[0]`` marker both sources use to recognise Intel-specific event
#: data. For sensor type 18 it gates the watchdog decode in both. For sensor type
#: 15 it is where the two sources **disagree** -- see :func:`_describe_firmware`.
_INTEL_EVENT_DATA_MARKER = 0xAA

#: ``EventSensorType`` values that carry a fixed description with no event-data
#: lookup at all. From go-wsman-messages' ``decodeEventDetailString``.
_FIXED_SENSOR_DESCRIPTIONS: dict[int, str] = {
    30: "No bootable media",
    32: "Operating system lockup or power interrupt",
    35: "System boot failure",
    37: "System firmware started (at least one CPU is properly executing).",
}

#: ``struct`` format for one record: little-endian ``UINT32`` timestamp, then
#: nine ``UINT8`` fields, then the 8-byte ``EventData`` array. The ``<`` is the
#: whole point -- see the byte-order note in :func:`decode_record`.
_RECORD_STRUCT = struct.Struct(f"<IBBBBBBBBB{EVENT_DATA_SIZE}s")

#: A ``UINT32`` timestamp of 0 or 0xFFFFFFFF is not a real time. MeshCentral
#: drops such records entirely; this collection keeps the record and reports
#: ``timestamp_utc: null`` instead, because silently dropping records is the
#: exact failure mode of the prior art.
_TIMESTAMP_SENTINELS = frozenset({0x00000000, 0xFFFFFFFF})

#: Errors that mean "this firmware does not have this class", as opposed to a
#: transport or credential failure. Mirrors ``client.py``'s ``_DEGRADABLE_ERRORS``.
_DEGRADABLE_ERRORS: tuple[type[AmtError], ...] = (ProtocolError, UnsupportedCapabilityError)


def _decode_table(table: dict[int, str], value: int) -> str:
    """Name an enumeration value, keeping an unrecognised one visible as ``unknown(<raw>)``.

    Same convention as ``models.py``'s ``_decode``: a value outside the table is
    still evidence, and rendering it identically to a defined "Unknown" entry
    (which several of these tables have, at index 2) would erase the difference
    between "firmware said Unknown" and "we do not know what firmware said".
    """
    return table.get(value, f"unknown({value})")


def _describe_firmware(event_offset: int, event_data: bytes) -> str | None:
    """Describe an ``EventSensorType == 15`` (system firmware) event, or ``None``.

    ``EventOffset == 0`` selects the *error* table and non-zero selects the
    *progress* table, indexed by ``EventData[1]``. Both sources agree on that.

    They **disagree** for offsets 3 and 5 when ``EventData[0] == 0xAA``:
    go-wsman-messages still reads the progress table, while MeshCentral's
    ``meshcmd`` decoder treats those as One-Click-Recovery / platform-erase /
    OEM-specific events with an entirely different layout. Two sources
    contradicting each other is not a source, so no description is produced for
    that case -- the raw ``event_data`` bytes are returned and the caller can see
    them. Emitting a progress string that MeshCentral says is a One-Click-Recovery
    event would be exactly the "plausible-looking garbage" this module exists to
    avoid.
    """
    if event_data[0] == _FIRMWARE_DATA_INVALID:
        return "Invalid Data"
    if event_offset == 0:
        return SYSTEM_FIRMWARE_ERROR_TABLE.get(event_data[1])
    if event_data[0] == _INTEL_EVENT_DATA_MARKER:
        # Sources conflict here. Say nothing rather than guessing.
        return None
    return SYSTEM_FIRMWARE_PROGRESS_TABLE.get(event_data[1])


def _describe_watchdog(event_data: bytes) -> str | None:
    """Describe an ``EventSensorType == 18`` agent-watchdog event, or ``None``.

    The watchdog GUID is rendered from ``EventData[1..6]`` in the byte order both
    sources use (4,3,2,1 then 6,5 -- i.e. the first two GUID groups
    little-endian), and deliberately kept as the truncated ``xxxxxxxx-xxxx-...``
    form both sources emit: the remaining GUID bytes are not in the record, so a
    full GUID cannot be reconstructed and must not be implied.

    ``EventData[7]`` is the new watchdog state. This is one of the two events the
    log exists to surface for an unattended install -- an agent watchdog that
    reached ``Expired`` is a hung install, observed from outside the host.
    """
    if event_data[0] != _INTEL_EVENT_DATA_MARKER:
        return None
    guid = f"{event_data[4]:02x}{event_data[3]:02x}{event_data[2]:02x}{event_data[1]:02x}-{event_data[6]:02x}{event_data[5]:02x}"
    state = _decode_table(WATCHDOG_STATE_TABLE, event_data[7])
    return f"Agent watchdog {guid}-... changed to {state}"


def describe_event(event_sensor_type: int, event_offset: int, event_data: bytes) -> str | None:
    """Render a human-readable description for a record, or ``None`` if unsourced.

    Implements go-wsman-messages' ``decodeEventDetailString`` (Intel-authored,
    Apache-2.0), whose outputs are checked against real-firmware records in that
    project's own ``log_test.go`` -- which is why this collection's unit tests
    expect the same strings for the same fixture bytes.

    Returns ``None`` rather than a placeholder for any sensor type with no
    established description. ``None`` reads unambiguously as "this collection
    cannot name this event"; a string like ``"Unknown Sensor Type #7"`` (which is
    what go-wsman-messages emits) invites an operator to read it as a firmware
    statement rather than as our own ignorance.
    """
    if len(event_data) < EVENT_DATA_SIZE:
        return None
    if event_sensor_type == 6:
        # Little-endian 16-bit failure count in EventData[1..2]. EventData[0] is
        # the 0xAA Intel marker.
        count = event_data[1] + (event_data[2] << 8)
        return f"Authentication failed {count} times. The system may be under attack."
    if event_sensor_type == 15:
        return _describe_firmware(event_offset, event_data)
    if event_sensor_type == 18:
        return _describe_watchdog(event_data)
    return _FIXED_SENSOR_DESCRIPTIONS.get(event_sensor_type)


@dataclass(frozen=True, slots=True)
class EventRecord:
    """One decoded ``AMT_MessageLog`` record, with its raw bytes always attached.

    ``raw_base64`` and ``raw_hex`` are present on **every** record, including one
    that failed to decode. The decode is derived from two third-party sources and
    has never been run against real firmware by this collection, so the raw bytes
    are the only thing that makes a wrong decode diagnosable rather than merely
    wrong.

    ``decode_error`` is ``None`` on a clean decode. When it is set, every decoded
    field is ``None`` -- a partial decode of a malformed record is worse than no
    decode, because half a struct read at the wrong offsets produces values that
    look real.
    """

    raw_base64: str
    raw_hex: str | None = None
    raw_length: int | None = None
    decode_error: str | None = None
    timestamp: int | None = None
    timestamp_utc: str | None = None
    device_address: int | None = None
    event_sensor_type: int | None = None
    event_type: int | None = None
    event_offset: int | None = None
    event_source_type: int | None = None
    event_severity: int | None = None
    event_severity_text: str | None = None
    sensor_number: int | None = None
    entity: int | None = None
    entity_text: str | None = None
    entity_instance: int | None = None
    event_data: list[int] | None = None
    description: str | None = None


def decode_record(encoded: str) -> EventRecord:
    """Decode one base64 ``RecordArray`` element into an :class:`EventRecord`.

    Never raises. Every failure mode -- invalid base64, a record shorter than
    :data:`RECORD_SIZE` -- comes back as a record carrying ``decode_error`` and
    whatever raw bytes were recoverable, because one unreadable record must not
    cost the caller the other 389.

    **Byte order.** The ``UINT32`` timestamp is **little-endian**; the remaining
    fields are single bytes and so have no byte order. Established twice: the
    ``// little endian`` comment on ``TimeStamp`` in go-wsman-messages'
    ``log.go`` struct and its ``binary.LittleEndian`` reads, and MeshCentral's
    ``ReadIntX(e, 0)``. Confirmed arithmetically against the real-firmware
    fixture record ``Y8iYZf8GbwVoEP8mYaoKAAAAAAAA``, whose leading bytes
    ``63 c8 98 65`` are asserted by go-wsman-messages' own test as the timestamp
    ``0x6598c863`` -- i.e. byte-reversed. Reading it big-endian would place this
    event in 1694-something and look merely odd rather than wrong.

    **Field order.** ``TimeStamp``, ``DeviceAddress``, ``EventSensorType``,
    ``EventType``, ``EventOffset``, ``EventSourceType``, ``EventSeverity``,
    ``SensorNumber``, ``Entity``, ``EntityInstance``, ``EventData[8]``. Both
    sources agree byte-for-byte (go-wsman-messages reads them in that sequence;
    MeshCentral indexes ``e[4]``..``e[12]`` then ``e[13..20]``).
    """
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        return EventRecord(raw_base64=encoded, decode_error=f"record is not valid base64: {exc}")

    raw_hex = raw.hex()
    if len(raw) < RECORD_SIZE:
        return EventRecord(
            raw_base64=encoded,
            raw_hex=raw_hex,
            raw_length=len(raw),
            decode_error=f"record is {len(raw)} bytes, expected at least {RECORD_SIZE}",
        )

    # Only the first RECORD_SIZE bytes are decoded. AMT_MessageLog advertises
    # capability 8 ("Variable Length Records Supported") while also reporting
    # MaxRecordSize == 21, and no source describes what a longer record would
    # contain -- so any tail is preserved in raw_hex/raw_base64 and not guessed at.
    (
        timestamp,
        device_address,
        event_sensor_type,
        event_type,
        event_offset,
        event_source_type,
        event_severity,
        sensor_number,
        entity,
        entity_instance,
        event_data,
    ) = _RECORD_STRUCT.unpack_from(raw, 0)

    return EventRecord(
        raw_base64=encoded,
        raw_hex=raw_hex,
        raw_length=len(raw),
        timestamp=timestamp,
        timestamp_utc=_format_timestamp(timestamp),
        device_address=device_address,
        event_sensor_type=event_sensor_type,
        event_type=event_type,
        event_offset=event_offset,
        event_source_type=event_source_type,
        event_severity=event_severity,
        event_severity_text=_decode_table(EVENT_SEVERITY_TABLE, event_severity),
        sensor_number=sensor_number,
        entity=entity,
        entity_text=_decode_table(SYSTEM_ENTITY_TABLE, entity),
        entity_instance=entity_instance,
        event_data=list(event_data),
        description=describe_event(event_sensor_type, event_offset, event_data),
    )


def _format_timestamp(timestamp: int) -> str | None:
    """Render the ``UINT32`` timestamp as an ISO-8601 UTC string, or ``None``.

    Interpreted as **Unix epoch seconds in UTC**, which is what
    go-wsman-messages does (``time.Unix(int64(event.TimeStamp), 0)``).
    MeshCentral instead adds the *client's* local timezone offset before
    constructing the date, which makes the rendered time depend on where the
    management station happens to be -- a property of the reader, not of the
    event, so it is not reproduced here. ``timestamp`` is always returned raw
    next to this, so a caller who disagrees with the interpretation still has
    the number.

    0 and 0xFFFFFFFF are treated as "no timestamp" rather than as 1970 or 2106.
    """
    if timestamp in _TIMESTAMP_SENTINELS:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        # A UINT32 cannot exceed what datetime handles on any supported
        # platform, but a read is not worth aborting over a clock value.
        return None


@dataclass(frozen=True, slots=True)
class MessageLogProperties:
    """The ``AMT_MessageLog`` container instance -- the log, not its records.

    ``current_number_of_records`` is the field the clear operation's before/after
    receipt is built from, and the field that lets a caller tell a truncated read
    from a genuinely short log. Every field is optional: a firmware generation
    that omits one must yield ``None`` rather than a fabricated zero, because
    "zero records" and "firmware did not say" are different findings and only one
    of them means the log is empty.
    """

    current_number_of_records: int | None = None
    max_number_of_records: int | None = None
    max_record_size: int | None = None
    element_name: str | None = None
    is_frozen: bool | None = None
    log_state: int | None = None
    overwrite_policy: int | None = None
    capabilities: list[int] = field(default_factory=list)

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> MessageLogProperties:
        raw_capabilities = instance.get("Capabilities")
        candidates = raw_capabilities if isinstance(raw_capabilities, list) else [raw_capabilities]
        return cls(
            current_number_of_records=optional_int(instance.get("CurrentNumberOfRecords")),
            max_number_of_records=optional_int(instance.get("MaxNumberOfRecords")),
            max_record_size=optional_int(instance.get("MaxRecordSize")),
            element_name=optional_str(instance.get("ElementName")),
            is_frozen=truthy(instance.get("IsFrozen")) if instance.get("IsFrozen") is not None else None,
            log_state=optional_int(instance.get("LogState")),
            overwrite_policy=optional_int(instance.get("OverwritePolicy")),
            capabilities=[number for item in candidates if (number := optional_int(item)) is not None],
        )


@dataclass(frozen=True, slots=True)
class MessageLogRead:
    """The result of following a ``GetRecords`` iteration to its end (or to a bound).

    ``truncated`` and ``stop_reason`` exist so that a short result is never
    ambiguous. The prior art fetches one batch and stops, reporting success --
    which is indistinguishable, from the outside, from a log that really had that
    many records. A caller here can always tell which happened:

    * ``stop_reason == "no_more_records"`` -- the firmware said the iteration is
      finished. The result is the whole log.
    * ``stop_reason == "max_records"`` -- ``truncated`` is ``True``; more records
      exist and were not fetched.
    * anything else -- the iteration ended abnormally and ``complete`` is
      ``False``. The records collected so far are still returned.
    """

    properties: MessageLogProperties
    records: list[EventRecord]
    total_records: int | None
    truncated: bool
    complete: bool
    stop_reason: str
    batches: int


def get_log_properties(wsman: WsmanClient) -> MessageLogProperties:
    """Read the ``AMT_MessageLog`` container instance.

    Uses a bare ``Get`` and falls back to ``Enumerate``, which is the
    ``CIM_BIOSElement`` pattern from ``docs/protocol-notes.md`` §2.7 rather than
    this collection's usual "``Get`` with an explicit selector" rule for
    ``AMT_``-prefixed classes. The reason is evidential, not stylistic: **no
    source names a selector for this class.** The real-firmware fixture
    ``responses/amt/messagelog/get.xml`` answers a ``Get`` carrying no
    ``SelectorSet`` at all, and the instance it returns has no ``InstanceID``
    property to build one from -- its keys are ``CreationClassName`` and ``Name``.
    Inventing ``InstanceID = "Intel(r) AMT:MessageLog 1"`` would be inventing.

    Unusually for an ``AMT_`` class, ``Enumerate`` is also evidenced here:
    ``enumerate.xml`` and ``pull.xml`` exist for ``AMT_MessageLog`` in the same
    fixture set and return the same instance. So both verbs are real for this
    class on the generation those fixtures came from, and trying both is cheap
    insurance for the AMT 10 generation where ``Enumerate`` on ``AMT_`` classes is
    HTTP 400.

    Raises :class:`UnsupportedCapabilityError` if neither verb yields the class.
    """
    instance: dict[str, Any] | None
    try:
        instance = wsman.get(MESSAGE_LOG_CLASS)
    except _DEGRADABLE_ERRORS:
        instance = None

    if not instance:
        try:
            instances = wsman.enumerate(MESSAGE_LOG_CLASS)
        except _DEGRADABLE_ERRORS:
            instances = []
        instance = next((item for item in instances or () if isinstance(item, dict) and item), None)

    if not instance:
        raise UnsupportedCapabilityError(
            f"{MESSAGE_LOG_CLASS} is not available on this endpoint: neither Get nor Enumerate returned an instance. "
            "This firmware does not appear to implement the AMT event log.",
            endpoint=wsman.endpoint,
            operation=f"Get {MESSAGE_LOG_CLASS}",
        )
    return MessageLogProperties.from_instance(instance)


def _invoke_tolerating_return_values(
    wsman: WsmanClient,
    method: str,
    params: dict[str, Any] | None,
    *,
    tolerated: dict[int, str],
) -> tuple[dict[str, Any], int]:
    """Invoke a ``AMT_MessageLog`` method, returning non-zero ``ReturnValue``s the caller expects.

    ``WsmanClient.invoke`` raises :class:`RemoteOperationError` for any non-zero
    ``ReturnValue``, which is the right default for a *mutation* -- it is what
    makes ``amt_log_clear`` fail loudly instead of reporting a success it did not
    get. But two of the read methods here use non-zero return values to say
    ordinary, non-error things: ``GetRecords`` returns 3 for "no record exists in
    log" and ``PositionToFirstRecord`` returns 2 for "no record exists". An empty
    event log is not a failure, so those are caught here and handed back to the
    caller to interpret. Anything not in ``tolerated`` still propagates.
    """
    try:
        output, return_value = wsman.invoke(MESSAGE_LOG_CLASS, method, params)
    except RemoteOperationError as err:
        if err.return_value is not None and err.return_value in tolerated:
            return {}, err.return_value
        raise
    return output, return_value


def _record_array(output: dict[str, Any]) -> list[str]:
    """Pull ``RecordArray`` out of a ``GetRecords_OUTPUT`` as a list of base64 strings.

    WS-Man renders a repeated element, and this collection's XML-to-dict
    conversion (``wsman._element_to_value``) collapses a *single* occurrence to a
    plain string and multiple occurrences to a list. So a log holding exactly one
    record arrives shaped differently from a log holding two, and code that
    assumes a list silently iterates that one record's *characters*. MeshCentral
    carries the same guard (``if typeof ra === 'string'``), which is how a
    one-record log is known to be a real shape and not a theoretical one.
    """
    raw = output.get("RecordArray")
    if raw is None:
        return []
    candidates = raw if isinstance(raw, list) else [raw]
    return [text for item in candidates if (text := optional_str(item)) is not None]


def read_records(
    wsman: WsmanClient,
    *,
    max_records: int = DEFAULT_MAX_RECORDS,
    batch_size: int = MAX_READ_RECORDS,
) -> MessageLogRead:
    """Read the event log, following the ``GetRecords`` iteration to completion.

    The sequence is ``Get AMT_MessageLog`` (for ``CurrentNumberOfRecords``), then
    ``PositionToFirstRecord``, then ``GetRecords`` repeatedly -- feeding each
    response's ``IterationIdentifier`` into the next request -- until firmware
    sets ``NoMoreRecords``, or ``max_records`` is reached. This is MeshCentral's
    ``GetMessageLog`` sequence exactly (``PositionToFirstRecord`` ->
    ``GetRecords(IterationIdentifier, 390)`` -> loop while
    ``NoMoreRecords != true``).

    ``PositionToFirstRecord`` is called even though go-wsman-messages documents it
    as having no effect on current firmware ("In current implementation this
    method doesn't have any affect... user should just call GetRecord or
    GetRecords") and defaults the identifier to 1. It is called because
    MeshCentral does, because it is the documented way to obtain a valid
    identifier rather than assuming one, and because its ``ReturnValue`` is a
    cheap, unambiguous "the log is empty" signal. If it returns no identifier the
    iteration starts at 1, which go-wsman-messages establishes as the first
    record's position.

    Raises :class:`UnsupportedCapabilityError` if the class or a method is absent.
    Never loops forever: an iteration whose identifier stops advancing while
    still claiming more records terminates with ``stop_reason ==
    "iteration_stalled"`` and ``complete == False``.
    """
    properties = get_log_properties(wsman)
    total_records = properties.current_number_of_records

    identifier, position_return_value = _position_to_first_record(wsman)
    if position_return_value == 2:  # "No record exists" -- an empty log, not a fault.
        return MessageLogRead(
            properties=properties,
            records=[],
            total_records=total_records,
            truncated=False,
            complete=True,
            stop_reason="no_record_exists",
            batches=0,
        )

    records: list[EventRecord] = []
    batches = 0
    stop_reason = "no_more_records"
    complete = True
    truncated = False

    while True:
        if len(records) >= max_records:
            stop_reason = "max_records"
            # Reaching here means firmware had *not* set NoMoreRecords -- that
            # check breaks out below, before control returns to the top of the
            # loop. So `truncated` is firmware's own claim that more records
            # remained, not our guess: a read that exactly fills the budget on a
            # final batch exits as "no_more_records" and is not truncated.
            truncated = True
            complete = False
            break

        remaining = max_records - len(records)
        output, return_value = _invoke_tolerating_return_values(
            wsman,
            "GetRecords",
            {"IterationIdentifier": identifier, "MaxReadRecords": min(batch_size, remaining, MAX_READ_RECORDS)},
            tolerated={2: "invalid_record_pointed", 3: "no_record_exists_in_log"},
        )
        batches += 1

        if return_value == 3:
            # "No record exists in log". On the first batch this is an empty log;
            # after records have been read it is how some firmware signals the
            # end without setting NoMoreRecords. Either way, a complete read.
            stop_reason = "no_record_exists_in_log"
            break
        if return_value == 2:
            # "Invalid record pointed" -- the identifier no longer addresses a
            # record. Not treated as a clean end: the records read so far are
            # returned, but `complete` is False so a caller is never told a
            # partial read was the whole log.
            stop_reason = "invalid_record_pointed"
            complete = False
            break

        batch = _record_array(output)
        records.extend(decode_record(item) for item in batch[:remaining])

        if truthy(output.get("NoMoreRecords")):
            stop_reason = "no_more_records"
            break

        next_identifier = optional_int(output.get("IterationIdentifier"))
        if next_identifier is None:
            # Firmware did not say where to continue from, and did not say it was
            # done either. Guessing the next position risks re-reading the same
            # batch forever or skipping records silently.
            stop_reason = "no_iteration_identifier"
            complete = False
            break
        if next_identifier == identifier:
            # The iterator did not move while NoMoreRecords was still false: the
            # next request would return the same batch again, forever.
            stop_reason = "iteration_stalled"
            complete = False
            break
        identifier = next_identifier

    return MessageLogRead(
        properties=properties,
        records=records,
        total_records=total_records,
        truncated=truncated,
        complete=complete,
        stop_reason=stop_reason,
        batches=batches,
    )


def _position_to_first_record(wsman: WsmanClient) -> tuple[int, int]:
    """Establish an iteration and return ``(identifier, return_value)``.

    ``ReturnValue == 1`` ("Not Supported") is escalated to
    :class:`UnsupportedCapabilityError` rather than left as a
    ``remote_operation`` failure: firmware that does not implement the method is a
    capability gap, and the whole point of the nine error classes is that a
    caller branches on them.
    """
    output, return_value = _invoke_tolerating_return_values(
        wsman,
        "PositionToFirstRecord",
        None,
        tolerated={1: "not_supported", 2: "no_record_exists"},
    )
    if return_value == 1:
        raise UnsupportedCapabilityError(
            f"{MESSAGE_LOG_CLASS}.PositionToFirstRecord reported ReturnValue=1 (Not Supported): this firmware does not implement event-log iteration.",
            endpoint=wsman.endpoint,
            operation=f"{MESSAGE_LOG_CLASS}.PositionToFirstRecord",
            return_value=return_value,
        )
    identifier = optional_int(output.get("IterationIdentifier"))
    # go-wsman-messages: "The IterationIdentifier input parameter is a numeric
    # value (starting at 1) which is the position of the first record in the log".
    return (identifier if identifier is not None and identifier >= 1 else 1), return_value


def filter_by_severity(records: list[EventRecord], severities: list[str] | None) -> list[EventRecord]:
    """Keep only records whose ``event_severity_text`` is in ``severities``.

    ``None`` (the default) keeps everything. Filtering is by **name**, never by
    numeric comparison: :data:`EVENT_SEVERITY_TABLE` is a sparse lookup, not an
    ordered scale, so "severity >= 4" would silently mean "at least OK" and pull
    in ``ok`` while excluding ``information``.

    A record whose severity byte is outside the table renders as
    ``unknown(<raw>)`` and is therefore **dropped** by any filter, as is a record
    that failed to decode at all. That is a real edge with a real cost, so the
    modules that call this report how many records the filter removed rather than
    letting the difference vanish.
    """
    if not severities:
        return list(records)
    wanted = set(severities)
    return [record for record in records if record.event_severity_text in wanted]


def clear_log(wsman: WsmanClient) -> int:
    """Invoke ``AMT_MessageLog.ClearLog``. Irreversible.

    Takes no parameters -- MeshCentral's ``AMT_MessageLog_ClearLog`` passes an
    empty parameter object, and the ``Capabilities`` array in the real-firmware
    fixture includes ``6`` (``ClearLogSupported``), which is the firmware itself
    saying the method is implemented.

    A non-zero ``ReturnValue`` propagates as :class:`RemoteOperationError` from
    ``WsmanClient.invoke``, deliberately unhandled here. The prior art demotes
    exactly this case to a warning and returns success, which tells an operator
    that forensic evidence was cleared when it was not (or, worse, the reverse).

    Note what is *not* claimed: ``ReturnValue == 0`` means AMT accepted the
    request, not that the log is empty. The caller re-reads
    ``CurrentNumberOfRecords`` afterwards and reports what it observed.
    """
    _output, return_value = wsman.invoke(MESSAGE_LOG_CLASS, "ClearLog", {})
    return return_value
