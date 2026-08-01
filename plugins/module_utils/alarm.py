# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Intel AMT alarm clock: scheduled wake at a wall-clock time.

Backs ``amt_alarm``. The wire format, every value table, and each of the three
questions the design turned on are recorded in ``docs/protocol-notes.md`` s2.10;
this docstring states only what the code here has to be read against.

Two classes, one method, one delete
-----------------------------------

* ``AMT_AlarmClockService`` -- the singleton service. Owns ``AddAlarm``, whose
  only input is an *embedded instance* of the occurrence class (hence
  :class:`wsman.EmbeddedInstance`).
* ``IPS_AlarmClockOccurrence`` -- one instance per configured alarm. Read by
  ``Enumerate``; destroyed by WS-Transfer ``Delete`` with an ``InstanceID``
  selector. **There is no ``Put``**: no source implements or evidences one, so
  changing an existing alarm is delete-then-add, and :func:`plan` says so.

Three findings that shape this file, none of which is obvious from the class names
---------------------------------------------------------------------------------

1. **``InstanceID`` is caller-supplied, so convergence has a real key.**
   go-wsman-messages types it "the instance key, set by the caller of
   ``AMT_AlarmClockService.AddAlarm``". Both other implementations of this class
   go further and make one caller-supplied name serve as *both* ``InstanceID``
   and ``ElementName``: Intel's own Console assigns
   ``alarm.InstanceID = alarm.ElementName`` outright, and MeshCentral's meshcmd
   passes its ``--add`` argument as both. This module does the same and calls the
   option ``name``, because the alternative -- letting them differ -- creates a
   resource that MeshCentral's own delete path (which matches on ``ElementName``
   but deletes by ``InstanceID``) cannot remove.

2. **The wire time is UTC, but the two authorities disagree, and firmware's own
   clock is a third opinion.** go-wsman converts to UTC before formatting;
   MeshCentral formats *local* components and appends a literal ``Z``. This file
   follows go-wsman -- see :func:`format_start_time` for the argument -- and, so
   that the disagreement is never silent, refuses a ``start_time`` that carries no
   timezone at all and reports firmware's own RTC reading alongside every result
   (:func:`read_firmware_clock`).

3. **What firmware does with a past-dated alarm is not established by any source
   this project has.** So the refusal in :func:`plan` is *this collection's*, is
   made against firmware's clock rather than the controller's, and is documented
   as ours. See ``docs/amt_alarm.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    AmtError,
    InvalidStateError,
    ProtocolError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    optional_bool,
    optional_int,
    optional_str,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import (
    NS_CIM_COMMON,
    EmbeddedInstance,
    WsmanClient,
    resource_uri,
)

#: The service singleton. ``AddAlarm`` is invoked on this class, not on the
#: occurrence class.
CLASS_ALARM_SERVICE = "AMT_AlarmClockService"
#: One instance per configured alarm.
CLASS_ALARM_OCCURRENCE = "IPS_AlarmClockOccurrence"
#: Reading firmware's own clock. A separate service, deliberately: the alarm
#: classes carry no clock of their own, and the skew between firmware and the
#: controller is the single most useful thing to report next to a wake time.
CLASS_TIME_SYNC = "AMT_TimeSynchronizationService"

METHOD_ADD_ALARM = "AddAlarm"
METHOD_GET_LOW_ACCURACY_TIME_SYNCH = "GetLowAccuracyTimeSynch"

#: ``AddAlarm``'s single input parameter: an embedded ``IPS_AlarmClockOccurrence``.
PARAM_ALARM_TEMPLATE = "AlarmTemplate"

#: The maximum number of ``IPS_AlarmClockOccurrence`` instances firmware will hold.
#:
#: **Vendor-documented, not measured here.** go-wsman-messages'
#: ``pkg/wsman/amt/alarmclock/service.go`` states on ``AddAlarm``: "The method
#: would fail if 5 instances or more of ``IPS_AlarmClockOccurrence`` already exist
#: in the system." Nothing in that library, in MeshCentral, or in any captured
#: response fixture says what *code* such a failure returns -- go-wsman's
#: ``returnValueToString`` for this class defines exactly one entry, ``0:
#: Success`` -- so a caller who hits the limit on firmware would get a
#: ``ReturnValue`` this collection could not name. :func:`plan` therefore checks
#: the count first and refuses with a message that names the limit and its source.
#: If a firmware generation turns out to allow more, this refuses a legal
#: operation, which is why the check reports the instances it counted.
MAX_ALARM_OCCURRENCES = 5

#: ``AMT_TimeSynchronizationService.TimeSource`` -- from go-wsman-messages
#: ``pkg/wsman/amt/timesynchronization/decoder.go`` (``TimeSource`` const block +
#: ``timeSourceString``), 2 values, 0-1 contiguous.
#:
#: This is the property that makes the timezone question answerable per machine
#: rather than in general. Its own class comment is "Determines if RTC was set to
#: UTC by any configuration SW" -- so ``configured`` means some management tool
#: set the clock (and, per that comment, set it to UTC), while ``bios_rtc`` means
#: firmware is reading whatever the platform RTC holds, which on a machine whose
#: BIOS keeps local time is *not* UTC. The vendor's own captured response reports
#: ``0``.
TIME_SOURCE_TABLE: dict[int, str] = {
    0: "bios_rtc",
    1: "configured",
}

#: ``AMT_TimeSynchronizationService.LocalTimeSyncEnabled`` -- same file,
#: ``LocalTimeSyncEnabled`` const block + ``localTimeSyncEnabledString``, 3 values,
#: 0-2 contiguous. Whether a local caller holding ``LOCAL_SYSTEM_REALM`` may set
#: the clock; reported because a machine where it is enabled has a clock the host
#: OS can move underneath a scheduled alarm.
#:
#: Note the vendor's names encode the *value* of the setting, not just its state:
#: ``0`` and ``1`` both mean enabled and differ only in whether that is the
#: default or was configured. Transcribed rather than collapsed to a boolean for
#: exactly that reason.
LOCAL_TIME_SYNC_ENABLED_TABLE: dict[int, str] = {
    0: "default_true",
    1: "configured_true",
    2: "false",
}

#: The ``Datetime`` format ``AddAlarm`` accepts: RFC 3339, second resolution, UTC.
#:
#: go-wsman-messages formats ``StartTime.UTC().Format(time.RFC3339Nano)`` and then
#: truncates at the first ``.``; its own test asserts the resulting body carries
#: ``2022-12-31T23:59:00Z``. Note the truncation is only correct because that test
#: uses a whole-second time -- ``RFC3339Nano`` omits the fractional part when it is
#: zero, so the ``Z`` survives, whereas a sub-second time would have the ``Z``
#: truncated away with the fraction. This collection formats to whole seconds
#: directly and never relies on that, so the ``Z`` is always present.
_START_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: The ISO-8601 duration shape both implementations emit for ``Interval``:
#: ``P<days>DT<hours>H<minutes>M``, every field present even when zero
#: (go-wsman writes ``P``, days, ``DT``, hours, ``H``, minutes, ``M``
#: unconditionally; MeshCentral's meshcmd builds ``'P' + d + 'DT' + h + 'H' + m +
#: 'M'`` the same way). Parsing is deliberately more permissive than emitting --
#: see :func:`decode_interval`.
_INTERVAL_RE = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")

_MINUTES_PER_HOUR = 60
_MINUTES_PER_DAY = 24 * _MINUTES_PER_HOUR

#: Errors that mean "this firmware does not implement the alarm clock", as opposed
#: to a transport or credential failure. Mirrors ``client.py``'s and
#: ``message_log.py``'s ``_DEGRADABLE_ERRORS``.
_DEGRADABLE_ERRORS: tuple[type[AmtError], ...] = (ProtocolError, UnsupportedCapabilityError)


def _decode_table(table: dict[int, str], value: int) -> str:
    """Name an enumeration value, keeping an unrecognised one visible.

    Same convention as ``models.py``'s ``_decode`` and ``hardware.py``'s namesake:
    a value outside the table renders ``unknown(<raw>)``, never a bare
    ``unknown``. Both tables in this file are small and contiguous, which makes an
    out-of-range value *more* interesting rather than less -- it would mean a
    firmware generation extended an enumeration these two sources describe as
    closed.
    """
    return table.get(value, f"unknown({value})")


# --------------------------------------------------------------------------
# Time and interval encoding
# --------------------------------------------------------------------------


def parse_start_time(value: str) -> datetime:
    """Parse a caller-supplied ``start_time`` into an aware UTC :class:`datetime`.

    **A value with no timezone is rejected.** That is the whole point of this
    function, and it is not defensive pedantry: the two implementations of this
    class that exist disagree about what an unqualified wall-clock time means.
    go-wsman-messages converts to UTC before formatting, so its ``23:59`` is
    23:59 UTC. MeshCentral's meshcmd builds the string from *local* date
    components and appends a literal ``Z``, so its ``23:59`` is 23:59 in the
    timezone of whoever ran meshcmd, mislabelled as UTC. A module that guessed
    would be right for one population of users and would silently wake the other
    population's machines at the wrong hour -- and "wrong by the controller's UTC
    offset" is the single most likely defect in a feature like this.

    So the caller must say. ``2026-08-01T03:00:00Z`` and
    ``2026-08-01T03:00:00-04:00`` are both accepted and mean different instants;
    ``2026-08-01T03:00:00`` is refused with a message naming both fixes.

    Accepts what :meth:`datetime.fromisoformat` accepts, which on Python 3.11+
    includes a trailing ``Z``. The explicit ``Z`` substitution keeps 3.10 -- the
    floor ansible-core 2.17 runs on -- behaving identically rather than rejecting
    the one spelling every example in the documentation uses.
    """
    text = (value or "").strip()
    if not text:
        raise InvalidStateError("start_time is empty; expected an ISO-8601 timestamp with a timezone, e.g. 2026-08-01T03:00:00Z", operation="parse_start_time")
    # Python 3.10's fromisoformat does not accept a trailing Z. Normalising here
    # rather than requiring 3.11 keeps the documented spelling working on the
    # declared floor.
    normalized = f"{text[:-1]}+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise InvalidStateError(
            f"start_time {value!r} is not an ISO-8601 timestamp: {exc}. Expected e.g. 2026-08-01T03:00:00Z or 2026-08-01T03:00:00-04:00",
            operation="parse_start_time",
        ) from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise InvalidStateError(
            f"start_time {value!r} carries no timezone, and this module will not guess one. "
            "Intel's own two implementations of IPS_AlarmClockOccurrence disagree about what an "
            "unqualified time means -- go-wsman-messages converts to UTC, MeshCentral sends local "
            "time labelled as UTC -- so an unqualified value would wake the machine at the wrong "
            "hour for one of them. Append 'Z' for UTC (2026-08-01T03:00:00Z) or an explicit offset "
            "(2026-08-01T03:00:00-04:00).",
            operation="parse_start_time",
        )
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def format_start_time(moment: datetime) -> str:
    """Render an aware :class:`datetime` as the ``<p:Datetime>`` text ``AddAlarm`` takes.

    Always UTC, always whole seconds, always with the ``Z``. This follows
    go-wsman-messages, which is the pinned authority for this collection and is
    Intel's own library, over MeshCentral, which sends local components under a
    ``Z``. Where the two prior-art sources contradict each other the same rule
    applies as in s2.8's timestamp rendering: prefer the one whose behaviour is
    a property of the *value* rather than of whoever happened to be reading it.

    Seconds are truncated to zero deliberately. MeshCentral's meshcmd carries the
    comment "seconds must be 00" against its own construction of this value; that
    is an undocumented firmware constraint reported by prior art, not something
    this project has tested, so the safe reading is to honour it. A caller who
    asked for ``03:00:30`` therefore gets ``03:00:00``, and the receipt reports
    the value actually sent so the truncation is visible rather than silent.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError("format_start_time requires a timezone-aware datetime; parse_start_time guarantees one")
    return moment.astimezone(timezone.utc).replace(second=0, microsecond=0).strftime(_START_TIME_FORMAT)


def encode_interval(minutes: int) -> str:
    """Encode a recurrence interval in minutes as ``P<d>DT<h>H<m>M``.

    The arithmetic is go-wsman-messages' own, transcribed rather than re-derived::

        minutes = Interval % 60
        hours   = (Interval / 60) % 24
        days    = Interval / 1440

    Its test asserts ``2879`` (one day, 23 hours, 59 minutes) encodes to
    ``P1DT23H59M``, which is the case that would catch a transposition of the
    ``%``/``/`` pair. Every field is emitted even when zero, matching both
    implementations: ``0`` renders ``P0DT0H0M`` rather than the shorter-but-valid
    ``P0D``, because nothing establishes that firmware's parser accepts the
    abbreviated forms and both sources avoid them.
    """
    if minutes < 0:
        raise ValueError(f"interval_minutes must not be negative, got {minutes}")
    days, remainder = divmod(minutes, _MINUTES_PER_DAY)
    hours, mins = divmod(remainder, _MINUTES_PER_HOUR)
    return f"P{days}DT{hours}H{mins}M"


def decode_interval(value: Any) -> int | None:
    """Decode an ``Interval`` back to whole minutes, or ``None`` if it says nothing.

    Deliberately more permissive than :func:`encode_interval` is: it accepts an
    omitted ``D`` or ``T`` group and a seconds field, because the shape firmware
    *emits* is not guaranteed to be the shape it *accepts*, and no captured
    response fixture shows a populated interval at all (the vendor's
    ``responses/ips/alarmclock/get.xml`` carries the literal placeholder string
    ``0``, not a duration). Being strict on read would turn a firmware that
    normalises ``P0DT0H0M`` to ``P0D`` into an unparseable alarm.

    Returns ``None`` -- not ``0`` -- when the value is absent or unparseable, and
    the two are different findings: ``0`` means firmware reported a one-shot
    alarm, ``None`` means it reported nothing this function could read. A
    convergence decision that conflated them would re-add a recurring alarm on
    every run.

    Sub-minute seconds are **truncated**, not rounded, and cannot silently make a
    30-second interval look like a one-shot: ``PT30S`` decodes to ``0``, which is
    also what a one-shot reports. Nothing in either source emits a seconds field,
    so this is a defensive branch rather than an observed one.
    """
    if value is None:
        return None
    # The parser may hand back a nested mapping ({"Interval": "P1DT0H0M"}) because
    # the wire element wraps its value in a DMTF-common child, or a bare string if
    # firmware sent it flat. Both shapes are real: the vendor's Go struct models the
    # nested one, and the vendor's own fixture for the same class sends it flat.
    if isinstance(value, dict):
        inner = value.get("Interval")
        return decode_interval(inner) if inner is not None else None
    text = str(value).strip()
    if not text:
        return None
    match = _INTERVAL_RE.match(text)
    if match is None:
        return None
    days, hours, minutes, seconds = (int(group) if group else 0 for group in match.groups())
    return days * _MINUTES_PER_DAY + hours * _MINUTES_PER_HOUR + minutes + seconds // 60


def decode_start_time(value: Any) -> str | None:
    """Extract the ``StartTime`` text firmware reported, or ``None``.

    Handles both wire shapes for the same reason :func:`decode_interval` does:
    the property is defined as a wrapper around a DMTF-common ``<Datetime>``
    child, and the vendor's own captured response for the class sends the value
    flat instead. The text is returned **verbatim**, not reparsed into a
    :class:`datetime` and reformatted, because a firmware that reported an offset
    other than ``Z`` or a shape this collection has never seen must be visible in
    the result rather than laundered into whatever this module would have sent.
    """
    if isinstance(value, dict):
        return optional_str(value.get("Datetime"))
    return optional_str(value)


# --------------------------------------------------------------------------
# Firmware clock
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FirmwareClock:
    """What firmware's own real-time clock reads, and how far it is from ours.

    ``epoch_seconds`` comes from ``GetLowAccuracyTimeSynch``'s ``Ta0``, which is
    Unix epoch seconds -- the same units and epoch as the ``AMT_MessageLog``
    record timestamps ``message_log.py`` already decodes, and the vendor's
    captured response value ``1704586865`` reads as 2024-01-07T00:21:05Z, which
    corroborates it.

    ``skew_seconds`` is ``firmware - controller``, so a **positive** value means
    firmware's clock is *ahead* of the controller's. Reported rather than
    corrected: this module never sets firmware's clock (that is
    ``SetHighAccuracyTimeSynch``, which writes to flash and has a write-limit
    return code), and an alarm whose time was silently adjusted for skew would be
    impossible to reason about.
    """

    epoch_seconds: int
    utc: str | None
    skew_seconds: int | None
    time_source: int | None
    time_source_name: str | None
    local_time_sync_enabled: int | None
    local_time_sync_enabled_name: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "epoch_seconds": self.epoch_seconds,
            "utc": self.utc,
            "skew_seconds": self.skew_seconds,
            "time_source": self.time_source,
            "time_source_name": self.time_source_name,
            "local_time_sync_enabled": self.local_time_sync_enabled,
            "local_time_sync_enabled_name": self.local_time_sync_enabled_name,
        }

    @property
    def moment(self) -> datetime:
        """The reading as an aware UTC datetime, for comparison against a start time."""
        return datetime.fromtimestamp(self.epoch_seconds, tz=timezone.utc)


def _format_epoch(epoch_seconds: int) -> str | None:
    """Render epoch seconds as an ISO-8601 UTC string, matching ``message_log.py``.

    Sentinel handling is deliberately *not* shared with that module: it treats
    ``0`` and ``0xFFFFFFFF`` as "no timestamp" because a log record slot can be
    unwritten, whereas a clock reading of 0 is a firmware clock that genuinely
    reads 1970 -- which is exactly the fault an operator setting a wake time needs
    to see, not something to blank out.
    """
    try:
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def read_firmware_clock(wsman: WsmanClient, *, now: datetime | None = None) -> FirmwareClock | None:
    """Read firmware's RTC and its time-source configuration, or ``None`` if it will not say.

    Degrades rather than failing, following ``client.py``'s rule 1: an alarm can
    still be set on firmware that does not implement
    ``AMT_TimeSynchronizationService``, so a missing clock reading downgrades the
    past-date check (see :func:`plan`) instead of aborting the run. Transport,
    credential and TLS failures still propagate -- only the two "this firmware
    does not have this class" errors are swallowed.

    The ``Get`` for ``TimeSource``/``LocalTimeSyncEnabled`` is a *second*,
    separately-degradable read: firmware that answers the method but not the
    property Get still yields a usable clock reading, with the two configuration
    fields ``None``.
    """
    try:
        output, _ = wsman.invoke(CLASS_TIME_SYNC, METHOD_GET_LOW_ACCURACY_TIME_SYNCH)
    except _DEGRADABLE_ERRORS:
        return None
    epoch_seconds = optional_int(output.get("Ta0"))
    if epoch_seconds is None:
        # A 0 ReturnValue with no Ta0 is a shape no source describes. Treat it as
        # "firmware would not say" rather than inventing a zero, which would read
        # as a 1970 clock and fail every past-date check.
        return None

    time_source: int | None = None
    local_time_sync: int | None = None
    try:
        instance = wsman.get(CLASS_TIME_SYNC)
    except _DEGRADABLE_ERRORS:
        instance = {}
    time_source = optional_int(instance.get("TimeSource"))
    local_time_sync = optional_int(instance.get("LocalTimeSyncEnabled"))

    reference = (now or datetime.now(tz=timezone.utc)).astimezone(timezone.utc)
    return FirmwareClock(
        epoch_seconds=epoch_seconds,
        utc=_format_epoch(epoch_seconds),
        skew_seconds=epoch_seconds - int(reference.timestamp()),
        time_source=time_source,
        time_source_name=None if time_source is None else _decode_table(TIME_SOURCE_TABLE, time_source),
        local_time_sync_enabled=local_time_sync,
        local_time_sync_enabled_name=None if local_time_sync is None else _decode_table(LOCAL_TIME_SYNC_ENABLED_TABLE, local_time_sync),
    )


# --------------------------------------------------------------------------
# Occurrences
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AlarmOccurrence:
    """One configured alarm, as firmware reports it.

    ``start_time`` is the verbatim firmware text (see :func:`decode_start_time`).
    ``interval_minutes`` is decoded, with ``interval`` alongside it holding the raw
    duration string -- the same raw-next-to-decoded rule every enumeration in this
    collection follows, applied to a duration instead of an integer, and for the
    same reason: a duration shape this collection has never seen must not be
    reported only as the ``None`` its decoder returned.
    """

    instance_id: str | None
    element_name: str | None
    start_time: str | None
    interval: str | None
    interval_minutes: int | None
    delete_on_completion: bool | None

    @classmethod
    def from_instance(cls, instance: dict[str, Any]) -> AlarmOccurrence:
        raw_interval = instance.get("Interval")
        return cls(
            instance_id=optional_str(instance.get("InstanceID")),
            element_name=optional_str(instance.get("ElementName")),
            start_time=decode_start_time(instance.get("StartTime")),
            interval=_interval_raw_text(raw_interval),
            interval_minutes=decode_interval(raw_interval),
            delete_on_completion=optional_bool(instance.get("DeleteOnCompletion")),
        )

    def to_dict(self) -> dict[str, Any]:
        # ``instance_id`` is what the module's ``name`` option becomes, and is the
        # only field convergence keys on. ``name`` is deliberately not duplicated
        # in here: two keys that must always agree are two keys that can disagree.
        return {
            "instance_id": self.instance_id,
            "element_name": self.element_name,
            "start_time": self.start_time,
            "interval": self.interval,
            "interval_minutes": self.interval_minutes,
            "delete_on_completion": self.delete_on_completion,
        }


def _interval_raw_text(value: Any) -> str | None:
    """The raw duration text, whichever of the two wire shapes carried it.

    The nested shape's inner element is ``<Interval>`` -- the property and its
    DMTF-common child share a name, unlike ``StartTime``/``Datetime``, which is
    why this cannot reuse :func:`decode_start_time`.
    """
    if isinstance(value, dict):
        return optional_str(value.get("Interval"))
    return optional_str(value)


def list_alarms(wsman: WsmanClient) -> list[AlarmOccurrence]:
    """Enumerate every configured alarm.

    ``Enumerate`` only, with no ``Get`` fallback, and that is a decision rather
    than an omission. ``IPS_AlarmClockOccurrence`` is a *collection* -- the whole
    question is "which alarms exist", which a ``Get`` cannot answer, and a ``Get``
    with an ``InstanceID`` selector for a name that does not exist is a fault
    rather than an empty answer, so it could not tell "no such alarm" from "no
    such class". The vendor ships ``enumerate.xml`` and ``pull.xml`` for the
    class, so the verb is directly evidenced.

    Note this is an ``IPS_``-prefixed class, so s2.7's hardware-verified
    "``Enumerate`` is HTTP 400 on AMT 10" finding does not reach it: that finding
    names five ``AMT_``-prefixed classes and says so.

    Raises :class:`UnsupportedCapabilityError` if the class is not implemented,
    which is *not* degraded here -- unlike a fact read, a caller of ``amt_alarm``
    asked specifically about alarms, and reporting "no alarms configured" for
    firmware that has no alarm clock at all would be a fabrication.
    """
    try:
        instances = wsman.enumerate(CLASS_ALARM_OCCURRENCE)
    except _DEGRADABLE_ERRORS as err:
        raise UnsupportedCapabilityError(
            f"firmware did not answer an Enumerate of {CLASS_ALARM_OCCURRENCE}: {err}",
            endpoint=wsman.endpoint,
            operation=f"Enumerate {CLASS_ALARM_OCCURRENCE}",
        ) from err
    return [AlarmOccurrence.from_instance(instance) for instance in instances]


def get_service(wsman: WsmanClient) -> dict[str, Any]:
    """``Get AMT_AlarmClockService`` -- the service instance, as a shallow dict.

    Read because it carries ``NextAMTAlarmTime`` and ``AMTAlarmClockInterval``,
    which are firmware's *own* summary of the next alarm as opposed to this
    module's reading of the occurrence list.

    **Both of those properties are absent from the vendor's captured response**
    (``responses/amt/alarmclock/get.xml`` reports only ``Name``,
    ``CreationClassName``, ``SystemName``, ``SystemCreationClassName`` and
    ``ElementName``) even though go-wsman's struct declares them. So they are
    reported as ``None`` when missing and never depended on -- convergence reads
    the occurrence list, which is evidenced.

    Degrades to ``{}`` rather than raising, deliberately: :func:`list_alarms` is
    the single gate on "does this firmware have an alarm clock", and it names the
    class and verb it actually needed. Letting this read fail the run first would
    report ``AMT_AlarmClockService`` in the error for a module whose real
    requirement is the occurrence class, and would also fail on firmware that
    happens to answer one and not the other.
    """
    try:
        return wsman.get(CLASS_ALARM_SERVICE)
    except _DEGRADABLE_ERRORS:
        return {}


def add_alarm(
    wsman: WsmanClient,
    *,
    name: str,
    start_time: datetime,
    interval_minutes: int = 0,
    delete_on_completion: bool = True,
) -> dict[str, Any]:
    """Invoke ``AMT_AlarmClockService.AddAlarm`` for one occurrence.

    The body is an embedded ``IPS_AlarmClockOccurrence`` under an ``AlarmTemplate``
    element, spanning three namespaces -- see docs/protocol-notes.md s2.10 for the
    exact shape and :class:`wsman.EmbeddedInstance` for how it is expressed.
    Property order follows both implementations' emitted order (``InstanceID``,
    ``ElementName``, ``StartTime``, ``Interval``, ``DeleteOnCompletion``); Python
    dicts preserve insertion order, so this is the order that goes on the wire.

    ``name`` becomes **both** ``InstanceID`` and ``ElementName``, per this
    module's docstring. ``Interval`` is always emitted, including for a one-shot
    alarm: go-wsman emits it unconditionally, and MeshCentral's library binding
    omits it while its own CLI always sends ``P0DT0H0M``, so "always present" is
    the shape supported by both.

    ``wsman.invoke`` raises :class:`errors.RemoteOperationError` on a non-zero
    ``ReturnValue``. That error carries the raw integer and no name, deliberately:
    go-wsman defines exactly one value for this method (``0: Success``), so
    naming anything else would be an invention.
    """
    template = EmbeddedInstance(
        namespace=resource_uri(CLASS_ALARM_OCCURRENCE),
        properties={
            "InstanceID": name,
            "ElementName": name,
            "StartTime": EmbeddedInstance(namespace=NS_CIM_COMMON, properties={"Datetime": format_start_time(start_time)}),
            "Interval": EmbeddedInstance(namespace=NS_CIM_COMMON, properties={"Interval": encode_interval(interval_minutes)}),
            "DeleteOnCompletion": delete_on_completion,
        },
    )
    output, _ = wsman.invoke(CLASS_ALARM_SERVICE, METHOD_ADD_ALARM, {PARAM_ALARM_TEMPLATE: template})
    return output


def delete_alarm(wsman: WsmanClient, name: str) -> None:
    """Destroy one occurrence by its ``InstanceID``.

    WS-Transfer ``Delete`` with a single ``InstanceID`` selector, which is exactly
    what go-wsman's ``Occurrence.Delete`` builds (``message.Selector{Name:
    "InstanceID", Value: handle}``) and what MeshCentral's meshcmd sends
    (``stack.Delete('IPS_AlarmClockOccurrence', { InstanceID: args.del })``).
    ``ElementName`` is **not** a selector on either -- MeshCentral matches on it
    only to decide whether to issue the delete, and gets away with it solely
    because it sets both fields to the same string.
    """
    wsman.delete(CLASS_ALARM_OCCURRENCE, selectors={"InstanceID": name})


# --------------------------------------------------------------------------
# Convergence
# --------------------------------------------------------------------------

#: :attr:`AlarmPlan.operation` -- desired state already holds; send nothing.
OPERATION_NONE = "none"
#: :attr:`AlarmPlan.operation` -- no such alarm; ``AddAlarm``.
OPERATION_ADD = "add"
#: :attr:`AlarmPlan.operation` -- an alarm with this name exists but differs.
#: ``Delete`` then ``AddAlarm``, in that order, because no source implements a
#: ``Put`` on the occurrence class and re-adding an existing ``InstanceID`` has no
#: defined behaviour.
OPERATION_REPLACE = "replace"
#: :attr:`AlarmPlan.operation` -- ``Delete``.
OPERATION_DELETE = "delete"


@dataclass(frozen=True, slots=True)
class AlarmPlan:
    """What convergence decided, before anything is sent.

    Separated from execution so ``check_mode`` reports the *same* decision the
    real run would make, rather than a second implementation of it -- the failure
    mode where check mode says "changed" and the real run says "ok" cannot occur
    if there is one planner.
    """

    operation: str
    changed: bool
    existing: AlarmOccurrence | None
    desired: dict[str, Any] | None

    @property
    def sends_delete(self) -> bool:
        return self.operation in (OPERATION_DELETE, OPERATION_REPLACE)

    @property
    def sends_add(self) -> bool:
        return self.operation in (OPERATION_ADD, OPERATION_REPLACE)


def find_alarm(alarms: list[AlarmOccurrence], name: str) -> AlarmOccurrence | None:
    """The occurrence whose ``InstanceID`` is ``name``, or ``None``.

    Matched on ``InstanceID`` and nothing else, because that is the key: it is
    what ``Delete``'s selector names and what ``AddAlarm`` sets. Matching on
    ``ElementName`` -- which is what MeshCentral's meshcmd does -- would find an
    alarm this module could not then delete, if the two ever differed.
    """
    return next((alarm for alarm in alarms if alarm.instance_id == name), None)


def plan(
    *,
    state: str,
    name: str,
    alarms: list[AlarmOccurrence],
    start_time: datetime | None = None,
    interval_minutes: int = 0,
    delete_on_completion: bool = True,
    firmware_clock: FirmwareClock | None = None,
    allow_past_start_time: bool = False,
    now: datetime | None = None,
) -> AlarmPlan:
    """Decide what to send, and refuse what should not be sent, without sending anything.

    ``state="present"`` compares the requested alarm against the existing one of
    the same name on **three** fields -- start time, interval and
    ``DeleteOnCompletion`` -- and reports ``changed=false`` only when all three
    already agree. Comparing on start time alone would silently leave a one-shot
    alarm where a daily one was asked for.

    The start-time comparison is between *formatted wire strings*, not parsed
    instants, and that is the conservative choice: this module knows exactly what
    text it would send, and firmware's reported text is returned verbatim. If a
    firmware generation normalises what it was given into some other spelling of
    the same instant, this reports ``changed`` forever rather than reporting
    ``ok`` for an alarm it cannot prove matches -- a loud wrong answer instead of
    a quiet one. ``docs/amt_alarm.md`` records this as the known way idempotence
    could fail on firmware nobody has run it against.

    Two refusals, both raised before any mutation:

    * **A past-dated start time**, unless ``allow_past_start_time``. Checked
      against ``firmware_clock`` when firmware would give one, and only against
      the controller's clock when it would not -- because the machine that decides
      whether the alarm has already passed is the machine holding the alarm. What
      firmware actually *does* with a past-dated alarm is not established by any
      source (see this module's docstring), which is the reason to refuse rather
      than a reason not to: "fires immediately" and "sits forever" are both
      plausible and one of them is a surprise reboot.
    * **The occurrence limit.** See :data:`MAX_ALARM_OCCURRENCES`.

    ``state="absent"`` never checks either: removing an alarm is safe whatever its
    time was, and cannot exceed a limit.
    """
    existing = find_alarm(alarms, name)

    if state == "absent":
        if existing is None:
            return AlarmPlan(operation=OPERATION_NONE, changed=False, existing=None, desired=None)
        return AlarmPlan(operation=OPERATION_DELETE, changed=True, existing=existing, desired=None)

    if start_time is None:
        raise InvalidStateError("state=present requires start_time", operation="plan_alarm")

    desired = {
        "name": name,
        "start_time": format_start_time(start_time),
        "interval": encode_interval(interval_minutes),
        "interval_minutes": interval_minutes,
        "delete_on_completion": delete_on_completion,
    }

    matches = existing is not None and (
        existing.start_time == desired["start_time"]
        and existing.interval_minutes == interval_minutes
        and existing.delete_on_completion == delete_on_completion
    )
    if matches:
        return AlarmPlan(operation=OPERATION_NONE, changed=False, existing=existing, desired=desired)

    if not allow_past_start_time:
        _refuse_past_start_time(start_time, firmware_clock=firmware_clock, now=now)

    if existing is None and len(alarms) >= MAX_ALARM_OCCURRENCES:
        raise InvalidStateError(
            f"firmware already holds {len(alarms)} {CLASS_ALARM_OCCURRENCE} instances and "
            f"{METHOD_ADD_ALARM} is documented to fail at {MAX_ALARM_OCCURRENCES} or more "
            f"(go-wsman-messages pkg/wsman/amt/alarmclock/service.go). Existing alarm names: "
            f"{sorted(alarm.instance_id or '' for alarm in alarms)}. Remove one with state=absent first.",
            operation="plan_alarm",
        )

    operation = OPERATION_REPLACE if existing is not None else OPERATION_ADD
    return AlarmPlan(operation=operation, changed=True, existing=existing, desired=desired)


def _refuse_past_start_time(start_time: datetime, *, firmware_clock: FirmwareClock | None, now: datetime | None) -> None:
    """Raise if the requested wake time has already gone by. See :func:`plan`."""
    wire_moment = datetime.strptime(format_start_time(start_time), _START_TIME_FORMAT).replace(tzinfo=timezone.utc)
    if firmware_clock is not None:
        reference = firmware_clock.moment
        whose = f"firmware's own clock ({firmware_clock.utc}, skew {firmware_clock.skew_seconds:+d}s vs this controller)"
    else:
        reference = (now or datetime.now(tz=timezone.utc)).astimezone(timezone.utc)
        whose = (
            f"this controller's clock ({reference.isoformat().replace('+00:00', 'Z')}) -- firmware would not report "
            f"its own via {CLASS_TIME_SYNC}.{METHOD_GET_LOW_ACCURACY_TIME_SYNCH}, so the comparison is against the "
            "controller and may be wrong by the RTC's drift"
        )
    if wire_moment > reference:
        return
    raise InvalidStateError(
        f"start_time resolves to {format_start_time(start_time)}, which is not in the future according to {whose}. "
        "No source this collection has establishes what firmware does with a past-dated alarm -- fire immediately, "
        "reject, or sit forever are all plausible, and one of them is an unscheduled reboot -- so this module refuses "
        "rather than finding out on your hardware. Set allow_past_start_time=true to send it anyway.",
        operation="plan_alarm",
    )
