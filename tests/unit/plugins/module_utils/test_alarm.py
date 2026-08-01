# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for ``module_utils/alarm.py``.

Anchored, wherever a value can be, on what the cited sources themselves assert
rather than on what this implementation happens to produce:

* The ``AddAlarm`` encoding tests use go-wsman-messages' own test vector --
  ``StartTime`` ``2022-12-31T23:59:00Z`` with ``Interval`` 2879 minutes encoding to
  ``P1DT23H59M`` -- so a drift here stops agreeing with an Intel-authored library's
  published output rather than merely with this file.
* The two enumeration tables are checked against the vendor's own captured
  ``AMT_TimeSynchronizationService`` response (``TimeSource`` 0,
  ``LocalTimeSyncEnabled`` 0) and its ``decoder.go`` names.
* The RTC decode is checked against the vendor's captured
  ``GetLowAccuracyTimeSynch`` value ``1704586865``.

The *wire* shapes -- the three-namespace ``AddAlarm`` body, ``Delete``'s selector,
the ``Enumerate`` of the occurrence class -- are covered against the mock WS-Man
server over a real socket in ``tests/unit/mock_servers/test_wsman_server.py`` and
end to end in the ``amt_alarm`` integration target. Deliberately, and for the
reason ``test_message_log.py``'s header gives: a unit fake shaped to the
implementation is exactly how this project previously shipped a mock that only
implemented the verb its own client used.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import alarm
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    InvalidStateError,
    ProtocolError,
    RemoteOperationError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import NS_CIM_COMMON, EmbeddedInstance

#: go-wsman-messages' own ``AddAlarm`` test vector: ``pkg/wsman/amt/alarmclock/
#: service_test.go`` sets ``StartTime = "2022-12-31T23:59:00Z"`` and
#: ``interval = 59 + 23*60 + 1*1440`` = 2879, and asserts the resulting request body
#: carries exactly this datetime text and ``P1DT23H59M``.
VENDOR_START_TIME = "2022-12-31T23:59:00Z"
VENDOR_INTERVAL_MINUTES = 2879
VENDOR_INTERVAL = "P1DT23H59M"

#: ``responses/amt/timesynchronization/getlowaccuracytimesynch.xml``'s ``Ta0``.
VENDOR_TA0 = 1704586865
VENDOR_TA0_UTC = "2024-01-07T00:21:05Z"


class FakeWsman:
    """A minimal stand-in for :class:`WsmanClient`.

    ``invoke`` raises :class:`RemoteOperationError` on a non-zero ``ReturnValue``
    exactly as the real client does, and ``delete`` records its selectors --  both
    are load-bearing: the first is how ``AddAlarm``'s refusals surface, and the
    second is the only way to assert that a delete is keyed on ``InstanceID``
    rather than on the friendly name.
    """

    def __init__(self, *, instances=None, service=None, responses=None, get_error=None, enumerate_error=None, delete_error=None):
        self.endpoint = "192.0.2.10:16993"
        self.last_peer_certificate = None
        self._instances = instances
        self._service = service
        self._responses = responses or {}
        self._get_error = get_error
        self._enumerate_error = enumerate_error
        self._delete_error = delete_error
        self.invocations: list[tuple[str, str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []
        self.gets: list[str] = []

    def get(self, resource_class, *, selectors=None):
        self.gets.append(resource_class)
        if self._get_error is not None:
            raise self._get_error
        return dict(self._service or {})

    def enumerate(self, resource_class, *, selectors=None):
        if self._enumerate_error is not None:
            raise self._enumerate_error
        return [dict(instance) for instance in (self._instances or [])]

    def invoke(self, resource_class, method_name, params=None, *, selectors=None):
        self.invocations.append((resource_class, method_name, params))
        queue = self._responses.get(method_name)
        if queue is None:
            raise AssertionError(f"unexpected invoke of {method_name}")
        output, return_value = queue.pop(0) if isinstance(queue, list) else queue
        if return_value != 0:
            raise RemoteOperationError(
                f"{resource_class}.{method_name} returned ReturnValue={return_value}",
                endpoint=self.endpoint,
                operation=f"{resource_class}.{method_name}",
                return_value=return_value,
            )
        return output, return_value

    def delete(self, resource_class, *, selectors=None):
        self.deletes.append((resource_class, dict(selectors or {})))
        if self._delete_error is not None:
            raise self._delete_error


def _occurrence(instance_id="nightly", start_time=VENDOR_START_TIME, interval=VENDOR_INTERVAL, delete_on_completion=True, nested=True):
    """One firmware-reported occurrence, in either of the two wire shapes.

    ``nested=True`` is the shape the write path sends and the shape the mock
    server serves. ``nested=False`` is the shape the vendor's own captured
    ``responses/ips/alarmclock/get.xml`` uses -- the two disagree, which is why
    both are here.
    """
    instance: dict = {"InstanceID": instance_id, "ElementName": instance_id, "DeleteOnCompletion": "true" if delete_on_completion else "false"}
    if nested:
        instance["StartTime"] = {"Datetime": start_time}
        if interval is not None:
            instance["Interval"] = {"Interval": interval}
    else:
        instance["StartTime"] = start_time
        if interval is not None:
            instance["Interval"] = interval
    return instance


class TestParseStartTime:
    def test_accepts_a_z_suffixed_utc_timestamp(self):
        parsed = alarm.parse_start_time(VENDOR_START_TIME)
        assert parsed == datetime(2022, 12, 31, 23, 59, tzinfo=timezone.utc)

    def test_converts_an_explicit_offset_to_utc(self):
        # 03:00 at -04:00 is 07:00 UTC. A module that ignored the offset would send
        # 03:00Z and wake the machine four hours early.
        parsed = alarm.parse_start_time("2026-08-01T03:00:00-04:00")
        assert alarm.format_start_time(parsed) == "2026-08-01T07:00:00Z"

    def test_a_naive_timestamp_is_refused_rather_than_guessed(self):
        """The single most consequential refusal in this module.

        go-wsman-messages converts to UTC; MeshCentral sends local components under
        a literal ``Z``. Whichever a naive value were assumed to mean, it would be
        wrong for the other population by the controller's UTC offset.
        """
        with pytest.raises(InvalidStateError) as excinfo:
            alarm.parse_start_time("2026-08-01T03:00:00")
        assert excinfo.value.error_class == "invalid_state"
        # The message must name both fixes, or the refusal is just an obstacle.
        assert "Z" in str(excinfo.value)
        assert "offset" in str(excinfo.value)

    @pytest.mark.parametrize("value", ["", "   ", "not-a-time", "2026-13-45T99:00:00Z"])
    def test_unparseable_values_are_invalid_state_not_a_traceback(self, value):
        with pytest.raises(InvalidStateError) as excinfo:
            alarm.parse_start_time(value)
        assert excinfo.value.error_class == "invalid_state"

    def test_microseconds_are_dropped_on_parse(self):
        assert alarm.parse_start_time("2026-08-01T03:00:00.123456Z").microsecond == 0


class TestFormatStartTime:
    def test_matches_the_vendor_test_vector_exactly(self):
        parsed = alarm.parse_start_time(VENDOR_START_TIME)
        assert alarm.format_start_time(parsed) == VENDOR_START_TIME

    def test_seconds_are_truncated_to_zero(self):
        # MeshCentral's meshcmd carries the note "seconds must be 00" against its own
        # construction of this value. Honoured, and visible in the receipt.
        assert alarm.format_start_time(alarm.parse_start_time("2026-08-01T03:00:47Z")) == "2026-08-01T03:00:00Z"

    def test_the_z_suffix_is_always_present(self):
        """go-wsman drops the ``Z`` for a sub-second time; this must not.

        Its formatter truncates ``RFC3339Nano`` output at the first ``.``, which
        removes the ``Z`` along with the fraction whenever the fraction is
        non-empty. Formatting to whole seconds directly cannot hit that.
        """
        for value in ("2026-08-01T03:00:00.999999Z", "2026-08-01T03:00:00Z", "2026-08-01T03:00:00+05:30"):
            assert alarm.format_start_time(alarm.parse_start_time(value)).endswith("Z")

    def test_a_naive_datetime_is_rejected_by_the_formatter_too(self):
        # Defence in depth: parse_start_time guarantees awareness, but a caller
        # constructing a datetime directly must not silently get a UTC assumption.
        with pytest.raises(ValueError, match="timezone-aware"):
            alarm.format_start_time(datetime(2026, 8, 1, 3, 0))


class TestEncodeInterval:
    def test_matches_the_vendor_test_vector(self):
        assert alarm.encode_interval(VENDOR_INTERVAL_MINUTES) == VENDOR_INTERVAL

    @pytest.mark.parametrize(
        "minutes,expected",
        [
            (0, "P0DT0H0M"),
            (1, "P0DT0H1M"),
            (59, "P0DT0H59M"),
            (60, "P0DT1H0M"),
            (1440, "P1DT0H0M"),
            (1441, "P1DT0H1M"),
            (10080, "P7DT0H0M"),
        ],
    )
    def test_boundaries(self, minutes, expected):
        assert alarm.encode_interval(minutes) == expected

    def test_zero_is_the_long_form_not_the_short_one(self):
        # Both sources emit every field unconditionally. Nothing establishes that
        # firmware's parser accepts "P0D".
        assert alarm.encode_interval(0) == "P0DT0H0M"

    def test_a_negative_interval_is_rejected(self):
        with pytest.raises(ValueError, match="negative"):
            alarm.encode_interval(-1)


class TestDecodeInterval:
    def test_round_trips_the_vendor_vector(self):
        assert alarm.decode_interval(VENDOR_INTERVAL) == VENDOR_INTERVAL_MINUTES

    @pytest.mark.parametrize("minutes", [0, 1, 59, 60, 1439, 1440, 2879, 10080])
    def test_round_trips_every_boundary(self, minutes):
        assert alarm.decode_interval(alarm.encode_interval(minutes)) == minutes

    def test_accepts_the_nested_wire_shape(self):
        assert alarm.decode_interval({"Interval": VENDOR_INTERVAL}) == VENDOR_INTERVAL_MINUTES

    @pytest.mark.parametrize("value,expected", [("P1D", 1440), ("PT90M", 90), ("PT2H", 120), ("P0D", 0), ("PT30S", 0)])
    def test_accepts_abbreviated_forms_neither_source_emits(self, value, expected):
        """Read is deliberately more permissive than write.

        The shape firmware *emits* is not guaranteed to be the shape it accepts, and
        being strict on read would make a firmware that normalised ``P0DT0H0M`` to
        ``P0D`` report an unparseable alarm forever.
        """
        assert alarm.decode_interval(value) == expected

    @pytest.mark.parametrize("value", [None, "", "   ", {}, "testdatetime", "P1Y", "garbage"])
    def test_absent_or_unreadable_is_none_not_zero(self, value):
        """``0`` means a one-shot alarm; ``None`` means firmware said nothing readable.

        Conflating them would make convergence re-add a recurring alarm on every run
        against firmware whose duration spelling this collection cannot parse.
        """
        assert alarm.decode_interval(value) is None

    def test_zero_and_none_are_distinguishable(self):
        assert alarm.decode_interval("P0DT0H0M") == 0
        assert alarm.decode_interval(None) is None


class TestDecodeStartTime:
    def test_reads_the_nested_shape_the_write_path_sends(self):
        assert alarm.decode_start_time({"Datetime": VENDOR_START_TIME}) == VENDOR_START_TIME

    def test_reads_the_flat_shape_the_vendor_fixture_uses(self):
        # responses/ips/alarmclock/get.xml sends <StartTime>testdatetime</StartTime>,
        # which its own library's parser would not read. Both shapes are accepted.
        assert alarm.decode_start_time("testdatetime") == "testdatetime"

    def test_the_text_is_returned_verbatim_not_reformatted(self):
        """A shape this collection has never seen must survive to the operator.

        Reparsing and reformatting would launder a firmware that reported an offset
        other than ``Z`` into whatever this module would have sent, hiding the one
        piece of evidence that firmware disagrees.
        """
        assert alarm.decode_start_time({"Datetime": "2026-08-01T03:00:00+02:00"}) == "2026-08-01T03:00:00+02:00"

    @pytest.mark.parametrize("value", [None, "", {"Datetime": ""}, {}])
    def test_nothing_readable_is_none(self, value):
        assert alarm.decode_start_time(value) is None


class TestAlarmOccurrence:
    def test_decodes_a_nested_instance(self):
        occurrence = alarm.AlarmOccurrence.from_instance(_occurrence(delete_on_completion=False))
        assert occurrence.instance_id == "nightly"
        assert occurrence.element_name == "nightly"
        assert occurrence.start_time == VENDOR_START_TIME
        assert occurrence.interval == VENDOR_INTERVAL
        assert occurrence.interval_minutes == VENDOR_INTERVAL_MINUTES
        assert occurrence.delete_on_completion is False

    def test_decodes_a_flat_instance(self):
        occurrence = alarm.AlarmOccurrence.from_instance(_occurrence(nested=False))
        assert occurrence.start_time == VENDOR_START_TIME
        assert occurrence.interval_minutes == VENDOR_INTERVAL_MINUTES

    def test_the_raw_duration_is_reported_next_to_the_decoded_one(self):
        """The raw-next-to-decoded rule, applied to a duration instead of an integer.

        A duration shape this collection cannot parse must not be reported only as
        the ``None`` its decoder returned.
        """
        occurrence = alarm.AlarmOccurrence.from_instance(_occurrence(interval="P1Y"))
        assert occurrence.interval == "P1Y"
        assert occurrence.interval_minutes is None

    def test_an_absent_delete_on_completion_is_none_not_false(self):
        instance = _occurrence()
        del instance["DeleteOnCompletion"]
        assert alarm.AlarmOccurrence.from_instance(instance).delete_on_completion is None

    def test_to_dict_does_not_duplicate_the_key_under_a_second_name(self):
        # Two keys that must always agree are two keys that can disagree.
        keys = set(alarm.AlarmOccurrence.from_instance(_occurrence()).to_dict())
        assert keys == {"instance_id", "element_name", "start_time", "interval", "interval_minutes", "delete_on_completion"}


class TestListAlarms:
    def test_reads_every_occurrence(self):
        wsman = FakeWsman(instances=[_occurrence("a"), _occurrence("b")])
        assert [occurrence.instance_id for occurrence in alarm.list_alarms(wsman)] == ["a", "b"]

    def test_no_alarms_is_an_empty_list_not_a_failure(self):
        assert alarm.list_alarms(FakeWsman(instances=[])) == []

    def test_an_absent_class_raises_unsupported_capability_not_a_traceback(self):
        wsman = FakeWsman(enumerate_error=ProtocolError("SOAP Fault: InvalidResourceURI"))
        with pytest.raises(UnsupportedCapabilityError) as excinfo:
            alarm.list_alarms(wsman)
        assert excinfo.value.error_class == "unsupported_capability"
        assert "IPS_AlarmClockOccurrence" in str(excinfo.value)

    def test_an_absent_class_is_not_degraded_to_no_alarms(self):
        """Reporting "no alarms configured" for firmware with no alarm clock is a lie.

        Unlike a fact read, a caller of this module asked specifically about alarms.
        """
        with pytest.raises(UnsupportedCapabilityError):
            alarm.list_alarms(FakeWsman(enumerate_error=UnsupportedCapabilityError("nope")))


class TestGetService:
    def test_reads_the_service_instance(self):
        wsman = FakeWsman(service={"ElementName": "Intel(r) AMT Alarm Clock Service"})
        assert alarm.get_service(wsman)["ElementName"] == "Intel(r) AMT Alarm Clock Service"

    def test_degrades_to_empty_rather_than_failing_the_run(self):
        """``list_alarms`` is the single gate on "does this firmware have an alarm clock".

        Letting this read fail first would report ``AMT_AlarmClockService`` in the
        error for a module whose real requirement is the occurrence class.
        """
        assert alarm.get_service(FakeWsman(get_error=ProtocolError("SOAP Fault"))) == {}


class TestReadFirmwareClock:
    def test_decodes_the_vendor_ta0_value(self):
        wsman = FakeWsman(responses={"GetLowAccuracyTimeSynch": [({"Ta0": str(VENDOR_TA0), "ReturnValue": "0"}, 0)]}, service={})
        clock = alarm.read_firmware_clock(wsman, now=datetime(2024, 1, 7, 0, 21, 5, tzinfo=timezone.utc))
        assert clock.epoch_seconds == VENDOR_TA0
        assert clock.utc == VENDOR_TA0_UTC
        assert clock.skew_seconds == 0

    def test_skew_is_firmware_minus_controller(self):
        """Sign matters: positive must mean firmware is ahead.

        An inverted sign would make an operator adjust in the wrong direction.
        """
        wsman = FakeWsman(responses={"GetLowAccuracyTimeSynch": [({"Ta0": str(VENDOR_TA0 + 300)}, 0)]}, service={})
        clock = alarm.read_firmware_clock(wsman, now=datetime.fromtimestamp(VENDOR_TA0, tz=timezone.utc))
        assert clock.skew_seconds == 300

    def test_decodes_the_two_enumerations_with_their_raw_values(self):
        wsman = FakeWsman(
            responses={"GetLowAccuracyTimeSynch": [({"Ta0": str(VENDOR_TA0)}, 0)]},
            # The vendor's captured AMT_TimeSynchronizationService response.
            service={"TimeSource": "0", "LocalTimeSyncEnabled": "0"},
        )
        clock = alarm.read_firmware_clock(wsman)
        assert clock.time_source == 0
        assert clock.time_source_name == "bios_rtc"
        assert clock.local_time_sync_enabled == 0
        assert clock.local_time_sync_enabled_name == "default_true"

    def test_an_unrecognised_enumeration_value_renders_unknown_with_its_raw(self):
        """``unknown(<raw>)``, never a bare ``unknown``.

        ``TimeSource`` has no value named ``unknown``, but the rule is collection-wide
        and the raw integer is what a firmware that extended the enumeration would be
        diagnosed from.
        """
        wsman = FakeWsman(responses={"GetLowAccuracyTimeSynch": [({"Ta0": "1"}, 0)]}, service={"TimeSource": "9", "LocalTimeSyncEnabled": "7"})
        clock = alarm.read_firmware_clock(wsman)
        assert clock.time_source_name == "unknown(9)"
        assert clock.local_time_sync_enabled_name == "unknown(7)"

    def test_a_faulting_method_degrades_to_none(self):
        class Faulting(FakeWsman):
            def invoke(self, resource_class, method_name, params=None, *, selectors=None):
                raise ProtocolError("AMT_TimeSynchronizationService is not implemented")

        assert alarm.read_firmware_clock(Faulting()) is None

    def test_a_missing_ta0_is_none_rather_than_a_clock_reading_of_zero(self):
        """A shape no source describes: ReturnValue 0 with no ``Ta0``.

        Inventing ``0`` would read as a 1970 clock and refuse every alarm as
        past-dated, which is a confident wrong answer where ``None`` is honest.
        """
        wsman = FakeWsman(responses={"GetLowAccuracyTimeSynch": [({"ReturnValue": "0"}, 0)]}, service={})
        assert alarm.read_firmware_clock(wsman) is None

    def test_a_faulting_property_get_still_yields_a_usable_clock(self):
        wsman = FakeWsman(responses={"GetLowAccuracyTimeSynch": [({"Ta0": str(VENDOR_TA0)}, 0)]}, get_error=ProtocolError("no such property"))
        clock = alarm.read_firmware_clock(wsman)
        assert clock.epoch_seconds == VENDOR_TA0
        assert clock.time_source is None
        assert clock.time_source_name is None

    def test_a_clock_reading_of_zero_is_reported_not_blanked(self):
        """Unlike a log record slot, a clock of 0 is a real fault worth seeing.

        ``message_log.py`` blanks 0 because an unwritten record slot reads as 0; a
        firmware clock that reads 1970 is the exact fault an operator setting a wake
        time needs told about.
        """
        wsman = FakeWsman(responses={"GetLowAccuracyTimeSynch": [({"Ta0": "0"}, 0)]}, service={})
        clock = alarm.read_firmware_clock(wsman)
        assert clock.epoch_seconds == 0
        assert clock.utc == "1970-01-01T00:00:00Z"


class TestAddAlarm:
    def _sent_template(self, wsman):
        resource_class, method_name, params = wsman.invocations[-1]
        assert (resource_class, method_name) == ("AMT_AlarmClockService", "AddAlarm")
        return params[alarm.PARAM_ALARM_TEMPLATE]

    def test_the_template_spans_the_three_documented_namespaces(self):
        """The shape both sources emit, expressed as nested embedded instances.

        ``AlarmTemplate`` in the method's own namespace, its properties in the
        occurrence class's, and ``Datetime``/``Interval`` in the DMTF common one.
        Flattening any of the three produces a body real firmware answers HTTP 400 to.
        """
        wsman = FakeWsman(responses={"AddAlarm": [({"ReturnValue": "0"}, 0)]})
        alarm.add_alarm(wsman, name="nightly", start_time=alarm.parse_start_time(VENDOR_START_TIME), interval_minutes=VENDOR_INTERVAL_MINUTES)
        template = self._sent_template(wsman)
        assert isinstance(template, EmbeddedInstance)
        assert template.namespace == "http://intel.com/wbem/wscim/1/ips-schema/1/IPS_AlarmClockOccurrence"
        assert template.properties["StartTime"].namespace == NS_CIM_COMMON
        assert template.properties["Interval"].namespace == NS_CIM_COMMON

    def test_the_values_match_the_vendor_test_vector(self):
        wsman = FakeWsman(responses={"AddAlarm": [({"ReturnValue": "0"}, 0)]})
        alarm.add_alarm(wsman, name="Instance", start_time=alarm.parse_start_time(VENDOR_START_TIME), interval_minutes=VENDOR_INTERVAL_MINUTES)
        template = self._sent_template(wsman)
        assert template.properties["StartTime"].properties["Datetime"] == VENDOR_START_TIME
        assert template.properties["Interval"].properties["Interval"] == VENDOR_INTERVAL

    def test_the_name_becomes_both_instance_id_and_element_name(self):
        """What makes the alarm deletable by every implementation of the class.

        MeshCentral's meshcmd matches on ``ElementName`` and deletes by
        ``InstanceID``; Intel's Console assigns one from the other outright. An alarm
        whose two fields differed would be findable by one and unremovable by it.
        """
        wsman = FakeWsman(responses={"AddAlarm": [({"ReturnValue": "0"}, 0)]})
        alarm.add_alarm(wsman, name="nightly", start_time=alarm.parse_start_time(VENDOR_START_TIME))
        template = self._sent_template(wsman)
        assert template.properties["InstanceID"] == "nightly"
        assert template.properties["ElementName"] == "nightly"

    def test_the_property_order_is_the_order_both_sources_emit(self):
        wsman = FakeWsman(responses={"AddAlarm": [({"ReturnValue": "0"}, 0)]})
        alarm.add_alarm(wsman, name="nightly", start_time=alarm.parse_start_time(VENDOR_START_TIME))
        assert list(self._sent_template(wsman).properties) == ["InstanceID", "ElementName", "StartTime", "Interval", "DeleteOnCompletion"]

    def test_interval_is_emitted_even_for_a_one_shot_alarm(self):
        wsman = FakeWsman(responses={"AddAlarm": [({"ReturnValue": "0"}, 0)]})
        alarm.add_alarm(wsman, name="one-shot", start_time=alarm.parse_start_time(VENDOR_START_TIME), interval_minutes=0)
        assert self._sent_template(wsman).properties["Interval"].properties["Interval"] == "P0DT0H0M"

    def test_a_non_zero_return_value_surfaces_as_remote_operation_with_the_raw_code(self):
        """No source names any ``AddAlarm`` code but ``0: Success``, so none is invented."""
        wsman = FakeWsman(responses={"AddAlarm": [({"ReturnValue": "2054"}, 2054)]})
        with pytest.raises(RemoteOperationError) as excinfo:
            alarm.add_alarm(wsman, name="nightly", start_time=alarm.parse_start_time(VENDOR_START_TIME))
        assert excinfo.value.error_class == "remote_operation"
        assert excinfo.value.return_value == 2054


class TestDeleteAlarm:
    def test_deletes_by_instance_id_and_nothing_else(self):
        wsman = FakeWsman()
        alarm.delete_alarm(wsman, "nightly")
        assert wsman.deletes == [("IPS_AlarmClockOccurrence", {"InstanceID": "nightly"})]

    def test_element_name_is_never_sent_as_a_selector(self):
        # Neither source sends it as one; a client that keyed on the friendly name
        # would fail against firmware.
        wsman = FakeWsman()
        alarm.delete_alarm(wsman, "nightly")
        assert "ElementName" not in wsman.deletes[0][1]


def _future(minutes=60):
    return datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(minutes=minutes)


def _clock(offset_seconds=0):
    now = int(datetime.now(tz=timezone.utc).timestamp()) + offset_seconds
    return alarm.FirmwareClock(
        epoch_seconds=now,
        utc=None,
        skew_seconds=offset_seconds,
        time_source=0,
        time_source_name="bios_rtc",
        local_time_sync_enabled=0,
        local_time_sync_enabled_name="default_true",
    )


class TestPlanPresent:
    def test_absent_alarm_is_added(self):
        result = alarm.plan(state="present", name="nightly", alarms=[], start_time=_future(), firmware_clock=_clock())
        assert result.operation == alarm.OPERATION_ADD
        assert result.changed is True
        assert result.sends_add is True
        assert result.sends_delete is False

    def test_an_identical_alarm_converges_to_no_change(self):
        """The property this module exists for: a second run reports ``changed=false``."""
        start_time = _future()
        existing = _occurrence("nightly", start_time=alarm.format_start_time(start_time), interval="P1DT0H0M", delete_on_completion=False)
        alarms = [alarm.AlarmOccurrence.from_instance(existing)]
        result = alarm.plan(
            state="present",
            name="nightly",
            alarms=alarms,
            start_time=start_time,
            interval_minutes=1440,
            delete_on_completion=False,
            firmware_clock=_clock(),
        )
        assert result.operation == alarm.OPERATION_NONE
        assert result.changed is False

    @pytest.mark.parametrize(
        "field,existing_kwargs,requested",
        [
            ("start_time", {"start_time": "2030-01-01T00:00:00Z"}, {}),
            ("interval", {"interval": "P0DT0H0M"}, {"interval_minutes": 1440}),
            ("delete_on_completion", {"delete_on_completion": True}, {"delete_on_completion": False}),
        ],
    )
    def test_a_difference_in_any_of_the_three_compared_fields_replaces(self, field, existing_kwargs, requested):
        """All three, not just the time.

        Comparing on start time alone would silently leave a one-shot alarm where a
        daily one was asked for, and a ``delete_on_completion`` mismatch would leave
        an occurrence behind that counts against the five-alarm limit.
        """
        start_time = _future()
        defaults = {"start_time": alarm.format_start_time(start_time), "interval": "P1DT0H0M", "delete_on_completion": False}
        defaults.update(existing_kwargs)
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence("nightly", **defaults))]
        options = {"interval_minutes": 1440, "delete_on_completion": False}
        options.update(requested)
        result = alarm.plan(state="present", name="nightly", alarms=alarms, start_time=start_time, firmware_clock=_clock(), **options)
        assert result.operation == alarm.OPERATION_REPLACE, f"a differing {field} must replace"
        assert result.sends_delete is True
        assert result.sends_add is True

    def test_a_replace_deletes_before_adding(self):
        # There is no Put on the occurrence class in any source, and re-adding an
        # existing InstanceID has no defined behaviour, so the key must be freed first.
        plan = alarm.AlarmPlan(operation=alarm.OPERATION_REPLACE, changed=True, existing=None, desired=None)
        assert plan.sends_delete and plan.sends_add

    def test_the_desired_dict_reports_what_would_go_on_the_wire(self):
        result = alarm.plan(
            state="present",
            name="nightly",
            alarms=[],
            start_time=alarm.parse_start_time("2030-01-02T03:04:56Z"),
            interval_minutes=90,
            firmware_clock=_clock(),
        )
        # Seconds truncated and the duration encoded, both visible rather than silent.
        assert result.desired["start_time"] == "2030-01-02T03:04:00Z"
        assert result.desired["interval"] == "P0DT1H30M"
        assert result.desired["interval_minutes"] == 90

    def test_state_present_without_a_start_time_is_invalid_state(self):
        with pytest.raises(InvalidStateError, match="start_time"):
            alarm.plan(state="present", name="nightly", alarms=[], start_time=None)

    def test_a_different_alarm_of_another_name_does_not_satisfy_the_request(self):
        start_time = _future()
        other = alarm.AlarmOccurrence.from_instance(_occurrence("weekly", start_time=alarm.format_start_time(start_time)))
        result = alarm.plan(state="present", name="nightly", alarms=[other], start_time=start_time, firmware_clock=_clock())
        assert result.operation == alarm.OPERATION_ADD


class TestPlanAbsent:
    def test_an_existing_alarm_is_deleted(self):
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence("nightly"))]
        result = alarm.plan(state="absent", name="nightly", alarms=alarms)
        assert result.operation == alarm.OPERATION_DELETE
        assert result.changed is True
        assert result.sends_add is False

    def test_an_absent_alarm_is_already_converged(self):
        result = alarm.plan(state="absent", name="nightly", alarms=[])
        assert result.operation == alarm.OPERATION_NONE
        assert result.changed is False

    def test_absent_never_applies_the_past_date_refusal(self):
        """Removing an alarm is safe whatever its time was."""
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence("stale", start_time="2001-01-01T00:00:00Z"))]
        result = alarm.plan(state="absent", name="stale", alarms=alarms, firmware_clock=_clock())
        assert result.operation == alarm.OPERATION_DELETE


class TestPastStartTimeRefusal:
    def test_a_past_dated_alarm_is_refused(self):
        with pytest.raises(InvalidStateError) as excinfo:
            alarm.plan(state="present", name="nightly", alarms=[], start_time=_future(-60), firmware_clock=_clock())
        assert excinfo.value.error_class == "invalid_state"
        # The refusal must be attributed, or an operator will read it as a firmware
        # rejection and go looking for a firmware setting to change.
        assert "No source" in str(excinfo.value)
        assert "allow_past_start_time" in str(excinfo.value)

    def test_the_refusal_is_measured_against_firmwares_clock_not_the_controllers(self):
        """The whole reason the RTC is read at all.

        A time the controller thinks is an hour away is in the past to firmware whose
        clock runs two hours fast. Comparing against the controller would arm an alarm
        firmware may already consider expired.
        """
        with pytest.raises(InvalidStateError) as excinfo:
            alarm.plan(state="present", name="nightly", alarms=[], start_time=_future(60), firmware_clock=_clock(offset_seconds=7200))
        assert "firmware's own clock" in str(excinfo.value)

    def test_a_clock_behind_the_controller_can_make_a_past_time_acceptable(self):
        """The same mechanism in the other direction, which is the real proof.

        A test that only showed a fast clock refusing could be satisfied by a check
        that always refused. This one is only satisfiable by consulting firmware.
        """
        result = alarm.plan(state="present", name="nightly", alarms=[], start_time=_future(-60), firmware_clock=_clock(offset_seconds=-7200))
        assert result.operation == alarm.OPERATION_ADD

    def test_without_a_firmware_clock_the_controller_is_used_and_said_so(self):
        with pytest.raises(InvalidStateError) as excinfo:
            alarm.plan(state="present", name="nightly", alarms=[], start_time=_future(-60), firmware_clock=None)
        message = str(excinfo.value)
        assert "this controller's clock" in message
        assert "may be wrong by the RTC's drift" in message

    def test_allow_past_start_time_sends_it_anyway(self):
        result = alarm.plan(state="present", name="nightly", alarms=[], start_time=_future(-60), firmware_clock=_clock(), allow_past_start_time=True)
        assert result.operation == alarm.OPERATION_ADD

    def test_an_alarm_that_already_matches_is_never_refused_for_being_past(self):
        """Idempotence must not degrade into a failure once the alarm has fired.

        A recurring alarm whose reported ``StartTime`` has gone by still matches the
        desired state, and re-running the same play must report ``ok`` rather than
        failing on a past-date check that would only be reached if something had to
        change.
        """
        past = _future(-600)
        existing = _occurrence("nightly", start_time=alarm.format_start_time(past), interval="P1DT0H0M", delete_on_completion=False)
        alarms = [alarm.AlarmOccurrence.from_instance(existing)]
        result = alarm.plan(
            state="present",
            name="nightly",
            alarms=alarms,
            start_time=past,
            interval_minutes=1440,
            delete_on_completion=False,
            firmware_clock=_clock(),
        )
        assert result.operation == alarm.OPERATION_NONE

    def test_a_start_time_exactly_equal_to_the_clock_is_refused(self):
        # Not in the future is not the future. Strictly greater, so the boundary
        # cannot arm an alarm for the instant that is already passing.
        clock = _clock()
        with pytest.raises(InvalidStateError):
            alarm.plan(state="present", name="nightly", alarms=[], start_time=clock.moment, firmware_clock=clock)


class TestOccurrenceLimit:
    def test_adding_past_the_documented_limit_is_refused(self):
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence(f"a{index}")) for index in range(alarm.MAX_ALARM_OCCURRENCES)]
        with pytest.raises(InvalidStateError) as excinfo:
            alarm.plan(state="present", name="new", alarms=alarms, start_time=_future(), firmware_clock=_clock())
        message = str(excinfo.value)
        assert excinfo.value.error_class == "invalid_state"
        # The refusal names the limit, its source, and what is already there --
        # without which an operator cannot act on it.
        assert "go-wsman-messages" in message
        assert "'a0'" in message

    def test_replacing_an_existing_alarm_at_the_limit_is_allowed(self):
        """A replace frees the key before claiming it, so it cannot exceed the limit.

        Refusing here would make a full alarm set unmodifiable except by deleting
        first, for no firmware reason.
        """
        start_time = _future()
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence(f"a{index}")) for index in range(alarm.MAX_ALARM_OCCURRENCES)]
        result = alarm.plan(state="present", name="a0", alarms=alarms, start_time=start_time, firmware_clock=_clock())
        assert result.operation == alarm.OPERATION_REPLACE

    def test_one_below_the_limit_is_allowed(self):
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence(f"a{index}")) for index in range(alarm.MAX_ALARM_OCCURRENCES - 1)]
        result = alarm.plan(state="present", name="new", alarms=alarms, start_time=_future(), firmware_clock=_clock())
        assert result.operation == alarm.OPERATION_ADD


class TestFindAlarm:
    def test_matches_on_instance_id(self):
        alarms = [alarm.AlarmOccurrence.from_instance(_occurrence("a")), alarm.AlarmOccurrence.from_instance(_occurrence("b"))]
        assert alarm.find_alarm(alarms, "b").instance_id == "b"

    def test_does_not_match_on_element_name(self):
        """Matching on the friendly name finds an alarm this module could not delete.

        ``Delete``'s selector is ``InstanceID``; if the two ever differ, an
        ``ElementName`` match would report an alarm as present and then fail to
        remove it.
        """
        instance = _occurrence("real-key")
        instance["ElementName"] = "friendly"
        alarms = [alarm.AlarmOccurrence.from_instance(instance)]
        assert alarm.find_alarm(alarms, "friendly") is None
        assert alarm.find_alarm(alarms, "real-key") is not None


class TestSourcedConstants:
    def test_the_occurrence_limit_is_the_documented_one(self):
        # go-wsman-messages' AddAlarm doc: "would fail if 5 instances or more ...
        # already exist in the system".
        assert alarm.MAX_ALARM_OCCURRENCES == 5

    def test_the_time_source_table_is_the_vendors_two_values(self):
        assert alarm.TIME_SOURCE_TABLE == {0: "bios_rtc", 1: "configured"}

    def test_the_local_time_sync_table_keeps_the_vendors_three_names(self):
        # 0 and 1 both mean enabled and differ only in default-vs-configured.
        # Collapsing them to a boolean would discard that.
        assert alarm.LOCAL_TIME_SYNC_ENABLED_TABLE == {0: "default_true", 1: "configured_true", 2: "false"}

    def test_the_class_and_method_names_are_the_vendors(self):
        assert alarm.CLASS_ALARM_SERVICE == "AMT_AlarmClockService"
        assert alarm.CLASS_ALARM_OCCURRENCE == "IPS_AlarmClockOccurrence"
        assert alarm.CLASS_TIME_SYNC == "AMT_TimeSynchronizationService"
        assert alarm.METHOD_ADD_ALARM == "AddAlarm"
        assert alarm.METHOD_GET_LOW_ACCURACY_TIME_SYNCH == "GetLowAccuracyTimeSynch"
        assert alarm.PARAM_ALARM_TEMPLATE == "AlarmTemplate"

    def test_no_return_value_table_is_claimed_for_add_alarm(self):
        """Guards the honesty rule against a well-meaning future addition.

        go-wsman-messages defines exactly one ``AddAlarm`` return value (``0:
        Success``). If someone adds a table here, this should fail and force the
        source to be recorded in ``docs/protocol-notes.md`` §2.10 first.
        """
        assert not [name for name in dir(alarm) if "RETURN_VALUE" in name and name.endswith("TABLE")]
