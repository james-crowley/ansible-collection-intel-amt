# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for ``module_utils/message_log.py``.

The record-decode tests are anchored on the **two real firmware records** in
``go-wsman-messages``' ``pkg/wsman/wsmantesting/responses/amt/messagelog/getrecords.xml``,
and the expected decoded values are the ones that project's own ``log_test.go``
asserts for those exact bytes. That is what makes them evidence rather than a
restatement of this collection's implementation: if the decode here drifts, it
stops agreeing with an Intel-authored decoder's published output for real
firmware data.

The iteration tests use a fake transport so that batch boundaries, stalled
iterators and hostile return values can be constructed directly. The
corresponding *wire* shapes are covered against the mock WS-Man server in
``tests/unit/mock_servers/test_wsman_server.py`` and end to end in the
integration targets -- deliberately, because a unit mock shaped to the
implementation is exactly how this project previously missed a mock server that
only implemented ``Get`` for a class firmware served via ``Enumerate``.
"""

from __future__ import annotations

import base64
import struct

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import message_log
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    ProtocolError,
    RemoteOperationError,
    UnsupportedCapabilityError,
)

#: Real firmware record, from ``getrecords.xml``. go-wsman-messages' own test
#: asserts: TimeStamp 0x6598c863, DeviceAddress 255, EventSensorType 6,
#: EventType 111, EventOffset 5, EventSourceType 104, EventSeverity 16,
#: SensorNumber 255, Entity 38, EntityInstance 97, EventData [0xaa,0x0a,0,...],
#: Entity "Intel(r) ME", EventSeverity "Critical condition", Description
#: "Authentication failed 10 times. The system may be under attack."
REAL_RECORD_AUTH_FAILURE = "Y8iYZf8GbwVoEP8mYaoKAAAAAAAA"

#: Real firmware record, from ``getrecords.xml``. Asserted upstream as:
#: TimeStamp 0x65010622, EventSensorType 15, EventOffset 2, EventSeverity 1,
#: Entity 34, Entity "BIOS", EventSeverity "Monitor", Description
#: "PCI resource configuration".
REAL_RECORD_FIRMWARE_PROGRESS = "IgYBZf8PbwJoAf8iAEAHAAAAAAAA"

#: An **empty record slot** as real firmware sends it: 21 zero bytes, base64. Copied
#: verbatim from the ``raw_base64`` of the record that appears **205 times** in the
#: 223-element read from ``amt-lab-01`` (AMT 16.1.30) captured as
#: ``hardware-evidence/amt-lab-01-qualify_event_log.json`` on CircleCI job 2976 --
#: the read whose ``CurrentNumberOfRecords`` was 18. Not constructed here; the string
#: is the evidence.
EMPTY_SLOT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _encode(
    *,
    timestamp: int = 0x65010622,
    device_address: int = 0xFF,
    event_sensor_type: int = 15,
    event_type: int = 0x6F,
    event_offset: int = 2,
    event_source_type: int = 0x68,
    event_severity: int = 1,
    sensor_number: int = 0xFF,
    entity: int = 34,
    entity_instance: int = 0,
    event_data: bytes = b"\x40\x07\x00\x00\x00\x00\x00\x00",
) -> str:
    """Build a synthetic 21-byte record, base64-encoded as firmware sends it."""
    raw = struct.pack(
        "<IBBBBBBBBB8s",
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
    )
    return base64.b64encode(raw).decode("ascii")


class FakeWsman:
    """A minimal stand-in for :class:`WsmanClient`.

    ``invoke`` raises :class:`RemoteOperationError` on a non-zero ``ReturnValue``,
    exactly as the real client does -- that behaviour is load-bearing here, because
    an empty event log *is* a non-zero return value and must not surface as a
    failure.
    """

    def __init__(self, *, instance=None, enumerate_result=None, responses=None, get_error=None, enumerate_error=None):
        self.endpoint = "192.0.2.10:16993"
        self.last_peer_certificate = None
        self._instance = instance
        self._enumerate_result = enumerate_result
        self._get_error = get_error
        self._enumerate_error = enumerate_error
        #: method name -> list of (output_dict, return_value) to serve in order
        self._responses = responses or {}
        self.calls: list[tuple[str, dict | None]] = []
        self.get_calls = 0

    def get(self, resource_class, *, selectors=None):
        self.get_calls += 1
        if self._get_error is not None:
            raise self._get_error
        return dict(self._instance) if self._instance else {}

    def enumerate(self, resource_class, *, selectors=None):
        if self._enumerate_error is not None:
            raise self._enumerate_error
        return list(self._enumerate_result or [])

    def invoke(self, resource_class, method_name, params=None, *, selectors=None):
        self.calls.append((method_name, params))
        queue = self._responses.get(method_name)
        if not queue:
            raise AssertionError(f"unexpected invoke of {method_name}")
        output, return_value = queue.pop(0)
        if return_value != 0:
            raise RemoteOperationError(
                f"{resource_class}.{method_name} returned ReturnValue={return_value}",
                endpoint=self.endpoint,
                operation=f"{resource_class}.{method_name}",
                return_value=return_value,
            )
        return output, return_value


LOG_INSTANCE = {
    "Capabilities": ["5", "6", "8", "7"],
    "CurrentNumberOfRecords": "6",
    "MaxNumberOfRecords": "390",
    "MaxRecordSize": "21",
    "ElementName": "Intel(r) AMT:MessageLog 1",
    "IsFrozen": "false",
    "LogState": "4",
    "OverwritePolicy": "2",
}


def _batch(records, *, next_identifier, no_more):
    return {
        "IterationIdentifier": str(next_identifier),
        "NoMoreRecords": "true" if no_more else "false",
        "RecordArray": records,
        "ReturnValue": "0",
    }


class TestDecodeRealFirmwareRecords:
    """The decode, checked against an Intel-authored decoder's published output."""

    def test_authentication_failure_record_matches_upstream_expectations(self):
        record = message_log.decode_record(REAL_RECORD_AUTH_FAILURE)
        assert record.decode_error is None
        assert record.timestamp == 0x6598C863
        assert record.device_address == 255
        assert record.event_sensor_type == 6
        assert record.event_type == 111
        assert record.event_offset == 5
        assert record.event_source_type == 104
        assert record.event_severity == 16
        assert record.sensor_number == 255
        assert record.entity == 38
        assert record.entity_instance == 97
        assert record.event_data == [0xAA, 0x0A, 0, 0, 0, 0, 0, 0]
        assert record.entity_text == "Intel(r) ME"
        assert record.event_severity_text == "critical"
        assert record.description == "Authentication failed 10 times. The system may be under attack."

    def test_firmware_progress_record_matches_upstream_expectations(self):
        record = message_log.decode_record(REAL_RECORD_FIRMWARE_PROGRESS)
        assert record.decode_error is None
        assert record.timestamp == 0x65010622
        assert record.event_sensor_type == 15
        assert record.event_offset == 2
        assert record.entity_text == "BIOS"
        assert record.event_severity_text == "monitor"
        assert record.description == "PCI resource configuration"

    def test_timestamp_is_little_endian(self):
        """Reading the timestamp big-endian would look odd, not wrong -- so assert it."""
        raw = base64.b64decode(REAL_RECORD_AUTH_FAILURE)
        assert raw[:4] == b"\x63\xc8\x98\x65"
        assert message_log.decode_record(REAL_RECORD_AUTH_FAILURE).timestamp == 0x6598C863
        assert int.from_bytes(raw[:4], "big") != 0x6598C863

    def test_raw_bytes_are_always_returned_alongside_the_decode(self):
        record = message_log.decode_record(REAL_RECORD_AUTH_FAILURE)
        assert record.raw_base64 == REAL_RECORD_AUTH_FAILURE
        assert record.raw_hex == "63c89865ff066f056810ff2661aa0a000000000000"
        assert record.raw_length == 21

    def test_timestamp_renders_as_iso8601_utc(self):
        assert message_log.decode_record(REAL_RECORD_AUTH_FAILURE).timestamp_utc == "2024-01-06T03:26:27Z"

    def test_every_real_record_is_exactly_the_documented_size(self):
        for encoded in (REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS):
            assert len(base64.b64decode(encoded, validate=True)) == message_log.RECORD_SIZE


class TestDecodeEdgeCases:
    def test_short_record_reports_a_decode_error_and_keeps_the_raw_bytes(self):
        encoded = base64.b64encode(b"\x01\x02\x03\x04\x05").decode("ascii")
        record = message_log.decode_record(encoded)
        assert record.decode_error == "record is 5 bytes, expected at least 21"
        assert record.raw_base64 == encoded
        assert record.raw_hex == "0102030405"
        assert record.raw_length == 5
        # No partial decode: half a struct read at the wrong offsets produces
        # values that look real.
        assert record.timestamp is None
        assert record.event_severity_text is None
        assert record.entity_text is None
        assert record.event_data is None
        assert record.description is None

    def test_empty_record_reports_a_decode_error(self):
        record = message_log.decode_record("")
        assert record.decode_error is not None
        assert record.raw_length == 0

    def test_invalid_base64_reports_a_decode_error_and_keeps_the_original_string(self):
        record = message_log.decode_record("this is not base64!!")
        assert record.decode_error is not None
        assert "base64" in record.decode_error
        assert record.raw_base64 == "this is not base64!!"
        assert record.raw_hex is None

    def test_decode_never_raises_for_any_input(self):
        for candidate in ("", "=", "!!!", "A", "AAAA", REAL_RECORD_AUTH_FAILURE):
            assert message_log.decode_record(candidate) is not None

    def test_unknown_severity_stays_visible_rather_than_collapsing_to_a_defined_value(self):
        record = message_log.decode_record(_encode(event_severity=99))
        assert record.event_severity == 99
        # Not "unspecified" (which is the *defined* value 0) -- the two findings
        # must not render identically.
        assert record.event_severity_text == "unknown(99)"

    def test_unknown_entity_stays_visible(self):
        record = message_log.decode_record(_encode(entity=200))
        assert record.entity == 200
        assert record.entity_text == "unknown(200)"

    @pytest.mark.parametrize("sentinel", [0x00000000, 0xFFFFFFFF])
    def test_sentinel_timestamps_render_as_null_not_as_1970_or_2106(self, sentinel):
        record = message_log.decode_record(_encode(timestamp=sentinel))
        assert record.timestamp == sentinel
        assert record.timestamp_utc is None

    def test_a_record_longer_than_21_bytes_decodes_its_first_21_and_keeps_the_tail(self):
        raw = base64.b64decode(_encode()) + b"\xde\xad\xbe\xef"
        record = message_log.decode_record(base64.b64encode(raw).decode("ascii"))
        assert record.decode_error is None
        assert record.raw_length == 25
        assert record.raw_hex.endswith("deadbeef")
        assert record.event_sensor_type == 15


class TestDescriptions:
    def test_watchdog_expiry_is_named(self):
        """The event an unattended install actually needs: a hung host, seen from outside."""
        record = message_log.decode_record(_encode(event_sensor_type=18, event_data=bytes([0xAA, 1, 2, 3, 4, 5, 6, 8])))
        assert record.description == "Agent watchdog 04030201-0605-... changed to Expired"

    def test_watchdog_without_the_intel_marker_gets_no_description(self):
        record = message_log.decode_record(_encode(event_sensor_type=18, event_data=bytes([0x01, 1, 2, 3, 4, 5, 6, 8])))
        assert record.description is None

    def test_watchdog_with_an_unknown_state_keeps_the_raw_value_visible(self):
        record = message_log.decode_record(_encode(event_sensor_type=18, event_data=bytes([0xAA, 1, 2, 3, 4, 5, 6, 77])))
        assert record.description.endswith("changed to unknown(77)")

    @pytest.mark.parametrize(
        ("sensor_type", "expected"),
        [
            (30, "No bootable media"),
            (32, "Operating system lockup or power interrupt"),
            (35, "System boot failure"),
            (37, "System firmware started (at least one CPU is properly executing)."),
        ],
    )
    def test_fixed_sensor_descriptions(self, sensor_type, expected):
        assert message_log.decode_record(_encode(event_sensor_type=sensor_type)).description == expected

    def test_firmware_error_offset_zero_uses_the_error_table(self):
        record = message_log.decode_record(_encode(event_sensor_type=15, event_offset=0, event_data=bytes([0x00, 8, 0, 0, 0, 0, 0, 0])))
        assert record.description == "Removable boot media not found."

    def test_firmware_invalid_data_sentinel_is_reported_as_such(self):
        record = message_log.decode_record(_encode(event_sensor_type=15, event_data=bytes([0xEB, 0, 0, 0, 0, 0, 0, 0])))
        assert record.description == "Invalid Data"

    def test_firmware_event_where_the_two_sources_disagree_gets_no_description(self):
        """Sensor 15 with the 0xAA marker at a non-zero offset.

        go-wsman-messages reads the firmware-progress table here; MeshCentral's
        meshcmd decoder treats it as a One-Click-Recovery / OEM event with an
        entirely different layout. Two sources contradicting each other is not a
        source, so nothing is claimed -- the raw event_data is still returned.
        """
        record = message_log.decode_record(_encode(event_sensor_type=15, event_offset=3, event_data=bytes([0xAA, 48, 1, 0, 0, 0, 0, 0])))
        assert record.description is None
        assert record.event_data == [0xAA, 48, 1, 0, 0, 0, 0, 0]

    def test_an_unsourced_sensor_type_gets_null_not_a_placeholder_string(self):
        record = message_log.decode_record(_encode(event_sensor_type=7))
        assert record.description is None

    def test_an_out_of_table_firmware_code_gets_no_description(self):
        record = message_log.decode_record(_encode(event_sensor_type=15, event_offset=0, event_data=bytes([0x00, 250, 0, 0, 0, 0, 0, 0])))
        assert record.description is None

    def test_authentication_failure_count_is_little_endian_across_two_bytes(self):
        record = message_log.decode_record(_encode(event_sensor_type=6, event_data=bytes([0xAA, 0x01, 0x01, 0, 0, 0, 0, 0])))
        assert record.description == "Authentication failed 257 times. The system may be under attack."


class TestGetLogProperties:
    def test_reads_the_container_properties_from_a_bare_get(self):
        properties = message_log.get_log_properties(FakeWsman(instance=LOG_INSTANCE))
        assert properties.current_number_of_records == 6
        assert properties.max_number_of_records == 390
        assert properties.max_record_size == 21
        assert properties.capabilities == [5, 6, 8, 7]
        assert properties.is_frozen is False

    def test_falls_back_to_enumerate_when_get_faults(self):
        wsman = FakeWsman(get_error=ProtocolError("SOAP Fault"), enumerate_result=[LOG_INSTANCE])
        assert message_log.get_log_properties(wsman).current_number_of_records == 6

    def test_falls_back_to_enumerate_when_get_returns_nothing(self):
        wsman = FakeWsman(instance={}, enumerate_result=[LOG_INSTANCE])
        assert message_log.get_log_properties(wsman).current_number_of_records == 6

    def test_absent_class_raises_unsupported_capability_not_a_traceback(self):
        wsman = FakeWsman(get_error=ProtocolError("SOAP Fault"), enumerate_error=ProtocolError("SOAP Fault"))
        with pytest.raises(UnsupportedCapabilityError) as excinfo:
            message_log.get_log_properties(wsman)
        assert excinfo.value.error_class == "unsupported_capability"
        assert "AMT_MessageLog" in str(excinfo.value)

    def test_a_missing_record_count_is_none_not_zero(self):
        """ "Firmware did not say" and "the log is empty" are different findings."""
        properties = message_log.get_log_properties(FakeWsman(instance={"ElementName": "x"}))
        assert properties.current_number_of_records is None
        assert properties.capabilities == []


class TestReadRecordsIteration:
    def test_follows_the_iteration_across_multiple_batches(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=3, no_more=False), 0),
                    (_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=5, no_more=False), 0),
                    (_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=6, no_more=True), 0),
                ],
            },
        )
        read = message_log.read_records(wsman)
        # Not one batch and stop, which is the specific defect in the prior art.
        assert read.batches == 3
        assert len(read.records) == 5
        assert read.stop_reason == "no_more_records"
        assert read.complete is True
        assert read.truncated is False

    def test_feeds_each_response_identifier_into_the_next_request(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=42, no_more=False), 0),
                    (_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=43, no_more=True), 0),
                ],
            },
        )
        message_log.read_records(wsman)
        get_records_calls = [params for method, params in wsman.calls if method == "GetRecords"]
        assert get_records_calls[0]["IterationIdentifier"] == 1
        # The returned identifier is treated as opaque and fed back verbatim.
        assert get_records_calls[1]["IterationIdentifier"] == 42

    def test_a_single_record_arrives_as_a_bare_string_and_is_not_iterated_as_characters(self):
        """WS-Man collapses one repeated element to a string, not a one-item list."""
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch(REAL_RECORD_AUTH_FAILURE, next_identifier=2, no_more=True), 0)],
            },
        )
        read = message_log.read_records(wsman)
        assert len(read.records) == 1
        assert read.records[0].raw_base64 == REAL_RECORD_AUTH_FAILURE

    def test_position_to_first_record_is_called_before_any_get_records(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=2, no_more=True), 0)],
            },
        )
        message_log.read_records(wsman)
        assert [method for method, _unused in wsman.calls] == ["PositionToFirstRecord", "GetRecords"]

    def test_a_missing_identifier_from_position_defaults_to_one(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=2, no_more=True), 0)],
            },
        )
        message_log.read_records(wsman)
        assert wsman.calls[1][1]["IterationIdentifier"] == 1

    def test_batch_size_never_exceeds_the_firmware_cap(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=2, no_more=True), 0)],
            },
        )
        message_log.read_records(wsman, max_records=100000)
        assert wsman.calls[1][1]["MaxReadRecords"] == message_log.MAX_READ_RECORDS


class TestReadRecordsTruncation:
    def test_hitting_max_records_reports_truncation_rather_than_a_silent_prefix(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=3, no_more=False), 0),
                ],
            },
        )
        read = message_log.read_records(wsman, max_records=2)
        assert len(read.records) == 2
        assert read.truncated is True
        assert read.complete is False
        assert read.stop_reason == "max_records"
        # total_records still reports the real size, so a caller can see what it missed.
        assert read.total_records == 6

    def test_a_batch_larger_than_the_remaining_budget_is_cut_and_reported(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS, REAL_RECORD_AUTH_FAILURE], next_identifier=4, no_more=False), 0),
                ],
            },
        )
        read = message_log.read_records(wsman, max_records=2)
        assert len(read.records) == 2
        assert read.truncated is True

    def test_a_read_that_exactly_fills_the_budget_and_is_finished_is_not_truncated(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=3, no_more=True), 0)],
            },
        )
        read = message_log.read_records(wsman, max_records=2)
        assert read.truncated is False
        assert read.complete is True
        assert read.stop_reason == "no_more_records"

    def test_max_records_asks_firmware_for_no_more_than_the_budget(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=2, no_more=True), 0)],
            },
        )
        message_log.read_records(wsman, max_records=3)
        assert wsman.calls[1][1]["MaxReadRecords"] == 3


class TestReadRecordsEmptyAndAbnormal:
    def test_empty_log_via_position_to_first_record_is_a_success_not_a_failure(self):
        wsman = FakeWsman(instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "0"}, responses={"PositionToFirstRecord": [({}, 2)]})
        read = message_log.read_records(wsman)
        assert read.records == []
        assert read.total_records == 0
        assert read.complete is True
        assert read.truncated is False
        assert read.stop_reason == "no_record_exists"
        assert read.batches == 0

    def test_empty_log_via_get_records_return_value_three_is_a_success(self):
        wsman = FakeWsman(
            instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "0"},
            responses={"PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)], "GetRecords": [({}, 3)]},
        )
        read = message_log.read_records(wsman)
        assert read.records == []
        assert read.complete is True
        assert read.stop_reason == "no_record_exists_in_log"

    def test_the_two_methods_empty_log_return_values_are_not_interchangeable(self):
        """``GetRecords`` 2 means "invalid record pointed", not "empty log"."""
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={"PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)], "GetRecords": [({}, 2)]},
        )
        read = message_log.read_records(wsman)
        assert read.stop_reason == "invalid_record_pointed"
        # Never reported as a complete read of an empty log.
        assert read.complete is False

    def test_position_to_first_record_not_supported_becomes_unsupported_capability(self):
        wsman = FakeWsman(instance=LOG_INSTANCE, responses={"PositionToFirstRecord": [({}, 1)]})
        with pytest.raises(UnsupportedCapabilityError) as excinfo:
            message_log.read_records(wsman)
        assert excinfo.value.error_class == "unsupported_capability"

    def test_get_records_not_supported_stays_a_remote_operation_failure(self):
        """``ReturnValue`` 1 on ``GetRecords`` is not in the tolerated set, so it propagates."""
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={"PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)], "GetRecords": [({}, 1)]},
        )
        with pytest.raises(RemoteOperationError) as excinfo:
            message_log.read_records(wsman)
        assert excinfo.value.error_class == "remote_operation"

    def test_an_absent_class_degrades_before_any_method_is_invoked(self):
        wsman = FakeWsman(get_error=ProtocolError("SOAP Fault"), enumerate_error=ProtocolError("SOAP Fault"))
        with pytest.raises(UnsupportedCapabilityError):
            message_log.read_records(wsman)
        assert wsman.calls == []

    def test_a_stalled_iterator_terminates_instead_of_looping_forever(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                # Same identifier back, NoMoreRecords false: the next request would
                # return this batch again, forever.
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=1, no_more=False), 0)],
            },
        )
        read = message_log.read_records(wsman)
        assert read.stop_reason == "iteration_stalled"
        assert read.complete is False
        assert len(read.records) == 1

    def test_a_missing_next_identifier_terminates_rather_than_guessing(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [({"NoMoreRecords": "false", "RecordArray": [REAL_RECORD_AUTH_FAILURE], "ReturnValue": "0"}, 0)],
            },
        )
        read = message_log.read_records(wsman)
        assert read.stop_reason == "no_iteration_identifier"
        assert read.complete is False

    def test_records_collected_before_an_abnormal_end_are_still_returned(self):
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=3, no_more=False), 0),
                    ({}, 2),
                ],
            },
        )
        read = message_log.read_records(wsman)
        assert len(read.records) == 2
        assert read.complete is False


class TestEmptyRecordSlots:
    """``is_empty_record_slot`` -- the strict all-21-bytes-zero test, and its edges.

    Anchored on the **real firmware padding string** ``amt-lab-01`` (AMT 16.1.30)
    actually sent, taken verbatim from the evidence artifact
    ``hardware-evidence/amt-lab-01-qualify_event_log.json`` on CircleCI job 2976,
    where it appears 205 times in a 223-element ``RecordArray`` whose
    ``CurrentNumberOfRecords`` was 18 (issue #105).

    The point of these tests is the *strictness*, not the happy path. A looser test
    -- ``timestamp == 0``, say -- would pass every assertion about padding while
    quietly discarding a real event from a firmware with a faulty RTC, which is a
    finding an operator needs rather than noise to swallow.
    """

    def test_the_padding_string_real_firmware_sent_is_recognised_as_a_slot(self):
        record = message_log.decode_record(EMPTY_SLOT)
        assert record.raw_hex == "00" * message_log.RECORD_SIZE
        assert message_log.is_empty_record_slot(record) is True

    def test_a_slot_still_decodes_and_still_carries_its_raw_bytes(self):
        """Recognising a slot must not turn it into an undecodable record.

        The classification is a *judgement about* a cleanly decoded record, not a
        decode failure. If it were reported as ``decode_error`` instead, the hardware
        stage's "every record decoded cleanly" assertion would start failing on a
        cleared log -- and that assertion is about the 21-byte layout, which is not
        what is wrong here.
        """
        record = message_log.decode_record(EMPTY_SLOT)
        assert record.decode_error is None
        assert record.raw_base64 == EMPTY_SLOT
        assert record.raw_length == 21
        assert record.timestamp == 0
        assert record.timestamp_utc is None

    def test_a_zero_timestamp_with_a_populated_body_is_not_a_slot(self):
        """The case the strict test exists for: an RTC fault on a real event.

        Every other byte is populated, so this record says *something* -- a critical
        event from the ME. Only its clock is wrong. Discarding it would hide a
        firmware fault; keeping it with ``timestamp_utc: null`` reports both facts.
        """
        record = message_log.decode_record(_encode(timestamp=0, event_severity=16, entity=38, event_sensor_type=6))
        assert message_log.is_empty_record_slot(record) is False
        assert record.timestamp == 0
        assert record.timestamp_utc is None
        assert record.event_severity_text == "critical"

    def test_a_record_that_is_zero_everywhere_but_one_byte_is_not_a_slot(self):
        """One non-zero byte anywhere is enough. Checked at both ends of the struct."""
        only_severity = message_log.decode_record(
            _encode(
                timestamp=0,
                device_address=0,
                event_sensor_type=0,
                event_type=0,
                event_offset=0,
                event_source_type=0,
                event_severity=2,
                sensor_number=0,
                entity=0,
                event_data=bytes(8),
            )
        )
        only_last_data_byte = message_log.decode_record(
            _encode(
                timestamp=0,
                device_address=0,
                event_sensor_type=0,
                event_type=0,
                event_offset=0,
                event_source_type=0,
                event_severity=0,
                sensor_number=0,
                entity=0,
                event_data=bytes(7) + b"\x01",
            )
        )
        assert message_log.is_empty_record_slot(only_severity) is False
        assert message_log.is_empty_record_slot(only_last_data_byte) is False

    @pytest.mark.parametrize("encoded", [REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS])
    def test_a_real_firmware_record_is_never_a_slot(self, encoded):
        assert message_log.is_empty_record_slot(message_log.decode_record(encoded)) is False

    def test_an_all_zero_record_longer_than_21_bytes_is_not_a_slot(self):
        """Strict means strict: an unexpected record length is itself a finding.

        No source describes what a record longer than ``MaxRecordSize`` holds, so a
        25-byte all-zero record is left visible rather than being assumed to be the
        same padding the 21-byte one is.
        """
        record = message_log.decode_record(base64.b64encode(bytes(25)).decode("ascii"))
        assert record.decode_error is None
        assert record.raw_length == 25
        assert message_log.is_empty_record_slot(record) is False

    def test_an_all_zero_record_shorter_than_21_bytes_is_not_a_slot(self):
        record = message_log.decode_record(base64.b64encode(bytes(5)).decode("ascii"))
        assert record.decode_error is not None
        assert message_log.is_empty_record_slot(record) is False

    def test_an_undecodable_record_is_never_a_slot(self):
        """Not readable is not the same finding as read-and-empty."""
        assert message_log.is_empty_record_slot(message_log.decode_record("not base64!!")) is False
        assert message_log.is_empty_record_slot(message_log.decode_record("")) is False


class TestReadRecordsEmptySlots:
    """Issue #105: the iteration must not count zero-filled slots as records.

    ``TestEmptyRecordSlots`` covers the predicate. These cover where it is *applied*
    -- the accounting in ``read_records`` -- because the defect was never in the
    decode. The decode read those 205 records perfectly; it was the counting that
    was wrong.
    """

    def test_the_amt_lab_01_shape_reads_as_eighteen_records_not_two_hundred_and_twenty_three(self):
        """The measured regression case, reproduced element for element.

        18 real records then 205 identical zero slots, one batch,
        ``NoMoreRecords`` set, ``CurrentNumberOfRecords`` 18 -- exactly what job
        2976's evidence artifact holds. Before the fix this returned
        ``records_read=223`` against ``total_records=18``, which is what the hardware
        stage's accounting assertion caught.
        """
        wsman = FakeWsman(
            instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "18"},
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE] * 18 + [EMPTY_SLOT] * 205, next_identifier=224, no_more=True), 0)],
            },
        )
        read = message_log.read_records(wsman)
        assert len(read.records) == 18
        assert read.empty_slots == 205
        # Firmware's counter was right all along and is not "corrected" here.
        assert read.total_records == 18
        assert len(read.records) == read.total_records
        # Padding is not a fault: nothing else about the read changes.
        assert read.batches == 1
        assert read.stop_reason == "no_more_records"
        assert read.truncated is False
        assert read.complete is True
        assert all(not message_log.is_empty_record_slot(record) for record in read.records)

    def test_a_real_record_after_a_slot_survives_because_slots_are_skipped_not_stopped(self):
        """Skip-not-stop, stated as an assertion.

        On the one firmware state ever observed the padding was contiguous and
        trailing, so treating the first slot as end-of-data would also have worked
        there. Nothing in either source describes the padding at all, so that
        placement is not a rule -- and if some generation interleaves a freed slot,
        stopping would silently drop every record after it and still report
        ``complete: true``, which is the prior art's exact defect. This test is the
        thing that would fail if someone "optimised" the skip into a break.
        """
        wsman = FakeWsman(
            instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "2"},
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([EMPTY_SLOT, REAL_RECORD_AUTH_FAILURE, EMPTY_SLOT, REAL_RECORD_FIRMWARE_PROGRESS, EMPTY_SLOT], next_identifier=6, no_more=True), 0)
                ],
            },
        )
        read = message_log.read_records(wsman)
        assert [record.raw_base64 for record in read.records] == [REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS]
        assert read.empty_slots == 3
        assert read.complete is True

    def test_a_batch_of_nothing_but_slots_does_not_end_the_iteration(self):
        """A wholly-empty batch must not be read as "the log is finished".

        Same failure as above one level up: if the batch's emptiness ended the read,
        the records in the *next* batch would be lost and the result would still
        claim to be complete.
        """
        wsman = FakeWsman(
            instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "1"},
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([EMPTY_SLOT, EMPTY_SLOT], next_identifier=3, no_more=False), 0),
                    (_batch([REAL_RECORD_AUTH_FAILURE], next_identifier=4, no_more=True), 0),
                ],
            },
        )
        read = message_log.read_records(wsman)
        assert read.batches == 2
        assert len(read.records) == 1
        assert read.empty_slots == 2
        assert read.stop_reason == "no_more_records"

    def test_max_records_still_bounds_a_read_that_is_all_padding(self):
        """The hang guard. ``max_records`` counts elements consumed, not records kept.

        Firmware here keeps advancing its identifier and keeps returning nothing but
        padding, without ever setting ``NoMoreRecords``. If the budget were spent
        only on *kept* records it would never be reached, and the loop's only exit
        would be a ``NoMoreRecords`` this firmware never sends -- a new way to hang a
        play, which is the exact thing ``max_records`` exists to prevent.

        Only two batches are queued, so a loop that did not stop at the bound fails
        loudly (``FakeWsman`` raises on an unexpected invoke) rather than spinning.
        """
        wsman = FakeWsman(
            instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "0"},
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [
                    (_batch([EMPTY_SLOT, EMPTY_SLOT], next_identifier=3, no_more=False), 0),
                    (_batch([EMPTY_SLOT, EMPTY_SLOT], next_identifier=5, no_more=False), 0),
                ],
            },
        )
        read = message_log.read_records(wsman, max_records=4)
        assert read.records == []
        assert read.empty_slots == 4
        assert read.batches == 2
        assert read.stop_reason == "max_records"
        assert read.truncated is True
        assert read.complete is False

    def test_padding_does_not_consume_the_budget_a_caller_meant_for_records(self):
        """A budget spent on padding still yields every real record in reach of it.

        ``max_records=4`` against a batch of two slots and two records: the read must
        come back with both records, not with "two slots and one record".
        """
        wsman = FakeWsman(
            instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "2"},
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([EMPTY_SLOT, EMPTY_SLOT, REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=5, no_more=True), 0)],
            },
        )
        read = message_log.read_records(wsman, max_records=4)
        assert len(read.records) == 2
        assert read.empty_slots == 2
        assert read.truncated is False

    def test_empty_slots_is_zero_on_a_log_firmware_did_not_pad(self):
        """The control. ``amt-lab-02`` (AMT 19.0.5) read cleanly in the same CI run."""
        wsman = FakeWsman(
            instance=LOG_INSTANCE,
            responses={
                "PositionToFirstRecord": [({"IterationIdentifier": "1"}, 0)],
                "GetRecords": [(_batch([REAL_RECORD_AUTH_FAILURE, REAL_RECORD_FIRMWARE_PROGRESS], next_identifier=3, no_more=True), 0)],
            },
        )
        read = message_log.read_records(wsman)
        assert read.empty_slots == 0
        assert len(read.records) == 2

    def test_an_empty_log_reports_no_slots(self):
        wsman = FakeWsman(instance={**LOG_INSTANCE, "CurrentNumberOfRecords": "0"}, responses={"PositionToFirstRecord": [({}, 2)]})
        assert message_log.read_records(wsman).empty_slots == 0


class TestFilterBySeverity:
    def _records(self):
        return [
            message_log.decode_record(_encode(event_severity=16)),
            message_log.decode_record(_encode(event_severity=1)),
            message_log.decode_record(_encode(event_severity=32)),
            message_log.decode_record(_encode(event_severity=99)),
            message_log.decode_record("not base64!!"),
        ]

    def test_no_filter_keeps_everything(self):
        records = self._records()
        assert len(message_log.filter_by_severity(records, None)) == 5
        assert len(message_log.filter_by_severity(records, [])) == 5

    def test_filters_by_name(self):
        kept = message_log.filter_by_severity(self._records(), ["critical", "non_recoverable"])
        assert [record.event_severity for record in kept] == [16, 32]

    def test_an_unknown_severity_is_dropped_by_any_filter(self):
        kept = message_log.filter_by_severity(self._records(), ["critical"])
        assert all(record.event_severity_text == "critical" for record in kept)
        assert 99 not in [record.event_severity for record in kept]

    def test_an_undecodable_record_is_dropped_by_any_filter(self):
        kept = message_log.filter_by_severity(self._records(), list(message_log.SEVERITY_CHOICES))
        assert all(record.decode_error is None for record in kept)

    def test_filtering_does_not_mutate_the_input(self):
        records = self._records()
        message_log.filter_by_severity(records, ["critical"])
        assert len(records) == 5

    def test_severity_choices_are_derived_from_the_table(self):
        assert set(message_log.SEVERITY_CHOICES) == set(message_log.EVENT_SEVERITY_TABLE.values())
        # Filtering is by name because the numeric values are a sparse lookup, not
        # a ladder: "ok" (4) outranks "information" (2) numerically.
        assert message_log.EVENT_SEVERITY_TABLE[4] == "ok"
        assert message_log.EVENT_SEVERITY_TABLE[2] == "information"


class TestClearLog:
    def test_clear_log_invokes_the_method_with_no_parameters(self):
        wsman = FakeWsman(instance=LOG_INSTANCE, responses={"ClearLog": [({"ReturnValue": "0"}, 0)]})
        assert message_log.clear_log(wsman) == 0
        assert wsman.calls == [("ClearLog", {})]

    def test_a_non_zero_return_value_raises_remote_operation(self):
        """The specific defect in the prior art: it demotes this to a warning."""
        wsman = FakeWsman(instance=LOG_INSTANCE, responses={"ClearLog": [({}, 5)]})
        with pytest.raises(RemoteOperationError) as excinfo:
            message_log.clear_log(wsman)
        assert excinfo.value.error_class == "remote_operation"
        assert excinfo.value.return_value == 5


class TestSourcedConstants:
    def test_record_size_is_the_documented_struct_size(self):
        assert message_log.RECORD_SIZE == 4 + 9 + message_log.EVENT_DATA_SIZE == 21

    def test_max_read_records_matches_both_sources(self):
        # go-wsman-messages caps at 390; MeshCentral's GetMessageLog passes 390.
        assert message_log.MAX_READ_RECORDS == 390
        assert message_log.DEFAULT_MAX_RECORDS == 390

    def test_return_value_tables_are_the_documented_value_maps(self):
        assert message_log.GET_RECORDS_RETURN_VALUES[3] == "no_record_exists_in_log"
        assert message_log.POSITION_TO_FIRST_RECORD_RETURN_VALUES[2] == "no_record_exists"
        # The same condition, different values per method. Conflating them would
        # read an empty log as a protocol error.
        assert 3 not in message_log.POSITION_TO_FIRST_RECORD_RETURN_VALUES

    def test_no_value_table_is_claimed_for_the_unsourced_byte_fields(self):
        """Guards the honesty rule against a well-meaning future addition.

        ``EventType``, ``EventOffset``, ``EventSourceType``, ``DeviceAddress`` and
        ``SensorNumber`` have no established value table. If someone adds one, this
        test should fail and force the source to be recorded in
        ``docs/protocol-notes.md`` §2.8 first.
        """
        record = message_log.decode_record(REAL_RECORD_AUTH_FAILURE)
        for name in ("event_type", "event_offset", "event_source_type", "device_address", "sensor_number"):
            assert not hasattr(record, f"{name}_text")
