# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import message_log
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ProtocolError, UnsupportedCapabilityError
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_event_log

PASSWORD = "Sup3rSecret!"

BASE_ARGS = {
    "host": "192.0.2.10",
    "username": "admin",
    "password": PASSWORD,
    "tls_fingerprint": "aa" * 32,
}

#: Real firmware records from go-wsman-messages' getrecords.xml fixture.
CRITICAL_RECORD = "Y8iYZf8GbwVoEP8mYaoKAAAAAAAA"  # severity 16 -> critical
MONITOR_RECORD = "IgYBZf8PbwJoAf8iAEAHAAAAAAAA"  # severity 1 -> monitor


def _set_module_args(args: dict) -> None:
    basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    basic._ANSIBLE_PROFILE = "legacy"


class AnsibleExitJson(Exception):
    pass


class AnsibleFailJson(Exception):
    pass


def _exit_json(*_args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _fail_json(*_args, **kwargs):
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def _patch_module_exit(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


def _properties(count: int = 6) -> message_log.MessageLogProperties:
    return message_log.MessageLogProperties(
        current_number_of_records=count,
        max_number_of_records=390,
        max_record_size=21,
        element_name="Intel(r) AMT:MessageLog 1",
        is_frozen=False,
        log_state=4,
        overwrite_policy=2,
        capabilities=[5, 6, 8, 7],
    )


def _read(
    encoded_records: list[str],
    *,
    total: int = 6,
    truncated: bool = False,
    complete: bool = True,
    stop_reason: str = "no_more_records",
    batches: int = 1,
) -> message_log.MessageLogRead:
    return message_log.MessageLogRead(
        properties=_properties(total),
        records=[message_log.decode_record(item) for item in encoded_records],
        total_records=total,
        truncated=truncated,
        complete=complete,
        stop_reason=stop_reason,
        batches=batches,
    )


def _wire(monkeypatch, read=None, error=None) -> dict:
    """Stub the transport, recording every WS-Man-shaped call the module makes."""
    calls: dict[str, int] = {"read_records": 0}
    monkeypatch.setattr(amt_event_log, "build_wsman_client", lambda params: Mock(endpoint="192.0.2.10:16993", last_peer_certificate=None))

    def _read_records(_wsman, **kwargs):
        calls["read_records"] += 1
        calls["max_records"] = kwargs.get("max_records")
        if error is not None:
            raise error
        return read

    monkeypatch.setattr(amt_event_log.message_log, "read_records", _read_records)
    return calls


def _run(args: dict, *, check_mode: bool = False) -> dict:
    payload = dict(args)
    if check_mode:
        payload["_ansible_check_mode"] = True
    _set_module_args(payload)
    with pytest.raises((AnsibleExitJson, AnsibleFailJson)) as excinfo:
        amt_event_log.main()
    return excinfo.value.args[0]


class TestArgumentSpec:
    def test_password_is_no_log(self):
        assert amt_event_log.argument_spec()["password"]["no_log"] is True

    def test_max_records_defaults_to_one_whole_log(self):
        spec = amt_event_log.argument_spec()["max_records"]
        assert spec["type"] == "int"
        assert spec["default"] == message_log.DEFAULT_MAX_RECORDS == 390

    def test_severity_choices_come_from_the_sourced_table(self):
        spec = amt_event_log.argument_spec()["severity"]
        assert spec["type"] == "list"
        assert spec["elements"] == "str"
        assert set(spec["choices"]) == set(message_log.EVENT_SEVERITY_TABLE.values())

    def test_the_option_surface_stays_small(self):
        """Only two module-specific options; everything else is the connection fragment."""
        spec = amt_event_log.argument_spec()
        connection = set(amt_event_log._connection_argument_spec())
        assert set(spec) - connection == {"max_records", "severity"}

    def test_an_invalid_severity_is_rejected_by_argument_validation(self, monkeypatch):
        _wire(monkeypatch, read=_read([]))
        result = _run({**BASE_ARGS, "severity": ["catastrophic"]})
        assert "msg" in result

    def test_max_records_below_one_is_refused(self, monkeypatch):
        _wire(monkeypatch, read=_read([]))
        result = _run({**BASE_ARGS, "max_records": 0})
        assert "max_records must be at least 1" in result["msg"]


class TestBuildWsmanClient:
    def test_builds_a_real_client_from_module_params_without_touching_a_socket(self):
        params = {
            "host": "192.0.2.10",
            "port": None,
            "username": "admin",
            "password": PASSWORD,
            "use_tls": False,
            "allow_insecure_transport": True,
            "validate_certs": True,
            "ca_path": None,
            "tls_fingerprint": None,
            "timeout": 30,
            "connect_timeout": 10,
        }
        wsman = amt_event_log.build_wsman_client(params)
        assert wsman.endpoint == "192.0.2.10:16992"
        wsman.close()


class TestReadOnly:
    def test_changed_is_always_false(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD]))
        result = _run(BASE_ARGS)
        assert result["changed"] is False
        assert result["operation"]["changed"] is False

    def test_check_mode_performs_the_identical_read_and_mutates_nothing(self, monkeypatch):
        """A read is a read: check mode must not skip it, and must return the same thing."""
        calls_normal = _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD]))
        normal = _run(BASE_ARGS)
        assert calls_normal["read_records"] == 1

        calls_check = _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD]))
        checked = _run(BASE_ARGS, check_mode=True)
        # The read still happened...
        assert calls_check["read_records"] == 1
        # ...and produced an identical result.
        assert checked == normal
        assert checked["changed"] is False

    def test_no_mutating_method_is_ever_reachable_from_this_module(self, monkeypatch):
        """The module's only transport entry point is ``read_records``."""
        called: list[str] = []
        monkeypatch.setattr(amt_event_log, "build_wsman_client", lambda params: Mock(endpoint="192.0.2.10:16993", last_peer_certificate=None))
        monkeypatch.setattr(amt_event_log.message_log, "read_records", lambda _w, **_k: _read([CRITICAL_RECORD]))
        monkeypatch.setattr(amt_event_log.message_log, "clear_log", lambda _w: called.append("clear_log"))
        _run(BASE_ARGS)
        assert called == []


class TestResultShape:
    def test_records_carry_the_raw_bytes_alongside_the_decode(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD]))
        record = _run(BASE_ARGS)["records"][0]
        assert record["raw_base64"] == CRITICAL_RECORD
        assert record["raw_hex"] == "63c89865ff066f056810ff2661aa0a000000000000"
        assert record["raw_length"] == 21
        assert record["event_severity_text"] == "critical"
        assert record["description"] == "Authentication failed 10 times. The system may be under attack."

    def test_total_records_lets_a_caller_tell_truncation_from_an_empty_log(self, monkeypatch):
        _wire(monkeypatch, read=_read([], total=0, stop_reason="no_record_exists", batches=0))
        result = _run(BASE_ARGS)
        assert result["records"] == []
        assert result["total_records"] == 0
        assert result["records_read"] == 0
        assert result["truncated"] is False
        assert result["complete"] is True

    def test_an_empty_result_with_a_non_zero_total_is_distinguishable(self, monkeypatch):
        _wire(monkeypatch, read=_read([], total=390, truncated=True, complete=False, stop_reason="max_records"))
        result = _run(BASE_ARGS)
        assert result["total_records"] == 390
        assert result["truncated"] is True

    def test_truncation_is_reported_not_silent(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD], total=390, truncated=True, complete=False, stop_reason="max_records", batches=1))
        result = _run({**BASE_ARGS, "max_records": 1})
        assert result["truncated"] is True
        assert result["complete"] is False
        assert result["stop_reason"] == "max_records"
        assert result["records_read"] == 1
        assert result["total_records"] == 390

    def test_max_records_is_passed_through_to_the_reader(self, monkeypatch):
        calls = _wire(monkeypatch, read=_read([]))
        _run({**BASE_ARGS, "max_records": 17})
        assert calls["max_records"] == 17

    def test_log_container_properties_are_surfaced(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD]))
        log = _run(BASE_ARGS)["log"]
        assert log["max_record_size"] == 21
        assert log["max_number_of_records"] == 390
        # Capability 6 is ClearLogSupported.
        assert 6 in log["capabilities"]

    def test_batches_and_stop_reason_are_reported(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD], batches=3, stop_reason="no_more_records"))
        result = _run(BASE_ARGS)
        assert result["batches"] == 3
        assert result["stop_reason"] == "no_more_records"

    def test_receipt_is_the_documented_schema(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD]))
        operation = _run(BASE_ARGS)["operation"]
        assert operation["schema"] == "intel-amt-operation/v1"
        assert operation["action"] == "amt_event_log.read"
        assert operation["endpoint"] == "192.0.2.10:16993"
        assert operation["changed"] is False
        assert operation["previous"] is None
        assert operation["desired"] is None
        assert operation["observed"]["max_record_size"] == 21
        assert operation["error_class"] is None

    def test_the_password_never_appears_anywhere_in_the_result(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD]))
        assert PASSWORD not in json.dumps(_run(BASE_ARGS))


class TestSeverityFilter:
    def test_no_filter_returns_every_record(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD]))
        result = _run(BASE_ARGS)
        assert len(result["records"]) == 2
        assert result["filtered_out"] == 0

    def test_filtering_reports_how_many_records_it_removed(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD]))
        result = _run({**BASE_ARGS, "severity": ["critical"]})
        assert [record["event_severity_text"] for record in result["records"]] == ["critical"]
        # records_read counts what firmware gave us, before the filter.
        assert result["records_read"] == 2
        assert result["filtered_out"] == 1

    def test_filtering_does_not_change_total_records(self, monkeypatch):
        _wire(monkeypatch, read=_read([CRITICAL_RECORD, MONITOR_RECORD], total=6))
        result = _run({**BASE_ARGS, "severity": ["critical"]})
        assert result["total_records"] == 6

    def test_a_filter_matching_nothing_returns_an_empty_list_not_a_failure(self, monkeypatch):
        _wire(monkeypatch, read=_read([MONITOR_RECORD]))
        result = _run({**BASE_ARGS, "severity": ["non_recoverable"]})
        assert result["records"] == []
        assert result["filtered_out"] == 1
        assert result["changed"] is False


class TestBuildResult:
    """``build_result`` directly, so the accounting is testable without a module run."""

    def test_filtered_out_plus_returned_equals_records_read(self):
        read = _read([CRITICAL_RECORD, MONITOR_RECORD, CRITICAL_RECORD])
        result = amt_event_log.build_result(read, ["critical"], "192.0.2.10:16993", None)
        assert result["records_read"] == 3
        assert result["filtered_out"] + len(result["records"]) == result["records_read"]

    def test_tls_fingerprint_is_carried_into_the_receipt(self):
        read = _read([CRITICAL_RECORD])
        result = amt_event_log.build_result(read, None, "192.0.2.10:16993", "ab" * 32)
        assert result["operation"]["tls_peer_fingerprint"] == "ab" * 32


class TestGracefulDegradation:
    def test_absent_class_reports_unsupported_capability_not_a_traceback(self, monkeypatch):
        _wire(monkeypatch, error=UnsupportedCapabilityError("AMT_MessageLog is not available", endpoint="192.0.2.10:16993"))
        result = _run(BASE_ARGS)
        assert result["error_class"] == "unsupported_capability"
        assert "AMT_MessageLog" in result["msg"]
        assert "Traceback" not in json.dumps(result)

    def test_a_faulting_method_reports_protocol_not_a_traceback(self, monkeypatch):
        _wire(monkeypatch, error=ProtocolError("SOAP Fault code=s:Receiver", endpoint="192.0.2.10:16993"))
        result = _run(BASE_ARGS)
        assert result["error_class"] == "protocol"
        assert "Traceback" not in json.dumps(result)

    def test_a_failure_message_is_redacted(self, monkeypatch):
        _wire(monkeypatch, error=ProtocolError(f"failed with password={PASSWORD}", endpoint="192.0.2.10:16993", secrets=PASSWORD))
        result = _run(BASE_ARGS)
        assert PASSWORD not in json.dumps(result)
