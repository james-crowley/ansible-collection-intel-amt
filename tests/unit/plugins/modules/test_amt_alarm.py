# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for ``plugins/modules/amt_alarm.py``.

Scoped to what the *module* adds on top of ``module_utils/alarm.py``: which reads it
performs and in what order, what it sends and refrains from sending in check mode,
the shape of the result document, and the re-read after a mutation. The convergence
decisions themselves are tested in ``test_alarm.py``, and the wire shapes over a real
socket in ``tests/unit/mock_servers/test_wsman_server.py``.

The fake client here is a ``FakeAlarmEndpoint`` that holds real state rather than a
bare ``Mock`` with canned returns, deliberately: the property this module exists for
is that a *second* run of the same arguments reports ``changed=false``, and a client
whose ``enumerate`` always returns the same canned list would report that whether or
not the first run wrote anything.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_alarm

#: RFC 5737 TEST-NET-1, reserved for documentation and guaranteed not to route.
HOST = "192.0.2.10"

BASE_ARGS = {
    "host": HOST,
    "username": "admin",
    "password": "test-password-not-real",
    "use_tls": False,
    "allow_insecure_transport": True,
}


class AnsibleExitJson(Exception):
    def __init__(self, kwargs):
        super().__init__("exit_json")
        self.kwargs = kwargs


class AnsibleFailJson(Exception):
    def __init__(self, kwargs):
        super().__init__("fail_json")
        self.kwargs = kwargs


def _set_module_args(args: dict) -> None:
    basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    # ansible-core >= 2.21 requires an explicit args-decoding profile alongside
    # _ANSIBLE_ARGS; older cores ignore the attribute, so setting it is harmless.
    basic._ANSIBLE_PROFILE = "legacy"


def _exit_json(*_args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _fail_json(*_args, **kwargs):
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def _patch_exit_and_fail(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


class FakeAlarmEndpoint:
    """A stateful stand-in for one AMT endpoint's alarm clock.

    ``AddAlarm`` and ``delete`` mutate ``self.alarms``, and ``enumerate`` reads it --
    so a second module run really does observe what the first one wrote. It also
    records every operation in ``self.log``, which is how the ordering assertions
    (read before decide, delete before add, re-read after mutate) are made without
    inspecting the module's internals.
    """

    def __init__(self, *, ta0=None, time_sync_absent=False, alarm_class_absent=False, service=None):
        self.endpoint = f"{HOST}:16992"
        self.last_peer_certificate = None
        self.alarms: dict[str, dict] = {}
        self.log: list[str] = []
        self.closed = False
        self._ta0 = ta0 if ta0 is not None else int(datetime.now(tz=timezone.utc).timestamp())
        self._time_sync_absent = time_sync_absent
        self._alarm_class_absent = alarm_class_absent
        self._service = service if service is not None else {"ElementName": "Intel(r) AMT Alarm Clock Service"}

    # -- WsmanClient surface --------------------------------------------------

    def get(self, resource_class, *, selectors=None):
        self.log.append(f"get:{resource_class}")
        if resource_class == "AMT_TimeSynchronizationService":
            if self._time_sync_absent:
                raise _protocol_error()
            return {"TimeSource": "0", "LocalTimeSyncEnabled": "0"}
        if resource_class == "AMT_AlarmClockService":
            if self._alarm_class_absent:
                raise _protocol_error()
            return dict(self._service)
        raise AssertionError(f"unexpected Get of {resource_class}")

    def enumerate(self, resource_class, *, selectors=None):
        self.log.append(f"enumerate:{resource_class}")
        assert resource_class == "IPS_AlarmClockOccurrence"
        if self._alarm_class_absent:
            raise _protocol_error()
        return [
            {
                "InstanceID": name,
                "ElementName": name,
                "StartTime": {"Datetime": occurrence["start_time"]},
                "Interval": {"Interval": occurrence["interval"]},
                "DeleteOnCompletion": "true" if occurrence["delete_on_completion"] else "false",
            }
            for name, occurrence in self.alarms.items()
        ]

    def invoke(self, resource_class, method_name, params=None, *, selectors=None):
        self.log.append(f"invoke:{method_name}")
        if method_name == "GetLowAccuracyTimeSynch":
            if self._time_sync_absent:
                raise _protocol_error()
            return {"Ta0": str(self._ta0), "ReturnValue": "0"}, 0
        assert method_name == "AddAlarm"
        template = params["AlarmTemplate"]
        name = template.properties["InstanceID"]
        self.alarms[name] = {
            "start_time": template.properties["StartTime"].properties["Datetime"],
            "interval": template.properties["Interval"].properties["Interval"],
            "delete_on_completion": template.properties["DeleteOnCompletion"],
        }
        return {"ReturnValue": "0"}, 0

    def delete(self, resource_class, *, selectors=None):
        self.log.append(f"delete:{selectors['InstanceID']}")
        self.alarms.pop(selectors["InstanceID"], None)

    def close(self):
        self.closed = True


def _protocol_error():
    from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ProtocolError

    return ProtocolError("SOAP Fault code=s:Receiver reason=w:InvalidResourceURI")


def _future(minutes=60) -> str:
    moment = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=minutes)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(monkeypatch, endpoint, args, *, check_mode=False):
    """Invoke ``amt_alarm.main()`` against ``endpoint`` and return the exit kwargs."""
    monkeypatch.setattr(amt_alarm, "build_wsman_client", lambda _params: endpoint)
    full = dict(BASE_ARGS, **args)
    if check_mode:
        full["_ansible_check_mode"] = True
    _set_module_args(full)
    with pytest.raises(AnsibleExitJson) as excinfo:
        amt_alarm.main()
    return excinfo.value.kwargs


def _run_failing(monkeypatch, endpoint, args):
    monkeypatch.setattr(amt_alarm, "build_wsman_client", lambda _params: endpoint)
    _set_module_args(dict(BASE_ARGS, **args))
    with pytest.raises(AnsibleFailJson) as excinfo:
        amt_alarm.main()
    return excinfo.value.kwargs


class TestQuery:
    def test_reports_no_alarms_without_changing_anything(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        result = _run(monkeypatch, endpoint, {})
        assert result["changed"] is False
        assert result["alarms"] == []
        assert result["alarm"] is None
        assert result["operation"]["alarm_operation"] == "none"
        assert not [entry for entry in endpoint.log if entry.startswith(("delete:", "invoke:AddAlarm"))]

    def test_reports_the_configured_alarms(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        endpoint.alarms["nightly"] = {"start_time": "2030-01-02T03:00:00Z", "interval": "P1DT0H0M", "delete_on_completion": False}
        result = _run(monkeypatch, endpoint, {})
        assert result["alarms"] == [
            {
                "instance_id": "nightly",
                "element_name": "nightly",
                "start_time": "2030-01-02T03:00:00Z",
                "interval": "P1DT0H0M",
                "interval_minutes": 1440,
                "delete_on_completion": False,
            }
        ]

    def test_a_name_with_state_query_reports_just_that_alarm_too(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        endpoint.alarms["nightly"] = {"start_time": "2030-01-02T03:00:00Z", "interval": "P0DT0H0M", "delete_on_completion": True}
        result = _run(monkeypatch, endpoint, {"name": "nightly"})
        assert result["changed"] is False
        assert result["alarm"]["instance_id"] == "nightly"

    def test_query_reports_firmwares_clock_and_the_service(self, monkeypatch):
        endpoint = FakeAlarmEndpoint(ta0=1704586865)
        result = _run(monkeypatch, endpoint, {})
        assert result["firmware_clock"]["epoch_seconds"] == 1704586865
        assert result["firmware_clock"]["utc"] == "2024-01-07T00:21:05Z"
        assert result["firmware_clock"]["time_source_name"] == "bios_rtc"
        assert result["service"]["element_name"] == "Intel(r) AMT Alarm Clock Service"

    def test_the_two_absent_service_properties_are_null_not_invented(self, monkeypatch):
        """The vendor's captured response omits both. Reported as ``null``.

        A module that synthesised them from its own reading of the occurrence list
        would be presenting its own answer as firmware's.
        """
        result = _run(monkeypatch, FakeAlarmEndpoint(), {})
        assert result["service"]["next_alarm_time"] is None
        assert result["service"]["alarm_interval"] is None


class TestPresent:
    def test_adds_an_absent_alarm(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        start_time = _future()
        result = _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": start_time, "interval_minutes": 1440})
        assert result["changed"] is True
        assert result["operation"]["alarm_operation"] == "add"
        assert result["alarm"]["start_time"] == start_time
        assert result["alarm"]["interval_minutes"] == 1440
        assert "nightly" in endpoint.alarms

    def test_a_second_identical_run_reports_no_change(self, monkeypatch):
        """The property in the issue title: an alarm is state, so it converges.

        Both runs go through the same stateful endpoint, so this can only pass if the
        first run really wrote and the second really read what it wrote.
        """
        endpoint = FakeAlarmEndpoint()
        args = {"state": "present", "name": "nightly", "start_time": _future(), "interval_minutes": 1440, "delete_on_completion": False}
        first = _run(monkeypatch, endpoint, args)
        second = _run(monkeypatch, endpoint, args)
        assert first["changed"] is True
        assert second["changed"] is False
        assert second["operation"]["alarm_operation"] == "none"
        # And exactly one alarm exists, not two under the same key.
        assert list(endpoint.alarms) == ["nightly"]

    def test_a_second_run_that_converged_sends_nothing_at_all(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        args = {"state": "present", "name": "nightly", "start_time": _future()}
        _run(monkeypatch, endpoint, args)
        endpoint.log.clear()
        _run(monkeypatch, endpoint, args)
        assert not [entry for entry in endpoint.log if entry.startswith(("delete:", "invoke:AddAlarm"))]

    def test_changing_the_time_deletes_before_adding(self, monkeypatch):
        """No source implements a ``Put`` on the occurrence class, so the key must be freed.

        The order is the assertion: an add-over-the-top would hit firmware's
        duplicate-key refusal.
        """
        endpoint = FakeAlarmEndpoint()
        _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future(60)})
        endpoint.log.clear()
        result = _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future(120)})
        assert result["operation"]["alarm_operation"] == "replace"
        mutations = [entry for entry in endpoint.log if entry.startswith(("delete:", "invoke:AddAlarm"))]
        assert mutations == ["delete:nightly", "invoke:AddAlarm"]

    def test_the_receipt_carries_previous_desired_and_observed(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        first_time, second_time = _future(60), _future(120)
        _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": first_time})
        result = _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": second_time})
        receipt = result["operation"]
        assert receipt["previous"]["start_time"] == first_time
        assert receipt["desired"]["start_time"] == second_time
        assert receipt["observed"]["start_time"] == second_time
        assert receipt["schema"] == "intel-amt-operation/v1"
        assert receipt["action"] == "amt_alarm"

    def test_the_desired_receipt_shows_the_truncated_seconds_and_encoded_interval(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        moment = datetime.now(tz=timezone.utc).replace(second=47, microsecond=0) + timedelta(hours=2)
        result = _run(
            monkeypatch,
            endpoint,
            {"state": "present", "name": "nightly", "start_time": moment.strftime("%Y-%m-%dT%H:%M:%SZ"), "interval_minutes": 90},
        )
        assert result["operation"]["desired"]["start_time"].endswith(":00Z")
        assert result["operation"]["desired"]["interval"] == "P0DT1H30M"

    def test_observed_is_re_read_rather_than_assumed_from_the_return_value(self, monkeypatch):
        """A mutation is requested, never confirmed, by ``ReturnValue == 0``.

        The endpoint whose ``AddAlarm`` silently stores nothing must produce
        ``observed: null``, not an echo of what was asked for.
        """

        class LyingEndpoint(FakeAlarmEndpoint):
            def invoke(self, resource_class, method_name, params=None, *, selectors=None):
                if method_name == "AddAlarm":
                    self.log.append("invoke:AddAlarm")
                    return {"ReturnValue": "0"}, 0
                return super().invoke(resource_class, method_name, params, selectors=selectors)

        endpoint = LyingEndpoint()
        result = _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future()})
        assert result["changed"] is True
        assert result["operation"]["observed"] is None
        assert result["alarm"] is None

    def test_a_naive_start_time_is_refused_before_the_endpoint_is_touched(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        result = _run_failing(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": "2030-01-02T03:00:00"})
        assert result["error_class"] == "invalid_state"
        # Not one request. The most likely mistake costs no round trips.
        assert endpoint.log == []

    def test_a_past_dated_alarm_is_refused_and_nothing_is_sent(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        result = _run_failing(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future(-60)})
        assert result["error_class"] == "invalid_state"
        assert "allow_past_start_time" in result["msg"]
        assert not [entry for entry in endpoint.log if entry.startswith(("delete:", "invoke:AddAlarm"))]

    def test_allow_past_start_time_sends_it(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        result = _run(
            monkeypatch,
            endpoint,
            {"state": "present", "name": "stale", "start_time": _future(-60), "allow_past_start_time": True},
        )
        assert result["changed"] is True
        assert "stale" in endpoint.alarms

    def test_a_firmware_clock_ahead_of_the_controller_refuses_a_near_future_alarm(self, monkeypatch):
        """Proves the check consults firmware, over the module boundary.

        The controller thinks this time is an hour away; firmware's clock is two hours
        fast, so to firmware it has passed.
        """
        endpoint = FakeAlarmEndpoint(ta0=int(datetime.now(tz=timezone.utc).timestamp()) + 7200)
        result = _run_failing(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future(60)})
        assert result["error_class"] == "invalid_state"
        assert "firmware's own clock" in result["msg"]

    def test_without_a_readable_clock_the_controller_is_used_and_the_message_says_so(self, monkeypatch):
        endpoint = FakeAlarmEndpoint(time_sync_absent=True)
        result = _run_failing(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future(-60)})
        assert "this controller's clock" in result["msg"]

    def test_an_absent_time_sync_service_still_allows_setting_an_alarm(self, monkeypatch):
        endpoint = FakeAlarmEndpoint(time_sync_absent=True)
        result = _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future()})
        assert result["changed"] is True
        assert result["firmware_clock"] is None


class TestAbsent:
    def test_removes_an_existing_alarm(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future()})
        result = _run(monkeypatch, endpoint, {"state": "absent", "name": "nightly"})
        assert result["changed"] is True
        assert result["operation"]["alarm_operation"] == "delete"
        assert result["alarm"] is None
        assert endpoint.alarms == {}

    def test_removing_an_absent_alarm_is_already_converged(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        result = _run(monkeypatch, endpoint, {"state": "absent", "name": "nightly"})
        assert result["changed"] is False
        # No optimistic Delete: firmware faults a Delete for a key that does not exist,
        # so the read-then-decide ordering is what makes this idempotent.
        assert not [entry for entry in endpoint.log if entry.startswith("delete:")]

    def test_absent_does_not_require_a_start_time(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        endpoint.alarms["stale"] = {"start_time": "2001-01-01T00:00:00Z", "interval": "P0DT0H0M", "delete_on_completion": True}
        result = _run(monkeypatch, endpoint, {"state": "absent", "name": "stale"})
        assert result["changed"] is True

    def test_a_stale_past_dated_alarm_can_still_be_removed(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        endpoint.alarms["stale"] = {"start_time": "2001-01-01T00:00:00Z", "interval": "P0DT0H0M", "delete_on_completion": True}
        result = _run(monkeypatch, endpoint, {"state": "absent", "name": "stale"})
        assert result["changed"] is True
        assert endpoint.alarms == {}


class TestCheckMode:
    def test_reports_the_change_it_would_make_and_sends_nothing(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        result = _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future()}, check_mode=True)
        assert result["changed"] is True
        assert result["operation"]["alarm_operation"] == "add"
        assert endpoint.alarms == {}
        assert not [entry for entry in endpoint.log if entry.startswith(("delete:", "invoke:AddAlarm"))]

    def test_a_converged_alarm_reports_no_change_in_check_mode_too(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        args = {"state": "present", "name": "nightly", "start_time": _future()}
        _run(monkeypatch, endpoint, args)
        result = _run(monkeypatch, endpoint, args, check_mode=True)
        assert result["changed"] is False

    def test_check_mode_and_a_real_run_agree_because_one_planner_decides_both(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        args = {"state": "present", "name": "nightly", "start_time": _future(), "interval_minutes": 1440}
        preview = _run(monkeypatch, endpoint, args, check_mode=True)
        real = _run(monkeypatch, endpoint, args)
        assert preview["changed"] is True
        assert real["changed"] is True
        assert preview["operation"]["alarm_operation"] == real["operation"]["alarm_operation"]
        assert preview["operation"]["desired"] == real["operation"]["desired"]

    def test_the_past_date_refusal_fires_in_check_mode(self, monkeypatch):
        """``--check`` is for previewing a correct play, not for discovering it is wrong.

        Same reasoning ``amt_log_clear``'s confirmation gate applies to check mode.
        """
        endpoint = FakeAlarmEndpoint()
        result = _run_failing(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future(-60), "_ansible_check_mode": True})
        assert result["error_class"] == "invalid_state"

    def test_check_mode_does_not_delete_for_state_absent(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        _run(monkeypatch, endpoint, {"state": "present", "name": "nightly", "start_time": _future()})
        result = _run(monkeypatch, endpoint, {"state": "absent", "name": "nightly"}, check_mode=True)
        assert result["changed"] is True
        assert "nightly" in endpoint.alarms


class TestFailurePaths:
    def test_firmware_with_no_alarm_clock_fails_unsupported_capability(self, monkeypatch):
        endpoint = FakeAlarmEndpoint(alarm_class_absent=True)
        result = _run_failing(monkeypatch, endpoint, {})
        assert result["error_class"] == "unsupported_capability"
        assert "IPS_AlarmClockOccurrence" in result["msg"]
        assert "MODULE FAILURE" not in result["msg"]

    def test_the_occurrence_limit_refusal_names_the_source(self, monkeypatch):
        endpoint = FakeAlarmEndpoint()
        for index in range(5):
            endpoint.alarms[f"a{index}"] = {"start_time": "2030-01-01T00:00:00Z", "interval": "P0DT0H0M", "delete_on_completion": True}
        result = _run_failing(monkeypatch, endpoint, {"state": "present", "name": "sixth", "start_time": _future()})
        assert result["error_class"] == "invalid_state"
        assert "go-wsman-messages" in result["msg"]

    def test_the_client_is_closed_even_when_the_run_fails(self, monkeypatch):
        endpoint = FakeAlarmEndpoint(alarm_class_absent=True)
        _run_failing(monkeypatch, endpoint, {})
        assert endpoint.closed is True

    @pytest.mark.parametrize(
        "args,missing",
        [
            ({"state": "present", "name": "nightly"}, "start_time"),
            ({"state": "present", "start_time": "2030-01-01T00:00:00Z"}, "name"),
            ({"state": "absent"}, "name"),
        ],
    )
    def test_required_if_is_enforced_by_the_argument_spec(self, monkeypatch, args, missing):
        endpoint = FakeAlarmEndpoint()
        result = _run_failing(monkeypatch, endpoint, args)
        assert missing in result["msg"]
        # Argument validation happens before any transport, so nothing is sent.
        assert endpoint.log == []


class TestArgumentSpec:
    def test_state_defaults_to_the_read_only_value(self):
        spec = amt_alarm.argument_spec()
        assert spec["state"]["default"] == "query"
        assert spec["state"]["choices"] == ["query", "present", "absent"]

    def test_the_interval_option_is_named_for_its_unit(self):
        # A bare `interval: 24` is ambiguous in a way a wake-up time cannot afford.
        spec = amt_alarm.argument_spec()
        assert "interval_minutes" in spec
        assert "interval" not in spec

    def test_the_dangerous_option_defaults_to_off(self):
        assert amt_alarm.argument_spec()["allow_past_start_time"]["default"] is False
