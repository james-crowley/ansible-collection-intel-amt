# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.client import PowerAction
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import RemoteOperationError, TimeoutError_
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import OperationReceipt, PowerState
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_power

PASSWORD = "Sup3rSecret!"

BASE_ARGS = {
    "host": "10.0.0.5",
    "username": "admin",
    "password": PASSWORD,
    "tls_fingerprint": "aa" * 32,
}


def _set_module_args(args: dict) -> None:
    basic._ANSIBLE_ARGS = to_bytes(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    # ansible-core >= 2.18 requires an explicit serialization profile alongside
    # the raw args buffer; "legacy" is the plain-JSON profile with no tagging,
    # which is what this hand-built buffer actually is.
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


def _wire_fake_client(monkeypatch, fake_client) -> None:
    monkeypatch.setattr(amt_power, "build_wsman_client", lambda params: Mock(endpoint="10.0.0.5:16993"))
    monkeypatch.setattr(amt_power, "AmtClient", lambda wsman: fake_client)


def _fake_client_at(power_normalized: str) -> Mock:
    client = Mock()
    client.get_power_state.return_value = PowerState.from_cim_value({"on": 2, "off": 8}[power_normalized])
    return client


def _run(args: dict) -> dict:
    _set_module_args(args)
    with pytest.raises((AnsibleExitJson, AnsibleFailJson)) as excinfo:
        amt_power.main()
    return excinfo.value.args[0]


class TestArgumentSpec:
    def test_password_is_no_log(self):
        assert amt_power.argument_spec()["password"]["no_log"] is True

    def test_state_choices_and_default(self):
        spec = amt_power.argument_spec()["state"]
        assert set(spec["choices"]) == {
            "on",
            "off",
            "reboot",
            "reset",
            "cycle",
            "sleep-light",
            "sleep-deep",
            "hibernate",
            "query",
        }
        assert spec["default"] == "query"

    def test_invalid_state_fails_argument_validation(self, monkeypatch):
        _wire_fake_client(monkeypatch, Mock())
        args = dict(BASE_ARGS)
        args["state"] = "explode"
        result = _run(args)
        assert "msg" in result  # AnsibleModule's own choice-validation failure


class TestBuildWsmanClient:
    def test_builds_a_real_client_from_module_params_without_touching_a_socket(self):
        params = {
            "host": "10.0.0.5",
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
        wsman = amt_power.build_wsman_client(params)
        assert wsman.endpoint == "10.0.0.5:16992"  # plaintext default port, resolved by tls.py
        wsman.close()


class TestPlan:
    def test_query_never_changes_anything(self):
        assert amt_power.plan("query", "on") == (False, None)
        assert amt_power.plan("query", "off") == (False, None)

    @pytest.mark.parametrize("current", ["on", "off", "sleep", "unknown"])
    def test_on_is_convergent(self, current):
        changed, desired = amt_power.plan("on", current)
        assert desired == "on"
        assert changed == (current != "on")

    @pytest.mark.parametrize("current", ["on", "off"])
    def test_off_is_convergent(self, current):
        changed, desired = amt_power.plan("off", current)
        assert desired == "off"
        assert changed == (current != "off")

    @pytest.mark.parametrize("state", ["reboot", "reset", "cycle"])
    @pytest.mark.parametrize("current", ["on", "off"])
    def test_imperative_states_always_report_changed(self, state, current):
        changed, desired = amt_power.plan(state, current)
        assert changed is True
        assert desired == "on"  # every imperative action here converges on "on"

    @pytest.mark.parametrize("current", ["on", "off", "hibernate", "unknown"])
    def test_hibernate_is_convergent(self, current):
        # CIM PowerState 7 is the only value that normalizes to "hibernate", so
        # unlike the sleep depths this reading can be trusted for convergence.
        changed, desired = amt_power.plan("hibernate", current)
        assert desired == "hibernate"
        assert changed == (current != "hibernate")

    @pytest.mark.parametrize("state", ["sleep-light", "sleep-deep"])
    @pytest.mark.parametrize("current", ["on", "off", "sleep", "hibernate", "unknown"])
    def test_sleep_depths_are_never_convergent(self, state, current):
        # The regression this guards: CIM 3 (S1) and CIM 4 (S3) both normalize to
        # "sleep", so treating sleep as convergent would report changed=False for a
        # machine sitting at the OTHER depth -- a transition that was never issued.
        # It must always send, including when already reported as "sleep".
        changed, desired = amt_power.plan(state, current)
        assert changed is True
        assert desired == "sleep"

    def test_every_choice_except_query_maps_to_an_action(self):
        # Guards the failure mode this change fixed: PowerAction carried
        # SLEEP_LIGHT/SLEEP_DEEP/HIBERNATE with correct CIM codes for three
        # releases while argument_spec's choices omitted them, so they were
        # unreachable. Any future choice added without a mapping fails here.
        choices = set(amt_power.argument_spec()["state"]["choices"]) - {"query"}
        assert choices == set(amt_power._STATE_TO_ACTION)
        for action in amt_power._STATE_TO_ACTION.values():
            assert action in amt_power._ACTION_EXPECTED_STATE

    def test_expected_states_agree_with_the_client_table(self):
        # The module keeps its own copy of the expected-state map for check mode.
        # If it ever disagrees with the client's, check mode would preview a
        # different outcome than the real run produces.
        from ansible_collections.james_crowley.intel_amt.plugins.module_utils import client as client_mod

        for action, expected in amt_power._ACTION_EXPECTED_STATE.items():
            assert client_mod._ACTION_EXPECTED_STATE[action] == expected


class TestConvergence:
    def test_on_when_already_on_is_a_noop(self, monkeypatch):
        fake_client = _fake_client_at("on")
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "on"
        result = _run(args)

        assert result["changed"] is False
        fake_client.request_power_state.assert_not_called()

    def test_off_when_already_off_is_a_noop(self, monkeypatch):
        fake_client = _fake_client_at("off")
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "off"
        result = _run(args)

        assert result["changed"] is False
        fake_client.request_power_state.assert_not_called()

    def test_second_run_of_the_same_task_is_idempotent(self, monkeypatch):
        # Simulate re-running the same "ensure on" task after it already
        # succeeded once: the endpoint is now on, so the second run is a noop.
        fake_client = _fake_client_at("on")
        _wire_fake_client(monkeypatch, fake_client)
        args = dict(BASE_ARGS)
        args["state"] = "on"

        first = _run(args)
        second = _run(args)

        assert first["changed"] is False
        assert second["changed"] is False
        fake_client.request_power_state.assert_not_called()

    def test_on_when_off_issues_the_request(self, monkeypatch):
        fake_client = _fake_client_at("off")
        fake_client.request_power_state.return_value = OperationReceipt(
            action="amt_power.on",
            endpoint="10.0.0.5:16993",
            changed=True,
            previous=PowerState.from_cim_value(8),
            desired="on",
            observed=PowerState.from_cim_value(2),
            extra={"return_value": 0, "probes": [{"normalized": "on", "raw": 2}]},
        )
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "on"
        result = _run(args)

        assert result["changed"] is True
        assert result["desired_state"] == "on"
        assert result["return_value"] == 0
        fake_client.request_power_state.assert_called_once_with(PowerAction.ON)


class TestImperativeActions:
    @pytest.mark.parametrize("state,action", [("reboot", PowerAction.REBOOT), ("reset", PowerAction.RESET), ("cycle", PowerAction.CYCLE)])
    def test_always_issues_the_request_regardless_of_current_state(self, monkeypatch, state, action):
        fake_client = _fake_client_at("on")
        fake_client.request_power_state.return_value = OperationReceipt(
            action=f"amt_power.{state}",
            endpoint="10.0.0.5:16993",
            changed=True,
            previous=PowerState.from_cim_value(2),
            desired="on",
            observed=PowerState.from_cim_value(2),
            extra={"return_value": 0, "probes": []},
        )
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = state
        result = _run(args)

        assert result["changed"] is True
        fake_client.request_power_state.assert_called_once_with(action)


class TestQuery:
    def test_query_never_mutates_even_when_state_could_change(self, monkeypatch):
        fake_client = _fake_client_at("off")
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "query"
        result = _run(args)

        assert result["changed"] is False
        assert result["desired_state"] is None
        fake_client.request_power_state.assert_not_called()


class TestCheckMode:
    @pytest.mark.parametrize("state", ["on", "reboot", "reset", "cycle"])
    def test_check_mode_reports_the_plan_without_sending_it(self, monkeypatch, state):
        fake_client = _fake_client_at("off")
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = state
        args["_ansible_check_mode"] = True
        result = _run(args)

        assert result["changed"] is True
        # The whole point of check mode: the mutating call is never made.
        fake_client.request_power_state.assert_not_called()

    @pytest.mark.parametrize(
        "initial,state",
        [
            ("on", "off"),
            ("on", "reset"),
            ("on", "cycle"),
            ("on", "reboot"),
            ("off", "on"),
        ],
    )
    def test_check_mode_never_mutates_from_any_starting_state(self, monkeypatch, initial, state):
        """`off` is as destructive as `reset` and was absent from the case list above.

        Parametrising over the starting state as well as the requested state
        means every transition that would mutate is proven not to, rather than
        only the ones reachable from a powered-off machine.
        """
        fake_client = _fake_client_at(initial)
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = state
        args["_ansible_check_mode"] = True
        result = _run(args)

        assert result["changed"] is True
        fake_client.request_power_state.assert_not_called()

    def test_check_mode_on_an_already_converged_state_reports_no_change(self, monkeypatch):
        fake_client = _fake_client_at("on")
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "on"
        args["_ansible_check_mode"] = True
        result = _run(args)

        assert result["changed"] is False
        fake_client.request_power_state.assert_not_called()


class TestErrorHandling:
    def test_nonzero_return_value_is_a_remote_operation_failure(self, monkeypatch):
        fake_client = _fake_client_at("off")
        fake_client.request_power_state.side_effect = RemoteOperationError(
            "RequestPowerStateChange returned ReturnValue=2",
            endpoint="10.0.0.5:16993",
            operation="CIM_PowerManagementService.RequestPowerStateChange",
            return_value=2,
        )
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "on"
        result = _run(args)

        assert result["error_class"] == "remote_operation"
        assert result["return_value"] == 2

    def test_timeout_after_send_is_reported_as_indeterminate(self, monkeypatch):
        fake_client = _fake_client_at("off")
        fake_client.request_power_state.side_effect = TimeoutError_(
            "timed out after send", endpoint="10.0.0.5:16993", operation="RequestPowerStateChange", indeterminate=True
        )
        _wire_fake_client(monkeypatch, fake_client)

        args = dict(BASE_ARGS)
        args["state"] = "reset"
        result = _run(args)

        assert result["error_class"] == "timeout"
        assert result["indeterminate"] is True

    def test_missing_requests_dependency_is_an_actionable_failure(self, monkeypatch):
        monkeypatch.setattr(amt_power, "HAS_REQUESTS", False)
        monkeypatch.setattr(amt_power, "REQUESTS_IMPORT_ERROR", "No module named 'requests'")
        args = dict(BASE_ARGS)
        args["state"] = "query"
        result = _run(args)
        assert "requests" in result["msg"]


class TestNoCredentialLeakage:
    def test_no_credential_in_a_successful_result(self, monkeypatch):
        fake_client = _fake_client_at("on")
        _wire_fake_client(monkeypatch, fake_client)
        args = dict(BASE_ARGS)
        args["state"] = "on"
        result = _run(args)
        assert PASSWORD not in json.dumps(result)

    def test_no_credential_in_a_failure_result(self, monkeypatch):
        fake_client = _fake_client_at("off")
        fake_client.request_power_state.side_effect = RemoteOperationError(
            f"rejected password={PASSWORD}", endpoint="10.0.0.5:16993", operation="x", return_value=1, secrets=PASSWORD
        )
        _wire_fake_client(monkeypatch, fake_client)
        args = dict(BASE_ARGS)
        args["state"] = "on"
        result = _run(args)
        assert PASSWORD not in json.dumps(result)
