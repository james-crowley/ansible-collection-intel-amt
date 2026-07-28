# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_redirection

BASE_ARGS = {
    "host": "10.0.0.5",
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
    # ansible-core >= 2.21 requires an explicit args-decoding profile alongside _ANSIBLE_ARGS;
    # older cores ignore this attribute entirely, so setting it is harmless either way.
    basic._ANSIBLE_PROFILE = "legacy"


def _exit_json(*_args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _fail_json(*_args, **kwargs):
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def _patch_exit_and_fail(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


def _make_fake_client(*, ider="true", sol="true", enabled_state="32768", listener_enabled="false") -> Mock:
    client = Mock()
    client.enumerate.return_value = [{"IDER": ider, "SOL": sol}]
    client.get.return_value = {"EnabledState": enabled_state, "ListenerEnabled": listener_enabled}
    client.invoke.return_value = ({"ReturnValue": "0"}, 0)
    client.last_peer_certificate = None
    return client


@pytest.fixture(autouse=True)
def _no_real_sockets(monkeypatch):
    # The module's connection to redirection_service.get_status() uses socket.create_connection
    # by default; nothing in this test module should ever open a real socket.
    monkeypatch.setattr("socket.create_connection", Mock(side_effect=OSError("no network in unit tests")))


class TestAmtRedirectionModule:
    def test_read_only_by_default_reports_changed_false(self):
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        result = excinfo.value.kwargs
        assert result["changed"] is False
        assert result["action"] == "amt_redirection"
        assert result["supported"] == {"ider": True, "sol": True}
        assert result["enabled"]["enabled_state"] == 32768
        assert result["transport_reachable"] == {16994: False, 16995: False}
        fake_client.invoke.assert_not_called()

    def test_three_signals_are_reported_as_separate_fields_not_one_boolean(self):
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client(ider="true", sol="false", enabled_state="32769")
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        result = excinfo.value.kwargs
        assert set(result) >= {"supported", "enabled", "transport_reachable"}
        assert isinstance(result["supported"], dict)
        assert isinstance(result["enabled"], dict)
        assert isinstance(result["transport_reachable"], dict)
        assert result["supported"]["sol"] is False
        assert result["enabled"]["ider_enabled"] is True

    def test_state_matching_current_state_reports_no_change(self):
        args = dict(BASE_ARGS, state="disabled")
        _set_module_args(args)
        fake_client = _make_fake_client(enabled_state="32768")
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        assert excinfo.value.kwargs["changed"] is False
        fake_client.invoke.assert_not_called()

    def test_state_mutation_diffs_and_applies(self):
        args = dict(BASE_ARGS, state="ider")
        _set_module_args(args)
        fake_client = _make_fake_client(enabled_state="32768")
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        assert excinfo.value.kwargs["changed"] is True
        fake_client.invoke.assert_called_once_with("AMT_RedirectionService", "RequestStateChange", {"RequestedState": 32769})

    def test_check_mode_diffs_but_does_not_invoke(self):
        args = dict(BASE_ARGS, state="ider", _ansible_check_mode=True)
        _set_module_args(args)
        fake_client = _make_fake_client(enabled_state="32768")
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        assert excinfo.value.kwargs["changed"] is True
        fake_client.invoke.assert_not_called()

    def test_unsupported_state_fails_before_any_mutation(self):
        args = dict(BASE_ARGS, state="ider")
        _set_module_args(args)
        fake_client = _make_fake_client(ider="false", enabled_state="32768")
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleFailJson) as excinfo:
                amt_redirection.main()
        assert excinfo.value.kwargs["error_class"] == "unsupported_capability"
        fake_client.invoke.assert_not_called()

    def test_invalid_state_choice_is_rejected_by_argument_spec(self):
        args = dict(BASE_ARGS, state="bogus")
        _set_module_args(args)
        with pytest.raises((AnsibleFailJson, SystemExit)):
            amt_redirection.main()

    def test_credential_never_appears_in_the_result(self):
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        assert BASE_ARGS["password"] not in json.dumps(excinfo.value.kwargs)
