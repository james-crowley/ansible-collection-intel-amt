# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import socket
from unittest.mock import Mock, patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import redirection_service
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_redirection

#: RFC 5737 TEST-NET-1. Deliberately not a private-range address: the reachability probe used to
#: run for real from these tests (see the fixture below), and a 10.0.0.0/8 fixture address is a
#: plausible host on the lab LAN this collection manages, where a live endpoint answering on
#: 16994 would change what the tests observe.
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


class ConnectRecorder:
    """The reachability probe's socket factory, replaced by something that never leaves the process.

    Records every ``(address, timeout)`` it was asked for, so a test can prove the probe went
    through this object rather than through a real socket, and refuses every port not listed in
    ``open_ports`` with ``OSError`` -- exactly what a closed port produces.
    """

    def __init__(self):
        self.open_ports: set[int] = set()
        self.calls: list[tuple[tuple[str, int], float]] = []

    def __call__(self, address, timeout):
        self.calls.append((address, timeout))
        if address[1] not in self.open_ports:
            raise OSError("connection refused (unit-test socket factory)")
        return Mock()  # anything with a callable close()

    @property
    def probed_ports(self) -> list[int]:
        return [address[1] for address, _timeout in self.calls]


@pytest.fixture(autouse=True)
def connect_probe(monkeypatch):
    """Replace the socket factory *where it is actually resolved from*.

    ``redirection_service.probe_transport_reachable`` declares
    ``connect: ConnectFn = socket.create_connection`` -- a default argument, so the function
    object binds ``socket.create_connection`` once at import time. ``amt_redirection.main()``
    calls ``get_status(client, host)`` without passing ``connect``, so the bound default is what
    runs, and rebinding the name ``socket.create_connection`` afterwards never reaches it.

    The previous fixture here did exactly that rebinding, and its comment claimed nothing in this
    file opens a real socket. Every test in the file was in fact making two real TCP connections
    to the fixture host on 16994/16995 and waiting for them to time out -- about 4s per test, 36s
    of a 78s unit run. Patching the entry in ``__kwdefaults__`` is what the call actually reads.
    """
    recorder = ConnectRecorder()
    monkeypatch.setitem(redirection_service.get_status.__kwdefaults__, "connect", recorder)
    monkeypatch.setitem(redirection_service.probe_transport_reachable.__kwdefaults__, "connect", recorder)
    # Belt and braces. If any future code path reaches the real factory instead, fail loudly here
    # rather than quietly dialling out to the fixture address.
    monkeypatch.setattr(socket, "create_connection", Mock(side_effect=AssertionError("a unit test opened a real socket")))
    return recorder


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
        assert result["operation"]["action"] == "amt_redirection"
        assert result["operation"]["schema"] == "intel-amt-operation/v1"
        assert result["supported"] == {"ider": True, "sol": True}
        assert result["enabled"]["enabled_state"] == 32768
        assert result["transport_reachable"] == {16994: False, 16995: False}
        fake_client.invoke.assert_not_called()

    def test_receipt_is_nested_under_operation_not_spread_at_top_level(self):
        # issue #22: the receipt lives under `operation`, never spread at the top level
        # alongside module-specific keys like `supported`/`enabled`/`transport_reachable`.
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        result = excinfo.value.kwargs
        for moved_field in ("schema", "action", "endpoint", "previous", "desired", "observed", "tls_peer_fingerprint"):
            assert moved_field not in result, f"{moved_field!r} must not be spread at the top level; it belongs under operation"
        assert result["operation"]["error_class"] is None

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
        # Each signal reported in full, and disagreeing with the others: firmware supports IDE-R
        # but not SOL, the service is enabled for IDE-R only, and neither port answers. A single
        # collapsed boolean could not express this machine at all. Asserting the whole dict rather
        # than one key each is what makes a field silently changing shape or disappearing fail.
        assert result["supported"] == {"ider": True, "sol": False}
        assert result["enabled"] == {"enabled_state": 32769, "listener_enabled": False, "ider_enabled": True, "sol_enabled": False}
        assert result["transport_reachable"] == {16994: False, 16995: False}

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


class TestReachabilityProbe:
    """The probe is a real TCP connect, so what it connects to -- and whether it connects at all
    from a unit test -- is part of what these tests have to pin."""

    def test_the_probe_goes_through_the_injected_factory_and_never_a_real_socket(self, connect_probe):
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson):
                amt_redirection.main()
        # The positive control for the fixture above: if the patch stopped reaching the call, this
        # list would be empty and the probe would be dialling out for real again.
        assert connect_probe.calls == [((HOST, 16994), 2.0), ((HOST, 16995), 2.0)]

    def test_the_probe_uses_the_redirection_ports_not_the_wsman_port(self, connect_probe):
        args = dict(BASE_ARGS, port=16992)
        _set_module_args(args)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson):
                amt_redirection.main()
        # A caller-supplied WS-Man `port` must not redirect the reachability probe, which is about
        # the separate redirection plane (docs/protocol-notes.md s1).
        assert connect_probe.probed_ports == [16994, 16995]

    def test_an_answering_port_is_reported_reachable_independently_of_the_other(self, connect_probe):
        connect_probe.open_ports = {16994}
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_redirection.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_redirection.main()
        # 16994 open and 16995 closed is the ordinary shape for an endpoint with TLS redirection
        # disabled; reporting one bool for both would erase the difference.
        assert excinfo.value.kwargs["transport_reachable"] == {16994: True, 16995: False}
