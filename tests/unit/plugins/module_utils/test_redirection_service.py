# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import dataclasses
from unittest.mock import Mock

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import redirection_service
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import UnsupportedCapabilityError


def _capabilities(ider="true", sol="true") -> dict:
    return {"IDER": ider, "SOL": sol}


def _make_client(*, capabilities: dict | None = None, enabled_state="32768", listener_enabled="false") -> Mock:
    client = Mock()
    client.enumerate.return_value = [capabilities if capabilities is not None else _capabilities()]
    client.get.return_value = {"EnabledState": enabled_state, "ListenerEnabled": listener_enabled}
    client.invoke.return_value = ({"ReturnValue": "0"}, 0)
    return client


class TestGetCapabilities:
    def test_both_supported(self):
        client = _make_client(capabilities=_capabilities(ider="true", sol="true"))
        capabilities = redirection_service.get_capabilities(client)
        assert capabilities.ider_supported is True
        assert capabilities.sol_supported is True

    @pytest.mark.parametrize(
        "ider,sol,expected_ider,expected_sol",
        [
            ("true", "false", True, False),
            ("false", "true", False, True),
            ("false", "false", False, False),
        ],
    )
    def test_each_combination(self, ider, sol, expected_ider, expected_sol):
        client = _make_client(capabilities=_capabilities(ider=ider, sol=sol))
        capabilities = redirection_service.get_capabilities(client)
        assert capabilities.ider_supported is expected_ider
        assert capabilities.sol_supported is expected_sol

    def test_ambiguous_capabilities_instance_is_rejected(self):
        client = Mock()
        client.enumerate.return_value = [_capabilities(), _capabilities()]
        with pytest.raises(UnsupportedCapabilityError):
            redirection_service.get_capabilities(client)

    def test_absent_capabilities_instance_is_rejected(self):
        client = Mock()
        client.enumerate.return_value = []
        with pytest.raises(UnsupportedCapabilityError):
            redirection_service.get_capabilities(client)


class TestGetState:
    @pytest.mark.parametrize(
        "enabled_state,expected_ider,expected_sol",
        [
            (redirection_service.ENABLED_STATE_DISABLED, False, False),
            (redirection_service.ENABLED_STATE_IDER_ONLY, True, False),
            (redirection_service.ENABLED_STATE_SOL_ONLY, False, True),
            (redirection_service.ENABLED_STATE_BOTH, True, True),
        ],
    )
    def test_all_four_enabled_state_values(self, enabled_state, expected_ider, expected_sol):
        client = _make_client(enabled_state=str(enabled_state))
        state = redirection_service.get_state(client)
        assert state.enabled_state == enabled_state
        assert state.ider_enabled is expected_ider
        assert state.sol_enabled is expected_sol

    def test_listener_enabled_is_reported(self):
        client = _make_client(listener_enabled="true")
        state = redirection_service.get_state(client)
        assert state.listener_enabled is True


class TestTransportReachableProbe:
    def test_open_port_reports_true(self):
        fake_socket = Mock()
        connect = Mock(return_value=fake_socket)
        reachable = redirection_service.probe_transport_reachable("10.0.0.5", (16994,), connect=connect)
        assert reachable == {16994: True}
        fake_socket.close.assert_called_once()
        connect.assert_called_once_with(("10.0.0.5", 16994), 2.0)

    def test_closed_port_reports_false_without_raising(self):
        connect = Mock(side_effect=OSError("connection refused"))
        reachable = redirection_service.probe_transport_reachable("10.0.0.5", (16994,), connect=connect)
        assert reachable == {16994: False}

    def test_both_ports_probed_independently(self):
        connect = Mock(side_effect=[Mock(), OSError("connection refused")])
        reachable = redirection_service.probe_transport_reachable("10.0.0.5", connect=connect)
        assert reachable == {16994: True, 16995: False}

    def test_never_uses_the_real_socket_module_by_default_call(self):
        # This test exists to document the contract: probe_transport_reachable always accepts an
        # injectable `connect`; every other test in this file uses it, and none opens a real
        # socket. A default-argument regression that made `connect` non-overridable would be a
        # silent test-suite integrity break, not just an API change.
        import inspect

        signature = inspect.signature(redirection_service.probe_transport_reachable)
        assert "connect" in signature.parameters


class TestGetStatus:
    def test_reports_all_three_signals_separately(self):
        client = _make_client(capabilities=_capabilities(ider="true", sol="false"), enabled_state=str(redirection_service.ENABLED_STATE_IDER_ONLY))
        connect = Mock(side_effect=[Mock(), OSError("closed")])
        status = redirection_service.get_status(client, "10.0.0.5", connect=connect)

        assert status.capabilities.ider_supported is True
        assert status.capabilities.sol_supported is False
        assert status.state.ider_enabled is True
        assert status.state.sol_enabled is False
        assert status.transport_reachable == {16994: True, 16995: False}

    def test_supported_enabled_and_reachable_are_independent_axes(self):
        # Supported but not enabled, and not reachable either -- three separate "no"s that must
        # not be collapsed into a single boolean.
        client = _make_client(capabilities=_capabilities(ider="true"), enabled_state=str(redirection_service.ENABLED_STATE_DISABLED))
        connect = Mock(side_effect=OSError("closed"))
        status = redirection_service.get_status(client, "10.0.0.5", connect=connect)
        assert status.capabilities.ider_supported is True
        assert status.state.ider_enabled is False
        assert status.transport_reachable == {16994: False, 16995: False}


class TestValidateStateChange:
    def test_disabled_never_requires_a_capability(self):
        capabilities = redirection_service.RedirectionCapabilities(ider_supported=False, sol_supported=False)
        redirection_service.validate_state_change(capabilities, "disabled")  # must not raise

    @pytest.mark.parametrize("state_name,attribute", [("ider", "ider_supported"), ("sol", "sol_supported"), ("all", "ider_supported")])
    def test_missing_capability_is_rejected(self, state_name, attribute):
        capabilities = redirection_service.RedirectionCapabilities(ider_supported=True, sol_supported=True)
        capabilities = dataclasses.replace(capabilities, **{attribute: False})
        with pytest.raises(UnsupportedCapabilityError):
            redirection_service.validate_state_change(capabilities, state_name)

    def test_unknown_state_name_is_rejected(self):
        capabilities = redirection_service.RedirectionCapabilities(ider_supported=True, sol_supported=True)
        with pytest.raises(ValueError, match="unknown redirection state"):
            redirection_service.validate_state_change(capabilities, "bogus")


class TestRequestStateChange:
    @pytest.mark.parametrize(
        "state_name,expected_value",
        [
            ("disabled", redirection_service.ENABLED_STATE_DISABLED),
            ("ider", redirection_service.ENABLED_STATE_IDER_ONLY),
            ("sol", redirection_service.ENABLED_STATE_SOL_ONLY),
            ("all", redirection_service.ENABLED_STATE_BOTH),
        ],
    )
    def test_invokes_request_state_change_with_the_right_value(self, state_name, expected_value):
        client = _make_client()
        redirection_service.request_state_change(client, state_name)
        client.invoke.assert_called_once_with("AMT_RedirectionService", "RequestStateChange", {"RequestedState": expected_value})

    def test_unknown_state_name_is_rejected_before_any_invoke(self):
        client = _make_client()
        with pytest.raises(ValueError, match="unknown redirection state"):
            redirection_service.request_state_change(client, "bogus")
        client.invoke.assert_not_called()


class TestEnabledStateNameRoundTrip:
    def test_every_state_name_round_trips_through_the_enabled_state_int(self):
        for state_name, enabled_state in redirection_service.STATE_NAME_TO_ENABLED_STATE.items():
            assert redirection_service.ENABLED_STATE_TO_STATE_NAME[enabled_state] == state_name
