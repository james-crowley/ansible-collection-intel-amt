# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Module-level tests for ``amt_network``: result shape, check mode, and the failure paths.

The planning and value-table work lives in
``tests/unit/plugins/module_utils/test_network.py``. What is left for this file is
what only the module can get wrong: which keys the result document carries, that
check mode issues nothing, and that the two unconfirmed-write outcomes come out
as *failures* with the right ``error_class`` rather than as a success with a
caveat.

The credential invariant is deliberately **not** re-asserted here -- see
``tests/unit/plugins/modules/test_credential_contract.py`` for why a test that
stubs ``exit_json`` cannot prove it. This module is covered there by discovery.
"""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import ConnectionError_, ErrorClass
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_network

BASE_ARGS = {
    "host": "192.0.2.10",
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
    # _ANSIBLE_ARGS; older cores ignore this attribute entirely.
    basic._ANSIBLE_PROFILE = "legacy"


def _exit_json(*_args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _fail_json(*_args, **kwargs):
    raise AnsibleFailJson(kwargs)


@pytest.fixture(autouse=True)
def _patch_exit_and_fail(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


def _ethernet(**overrides) -> dict:
    instance = {
        "ElementName": "Intel(r) AMT Ethernet Port Settings",
        "InstanceID": "Intel(r) AMT Ethernet Port Settings 0",
        "MACAddress": "00-00-5e-00-53-01",
        "IPAddress": "192.0.2.10",
        "SubnetMask": "255.255.255.0",
        "DefaultGateway": "192.0.2.1",
        "PrimaryDNS": "192.0.2.2",
        "SecondaryDNS": "192.0.2.3",
        "DHCPEnabled": "false",
        "LinkIsUp": "true",
        "IpSyncEnabled": "false",
        "SharedMAC": "true",
        "SharedStaticIp": "true",
        "LinkPolicy": ["1", "14", "16"],
        "LinkControl": "2",
        "SharedDynamicIP": "true",
        "WLANLinkProtectionLevel": "1",
    }
    instance.update(overrides)
    return instance


def _general(**overrides) -> dict:
    instance = {
        "ElementName": "Intel(r) AMT General Settings",
        "InstanceID": "Intel(r) AMT: General Settings",
        "NetworkInterfaceEnabled": "true",
        "DigestRealm": "Digest:A4000000000000000000000000000000",
        "HostName": "mock-amt-host",
        "DomainName": "example.invalid",
        "PingResponseEnabled": "true",
        "RmcpPingResponseEnabled": "true",
        "WsmanOnlyMode": "false",
    }
    instance.update(overrides)
    return instance


def _client(get_sequence) -> Mock:
    """A fake ``WsmanClient`` whose ``get`` walks ``get_sequence``.

    ``get_sequence`` is a list of (resource_class, value) pairs consumed in order,
    where the value is either an instance dict or an exception to raise. Keyed by
    order rather than by class because the module reads each class twice -- once to
    plan, once to confirm -- and the *second* reading is what the confirmation
    tests need to differ.
    """
    remaining = list(get_sequence)

    def _get(resource_class, **_kwargs):
        expected_class, value = remaining.pop(0)
        assert resource_class == expected_class, f"expected a Get of {expected_class}, module asked for {resource_class}"
        if isinstance(value, Exception):
            raise value
        return value

    client = Mock()
    client.get.side_effect = _get
    client.put.return_value = {}
    client.last_peer_certificate = None
    client.endpoint = "192.0.2.10:16992"
    return client


def _run(args: dict, client: Mock):
    _set_module_args({**BASE_ARGS, **args})
    with patch.object(amt_network, "build_wsman_client", return_value=client):
        try:
            amt_network.main()
        except (AnsibleExitJson, AnsibleFailJson) as outcome:
            return outcome
    raise AssertionError("main() returned without calling exit_json or fail_json")


#: The reads the module makes before planning, in order.
_PLAN_READS = [("AMT_EthernetPortSettings", _ethernet()), ("AMT_GeneralSettings", _general())]


class TestSuccessfulConvergence:
    def test_a_general_settings_change_is_written_and_confirmed(self):
        client = _client([*_PLAN_READS, ("AMT_GeneralSettings", _general(PingResponseEnabled="false"))])
        outcome = _run({"ping_response_enabled": False}, client)
        assert isinstance(outcome, AnsibleExitJson)
        result = outcome.kwargs
        assert result["changed"] is True
        assert result["written_classes"] == ["AMT_GeneralSettings"]
        assert result["indeterminate"] is False
        assert result["general"]["ping_response_enabled"] is False

    def test_an_already_converged_call_reports_changed_false_and_writes_nothing(self):
        client = _client(list(_PLAN_READS))
        outcome = _run({"ping_response_enabled": True, "hostname": "mock-amt-host"}, client)
        assert outcome.kwargs["changed"] is False
        assert outcome.kwargs["changes"] == []
        assert client.put.call_count == 0

    def test_the_receipt_carries_the_exact_put_bodies_keyed_by_class(self):
        client = _client([*_PLAN_READS, ("AMT_GeneralSettings", _general(HostName="renamed"))])
        outcome = _run({"hostname": "renamed"}, client)
        receipt = outcome.kwargs["operation"]
        assert receipt["schema"] == "intel-amt-operation/v1"
        assert receipt["action"] == "amt_network"
        assert receipt["desired"]["AMT_GeneralSettings"]["HostName"] == "renamed"
        # Nothing to write on the other class, so no body -- not an empty dict,
        # which would read as "we sent an empty Put".
        assert receipt["desired"]["AMT_EthernetPortSettings"] is None
        # The read-only properties really are stripped from the body an operator
        # can inspect, not merely from the one that went on the wire.
        assert "DigestRealm" not in receipt["desired"]["AMT_GeneralSettings"]

    def test_a_link_policy_change_reports_integers_and_names(self):
        client = _client([*_PLAN_READS, ("AMT_EthernetPortSettings", _ethernet(LinkPolicy=["1", "14"]))])
        outcome = _run({"link_policy": ["s0_ac", "sx_ac"]}, client)
        (change,) = outcome.kwargs["changes"]
        assert change["previous"] == {"values": [1, 14, 16], "names": ["s0_ac", "sx_ac", "s0_dc"]}
        assert change["desired"] == {"values": [1, 14], "names": ["s0_ac", "sx_ac"]}
        assert outcome.kwargs["network"]["wake_on_lan_capable"] is True

    def test_an_off_link_gateway_warns_without_failing(self):
        client = _client([*_PLAN_READS, ("AMT_EthernetPortSettings", _ethernet(DefaultGateway="198.51.100.1"))])
        _set_module_args({**BASE_ARGS, "default_gateway": "198.51.100.1", "allow_self_disconnect": True})
        warnings: list[str] = []

        def record_warning(_self, message):
            warnings.append(message)

        with patch.object(amt_network, "build_wsman_client", return_value=client), patch.object(basic.AnsibleModule, "warn", record_warning):
            with pytest.raises(AnsibleExitJson):
                amt_network.main()
        assert len(warnings) == 1
        assert "not on the same subnet" in warnings[0]


class TestCheckMode:
    def test_check_mode_plans_without_issuing_a_put(self):
        client = _client(list(_PLAN_READS))
        outcome = _run({"hostname": "renamed", "_ansible_check_mode": True}, client)
        assert outcome.kwargs["changed"] is True
        assert client.put.call_count == 0
        assert outcome.kwargs["written_classes"] == []
        # The plan is the finished body, not a paraphrase of the options.
        assert outcome.kwargs["operation"]["desired"]["AMT_GeneralSettings"]["HostName"] == "renamed"
        assert outcome.kwargs["operation"]["observed"]["AMT_GeneralSettings"] is None

    def test_check_mode_still_applies_the_self_disconnect_refusal(self):
        # A dry run that skipped the gate would tell an operator a dangerous write
        # is fine, which is worse than having no dry run at all.
        client = _client(list(_PLAN_READS))
        outcome = _run({"ip_address": "198.51.100.7", "_ansible_check_mode": True}, client)
        assert isinstance(outcome, AnsibleFailJson)
        assert outcome.kwargs["error_class"] == ErrorClass.INVALID_STATE
        assert "allow_self_disconnect" in outcome.kwargs["msg"]

    def test_check_mode_still_applies_the_wake_capability_refusal(self):
        client = _client(list(_PLAN_READS))
        outcome = _run({"link_policy": ["s0_ac"], "_ansible_check_mode": True}, client)
        assert isinstance(outcome, AnsibleFailJson)
        assert "allow_wake_capability_loss" in outcome.kwargs["msg"]

    def test_check_mode_reports_a_forced_addressing_plan_it_would_send(self):
        client = _client(list(_PLAN_READS))
        outcome = _run({"dhcp_enabled": True, "allow_self_disconnect": True, "_ansible_check_mode": True}, client)
        body = outcome.kwargs["operation"]["desired"]["AMT_EthernetPortSettings"]
        assert body["DHCPEnabled"] is True
        # Visible in the plan, not just on the wire: the static addressing was dropped.
        assert "IPAddress" not in body
        assert outcome.kwargs["addressing_change"] is True


class TestUnconfirmedWrites:
    def test_a_lost_connection_after_the_put_fails_with_indeterminate_true(self):
        client = _client([*_PLAN_READS, ("AMT_EthernetPortSettings", ConnectionError_("connection refused", endpoint="192.0.2.10:16992"))])
        outcome = _run({"ip_address": "198.51.100.7", "allow_self_disconnect": True}, client)
        assert isinstance(outcome, AnsibleFailJson), "an unconfirmed write must never be reported as a success"
        assert outcome.kwargs["indeterminate"] is True
        assert outcome.kwargs["error_class"] == ErrorClass.CONNECTION
        # The caller is told which classes were written, so a re-probe knows what
        # to look for.
        assert outcome.kwargs["written_classes"] == ["AMT_EthernetPortSettings"]
        assert "re-probe" in outcome.kwargs["msg"].lower()

    def test_a_put_firmware_accepted_and_ignored_fails_with_unsupported_capability(self):
        # The confirming read succeeds and reports the OLD value. Settled, so not
        # indeterminate: there is nothing in flight to re-probe.
        client = _client([*_PLAN_READS, ("AMT_GeneralSettings", _general(PingResponseEnabled="true"))])
        outcome = _run({"ping_response_enabled": False}, client)
        assert isinstance(outcome, AnsibleFailJson)
        assert outcome.kwargs["error_class"] == ErrorClass.UNSUPPORTED_CAPABILITY
        assert "indeterminate" not in outcome.kwargs
        assert "PingResponseEnabled" in outcome.kwargs["msg"]


class TestUsageErrors:
    def test_a_call_with_no_setting_is_refused(self):
        client = _client(list(_PLAN_READS))
        outcome = _run({}, client)
        assert isinstance(outcome, AnsibleFailJson)
        assert "no setting to apply" in outcome.kwargs["msg"]

    def test_an_unknown_link_policy_name_is_rejected_by_the_argument_spec(self):
        _set_module_args({**BASE_ARGS, "link_policy": ["always_on"]})
        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_network.main()
        assert "always_on" in excinfo.value.kwargs["msg"]


class TestArgumentSpec:
    def test_no_setting_option_carries_a_default(self):
        # A default would make every call assert a value, turning a task that only
        # wanted the hostname into an addressing change.
        spec = amt_network.argument_spec()
        for name in (
            "dhcp_enabled",
            "ip_address",
            "subnet_mask",
            "default_gateway",
            "primary_dns",
            "secondary_dns",
            "link_policy",
            "ping_response_enabled",
            "rmcp_ping_response_enabled",
            "hostname",
            "domain_name",
        ):
            assert "default" not in spec[name], f"{name} must default to 'leave this alone', i.e. no default at all"

    def test_both_acknowledgements_default_to_false(self):
        spec = amt_network.argument_spec()
        assert spec["allow_self_disconnect"]["default"] is False
        assert spec["allow_wake_capability_loss"]["default"] is False

    def test_link_policy_choices_are_exactly_the_four_vendor_names(self):
        assert amt_network.argument_spec()["link_policy"]["choices"] == ["s0_ac", "s0_dc", "sx_ac", "sx_dc"]
