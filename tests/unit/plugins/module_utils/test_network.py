# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for ``module_utils/network.py`` -- the ``amt_network`` write path.

Two things this file is deliberately careful about.

**The value tables are asserted against the vendor numbers written out
longhand**, not against the constants they are built from. Asserting
``LINK_POLICY_WRITE_VALUES["sx_ac"] == LINK_POLICY_SX_AC`` would pass for any
value at all, including the inverted table this collection shipped in 0.2.0 and
0.3.0. The literal ``14`` is the whole point.

**The refusals are asserted to fire, and their absence asserted to let the write
through.** A guard that refuses everything is as broken as one that refuses
nothing, so every gate has both a positive and a negative case.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import network
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    ConnectionError_,
    ErrorClass,
    InvalidStateError,
    TimeoutError_,
    UnsupportedCapabilityError,
)

HOST = "192.0.2.10"


def _ethernet_instance(**overrides) -> dict:
    """A static-mode ``AMT_EthernetPortSettings`` instance, as firmware sends it.

    Every scalar is a **string**, because WS-Man element text is what
    ``wsman._element_to_value`` produces -- there are no Python bools coming off
    the wire. A test that fed real bools here would not exercise the
    string-versus-bool comparison that idempotence turns on.
    """
    instance = {
        "ElementName": "Intel(r) AMT Ethernet Port Settings",
        "InstanceID": network.ETHERNET_PORT_0_SELECTOR["InstanceID"],
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


def _general_instance(**overrides) -> dict:
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
        "IdleWakeTimeout": "1",
    }
    instance.update(overrides)
    return instance


def _options(**supplied) -> dict:
    """Module params with every setting option present and ``None`` unless supplied.

    Mirrors what ``AnsibleModule`` actually hands the planner: absent options are
    ``None``, not missing keys.
    """
    options = {name: None for name in (*network.ETHERNET_OPTION_TO_PROPERTY, *network.GENERAL_OPTION_TO_PROPERTY)}
    options.update(supplied)
    return options


def _plan(**supplied):
    ethernet = supplied.pop("ethernet_instance", None)
    general = supplied.pop("general_instance", None)
    allow_self_disconnect = supplied.pop("allow_self_disconnect", False)
    allow_wake_capability_loss = supplied.pop("allow_wake_capability_loss", False)
    host = supplied.pop("host", HOST)
    return network.plan_network_change(
        ethernet_instance=_ethernet_instance() if ethernet is None else ethernet,
        general_instance=_general_instance() if general is None else general,
        options=_options(**supplied),
        host=host,
        allow_self_disconnect=allow_self_disconnect,
        allow_wake_capability_loss=allow_wake_capability_loss,
    )


class TestLinkPolicyWriteTable:
    """The write-side table, against the vendor numbers spelled out.

    Re-derived from ``go-wsman-messages`` v2.48.3
    ``pkg/wsman/amt/ethernetport/decoder.go``: ``LinkPolicyS0AC = 1``,
    ``LinkPolicySxAC = 14``, ``LinkPolicyS0DC = 16``, ``LinkPolicySxDC = 224``,
    with ``types.go``'s schema annotation ``ValueMap={1, 14, 16, 224}`` /
    ``Values={available on S0 AC, available on Sx AC, available on S0 DC,
    available on Sx DC}`` on the ``LinkPolicy`` type that *both* the request and
    the response struct use.

    The values below are the literal integers on purpose. This is the table whose
    predecessor was wrong in three of five entries and inverted
    ``wake_on_lan_capable`` for two releases.
    """

    def test_the_four_vendor_values_and_no_others(self):
        assert network.LINK_POLICY_WRITE_VALUES == {"s0_ac": 1, "sx_ac": 14, "s0_dc": 16, "sx_dc": 224}

    def test_the_sx_values_are_14_and_224_not_16(self):
        # 16 is S0 DC. The 0.2.0/0.3.0 table called it "always_on" and derived
        # wake_on_lan_capable from it, which made the boolean test "reachable on
        # battery?" and read false on every mains-powered desktop.
        assert network.LINK_POLICY_SX_WRITE_VALUES == (14, 224)
        assert 16 not in network.LINK_POLICY_SX_WRITE_VALUES

    def test_the_values_parmstro_invented_are_absent(self):
        # 2 and 15 are in no Intel enum. See docs/protocol-notes.md 2.7.
        assert 2 not in network.LINK_POLICY_WRITE_VALUES.values()
        assert 15 not in network.LINK_POLICY_WRITE_VALUES.values()

    def test_decode_is_sorted_and_deduplicated(self):
        assert network.decode_link_policy_option(["sx_dc", "s0_ac", "s0_ac"]) == [1, 224]

    def test_an_unknown_name_raises_valueerror_not_an_amt_error(self):
        with pytest.raises(ValueError, match="unknown link_policy name"):
            network.decode_link_policy_option(["always_on"])

    def test_an_empty_link_policy_list_is_refused_rather_than_written_as_an_absent_property(self):
        # An empty array emits no elements at all (wsman._append_params), so the Put
        # body would simply omit LinkPolicy and firmware would be asked nothing.
        # `link_policy: []` passes the module's `choices` validation, so it is
        # reachable from a playbook and has to be refused here.
        with pytest.raises(InvalidStateError) as excinfo:
            _plan(link_policy=[])
        assert excinfo.value.error_class == ErrorClass.INVALID_STATE
        assert "empty list" in str(excinfo.value)
        assert "Omit the option entirely" in str(excinfo.value)

    def test_a_non_empty_link_policy_list_is_not_caught_by_that_refusal(self):
        # The negative control: the refusal is about emptiness, not about
        # link_policy being suspicious.
        plan = _plan(link_policy=["s0_ac", "sx_ac"])
        assert plan.ethernet_put["LinkPolicy"] == [1, 14]

    def test_an_unrecognised_raw_value_renders_unknown_with_its_integer(self):
        # Never a bare "unknown": 0 is not a member of this enum, so collapsing an
        # unnamed value onto the word alone would discard the only evidence there is.
        assert network.link_policy_names([1, 99]) == ["s0_ac", "unknown(99)"]


class TestAddressValidation:
    @pytest.mark.parametrize("value", ["192.0.2.1", "0.0.0.0", "255.255.255.255", "10.0.0.7"])
    def test_valid_dotted_quads_are_accepted(self, value):
        assert network.is_ipv4(value)

    @pytest.mark.parametrize(
        "value",
        [
            "192.0.2.010",  # leading zero: octal to some resolvers, decimal to others
            "192.0.2",
            "192.0.2.1.5",
            "192.0.2.256",
            "192.0.2.-1",
            "192.0.2.x",
            "",
            "  ",
            "example.invalid",
        ],
    )
    def test_invalid_forms_are_rejected(self, value):
        assert not network.is_ipv4(value)

    @pytest.mark.parametrize("mask", ["0.0.0.0", "128.0.0.0", "255.255.255.0", "255.255.255.252", "255.255.255.255"])
    def test_contiguous_masks_are_accepted(self, mask):
        assert network.is_contiguous_netmask(mask)

    @pytest.mark.parametrize("mask", ["255.255.0.255", "255.0.255.0", "0.255.255.255", "254.255.255.0"])
    def test_masks_with_a_hole_are_rejected(self, mask):
        assert not network.is_contiguous_netmask(mask)

    def test_same_subnet(self):
        assert network.same_subnet("192.0.2.10", "192.0.2.1", "255.255.255.0")
        assert not network.same_subnet("192.0.2.10", "198.51.100.1", "255.255.255.0")

    def test_same_subnet_is_false_rather_than_raising_on_junk(self):
        # It feeds a warning, and a warning must never be the thing that fails a run.
        assert not network.same_subnet("nonsense", "192.0.2.1", "255.255.255.0")

    def test_a_malformed_address_is_refused_before_any_put(self):
        with pytest.raises(InvalidStateError) as excinfo:
            _plan(ip_address="192.0.2.010", allow_self_disconnect=True)
        assert excinfo.value.error_class == ErrorClass.INVALID_STATE
        assert "not a dotted-quad" in str(excinfo.value)

    def test_a_non_contiguous_mask_is_refused(self):
        with pytest.raises(InvalidStateError, match="not a contiguous netmask"):
            _plan(subnet_mask="255.255.0.255", allow_self_disconnect=True)

    def test_a_static_configuration_with_no_address_anywhere_is_refused(self):
        instance = _ethernet_instance(DHCPEnabled="true", IPAddress="", SubnetMask="")
        with pytest.raises(InvalidStateError) as excinfo:
            network.plan_network_change(
                ethernet_instance=instance,
                general_instance=_general_instance(),
                options=_options(dhcp_enabled=False),
                host=HOST,
                allow_self_disconnect=True,
            )
        assert "needs IPAddress" in str(excinfo.value)

    def test_a_static_configuration_supplying_the_missing_address_is_allowed(self):
        # The negative control for the test above: the refusal is about the *end
        # state* lacking an address, not about dhcp_enabled=false being suspicious.
        instance = _ethernet_instance(DHCPEnabled="true", IPAddress="", SubnetMask="")
        plan = network.plan_network_change(
            ethernet_instance=instance,
            general_instance=_general_instance(),
            options=_options(dhcp_enabled=False, ip_address="198.51.100.7", subnet_mask="255.255.255.0"),
            host=HOST,
            allow_self_disconnect=True,
        )
        assert plan.ethernet_put["IPAddress"] == "198.51.100.7"

    def test_an_off_link_gateway_warns_and_does_not_refuse(self):
        plan = _plan(default_gateway="198.51.100.1", allow_self_disconnect=True)
        assert plan.changed
        assert len(plan.warnings) == 1
        assert "not on the same subnet" in plan.warnings[0]

    def test_an_on_link_gateway_produces_no_warning(self):
        plan = _plan(default_gateway="192.0.2.254", allow_self_disconnect=True)
        assert plan.warnings == ()

    def test_the_all_zeroes_gateway_sentinel_does_not_warn(self):
        instance = _ethernet_instance(DefaultGateway="0.0.0.0")
        plan = network.plan_network_change(
            ethernet_instance=instance,
            general_instance=_general_instance(),
            options=_options(primary_dns="192.0.2.9"),
            host=HOST,
        )
        assert plan.warnings == ()


class TestPutBodyConstruction:
    def test_read_only_properties_are_deleted(self):
        body = network.build_ethernet_put_properties(_ethernet_instance(), {"PrimaryDNS": "192.0.2.9"})
        for name in network.ETHERNET_READ_ONLY_FIELDS:
            assert name not in body, f"{name} is read-only per the vendor request struct and must not be echoed back"

    def test_the_read_only_list_is_exactly_the_vendor_diff(self):
        # SettingsResponse minus SettingsRequest in
        # go-wsman-messages pkg/wsman/amt/ethernetport/types.go. Spelled out so a
        # future edit that widens or narrows it has to argue with this list.
        assert set(network.ETHERNET_READ_ONLY_FIELDS) == {"MACAddress", "LinkControl", "SharedDynamicIP", "WLANLinkProtectionLevel"}

    def test_settable_properties_meshcmd_happens_to_delete_are_kept(self):
        # MeshCmd deletes SharedMAC/SharedStaticIp/LinkIsUp/LinkPolicy/IpSyncEnabled
        # for its own convenience. The vendor request struct lists all five as
        # settable, and LinkPolicy is a property this module exists to write.
        body = network.build_ethernet_put_properties(_ethernet_instance(), {})
        for name in ("SharedMAC", "SharedStaticIp", "LinkIsUp", "IpSyncEnabled", "LinkPolicy"):
            assert name in body

    def test_switching_to_dhcp_drops_the_static_addressing(self):
        body = network.build_ethernet_put_properties(_ethernet_instance(), {"DHCPEnabled": True})
        assert body["DHCPEnabled"] is True
        for name in network.ETHERNET_STATIC_ADDRESS_FIELDS:
            assert name not in body, f"{name} must not accompany DHCPEnabled=true (firmware: settable in static mode only)"

    def test_staying_static_keeps_the_static_addressing(self):
        body = network.build_ethernet_put_properties(_ethernet_instance(), {"PrimaryDNS": "192.0.2.9"})
        assert body["IPAddress"] == "192.0.2.10"
        assert body["PrimaryDNS"] == "192.0.2.9"

    def test_the_dhcp_drop_keys_off_the_value_being_written_not_the_one_read(self):
        # The instance reads DHCPEnabled=true; the write turns it off. If the drop
        # were decided before the merge it would strip the very address being set.
        instance = _ethernet_instance(DHCPEnabled="true")
        body = network.build_ethernet_put_properties(instance, {"DHCPEnabled": False, "IPAddress": "198.51.100.7", "SubnetMask": "255.255.255.0"})
        assert body["IPAddress"] == "198.51.100.7"

    def test_a_missing_required_property_is_refused_rather_than_written(self):
        instance = _ethernet_instance()
        del instance["DHCPEnabled"]
        with pytest.raises(InvalidStateError) as excinfo:
            network.build_ethernet_put_properties(instance, {})
        assert "DHCPEnabled" in str(excinfo.value)
        assert "required for the Put command" in str(excinfo.value)

    def test_general_read_only_properties_are_deleted(self):
        body = network.build_general_put_properties(_general_instance(), {"HostName": "renamed"})
        for name in network.GENERAL_READ_ONLY_FIELDS:
            assert name not in body
        assert body["HostName"] == "renamed"

    def test_general_required_properties_survive(self):
        body = network.build_general_put_properties(_general_instance(), {"HostName": "renamed"})
        for name in network.GENERAL_REQUIRED_FOR_PUT:
            assert name in body

    def test_a_general_instance_missing_wsman_only_mode_is_refused(self):
        # WsmanOnlyMode is required for the Put and is a property this module never
        # sets -- it only ever passes it through. If it is not there to pass
        # through, the Put must not be attempted.
        instance = _general_instance()
        del instance["WsmanOnlyMode"]
        with pytest.raises(InvalidStateError, match="WsmanOnlyMode"):
            network.build_general_put_properties(instance, {"HostName": "renamed"})


class TestPlanning:
    def test_a_no_op_call_is_refused_rather_than_reported_converged(self):
        with pytest.raises(InvalidStateError) as excinfo:
            _plan()
        assert "no setting to apply" in str(excinfo.value)

    def test_an_absent_ethernet_port_is_unsupported_capability(self):
        with pytest.raises(UnsupportedCapabilityError) as excinfo:
            _plan(ethernet_instance={}, ping_response_enabled=False)
        assert excinfo.value.error_class == ErrorClass.UNSUPPORTED_CAPABILITY

    def test_an_absent_general_settings_class_blocks_the_whole_call(self):
        # Not a partial application: a call that asked for both classes and wrote
        # only one leaves the endpoint in a state the caller did not describe.
        with pytest.raises(UnsupportedCapabilityError):
            _plan(general_instance={}, hostname="renamed")

    def test_a_value_already_set_reports_no_change_despite_arriving_as_a_string(self):
        # Firmware sends "true"; the option is the bool True. Comparing those
        # naively is the classic always-changed bug.
        plan = _plan(ping_response_enabled=True)
        assert not plan.changed
        assert plan.general_put is None

    def test_a_link_policy_already_set_in_a_different_order_reports_no_change(self):
        plan = _plan(link_policy=["s0_dc", "sx_ac", "s0_ac"])
        assert not plan.changed

    def test_only_the_class_with_a_change_gets_a_put_body(self):
        plan = _plan(hostname="renamed")
        assert plan.general_put is not None
        assert plan.ethernet_put is None

    def test_a_change_records_both_readings(self):
        plan = _plan(ping_response_enabled=False)
        (change,) = plan.changes
        assert change.resource_class == "AMT_GeneralSettings"
        assert change.property_name == "PingResponseEnabled"
        assert change.previous is True
        assert change.desired is False

    def test_a_link_policy_change_reports_raw_integers_beside_their_names(self):
        plan = _plan(link_policy=["s0_ac", "sx_ac"])
        (change,) = plan.changes
        assert change.previous == {"values": [1, 14, 16], "names": ["s0_ac", "sx_ac", "s0_dc"]}
        assert change.desired == {"values": [1, 14], "names": ["s0_ac", "sx_ac"]}

    def test_dns_only_changes_are_not_addressing_changes(self):
        plan = _plan(primary_dns="192.0.2.9", secondary_dns="192.0.2.8")
        assert plan.changed
        assert plan.addressing_change is False


class TestSelfDisconnectGate:
    @pytest.mark.parametrize(
        ("option", "value"),
        [
            ("ip_address", "198.51.100.7"),
            ("subnet_mask", "255.255.0.0"),
            ("default_gateway", "192.0.2.254"),
            ("dhcp_enabled", True),
        ],
    )
    def test_each_addressing_option_is_refused_without_the_acknowledgement(self, option, value):
        with pytest.raises(InvalidStateError) as excinfo:
            _plan(**{option: value})
        assert excinfo.value.error_class == ErrorClass.INVALID_STATE
        assert "allow_self_disconnect" in str(excinfo.value)

    @pytest.mark.parametrize(
        ("option", "value"),
        [
            ("ip_address", "198.51.100.7"),
            ("subnet_mask", "255.255.0.0"),
            ("default_gateway", "192.0.2.254"),
            ("dhcp_enabled", True),
        ],
    )
    def test_each_addressing_option_proceeds_with_it(self, option, value):
        plan = _plan(allow_self_disconnect=True, **{option: value})
        assert plan.changed
        assert plan.addressing_change is True

    @pytest.mark.parametrize("option", ["primary_dns", "secondary_dns", "ping_response_enabled", "rmcp_ping_response_enabled", "hostname", "domain_name"])
    def test_the_ungated_options_need_no_acknowledgement(self, option):
        # The negative control on the gate. A gate that fired for these would be
        # set routinely, which is the same as not having one.
        value = False if option.endswith("_enabled") else "192.0.2.9" if option.endswith("_dns") else "changed"
        plan = _plan(**{option: value})
        assert plan.changed
        assert plan.addressing_change is False

    def test_a_no_op_addressing_option_does_not_trip_the_gate(self):
        # ip_address supplied but equal to what firmware already reports: nothing
        # moves, so nothing can disconnect, so no acknowledgement is demanded.
        plan = _plan(ip_address="192.0.2.10", hostname="renamed")
        assert plan.addressing_change is False
        assert plan.changed

    def test_the_message_names_the_properties_it_refused(self):
        with pytest.raises(InvalidStateError) as excinfo:
            _plan(ip_address="198.51.100.7", default_gateway="198.51.100.1")
        message = str(excinfo.value)
        assert "DefaultGateway" in message
        assert "IPAddress" in message

    def test_connected_through_managed_address_is_true_when_host_is_the_reported_ip(self):
        plan = _plan(host="192.0.2.10", hostname="renamed")
        assert plan.connected_through_managed_address is True

    def test_it_is_false_when_host_is_a_different_literal(self):
        plan = _plan(host="198.51.100.5", hostname="renamed")
        assert plan.connected_through_managed_address is False

    def test_it_is_none_for_a_hostname_rather_than_guessing(self):
        # A third state, not a synonym for false: this module does not resolve
        # names, so it genuinely does not know.
        plan = _plan(host="amt-lab-01.example.invalid", hostname="renamed")
        assert plan.connected_through_managed_address is None

    def test_the_gate_does_not_depend_on_that_evidence(self):
        # Even when host is demonstrably NOT the managed address, the change is
        # still gated: instance 0 is the port AMT answers on, so the module has no
        # basis for believing a second path exists.
        with pytest.raises(InvalidStateError, match="allow_self_disconnect"):
            _plan(host="198.51.100.5", ip_address="198.51.100.7")


class TestWakeCapabilityGate:
    def test_dropping_the_last_sx_value_is_refused(self):
        with pytest.raises(InvalidStateError) as excinfo:
            _plan(link_policy=["s0_ac", "s0_dc"])
        assert "allow_wake_capability_loss" in str(excinfo.value)
        # Both readings named, with raw integers, so an operator can see what they
        # are giving up rather than a bare "unsafe".
        assert "sx_ac" in str(excinfo.value)
        assert "224" in str(excinfo.value)

    def test_it_proceeds_with_the_acknowledgement(self):
        plan = _plan(link_policy=["s0_ac", "s0_dc"], allow_wake_capability_loss=True)
        assert plan.wake_capability_loss is True
        assert plan.ethernet_put["LinkPolicy"] == [1, 16]

    def test_keeping_an_sx_value_needs_no_acknowledgement(self):
        plan = _plan(link_policy=["s0_ac", "sx_dc"])
        assert plan.changed
        assert plan.wake_capability_loss is False

    def test_adding_an_sx_value_to_a_policy_that_had_none_is_not_a_loss(self):
        instance = _ethernet_instance(LinkPolicy=["1", "16"])
        plan = network.plan_network_change(
            ethernet_instance=instance,
            general_instance=_general_instance(),
            options=_options(link_policy=["s0_ac", "s0_dc", "sx_ac"]),
            host=HOST,
        )
        assert plan.wake_capability_loss is False

    def test_a_policy_that_never_had_an_sx_value_can_be_changed_without_the_gate(self):
        # "Loss" means losing something that was there. An endpoint already
        # S0-only is not made worse by another S0-only policy, and demanding an
        # acknowledgement for it would be the gate crying wolf.
        instance = _ethernet_instance(LinkPolicy=["1"])
        plan = network.plan_network_change(
            ethernet_instance=instance,
            general_instance=_general_instance(),
            options=_options(link_policy=["s0_ac", "s0_dc"]),
            host=HOST,
        )
        assert plan.wake_capability_loss is False
        assert plan.changed

    def test_the_self_disconnect_acknowledgement_does_not_unlock_this_one(self):
        # The two hazards differ in kind and each has its own flag; one must not
        # stand in for the other.
        with pytest.raises(InvalidStateError, match="allow_wake_capability_loss"):
            _plan(link_policy=["s0_ac", "s0_dc"], allow_self_disconnect=True)


def _fake_client() -> Mock:
    client = Mock()
    client.endpoint = f"{HOST}:16992"
    client.last_peer_certificate = None
    return client


class TestApply:
    def test_check_mode_issues_no_put_and_no_confirming_read(self):
        plan = _plan(hostname="renamed")
        client = _fake_client()
        result = network.apply_network_change(client, plan, check_mode=True)
        assert client.put.call_count == 0
        assert client.get.call_count == 0
        assert result.written_classes == ()
        assert result.indeterminate is False

    def test_an_already_converged_plan_issues_nothing(self):
        plan = _plan(ping_response_enabled=True)
        client = _fake_client()
        result = network.apply_network_change(client, plan)
        assert client.put.call_count == 0
        assert not result.plan.changed

    def test_general_settings_is_written_before_the_ethernet_port(self):
        # The ethernet Put is the one that can end the connection. Writing it last
        # means a self-disconnecting change does not also lose the hostname change
        # requested in the same task.
        plan = _plan(hostname="renamed", ip_address="198.51.100.7", allow_self_disconnect=True)
        client = _fake_client()
        client.get.side_effect = [_general_instance(HostName="renamed"), _ethernet_instance(IPAddress="198.51.100.7")]
        result = network.apply_network_change(client, plan)
        assert [call.args[0] for call in client.put.call_args_list] == ["AMT_GeneralSettings", "AMT_EthernetPortSettings"]
        assert result.written_classes == ("AMT_GeneralSettings", "AMT_EthernetPortSettings")

    def test_the_ethernet_put_carries_the_instance_selector_and_general_does_not(self):
        plan = _plan(hostname="renamed", primary_dns="192.0.2.9")
        client = _fake_client()
        client.get.side_effect = [_general_instance(HostName="renamed"), _ethernet_instance(PrimaryDNS="192.0.2.9")]
        network.apply_network_change(client, plan)
        by_class = {call.args[0]: call.kwargs["selectors"] for call in client.put.call_args_list}
        assert by_class["AMT_EthernetPortSettings"] == network.ETHERNET_PORT_0_SELECTOR
        assert by_class["AMT_GeneralSettings"] is None

    def test_a_confirmed_write_is_not_indeterminate_and_has_nothing_unapplied(self):
        plan = _plan(ping_response_enabled=False)
        client = _fake_client()
        client.get.return_value = _general_instance(PingResponseEnabled="false")
        result = network.apply_network_change(client, plan)
        assert result.indeterminate is False
        assert result.unapplied == ()
        assert result.general_observed is not None

    def test_a_failed_confirming_read_is_indeterminate(self):
        plan = _plan(ip_address="198.51.100.7", allow_self_disconnect=True)
        client = _fake_client()
        client.get.side_effect = ConnectionError_("connection refused", endpoint=f"{HOST}:16992")
        result = network.apply_network_change(client, plan)
        assert result.indeterminate is True
        assert result.ethernet_observed is None

    def test_the_indeterminate_error_keeps_the_original_classification(self):
        # Coercing everything to TimeoutError_ would misclassify the most likely
        # case: the endpoint refusing connections at the old address.
        plan = _plan(ip_address="198.51.100.7", allow_self_disconnect=True)
        client = _fake_client()
        client.get.side_effect = ConnectionError_("connection refused", endpoint=f"{HOST}:16992")
        result = network.apply_network_change(client, plan)
        err = network.indeterminate_error(result, endpoint=f"{HOST}:16992")
        assert isinstance(err, ConnectionError_)
        assert err.error_class == ErrorClass.CONNECTION
        assert err.to_result()["indeterminate"] is True
        assert "re-probe" in str(err).lower()

    def test_a_timeout_stays_a_timeout(self):
        plan = _plan(ip_address="198.51.100.7", allow_self_disconnect=True)
        client = _fake_client()
        client.get.side_effect = TimeoutError_("no reply", endpoint=f"{HOST}:16992", indeterminate=True)
        result = network.apply_network_change(client, plan)
        err = network.indeterminate_error(result, endpoint=f"{HOST}:16992")
        assert err.error_class == ErrorClass.TIMEOUT

    def test_indeterminate_error_refuses_to_be_built_from_a_confirmed_result(self):
        plan = _plan(ping_response_enabled=False)
        client = _fake_client()
        client.get.return_value = _general_instance(PingResponseEnabled="false")
        result = network.apply_network_change(client, plan)
        with pytest.raises(ValueError, match="nothing indeterminate"):
            network.indeterminate_error(result, endpoint=f"{HOST}:16992")

    def test_a_put_firmware_accepted_and_ignored_is_reported_unapplied(self):
        plan = _plan(ping_response_enabled=False)
        client = _fake_client()
        # The confirming read succeeds and reports the OLD value.
        client.get.return_value = _general_instance(PingResponseEnabled="true")
        result = network.apply_network_change(client, plan)
        assert result.indeterminate is False, "a successful read is a verdict, not an absence of one"
        (unapplied,) = result.unapplied
        assert unapplied.property_name == "PingResponseEnabled"

    def test_the_unapplied_error_is_unsupported_capability_and_not_indeterminate(self):
        plan = _plan(ping_response_enabled=False)
        client = _fake_client()
        client.get.return_value = _general_instance(PingResponseEnabled="true")
        result = network.apply_network_change(client, plan)
        err = network.unapplied_error(result, endpoint=f"{HOST}:16992")
        assert err.error_class == ErrorClass.UNSUPPORTED_CAPABILITY
        assert "indeterminate" not in err.to_result()
        assert "PingResponseEnabled" in str(err)

    def test_a_class_with_no_observation_contributes_nothing_to_unapplied(self):
        # "We could not look" and "we looked and it had not changed" are different
        # findings; only the second is firmware refusing a write.
        plan = _plan(ping_response_enabled=False)
        client = _fake_client()
        client.get.side_effect = ConnectionError_("gone", endpoint=f"{HOST}:16992")
        result = network.apply_network_change(client, plan)
        assert result.unapplied == ()
        assert result.indeterminate is True

    def test_a_put_error_propagates_unwrapped(self):
        plan = _plan(hostname="renamed")
        client = _fake_client()
        client.put.side_effect = TimeoutError_("timed out after the request was sent", endpoint=f"{HOST}:16992", indeterminate=True)
        with pytest.raises(TimeoutError_) as excinfo:
            network.apply_network_change(client, plan)
        # The transport already classified this correctly, including indeterminate.
        assert excinfo.value.indeterminate is True


class TestReadAndDecode:
    def test_read_uses_the_selector_asymmetry_the_vendor_uses(self):
        client = _fake_client()
        client.get.side_effect = [_ethernet_instance(), _general_instance()]
        network.read_network_state(client)
        calls = {call.args[0]: call.kwargs["selectors"] for call in client.get.call_args_list}
        assert calls["AMT_EthernetPortSettings"] == network.ETHERNET_PORT_0_SELECTOR
        assert calls["AMT_GeneralSettings"] is None

    def test_read_does_not_tolerate_a_failure_the_way_facts_gathering_does(self):
        # A mutation must not proceed on a class it could not read: the Put body
        # *is* the read instance with edits applied.
        client = _fake_client()
        client.get.side_effect = UnsupportedCapabilityError("no such class")
        with pytest.raises(UnsupportedCapabilityError):
            network.read_network_state(client)

    def test_decode_reuses_the_reader_amt_info_publishes(self):
        decoded = network.decode_ethernet(_ethernet_instance())
        assert decoded["mac_address"] == "00:00:5e:00:53:01", "normalized, as amt_info reports it"
        assert decoded["link_policy"] == [1, 14, 16]
        assert decoded["link_policy_names"] == ["s0_ac", "sx_ac", "s0_dc"]
        assert decoded["wake_on_lan_capable"] is True

    def test_decode_reports_wake_capability_false_for_an_s0_only_policy(self):
        decoded = network.decode_ethernet(_ethernet_instance(LinkPolicy=["1", "16"]))
        assert decoded["wake_on_lan_capable"] is False

    def test_decode_of_nothing_is_none(self):
        assert network.decode_ethernet({}) is None
        assert network.decode_general(None) is None

    def test_general_decode_surfaces_the_read_only_interface_flag(self):
        decoded = network.decode_general(_general_instance(NetworkInterfaceEnabled="false"))
        assert decoded["network_interface_enabled"] is False
        assert decoded["hostname"] == "mock-amt-host"
