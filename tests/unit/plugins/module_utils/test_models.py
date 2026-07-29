# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import dataclasses
from typing import ClassVar

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    LINK_POLICY_S0_AC,
    LINK_POLICY_S0_DC,
    LINK_POLICY_SX_AC,
    LINK_POLICY_SX_DC,
    RECEIPT_SCHEMA,
    AmtFacts,
    BootConfiguration,
    CallerSuppliedIdentity,
    EthernetSettings,
    OperationReceipt,
    PowerState,
    RedirectionState,
    SystemState,
    optional_bool,
    optional_int,
    optional_str,
    truthy,
)

SECRET = "Sup3rSecret!"


class TestPowerState:
    # The full docs/protocol-notes.md s2.4 table. Getting any one of these
    # wrong means a module reports the wrong power state to a playbook that
    # may be deciding whether it is safe to, say, force a reboot.
    @pytest.mark.parametrize(
        "cim_value,expected",
        [
            (2, "on"),  # On
            (3, "sleep"),  # Sleep - Light
            (4, "sleep"),  # Sleep - Deep
            (5, "on"),  # Power Cycle (soft) -- ends powered on
            (6, "off"),  # Off - Hard
            (7, "hibernate"),  # Hibernate
            (8, "off"),  # Off - Soft
            (9, "off"),  # Power Cycle (off-hard) -- ends powered off
            (13, "off"),  # Off - Hard Graceful
        ],
    )
    def test_known_cim_values(self, cim_value, expected):
        state = PowerState.from_cim_value(cim_value)
        assert state.normalized == expected
        assert state.raw == cim_value

    def test_numeric_string_input_is_accepted(self):
        # WS-Man responses hand back element text, i.e. always a string.
        assert PowerState.from_cim_value("6").normalized == "off"

    @pytest.mark.parametrize("cim_value", [0, 1, 10, 11, 12, 999])
    def test_unrecognised_numeric_value_is_unknown_but_raw_is_kept(self, cim_value):
        state = PowerState.from_cim_value(cim_value)
        assert state.normalized == "unknown"
        # The raw value must survive -- a forward-compatibility gap in the
        # table must not turn into silently discarded evidence.
        assert state.raw == cim_value

    def test_non_numeric_value_degrades_to_unknown_without_raising(self):
        state = PowerState.from_cim_value("not-a-number")
        assert state.normalized == "unknown"


class TestWsmanValueCoercion:
    @pytest.mark.parametrize("value,expected", [("true", True), ("false", False), ("1", True), ("0", False), (True, True), (False, False), (None, False)])
    def test_wsman_boolean_text_is_interpreted(self, value, expected):
        assert truthy(value) is expected

    @pytest.mark.parametrize("value,expected", [("true", True), ("false", False), (True, True), (False, False)])
    def test_optional_bool_reports_what_firmware_said(self, value, expected):
        assert optional_bool(value) is expected

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_optional_bool_keeps_absent_distinct_from_false(self, value):
        # "This firmware does not implement the property" and "the feature is
        # switched off" are different findings. Collapsing them would have an
        # operator acting on an invention.
        assert optional_bool(value) is None

    @pytest.mark.parametrize("value,expected", [("1", 1), (" 42 ", 42), (0, 0), ("-3", -3)])
    def test_optional_int_parses_element_text(self, value, expected):
        assert optional_int(value) == expected

    @pytest.mark.parametrize("value", [None, "", "not-a-number", True, False, {}, []])
    def test_optional_int_degrades_to_none_rather_than_raising(self, value):
        assert optional_int(value) is None

    @pytest.mark.parametrize("value,expected", [("x", "x"), ("  padded  ", "padded"), (7, "7")])
    def test_optional_str_strips_and_stringifies(self, value, expected):
        assert optional_str(value) == expected

    @pytest.mark.parametrize("value", [None, "", "   ", {}, []])
    def test_optional_str_degrades_to_none(self, value):
        assert optional_str(value) is None


class TestEthernetSettings:
    """``AMT_EthernetPortSettings`` instance 0, per docs/protocol-notes.md §2.7."""

    #: Obviously-fake throughout: the MAC is from the RFC 7042 documentation
    #: range and the addresses are RFC 5737 TEST-NET-1. Never put a real lab's
    #: MAC, hostname or IP in this repository.
    FULL_INSTANCE: ClassVar[dict[str, object]] = {
        "MACAddress": "00-00-5E-00-53-01",
        "IPAddress": "192.0.2.10",
        "SubnetMask": "255.255.255.0",
        "DefaultGateway": "192.0.2.1",
        "PrimaryDNS": "192.0.2.2",
        "SecondaryDNS": "192.0.2.3",
        "DHCPEnabled": "false",
        "LinkIsUp": "true",
        "IpSyncEnabled": "false",
        "LinkPolicy": ["1", "14", "16"],
    }

    def test_every_field_is_parsed(self):
        settings = EthernetSettings.from_instance(self.FULL_INSTANCE)
        assert settings.ip_address == "192.0.2.10"
        assert settings.subnet_mask == "255.255.255.0"
        assert settings.default_gateway == "192.0.2.1"
        assert settings.primary_dns == "192.0.2.2"
        assert settings.secondary_dns == "192.0.2.3"
        assert settings.dhcp_enabled is False
        assert settings.link_is_up is True
        assert settings.ip_sync_enabled is False

    @pytest.mark.parametrize(
        "reported",
        [
            "00-00-5E-00-53-01",  # what real AMT 10.0.56 firmware returned: dashes
            "00:00:5E:00:53:01",  # what parmstro's own RETURN sample claims: colons
            "00-00-5e-00-53-01",
            "00:00:5e:00:53:01",
            "00005E005301",  # bare hex, defensively supported
            "  00-00-5E-00-53-01  ",
        ],
    )
    def test_mac_is_normalized_from_every_separator_firmware_might_use(self, reported):
        # The MAC is a second identity anchor and the key a PXE reservation is made
        # against, so a stray separator or case difference must not make two
        # readings of the same machine compare unequal.
        settings = EthernetSettings.from_instance({"MACAddress": reported})
        assert settings.mac_address == "00:00:5e:00:53:01"

    def test_raw_mac_is_preserved_exactly_as_reported(self):
        settings = EthernetSettings.from_instance({"MACAddress": "00-00-5E-00-53-01"})
        assert settings.mac_address_raw == "00-00-5E-00-53-01"

    @pytest.mark.parametrize("weird", ["not-a-mac", "00-00-5E-00-53", "00-00-5E-00-53-01-02", "ZZ-00-5E-00-53-01"])
    def test_unexpected_mac_shapes_are_surfaced_verbatim_and_never_raise(self, weird):
        settings = EthernetSettings.from_instance({"MACAddress": weird})
        assert settings.mac_address == weird
        assert settings.mac_address_raw == weird

    def test_absent_mac_is_none_not_an_empty_string(self):
        settings = EthernetSettings.from_instance({})
        assert settings.mac_address is None
        assert settings.mac_address_raw is None

    def test_regression_link_policy_1_and_14_is_wake_capable(self):
        # REGRESSION GUARD for the inverted `wake_on_lan_capable` shipped in 0.2.0
        # and 0.3.0. Both lab machines report exactly `[1, 14]`. 14 is `Sx AC`
        # (link maintained while the host is asleep or off, on mains) per
        # go-wsman-messages `pkg/wsman/amt/ethernetport`; the old table called it
        # `s0_dc` and keyed the boolean off 16 as an invented "always on", so
        # every mains-powered desktop got `false` when the truth is `true`. The
        # MEBx screen on one of those machines reads "ON in S0, ME Wake in S3,
        # S4-5", which agrees with the corrected table and not with the old one.
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1", "14"]})
        assert settings.link_policy == [1, 14]
        assert settings.link_policy_names == ["s0_ac", "sx_ac"]
        assert settings.wake_on_lan_capable is True

    @pytest.mark.parametrize(
        ("value", "name"),
        [
            (LINK_POLICY_S0_AC, "s0_ac"),
            (LINK_POLICY_SX_AC, "sx_ac"),
            (LINK_POLICY_S0_DC, "s0_dc"),
            (LINK_POLICY_SX_DC, "sx_dc"),
        ],
    )
    def test_every_authoritative_link_policy_value_decodes_to_its_vendor_name(self, value, name):
        # The whole enum, exactly as go-wsman-messages defines it:
        # ValueMap={1, 14, 16, 224} / Values={available on S0 AC, available on
        # Sx AC, available on S0 DC, available on Sx DC}. Nothing else is named.
        settings = EthernetSettings.from_instance({"LinkPolicy": [str(value)]})
        assert settings.link_policy == [value]
        assert settings.link_policy_names == [name]

    def test_sx_dc_224_is_recognised_and_wake_capable(self):
        # 224 was missing from the table entirely, so a battery-powered endpoint
        # that does maintain its link while asleep decoded as `unknown(224)` and
        # reported `wake_on_lan_capable: false`.
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1", "224"]})
        assert settings.link_policy == [1, 224]
        assert settings.link_policy_names == ["s0_ac", "sx_dc"]
        assert settings.wake_on_lan_capable is True

    def test_wake_on_lan_is_false_when_only_s0_values_are_present(self):
        # S0 AC + S0 DC: the link is maintained on mains and on battery, but only
        # while the host is already running. Nothing here says the endpoint
        # answers WS-Man once it leaves S0, so `amt_power state=on` against it
        # may fail looking exactly like a network fault. 16 being present is
        # specifically *not* enough -- it used to be the whole test.
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1", "16"]})
        assert settings.link_policy == [1, 16]
        assert settings.link_policy_names == ["s0_ac", "s0_dc"]
        assert settings.wake_on_lan_capable is False

    def test_wake_on_lan_is_false_for_s0_ac_alone(self):
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1"]})
        assert settings.link_policy == [LINK_POLICY_S0_AC]
        assert settings.wake_on_lan_capable is False

    def test_link_policy_repeated_plain_elements(self):
        # The shape AMT's schema implies (LinkPolicy is a uint32 array).
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1", "14", "16"]})
        assert settings.link_policy == [1, 14, 16]
        assert settings.link_policy_names == ["s0_ac", "sx_ac", "s0_dc"]
        assert settings.wake_on_lan_capable is True

    def test_link_policy_nested_policy_value_elements(self):
        # The shape parmstro's own module code parses. Their hardware notes record
        # only the decoded result, so neither shape is ruled out by evidence and
        # both are accepted.
        settings = EthernetSettings.from_instance({"LinkPolicy": [{"PolicyValue": "1"}, {"PolicyValue": "14"}, {"PolicyValue": "16"}]})
        assert settings.link_policy == [1, 14, 16]
        assert settings.wake_on_lan_capable is True

    def test_link_policy_single_nested_wrapper_holding_several_values(self):
        settings = EthernetSettings.from_instance({"LinkPolicy": {"PolicyValue": ["1", "224"]}})
        assert settings.link_policy == [1, 224]
        assert settings.wake_on_lan_capable is True

    def test_link_policy_single_value_is_not_mistaken_for_a_character_sequence(self):
        settings = EthernetSettings.from_instance({"LinkPolicy": "14"})
        assert settings.link_policy == [LINK_POLICY_SX_AC]
        assert settings.wake_on_lan_capable is True

    def test_empty_link_policy_is_an_empty_list_and_not_wake_capable(self):
        settings = EthernetSettings.from_instance({"LinkPolicy": ""})
        assert settings.link_policy == []
        assert settings.link_policy_names == []
        assert settings.wake_on_lan_capable is False

    def test_missing_link_policy_is_unknown_not_false(self):
        # None, not False: "the firmware did not report a link policy" is not the
        # same diagnosis as "this link will not stay up while powered off".
        settings = EthernetSettings.from_instance({"MACAddress": "00-00-5E-00-53-01"})
        assert settings.link_policy is None
        assert settings.link_policy_names is None
        assert settings.wake_on_lan_capable is None

    def test_unrecognised_link_policy_value_is_kept_and_named_with_its_raw_value(self):
        settings = EthernetSettings.from_instance({"LinkPolicy": ["14", "99"]})
        assert settings.link_policy == [14, 99]
        assert settings.link_policy_names == ["sx_ac", "unknown(99)"]
        assert settings.wake_on_lan_capable is True

    @pytest.mark.parametrize("undefined", ["2", "15"])
    def test_values_absent_from_the_vendor_enum_are_passed_through_unnamed(self, undefined):
        # 2 and 15 came from parmstro's constants file as `sx_ac`/`sx_dc`. They
        # are not in Intel's enum, so they are no longer named -- but they are
        # still surfaced raw and rendered `unknown(<raw>)` rather than dropped.
        # Inventing a name for an undefined value is what caused this bug; the
        # fix is to stop naming them, not to stop reporting them.
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1", undefined]})
        assert settings.link_policy == [1, int(undefined)]
        assert settings.link_policy_names == ["s0_ac", f"unknown({undefined})"]
        assert settings.wake_on_lan_capable is False

    def test_non_numeric_link_policy_entries_are_dropped_rather_than_raising(self):
        settings = EthernetSettings.from_instance({"LinkPolicy": ["1", "junk", "16"]})
        assert settings.link_policy == [1, 16]

    def test_an_entirely_empty_instance_yields_all_none(self):
        settings = EthernetSettings.from_instance({})
        assert dataclasses.asdict(settings) == dict.fromkeys(dataclasses.asdict(settings))


class TestSystemState:
    """``CIM_ComputerSystem`` state decoding, per docs/protocol-notes.md §2.7."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, "unknown"),
            (1, "other"),
            (2, "enabled"),
            (3, "disabled"),
            (4, "shutting_down"),
            (5, "not_applicable"),
            (6, "enabled_but_offline"),
            (7, "in_test"),
            (8, "deferred"),
            (9, "quiesce"),
            (10, "starting"),
        ],
    )
    def test_every_dmtf_enabled_state_value(self, value, expected):
        state = SystemState.from_instance({"EnabledState": str(value)})
        assert state.enabled_state == value
        assert state.enabled_state_text == expected

    def test_unrecognised_enabled_state_is_distinguishable_from_the_defined_unknown(self):
        # 0 legitimately decodes to "unknown". A value outside the table must not
        # render identically to it.
        assert SystemState.from_instance({"EnabledState": "77"}).enabled_state_text == "unknown(77)"
        assert SystemState.from_instance({"EnabledState": "0"}).enabled_state_text == "unknown"

    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, "unknown"),
            (1, "other"),
            (2, "ok"),
            (3, "degraded"),
            (4, "stressed"),
            (5, "predictive_failure"),
            (6, "error"),
            (7, "non_recoverable_error"),
            (8, "starting"),
            (9, "stopping"),
            (10, "stopped"),
            (11, "in_service"),
            (12, "no_contact"),
            (13, "lost_communication"),
            (14, "aborted"),
            (15, "dormant"),
            (16, "supporting_entity_in_error"),
            (17, "completed"),
            (18, "power_mode"),
            (19, "relocating"),
        ],
    )
    def test_every_dmtf_operational_status_value(self, value, expected):
        state = SystemState.from_instance({"OperationalStatus": str(value)})
        assert state.operational_status == [value]
        assert state.operational_status_text == [expected]

    def test_operational_status_is_a_list_because_cim_types_it_as_an_array(self):
        # Firmware reporting several statuses is the normal case for a degraded
        # machine, and the ones after the first are exactly the interesting ones.
        state = SystemState.from_instance({"OperationalStatus": ["3", "5"]})
        assert state.operational_status == [3, 5]
        assert state.operational_status_text == ["degraded", "predictive_failure"]

    def test_element_name_is_read_and_the_selector_key_is_not(self):
        state = SystemState.from_instance({"ElementName": "ManagedSystem", "Name": "ManagedSystem"})
        assert state.element_name == "ManagedSystem"

    def test_requested_state_is_reported_raw_without_an_invented_table(self):
        state = SystemState.from_instance({"RequestedState": "12"})
        assert state.requested_state == 12
        assert not hasattr(state, "requested_state_text")

    def test_absent_properties_degrade_to_none(self):
        state = SystemState.from_instance({})
        assert state.element_name is None
        assert state.enabled_state is None
        assert state.enabled_state_text is None
        assert state.requested_state is None
        assert state.operational_status is None
        assert state.operational_status_text is None

    def test_non_numeric_values_do_not_raise(self):
        state = SystemState.from_instance({"EnabledState": "junk", "OperationalStatus": ["junk", "2"]})
        assert state.enabled_state is None
        assert state.operational_status == [2]


class TestCallerIdentitySeparation:
    def test_amt_facts_has_no_caller_supplied_fields(self):
        # Structural, not a comment: a hostname or MAC from inventory must be
        # impossible to store on AmtFacts, because AmtFacts is documented and
        # consumed as firmware-observed evidence only.
        field_names = {f.name for f in dataclasses.fields(AmtFacts)}
        assert "hostname" not in field_names
        assert "mac_address" not in field_names

    def test_caller_supplied_identity_is_its_own_type(self):
        identity = CallerSuppliedIdentity(hostname="esxi-07.example", mac_address="AA:BB:CC:DD:EE:FF")
        assert identity.hostname == "esxi-07.example"
        assert not dataclasses.is_dataclass(AmtFacts) or not isinstance(identity, AmtFacts)


class TestBootConfiguration:
    def test_defaults_match_protocol_notes_step_3(self):
        config = BootConfiguration()
        assert config.configuration_data_reset is False
        assert config.bios_pause is False
        assert config.enforce_secure_boot is False
        assert config.boot_media_index == 0
        assert config.firmware_verbosity == 0
        assert config.ider_boot_device == 0
        assert config.use_ider is False
        assert config.use_sol is False
        # Absent-vs-false is a meaningful distinction for these two fields --
        # newer firmware may not expose them at all.
        assert config.secure_erase is None
        assert config.platform_erase is None


class TestRedirectionState:
    @pytest.mark.parametrize(
        "enabled_state,ider,sol",
        [
            (32768, False, False),  # disabled
            (32769, True, False),  # IDER only
            (32770, False, True),  # SOL only
            (32771, True, True),  # both
        ],
    )
    def test_derived_flags_match_protocol_notes(self, enabled_state, ider, sol):
        state = RedirectionState.from_enabled_state(enabled_state, listener_enabled=True)
        assert state.ider_enabled is ider
        assert state.sol_enabled is sol
        assert state.enabled_state == enabled_state

    def test_unrecognised_state_keeps_raw_value_and_reports_both_disabled(self):
        state = RedirectionState.from_enabled_state(99999, listener_enabled=False)
        assert state.enabled_state == 99999
        assert state.ider_enabled is False
        assert state.sol_enabled is False


class TestOperationReceipt:
    def test_serializes_to_the_documented_schema(self):
        receipt = OperationReceipt(
            action="amt_power.set",
            endpoint="10.0.0.5:16993",
            changed=True,
            previous=PowerState.from_cim_value(8),
            desired=PowerState.from_cim_value(2),
            observed=PowerState.from_cim_value(2),
            tls_peer_fingerprint="aa" * 32,
            error_class=None,
        )
        document = receipt.to_dict()
        assert set(document) == {
            "schema",
            "action",
            "endpoint",
            "changed",
            "previous",
            "desired",
            "observed",
            "tls_peer_fingerprint",
            "error_class",
        }
        assert document["schema"] == RECEIPT_SCHEMA == "intel-amt-operation/v1"
        assert document["changed"] is True
        # Typed dataclass fields must come through as plain JSON-safe dicts.
        assert document["previous"] == {"normalized": "off", "raw": 8}
        assert document["desired"] == {"normalized": "on", "raw": 2}

    def test_plain_dict_and_none_payloads_pass_through(self):
        receipt = OperationReceipt(action="amt_info.gather", endpoint="10.0.0.5:16992", changed=False, observed={"version": "11.8.50"})
        document = receipt.to_dict()
        assert document["observed"] == {"version": "11.8.50"}
        assert document["previous"] is None
        assert document["desired"] is None

    def test_no_secret_survives_serialization_even_if_smuggled_into_a_payload(self):
        # OperationReceipt has no credential-shaped field by construction, but
        # to_dict() also runs every string through redact() as a backstop in
        # case a caller passes through something it should not have.
        receipt = OperationReceipt(
            action="amt_boot.set",
            endpoint="10.0.0.5:16993",
            changed=True,
            observed={"note": f"password={SECRET}"},
        )
        rendered = repr(receipt.to_dict())
        assert SECRET not in rendered
        assert "REDACTED" in rendered

    def test_extra_fields_are_merged_in(self):
        receipt = OperationReceipt(action="amt_media.attach", endpoint="10.0.0.5:16992", changed=True, extra={"bytes_written": 512})
        assert receipt.to_dict()["bytes_written"] == 512
