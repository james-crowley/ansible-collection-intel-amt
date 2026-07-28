# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import dataclasses

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    RECEIPT_SCHEMA,
    AmtFacts,
    BootConfiguration,
    CallerSuppliedIdentity,
    OperationReceipt,
    PowerState,
    RedirectionState,
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
