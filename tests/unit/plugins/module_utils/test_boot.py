# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from unittest.mock import Mock, call

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils import boot
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    InvalidStateError,
    RemoteOperationError,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import EndpointReference

TOKEN = "test-action-token-not-a-secret"

_BOOT_CONFIG_SELECTOR = {"InstanceID": boot.BOOT_CONFIG_INSTANCE_ID}

#: A full-ish AMT_BootSettingData instance as read from firmware, including every field the
#: delete-list/zero-list care about, so tests can assert on their absence/mutation after Put.
_FULL_READ_INSTANCE: dict = {
    "InstanceID": "Intel(r) AMT: Boot Configuration Data",
    "ElementName": "Intel(r) AMT: Boot Configuration Data",
    "WinREBootEnabled": "true",
    "UEFILocalPBABootEnabled": "false",
    "UEFIHTTPSBootEnabled": "false",
    "SecureBootControlEnabled": "false",
    "BootguardStatus": "0",
    "OptionsCleared": "true",
    "BIOSLastStatus": "0,0",
    "UefiBootParametersArray": "",
    "UefiBootNumberOfParams": "3",
    "SecureErase": "false",
    "PlatformErase": "false",
    "UseIDER": "false",
    "UseSOL": "false",
}


def _capabilities(**overrides) -> dict:
    base = {
        "ForcePXEBoot": "true",
        "ForceHardDriveBoot": "true",
        "ForceCDorDVDBoot": "true",
        "BIOSSetup": "true",
        "IDER": "true",
        "SOL": "true",
    }
    base.update(overrides)
    return base


def _make_client(*, read_instance: dict | None = None, capabilities: dict | None = None, sources: list[dict] | None = None) -> Mock:
    """A WsmanClient double wired for the happy path: discovery finds exactly one match, every
    invoke() succeeds with ReturnValue==0 (the real invoke() raises on non-zero, so the mock just
    returns a benign tuple, and tests that want a failure override .invoke.side_effect directly).
    """
    client = Mock()
    client.enumerate.side_effect = lambda resource_class, **kwargs: (
        [capabilities if capabilities is not None else _capabilities()]
        if resource_class == "AMT_BootCapabilities"
        else (sources if sources is not None else _default_sources())
    )
    client.get.return_value = dict(read_instance if read_instance is not None else _FULL_READ_INSTANCE)
    client.invoke.return_value = ({"ReturnValue": "0"}, 0)
    client.put.return_value = {}
    return client


def _default_sources() -> list[dict]:
    return [
        {"InstanceID": "Intel(r) AMT: Force PXE Boot"},
        {"InstanceID": "Intel(r) AMT: Force Hard-drive Boot"},
        {"InstanceID": "Intel(r) AMT: Force CD/DVD Boot"},
    ]


class TestBuildBootPlan:
    @pytest.mark.parametrize(
        "target,expected_source,expected_use_ider,expected_ider_device,expected_bios_setup",
        [
            ("pxe", "Intel(r) AMT: Force PXE Boot", False, 0, False),
            ("hdd", "Intel(r) AMT: Force Hard-drive Boot", False, 0, False),
            ("cd", "Intel(r) AMT: Force CD/DVD Boot", False, 0, False),
            ("bios", None, False, 0, True),
            ("ider_floppy", None, True, 0, False),
            ("ider_cdrom", None, True, 1, False),
        ],
    )
    def test_each_target_produces_the_documented_combination(self, target, expected_source, expected_use_ider, expected_ider_device, expected_bios_setup):
        plan = boot.build_boot_plan(target)
        assert plan.boot_source_instance_id == expected_source
        assert plan.use_ider == expected_use_ider
        assert plan.ider_boot_device == expected_ider_device
        assert plan.bios_setup == expected_bios_setup

    def test_unknown_target_is_rejected(self):
        with pytest.raises(ValueError, match="unknown boot target"):
            boot.build_boot_plan("floppy")

    def test_pxe_and_ider_conflict_is_rejected(self):
        # Not reachable through build_boot_plan()'s fixed target table, but BootPlan itself must
        # refuse this combination unconditionally -- naming a native boot source in step 5 would
        # silently override IDE-R redirection on real firmware.
        with pytest.raises(InvalidStateError):
            boot.BootPlan(
                target="pxe+ider",
                boot_source_instance_id="Intel(r) AMT: Force PXE Boot",
                use_ider=True,
                ider_boot_device=0,
                bios_setup=False,
            )


class TestDiscoverAndValidate:
    def test_passes_when_capability_and_source_both_match(self):
        client = _make_client()
        boot.discover_and_validate(client, "pxe")  # must not raise

    def test_missing_capability_is_rejected_before_any_mutation(self):
        client = _make_client(capabilities=_capabilities(ForcePXEBoot="false"))
        with pytest.raises(UnsupportedCapabilityError):
            boot.discover_and_validate(client, "pxe")
        client.get.assert_not_called()
        client.put.assert_not_called()
        client.invoke.assert_not_called()

    def test_ambiguous_boot_source_is_rejected(self):
        client = _make_client(sources=[{"InstanceID": "Intel(r) AMT: Force PXE Boot"}, {"InstanceID": "Intel(r) AMT: Force PXE Boot"}])
        with pytest.raises(UnsupportedCapabilityError):
            boot.discover_and_validate(client, "pxe")

    def test_absent_boot_source_is_rejected(self):
        client = _make_client(sources=[])
        with pytest.raises(UnsupportedCapabilityError):
            boot.discover_and_validate(client, "hdd")

    def test_ambiguous_capabilities_instance_is_rejected(self):
        client = Mock()
        client.enumerate.return_value = [_capabilities(), _capabilities()]
        with pytest.raises(UnsupportedCapabilityError):
            boot.discover_and_validate(client, "pxe")

    def test_ider_target_never_enumerates_boot_source(self):
        # IDE-R targets have no CIM_BootSourceSetting to confirm; discovery must not even ask.
        client = _make_client()
        boot.discover_and_validate(client, "ider_floppy")
        assert all(c.args[0] != "CIM_BootSourceSetting" for c in client.enumerate.call_args_list)

    def test_bios_target_never_enumerates_boot_source(self):
        client = _make_client()
        boot.discover_and_validate(client, "bios")
        assert all(c.args[0] != "CIM_BootSourceSetting" for c in client.enumerate.call_args_list)


class TestArmOneTimeBootCallOrdering:
    """Ordering is the whole contract per protocol-notes.md s2.5. These assert the exact sequence
    of WS-Man calls, not merely that each happened."""

    def test_five_steps_run_in_exact_order_for_pxe(self):
        client = _make_client()

        result = boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)

        assert result.mutated is True

        # Discovery (2 enumerates) -> Get -> invoke(ChangeBootOrder, null) -> Put -> invoke(SetBootConfigRole)
        # -> invoke(ChangeBootOrder, EPR) -> Get.
        get_calls = [c.args[0] for c in client.get.call_args_list]
        assert get_calls == ["AMT_BootSettingData", "AMT_BootSettingData"]

        put_calls = client.put.call_args_list
        assert len(put_calls) == 1
        assert put_calls[0].args[0] == "AMT_BootSettingData"

        invoke_calls = client.invoke.call_args_list
        assert len(invoke_calls) == 3

        first_class, first_method = invoke_calls[0].args[0], invoke_calls[0].args[1]
        assert (first_class, first_method) == ("CIM_BootConfigSetting", "ChangeBootOrder")
        assert invoke_calls[0].args[2] == {"Source": None}
        assert invoke_calls[0].kwargs["selectors"] == _BOOT_CONFIG_SELECTOR

        second_class, second_method = invoke_calls[1].args[0], invoke_calls[1].args[1]
        assert (second_class, second_method) == ("CIM_BootService", "SetBootConfigRole")
        second_params = invoke_calls[1].args[2]
        assert second_params["Role"] == 1
        assert isinstance(second_params["BootConfigSetting"], EndpointReference)
        assert second_params["BootConfigSetting"].selectors == _BOOT_CONFIG_SELECTOR

        third_class, third_method = invoke_calls[2].args[0], invoke_calls[2].args[1]
        assert (third_class, third_method) == ("CIM_BootConfigSetting", "ChangeBootOrder")
        third_source = invoke_calls[2].args[2]["Source"]
        assert isinstance(third_source, EndpointReference)
        assert third_source.selectors == {"InstanceID": "Intel(r) AMT: Force PXE Boot"}
        assert invoke_calls[2].kwargs["selectors"] == _BOOT_CONFIG_SELECTOR

        # Absolute ordering across ALL mocked calls on the client, not just within one method type.
        assert client.mock_calls[0] == call.enumerate("AMT_BootCapabilities")
        method_sequence = [c[0] for c in client.mock_calls if c[0] in ("enumerate", "get", "invoke", "put")]
        assert method_sequence == ["enumerate", "enumerate", "get", "invoke", "put", "invoke", "invoke", "get"]

    def test_ider_floppy_passes_null_source_in_step_five(self):
        client = _make_client()
        boot.arm_one_time_boot(client, "ider_floppy", action_token=TOKEN)
        invoke_calls = client.invoke.call_args_list
        change_boot_order_calls = [c for c in invoke_calls if c.args[1] == "ChangeBootOrder"]
        assert len(change_boot_order_calls) == 2
        assert change_boot_order_calls[0].args[2] == {"Source": None}
        assert change_boot_order_calls[1].args[2] == {"Source": None}

    def test_put_body_never_includes_deleted_fields_and_zeroes_uefi_param_count(self):
        client = _make_client()
        boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)
        put_properties = client.put.call_args_list[0].args[1]
        for field_name in boot.DELETE_BEFORE_PUT_FIELDS:
            assert field_name not in put_properties
        assert put_properties["UefiBootNumberOfParams"] == 0

    @pytest.mark.parametrize("field_name", boot.OPTIONAL_ERASE_FIELDS)
    def test_erase_fields_set_false_only_when_present_in_read_instance(self, field_name):
        with_field = _make_client(read_instance={**_FULL_READ_INSTANCE, field_name: "true"})
        boot.arm_one_time_boot(with_field, "pxe", action_token=TOKEN)
        assert with_field.put.call_args_list[0].args[1][field_name] is False

        without_field = _make_client(read_instance={k: v for k, v in _FULL_READ_INSTANCE.items() if k not in boot.OPTIONAL_ERASE_FIELDS})
        boot.arm_one_time_boot(without_field, "pxe", action_token=TOKEN)
        assert field_name not in without_field.put.call_args_list[0].args[1]


class TestArmOneTimeBootTargets:
    @pytest.mark.parametrize(
        "target,expected_use_ider,expected_ider_device,expected_source",
        [
            ("pxe", False, 0, "Intel(r) AMT: Force PXE Boot"),
            ("hdd", False, 0, "Intel(r) AMT: Force Hard-drive Boot"),
            ("cd", False, 0, "Intel(r) AMT: Force CD/DVD Boot"),
            ("bios", False, 0, None),
            ("ider_floppy", True, 0, None),
            ("ider_cdrom", True, 1, None),
        ],
    )
    def test_put_body_and_epr_match_target(self, target, expected_use_ider, expected_ider_device, expected_source):
        client = _make_client()
        result = boot.arm_one_time_boot(client, target, action_token=TOKEN)

        put_properties = client.put.call_args_list[0].args[1]
        assert put_properties["UseIDER"] == expected_use_ider
        assert put_properties["UseSOL"] == expected_use_ider
        assert put_properties["IDERBootDevice"] == expected_ider_device

        final_change_boot_order = client.invoke.call_args_list[-1]
        source_param = final_change_boot_order.args[2]["Source"]
        if expected_source is None:
            assert source_param is None
        else:
            assert isinstance(source_param, EndpointReference)
            assert source_param.selectors == {"InstanceID": expected_source}

        assert result.boot_source_selector == ({"InstanceID": expected_source} if expected_source else None)


class TestUnsupportedCapabilityNeverMutates:
    def test_absent_capability_aborts_before_any_get_put_or_invoke(self):
        client = _make_client(capabilities=_capabilities(IDER="false"))
        with pytest.raises(UnsupportedCapabilityError):
            boot.arm_one_time_boot(client, "ider_floppy", action_token=TOKEN)
        client.get.assert_not_called()
        client.put.assert_not_called()
        client.invoke.assert_not_called()

    def test_ambiguous_boot_source_aborts_before_any_get_put_or_invoke(self):
        client = _make_client(sources=[])
        with pytest.raises(UnsupportedCapabilityError):
            boot.arm_one_time_boot(client, "cd", action_token=TOKEN)
        client.get.assert_not_called()
        client.put.assert_not_called()
        client.invoke.assert_not_called()


class TestNonZeroReturnValueAborts:
    def test_step_two_failure_aborts_before_put(self):
        client = _make_client()
        client.invoke.side_effect = RemoteOperationError("ChangeBootOrder rejected", return_value=2)
        with pytest.raises(RemoteOperationError):
            boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)
        client.put.assert_not_called()
        assert client.invoke.call_count == 1

    def test_step_four_failure_aborts_before_final_change_boot_order(self):
        client = _make_client()
        client.invoke.side_effect = [
            ({"ReturnValue": "0"}, 0),  # step 2 succeeds
            RemoteOperationError("SetBootConfigRole rejected", return_value=1),  # step 4 fails
        ]
        with pytest.raises(RemoteOperationError):
            boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)
        assert client.put.call_count == 1  # step 3 already ran
        assert client.invoke.call_count == 2  # never reached step 5

    def test_step_five_failure_still_surfaces_after_put_and_role_succeeded(self):
        client = _make_client()
        client.invoke.side_effect = [
            ({"ReturnValue": "0"}, 0),  # step 2
            ({"ReturnValue": "0"}, 0),  # step 4
            RemoteOperationError("ChangeBootOrder rejected", return_value=2),  # step 5
        ]
        with pytest.raises(RemoteOperationError):
            boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)
        assert client.put.call_count == 1
        assert client.invoke.call_count == 3
        # The final observed Get (step "6" in this module's numbering) never ran.
        assert client.get.call_count == 1


class TestCheckMode:
    def test_check_mode_performs_no_mutation(self):
        client = _make_client()
        result = boot.arm_one_time_boot(client, "pxe", action_token=TOKEN, check_mode=True)
        assert result.mutated is False
        client.put.assert_not_called()
        client.invoke.assert_not_called()
        assert result.observed == result.previous

    def test_check_mode_still_runs_discovery_and_reports_the_intended_put_body(self):
        client = _make_client()
        result = boot.arm_one_time_boot(client, "hdd", action_token=TOKEN, check_mode=True)
        assert client.enumerate.call_count == 2
        assert client.get.call_count == 1
        assert result.put_properties["UseIDER"] is False

    def test_check_mode_still_requires_a_capability_match(self):
        client = _make_client(capabilities=_capabilities(ForceHardDriveBoot="false"))
        with pytest.raises(UnsupportedCapabilityError):
            boot.arm_one_time_boot(client, "hdd", action_token=TOKEN, check_mode=True)


class TestActionTokenRequired:
    @pytest.mark.parametrize("token", [None, ""])
    def test_missing_or_empty_token_refuses_to_arm(self, token):
        client = _make_client()
        with pytest.raises(InvalidStateError):
            boot.arm_one_time_boot(client, "pxe", action_token=token)
        client.enumerate.assert_not_called()
        client.get.assert_not_called()
        client.put.assert_not_called()
        client.invoke.assert_not_called()

    def test_missing_token_is_refused_even_in_check_mode(self):
        # No auto re-arm, no implicit arming -- not even a preview should skip the gate.
        client = _make_client()
        with pytest.raises(InvalidStateError):
            boot.arm_one_time_boot(client, "pxe", action_token=None, check_mode=True)
        client.get.assert_not_called()

    def test_no_automatic_rearm_between_separate_calls(self):
        # Each call to arm_one_time_boot is independent -- calling it once with a token does not
        # let a later call omit one. There is no persisted "already armed" state in this module.
        client = _make_client()
        boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)
        with pytest.raises(InvalidStateError):
            boot.arm_one_time_boot(client, "pxe", action_token=None)


class TestNoCredentialLeakage:
    def test_receipt_inputs_contain_no_secret_shaped_values(self):
        client = _make_client()
        result = boot.arm_one_time_boot(client, "pxe", action_token=TOKEN)
        # The action_token itself is not a credential, but confirm it is not echoed into anything
        # that becomes part of the receipt -- these dataclasses only ever carry AMT properties.
        assert TOKEN not in repr(result.put_properties)
        assert TOKEN not in repr(result.previous)
        assert TOKEN not in repr(result.observed)
