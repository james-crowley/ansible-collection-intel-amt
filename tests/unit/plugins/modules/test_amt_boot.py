# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from unittest.mock import Mock, patch

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_boot

BASE_ARGS = {
    "host": "10.0.0.5",
    "username": "admin",
    "password": "test-password-not-real",
    "use_tls": False,
    "allow_insecure_transport": True,
    "device": "pxe",
    "action_token": "test-action-token-not-a-secret",
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


def _capabilities() -> dict:
    return {"ForcePXEBoot": "true", "ForceHardDriveBoot": "true", "ForceCDorDVDBoot": "true", "BIOSSetup": "true", "IDER": "true", "SOL": "true"}


def _sources() -> list:
    return [
        {"InstanceID": "Intel(r) AMT: Force PXE Boot"},
        {"InstanceID": "Intel(r) AMT: Force Hard-drive Boot"},
        {"InstanceID": "Intel(r) AMT: Force CD/DVD Boot"},
    ]


def _make_fake_client() -> Mock:
    client = Mock()
    client.enumerate.side_effect = lambda resource_class, **kwargs: [_capabilities()] if resource_class == "AMT_BootCapabilities" else _sources()
    client.get.return_value = {"UseIDER": "false", "UseSOL": "false", "InstanceID": "Intel(r) AMT: Boot Configuration Data"}
    client.invoke.return_value = ({"ReturnValue": "0"}, 0)
    client.put.return_value = {}
    client.last_peer_certificate = None
    return client


@pytest.fixture(autouse=True)
def _patch_exit_and_fail(monkeypatch):
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", _fail_json)


class TestAmtBootModule:
    def test_successful_arm_reports_changed_true(self):
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_boot.main()
        result = excinfo.value.kwargs
        assert result["changed"] is True
        assert result["operation"]["action"] == "amt_boot"
        assert result["operation"]["schema"] == "intel-amt-operation/v1"
        assert result["operation"]["changed"] is True
        assert result["device"] == "pxe"
        fake_client.close.assert_called_once()

    def test_receipt_is_nested_under_operation_not_spread_at_top_level(self):
        # issue #22: the receipt lives under `operation` on every module, amt_boot included --
        # never spread at the top level alongside module-specific keys like `device`.
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_boot.main()
        result = excinfo.value.kwargs
        for moved_field in ("schema", "action", "endpoint", "previous", "desired", "observed", "tls_peer_fingerprint"):
            assert moved_field not in result, f"{moved_field!r} must not be spread at the top level; it belongs under operation"
        operation = result["operation"]
        assert operation["previous"] is not None
        assert operation["desired"] is not None
        assert operation["observed"] is not None
        assert operation["error_class"] is None

    def test_check_mode_performs_no_mutation(self):
        args = dict(BASE_ARGS, _ansible_check_mode=True)
        _set_module_args(args)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_boot.main()
        assert excinfo.value.kwargs["changed"] is True  # the plan would change something
        fake_client.put.assert_not_called()
        fake_client.invoke.assert_not_called()

    def test_missing_action_token_is_rejected_by_argument_spec(self):
        args = {k: v for k, v in BASE_ARGS.items() if k != "action_token"}
        _set_module_args(args)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises((AnsibleFailJson, SystemExit)):
                amt_boot.main()
        fake_client.invoke.assert_not_called()

    def test_empty_action_token_is_rejected_by_module_utils_gate(self):
        # required=True in the argument spec only rejects a wholly absent key; an empty string
        # still passes that check, so amt_boot.boot.arm_one_time_boot()'s own truthiness gate is
        # what actually catches this.
        args = dict(BASE_ARGS, action_token="")
        _set_module_args(args)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleFailJson) as excinfo:
                amt_boot.main()
        assert excinfo.value.kwargs["error_class"] == "invalid_state"
        fake_client.invoke.assert_not_called()

    def test_pxe_ider_conflict_cannot_be_expressed_but_unsupported_capability_still_fails_closed(self):
        # device is a closed six-value enum, so the module itself cannot construct a mixed
        # PXE+IDE-R request; this exercises the other mutation-safety path -- an unsupported
        # capability reported by firmware aborts before any Get/Put/Invoke.
        args = dict(BASE_ARGS, device="ider_floppy")
        _set_module_args(args)
        fake_client = _make_fake_client()
        fake_client.enumerate.side_effect = lambda resource_class, **kwargs: (
            [{"ForcePXEBoot": "true", "ForceHardDriveBoot": "true", "ForceCDorDVDBoot": "true", "BIOSSetup": "true", "IDER": "false", "SOL": "true"}]
            if resource_class == "AMT_BootCapabilities"
            else _sources()
        )
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleFailJson) as excinfo:
                amt_boot.main()
        assert excinfo.value.kwargs["error_class"] == "unsupported_capability"
        fake_client.get.assert_not_called()
        fake_client.put.assert_not_called()

    def test_invalid_device_choice_is_rejected_by_argument_spec(self):
        args = dict(BASE_ARGS, device="floppy")
        _set_module_args(args)
        with pytest.raises((AnsibleFailJson, SystemExit)):
            amt_boot.main()

    def test_credential_never_appears_in_the_result(self):
        _set_module_args(BASE_ARGS)
        fake_client = _make_fake_client()
        with patch(
            "ansible_collections.james_crowley.intel_amt.plugins.modules.amt_boot.WsmanClient.from_connection_options",
            return_value=fake_client,
        ):
            with pytest.raises(AnsibleExitJson) as excinfo:
                amt_boot.main()
        assert BASE_ARGS["password"] not in json.dumps(excinfo.value.kwargs)
