# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AuthenticationError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import AmtCapabilities, AmtFacts, PowerState, RedirectionState
from ansible_collections.james_crowley.intel_amt.plugins.modules import amt_info

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


def _full_facts() -> AmtFacts:
    return AmtFacts(
        version="11.8.50",
        uuid="4C4C4544-0000-0000-0000-000000000000",
        control_mode="1",
        provisioning_state="2",
        power_state=PowerState.from_cim_value(2),
        reported_hostname="amt-host-07",
        capabilities=AmtCapabilities(power=True, boot_once_pxe=True, sol=True, storage_redirection=True),
        redirection=RedirectionState.from_enabled_state(32771, listener_enabled=True),
    )


class TestArgumentSpec:
    def test_password_is_no_log(self):
        assert amt_info._connection_argument_spec()["password"]["no_log"] is True

    def test_host_and_password_are_required(self):
        spec = amt_info._connection_argument_spec()
        assert spec["host"]["required"] is True
        assert spec["password"]["required"] is True

    def test_missing_password_fails_argument_validation(self):
        _set_module_args({"host": "10.0.0.5"})
        with pytest.raises(AnsibleFailJson):
            amt_info.main()

    def test_missing_requests_dependency_is_an_actionable_failure(self, monkeypatch):
        _set_module_args(BASE_ARGS)
        monkeypatch.setattr(amt_info, "HAS_REQUESTS", False)
        monkeypatch.setattr(amt_info, "REQUESTS_IMPORT_ERROR", "No module named 'requests'")

        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_info.main()
        assert "requests" in excinfo.value.args[0]["msg"]


class TestBuildWsmanClient:
    def test_builds_a_real_client_from_module_params_without_touching_a_socket(self):
        params = {
            "host": "10.0.0.5",
            "port": None,
            "username": "admin",
            "password": PASSWORD,
            "use_tls": True,
            "allow_insecure_transport": False,
            "validate_certs": True,
            "ca_path": None,
            "tls_fingerprint": "aa" * 32,
            "timeout": 30,
            "connect_timeout": 10,
        }
        wsman = amt_info.build_wsman_client(params)
        assert wsman.endpoint == "10.0.0.5:16993"  # TLS default port, resolved by tls.py
        wsman.close()


class TestFactsToResult:
    def test_full_facts_are_shaped_into_the_amt_key(self):
        client = Mock()
        client.get_facts.return_value = _full_facts()

        amt = amt_info.facts_to_result(client)

        assert amt["reachable"] is True
        assert amt["version"] == "11.8.50"
        assert amt["hostname"] == "amt-host-07"
        assert amt["power_state"] == {"normalized": "on", "raw": 2}
        assert amt["capabilities"] == {"power": True, "boot_once_pxe": True, "sol": True, "storage_redirection": True}
        assert amt["redirection_status"]["ider_enabled"] is True
        assert amt["redirection_status"]["sol_enabled"] is True

    def test_absent_optional_facts_degrade_to_none_not_a_crash(self):
        client = Mock()
        client.get_facts.return_value = AmtFacts()  # every optional class absent

        amt = amt_info.facts_to_result(client)

        assert amt["reachable"] is True
        assert amt["power_state"] is None
        assert amt["redirection_status"] is None
        assert amt["capabilities"] == {"power": False, "boot_once_pxe": False, "sol": False, "storage_redirection": False}


def _fake_wsman(*, tls_peer_fingerprint: str | None = None) -> Mock:
    """A stand-in for the real WsmanClient main() holds directly (not just via AmtClient).

    ``last_peer_certificate`` and ``endpoint`` must be set explicitly rather than left as
    auto-generated ``Mock`` attributes: ``main()`` now reads
    ``wsman.last_peer_certificate.sha256_fingerprint`` to build the operation receipt's
    ``tls_peer_fingerprint``, and an un-configured ``Mock()`` there would be truthy and
    JSON-unserializable, breaking every credential-safety assertion that calls ``json.dumps``.
    """
    wsman = Mock()
    wsman.endpoint = "10.0.0.5:16993"
    wsman.last_peer_certificate = Mock(sha256_fingerprint=tls_peer_fingerprint) if tls_peer_fingerprint else None
    return wsman


class TestMainReadOnly:
    def test_successful_read_reports_changed_false(self, monkeypatch):
        _set_module_args(BASE_ARGS)
        fake_client = Mock()
        fake_client.get_facts.return_value = _full_facts()
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman())
        monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: fake_client)

        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_info.main()

        result = excinfo.value.args[0]
        assert result["changed"] is False
        assert result["amt"]["capabilities"]["storage_redirection"] is True

    def test_check_mode_still_performs_a_full_read(self, monkeypatch):
        args = dict(BASE_ARGS)
        args["_ansible_check_mode"] = True
        _set_module_args(args)
        fake_client = Mock()
        fake_client.get_facts.return_value = _full_facts()
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman())
        monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: fake_client)

        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_info.main()

        result = excinfo.value.args[0]
        assert result["changed"] is False
        assert result["amt"]["reachable"] is True
        fake_client.get_facts.assert_called_once()

    def test_amt_error_is_surfaced_via_fail_json_without_reformatting(self, monkeypatch):
        _set_module_args(BASE_ARGS)
        fake_client = Mock()
        fake_client.get_facts.side_effect = AuthenticationError(
            f"rejected password={PASSWORD}", endpoint="10.0.0.5:16993", operation="get_facts", secrets=PASSWORD
        )
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman())
        monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: fake_client)

        with pytest.raises(AnsibleFailJson) as excinfo:
            amt_info.main()

        result = excinfo.value.args[0]
        assert result["error_class"] == "authentication"
        assert PASSWORD not in json.dumps(result)

    def test_no_credential_appears_anywhere_in_a_successful_result(self, monkeypatch):
        _set_module_args(BASE_ARGS)
        fake_client = Mock()
        fake_client.get_facts.return_value = _full_facts()
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman())
        monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: fake_client)

        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_info.main()

        assert PASSWORD not in json.dumps(excinfo.value.args[0])

    def test_gains_a_non_secret_operation_receipt(self, monkeypatch):
        # issue #22: amt_info previously had neither shape at all. It now gets the same
        # `operation` receipt every other module returns, with action=get_facts and
        # previous/desired/observed left null since a read has no prior/intended/re-observed
        # state distinct from RV(amt) to report.
        _set_module_args(BASE_ARGS)
        fake_client = Mock()
        fake_client.get_facts.return_value = _full_facts()
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman(tls_peer_fingerprint="bb" * 32))
        monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: fake_client)

        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_info.main()

        result = excinfo.value.args[0]
        operation = result["operation"]
        assert operation["schema"] == "intel-amt-operation/v1"
        assert operation["action"] == "get_facts"
        assert operation["endpoint"] == "10.0.0.5:16993"
        assert operation["changed"] is False
        assert operation["previous"] is None
        assert operation["desired"] is None
        assert operation["observed"] is None
        assert operation["tls_peer_fingerprint"] == "bb" * 32
        assert operation["error_class"] is None
