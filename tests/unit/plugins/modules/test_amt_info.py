# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import dataclasses
import json
from unittest.mock import Mock

import pytest
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import AuthenticationError
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.hardware import (
    BaseboardInfo,
    ChassisInfo,
    ChipInfo,
    ClassRead,
    HardwareFacts,
    MemoryInfo,
    ProcessorInfo,
    StorageInfo,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.models import (
    AmtCapabilities,
    AmtFacts,
    EthernetSettings,
    PowerState,
    RedirectionState,
    SystemState,
)
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
        reported_domain_name="lab.example.invalid",
        idle_wake_timeout=1,
        ping_response_enabled=True,
        rmcp_ping_response_enabled=True,
        network_interface_enabled=True,
        ddns_update_enabled=False,
        # Obviously-fake values only: RFC 7042 documentation MAC, RFC 5737 TEST-NET-1
        # addresses. A real MAC or IP must never enter this repository.
        network=EthernetSettings.from_instance(
            {
                "MACAddress": "00-00-5E-00-53-01",
                "IPAddress": "192.0.2.10",
                "DHCPEnabled": "false",
                "LinkIsUp": "true",
                "IpSyncEnabled": "false",
                "LinkPolicy": ["1", "14", "16"],
            }
        ),
        system_state=SystemState.from_instance({"ElementName": "ManagedSystem", "EnabledState": "2", "RequestedState": "12", "OperationalStatus": ["2"]}),
        bios_version="EXAMPLE10H.86A.0000.2026.0101.0000",
    )


#: The exact `amt` keys 0.1.0 returned, in the order it returned them. New facts
#: are additive: an existing consumer (roles/amt_baremetal_install, the
#: integration targets, tests/hardware, the docs) must not have to change, and a
#: key that quietly moved or changed shape would break it silently.
LEGACY_AMT_KEYS = (
    "reachable",
    "version",
    "uuid",
    "control_mode",
    "provisioning_state",
    "hostname",
    "power_state",
    "capabilities",
    "redirection_status",
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
        # Every new fact degrades the same way: null, never a module failure and
        # never an invented default.
        assert amt["network"] is None
        assert amt["system_state"] is None
        assert amt["bios_version"] is None
        assert amt["domain_name"] is None
        assert amt["idle_wake_timeout"] is None
        assert amt["ping_response_enabled"] is None
        assert amt["rmcp_ping_response_enabled"] is None
        assert amt["network_interface_enabled"] is None
        assert amt["ddns_update_enabled"] is None

    def test_the_new_network_and_state_facts_are_shaped_into_the_amt_key(self):
        client = Mock()
        client.get_facts.return_value = _full_facts()

        amt = amt_info.facts_to_result(client)

        assert amt["domain_name"] == "lab.example.invalid"
        assert amt["idle_wake_timeout"] == 1
        assert amt["ping_response_enabled"] is True
        assert amt["rmcp_ping_response_enabled"] is True
        assert amt["network_interface_enabled"] is True
        assert amt["ddns_update_enabled"] is False
        assert amt["bios_version"] == "EXAMPLE10H.86A.0000.2026.0101.0000"
        assert amt["network"]["mac_address"] == "00:00:5e:00:53:01"
        assert amt["network"]["mac_address_raw"] == "00-00-5E-00-53-01"
        assert amt["network"]["ip_address"] == "192.0.2.10"
        assert amt["network"]["link_policy"] == [1, 14, 16]
        assert amt["network"]["link_policy_names"] == ["s0_ac", "sx_ac", "s0_dc"]
        assert amt["network"]["wake_on_lan_capable"] is True
        assert amt["network"]["ip_sync_enabled"] is False
        assert amt["system_state"]["element_name"] == "ManagedSystem"
        assert amt["system_state"]["enabled_state_text"] == "enabled"
        assert amt["system_state"]["operational_status_text"] == ["ok"]

    def test_the_result_is_json_serializable(self):
        # dataclasses.asdict on the two new nested types must produce plain
        # dicts/lists; anything else fails at exit_json rather than here.
        client = Mock()
        client.get_facts.return_value = _full_facts()

        assert json.loads(json.dumps(amt_info.facts_to_result(client)))["network"]["link_policy"] == [1, 14, 16]


class TestBackwardCompatibility:
    """The `amt` return key is additive only. Nothing existing may move or change shape.

    Existing consumers are `roles/amt_baremetal_install` (which reads
    `amt.reachable` and `amt.capabilities.*`), the integration targets,
    `tests/hardware/`, and the documented return table.
    """

    def test_every_pre_existing_key_is_still_present_in_its_original_position(self):
        client = Mock()
        client.get_facts.return_value = _full_facts()

        keys = list(amt_info.facts_to_result(client))

        assert keys[: len(LEGACY_AMT_KEYS)] == list(LEGACY_AMT_KEYS)

    def test_pre_existing_keys_keep_their_shape(self):
        client = Mock()
        client.get_facts.return_value = _full_facts()

        amt = amt_info.facts_to_result(client)

        assert amt["reachable"] is True
        assert amt["hostname"] == "amt-host-07"
        assert set(amt["power_state"]) == {"normalized", "raw"}
        assert set(amt["capabilities"]) == {"power", "boot_once_pxe", "sol", "storage_redirection"}
        assert set(amt["redirection_status"]) == {"enabled_state", "listener_enabled", "ider_enabled", "sol_enabled"}
        # The MAC lives under `network`, not at the top level: a top-level
        # `mac_address` would collide with the caller-supplied identity that
        # models.CallerSuppliedIdentity deliberately keeps separate.
        assert "mac_address" not in amt


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
        # Redacted, not truncated: an operator still sees that it was the password that was
        # rejected. This one is a real test of errors.redact, which is why it survives while the
        # successful-result variant did not -- see the note below.
        assert result["msg"] == "rejected password=[REDACTED]"

    # The successful-result password assertion that used to sit here was deleted rather than
    # repaired: with exit_json replaced by the bare raiser in the autouse fixture above, the
    # credential could not be in those kwargs, because the real exit_json is what injects
    # invocation.module_args and what applies no_log censoring. That invariant now runs against
    # the real serializer in tests/unit/plugins/modules/test_credential_contract.py. The
    # AuthenticationError test above stays: there the credential really is in the message being
    # handled, and it is this collection's own errors.redact that has to remove it.

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


def _hardware_facts() -> HardwareFacts:
    """A fully-populated inventory, shaped like the real firmware fixtures.

    Every identity-shaped value is obviously fake. The vendor fixtures these
    property sets come from do carry what look like a real machine's serials and
    model numbers; none of those is reproduced anywhere in this repository.
    """
    return HardwareFacts(
        chassis=ChassisInfo.from_instance(
            {
                "SerialNumber": "MOCKCHASSIS0001",
                "Model": "MOCK-CHASSIS-0000",
                "Manufacturer": "Mock Systems (example.invalid)",
                "ChassisPackageType": "3",
                "PackageType": "3",
                "Tag": "CIM_Chassis",
                "OperationalStatus": "2",
            }
        ),
        baseboard=BaseboardInfo.from_instance({"SerialNumber": "MOCKBOARD0001", "Model": "MOCK-BOARD-0000", "PackageType": "9", "CanBeFRUed": "true"}),
        processors=[ProcessorInfo.from_instance({"DeviceID": "CPU 0", "Family": "198", "UpgradeMethod": "52", "MaxClockSpeed": "8300"})],
        chips=[ChipInfo.from_instance({"Tag": "CPU 0", "Version": "Mock(R) Example(TM) CPU E0000 @ 2.40GHz"})],
        memory=[
            MemoryInfo.from_instance({"BankLabel": "BANK 0", "Capacity": "17179869184", "MemoryType": "26", "FormFactor": "13"}),
            MemoryInfo.from_instance({"BankLabel": "BANK 2", "Capacity": "17179869184", "MemoryType": "26", "FormFactor": "13"}),
        ],
        storage=[StorageInfo.from_instance({"DeviceID": "MEDIA DEV 0", "MaxMediaSize": "960197124", "Capabilities": "4", "Security": "2"})],
        requested=frozenset({"chassis", "baseboard", "processors", "chips", "memory", "storage"}),
        # The per-class read outcomes the client records alongside the facts. The
        # two singletons answered their bare Get; the four multi-instance classes
        # answered an Enumerate. Instance counts match the groups above, because a
        # receipt that disagreed with its own facts would be worse than none.
        reads={
            "CIM_Chassis": ClassRead(fact_group="chassis", outcome="read", verb="Get", instances=1),
            "CIM_Card": ClassRead(fact_group="baseboard", outcome="read", verb="Get", instances=1),
            "CIM_Processor": ClassRead(fact_group="processors", outcome="read", verb="Enumerate", instances=1),
            "CIM_Chip": ClassRead(fact_group="chips", outcome="read", verb="Enumerate", instances=1),
            "CIM_PhysicalMemory": ClassRead(fact_group="memory", outcome="read", verb="Enumerate", instances=2),
            "CIM_MediaAccessDevice": ClassRead(fact_group="storage", outcome="read", verb="Enumerate", instances=1),
        },
    )


class TestGatherSubsetArgumentSpec:
    def test_gather_subset_defaults_to_config_only(self):
        # The one deliberate divergence from ansible.builtin.setup, which defaults
        # to gathering everything. Everything here means ten extra WS-Man round
        # trips against firmware, and no existing caller should start paying for
        # inventory they never asked for.
        assert amt_info._connection_argument_spec()["gather_subset"]["default"] == ["config"]

    def test_gather_subset_is_a_list_of_strings(self):
        spec = amt_info._connection_argument_spec()["gather_subset"]
        assert spec["type"] == "list"
        assert spec["elements"] == "str"

    def test_every_subset_and_alias_is_offered_in_both_polarities(self):
        choices = set(amt_info._connection_argument_spec()["gather_subset"]["choices"])
        names = {"all", "min", "config", "hardware", "system", "processor", "memory", "storage"}
        assert choices == names | {f"!{name}" for name in names}

    def test_an_unrecognised_subset_is_refused_by_argument_validation(self, monkeypatch):
        # Validated by `choices` rather than in module code, so the refusal happens
        # before any connection is attempted -- and a typo never has to be squeezed
        # into one of errors.py's nine operation-failure classes, none of which
        # describes "you made a typo".
        _set_module_args({**BASE_ARGS, "gather_subset": ["hardwear"]})
        built = []
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: built.append(params) or _fake_wsman())

        with pytest.raises(AnsibleFailJson):
            amt_info.main()
        assert built == [], "argument validation must reject the subset before a client is built"


class TestMainGatherSubsetPlumbing:
    def _run(self, monkeypatch, args, facts=None, hardware=None):
        _set_module_args(args)
        fake_client = Mock()
        base = _full_facts()
        fake_client.get_facts.return_value = facts if facts is not None else dataclasses.replace(base, hardware=hardware)
        monkeypatch.setattr(amt_info, "build_wsman_client", lambda params: _fake_wsman())
        monkeypatch.setattr(amt_info, "AmtClient", lambda wsman: fake_client)
        with pytest.raises(AnsibleExitJson) as excinfo:
            amt_info.main()
        return excinfo.value.args[0], fake_client

    def test_the_default_passes_only_config_through_to_the_client(self, monkeypatch):
        _result, client = self._run(monkeypatch, dict(BASE_ARGS))
        assert client.get_facts.call_args.args[0] == frozenset({"config"})

    def test_all_resolves_to_every_subset_before_reaching_the_client(self, monkeypatch):
        _result, client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]})
        assert client.get_facts.call_args.args[0] == frozenset({"config", "system", "processor", "memory", "storage"})

    def test_negation_is_resolved_before_reaching_the_client(self, monkeypatch):
        _result, client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all", "!memory"]})
        assert client.get_facts.call_args.args[0] == frozenset({"config", "system", "processor", "storage"})

    def test_hardware_is_null_when_no_hardware_subset_was_requested(self, monkeypatch):
        result, _client = self._run(monkeypatch, dict(BASE_ARGS))
        assert result["amt"]["hardware"] is None

    def test_the_legacy_amt_keys_are_unchanged_by_the_new_option(self, monkeypatch):
        # The backward-compatibility promise, asserted at the module boundary:
        # roles/amt_baremetal_install, the integration targets and tests/hardware
        # all read these keys and must not have to change.
        result, _client = self._run(monkeypatch, dict(BASE_ARGS))
        for key in LEGACY_AMT_KEYS:
            assert key in result["amt"], key

    def test_hardware_is_rendered_when_a_subset_was_requested(self, monkeypatch):
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        hardware = result["amt"]["hardware"]
        assert hardware["chassis"]["serial_number"] == "MOCKCHASSIS0001"
        assert hardware["baseboard"]["serial_number"] == "MOCKBOARD0001"
        assert hardware["chips"][0]["version"] == "Mock(R) Example(TM) CPU E0000 @ 2.40GHz"
        assert [dimm["bank_label"] for dimm in hardware["memory"]] == ["BANK 0", "BANK 2"]
        assert hardware["storage"][0]["max_media_size_kb"] == 960197124

    def test_a_group_that_was_not_requested_is_absent_rather_than_null(self, monkeypatch):
        # 'memory' in amt.hardware answers "did I ask for it"; is none answers
        # "does this firmware have it". Rendering via HardwareFacts.to_dict()
        # rather than dataclasses.asdict() is what keeps those apart.
        hardware = HardwareFacts(memory=[], requested=frozenset({"memory"}))
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["memory"]}, hardware=hardware)
        assert "memory" in result["amt"]["hardware"]
        assert "storage" not in result["amt"]["hardware"]

    def test_the_receipt_records_the_resolved_subset_and_the_request_estimate(self, monkeypatch):
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        assert result["operation"]["gather_subset"] == ["config", "memory", "processor", "storage", "system"]
        assert result["operation"]["wsman_requests_estimated"] == 20

    def test_the_default_receipt_reports_the_pre_0_5_0_request_count(self, monkeypatch):
        result, _client = self._run(monkeypatch, dict(BASE_ARGS))
        assert result["operation"]["gather_subset"] == ["config"]
        assert result["operation"]["wsman_requests_estimated"] == 10

    def test_the_receipt_reports_the_per_class_read_outcome_for_every_class(self, monkeypatch):
        # The diagnostic the first hardware run needed and did not have. A `null`
        # fact group is correct behaviour but it is not a diagnosis, and this is
        # where the reason lives.
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        reads = result["operation"]["hardware_reads"]

        assert list(reads) == ["CIM_Chassis", "CIM_Card", "CIM_Processor", "CIM_Chip", "CIM_PhysicalMemory", "CIM_MediaAccessDevice"]
        assert reads["CIM_Chassis"] == {
            "fact_group": "chassis",
            "outcome": "read",
            "verb": "Get",
            "instances": 1,
            "error_class": None,
            # 0.7.0: the per-property shape census. `_hardware_facts()` builds its
            # ClassReads directly rather than by reading a fake endpoint, so there
            # is no instance behind this one to census -- which is exactly the
            # "nothing answered, nothing to census" case rendering as null.
            "property_shapes": None,
            "property_names_dropped": 0,
        }
        assert reads["CIM_PhysicalMemory"]["fact_group"] == "memory"

    def test_the_receipt_read_outcomes_map_onto_keys_that_actually_exist(self, monkeypatch):
        # The regression guard for the qualification-playbook defect: that summary
        # read `amt.hardware.system` and `amt.hardware.processor`, which are
        # gather_subset names and not fact keys, so `| default(none)` printed
        # "null" for four groups firmware had in fact populated. Every fact_group
        # named in the receipt must be a key that really is present.
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        hardware = result["amt"]["hardware"]

        for class_name, read in result["operation"]["hardware_reads"].items():
            assert read["fact_group"] in hardware, f"{class_name} claims a fact group that is not in amt.hardware"
        assert "system" not in hardware, "`system` is a gather_subset name, never a fact key"
        assert "processor" not in hardware, "`processor` is a gather_subset name, never a fact key"

    def test_a_degraded_class_reports_absent_with_its_error_class_beside_the_null(self, monkeypatch):
        hardware = HardwareFacts(
            requested=frozenset({"memory"}),
            reads={"CIM_PhysicalMemory": ClassRead(fact_group="memory", outcome="absent", verb="Enumerate", error_class="protocol")},
        )
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["memory"]}, hardware=hardware)
        read = result["operation"]["hardware_reads"]["CIM_PhysicalMemory"]

        assert result["amt"]["hardware"]["memory"] is None, "the null fact value must be unchanged by the diagnostics"
        assert (read["outcome"], read["error_class"]) == ("absent", "protocol")

    def test_the_receipt_omits_hardware_reads_entirely_when_no_inventory_was_asked_for(self, monkeypatch):
        # Absent means "not attempted", the same convention amt.hardware itself
        # uses. A key present but empty would claim inventory had been tried.
        result, _client = self._run(monkeypatch, dict(BASE_ARGS))
        assert "hardware_reads" not in result["operation"]

    def test_the_receipt_still_reports_changed_false_and_no_error(self, monkeypatch):
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        assert result["changed"] is False
        assert result["operation"]["schema"] == "intel-amt-operation/v1"
        assert result["operation"]["action"] == "get_facts"
        assert result["operation"]["changed"] is False
        assert result["operation"]["error_class"] is None

    def test_check_mode_gathers_inventory_identically(self, monkeypatch):
        # Read-only module: there is nothing for check mode to skip, and an
        # inventory read that silently returned nothing under --check would make
        # a dry run useless for exactly the audience this feature exists for.
        result, client = self._run(
            monkeypatch,
            {**BASE_ARGS, "gather_subset": ["all"], "_ansible_check_mode": True},
            hardware=_hardware_facts(),
        )
        assert result["changed"] is False
        assert result["amt"]["hardware"]["chassis"]["serial_number"] == "MOCKCHASSIS0001"
        assert client.get_facts.call_args.args[0] == frozenset({"config", "system", "processor", "memory", "storage"})

    def test_a_fully_degraded_inventory_is_still_a_success(self, monkeypatch):
        hardware = HardwareFacts(requested=frozenset({"chassis", "baseboard", "processors", "chips", "memory", "storage"}))
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=hardware)
        assert result["changed"] is False
        assert all(value is None for value in result["amt"]["hardware"].values())

    def test_the_whole_result_is_json_serializable_with_inventory_present(self, monkeypatch):
        # Ansible serializes module results to JSON. A frozenset or a dataclass
        # leaking through to_dict() would fail at exit_json, not in a parse test.
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        assert json.loads(json.dumps(result))["amt"]["hardware"]["memory"][0]["memory_type_text"] == "ddr4"

    def test_the_password_never_appears_in_a_result_carrying_inventory(self, monkeypatch):
        # The collection's most security-critical invariant, re-checked on the new
        # code path: hardware facts pass through OperationReceipt's redaction
        # backstop and a serialized result must not contain the credential.
        result, _client = self._run(monkeypatch, {**BASE_ARGS, "gather_subset": ["all"]}, hardware=_hardware_facts())
        assert PASSWORD not in json.dumps(result)
