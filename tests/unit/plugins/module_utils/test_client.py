# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ansible_collections.james_crowley.intel_amt.plugins.module_utils.client import (
    AmtClient,
    PowerAction,
    _canonical_uuid,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.errors import (
    ProtocolError,
    RemoteOperationError,
    TimeoutError_,
    UnsupportedCapabilityError,
)
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.tls import PeerCertificateEvidence
from ansible_collections.james_crowley.intel_amt.plugins.module_utils.wsman import WsmanClient

PASSWORD = "Sup3rSecret!"


def _fake_wsman() -> Mock:
    """A stand-in for :class:`WsmanClient`, mocked at the class boundary.

    Configured with sensible defaults (no TLS evidence, a plausible endpoint
    string) so individual tests only need to override ``get``/``invoke``.
    Never touches a socket: no ``requests.Session`` involved at all.
    """
    wsman = Mock(spec_set=["get", "put", "enumerate", "invoke", "endpoint", "last_peer_certificate", "close"])
    wsman.endpoint = "10.0.0.5:16993"
    wsman.last_peer_certificate = None
    # enumerate() returns list[dict] in the real client. Default it to an empty
    # list rather than leaving a bare Mock, which is not iterable and makes any
    # test that does not explicitly stub enumeration fail with a confusing
    # TypeError from deep inside the code under test.
    wsman.enumerate.return_value = []
    return wsman


def _client(wsman: Mock, **kwargs) -> AmtClient:
    kwargs.setdefault("poll_count", 3)
    kwargs.setdefault("poll_delay", 0)
    kwargs.setdefault("sleep", lambda _seconds: None)
    return AmtClient(wsman, **kwargs)


class TestGetPowerState:
    @pytest.mark.parametrize(
        "cim_value,expected",
        [
            (2, "on"),
            (3, "sleep"),
            (4, "sleep"),
            (5, "on"),
            (6, "off"),
            (7, "hibernate"),
            (8, "off"),
            (9, "off"),
            (13, "off"),
        ],
    )
    def test_normalizes_across_the_whole_cim_table(self, cim_value, expected):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": str(cim_value)}
        client = _client(wsman)

        state = client.get_power_state()

        assert state.normalized == expected
        assert state.raw == cim_value
        wsman.get.assert_called_once_with("CIM_AssociatedPowerManagementService")

    def test_failure_propagates_unmodified(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = ProtocolError("boom", endpoint="10.0.0.5:16993")
        client = _client(wsman)

        with pytest.raises(ProtocolError):
            client.get_power_state()


class TestGetFacts:
    #: Enumerated separately from the Get map: firmware version lives in
    #: CIM_SoftwareIdentity, not in AMT_GeneralSettings (which has no version
    #: property at all). The BIOS/AMTApps siblings are present because real
    #: firmware returns them and the AMT instance must be selected exactly.
    #: A tuple, not a list: an immutable fixture cannot be mutated by one test
    #: and observed by the next.
    _SOFTWARE_IDENTITY = (
        {"InstanceID": "BIOS", "VersionString": "MYBDWi5v.86A.0059"},
        {"InstanceID": "AMTApps", "VersionString": "11.8.50"},
        {"InstanceID": "AMT", "VersionString": "11.8.50"},
    )

    def _full_response_map(self) -> dict:
        return {
            "AMT_GeneralSettings": {
                "HostName": "amt-host-07",
                "DomainName": "lab.example.invalid",
                "IdleWakeTimeout": "1",
                "PingResponseEnabled": "true",
                "RmcpPingResponseEnabled": "true",
                "NetworkInterfaceEnabled": "true",
                "DDNSUpdateEnabled": "false",
            },
            "AMT_SetupAndConfigurationService": {"ProvisioningState": "2", "ProvisioningMode": "1"},
            # PlatformGUID lives on CIM_ComputerSystemPackage. CIM_ComputerSystem
            # has no UUID property at all, which is why reading it there returned
            # None on every endpoint.
            "CIM_ComputerSystemPackage": {"PlatformGUID": "4C4C4544-0000-0000-0000-000000000000"},
            "CIM_AssociatedPowerManagementService": {"PowerState": "2"},
            "AMT_BootCapabilities": {"IDER": "true", "SOL": "true", "ForcePXEBoot": "true"},
            "AMT_RedirectionService": {"EnabledState": "32771", "ListenerEnabled": "true"},
            "AMT_EthernetPortSettings": {
                "MACAddress": "00-00-5e-00-53-01",
                "IPAddress": "192.0.2.10",
                "SubnetMask": "255.255.255.0",
                "DefaultGateway": "192.0.2.1",
                "PrimaryDNS": "192.0.2.2",
                "SecondaryDNS": "192.0.2.3",
                "DHCPEnabled": "false",
                "LinkIsUp": "true",
                "IpSyncEnabled": "false",
                "LinkPolicy": ["1", "14", "16"],
            },
            "CIM_ComputerSystem": {
                "ElementName": "ManagedSystem",
                "Name": "ManagedSystem",
                "EnabledState": "2",
                "RequestedState": "12",
                "OperationalStatus": ["2"],
            },
            "CIM_BIOSElement": {"Version": "EXAMPLE10H.86A.0000.2026.0101.0000"},
        }

    @staticmethod
    def _responder(responses: dict):
        """A ``wsman.get`` stand-in that ignores selectors and reports absent classes as faults.

        Selectors are asserted separately (see :class:`TestNewFactSelectors`);
        here the point is only which class was asked for. A class missing from the
        map raises the same degradable error real firmware sends for a class it
        does not implement, so the map doubles as the "which classes exist"
        fixture rather than a KeyError.
        """

        def _get(resource_class, **_kwargs):
            if resource_class not in responses:
                raise ProtocolError(f"{resource_class}: SOAP Fault code=wsman:InvalidResourceURI", endpoint="10.0.0.5:16993")
            return responses[resource_class]

        return _get

    def test_full_firmware_response_yields_complete_facts(self):
        wsman = _fake_wsman()
        responses = self._full_response_map()
        wsman.get.side_effect = self._responder(responses)
        wsman.enumerate.side_effect = lambda resource_class, **kwargs: self._SOFTWARE_IDENTITY if resource_class == "CIM_SoftwareIdentity" else []
        client = _client(wsman)

        facts = client.get_facts()

        assert facts.version == "11.8.50"
        assert facts.uuid == "4C4C4544-0000-0000-0000-000000000000"
        assert facts.provisioning_state == "2"
        assert facts.control_mode == "1"
        assert facts.reported_hostname == "amt-host-07"
        assert facts.power_state.normalized == "on"
        assert facts.capabilities.power is True
        assert facts.capabilities.boot_once_pxe is True
        assert facts.capabilities.sol is True
        assert facts.capabilities.storage_redirection is True
        assert facts.redirection.ider_enabled is True
        assert facts.redirection.sol_enabled is True

    @pytest.mark.parametrize(
        "missing_class",
        [
            "AMT_BootCapabilities",
            "AMT_RedirectionService",
            "AMT_GeneralSettings",
            "AMT_SetupAndConfigurationService",
            "AMT_EthernetPortSettings",
            "CIM_ComputerSystem",
            "CIM_BIOSElement",
        ],
    )
    def test_a_single_missing_optional_class_degrades_gracefully(self, missing_class):
        # "Tolerate a firmware that omits optional classes -- a missing optional
        # class must degrade a capability to false/unknown, not fail the whole read."
        wsman = _fake_wsman()
        responses = self._full_response_map()
        responses.pop(missing_class)

        wsman.get.side_effect = self._responder(responses)
        client = _client(wsman)

        facts = client.get_facts()  # must not raise

        if missing_class == "AMT_BootCapabilities":
            assert facts.capabilities.boot_once_pxe is False
            assert facts.capabilities.sol is False
            assert facts.capabilities.storage_redirection is False
        if missing_class == "AMT_RedirectionService":
            assert facts.redirection is None
        if missing_class == "AMT_GeneralSettings":
            assert facts.reported_hostname is None
            assert facts.reported_domain_name is None
            assert facts.idle_wake_timeout is None
            assert facts.ping_response_enabled is None
            assert facts.rmcp_ping_response_enabled is None
            assert facts.network_interface_enabled is None
            assert facts.ddns_update_enabled is None
        if missing_class == "AMT_SetupAndConfigurationService":
            assert facts.provisioning_state is None
            assert facts.control_mode is None
        if missing_class == "AMT_EthernetPortSettings":
            assert facts.network is None
        if missing_class == "CIM_ComputerSystem":
            assert facts.system_state is None
        if missing_class == "CIM_BIOSElement":
            # The Enumerate fallback is stubbed to return nothing here, so the
            # whole path degrades to null rather than failing the module.
            assert facts.bios_version is None
        # Unrelated facts still come through -- one absent class must not
        # blank out everything else.
        assert facts.power_state.normalized == "on"

    def test_unsupported_capability_error_is_also_tolerated(self):
        wsman = _fake_wsman()
        responses = self._full_response_map()

        def _get(resource_class, **_kwargs):
            if resource_class == "AMT_BootCapabilities":
                raise UnsupportedCapabilityError("not implemented", endpoint="10.0.0.5:16993")
            return responses[resource_class]

        wsman.get.side_effect = _get
        client = _client(wsman)

        facts = client.get_facts()

        assert facts.capabilities.storage_redirection is False

    def test_every_optional_class_missing_still_yields_a_usable_result(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = ProtocolError("nothing supported", endpoint="10.0.0.5:16993")
        client = _client(wsman)

        facts = client.get_facts()

        assert facts.version is None
        assert facts.power_state is None
        assert facts.capabilities.power is False
        assert facts.capabilities.boot_once_pxe is False
        assert facts.redirection is None

    def test_real_transport_failure_is_not_tolerated(self):
        # A connection failure means the whole read failed, not "class absent".
        wsman = _fake_wsman()
        wsman.get.side_effect = TimeoutError_("timed out", endpoint="10.0.0.5:16993")
        client = _client(wsman)

        with pytest.raises(TimeoutError_):
            client.get_facts()

    def test_general_settings_fields_come_from_the_instance_already_being_read(self):
        # The whole justification for these six fields is that they cost nothing:
        # AMT_GeneralSettings was already read for HostName. If this ever starts
        # reading the class twice, that justification is gone.
        wsman = _fake_wsman()
        wsman.get.side_effect = self._responder(self._full_response_map())
        facts = _client(wsman).get_facts()

        general_reads = [call for call in wsman.get.call_args_list if call.args[0] == "AMT_GeneralSettings"]
        assert len(general_reads) == 1
        assert facts.reported_hostname == "amt-host-07"
        assert facts.reported_domain_name == "lab.example.invalid"
        assert facts.idle_wake_timeout == 1
        assert facts.ping_response_enabled is True
        assert facts.rmcp_ping_response_enabled is True
        assert facts.network_interface_enabled is True
        assert facts.ddns_update_enabled is False

    def test_ethernet_and_system_state_are_parsed_end_to_end(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = self._responder(self._full_response_map())
        facts = _client(wsman).get_facts()

        assert facts.network.mac_address == "00:00:5e:00:53:01"
        assert facts.network.mac_address_raw == "00-00-5e-00-53-01"
        assert facts.network.ip_address == "192.0.2.10"
        assert facts.network.dhcp_enabled is False
        assert facts.network.link_is_up is True
        assert facts.network.ip_sync_enabled is False
        assert facts.network.link_policy == [1, 14, 16]
        assert facts.network.wake_on_lan_capable is True
        assert facts.system_state.element_name == "ManagedSystem"
        assert facts.system_state.enabled_state == 2
        assert facts.system_state.enabled_state_text == "enabled"
        assert facts.system_state.requested_state == 12
        assert facts.system_state.operational_status == [2]
        assert facts.system_state.operational_status_text == ["ok"]
        assert facts.bios_version == "EXAMPLE10H.86A.0000.2026.0101.0000"


class TestNewFactSelectors:
    """The new AMT_-prefixed and CIM_ComputerSystem reads must use Get + an exact selector.

    On AMT 10, ``Enumerate`` returns HTTP 400 for ``AMT_EthernetPortSettings``,
    ``AMT_GeneralSettings``, ``AMT_BootCapabilities``, ``AMT_BootSettingData`` and
    ``AMT_TLSSettingData``, while a ``Get`` with an exact selector works
    (``parmstro``, hardware-verified on 10.0.56; docs/protocol-notes.md §2.7).
    This collection's habit elsewhere is enumerate-first, so the selector is
    asserted rather than assumed.
    """

    @staticmethod
    def _calls_for(wsman: Mock, resource_class: str) -> list:
        return [call for call in wsman.get.call_args_list if call.args[0] == resource_class]

    def test_ethernet_port_settings_is_read_by_get_with_the_instance_0_selector(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {}
        _client(wsman).get_facts()

        calls = self._calls_for(wsman, "AMT_EthernetPortSettings")
        assert len(calls) == 1
        assert calls[0].kwargs["selectors"] == {"InstanceID": "Intel(r) AMT Ethernet Port Settings 0"}

    def test_ethernet_port_settings_is_never_enumerated(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {}
        _client(wsman).get_facts()

        enumerated = [call.args[0] for call in wsman.enumerate.call_args_list]
        assert "AMT_EthernetPortSettings" not in enumerated

    def test_computer_system_is_read_with_the_managed_system_selector(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {}
        _client(wsman).get_facts()

        calls = self._calls_for(wsman, "CIM_ComputerSystem")
        assert len(calls) == 1
        assert calls[0].kwargs["selectors"] == {"Name": "ManagedSystem"}

    def test_computer_system_is_not_read_for_a_uuid(self):
        # Regression guard for the original defect: CIM_ComputerSystem has no UUID
        # property, and reintroducing this read must not reintroduce that mistake.
        wsman = _fake_wsman()
        wsman.get.side_effect = lambda rc, **_kw: {"UUID": "should-never-be-used", "PlatformGUID": "ALSO-NOT-FROM-HERE"} if rc == "CIM_ComputerSystem" else {}
        facts = _client(wsman).get_facts()

        assert facts.uuid is None
        assert facts.system_state is not None


class TestBiosVersionSource:
    """``CIM_BIOSElement.Version`` -- the weakest-evidenced fact this client reads.

    ``parmstro``'s notes claim the class works on AMT 10.0.56 but record no dumped
    value, and their implementation swallows failures to ``None``, so their "pass"
    proves nothing. It is therefore read optionally, with an ``Enumerate``
    fallback for the case where a class with no selector needs enumerating.
    """

    def test_bare_get_is_tried_first(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = lambda rc, **_kw: {"Version": "EXAMPLE10H.86A.0000.2026.0101.0000"} if rc == "CIM_BIOSElement" else {}

        assert _client(wsman).get_facts().bios_version == "EXAMPLE10H.86A.0000.2026.0101.0000"
        # No enumeration needed when the Get answered.
        assert "CIM_BIOSElement" not in [call.args[0] for call in wsman.enumerate.call_args_list]

    def test_get_is_called_without_a_selector(self):
        # The class has no documented instance key; inventing one would fault on
        # firmware that does answer the bare Get.
        wsman = _fake_wsman()
        wsman.get.return_value = {}
        _client(wsman).get_facts()

        calls = [call for call in wsman.get.call_args_list if call.args[0] == "CIM_BIOSElement"]
        assert len(calls) == 1
        assert calls[0].kwargs.get("selectors") is None

    @staticmethod
    def _wsman_whose_bios_get_faults() -> Mock:
        wsman = _fake_wsman()

        def _get(resource_class, **_kwargs):
            if resource_class == "CIM_BIOSElement":
                raise ProtocolError("SOAP Fault code=wsman:InvalidSelectors", endpoint="10.0.0.5:16993")
            return {}

        wsman.get.side_effect = _get
        return wsman

    def test_enumerate_fallback_when_the_bare_get_faults(self):
        wsman = self._wsman_whose_bios_get_faults()
        wsman.enumerate.side_effect = lambda rc, **_kw: [{"Version": "EXAMPLE20H.86A.0001.2026.0202.0000"}] if rc == "CIM_BIOSElement" else []

        assert _client(wsman).get_facts().bios_version == "EXAMPLE20H.86A.0001.2026.0202.0000"

    def test_both_verbs_failing_degrades_to_none_without_failing_the_read(self):
        wsman = self._wsman_whose_bios_get_faults()
        wsman.enumerate.side_effect = ProtocolError("nope either", endpoint="10.0.0.5:16993")

        facts = _client(wsman).get_facts()
        assert facts.bios_version is None
        assert facts.capabilities is not None  # the rest of the read still happened

    def test_non_dict_enumeration_entries_are_skipped(self):
        wsman = self._wsman_whose_bios_get_faults()
        wsman.enumerate.side_effect = lambda rc, **_kw: [None, "junk", {"Version": "EXAMPLE30H.86A.0002.2026.0303.0000"}] if rc == "CIM_BIOSElement" else []

        assert _client(wsman).get_facts().bios_version == "EXAMPLE30H.86A.0002.2026.0303.0000"

    def test_empty_version_property_degrades_to_none(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = lambda rc, **_kw: {"Version": "   "} if rc == "CIM_BIOSElement" else {}
        wsman.enumerate.return_value = []

        assert _client(wsman).get_facts().bios_version is None


class TestRequestPowerState:
    @pytest.mark.parametrize(
        "action,expected_code",
        [
            (PowerAction.ON, 2),
            (PowerAction.SLEEP_LIGHT, 3),
            (PowerAction.SLEEP_DEEP, 4),
            (PowerAction.CYCLE, 5),
            (PowerAction.HIBERNATE, 7),
            (PowerAction.OFF, 8),
            (PowerAction.RESET, 10),
            (PowerAction.REBOOT, 10),
        ],
    )
    def test_every_action_code(self, action, expected_code):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": "8"}
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        client = _client(wsman, poll_count=0)

        client.request_power_state(action)

        call = wsman.invoke.call_args
        assert call.args[2]["PowerState"] == expected_code

    def test_managed_element_names_the_computer_system_selector(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": "8"}
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        client = _client(wsman, poll_count=0)

        client.request_power_state(PowerAction.ON)

        call = wsman.invoke.call_args
        assert call.args[0] == "CIM_PowerManagementService"
        assert call.args[1] == "RequestPowerStateChange"
        epr = call.args[2]["ManagedElement"]
        assert epr.resource_class == "CIM_ComputerSystem"
        assert epr.selectors == {"Name": "ManagedSystem"}

    def test_returns_a_receipt_with_previous_desired_and_return_value(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = [{"PowerState": "8"}, {"PowerState": "2"}]
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        client = _client(wsman, poll_count=1)

        receipt = client.request_power_state(PowerAction.ON)

        assert receipt.changed is True
        assert receipt.previous.normalized == "off"
        assert receipt.desired == "on"
        assert receipt.observed.normalized == "on"
        assert receipt.extra["return_value"] == 0
        assert receipt.extra["probes"] == [{"normalized": "on", "raw": 2}]
        assert receipt.endpoint == "10.0.0.5:16993"

    def test_bounded_poll_stops_early_once_expected_state_is_observed(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = [{"PowerState": "8"}, {"PowerState": "2"}, {"PowerState": "2"}]
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        client = _client(wsman, poll_count=5)

        receipt = client.request_power_state(PowerAction.ON)

        # 1 initial read + 1 poll that already matches "on" -- must not poll
        # the remaining 4 allowed attempts once satisfied.
        assert wsman.get.call_count == 2
        assert len(receipt.extra["probes"]) == 1

    def test_poll_count_and_delay_are_injectable_so_tests_never_sleep(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = [{"PowerState": "8"}] + [{"PowerState": "3"}] * 4
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        sleep_calls = []
        client = _client(wsman, poll_count=4, poll_delay=99, sleep=sleep_calls.append)

        client.request_power_state(PowerAction.ON)

        assert sleep_calls == [99, 99, 99, 99]  # never actually slept

    def test_nonzero_return_value_raises_remote_operation_error(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": "8"}
        wsman.invoke.side_effect = RemoteOperationError(
            "RequestPowerStateChange returned ReturnValue=2",
            endpoint="10.0.0.5:16993",
            operation="CIM_PowerManagementService.RequestPowerStateChange",
            return_value=2,
        )
        client = _client(wsman)

        with pytest.raises(RemoteOperationError) as excinfo:
            client.request_power_state(PowerAction.ON)
        assert excinfo.value.return_value == 2
        # No postcondition polling was attempted after a rejected request.
        wsman.get.assert_called_once()

    def test_timeout_after_send_propagates_as_indeterminate_without_retry(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": "8"}
        wsman.invoke.side_effect = TimeoutError_(
            "timed out after send",
            endpoint="10.0.0.5:16993",
            operation="CIM_PowerManagementService.RequestPowerStateChange",
            indeterminate=True,
        )
        client = _client(wsman)

        with pytest.raises(TimeoutError_) as excinfo:
            client.request_power_state(PowerAction.ON)
        assert excinfo.value.indeterminate is True
        wsman.invoke.assert_called_once()  # never retried by this layer

    def test_a_failed_postcondition_probe_does_not_mask_a_successful_request(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = [{"PowerState": "8"}, TimeoutError_("probe timed out", endpoint="10.0.0.5:16993"), {"PowerState": "2"}]
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        client = _client(wsman, poll_count=2)

        receipt = client.request_power_state(PowerAction.ON)

        assert receipt.changed is True
        assert receipt.observed.normalized == "on"
        assert len(receipt.extra["probes"]) == 1  # the failed probe is not recorded

    def test_tls_peer_fingerprint_is_included_when_available(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": "2"}
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        wsman.last_peer_certificate = PeerCertificateEvidence(sha256_fingerprint="aa" * 32, subject=None, issuer=None, not_after=None)
        client = _client(wsman, poll_count=0)

        receipt = client.request_power_state(PowerAction.ON)

        assert receipt.tls_peer_fingerprint == "aa" * 32


class TestNoCredentialLeakage:
    def test_password_never_appears_in_a_receipt_or_facts(self):
        wsman = _fake_wsman()
        wsman.get.return_value = {"PowerState": "2", "HostName": "x"}
        wsman.invoke.return_value = ({"ReturnValue": "0"}, 0)
        client = _client(wsman, poll_count=0)

        receipt = client.request_power_state(PowerAction.ON)
        facts = client.get_facts()

        assert PASSWORD not in repr(receipt.to_dict())
        assert PASSWORD not in repr(facts)


class TestAmtClientAcceptsRealWsmanClient:
    """AmtClient's constructor takes the concrete WsmanClient type -- confirm a
    real instance (with its own mocked `requests.Session`, never a socket) can
    be handed in directly, not only the test double used elsewhere here."""

    def test_constructs_with_a_real_wsman_client(self):
        session = Mock()
        wsman = WsmanClient(
            host="10.0.0.5",
            port=16992,
            username="admin",
            password="test-password-not-real",
            use_tls=False,
            allow_insecure_transport=True,
            session=session,
        )
        client = AmtClient(wsman)
        assert client is not None
        wsman.close()


class TestAmtVersionSource:
    """Firmware version comes from CIM_SoftwareIdentity, not from
    AMT_GeneralSettings or AMT_SetupAndConfigurationService.

    Neither of those classes defines a version property -- verified against the
    class definitions in device-management-toolkit/go-wsman-messages. An earlier
    implementation read ``Version``/``VersionsSupported`` from them, so the
    reported version was silently always None.
    """

    @staticmethod
    def _client_with(instances):
        wsman = Mock()
        wsman.get.side_effect = lambda resource_class, **kwargs: {}
        wsman.enumerate.side_effect = lambda resource_class, **kwargs: instances if resource_class == "CIM_SoftwareIdentity" else []
        return AmtClient(wsman)

    def test_version_read_from_the_amt_instance(self):
        client = self._client_with(
            [
                {"InstanceID": "BIOS", "VersionString": "MYBDWi5v.86A.0059"},
                {"InstanceID": "AMT", "VersionString": "11.8.50"},
                {"InstanceID": "AMTApps", "VersionString": "11.8.50"},
            ]
        )
        assert client.get_facts().version == "11.8.50"

    def test_amt_instance_matched_exactly_not_by_substring(self):
        # "AMTApps" contains "AMT". A substring match would return whichever
        # instance the firmware happened to enumerate first.
        client = self._client_with(
            [
                {"InstanceID": "AMTApps", "VersionString": "wrong-apps-version"},
                {"InstanceID": "AMT", "VersionString": "16.1.25"},
            ]
        )
        assert client.get_facts().version == "16.1.25"

    def test_missing_amt_instance_degrades_to_none(self):
        client = self._client_with([{"InstanceID": "BIOS", "VersionString": "x"}])
        assert client.get_facts().version is None

    def test_enumeration_failure_degrades_to_none(self):
        wsman = Mock()
        wsman.get.side_effect = lambda resource_class, **kwargs: {}
        wsman.enumerate.side_effect = ProtocolError("class not implemented")
        assert AmtClient(wsman).get_facts().version is None

    def test_non_dict_entries_are_skipped(self):
        client = self._client_with([None, "junk", {"InstanceID": "AMT", "VersionString": "12.0.0"}])
        assert client.get_facts().version == "12.0.0"


class TestSystemUuidSource:
    """The system UUID comes from CIM_ComputerSystemPackage.PlatformGUID.

    It was previously read as ``UUID`` from ``CIM_ComputerSystem``, which has no
    such property, so it was ``None`` on every endpoint. That silently disabled
    the stage-2 identity cross-check -- the guard that stops a reset landing on
    the wrong machine -- which is why this is tested rather than assumed.
    """

    @staticmethod
    def _client_with(package):
        wsman = _fake_wsman()

        def _get(resource_class, **kwargs):
            if resource_class == "CIM_ComputerSystemPackage":
                if package is None:
                    raise ProtocolError("class not implemented", endpoint="10.0.0.5:16993")
                return package
            return {}

        wsman.get.side_effect = _get
        return _client(wsman)

    def test_uuid_read_from_platform_guid(self):
        client = self._client_with({"PlatformGUID": "4C4C4544-0044-5310-8051-B3C04F464331"})
        assert client.get_facts().uuid == "4C4C4544-0044-5310-8051-B3C04F464331"

    def test_whitespace_is_stripped(self):
        client = self._client_with({"PlatformGUID": "  4C4C4544-0044  "})
        assert client.get_facts().uuid == "4C4C4544-0044"

    def test_absent_property_degrades_to_none(self):
        client = self._client_with({"SomethingElse": "x"})
        assert client.get_facts().uuid is None

    def test_empty_property_degrades_to_none(self):
        # An empty string must not be reported as an identity: it would compare
        # equal to another endpoint that also reported nothing.
        client = self._client_with({"PlatformGUID": "   "})
        assert client.get_facts().uuid is None

    def test_absent_class_degrades_without_failing_the_whole_read(self):
        client = self._client_with(None)
        facts = client.get_facts()
        assert facts.uuid is None
        # The rest of facts gathering must still succeed.
        assert facts.capabilities is not None

    def test_computer_system_is_no_longer_consulted_for_uuid(self):
        # Regression guard: reading UUID from CIM_ComputerSystem is what produced
        # a permanently-null identity.
        client = self._client_with({"PlatformGUID": "GOOD-GUID"})
        assert client.get_facts().uuid == "GOOD-GUID"


class TestCanonicalUuidFormatting:
    """PlatformGUID must be rendered the way MEBx displays it.

    The SMBIOS Type 1 UUID stores its first three fields little-endian. Reading
    them big-endian produces something that still looks like a UUID, so the
    identity cross-check would fail against a correctly-recorded expectation and
    be quietly useless. The version-nibble assertions below are the cheap
    invariant that distinguishes the correct byte order from the plausible-but-
    wrong one.
    """

    #: Shaped exactly like what AMT 16.1.30 returns, but with illustrative digits:
    #: this repository is public and a platform GUID identifies a physical machine.
    #: The two properties the tests actually rely on are preserved -- the
    #: little-endian reading yields a valid version nibble (1) and the naive
    #: big-endian reading yields an invalid one (F) -- so the proof is unchanged.
    REAL_PLATFORM_GUID = "DDCCBBAAFFEEF0118899001122334455"
    EXPECTED = "AABBCCDD-EEFF-11F0-8899-001122334455"

    def test_real_firmware_value_renders_canonically(self):
        assert _canonical_uuid(self.REAL_PLATFORM_GUID) == self.EXPECTED

    def test_version_nibble_is_valid(self):
        # A valid UUID version is 1-8. The naive big-endian reading of this same
        # value yields 'F', which is not a version at all -- that is how we know
        # the field reversal is right rather than merely self-consistent.
        version = _canonical_uuid(self.REAL_PLATFORM_GUID).split("-")[2][0]
        assert version in "12345678", f"version nibble {version} is not a valid UUID version"

    def test_naive_big_endian_would_be_invalid(self):
        # Guards the reasoning itself: if someone "simplifies" the function to a
        # plain dash-insertion, this documents why that is wrong.
        raw = self.REAL_PLATFORM_GUID
        naive = f"{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}".upper()
        assert naive.split("-")[2][0] not in "12345678"
        assert _canonical_uuid(raw) != naive

    def test_already_dashed_value_is_not_converted_twice(self):
        # Firmware generations differ; a value that already carries dashes must be
        # left alone rather than reversed again.
        assert _canonical_uuid(self.EXPECTED) == self.EXPECTED

    def test_case_is_normalised(self):
        assert _canonical_uuid(self.REAL_PLATFORM_GUID.lower()) == self.EXPECTED

    @pytest.mark.parametrize("weird", ["", "not-hex-at-all", "0064", "ZZ6467CCB605F0118833AD07FBD52200", "00" * 20])
    def test_unexpected_shapes_are_returned_unchanged_and_never_raise(self, weird):
        # Better to surface an odd value verbatim than to mangle it into a
        # confident lie about a machine's identity.
        assert _canonical_uuid(weird) == weird

    def test_end_to_end_through_get_facts(self):
        wsman = _fake_wsman()
        wsman.get.side_effect = lambda rc, **kw: {"PlatformGUID": self.REAL_PLATFORM_GUID} if rc == "CIM_ComputerSystemPackage" else {}
        assert _client(wsman).get_facts().uuid == self.EXPECTED
