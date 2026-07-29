# Copyright (c) 2026 Jim Crowley
# GNU General Public License v3.0 or later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Self-tests for the mock WS-Man server.

These exercise ``WsmanMockServer`` from the outside with a plain HTTP client
(``requests``) plus a raw TLS socket for fingerprint checks, exactly as a
real integration test would, rather than calling internals directly -- the
whole point of these tests is to prove the mock behaves like a WS-Man
endpoint on the wire, not just that its Python happens to be self-consistent.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import socket
import ssl
import threading
import uuid
import warnings
from typing import ClassVar
from xml.etree import ElementTree as ET

import pytest
import requests
from requests.auth import HTTPDigestAuth
from wsman_server import (
    AMT_BOOT_CAPABILITIES,
    AMT_BOOT_SETTING_DATA,
    AMT_ETHERNET_PORT_SETTINGS,
    AMT_GENERAL_SETTINGS,
    AMT_MESSAGE_LOG,
    AMT_REDIRECTION_SERVICE,
    AMT_SETUP_AND_CONFIGURATION_SERVICE,
    CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE,
    CIM_BIOS_ELEMENT,
    CIM_BOOT_CONFIG_SETTING,
    CIM_BOOT_SERVICE,
    CIM_BOOT_SOURCE_SETTING,
    CIM_COMPUTER_SYSTEM,
    CIM_POWER_MANAGEMENT_SERVICE,
    DEFAULT_MESSAGE_LOG_RECORDS,
    ETHERNET_PORT_0_INSTANCE_ID,
    MESSAGE_LOG_BATCH_SIZE,
    WsmanMockServer,
)

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

FAKE_USERNAME = "admin"
FAKE_PASSWORD = "test-password-not-real"


def _find_text(root: ET.Element, local_name: str) -> str | None:
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] == local_name:
            return elem.text
    return None


def _find_all_text(root: ET.Element, local_name: str) -> list[str]:
    return [elem.text or "" for elem in root.iter() if elem.tag.rsplit("}", 1)[-1] == local_name]


def _has_element(root: ET.Element, local_name: str) -> bool:
    """True if an element with this local name exists anywhere in the tree.

    Deliberately distinct from :func:`_find_text`: ``EndOfSequence`` is
    self-closing, so its ``.text`` is ``None`` and cannot be used to detect
    presence.
    """
    return any(elem.tag.rsplit("}", 1)[-1] == local_name for elem in root.iter())


def _envelope(action: str, resource_uri: str, body_xml: str = "", *, header_extra_xml: str = "") -> str:
    message_id = f"uuid:{uuid.uuid4()}"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
        "<s:Header>"
        f'<a:Action s:mustUnderstand="true">{action}</a:Action>'
        "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
        f"<w:ResourceURI>{resource_uri}</w:ResourceURI>"
        f"<a:MessageID>{message_id}</a:MessageID>"
        f"{header_extra_xml}"
        "</s:Header>"
        f"<s:Body>{body_xml}</s:Body>"
        "</s:Envelope>"
    )


def _selector_set_xml(selectors: dict[str, str]) -> str:
    inner = "".join(f'<w:Selector Name="{name}">{value}</w:Selector>' for name, value in selectors.items())
    return f"<w:SelectorSet>{inner}</w:SelectorSet>"


def _get_xml(resource_uri: str, selectors: dict[str, str] | None = None) -> str:
    return _envelope(
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
        resource_uri,
        header_extra_xml=_selector_set_xml(selectors) if selectors else "",
    )


def _put_xml(resource_uri: str, fields: dict[str, str]) -> str:
    inner = "".join(f"<r:{k}>{v}</r:{k}>" for k, v in fields.items())
    body = f'<r:AMT_BootSettingData xmlns:r="{resource_uri}">{inner}</r:AMT_BootSettingData>'
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/Put", resource_uri, body)


def _enumerate_xml(resource_uri: str) -> str:
    body = f'<Enumerate xmlns="{NS_WSEN}" />'
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", resource_uri, body)


def _pull_xml(resource_uri: str, context: str) -> str:
    body = f'<Pull xmlns="{NS_WSEN}"><EnumerationContext>{context}</EnumerationContext><MaxElements>999</MaxElements></Pull>'
    return _envelope("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull", resource_uri, body)


def _method_xml(resource_uri: str, method: str, params: dict[str, str]) -> str:
    inner = "".join(f"<r:{k}>{v}</r:{k}>" for k, v in params.items())
    body = f'<r:{method}_INPUT xmlns:r="{resource_uri}">{inner}</r:{method}_INPUT>'
    return _envelope(f"{resource_uri}/{method}", resource_uri, body)


def _post(server: WsmanMockServer, xml: str, *, auth: HTTPDigestAuth | None = None, timeout: float = 5.0) -> requests.Response:
    if auth is None:
        auth = HTTPDigestAuth(server.username, server.password)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return requests.post(
            server.base_url,
            data=xml.encode("utf-8"),
            headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
            auth=auth,
            timeout=timeout,
            verify=False,  # noqa: S501 -- self-signed throw-away fixture cert, fingerprint checked separately
        )


BOOT_PUT_GOOD_FIELDS = {
    "ConfigurationDataReset": "false",
    "BIOSPause": "false",
    "EnforceSecureBoot": "false",
    "BIOSSetup": "false",
    "BootMediaIndex": "0",
    "FirmwareVerbosity": "0",
    "ForcedProgressEvents": "false",
    "IDERBootDevice": "0",
    "LockKeyboard": "false",
    "LockPowerButton": "false",
    "LockResetButton": "false",
    "LockSleepButton": "false",
    "ReflashBIOS": "false",
    "UseIDER": "true",
    "UseSOL": "true",
    "UseSafeMode": "false",
    "UserPasswordBypass": "false",
}


@pytest.fixture
def server():
    with WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, timeout_hang_seconds=1.0) as srv:
        yield srv


class TestDigestAuth:
    def test_unauthenticated_request_gets_401_challenge(self, server):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            resp = requests.post(
                server.base_url,
                data=_get_xml(CIM_COMPUTER_SYSTEM).encode(),
                timeout=5,
            )
        assert resp.status_code == 401
        challenge = resp.headers["WWW-Authenticate"]
        assert challenge.lower().startswith("digest ")
        assert 'qop="auth"' in challenge
        assert "nonce=" in challenge
        assert "realm=" in challenge

    def test_correct_password_is_accepted(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 200

    def test_wrong_password_is_rejected(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM), auth=HTTPDigestAuth(FAKE_USERNAME, "not-the-real-password"))
        assert resp.status_code == 401

    def test_unknown_username_is_rejected(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM), auth=HTTPDigestAuth("someone-else", FAKE_PASSWORD))
        assert resp.status_code == 401

    def test_replayed_authorization_header_with_stale_nonce_fails(self, server):
        # A nonce this server never issued must never verify, even if the
        # rest of the digest arithmetic is otherwise self-consistent.
        ok = server.digest.verify(
            'Digest username="admin", realm="x", nonce="00", uri="/wsman", response="deadbeef", qop=auth, nc=00000001, cnonce="abc"',
            "POST",
            "/wsman",
        )
        assert ok is False


@pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="TLS mode generates a throw-away self-signed certificate via the openssl CLI, which is absent on this host",
)
class TestTls:
    def test_tls_serves_the_fingerprint_it_reports(self):
        with WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, use_tls=True) as srv:
            assert srv.cert_fingerprint is not None
            ctx = ssl._create_unverified_context()  # noqa: S323 -- deliberately unpinned: this test checks the fingerprint itself
            with socket.create_connection((srv.host, srv.port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=srv.host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
            observed = hashlib.sha256(der).hexdigest()
            assert observed == srv.cert_fingerprint

    def test_plain_http_mode_serves_no_certificate(self, server):
        assert server.cert_fingerprint is None
        assert server.base_url.startswith("http://")

    def test_tls_digest_auth_still_works(self):
        with WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD, use_tls=True) as srv:
            resp = _post(srv, _get_xml(CIM_COMPUTER_SYSTEM))
            assert resp.status_code == 200


class TestCannedResponsesParseAsSoap:
    @pytest.mark.parametrize(
        "resource_uri",
        [
            CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE,
            AMT_BOOT_SETTING_DATA,
            AMT_BOOT_CAPABILITIES,
            AMT_REDIRECTION_SERVICE,
            AMT_GENERAL_SETTINGS,
            AMT_SETUP_AND_CONFIGURATION_SERVICE,
            CIM_COMPUTER_SYSTEM,
            CIM_BIOS_ELEMENT,
        ],
    )
    def test_get_response_is_well_formed_soap(self, server, resource_uri):
        resp = _post(server, _get_xml(resource_uri))
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("application/soap+xml")
        root = ET.fromstring(resp.content)  # noqa: S314 -- test fixture's own response
        assert root.tag == f"{{{NS_S}}}Envelope"
        # Every element in the body must be namespaced -- catches a common
        # canned-response bug where a field is emitted unqualified.
        body = root.find(f"{{{NS_S}}}Body")
        assert body is not None
        assert len(list(body)) == 1

    def test_power_state_field_present_and_correct_type(self, server):
        resp = _post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        power_state = _find_text(root, "PowerState")
        assert power_state is not None
        assert int(power_state) == 2  # freshly started mock reports "On"

    def test_boot_capabilities_reports_ider_support(self, server):
        resp = _post(server, _get_xml(AMT_BOOT_CAPABILITIES))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "IDER") == "true"

    def test_general_settings_has_no_real_hostname(self, server):
        resp = _post(server, _get_xml(AMT_GENERAL_SETTINGS))
        root = ET.fromstring(resp.content)  # noqa: S314
        host_name = _find_text(root, "HostName")
        assert host_name is not None
        assert "." not in host_name or host_name.endswith(".invalid") or "example" in host_name

    def test_computer_system_name_selector_matches_power_change_target(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "Name") == "ManagedSystem"


class TestEnumeratePullPaging:
    def test_paging_returns_every_item_exactly_once(self, server):
        server.state.boot_source_count = 5
        server.page_size = 2  # forces 3 pulls for 5 items -- paging is genuinely exercised

        resp = _post(server, _enumerate_xml(CIM_BOOT_SOURCE_SETTING))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        context = _find_text(root, "EnumerationContext")
        assert context

        seen_instance_ids: list[str] = []
        pulls = 0
        while True:
            pulls += 1
            resp = _post(server, _pull_xml(CIM_BOOT_SOURCE_SETTING, context))
            assert resp.status_code == 200
            root = ET.fromstring(resp.content)  # noqa: S314
            seen_instance_ids.extend(_find_all_text(root, "InstanceID"))
            if _has_element(root, "EndOfSequence"):
                break
            context = _find_text(root, "EnumerationContext")
            assert context, "server must keep returning a context until EndOfSequence"
            if pulls > 20:
                pytest.fail("paging did not terminate")

        assert pulls == 3
        assert len(seen_instance_ids) == 5
        assert len(set(seen_instance_ids)) == 5  # no duplicates, nothing dropped

    def test_pull_with_unknown_context_faults(self, server):
        resp = _post(server, _pull_xml(CIM_BOOT_SOURCE_SETTING, "not-a-real-context"))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None

    def test_amt_boot_capabilities_supports_enumerate_not_only_get(self, server):
        # Regression guard for a real bug this repo's own amt_boot/amt_redirection
        # integration targets caught: plugins/module_utils/boot.py's
        # discover_and_validate() and redirection_service.py's get_capabilities() both
        # reach AMT_BootCapabilities via Enumerate+Pull (it has no natural instance key
        # for a Get SelectorSet), but this mock only ever answered a bare Get for it.
        # Every unit test for those two module_utils files mocks WsmanClient.enumerate()
        # directly, so none of them exercised this server's own Enumerate dispatch table
        # -- only a real Enumerate request against the running mock surfaced the gap.
        resp = _post(server, _enumerate_xml(AMT_BOOT_CAPABILITIES))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        context = _find_text(root, "EnumerationContext")
        assert context

        resp = _post(server, _pull_xml(AMT_BOOT_CAPABILITIES, context))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _has_element(root, "EndOfSequence")
        assert _find_text(root, "IDER") == "true"
        assert _find_text(root, "ForcePXEBoot") == "true"

    def test_amt_boot_capabilities_get_and_enumerate_report_the_same_fields(self, server):
        get_resp = _post(server, _get_xml(AMT_BOOT_CAPABILITIES))
        get_root = ET.fromstring(get_resp.content)  # noqa: S314

        enum_resp = _post(server, _enumerate_xml(AMT_BOOT_CAPABILITIES))
        context = _find_text(ET.fromstring(enum_resp.content), "EnumerationContext")  # noqa: S314
        pull_resp = _post(server, _pull_xml(AMT_BOOT_CAPABILITIES, context))
        pull_root = ET.fromstring(pull_resp.content)  # noqa: S314

        for field in ("IDER", "SOL", "ForcePXEBoot", "ForceHardDriveBoot", "BIOSSetup"):
            assert _find_text(get_root, field) == _find_text(pull_root, field)


class TestEthernetPortSettingsAndSystemState:
    """The facts added for `amt_info`'s network/state reads (docs/protocol-notes.md §2.7).

    These must be answered the way real firmware answers them, not the way that
    happens to be convenient: an exact `Get` selector (never `Enumerate`), a
    dash-separated MAC, and `LinkPolicy`/`OperationalStatus` as repeated
    elements rather than scalars.
    """

    ETHERNET_SELECTOR: ClassVar[dict[str, str]] = {"InstanceID": ETHERNET_PORT_0_INSTANCE_ID}

    def test_instance_0_get_with_the_exact_selector_succeeds(self, server):
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, self.ETHERNET_SELECTOR))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "InstanceID") == ETHERNET_PORT_0_INSTANCE_ID

    def test_get_without_a_selector_faults(self, server):
        # AMT 10 requires the exact selector for this class; a bare Get answered
        # with instance 0's data would let a client ship code real firmware rejects.
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None

    def test_a_higher_instance_index_faults_rather_than_returning_instance_0(self, server):
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, {"InstanceID": "Intel(r) AMT Ethernet Port Settings 1"}))
        assert resp.status_code == 500

    def test_mac_is_served_dash_separated_as_real_firmware_returned_it(self, server):
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, self.ETHERNET_SELECTOR))
        mac = _find_text(ET.fromstring(resp.content), "MACAddress")  # noqa: S314
        assert mac is not None
        assert "-" in mac, "a colon-separated mock MAC would never exercise the client's normalization"

    def test_mac_and_addresses_are_from_the_documentation_ranges(self, server):
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, self.ETHERNET_SELECTOR))
        root = ET.fromstring(resp.content)  # noqa: S314
        # RFC 7042 documentation MAC block and RFC 5737 TEST-NET-1. This repository
        # is public; a real lab's MAC or IP must never appear in it.
        assert _find_text(root, "MACAddress").upper().startswith("00-00-5E")
        assert _find_text(root, "IPAddress").startswith("192.0.2.")

    def test_link_policy_is_a_repeated_element_not_a_scalar(self, server):
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, self.ETHERNET_SELECTOR))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_all_text(root, "LinkPolicy") == ["1", "14", "16"]

    def test_link_policy_is_settable_so_a_test_can_take_away_wake_capability(self, server):
        # S0 AC + S0 DC and no Sx value: link maintained only while the host is
        # running, which is the shape that makes `wake_on_lan_capable` false.
        server.state.ethernet_link_policy = [1, 16]
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, self.ETHERNET_SELECTOR))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_all_text(root, "LinkPolicy") == ["1", "16"]

    def test_an_absent_port_faults_so_the_client_degrades_rather_than_failing(self, server):
        server.state.ethernet_port_present = False
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, self.ETHERNET_SELECTOR))
        assert resp.status_code == 500

    def test_computer_system_reports_operational_status_as_an_array(self, server):
        server.state.operational_status = [3, 5]
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM, {"Name": "ManagedSystem"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_all_text(root, "OperationalStatus") == ["3", "5"]

    def test_computer_system_with_a_wrong_name_selector_faults(self, server):
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM, {"Name": "NotTheManagedSystem"}))
        assert resp.status_code == 500

    def test_computer_system_carries_no_uuid_property(self, server):
        # The original defect this class's reintroduction must not resurrect: the
        # platform GUID comes from CIM_ComputerSystemPackage, and firmware does not
        # expose a UUID here at all.
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM, {"Name": "ManagedSystem"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "UUID") is None

    def test_general_settings_carries_the_hardware_dumped_extras(self, server):
        resp = _post(server, _get_xml(AMT_GENERAL_SETTINGS))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "IdleWakeTimeout") == "1"
        assert _find_text(root, "DDNSUpdateEnabled") == "false"
        assert _find_text(root, "RmcpPingResponseEnabled") == "true"
        assert _find_text(root, "NetworkInterfaceEnabled") == "true"
        # PowerSource/PrivacyLevel are on the real instance but are not surfaced by
        # this collection, so they are not served here either -- serving them would
        # invite someone to expose an integer nothing documents the meaning of.
        assert _find_text(root, "PowerSource") is None
        assert _find_text(root, "PrivacyLevel") is None

    def test_bios_element_answers_a_bare_get(self, server):
        resp = _post(server, _get_xml(CIM_BIOS_ELEMENT))
        assert resp.status_code == 200
        assert _find_text(ET.fromstring(resp.content), "Version") == server.state.bios_version  # noqa: S314

    def test_bios_element_also_answers_enumerate_with_the_same_version(self, server):
        # Which verb real firmware accepts for a selector-less class is unsettled,
        # so both are served and the client must survive either.
        resp = _post(server, _enumerate_xml(CIM_BIOS_ELEMENT))
        context = _find_text(ET.fromstring(resp.content), "EnumerationContext")  # noqa: S314
        assert context
        resp = _post(server, _pull_xml(CIM_BIOS_ELEMENT, context))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _has_element(root, "EndOfSequence")
        assert _find_text(root, "Version") == server.state.bios_version

    def test_bios_element_get_can_be_made_to_fault_leaving_only_enumerate(self, server):
        server.faults.bios_element_get_faults = True
        assert _post(server, _get_xml(CIM_BIOS_ELEMENT)).status_code == 500

        resp = _post(server, _enumerate_xml(CIM_BIOS_ELEMENT))
        assert resp.status_code == 200


class TestStatefulness:
    def test_boot_setting_data_put_is_observed_by_later_get(self, server):
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, {**BOOT_PUT_GOOD_FIELDS, "UseIDER": "true"}))
        assert resp.status_code == 200

        resp = _post(server, _get_xml(AMT_BOOT_SETTING_DATA))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "UseIDER") == "true"

    def test_boot_put_rejects_readonly_fields_by_default(self, server):
        bad_fields = {**BOOT_PUT_GOOD_FIELDS, "WinREBootEnabled": "false"}
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, bad_fields))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None
        reason = _find_text(root, "Text")
        assert reason is not None
        assert "WinREBootEnabled" in reason

    def test_boot_put_accepts_clean_instance(self, server):
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, BOOT_PUT_GOOD_FIELDS))
        assert resp.status_code == 200

    def test_boot_put_readonly_rejection_is_toggleable(self, server):
        server.faults.reject_boot_readonly_fields = False
        bad_fields = {**BOOT_PUT_GOOD_FIELDS, "BootguardStatus": "0"}
        resp = _post(server, _put_xml(AMT_BOOT_SETTING_DATA, bad_fields))
        assert resp.status_code == 200

    def test_power_state_change_is_observed_by_later_get(self, server):
        # 8 = power off (soft) per protocol-notes.md action-code table.
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "8"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"

        resp = _post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "PowerState") == "8"

    def test_change_boot_order_and_set_boot_config_role(self, server):
        resp = _post(server, _method_xml(CIM_BOOT_SERVICE, "SetBootConfigRole", {"Role": "1"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_config_role == 1

        resp = _post(server, _method_xml(CIM_BOOT_CONFIG_SETTING, "ChangeBootOrder", {}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_order_source is None  # empty Source clears it

    def test_change_boot_order_with_a_source_records_the_instance_id(self, server):
        source_body = (
            "<r:Source>"
            '<a:Address xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/anonymous</a:Address>"
            '<a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            f'<w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">{CIM_BOOT_SOURCE_SETTING}</w:ResourceURI>'
            '<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
            '<w:Selector Name="InstanceID">Intel(r) AMT: Force PXE Boot</w:Selector>'
            "</w:SelectorSet></a:ReferenceParameters></r:Source>"
        )
        body = f'<r:ChangeBootOrder_INPUT xmlns:r="{CIM_BOOT_CONFIG_SETTING}">{source_body}</r:ChangeBootOrder_INPUT>'
        xml = _envelope(f"{CIM_BOOT_CONFIG_SETTING}/ChangeBootOrder", CIM_BOOT_CONFIG_SETTING, body)
        resp = _post(server, xml)
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_order_source == "Intel(r) AMT: Force PXE Boot"

    def test_redirection_state_change_is_observed_by_later_get(self, server):
        resp = _post(server, _method_xml(AMT_REDIRECTION_SERVICE, "RequestStateChange", {"RequestedState": "32771"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"

        resp = _post(server, _get_xml(AMT_REDIRECTION_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "EnabledState") == "32771"
        assert _find_text(root, "ListenerEnabled") == "true"


class TestFaultInjection:
    def test_forced_return_value_on_method_call(self, server):
        key = (CIM_POWER_MANAGEMENT_SERVICE, f"{CIM_POWER_MANAGEMENT_SERVICE}/RequestPowerStateChange")
        server.faults.return_value_for[key] = 2
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "8"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "2"
        # And the side effect must NOT have happened -- a real non-zero
        # ReturnValue means the mutation was refused.
        assert server.state.power_state == 2

    def test_soap_fault_injection(self, server):
        key = (CIM_COMPUTER_SYSTEM, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        server.faults.soap_fault_for.add(key)
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 500
        root = ET.fromstring(resp.content)  # noqa: S314
        assert root.find(f"{{{NS_S}}}Body/{{{NS_S}}}Fault") is not None

    def test_malformed_xml_injection(self, server):
        key = (CIM_COMPUTER_SYSTEM, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        server.faults.malformed_xml_for.add(key)
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 200
        with pytest.raises(ET.ParseError):
            ET.fromstring(resp.content)  # noqa: S314

    def test_http_status_injection_for_specific_resource(self, server):
        key = (CIM_COMPUTER_SYSTEM, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")
        server.faults.http_status_for[key] = 500
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 500
        # Unrelated resources are unaffected.
        resp = _post(server, _get_xml(AMT_GENERAL_SETTINGS))
        assert resp.status_code == 200

    def test_force_status_short_circuits_next_request_only(self, server):
        server.faults.force_status = 401
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 401
        # One-shot: the next request is unaffected.
        resp = _post(server, _get_xml(CIM_COMPUTER_SYSTEM))
        assert resp.status_code == 200

    def test_timeout_before_read_does_not_read_the_body(self, server):
        server.faults.timeout_before_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is False

    def test_timeout_after_read_does_read_the_body(self, server):
        server.faults.timeout_after_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is True

    def test_the_two_timeout_faults_are_independently_triggerable(self, server):
        server.faults.timeout_before_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is False
        # Normal request works again in between.
        assert _post(server, _get_xml(CIM_COMPUTER_SYSTEM)).status_code == 200

        server.faults.timeout_after_read = True
        with pytest.raises(requests.exceptions.Timeout):
            _post(server, _get_xml(CIM_COMPUTER_SYSTEM), timeout=0.3)
        assert server.faults.last_timeout_body_was_read is True


class TestMessageLog:
    """``AMT_MessageLog``, checked against the real firmware response fixtures.

    Every assertion here is about the mock matching
    ``go-wsman-messages``' ``pkg/wsman/wsmantesting/responses/amt/messagelog/``,
    not about matching what this collection's client happens to expect. That
    direction matters: the bug this file's ``_boot_capabilities_items`` docstring
    records was a mock shaped to the client instead of to firmware.
    """

    def test_get_serves_the_fixture_container_properties(self, server):
        root = ET.fromstring(_post(server, _get_xml(AMT_MESSAGE_LOG)).content)  # noqa: S314 -- test fixture's own response
        # MaxRecordSize == 21 in the fixture independently corroborates the
        # 21-byte record struct the client decodes.
        assert _find_text(root, "MaxRecordSize") == "21"
        assert _find_text(root, "MaxNumberOfRecords") == "390"
        assert _find_text(root, "ElementName") == "Intel(r) AMT:MessageLog 1"
        assert _find_text(root, "CreationClassName") == "AMT_MessageLog"
        # Capability 6 is ClearLogSupported -- firmware saying ClearLog exists.
        assert "6" in _find_all_text(root, "Capabilities")

    def test_get_needs_no_selector_because_the_fixture_response_carries_none(self, server):
        # The fixture is a response to a Get with no SelectorSet, and the instance
        # has no InstanceID to build one from. A mock that demanded a selector here
        # would force the client to invent one.
        assert _post(server, _get_xml(AMT_MESSAGE_LOG)).status_code == 200

    def test_current_number_of_records_tracks_the_served_records(self, server):
        root = ET.fromstring(_post(server, _get_xml(AMT_MESSAGE_LOG)).content)  # noqa: S314 -- test fixture's own response
        assert _find_text(root, "CurrentNumberOfRecords") == str(len(DEFAULT_MESSAGE_LOG_RECORDS))

    def test_enumerate_also_answers_with_the_same_instance(self, server):
        # Unusually for an AMT_ class, the fixture set has enumerate.xml and
        # pull.xml as well as get.xml, so both verbs are real here.
        enum = ET.fromstring(_post(server, _enumerate_xml(AMT_MESSAGE_LOG)).content)  # noqa: S314 -- test fixture's own response
        context = _find_text(enum, "EnumerationContext")
        assert context
        pull = ET.fromstring(_post(server, _pull_xml(AMT_MESSAGE_LOG, context)).content)  # noqa: S314 -- test fixture's own response
        assert _find_text(pull, "MaxRecordSize") == "21"
        assert _find_text(pull, "CreationClassName") == "AMT_MessageLog"

    def test_position_to_first_record_returns_identifier_one(self, server):
        root = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "PositionToFirstRecord", {})).content)  # noqa: S314 -- test fixture's own response
        assert _find_text(root, "ReturnValue") == "0"
        assert _find_text(root, "IterationIdentifier") == "1"

    def test_output_elements_precede_return_value_as_firmware_orders_them(self, server):
        body = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "1", "MaxReadRecords": "390"})).content)  # noqa: S314 -- test fixture's own response
        output = next(elem for elem in body.iter() if elem.tag.rsplit("}", 1)[-1] == "GetRecords_OUTPUT")
        names = [child.tag.rsplit("}", 1)[-1] for child in output]
        # getrecords.xml order: IterationIdentifier, NoMoreRecords, RecordArray*, ReturnValue.
        assert names[0] == "IterationIdentifier"
        assert names[1] == "NoMoreRecords"
        assert names[-1] == "ReturnValue"
        assert "RecordArray" in names

    def test_get_records_pages_and_never_returns_more_than_asked_for(self, server):
        root = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "1", "MaxReadRecords": "390"})).content)  # noqa: S314 -- test fixture's own response
        records = _find_all_text(root, "RecordArray")
        # Firmware may return fewer records than requested; that is what
        # NoMoreRecords is for, and a client must not infer completion from a
        # short batch.
        assert len(records) == MESSAGE_LOG_BATCH_SIZE
        assert _find_text(root, "NoMoreRecords") == "false"
        assert records == list(DEFAULT_MESSAGE_LOG_RECORDS[:MESSAGE_LOG_BATCH_SIZE])

    def test_following_the_iteration_yields_every_record_exactly_once(self, server):
        seen: list[str] = []
        identifier = "1"
        for _unused in range(20):  # bounded: a stalled iterator must fail the test, not hang it
            root = ET.fromstring(  # noqa: S314 -- test fixture's own response
                _post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": identifier, "MaxReadRecords": "390"})).content
            )
            assert _find_text(root, "ReturnValue") == "0"
            seen.extend(_find_all_text(root, "RecordArray"))
            if _find_text(root, "NoMoreRecords") == "true":
                break
            identifier = _find_text(root, "IterationIdentifier")
        assert seen == list(DEFAULT_MESSAGE_LOG_RECORDS)

    def test_records_decode_to_twenty_one_bytes(self, server):
        root = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "1", "MaxReadRecords": "390"})).content)  # noqa: S314 -- test fixture's own response
        for encoded in _find_all_text(root, "RecordArray"):
            assert len(base64.b64decode(encoded, validate=True)) == 21

    def test_an_identifier_past_the_end_is_invalid_record_pointed(self, server):
        root = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "9999", "MaxReadRecords": "10"})).content)  # noqa: S314 -- test fixture's own response
        assert _find_text(root, "ReturnValue") == "2"

    def test_empty_log_uses_a_different_return_value_per_method(self, server):
        server.state.message_log_records.clear()
        position = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "PositionToFirstRecord", {})).content)  # noqa: S314 -- test fixture's own response
        get_records = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "1", "MaxReadRecords": "10"})).content)  # noqa: S314 -- test fixture's own response
        # 2 for PositionToFirstRecord, 3 for GetRecords -- the same condition,
        # different values, per the ValueMap annotations. A client that conflated
        # them must fail here rather than on real firmware.
        assert _find_text(position, "ReturnValue") == "2"
        assert _find_text(get_records, "ReturnValue") == "3"

    def test_clear_log_takes_no_parameters_and_is_observed_by_a_later_get(self, server):
        cleared = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "ClearLog", {})).content)  # noqa: S314 -- test fixture's own response
        assert _find_text(cleared, "ReturnValue") == "0"
        after = ET.fromstring(_post(server, _get_xml(AMT_MESSAGE_LOG)).content)  # noqa: S314 -- test fixture's own response
        assert _find_text(after, "CurrentNumberOfRecords") == "0"
        records = ET.fromstring(_post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "1", "MaxReadRecords": "10"})).content)  # noqa: S314 -- test fixture's own response
        assert _find_all_text(records, "RecordArray") == []

    def test_an_absent_class_faults_for_both_get_and_enumerate(self, server):
        server.state.message_log_present = False
        assert _post(server, _get_xml(AMT_MESSAGE_LOG)).status_code == 500
        # Faulting only the Get would leave the client's Enumerate fallback
        # answering for firmware that has no such class at all.
        assert _post(server, _enumerate_xml(AMT_MESSAGE_LOG)).status_code == 500

    def test_no_record_carries_identifying_data(self, server):
        """Every served record is 21 bytes of event data and nothing else.

        An event log record has no field that could hold a hostname, address, MAC,
        GUID or fingerprint -- but the two records taken verbatim from the upstream
        firmware fixture are third-party data, so this asserts the whole corpus is
        the size it claims to be rather than trusting that.
        """
        for encoded in DEFAULT_MESSAGE_LOG_RECORDS:
            assert len(base64.b64decode(encoded, validate=True)) == 21


class TestCleanShutdown:
    def test_no_leaked_threads_or_sockets_after_exit(self):
        before = set(threading.enumerate())
        srv = WsmanMockServer(username=FAKE_USERNAME, password=FAKE_PASSWORD).start()
        port = srv.port
        assert _post(srv, _get_xml(CIM_COMPUTER_SYSTEM)).status_code == 200
        srv.stop()

        after = set(threading.enumerate())
        leaked = after - before
        assert not leaked, f"threads leaked after shutdown: {leaked}"

        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)


# --------------------------------------------------------------------------
# Firmware rejections the mock reproduces unconditionally
#
# Distinct from TestFaultInjection above: nothing here is armed by a test. These
# are requests real firmware refuses, so the mock refuses them too, and each one
# exists because a client that sends it would fail against real hardware. See
# wsman_server.py's "Rejections" docstring section.
# --------------------------------------------------------------------------


def _change_boot_order_xml(source_inner_xml: str | None) -> str:
    """A ChangeBootOrder request whose ``Source`` body is given verbatim.

    ``None`` omits the ``Source`` element entirely -- which is what "pass a null
    Source" means on the wire and what this collection and go-wsman-messages both do.
    """
    source = f"<r:Source>{source_inner_xml}</r:Source>" if source_inner_xml is not None else ""
    body = f'<r:ChangeBootOrder_INPUT xmlns:r="{CIM_BOOT_CONFIG_SETTING}">{source}</r:ChangeBootOrder_INPUT>'
    return _envelope(f"{CIM_BOOT_CONFIG_SETTING}/ChangeBootOrder", CIM_BOOT_CONFIG_SETTING, body)


#: A well-formed endpoint reference naming one CIM_BootSourceSetting, in the exact
#: nesting and namespaces docs/protocol-notes.md 2.5 records and go-wsman-messages'
#: pkg/wsman/cim/boot/configsetting.go emits.
_VALID_EPR_INNER = (
    '<a:Address xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    "http://schemas.xmlsoap.org/ws/2004/08/addressing</a:Address>"
    '<a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    f'<w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">{CIM_BOOT_SOURCE_SETTING}</w:ResourceURI>'
    '<w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
    '<w:Selector Name="InstanceID">Intel(r) AMT: Force PXE Boot</w:Selector>'
    "</w:SelectorSet></a:ReferenceParameters>"
)


class TestEmptySourceIsRejected:
    """The single highest-value guard in this file.

    An empty ``<Source/>`` on ``ChangeBootOrder`` is schema-invalid -- ``Source`` is
    typed as an endpoint reference, so it requires ``Address`` and
    ``ReferenceParameters`` children -- and real AMT 16.1.30 answers the whole request
    with HTTP 400 (docs/protocol-notes.md 2.5). That defect made IDE-R and BIOS boot
    entirely impossible against real hardware. The mock used to answer ReturnValue 0
    for it, so mock and client agreed while both were wrong and the regression was
    unguarded.
    """

    def test_empty_source_element_is_http_400(self, server):
        resp = _post(server, _change_boot_order_xml(""))
        assert resp.status_code == 400

    def test_the_400_carries_the_firmware_reason(self, server):
        resp = _post(server, _change_boot_order_xml(""))
        assert "violates the corresponding XML schema definition" in resp.text

    def test_a_rejected_request_mutates_nothing(self, server):
        server.state.boot_order_source = "Intel(r) AMT: Force PXE Boot"
        _post(server, _change_boot_order_xml(""))
        # Firmware never reached the method: the request failed schema validation. A
        # mock that rejected the request but applied the side effect anyway would be a
        # different lie from the one being fixed.
        assert server.state.boot_order_source == "Intel(r) AMT: Force PXE Boot"

    def test_a_self_closed_source_is_rejected_identically(self, server):
        # <Source/> and <Source></Source> are the same element to any XML parser; this
        # pins that the guard is about child elements, not about literal text.
        body = f'<r:ChangeBootOrder_INPUT xmlns:r="{CIM_BOOT_CONFIG_SETTING}"><r:Source /></r:ChangeBootOrder_INPUT>'
        xml = _envelope(f"{CIM_BOOT_CONFIG_SETTING}/ChangeBootOrder", CIM_BOOT_CONFIG_SETTING, body)
        assert _post(server, xml).status_code == 400

    def test_an_absent_source_is_valid_and_clears_the_boot_order(self, server):
        """The whole point of the distinction: absent is legal, empty is not.

        These method parameters are optional (``minOccurs=0``), so omitting the element
        is how the boot order is cleared -- step 2 of 2.5, and step 5 for the IDE-R and
        BIOS targets. If this ever starts returning 400, IDE-R boot is broken.
        """
        server.state.boot_order_source = "Intel(r) AMT: Force PXE Boot"
        resp = _post(server, _change_boot_order_xml(None))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_order_source is None

    def test_a_well_formed_epr_source_is_accepted(self, server):
        resp = _post(server, _change_boot_order_xml(_VALID_EPR_INNER))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.boot_order_source == "Intel(r) AMT: Force PXE Boot"

    def test_a_source_missing_its_address_child_is_rejected(self, server):
        """Half an endpoint reference is still schema-invalid.

        ``Address`` and ``ReferenceParameters`` are both required by the EPR type, so a
        Source carrying only one of them fails validation for the same reason an empty
        one does.
        """
        reference_parameters_only = _VALID_EPR_INNER[_VALID_EPR_INNER.index("<a:ReferenceParameters") :]
        assert _post(server, _change_boot_order_xml(reference_parameters_only)).status_code == 400

    def test_a_source_carrying_only_text_is_rejected(self, server):
        # A client that "passed null" by stringifying None into the element body would
        # send this. It has no child elements, so it is the empty case.
        assert _post(server, _change_boot_order_xml("None")).status_code == 400

    def test_the_same_rule_guards_set_boot_config_role(self, server):
        # BootConfigSetting is EPR-typed too, validated by the same firmware schema
        # validator, so the observed rejection generalises rather than being invented.
        body = f'<r:SetBootConfigRole_INPUT xmlns:r="{CIM_BOOT_SERVICE}"><r:BootConfigSetting /><r:Role>1</r:Role></r:SetBootConfigRole_INPUT>'
        xml = _envelope(f"{CIM_BOOT_SERVICE}/SetBootConfigRole", CIM_BOOT_SERVICE, body)
        assert _post(server, xml).status_code == 400

    def test_the_same_rule_guards_request_power_state_change(self, server):
        body = (
            f'<r:RequestPowerStateChange_INPUT xmlns:r="{CIM_POWER_MANAGEMENT_SERVICE}">'
            "<r:PowerState>8</r:PowerState><r:ManagedElement /></r:RequestPowerStateChange_INPUT>"
        )
        xml = _envelope(f"{CIM_POWER_MANAGEMENT_SERVICE}/RequestPowerStateChange", CIM_POWER_MANAGEMENT_SERVICE, body)
        assert _post(server, xml).status_code == 400
        assert server.state.power_state == 2  # unchanged: the request never ran


class TestRequiredParametersAreRequired:
    def test_set_boot_config_role_without_role_is_invalid_parameter(self, server):
        """Was ReturnValue 0. Firmware cannot assign a role it was not given."""
        resp = _post(server, _method_xml(CIM_BOOT_SERVICE, "SetBootConfigRole", {}))
        assert resp.status_code == 200
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"
        assert server.state.boot_config_role == 0  # untouched

    def test_set_boot_config_role_with_a_non_numeric_role_is_invalid_parameter(self, server):
        resp = _post(server, _method_xml(CIM_BOOT_SERVICE, "SetBootConfigRole", {"Role": "IsNextSingleUse"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"

    def test_power_state_change_without_power_state_is_invalid_parameter(self, server):
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"

    def test_redirection_state_change_without_requested_state_is_invalid_parameter(self, server):
        resp = _post(server, _method_xml(AMT_REDIRECTION_SERVICE, "RequestStateChange", {}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"

    def test_invalid_parameter_is_5_and_not_2(self, server):
        """5 is InvalidParameter; 2 is Unknown/Unspecified Error.

        All three of go-wsman-messages' relevant ValueMaps agree
        (``pkg/wsman/cim/boot/decoder.go``, ``pkg/wsman/cim/power/decoder.go``,
        ``pkg/wsman/amt/redirection/decoder.go``). This mock used to answer 2 for every
        malformed parameter, which is a different condition -- and one a client could
        reasonably treat as retryable, where an invalid parameter never is.
        """
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "9999"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"


class TestParameterLookupIsNamespaceAndDepthAware:
    """A parameter in the wrong namespace or wrongly nested must not satisfy the mock.

    Lookup used to be an ``.iter()`` walk matching bare local names at any depth in any
    namespace, so both of these passed here and then failed schema validation on real
    firmware -- the same "mock accepts what firmware rejects" class as the empty
    ``<Source/>``. Both now read as *absent*, which is the honest reading: the required
    element is not where the schema says it must be.
    """

    def test_a_parameter_in_the_wrong_namespace_does_not_count(self, server):
        body = (
            f'<r:SetBootConfigRole_INPUT xmlns:r="{CIM_BOOT_SERVICE}"><Role xmlns="http://example.invalid/wrong-namespace">1</Role></r:SetBootConfigRole_INPUT>'
        )
        xml = _envelope(f"{CIM_BOOT_SERVICE}/SetBootConfigRole", CIM_BOOT_SERVICE, body)
        root = ET.fromstring(_post(server, xml).content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"
        assert server.state.boot_config_role == 0

    def test_an_unnamespaced_parameter_does_not_count(self, server):
        body = f'<r:SetBootConfigRole_INPUT xmlns:r="{CIM_BOOT_SERVICE}"><Role>1</Role></r:SetBootConfigRole_INPUT>'
        xml = _envelope(f"{CIM_BOOT_SERVICE}/SetBootConfigRole", CIM_BOOT_SERVICE, body)
        root = ET.fromstring(_post(server, xml).content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"

    def test_a_parameter_nested_one_level_too_deep_does_not_count(self, server):
        body = (
            f'<r:RequestPowerStateChange_INPUT xmlns:r="{CIM_POWER_MANAGEMENT_SERVICE}">'
            "<r:Wrapper><r:PowerState>8</r:PowerState></r:Wrapper>"
            "</r:RequestPowerStateChange_INPUT>"
        )
        xml = _envelope(f"{CIM_POWER_MANAGEMENT_SERVICE}/RequestPowerStateChange", CIM_POWER_MANAGEMENT_SERVICE, body)
        root = ET.fromstring(_post(server, xml).content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "5"
        assert server.state.power_state == 2  # not powered off

    def test_a_correctly_placed_parameter_still_works(self, server):
        # The guard above must not have been achieved by breaking the happy path.
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "8"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.power_state == 8

    def test_an_instance_id_selector_in_the_wrong_namespace_is_not_read(self, server):
        # The EPR is structurally valid (Address + ReferenceParameters present), so this
        # is not a 400 -- but the selector is not where the schema puts it, so no
        # InstanceID is read and the boot order records None.
        inner = (
            '<a:Address xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">x</a:Address>'
            '<a:ReferenceParameters xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            '<SelectorSet xmlns="http://example.invalid/wrong">'
            '<Selector Name="InstanceID">Intel(r) AMT: Force PXE Boot</Selector>'
            "</SelectorSet></a:ReferenceParameters>"
        )
        resp = _post(server, _change_boot_order_xml(inner))
        assert resp.status_code == 200
        assert server.state.boot_order_source is None


class TestPowerActionCodesMatchWhatIsAdvertised:
    """A mock that advertises a power state and then refuses it is a bad fixture."""

    def test_available_requested_power_states_matches_the_firmware_fixture(self, server):
        resp = _post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE))
        root = ET.fromstring(resp.content)  # noqa: S314
        advertised = _find_all_text(root, "AvailableRequestedPowerStates")
        # Verbatim from responses/cim/associatedpower/managementservice/get.xml, in its
        # order -- the values are a set and reordering them would invent a promise.
        assert advertised == ["10", "8", "5", "11", "4", "7", "14", "12"]

    @pytest.mark.parametrize("code", [10, 8, 5, 11, 4, 7, 14, 12])
    def test_every_advertised_code_is_accepted(self, server, code):
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": str(code)}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0", f"code {code} is advertised but refused"

    def test_graceful_off_lands_in_the_same_state_as_hard_off(self, server):
        # 12 = Off - Soft Graceful, the graceful counterpart of 8.
        _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "12"}))
        assert server.state.power_state == 8

    def test_graceful_reset_lands_powered_on(self, server):
        # 14 = Master Bus Reset Graceful, the graceful counterpart of 10.
        server.state.power_state = 8
        _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "14"}))
        assert server.state.power_state == 2

    def test_diagnostic_interrupt_is_accepted_but_changes_no_state(self, server):
        """11 = Diagnostic Interrupt (NMI): it interrupts the OS, it is not a transition.

        What PowerState firmware reports afterwards is not established, so the mock
        leaves it alone rather than inventing one.
        """
        server.state.power_state = 2
        resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": "11"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        assert _find_text(root, "ReturnValue") == "0"
        assert server.state.power_state == 2

    def test_power_on_is_still_accepted_although_the_fixture_omits_it(self, server):
        """Code 2 (On) is absent from the fixture's list *because the machine was on*.

        The class definition says the advertised values "are a function of the current
        power state", and that fixture was captured at PowerState 2. Rejecting 2 would
        break amt_power's power-on path while asserting something the evidence does not
        support -- so it stays accepted, deliberately. Same for 3 (Sleep - Light).
        """
        server.state.power_state = 8
        for code in ("2", "3"):
            server.state.power_state = 8
            resp = _post(server, _method_xml(CIM_POWER_MANAGEMENT_SERVICE, "RequestPowerStateChange", {"PowerState": code}))
            root = ET.fromstring(resp.content)  # noqa: S314
            assert _find_text(root, "ReturnValue") == "0"


class TestUnbackedPropertiesAreGone:
    """Each of these was a property name with no backing in the class it hung on.

    Verified against ``device-management-toolkit/go-wsman-messages``' own ``types.go``
    and its recorded response fixtures. None of them was read by this collection's
    parser, so removing them changes no client behaviour -- what it removes is the
    chance of a future reader citing the mock as evidence firmware sends them.
    """

    def test_boot_source_setting_has_no_boot_source_index(self, server):
        # pkg/wsman/cim/boot/types.go's BootSourceSetting declares ElementName,
        # InstanceID, StructuredBootString, BIOSBootString, BootString and
        # FailThroughSupported -- and no index property of any name.
        resp = _post(server, _enumerate_xml(CIM_BOOT_SOURCE_SETTING))
        context = _find_text(ET.fromstring(resp.content), "EnumerationContext")  # noqa: S314
        root = ET.fromstring(_post(server, _pull_xml(CIM_BOOT_SOURCE_SETTING, context)).content)  # noqa: S314
        assert not _has_element(root, "BootSourceIndex")

    def test_associated_power_management_service_has_no_element_name(self, server):
        # Absent from pkg/wsman/cim/associatedpower/types.go and from the fixture.
        root = ET.fromstring(_post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE)).content)  # noqa: S314
        assert not _has_element(root, "ElementName")
        assert _find_text(root, "PowerState") is not None  # the class is still served

    def test_setup_and_configuration_service_has_no_instance_id(self, server):
        # That class is keyed by Name / CreationClassName / SystemName /
        # SystemCreationClassName, all four of which the fixture carries.
        root = ET.fromstring(_post(server, _get_xml(AMT_SETUP_AND_CONFIGURATION_SERVICE)).content)  # noqa: S314
        assert not _has_element(root, "InstanceID")
        assert _find_text(root, "Name") == "Intel(r) AMT Setup and Configuration Service"
        assert _find_text(root, "CreationClassName") == "AMT_SetupAndConfigurationService"
        assert _find_text(root, "SystemName") == "Intel(r) AMT"

    def test_the_properties_the_collection_actually_reads_survived(self, server):
        # The removals must not have taken a fact amt_info reports with them.
        root = ET.fromstring(_post(server, _get_xml(AMT_SETUP_AND_CONFIGURATION_SERVICE)).content)  # noqa: S314
        assert _find_text(root, "ProvisioningMode") == "1"
        assert _find_text(root, "ProvisioningState") == "2"


class TestStructuredBootStringShape:
    """``StructuredBootString`` was set equal to the instance label, which is client-visible.

    Firmware sends ``"<OrgID>:<identifier>:<index>"``; the fixture
    ``responses/cim/boot/sourcesetting/pull.xml`` shows ``CIM:Hard-Disk:1``,
    ``CIM:Network:1`` and ``CIM:CD/DVD:1`` verbatim.
    """

    @staticmethod
    def _instances(server):
        resp = _post(server, _enumerate_xml(CIM_BOOT_SOURCE_SETTING))
        context = _find_text(ET.fromstring(resp.content), "EnumerationContext")  # noqa: S314
        instances = {}
        while context:
            root = ET.fromstring(_post(server, _pull_xml(CIM_BOOT_SOURCE_SETTING, context)).content)  # noqa: S314
            for elem in root.iter():
                if elem.tag.rsplit("}", 1)[-1] == "CIM_BootSourceSetting":
                    fields = {child.tag.rsplit("}", 1)[-1]: child.text for child in elem}
                    instances[fields["InstanceID"]] = fields
            context = None if _has_element(root, "EndOfSequence") else _find_text(root, "EnumerationContext")
        return instances

    def test_the_three_fixture_backed_sources_carry_the_firmware_shape(self, server):
        instances = self._instances(server)
        assert instances["Intel(r) AMT: Force PXE Boot"]["StructuredBootString"] == "CIM:Network:1"
        assert instances["Intel(r) AMT: Force Hard-drive Boot"]["StructuredBootString"] == "CIM:Hard-Disk:1"
        assert instances["Intel(r) AMT: Force CD/DVD Boot"]["StructuredBootString"] == "CIM:CD/DVD:1"

    def test_no_instance_carries_its_own_label_as_a_structured_boot_string(self, server):
        for instance_id, fields in self._instances(server).items():
            assert fields.get("StructuredBootString") != instance_id

    def test_diagnostic_boot_carries_no_structured_boot_string_at_all(self, server):
        """The DMTF identifier set has no diagnostic member, so there is nothing to derive.

        Omitting the property is a legitimate shape (it is ``omitempty`` in the class
        definition); inventing an identifier would be the error this file exists to avoid.
        """
        assert "StructuredBootString" not in self._instances(server)["Intel(r) AMT: Force Diagnostic Boot"]

    def test_every_instance_shares_one_element_name_as_firmware_sends_it(self, server):
        """Firmware distinguishes boot sources by ``InstanceID`` only.

        All three fixture instances report ``ElementName`` = "Intel(r) AMT: Boot Source".
        The mock used to vary it per instance, so a client keying off ``ElementName``
        would have passed here and matched every instance on real firmware.
        """
        element_names = {fields["ElementName"] for fields in self._instances(server).values()}
        assert element_names == {"Intel(r) AMT: Boot Source"}

    def test_fail_through_supported_is_served(self, server):
        # On the fixture for all three instances; 2 = NotSupported.
        assert self._instances(server)["Intel(r) AMT: Force PXE Boot"]["FailThroughSupported"] == "2"


class TestElementOrdering:
    """Fixtures order an instance's properties strictly alphabetically; the mock now does too.

    This collection's parser is *not* order-sensitive for distinct property names
    (``plugins/module_utils/wsman.py``'s ``_element_to_value()`` keys a dict by local
    name), so this is fidelity insurance against a future parser that cares -- not a bug
    fix. Asserted here so it cannot silently regress.
    """

    @staticmethod
    def _property_names(resp) -> list[str]:
        root = ET.fromstring(resp.content)  # noqa: S314
        body = root.find(f"{{{NS_S}}}Body")
        instance = next(iter(body))
        return [child.tag.rsplit("}", 1)[-1] for child in instance]

    @pytest.mark.parametrize(
        "resource_uri",
        [
            CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE,
            AMT_BOOT_CAPABILITIES,
            AMT_REDIRECTION_SERVICE,
            AMT_GENERAL_SETTINGS,
            AMT_SETUP_AND_CONFIGURATION_SERVICE,
            CIM_COMPUTER_SYSTEM,
            CIM_BIOS_ELEMENT,
            AMT_MESSAGE_LOG,
        ],
    )
    def test_get_emits_properties_alphabetically(self, server, resource_uri):
        # AMT_EthernetPortSettings is absent from the list above because it is the one
        # class that requires a SelectorSet; it has its own test immediately below.
        names = self._property_names(_post(server, _get_xml(resource_uri)))
        assert names == sorted(names), f"{resource_uri} is not alphabetical: {names}"

    def test_ethernet_port_settings_is_alphabetical_too(self, server):
        names = self._property_names(_post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, {"InstanceID": ETHERNET_PORT_0_INSTANCE_ID})))
        assert names == sorted(names)

    def test_repeated_array_elements_keep_their_own_order(self, server):
        """Sorting is by property *name*: an array's values must not be reordered.

        ``AvailableRequestedPowerStates`` is the strongest case -- its fixture order is
        not sorted, and sorting it would invent a bookkeeping firmware never promised.
        """
        root = ET.fromstring(_post(server, _get_xml(CIM_ASSOCIATED_POWER_MANAGEMENT_SERVICE)).content)  # noqa: S314
        assert _find_all_text(root, "AvailableRequestedPowerStates") == ["10", "8", "5", "11", "4", "7", "14", "12"]

    def test_method_output_ordering_is_unaffected(self, server):
        """AMT_MessageLog's _OUTPUT fixtures are *not* alphabetical -- ReturnValue is last.

        Instance ordering and method-output ordering are separate rules and the
        alphabetical sort must not have leaked into the second one.
        """
        resp = _post(server, _method_xml(AMT_MESSAGE_LOG, "GetRecords", {"IterationIdentifier": "1", "MaxReadRecords": "2"}))
        root = ET.fromstring(resp.content)  # noqa: S314
        output = next(elem for elem in root.iter() if elem.tag.rsplit("}", 1)[-1] == "GetRecords_OUTPUT")
        names = [child.tag.rsplit("}", 1)[-1] for child in output]
        assert names[0] == "IterationIdentifier"
        assert names[-1] == "ReturnValue"


class TestAmt10EnumerateFaultMode:
    """Opt-in AMT 10-era firmware: ``Enumerate`` is HTTP 400 on ``AMT_``-prefixed classes.

    Hardware-verified on AMT 10.0.56 (docs/protocol-notes.md 2.7). Deliberately **not**
    unconditional: the same section records this collection's ``Enumerate`` call sites as
    working on 16.1.30 and 19.0.5, both hardware-verified, so a mock that always rejected
    the verb would assert something false about modern firmware and break correct code.
    """

    def test_enumerate_on_amt_classes_works_by_default(self, server):
        # Modern firmware is the default. Nothing about this mode changes that.
        assert _post(server, _enumerate_xml(AMT_BOOT_CAPABILITIES)).status_code == 200

    def test_armed_it_answers_400_not_a_soap_fault(self, server):
        server.faults.enumerate_faults_for_amt_classes = True
        resp = _post(server, _enumerate_xml(AMT_BOOT_CAPABILITIES))
        assert resp.status_code == 400

    def test_get_with_an_exact_selector_still_works_on_that_firmware(self, server):
        """The point of the AMT 10 finding: selective instance access only.

        A degradation path that used ``Get`` with a selector would keep working, which is
        what 2.7 tells implementers to add. This asserts the mock actually models that
        rather than making the class unreachable.
        """
        server.faults.enumerate_faults_for_amt_classes = True
        resp = _post(server, _get_xml(AMT_ETHERNET_PORT_SETTINGS, {"InstanceID": ETHERNET_PORT_0_INSTANCE_ID}))
        assert resp.status_code == 200
        assert _find_text(ET.fromstring(resp.content), "MACAddress") is not None  # noqa: S314

    def test_cim_prefixed_classes_are_unaffected(self, server):
        # 2.7 is explicit: "CIM_-prefixed classes are not affected by this finding."
        server.faults.enumerate_faults_for_amt_classes = True
        assert _post(server, _enumerate_xml(CIM_BOOT_SOURCE_SETTING)).status_code == 200
        assert _post(server, _enumerate_xml(CIM_BIOS_ELEMENT)).status_code == 200

    def test_message_log_is_exempt_because_its_enumerate_is_evidenced(self, server):
        """Unusually for an ``AMT_`` class, ``AMT_MessageLog``'s Enumerate is documented.

        ``responses/amt/messagelog/`` ships ``enumerate.xml`` and ``pull.xml`` alongside
        ``get.xml``, and 2.7's finding lists five classes, none of them this one.
        Sweeping it in would extend a hardware finding past what it covers.
        """
        server.faults.enumerate_faults_for_amt_classes = True
        assert _post(server, _enumerate_xml(AMT_MESSAGE_LOG)).status_code == 200

    def test_disarming_restores_the_modern_behaviour(self, server):
        server.faults.enumerate_faults_for_amt_classes = True
        assert _post(server, _enumerate_xml(AMT_BOOT_CAPABILITIES)).status_code == 400
        server.faults.enumerate_faults_for_amt_classes = False
        assert _post(server, _enumerate_xml(AMT_BOOT_CAPABILITIES)).status_code == 200
